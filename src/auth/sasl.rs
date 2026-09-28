use anyhow::{anyhow, Result};
use base64::Engine;
use zeroize::Zeroizing;

/// The credential of an OAuth SASL response. No `Debug` derive and no
/// `Clone`: the token must not reach a log line or be copied.
pub struct SaslCreds {
    pub user: String,
    pub token: Zeroizing<String>,
}

impl std::fmt::Debug for SaslCreds {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SaslCreds")
            .field("user", &self.user)
            .field("token", &"<redacted>")
            .finish()
    }
}

/// Decode base64 that carries a credential into a buffer that is overwritten
/// when dropped, also when decoding fails half-way. The error names no input
/// byte: the input is the encoded credential.
pub fn decode_secret_b64(b64: &str) -> Result<Zeroizing<Vec<u8>>> {
    let mut raw = Zeroizing::new(Vec::new());
    base64::engine::general_purpose::STANDARD
        .decode_vec(b64.trim(), &mut raw)
        .map_err(|e| {
            anyhow!(
                "base64 decode: {}",
                match e {
                    base64::DecodeError::InvalidByte(..) => "invalid character",
                    base64::DecodeError::InvalidLength(_) => "invalid length",
                    base64::DecodeError::InvalidLastSymbol { .. } => "invalid last symbol",
                    base64::DecodeError::InvalidPadding => "invalid padding",
                }
            )
        })?;
    Ok(raw)
}

/// Extract the `auth=Bearer <token>` value from ^A-separated fields. The
/// scheme name is case-insensitive (RFC 6750 §2.1, RFC 7628 §3.1).
fn extract_bearer(s: &str) -> Option<Zeroizing<String>> {
    const PREFIX: &str = "auth=bearer ";
    s.split('\x01')
        .find_map(|f| {
            f.get(..PREFIX.len())
                .filter(|p| p.eq_ignore_ascii_case(PREFIX))
                .map(|_| f[PREFIX.len()..].trim())
        })
        .filter(|t| !t.is_empty())
        .map(|t| Zeroizing::new(t.to_owned()))
}

pub fn parse_sasl(mechanism: &str, b64_ir: &str) -> Result<SaslCreds> {
    let raw = decode_secret_b64(b64_ir)?;
    let s = std::str::from_utf8(&raw).map_err(|e| anyhow!("utf8: {e}"))?;
    let token = extract_bearer(s).ok_or_else(|| anyhow!("no bearer token in SASL"))?;
    let user = match mechanism.to_ascii_uppercase().as_str() {
        "XOAUTH2" => s
            .split('\x01')
            .find_map(|f| f.strip_prefix("user=").map(|u| u.to_string()))
            .ok_or_else(|| anyhow!("no user= in XOAUTH2"))?,
        // gs2 header: n,a=<user>, — the authzid is optional (RFC 7628 §3.1,
        // `n,,`). It is only logged; the mailbox comes from the token.
        "OAUTHBEARER" => {
            let first = s.split('\x01').next().unwrap_or("");
            first
                .split(',')
                .find_map(|p| p.strip_prefix("a=").map(|u| u.to_string()))
                .unwrap_or_default()
        }
        m => return Err(anyhow!("unsupported mechanism {m}")),
    };
    if user.is_empty() && mechanism.eq_ignore_ascii_case("XOAUTH2") {
        return Err(anyhow!("empty user"));
    }
    Ok(SaslCreds { user, token })
}

/// Whether a client may name `authzid` (XOAUTH2 `user=`, OAUTHBEARER `a=`)
/// with a token whose verified identity is `identity`. Acting as another
/// user is not supported (RFC 4422 §3.6), so the exchange fails unless the
/// authzid is empty, names the same identity, or is the identity's local
/// part without a domain (clients configured with a short username), all
/// ASCII case-insensitive as mailbox logins are matched. A different full
/// address always fails.
pub fn authzid_allowed(authzid: &str, identity: &str) -> bool {
    authzid.is_empty()
        || authzid.eq_ignore_ascii_case(identity)
        || (!authzid.contains('@')
            && identity
                .rsplit_once('@')
                .is_some_and(|(local, _)| authzid.eq_ignore_ascii_case(local)))
}

/// Build an XOAUTH2 response to forward to the backend. Both the raw form
/// and the base64 are zeroized on drop; `concat` sizes its buffer once, so no
/// reallocation leaves a copy of the token behind.
pub fn build_xoauth2(user: &str, token: &str) -> Zeroizing<String> {
    let raw = Zeroizing::new(["user=", user, "\x01auth=Bearer ", token, "\x01\x01"].concat());
    Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(raw.as_bytes()))
}

/// What a client authenticated with. The proxy either forwards an OAuth bearer
/// token (validated locally first) or a password (validated by the backend).
/// `Debug` is hand-written to REDACT the secret — a password/token must never
/// reach a log line. The secret is zeroized on drop; there is no `Clone`.
pub enum ClientAuthKind {
    OAuth {
        user: String,
        token: Zeroizing<String>,
    },
    Password {
        user: String,
        pass: Zeroizing<String>,
    },
}

impl std::fmt::Debug for ClientAuthKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientAuthKind::OAuth { user, .. } => f
                .debug_struct("OAuth")
                .field("user", user)
                .field("token", &"<redacted>")
                .finish(),
            ClientAuthKind::Password { user, .. } => f
                .debug_struct("Password")
                .field("user", user)
                .field("pass", &"<redacted>")
                .finish(),
        }
    }
}

/// Parse a SASL PLAIN initial response: `authzid \0 authcid \0 passwd` (RFC 4616).
/// Returns (login_user, password). The login is the authcid; an authzid is only
/// accepted when it names the same user — acting as another user is not
/// supported, and forwarding the authzid as the login would check the password
/// against the wrong account.
pub fn parse_plain(b64_ir: &str) -> Result<(String, Zeroizing<String>)> {
    let raw = decode_secret_b64(b64_ir)?;
    let mut it = raw.splitn(3, |&b| b == 0);
    let authzid = it.next().ok_or_else(|| anyhow!("PLAIN: missing authzid"))?;
    let authcid = it
        .next()
        .ok_or_else(|| anyhow!("PLAIN: missing authcid (NUL-separated)"))?;
    let passwd = it
        .next()
        .ok_or_else(|| anyhow!("PLAIN: missing passwd (NUL-separated)"))?;
    if !authzid.is_empty() && authzid != authcid {
        return Err(anyhow!(
            "PLAIN: authorization identity differs from the login"
        ));
    }
    let user = String::from_utf8(authcid.to_vec()).map_err(|e| anyhow!("PLAIN user utf8: {e}"))?;
    let pass = std::str::from_utf8(passwd).map_err(|e| anyhow!("PLAIN pass utf8: {e}"))?;
    let pass = Zeroizing::new(pass.to_owned());
    if user.is_empty() {
        return Err(anyhow!("PLAIN: empty user"));
    }
    if pass.is_empty() {
        return Err(anyhow!("PLAIN: empty password"));
    }
    Ok((user, pass))
}

/// Build a SASL PLAIN IR to forward to the backend: `\0user\0pass` (empty
/// authzid). Zeroized on drop like `build_xoauth2`.
pub fn build_plain(user: &str, pass: &str) -> Zeroizing<String> {
    let mut raw = Zeroizing::new(Vec::with_capacity(2 + user.len() + pass.len()));
    raw.push(0u8);
    raw.extend_from_slice(user.as_bytes());
    raw.push(0u8);
    raw.extend_from_slice(pass.as_bytes());
    Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(raw.as_slice()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_xoauth2_ir() {
        // user=alice@x.tld^Aauth=Bearer TKN^A^A
        let raw = "user=alice@x.tld\x01auth=Bearer TKN\x01\x01";
        let ir = base64::engine::general_purpose::STANDARD.encode(raw);
        let c = parse_sasl("XOAUTH2", &ir).unwrap();
        assert_eq!(c.user, "alice@x.tld");
        assert_eq!(*c.token, "TKN");
    }

    #[test]
    fn parse_oauthbearer_ir() {
        // n,a=bob@y.tld,^Ahost=h^Aport=993^Aauth=Bearer TK2^A^A
        let raw = "n,a=bob@y.tld,\x01host=h\x01port=993\x01auth=Bearer TK2\x01\x01";
        let ir = base64::engine::general_purpose::STANDARD.encode(raw);
        let c = parse_sasl("OAUTHBEARER", &ir).unwrap();
        assert_eq!(c.user, "bob@y.tld");
        assert_eq!(*c.token, "TK2");
    }

    #[test]
    fn build_roundtrip() {
        let ir = build_xoauth2("alice@x.tld", "TKN");
        let c = parse_sasl("XOAUTH2", &ir).unwrap();
        assert_eq!(c.user, "alice@x.tld");
        assert_eq!(*c.token, "TKN");
    }

    #[test]
    fn malformed_rejected() {
        assert!(parse_sasl("XOAUTH2", "not*base64!!").is_err());
        let noauth = base64::engine::general_purpose::STANDARD.encode("user=x\x01\x01");
        assert!(parse_sasl("XOAUTH2", &noauth).is_err());
    }

    #[test]
    fn parse_plain_ir() {
        let ir = base64::engine::general_purpose::STANDARD.encode("\0alice@x.tld\0s3cret");
        let (u, p) = parse_plain(&ir).unwrap();
        assert_eq!(u, "alice@x.tld");
        assert_eq!(*p, "s3cret");
    }

    #[test]
    fn parse_plain_authzid_must_match_login() {
        let other =
            base64::engine::general_purpose::STANDARD.encode("authz@x.tld\0authc@x.tld\0pw");
        assert!(parse_plain(&other).is_err());
        let same = base64::engine::general_purpose::STANDARD.encode("authc@x.tld\0authc@x.tld\0pw");
        assert_eq!(parse_plain(&same).unwrap().0, "authc@x.tld");
    }

    #[test]
    fn plain_roundtrip_preserves_specials() {
        let ir = build_plain("bob@y.tld", "p@ss\x01word");
        let (u, p) = parse_plain(&ir).unwrap();
        assert_eq!(u, "bob@y.tld");
        assert_eq!(*p, "p@ss\x01word");
    }

    #[test]
    fn plain_malformed_rejected() {
        assert!(parse_plain("not*base64!!").is_err());
        let two = base64::engine::general_purpose::STANDARD.encode("\0user");
        assert!(parse_plain(&two).is_err());
        let empty_pw = base64::engine::general_purpose::STANDARD.encode("\0user\0");
        assert!(parse_plain(&empty_pw).is_err());
    }

    #[test]
    fn debug_redacts_secret() {
        let k = ClientAuthKind::Password {
            user: "u@x".into(),
            pass: String::from("TOPSECRET").into(),
        };
        let s = format!("{k:?}");
        assert!(!s.contains("TOPSECRET"), "password leaked in Debug: {s}");
        assert!(s.contains("redacted"));
        let o = ClientAuthKind::OAuth {
            user: "u@x".into(),
            token: String::from("TKSECRET").into(),
        };
        assert!(
            !format!("{o:?}").contains("TKSECRET"),
            "token leaked in Debug"
        );
    }

    #[test]
    fn authzid_must_be_empty_or_the_identity() {
        assert!(authzid_allowed("", "alice@example.org"));
        assert!(authzid_allowed("alice@example.org", "alice@example.org"));
        assert!(authzid_allowed("Alice@Example.ORG", "alice@example.org"));
        assert!(!authzid_allowed("bob@example.org", "alice@example.org"));
        assert!(authzid_allowed("alice", "alice@example.org"));
        assert!(authzid_allowed("ALICE", "alice@example.org"));
        assert!(!authzid_allowed("bob", "alice@example.org"));
        assert!(!authzid_allowed("alice@other.org", "alice@example.org"));
        // An identity that is no address has no local part to match.
        assert!(!authzid_allowed("ali", "alice"));
        assert!(!authzid_allowed(
            "alice@example.org.evil",
            "alice@example.org"
        ));
    }

    /// RFC 7628: `n,,` (no authzid) is valid, and the scheme is case-insensitive.
    #[test]
    fn oauthbearer_without_authzid_and_lowercase_scheme() {
        let raw = "n,,\x01auth=bearer TK3\x01\x01";
        let ir = base64::engine::general_purpose::STANDARD.encode(raw);
        let c = parse_sasl("OAUTHBEARER", &ir).unwrap();
        assert_eq!(*c.token, "TK3");
        assert_eq!(c.user, "");
        // XOAUTH2 still needs its user= field.
        let ir = base64::engine::general_purpose::STANDARD.encode("user=\x01auth=Bearer T\x01\x01");
        assert!(parse_sasl("XOAUTH2", &ir).is_err());
    }

    /// Every value holding a password, token or response is zeroized on
    /// drop. Turning one of them back into a plain `String` fails to compile.
    #[test]
    fn secrets_are_zeroize_on_drop() {
        fn zeroized<T: zeroize::ZeroizeOnDrop>(_: &T) {}
        let ir = build_xoauth2("u@x", "TKN");
        zeroized(&ir);
        zeroized(&parse_sasl("XOAUTH2", &ir).unwrap().token);
        let plain = build_plain("u@x", "pw");
        zeroized(&plain);
        zeroized(&parse_plain(&plain).unwrap().1);
        zeroized(&decode_secret_b64(&plain).unwrap());
        for kind in [
            ClientAuthKind::OAuth {
                user: "u@x".into(),
                token: String::from("TKN").into(),
            },
            ClientAuthKind::Password {
                user: "u@x".into(),
                pass: String::from("pw").into(),
            },
        ] {
            match &kind {
                ClientAuthKind::OAuth { token, .. } => zeroized(token),
                ClientAuthKind::Password { pass, .. } => zeroized(pass),
            }
        }
    }

    #[test]
    fn sasl_creds_debug_redacts_token() {
        let ir = build_xoauth2("u@x", "TKSECRET");
        let s = format!("{:?}", parse_sasl("XOAUTH2", &ir).unwrap());
        assert!(!s.contains("TKSECRET"), "token leaked in Debug: {s}");
        assert!(s.contains("u@x") && s.contains("redacted"), "{s}");
    }

    /// A base64 error names no byte of the input: the input is the encoded
    /// credential and the error text reaches the journal.
    #[test]
    fn base64_errors_carry_no_input() {
        // The base64 crate would name the offending symbol: `R` as a last
        // symbol with trailing bits set, `*` as an invalid byte.
        for (bad, why) in [
            ("QUJDRR==", "invalid last symbol"),
            ("QUJ*RA==", "invalid character"),
            ("QUJDR", "invalid length"),
        ] {
            let e = decode_secret_b64(bad).unwrap_err().to_string();
            assert_eq!(e, format!("base64 decode: {why}"));
        }
        let e = parse_plain("QUJDRR==").unwrap_err().to_string();
        assert_eq!(e, "base64 decode: invalid last symbol");
    }
}
