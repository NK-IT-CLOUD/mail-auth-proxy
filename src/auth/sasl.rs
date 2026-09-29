use anyhow::{anyhow, Result};
use base64::Engine;
use zeroize::Zeroizing;

/// The credential of an OAuth SASL response. `Debug` redacts the token and
/// there is no `Clone`: the token must not reach a log line or be copied.
pub struct SaslCreds {
    pub user: String,
    pub token: Zeroizing<String>,
    /// OAUTHBEARER `host`: the server name the client connected to (RFC
    /// 7628 §3.1), if it sent one.
    pub host: Option<String>,
}

impl std::fmt::Debug for SaslCreds {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SaslCreds")
            .field("user", &self.user)
            .field("token", &"<redacted>")
            .field("host", &self.host)
            .finish()
    }
}

/// Whether the OAUTHBEARER `host` names `server`, the name the client asked
/// for in TLS (SNI): ASCII case-insensitive, a trailing dot ignored.
pub fn host_matches(host: &str, server: &str) -> bool {
    let bare = |n: &str| n.strip_suffix('.').unwrap_or(n).to_string();
    bare(host).eq_ignore_ascii_case(&bare(server))
}

/// A SASL client response that is not base64, or a cancel (`*`). IMAP
/// answers it with BAD (RFC 9051 §6.2.2) and SMTP with 501 (RFC 4954 §4); a
/// response that decodes but holds no valid credential is a failed
/// authentication instead (IMAP NO, SMTP 535).
#[derive(Debug)]
pub struct BadResponse(pub &'static str);

impl std::fmt::Display for BadResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for BadResponse {}

/// Decode base64 that carries a credential into a buffer that is overwritten
/// when dropped, also when decoding fails half-way. The error (a
/// `BadResponse`) names no input byte: the input is the encoded credential.
pub fn decode_secret_b64(b64: &str) -> Result<Zeroizing<Vec<u8>>> {
    let mut raw = Zeroizing::new(Vec::new());
    base64::engine::general_purpose::STANDARD
        .decode_vec(b64.trim(), &mut raw)
        .map_err(|e| {
            anyhow::Error::new(BadResponse(match e {
                base64::DecodeError::InvalidByte(..) => "base64 decode: invalid character",
                base64::DecodeError::InvalidLength(_) => "base64 decode: invalid length",
                base64::DecodeError::InvalidLastSymbol { .. } => {
                    "base64 decode: invalid last symbol"
                }
                base64::DecodeError::InvalidPadding => "base64 decode: invalid padding",
            }))
        })?;
    Ok(raw)
}

/// A SASL mechanism the proxy takes from clients.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mechanism {
    XOAuth2,
    OAuthBearer,
    Plain,
    Login,
}

impl Mechanism {
    /// The mechanism named `name`, ASCII case-insensitive (RFC 4422 §3.1).
    pub fn parse(name: &str) -> Option<Mechanism> {
        [
            ("XOAUTH2", Mechanism::XOAuth2),
            ("OAUTHBEARER", Mechanism::OAuthBearer),
            ("PLAIN", Mechanism::Plain),
            ("LOGIN", Mechanism::Login),
        ]
        .into_iter()
        .find_map(|(n, m)| n.eq_ignore_ascii_case(name).then_some(m))
    }
}

/// Longest SASL user a client may name (XOAUTH2 `user=`, OAUTHBEARER `a=`),
/// the same bound as for a legacy login.
pub const MAX_SASL_USER: usize = 255;

/// A client-named SASL user as the proxy takes it: at most `MAX_SASL_USER`
/// bytes, no control characters. It is compared with the token's identity
/// and logged; a longer or controlled one is malformed.
fn check_sasl_user(user: String) -> Result<String> {
    if user.len() > MAX_SASL_USER {
        return Err(anyhow!("SASL user longer than {MAX_SASL_USER} bytes"));
    }
    if user.chars().any(char::is_control) {
        return Err(anyhow!("control character in the SASL user"));
    }
    Ok(user)
}

/// The authzid of the GS2 header that starts an OAUTHBEARER response (RFC
/// 7628 §3.1, RFC 5801 §4): `gs2-cbind-flag "," [ "a=" saslname ] ","`,
/// empty without one. The flag must be `n` or `y`: OAUTHBEARER has no
/// channel binding, so `p=` is refused. In the saslname `=2C` and `=3D`
/// stand for `,` and `=`; any other `=` and a raw `,` are malformed.
fn gs2_authzid(field: &str) -> Result<String> {
    let (flag, rest) = field
        .split_once(',')
        .ok_or_else(|| anyhow!("GS2 header without flag"))?;
    match flag {
        "n" | "y" => {}
        f if f.starts_with("p=") => return Err(anyhow!("GS2 channel binding not supported")),
        _ => return Err(anyhow!("GS2 header with an unknown flag")),
    }
    let authzid = rest
        .strip_suffix(',')
        .ok_or_else(|| anyhow!("GS2 header not terminated"))?;
    if authzid.is_empty() {
        return Ok(String::new());
    }
    let name = authzid
        .strip_prefix("a=")
        .filter(|n| !n.is_empty())
        .ok_or_else(|| anyhow!("GS2 authzid malformed"))?;
    let mut out = String::with_capacity(name.len());
    let mut chars = name.chars();
    while let Some(c) = chars.next() {
        match c {
            '=' => {
                let code: String = chars.by_ref().take(2).collect();
                match code.to_ascii_uppercase().as_str() {
                    "2C" => out.push(','),
                    "3D" => out.push('='),
                    _ => return Err(anyhow!("GS2 authzid with a bad escape")),
                }
            }
            ',' => return Err(anyhow!("GS2 authzid malformed")),
            c => out.push(c),
        }
    }
    Ok(out)
}

/// An OAuth response whose `auth` value is empty (`auth=`, or the Bearer
/// scheme without a token): the client asks which IdP and scope to use
/// (RFC 7628 §4.3). It carries no credential. `user` is the SASL user it
/// named; `tag` is set by the IMAP dialog to the command's tag.
#[derive(Debug)]
pub struct Discovery {
    pub mech: String,
    pub user: String,
    pub tag: String,
}

impl std::fmt::Display for Discovery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("empty auth value: a discovery request (RFC 7628 §4.3)")
    }
}

impl std::error::Error for Discovery {}

/// The `auth` field of an OAuth response.
enum Auth {
    Bearer(Zeroizing<String>),
    /// Empty, or the Bearer scheme without a token (`Discovery`).
    Empty,
    /// No `auth` field, or another scheme.
    Missing,
}

/// The first `auth=` of the ^A-separated fields. `auth` carries what the
/// HTTP Authorization header would (RFC 7628 §3.1), whose scheme name is
/// case-insensitive (RFC 9110 §11.1).
fn extract_bearer(s: &str) -> Auth {
    let Some(value) = s.split('\x01').find_map(|f| {
        f.get(..5)
            .filter(|k| k.eq_ignore_ascii_case("auth="))
            .map(|_| f[5..].trim())
    }) else {
        return Auth::Missing;
    };
    if value.is_empty() {
        return Auth::Empty;
    }
    let is_bearer = value
        .get(..6)
        .is_some_and(|s| s.eq_ignore_ascii_case("bearer"));
    match value.get(6..) {
        Some(rest) if is_bearer && rest.trim().is_empty() => Auth::Empty,
        Some(rest) if is_bearer && rest.starts_with(' ') => {
            Auth::Bearer(Zeroizing::new(rest.trim().to_owned()))
        }
        _ => Auth::Missing,
    }
}

/// The user and token of an XOAUTH2 or OAUTHBEARER response. An empty
/// `auth` value is the error `Discovery`.
pub fn parse_sasl(mechanism: &str, b64_ir: &str) -> Result<SaslCreds> {
    let raw = decode_secret_b64(b64_ir)?;
    let s = std::str::from_utf8(&raw).map_err(|e| anyhow!("utf8: {e}"))?;
    let token = match extract_bearer(s) {
        Auth::Bearer(token) => Some(token),
        Auth::Empty => None,
        Auth::Missing => return Err(anyhow!("no bearer token in SASL")),
    };
    let user = match Mechanism::parse(mechanism) {
        Some(Mechanism::XOAuth2) => {
            let user = s
                .split('\x01')
                .find_map(|f| f.strip_prefix("user=").map(|u| u.to_string()))
                .ok_or_else(|| anyhow!("no user= in XOAUTH2"))?;
            if user.is_empty() {
                return Err(anyhow!("empty user"));
            }
            user
        }
        // The authzid is optional (RFC 7628 §3.1, `n,,`). It is checked
        // against the token's identity (`authzid_allowed`); the mailbox comes
        // from the token.
        Some(Mechanism::OAuthBearer) => gs2_authzid(s.split('\x01').next().unwrap_or(""))?,
        Some(Mechanism::Plain | Mechanism::Login) | None => {
            return Err(anyhow!("not an OAuth mechanism"))
        }
    };
    let user = check_sasl_user(user)?;
    // OAUTHBEARER kvpairs follow the GS2 header; XOAUTH2 has no host.
    let host = match Mechanism::parse(mechanism) {
        Some(Mechanism::OAuthBearer) => s
            .split('\x01')
            .skip(1)
            .find_map(|f| f.strip_prefix("host="))
            .map(|h| {
                if h.is_empty() || h.len() > 255 || !h.bytes().all(|b| b.is_ascii_graphic()) {
                    Err(anyhow!("malformed host"))
                } else {
                    Ok(h.to_string())
                }
            })
            .transpose()?,
        _ => None,
    };
    match token {
        Some(token) => Ok(SaslCreds { user, token, host }),
        None => Err(anyhow::Error::new(Discovery {
            mech: mechanism.to_string(),
            user,
            tag: String::new(),
        })),
    }
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

/// Build an OAUTHBEARER response (RFC 7628 §3.1) to forward to the backend:
/// the GS2 header with `user` as authzid (RFC 5801 §4, `,` and `=` escaped),
/// the backend's `host` and `port` (the server the proxy connects to; port 0
/// is left out), the token. Zeroized on drop like `build_xoauth2`.
pub fn build_oauthbearer(user: &str, host: &str, port: u16, token: &str) -> Zeroizing<String> {
    let authzid = user.replace('=', "=3D").replace(',', "=2C");
    let port = if port == 0 {
        String::new()
    } else {
        format!("port={port}\x01")
    };
    let raw = Zeroizing::new(
        [
            "n,a=",
            &authzid,
            ",\x01host=",
            host,
            "\x01",
            &port,
            "auth=Bearer ",
            token,
            "\x01\x01",
        ]
        .concat(),
    );
    Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(raw.as_bytes()))
}

/// The dummy response that completes a failed OAUTHBEARER exchange after
/// the server's error result (RFC 7628 §3.2.3): `%x01`, base64.
pub const OAUTHBEARER_DUMMY: &str = "AQ==";

/// What a backend's error result (RFC 7628 §3.2.2) to a forwarded
/// OAUTHBEARER token says: the base64 of its challenge, a JSON object whose
/// `status` is an OAuth error code (RFC 6750 §3.1).
#[derive(Debug, PartialEq, Eq)]
pub enum ErrorResult {
    /// `invalid_request`: the backend could not use the request and judged
    /// no token. An outage, not a verdict.
    BadRequest,
    /// Any other status (`invalid_token`, `insufficient_scope`, …): a
    /// verdict on the token. The status as `authlog::sanitize` leaves it.
    Status(String),
    /// Not base64 of a JSON object with a string `status`.
    Malformed,
}

/// Largest error result read from a backend challenge (base64); a status,
/// a scope and a URL fit in far less.
const MAX_ERROR_RESULT: usize = 4096;

/// Classify a backend's error result (`b64`, the challenge text without
/// the protocol's prefix).
pub fn parse_error_result(b64: &str) -> ErrorResult {
    let b64 = b64.trim();
    if b64.len() > MAX_ERROR_RESULT {
        return ErrorResult::Malformed;
    }
    let Ok(raw) = base64::engine::general_purpose::STANDARD.decode(b64) else {
        return ErrorResult::Malformed;
    };
    let Ok(serde_json::Value::Object(o)) = serde_json::from_slice::<serde_json::Value>(&raw) else {
        return ErrorResult::Malformed;
    };
    match o.get("status").and_then(|v| v.as_str()) {
        Some("invalid_request") => ErrorResult::BadRequest,
        Some(status) => ErrorResult::Status(crate::obs::authlog::sanitize(status)),
        None => ErrorResult::Malformed,
    }
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
    // RFC 4616 §2: NUL MUST NOT appear in authzid, authcid or passwd; the
    // split leaves any further NUL in the password.
    if passwd.contains(&0) {
        return Err(anyhow!("PLAIN: NUL in the password"));
    }
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

    /// The forwarded OAUTHBEARER response parses back with the client-side
    /// parser: the authzid survives `,` and `=`, and the token is intact.
    #[test]
    fn oauthbearer_forward_round_trips() {
        let b64 = build_oauthbearer("a,b=c@example.org", "mail.example.org", 993, "TKN");
        let raw = String::from_utf8(
            base64::engine::general_purpose::STANDARD
                .decode(b64.as_str())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            raw,
            "n,a=a=2Cb=3Dc@example.org,\x01host=mail.example.org\x01port=993\x01auth=Bearer TKN\x01\x01"
        );
        let c = parse_sasl("OAUTHBEARER", &b64).unwrap();
        assert_eq!(c.user, "a,b=c@example.org");
        assert_eq!(c.token.as_str(), "TKN");
        assert_eq!(c.host.as_deref(), Some("mail.example.org"));
        let raw = base64::engine::general_purpose::STANDARD
            .decode(build_oauthbearer("u@example.org", "192.0.2.1", 0, "T").as_str())
            .unwrap();
        assert_eq!(
            raw,
            b"n,a=u@example.org,\x01host=192.0.2.1\x01auth=Bearer T\x01\x01"
        );
    }

    #[test]
    fn backend_error_results() {
        let b = |s: &str| base64::engine::general_purpose::STANDARD.encode(s);
        assert_eq!(
            parse_error_result(&b(r#"{"status":"invalid_token","scope":"mail"}"#)),
            ErrorResult::Status("invalid_token".into())
        );
        assert_eq!(
            parse_error_result(&b(r#"{"status":"invalid_request"}"#)),
            ErrorResult::BadRequest
        );
        assert_eq!(
            parse_error_result(&format!(" {} ", b(r#"{"status":"x\ny"}"#))),
            ErrorResult::Status("x?y".into())
        );
        for bad in [
            b(r#"{"scope":"mail"}"#),
            b(r#"{"status":401}"#),
            b(r#"["invalid_token"]"#),
            b("not json"),
            "***".into(),
            String::new(),
            b(&format!(r#"{{"status":"{}"}}"#, "x".repeat(4000))),
        ] {
            assert_eq!(parse_error_result(&bad), ErrorResult::Malformed, "{bad}");
        }
    }

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

    /// RFC 4616 §2: NUL must not appear in the password (the split leaves
    /// any further NUL there).
    #[test]
    fn plain_nul_in_password_rejected() {
        let ir = base64::engine::general_purpose::STANDARD.encode("\0user\0pa\0ss");
        assert!(parse_plain(&ir).is_err());
        let ir = base64::engine::general_purpose::STANDARD.encode("\0user\0pass\0");
        assert!(parse_plain(&ir).is_err());
    }

    /// The GS2 header of OAUTHBEARER (RFC 7628 §3.1, RFC 5801 §4).
    #[test]
    fn oauthbearer_gs2_header() {
        let parse = |gs2: &str| {
            let raw = format!("{gs2}\x01auth=Bearer T\x01\x01");
            let ir = base64::engine::general_purpose::STANDARD.encode(raw);
            parse_sasl("OAUTHBEARER", &ir).map(|c| c.user)
        };
        assert_eq!(parse("n,,").unwrap(), "");
        assert_eq!(parse("y,,").unwrap(), "");
        assert_eq!(parse("n,a=bob@y.tld,").unwrap(), "bob@y.tld");
        assert_eq!(parse("n,a=a=2Cb=3Dc=2c,").unwrap(), "a,b=c,");
        for bad in [
            "p=tls-unique,,",
            "p=tls-unique,a=bob@y.tld,",
            "x,,",
            ",,",
            "n,",
            "n,a=bob@y.tld",
            "n,a=,",
            "n,b=bob,",
            "n,a=bo,b,",
            "n,a=bob=2,",
            "n,a=bob=41,",
            "n,a=bob,extra,",
            "",
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
    }

    /// A client-named SASL user is bounded and has no control characters.
    #[test]
    fn sasl_user_is_checked() {
        let xoauth2 = |user: &str| {
            let ir = base64::engine::general_purpose::STANDARD
                .encode(format!("user={user}\x01auth=Bearer T\x01\x01"));
            parse_sasl("XOAUTH2", &ir)
        };
        assert!(xoauth2(&"a".repeat(MAX_SASL_USER)).is_ok());
        assert!(xoauth2(&"a".repeat(MAX_SASL_USER + 1)).is_err());
        assert!(xoauth2("bob\x1b[2J@y.tld").is_err());
        assert!(xoauth2("bob\n@y.tld").is_err());
        let ir = base64::engine::general_purpose::STANDARD
            .encode("n,a=bob\x7f@y.tld,\x01auth=Bearer T\x01\x01");
        assert!(parse_sasl("OAUTHBEARER", &ir).is_err());
    }

    /// An empty `auth` value is a discovery request (RFC 7628 §4.3), not a
    /// parse error; another scheme or no `auth` field stays one.
    #[test]
    fn empty_auth_is_discovery() {
        let parse = |mech: &str, raw: &str| {
            parse_sasl(mech, &base64::engine::general_purpose::STANDARD.encode(raw))
        };
        for (mech, raw) in [
            ("OAUTHBEARER", "n,a=bob@y.tld,\x01host=h\x01auth=\x01\x01"),
            ("OAUTHBEARER", "n,,\x01auth=Bearer\x01\x01"),
            ("XOAUTH2", "user=bob@y.tld\x01auth=Bearer \x01\x01"),
            ("XOAUTH2", "user=bob@y.tld\x01AUTH=bearer   \x01\x01"),
        ] {
            let e = parse(mech, raw).unwrap_err();
            let d = e.downcast_ref::<Discovery>().expect(raw);
            assert_eq!(d.mech, mech);
        }
        assert_eq!(
            parse("OAUTHBEARER", "n,a=bob@y.tld,\x01auth=\x01\x01")
                .unwrap_err()
                .downcast_ref::<Discovery>()
                .unwrap()
                .user,
            "bob@y.tld"
        );
        for raw in [
            "user=bob\x01auth=Basic eDp5\x01\x01",
            "user=bob\x01auth=BearerX T\x01\x01",
            "user=bob\x01\x01",
        ] {
            let e = parse("XOAUTH2", raw).unwrap_err();
            assert!(!e.is::<Discovery>(), "{raw:?}");
        }
        assert_eq!(
            *parse("XOAUTH2", "user=bob\x01AUTH=BEARER T1\x01\x01")
                .unwrap()
                .token,
            "T1"
        );
    }

    /// The OAUTHBEARER `host` is read from the kvpairs and compared with
    /// the SNI name ASCII case-insensitively, a trailing dot ignored.
    #[test]
    fn oauthbearer_host() {
        let parse = |raw: &str| {
            parse_sasl(
                "OAUTHBEARER",
                &base64::engine::general_purpose::STANDARD.encode(raw),
            )
        };
        let c = parse("n,,\x01host=Mail.Example.org\x01port=993\x01auth=Bearer T\x01\x01").unwrap();
        assert_eq!(c.host.as_deref(), Some("Mail.Example.org"));
        assert_eq!(parse("n,,\x01auth=Bearer T\x01\x01").unwrap().host, None);
        for bad in ["host=", "host=a b", "host=a\x7f"] {
            assert!(parse(&format!("n,,\x01{bad}\x01auth=Bearer T\x01\x01")).is_err());
        }
        // XOAUTH2 has no host field.
        let ir = build_xoauth2("u@x", "T");
        assert_eq!(parse_sasl("XOAUTH2", &ir).unwrap().host, None);
        assert!(host_matches("Mail.Example.org", "mail.example.org"));
        assert!(host_matches("mail.example.org.", "mail.example.org"));
        assert!(!host_matches("mail.example.org", "imap.example.org"));
        assert!(!host_matches("mail.example.org.evil", "mail.example.org"));
    }

    #[test]
    fn mechanism_names() {
        assert_eq!(Mechanism::parse("xoauth2"), Some(Mechanism::XOAuth2));
        assert_eq!(
            Mechanism::parse("OAuthBearer"),
            Some(Mechanism::OAuthBearer)
        );
        assert_eq!(Mechanism::parse("PLAIN"), Some(Mechanism::Plain));
        assert_eq!(Mechanism::parse("login"), Some(Mechanism::Login));
        assert_eq!(Mechanism::parse("CRAM-MD5"), None);
        assert_eq!(Mechanism::parse("PLAINX"), None);
        assert!(parse_sasl("PLAIN", &build_xoauth2("u@x", "T")).is_err());
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
