//! Structured auth-outcome logging for downstream consumers.
//!
//! CrowdSec parses these lines to ban brute-force sources; Grafana reads the
//! counters in `obs/metrics.rs`. One event per auth outcome, emitted on a stable
//! `authlog` target with a fixed `authresult` message so a log parser can
//! anchor reliably. Fields: result, proto, scope (internal/external), mech,
//! user, peer (source IP), reason, pwfp, rule (the legacy rule that decided,
//! empty otherwise). New fields are only ever appended at the end.
//!
//! SECURITY:
//! - The attempted password is NEVER logged in clear. Only a truncated
//!   HMAC-SHA256 fingerprint (`pwfp`, keyed per process) is emitted — enough to correlate password-spraying
//!   ("same password from many IPs") without exposing a possibly-real secret.
//! - `user`/`mech` are attacker-controlled, so they are sanitised before
//!   logging (control chars / spaces / newlines stripped) to prevent log
//!   injection — otherwise a crafted username could forge extra log lines and
//!   mislead CrowdSec.

use super::metrics::Proto;
use std::fmt::Write as _;
use std::net::IpAddr;

/// Process-lifetime HMAC key for password fingerprints, generated once at first
/// use from the system RNG and never persisted.
///
/// A plain digest of the attempted password is offline-guessable: anyone who
/// obtains the logs can hash a wordlist and recover every weak password that was
/// ever tried, including real ones typed into the wrong field. Keying the digest
/// removes that, because the key never leaves memory.
///
/// The trade-off is deliberate: fingerprints are comparable only within one
/// process lifetime, so spraying correlation resets on restart. That is the
/// window CrowdSec acts on anyway.
fn fingerprint_key() -> &'static aws_lc_rs::hmac::Key {
    static KEY: std::sync::OnceLock<aws_lc_rs::hmac::Key> = std::sync::OnceLock::new();
    KEY.get_or_init(|| {
        aws_lc_rs::hmac::Key::generate(
            aws_lc_rs::hmac::HMAC_SHA256,
            &aws_lc_rs::rand::SystemRandom::new(),
        )
        .expect("system RNG unavailable for fingerprint key")
    })
}

/// 64-bit hex fingerprint of an attempted password, keyed with a per-process
/// secret. Empty for `None` (OAuth has no password). One-way, and not
/// guessable offline without the key.
pub fn pw_fingerprint(pass: Option<&str>) -> String {
    match pass {
        None => String::new(),
        Some(p) => {
            let tag = aws_lc_rs::hmac::sign(fingerprint_key(), p.as_bytes());
            tag.as_ref()[..8]
                .iter()
                .fold(String::with_capacity(16), |mut s, b| {
                    let _ = write!(s, "{b:02x}");
                    s
                })
        }
    }
}

/// Keep only characters safe for a single-token log field; cap the length.
/// Anything else becomes `?`. Emails and usernames pass through unchanged.
/// Also used for client-supplied words (command, mechanism) in error texts.
pub fn sanitize(s: &str) -> String {
    s.chars()
        .take(64)
        .map(|c| {
            if c.is_ascii_alphanumeric() || "@._-+".contains(c) {
                c
            } else {
                '?'
            }
        })
        .collect()
}

/// Make attacker-influenced text safe for a free-text log field: control
/// characters (newline, ESC, …) are escaped, so one value can never start a
/// forged log line or inject terminal sequences. Printable text is unchanged.
pub fn escape(s: &str) -> String {
    s.chars()
        .flat_map(|c| {
            let esc = c.is_control().then(|| c.escape_default());
            let plain = (!c.is_control()).then_some(c);
            esc.into_iter().flatten().chain(plain)
        })
        .collect()
}

/// Why an auth attempt ended as it did: the `reason` field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    /// The backend accepted the credential.
    Ok,
    /// The session ended before a credential was presented.
    Protocol,
    /// A password on a connection the password gate does not allow it on.
    BlockedEndpoint,
    /// The token failed local validation.
    BadToken,
    /// A valid token, but the client asked to act as another identity (the
    /// SASL authorisation identity).
    AuthzidMismatch,
    /// The backend rejected the credential.
    BackendReject,
    /// Legacy gate: the login's domain is not allowed.
    UnknownDomain,
    /// Legacy gate: the account does not exist.
    UnknownAccount,
    /// Legacy gate: too many rejected passwords for this account.
    Throttled,
    /// The password is longer than the proxy forwards.
    Oversize,
}

impl Reason {
    /// The `reason` value in the log line.
    pub fn as_str(self) -> &'static str {
        match self {
            Reason::Ok => "ok",
            Reason::Protocol => "protocol",
            Reason::BlockedEndpoint => "blocked_endpoint",
            Reason::BadToken => "bad_token",
            Reason::AuthzidMismatch => "authzid_mismatch",
            Reason::BackendReject => "backend_reject",
            Reason::UnknownDomain => "unknown_domain",
            Reason::UnknownAccount => "unknown_account",
            Reason::Throttled => "throttled",
            Reason::Oversize => "oversize",
        }
    }
}

/// One auth outcome. `user` and `pwfp` are empty when there is none (no
/// credential yet; OAuth carries no password).
pub struct AuthEvent<'a> {
    pub proto: Proto,
    /// `internal` or `external`.
    pub scope: &'a str,
    pub mech: &'a str,
    pub user: &'a str,
    pub peer: IpAddr,
    pub reason: Reason,
    /// `pw_fingerprint` of the attempted password, or empty.
    pub pwfp: &'a str,
    /// Name of the legacy rule that decided, or empty (OAuth, no rule).
    pub rule: &'a str,
}

impl AuthEvent<'_> {
    /// Emit the `authresult` line: INFO with `result="ok"` for `Reason::Ok`,
    /// WARN with `result="fail"` for every other reason.
    pub fn record(&self) {
        let proto = self.proto.label();
        let scope = self.scope;
        let user = sanitize(self.user);
        let mech = sanitize(self.mech);
        // A dual-stack listener sees IPv4 clients as `::ffff:a.b.c.d`; log
        // the IPv4 address they are, as every other record does.
        let peer = self.peer.to_canonical();
        let reason = self.reason.as_str();
        let pwfp = self.pwfp;
        // Rule names are validated at startup; sanitised anyway, the field is
        // parsed.
        let rule = sanitize(self.rule);
        if self.reason == Reason::Ok {
            tracing::info!(target: "authlog",
                result = "ok", proto, scope, mech = %mech, user = %user, peer = %peer, reason, pwfp, rule = rule.as_str(), "authresult");
        } else {
            tracing::warn!(target: "authlog",
                result = "fail", proto, scope, mech = %mech, user = %user, peer = %peer, reason, pwfp, rule = rule.as_str(), "authresult");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_stable_and_16_hex() {
        let a = pw_fingerprint(Some("hunter2"));
        let b = pw_fingerprint(Some("hunter2"));
        assert_eq!(
            a, b,
            "same password → same fingerprint (spraying correlation)"
        );
        assert_eq!(a.len(), 16);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn fingerprint_differs_per_password_and_hides_clear() {
        let a = pw_fingerprint(Some("hunter2"));
        let b = pw_fingerprint(Some("hunter3"));
        assert_ne!(a, b);
        assert!(!a.contains("hunter"), "must not leak the clear password");
    }

    /// The `reason` values are parsed by CrowdSec and Wazuh.
    #[test]
    fn reason_strings_are_stable() {
        let all = [
            (Reason::Ok, "ok"),
            (Reason::Protocol, "protocol"),
            (Reason::BlockedEndpoint, "blocked_endpoint"),
            (Reason::BadToken, "bad_token"),
            (Reason::AuthzidMismatch, "authzid_mismatch"),
            (Reason::BackendReject, "backend_reject"),
            (Reason::UnknownDomain, "unknown_domain"),
            (Reason::UnknownAccount, "unknown_account"),
            (Reason::Throttled, "throttled"),
            (Reason::Oversize, "oversize"),
        ];
        for (r, s) in all {
            assert_eq!(r.as_str(), s);
        }
    }

    /// An IPv4-mapped IPv6 peer is logged as the IPv4 address.
    #[test]
    fn peer_is_canonical() {
        use std::io::Write;
        use std::sync::{Arc, Mutex};
        #[derive(Clone, Default)]
        struct Buf(Arc<Mutex<Vec<u8>>>);
        impl Write for Buf {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let buf = Buf::default();
        let out = buf.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || out.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            AuthEvent {
                proto: Proto::Imap,
                scope: "external",
                mech: "PLAIN",
                user: "u@x",
                peer: "::ffff:192.0.2.7".parse().unwrap(),
                reason: Reason::BackendReject,
                pwfp: "",
                rule: "",
            }
            .record();
        });
        let line = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        assert!(line.contains(" peer=192.0.2.7 "), "{line}");
    }

    #[test]
    fn fingerprint_none_is_empty() {
        assert_eq!(pw_fingerprint(None), "");
    }

    #[test]
    fn sanitize_strips_injection_and_caps() {
        // Newline + space + quotes would let an attacker forge log fields.
        assert_eq!(sanitize("a b\nc\"d"), "a?b?c?d");
        assert_eq!(sanitize("user@example.org"), "user@example.org");
        assert_eq!(sanitize(&"x".repeat(200)).len(), 64);
    }

    /// Error texts reach the journal via `escape`; a newline or ESC in client
    /// input must not start a new (forged) log line or a terminal sequence.
    #[test]
    fn escape_neutralises_control_characters() {
        let e = escape("x\nFAKE authresult result=ok\x1b[31m\r");
        assert!(
            !e.contains('\n') && !e.contains('\r') && !e.contains('\x1b'),
            "{e}"
        );
        assert!(e.starts_with("x\\nFAKE"), "{e}");
        assert_eq!(
            escape("alice@example.org Ümlaut"),
            "alice@example.org Ümlaut"
        );
    }
}
