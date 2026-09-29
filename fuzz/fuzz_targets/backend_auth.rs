//! What a backend answers a forwarded token with: the OAUTHBEARER error
//! result (RFC 7628 §3.2.2) and the ManageSieve challenge string it comes
//! in (RFC 5804 §4), plus the build/parse roundtrip of the forwarded
//! OAUTHBEARER response.
#![no_main]

use base64::Engine as _;
use libfuzzer_sys::fuzz_target;
use mail_auth_proxy::fuzz_api::*;
use mail_auth_proxy_fuzz::{block_on, Peer};

/// A status that reaches a log line is a plain word.
fn check_result(r: ErrorResult) {
    if let ErrorResult::Status(s) = r {
        assert!(s.len() <= 64, "status too long");
        assert!(
            s.chars().all(|c| c.is_ascii_alphanumeric() || "@._-+?".contains(c)),
            "unsanitised status {s:?}"
        );
    }
}

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    check_result(parse_error_result(&text));
    check_result(parse_error_result(
        &base64::engine::general_purpose::STANDARD.encode(data),
    ));

    // The first line is the challenge line, the rest what follows it.
    let split = data.iter().position(|&c| c == b'\n').unwrap_or(data.len());
    let line = String::from_utf8_lossy(&data[..split]);
    let line = line.trim_end_matches('\r');
    let rest = data.get(split + 1..).unwrap_or_default();
    let mut peer = Peer::new(rest);
    let r = block_on(sieve_read_challenge(&mut peer, line));
    // Nothing is read past the literal's closing line: the next line is the
    // backend's verdict.
    assert!(peer.at_line_boundary(), "read past the challenge");
    if let Ok(challenge) = r {
        assert!(challenge.len() <= 4096 || line.starts_with('"'));
        check_result(parse_error_result(&challenge));
    }

    // Roundtrip: the forwarded response parses back to the identity and token.
    let (user, token) = text.split_once('\n').unwrap_or((&text, "t"));
    let token = token.trim();
    let clean = |s: &str| !s.is_empty() && !s.chars().any(char::is_control) && s.len() <= 200;
    if clean(user) && clean(token) && !token.contains(' ') {
        let b64 = build_oauthbearer(user, "backend.example.org", 993, token);
        let c = parse_sasl("OAUTHBEARER", &b64).expect("forwarded OAUTHBEARER parses");
        assert_eq!(c.user, user);
        assert_eq!(c.token.as_str(), token);
        assert_eq!(c.host.as_deref(), Some("backend.example.org"));
    }
});
