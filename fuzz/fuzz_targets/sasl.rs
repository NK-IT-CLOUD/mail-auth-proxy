//! SASL initial responses (XOAUTH2, OAUTHBEARER RFC 7628, PLAIN RFC 4616,
//! LOGIN fields), their base64 decoding, the authzid rule and the
//! build/parse roundtrips.
#![no_main]

use base64::Engine as _;
use libfuzzer_sys::fuzz_target;
use mail_auth_proxy::fuzz_api::*;

const MECHS: [&str; 6] = [
    "XOAUTH2",
    "OAUTHBEARER",
    "xoauth2",
    "OAuthBearer",
    "PLAIN",
    "X",
];

/// What any successful parse must satisfy.
fn check_sasl<E>(mech: &str, r: Result<SaslCreds, E>) {
    let Ok(c) = r else { return };
    assert!(
        mech.eq_ignore_ascii_case("XOAUTH2") || mech.eq_ignore_ascii_case("OAUTHBEARER"),
        "{mech} accepted"
    );
    assert!(!c.token.is_empty(), "empty token");
    assert_eq!(c.token.as_str(), c.token.trim(), "token not trimmed");
    assert!(!c.token.contains('\x01'), "token spans fields");
    assert!(!c.user.contains('\x01'), "user spans fields");
    if mech.eq_ignore_ascii_case("XOAUTH2") {
        assert!(!c.user.is_empty(), "XOAUTH2 without user");
    }
}

fn check_plain<P: AsRef<str>, E>(r: Result<(String, P), E>) {
    let Ok((user, pass)) = r else { return };
    assert!(
        !user.is_empty() && !pass.as_ref().is_empty(),
        "empty PLAIN field"
    );
    assert!(!user.contains('\0'), "PLAIN user with NUL");
}

fn parse_all(ir: &str) {
    for mech in MECHS {
        check_sasl(mech, parse_sasl(mech, ir));
    }
    check_plain(parse_plain(ir));
    let _ = decode_login_field(ir);
}

fuzz_target!(|data: &[u8]| {
    // The raw bytes as the base64 text a client sends, and base64-encoded,
    // so the decoded SASL structure is explored directly.
    parse_all(&String::from_utf8_lossy(data));
    parse_all(&base64::engine::general_purpose::STANDARD.encode(data));

    // Split at the first LF into two fields for the roundtrips and the
    // authzid rule (LF, not NUL: seed files must stay text for the leak gate).
    let (a, b) = match data.iter().position(|&c| c == b'\n') {
        Some(i) => (&data[..i], &data[i + 1..]),
        None => (data, &[][..]),
    };
    let a = String::from_utf8_lossy(a).into_owned();
    let b = String::from_utf8_lossy(b).into_owned();

    // XOAUTH2: what the proxy builds for the backend parses back to itself.
    // The parser refuses a user with control characters (\x01 included) or
    // over 255 bytes.
    let user: String = a.chars().filter(|&c| !c.is_control()).take(63).collect();
    let token: String = b.chars().filter(|&c| c != '\x01').collect();
    let token = token.trim();
    if !user.is_empty() && !token.is_empty() {
        let c = parse_sasl("XOAUTH2", &build_xoauth2(&user, token)).expect("XOAUTH2 roundtrip");
        assert_eq!((c.user.as_str(), c.token.as_str()), (user.as_str(), token));
    }

    // PLAIN: the same for the password path. NUL separates the fields and
    // must not appear in any of them (RFC 4616 §2).
    let login: String = a.chars().filter(|&c| c != '\0').collect();
    let pass: String = b.chars().filter(|&c| c != '\0').collect();
    if !login.is_empty() && !pass.is_empty() {
        let (u, p) = parse_plain(&build_plain(&login, &pass)).expect("PLAIN roundtrip");
        assert_eq!((u.as_str(), p.as_str()), (login.as_str(), pass.as_str()));
    }

    // authzid rule (RFC 4422 §3.6): empty and the identity itself always
    // pass; an authzid with a domain passes only as the identity itself.
    assert!(authzid_allowed("", &b));
    assert!(authzid_allowed(&b, &b));
    if authzid_allowed(&a, &b) && a.contains('@') {
        assert!(a.eq_ignore_ascii_case(&b), "{a:?} may act as {b:?}");
    }
    if authzid_allowed(&a, &b) && !a.is_empty() && !a.eq_ignore_ascii_case(&b) {
        let local = b.rsplit_once('@').map(|(l, _)| l).expect("local part");
        assert!(a.eq_ignore_ascii_case(local), "{a:?} may act as {b:?}");
    }

    // The answer to the RFC 7628 error challenge (section 3.2.3).
    let text = String::from_utf8_lossy(data);
    for (mech, dummy) in [("OAUTHBEARER", &b"\x01"[..]), ("XOAUTH2", &b""[..])] {
        let expect = if text.trim() == "*" {
            Answer::Cancelled
        } else {
            match base64::engine::general_purpose::STANDARD.decode(text.trim()) {
                Err(_) => Answer::Undecodable,
                Ok(d) if d == dummy => Answer::Dummy,
                Ok(_) => Answer::Unexpected,
            }
        };
        assert_eq!(classify(mech, &text), expect);
    }

    // The error result (section 3.2.2) stays JSON with exactly the given
    // values, whatever the configured scope and URL contain.
    let challenge = ErrorChallenge::new(Some(&a), Some(&b));
    let raw = base64::engine::general_purpose::STANDARD
        .decode(challenge.base64())
        .expect("challenge is base64");
    let json: serde_json::Value = serde_json::from_slice(&raw).expect("challenge is JSON");
    let expect = serde_json::json!({
        "status": "invalid_token",
        "scope": b,
        "openid-configuration": a,
    });
    assert_eq!(json, expect);
});
