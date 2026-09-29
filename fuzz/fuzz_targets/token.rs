//! Bearer tokens before the signature is trusted: the unverified `iss`
//! lookup, header and payload decoding in `Validator::validate`, and the
//! claim checks that follow a valid signature.
#![no_main]

use libfuzzer_sys::fuzz_target;
use mail_auth_proxy::fuzz_api::*;
use std::sync::OnceLock;

/// A P-256 public key whose private key was discarded: no token can carry a
/// valid signature, so every one must be refused.
const JWKS: &str = r#"{"keys":[{"kty":"EC","crv":"P-256","use":"sig","alg":"ES256","kid":"fuzz",
  "x":"0aRJ0ZO6QvgaOCSWKLGDXXaqdoG1RjgW6PR48s7o2rc","y":"RSjare-kpDymOFvJ_QiJN09X3ytCsD9DEdx3CHm2u_Y"}]}"#;

fn validator() -> &'static Validator {
    static V: OnceLock<Validator> = OnceLock::new();
    V.get_or_init(|| {
        token_validator(
            serde_json::from_str(JWKS).unwrap(),
            "https://sso.example.org",
            "mail",
        )
        .expect("validator")
    })
}

/// Error texts reach the journal: no control characters (forged log lines).
fn assert_loggable(e: &TokenError) {
    let s = e.to_string();
    assert!(!s.chars().any(char::is_control), "control char in {s:?}");
}

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let _ = token_unverified_iss(&text);
    match validator().validate(&text) {
        Ok(id) => panic!("token without a valid signature accepted: {id}"),
        Err(e) => assert_loggable(&e),
    }

    // The claims of a correctly signed token. The identity becomes the
    // backend login: one plain address, no whitespace or control characters.
    for typ in [None, Some("JWT"), Some("at+jwt")] {
        match token_check_claims(data, typ) {
            Some(Ok(id)) => {
                assert!(!id.is_empty() && id.len() <= 254);
                assert!(!id.chars().any(|c| c.is_whitespace() || c.is_control()));
                let parts: Vec<&str> = id.split('@').collect();
                assert!(
                    parts.len() == 2 && parts.iter().all(|p| !p.is_empty()),
                    "{id:?}"
                );
            }
            Some(Err(e)) => assert_loggable(&e),
            None => {}
        }
    }
});
