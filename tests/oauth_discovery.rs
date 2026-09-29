//! RFC 7628 IdP discovery. A rejected token is answered with the JSON error
//! result as a SASL challenge (section 3.2.2); the client completes it with
//! the dummy response or an abort (section 3.2.3) and only then gets the
//! final failure. The result is the same for every rejected token. Tokens
//! that validate and outages keep their direct answers, and each attempt
//! still writes exactly one `authresult` line.

mod common;
use common::*;
use serde_json::json;
use std::time::{Duration, Instant};

const WELL_KNOWN: &str = "https://idp.test/realms/mail/.well-known/openid-configuration";
const DISCOVERY: &str = "openid_configuration_url = \"https://idp.test/realms/mail/.well-known/openid-configuration\"\nscope = \"openid\"";
const CLIENT_USER: &str = "mallory@evil.test";
const MECHS: [&str; 2] = ["XOAUTH2", "OAUTHBEARER"];

fn ir(mech: &str, token: &str) -> String {
    match mech {
        "XOAUTH2" => xoauth2(CLIENT_USER, token),
        _ => oauthbearer(CLIENT_USER, token),
    }
}

/// The final failure after the dummy response.
fn failed(kind: Kind) -> &'static str {
    match kind {
        Kind::Imap => "a NO [AUTHENTICATIONFAILED] Authentication failed",
        Kind::Smtp => "535 5.7.8 Authentication credentials invalid",
        Kind::Sieve => "NO \"Authentication failed\"",
    }
}

/// The final reply to an abort or an undecodable answer.
fn aborted(kind: Kind) -> &'static str {
    match kind {
        Kind::Imap => "a BAD AUTHENTICATE failed: invalid or cancelled response",
        Kind::Smtp => "501 5.5.2 Invalid or cancelled authentication response",
        Kind::Sieve => failed(kind),
    }
}

async fn harness(opts: Opts) -> Harness {
    Harness::start_with(Opts {
        issuer_extra: DISCOVERY,
        rust_log: "info,mail_auth_proxy=debug",
        ..opts
    })
    .await
}

/// The `bad_token` record of the `n`-th attempt, which must also be the last.
async fn expect_bad_token(h: &Harness, kind: Kind, mech: &str, n: usize) {
    let ars = h.proxy.wait_authresults(n).await;
    assert_eq!(ars.len(), n, "{kind:?} {mech}: one authresult per attempt");
    assert_eq!(
        ars[n - 1],
        AuthResult {
            level: "WARN".into(),
            result: "fail".into(),
            proto: kind.label().into(),
            scope: "external".into(),
            mech: mech.into(),
            user: CLIENT_USER.into(),
            peer: "127.0.0.2".into(),
            reason: "bad_token".into(),
            pwfp: String::new(),
        },
        "{kind:?} {mech}"
    );
}

/// Every protocol and mechanism: the error result names the configured IdP
/// and scope, the dummy response gets the usual failure, and the record,
/// metrics and backend are as without the extra round trip.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn error_result_names_the_idp_then_fails() {
    let h = harness(Opts::default()).await;
    let bad = h.idp.mint(json!({"aud": "roundcube"}));
    let mut n = 0;
    for kind in Kind::ALL {
        for (ended, mech) in MECHS.into_iter().enumerate() {
            let (mut c, challenge) = h
                .auth(kind, Src::External, Sni::Public, mech, &ir(mech, &bad))
                .await;
            // Byte for byte on the wire, then as JSON.
            assert_eq!(
                String::from_utf8(unb64(challenge_data(kind, &challenge))).unwrap(),
                format!(
                    r#"{{"status":"invalid_token","scope":"openid","openid-configuration":"{WELL_KNOWN}"}}"#
                ),
                "{kind:?} {mech}"
            );
            assert_eq!(
                error_result(kind, &challenge),
                json!({"status": "invalid_token", "scope": "openid", "openid-configuration": WELL_KNOWN})
            );
            c.send(&sasl_response(kind, dummy_response(mech))).await;
            assert_eq!(c.line().await, failed(kind), "{kind:?} {mech}");
            c.expect_closed().await;
            n += 1;
            expect_bad_token(&h, kind, mech, n).await;
            let line = h.wait_session_ended(kind, ended + 1).await;
            assert!(line.contains(" DEBUG "), "{line}");
            assert!(!line.contains("error challenge"), "{line}");
        }
        let proto = kind.label();
        for mech in ["xoauth2", "oauthbearer"] {
            assert_eq!(
                h.proxy
                    .metric(&format!("mail_auth_proxy_auth_attempts_total{{proto=\"{proto}\",scope=\"external\",mechanism=\"{mech}\",result=\"fail\"}}"))
                    .await,
                1,
                "{proto} {mech}"
            );
        }
        assert_eq!(
            h.proxy
                .metric(&format!(
                    "mail_auth_proxy_preauth_aborts_total{{proto=\"{proto}\",scope=\"external\"}}"
                ))
                .await,
            0,
            "{proto}"
        );
        assert!(h.backend(kind).sessions().is_empty(), "{proto}");
    }
}

/// No oracle: whatever made the token fail (and whatever issuer it claims),
/// the challenge is the same bytes on every protocol.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn error_result_is_the_same_for_every_rejection() {
    let h = harness(Opts::default()).await;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let evil = "https://evil.example/realms/mail";
    let tokens = [
        h.idp.mint(json!({"aud": "roundcube"})),
        h.idp.mint(json!({"exp": now - 3600, "iat": now - 7200})),
        h.idp.mint(json!({"iss": evil})),
        h.idp.mint(json!({"email_verified": false})),
        h.idp.mint_with_kid("rotated-key", json!({})),
        "not-a-jwt".to_string(),
    ];
    let mut seen = std::collections::HashSet::new();
    for kind in Kind::ALL {
        for token in &tokens {
            let (_c, challenge) = h
                .auth(
                    kind,
                    Src::External,
                    Sni::Public,
                    "XOAUTH2",
                    &ir("XOAUTH2", token),
                )
                .await;
            let data = challenge_data(kind, &challenge).to_string();
            assert!(!String::from_utf8(unb64(&data)).unwrap().contains("evil"));
            seen.insert(data);
        }
    }
    assert_eq!(seen.len(), 1, "{seen:?}");
    let n = Kind::ALL.len() * tokens.len();
    let ars = h.proxy.wait_authresults(n).await;
    assert!(ars.iter().all(|a| a.reason == "bad_token"), "{ars:?}");
}

/// Answers other than the dummy: the other mechanism's dummy (an empty line
/// to OAUTHBEARER) still ends in the usual failure; an abort or undecodable
/// answer (a resent AUTHENTICATE line) in the protocol's abort reply. The
/// record stays one `bad_token`, and the session end names the answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn answers_other_than_the_dummy() {
    let h = harness(Opts::default()).await;
    let bad = h.idp.mint(json!({"aud": "roundcube"}));
    let mut n = 0;
    for kind in Kind::ALL {
        let mut ended = 0;
        for mech in MECHS {
            let other_dummy = dummy_response(if mech == "XOAUTH2" {
                "OAUTHBEARER"
            } else {
                "XOAUTH2"
            });
            let cases = [
                (
                    sasl_response(kind, other_dummy),
                    failed(kind),
                    "was not the dummy",
                ),
                (sasl_response(kind, "*"), aborted(kind), "cancelled"),
                (sasl_response(kind, "!!"), aborted(kind), "was not base64"),
                (
                    auth_command(kind, mech, &ir(mech, &bad)),
                    aborted(kind),
                    "was not base64",
                ),
            ];
            for (answer, reply, note) in cases {
                let (mut c, challenge) = h
                    .auth(kind, Src::External, Sni::Public, mech, &ir(mech, &bad))
                    .await;
                error_result(kind, &challenge);
                c.send(&answer).await;
                assert_eq!(c.line().await, reply, "{kind:?} {mech} {answer:?}");
                c.expect_closed().await;
                n += 1;
                expect_bad_token(&h, kind, mech, n).await;
                ended += 1;
                let line = h.wait_session_ended(kind, ended).await;
                assert!(line.contains(note), "{kind:?} {mech} {answer:?}: {line}");
                assert!(line.contains("error=token rejected: "), "{line}");
            }
        }
    }
    // A ManageSieve literal is a string too.
    let (mut c, challenge) = h
        .auth(
            Kind::Sieve,
            Src::External,
            Sni::Public,
            "OAUTHBEARER",
            &ir("OAUTHBEARER", &bad),
        )
        .await;
    error_result(Kind::Sieve, &challenge);
    c.send_raw(b"{4+}\r\nAQ==\r\n").await;
    assert_eq!(c.line().await, failed(Kind::Sieve));
    c.expect_closed().await;
    expect_bad_token(&h, Kind::Sieve, "OAUTHBEARER", n + 1).await;
    assert!(!h.proxy.log_contains("panicked"));
}

/// An answer over the line limit ends the exchange like a missing answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn overlong_answer_hits_the_line_limit() {
    let h = harness(Opts::default()).await;
    let bad = h.idp.mint(json!({"aud": "roundcube"}));
    for (i, kind) in Kind::ALL.into_iter().enumerate() {
        let (mut c, challenge) = h
            .auth(
                kind,
                Src::External,
                Sni::Public,
                "XOAUTH2",
                &ir("XOAUTH2", &bad),
            )
            .await;
        error_result(kind, &challenge);
        c.send(&"A".repeat(20_000)).await;
        // The proxy closes with the rest of the line unread, so its reply
        // may be lost to the reset; the session end is what counts.
        let _ = c.read_to_close().await;
        let line = h.wait_session_ended(kind, 1).await;
        assert!(
            line.contains("no answer to the error challenge: line too long"),
            "{line}"
        );
        expect_bad_token(&h, kind, "XOAUTH2", i + 1).await;
    }
}

/// A client that closes at the challenge: the session ends without a panic
/// or a second record.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_closing_at_the_challenge() {
    let h = harness(Opts::default()).await;
    let bad = h.idp.mint(json!({"aud": "roundcube"}));
    for (i, kind) in Kind::ALL.into_iter().enumerate() {
        let (c, challenge) = h
            .auth(
                kind,
                Src::External,
                Sni::Public,
                "OAUTHBEARER",
                &ir("OAUTHBEARER", &bad),
            )
            .await;
        error_result(kind, &challenge);
        drop(c);
        let line = h.wait_session_ended(kind, 1).await;
        // Dropped without a TLS close_notify: an unexpected EOF.
        assert!(
            line.contains("no answer to the error challenge: "),
            "{line}"
        );
        assert!(line.contains(" DEBUG "), "{line}");
        expect_bad_token(&h, kind, "OAUTHBEARER", i + 1).await;
    }
    assert!(!h.proxy.log_contains("panicked"));
}

/// A client that never answers is cut off by the pre-auth budget, which
/// covers the extra round trip: the usual failure, then the close.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn silent_client_is_cut_off_by_the_preauth_budget() {
    let h = harness(Opts {
        preauth_secs: 2,
        idle_secs: 30,
        ..Opts::default()
    })
    .await;
    let bad = h.idp.mint(json!({"aud": "roundcube"}));
    for (i, kind) in Kind::ALL.into_iter().enumerate() {
        let started = Instant::now();
        let (mut c, challenge) = h
            .auth(
                kind,
                Src::External,
                Sni::Public,
                "XOAUTH2",
                &ir("XOAUTH2", &bad),
            )
            .await;
        error_result(kind, &challenge);
        assert_eq!(c.line().await, failed(kind), "{kind:?}");
        c.expect_closed().await;
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "{:?}",
            started.elapsed()
        );
        let line = h.wait_session_ended(kind, 1).await;
        assert!(line.contains("pre-auth budget of 2s used up"), "{line}");
        expect_bad_token(&h, kind, "XOAUTH2", i + 1).await;
    }
}

/// The idle timeout bounds the read of the answer as well.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn silent_client_is_cut_off_by_the_idle_timeout() {
    let h = harness(Opts {
        idle_secs: 1,
        ..Opts::default()
    })
    .await;
    let bad = h.idp.mint(json!({"aud": "roundcube"}));
    for (i, kind) in Kind::ALL.into_iter().enumerate() {
        let (mut c, challenge) = h
            .auth(
                kind,
                Src::External,
                Sni::Public,
                "OAUTHBEARER",
                &ir("OAUTHBEARER", &bad),
            )
            .await;
        error_result(kind, &challenge);
        assert_eq!(c.line().await, failed(kind), "{kind:?}");
        c.expect_closed().await;
        let line = h.wait_session_ended(kind, 1).await;
        assert!(line.contains("read timed out after 1s"), "{line}");
        expect_bad_token(&h, kind, "OAUTHBEARER", i + 1).await;
    }
}

/// A valid token gets no challenge: the first reply is the success.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn valid_token_gets_no_challenge() {
    let h = harness(Opts::default()).await;
    let token = h.idp.token(EMAIL);
    let mut n = 0;
    for kind in Kind::ALL {
        for mech in MECHS {
            let ir = match mech {
                "XOAUTH2" => xoauth2(EMAIL, &token),
                _ => oauthbearer(EMAIL, &token),
            };
            let (_c, reply) = h.auth(kind, Src::External, Sni::Public, mech, &ir).await;
            let ok = match kind {
                Kind::Imap => reply.starts_with("a OK"),
                Kind::Smtp => reply == "235 2.7.0 Authentication successful",
                Kind::Sieve => reply.starts_with("OK"),
            };
            assert!(ok, "{kind:?} {mech}: {reply}");
            n += 1;
            let ars = h.proxy.wait_authresults(n).await;
            assert_eq!(
                (ars[n - 1].reason.as_str(), ars[n - 1].user.as_str()),
                ("ok", EMAIL)
            );
        }
    }
}

/// Keys that could not be refreshed are no verdict on the token: still the
/// direct retry-later, no challenge and no record.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stale_keys_get_retry_later_without_challenge() {
    let h = harness(Opts::default()).await;
    h.idp.stop().await;
    let token = h.idp.mint_with_kid("rotated-key", json!({}));
    for kind in Kind::ALL {
        let (mut c, reply) = h
            .auth(
                kind,
                Src::External,
                Sni::Public,
                "OAUTHBEARER",
                &ir("OAUTHBEARER", &token),
            )
            .await;
        let want = match kind {
            Kind::Imap => "a NO [UNAVAILABLE] Backend temporarily unavailable",
            Kind::Smtp => "454 4.7.0 Temporary authentication failure",
            Kind::Sieve => "NO (TRYLATER) \"Service temporarily unavailable\"",
        };
        assert_eq!(reply, want, "{kind:?}");
        c.expect_closed().await;
        h.wait_session_ended(kind, 1).await;
    }
    assert!(h.proxy.authresults().is_empty());
}
