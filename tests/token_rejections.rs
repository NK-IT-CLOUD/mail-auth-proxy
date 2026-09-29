//! Tokens that fail local validation: every protocol answers with the
//! RFC 7628 error challenge and then its fixed failure text, logs `bad_token`
//! with the client's own SASL user, and never opens a backend session. The
//! precise reason goes only to the journal.

mod common;
use common::*;
use serde_json::json;

const CLIENT_USER: &str = "mallory@evil.test";

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// (case, token, detail in the `session ended` line)
fn cases(idp: &Idp) -> Vec<(&'static str, String, &'static str)> {
    vec![
        (
            "wrong aud",
            idp.mint(json!({"aud": "roundcube"})),
            "InvalidAudience",
        ),
        (
            "wrong iss",
            idp.mint(json!({"iss": "https://evil.test/realms/mail"})),
            "InvalidIssuer",
        ),
        // Beyond the 60 s leeway.
        (
            "expired",
            idp.mint(json!({"exp": now() - 3600, "iat": now() - 7200})),
            "ExpiredSignature",
        ),
        (
            "ID token",
            idp.mint(json!({"typ": "ID"})),
            "not an access token",
        ),
        (
            "email not verified",
            idp.mint(json!({"email_verified": false})),
            "email not verified",
        ),
        (
            "unknown kid",
            idp.mint_with_kid("rotated-key", json!({})),
            "unknown kid",
        ),
    ]
}

fn rejection(kind: Kind) -> &'static str {
    match kind {
        Kind::Imap => "a NO [AUTHENTICATIONFAILED] Authentication failed",
        Kind::Smtp => "535 5.7.8 Authentication credentials invalid",
        Kind::Sieve => "NO \"Authentication failed\"",
    }
}

async fn rejections(kind: Kind) {
    // A refusal's session end, with the precise reason, is logged at DEBUG.
    let h = Harness::start_with(Opts {
        rust_log: "info,mail_auth_proxy=debug",
        ..Opts::default()
    })
    .await;
    let proto = kind.label();
    assert_eq!(
        h.idp.fetches.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "one JWKS fetch at startup"
    );
    for (i, (case, token, detail)) in cases(&h.idp).into_iter().enumerate() {
        let fails = h
            .proxy
            .metric("mail_auth_proxy_token_validate_total{result=\"fail\"}")
            .await;
        let (mut c, result, reply) = h
            .auth_rejected(
                kind,
                Src::External,
                Sni::Public,
                "XOAUTH2",
                &xoauth2(CLIENT_USER, &token),
            )
            .await;
        // Without discovery settings the error result is the status alone.
        assert_eq!(
            result,
            json!({"status": "invalid_token"}),
            "{proto}: {case}"
        );
        assert_eq!(reply, rejection(kind), "{proto}: {case}");
        c.expect_end(kind).await;

        let ars = h.proxy.wait_authresults(i + 1).await;
        assert_eq!(ars.len(), i + 1, "{proto}: {case}");
        assert_eq!(
            ars[i],
            AuthResult {
                level: "WARN".into(),
                result: "fail".into(),
                proto: proto.into(),
                scope: "external".into(),
                mech: "XOAUTH2".into(),
                // The token was not trusted, so the user is what the client said.
                user: CLIENT_USER.into(),
                peer: "127.0.0.2".into(),
                reason: "bad_token".into(),
                pwfp: String::new(),
            },
            "{proto}: {case}"
        );
        let ended = h.wait_session_ended(kind, i + 1).await;
        assert!(ended.contains(detail), "{proto}: {case}: {ended}");
        assert!(ended.contains(" DEBUG "), "{proto}: {case}: {ended}");
        assert!(
            ended.contains("error=token rejected: ") && !ended.contains("rejected: token rejected"),
            "{proto}: {case}: {ended}"
        );
        assert_eq!(
            h.proxy
                .metric("mail_auth_proxy_token_validate_total{result=\"fail\"}")
                .await,
            fails + 1,
            "{proto}: {case}"
        );
    }
    // The unknown kid triggered exactly one JWKS refresh.
    assert_eq!(h.idp.fetches.load(std::sync::atomic::Ordering::SeqCst), 2);

    // A second unknown kid within 30 s does not fetch again; the last
    // refresh succeeded, so it is still a bad_token (a flood of random kids
    // stays visible to CrowdSec and is no backend error).
    let token = h.idp.mint_with_kid("another-key", json!({}));
    let (mut c, _, reply) = h
        .auth_rejected(
            kind,
            Src::External,
            Sni::Public,
            "XOAUTH2",
            &xoauth2(CLIENT_USER, &token),
        )
        .await;
    assert_eq!(reply, rejection(kind));
    c.expect_end(kind).await;
    h.wait_session_ended(kind, 7).await;
    assert_eq!(h.idp.fetches.load(std::sync::atomic::Ordering::SeqCst), 2);

    // None of this reached the backend.
    assert!(h.backend(kind).sessions().is_empty(), "{proto}");
    assert_eq!(
        h.proxy
            .metric(&format!(
                "mail_auth_proxy_auth_attempts_total{{proto=\"{proto}\",scope=\"external\",mechanism=\"xoauth2\",result=\"fail\"}}"
            ))
            .await,
        7
    );
    assert_eq!(
        h.proxy
            .metric(&format!(
                "mail_auth_proxy_auth_refusals_total{{proto=\"{proto}\",reason=\"bad_token\"}}"
            ))
            .await,
        7
    );
    assert_eq!(
        h.proxy
            .metric(&format!(
                "mail_auth_proxy_backend_errors_total{{proto=\"{proto}\"}}"
            ))
            .await,
        0
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn imap_token_rejections() {
    rejections(Kind::Imap).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn smtp_token_rejections() {
    rejections(Kind::Smtp).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sieve_token_rejections() {
    rejections(Kind::Sieve).await;
}

/// A token over 16384 bytes (reachable through a ManageSieve literal) is a
/// bad token without validation.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversize_token_is_bad_token() {
    let h = Harness::start().await;
    let token = h.idp.mint(json!({ "pad": "x".repeat(20_000) }));
    assert!(token.len() > 16384);
    let ir = xoauth2(EMAIL, &token);
    let (mut c, _, _) = h.sieve(Src::External, Sni::Public).await;
    c.send_raw(format!("AUTHENTICATE \"XOAUTH2\" {{{}+}}\r\n{ir}\r\n", ir.len()).as_bytes())
        .await;
    error_result(Kind::Sieve, &c.line().await);
    c.send("\"\"").await;
    assert_eq!(c.line().await, "NO \"Authentication failed\"");
    let ar = &h.proxy.wait_authresults(1).await[0];
    assert_eq!((ar.reason.as_str(), ar.user.as_str()), ("bad_token", EMAIL));
    assert!(h.sieve_be.sessions().is_empty());
    assert_eq!(
        h.proxy
            .metric("mail_auth_proxy_token_validate_total{result=\"fail\"}")
            .await,
        1
    );
}
