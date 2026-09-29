//! A backend verdict versus a backend outage, per protocol.
//!
//! A rejection (IMAP `NO`, SMTP 5xx, ManageSieve `NO`) is a failed login:
//! `backend_reject` in the log and a failed attempt in the metrics. A
//! temporary failure (IMAP `NO [UNAVAILABLE]`, SMTP 4xx, ManageSieve
//! `NO (TRYLATER)`) or an unreachable backend is an outage: the client is told
//! to retry later, no authresult line is written (nothing for CrowdSec to ban
//! on) and only `mail_auth_proxy_backend_errors_total` counts it.

mod common;
use common::*;

fn rejected_token(kind: Kind) -> &'static str {
    match kind {
        Kind::Imap => "a NO [AUTHENTICATIONFAILED] backend rejected token",
        Kind::Smtp => "535 5.7.8 Authentication credentials invalid",
        Kind::Sieve => "NO \"Authentication failed\"",
    }
}

fn rejected_password(kind: Kind) -> &'static str {
    match kind {
        Kind::Imap => "a NO [AUTHENTICATIONFAILED] backend rejected credentials",
        _ => rejected_token(kind),
    }
}

fn retry_later(kind: Kind) -> &'static str {
    match kind {
        Kind::Imap => "a NO [UNAVAILABLE] Backend temporarily unavailable",
        Kind::Smtp => "454 4.7.0 Temporary authentication failure",
        Kind::Sieve => "NO (TRYLATER) \"Service temporarily unavailable\"",
    }
}

fn backend_errors(kind: Kind) -> String {
    format!(
        "mail_auth_proxy_backend_errors_total{{proto=\"{}\"}}",
        kind.label()
    )
}

/// Sum of every auth_attempts series of this protocol.
async fn attempts(h: &Harness, kind: Kind) -> u64 {
    let prefix = format!(
        "mail_auth_proxy_auth_attempts_total{{proto=\"{}\"",
        kind.label()
    );
    h.proxy
        .metrics()
        .await
        .iter()
        .filter(|(k, _)| k.starts_with(&prefix))
        .map(|(_, v)| v)
        .sum()
}

/// A rejected credential: reply, one backend_reject record, one failed attempt.
async fn expect_reject(h: &Harness, kind: Kind, password: bool) {
    let before = h.proxy.authresults().len();
    let tries = attempts(h, kind).await;
    let errors = h.proxy.metric(&backend_errors(kind)).await;
    let rejects = format!(
        "mail_auth_proxy_auth_refusals_total{{proto=\"{}\",reason=\"backend_reject\"}}",
        kind.label()
    );
    let rejected = h.proxy.metric(&rejects).await;
    let (src, sni, mech, ir, user) = if password {
        let user = "reject-pw@example.test";
        (
            Src::Internal,
            Sni::Internal,
            "PLAIN",
            plain(user, "wrong"),
            user,
        )
    } else {
        let user = "reject-oauth@example.test";
        let ir = xoauth2(user, &h.idp.token(user));
        (Src::External, Sni::Public, "XOAUTH2", ir, user)
    };
    let (mut c, reply) = h.auth(kind, src, sni, mech, &ir).await;
    let expected = if password {
        rejected_password(kind)
    } else {
        rejected_token(kind)
    };
    assert_eq!(reply, expected, "{kind:?}");
    c.expect_end(kind).await;

    let ars = h.proxy.wait_authresults(before + 1).await;
    assert_eq!(ars.len(), before + 1);
    let ar = &ars[before];
    assert_eq!(
        (
            ar.result.as_str(),
            ar.reason.as_str(),
            ar.user.as_str(),
            ar.mech.as_str()
        ),
        ("fail", "backend_reject", user, mech),
        "{kind:?}"
    );
    assert_eq!(ar.scope, src.scope());
    if password {
        assert_eq!(ar.pwfp.len(), 16, "{kind:?}: password fingerprint");
    } else {
        assert_eq!(ar.pwfp, "");
    }
    assert_eq!(attempts(h, kind).await, tries + 1);
    assert_eq!(h.proxy.metric(&rejects).await, rejected + 1);
    assert_eq!(h.proxy.metric(&backend_errors(kind)).await, errors);
    // The backend did see (and judge) the credential.
    let s = h.backend(kind).sessions().pop().unwrap();
    assert_eq!(s.login.as_deref(), Some(user));
    if !password && kind != Kind::Sieve {
        // The XOAUTH2 error challenge was answered with an empty response,
        // not cancelled.
        assert_eq!(s.error_answer.as_deref(), Some(""), "{kind:?}");
    }
}

/// The backend's temporary-failure reply, as the journal quotes it.
fn temporary_failure(kind: Kind) -> &'static str {
    match kind {
        Kind::Imap => "NO [UNAVAILABLE] Temporary authentication failure.",
        Kind::Smtp => "without a verdict: 454",
        Kind::Sieve => "NO (TRYLATER) \"Temporary authentication failure.\"",
    }
}

/// An outage: retry-later reply, no authresult line, backend_errors + 1, and
/// a WARN session-end line that keeps the `cause`.
async fn expect_outage(h: &Harness, kind: Kind, mut c: Client, cmd: &str, cause: &str) {
    let before = h.proxy.authresults().len();
    let ended = h.sessions_ended(kind);
    let tries = attempts(h, kind).await;
    let errors = h.proxy.metric(&backend_errors(kind)).await;
    c.send(cmd).await;
    assert_eq!(c.line().await, retry_later(kind), "{kind:?}");
    c.expect_end(kind).await;
    // The session-ended line is written after any authresult would have been.
    let line = h.wait_session_ended(kind, ended + 1).await;
    // The journal keeps the whole chain: the outage and its cause.
    assert!(line.contains(" WARN "), "{line}");
    assert!(line.contains(" error=backend unavailable: "), "{line}");
    assert!(line.contains(cause), "{kind:?}: {cause:?} missing: {line}");
    assert_eq!(
        h.proxy.authresults().len(),
        before,
        "{kind:?}: no authresult for an outage"
    );
    assert_eq!(
        attempts(h, kind).await,
        tries,
        "{kind:?}: not a failed login"
    );
    assert_eq!(h.proxy.metric(&backend_errors(kind)).await, errors + 1);
}

async fn outcomes(kind: Kind) {
    let h = Harness::start().await;

    // Rejections.
    expect_reject(&h, kind, false).await;
    expect_reject(&h, kind, true).await;

    // The backend answers "temporarily unavailable".
    let token = h.idp.token("unavail-oauth@example.test");
    let c = h.ready(kind, Src::External, Sni::Public).await;
    expect_outage(
        &h,
        kind,
        c,
        &auth_command(
            kind,
            "XOAUTH2",
            &xoauth2("unavail-oauth@example.test", &token),
        ),
        temporary_failure(kind),
    )
    .await;
    let c = h.ready(kind, Src::Internal, Sni::Internal).await;
    expect_outage(
        &h,
        kind,
        c,
        &auth_command(kind, "PLAIN", &plain("unavail-pw@example.test", "pw")),
        temporary_failure(kind),
    )
    .await;

    // The backend port is closed. The session is opened first so that the
    // ManageSieve capability probe has already happened.
    let c = h.ready(kind, Src::External, Sni::Public).await;
    h.backend(kind).shutdown().await;
    let token = h.idp.token("alice@example.test");
    expect_outage(
        &h,
        kind,
        c,
        &auth_command(kind, "XOAUTH2", &xoauth2("alice@example.test", &token)),
        "Connection refused",
    )
    .await;
    let c = h.ready(kind, Src::Internal, Sni::Internal).await;
    expect_outage(
        &h,
        kind,
        c,
        &auth_command(kind, "PLAIN", &plain("bob@example.test", "pw")),
        "Connection refused",
    )
    .await;
    // At the default level only the outages end with a session line; the two
    // rejections are recorded once, by their authresult line.
    assert_eq!(h.sessions_ended(kind), 4, "{kind:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn imap_reject_vs_outage() {
    outcomes(Kind::Imap).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn smtp_reject_vs_outage() {
    outcomes(Kind::Smtp).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sieve_reject_vs_outage() {
    outcomes(Kind::Sieve).await;
}

/// ManageSieve with a cold capability cache and the backend down: the
/// greeting has no SIEVE line and the client gets BYE right after STARTTLS.
/// The failed probe is one backend error (the second, post-TLS, is not
/// attempted within the retry spacing); no pre-auth abort is counted, and
/// no authresult is written.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sieve_capability_probe_failure() {
    let h = Harness::start().await;
    h.sieve_be.shutdown().await;
    let mut c = Client::connect(h.proxy.sieve, Src::External).await;
    let greeting = c.sieve_response().await;
    assert!(!greeting.iter().any(|l| l.starts_with("\"SIEVE\"")));
    c.send("STARTTLS").await;
    assert_eq!(c.line().await, "OK \"Begin TLS negotiation now\"");
    c.tls(&h.pki, Sni::Public).await;
    assert_eq!(c.line().await, "BYE \"Service temporarily unavailable\"");
    c.expect_closed().await;
    h.wait_session_ended(Kind::Sieve, 1).await;
    assert!(h.proxy.authresults().is_empty());
    let m = h.proxy.metrics().await;
    assert_eq!(
        m["mail_auth_proxy_backend_errors_total{proto=\"sieve\"}"],
        1
    );
    assert_eq!(
        m["mail_auth_proxy_preauth_aborts_total{proto=\"sieve\",scope=\"external\"}"],
        0
    );
}

/// A bearer token of 2 KiB or more fits the backend: the SMTP response goes
/// after `334`, not on the AUTH line that Postfix limits to 2048 octets.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn smtp_long_token_sent_after_challenge() {
    let h = Harness::start().await;
    let token = h.idp.mint(serde_json::json!({
        "email": "long@example.test",
        "pad": "x".repeat(2500),
    }));
    assert!(token.len() >= 2048, "{}", token.len());
    let (mut c, reply) = h
        .auth(
            Kind::Smtp,
            Src::External,
            Sni::Public,
            "XOAUTH2",
            &xoauth2("long@example.test", &token),
        )
        .await;
    assert_eq!(reply, "235 2.7.0 Authentication successful");
    c.send("NOOP").await;
    assert_eq!(c.line().await, "ECHO NOOP");
    let s = h.smtp_be.sessions().pop().unwrap();
    assert_eq!(s.login.as_deref(), Some("long@example.test"));
    assert_eq!(s.secret.as_deref(), Some(token.as_str()));
    let ars = h.proxy.wait_authresults(1).await;
    assert_eq!(ars[0].reason, "ok");
}

/// SMTP 50x to the backend AUTH exchange (syntax class: command too long,
/// malformed response) is no verdict on a token: an outage.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn smtp_backend_syntax_error_on_token_is_outage() {
    let h = Harness::start().await;
    let token = h.idp.token("garbled-oauth@example.test");
    let c = h.ready(Kind::Smtp, Src::External, Sni::Public).await;
    expect_outage(
        &h,
        Kind::Smtp,
        c,
        &auth_command(
            Kind::Smtp,
            "XOAUTH2",
            &xoauth2("garbled-oauth@example.test", &token),
        ),
        "without a verdict: 501",
    )
    .await;
}

/// A protocol error (SMTP 50x, IMAP BAD) answering a password is a
/// rejection: the client chose the bytes, and an instant retry-later for
/// accounts that pass the gate would tell them from refused ones.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn backend_syntax_error_on_password_is_rejection() {
    let h = Harness::start().await;
    let user = "garbled-pw@example.test";
    for (n, kind) in [Kind::Imap, Kind::Smtp].into_iter().enumerate() {
        let errors = h.proxy.metric(&backend_errors(kind)).await;
        let (mut c, reply) = h
            .auth(
                kind,
                Src::Internal,
                Sni::Internal,
                "PLAIN",
                &plain(user, "pw"),
            )
            .await;
        assert_eq!(reply, rejected_password(kind), "{kind:?}");
        c.expect_end(kind).await;
        let ar = &h.proxy.wait_authresults(n + 1).await[n];
        assert_eq!(
            (ar.reason.as_str(), ar.user.as_str()),
            ("backend_reject", user),
            "{kind:?}"
        );
        assert_eq!(h.proxy.metric(&backend_errors(kind)).await, errors);
    }
}

/// A reply other than `334` to the bare SMTP `AUTH <mech>` line comes before
/// any credential: backend configuration (AUTH not enabled, unknown
/// mechanism), an outage on both paths.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn smtp_auth_line_refused_is_outage() {
    let h = Harness::start().await;
    for (reply, code) in [
        ("503 5.5.1 Error: authentication not enabled", "503"),
        ("504 5.5.4 Unrecognized authentication type", "504"),
    ] {
        *h.smtp_be.auth_reply.lock().unwrap() = Some(reply.into());
        let cause = format!("before the credential: {code}");
        let token = h.idp.token(EMAIL);
        let c = h.ready(Kind::Smtp, Src::External, Sni::Public).await;
        expect_outage(
            &h,
            Kind::Smtp,
            c,
            &auth_command(Kind::Smtp, "XOAUTH2", &xoauth2(EMAIL, &token)),
            &cause,
        )
        .await;
        let c = h.ready(Kind::Smtp, Src::Internal, Sni::Internal).await;
        expect_outage(
            &h,
            Kind::Smtp,
            c,
            &auth_command(Kind::Smtp, "PLAIN", &plain("bob@example.test", "pw")),
            &cause,
        )
        .await;
    }
}

/// A backend that advertises XCLIENT to a proxy with `submission.xclient =
/// false` is misconfigured: after the relay starts, the client could send its
/// own `XCLIENT LOGIN=<other> ADDR=…` on the proxy's authorization. Every
/// login is an outage, on both paths, and no credential reaches the backend.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn smtp_xclient_offered_but_disabled_is_outage() {
    let h = Harness::start_with(Opts {
        smtp_xclient: false,
        ..Opts::default()
    })
    .await;
    let cause = "submission.xclient = false";
    let token = h.idp.token(EMAIL);
    let c = h.ready(Kind::Smtp, Src::External, Sni::Public).await;
    expect_outage(
        &h,
        Kind::Smtp,
        c,
        &auth_command(Kind::Smtp, "XOAUTH2", &xoauth2(EMAIL, &token)),
        cause,
    )
    .await;
    let c = h.ready(Kind::Smtp, Src::Internal, Sni::Internal).await;
    expect_outage(
        &h,
        Kind::Smtp,
        c,
        &auth_command(Kind::Smtp, "PLAIN", &plain("bob@example.test", "pw")),
        cause,
    )
    .await;
    assert!(h.proxy.log_contains("smtpd_authorized_xclient_hosts"));
    let sessions = h.smtp_be.sessions();
    assert_eq!(sessions.len(), 2);
    for s in sessions {
        assert_eq!(s.xclient, None);
        assert_eq!(s.login, None, "no credential sent");
    }
}

/// With `submission.xclient = true`: a backend that still advertises XCLIENT
/// in the EHLO after the proxy's own XCLIENT (the client's address is itself
/// authorized) would let the client send its own XCLIENT after the splice.
/// An outage on both paths; the credential is never sent. The default mock
/// stops advertising it, and a login goes through.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn smtp_xclient_still_offered_after_xclient_is_outage() {
    let h = Harness::start().await;
    let (_c, reply) = h
        .auth(
            Kind::Smtp,
            Src::External,
            Sni::Public,
            "XOAUTH2",
            &xoauth2(EMAIL, &h.idp.token(EMAIL)),
        )
        .await;
    assert_eq!(reply, "235 2.7.0 Authentication successful");
    h.smtp_be
        .xclient_sticky
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let cause = "still advertises XCLIENT after XCLIENT";
    let token = h.idp.token(EMAIL);
    let c = h.ready(Kind::Smtp, Src::External, Sni::Public).await;
    expect_outage(
        &h,
        Kind::Smtp,
        c,
        &auth_command(Kind::Smtp, "XOAUTH2", &xoauth2(EMAIL, &token)),
        cause,
    )
    .await;
    let c = h.ready(Kind::Smtp, Src::Internal, Sni::Internal).await;
    expect_outage(
        &h,
        Kind::Smtp,
        c,
        &auth_command(Kind::Smtp, "PLAIN", &plain("bob@example.test", "pw")),
        cause,
    )
    .await;
    let sessions = h.smtp_be.sessions();
    assert_eq!(sessions.len(), 3);
    for s in &sessions[1..] {
        assert!(s.xclient.is_some(), "the proxy's own XCLIENT was sent");
        assert_eq!(s.login, None, "no credential sent");
    }
}

/// IMAP `NO` with a temporary RFC 5530 code other than `[UNAVAILABLE]`
/// (`[INUSE]`, `[SERVERBUG]`, `[LIMIT]`) is no verdict on the credential: an
/// outage on both paths.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn imap_temporary_codes_are_outages() {
    let h = Harness::start().await;
    for code in ["[INUSE]", "[SERVERBUG]", "[LIMIT]"] {
        let reply = format!("P1 NO {code} Try again later.");
        *h.imap_be.auth_reply.lock().unwrap() = Some(reply.clone());
        let token = h.idp.token(EMAIL);
        let c = h.ready(Kind::Imap, Src::External, Sni::Public).await;
        expect_outage(
            &h,
            Kind::Imap,
            c,
            &auth_command(Kind::Imap, "XOAUTH2", &xoauth2(EMAIL, &token)),
            &reply,
        )
        .await;
        let c = h.ready(Kind::Imap, Src::Internal, Sni::Internal).await;
        expect_outage(
            &h,
            Kind::Imap,
            c,
            &auth_command(Kind::Imap, "PLAIN", &plain("bob@example.test", "pw")),
            &reply,
        )
        .await;
    }
}

/// Dovecot's untagged BYE (mail_max_userip_connections, shutdown) in answer
/// to a password is an outage, not a rejection: no failed attempt, and the
/// throttle is not charged.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn imap_bye_on_password_is_outage() {
    let h = Harness::start_with(Opts {
        legacy: Some(
            "[legacy]\nthrottle = { failures = 1, window_secs = 3600 }\n[[legacy.rules]]\nname = \"all\"\nnetworks = [\"127.0.0.0/8\"]\n".into(),
        ),
        ..Opts::default()
    })
    .await;
    *h.imap_be.auth_reply.lock().unwrap() = Some(
        "* BYE Maximum number of connections from user+IP exceeded (mail_max_userip_connections=10)"
            .into(),
    );
    let c = h.ready(Kind::Imap, Src::Internal, Sni::Internal).await;
    expect_outage(
        &h,
        Kind::Imap,
        c,
        &auth_command(Kind::Imap, "PLAIN", &plain("bob@example.test", "pw")),
        "eof",
    )
    .await;
    // Not throttled: the next login of the account goes through.
    *h.imap_be.auth_reply.lock().unwrap() = None;
    let (_c, reply) = h
        .auth(
            Kind::Imap,
            Src::Internal,
            Sni::Internal,
            "PLAIN",
            &plain("bob@example.test", "pw"),
        )
        .await;
    assert_eq!(reply, "a OK [CAPABILITY IMAP4rev1 IDLE MOVE] Logged in");
}
