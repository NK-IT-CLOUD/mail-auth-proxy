//! Pre-auth limits: the per-IP cap on unauthenticated connections (shared by
//! all three listeners, released on login) and the total pre-auth budget.
//! Both close silently: no greeting, no 421, no BYE.

mod common;
use common::*;
use std::time::{Duration, Instant};

fn rejected(proto: &str) -> String {
    format!("mail_auth_proxy_connections_rejected_total{{proto=\"{proto}\"}}")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn max_preauth_per_ip() {
    let h = Harness::start_with(Opts {
        max_preauth_per_ip: 2,
        ..Opts::default()
    })
    .await;

    // Two unauthenticated IMAP sessions from 127.0.0.2 fill its quota.
    let (mut first, _) = h.imap(Src::External, Sni::Public).await;
    let (_second, _) = h.imap(Src::External, Sni::Public).await;

    // The third is closed at accept, before TLS.
    let mut third = Client::connect(h.proxy.imap, Src::External).await;
    assert!(third.try_tls(&h.pki, Sni::Public).await.is_err());
    assert_eq!(h.proxy.metric(&rejected("imap")).await, 1);

    // The quota is shared: SMTP and ManageSieve from the same IP get nothing,
    // not even a greeting.
    let mut smtp = Client::connect(h.proxy.smtp, Src::External).await;
    smtp.expect_closed().await;
    let mut sieve = Client::connect(h.proxy.sieve, Src::External).await;
    sieve.expect_closed().await;
    let m = h.proxy.metrics().await;
    assert_eq!(m[&rejected("smtp")], 1);
    assert_eq!(m[&rejected("sieve")], 1);
    // Rejected connections are not admitted connections.
    assert_eq!(m["mail_auth_proxy_connections_total{proto=\"imap\"}"], 2);
    assert_eq!(m["mail_auth_proxy_connections_total{proto=\"smtp\"}"], 0);

    // Another source is unaffected.
    let (_internal, greeting) = h.imap(Src::Internal, Sni::Public).await;
    assert!(greeting.starts_with("* OK "));

    // A login gives the slot back while the session stays open.
    let token = h.idp.token(EMAIL);
    first
        .send(&format!(
            "a AUTHENTICATE XOAUTH2 {}",
            xoauth2(EMAIL, &token)
        ))
        .await;
    assert_eq!(
        first.line().await,
        "a OK [CAPABILITY IMAP4rev1 IDLE MOVE] Logged in"
    );
    let (_fourth, greeting) = h.imap(Src::External, Sni::Public).await;
    assert!(greeting.starts_with("* OK "));
    assert_eq!(h.proxy.metric(&rejected("imap")).await, 1);

    // No authresult for the rejected connections, only the one login.
    let ars = h.proxy.wait_authresults(1).await;
    assert_eq!(ars.len(), 1);
    assert_eq!(ars[0].reason, "ok");
}

/// Run `closed` (which ends when the proxy closes) and check it took about
/// the 1 s budget.
async fn closed_after_budget(closed: impl std::future::Future<Output = ()>) {
    let t = Instant::now();
    closed.await;
    let e = t.elapsed();
    assert!(
        e >= Duration::from_millis(900) && e < Duration::from_secs(5),
        "closed after {e:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn preauth_budget_closes_silent_clients() {
    let h = Harness::start_with(Opts {
        preauth_secs: 1,
        idle_secs: 30,
        ..Opts::default()
    })
    .await;
    let h = &h;

    // Each client stays silent (or drips) and must be closed after ~1 s.
    let imap_after_greeting = async {
        let (mut c, _) = h.imap(Src::External, Sni::Public).await;
        c.expect_closed().await;
    };
    let imap_drip = async {
        // Activity does not extend the budget. (Slow enough to stay under
        // the 8-command limit.)
        let (mut c, _) = h.imap(Src::Internal, Sni::Public).await;
        let t = Instant::now();
        loop {
            c.send("n NOOP").await;
            match c.try_line().await {
                Some(l) => assert_eq!(l, "n OK NOOP completed"),
                None => break,
            }
            assert!(t.elapsed() < Duration::from_secs(5), "never closed");
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    };
    let imap_no_tls = async {
        let mut c = Client::connect(h.proxy.imap, Src::External).await;
        c.expect_closed().await;
    };
    let smtp_silent = async {
        let mut c = Client::connect(h.proxy.smtp, Src::External).await;
        assert_eq!(c.line().await, format!("220 {HOSTNAME} ESMTP"));
        c.expect_closed().await;
    };
    let sieve_silent = async {
        let mut c = Client::connect(h.proxy.sieve, Src::External).await;
        c.sieve_response().await;
        c.expect_closed().await;
    };
    tokio::join!(
        closed_after_budget(imap_after_greeting),
        closed_after_budget(imap_drip),
        closed_after_budget(imap_no_tls),
        closed_after_budget(smtp_silent),
        closed_after_budget(sieve_silent),
    );

    h.wait_session_ended(Kind::Imap, 3).await;
    h.wait_session_ended(Kind::Smtp, 1).await;
    h.wait_session_ended(Kind::Sieve, 1).await;
    let ended: Vec<String> = h
        .proxy
        .logs()
        .into_iter()
        .filter(|l| l.contains("session ended"))
        .collect();
    assert!(
        ended
            .iter()
            .all(|l| l.contains("pre-auth budget of 1s used up")),
        "{ended:#?}"
    );

    // IMAP writes a protocol record for a pre-auth failure after TLS; a TLS
    // timeout and the plaintext phases of SMTP/ManageSieve write none.
    let mut ars = h.proxy.authresults();
    ars.sort_by(|a, b| a.peer.cmp(&b.peer));
    let protocol = |peer: &str, scope: &str| AuthResult {
        level: "WARN".into(),
        result: "fail".into(),
        proto: "imap".into(),
        scope: scope.into(),
        mech: "other".into(),
        user: String::new(),
        peer: peer.into(),
        reason: "protocol".into(),
        pwfp: String::new(),
        backend: String::new(),
    };
    assert_eq!(
        ars,
        vec![
            protocol("127.0.0.1", "internal"),
            protocol("127.0.0.2", "external")
        ]
    );
    let m = h.proxy.metrics().await;
    assert_eq!(
        m["mail_auth_proxy_preauth_aborts_total{proto=\"imap\",scope=\"external\"}"],
        2
    );
    assert_eq!(
        m["mail_auth_proxy_preauth_aborts_total{proto=\"imap\",scope=\"internal\"}"],
        1
    );
    assert_eq!(
        m["mail_auth_proxy_preauth_aborts_total{proto=\"smtp\",scope=\"external\"}"],
        1
    );
    assert_eq!(
        m["mail_auth_proxy_preauth_aborts_total{proto=\"sieve\",scope=\"external\"}"],
        1
    );
}
