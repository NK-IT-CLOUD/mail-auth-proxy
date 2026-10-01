//! After login: the `[session]` limits end a session, traffic keeps it, and
//! `mail_auth_proxy_sessions_ended_total` says why each session ended. The
//! proxy closes a limited session without a protocol message of its own.

mod common;
use common::*;
use std::time::{Duration, Instant};

/// A logged-in session of `kind` that relays to the backend.
async fn logged_in(h: &Harness, kind: Kind) -> Client {
    let token = h.idp.token(EMAIL);
    let (mut c, reply) = h
        .auth(
            kind,
            Src::External,
            Sni::Public,
            "XOAUTH2",
            &xoauth2(EMAIL, &token),
        )
        .await;
    assert!(
        reply.starts_with("a OK") || reply.starts_with("235") || reply.starts_with("OK"),
        "{kind:?}: {reply}"
    );
    c.send("n NOOP").await;
    assert_eq!(c.line().await, "ECHO n NOOP");
    c
}

fn ended(kind: Kind, reason: &str) -> String {
    format!(
        "mail_auth_proxy_sessions_ended_total{{proto=\"{}\",reason=\"{reason}\"}}",
        kind.label()
    )
}

/// The counter reaches `n` (the relay records after the client saw the
/// close).
async fn wait_metric(h: &Harness, key: &str, n: u64) {
    let until = Instant::now() + IO_TIMEOUT;
    while h.proxy.metric(key).await != n {
        assert!(Instant::now() < until, "{key} did not reach {n}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn with_session(keys: &str) -> Opts {
    Opts {
        session: Some(keys.to_string()),
        ..Opts::default()
    }
}

/// A silent session is closed once the idle limit passes: no BYE, 421 or
/// other text from the proxy, just the end of the stream. A limit below
/// 30 minutes is accepted with a warning naming the RFCs.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn idle_limit_closes_a_silent_session() {
    let h = Harness::start_with(with_session("idle_limit_secs = 1")).await;
    assert!(h
        .proxy
        .log_contains("session.idle_limit_secs = 1 is below 30 minutes"));
    assert!(h.proxy.log_contains("RFC 9051 section 5.4"));
    for kind in Kind::ALL {
        let mut c = logged_in(&h, kind).await;
        let t0 = Instant::now();
        c.expect_closed().await;
        assert!(t0.elapsed() >= Duration::from_millis(900), "{kind:?}");
        wait_metric(&h, &ended(kind, "idle_limit"), 1).await;
        assert_eq!(h.proxy.metric(&ended(kind, "client_close")).await, 0);
    }
    h.proxy
        .wait_logs(
            "session closed by limit proto=\"imap\" reason=\"idle_limit\"",
            1,
        )
        .await;
}

/// Traffic resets the idle timer: a client that keeps talking (an IDLE
/// client re-issuing IDLE) stays connected well past the limit.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn traffic_keeps_the_session_open() {
    let h = Harness::start_with(with_session("idle_limit_secs = 2")).await;
    let mut c = logged_in(&h, Kind::Imap).await;
    let t0 = Instant::now();
    let mut i = 0;
    while t0.elapsed() < Duration::from_secs(5) {
        tokio::time::sleep(Duration::from_millis(700)).await;
        c.send(&format!("i{i} IDLE")).await;
        assert_eq!(c.line().await, "+ idling");
        c.send("DONE").await;
        assert_eq!(c.line().await, format!("i{i} OK Idle completed."));
        i += 1;
    }
    assert_eq!(h.proxy.metric(&ended(Kind::Imap, "idle_limit")).await, 0);
    // Then silence: the limit applies.
    c.expect_closed().await;
    wait_metric(&h, &ended(Kind::Imap, "idle_limit"), 1).await;
}

/// `max_session_secs` ends a session that is busy the whole time.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn max_session_ends_a_busy_session() {
    let h = Harness::start_with(with_session("max_session_secs = 2")).await;
    let mut c = logged_in(&h, Kind::Smtp).await;
    let t0 = Instant::now();
    let mut i = 0;
    loop {
        tokio::time::sleep(Duration::from_millis(200)).await;
        c.send(&format!("NOOP {i}")).await;
        match c.try_line().await {
            Some(l) => assert_eq!(l, format!("ECHO NOOP {i}")),
            None => break,
        }
        i += 1;
        assert!(t0.elapsed() < IO_TIMEOUT, "session was not ended");
    }
    let took = t0.elapsed();
    assert!(took >= Duration::from_millis(1500), "{took:?}");
    wait_metric(&h, &ended(Kind::Smtp, "max_session"), 1).await;
    assert_eq!(h.proxy.metric(&ended(Kind::Smtp, "idle_limit")).await, 0);
}

/// Without limits, the side that closes first is counted; the backend's
/// close reaches the client.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ends_are_counted_by_who_closed() {
    let h = Harness::start().await;
    let c = logged_in(&h, Kind::Sieve).await;
    drop(c);
    wait_metric(&h, &ended(Kind::Sieve, "client_close"), 1).await;

    let mut c = logged_in(&h, Kind::Imap).await;
    c.send("BACKEND-CLOSE").await;
    c.expect_closed().await;
    wait_metric(&h, &ended(Kind::Imap, "backend_close"), 1).await;
    for kind in Kind::ALL {
        for reason in ["idle_limit", "max_session", "error"] {
            assert_eq!(h.proxy.metric(&ended(kind, reason)).await, 0);
        }
    }
}
