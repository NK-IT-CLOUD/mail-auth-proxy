//! After login: the `[session]` limits end a session, traffic keeps it, and
//! `mail_auth_proxy_sessions_ended_total` says why each session ended. The
//! proxy closes a limited session without a protocol message of its own.

mod common;
use common::*;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// A logged-in session of `kind` that relays to the backend.
async fn logged_in(h: &Harness, kind: Kind) -> Client {
    logged_in_with(h, kind, &h.idp.token(EMAIL)).await
}

/// A logged-in session of `kind` with `token`.
async fn logged_in_with(h: &Harness, kind: Kind, token: &str) -> Client {
    let (mut c, reply) = h
        .auth(
            kind,
            Src::External,
            Sni::Public,
            "XOAUTH2",
            &xoauth2(EMAIL, token),
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

/// A token for `EMAIL` that expires `secs` from now (negative: in the past).
fn token_expiring_in(h: &Harness, secs: i64) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    h.idp.mint(serde_json::json!({ "exp": now + secs }))
}

/// Keep `c` (a logged-in IMAP session) busy until the proxy closes it;
/// returns how long that took.
async fn busy_imap_until_closed(c: &mut Client) -> Duration {
    let t0 = Instant::now();
    let mut i = 0;
    loop {
        tokio::time::sleep(Duration::from_millis(200)).await;
        c.send(&format!("b{i} NOOP")).await;
        match c.try_line().await {
            Some(l) => assert_eq!(l, format!("ECHO b{i} NOOP")),
            None => return t0.elapsed(),
        }
        i += 1;
        assert!(t0.elapsed() < IO_TIMEOUT, "session was not ended");
    }
}

/// `end_at_token_expiry` ends a busy OAuth session of each protocol once
/// the token's `exp` plus the grace has passed: closed without a message,
/// counted as `token_expired`, logged with that reason.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn token_expiry_ends_an_oauth_session() {
    let h = Harness::start_with(with_session(
        "end_at_token_expiry = true\ntoken_expiry_grace_secs = 1",
    ))
    .await;
    for kind in Kind::ALL {
        let mut c = logged_in_with(&h, kind, &token_expiring_in(&h, 1)).await;
        let t0 = Instant::now();
        c.expect_closed().await;
        // exp has a resolution of one second: at least the grace.
        let took = t0.elapsed();
        assert!(took >= Duration::from_millis(900), "{kind:?}: {took:?}");
        assert!(took < Duration::from_secs(4), "{kind:?}: {took:?}");
        wait_metric(&h, &ended(kind, "token_expired"), 1).await;
        for reason in ["idle_limit", "max_session", "client_close", "error"] {
            assert_eq!(h.proxy.metric(&ended(kind, reason)).await, 0, "{kind:?}");
        }
    }
    h.proxy
        .wait_logs(
            "session closed by limit proto=\"imap\" reason=\"token_expired\"",
            1,
        )
        .await;
}

/// Log in as `user` with `token` (IMAP); how long after the login's OK the
/// proxy closed the session.
async fn closed_after_login(h: &Harness, user: &str, token: &str) -> Duration {
    let (mut c, reply) = h
        .auth(
            Kind::Imap,
            Src::External,
            Sni::Public,
            "XOAUTH2",
            &xoauth2(user, token),
        )
        .await;
    assert!(reply.starts_with("a OK"), "{reply}");
    let t0 = Instant::now();
    c.expect_closed().await;
    t0.elapsed()
}

/// The session ends at `exp` plus the grace as an absolute time, whenever
/// the session started: a token already past `exp` (accepted within
/// `oauth.leeway_secs`) and a slow backend login both leave only the rest
/// of the grace, and a session whose deadline has passed by the end of the
/// login is closed right after it. A grace below the leeway is a warning.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn token_deadline_is_absolute() {
    let h = Harness::start_with(with_session(
        "end_at_token_expiry = true\ntoken_expiry_grace_secs = 2",
    ))
    .await;
    assert!(h
        .proxy
        .log_contains("session.token_expiry_grace_secs = 2 is below oauth.leeway_secs = 60"));
    let key = ended(Kind::Imap, "token_expired");

    // exp one second ago: at most one second of the grace is left.
    let took = closed_after_login(&h, EMAIL, &token_expiring_in(&h, -1)).await;
    assert!(took < Duration::from_millis(1500), "{took:?}");
    wait_metric(&h, &key, 1).await;

    // Past exp + grace already at the login: closed at once.
    let took = closed_after_login(&h, EMAIL, &token_expiring_in(&h, -10)).await;
    assert!(took < Duration::from_millis(500), "{took:?}");
    wait_metric(&h, &key, 2).await;

    // A backend login of SLOW_OK counts against the deadline too.
    let user = "slowok@example.test";
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let token = h
        .idp
        .mint(serde_json::json!({ "email": user, "exp": now + 1 }));
    let took = closed_after_login(&h, user, &token).await;
    assert!(took < Duration::from_millis(1500), "{took:?}");
    wait_metric(&h, &key, 3).await;
}

/// With `max_session_secs` shorter than the token's lifetime, that limit
/// ends the session and names itself; the token's deadline does not fire
/// for a session that has already ended.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn earlier_max_session_wins_over_token_expiry() {
    let h = Harness::start_with(with_session(
        "max_session_secs = 1\nend_at_token_expiry = true\ntoken_expiry_grace_secs = 0",
    ))
    .await;
    let mut c = logged_in(&h, Kind::Imap).await;
    busy_imap_until_closed(&mut c).await;
    wait_metric(&h, &ended(Kind::Imap, "max_session"), 1).await;
    assert_eq!(h.proxy.metric(&ended(Kind::Imap, "token_expired")).await, 0);
}

/// The option only touches OAuth sessions: a password session has no
/// `exp` and stays, even with no grace. Without the option a session lives
/// on past its token's `exp`, as before.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn password_sessions_and_the_default_ignore_token_expiry() {
    let h = Harness::start_with(with_session(
        "end_at_token_expiry = true\ntoken_expiry_grace_secs = 0",
    ))
    .await;
    let (mut pw, reply) = h
        .auth(
            Kind::Imap,
            Src::Internal,
            Sni::Internal,
            "PLAIN",
            &plain("bob@example.test", "pw"),
        )
        .await;
    assert!(reply.starts_with("a OK"), "{reply}");
    let mut oauth = logged_in_with(&h, Kind::Imap, &token_expiring_in(&h, 1)).await;
    oauth.expect_closed().await;
    wait_metric(&h, &ended(Kind::Imap, "token_expired"), 1).await;
    tokio::time::sleep(Duration::from_millis(1500)).await;
    pw.send("p NOOP").await;
    assert_eq!(pw.line().await, "ECHO p NOOP");

    // The grace alone does nothing.
    let h = Harness::start_with(with_session("token_expiry_grace_secs = 0")).await;
    let mut c = logged_in_with(&h, Kind::Imap, &token_expiring_in(&h, 1)).await;
    tokio::time::sleep(Duration::from_millis(2500)).await;
    c.send("late NOOP").await;
    assert_eq!(c.line().await, "ECHO late NOOP");
    assert_eq!(h.proxy.metric(&ended(Kind::Imap, "token_expired")).await, 0);
}
