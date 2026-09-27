//! Process lifecycle: SIGHUP reloads the certificate and the JWKS without
//! touching open sessions; SIGTERM closes the listeners, lets open sessions
//! finish for a bounded time and exits; systemd is told READY and STOPPING.

mod common;
use common::*;
use std::sync::atomic::Ordering;
use std::time::Duration;

/// An IMAP session logged in with a token, relaying to the backend.
async fn logged_in(h: &Harness) -> Client {
    let token = h.idp.token(EMAIL);
    let (mut c, reply) = h
        .auth(
            Kind::Imap,
            Src::External,
            Sni::Public,
            "XOAUTH2",
            &xoauth2(EMAIL, &token),
        )
        .await;
    assert_eq!(reply, "a OK [CAPABILITY IMAP4rev1 IDLE MOVE] Logged in");
    c.send("n NOOP").await;
    assert_eq!(c.line().await, "ECHO n NOOP");
    c
}

/// The certificate a new IMAP connection is served.
async fn served_cert(h: &Harness) -> Vec<u8> {
    let mut c = Client::connect(h.proxy.imap, Src::External).await;
    c.tls_full(&h.pki, Sni::Public).await;
    c.line().await;
    c.peer_cert()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sighup_reloads_certificate_and_jwks() {
    let h = Harness::start().await;
    let mut session = logged_in(&h).await;
    let before = served_cert(&h).await;
    assert_ne!(before, h.pki.renewed_der);
    assert_eq!(h.idp.fetches.load(Ordering::SeqCst), 1);

    std::fs::copy(&h.pki.renewed_cert, &h.pki.proxy_cert).unwrap();
    std::fs::copy(&h.pki.renewed_key, &h.pki.proxy_key).unwrap();
    h.proxy.signal("HUP");
    h.proxy.wait_logs("reload: certificate loaded", 1).await;
    h.proxy.wait_logs("reload: JWKS refreshed", 1).await;
    assert_eq!(h.idp.fetches.load(Ordering::SeqCst), 2);
    assert_eq!(served_cert(&h).await, h.pki.renewed_der);
    // The session opened before the reload is untouched.
    session.send("n2 NOOP").await;
    assert_eq!(session.line().await, "ECHO n2 NOOP");

    // A broken certificate file is refused; the loaded one stays in use.
    std::fs::write(&h.pki.proxy_cert, "not a certificate").unwrap();
    h.proxy.signal("HUP");
    h.proxy
        .wait_logs("reload: certificate unusable; keeping the current one", 1)
        .await;
    assert_eq!(served_cert(&h).await, h.pki.renewed_der);
    let _ = logged_in(&h).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sigterm_drains_open_sessions_then_exits() {
    let pki = Pki::new();
    let socket = pki.dir.path().join("notify.sock");
    let notify = std::os::unix::net::UnixDatagram::bind(&socket).unwrap();
    notify
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let recv = || {
        let mut buf = [0u8; 256];
        let n = notify.recv(&mut buf).expect("systemd notification");
        String::from_utf8_lossy(&buf[..n]).into_owned()
    };
    let mut h = Harness::start_on(
        pki,
        Opts {
            notify_socket: Some(socket.clone()),
            ..Opts::default()
        },
    )
    .await;
    assert_eq!(recv(), "READY=1");

    let mut session = logged_in(&h).await;
    h.proxy.signal("TERM");
    assert_eq!(recv(), "STOPPING=1");
    h.proxy
        .wait_logs("shutting down: listeners closed", 1)
        .await;
    // No new connections; the listener port is closed.
    let until = std::time::Instant::now() + IO_TIMEOUT;
    while tokio::net::TcpStream::connect(h.proxy.imap).await.is_ok() {
        assert!(std::time::Instant::now() < until, "listener still open");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // The open session keeps working until it ends.
    session.send("n2 NOOP").await;
    assert_eq!(session.line().await, "ECHO n2 NOOP");
    assert!(h
        .proxy
        .wait_exit(Duration::from_millis(300))
        .await
        .is_none());
    drop(session);
    let status = h
        .proxy
        .wait_exit(Duration::from_secs(5))
        .await
        .expect("exited once the last session ended");
    assert!(status.success(), "{status}");
    assert!(h.proxy.log_contains("all sessions ended; exiting"));
}

/// A session that never ends does not hold the shutdown up for longer than
/// the drain time (10 s).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sigterm_closes_sessions_after_the_drain_time() {
    let mut h = Harness::start().await;
    let mut session = logged_in(&h).await;
    let started = std::time::Instant::now();
    h.proxy.signal("TERM");
    let status = h
        .proxy
        .wait_exit(Duration::from_secs(20))
        .await
        .expect("exited after the drain time");
    let took = started.elapsed();
    assert!(status.success(), "{status}");
    assert!(
        (Duration::from_secs(9)..Duration::from_secs(15)).contains(&took),
        "{took:?}"
    );
    assert!(h
        .proxy
        .log_contains("sessions still open after the drain time"));
    session.expect_closed().await;
}

/// A slow JWKS refresh after SIGHUP does not hold up SIGTERM, and a second
/// SIGHUP meanwhile starts no second refresh.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sigterm_is_not_blocked_by_a_slow_reload() {
    let mut h = Harness::start().await;
    h.idp.delay_ms.store(5000, Ordering::SeqCst);
    h.proxy.signal("HUP");
    h.proxy.wait_logs("reload: certificate loaded", 1).await;
    h.proxy.signal("HUP");
    h.proxy
        .wait_logs("reload: JWKS refresh already running", 1)
        .await;
    let started = std::time::Instant::now();
    h.proxy.signal("TERM");
    let status = h
        .proxy
        .wait_exit(Duration::from_secs(3))
        .await
        .expect("SIGTERM handled while the refresh was running");
    assert!(status.success(), "{status}");
    assert!(started.elapsed() < Duration::from_secs(3));
    assert_eq!(h.idp.fetches.load(Ordering::SeqCst), 2, "one refresh");
}
