//! STARTTLS command injection (CVE-2011-0411 class): bytes a client pipelines
//! after STARTTLS in the same write must never be executed, neither as
//! plaintext commands nor after the handshake. The proxy reads byte by byte,
//! leaves them in the socket and hands them to the TLS acceptor, which fails.

mod common;
use common::*;

/// After the STARTTLS reply the proxy may send a TLS alert record
/// (content type 0x15), but never a plaintext protocol reply.
fn assert_no_plaintext_reply(rest: &[u8]) {
    assert!(
        rest.is_empty() || rest[0] == 0x15,
        "injected commands were answered: {:?}",
        String::from_utf8_lossy(rest)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn smtp_starttls_injection() {
    let h = Harness::start().await;
    let mut c = Client::connect(h.proxy.smtp, Src::Internal).await;
    assert_eq!(c.line().await, format!("220 {HOSTNAME} ESMTP"));
    c.send("EHLO client.test").await;
    c.smtp_reply().await;
    // A password that the gate would accept on this connection's source.
    let injected = format!(
        "STARTTLS\r\nEHLO injected.test\r\nAUTH PLAIN {}\r\nMAIL FROM:<x@y.test>\r\n",
        plain("bob@example.test", "hunter2")
    );
    c.send_raw(injected.as_bytes()).await;
    assert_eq!(c.line().await, "220 2.0.0 Ready to start TLS");
    assert_no_plaintext_reply(&c.read_to_close().await);

    h.wait_session_ended(Kind::Smtp, 1).await;
    // A TLS failure writes no authresult for SMTP; it is a pre-auth abort.
    assert!(h.proxy.authresults().is_empty());
    assert!(h.smtp_be.seen().is_empty(), "backend contacted");
    assert_eq!(
        h.proxy
            .metric("mail_auth_proxy_preauth_aborts_total{proto=\"smtp\",scope=\"internal\"}")
            .await,
        1
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sieve_starttls_injection() {
    let h = Harness::start().await;
    let mut c = Client::connect(h.proxy.sieve, Src::Internal).await;
    c.sieve_response().await;
    let injected = format!(
        "STARTTLS\r\nCAPABILITY\r\nAUTHENTICATE \"PLAIN\" \"{}\"\r\n",
        plain("bob@example.test", "hunter2")
    );
    c.send_raw(injected.as_bytes()).await;
    assert_eq!(c.line().await, "OK \"Begin TLS negotiation now\"");
    assert_no_plaintext_reply(&c.read_to_close().await);

    h.wait_session_ended(Kind::Sieve, 1).await;
    assert!(h.proxy.authresults().is_empty());
    // No session and no credential reached the backend. The only contact is
    // the capability probe for the first greeting after startup (RFC 5804
    // §1.7), the proxy's own connection.
    assert!(h.sieve_be.sessions().is_empty(), "backend session");
    assert!(
        h.sieve_be
            .seen()
            .iter()
            .all(|s| s.probe && s.login.is_none()),
        "backend contacted"
    );
    assert_eq!(
        h.proxy
            .metric("mail_auth_proxy_preauth_aborts_total{proto=\"sieve\",scope=\"internal\"}")
            .await,
        1
    );
}

/// Control: the same dialog without pipelining works, so the tests above
/// fail for the right reason.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn starttls_without_injection_works() {
    let h = Harness::start().await;
    let (mut c, _) = h.smtp(Src::Internal, Sni::Internal).await;
    c.send(&format!(
        "AUTH PLAIN {}",
        plain("bob@example.test", "hunter2")
    ))
    .await;
    assert_eq!(c.line().await, "235 2.7.0 Authentication successful");
    let (mut c, _, _) = h.sieve(Src::Internal, Sni::Internal).await;
    c.send(&format!(
        "AUTHENTICATE \"PLAIN\" \"{}\"",
        plain("bob@example.test", "hunter2")
    ))
    .await;
    assert_eq!(c.line().await, "OK \"Logged in.\"");
}
