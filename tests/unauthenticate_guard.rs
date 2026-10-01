//! After login no client command takes the session back to the
//! unauthenticated state (RFC 8437 UNAUTHENTICATE, RFC 5804 §2.14.1), or
//! presents a second credential, whatever the backend offers or does: the
//! relay's guard answers such a command itself, or ends the session, and the
//! backend never sees it. The mock backends take UNAUTHENTICATE whether they
//! offer it or not.

mod common;
use common::*;
use std::time::Instant;

const REFUSED: &str = "BAD Command not permitted after login";
const SIEVE_REFUSED: &str = "NO \"Command not permitted after login\"";

async fn login(h: &Harness, kind: Kind) -> (Client, String) {
    h.auth(
        kind,
        Src::External,
        Sni::Public,
        "XOAUTH2",
        &xoauth2(EMAIL, &h.idp.token(EMAIL)),
    )
    .await
}

/// Lines the backend received after the login.
fn relayed(be: &MockBackend) -> Vec<String> {
    be.sessions().into_iter().flat_map(|s| s.relayed).collect()
}

fn assert_never_relayed(be: &MockBackend, needle: &str) {
    let lines = relayed(be);
    assert!(
        !lines
            .iter()
            .any(|l| l.to_ascii_uppercase().contains(needle)),
        "{lines:?}"
    );
}

async fn wait_blocked(h: &Harness, kind: Kind, n: u64) {
    let key = format!(
        "mail_auth_proxy_sessions_ended_total{{proto=\"{}\",reason=\"blocked\"}}",
        kind.label()
    );
    let until = Instant::now() + IO_TIMEOUT;
    while h.proxy.metric(&key).await < n {
        assert!(Instant::now() < until, "{key} did not reach {n}");
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

/// A backend that offers UNAUTHENTICATE (Stalwart) can be used: the
/// capability is taken out of the login's CAPABILITY code and of every
/// CAPABILITY response, and the command, in any spelling, as well as a
/// second login and COMPRESS, is answered by the proxy.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn imap_unauthenticate_is_refused_and_not_offered() {
    let h = Harness::start().await;
    *h.imap_be.login_caps.lock().unwrap() =
        Some("IMAP4rev1 IDLE UNAUTHENTICATE COMPRESS=DEFLATE MOVE".into());
    let (mut c, reply) = login(&h, Kind::Imap).await;
    assert_eq!(reply, "a OK [CAPABILITY IMAP4rev1 IDLE MOVE] Logged in");
    for (tag, cmd) in [
        ("b", "UNAUTHENTICATE"),
        ("c", "unauthenticate"),
        ("d", "\"UNAUTHENTICATE\""),
        ("e", "UNAUTHENTICATE now"),
        ("e2", " UNAUTHENTICATE"),
        ("e3", "\tUNAUTHENTICATE"),
        ("f", "LOGIN other@example.test secret"),
        ("g", "AUTHENTICATE PLAIN"),
        ("h", "COMPRESS DEFLATE"),
        ("i", "STARTTLS"),
    ] {
        c.send(&format!("{tag} {cmd}")).await;
        assert_eq!(c.line().await, format!("{tag} {REFUSED}"), "{cmd}");
    }
    // A bare LF ends the line as CRLF does (Stalwart takes both).
    c.send_raw(b"l UNAUTHENTICATE\n").await;
    assert_eq!(c.line().await, format!("l {REFUSED}"));
    c.send("j CAPABILITY").await;
    let caps = "IMAP4rev1 IMAP4rev2 LITERAL+ IDLE MOVE";
    assert_eq!(c.line().await, format!("* CAPABILITY {caps}"));
    assert_eq!(
        c.line().await,
        format!("j OK [CAPABILITY {caps}] Capability completed.")
    );
    // The session goes on.
    c.send("k NOOP").await;
    assert_eq!(c.line().await, "ECHO k NOOP");
    for needle in [
        "UNAUTHENTICATE",
        "LOGIN",
        "AUTHENTICATE",
        "COMPRESS",
        "STARTTLS",
    ] {
        assert_never_relayed(&h.imap_be, needle);
    }
    assert_eq!(h.proxy.authresults().len(), 1);
}

/// A backend that does not offer UNAUTHENTICATE but takes it all the same
/// gets it no more than one that offers it. A login OK without a CAPABILITY
/// code is relayed as it is.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn imap_unauthenticate_is_refused_when_not_offered() {
    let h = Harness::start().await;
    h.imap_be
        .caps_untagged
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let (mut c, reply) = login(&h, Kind::Imap).await;
    assert_eq!(reply, "a OK Logged in");
    c.send("b UNAUTHENTICATE").await;
    assert_eq!(c.line().await, format!("b {REFUSED}"));
    c.send("c NOOP").await;
    assert_eq!(c.line().await, "ECHO c NOOP");
    assert_never_relayed(&h.imap_be, "UNAUTHENTICATE");
    // The proxy asks the backend nothing of its own after the login.
    assert_eq!(relayed(&h.imap_be), vec!["c NOOP".to_string()]);
}

/// Literal data that reads like the command is data: APPEND with a
/// synchronizing literal, and with a non-synchronizing one, which the proxy
/// passes on as synchronizing (the backend confirms it with `+`, which the
/// client does not see).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn imap_literal_data_is_not_a_command() {
    let h = Harness::start().await;
    let (mut c, _) = login(&h, Kind::Imap).await;
    let mail = "Subject: UNAUTHENTICATE\r\n\r\nb UNAUTHENTICATE\r\nc LOGIN x y\r\n";
    c.send(&format!("b APPEND INBOX {{{}}}", mail.len())).await;
    assert_eq!(c.line().await, "+ Ready for literal data");
    c.send_raw(mail.as_bytes()).await;
    c.send("").await;
    assert_eq!(c.line().await, "b OK APPEND completed.");

    c.send_raw(format!("c APPEND INBOX {{{}+}}\r\n{mail}\r\n", mail.len()).as_bytes())
        .await;
    assert_eq!(c.line().await, "c OK APPEND completed.");
    c.send("d NOOP").await;
    assert_eq!(c.line().await, "ECHO d NOOP");

    let lines = relayed(&h.imap_be);
    let literal = format!("LITERAL {mail}");
    assert_eq!(
        lines,
        vec![
            format!("b APPEND INBOX {{{}}}", mail.len()),
            literal.clone(),
            String::new(),
            format!("c APPEND INBOX {{{}}}", mail.len()),
            literal,
            String::new(),
            "d NOOP".to_string(),
        ]
    );
}

/// IDLE and DONE pass as before; a command in place of DONE that the proxy
/// cannot answer ends the session before the backend has it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn imap_idle() {
    let h = Harness::start().await;
    let (mut c, _) = login(&h, Kind::Imap).await;
    c.send("b IDLE").await;
    assert_eq!(c.line().await, "+ idling");
    c.send("DONE").await;
    assert_eq!(c.line().await, "b OK Idle completed.");
    c.send("c NOOP").await;
    assert_eq!(c.line().await, "ECHO c NOOP");

    let (mut c, _) = login(&h, Kind::Imap).await;
    c.send("b IDLE").await;
    assert_eq!(c.line().await, "+ idling");
    c.send("c UNAUTHENTICATE").await;
    c.expect_closed().await;
    wait_blocked(&h, Kind::Imap, 1).await;
    assert_never_relayed(&h.imap_be, "UNAUTHENTICATE");
    assert!(h
        .proxy
        .log_contains("where it cannot be refused; session closed"));
}

/// ManageSieve: UNAUTHENTICATE is answered with NO and never offered; a
/// script that mentions it is uploaded; a literal line that is the command
/// ends the session.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sieve_unauthenticate_is_refused_and_not_offered() {
    let h = Harness::start().await;
    *h.sieve_be.login_caps.lock().unwrap() = Some("\"UNAUTHENTICATE\"".into());
    let (_c, _greeting, caps) = h.sieve(Src::External, Sni::Public).await;
    assert!(
        !caps.iter().any(|l| l.contains("UNAUTHENTICATE")),
        "{caps:?}"
    );
    let (mut c, reply) = login(&h, Kind::Sieve).await;
    assert_eq!(reply, "OK \"Logged in.\"");
    for cmd in [
        "UNAUTHENTICATE",
        "unauthenticate",
        "  UNAUTHENTICATE",
        "\tUNAUTHENTICATE",
        "UNAUTHENTICATE now",
        "\"UNAUTHENTICATE\"",
        "AUTHENTICATE \"PLAIN\"",
        "STARTTLS",
    ] {
        c.send(cmd).await;
        assert_eq!(c.line().await, SIEVE_REFUSED, "{cmd}");
    }
    c.send_raw(b"UNAUTHENTICATE\n").await;
    assert_eq!(c.line().await, SIEVE_REFUSED);
    c.send("CAPABILITY").await;
    assert_eq!(
        c.sieve_response().await,
        vec![
            "\"IMPLEMENTATION\" \"mock\"",
            "\"SIEVE\" \"fileinto\"",
            "\"VERSION\" \"1.0\"",
            "OK \"Capability completed.\"",
        ]
    );
    let script =
        "# UNAUTHENTICATE\r\nif header :contains \"subject\" \"UNAUTHENTICATE\" { stop; }\r\n";
    c.send_raw(format!("PUTSCRIPT \"s\" {{{}+}}\r\n{script}\r\n", script.len()).as_bytes())
        .await;
    assert!(c.line().await.starts_with("OK "));
    assert!(relayed(&h.sieve_be).contains(&format!("LITERAL {script}")));
    assert!(!relayed(&h.sieve_be)
        .iter()
        .any(|l| l.eq_ignore_ascii_case("UNAUTHENTICATE")));

    // In literal data, where the proxy cannot tell whether the backend reads
    // it as data: the session ends before the line does.
    let script = "require \"fileinto\";\r\nUNAUTHENTICATE\r\n";
    c.send_raw(format!("PUTSCRIPT \"t\" {{{}+}}\r\n{script}\r\n", script.len()).as_bytes())
        .await;
    c.expect_closed().await;
    wait_blocked(&h, Kind::Sieve, 1).await;
    assert!(!relayed(&h.sieve_be)
        .iter()
        .any(|l| l.starts_with("LITERAL require")));
}
