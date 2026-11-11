//! The token size limit against the line limit, per protocol. A token of up
//! to 16384 bytes (`auth::MAX_TOKEN`) logs in on IMAP, SMTP and ManageSieve
//! with the initial response on the command line or after the server's
//! challenge; a longer one is a `bad_token` with the protocol's normal
//! failure reply. Only a line beyond `MAX_AUTH_LINE` ends the connection:
//! after a challenge with the protocol's failure reply, a command line
//! without one (its tag and command are lost).

mod common;
use common::*;
use serde_json::json;

/// `auth::MAX_TOKEN`.
const MAX_TOKEN: usize = 16384;

/// `wire::line::MAX_AUTH_LINE`: the longest client line that can carry a
/// SASL response (pinned by a unit test there).
const MAX_AUTH_LINE: usize = 23512;

/// A token of the harness IdP for `EMAIL` whose length is in `range`, padded
/// with a claim.
fn token_in(idp: &Idp, range: std::ops::RangeInclusive<usize>) -> String {
    let base = idp.mint(json!({ "pad": "" })).len();
    // base64url: four characters for three bytes of the claim.
    let mut pad = (range.start() - base) * 3 / 4 - 8;
    loop {
        let token = idp.mint(json!({ "pad": "x".repeat(pad) }));
        if range.contains(&token.len()) {
            return token;
        }
        assert!(token.len() < *range.start(), "{} bytes", token.len());
        pad += 1;
    }
}

fn logged_in(kind: Kind) -> &'static str {
    match kind {
        Kind::Imap => "a OK [CAPABILITY IMAP4rev1 IDLE MOVE] Logged in",
        Kind::Smtp => "235 2.7.0 Authentication successful",
        Kind::Sieve => "OK \"Logged in.\"",
    }
}

fn rejection(kind: Kind) -> &'static str {
    match kind {
        Kind::Imap => "a NO [AUTHENTICATIONFAILED] Authentication failed",
        Kind::Smtp => "535 5.7.8 Authentication credentials invalid",
        Kind::Sieve => "NO \"Authentication failed\"",
    }
}

/// The failure reply to a response line that cannot be read.
fn unreadable(kind: Kind) -> &'static str {
    match kind {
        Kind::Imap => "a BAD AUTHENTICATE failed: invalid or cancelled response",
        Kind::Smtp => "501 5.5.2 Invalid or cancelled authentication response",
        Kind::Sieve => "NO \"Invalid authentication response\"",
    }
}

/// The command that asks for the response after an empty challenge.
fn auth_without_ir(kind: Kind, mech: &str) -> String {
    match kind {
        Kind::Imap => format!("a AUTHENTICATE {mech}"),
        Kind::Smtp => format!("AUTH {mech}"),
        Kind::Sieve => format!("AUTHENTICATE \"{mech}\""),
    }
}

/// The empty challenge of `kind`.
fn empty_challenge(kind: Kind) -> &'static str {
    match kind {
        Kind::Imap => "+ ",
        Kind::Smtp => "334 ",
        Kind::Sieve => "\"\"",
    }
}

/// A token just under `MAX_TOKEN` logs in on every protocol, as an initial
/// response on the command line and as the response after the challenge,
/// and reaches the backend whole. Its base64 is longer than `MAX_LINE`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn largest_token_logs_in() {
    let h = Harness::start().await;
    // A Postfix whose smtpd_sasl_response_limit fits the token.
    h.smtp_be
        .smtp_long_sasl
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let token = token_in(&h.idp, MAX_TOKEN - 8..=MAX_TOKEN);
    let ir = xoauth2(EMAIL, &token);
    assert!(ir.len() > 16384, "{}", ir.len());
    let mut n = 0;
    for kind in Kind::ALL {
        let (c, reply) = h
            .auth(kind, Src::External, Sni::Public, "XOAUTH2", &ir)
            .await;
        assert_eq!(reply, logged_in(kind), "{kind:?}: initial response");
        drop(c);
        n += 1;

        let mut c = h.ready(kind, Src::External, Sni::Public).await;
        c.send(&auth_without_ir(kind, "XOAUTH2")).await;
        assert_eq!(c.line().await, empty_challenge(kind), "{kind:?}");
        c.send(&sasl_response(kind, &ir)).await;
        assert_eq!(
            c.line().await,
            logged_in(kind),
            "{kind:?}: after the challenge"
        );
        n += 1;

        for s in h.backend(kind).sessions() {
            assert_eq!(s.secret.as_deref(), Some(token.as_str()), "{kind:?}");
        }
        let ars = h.proxy.wait_authresults(n).await;
        assert!(
            ars.iter().all(|a| a.reason == "ok" && a.user == EMAIL),
            "{kind:?}: {ars:?}"
        );
    }
}

/// A token just over `MAX_TOKEN` is a `bad_token` on every protocol, with
/// the error challenge and the normal failure reply, and never reaches the
/// backend.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn token_over_the_limit_is_bad_token() {
    let h = Harness::start().await;
    let token = token_in(&h.idp, MAX_TOKEN + 1..=MAX_TOKEN + 8);
    let ir = xoauth2(EMAIL, &token);
    for (i, kind) in Kind::ALL.into_iter().enumerate() {
        let (mut c, result, reply) = h
            .auth_rejected(kind, Src::External, Sni::Public, "XOAUTH2", &ir)
            .await;
        assert_eq!(result, json!({"status": "invalid_token"}), "{kind:?}");
        assert_eq!(reply, rejection(kind), "{kind:?}");
        c.expect_end(kind).await;
        let ar = &h.proxy.wait_authresults(i + 1).await[i];
        assert_eq!(
            (ar.proto.as_str(), ar.reason.as_str(), ar.user.as_str()),
            (kind.label(), "bad_token", EMAIL)
        );
        assert!(h.backend(kind).sessions().is_empty(), "{kind:?}");
    }
    assert_eq!(
        h.proxy
            .metric("mail_auth_proxy_token_validations_total{result=\"fail\"}")
            .await,
        3
    );
}

/// A line beyond `MAX_AUTH_LINE` ends the connection: a response after the
/// challenge gets the protocol's failure reply first, a command line (whose
/// tag and command are lost) none. Either is a `protocol` record.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn overlong_auth_line_ends_the_connection() {
    let h = Harness::start().await;
    // Exactly one byte over the limit and no line end: the proxy has read
    // all of it when it closes, so its reply is not lost to a reset.
    let overlong = vec![b'A'; MAX_AUTH_LINE + 1];
    for kind in Kind::ALL {
        let mut c = h.ready(kind, Src::External, Sni::Public).await;
        c.send(&auth_without_ir(kind, "XOAUTH2")).await;
        assert_eq!(c.line().await, empty_challenge(kind), "{kind:?}");
        c.send_raw(&overlong).await;
        assert_eq!(c.line().await, unreadable(kind), "{kind:?}");
        c.expect_end(kind).await;
        let line = h.wait_session_ended(kind, 1).await;
        assert!(line.contains("line too long"), "{kind:?}: {line}");

        // An initial response that makes the command line overlong.
        let mut c = h.ready(kind, Src::External, Sni::Public).await;
        let prefix = match kind {
            Kind::Sieve => "AUTHENTICATE \"XOAUTH2\" \"".to_string(),
            _ => format!("{} ", auth_without_ir(kind, "XOAUTH2")),
        };
        let mut line = prefix.into_bytes();
        line.resize(MAX_AUTH_LINE + 1, b'A');
        c.send_raw(&line).await;
        c.expect_closed().await;
        let line = h.wait_session_ended(kind, 2).await;
        assert!(line.contains("line too long"), "{kind:?}: {line}");
    }
    let ars = h.proxy.wait_authresults(6).await;
    assert!(ars.iter().all(|a| a.reason == "protocol"), "{ars:?}");
    for kind in Kind::ALL {
        assert!(h.backend(kind).sessions().is_empty(), "{kind:?}");
    }
}
