//! Several authentication attempts per connection (`limits.max_auth_attempts`):
//! a client may try again after a refusal (RFC 9051 §6.2.2, RFC 4954 §4,
//! RFC 5804 §2.1). Every attempt is judged, logged and counted by the rate
//! limit on its own, like one on a new connection; the pre-auth budget spans
//! all of them.

mod common;
use common::*;
use std::time::{Duration, Instant};

fn opts(attempts: u32) -> Opts {
    Opts {
        max_auth_attempts: attempts,
        ..Opts::default()
    }
}

/// The command presenting PLAIN for `user`/`pass`, with tag `tag` for IMAP.
fn plain_command(kind: Kind, tag: &str, user: &str, pass: &str) -> String {
    let ir = plain(user, pass);
    match kind {
        Kind::Imap => format!("{tag} AUTHENTICATE PLAIN {ir}"),
        _ => auth_command(kind, "PLAIN", &ir),
    }
}

/// The refusal of a wrong password, without the IMAP tag.
fn refusal(kind: Kind) -> &'static str {
    match kind {
        Kind::Imap => "NO [AUTHENTICATIONFAILED] backend rejected credentials",
        Kind::Smtp => "535 5.7.8 Authentication credentials invalid",
        Kind::Sieve => "NO \"Authentication failed\"",
    }
}

fn untagged(kind: Kind, reply: &str) -> String {
    match kind {
        Kind::Imap => reply.split_once(' ').unwrap().1.to_string(),
        _ => reply.to_string(),
    }
}

fn is_ok(kind: Kind, reply: &str) -> bool {
    match kind {
        Kind::Imap => untagged(kind, reply).starts_with("OK "),
        Kind::Smtp => reply == "235 2.7.0 Authentication successful",
        Kind::Sieve => reply == "OK \"Logged in.\"",
    }
}

fn reasons(h: &Harness) -> Vec<(String, String)> {
    h.proxy
        .authresults()
        .into_iter()
        .map(|a| (a.mech, a.reason))
        .collect()
}

fn preauth_aborts(kind: Kind, scope: &str) -> String {
    format!(
        "mail_auth_proxy_preauth_aborts_total{{proto=\"{}\",scope=\"{scope}\"}}",
        kind.label()
    )
}

/// A wrong password, then the right one on the same connection: the second
/// is judged as if it were the first, and the session is relayed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retry_after_a_wrong_password() {
    let h = Harness::start_with(opts(3)).await;
    for (i, kind) in Kind::ALL.into_iter().enumerate() {
        let mut c = h.ready(kind, Src::Internal, Sni::Internal).await;
        c.send(&plain_command(kind, "a", "reject@example.test", "old"))
            .await;
        assert_eq!(untagged(kind, &c.line().await), refusal(kind), "{kind:?}");
        c.send(&plain_command(kind, "b", "bob@example.test", "new"))
            .await;
        let reply = c.line().await;
        assert!(is_ok(kind, &reply), "{kind:?}: {reply}");
        c.send("PING").await;
        assert_eq!(c.line().await, "ECHO PING", "{kind:?}");
        let ars = h.proxy.wait_authresults(2 * (i + 1)).await;
        assert_eq!(
            ars[2 * i..]
                .iter()
                .map(|a| (a.reason.as_str(), a.user.as_str()))
                .collect::<Vec<_>>(),
            [
                ("backend_reject", "reject@example.test"),
                ("ok", "bob@example.test")
            ],
            "{kind:?}"
        );
        // Two backend logins, one per attempt.
        let sessions = h.backend(kind).sessions();
        assert_eq!(sessions.len(), 2, "{kind:?}");
    }
}

/// Python smtplib offers PLAIN first and falls back to LOGIN on the same
/// connection; the refusal is not followed by 421.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn smtp_falls_back_from_plain_to_login() {
    let h = Harness::start_with(opts(3)).await;
    let mut c = h.ready(Kind::Smtp, Src::Internal, Sni::Internal).await;
    c.send(&format!(
        "AUTH PLAIN {}",
        plain("reject@example.test", "pw")
    ))
    .await;
    assert_eq!(c.line().await, refusal(Kind::Smtp));
    c.send("AUTH LOGIN").await;
    assert_eq!(c.line().await, "334 VXNlcm5hbWU6");
    c.send(&b64("carol@example.test")).await;
    assert_eq!(c.line().await, "334 UGFzc3dvcmQ6");
    c.send(&b64("pw")).await;
    assert_eq!(c.line().await, "235 2.7.0 Authentication successful");
    h.proxy.wait_authresults(2).await;
    assert_eq!(
        reasons(&h),
        [
            ("PLAIN".into(), "backend_reject".into()),
            ("LOGIN".into(), "ok".into())
        ]
    );
}

/// The last attempt ends the session as the only one did before: SMTP with
/// 421, IMAP and ManageSieve with the close.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_last_attempt_ends_the_session() {
    let h = Harness::start_with(opts(3)).await;
    for kind in Kind::ALL {
        let mut c = h.ready(kind, Src::Internal, Sni::Internal).await;
        for n in 0..3 {
            c.send(&plain_command(
                kind,
                "a",
                "reject@example.test",
                &format!("pw{n}"),
            ))
            .await;
            assert_eq!(
                untagged(kind, &c.line().await),
                refusal(kind),
                "{kind:?} {n}"
            );
        }
        c.expect_end(kind).await;
        assert_eq!(h.backend(kind).sessions().len(), 3, "{kind:?}");
    }
    let ars = h.proxy.wait_authresults(9).await;
    assert!(ars.iter().all(|a| a.reason == "backend_reject"), "{ars:?}");
}

/// Attempts without a credential (an unsupported mechanism, a cancelled
/// exchange) are answered, logged as `protocol`, count as attempts, and
/// leave room for another; the connection is no pre-auth abort once a
/// credential was presented.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn attempts_without_a_credential_count() {
    let h = Harness::start_with(opts(3)).await;
    let good = plain("bob@example.test", "pw");

    let mut c = h.ready(Kind::Imap, Src::Internal, Sni::Internal).await;
    c.send("a AUTHENTICATE FOO").await;
    assert_eq!(c.line().await, "a NO unsupported SASL mechanism");
    c.send("b AUTHENTICATE PLAIN").await;
    assert_eq!(c.line().await, "+ ");
    c.send("*").await;
    assert_eq!(
        c.line().await,
        "b BAD AUTHENTICATE failed: invalid or cancelled response"
    );
    c.send(&format!("c AUTHENTICATE PLAIN {good}")).await;
    assert!(c.line().await.starts_with("c OK "));

    let mut c = h.ready(Kind::Smtp, Src::Internal, Sni::Internal).await;
    c.send("AUTH FOO").await;
    assert_eq!(c.line().await, "504 5.5.4 Unrecognized authentication type");
    c.send("AUTH PLAIN").await;
    assert_eq!(c.line().await, "334 ");
    c.send("*").await;
    assert_eq!(
        c.line().await,
        "501 5.5.2 Invalid or cancelled authentication response"
    );
    c.send(&format!("AUTH PLAIN {good}")).await;
    assert_eq!(c.line().await, "235 2.7.0 Authentication successful");

    let mut c = h.ready(Kind::Sieve, Src::Internal, Sni::Internal).await;
    c.send("AUTHENTICATE \"FOO\"").await;
    assert_eq!(
        c.line().await,
        "NO \"Authentication mechanism not supported\""
    );
    c.send("AUTHENTICATE \"PLAIN\"").await;
    assert_eq!(c.line().await, "\"\"");
    c.send("\"*\"").await;
    assert_eq!(c.line().await, "NO \"Invalid authentication response\"");
    c.send(&format!("AUTHENTICATE \"PLAIN\" \"{good}\"")).await;
    assert_eq!(c.line().await, "OK \"Logged in.\"");

    h.proxy.wait_authresults(9).await;
    let per_proto = [
        ("other", "protocol"),
        ("other", "protocol"),
        ("PLAIN", "ok"),
    ];
    let want: Vec<(String, String)> = per_proto
        .repeat(3)
        .into_iter()
        .map(|(m, r)| (m.to_string(), r.to_string()))
        .collect();
    assert_eq!(reasons(&h), want);
    for kind in Kind::ALL {
        assert_eq!(
            h.proxy.metric(&preauth_aborts(kind, "internal")).await,
            0,
            "{kind:?}"
        );
    }

    // Three attempts without a credential: the connection ends as a
    // pre-auth abort.
    let mut c = h.ready(Kind::Smtp, Src::Internal, Sni::Internal).await;
    for _ in 0..3 {
        c.send("AUTH FOO").await;
        assert_eq!(c.line().await, "504 5.5.4 Unrecognized authentication type");
    }
    c.expect_end(Kind::Smtp).await;
    h.proxy.wait_authresults(12).await;
    assert_eq!(
        h.proxy
            .metric(&preauth_aborts(Kind::Smtp, "internal"))
            .await,
        1
    );
}

/// An outage ends the session although attempts are left: another attempt
/// would meet it too.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_outage_ends_the_session() {
    let h = Harness::start_with(opts(3)).await;
    for kind in Kind::ALL {
        let mut c = h.ready(kind, Src::Internal, Sni::Internal).await;
        c.send(&plain_command(kind, "a", "unavail@example.test", "pw"))
            .await;
        let reply = c.line().await;
        assert!(
            reply.contains("UNAVAILABLE")
                || reply.starts_with("454 ")
                || reply.contains("TRYLATER"),
            "{kind:?}: {reply}"
        );
        c.expect_end(kind).await;
    }
}

/// A client that gives up after a refusal closes the connection: no further
/// `authresult` line, no pre-auth abort.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn closing_after_a_refusal_adds_no_line() {
    let h = Harness::start_with(opts(3)).await;
    for kind in Kind::ALL {
        let mut c = h.ready(kind, Src::Internal, Sni::Internal).await;
        c.send(&plain_command(kind, "a", "reject@example.test", "pw"))
            .await;
        assert_eq!(untagged(kind, &c.line().await), refusal(kind), "{kind:?}");
        drop(c);
    }
    h.proxy.wait_authresults(3).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let ars = h.proxy.authresults();
    assert!(
        ars.len() == 3 && ars.iter().all(|a| a.reason == "backend_reject"),
        "{ars:?}"
    );
    for kind in Kind::ALL {
        assert_eq!(h.proxy.metric(&preauth_aborts(kind, "internal")).await, 0);
    }
}

/// Three refusals within a minute block the source; not exempt, so the
/// harness sources can be blocked.
const RL: &str =
    "failures = 3\nwindow_secs = 60\nblock_secs = 60\nmax_block_secs = 60\nexempt_networks = []\n";

/// Each attempt counts for the rate limit on its own: once the attempts of
/// one connection have blocked the source, its next credential is not
/// judged and the connection closes without an answer, as a new connection
/// would be closed at accept.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_attempt_counts_for_the_rate_limit() {
    for kind in Kind::ALL {
        let h = Harness::start_with(Opts {
            ratelimit: Some(RL.into()),
            ..opts(5)
        })
        .await;
        let mut c = h.ready(kind, Src::Internal, Sni::Internal).await;
        for n in 0..3 {
            c.send(&plain_command(
                kind,
                "a",
                "reject@example.test",
                &format!("pw{n}"),
            ))
            .await;
            assert_eq!(
                untagged(kind, &c.line().await),
                refusal(kind),
                "{kind:?} {n}"
            );
        }
        h.proxy.wait_logs("authlog: ratelimit", 1).await;
        c.send(&plain_command(kind, "b", "bob@example.test", "pw"))
            .await;
        c.expect_closed().await;
        assert_eq!(h.backend(kind).sessions().len(), 3, "{kind:?}");
        assert_eq!(h.proxy.authresults().len(), 3, "{kind:?}");
        assert_eq!(
            h.proxy
                .metric(&format!(
                    "mail_auth_proxy_ratelimit_blocks_total{{proto=\"{}\"}}",
                    kind.label()
                ))
                .await,
            1,
            "{kind:?}"
        );
    }
}

/// A block that other connections started applies to an open connection's
/// next attempt as well.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_block_from_other_connections_applies() {
    let h = Harness::start_with(Opts {
        ratelimit: Some(RL.into()),
        ..opts(3)
    })
    .await;
    let mut open = h.ready(Kind::Imap, Src::Internal, Sni::Internal).await;
    for n in 0..3 {
        let (_c, reply) = h
            .auth(
                Kind::Smtp,
                Src::Internal,
                Sni::Internal,
                "PLAIN",
                &plain("reject@example.test", &format!("pw{n}")),
            )
            .await;
        assert_eq!(reply, refusal(Kind::Smtp));
    }
    h.proxy.wait_logs("authlog: ratelimit", 1).await;
    open.send(&plain_command(Kind::Imap, "a", "bob@example.test", "pw"))
        .await;
    open.expect_closed().await;
    assert!(h.imap_be.sessions().is_empty());
}

/// On one connection, a password the gate refuses (unknown domain) and one
/// the backend rejects get the same answer, both no earlier than the failure
/// delay, and both leave the same attempts: the next attempt tells nothing
/// about the previous account.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refusals_look_alike_across_attempts() {
    const DELAY: Duration = Duration::from_millis(300);
    let h = Harness::start_with(Opts {
        legacy: Some(format!(
            "[legacy]\nallowed_domains = [\"example.test\"]\nfailure_delay_ms = {}\n[[legacy.rules]]\nname = \"all\"\nnetworks = [\"127.0.0.0/8\"]\n",
            DELAY.as_millis()
        )),
        ..opts(3)
    })
    .await;
    for kind in Kind::ALL {
        for order in [
            ["a@unknown.test", "reject@example.test"],
            ["reject@example.test", "a@unknown.test"],
        ] {
            let mut c = h.ready(kind, Src::Internal, Sni::Internal).await;
            for user in order {
                let started = Instant::now();
                c.send(&plain_command(kind, "a", user, "pw")).await;
                assert_eq!(
                    untagged(kind, &c.line().await),
                    refusal(kind),
                    "{kind:?} {user}"
                );
                assert!(started.elapsed() >= DELAY, "{kind:?} {user}");
            }
            c.send(&plain_command(kind, "b", "bob@example.test", "pw"))
                .await;
            let reply = c.line().await;
            assert!(is_ok(kind, &reply), "{kind:?}: {reply}");
        }
    }
    let ars = h.proxy.wait_authresults(18).await;
    let got: Vec<&str> = ars.iter().map(|a| a.reason.as_str()).collect();
    assert_eq!(
        got,
        [
            "unknown_domain",
            "backend_reject",
            "ok",
            "backend_reject",
            "unknown_domain",
            "ok"
        ]
        .repeat(3)
    );
}

/// The pre-auth budget bounds the whole connection, not each attempt.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_preauth_budget_spans_all_attempts() {
    let h = Harness::start_with(Opts {
        preauth_secs: 2,
        ..opts(3)
    })
    .await;
    let mut c = h.ready(Kind::Imap, Src::Internal, Sni::Internal).await;
    c.send(&plain_command(Kind::Imap, "a", "reject@example.test", "pw"))
        .await;
    assert_eq!(untagged(Kind::Imap, &c.line().await), refusal(Kind::Imap));
    tokio::time::sleep(Duration::from_millis(2200)).await;
    assert!(c.try_line().await.is_none(), "still open past the budget");
    assert_eq!(h.imap_be.sessions().len(), 1);
}
