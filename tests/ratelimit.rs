//! The auth rate limit: a source with too many refused credentials gets its
//! new connections closed at accept (no TLS, no greeting, on every
//! listener) until the block ends. Outages, pre-auth aborts and a repeated
//! identical credential do not count; exempt sources never block.

mod common;
use common::*;
use std::time::Duration;

/// Three failures within a minute block for two seconds, no escalation;
/// loopback is not exempt, so the harness sources can be blocked.
const RL: &str =
    "failures = 3\nwindow_secs = 60\nblock_secs = 2\nmax_block_secs = 2\nexempt_networks = []\n";

fn opts(ratelimit: &str) -> Opts {
    Opts {
        ratelimit: Some(ratelimit.into()),
        ..Opts::default()
    }
}

/// A password from outside, where passwords are not offered:
/// `blocked_endpoint`, answered at once.
async fn refused_password(h: &Harness, kind: Kind, src: Src, pass: &str) {
    let (_c, reply) = h
        .auth(
            kind,
            src,
            Sni::Public,
            "PLAIN",
            &plain("bob@example.test", pass),
        )
        .await;
    assert!(!reply.is_empty());
}

fn blocks(proto: &str) -> String {
    format!("mail_auth_proxy_ratelimit_blocks_total{{proto=\"{proto}\"}}")
}

/// The part of the `ratelimit` log line after the timestamp.
fn ratelimit_lines(h: &Harness) -> Vec<String> {
    h.proxy
        .logs()
        .into_iter()
        .filter_map(|l| {
            l.find(" WARN authlog: ratelimit ")
                .map(|i| l[i + 1..].to_string())
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failures_block_the_source_until_the_block_ends() {
    let h = Harness::start_with(opts(RL)).await;

    refused_password(&h, Kind::Imap, Src::External, "guess1").await;
    refused_password(&h, Kind::Smtp, Src::External, "guess2").await;
    assert_eq!(h.proxy.count_logs("authlog: ratelimit"), 0);
    refused_password(&h, Kind::Imap, Src::External, "guess3").await;
    h.proxy.wait_logs("authlog: ratelimit", 1).await;
    assert_eq!(
        ratelimit_lines(&h),
        ["WARN authlog: ratelimit action=\"block\" proto=\"imap\" scope=\"external\" peer=127.0.0.2 source=127.0.0.2/32 failures=3 block_secs=2 strikes=1"]
    );
    // The three refusals are ordinary authresult lines.
    let ars = h.proxy.wait_authresults(3).await;
    assert!(
        ars.iter().all(|a| a.reason == "blocked_endpoint"),
        "{ars:?}"
    );

    // Every listener closes the source at accept: no TLS, no greeting.
    let mut imap = Client::connect(h.proxy.imap, Src::External).await;
    assert!(imap.try_tls(&h.pki, Sni::Public).await.is_err());
    let mut smtp = Client::connect(h.proxy.smtp, Src::External).await;
    smtp.expect_closed().await;
    let mut sieve = Client::connect(h.proxy.sieve, Src::External).await;
    sieve.expect_closed().await;

    // Another source is unaffected.
    let (_c, greeting) = h.imap(Src::Internal, Sni::Public).await;
    assert!(greeting.starts_with("* OK "), "{greeting}");

    let m = h.proxy.metrics().await;
    assert_eq!(m[&blocks("imap")], 1);
    assert_eq!(m[&blocks("smtp")], 1);
    assert_eq!(m[&blocks("sieve")], 1);
    assert_eq!(m["mail_auth_proxy_ratelimit_bans_total"], 1);
    assert_eq!(m["mail_auth_proxy_ratelimit_active_blocks"], 1);
    assert_eq!(
        m["mail_auth_proxy_connections_rejected_total{proto=\"imap\"}"], 0,
        "not a connection-limit rejection"
    );
    // A blocked connection writes no authresult.
    assert_eq!(h.proxy.authresults().len(), 3);

    // After the block the source is served again.
    tokio::time::sleep(Duration::from_millis(2200)).await;
    let (_c, greeting) = h.imap(Src::External, Sni::Public).await;
    assert!(greeting.starts_with("* OK "), "{greeting}");
}

/// An outage, a session without a credential and the same credential
/// again do not count.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn outages_aborts_and_repeats_do_not_count() {
    let h = Harness::start_with(opts(
        "failures = 2\nwindow_secs = 60\nblock_secs = 60\nexempt_networks = []\n",
    ))
    .await;

    // Backend outage on the token path: retry-later, no authresult.
    for i in 0..3 {
        let token = h.idp.mint(serde_json::json!({
            "email": "unavail-oauth@example.test",
            "jti": format!("t{i}"),
        }));
        let (_c, reply) = h
            .auth(
                Kind::Imap,
                Src::External,
                Sni::Public,
                "XOAUTH2",
                &xoauth2("unavail-oauth@example.test", &token),
            )
            .await;
        assert!(reply.contains("UNAVAILABLE"), "{reply}");
    }
    // Sessions that end before a credential (`protocol`): a mechanism the
    // proxy does not know.
    for i in 0..3 {
        h.auth(
            Kind::Imap,
            Src::External,
            Sni::Public,
            "CRAM-MD5",
            &b64(format!("x{i}")),
        )
        .await;
    }
    let ars = h.proxy.wait_authresults(3).await;
    assert!(ars.iter().all(|a| a.reason == "protocol"), "{ars:?}");
    // One refused password, repeated: counts once.
    for _ in 0..3 {
        refused_password(&h, Kind::Smtp, Src::External, "stale").await;
    }
    h.proxy.wait_authresults(6).await;

    let (_c, greeting) = h.imap(Src::External, Sni::Public).await;
    assert!(greeting.starts_with("* OK "), "{greeting}");
    assert_eq!(h.proxy.count_logs("authlog: ratelimit"), 0);

    // A second, different refusal reaches the threshold.
    refused_password(&h, Kind::Smtp, Src::External, "other").await;
    h.proxy.wait_logs("authlog: ratelimit", 1).await;
    let mut c = Client::connect(h.proxy.smtp, Src::External).await;
    c.expect_closed().await;
}

/// `exempt_internal`: sources in `scope.internal_networks` (the harness's
/// 127.0.0.1) are never blocked; others still are.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn internal_sources_can_be_exempt() {
    let h = Harness::start_with(opts(
        "failures = 2\nwindow_secs = 60\nblock_secs = 60\nexempt_internal = true\nexempt_networks = []\n",
    ))
    .await;
    for i in 0..4 {
        refused_password(&h, Kind::Imap, Src::Internal, &format!("in{i}")).await;
    }
    h.proxy.wait_authresults(4).await;
    let (_c, greeting) = h.imap(Src::Internal, Sni::Public).await;
    assert!(greeting.starts_with("* OK "), "{greeting}");

    for i in 0..2 {
        refused_password(&h, Kind::Imap, Src::External, &format!("out{i}")).await;
    }
    h.proxy.wait_logs("authlog: ratelimit", 1).await;
    let mut c = Client::connect(h.proxy.imap, Src::External).await;
    assert!(c.try_tls(&h.pki, Sni::Public).await.is_err());
    let (_c, greeting) = h.imap(Src::Internal, Sni::Public).await;
    assert!(greeting.starts_with("* OK "), "{greeting}");
}

/// The defaults exempt loopback: a local webmail or relay is never blocked.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn loopback_is_exempt_by_default() {
    let h = Harness::start_with(opts("failures = 2\n")).await;
    for i in 0..4 {
        refused_password(&h, Kind::Imap, Src::External, &format!("g{i}")).await;
    }
    h.proxy.wait_authresults(4).await;
    let (_c, greeting) = h.imap(Src::External, Sni::Public).await;
    assert!(greeting.starts_with("* OK "), "{greeting}");
    assert_eq!(h.proxy.count_logs("authlog: ratelimit"), 0);
}

/// `enabled = false`: nothing is counted or blocked.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disabled_never_blocks() {
    let h = Harness::start_with(opts(&format!("{RL}enabled = false\n"))).await;
    for i in 0..5 {
        refused_password(&h, Kind::Imap, Src::External, &format!("g{i}")).await;
    }
    h.proxy.wait_authresults(5).await;
    let (_c, greeting) = h.imap(Src::External, Sni::Public).await;
    assert!(greeting.starts_with("* OK "), "{greeting}");
    assert!(h.proxy.log_contains("auth rate limit disabled"));
}

/// A rejected token gets an RFC 7628 error challenge before the final
/// failure: the attempt still counts once and writes one authresult line.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bad_token_with_challenge_counts_once() {
    let h = Harness::start_with(opts(RL)).await;
    for i in 0..3 {
        let bad = h
            .idp
            .mint(serde_json::json!({"aud": "other", "jti": format!("b{i}")}));
        let (mut c, line) = h
            .auth(
                Kind::Imap,
                Src::External,
                Sni::Public,
                "OAUTHBEARER",
                &oauthbearer(EMAIL, &bad),
            )
            .await;
        challenge_data(Kind::Imap, &line);
        c.send(dummy_response("OAUTHBEARER")).await;
        let reply = c.line().await;
        assert!(reply.starts_with("a NO "), "{reply}");
        let ars = h.proxy.wait_authresults(i + 1).await;
        assert_eq!(ars.len(), i + 1, "one authresult per attempt");
        assert_eq!(ars[i].reason, "bad_token");
        if i < 2 {
            let (_c, greeting) = h.imap(Src::External, Sni::Public).await;
            assert!(
                greeting.starts_with("* OK "),
                "not blocked after {} failures",
                i + 1
            );
        }
    }
    h.proxy.wait_logs("authlog: ratelimit", 1).await;
    assert!(ratelimit_lines(&h)[0].contains(" failures=3 "));
    let mut c = Client::connect(h.proxy.imap, Src::External).await;
    assert!(c.try_tls(&h.pki, Sni::Public).await.is_err());
}
