//! Backend pools: several addresses of one backend. A login moves to the
//! next address only while no credential has been sent; after the credential
//! a temporary failure is an outage of that login. Addresses go down after
//! `FALL` failures in a row and come back after `RISE` successes, from the
//! logins or from active checks; when all are down one login at a time tries
//! one. An outage is never a failed login.

mod common;
use common::*;
use std::time::Duration;

/// An IMAP backend `store` with the addresses of the mocks `a` and `b`.
fn imap_pool(extra: &'static str) -> Opts {
    Opts {
        named: vec![
            ("a", Kind::Imap, Profile::default()),
            ("b", Kind::Imap, Profile::default()),
        ],
        pools: vec![("store", vec!["a", "b"], extra)],
        listener_backends: [Some("store"), None, None],
        ..Opts::default()
    }
}

async fn token_login(h: &Harness, user: &str) -> String {
    let token = h.idp.token(user);
    let (_c, reply) = h
        .auth(
            Kind::Imap,
            Src::External,
            Sni::Public,
            "XOAUTH2",
            &xoauth2(user, &token),
        )
        .await;
    reply
}

/// Sessions (with a login) each mock got.
fn logins(h: &Harness, name: &str) -> usize {
    h.named(name).sessions().len()
}

fn metric_key(family: &str, labels: &str) -> String {
    format!("mail_auth_proxy_{family}{{{labels}}}")
}

async fn address_metric(h: &Harness, family: &str, mock: &str, stage: Option<&str>) -> u64 {
    let address = h.named(mock).addr;
    let labels = match stage {
        Some(s) => format!("backend=\"store\",address=\"{address}\",stage=\"{s}\""),
        None => format!("backend=\"store\",address=\"{address}\""),
    };
    h.proxy.metric(&metric_key(family, &labels)).await
}

/// `a` closes every connection at accept: the login moves to `b`
/// and succeeds, a failover; after `FALL` failures `a` is down and logins go
/// straight to `b`. No failed login is logged, the `authresult` names the
/// backend.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fails_over_before_the_credential() {
    let h = Harness::start_with(imap_pool("")).await;
    h.named("a")
        .refuse
        .store(true, std::sync::atomic::Ordering::SeqCst);
    for _ in 0..4 {
        let reply = token_login(&h, EMAIL).await;
        assert!(reply.starts_with("a OK"), "{reply}");
    }
    assert_eq!(logins(&h, "a"), 0);
    assert_eq!(logins(&h, "b"), 4);
    // Closed before the implicit-TLS handshake: the TLS stage.
    assert_eq!(
        address_metric(&h, "backend_address_errors_total", "a", Some("tls")).await,
        3
    );
    assert_eq!(address_metric(&h, "backend_up", "a", None).await, 0);
    assert_eq!(address_metric(&h, "backend_up", "b", None).await, 1);
    assert_eq!(
        h.proxy
            .metric(&metric_key("backend_failovers_total", "backend=\"store\""))
            .await,
        3
    );
    assert_eq!(
        h.proxy
            .metric(&metric_key(
                "backend_sessions_total",
                "proto=\"imap\",backend=\"store\""
            ))
            .await,
        4
    );
    assert_eq!(
        h.proxy
            .metric(r#"mail_auth_proxy_backend_errors_total{proto="imap"}"#)
            .await,
        0
    );
    h.proxy.wait_logs("authresult", 4).await;
    assert!(h
        .proxy
        .authresults()
        .iter()
        .all(|a| a.reason == "ok" && a.backend == "store"));
    assert_eq!(
        h.proxy
            .count_logs("backend address failed; trying the next"),
        3
    );
}

/// A temporary failure after the credential (`NO [UNAVAILABLE]`) is an
/// outage of that login: the credential goes to no second address, no
/// `authresult` line, the address stays up.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_failover_after_the_credential() {
    let h = Harness::start_with(imap_pool("")).await;
    let reply = token_login(&h, "unavail@example.test").await;
    assert_eq!(reply, "a NO [UNAVAILABLE] Backend temporarily unavailable");
    assert_eq!(logins(&h, "a"), 1);
    assert_eq!(logins(&h, "b"), 0, "the credential went to one address");
    assert_eq!(
        address_metric(
            &h,
            "backend_address_errors_total",
            "a",
            Some("auth_tempfail")
        )
        .await,
        1
    );
    assert_eq!(address_metric(&h, "backend_up", "a", None).await, 1);
    assert_eq!(
        h.proxy
            .metric(r#"mail_auth_proxy_backend_errors_total{proto="imap"}"#)
            .await,
        1
    );
    assert!(h.proxy.authresults().is_empty());
}

/// Both addresses down: a login is an outage (retry-later, no failed login).
/// When they answer again, the next login tries the longest-failed one as a
/// trial and succeeds; `RISE` successes bring it up.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn all_down_then_back() {
    let h = Harness::start_with(imap_pool("")).await;
    for m in ["a", "b"] {
        h.named(m)
            .refuse
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
    // Each login tries both (a, then b): after three logins both are down.
    for _ in 0..3 {
        let reply = token_login(&h, EMAIL).await;
        assert_eq!(reply, "a NO [UNAVAILABLE] Backend temporarily unavailable");
    }
    for m in ["a", "b"] {
        assert_eq!(address_metric(&h, "backend_up", m, None).await, 0, "{m}");
    }
    assert!(
        h.proxy.authresults().is_empty(),
        "an outage is no failed login"
    );
    for m in ["a", "b"] {
        h.named(m)
            .refuse
            .store(false, std::sync::atomic::Ordering::SeqCst);
    }
    for _ in 0..2 {
        let reply = token_login(&h, EMAIL).await;
        assert!(reply.starts_with("a OK"), "{reply}");
    }
    // `a` failed first, so it is the trial both times, and up again.
    assert_eq!(logins(&h, "a"), 2);
    assert_eq!(address_metric(&h, "backend_up", "a", None).await, 1);
    assert_eq!(address_metric(&h, "backend_up", "b", None).await, 0);
}

/// Active checks (`health_check_secs`) find an address that is back and
/// bring it up without a login; failover sends logins to the first address
/// again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn active_checks_bring_an_address_back() {
    let h = Harness::start_with(imap_pool("health_check_secs = 1")).await;
    h.named("a")
        .refuse
        .store(true, std::sync::atomic::Ordering::SeqCst);
    // The checks alone mark it down.
    wait_for(|| async { address_metric(&h, "backend_up", "a", None).await == 0 }).await;
    assert!(token_login(&h, EMAIL).await.starts_with("a OK"));
    assert_eq!((logins(&h, "a"), logins(&h, "b")), (0, 1));
    h.named("a")
        .refuse
        .store(false, std::sync::atomic::Ordering::SeqCst);
    wait_for(|| async { address_metric(&h, "backend_up", "a", None).await == 1 }).await;
    assert!(token_login(&h, EMAIL).await.starts_with("a OK"));
    assert_eq!((logins(&h, "a"), logins(&h, "b")), (1, 1));
    // The checks sent no credential: only the proxy's LOCAL header, no login.
    assert!(
        h.named("a")
            .seen()
            .iter()
            .filter(|s| s.login.is_none())
            .count()
            >= 2
    );
}

async fn wait_for<F, Fut>(cond: F)
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    for _ in 0..100 {
        if cond().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("condition not reached within 10 s");
}

/// `hash`: each user stays on one address, users spread over both.
/// `round_robin`: logins alternate.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hash_and_round_robin() {
    let h = Harness::start_with(imap_pool("strategy = \"hash\"")).await;
    let users: Vec<String> = (0..12).map(|i| format!("user{i}@example.test")).collect();
    let mut first = Vec::new();
    for u in &users {
        assert!(token_login(&h, u).await.starts_with("a OK"));
        let at_a = h
            .named("a")
            .sessions()
            .iter()
            .any(|s| s.login.as_deref() == Some(u));
        first.push(at_a);
    }
    assert!(
        first.iter().any(|a| *a) && first.iter().any(|a| !*a),
        "both get users: {first:?}"
    );
    for (u, at_a) in users.iter().zip(&first) {
        assert!(token_login(&h, u).await.starts_with("a OK"));
        let mock = if *at_a { "a" } else { "b" };
        let n = h
            .named(mock)
            .sessions()
            .iter()
            .filter(|s| s.login.as_deref() == Some(u))
            .count();
        assert_eq!(n, 2, "{u} stays on {mock}");
    }

    let h = Harness::start_with(imap_pool("strategy = \"round_robin\"")).await;
    for _ in 0..4 {
        assert!(token_login(&h, EMAIL).await.starts_with("a OK"));
    }
    assert_eq!((logins(&h, "a"), logins(&h, "b")), (2, 2));
}

/// Submission and ManageSieve fail over the same way, their capability
/// probes included.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn submission_and_sieve_fail_over() {
    let h = Harness::start_with(Opts {
        named: vec![
            ("s1", Kind::Smtp, Profile::default()),
            ("s2", Kind::Smtp, Profile::default()),
            ("v1", Kind::Sieve, Profile::default()),
            ("v2", Kind::Sieve, Profile::default()),
        ],
        pools: vec![
            ("smtp", vec!["s1", "s2"], ""),
            ("sieve-pool", vec!["v1", "v2"], ""),
        ],
        listener_backends: [None, Some("smtp"), Some("sieve-pool")],
        ..Opts::default()
    })
    .await;
    for m in ["s1", "v1"] {
        h.named(m)
            .refuse
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
    let token = h.idp.token(EMAIL);
    for kind in [Kind::Smtp, Kind::Sieve] {
        let (_c, reply) = h
            .auth(
                kind,
                Src::External,
                Sni::Public,
                "XOAUTH2",
                &xoauth2(EMAIL, &token),
            )
            .await;
        let ok = match kind {
            Kind::Smtp => reply.starts_with("235 "),
            _ => reply.starts_with("OK"),
        };
        assert!(ok, "{kind:?}: {reply}");
    }
    assert_eq!(h.named("s2").sessions().len(), 1);
    assert_eq!(h.named("v2").sessions().len(), 1);
    assert!(h.named("s1").sessions().is_empty());
    assert!(h.named("v1").sessions().is_empty());
}

/// A reload that keeps the backend keeps each address's health: a down
/// address stays down.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reload_keeps_health() {
    let h = Harness::start_with(imap_pool("")).await;
    h.named("a")
        .refuse
        .store(true, std::sync::atomic::Ordering::SeqCst);
    for _ in 0..3 {
        assert!(token_login(&h, EMAIL).await.starts_with("a OK"));
    }
    assert_eq!(address_metric(&h, "backend_up", "a", None).await, 0);
    let mut opts = imap_pool("");
    opts.hostname = "mx.test";
    h.proxy.reload(&h.config(&opts)).await.unwrap();
    assert_eq!(address_metric(&h, "backend_up", "a", None).await, 0);
    assert_eq!(
        h.proxy
            .metric(&metric_key("backend_failovers_total", "backend=\"store\""))
            .await,
        3,
        "counters go on"
    );
}
