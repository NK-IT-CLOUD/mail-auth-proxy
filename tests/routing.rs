//! Routes: one endpoint, several backends. A credential goes to the backend
//! of the first route that takes the domain of its validated identity (OAuth)
//! or login (password); issuer, audience and SNI only narrow a route. A
//! credential no route takes is refused like an unknown domain, without
//! backend contact.

mod common;
use common::*;
use std::time::{Duration, Instant};

const ONE: &str = "a@one.test";
const TWO: &str = "b@two.test";
const NOWHERE: &str = "c@nowhere.test";

/// Two mail systems, `one` and `two`, each with a backend per protocol; the
/// protocol sections name none.
fn two_systems(routes: &str) -> Opts {
    let mut named = Vec::new();
    for system in ["one", "two"] {
        for (kind, suffix) in [
            (Kind::Imap, "imap"),
            (Kind::Smtp, "smtp"),
            (Kind::Sieve, "sieve"),
        ] {
            let name: &'static str = Box::leak(format!("{system}-{suffix}").into_boxed_str());
            named.push((name, kind, Profile::default()));
        }
    }
    Opts {
        named,
        listener_backends: [Some(""); 3],
        routes: routes.to_string(),
        ..Opts::default()
    }
}

/// One route per system, by domain.
const BY_DOMAIN: &str = r#"
[[routes]]
name = "one"
domains = ["one.test"]
imap = "one-imap"
submission = "one-smtp"
sieve = "one-sieve"

[[routes]]
name = "two"
domains = ["two.test"]
imap = "two-imap"
submission = "two-smtp"
sieve = "two-sieve"
"#;

fn suffix(kind: Kind) -> &'static str {
    match kind {
        Kind::Imap => "imap",
        Kind::Smtp => "smtp",
        Kind::Sieve => "sieve",
    }
}

fn ok(kind: Kind, reply: &str) -> bool {
    match kind {
        Kind::Imap => reply.starts_with("a OK"),
        Kind::Smtp => reply.starts_with("235 "),
        Kind::Sieve => reply.starts_with("OK"),
    }
}

/// The logins the mock of `name` saw.
fn logins(h: &Harness, name: &str) -> Vec<String> {
    h.named(name)
        .sessions()
        .into_iter()
        .filter_map(|s| s.login)
        .collect()
}

/// Tokens and passwords of each domain reach that domain's backend, on every
/// protocol, and nothing reaches the other one. The `authresult` line names
/// the backend.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn credentials_go_to_the_route_of_their_domain() {
    let h = Harness::start_with(two_systems(BY_DOMAIN)).await;
    let mut n = 0;
    for kind in Kind::ALL {
        let token = h.idp.token(ONE);
        let (_c, reply) = h
            .auth(
                kind,
                Src::External,
                Sni::Public,
                "XOAUTH2",
                &xoauth2(ONE, &token),
            )
            .await;
        assert!(ok(kind, &reply), "{kind:?}: {reply}");
        let (_c, reply) = h
            .auth(
                kind,
                Src::Internal,
                Sni::Internal,
                "PLAIN",
                &plain(TWO, "pw"),
            )
            .await;
        assert!(ok(kind, &reply), "{kind:?}: {reply}");
        let (one, two) = (
            format!("one-{}", suffix(kind)),
            format!("two-{}", suffix(kind)),
        );
        assert_eq!(logins(&h, &one), [ONE], "{kind:?}");
        assert_eq!(logins(&h, &two), [TWO], "{kind:?}");
        n += 2;
        h.proxy.wait_logs("authresult", n).await;
        let ars = h.proxy.authresults();
        let last: Vec<(&str, &str, &str)> = ars[n - 2..]
            .iter()
            .map(|a| (a.reason.as_str(), a.user.as_str(), a.backend.as_str()))
            .collect();
        assert_eq!(last, [("ok", ONE, one.as_str()), ("ok", TWO, two.as_str())]);
    }
}

/// A credential no route takes: refused like an unknown domain, without
/// backend contact, with a WARN line and `route_misses_total`. The password
/// gets the same reply as a wrong one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unknown_tenant_is_an_unknown_domain() {
    let h = Harness::start_with(two_systems(BY_DOMAIN)).await;
    let token = h.idp.token(NOWHERE);
    let (_c, reply) = h
        .auth(
            Kind::Imap,
            Src::External,
            Sni::Public,
            "XOAUTH2",
            &xoauth2(NOWHERE, &token),
        )
        .await;
    assert_eq!(reply, "a NO [AUTHENTICATIONFAILED] backend rejected token");
    let (_c, refused) = h
        .auth(
            Kind::Imap,
            Src::Internal,
            Sni::Internal,
            "PLAIN",
            &plain(NOWHERE, "pw"),
        )
        .await;
    let (_c, wrong) = h
        .auth(
            Kind::Imap,
            Src::Internal,
            Sni::Internal,
            "PLAIN",
            &plain("reject@one.test", "pw"),
        )
        .await;
    assert_eq!(refused, wrong);
    h.proxy.wait_logs("authresult", 3).await;
    let ars = h.proxy.authresults();
    let got: Vec<(&str, &str, &str)> = ars
        .iter()
        .map(|a| (a.reason.as_str(), a.user.as_str(), a.backend.as_str()))
        .collect();
    assert_eq!(
        got,
        [
            ("unknown_domain", NOWHERE, ""),
            ("unknown_domain", NOWHERE, ""),
            ("backend_reject", "reject@one.test", "one-imap"),
        ]
    );
    assert!(
        ars[1].pwfp.len() == 16,
        "a refused password keeps its fingerprint"
    );
    for name in ["one-imap", "two-imap"] {
        assert!(!logins(&h, name).contains(&NOWHERE.to_string()), "{name}");
    }
    assert_eq!(h.proxy.count_logs("no route for the login's domain"), 2);
    assert!(h.proxy.log_contains("domain=nowhere.test"));
    assert_eq!(
        h.proxy
            .metric(r#"mail_auth_proxy_route_misses_total{proto="imap"}"#)
            .await,
        2
    );
    assert_eq!(
        h.proxy
            .metric(r#"mail_auth_proxy_auth_refusals_total{proto="imap",reason="unknown_domain"}"#)
            .await,
        2
    );
}

/// A catch-all route takes every other domain and a login without one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn catch_all_takes_the_rest() {
    let routes = format!(
        "{BY_DOMAIN}\n[[routes]]\nname = \"rest\"\ndomains = [\"*\"]\nimap = \"two-imap\"\n"
    );
    let h = Harness::start_with(two_systems(&routes)).await;
    for user in [NOWHERE, "bare"] {
        let (_c, reply) = h
            .auth(
                Kind::Imap,
                Src::Internal,
                Sni::Internal,
                "PLAIN",
                &plain(user, "pw"),
            )
            .await;
        assert!(reply.starts_with("a OK"), "{user}: {reply}");
    }
    assert_eq!(logins(&h, "two-imap"), [NOWHERE, "bare"]);
    // The catch-all serves IMAP only: submission has no route for it.
    let (_c, reply) = h
        .auth(
            Kind::Smtp,
            Src::Internal,
            Sni::Internal,
            "PLAIN",
            &plain(NOWHERE, "pw"),
        )
        .await;
    assert_eq!(reply, "535 5.7.8 Authentication credentials invalid");
}

/// Audience and SNI narrow a route: a token for `one.test` goes to `two`
/// only with the audience `partner`, a login for `two.test` only with the
/// public server name.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn audience_and_sni_narrow_a_route() {
    let routes = r#"
[[routes]]
name = "partner"
domains = ["one.test"]
audiences = ["partner"]
imap = "two-imap"

[[routes]]
name = "one"
domains = ["one.test"]
imap = "one-imap"

[[routes]]
name = "two"
domains = ["two.test"]
sni = ["mail.public.test"]
imap = "two-imap"
"#;
    let mut opts = two_systems(routes);
    // Only IMAP has routes; the other sections keep their own mocks.
    opts.listener_backends = [Some(""), None, None];
    opts.named.retain(|(name, ..)| name.ends_with("-imap"));
    let h = Harness::start_with(opts).await;
    let plain_token = h.idp.token(ONE);
    let partner = h.idp.mint(serde_json::json!({
        "email": ONE,
        "aud": [AUDIENCE, "partner"],
    }));
    for token in [plain_token, partner] {
        let (_c, reply) = h
            .auth(
                Kind::Imap,
                Src::External,
                Sni::Public,
                "XOAUTH2",
                &xoauth2(ONE, &token),
            )
            .await;
        assert!(reply.starts_with("a OK"), "{reply}");
    }
    assert_eq!(logins(&h, "one-imap"), [ONE]);
    assert_eq!(logins(&h, "two-imap"), [ONE]);

    let token = h.idp.token(TWO);
    let (_c, reply) = h
        .auth(
            Kind::Imap,
            Src::External,
            Sni::Public,
            "XOAUTH2",
            &xoauth2(TWO, &token),
        )
        .await;
    assert!(reply.starts_with("a OK"), "{reply}");
    let (_c, reply) = h
        .auth(
            Kind::Imap,
            Src::External,
            Sni::None,
            "XOAUTH2",
            &xoauth2(TWO, &token),
        )
        .await;
    assert_eq!(
        reply, "a NO [AUTHENTICATIONFAILED] backend rejected token",
        "no SNI, no route"
    );
    assert_eq!(logins(&h, "two-imap"), [ONE, TWO]);
}

/// A section may name a `[backends]` entry instead of a table of its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_section_names_its_backend() {
    let h = Harness::start_with(Opts {
        named: vec![("mailstore", Kind::Imap, Profile::default())],
        listener_backends: [Some("mailstore"), None, None],
        ..Opts::default()
    })
    .await;
    let token = h.idp.token(EMAIL);
    let (_c, reply) = h
        .auth(
            Kind::Imap,
            Src::External,
            Sni::Public,
            "XOAUTH2",
            &xoauth2(EMAIL, &token),
        )
        .await;
    assert!(reply.starts_with("a OK"), "{reply}");
    assert_eq!(logins(&h, "mailstore"), [EMAIL]);
    assert!(h.imap_be.sessions().is_empty());
    h.proxy.wait_logs("authresult", 1).await;
    assert_eq!(h.proxy.authresults()[0].backend, "mailstore");
    assert!(
        h.proxy.log_contains("backends=[\"mailstore="),
        "startup line names the backend"
    );
}

/// The EHLO reply after TLS lists only what every submission backend offers,
/// with the smallest SIZE: the client does not send EHLO again after AUTH
/// and uses the list against whichever backend it is routed to.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ehlo_lists_what_every_backend_offers() {
    let mut opts = two_systems(BY_DOMAIN);
    opts.submission_extra = "capability_cache_secs = 1";
    let h = Harness::start_with(opts).await;
    // The second backend offers less and a smaller SIZE: the list is not
    // the first backend's.
    *h.named("two-smtp").smtp_ehlo.lock().unwrap() = Some(
        ["PIPELINING", "SIZE 1000", "8BITMIME", "ENHANCEDSTATUSCODES"]
            .map(String::from)
            .to_vec(),
    );
    // The startup probes cached the defaults; the next EHLO after the cache
    // time probes again.
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let (_c, ehlo) = h.smtp(Src::External, Sni::Public).await;
    assert_eq!(
        ehlo,
        [
            format!("250-{HOSTNAME}"),
            "250-PIPELINING".to_string(),
            "250-SIZE 1000".to_string(),
            "250-ENHANCEDSTATUSCODES".to_string(),
            "250-8BITMIME".to_string(),
            "250 AUTH XOAUTH2 OAUTHBEARER".to_string(),
        ]
    );
}

/// A reload moves a domain to another backend for new logins; an open
/// session stays where it is.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reload_moves_a_domain() {
    let h = Harness::start_with(two_systems(BY_DOMAIN)).await;
    let token = h.idp.token(ONE);
    let (mut open, reply) = h
        .auth(
            Kind::Imap,
            Src::External,
            Sni::Public,
            "XOAUTH2",
            &xoauth2(ONE, &token),
        )
        .await;
    assert!(reply.starts_with("a OK"), "{reply}");
    let moved = BY_DOMAIN
        .replace("domains = [\"one.test\"]", "domains = [\"old.test\"]")
        .replace(
            "domains = [\"two.test\"]",
            "domains = [\"two.test\", \"one.test\"]",
        );
    h.proxy
        .reload(&h.config(&two_systems(&moved)))
        .await
        .unwrap();
    let (_c, reply) = h
        .auth(
            Kind::Imap,
            Src::External,
            Sni::Public,
            "XOAUTH2",
            &xoauth2(ONE, &token),
        )
        .await;
    assert!(reply.starts_with("a OK"), "{reply}");
    assert_eq!(logins(&h, "one-imap"), [ONE]);
    assert_eq!(logins(&h, "two-imap"), [ONE]);
    // The open session still talks to its backend.
    open.send("b NOOP").await;
    assert_eq!(open.line().await, "ECHO b NOOP");
    assert_eq!(h.named("one-imap").sessions()[0].relayed, ["b NOOP"]);
    assert!(
        h.proxy.log_contains("changed=[\"routes\"]"),
        "{:?}",
        h.proxy.logs()
    );
}

/// Refusal timing per backend, end to end: `fast` rejects at once, `slow`
/// after 800 ms. A throttled `slow` account is refused as late as a wrong
/// password at `slow`, a throttled `fast` account as early as at `fast`, and
/// a login no route takes waits for the slower one. One latency pool for
/// both backends would answer the `slow` refusal at the mixed median, well
/// before a wrong password there: an account oracle.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refusal_timing_follows_the_routed_backend() {
    const DELAY_MS: u64 = 100;
    let routes = r#"
[[routes]]
name = "fast"
domains = ["fast.test"]
imap = "fast"

[[routes]]
name = "slow"
domains = ["slow.test"]
imap = "slow"
"#;
    let h = Harness::start_with(Opts {
        named: vec![
            ("fast", Kind::Imap, Profile::default()),
            ("slow", Kind::Imap, Profile::default()),
        ],
        listener_backends: [Some(""), None, None],
        routes: routes.to_string(),
        legacy: Some(format!(
            "[legacy]\nfailure_delay_ms = {DELAY_MS}\nthrottle = {{ failures = 1, window_secs = 3600 }}\n[[legacy.rules]]\nname = \"all\"\nnetworks = [\"127.0.0.0/8\"]\n"
        )),
        ..Opts::default()
    })
    .await;
    let attempt = |user: String| {
        let h = &h;
        async move {
            let mut c = h.ready(Kind::Imap, Src::Internal, Sni::None).await;
            let t0 = Instant::now();
            c.send(&format!("a LOGIN {user} pw")).await;
            let reply = c.line().await;
            let took = t0.elapsed();
            assert!(
                reply.starts_with("a NO [AUTHENTICATIONFAILED]"),
                "{user}: {reply}"
            );
            took
        }
    };
    // Warm-up: more fast rejections than slow ones, so a mixed median would
    // be the fast one.
    for i in 0..6 {
        attempt(format!("reject-w{i}@fast.test")).await;
    }
    for i in 0..3 {
        attempt(format!("slowreject-w{i}@slow.test")).await;
    }
    // Throttled accounts: one rejection each, then refused by the throttle.
    attempt("reject-t@fast.test".into()).await;
    attempt("slowreject-t@slow.test".into()).await;
    let (mut slow_refused, mut slow_rejected, mut fast_refused, mut unrouted) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    for i in 0..4 {
        slow_refused.push(attempt("slowreject-t@slow.test".into()).await);
        slow_rejected.push(attempt(format!("slowreject-{i}@slow.test")).await);
        fast_refused.push(attempt("reject-t@fast.test".into()).await);
        unrouted.push(attempt(format!("u{i}@nowhere.test")).await);
    }
    eprintln!(
        "slow refused {slow_refused:?}, slow rejected {slow_rejected:?}, fast refused {fast_refused:?}, unrouted {unrouted:?}"
    );
    let floor = SLOW_REJECT - Duration::from_millis(50);
    assert!(
        slow_refused.iter().all(|t| *t >= floor),
        "a slow refusal waits like a slow rejection: {slow_refused:?}"
    );
    assert!(
        slow_rejected.iter().all(|t| *t >= SLOW_REJECT),
        "{slow_rejected:?}"
    );
    assert!(
        fast_refused.iter().all(|t| *t < SLOW_REJECT / 2),
        "a fast refusal does not wait for the slow backend: {fast_refused:?}"
    );
    assert!(
        unrouted.iter().all(|t| *t >= floor),
        "before the route the slowest backend counts: {unrouted:?}"
    );
    // The throttle refused (the backend saw each throttled account once).
    assert_eq!(
        logins(&h, "slow")
            .iter()
            .filter(|l| *l == "slowreject-t@slow.test")
            .count(),
        1
    );
}
