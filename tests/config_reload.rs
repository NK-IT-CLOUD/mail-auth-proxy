//! SIGHUP reloads the configuration file: a valid one that changes nothing
//! bound at startup is used by every connection accepted afterwards, while
//! connections already open keep the configuration they were accepted with
//! and are never closed. A broken file, or one that changes a listener or
//! the metrics endpoint, is refused as a whole and the configuration in use
//! stays.

mod common;
use common::*;
use std::time::{Duration, Instant};

/// A second issuer, served by the harness IdP under another path.
const OTHER: &str = "https://idp.test/realms/other";

const RELOADS_OK: &str = "mail_auth_proxy_config_reload_total{result=\"ok\"}";
const RELOADS_ERROR: &str = "mail_auth_proxy_config_reload_total{result=\"error\"}";
const LAST_RELOAD: &str = "mail_auth_proxy_config_last_reload_success_timestamp_seconds";

/// `limits.max_preauth_per_ip` etc. on top of the defaults.
fn with(f: impl FnOnce(&mut Opts)) -> Opts {
    let mut o = Opts::default();
    f(&mut o);
    o
}

/// Reload `opts` and require success.
async fn reload(h: &Harness, opts: &Opts) {
    reload_text(h, &h.config(opts)).await;
}

async fn reload_text(h: &Harness, text: &str) {
    if let Err(line) = h.proxy.reload(text).await {
        panic!("reload refused: {line}\n{}", h.proxy.logs().join("\n"));
    }
}

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
    assert!(reply.starts_with("a OK"), "{reply}");
    relays(&mut c, "n0").await;
    c
}

/// The session relays a line to the backend and back.
async fn relays(c: &mut Client, tag: &str) {
    c.send(&format!("{tag} NOOP")).await;
    assert_eq!(c.line().await, format!("ECHO {tag} NOOP"));
}

/// PLAIN from the password endpoint (127.0.0.1, internal SNI) on an open
/// IMAP connection; the reply.
async fn imap_plain(c: &mut Client, tag: &str, user: &str) -> String {
    c.send(&format!("{tag} AUTHENTICATE PLAIN {}", plain(user, "pw")))
        .await;
    c.line().await
}

/// The legacy rules are what a new connection offers and allows; a
/// connection accepted before the reload keeps the rules it was accepted
/// with (for its remaining pre-auth time), and a logged-in session goes on.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn legacy_rules_apply_to_new_connections() {
    let h = Harness::start().await;
    let (mut before, greeting) = h.imap(Src::Internal, Sni::Internal).await;
    assert!(greeting.contains("AUTH=PLAIN"), "{greeting}");
    let mut session = h.imap(Src::Internal, Sni::Internal).await.0;
    assert!(imap_plain(&mut session, "s", "alice@example.test")
        .await
        .starts_with("s OK"));
    relays(&mut session, "s1").await;

    // No rule left: OAuth only.
    reload(&h, &with(|o| o.legacy = Some(String::new()))).await;
    let (mut after, greeting) = h.imap(Src::Internal, Sni::Internal).await;
    assert!(!greeting.contains("AUTH=PLAIN"), "{greeting}");
    assert_eq!(
        imap_plain(&mut after, "a", "alice@example.test").await,
        "a NO password authentication not available on this endpoint"
    );
    // Accepted under the old rules: they apply to it until it ends.
    assert!(imap_plain(&mut before, "b", "bob@example.test")
        .await
        .starts_with("b OK"));
    relays(&mut before, "b1").await;
    relays(&mut session, "s2").await;

    // A rule restricted to one user: others are refused on new connections.
    let one_user = "[[legacy.rules]]\nname = \"one\"\nnetworks = [\"127.0.0.1/32\"]\nusers = [\"carol@example.test\"]\n".to_string();
    reload(&h, &with(|o| o.legacy = Some(one_user))).await;
    let mut c = h.imap(Src::Internal, Sni::Public).await.0;
    assert!(imap_plain(&mut c, "c", "carol@example.test")
        .await
        .starts_with("c OK"));
    let mut c = h.imap(Src::Internal, Sni::Public).await.0;
    assert!(imap_plain(&mut c, "d", "dave@example.test")
        .await
        .starts_with("d NO"));
    assert_eq!(h.proxy.authresult_rules().last().unwrap(), "");
    relays(&mut session, "s3").await;
}

/// `server.hostname` names new connections; an open one keeps its name.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hostname_applies_to_new_connections() {
    let h = Harness::start().await;
    let mut old = Client::connect(h.proxy.smtp, Src::External).await;
    assert_eq!(old.line().await, "220 proxy.test ESMTP");

    reload(&h, &with(|o| o.hostname = "mx.test")).await;
    let mut new = Client::connect(h.proxy.smtp, Src::External).await;
    assert_eq!(new.line().await, "220 mx.test ESMTP");
    let (_c, greeting) = h.imap(Src::External, Sni::Public).await;
    assert!(greeting.ends_with("] mx.test ready"), "{greeting}");
    old.send("EHLO client.test").await;
    assert_eq!(old.smtp_reply().await[0], "250-proxy.test");
}

/// `[limits]`: a lower per-source limit refuses new connections while the
/// open ones stay; more authentication attempts apply to new connections.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn limits_apply_to_new_connections() {
    let h = Harness::start().await;
    let (mut a, _) = h.imap(Src::External, Sni::Public).await;
    let (mut b, _) = h.imap(Src::External, Sni::Public).await;
    // Accepted with one attempt: it ends after a wrong password.
    let mut one_attempt = h.imap(Src::Internal, Sni::Internal).await.0;

    reload(
        &h,
        &with(|o| {
            o.max_preauth_per_ip = 1;
            o.max_auth_attempts = 3;
        }),
    )
    .await;
    let mut c = Client::connect(h.proxy.imap, Src::External).await;
    assert!(
        c.try_tls(&h.pki, Sni::Public).await.is_err(),
        "a third pre-auth connection from the source"
    );
    for (c, tag) in [(&mut a, "a"), (&mut b, "b")] {
        c.send(&format!("{tag} CAPABILITY")).await;
        assert!(c.line().await.starts_with("* CAPABILITY"), "{tag} open");
        assert!(c.line().await.starts_with(&format!("{tag} OK")));
    }
    assert_eq!(
        h.proxy
            .metric("mail_auth_proxy_connections_rejected_total{proto=\"imap\"}")
            .await,
        1
    );

    assert!(imap_plain(&mut one_attempt, "o", "reject@example.test")
        .await
        .starts_with("o NO"));
    one_attempt.expect_closed().await;
    // Its pre-auth slot is free again: three attempts on a new connection.
    let mut three = h.imap(Src::Internal, Sni::Internal).await.0;
    assert!(imap_plain(&mut three, "t", "reject@example.test")
        .await
        .starts_with("t NO"));
    assert!(imap_plain(&mut three, "u", "bob@example.test")
        .await
        .starts_with("u OK"));
}

/// Two failures within a minute block the source for a minute; loopback
/// is not exempt.
const BLOCKING: &str =
    "failures = 2\nwindow_secs = 60\nblock_secs = 60\nmax_block_secs = 60\nexempt_networks = []\n";

/// `[auth_ratelimit]`: running blocks survive a reload with other settings;
/// a network the new settings exempt is free at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ratelimit_keeps_blocks_and_takes_new_settings() {
    let opts = with(|o| o.ratelimit = Some(BLOCKING.into()));
    let h = Harness::start_with(opts.clone()).await;
    for pass in ["guess1", "guess2"] {
        let (_c, reply) = h
            .auth(
                Kind::Imap,
                Src::External,
                Sni::Public,
                "PLAIN",
                &plain("bob@example.test", pass),
            )
            .await;
        assert!(reply.starts_with("a NO"), "{reply}");
    }
    h.proxy.wait_logs("authlog: ratelimit", 1).await;
    assert!(blocked(&h).await);

    let looser = BLOCKING.replace("failures = 2", "failures = 5");
    reload(&h, &with(|o| o.ratelimit = Some(looser.clone()))).await;
    assert!(blocked(&h).await, "the block runs on");

    let exempt = looser.replace(
        "exempt_networks = []",
        "exempt_networks = [\"127.0.0.2/32\"]",
    );
    reload(&h, &with(|o| o.ratelimit = Some(exempt))).await;
    assert!(!blocked(&h).await, "exempt now");
    reload(&h, &with(|o| o.ratelimit = Some(looser))).await;
    assert!(blocked(&h).await, "the block was kept, only not applied");
}

/// `[timeouts]` and `[session]`: a new connection gets the new times, an
/// open one keeps its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn timeouts_and_session_limits_apply_to_new_connections() {
    let h = Harness::start().await;
    let (mut old_preauth, _) = h.imap(Src::External, Sni::Public).await;
    let mut old_session = logged_in(&h).await;

    reload(
        &h,
        &with(|o| {
            o.idle_secs = 1;
            o.session = Some("idle_limit_secs = 1".into());
        }),
    )
    .await;
    let t0 = Instant::now();
    let (mut new_preauth, _) = h.imap(Src::External, Sni::Public).await;
    let mut new_session = logged_in(&h).await;
    new_session.expect_closed().await;
    new_preauth.read_to_close().await;
    assert!(t0.elapsed() < Duration::from_secs(5), "{:?}", t0.elapsed());

    tokio::time::sleep(Duration::from_millis(1500)).await;
    old_preauth.send("a CAPABILITY").await;
    assert!(old_preauth.line().await.starts_with("* CAPABILITY"));
    relays(&mut old_session, "n1").await;
}

/// Whether a new connection from 127.0.0.2 is closed at accept.
async fn blocked(h: &Harness) -> bool {
    let mut c = Client::connect(h.proxy.imap, Src::External).await;
    c.try_tls(&h.pki, Sni::Public).await.is_err()
}

/// The extension lines of a new submission session's post-TLS EHLO reply.
async fn extensions(h: &Harness) -> Vec<String> {
    let (_c, ehlo) = h.smtp(Src::External, Sni::Public).await;
    ehlo[1..ehlo.len() - 1].to_vec()
}

/// The certificate a new IMAP connection asking for `name` is served.
async fn handshake(h: &Harness, name: &'static str) -> std::io::Result<Vec<u8>> {
    let mut c = Client::connect(h.proxy.imap, Src::External).await;
    c.try_tls(&h.pki, Sni::Name(name)).await?;
    Ok(c.peer_cert())
}

/// The EHLO extensions of `[submission]` apply to new sessions; the
/// backend's cached capabilities stay while the backend does.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn submission_ehlo_extensions_reload() {
    let h = Harness::start().await;
    assert!(extensions(&h).await.len() > 1);
    let probes = || h.smtp_be.seen().iter().filter(|s| s.probe).count();
    let probed = probes();

    reload(
        &h,
        &with(|o| o.submission_extra = "ehlo_extensions = [\"PIPELINING\"]"),
    )
    .await;
    assert_eq!(extensions(&h).await, ["250-PIPELINING"]);
    assert_eq!(probes(), probed, "the cache was kept");
}

/// `[[tls.certificates]]` added by a reload serves its name on the next
/// handshake; removed again, the name is refused. The expiry series follow.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn certificates_are_added_and_removed() {
    const TENANT: &str = "mail.tenant.test";
    let h = Harness::start().await;
    let tenant = h.pki.issue("tenant", &[TENANT], Some((2049, 12, 31)));
    let expiry = format!(
        "mail_auth_proxy_tls_cert_expiry_timestamp_seconds{{cert=\"{}\"}}",
        tenant.cert.display()
    );
    assert!(handshake(&h, TENANT).await.is_err());

    let added = with(|o| o.tls_certificates = vec![(tenant.cert.clone(), tenant.key.clone())]);
    reload(&h, &added).await;
    assert!(handshake(&h, TENANT).await.unwrap() == tenant.der);
    assert_eq!(h.proxy.metric(&expiry).await, RENEWED_NOT_AFTER);

    reload(&h, &Opts::default()).await;
    assert!(handshake(&h, TENANT).await.is_err());
    assert!(!h.proxy.metrics().await.contains_key(&expiry));
}

/// `[[oauth.issuers]]` for `issuer`, JWKS from the harness IdP.
fn issuer_block(issuer: &str, jwks_url: &str) -> String {
    format!(
        "[[oauth.issuers]]\nissuer = \"{issuer}\"\njwks_url = \"{jwks_url}\"\naudiences = [\"{AUDIENCE}\"]\ntoken_type = \"keycloak\"\n"
    )
}

/// The harness configuration with `[oauth]` holding `issuers` only.
fn with_issuers(h: &Harness, issuers: &[String]) -> String {
    let text = h.config(&Opts::default());
    let start = text.find("[[oauth.issuers]]").unwrap();
    let end = start + text[start..].find("\n\n").unwrap();
    format!("{}{}{}", &text[..start], issuers.concat(), &text[end..])
}

/// A token login on a new IMAP connection: whether it was accepted.
async fn token_accepted(h: &Harness, token: &str) -> bool {
    let (mut c, reply) = h
        .auth(
            Kind::Imap,
            Src::External,
            Sni::Public,
            "XOAUTH2",
            &xoauth2(EMAIL, token),
        )
        .await;
    if reply.starts_with("a OK") {
        return true;
    }
    c.send("").await;
    assert!(c.line().await.starts_with("a NO"));
    false
}

/// A new issuer's JWKS is fetched by the reload and its tokens are
/// accepted; a removed issuer's tokens are refused on new connections. An
/// issuer whose JWKS cannot be fetched fails the reload. The JWKS metrics
/// follow the issuers.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn issuers_are_added_and_removed() {
    let h = Harness::start().await;
    let other_url = format!("http://{}/realms/other/certs", h.idp.addr);
    let harness_issuer = issuer_block(ISSUER, &h.idp.jwks_url());
    let other = issuer_block(OTHER, &other_url);
    let other_token = h.idp.mint(serde_json::json!({ "iss": OTHER }));
    let token = h.idp.token(EMAIL);
    let series = |issuer: &str| {
        format!("mail_auth_proxy_jwks_last_success_timestamp_seconds{{issuer=\"{issuer}\"}}")
    };
    assert!(!token_accepted(&h, &other_token).await);

    reload_text(
        &h,
        &with_issuers(&h, &[harness_issuer.clone(), other.clone()]),
    )
    .await;
    assert!(token_accepted(&h, &other_token).await);
    assert!(token_accepted(&h, &token).await);
    assert!(h.proxy.metric(&series(OTHER)).await > 0);

    reload_text(&h, &with_issuers(&h, std::slice::from_ref(&other))).await;
    assert!(!token_accepted(&h, &token).await);
    assert!(token_accepted(&h, &other_token).await);
    assert!(!h.proxy.metrics().await.contains_key(&series(ISSUER)));

    let down = issuer_block("https://idp.test/realms/down", "http://127.0.0.1:1/certs");
    let e = h
        .proxy
        .reload(&with_issuers(&h, &[other, down]))
        .await
        .unwrap_err();
    assert!(e.contains("https://idp.test/realms/down"), "{e}");
    assert!(
        token_accepted(&h, &other_token).await,
        "the configuration in use stays"
    );
}

/// A file that does not parse, one that fails validation and one whose
/// certificate is missing are each refused with an ERROR naming the
/// problem; the configuration in use stays, and the metrics count them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_broken_configuration_is_refused() {
    let h = Harness::start().await;
    let loaded_at = h.proxy.metric(LAST_RELOAD).await;
    assert!(loaded_at > 0);
    let good = h.config(&with(|o| o.hostname = "mx.test"));
    let missing = h.pki.dir.path().join("missing.pem");
    for (text, needle) in [
        (
            "config_version = 2\n[server\n".to_string(),
            "TOML parse error",
        ),
        (
            good.replace("max_auth_attempts = 1", "max_auth_attempts = 0"),
            "max_auth_attempts",
        ),
        (
            good.replace(
                &h.pki.proxy_cert.display().to_string(),
                &missing.display().to_string(),
            ),
            "missing.pem",
        ),
    ] {
        let e = h.proxy.reload(&text).await.unwrap_err();
        assert!(e.contains(" ERROR ") && e.contains(needle), "{needle}: {e}");
        let mut c = Client::connect(h.proxy.smtp, Src::External).await;
        assert_eq!(c.line().await, "220 proxy.test ESMTP", "{needle}");
    }
    let m = h.proxy.metrics().await;
    assert_eq!((m[RELOADS_OK], m[RELOADS_ERROR]), (0, 3));
    assert_eq!(m[LAST_RELOAD], loaded_at);

    tokio::time::sleep(Duration::from_millis(1100)).await;
    reload_text(&h, &good).await;
    let m = h.proxy.metrics().await;
    assert_eq!((m[RELOADS_OK], m[RELOADS_ERROR]), (1, 3));
    assert!(m[LAST_RELOAD] > loaded_at);
}

/// A renewed certificate file is served after a SIGHUP even while the
/// configuration file is broken.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn certificates_reload_while_the_configuration_is_broken() {
    let h = Harness::start().await;
    std::fs::copy(&h.pki.renewed_cert, &h.pki.proxy_cert).unwrap();
    std::fs::copy(&h.pki.renewed_key, &h.pki.proxy_key).unwrap();
    assert!(h.proxy.reload("not toml [").await.is_err());
    h.proxy.wait_logs("reload: certificate loaded", 1).await;
    let mut c = Client::connect(h.proxy.imap, Src::External).await;
    c.tls_full(&h.pki, Sni::Public).await;
    assert!(c.peer_cert() == h.pki.renewed_der);
}

/// A change to a listener or the metrics endpoint needs a restart: the
/// reload is refused as a whole, naming the key, and none of the other
/// changes in the file take effect.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restart_only_changes_refuse_the_whole_reload() {
    let h = Harness::start().await;
    let renamed = h.config(&with(|o| o.hostname = "mx.test"));
    let sieve_section = renamed.find("[sieve]").unwrap();
    let sieve_end = sieve_section + renamed[sieve_section..].find("\n\n").unwrap();
    for (text, key) in [
        (
            renamed.replace("127.0.0.10:0", "127.0.0.20:0"),
            "imap.listen",
        ),
        (
            renamed.replace("127.0.0.11:0", "127.0.0.21:0"),
            "submission.listen",
        ),
        (
            format!("{}{}", &renamed[..sieve_section], &renamed[sieve_end..]),
            "sieve",
        ),
        (
            renamed.replace("[metrics]\n", "[metrics]\nenabled = false\n"),
            "metrics.enabled",
        ),
        (
            renamed.replace(
                &format!("listen = \"{METRICS_IP}:0\""),
                &format!("listen = \"{METRICS_IP}:1\""),
            ),
            "metrics.listen",
        ),
    ] {
        assert_ne!(text, renamed, "{key}: the test changes the file");
        let e = h.proxy.reload(&text).await.unwrap_err();
        assert!(
            e.contains(" ERROR ") && e.contains(&format!("changed {key}: needs a restart")),
            "{key}: {e}"
        );
        let mut c = Client::connect(h.proxy.smtp, Src::External).await;
        assert_eq!(c.line().await, "220 proxy.test ESMTP", "{key}");
    }
    assert_eq!(h.proxy.metric(RELOADS_ERROR).await, 5);
    reload_text(&h, &renamed).await;
    let mut c = Client::connect(h.proxy.smtp, Src::External).await;
    assert_eq!(c.line().await, "220 mx.test ESMTP");
}

/// Sessions open across reloads, refused or not, are neither closed nor
/// changed: they relay on, and nothing counts them as ended.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn open_sessions_survive_every_reload() {
    let h = Harness::start().await;
    let mut imap = logged_in(&h).await;
    let token = h.idp.token(EMAIL);
    let (mut smtp, reply) = h
        .auth(
            Kind::Smtp,
            Src::External,
            Sni::Public,
            "XOAUTH2",
            &xoauth2(EMAIL, &token),
        )
        .await;
    assert_eq!(reply, "235 2.7.0 Authentication successful");

    let changed = h.config(&with(|o| {
        o.hostname = "mx.test";
        o.legacy = Some(String::new());
        o.session = Some("idle_limit_secs = 1\nmax_session_secs = 1".into());
    }));
    reload_text(&h, &changed).await;
    assert!(h.proxy.reload("broken [").await.is_err());
    assert!(h
        .proxy
        .reload(&changed.replace("127.0.0.10:0", "127.0.0.20:0"))
        .await
        .is_err());
    // Beyond the new session limits, which apply to new sessions only.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    relays(&mut imap, "n1").await;
    smtp.send("NOOP").await;
    assert_eq!(smtp.line().await, "ECHO NOOP");

    let m = h.proxy.metrics().await;
    for proto in ["imap", "smtp"] {
        assert_eq!(
            m[&format!("mail_auth_proxy_active_connections{{proto=\"{proto}\"}}")],
            1,
            "{proto}"
        );
        for reason in [
            "client_close",
            "backend_close",
            "idle_limit",
            "max_session",
            "error",
        ] {
            let key = format!(
                "mail_auth_proxy_sessions_ended_total{{proto=\"{proto}\",reason=\"{reason}\"}}"
            );
            assert_eq!(m[&key], 0, "{key}");
        }
    }
}

/// A backend address is reloadable: new sessions go to the new backend,
/// open ones stay with the one they logged in to.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn backend_change_applies_to_new_sessions() {
    let h = Harness::start().await;
    let mut old = logged_in(&h).await;
    let other = MockBackend::start(Kind::Imap, h.pki.backend.clone()).await;
    let text = h.config(&Opts::default()).replace(
        &format!("address = \"{}\"", h.imap_be.addr),
        &format!("address = \"{}\"", other.addr),
    );
    reload_text(&h, &text).await;
    let mut new = logged_in(&h).await;
    relays(&mut new, "n1").await;
    relays(&mut old, "o1").await;
    assert_eq!(other.sessions().len(), 1);
    assert_eq!(h.imap_be.sessions().len(), 1);
    assert!(h.imap_be.sessions()[0]
        .relayed
        .iter()
        .any(|l| l == "o1 NOOP"));
}
