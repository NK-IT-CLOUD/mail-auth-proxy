//! `post_login_guard` per backend. Unset or `true`, the relay passes the
//! client's IMAP and ManageSieve commands through the command guard after the
//! login (`unauthenticate_guard.rs` covers what it does). `false` relays the
//! sessions of that backend as they are, for backends known to refuse
//! UNAUTHENTICATE and a second login themselves: every command, COMPRESS
//! included, reaches the backend and the capabilities are relayed unchanged.
//! The setting is the backend's, for all its addresses, and only of the
//! backend the session is logged in to. A backend that advertises
//! UNAUTHENTICATE in the capabilities the proxy reads before the splice is
//! relayed through the guard whatever the setting.
//!
//! `mail_auth_proxy_post_login_guard_sessions_total` counts each login by
//! how its session is relayed: `on`, `off`, or `safety_net` for the last case.
//!
//! The mock backends execute UNAUTHENTICATE and echo every other command, so
//! an unguarded session shows what the backend receives.

mod common;
use common::*;

const REFUSED: &str = "BAD Command not permitted after login";
const SIEVE_REFUSED: &str = "NO \"Command not permitted after login\"";
const OFF: &str = "post_login_guard = false";
const ON: &str = "post_login_guard = true";

const ONE: &str = "a@one.test";
const TWO: &str = "b@two.test";

/// The commands the guard keeps from an IMAP backend, with a tag each.
const IMAP_GUARDED: [(&str, &str); 5] = [
    ("b", "UNAUTHENTICATE"),
    ("c", "LOGIN other@example.test secret"),
    ("d", "AUTHENTICATE PLAIN"),
    ("e", "COMPRESS DEFLATE"),
    ("f", "STARTTLS"),
];
/// The commands the guard keeps from a ManageSieve backend.
const SIEVE_GUARDED: [&str; 3] = ["UNAUTHENTICATE", "AUTHENTICATE \"PLAIN\"", "STARTTLS"];

/// `mail_auth_proxy_post_login_guard_sessions_total` per protocol and
/// `guard` label (`on`, `off`, `safety_net`), as `[imap, sieve]`.
async fn guard_counts(h: &Harness) -> [[u64; 3]; 2] {
    let m = h.proxy.metrics().await;
    ["imap", "sieve"].map(|p| {
        ["on", "off", "safety_net"].map(|g| {
            let key = format!(
                "mail_auth_proxy_post_login_guard_sessions_total{{proto=\"{p}\",guard=\"{g}\"}}"
            );
            *m.get(&key).unwrap_or_else(|| panic!("no metric {key}"))
        })
    })
}

/// Lines the backend received after the login.
fn relayed(be: &MockBackend) -> Vec<String> {
    be.sessions().into_iter().flat_map(|s| s.relayed).collect()
}

/// A token login of `user` on `kind`; the client and the login reply.
async fn login(h: &Harness, kind: Kind, user: &str) -> (Client, String) {
    h.auth(
        kind,
        Src::External,
        Sni::Public,
        "XOAUTH2",
        &xoauth2(user, &h.idp.token(user)),
    )
    .await
}

/// The IMAP and ManageSieve backends of the harness with `extra` keys.
fn sections(extra: &'static str) -> Opts {
    let p = Profile {
        extra,
        ..Profile::default()
    };
    Opts {
        profiles: [p, Profile::default(), p],
        ..Opts::default()
    }
}

/// Every guarded IMAP command is answered by the proxy and never reaches
/// the backend.
async fn assert_imap_guarded(c: &mut Client, be: &MockBackend) {
    for (tag, cmd) in IMAP_GUARDED {
        c.send(&format!("{tag} {cmd}")).await;
        assert_eq!(c.line().await, format!("{tag} {REFUSED}"), "{cmd}");
    }
    c.send("g NOOP").await;
    assert_eq!(c.line().await, "ECHO g NOOP");
    let lines = relayed(be);
    for (_, cmd) in IMAP_GUARDED {
        let word = cmd.split(' ').next().unwrap();
        assert!(
            !lines.iter().any(|l| l.to_ascii_uppercase().contains(word)),
            "{word} reached the backend: {lines:?}"
        );
    }
}

/// Every guarded IMAP command reaches the backend as the client sent it.
async fn assert_imap_unguarded(c: &mut Client, be: &MockBackend) {
    for (tag, cmd) in IMAP_GUARDED {
        c.send(&format!("{tag} {cmd}")).await;
        let want = if cmd == "UNAUTHENTICATE" {
            format!("{tag} OK Unauthenticated.")
        } else {
            format!("ECHO {tag} {cmd}")
        };
        assert_eq!(c.line().await, want, "{cmd}");
    }
    let lines = relayed(be);
    for (tag, cmd) in IMAP_GUARDED {
        let line = format!("{tag} {cmd}");
        assert!(lines.contains(&line), "{line:?} missing in {lines:?}");
    }
}

async fn assert_sieve_guarded(c: &mut Client, be: &MockBackend) {
    for cmd in SIEVE_GUARDED {
        c.send(cmd).await;
        assert_eq!(c.line().await, SIEVE_REFUSED, "{cmd}");
    }
    c.send("NOOP").await;
    assert_eq!(c.line().await, "ECHO NOOP");
    assert_eq!(relayed(be), ["NOOP"]);
}

async fn assert_sieve_unguarded(c: &mut Client, be: &MockBackend) {
    for cmd in SIEVE_GUARDED {
        c.send(cmd).await;
        let want = if cmd == "UNAUTHENTICATE" {
            "OK \"Unauthenticated.\"".to_string()
        } else {
            format!("ECHO {cmd}")
        };
        assert_eq!(c.line().await, want, "{cmd}");
    }
    assert_eq!(relayed(be), SIEVE_GUARDED);
}

/// Unset and `true` are the guard: each command it covers, per protocol,
/// is answered by the proxy, and the capabilities lose UNAUTHENTICATE and
/// COMPRESS. No warning.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unset_or_true_keeps_the_guard() {
    for extra in ["", ON] {
        let h = Harness::start_with(sections(extra)).await;
        *h.imap_be.login_caps.lock().unwrap() = Some("IMAP4rev1 IDLE COMPRESS=DEFLATE MOVE".into());
        let (mut c, reply) = login(&h, Kind::Imap, EMAIL).await;
        assert_eq!(
            reply, "a OK [CAPABILITY IMAP4rev1 IDLE MOVE] Logged in",
            "{extra:?}"
        );
        assert_imap_guarded(&mut c, &h.imap_be).await;

        let (mut c, reply) = login(&h, Kind::Sieve, EMAIL).await;
        assert_eq!(reply, "OK \"Logged in.\"");
        assert_sieve_guarded(&mut c, &h.sieve_be).await;
        assert!(!h.proxy.log_contains("post_login_guard"), "{extra:?}");
        assert_eq!(guard_counts(&h).await, [[1, 0, 0], [1, 0, 0]], "{extra:?}");
    }
}

/// `false`: the session is relayed as it is. The login's CAPABILITY code
/// and every CAPABILITY response reach the client unchanged, COMPRESS and
/// the commands the guard would keep reach the backend, a non-synchronizing
/// literal stays one, and literal data is not looked at. Submission is not
/// affected (it has no guard). The configuration check warns.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn false_relays_the_session_as_it_is() {
    let h = Harness::start_with(sections(OFF)).await;
    assert!(
        h.proxy
            .log_contains("imap.backend: post_login_guard = false relays"),
        "{}",
        h.proxy.logs().join("\n")
    );
    assert!(h
        .proxy
        .log_contains("sieve.backend: post_login_guard = false relays"));
    *h.imap_be.login_caps.lock().unwrap() = Some("IMAP4rev1 IDLE COMPRESS=DEFLATE MOVE".into());
    let (mut c, reply) = login(&h, Kind::Imap, EMAIL).await;
    assert_eq!(
        reply,
        "a OK [CAPABILITY IMAP4rev1 IDLE COMPRESS=DEFLATE MOVE] Logged in"
    );
    assert_imap_unguarded(&mut c, &h.imap_be).await;
    c.send("h CAPABILITY").await;
    assert_eq!(
        c.line().await,
        format!("* CAPABILITY {IMAP_POSTLOGIN_CAPS}")
    );
    assert_eq!(
        c.line().await,
        format!("h OK [CAPABILITY {IMAP_POSTLOGIN_CAPS}] Capability completed.")
    );
    let mail = "Subject: x\r\n\r\ni UNAUTHENTICATE\r\n";
    c.send_raw(format!("i APPEND INBOX {{{}+}}\r\n{mail}\r\n", mail.len()).as_bytes())
        .await;
    assert_eq!(c.line().await, "i OK APPEND completed.");
    let lines = relayed(&h.imap_be);
    assert!(
        lines.contains(&format!("i APPEND INBOX {{{}+}}", mail.len())),
        "{lines:?}"
    );

    let (mut c, reply) = login(&h, Kind::Sieve, EMAIL).await;
    assert_eq!(reply, "OK \"Logged in.\"");
    assert_sieve_unguarded(&mut c, &h.sieve_be).await;
    c.send("CAPABILITY").await;
    assert!(c
        .sieve_response()
        .await
        .contains(&"\"UNAUTHENTICATE\"".to_string()));
    // A script line the guard would end the session for.
    let script = "require \"fileinto\";\r\nUNAUTHENTICATE\r\n";
    c.send_raw(format!("PUTSCRIPT \"t\" {{{}+}}\r\n{script}\r\n", script.len()).as_bytes())
        .await;
    assert!(c.line().await.starts_with("OK "));
    assert!(relayed(&h.sieve_be).contains(&format!("LITERAL {script}")));
    assert_eq!(
        h.proxy
            .metric("mail_auth_proxy_sessions_ended_total{proto=\"imap\",reason=\"blocked\"}")
            .await,
        0
    );
    // One authresult per login, as with the guard.
    assert_eq!(h.proxy.wait_authresults(2).await.len(), 2);
    assert_eq!(guard_counts(&h).await, [[0, 1, 0], [0, 1, 0]]);
}

/// A backend that advertises UNAUTHENTICATE contradicts `false`: the
/// session is relayed through the guard, and a warning names the backend.
/// IMAP reads it from the login's CAPABILITY code and from an untagged
/// CAPABILITY response before the tagged OK, ManageSieve from the
/// capabilities after TLS.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn false_with_unauthenticate_advertised_keeps_the_guard() {
    let h = Harness::start_with(sections(OFF)).await;
    *h.imap_be.login_caps.lock().unwrap() =
        Some("IMAP4rev1 IDLE UNAUTHENTICATE COMPRESS=DEFLATE MOVE".into());
    *h.sieve_be.login_caps.lock().unwrap() = Some("\"UNAUTHENTICATE\"".into());
    let (mut c, reply) = login(&h, Kind::Imap, EMAIL).await;
    assert_eq!(reply, "a OK [CAPABILITY IMAP4rev1 IDLE MOVE] Logged in");
    assert_imap_guarded(&mut c, &h.imap_be).await;
    // Announced only in an untagged response during the login, which the
    // client never sees.
    *h.imap_be.login_caps.lock().unwrap() = None;
    *h.imap_be.announced_caps.lock().unwrap() = Some("IMAP4rev1 IDLE UNAUTHENTICATE MOVE".into());
    let (mut c, reply) = login(&h, Kind::Imap, EMAIL).await;
    assert_eq!(reply, "a OK [CAPABILITY IMAP4rev1 IDLE MOVE] Logged in");
    assert_imap_guarded(&mut c, &h.imap_be).await;
    let (mut c, _) = login(&h, Kind::Sieve, EMAIL).await;
    assert_sieve_guarded(&mut c, &h.sieve_be).await;
    let warning = "advertises UNAUTHENTICATE although post_login_guard = false";
    assert_eq!(
        h.proxy.count_logs(warning),
        3,
        "{}",
        h.proxy.logs().join("\n")
    );
    assert!(h.proxy.log_contains("backend=imap"));
    assert_eq!(guard_counts(&h).await, [[0, 0, 2], [0, 0, 1]]);
}

/// Routes: two mail systems, `one` with the guard off, `two` with it on.
/// Each session follows the backend it is logged in to.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_setting_is_that_of_the_backend_the_session_uses() {
    let off = Profile {
        extra: OFF,
        ..Profile::default()
    };
    let opts = Opts {
        named: vec![
            ("one-imap", Kind::Imap, off),
            ("one-sieve", Kind::Sieve, off),
            ("two-imap", Kind::Imap, Profile::default()),
            ("two-sieve", Kind::Sieve, Profile::default()),
        ],
        listener_backends: [Some(""), None, Some("")],
        routes: r#"
[[routes]]
name = "one"
domains = ["one.test"]
imap = "one-imap"
sieve = "one-sieve"

[[routes]]
name = "two"
domains = ["two.test"]
imap = "two-imap"
sieve = "two-sieve"
"#
        .into(),
        ..Opts::default()
    };
    let h = Harness::start_with(opts).await;
    let (mut c, _) = login(&h, Kind::Imap, TWO).await;
    assert_imap_guarded(&mut c, h.named("two-imap")).await;
    let (mut c, _) = login(&h, Kind::Imap, ONE).await;
    assert_imap_unguarded(&mut c, h.named("one-imap")).await;
    let (mut c, _) = login(&h, Kind::Sieve, ONE).await;
    assert_sieve_unguarded(&mut c, h.named("one-sieve")).await;
    let (mut c, _) = login(&h, Kind::Sieve, TWO).await;
    assert_sieve_guarded(&mut c, h.named("two-sieve")).await;
    assert_eq!(guard_counts(&h).await, [[1, 1, 0], [1, 1, 0]]);
    assert!(h
        .proxy
        .log_contains("backends.one-imap: post_login_guard = false relays"));
    assert!(!h.proxy.log_contains("backends.two-imap: post_login_guard"));
}

/// A pool: the setting holds for every address, also the one a login fails
/// over to.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pool_has_one_setting_for_all_addresses() {
    let h = Harness::start_with(Opts {
        named: vec![
            ("a", Kind::Imap, Profile::default()),
            ("b", Kind::Imap, Profile::default()),
        ],
        pools: vec![("store", vec!["a", "b"], OFF)],
        listener_backends: [Some("store"), None, None],
        ..Opts::default()
    })
    .await;
    let (mut c, _) = login(&h, Kind::Imap, EMAIL).await;
    assert_imap_unguarded(&mut c, h.named("a")).await;
    h.named("a")
        .refuse
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let (mut c, _) = login(&h, Kind::Imap, EMAIL).await;
    assert_imap_unguarded(&mut c, h.named("b")).await;
}

/// A reload that turns the guard on applies to the sessions that log in
/// after it; one logged in before keeps the setting it started with, as it
/// keeps the rest of its configuration.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reload_applies_to_new_sessions() {
    let h = Harness::start_with(sections(OFF)).await;
    let (mut before, _) = login(&h, Kind::Imap, EMAIL).await;
    let text = h.config(&sections(ON));
    if let Err(line) = h.proxy.reload(&text).await {
        panic!("reload refused: {line}");
    }
    let (mut after, _) = login(&h, Kind::Imap, EMAIL).await;
    after.send("b COMPRESS DEFLATE").await;
    assert_eq!(after.line().await, format!("b {REFUSED}"));
    before.send("b COMPRESS DEFLATE").await;
    assert_eq!(before.line().await, "ECHO b COMPRESS DEFLATE");
}
