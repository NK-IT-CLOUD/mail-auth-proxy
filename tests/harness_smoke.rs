//! The harness itself: the proxy comes up on its own ports with a fresh
//! metrics state, fetched the JWKS once, and each protocol completes an OAuth
//! login through to its mock backend.

mod common;
use common::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_starts_and_relays_each_protocol() {
    let h = Harness::start().await;
    assert_eq!(h.idp.fetches.load(std::sync::atomic::Ordering::SeqCst), 1);
    // The [password_gate] short form runs as one rule of that name.
    assert!(h
        .proxy
        .log_contains("legacy password rule rule=password_gate"));
    let m = h.proxy.metrics().await;
    assert_eq!(
        m[&format!(
            "mail_auth_proxy_build_info{{version=\"{}\"}}",
            env!("CARGO_PKG_VERSION")
        )],
        1
    );
    assert!(
        m.iter()
            .filter(|(k, _)| !k.starts_with("mail_auth_proxy_build_info"))
            .all(|(_, v)| *v == 0),
        "fresh process, all series at 0: {m:?}"
    );

    let token = h.idp.token(EMAIL);
    let mut open = Vec::new();
    for kind in Kind::ALL {
        let (mut c, reply) = h
            .auth(
                kind,
                Src::External,
                Sni::Public,
                "XOAUTH2",
                &xoauth2(EMAIL, &token),
            )
            .await;
        assert!(reply.starts_with("a OK") || reply.starts_with("235") || reply.starts_with("OK"));
        c.send("ping").await;
        assert_eq!(c.line().await, "ECHO ping", "{kind:?}");
        assert_eq!(h.backend(kind).sessions()[0].relayed, ["ping"]);
        open.push(c);
    }
    let m = h.proxy.metrics().await;
    for kind in Kind::ALL {
        let p = kind.label();
        assert_eq!(
            m[&format!("mail_auth_proxy_upstream_forward_total{{proto=\"{p}\"}}")],
            1
        );
        assert_eq!(
            m[&format!("mail_auth_proxy_active_connections{{proto=\"{p}\"}}")],
            1
        );
    }
}

#[test]
fn version_prints_semver_and_commit() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_mail-auth-proxy"))
        .arg("--version")
        .output()
        .unwrap();
    assert!(out.status.success());
    assert_eq!(
        String::from_utf8(out.stdout).unwrap(),
        format!("mail-auth-proxy {}\n", mail_auth_proxy::version())
    );
}
