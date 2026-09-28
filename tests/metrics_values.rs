//! Metric values that the auth-path tests do not cover: the JWKS state per
//! issuer and the certificate expiry.

mod common;
use common::*;
use std::time::{SystemTime, UNIX_EPOCH};

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn jwks_success_and_failures_by_issuer() {
    let h = Harness::start().await;
    let success =
        format!("mail_auth_proxy_jwks_last_success_timestamp_seconds{{issuer=\"{ISSUER}\"}}");
    let failures = format!("mail_auth_proxy_jwks_refresh_failures_total{{issuer=\"{ISSUER}\"}}");

    // The startup fetch counts as a success.
    let m = h.proxy.metrics().await;
    let loaded = m[&success];
    assert!(loaded <= now() && now() - loaded < 60, "{loaded}");
    assert_eq!(m[&failures], 0);

    // The IdP goes away: the SIGHUP refresh fails, the issuer keeps its keys
    // and its last success time.
    h.idp.stop().await;
    h.proxy.signal("HUP");
    h.proxy.wait_logs("reload: JWKS refresh failed", 1).await;
    let m = h.proxy.metrics().await;
    assert_eq!(m[&failures], 1);
    assert_eq!(m[&success], loaded);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn certificate_expiry_follows_reload() {
    let h = Harness::start().await;
    let expiry = "mail_auth_proxy_tls_cert_expiry_timestamp_seconds";
    assert_eq!(h.proxy.metric(expiry).await, PROXY_NOT_AFTER);

    std::fs::copy(&h.pki.renewed_cert, &h.pki.proxy_cert).unwrap();
    std::fs::copy(&h.pki.renewed_key, &h.pki.proxy_key).unwrap();
    h.proxy.signal("HUP");
    h.proxy.wait_logs("reload: certificate loaded", 1).await;
    assert_eq!(h.proxy.metric(expiry).await, RENEWED_NOT_AFTER);

    // A refused reload keeps the certificate in use, and its expiry.
    std::fs::write(&h.pki.proxy_cert, "not a certificate").unwrap();
    h.proxy.signal("HUP");
    h.proxy
        .wait_logs("reload: certificate unusable; keeping the current one", 1)
        .await;
    assert_eq!(h.proxy.metric(expiry).await, RENEWED_NOT_AFTER);
}

/// Wait until the metric `key` has the value `want`.
async fn wait_metric(h: &Harness, key: &str, want: u64) {
    let until = std::time::Instant::now() + IO_TIMEOUT;
    loop {
        let v = h.proxy.metric(key).await;
        if v == want {
            return;
        }
        assert!(
            std::time::Instant::now() < until,
            "{key} = {v}, want {want}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

/// Every way a client can leave takes its connection off the gauge: before
/// TLS, after the greeting, and from a relayed session. Each connection is
/// counted once, and only ones that ended before a credential are pre-auth
/// aborts.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn active_connections_return_to_zero_on_client_abort() {
    let h = Harness::start().await;
    let token = h.idp.token(EMAIL);
    for kind in Kind::ALL {
        let p = kind.label();
        let active = format!("mail_auth_proxy_active_connections{{proto=\"{p}\"}}");
        let total = format!("mail_auth_proxy_connections_total{{proto=\"{p}\"}}");
        let aborts =
            format!("mail_auth_proxy_preauth_aborts_total{{proto=\"{p}\",scope=\"external\"}}");
        let server = match kind {
            Kind::Imap => h.proxy.imap,
            Kind::Smtp => h.proxy.smtp,
            Kind::Sieve => h.proxy.sieve,
        };

        // TCP only, closed before anything happened.
        let c = Client::connect(server, Src::External).await;
        wait_metric(&h, &active, 1).await;
        drop(c);
        wait_metric(&h, &active, 0).await;

        // Past the greeting (and TLS), then gone.
        let c = h.ready(kind, Src::External, Sni::Public).await;
        assert_eq!(h.proxy.metric(&active).await, 1, "{p}");
        drop(c);
        wait_metric(&h, &active, 0).await;

        // Relayed session, closed by the client.
        let (mut c, _) = h
            .auth(
                kind,
                Src::External,
                Sni::Public,
                "XOAUTH2",
                &xoauth2(EMAIL, &token),
            )
            .await;
        c.send("ping").await;
        assert_eq!(c.line().await, "ECHO ping");
        assert_eq!(h.proxy.metric(&active).await, 1, "{p}");
        drop(c);
        wait_metric(&h, &active, 0).await;

        let m = h.proxy.metrics().await;
        assert_eq!(m[&total], 3, "{p}");
        // Before TLS always; after the greeting too, except for IMAP, where
        // a disconnect right after it is a clean end (a health check).
        let want = if kind == Kind::Imap { 1 } else { 2 };
        assert_eq!(m[&aborts], want, "{p}");
        assert_eq!(
            m[&format!("mail_auth_proxy_upstream_forward_total{{proto=\"{p}\"}}")],
            1,
            "{p}"
        );
    }
}
