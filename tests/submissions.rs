//! The implicit-TLS submission listener (`submission.implicit_tls_listen`,
//! port 465, RFC 8314 §3.3): TLS from the first byte, then the greeting and
//! the same dialog, gate and backend login as after STARTTLS on 587. Logs
//! and metrics tell the two listeners apart (`listener`).

mod common;
use common::*;

fn submissions() -> Opts {
    Opts {
        submissions: true,
        ..Opts::default()
    }
}

/// Up to the EHLO reply on the implicit-TLS listener.
async fn smtps(h: &Harness, src: Src, sni: Sni) -> (Client, Vec<String>) {
    let mut c = Client::connect(h.proxy.smtps, src).await;
    c.tls(&h.pki, sni).await;
    assert_eq!(c.line().await, format!("220 {HOSTNAME} ESMTP"));
    c.send("EHLO client.test").await;
    let ehlo = c.smtp_reply().await;
    (c, ehlo)
}

/// A token login on 465: greeting over TLS, the EHLO reply of 587 after
/// STARTTLS, 235, the relay. The authresult says `listener="submissions"`,
/// a login on 587 `listener="submission"`, both `proto="smtp"`; the listener
/// metrics count each on its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn token_login_on_implicit_tls() {
    let h = Harness::start_with(submissions()).await;
    let token = h.idp.token(EMAIL);
    let (mut c, ehlo) = smtps(&h, Src::External, Sni::Public).await;
    let (_c587, ehlo_587) = h.smtp(Src::External, Sni::Public).await;
    assert_eq!(ehlo, ehlo_587);
    assert!(!ehlo.iter().any(|l| l.contains("STARTTLS")), "{ehlo:?}");
    c.send(&format!("AUTH XOAUTH2 {}", xoauth2(EMAIL, &token)))
        .await;
    assert_eq!(c.line().await, "235 2.7.0 Authentication successful");
    c.send("NOOP").await;
    assert_eq!(c.line().await, "ECHO NOOP");
    let s = h.smtp_be.sessions().pop().unwrap();
    assert_eq!(s.login.as_deref(), Some(EMAIL));
    assert!(s.xclient.as_deref().unwrap().ends_with("ADDR=127.0.0.2"));

    let (_c, reply) = h
        .auth(
            Kind::Smtp,
            Src::External,
            Sni::Public,
            "XOAUTH2",
            &xoauth2(EMAIL, &token),
        )
        .await;
    assert!(reply.starts_with("235 "), "{reply}");
    let ars = h.proxy.wait_authresults(2).await;
    assert!(ars.iter().all(|a| a.proto == "smtp" && a.reason == "ok"));
    assert_eq!(
        h.proxy.authresult_listeners(),
        ["submissions", "submission"]
    );
    let m = h.proxy.metrics().await;
    for (key, want) in [
        (
            "mail_auth_proxy_listener_connections_total{listener=\"submissions\"}",
            1,
        ),
        (
            "mail_auth_proxy_listener_connections_total{listener=\"submission\"}",
            2,
        ),
        (
            "mail_auth_proxy_listener_auth_attempts_total{listener=\"submissions\",result=\"ok\"}",
            1,
        ),
        (
            "mail_auth_proxy_listener_auth_attempts_total{listener=\"submission\",result=\"ok\"}",
            1,
        ),
        (
            "mail_auth_proxy_listener_auth_attempts_total{listener=\"imap\",result=\"ok\"}",
            0,
        ),
        ("mail_auth_proxy_connections_total{proto=\"smtp\"}", 3),
    ] {
        assert_eq!(m.get(key).copied(), Some(want), "{key}");
    }
}

/// The same gate as on 587: a password from outside is refused before any
/// backend contact, a rejected token gets the error result (RFC 7628
/// section 3.2.2); STARTTLS is refused, TLS being active.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gate_and_dialog_on_implicit_tls() {
    let h = Harness::start_with(submissions()).await;
    let (mut c, ehlo) = smtps(&h, Src::External, Sni::Internal).await;
    assert!(ehlo
        .last()
        .unwrap()
        .starts_with("250 AUTH XOAUTH2 OAUTHBEARER"));
    assert!(!ehlo.last().unwrap().contains("PLAIN"), "{ehlo:?}");
    c.send("STARTTLS").await;
    assert_eq!(c.line().await, "503 5.5.1 TLS already active");
    c.send(&format!("AUTH PLAIN {}", plain("bob@example.test", "pw")))
        .await;
    assert_eq!(
        c.line().await,
        "504 5.5.4 password authentication not available on this endpoint"
    );
    let ar = &h.proxy.wait_authresults(1).await[0];
    assert_eq!(ar.reason, "blocked_endpoint");

    // From inside with the internal name, passwords are offered as on 587.
    let (_c, ehlo) = smtps(&h, Src::Internal, Sni::Internal).await;
    assert!(ehlo.last().unwrap().contains(" PLAIN"), "{ehlo:?}");

    let bad = h.idp.mint(serde_json::json!({"aud": "other"}));
    let (mut c, _) = smtps(&h, Src::External, Sni::Public).await;
    c.send(&format!("AUTH XOAUTH2 {}", xoauth2(EMAIL, &bad)))
        .await;
    let challenge = c.line().await;
    assert_eq!(
        error_result(Kind::Smtp, &challenge)["status"],
        "invalid_token"
    );
    c.send("").await;
    assert_eq!(
        c.line().await,
        "535 5.7.8 Authentication credentials invalid"
    );
    let ars = h.proxy.wait_authresults(2).await;
    assert_eq!(ars[1].reason, "bad_token");
    assert_eq!(
        h.proxy.authresult_listeners(),
        ["submissions", "submissions"]
    );
    assert!(h.smtp_be.sessions().is_empty(), "no backend login");
}

/// A client that speaks plaintext SMTP to the implicit-TLS port gets no
/// greeting in the clear: the handshake fails and counts as a pre-auth
/// abort.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn plaintext_on_implicit_tls_is_a_preauth_abort() {
    let h = Harness::start_with(submissions()).await;
    let key = "mail_auth_proxy_preauth_aborts_total{proto=\"smtp\",scope=\"external\"}";
    let before = h.proxy.metric(key).await;
    let mut c = Client::connect(h.proxy.smtps, Src::External).await;
    c.send("EHLO client.test").await;
    let rest = c.read_to_close().await;
    assert!(
        !rest.starts_with(b"220"),
        "{:?}",
        String::from_utf8_lossy(&rest)
    );
    h.wait_session_ended(Kind::Smtp, 1).await;
    assert_eq!(h.proxy.metric(key).await, before + 1);
    assert!(h.proxy.authresults().is_empty());
}

/// The implicit-TLS listener binds a socket: adding it by reload is refused
/// as a whole; the backend profile keys are taken over by a reload.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn implicit_listener_needs_a_restart_profile_reloads() {
    let h = Harness::start().await;
    let e = h.proxy.reload(&h.config(&submissions())).await.unwrap_err();
    assert!(
        e.contains("changed submission.implicit_tls_listen: needs a restart"),
        "{e}"
    );
    let oauthbearer = Profile {
        auth_forward: Some("oauthbearer"),
        ..Profile::default()
    };
    let opts = Opts {
        profiles: [oauthbearer, Profile::default(), Profile::default()],
        ..Opts::default()
    };
    h.proxy.reload(&h.config(&opts)).await.unwrap();
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
    let s = h.imap_be.sessions().pop().unwrap();
    assert_eq!(s.mech.as_deref(), Some("OAUTHBEARER"));
}

/// ALPN on both submission listeners (RFC 7301 §3.2, RFC 9325 §3.8): SMTP
/// has no IANA ID, so a client that offers a registered ID of another
/// protocol is refused before the ServerHello with `no_application_protocol`
/// (alert 120), also when it offers an unregistered value besides. Without
/// ALPN, or with only unregistered values (`smtp`) or a GREASE value (RFC
/// 8701), the handshake goes on and no protocol is selected.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn registered_foreign_alpn_is_refused() {
    let h = Harness::start_with(submissions()).await;
    let handshake = |implicit: bool, alpn: &'static [&'static [u8]]| {
        let h = &h;
        async move {
            let mut c = if implicit {
                Client::connect(h.proxy.smtps, Src::External).await
            } else {
                let mut c = Client::connect(h.proxy.smtp, Src::External).await;
                c.line().await;
                c.send("STARTTLS").await;
                assert_eq!(c.line().await, "220 2.0.0 Ready to start TLS");
                c
            };
            let r = c.try_tls_alpn(&h.pki, Sni::Public, alpn).await;
            if implicit && r.is_ok() {
                assert_eq!(c.line().await, format!("220 {HOSTNAME} ESMTP"));
            }
            r
        }
    };
    const REFUSED: [&[&[u8]]; 4] = [&[b"h2"], &[b"http/1.1"], &[b"imap"], &[b"smtp", b"h2"]];
    const ACCEPTED: [&[&[u8]]; 3] = [&[], &[b"smtp"], &[b"\x0a\x0a"]];
    for implicit in [false, true] {
        for alpn in REFUSED {
            let e = handshake(implicit, alpn).await.unwrap_err();
            assert!(
                e.to_string().contains("NoApplicationProtocol"),
                "{implicit} {alpn:?}: {e}"
            );
        }
        for alpn in ACCEPTED {
            assert_eq!(
                handshake(implicit, alpn).await.unwrap(),
                None,
                "{implicit} {alpn:?}"
            );
        }
    }
    h.proxy
        .wait_logs("names another protocol", 2 * REFUSED.len())
        .await;
    assert!(h.proxy.log_contains("http/1.1"));
}
