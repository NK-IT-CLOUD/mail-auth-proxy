//! Backend profiles: per backend, how the client address travels
//! (`client_ip`), how a token is forwarded (`auth_forward`) and how the
//! connection is secured (`tls`). Each profile is run against a mock backend
//! that serves only that profile.

mod common;
use common::*;

/// The start of a successful login reply.
fn ok_prefix(kind: Kind) -> &'static str {
    match kind {
        Kind::Imap => "a OK",
        Kind::Smtp => "235 ",
        Kind::Sieve => "OK",
    }
}

fn with_profiles(profiles: [Profile; 3]) -> Opts {
    Opts {
        profiles,
        ..Opts::default()
    }
}

/// Log in with a token on `kind`; the backend session it made.
async fn token_login(h: &Harness, kind: Kind) -> (Client, Seen) {
    let token = h.idp.token(EMAIL);
    let (c, reply) = h
        .auth(
            kind,
            Src::External,
            Sni::Public,
            "XOAUTH2",
            &xoauth2(EMAIL, &token),
        )
        .await;
    assert!(reply.starts_with(ok_prefix(kind)), "{kind:?}: {reply}");
    let s = h.backend(kind).sessions().pop().expect("a backend session");
    assert_eq!(s.secret.as_deref(), Some(token.as_str()));
    (c, s)
}

// ── client_ip ──────────────────────────────────────────────────────────────

/// `client_ip = "proxy_v2"` on the submission backend: the PROXY v2 header
/// carries the client address, no XCLIENT is sent, and the EHLO probe (the
/// proxy's own connection) sends a LOCAL header.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn submission_client_ip_proxy_v2() {
    let h = Harness::start_with(with_profiles([
        Profile::default(),
        Profile {
            client_ip: Some("proxy_v2"),
            ..Profile::default()
        },
        Profile::default(),
    ]))
    .await;
    let (c, s) = token_login(&h, Kind::Smtp).await;
    assert_eq!(
        s.proxy_header,
        Some(ProxyHeader {
            local: false,
            src: Some(c.local),
            dst: Some(h.proxy.smtp),
        })
    );
    assert_eq!(s.xclient, None);
    let probes: Vec<Seen> = h.smtp_be.seen().into_iter().filter(|s| s.probe).collect();
    assert!(!probes.is_empty(), "the EHLO probe ran");
    for p in probes {
        assert_eq!(
            p.proxy_header,
            Some(ProxyHeader {
                local: true,
                src: None,
                dst: None
            })
        );
    }
}

/// `client_ip = "none"`: no PROXY header and no XCLIENT on any backend; the
/// mocks read none, so a header would break the dialog. Validation warns
/// about each such backend.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_ip_none_sends_nothing() {
    let none = Profile {
        client_ip: Some("none"),
        ..Profile::default()
    };
    let h = Harness::start_with(with_profiles([none; 3])).await;
    for kind in Kind::ALL {
        let (_c, s) = token_login(&h, kind).await;
        assert_eq!(s.proxy_header, None, "{kind:?}");
        assert_eq!(s.xclient, None, "{kind:?}");
    }
    for name in ["imap.backend", "submission.backend", "sieve.backend"] {
        assert!(
            h.proxy
                .log_contains(&format!("config: {name}: client_ip = \"none\"")),
            "{name}"
        );
    }
}

// ── auth_forward ───────────────────────────────────────────────────────────

fn oauthbearer_all() -> Opts {
    let p = Profile {
        auth_forward: Some("oauthbearer"),
        ..Profile::default()
    };
    with_profiles([p; 3])
}

/// `auth_forward = "oauthbearer"`: whichever mechanism the client used, the
/// token goes to the backend as OAUTHBEARER (RFC 7628 §3.1) with the verified
/// identity as GS2 authzid and the backend's name and port.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn token_forwarded_as_oauthbearer() {
    let h = Harness::start_with(oauthbearer_all()).await;
    let token = h.idp.token(EMAIL);
    for kind in Kind::ALL {
        for (mech, ir) in [
            ("XOAUTH2", xoauth2(EMAIL, &token)),
            ("OAUTHBEARER", oauthbearer("", &token)),
        ] {
            let (_c, reply) = h.auth(kind, Src::External, Sni::Public, mech, &ir).await;
            assert!(
                reply.starts_with(ok_prefix(kind)),
                "{kind:?} {mech}: {reply}"
            );
            let s = h.backend(kind).sessions().pop().unwrap();
            assert_eq!(s.mech.as_deref(), Some("OAUTHBEARER"), "{kind:?} {mech}");
            assert_eq!(s.authzid.as_deref(), Some(EMAIL), "{kind:?} {mech}");
            assert_eq!(s.secret.as_deref(), Some(token.as_str()));
            assert_eq!(s.oauth_host.as_deref(), Some(BACKEND_NAME));
            let port = h.backend(kind).addr.port().to_string();
            assert_eq!(s.oauth_port.as_deref(), Some(port.as_str()));
        }
    }
    // A password still goes as PLAIN.
    let (_c, reply) = h
        .auth(
            Kind::Imap,
            Src::Internal,
            Sni::Internal,
            "PLAIN",
            &plain("bob@example.test", "pw"),
        )
        .await;
    assert!(reply.starts_with("a OK"), "{reply}");
    assert_eq!(
        h.imap_be.sessions().pop().unwrap().mech.as_deref(),
        Some("PLAIN")
    );
}

/// The backend rejects the OAUTHBEARER token: its error result is answered
/// with `%x01` (RFC 7628 §3.2.3, a string on ManageSieve), and its final
/// failure is a `backend_reject` like any other.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oauthbearer_backend_rejection_is_a_verdict() {
    let h = Harness::start_with(oauthbearer_all()).await;
    let user = "reject-oauth@example.test";
    let token = h.idp.token(user);
    for (i, kind) in Kind::ALL.into_iter().enumerate() {
        let (mut c, reply) = h
            .auth(
                kind,
                Src::External,
                Sni::Public,
                "XOAUTH2",
                &xoauth2(user, &token),
            )
            .await;
        let expected = match kind {
            Kind::Imap => "a NO [AUTHENTICATIONFAILED] backend rejected token",
            Kind::Smtp => "535 5.7.8 Authentication credentials invalid",
            Kind::Sieve => "NO \"Authentication failed\"",
        };
        assert_eq!(reply, expected, "{kind:?}");
        c.expect_end(kind).await;
        let s = h.backend(kind).sessions().pop().unwrap();
        let answer = if kind == Kind::Sieve {
            "\"AQ==\""
        } else {
            "AQ=="
        };
        assert_eq!(s.error_answer.as_deref(), Some(answer), "{kind:?}");
        let ar = &h.proxy.wait_authresults(i + 1).await[i];
        assert_eq!(
            (ar.result.as_str(), ar.reason.as_str(), ar.user.as_str()),
            ("fail", "backend_reject", user),
            "{kind:?}"
        );
    }
}

/// An error result with status `invalid_request` judged no token: an outage
/// (retry later, no authresult, a backend error), not a failed login. The
/// ManageSieve mock sends it as a literal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oauthbearer_invalid_request_is_an_outage() {
    let h = Harness::start_with(oauthbearer_all()).await;
    let user = "badreq@example.test";
    let token = h.idp.token(user);
    for kind in Kind::ALL {
        let errors = format!(
            "mail_auth_proxy_backend_errors_total{{proto=\"{}\"}}",
            kind.label()
        );
        let before = h.proxy.metric(&errors).await;
        let (_c, reply) = h
            .auth(
                kind,
                Src::External,
                Sni::Public,
                "XOAUTH2",
                &xoauth2(user, &token),
            )
            .await;
        let expected = match kind {
            Kind::Imap => "a NO [UNAVAILABLE] Backend temporarily unavailable",
            Kind::Smtp => "454 4.7.0 Temporary authentication failure",
            Kind::Sieve => "NO (TRYLATER) \"Service temporarily unavailable\"",
        };
        assert_eq!(reply, expected, "{kind:?}");
        let s = h.backend(kind).sessions().pop().unwrap();
        assert!(
            s.error_answer.as_deref().unwrap().contains("AQ=="),
            "{kind:?}"
        );
        assert_eq!(h.proxy.metric(&errors).await, before + 1, "{kind:?}");
        h.wait_session_ended(kind, 1).await;
        assert!(h.proxy.log_contains("as invalid_request"), "{kind:?}");
    }
    assert!(h.proxy.authresults().is_empty());
}

// ── tls ────────────────────────────────────────────────────────────────────

/// Each backend reached the other way than its default: IMAP with STARTTLS
/// (capabilities asked anew over TLS, RFC 9051 §6.2.1), submission and
/// ManageSieve with implicit TLS. The capability probes take the same way;
/// the client sees the backend's extensions as before.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn backend_tls_both_ways() {
    let tls = |t| Profile {
        tls: Some(t),
        ..Profile::default()
    };
    let h = Harness::start_with(with_profiles([
        tls("starttls"),
        tls("implicit"),
        tls("implicit"),
    ]))
    .await;
    for kind in Kind::ALL {
        let (mut c, s) = token_login(&h, kind).await;
        assert_eq!(s.starttls, kind == Kind::Imap, "{kind:?}");
        assert_eq!(s.login.as_deref(), Some(EMAIL));
        // The relay runs over the chosen connection.
        c.send("PING").await;
        assert_eq!(c.line().await, "ECHO PING", "{kind:?}");
    }
    for kind in [Kind::Smtp, Kind::Sieve] {
        let probes: Vec<Seen> = h
            .backend(kind)
            .seen()
            .into_iter()
            .filter(|s| s.probe)
            .collect();
        assert!(!probes.is_empty(), "{kind:?}: the probe ran");
        assert!(probes.iter().all(|p| !p.starttls), "{kind:?}");
    }
    let (_c, ehlo) = h.smtp(Src::External, Sni::Public).await;
    assert!(ehlo.iter().any(|l| l.ends_with("PIPELINING")), "{ehlo:?}");
    let (_c, _, caps) = h.sieve(Src::External, Sni::Public).await;
    assert!(caps.iter().any(|l| l.starts_with("\"SIEVE\" ")), "{caps:?}");
}

/// The defaults: IMAP implicit TLS, submission and ManageSieve STARTTLS.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn backend_tls_defaults() {
    let h = Harness::start().await;
    for kind in Kind::ALL {
        let (_c, s) = token_login(&h, kind).await;
        assert_eq!(s.starttls, kind != Kind::Imap, "{kind:?}");
    }
}

/// A backend that answers the other TLS way than configured is an outage,
/// not a failed login: the IMAP mock expects STARTTLS, the proxy starts TLS.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn backend_tls_mismatch_is_an_outage() {
    let h = Harness::start().await;
    // A second IMAP backend that speaks STARTTLS, while the configuration
    // keeps implicit TLS.
    let starttls = MockBackend::start_mode(
        Kind::Imap,
        h.pki.backend.clone(),
        Profile {
            tls: Some("starttls"),
            ..Profile::default()
        }
        .mode(Kind::Imap),
    )
    .await;
    let text = h
        .config(&Opts::default())
        .replace(&h.imap_be.addr.to_string(), &starttls.addr.to_string());
    h.proxy.reload(&text).await.unwrap();
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
    assert_eq!(reply, "a NO [UNAVAILABLE] Backend temporarily unavailable");
    assert!(h.proxy.authresults().is_empty());
}
