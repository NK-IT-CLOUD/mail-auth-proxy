//! Who the backend sees: the mailbox login is the token's email (a SASL
//! authorisation identity naming anyone else fails), OAUTHBEARER is converted
//! to XOAUTH2 with the same token, a password is forwarded as PLAIN with an
//! empty authzid, and the client address travels in a PROXY v2 header (IMAP,
//! ManageSieve) or XCLIENT (SMTP).

mod common;
use common::*;

const CLAIMED: &str = "admin@example.test";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn backend_login_is_the_token_email() {
    let h = Harness::start().await;
    let token = h.idp.token(EMAIL);
    for kind in Kind::ALL {
        // The same mailbox in another case, its local part alone, and
        // OAUTHBEARER without authzid.
        let local = EMAIL.split('@').next().unwrap().to_ascii_uppercase();
        for (mech, ir) in [
            ("XOAUTH2", xoauth2(&EMAIL.to_ascii_uppercase(), &token)),
            ("XOAUTH2", xoauth2(&local, &token)),
            ("OAUTHBEARER", oauthbearer("", &token)),
        ] {
            let n = h.proxy.authresults().len();
            let mut c = h.ready(kind, Src::External, Sni::Public).await;
            c.send(&auth_command(kind, mech, &ir)).await;
            c.line().await;
            let s = h.backend(kind).sessions().pop().unwrap();
            assert_eq!(s.mech.as_deref(), Some("XOAUTH2"), "{kind:?} {mech}");
            assert_eq!(s.login.as_deref(), Some(EMAIL), "{kind:?} {mech}");
            assert_eq!(s.secret.as_deref(), Some(token.as_str()), "{kind:?} {mech}");
            let ar = &h.proxy.wait_authresults(n + 1).await[n];
            assert_eq!((ar.user.as_str(), ar.reason.as_str()), (EMAIL, "ok"));
            match kind {
                Kind::Imap | Kind::Sieve => {
                    let server = if kind == Kind::Imap {
                        h.proxy.imap
                    } else {
                        h.proxy.sieve
                    };
                    assert_eq!(
                        s.proxy_header,
                        Some(ProxyHeader {
                            local: false,
                            src: Some(c.local),
                            dst: Some(server),
                        }),
                        "{kind:?}"
                    );
                    assert_eq!(c.local.ip().to_string(), "127.0.0.2");
                }
                Kind::Smtp => {
                    // SMTP never sends PROXY protocol; XCLIENT carries the IP.
                    assert_eq!(s.proxy_header, None);
                    assert_eq!(
                        s.xclient.as_deref(),
                        Some("XCLIENT NAME=[UNAVAILABLE] ADDR=127.0.0.2")
                    );
                }
            }
        }
    }
}

/// An OAuth authorisation identity (XOAUTH2 `user=`, OAUTHBEARER `a=`) that
/// names another user than the valid token's fails (RFC 4422 §3.6) without
/// contacting the backend.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oauth_authzid_naming_another_user_fails() {
    let h = Harness::start().await;
    let token = h.idp.token(EMAIL);
    let mut n = 0;
    for kind in Kind::ALL {
        let expected = match kind {
            Kind::Imap => "a NO [AUTHORIZATIONFAILED] Authorization failed",
            Kind::Smtp => "535 5.7.8 Authentication credentials invalid",
            Kind::Sieve => "NO \"Authorization failed\"",
        };
        for (mech, ir) in [
            ("XOAUTH2", xoauth2(CLAIMED, &token)),
            ("OAUTHBEARER", oauthbearer(CLAIMED, &token)),
        ] {
            let (mut c, reply) = h.auth(kind, Src::External, Sni::Public, mech, &ir).await;
            assert_eq!(reply, expected, "{kind:?} {mech}");
            c.expect_end(kind).await;
            n += 1;
            let ar = &h.proxy.wait_authresults(n).await[n - 1];
            assert_eq!(
                (
                    ar.result.as_str(),
                    ar.user.as_str(),
                    ar.reason.as_str(),
                    ar.mech.as_str()
                ),
                ("fail", CLAIMED, "authzid_mismatch", mech),
                "{kind:?} {mech}"
            );
            assert!(h.backend(kind).sessions().is_empty(), "{kind:?} {mech}");
        }
        assert_eq!(
            h.proxy
                .metric(&format!(
                    "mail_auth_proxy_auth_attempts_total{{proto=\"{}\",scope=\"external\",mechanism=\"xoauth2\",result=\"fail\"}}",
                    kind.label()
                ))
                .await,
            1
        );
    }
    for kind in Kind::ALL {
        assert_eq!(
            h.proxy
                .metric(&format!(
                    "mail_auth_proxy_auth_refusals_total{{proto=\"{}\",reason=\"authzid_mismatch\"}}",
                    kind.label()
                ))
                .await,
            2
        );
    }
    // The tokens themselves were valid.
    assert_eq!(
        h.proxy
            .metric("mail_auth_proxy_token_validate_total{result=\"fail\"}")
            .await,
        0
    );
}

/// PLAIN with an authzid equal to the login is accepted; the backend gets an
/// empty authzid. An authzid naming another user is a SASL error.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn plain_authzid() {
    let h = Harness::start().await;
    let ir = b64("bob@example.test\0bob@example.test\0hunter2");
    let (_c, reply) = h
        .auth(Kind::Imap, Src::Internal, Sni::Internal, "PLAIN", &ir)
        .await;
    assert_eq!(reply, "a OK [CAPABILITY IMAP4rev1 IDLE MOVE] Logged in");
    let s = h.imap_be.sessions().pop().unwrap();
    assert_eq!(
        (
            s.authzid.as_deref(),
            s.login.as_deref(),
            s.secret.as_deref()
        ),
        (Some(""), Some("bob@example.test"), Some("hunter2"))
    );

    let ir = b64("admin@example.test\0bob@example.test\0hunter2");
    let (mut c, reply) = h
        .auth(Kind::Imap, Src::Internal, Sni::Internal, "PLAIN", &ir)
        .await;
    // Valid base64 with an unusable credential: NO, not BAD (RFC 9051
    // §6.2.2).
    assert_eq!(reply, "a NO [AUTHENTICATIONFAILED] Authentication failed");
    c.expect_closed().await;
    assert_eq!(h.imap_be.sessions().len(), 1);
    let ar = &h.proxy.wait_authresults(2).await[1];
    assert_eq!(
        (ar.reason.as_str(), ar.mech.as_str()),
        ("protocol", "other")
    );
}
