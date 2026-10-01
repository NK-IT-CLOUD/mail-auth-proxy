//! Domains are compared in one canonical form (UTS #46 ToASCII, lower case,
//! no trailing dot): a U-label in the configuration matches an A-label in a
//! login and the other way round, through the domain gate, the users of a
//! rule, the routes and `identity_domains`. The login the backend gets, and
//! the one the log shows, stay exactly as the client sent them.

mod common;
use common::*;

/// The same domain in two spellings.
const U_LOGIN: &str = "MAIL@Exämple.ORG.";
const A_LOGIN: &str = "mail@xn--exmple-cua.org";

fn gate(domain: &str) -> String {
    format!(
        "[legacy]\nallowed_domains = [\"{domain}\"]\nfailure_delay_ms = 100\n[[legacy.rules]]\nname = \"idn\"\nnetworks = [\"127.0.0.0/8\"]\nusers = [\"*@{domain}\"]\n"
    )
}

async fn password(h: &Harness, kind: Kind, login: &str) -> String {
    let (_c, reply) = h
        .auth(kind, Src::Internal, Sni::None, "PLAIN", &plain(login, "pw"))
        .await;
    reply
}

fn logins(m: &MockBackend) -> Vec<String> {
    m.sessions().into_iter().filter_map(|s| s.login).collect()
}

/// Domain gate and rule users: an A-label configuration admits a U-label
/// login with capitals and a trailing dot, and a U-label configuration an
/// A-label login. The backend gets the login byte for byte, the
/// `authresult` line shows it as sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn domain_gate_and_users_take_either_form() {
    for (config, login) in [("xn--exmple-cua.org", U_LOGIN), ("Exämple.org", A_LOGIN)] {
        let h = Harness::start_with(Opts {
            legacy: Some(gate(config)),
            ..Opts::default()
        })
        .await;
        for kind in Kind::ALL {
            let reply = password(&h, kind, login).await;
            let ok = match kind {
                Kind::Imap => reply.starts_with("a OK"),
                Kind::Smtp => reply.starts_with("235 "),
                Kind::Sieve => reply.starts_with("OK"),
            };
            assert!(ok, "{config} {login} {kind:?}: {reply}");
            assert_eq!(logins(h.backend(kind)), [login], "{kind:?}: byte for byte");
        }
        h.proxy.wait_logs("authresult", 3).await;
        for a in h.proxy.authresults() {
            assert_eq!(
                (a.reason.as_str(), a.user.as_str()),
                ("ok", login.replace('ä', "?").as_str())
            );
        }
        // Another domain stays outside.
        let reply = password(&h, Kind::Imap, "mail@example.org").await;
        assert_eq!(
            reply,
            "a NO [AUTHENTICATIONFAILED] backend rejected credentials"
        );
    }
}

/// Routes: a login reaches the backend of the route whose domain is the
/// same domain in the other spelling.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn routes_take_either_form() {
    for (config, login) in [("xn--exmple-cua.org", U_LOGIN), ("exämple.org", A_LOGIN)] {
        let h = Harness::start_with(Opts {
            // Passwords from loopback without SNI; no domain gate, the
            // route decides.
            legacy: Some(
                "[legacy]\nfailure_delay_ms = 100\n[[legacy.rules]]\nname = \"all\"\nnetworks = [\"127.0.0.0/8\"]\n"
                    .to_string(),
            ),
            named: vec![("idn", Kind::Imap, Profile::default())],
            listener_backends: [Some(""), None, None],
            routes: format!(
                "[[routes]]\nname = \"idn\"\ndomains = [\"{config}\"]\nimap = \"idn\"\n"
            ),
            ..Opts::default()
        })
        .await;
        let reply = password(&h, Kind::Imap, login).await;
        assert!(reply.starts_with("a OK"), "{config} {login}: {reply}");
        assert_eq!(logins(h.named("idn")), [login]);
        h.proxy.wait_logs("authresult", 1).await;
        assert_eq!(h.proxy.authresults()[0].backend, "idn");
    }
}

/// `identity_domains`: a token whose identity is the A-label (upper case)
/// passes an issuer bounded to the U-label, and the other way round; the
/// backend gets the identity as the token has it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn identity_domains_take_either_form() {
    for (config, identity) in [
        ("exämple.org", "mail@XN--EXMPLE-CUA.ORG"),
        ("xn--exmple-cua.org", U_LOGIN),
    ] {
        let extra: &'static str =
            Box::leak(format!("identity_domains = [\"{config}\"]").into_boxed_str());
        let h = Harness::start_with(Opts {
            issuer_extra: extra,
            ..Opts::default()
        })
        .await;
        let token = h.idp.token(identity);
        let (_c, reply) = h
            .auth(
                Kind::Imap,
                Src::External,
                Sni::Public,
                "XOAUTH2",
                &xoauth2(identity, &token),
            )
            .await;
        assert!(reply.starts_with("a OK"), "{config} {identity}: {reply}");
        assert_eq!(logins(&h.imap_be), [identity]);
        // A domain outside the bound stays a bad token.
        let token = h.idp.token("mail@example.org");
        let (_c, _, reply) = h
            .auth_rejected(
                Kind::Imap,
                Src::External,
                Sni::Public,
                "XOAUTH2",
                &xoauth2("mail@example.org", &token),
            )
            .await;
        assert_eq!(reply, "a NO [AUTHENTICATIONFAILED] Authentication failed");
    }
}

/// A login whose domain is not a valid name is refused like an unknown
/// domain, without backend contact.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_login_domain_is_unknown() {
    // A rule without users: the domain gate decides.
    let legacy = gate("example.org").replace("users = [\"*@example.org\"]\n", "");
    let h = Harness::start_with(Opts {
        legacy: Some(legacy),
        ..Opts::default()
    })
    .await;
    let reply = password(&h, Kind::Imap, "mail@exa_mple.org").await;
    assert_eq!(
        reply,
        "a NO [AUTHENTICATIONFAILED] backend rejected credentials"
    );
    h.proxy.wait_logs("authresult", 1).await;
    assert_eq!(h.proxy.authresults()[0].reason, "unknown_domain");
    assert!(h.imap_be.sessions().is_empty());
}
