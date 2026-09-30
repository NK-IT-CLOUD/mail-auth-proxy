//! The account check per backend: a password routed to a backend is checked
//! as that backend says (`account_check` on the backend), else as `[legacy]`
//! says. One mail system's doveadm must not judge another's accounts.

mod common;
use common::*;

fn leak(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}

fn doveadm_keys(dv: &MockDoveadm, key: &std::path::Path) -> String {
    format!(
        "account_check = \"doveadm\", doveadm_url = \"{}\", doveadm_key_file = \"{}\"",
        dv.url(false),
        key.display()
    )
}

/// `one.test` inherits the doveadm of `[legacy]`, `two.test` has none,
/// `three.test` a doveadm of its own. Each unknown account is refused by the
/// check its backend uses, and only that check is asked.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn each_backend_checks_its_own_accounts() {
    let files = tempfile::tempdir().unwrap();
    let (legacy_dv, own_dv) = (
        MockDoveadm::start(None).await,
        MockDoveadm::start(None).await,
    );
    let key = |name: &str, dv: &MockDoveadm| {
        let p = files.path().join(name);
        std::fs::write(&p, format!("{}\n", dv.key)).unwrap();
        p
    };
    let (legacy_key, own_key) = (key("legacy.key", &legacy_dv), key("own.key", &own_dv));
    let routes = r#"
[[routes]]
name = "one"
domains = ["one.test"]
imap = "dovecot"

[[routes]]
name = "two"
domains = ["two.test"]
imap = "stalwart"

[[routes]]
name = "three"
domains = ["three.test"]
imap = "own"
"#;
    let h = Harness::start_with(Opts {
        named: vec![
            ("dovecot", Kind::Imap, Profile::default()),
            (
                "stalwart",
                Kind::Imap,
                Profile {
                    extra: "account_check = \"none\"",
                    ..Profile::default()
                },
            ),
            (
                "own",
                Kind::Imap,
                Profile {
                    extra: leak(doveadm_keys(&own_dv, &own_key)),
                    ..Profile::default()
                },
            ),
        ],
        listener_backends: [Some(""), None, None],
        routes: routes.to_string(),
        legacy: Some(format!(
            "[legacy]\nfailure_delay_ms = 100\n{}\n[[legacy.rules]]\nname = \"all\"\nnetworks = [\"127.0.0.0/8\"]\n",
            doveadm_keys(&legacy_dv, &legacy_key).replace(", ", "\n")
        )),
        ..Opts::default()
    })
    .await;
    let login = |user: &'static str| {
        let h = &h;
        async move {
            let (_c, reply) = h
                .auth(
                    Kind::Imap,
                    Src::Internal,
                    Sni::None,
                    "PLAIN",
                    &plain(user, "pw"),
                )
                .await;
            reply
        }
    };
    let refused = "a NO [AUTHENTICATIONFAILED] backend rejected credentials";
    assert_eq!(login("missing@one.test").await, refused);
    assert!(
        login("missing@two.test").await.starts_with("a OK"),
        "no check: the backend decides"
    );
    assert_eq!(login("missing@three.test").await, refused);
    assert_eq!(*legacy_dv.lookups.lock().unwrap(), ["missing@one.test"]);
    assert_eq!(*own_dv.lookups.lock().unwrap(), ["missing@three.test"]);
    h.proxy.wait_logs("authresult", 3).await;
    let got: Vec<(String, String)> = h
        .proxy
        .authresults()
        .into_iter()
        .map(|a| (a.reason, a.backend))
        .collect();
    assert_eq!(
        got,
        [
            ("unknown_account".to_string(), String::new()),
            ("ok".to_string(), "stalwart".to_string()),
            ("unknown_account".to_string(), String::new()),
        ]
    );
    // The backend that inherits one doveadm among several gets a warning.
    assert!(h.proxy.log_contains(
        "config: backends.dovecot: uses legacy.account_check = \"doveadm\" although [imap] has 3 backends"
    ));
}
