//! The legacy (PLAIN/LOGIN) gate end to end, with the real binary:
//!
//! - a matrix per rule: source × SNI × protocol × mechanism × user;
//! - the domain gate (list and reloaded file), the account check against a
//!   mock doveadm HTTP API (exists / missing / down → outage, http and
//!   https), the per-account throttle;
//! - no account enumeration: every refusal gets the wrong-password reply,
//!   no earlier than `failure_delay_ms`, with comparable timing;
//! - `public = true` validation, `[password_gate]` next to `[legacy]`
//!   settings, metrics opt-in.

mod common;
use common::*;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mech {
    /// SASL PLAIN with initial response.
    Plain,
    /// IMAP `LOGIN` command / SMTP `AUTH LOGIN` with the user as initial
    /// response.
    Login,
}

impl Mech {
    fn logged(self) -> &'static str {
        match self {
            Mech::Plain => "PLAIN",
            Mech::Login => "LOGIN",
        }
    }
}

/// What the client was told.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Answer {
    Ok,
    /// "not available on this endpoint": the mechanism is not offered here.
    NotHere,
    /// The wrong-password reply.
    Failed,
    /// Retry later.
    Unavailable,
}

fn classify(kind: Kind, reply: &str) -> Answer {
    let is = |p: &str| reply.starts_with(p);
    match kind {
        Kind::Imap if is("a OK") => Answer::Ok,
        Kind::Imap if reply == "a NO password authentication not available on this endpoint" => {
            Answer::NotHere
        }
        Kind::Imap if reply == "a NO [AUTHENTICATIONFAILED] backend rejected credentials" => {
            Answer::Failed
        }
        Kind::Imap if reply == "a NO [UNAVAILABLE] Backend temporarily unavailable" => {
            Answer::Unavailable
        }
        Kind::Smtp if reply == "235 2.7.0 Authentication successful" => Answer::Ok,
        Kind::Smtp
            if reply == "504 5.5.4 password authentication not available on this endpoint" =>
        {
            Answer::NotHere
        }
        Kind::Smtp if reply == "535 5.7.8 Authentication credentials invalid" => Answer::Failed,
        Kind::Smtp if reply == "454 4.7.0 Temporary authentication failure" => Answer::Unavailable,
        Kind::Sieve if is("OK") => Answer::Ok,
        Kind::Sieve if reply == "NO \"password authentication not available on this endpoint\"" => {
            Answer::NotHere
        }
        Kind::Sieve if reply == "NO \"Authentication failed\"" => Answer::Failed,
        Kind::Sieve if reply == "NO (TRYLATER) \"Service temporarily unavailable\"" => {
            Answer::Unavailable
        }
        _ => panic!("{kind:?}: unexpected reply {reply:?}"),
    }
}

/// The password mechanisms a session advertises: (PLAIN, LOGIN).
fn offered(kind: Kind, advert: &[String]) -> (bool, bool) {
    match kind {
        Kind::Imap => {
            let g = &advert[0];
            let login = g.contains("AUTH=LOGIN");
            // LOGINDISABLED exactly when LOGIN is not offered.
            assert_eq!(g.contains("LOGINDISABLED"), !login, "{g}");
            (g.contains("AUTH=PLAIN"), login)
        }
        Kind::Smtp => {
            let last = advert.last().unwrap();
            assert!(last.starts_with("250 AUTH XOAUTH2 OAUTHBEARER"), "{last}");
            (last.contains(" PLAIN"), last.contains(" LOGIN"))
        }
        Kind::Sieve => {
            let sasl = advert.iter().find(|l| l.starts_with("\"SASL\"")).unwrap();
            assert!(!sasl.contains("LOGIN"), "{sasl}");
            (sasl.contains("PLAIN"), false)
        }
    }
}

/// One password attempt: the advertised mechanisms, the reply, and the time
/// from the last credential byte to the reply.
struct Attempt {
    offered: (bool, bool),
    answer: Answer,
    reply: String,
    took: Duration,
}

async fn attempt(
    h: &Harness,
    kind: Kind,
    src: Src,
    sni: Sni,
    mech: Mech,
    user: &str,
    pass: &str,
) -> Attempt {
    let (mut c, advert) = match kind {
        Kind::Imap => {
            let (c, g) = h.imap(src, sni).await;
            (c, vec![g])
        }
        Kind::Smtp => h.smtp(src, sni).await,
        Kind::Sieve => {
            let (c, _, caps) = h.sieve(src, sni).await;
            (c, caps)
        }
    };
    let offered = offered(kind, &advert);
    let last = match (kind, mech) {
        (Kind::Imap, Mech::Plain) => format!("a AUTHENTICATE PLAIN {}", plain(user, pass)),
        (Kind::Imap, Mech::Login) => format!("a LOGIN {user} {pass}"),
        (Kind::Smtp, Mech::Plain) => format!("AUTH PLAIN {}", plain(user, pass)),
        (Kind::Smtp, Mech::Login) => {
            c.send(&format!("AUTH LOGIN {}", b64(user))).await;
            assert_eq!(c.line().await, "334 UGFzc3dvcmQ6");
            b64(pass)
        }
        (Kind::Sieve, Mech::Plain) => format!("AUTHENTICATE \"PLAIN\" \"{}\"", plain(user, pass)),
        (Kind::Sieve, Mech::Login) => unreachable!("ManageSieve has no LOGIN"),
    };
    c.send(&last).await;
    let t0 = Instant::now();
    let reply = c.line().await;
    let took = t0.elapsed();
    Attempt {
        offered,
        answer: classify(kind, &reply),
        reply,
        took,
    }
}

fn mechs(kind: Kind) -> &'static [Mech] {
    match kind {
        Kind::Sieve => &[Mech::Plain],
        _ => &[Mech::Plain, Mech::Login],
    }
}

/// The last authresult line after `before` lines: (reason, rule, user).
async fn last_result(h: &Harness, before: usize) -> (String, String, String, String) {
    let ars = h.proxy.wait_authresults(before + 1).await;
    assert_eq!(ars.len(), before + 1);
    let ar = ars.last().unwrap();
    let rule = h.proxy.authresult_rules().last().unwrap().clone();
    (ar.reason.clone(), rule, ar.user.clone(), ar.pwfp.clone())
}

fn is_fp(s: &str) -> bool {
    s.len() == 16 && s.chars().all(|c| c.is_ascii_hexdigit())
}

const DELAY_MS: u64 = 300;

fn opts(legacy: String) -> Opts {
    Opts {
        legacy: Some(legacy),
        ..Opts::default()
    }
}

// ── The rule matrix ─────────────────────────────────────────────────────────

/// Two rules: `internal` (127.0.0.1 with the internal SNI, everything) and
/// `partner` (127.0.0.2, any SNI, two users and a domain, IMAP + submission,
/// PLAIN only). Every cell: what is advertised, what the client is told,
/// what is logged, and whether the password reached the backend.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rule_matrix() {
    let h = Harness::start_with(opts(format!(
        r#"[scope]
internal_networks = ["127.0.0.1/32"]

[legacy]
failure_delay_ms = {DELAY_MS}

[[legacy.rules]]
name = "internal"
networks = ["127.0.0.1/32"]
sni = ["{INTERNAL_SNI}"]

[[legacy.rules]]
name = "partner"
networks = ["127.0.0.2/32"]
users = ["partner@example.test", "*@partner.test"]
protocols = ["imap", "submission"]
mechanisms = ["PLAIN"]
"#
    )))
    .await;
    let users = [
        "partner@example.test",
        "someone@partner.test",
        "other@example.test",
    ];
    let mut cells = 0;
    for kind in Kind::ALL {
        for src in [Src::Internal, Src::External] {
            for sni in [Sni::Internal, Sni::Public, Sni::None] {
                for &mech in mechs(kind) {
                    for user in users {
                        cells += 1;
                        let id = format!("{kind:?}-{src:?}-{sni:?}-{mech:?}-{user}");
                        // What the rules say.
                        let internal = src == Src::Internal && sni == Sni::Internal;
                        let partner_endpoint = src == Src::External && kind != Kind::Sieve;
                        let exp_offered = if internal {
                            (true, kind != Kind::Sieve)
                        } else if partner_endpoint {
                            (true, false)
                        } else {
                            (false, false)
                        };
                        let offered_here = match mech {
                            Mech::Plain => exp_offered.0,
                            Mech::Login => exp_offered.1,
                        };
                        let partner_user = user != "other@example.test";
                        let (exp_answer, exp_reason, exp_rule) = if !offered_here {
                            (Answer::NotHere, "blocked_endpoint", "")
                        } else if internal {
                            (Answer::Ok, "ok", "internal")
                        } else if partner_user {
                            (Answer::Ok, "ok", "partner")
                        } else {
                            (Answer::Failed, "blocked_endpoint", "")
                        };

                        let before = h.proxy.authresults().len();
                        let sessions = h.backend(kind).sessions().len();
                        let pass = format!("pw-{id}");
                        let a = attempt(&h, kind, src, sni, mech, user, &pass).await;
                        assert_eq!(a.offered, exp_offered, "{id}");
                        assert_eq!(a.answer, exp_answer, "{id}: {}", a.reply);
                        let (reason, rule, logged_user, pwfp) = last_result(&h, before).await;
                        assert_eq!(
                            (reason.as_str(), rule.as_str()),
                            (exp_reason, exp_rule),
                            "{id}"
                        );
                        assert_eq!(logged_user, user, "{id}");
                        assert_eq!(
                            h.proxy.authresults().last().unwrap().mech,
                            mech.logged(),
                            "{id}"
                        );
                        let ok = exp_answer == Answer::Ok;
                        assert_eq!(ok, pwfp.is_empty(), "{id}: pwfp {pwfp:?}");
                        assert!(ok || is_fp(&pwfp), "{id}");
                        let seen = h.backend(kind).sessions();
                        if ok {
                            assert_eq!(seen.len(), sessions + 1, "{id}");
                            assert_eq!(seen.last().unwrap().secret.as_deref(), Some(pass.as_str()));
                        } else {
                            // A refused password never reaches the backend.
                            assert_eq!(seen.len(), sessions, "{id}");
                            assert!(
                                h.backend(kind)
                                    .seen()
                                    .iter()
                                    .all(|s| s.secret.as_deref() != Some(pass.as_str())),
                                "{id}"
                            );
                        }
                        // The wrong-password reply is never faster than the delay.
                        if exp_answer == Answer::Failed {
                            assert!(
                                a.took >= Duration::from_millis(DELAY_MS),
                                "{id}: {:?}",
                                a.took
                            );
                        }
                    }
                }
            }
        }
    }
    assert_eq!(cells, 2 * 3 * (2 + 2 + 1) * 3);
}

// ── Domain gate and account check ───────────────────────────────────────────

fn doveadm_section(
    dv: &MockDoveadm,
    key_file: &std::path::Path,
    https_ca: Option<&std::path::Path>,
) -> String {
    let ca = https_ca
        .map(|p| format!("doveadm_ca_file = \"{}\"\n", p.display()))
        .unwrap_or_default();
    format!(
        "account_check = \"doveadm\"\ndoveadm_url = \"{}\"\ndoveadm_key_file = \"{}\"\n{ca}",
        dv.url(https_ca.is_some()),
        key_file.display()
    )
}

fn write_key(dir: &std::path::Path, dv: &MockDoveadm) -> std::path::PathBuf {
    let p = dir.join("doveadm.key");
    std::fs::write(&p, format!("{}\n", dv.key)).unwrap();
    p
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn domain_gate_and_account_check() {
    let files = tempfile::tempdir().unwrap();
    let dv = MockDoveadm::start(None).await;
    let key = write_key(files.path(), &dv);
    let domains = files.path().join("domains");
    std::fs::write(&domains, "# relay domains\nfile.test\n").unwrap();
    let h = Harness::start_with(opts(format!(
        r#"[legacy]
allowed_domains = ["example.test"]
domains_file = "{}"
failure_delay_ms = {DELAY_MS}
{}
[[legacy.rules]]
name = "all"
networks = ["127.0.0.0/8"]
"#,
        domains.display(),
        doveadm_section(&dv, &key, None)
    )))
    .await;

    let check = |user: &'static str, answer: Answer, reason: &'static str, lookups: usize| {
        let h = &h;
        let dv = &dv;
        async move {
            let before = h.proxy.authresults().len();
            let sessions = h.imap_be.sessions().len();
            let a = attempt(
                h,
                Kind::Imap,
                Src::External,
                Sni::Public,
                Mech::Plain,
                user,
                "pw",
            )
            .await;
            assert_eq!(a.answer, answer, "{user}: {}", a.reply);
            let (r, rule, _, _) = last_result(h, before).await;
            assert_eq!((r.as_str(), rule.as_str()), (reason, "all"), "{user}");
            assert_eq!(dv.lookups().len(), lookups, "{user}: {:?}", dv.lookups());
            let forwarded = h.imap_be.sessions().len() - sessions;
            assert_eq!(
                forwarded,
                usize::from(matches!(reason, "ok" | "backend_reject")),
                "{user}"
            );
        }
    };
    // Unknown domain: neither doveadm nor the backend is asked.
    check("a@unknown.test", Answer::Failed, "unknown_domain", 0).await;
    check("nodomain", Answer::Failed, "unknown_domain", 0).await;
    // Unknown account: asked once, then answered from the cache.
    check("missing@example.test", Answer::Failed, "unknown_account", 1).await;
    check("missing@example.test", Answer::Failed, "unknown_account", 1).await;
    // A wildcard login would make doveadm list users: never sent.
    check("*@example.test", Answer::Failed, "unknown_account", 1).await;
    check("alice@example.test", Answer::Ok, "ok", 2).await;
    check("alice@FILE.test", Answer::Ok, "ok", 3).await;
    check("reject@example.test", Answer::Failed, "backend_reject", 4).await;
    assert_eq!(
        dv.lookups(),
        [
            "missing@example.test",
            "alice@example.test",
            "alice@FILE.test",
            "reject@example.test"
        ]
    );

    // The domains file is re-read when it changes.
    check("a@new.test", Answer::Failed, "unknown_domain", 4).await;
    std::fs::write(&domains, "file.test\nnew.test\n").unwrap();
    tokio::time::sleep(Duration::from_millis(2200)).await;
    check("a@new.test", Answer::Ok, "ok", 5).await;
    assert!(h.proxy.log_contains("legacy list file reloaded"));

    // Failed attempts are counted as failed logins, per mechanism.
    let fail = h
        .proxy
        .metric(r#"mail_auth_proxy_auth_attempts_total{proto="imap",scope="external",mechanism="plain",result="fail"}"#)
        .await;
    assert_eq!(fail, 7);

    // A broken domains file fails closed (inline domains included), is
    // counted and logged at ERROR, and recovers when fixed.
    std::fs::write(&domains, "new.test\nnot a domain\n").unwrap();
    tokio::time::sleep(Duration::from_millis(2200)).await;
    check("alice@example.test", Answer::Failed, "unknown_domain", 5).await;
    assert!(h.proxy.log_contains("ERROR"), "logged at ERROR");
    assert!(
        h.proxy
            .metric(r#"mail_auth_proxy_legacy_list_errors_total{list="domains_file"}"#)
            .await
            >= 1
    );
    std::fs::write(&domains, "new.test\n").unwrap();
    tokio::time::sleep(Duration::from_millis(2200)).await;
    check("a@new.test", Answer::Ok, "ok", 5).await;
    assert!(h.proxy.log_contains("legacy list file usable again"));
}

/// An account check that cannot answer is an outage, never a reject: the
/// retry-later reply, `backend_errors`, no authresult line, no failed login.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn doveadm_down_is_an_outage() {
    let files = tempfile::tempdir().unwrap();
    let dv = MockDoveadm::start(None).await;
    let key = write_key(files.path(), &dv);
    let h = Harness::start_with(opts(format!(
        "[legacy]\nfailure_delay_ms = {DELAY_MS}\n{}\n[[legacy.rules]]\nname = \"all\"\nnetworks = [\"127.0.0.0/8\"]\n",
        doveadm_section(&dv, &key, None)
    )))
    .await;
    let outage = |kind: Kind, user: &'static str| {
        let h = &h;
        async move {
            let before = h.proxy.authresults().len();
            let label = kind.label();
            let errors = format!("mail_auth_proxy_backend_errors_total{{proto=\"{label}\"}}");
            let e0 = h.proxy.metric(&errors).await;
            let ended = h.sessions_ended(kind);
            let a = attempt(h, kind, Src::Internal, Sni::None, Mech::Plain, user, "pw").await;
            assert_eq!(
                a.answer,
                Answer::Unavailable,
                "{kind:?} {user}: {}",
                a.reply
            );
            h.wait_session_ended(kind, ended + 1).await;
            assert_eq!(
                h.proxy.authresults().len(),
                before,
                "no authresult for an outage"
            );
            assert_eq!(h.proxy.metric(&errors).await, e0 + 1);
            assert_eq!(h.backend(kind).sessions().len(), 0, "backend never asked");
        }
    };
    // doveadm answers EX_TEMPFAIL.
    outage(Kind::Imap, "tempfail@example.test").await;
    // doveadm is gone (connection refused).
    dv.shutdown().await;
    for kind in Kind::ALL {
        outage(kind, "bob@example.test").await;
    }
    let m = h.proxy.metrics().await;
    assert!(
        m.iter()
            .filter(|(k, _)| k.starts_with("mail_auth_proxy_auth_attempts_total"))
            .all(|(_, v)| *v == 0),
        "an outage is not a failed login"
    );
}

/// A wrong API key (HTTP 401) is an outage too, not a verdict on the user.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn doveadm_wrong_key_is_an_outage() {
    let files = tempfile::tempdir().unwrap();
    let dv = MockDoveadm::start(None).await;
    let key = files.path().join("doveadm.key");
    std::fs::write(&key, "not-the-key\n").unwrap();
    let h = Harness::start_with(opts(format!(
        "[legacy]\n{}\n[[legacy.rules]]\nname = \"all\"\nnetworks = [\"127.0.0.0/8\"]\n",
        doveadm_section(&dv, &key, None)
    )))
    .await;
    let a = attempt(
        &h,
        Kind::Smtp,
        Src::Internal,
        Sni::None,
        Mech::Plain,
        "bob@example.test",
        "pw",
    )
    .await;
    assert_eq!(a.answer, Answer::Unavailable, "{}", a.reply);
    assert!(dv.lookups().is_empty());
}

/// doveadm over https: verified against `doveadm_ca_file`; without it the
/// system store does not know the test CA and the check is an outage.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn doveadm_over_verified_https() {
    let files = tempfile::tempdir().unwrap();
    let pki = Pki::new();
    let dv = MockDoveadm::start(Some(pki.proxy_server.clone())).await;
    let key = write_key(files.path(), &dv);
    let rule = "\n[[legacy.rules]]\nname = \"all\"\nnetworks = [\"127.0.0.0/8\"]\n";
    let ca = pki.ca_file.clone();
    let h = Harness::start_on(
        pki,
        opts(format!(
            "[legacy]\n{}{rule}",
            doveadm_section(&dv, &key, Some(&ca))
        )),
    )
    .await;
    let a = attempt(
        &h,
        Kind::Imap,
        Src::Internal,
        Sni::None,
        Mech::Plain,
        "alice@example.test",
        "pw",
    )
    .await;
    assert_eq!(a.answer, Answer::Ok, "{}", a.reply);
    let a = attempt(
        &h,
        Kind::Imap,
        Src::Internal,
        Sni::None,
        Mech::Plain,
        "missing@example.test",
        "pw",
    )
    .await;
    assert_eq!(a.answer, Answer::Failed, "{}", a.reply);
    assert_eq!(dv.lookups().len(), 2);

    let untrusted = format!(
        "[legacy]\naccount_check = \"doveadm\"\ndoveadm_url = \"{}\"\ndoveadm_key_file = \"{}\"\n{rule}",
        dv.url(true),
        key.display()
    );
    let h2 = Harness::start_with(opts(untrusted)).await;
    let a = attempt(
        &h2,
        Kind::Imap,
        Src::Internal,
        Sni::None,
        Mech::Plain,
        "alice@example.test",
        "pw",
    )
    .await;
    assert_eq!(a.answer, Answer::Unavailable, "{}", a.reply);
    assert_eq!(
        dv.lookups().len(),
        2,
        "no request without a verified TLS session"
    );
}

// ── Throttle ────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn throttle_after_backend_rejections() {
    let h = Harness::start_with(opts(format!(
        "[legacy]\nfailure_delay_ms = {DELAY_MS}\nthrottle = {{ failures = 2, window_secs = 3600 }}\n[[legacy.rules]]\nname = \"all\"\nnetworks = [\"127.0.0.0/8\"]\n"
    )))
    .await;
    let mut reasons = Vec::new();
    for kind in [Kind::Imap, Kind::Smtp, Kind::Imap, Kind::Sieve] {
        let before = h.proxy.authresults().len();
        let a = attempt(
            &h,
            kind,
            Src::Internal,
            Sni::None,
            Mech::Plain,
            "reject-bob@example.test",
            "pw",
        )
        .await;
        assert_eq!(a.answer, Answer::Failed, "{}", a.reply);
        reasons.push(last_result(&h, before).await.0);
    }
    // Per account, across protocols: two rejections, then refused locally.
    assert_eq!(
        reasons,
        ["backend_reject", "backend_reject", "throttled", "throttled"]
    );
    let forwarded: usize = Kind::ALL
        .iter()
        .map(|k| h.backend(*k).sessions().len())
        .sum();
    assert_eq!(forwarded, 2);
    // Another account is not affected.
    let a = attempt(
        &h,
        Kind::Imap,
        Src::Internal,
        Sni::None,
        Mech::Plain,
        "carol@example.test",
        "pw",
    )
    .await;
    assert_eq!(a.answer, Answer::Ok, "{}", a.reply);
}

// ── No account enumeration ──────────────────────────────────────────────────

/// Unknown domain, unknown account, throttled, a user the rule does not
/// allow and a wrong password: per protocol the same reply bytes, none
/// faster than `failure_delay_ms`, all within a tolerance of each other. The
/// log keeps them apart.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refusals_are_indistinguishable() {
    let files = tempfile::tempdir().unwrap();
    let dv = MockDoveadm::start(None).await;
    let key = write_key(files.path(), &dv);
    let h = Harness::start_with(opts(format!(
        r#"[legacy]
allowed_domains = ["example.test"]
failure_delay_ms = {DELAY_MS}
throttle = {{ failures = 1, window_secs = 3600 }}
{}
[[legacy.rules]]
name = "users"
networks = ["127.0.0.0/8"]
users = ["*@example.test", "*@gone.test"]
"#,
        doveadm_section(&dv, &key, None)
    )))
    .await;
    // Throttle the account first (one rejection).
    for kind in Kind::ALL {
        let a = attempt(
            &h,
            kind,
            Src::Internal,
            Sni::None,
            Mech::Plain,
            &format!("reject-t-{}@example.test", kind.label()),
            "pw",
        )
        .await;
        assert_eq!(a.answer, Answer::Failed);
    }
    let cases = [
        ("someone@elsewhere.test", "blocked_endpoint", ""),
        ("a@gone.test", "unknown_domain", "users"),
        ("missing@example.test", "unknown_account", "users"),
        ("reject-t-{p}@example.test", "throttled", "users"),
        ("reject-w-{p}@example.test", "backend_reject", "users"),
    ];
    let mut report = Vec::new();
    for kind in Kind::ALL {
        let mut replies = Vec::new();
        let mut times = Vec::new();
        for (user, reason, rule) in cases {
            let user = user.replace("{p}", kind.label());
            let before = h.proxy.authresults().len();
            let a = attempt(&h, kind, Src::Internal, Sni::None, Mech::Plain, &user, "pw").await;
            let (r, ru, _, pwfp) = last_result(&h, before).await;
            assert_eq!((r.as_str(), ru.as_str()), (reason, rule), "{kind:?} {user}");
            assert!(is_fp(&pwfp));
            replies.push(a.reply);
            times.push(a.took);
        }
        assert!(
            replies.iter().all(|r| *r == replies[0]),
            "{kind:?}: {replies:?}"
        );
        assert_eq!(classify(kind, &replies[0]), Answer::Failed);
        let min = *times.iter().min().unwrap();
        let max = *times.iter().max().unwrap();
        assert!(
            min >= Duration::from_millis(DELAY_MS),
            "{kind:?}: {times:?}"
        );
        assert!(
            max - min < Duration::from_millis(150),
            "{kind:?}: {times:?}"
        );
        report.push(format!(
            "{kind:?}: {:?}",
            times.iter().map(|t| t.as_millis()).collect::<Vec<_>>()
        ));
    }
    // The legacy reasons, pinned byte for byte after the timestamp (IMAP).
    let stamp = regex::Regex::new(r"^\S+Z  ").unwrap();
    let fp = regex::Regex::new(r#"pwfp="[0-9a-f]{16}""#).unwrap();
    let imap: Vec<String> = h
        .proxy
        .logs()
        .iter()
        .filter(|l| l.contains("authresult") && l.contains(r#"proto="imap""#))
        .skip(1)
        .map(|l| {
            fp.replace(&stamp.replace(l, ""), r#"pwfp="<fp>""#)
                .into_owned()
        })
        .collect();
    let line = |user: &str, reason: &str, rule: &str| {
        format!(
            r#"WARN authlog: authresult result="fail" proto="imap" scope="external" mech=PLAIN user={user} peer=127.0.0.1 reason="{reason}" pwfp="<fp>" rule="{rule}""#
        )
    };
    assert_eq!(
        imap,
        [
            line("someone@elsewhere.test", "blocked_endpoint", ""),
            line("a@gone.test", "unknown_domain", "users"),
            line("missing@example.test", "unknown_account", "users"),
            line("reject-t-imap@example.test", "throttled", "users"),
            line("reject-w-imap@example.test", "backend_reject", "users"),
        ]
    );
    eprintln!(
        "refusal reply times (ms, cases in order {:?}): {report:?}",
        cases.map(|c| c.1)
    );
}

/// A backend that takes 800 ms to reject (like Dovecot's auth_failure_delay):
/// refusals by the gate learn that latency and are answered as late, with
/// jitter, so the two timing distributions overlap instead of the refusals
/// standing out at `failure_delay_ms`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refusals_follow_a_slow_backend() {
    let h = Harness::start_with(opts(format!(
        "[legacy]\nallowed_domains = [\"example.test\"]\nfailure_delay_ms = {DELAY_MS}\n[[legacy.rules]]\nname = \"all\"\nnetworks = [\"127.0.0.0/8\"]\n"
    )))
    .await;
    let try_once = |user: String| {
        let h = &h;
        async move {
            let a = attempt(
                h,
                Kind::Imap,
                Src::Internal,
                Sni::None,
                Mech::Plain,
                &user,
                "pw",
            )
            .await;
            assert_eq!(a.answer, Answer::Failed, "{user}: {}", a.reply);
            a.took
        }
    };
    // Warm-up: the proxy learns the backend's rejection latency.
    for i in 0..3 {
        try_once(format!("slowreject-w{i}@example.test")).await;
    }
    let (mut refused, mut rejected) = (Vec::new(), Vec::new());
    for i in 0..6 {
        refused.push(try_once(format!("u{i}@unknown.test")).await);
        rejected.push(try_once(format!("slowreject-{i}@example.test")).await);
    }
    let ms = |v: &[Duration]| v.iter().map(|d| d.as_millis()).collect::<Vec<_>>();
    eprintln!(
        "slow backend: refused {:?} ms, rejected {:?} ms",
        ms(&refused),
        ms(&rejected)
    );
    let (rmin, rmax) = (
        *refused.iter().min().unwrap(),
        *refused.iter().max().unwrap(),
    );
    let (bmin, bmax) = (
        *rejected.iter().min().unwrap(),
        *rejected.iter().max().unwrap(),
    );
    assert!(
        rmin >= SLOW_REJECT - Duration::from_millis(50),
        "refusals padded to the backend: {refused:?}"
    );
    assert!(bmin >= SLOW_REJECT, "{rejected:?}");
    assert!(
        rmin.max(bmin) <= rmax.min(bmax),
        "distributions overlap: refused {refused:?} rejected {rejected:?}"
    );
    assert!(rmax > rmin && bmax > bmin, "jitter on both");
}

/// An outage on the password path (account check down, backend temporarily
/// unavailable) only happens to accounts that passed the earlier stages, so
/// it is answered no earlier than a refusal: an instant retry-later next to
/// the delayed refusals would tell those accounts apart.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn password_outages_are_padded_like_refusals() {
    let files = tempfile::tempdir().unwrap();
    let dv = MockDoveadm::start(None).await;
    let key = write_key(files.path(), &dv);
    let h = Harness::start_with(opts(format!(
        "[legacy]\nallowed_domains = [\"example.test\"]\nfailure_delay_ms = {DELAY_MS}\n{}\n[[legacy.rules]]\nname = \"all\"\nnetworks = [\"127.0.0.0/8\"]\n",
        doveadm_section(&dv, &key, None)
    )))
    .await;
    let cases = [
        // Refused by the domain gate.
        ("a@unknown.test", Answer::Failed),
        // doveadm answers EX_TEMPFAIL: the account check is down.
        ("tempfail@example.test", Answer::Unavailable),
        // The account passes; the backend answers "temporarily unavailable".
        ("unavail-{p}@example.test", Answer::Unavailable),
    ];
    for kind in Kind::ALL {
        let mut times = Vec::new();
        for (user, answer) in cases {
            let user = user.replace("{p}", kind.label());
            let a = attempt(&h, kind, Src::Internal, Sni::None, Mech::Plain, &user, "pw").await;
            assert_eq!(a.answer, answer, "{kind:?} {user}: {}", a.reply);
            times.push(a.took);
        }
        let min = *times.iter().min().unwrap();
        let max = *times.iter().max().unwrap();
        assert!(
            min >= Duration::from_millis(DELAY_MS),
            "{kind:?}: {times:?}"
        );
        assert!(
            max - min < Duration::from_millis(150),
            "{kind:?}: {times:?}"
        );
    }
}

// ── Configuration ───────────────────────────────────────────────────────────

fn check_config(pki: &Pki, extra: &str) -> (bool, String) {
    let cfg = format!(
        r#"config_version = 2
[tls]
cert = "{}"
key = "{}"
[imap]
listen = "127.0.0.10:0"
backend = {{ address = "127.0.0.1:1", verify_name = "{BACKEND_NAME}", ca_file = "{}" }}
[oauth]
[[oauth.issuers]]
issuer = "{ISSUER}"
jwks_url = "https://idp.test/certs"
audiences = ["{AUDIENCE}"]
token_type = "keycloak"
{extra}"#,
        pki.proxy_cert.display(),
        pki.proxy_key.display(),
        pki.ca_file.display()
    );
    let path = pki.dir.path().join("check.toml");
    std::fs::write(&path, cfg).unwrap();
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_mail-auth-proxy"))
        .arg("--check-config")
        .arg(&path)
        .output()
        .unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.success(), text)
}

#[test]
fn public_rules_need_public_true() {
    let pki = Pki::new();
    let rule = "[[legacy.rules]]\nname = \"everyone\"\nnetworks = [\"0.0.0.0/0\", \"::/0\"]\n";
    let (ok, out) = check_config(&pki, rule);
    assert!(!ok, "{out}");
    assert!(
        out.contains(
            "public networks (0.0.0.0/0, ::/0) without users or users_file need public = true"
        ),
        "{out}"
    );
    let (ok, out) = check_config(&pki, &format!("{rule}public = true\n"));
    assert!(ok, "{out}");
    assert!(
        out.contains("accepts passwords of every user from public networks"),
        "{out}"
    );
    // With a user list it is not "everyone": no flag needed.
    let users = pki.dir.path().join("legacy-users");
    std::fs::write(&users, "# opt-in\nalice@example.test\n*@partner.test\n").unwrap();
    let (ok, out) = check_config(
        &pki,
        &format!("{rule}users_file = \"{}\"\n", users.display()),
    );
    assert!(ok, "{out}");
    // --check-config reads the list files.
    std::fs::write(&users, "a b\n").unwrap();
    let (ok, out) = check_config(
        &pki,
        &format!("{rule}users_file = \"{}\"\n", users.display()),
    );
    assert!(
        !ok && out.contains("users_file") && out.contains("line 1"),
        "{out}"
    );
    let (ok, out) = check_config(&pki, "[legacy]\naccount_check = \"doveadm\"\ndoveadm_url = \"https://127.0.0.1:1/doveadm/v1\"\ndoveadm_key_file = \"/nonexistent/key\"\n");
    assert!(!ok && out.contains("legacy.doveadm_key_file"), "{out}");
}

/// An empty list-file path is one problem ("is empty"), not also a failed read.
#[test]
fn empty_list_file_path_is_reported_once() {
    let pki = Pki::new();
    let (ok, out) = check_config(
        &pki,
        "[legacy]\ndomains_file = \"\"\n[[legacy.rules]]\nname = \"internal\"\nnetworks = [\"10.0.0.0/8\"]\nusers_file = \"\"\n",
    );
    assert!(!ok, "{out}");
    assert!(out.contains("legacy.domains_file is empty"), "{out}");
    assert!(
        out.contains("legacy.rules[internal].users_file is empty"),
        "{out}"
    );
    assert_eq!(out.matches("domains_file").count(), 1, "{out}");
    assert_eq!(out.matches("users_file").count(), 1, "{out}");
}

/// `[password_gate]` stays the short form of one rule and combines with
/// `[legacy]` settings: here the domain gate applies to it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn password_gate_with_legacy_settings() {
    let h = Harness::start_with(opts(format!(
        "[password_gate]\nenabled = true\nsni = [\"{INTERNAL_SNI}\"]\ninternal_networks = [\"127.0.0.1/32\"]\n[legacy]\nallowed_domains = [\"example.test\"]\nfailure_delay_ms = {DELAY_MS}\n"
    )))
    .await;
    let before = h.proxy.authresults().len();
    let a = attempt(
        &h,
        Kind::Imap,
        Src::Internal,
        Sni::Internal,
        Mech::Login,
        "a@other.test",
        "pw",
    )
    .await;
    assert_eq!(a.answer, Answer::Failed);
    let (r, rule, _, _) = last_result(&h, before).await;
    assert_eq!(
        (r.as_str(), rule.as_str()),
        ("unknown_domain", "password_gate")
    );
    let a = attempt(
        &h,
        Kind::Imap,
        Src::Internal,
        Sni::Internal,
        Mech::Login,
        "a@example.test",
        "pw",
    )
    .await;
    assert_eq!(a.answer, Answer::Ok);
    assert_eq!(h.proxy.authresult_rules().last().unwrap(), "password_gate");
    // The label follows the short form's networks.
    assert_eq!(h.proxy.authresults().last().unwrap().scope, "internal");
}

/// Metrics are opt-in: `enabled = false` serves no endpoint, and auth works
/// as before.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn metrics_disabled_serves_nothing() {
    let h = Harness::start_with(Opts {
        metrics: false,
        ..Opts::default()
    })
    .await;
    assert!(!h.proxy.log_contains("metrics endpoint up"));
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
    h.proxy.wait_authresults(1).await;
    assert!(!h.proxy.log_contains("metrics endpoint up"));
}

/// A password longer than the proxy forwards (1024 bytes) is refused before
/// the gate, like a wrong password: the same reply, no earlier than
/// `failure_delay_ms`, an `oversize` record, and no backend contact. Without
/// the cap, Postfix would answer 500 (beyond `smtpd_sasl_response_limit`)
/// only for accounts that pass the gate.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oversize_password_is_refused_like_a_wrong_one() {
    let h = Harness::start_with(opts(format!(
        "[legacy]\nfailure_delay_ms = {DELAY_MS}\n[[legacy.rules]]\nname = \"all\"\nnetworks = [\"127.0.0.0/8\"]\n"
    )))
    .await;
    let huge = "p".repeat(10_000);
    for kind in Kind::ALL {
        let label = kind.label();
        let sessions = h.backend(kind).sessions().len();
        let before = h.proxy.authresults().len();
        let user = format!("bob-{label}@example.test");
        let big = attempt(
            &h,
            kind,
            Src::Internal,
            Sni::None,
            Mech::Plain,
            &user,
            &huge,
        )
        .await;
        let (reason, rule, logged, pwfp) = last_result(&h, before).await;
        assert_eq!(
            (reason.as_str(), rule.as_str(), logged.as_str()),
            ("oversize", "", user.as_str()),
            "{kind:?}"
        );
        assert!(is_fp(&pwfp));
        assert_eq!(
            h.backend(kind).sessions().len(),
            sessions,
            "{kind:?}: backend asked"
        );

        let before = h.proxy.authresults().len();
        let wrong = format!("reject-o-{label}@example.test");
        let a = attempt(
            &h,
            kind,
            Src::Internal,
            Sni::None,
            Mech::Plain,
            &wrong,
            "pw",
        )
        .await;
        assert_eq!(last_result(&h, before).await.0, "backend_reject");

        assert_eq!(big.reply, a.reply, "{kind:?}");
        assert_eq!(big.answer, Answer::Failed, "{kind:?}");
        for t in [big.took, a.took] {
            assert!(t >= Duration::from_millis(DELAY_MS), "{kind:?}: {t:?}");
        }
        assert!(
            big.took.abs_diff(a.took) < Duration::from_millis(150),
            "{kind:?}: {:?} vs {:?}",
            big.took,
            a.took
        );
        assert_eq!(
            h.proxy
                .metric(&format!(
                    "mail_auth_proxy_auth_refusals_total{{proto=\"{label}\",reason=\"oversize\"}}"
                ))
                .await,
            1
        );
    }
}

/// The password cap holds for every form a password can arrive in: IMAP
/// LOGIN with a quoted string, SMTP AUTH LOGIN with the password on its own
/// continuation line. An IMAP literal is not accepted at all (protocol
/// error) and never reaches the backend either.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oversize_password_in_login_forms() {
    let h = Harness::start_with(opts(format!(
        "[legacy]\nfailure_delay_ms = {DELAY_MS}\n[[legacy.rules]]\nname = \"all\"\nnetworks = [\"127.0.0.0/8\"]\n"
    )))
    .await;
    let huge = "p".repeat(10_000);
    let expect_oversize = |before: usize, user: &'static str| {
        let h = &h;
        async move {
            let (reason, _, logged, pwfp) = last_result(h, before).await;
            assert_eq!((reason.as_str(), logged.as_str()), ("oversize", user));
            assert!(is_fp(&pwfp));
        }
    };

    // IMAP LOGIN, quoted strings.
    let before = h.proxy.authresults().len();
    let (mut c, _) = h.imap(Src::Internal, Sni::None).await;
    let t0 = Instant::now();
    c.send(&format!("a LOGIN \"bob@example.test\" \"{huge}\""))
        .await;
    assert_eq!(classify(Kind::Imap, &c.line().await), Answer::Failed);
    assert!(t0.elapsed() >= Duration::from_millis(DELAY_MS));
    expect_oversize(before, "bob@example.test").await;

    // SMTP AUTH LOGIN: user name as initial response, password after 334.
    let before = h.proxy.authresults().len();
    let a = attempt(
        &h,
        Kind::Smtp,
        Src::Internal,
        Sni::None,
        Mech::Login,
        "carol@example.test",
        &huge,
    )
    .await;
    assert_eq!(a.answer, Answer::Failed, "{}", a.reply);
    assert!(a.took >= Duration::from_millis(DELAY_MS));
    expect_oversize(before, "carol@example.test").await;

    // IMAP LOGIN with a literal: refused as a protocol error.
    let before = h.proxy.authresults().len();
    let (mut c, _) = h.imap(Src::Internal, Sni::None).await;
    c.send(&format!("a LOGIN bob@example.test {{{}}}", huge.len()))
        .await;
    let reply = c.line().await;
    assert!(reply.starts_with("a BAD"), "{reply}");
    assert_eq!(last_result(&h, before).await.0, "protocol");

    for kind in [Kind::Imap, Kind::Smtp] {
        assert!(h.backend(kind).sessions().is_empty(), "{kind:?}");
    }
}
