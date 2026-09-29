//! The `authresult` line is an API for log parsers. Every reason the
//! binary emits is produced here once and pinned byte for byte after the
//! timestamp; every line must also match the CrowdSec grok pattern. The
//! legacy-gate reasons are pinned in `legacy_gate.rs`. New fields (`rule`)
//! are only appended at the end, so existing patterns keep matching. (The
//! harness checks the grok pattern for every authresult line of every test
//! when the proxy is dropped.)

mod common;
use common::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn golden_authresult_lines() {
    let h = Harness::start().await;
    let token = h.idp.token(EMAIL);
    let bad = h.idp.mint(serde_json::json!({"aud": "other"}));

    // ok: OAuth, mechanism spelled in lower case by the client.
    let (_ok, reply) = h
        .auth(
            Kind::Imap,
            Src::External,
            Sni::Public,
            "xoauth2",
            &xoauth2(EMAIL, &token),
        )
        .await;
    assert!(reply.starts_with("a OK"), "{reply}");
    h.proxy.wait_authresults(1).await;

    // bad_token, with a hostile SASL user that tries to forge fields.
    let hostile = "evil\" result=\"ok\" user=root peer=10.0.0.1 x";
    let (_c, _) = h
        .auth(
            Kind::Smtp,
            Src::External,
            Sni::Public,
            "XOAUTH2",
            &xoauth2(hostile, &bad),
        )
        .await;
    h.proxy.wait_authresults(2).await;

    // blocked_endpoint: a password from outside.
    let (_c, _) = h
        .auth(
            Kind::Sieve,
            Src::External,
            Sni::Internal,
            "PLAIN",
            &plain("bob@example.test", "hunter2"),
        )
        .await;
    h.proxy.wait_authresults(3).await;

    // backend_reject: a password the backend refuses.
    let (_c, _) = h
        .auth(
            Kind::Imap,
            Src::Internal,
            Sni::Internal,
            "PLAIN",
            &plain("reject@example.test", "hunter2"),
        )
        .await;
    h.proxy.wait_authresults(4).await;

    // protocol: a command the proxy does not allow before authentication.
    let (mut c, _) = h.imap(Src::External, Sni::None).await;
    c.send("a SELECT INBOX").await;
    assert_eq!(
        c.line().await,
        "a NO command not supported before authentication"
    );
    h.proxy.wait_authresults(5).await;

    let lines: Vec<String> = h
        .proxy
        .logs()
        .into_iter()
        .filter(|l| l.contains("authresult"))
        .collect();
    let stamp = regex::Regex::new(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z  ").unwrap();
    let fp = regex::Regex::new(r#"pwfp="[0-9a-f]{16}""#).unwrap();
    let got: Vec<String> = lines
        .iter()
        .map(|l| {
            assert!(stamp.is_match(l), "timestamp: {l}");
            fp.replace(&stamp.replace(l, ""), r#"pwfp="<fp>""#)
                .into_owned()
        })
        .collect();
    assert_eq!(
        got,
        [
            r#"INFO authlog: authresult result="ok" proto="imap" scope="external" mech=xoauth2 user=alice@example.test peer=127.0.0.2 reason="ok" pwfp="" rule="""#,
            r#"WARN authlog: authresult result="fail" proto="smtp" scope="external" mech=XOAUTH2 user=evil??result??ok??user?root?peer?10.0.0.1?x peer=127.0.0.2 reason="bad_token" pwfp="" rule="""#,
            r#"WARN authlog: authresult result="fail" proto="sieve" scope="external" mech=PLAIN user=bob@example.test peer=127.0.0.2 reason="blocked_endpoint" pwfp="<fp>" rule="""#,
            r#"WARN authlog: authresult result="fail" proto="imap" scope="internal" mech=PLAIN user=reject@example.test peer=127.0.0.1 reason="backend_reject" pwfp="<fp>" rule="password_gate""#,
            r#"WARN authlog: authresult result="fail" proto="imap" scope="external" mech=other user= peer=127.0.0.2 reason="protocol" pwfp="" rule="""#,
        ]
    );

    // The CrowdSec pattern extracts the intended fields from each line.
    let grok = grok_regex();
    let fields: Vec<Vec<String>> = lines
        .iter()
        .map(|l| {
            let c = grok.captures(l).unwrap_or_else(|| panic!("grok: {l}"));
            (1..=7).map(|i| c[i].to_string()).collect()
        })
        .collect();
    assert_eq!(
        fields[1],
        [
            "fail",
            "smtp",
            "external",
            "XOAUTH2",
            "evil??result??ok??user?root?peer?10.0.0.1?x",
            "127.0.0.2",
            "bad_token"
        ]
    );
    assert_eq!(fields[4][4], "", "empty user");
    // One authresult per line: the hostile user did not forge a second one.
    assert!(lines.iter().all(|l| l.matches("result=").count() == 1));

    // The same password gives the same fingerprint within one process.
    let pwfp = |l: &str| fp.find(l).unwrap().as_str().to_string();
    assert_eq!(pwfp(&lines[2]), pwfp(&lines[3]));
}
