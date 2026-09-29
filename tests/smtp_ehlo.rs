//! The EHLO reply after STARTTLS lists the backend's own extensions, as far
//! as the proxy handles them (RFC 5321 §4.2.4: only extensions that work),
//! from a cached probe of the backend.

mod common;
use common::*;
use std::time::Duration;

fn opts(extra: &'static str) -> Opts {
    Opts {
        submission_extra: extra,
        ..Opts::default()
    }
}

/// The EHLO reply of a session from `src`: the extension lines between the
/// name and the AUTH line.
async fn extensions(h: &Harness) -> Vec<String> {
    let (_c, ehlo) = h.smtp(Src::External, Sni::Public).await;
    assert_eq!(ehlo.first().unwrap(), &format!("250-{HOSTNAME}"));
    assert_eq!(ehlo.last().unwrap(), "250 AUTH XOAUTH2 OAUTHBEARER");
    ehlo[1..ehlo.len() - 1]
        .iter()
        .map(|l| l.strip_prefix("250-").unwrap().to_string())
        .collect()
}

fn set_backend_ehlo(h: &Harness, lines: &[&str]) {
    *h.smtp_be.smtp_ehlo.lock().unwrap() = Some(lines.iter().map(|s| s.to_string()).collect());
}

fn probes(h: &Harness) -> usize {
    h.smtp_be.seen().iter().filter(|s| s.probe).count()
}

/// What the backend offers, filtered to what the proxy handles, with the
/// backend's parameters; XCLIENT, VRFY, ETRN and unknown ones are left out.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ehlo_lists_what_the_backend_offers() {
    let h = Harness::start_with(opts("capability_cache_secs = 1")).await;
    assert_eq!(
        extensions(&h).await,
        [
            "PIPELINING",
            "SIZE 10240000",
            "ENHANCEDSTATUSCODES",
            "8BITMIME",
            "DSN",
            "SMTPUTF8",
            "CHUNKING"
        ]
    );
    set_backend_ehlo(
        &h,
        &[
            "SIZE 35882577",
            "8BITMIME",
            "XFORWARD NAME ADDR",
            "VRFY",
            "BINARYMIME",
        ],
    );
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert_eq!(extensions(&h).await, ["SIZE 35882577", "8BITMIME"]);
}

/// Within the TTL the cached list is used: one probe at startup, none per
/// client; after it the next EHLO probes again. A session keeps the list it
/// was shown first.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_list_is_cached() {
    let h = Harness::start_with(opts("capability_cache_secs = 2")).await;
    let (mut c, first) = h.smtp(Src::External, Sni::Public).await;
    extensions(&h).await;
    assert_eq!(probes(&h), 1);
    assert_eq!(
        h.smtp_be.seen().len(),
        1,
        "no backend connection per client"
    );
    set_backend_ehlo(&h, &["DSN"]);
    tokio::time::sleep(Duration::from_millis(2100)).await;
    assert_eq!(extensions(&h).await, ["DSN"]);
    assert_eq!(probes(&h), 2);
    c.send("EHLO again.test").await;
    assert_eq!(c.smtp_reply().await, first);
}

/// `submission.ehlo_extensions` narrows the list; its parameters do not
/// replace the backend's.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn configured_extensions_narrow_the_list() {
    let h = Harness::start_with(opts(
        "ehlo_extensions = [\"CHUNKING\", \"SIZE 1000\", \"PIPELINING\"]",
    ))
    .await;
    assert_eq!(
        extensions(&h).await,
        ["PIPELINING", "SIZE 10240000", "CHUNKING"]
    );
}

/// While the backend is down the last list stays in use; before any probe
/// succeeded no extension is advertised. Failed probes count as backend
/// errors and are spaced.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_backend_outage_keeps_the_last_list() {
    let h = Harness::start_with(opts("capability_cache_secs = 1")).await;
    let before = extensions(&h).await;
    h.smtp_be.shutdown().await;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert_eq!(extensions(&h).await, before);
    assert_eq!(extensions(&h).await, before);
    let errors = "mail_auth_proxy_backend_errors_total{proto=\"smtp\"}";
    assert_eq!(
        h.proxy.metric(errors).await,
        1,
        "one probe within the retry spacing"
    );

    let h = Harness::start_with(Opts {
        smtp_down: true,
        ..opts("")
    })
    .await;
    assert!(extensions(&h).await.is_empty());
}

/// BDAT before AUTH: its chunk is never read as commands. The reply is 530,
/// then 421 and the close (RFC 3030 §2, RFC 5321 §3.8).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bdat_before_auth_closes() {
    let h = Harness::start().await;
    let (mut c, _) = h.smtp(Src::Internal, Sni::Internal).await;
    let chunk = format!("AUTH PLAIN {}\r\n", plain("bob@example.test", "pw"));
    c.send_raw(format!("BDAT {} LAST\r\n{chunk}", chunk.len()).as_bytes())
        .await;
    assert_eq!(c.line().await, "530 5.7.0 Authentication required");
    c.expect_end(Kind::Smtp).await;
    assert!(h.smtp_be.sessions().is_empty());
}
