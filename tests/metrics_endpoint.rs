//! The `/metrics` endpoint over the wire: only `GET /metrics` gets the
//! exposition text, the number of concurrent scrapes is capped, a slow or
//! oversized request head is cut off, and none of it is logged. With TLS and
//! a bearer token, only a scrape over TLS with the token gets an answer, and
//! a reload takes over a renewed certificate and a new token.

mod common;
use common::*;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Send `req` and read the whole response (the endpoint closes after one).
async fn exchange(addr: SocketAddr, req: &[u8]) -> String {
    try_exchange(addr, req).await.unwrap()
}

/// `exchange`, but a connection closed at accept (over the scrape limit) is
/// an error: the unread request makes the close a reset.
async fn try_exchange(addr: SocketAddr, req: &[u8]) -> std::io::Result<String> {
    let mut s = TcpStream::connect(addr).await?;
    s.write_all(req).await?;
    let mut out = Vec::new();
    tokio::time::timeout(IO_TIMEOUT, s.read_to_end(&mut out))
        .await
        .expect("response timed out")?;
    Ok(String::from_utf8(out).unwrap())
}

fn status(resp: &str) -> &str {
    resp.split("\r\n").next().unwrap()
}

/// Wait until the peer closes `s`; returns what it sent before.
async fn read_until_closed(s: &mut TcpStream, within: Duration) -> Vec<u8> {
    let mut out = Vec::new();
    tokio::time::timeout(within, s.read_to_end(&mut out))
        .await
        .expect("connection not closed in time")
        .unwrap_or_default();
    out
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn answers_only_get_metrics() {
    let h = Harness::start().await;
    let addr = h.proxy.metrics;

    let ok = exchange(addr, b"GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n").await;
    assert_eq!(status(&ok), "HTTP/1.1 200 OK");
    let (head, body) = ok.split_once("\r\n\r\n").unwrap();
    assert!(head.contains("\r\nContent-Length: "));
    let len: usize = head
        .split("\r\n")
        .find_map(|l| l.strip_prefix("Content-Length: "))
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(len, body.len());

    for (req, want) in [
        (&b"GET / HTTP/1.1\r\n\r\n"[..], "HTTP/1.1 404 Not Found"),
        (
            b"GET /favicon.ico HTTP/1.1\r\n\r\n",
            "HTTP/1.1 404 Not Found",
        ),
        (
            b"POST /metrics HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
            "HTTP/1.1 405 Method Not Allowed",
        ),
        (
            b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03\n\n",
            "HTTP/1.1 400 Bad Request",
        ),
        (b"SSH-2.0-OpenSSH_9.6\r\n\r\n", "HTTP/1.1 400 Bad Request"),
    ] {
        let resp = exchange(addr, req).await;
        assert_eq!(status(&resp), want, "{resp}");
        assert!(!resp.contains("mail_auth_proxy"), "{resp}");
    }

    // An oversized head is answered 431 without waiting for its end.
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(b"GET /metrics HTTP/1.1\r\n").await.unwrap();
    s.write_all(format!("X-Pad: {}\r\n", "a".repeat(8192)).as_bytes())
        .await
        .unwrap();
    let resp = String::from_utf8(read_until_closed(&mut s, IO_TIMEOUT).await).unwrap();
    assert_eq!(
        status(&resp),
        "HTTP/1.1 431 Request Header Fields Too Large"
    );

    // Scanner noise leaves no trace in the journal.
    assert_eq!(
        h.proxy.count_logs("mail_auth_proxy::metrics"),
        1,
        "{:?}",
        h.proxy.logs()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn caps_concurrent_scrapes() {
    let h = Harness::start().await;
    let addr = h.proxy.metrics;

    // Connections that have not sent a request (or not finished the TLS
    // handshake) do not take the scrape slots: a scrape still gets through.
    let mut idle = Vec::new();
    for _ in 0..8 {
        idle.push(TcpStream::connect(addr).await.unwrap());
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let resp = exchange(addr, b"GET /metrics HTTP/1.1\r\n\r\n").await;
    assert_eq!(status(&resp), "HTTP/1.1 200 OK");

    // At most 64 connections wait for their request at a time.
    while idle.len() < 64 {
        idle.push(TcpStream::connect(addr).await.unwrap());
    }
    // Let the accept loop hand out the slots before the next connection.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // The next one is closed at once, without an answer.
    let mut fifth = TcpStream::connect(addr).await.unwrap();
    let _ = fifth.write_all(b"GET /metrics HTTP/1.1\r\n\r\n").await;
    let t = Instant::now();
    assert!(read_until_closed(&mut fifth, Duration::from_secs(2))
        .await
        .is_empty());
    assert!(t.elapsed() < Duration::from_secs(2));

    // Closing the idle ones gives the slots back.
    drop(idle);
    let until = Instant::now() + IO_TIMEOUT;
    loop {
        // Until the slots are free, a connection is closed unanswered (an
        // empty response or a reset).
        if let Ok(resp) = try_exchange(addr, b"GET /metrics HTTP/1.1\r\n\r\n").await {
            if status(&resp) == "HTTP/1.1 200 OK" {
                break;
            }
        }
        assert!(Instant::now() < until, "slots not released");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(h.proxy.count_logs("mail_auth_proxy::metrics"), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn slow_request_head_is_cut_off() {
    let h = Harness::start().await;
    let addr = h.proxy.metrics;

    // One byte every 500 ms never completes the head: the connection is
    // closed after the fixed 5 s deadline for the whole head, unanswered.
    let mut slow = TcpStream::connect(addr).await.unwrap();
    let t = Instant::now();
    let drip = async {
        for b in b"GET /metrics HTTP/1.1\r\nX-Slow: ".iter().cycle() {
            if slow.write_all(&[*b]).await.is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    };
    // Scrapes keep working meanwhile (the drip holds one slot).
    let scrape = async {
        tokio::time::sleep(Duration::from_secs(1)).await;
        exchange(addr, b"GET /metrics HTTP/1.1\r\n\r\n").await
    };
    let (_, resp) = tokio::join!(tokio::time::timeout(Duration::from_secs(15), drip), scrape);
    assert_eq!(status(&resp), "HTTP/1.1 200 OK");
    let e = t.elapsed();
    assert!(
        e >= Duration::from_secs(4) && e < Duration::from_secs(9),
        "closed after {e:?}"
    );
    let mut rest = Vec::new();
    let _ = slow.read_to_end(&mut rest).await;
    assert!(rest.is_empty(), "{}", String::from_utf8_lossy(&rest));
}

/// One request over TLS with `client` (SNI `INTERNAL_SNI`), in a new TLS
/// session (a resumed one would show the certificate of the first): the
/// response and the server's certificate (DER).
async fn tls_exchange(
    client: Arc<rustls::ClientConfig>,
    addr: SocketAddr,
    req: Vec<u8>,
) -> std::io::Result<(String, Vec<u8>)> {
    let mut client = (*client).clone();
    client.resumption = rustls::client::Resumption::disabled();
    let client = Arc::new(client);
    let tcp = TcpStream::connect(addr).await?;
    let name = rustls::pki_types::ServerName::try_from(INTERNAL_SNI).unwrap();
    let mut s = tokio_rustls::TlsConnector::from(client)
        .connect(name, tcp)
        .await?;
    let der = s.get_ref().1.peer_certificates().unwrap()[0].to_vec();
    assert_eq!(s.get_ref().1.alpn_protocol(), None);
    s.write_all(&req).await?;
    let mut out = Vec::new();
    tokio::time::timeout(IO_TIMEOUT, s.read_to_end(&mut out))
        .await
        .expect("response timed out")?;
    Ok((String::from_utf8(out).unwrap(), der))
}

fn scrape_with(token: &str) -> Vec<u8> {
    format!("GET /metrics HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {token}\r\n\r\n")
        .into_bytes()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_and_bearer_token() {
    const FIRST: &str = "first-token-0123456789abcdefghijklmnopqrstuvwxyz";
    const SECOND: &str = "second-token-0123456789abcdefghijklmnopqrstuvwxyz";
    let pki = Pki::new();
    let file = |name: &str| pki.dir.path().join(name);
    let (cert, key, token) = (
        file("metrics.pem"),
        file("metrics.key"),
        file("metrics.token"),
    );
    std::fs::copy(&pki.proxy_cert, &cert).unwrap();
    std::fs::copy(&pki.proxy_key, &key).unwrap();
    std::fs::write(&token, format!("{FIRST}\n")).unwrap();
    let opts = Opts {
        metrics_extra: format!(
            "tls_cert = \"{}\"\ntls_key = \"{}\"\nbearer_token_file = \"{}\"\n",
            cert.display(),
            key.display(),
            token.display()
        ),
        ..Opts::default()
    };
    let h = Harness::start_on(pki, opts.clone()).await;
    let addr = h.proxy.metrics;
    let client = h.pki.client.clone();
    let get = |req: Vec<u8>| tls_exchange(client.clone(), addr, req);

    let (ok, der) = get(scrape_with(FIRST)).await.unwrap();
    assert_eq!(status(&ok), "HTTP/1.1 200 OK", "{ok}");
    assert!(ok.contains("\r\n\r\n# HELP mail_auth_proxy_"));
    assert_eq!(der, h.pki.proxy_der);

    for req in [
        b"GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n".to_vec(),
        scrape_with(SECOND),
        scrape_with(&FIRST[..FIRST.len() - 1]),
        format!("GET /metrics HTTP/1.1\r\nAuthorization: Basic {FIRST}\r\n\r\n").into_bytes(),
    ] {
        let (resp, _) = get(req).await.unwrap();
        assert_eq!(status(&resp), "HTTP/1.1 401 Unauthorized", "{resp}");
        assert!(resp.contains("\r\nWWW-Authenticate: Bearer\r\n"), "{resp}");
        assert!(resp.ends_with("\r\n\r\nunauthorized\n"), "{resp}");
    }

    // HTTP clients offer h2 next to http/1.1: http/1.1 is selected.
    let mut alpn = (*h.pki.client).clone();
    alpn.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let tcp = TcpStream::connect(addr).await.unwrap();
    let s = tokio_rustls::TlsConnector::from(Arc::new(alpn))
        .connect(
            rustls::pki_types::ServerName::try_from(INTERNAL_SNI).unwrap(),
            tcp,
        )
        .await
        .unwrap();
    assert_eq!(s.get_ref().1.alpn_protocol(), Some(&b"http/1.1"[..]));
    drop(s);

    // Plain HTTP gets no HTTP answer, so the token never travels in clear
    // to a responder that would read it.
    let resp = try_exchange(addr, &scrape_with(FIRST))
        .await
        .unwrap_or_default();
    assert!(!resp.contains("HTTP/"), "{resp:?}");

    // A reload takes over a renewed certificate and a new token.
    std::fs::copy(&h.pki.renewed_cert, &cert).unwrap();
    std::fs::copy(&h.pki.renewed_key, &key).unwrap();
    std::fs::write(&token, format!("  {SECOND}\r\n")).unwrap();
    h.proxy.reload(&h.config(&opts)).await.unwrap();
    let (resp, der) = get(scrape_with(SECOND)).await.unwrap();
    assert_eq!(status(&resp), "HTTP/1.1 200 OK", "{resp}");
    assert_eq!(der, h.pki.renewed_der);
    let (resp, _) = get(scrape_with(FIRST)).await.unwrap();
    assert_eq!(status(&resp), "HTTP/1.1 401 Unauthorized");

    // Unusable files refuse the reload; the endpoint keeps what it has.
    std::fs::write(&token, "too-short\n").unwrap();
    std::fs::write(&cert, "not a certificate").unwrap();
    let e = h.proxy.reload(&h.config(&opts)).await.unwrap_err();
    assert!(e.contains("metrics.bearer_token_file"), "{e}");
    assert!(e.contains(&format!("metrics: {}", cert.display())), "{e}");
    let (resp, der) = get(scrape_with(SECOND)).await.unwrap();
    assert_eq!(status(&resp), "HTTP/1.1 200 OK", "{resp}");
    assert_eq!(der, h.pki.renewed_der);
    h.proxy
        .wait_logs("metrics bearer token unusable; keeping the current one", 1)
        .await;
    h.proxy
        .wait_logs("metrics certificate unusable; keeping the current one", 1)
        .await;

    // A refused configuration still lets renewed files in, each on its own.
    const THIRD: &str = "third-token-0123456789abcdefghijklmnopqrstuvwxyz";
    std::fs::write(&token, THIRD).unwrap();
    std::fs::copy(&h.pki.proxy_cert, &cert).unwrap();
    std::fs::copy(&h.pki.proxy_key, &key).unwrap();
    let broken = format!("{}\nunknown_key = 1\n", h.config(&opts));
    h.proxy.reload(&broken).await.unwrap_err();
    let (resp, der) = get(scrape_with(THIRD)).await.unwrap();
    assert_eq!(status(&resp), "HTTP/1.1 200 OK", "{resp}");
    assert_eq!(der, h.pki.proxy_der);
    let (resp, _) = get(scrape_with(SECOND)).await.unwrap();
    assert_eq!(status(&resp), "HTTP/1.1 401 Unauthorized");

    // The mail listeners never noticed.
    let (mut c, _) = h.imap(Src::Internal, Sni::Internal).await;
    c.send("a LOGOUT").await;

    // Neither token reaches the log; the endpoint logged its start only.
    let logs = h.proxy.logs();
    assert!(
        !logs.iter().any(|l| l.contains(FIRST) || l.contains(SECOND)),
        "{logs:?}"
    );
    assert_eq!(
        h.proxy.count_logs("mail_auth_proxy::metrics"),
        1,
        "{logs:?}"
    );
    assert!(
        h.proxy.log_contains("tls=true bearer_token=true"),
        "{logs:?}"
    );
}

/// A request is answered only under the settings in use when it is
/// answered: a connection accepted before a reload changed TLS or the token
/// is closed unanswered, so a plaintext request cannot slip past newly added
/// TLS and a revoked token is refused at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reload_closes_connections_of_replaced_settings() {
    const FIRST: &str = "first-token-0123456789abcdefghijklmnopqrstuvwxyz";
    const SECOND: &str = "second-token-0123456789abcdefghijklmnopqrstuvwxyz";
    let h = Harness::start().await;
    let addr = h.proxy.metrics;
    let file = |name: &str| h.pki.dir.path().join(name);
    let (cert, key, token) = (
        file("metrics.pem"),
        file("metrics.key"),
        file("metrics.token"),
    );
    std::fs::copy(&h.pki.proxy_cert, &cert).unwrap();
    std::fs::copy(&h.pki.proxy_key, &key).unwrap();
    std::fs::write(&token, FIRST).unwrap();
    let secured = Opts {
        metrics_extra: format!(
            "tls_cert = \"{}\"\ntls_key = \"{}\"\nbearer_token_file = \"{}\"\n",
            cert.display(),
            key.display(),
            token.display()
        ),
        ..Opts::default()
    };

    // Plain HTTP, then a reload adds TLS and the token: a connection opened
    // before gets nothing for its plaintext request.
    let mut early = TcpStream::connect(addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    h.proxy.reload(&h.config(&secured)).await.unwrap();
    early
        .write_all(b"GET /metrics HTTP/1.1\r\n\r\n")
        .await
        .unwrap();
    let resp = read_until_closed(&mut early, IO_TIMEOUT).await;
    assert!(resp.is_empty(), "{}", String::from_utf8_lossy(&resp));

    // A rotated token: a TLS connection opened before the reload cannot use
    // the old one afterwards.
    let mut client = (*h.pki.client).clone();
    client.resumption = rustls::client::Resumption::disabled();
    let tcp = TcpStream::connect(addr).await.unwrap();
    let mut s = tokio_rustls::TlsConnector::from(Arc::new(client))
        .connect(
            rustls::pki_types::ServerName::try_from(INTERNAL_SNI).unwrap(),
            tcp,
        )
        .await
        .unwrap();
    std::fs::write(&token, SECOND).unwrap();
    h.proxy.reload(&h.config(&secured)).await.unwrap();
    s.write_all(&scrape_with(FIRST)).await.unwrap();
    let mut out = Vec::new();
    let _ = tokio::time::timeout(IO_TIMEOUT, s.read_to_end(&mut out))
        .await
        .expect("connection not closed in time");
    assert!(out.is_empty(), "{}", String::from_utf8_lossy(&out));

    // New connections get the new settings.
    let (resp, _) = tls_exchange(h.pki.client.clone(), addr, scrape_with(SECOND))
        .await
        .unwrap();
    assert_eq!(status(&resp), "HTTP/1.1 200 OK", "{resp}");
    let (resp, _) = tls_exchange(h.pki.client.clone(), addr, scrape_with(FIRST))
        .await
        .unwrap();
    assert_eq!(status(&resp), "HTTP/1.1 401 Unauthorized", "{resp}");
}
