//! The `/metrics` endpoint over the wire: only `GET /metrics` gets the
//! exposition text, the number of concurrent scrapes is capped, a slow or
//! oversized request head is cut off, and none of it is logged.

mod common;
use common::*;
use std::net::SocketAddr;
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

    // Four idle connections take every slot.
    let mut idle = Vec::new();
    for _ in 0..4 {
        idle.push(TcpStream::connect(addr).await.unwrap());
    }
    // Let the accept loop hand out the slots before the next connection.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // The fifth is closed at once, without an answer.
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
    // closed after the fixed 10 s deadline for the whole head, unanswered.
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
        e >= Duration::from_secs(9) && e < Duration::from_secs(14),
        "closed after {e:?}"
    );
    let mut rest = Vec::new();
    let _ = slow.read_to_end(&mut rest).await;
    assert!(rest.is_empty(), "{}", String::from_utf8_lossy(&rest));
}
