//! The byte relay after login, with the session limits of `[session]`.
//!
//! The relay does not interpret what it carries, so it cannot tell where a
//! response ends: an IMAP or ManageSieve literal, or an SMTP multi-line
//! reply, can hold any line. When a limit ends a session the proxy therefore
//! sends no `* BYE`, `BYE` or `421` of its own (RFC 9051 section 3.4, RFC
//! 5804 section 1.2 and RFC 5321 section 3.8 ask for one, but one inside a
//! literal would become part of the client's data); it closes both TLS
//! streams (close_notify, then FIN) and the client sees a closed connection.

use super::Tuning;
use crate::obs::metrics::{self, Proto, SessionEnd};
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::time::Instant;

/// How long closing both streams may take after a limit: a peer that no
/// longer reads must not keep the session (and its slot) open.
const CLOSE_GRACE: Duration = Duration::from_secs(2);

const CLIENT: u8 = 1;
const BACKEND: u8 = 2;

/// Relay bytes both ways until either side closes or a `[session]` limit
/// ends the session; record why it ended. A peer that disconnects without a
/// TLS close_notify ends the relay with an error; that is the normal end of
/// many sessions, so it counts as that peer's close and is not worth a
/// warning.
pub async fn splice<A, B>(client: &mut A, backend: &mut B, proto: Proto, tuning: &Tuning)
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let start = Instant::now();
    let end = relay(client, backend, tuning).await;
    metrics::record_session_end(proto, end);
    if matches!(end, SessionEnd::IdleLimit | SessionEnd::MaxSession) {
        tracing::info!(target: crate::obs::target::RELAY, proto = proto.label(), reason = end.label(),
            secs = start.elapsed().as_secs(), "session closed by limit");
    }
}

async fn relay<A, B>(client: &mut A, backend: &mut B, tuning: &Tuning) -> SessionEnd
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let activity = Activity::new();
    let mut client = Tap {
        io: client,
        side: CLIENT,
        activity: &activity,
    };
    let mut backend = Tap {
        io: backend,
        side: BACKEND,
        activity: &activity,
    };
    let idle = async {
        match tuning.session_idle {
            Some(limit) => activity.idle_for(limit).await,
            None => std::future::pending().await,
        }
    };
    let max = async {
        match tuning.max_session {
            Some(d) => tokio::time::sleep(d).await,
            None => std::future::pending().await,
        }
    };
    let end = tokio::select! {
        r = tokio::io::copy_bidirectional(&mut client, &mut backend) => {
            if let Err(e) = &r {
                tracing::debug!(target: crate::obs::target::RELAY, error=%e, "relay ended with an error");
            }
            match activity.first_close.load(Ordering::Relaxed) {
                CLIENT => SessionEnd::ClientClose,
                BACKEND => SessionEnd::BackendClose,
                _ => SessionEnd::Error,
            }
        }
        _ = idle => SessionEnd::IdleLimit,
        _ = max => SessionEnd::MaxSession,
    };
    if matches!(end, SessionEnd::IdleLimit | SessionEnd::MaxSession) {
        let _ = tokio::time::timeout(CLOSE_GRACE, async {
            tokio::join!(client.shutdown(), backend.shutdown())
        })
        .await;
    }
    end
}

/// What both directions of one relay share: when a byte last moved, and
/// which side closed first.
struct Activity {
    start: Instant,
    /// Milliseconds from `start` to the last read or write that moved data.
    last_ms: AtomicU64,
    /// `CLIENT` or `BACKEND`, whichever read end-of-stream first; 0 before.
    first_close: AtomicU8,
}

impl Activity {
    fn new() -> Activity {
        Activity {
            start: Instant::now(),
            last_ms: AtomicU64::new(0),
            first_close: AtomicU8::new(0),
        }
    }

    fn touch(&self) {
        let ms = u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.last_ms.fetch_max(ms, Ordering::Relaxed);
    }

    fn closed(&self, side: u8) {
        let _ = self
            .first_close
            .compare_exchange(0, side, Ordering::Relaxed, Ordering::Relaxed);
    }

    /// Resolves once `limit` has passed without a byte moving either way.
    async fn idle_for(&self, limit: Duration) {
        loop {
            let last = self.start + Duration::from_millis(self.last_ms.load(Ordering::Relaxed));
            let deadline = last + limit;
            if Instant::now() >= deadline {
                return;
            }
            tokio::time::sleep_until(deadline).await;
        }
    }
}

/// One side of the relay: passes everything through and notes activity and
/// end-of-stream. A write that moves data counts too, so a client slowly
/// draining a large response is not idle.
struct Tap<'a, S: ?Sized> {
    io: &'a mut S,
    side: u8,
    activity: &'a Activity,
}

impl<S: AsyncRead + Unpin + ?Sized> AsyncRead for Tap<'_, S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        let (before, room) = (buf.filled().len(), buf.remaining() > 0);
        let r = Pin::new(&mut *this.io).poll_read(cx, buf);
        match &r {
            Poll::Ready(Ok(())) if buf.filled().len() > before => this.activity.touch(),
            Poll::Ready(Ok(())) if room => this.activity.closed(this.side),
            // TLS without close_notify: the peer is gone all the same.
            Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::UnexpectedEof => {
                this.activity.closed(this.side)
            }
            _ => {}
        }
        r
    }
}

impl<S: AsyncWrite + Unpin + ?Sized> AsyncWrite for Tap<'_, S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        let r = Pin::new(&mut *this.io).poll_write(cx, data);
        if matches!(r, Poll::Ready(Ok(n)) if n > 0) {
            this.activity.touch();
        }
        r
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.io).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, DuplexStream};

    /// Client and backend ends of a relay running with `tuning`; the task
    /// returns why the relay ended.
    fn start(
        tuning: Tuning,
    ) -> (
        DuplexStream,
        DuplexStream,
        tokio::task::JoinHandle<SessionEnd>,
    ) {
        let (client, mut proxy_client) = tokio::io::duplex(1024);
        let (backend, mut proxy_backend) = tokio::io::duplex(1024);
        let task =
            tokio::spawn(
                async move { relay(&mut proxy_client, &mut proxy_backend, &tuning).await },
            );
        (client, backend, task)
    }

    fn limits(idle: Option<u64>, max: Option<u64>) -> Tuning {
        Tuning {
            session_idle: idle.map(Duration::from_secs),
            max_session: max.map(Duration::from_secs),
            ..Tuning::default()
        }
    }

    /// Bytes both ways, then one round trip each way.
    async fn exchange(client: &mut DuplexStream, backend: &mut DuplexStream) {
        let mut buf = [0u8; 4];
        client.write_all(b"ping").await.unwrap();
        backend.read_exact(&mut buf).await.unwrap();
        backend.write_all(b"pong").await.unwrap();
        client.read_exact(&mut buf).await.unwrap();
    }

    /// Nothing more to read: the relay closed this end.
    async fn assert_closed(s: &mut DuplexStream) {
        let mut rest = Vec::new();
        s.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty(), "{rest:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn idle_limit_closes_a_silent_session_without_a_message() {
        let (mut client, mut backend, task) = start(limits(Some(1800), None));
        exchange(&mut client, &mut backend).await;
        let t0 = Instant::now();
        assert_eq!(task.await.unwrap(), SessionEnd::IdleLimit);
        assert!(t0.elapsed() >= Duration::from_secs(1800));
        assert_closed(&mut client).await;
        assert_closed(&mut backend).await;
    }

    /// Traffic in either direction resets the idle timer: an IDLE client
    /// that re-issues IDLE every 29 minutes, or a backend that sends
    /// untagged updates, keeps the session.
    #[tokio::test(start_paused = true)]
    async fn traffic_either_way_keeps_the_session() {
        let (mut client, mut backend, task) = start(limits(Some(1800), None));
        let mut buf = [0u8; 4];
        for i in 0..6 {
            tokio::time::sleep(Duration::from_secs(29 * 60)).await;
            if i % 2 == 0 {
                client.write_all(b"DONE").await.unwrap();
                backend.read_exact(&mut buf).await.unwrap();
            } else {
                backend.write_all(b"* OK").await.unwrap();
                client.read_exact(&mut buf).await.unwrap();
            }
        }
        assert!(!task.is_finished());
        drop(client);
        // The relay passes the close on; the backend answers with its own.
        assert_closed(&mut backend).await;
        drop(backend);
        assert_eq!(task.await.unwrap(), SessionEnd::ClientClose);
    }

    #[tokio::test(start_paused = true)]
    async fn max_session_ends_a_busy_session() {
        let (mut client, mut backend, task) = start(limits(Some(1800), Some(3600)));
        let t0 = Instant::now();
        while !task.is_finished() {
            // Not a divisor of 3600, so the limit never fires mid-exchange.
            tokio::time::sleep(Duration::from_secs(70)).await;
            if task.is_finished() {
                break;
            }
            exchange(&mut client, &mut backend).await;
        }
        assert_eq!(task.await.unwrap(), SessionEnd::MaxSession);
        assert!(t0.elapsed() >= Duration::from_secs(3600));
        assert_closed(&mut client).await;
    }

    #[tokio::test]
    async fn who_closed_first() {
        let (mut client, mut backend, task) = start(limits(None, None));
        exchange(&mut client, &mut backend).await;
        drop(backend);
        assert_closed(&mut client).await;
        drop(client);
        assert_eq!(task.await.unwrap(), SessionEnd::BackendClose);

        let (client, backend, task) = start(limits(None, None));
        drop(client);
        drop(backend);
        let end = task.await.unwrap();
        assert!(
            matches!(end, SessionEnd::ClientClose | SessionEnd::BackendClose),
            "{end:?}"
        );
    }
}
