//! The byte relay after login, with the session limits of `[session]`.
//!
//! For IMAP and ManageSieve the client's commands pass the guard
//! (`wire::guard`), which keeps the session from returning to the
//! unauthenticated state; SMTP is relayed as it is. A limit can end a
//! session in the middle of a response: an IMAP or ManageSieve literal, or
//! an SMTP multi-line reply, can hold any line. When a limit ends a session
//! the proxy therefore sends no `* BYE`, `BYE` or `421` of its own (RFC 9051
//! section 3.4, RFC 5804 section 1.2 and RFC 5321 section 3.8 ask for one,
//! but one inside a literal would become part of the client's data); it
//! closes both TLS streams (close_notify, then FIN) and the client sees a
//! closed connection. The same goes for a session the guard ends.

use super::guard::{Dialect, Event, Guard};
use super::Tuning;
use crate::obs::metrics::{self, Proto, SessionEnd};
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::Notify;
use tokio::time::Instant;

const CLIENT: u8 = 1;
const BACKEND: u8 = 2;

/// Relay bytes both ways until either side closes or a `[session]` limit
/// ends the session; record why it ended. `token_exp`: the `exp` (Unix
/// seconds) of the token the client logged in with, `None` for a password.
/// A peer that disconnects without a TLS close_notify ends the relay with an
/// error; that is the normal end of many sessions, so it counts as that
/// peer's close and is not worth a warning.
pub async fn splice<A, B>(
    client: &mut A,
    backend: &mut B,
    proto: Proto,
    tuning: &Tuning,
    token_exp: Option<u64>,
) where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let start = Instant::now();
    let token_end = tuning
        .token_expiry_grace
        .zip(token_exp)
        .and_then(|(grace, exp)| token_end(exp, grace));
    let dialect = match proto {
        Proto::Imap => Some(Dialect::Imap),
        Proto::Sieve => Some(Dialect::Sieve),
        Proto::Smtp => None,
    };
    let end = relay(
        client,
        backend,
        tuning,
        token_end,
        &SystemTime::now,
        dialect,
    )
    .await;
    metrics::record_session_end(proto, end);
    if is_limit(end) {
        tracing::info!(target: crate::obs::target::RELAY, proto = proto.label(), reason = end.label(),
            secs = start.elapsed().as_secs(), "session closed by limit");
    }
}

/// An end the proxy chose by a `[session]` limit.
fn is_limit(end: SessionEnd) -> bool {
    matches!(
        end,
        SessionEnd::IdleLimit | SessionEnd::MaxSession | SessionEnd::TokenExpired
    )
}

/// With `session.end_at_token_expiry`, when a session whose token expires
/// at `exp` (Unix seconds) ends: at `exp` plus the grace, by the system
/// clock, however late the session started. `None` past what the clock can
/// represent: never.
fn token_end(exp: u64, grace: Duration) -> Option<SystemTime> {
    UNIX_EPOCH.checked_add(Duration::from_secs(exp).saturating_add(grace))
}

/// Longest single wait for a token's end: the system clock is read again
/// after each, so a clock step after the login moves the session's end by
/// at most this much.
const CLOCK_RECHECK: Duration = Duration::from_secs(60);

/// Resolves once `now()` reaches `end`; at once if it already has.
async fn until_clock(end: SystemTime, now: &(dyn Fn() -> SystemTime + Sync)) {
    loop {
        match end.duration_since(now()) {
            Ok(left) if !left.is_zero() => tokio::time::sleep(left.min(CLOCK_RECHECK)).await,
            _ => return,
        }
    }
}

async fn relay<A, B>(
    client: &mut A,
    backend: &mut B,
    tuning: &Tuning,
    token_end: Option<SystemTime>,
    clock: &(dyn Fn() -> SystemTime + Sync),
    dialect: Option<Dialect>,
) -> SessionEnd
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
    let token = async {
        match token_end {
            Some(end) => until_clock(end, clock).await,
            None => std::future::pending().await,
        }
    };
    let copy = async {
        match dialect {
            Some(d) => guarded(&mut client, &mut backend, Guard::new(d)).await,
            None => tokio::io::copy_bidirectional(&mut client, &mut backend)
                .await
                .map(|_| ()),
        }
    };
    let end = tokio::select! {
        r = copy => match r {
            Err(e) if e.get_ref().is_some_and(|e| e.is::<Blocked>()) => SessionEnd::Blocked,
            r => {
                if let Err(e) = &r {
                    tracing::debug!(target: crate::obs::target::RELAY, error=%e, "relay ended with an error");
                }
                match activity.first_close.load(Ordering::Relaxed) {
                    CLIENT => SessionEnd::ClientClose,
                    BACKEND => SessionEnd::BackendClose,
                    _ => SessionEnd::Error,
                }
            }
        },
        _ = idle => SessionEnd::IdleLimit,
        _ = max => SessionEnd::MaxSession,
        _ = token => SessionEnd::TokenExpired,
    };
    if is_limit(end) || end == SessionEnd::Blocked {
        let _ = tokio::time::timeout(super::CLOSE_GRACE, async {
            tokio::join!(client.shutdown(), backend.shutdown())
        })
        .await;
    }
    end
}

/// The guard ended the session: a command it keeps from the backend where it
/// cannot answer it.
#[derive(Debug)]
struct Blocked(&'static str);

impl std::fmt::Display for Blocked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} after login", self.0)
    }
}

impl std::error::Error for Blocked {}

/// Octets read per call, each direction.
const CHUNK: usize = 16 * 1024;

/// Relay both ways through `guard` until both sides have closed, as
/// `copy_bidirectional` does: an end-of-stream from one side shuts down
/// writing to the other. The two directions run concurrently in this task
/// and share the guard (an uncontended lock: the task is polled by one
/// thread at a time); neither holds it across an await. While the guard
/// waits for the backend, the client is not read (TCP pushes back); the
/// backend direction wakes it, and writes the guard's local replies between
/// responses.
async fn guarded<A, B>(client: &mut A, backend: &mut B, guard: Guard) -> io::Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let (mut client_rd, mut client_wr) = tokio::io::split(client);
    let (mut backend_rd, mut backend_wr) = tokio::io::split(backend);
    let guard = Mutex::new(guard);
    // A panic cannot leave the guard half-updated in a way that matters:
    // the session ends with it.
    let lock = || -> MutexGuard<'_, Guard> { guard.lock().unwrap_or_else(|p| p.into_inner()) };
    // `notify_one` keeps a permit, so a wake between check and wait is not
    // lost.
    let wake_client = Notify::new();
    let wake_backend = Notify::new();

    let upstream = async {
        let mut buf = vec![0u8; CHUNK];
        let mut out = Vec::with_capacity(CHUNK);
        let (mut start, mut end) = (0, 0);
        loop {
            while lock().client_waits() {
                wake_client.notified().await;
            }
            if start == end {
                let n = client_rd.read(&mut buf).await?;
                if n == 0 {
                    // Octets held back for an undecided line start are
                    // dropped with it.
                    backend_wr.shutdown().await?;
                    return Ok(());
                }
                (start, end) = (0, n);
                continue;
            }
            out.clear();
            let (used, event) = lock().on_client(&buf[start..end], &mut out);
            start += used;
            if !out.is_empty() {
                backend_wr.write_all(&out).await?;
                backend_wr.flush().await?;
            }
            match event {
                Event::None => {}
                Event::Refused(word) => {
                    tracing::info!(target: crate::obs::target::RELAY, command = word, "command not permitted after login; refused");
                    wake_backend.notify_one();
                }
                Event::Close(word) => {
                    tracing::warn!(target: crate::obs::target::RELAY, command = word, "command not permitted after login where it cannot be refused; session closed");
                    return Err(io::Error::other(Blocked(word)));
                }
            }
        }
    };

    let downstream = async {
        let mut buf = vec![0u8; CHUNK];
        let mut out = Vec::with_capacity(CHUNK);
        loop {
            let local = lock().take_local();
            if let Some(reply) = local {
                client_wr.write_all(&reply).await?;
                client_wr.flush().await?;
                wake_client.notify_one();
            }
            let n = tokio::select! {
                r = backend_rd.read(&mut buf) => r?,
                _ = wake_backend.notified() => continue,
            };
            if n == 0 {
                lock().server_closed();
                wake_client.notify_one();
                client_wr.shutdown().await?;
                return Ok(());
            }
            out.clear();
            lock().on_server(&buf[..n], &mut out);
            if !out.is_empty() {
                client_wr.write_all(&out).await?;
                client_wr.flush().await?;
            }
            wake_client.notify_one();
        }
    };

    tokio::try_join!(upstream, downstream).map(|_| ())
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
        let (client, backend, task, _) = start_with_token(tuning, None);
        (client, backend, task)
    }

    /// A system clock for paused tests: a fixed start that advances with
    /// Tokio's clock, plus a step in seconds set by the test.
    struct TestClock {
        base: SystemTime,
        t0: Instant,
        step: std::sync::atomic::AtomicI64,
    }

    impl TestClock {
        fn new() -> TestClock {
            TestClock {
                base: UNIX_EPOCH + Duration::from_secs(1_800_000_000),
                t0: Instant::now(),
                step: Default::default(),
            }
        }

        fn now(&self) -> SystemTime {
            let t = self.base + self.t0.elapsed();
            let step = self.step.load(Ordering::Relaxed);
            let by = Duration::from_secs(step.unsigned_abs());
            if step < 0 {
                t - by
            } else {
                t + by
            }
        }
    }

    /// Like `start`, for a token session that ends `token_in` seconds after
    /// the start by the returned clock (negative: already past).
    fn start_with_token(
        tuning: Tuning,
        token_in: Option<i64>,
    ) -> (
        DuplexStream,
        DuplexStream,
        tokio::task::JoinHandle<SessionEnd>,
        std::sync::Arc<TestClock>,
    ) {
        let (client, mut proxy_client) = tokio::io::duplex(1024);
        let (backend, mut proxy_backend) = tokio::io::duplex(1024);
        let clock = std::sync::Arc::new(TestClock::new());
        let end = token_in.map(|secs| {
            let by = Duration::from_secs(secs.unsigned_abs());
            if secs < 0 {
                clock.now() - by
            } else {
                clock.now() + by
            }
        });
        let c = clock.clone();
        let task = tokio::spawn(async move {
            let now = move || c.now();
            relay(
                &mut proxy_client,
                &mut proxy_backend,
                &tuning,
                end,
                &now,
                None,
            )
            .await
        });
        (client, backend, task, clock)
    }

    /// Keep both directions busy until the relay ends; how long it ran.
    async fn busy_until_end(
        client: &mut DuplexStream,
        backend: &mut DuplexStream,
        task: &tokio::task::JoinHandle<SessionEnd>,
    ) -> Duration {
        let t0 = Instant::now();
        while !task.is_finished() {
            // Not a divisor of the limits below, so none fires mid-exchange.
            tokio::time::sleep(Duration::from_secs(70)).await;
            if task.is_finished() {
                break;
            }
            exchange(client, backend).await;
        }
        t0.elapsed()
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

    /// The token's end ends a session that is busy the whole time,
    /// closing both sides like `max_session`.
    #[tokio::test(start_paused = true)]
    async fn token_expiry_ends_a_busy_session() {
        let (mut client, mut backend, task, _) =
            start_with_token(limits(Some(1800), None), Some(3600));
        let took = busy_until_end(&mut client, &mut backend, &task).await;
        assert_eq!(task.await.unwrap(), SessionEnd::TokenExpired);
        assert!(took >= Duration::from_secs(3600), "{took:?}");
        assert!(took < Duration::from_secs(3600 + 70), "{took:?}");
        assert_closed(&mut client).await;
        assert_closed(&mut backend).await;
    }

    /// A session whose token end has passed when the relay starts (a token
    /// accepted within the leeway, a slow backend login) ends at once.
    #[tokio::test(start_paused = true)]
    async fn token_end_already_past_ends_at_once() {
        for past in [0, -1, -3600] {
            let t0 = Instant::now();
            let (mut client, mut backend, task, _) =
                start_with_token(limits(None, None), Some(past));
            assert_eq!(task.await.unwrap(), SessionEnd::TokenExpired, "{past}");
            assert_eq!(t0.elapsed(), Duration::ZERO, "{past}");
            assert_closed(&mut client).await;
            assert_closed(&mut backend).await;
        }
    }

    /// With both `max_session` and a token end, the earlier one ends the
    /// session and names the reason.
    #[tokio::test(start_paused = true)]
    async fn earliest_deadline_wins() {
        for (max, token, reason) in [
            (3600, 1800, SessionEnd::TokenExpired),
            (1800, 3600, SessionEnd::MaxSession),
        ] {
            let (mut client, mut backend, task, _) =
                start_with_token(limits(None, Some(max)), Some(token));
            let took = busy_until_end(&mut client, &mut backend, &task).await;
            assert_eq!(task.await.unwrap(), reason);
            let first = Duration::from_secs(max.min(token as u64));
            assert!(
                took >= first && took < first + Duration::from_secs(70),
                "{took:?}"
            );
        }
    }

    /// The token's end is a time of the system clock: a step of that clock
    /// after the login moves the end within `CLOCK_RECHECK`, either way.
    #[tokio::test(start_paused = true)]
    async fn token_end_follows_a_clock_step() {
        for (step, at) in [(2000, 1600), (-2000, 5600)] {
            let (_client, _backend, task, clock) = start_with_token(limits(None, None), Some(3600));
            let t0 = Instant::now();
            tokio::time::sleep(Duration::from_secs(600)).await;
            clock.step.store(step, Ordering::Relaxed);
            assert_eq!(task.await.unwrap(), SessionEnd::TokenExpired, "{step}");
            let (took, at) = (t0.elapsed(), Duration::from_secs(at));
            assert!(took >= at && took <= at + CLOCK_RECHECK, "{step}: {took:?}");
        }
    }

    /// The token's end: `exp` plus the grace, as a time; never for an
    /// `exp` past what the clock can represent.
    #[test]
    fn token_end_is_exp_plus_grace() {
        let grace = Duration::from_secs(300);
        assert_eq!(
            token_end(1_800_000_000, grace),
            Some(UNIX_EPOCH + Duration::from_secs(1_800_000_300))
        );
        assert_eq!(token_end(0, Duration::ZERO), Some(UNIX_EPOCH));
        assert_eq!(token_end(u64::MAX, grace), None);
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
