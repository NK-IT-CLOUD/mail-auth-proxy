//! Wire-level helpers shared by all protocols: timeouts, deadlines, the
//! line reader, backend connects and the byte relay.

pub mod connect;
pub mod line;
pub mod proxyproto;

use anyhow::{anyhow, Result};
use std::time::Duration;

/// Timeouts and the pre-auth command limit, from the configuration
/// (`[timeouts]`, `[limits]`).
#[derive(Debug, Clone, Copy)]
pub struct Tuning {
    /// Longest silence on any single wire read. Every protocol read goes
    /// through `read_line`, so this bounds a stalled peer everywhere: a client
    /// that never speaks, or a backend that accepts and goes silent.
    pub idle: Duration,
    /// Backend TCP connect, TLS handshake and PROXY header, each.
    pub connect: Duration,
    /// Total budget from accept to a presented credential. The idle timeout
    /// alone is not enough: a client that drip-feeds one byte just under it
    /// would reset it forever.
    pub preauth: Duration,
    /// Commands accepted before authentication.
    pub max_preauth_commands: usize,
}

/// The configuration defaults, for unit tests.
#[cfg(test)]
impl Default for Tuning {
    fn default() -> Self {
        Tuning {
            idle: Duration::from_secs(30),
            connect: Duration::from_secs(10),
            preauth: Duration::from_secs(60),
            max_preauth_commands: 8,
        }
    }
}

/// Run `fut` until the absolute instant `until`. Used for the pre-auth budget,
/// which spans several phases (plaintext dialog, TLS handshake, SASL) and must
/// not restart with each of them. `budget` is the whole budget, for the error.
pub async fn deadline_at<F, T>(
    until: tokio::time::Instant,
    budget: Duration,
    what: &str,
    fut: F,
) -> Result<T>
where
    F: std::future::Future<Output = Result<T>>,
{
    match tokio::time::timeout_at(until, fut).await {
        Ok(r) => r,
        Err(_) => Err(anyhow!(
            "{what}: pre-auth budget of {}s used up",
            budget.as_secs()
        )),
    }
}

/// Run `fut` with a deadline, turning an elapsed timer into an error labelled
/// with `what`.
pub async fn deadline<F, T>(d: Duration, what: &str, fut: F) -> Result<T>
where
    F: std::future::Future<Output = Result<T>>,
{
    match tokio::time::timeout(d, fut).await {
        Ok(r) => r,
        Err(_) => Err(anyhow!("{what} timed out after {}s", d.as_secs())),
    }
}

/// Relay bytes both ways until either side closes. A peer that disconnects
/// without a TLS close_notify ends the relay with an error; that is the normal
/// end of many sessions, so it is not worth a warning.
pub async fn splice<A, B>(a: &mut A, b: &mut B)
where
    A: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + ?Sized,
    B: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + ?Sized,
{
    if let Err(e) = tokio::io::copy_bidirectional(a, b).await {
        tracing::debug!(target: crate::obs::target::RELAY, error=%e, "relay ended with an error");
    }
}
