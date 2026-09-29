//! Wire-level helpers shared by all protocols: timeouts, deadlines, the
//! line reader, backend connects and the byte relay.

pub mod connect;
pub mod line;
pub mod proxyproto;
mod relay;

pub use relay::splice;

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
    /// TCP keepalive of every client and backend connection.
    pub keepalive: Keepalive,
    /// After login: end the session after this long without a byte in
    /// either direction.
    pub session_idle: Option<Duration>,
    /// After login: end the session this long after the login.
    pub max_session: Option<Duration>,
}

/// The configuration defaults, for unit tests and fuzz targets.
#[cfg(any(test, fuzzing))]
impl Default for Tuning {
    fn default() -> Self {
        Tuning {
            idle: Duration::from_secs(30),
            connect: Duration::from_secs(10),
            preauth: Duration::from_secs(60),
            max_preauth_commands: 8,
            keepalive: Keepalive {
                idle: Duration::from_secs(600),
                interval: Duration::from_secs(60),
                count: 5,
            },
            session_idle: None,
            max_session: None,
        }
    }
}

/// TCP keepalive (`[session]` `keepalive_*`): after `idle` of silence the
/// kernel sends a probe every `interval`, and drops the connection after
/// `count` unanswered ones. A read or write on a dropped connection fails,
/// which ends the session.
#[derive(Debug, Clone, Copy)]
pub struct Keepalive {
    pub idle: Duration,
    pub interval: Duration,
    pub count: u32,
}

impl Keepalive {
    /// Turn keepalive on for `tcp` with these values.
    pub fn apply(&self, tcp: &tokio::net::TcpStream) -> std::io::Result<()> {
        let params = socket2::TcpKeepalive::new()
            .with_time(self.idle)
            .with_interval(self.interval)
            .with_retries(self.count);
        socket2::SockRef::from(tcp).set_tcp_keepalive(&params)
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

#[cfg(test)]
mod tests {
    use super::*;

    /// `apply` turns keepalive on with exactly the configured values, read
    /// back with getsockopt, on both ends of a connection.
    #[tokio::test]
    async fn keepalive_is_set_on_the_socket() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let out = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (accepted, _) = listener.accept().await.unwrap();
        // The largest values Linux takes (see `config::validate`).
        let ka = Keepalive {
            idle: Duration::from_secs(32_767),
            interval: Duration::from_secs(17),
            count: 127,
        };
        for tcp in [&out, &accepted] {
            let before = socket2::SockRef::from(tcp);
            assert!(!before.keepalive().unwrap(), "off until set");
            ka.apply(tcp).unwrap();
            let s = socket2::SockRef::from(tcp);
            assert!(s.keepalive().unwrap());
            assert_eq!(s.tcp_keepalive_time().unwrap(), ka.idle);
            assert_eq!(s.tcp_keepalive_interval().unwrap(), ka.interval);
            assert_eq!(s.tcp_keepalive_retries().unwrap(), ka.count);
        }
        // One past the kernel's range is refused, not clamped.
        let too_long = Keepalive {
            idle: Duration::from_secs(32_768),
            ..ka
        };
        assert!(too_long.apply(&out).is_err());
    }
}
