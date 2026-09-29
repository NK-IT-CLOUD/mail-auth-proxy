//! ManageSieve backend sessions and the cached backend capabilities.

use super::Sieve;
use crate::auth::{BackendCredential, BackendError, BackendLogin};
use crate::server::BackendConn;
use crate::wire::line::read_line;
use crate::wire::{connect, Tuning};
use anyhow::{anyhow, Result};
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::Instant;
use tokio_rustls::client::TlsStream;
use zeroize::Zeroizing;

/// The backend's post-STARTTLS capabilities (SIEVE extensions, limits, …),
/// relayed to clients before they authenticate.
///
/// Caching them means an unauthenticated client never causes a backend
/// connection, which would hold a Dovecot login process and a backend TLS
/// session for up to the pre-auth budget per TLS handshake on 4190. Only a
/// cache miss (once per TTL) opens a probe connection.
#[derive(Default)]
pub struct CapsCache(RwLock<Option<(Instant, Arc<Vec<String>>)>>);

impl CapsCache {
    /// The backend's `"SIEVE"` capability line from the last successful probe,
    /// whatever its age. The pre-TLS greeting must list SIEVE (RFC 5804 §1.7)
    /// but must not open a backend connection for an unencrypted client, so
    /// it is missing until the first probe after startup.
    pub fn sieve_line(&self) -> Option<String> {
        let caps = self.0.read().unwrap_or_else(|p| p.into_inner());
        caps.as_ref()?
            .1
            .iter()
            .find(|l| l.to_ascii_uppercase().starts_with("\"SIEVE\""))
            .cloned()
    }
}

/// Open a backend ManageSieve session up to (and including) the post-TLS
/// capability list.
/// `origin` is `(client, local)` for a client's session, `None` for the
/// capability probe, which is the proxy's own connection.
pub(super) async fn backend_session(
    backend: &BackendConn,
    origin: Option<(SocketAddr, SocketAddr)>,
    tuning: &Tuning,
) -> Result<(TlsStream<TcpStream>, Vec<String>)> {
    // The PROXY header goes first, before the backend's greeting.
    let mut tcp_be = connect::connect(backend, origin, tuning.connect, "sieve backend").await?;
    // Greeting capabilities, then STARTTLS and its OK.
    read_caps_until_ok(&mut tcp_be, tuning.idle).await?;
    tcp_be.write_all(b"STARTTLS\r\n").await?;
    read_caps_until_ok(&mut tcp_be, tuning.idle).await?;
    let mut be = connect::tls(backend, tcp_be, tuning.connect, "sieve backend").await?;
    let caps = read_caps_until_ok(&mut be, tuning.idle).await?;
    Ok((be, caps))
}

/// The backend's post-TLS capabilities, from the cache or a probe session.
pub(super) async fn backend_caps(sieve: &Sieve, tuning: &Tuning) -> Result<Arc<Vec<String>>> {
    if let Some((at, caps)) = sieve
        .caps
        .0
        .read()
        .unwrap_or_else(|p| p.into_inner())
        .as_ref()
    {
        if at.elapsed() < sieve.caps_ttl {
            return Ok(caps.clone());
        }
    }
    let (mut be, caps) = backend_session(&sieve.backend, None, tuning).await?;
    // End the probe politely; it carries no credential.
    let _ = tokio::time::timeout(Duration::from_secs(2), async {
        be.write_all(b"LOGOUT\r\n").await?;
        be.flush().await
    })
    .await;
    let caps = Arc::new(caps);
    *sieve.caps.0.write().unwrap_or_else(|p| p.into_inner()) = Some((Instant::now(), caps.clone()));
    Ok(caps)
}

/// The ManageSieve backend login of one client session.
pub(super) struct SieveLogin<'a> {
    pub backend: &'a BackendConn,
    pub tuning: &'a Tuning,
    /// `(client, local)`: the client's address and the address it dialed.
    pub origin: (SocketAddr, SocketAddr),
}

impl BackendLogin for SieveLogin<'_> {
    /// The backend connection and its OK line, relayed to the client.
    type Conn = (TlsStream<TcpStream>, String);

    async fn login(&self, credential: BackendCredential<'_>) -> Result<Self::Conn, BackendError> {
        let (mech, response) = match credential {
            BackendCredential::Token { identity, token } => {
                ("XOAUTH2", crate::auth::sasl::build_xoauth2(identity, token))
            }
            BackendCredential::Password { user, pass } => {
                ("PLAIN", crate::auth::sasl::build_plain(user, pass))
            }
        };
        // `concat` sizes the line once; it is zeroized on drop like the response.
        let auth_line =
            Zeroizing::new(["AUTHENTICATE \"", mech, "\" \"", &response, "\"\r\n"].concat());
        let (mut be, _caps) = backend_session(self.backend, Some(self.origin), self.tuning).await?;
        be.write_all(auth_line.as_bytes()).await?;
        // The backend's reply; it is forwarded verbatim on OK.
        let be_reply = read_line(&mut be, self.tuning.idle).await?;
        // `NO (TRYLATER)` (RFC 5804) is a temporary failure: an outage.
        if be_reply.to_ascii_uppercase().starts_with("NO (TRYLATER)") {
            return Err(anyhow!("backend temporarily unavailable: {be_reply}").into());
        }
        if !be_reply.to_ascii_uppercase().starts_with("OK") {
            return Err(BackendError::Rejected(be_reply));
        }
        Ok((be, be_reply))
    }
}

/// Most capability lines accepted from the backend. Pigeonhole sends a
/// handful; a backend that never ends the list must not grow it without bound.
const MAX_CAP_LINES: usize = 64;

/// Read ManageSieve capability lines until (and not including) the `OK` line.
/// Returns the capability lines (without CRLF).
/// Returns error if `NO` or `BYE` is seen, on EOF, or after `MAX_CAP_LINES`
/// lines without `OK`.
async fn read_caps_until_ok<S: tokio::io::AsyncRead + Unpin>(
    s: &mut S,
    idle: Duration,
) -> Result<Vec<String>> {
    let mut caps = Vec::new();
    loop {
        let line = read_line(s, idle).await?;
        let upper = line.to_ascii_uppercase();
        if upper.starts_with("OK") {
            return Ok(caps);
        }
        if upper.starts_with("NO") || upper.starts_with("BYE") {
            return Err(anyhow!("backend error: {line}"));
        }
        if caps.len() == MAX_CAP_LINES {
            return Err(anyhow!(
                "backend sent more than {MAX_CAP_LINES} capability lines"
            ));
        }
        caps.push(line);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// read_caps_until_ok stops on the OK line and returns the capability lines.
    #[tokio::test]
    async fn drain_caps_stops_on_ok() {
        use std::io::Cursor;
        let input = b"\"IMPLEMENTATION\" \"Dovecot\"\r\n\"SASL\" \"PLAIN\"\r\nOK \"ready\"\r\n";
        let mut cursor = Cursor::new(input.to_vec());
        assert_eq!(
            read_caps_until_ok(&mut cursor, Duration::from_secs(30))
                .await
                .unwrap()
                .len(),
            2
        );
    }

    /// A capability list that never ends is an error after MAX_CAP_LINES.
    #[tokio::test]
    async fn drain_caps_is_bounded() {
        use std::io::Cursor;
        let lines = |n: usize| "\"X\" \"y\"\r\n".repeat(n) + "OK \"ready\"\r\n";
        let mut ok = Cursor::new(lines(MAX_CAP_LINES).into_bytes());
        assert_eq!(
            read_caps_until_ok(&mut ok, Duration::from_secs(30))
                .await
                .unwrap()
                .len(),
            MAX_CAP_LINES
        );
        let mut long = Cursor::new(lines(MAX_CAP_LINES + 1).into_bytes());
        assert!(read_caps_until_ok(&mut long, Duration::from_secs(30))
            .await
            .is_err());
    }

    /// read_caps_until_ok returns error on NO.
    #[tokio::test]
    async fn drain_caps_errors_on_no() {
        use std::io::Cursor;
        let input = b"NO \"not available\"\r\n";
        let mut cursor = Cursor::new(input.to_vec());
        assert!(read_caps_until_ok(&mut cursor, Duration::from_secs(30))
            .await
            .is_err());
    }

    /// A Pigeonhole capability block through `read_caps_until_ok` and a copy
    /// of the relay rule of `sieve::handle`: SIEVE, IMPLEMENTATION and NOTIFY
    /// kept, SASL rewritten, STARTTLS dropped.
    #[tokio::test]
    async fn cap_rewrite_keeps_sieve_rewrites_sasl_drops_starttls() {
        use std::io::Cursor;
        let input = concat!(
            "\"IMPLEMENTATION\" \"Dovecot Pigeonhole\"\r\n",
            "\"SIEVE\" \"fileinto reject envelope vacation\"\r\n",
            "\"NOTIFY\" \"mailto\"\r\n",
            "\"SASL\" \"OAUTHBEARER XOAUTH2 LOGIN PLAIN\"\r\n",
            "\"STARTTLS\"\r\n",
            "\"VERSION\" \"1.0\"\r\n",
            "OK \"TLS negotiation successful.\"\r\n",
        );
        let mut cursor = Cursor::new(input.as_bytes().to_vec());
        let caps = read_caps_until_ok(&mut cursor, Duration::from_secs(30))
            .await
            .unwrap();

        let mut output_lines: Vec<String> = Vec::new();
        for cap_line in &caps {
            let upper = cap_line.to_ascii_uppercase();
            if upper.starts_with("\"STARTTLS\"") {
                continue;
            }
            if upper.starts_with("\"SASL\"") {
                output_lines.push("\"SASL\" \"XOAUTH2 OAUTHBEARER\"".to_string());
            } else {
                output_lines.push(cap_line.clone());
            }
        }

        assert!(
            output_lines
                .iter()
                .any(|l| l.contains("\"SIEVE\"") && l.contains("fileinto")),
            "SIEVE capability must be forwarded: {output_lines:?}"
        );
        assert!(
            output_lines
                .iter()
                .any(|l| l.contains("\"IMPLEMENTATION\"")),
            "IMPLEMENTATION capability must be forwarded"
        );
        assert!(
            output_lines.iter().any(|l| l.contains("\"NOTIFY\"")),
            "NOTIFY capability must be forwarded"
        );
        assert!(
            output_lines
                .iter()
                .any(|l| l == "\"SASL\" \"XOAUTH2 OAUTHBEARER\""),
            "SASL must be rewritten to OAuth-only: {output_lines:?}"
        );
        assert!(
            !output_lines.iter().any(|l| {
                let u = l.to_ascii_uppercase();
                u.starts_with("\"SASL\"") && (u.contains("LOGIN") || u.contains("PLAIN"))
            }),
            "SASL must not contain LOGIN/PLAIN: {output_lines:?}"
        );
        assert!(
            !output_lines
                .iter()
                .any(|l| l.to_ascii_uppercase().starts_with("\"STARTTLS\"")),
            "STARTTLS must be dropped: {output_lines:?}"
        );
    }
}
