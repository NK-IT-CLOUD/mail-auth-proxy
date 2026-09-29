//! Backend connections: TCP connect, PROXY protocol header and TLS handshake,
//! each under the connect timeout; address parsing.

use super::deadline;
use crate::server::BackendConn;
use anyhow::Result;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

/// Open a TCP connection to `backend` and write the PROXY protocol header if
/// the backend expects one (see `send_proxy_header` for `origin`). `what`
/// names the backend in errors (`backend`, `sieve backend`, …).
pub async fn connect(
    backend: &BackendConn,
    origin: Option<(SocketAddr, SocketAddr)>,
    timeout: Duration,
    what: &str,
) -> Result<TcpStream> {
    let mut tcp = deadline(timeout, &format!("{what} connect"), async {
        Ok(TcpStream::connect(&backend.address).await?)
    })
    .await?;
    if let Err(e) = backend.keepalive.apply(&tcp) {
        tracing::warn!(target: crate::obs::target::MAIN, backend=%backend.address, error=%e, "{what}: TCP keepalive not set");
    }
    send_proxy_header(backend, &mut tcp, origin, timeout).await?;
    Ok(tcp)
}

/// TLS handshake with `backend` on `tcp`, verified against its `verify_name`.
pub async fn tls(
    backend: &BackendConn,
    tcp: TcpStream,
    timeout: Duration,
    what: &str,
) -> Result<TlsStream<TcpStream>> {
    deadline(timeout, &format!("{what} TLS handshake"), async {
        Ok(backend.tls.connect(backend.name.clone(), tcp).await?)
    })
    .await
}

/// Write the PROXY protocol v2 header if enabled (see `proxyproto`): the
/// first bytes on the connection, before the TLS handshake. `origin` is
/// `(client, local)`, local being the address the client dialed (this
/// socket's local addr); the two always share an address family. `None`
/// marks a connection the proxy makes for itself and sends a LOCAL header.
async fn send_proxy_header(
    backend: &BackendConn,
    tcp: &mut TcpStream,
    origin: Option<(SocketAddr, SocketAddr)>,
    timeout: Duration,
) -> Result<()> {
    if backend.client_ip != crate::config::ClientIp::ProxyV2 {
        return Ok(());
    }
    let hdr = match origin {
        // A backend that expects the header refuses a connection without
        // one: an outage with its cause, not a silent omission.
        Some((client, local)) => super::proxyproto::v2_header(client, local).ok_or_else(|| {
            anyhow::anyhow!(
                "PROXY header: client {client} and local {local} differ in address family"
            )
        })?,
        None => super::proxyproto::v2_local_header(),
    };
    deadline(timeout, "backend PROXY header", async {
        tcp.write_all(&hdr).await?;
        Ok(())
    })
    .await
}

/// Split a `host:port` (or bare host) into just the host, handling bracketed
/// IPv6 (`[::1]:993`) and bare IPv6 literals (`::1`) correctly.
pub fn host_of(addr: &str) -> &str {
    if let Some(rest) = addr.strip_prefix('[') {
        // [v6]:port or [v6]
        return rest.split(']').next().unwrap_or(rest);
    }
    // A bare IPv6 literal has more than one colon and no port; leave it whole.
    if addr.matches(':').count() > 1 {
        return addr;
    }
    addr.split(':').next().unwrap_or(addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Timeouts name the backend and the step; the text reaches the journal
    /// in the "session ended" lines.
    #[tokio::test]
    async fn timeouts_name_the_backend_and_step() {
        use std::sync::Arc;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        // Accepts, then never answers the TLS ClientHello.
        let silent = tokio::spawn(async move {
            let (_s, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(5)).await;
        });
        let cfg = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        let backend = BackendConn {
            address,
            name: rustls::pki_types::ServerName::try_from("backend.test").unwrap(),
            tls: tokio_rustls::TlsConnector::from(Arc::new(cfg)),
            client_ip: crate::config::ClientIp::None,
            tls_mode: crate::config::BackendTls::Implicit,
            auth_forward: crate::config::AuthForward::Xoauth2,
            keepalive: crate::wire::Tuning::default().keepalive,
        };
        let tcp = connect(&backend, None, Duration::from_secs(5), "sieve backend")
            .await
            .unwrap();
        let e = tls(&backend, tcp, Duration::from_millis(50), "sieve backend")
            .await
            .unwrap_err();
        assert_eq!(
            e.to_string(),
            "sieve backend TLS handshake timed out after 0s"
        );
        silent.abort();
    }

    /// Client and local address from different families cannot be put in
    /// one PROXY header; the connect fails instead of going ahead without
    /// the header the backend expects.
    #[tokio::test]
    async fn mixed_family_origin_is_an_error() {
        use std::sync::Arc;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let cfg = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        let backend = BackendConn {
            address: listener.local_addr().unwrap().to_string(),
            name: rustls::pki_types::ServerName::try_from("backend.test").unwrap(),
            tls: tokio_rustls::TlsConnector::from(Arc::new(cfg)),
            client_ip: crate::config::ClientIp::ProxyV2,
            tls_mode: crate::config::BackendTls::Implicit,
            auth_forward: crate::config::AuthForward::Xoauth2,
            keepalive: crate::wire::Tuning::default().keepalive,
        };
        let client: SocketAddr = "192.0.2.7:40000".parse().unwrap();
        let local: SocketAddr = "[2001:db8::1]:993".parse().unwrap();
        let e = connect(
            &backend,
            Some((client, local)),
            Duration::from_secs(5),
            "backend",
        )
        .await
        .unwrap_err();
        assert!(e.to_string().contains("address family"), "{e}");
    }

    #[test]
    fn host_of_handles_v4_v6_and_bare() {
        assert_eq!(host_of("192.0.2.10:993"), "192.0.2.10");
        assert_eq!(host_of("mail.example.org:587"), "mail.example.org");
        assert_eq!(host_of("mail.example.org"), "mail.example.org");
        assert_eq!(host_of("[2001:db8::1]:993"), "2001:db8::1");
        assert_eq!(host_of("::1"), "::1");
        assert_eq!(host_of("2001:db8::1"), "2001:db8::1");
    }
}
