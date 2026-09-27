//! TLS material: the client-facing certificate and the backend trust anchors.

use anyhow::Result;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::sync::{Arc, RwLock};
use tokio_rustls::{TlsAcceptor, TlsConnector};

/// The client-facing certificate, replaceable while the server runs.
///
/// rustls asks the resolver for the certificate on every handshake, so a
/// `reload` takes effect for the next connection; established sessions keep
/// the certificate they were opened with.
#[derive(Debug)]
pub(super) struct CertStore {
    cert: String,
    key: String,
    provider: Arc<CryptoProvider>,
    current: RwLock<Arc<CertifiedKey>>,
}

impl CertStore {
    /// Re-read the certificate and key files. On any error the certificate
    /// in use stays.
    pub(super) fn reload(&self) -> Result<()> {
        let fresh = load_certified_key(&self.cert, &self.key, &self.provider)?;
        *self.current.write().unwrap_or_else(|p| p.into_inner()) = Arc::new(fresh);
        Ok(())
    }
}

impl ResolvesServerCert for CertStore {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(
            self.current
                .read()
                .unwrap_or_else(|p| p.into_inner())
                .clone(),
        )
    }
}

/// The certificate chain and its private key, checked to belong together.
fn load_certified_key(cert: &str, key: &str, provider: &CryptoProvider) -> Result<CertifiedKey> {
    let certs: Vec<CertificateDer> = CertificateDer::pem_file_iter(cert)
        .map_err(|e| anyhow::anyhow!("{cert}: {e}"))?
        .collect::<std::result::Result<_, _>>()
        .map_err(|e| anyhow::anyhow!("{cert}: {e}"))?;
    if certs.is_empty() {
        return Err(anyhow::anyhow!("{cert}: no certificates"));
    }
    let key = PrivateKeyDer::from_pem_file(key).map_err(|e| anyhow::anyhow!("{key}: {e}"))?;
    Ok(CertifiedKey::from_der(certs, key, provider)?)
}

/// The TLS acceptor for clients and the store behind it (for `reload`).
pub(super) fn load_server_tls(cert: &str, key: &str) -> Result<(TlsAcceptor, Arc<CertStore>)> {
    let builder = rustls::ServerConfig::builder().with_no_client_auth();
    let provider = builder.crypto_provider().clone();
    let store = Arc::new(CertStore {
        current: RwLock::new(Arc::new(load_certified_key(cert, key, &provider)?)),
        cert: cert.to_string(),
        key: key.to_string(),
        provider,
    });
    let cfg = builder.with_cert_resolver(store.clone());
    Ok((TlsAcceptor::from(Arc::new(cfg)), store))
}

/// Trust anchors for a backend: the CAs in `ca_file` only, or the system
/// store (public roots plus whatever internal CA the host trusts).
pub(super) fn backend_connector(ca_file: Option<&str>) -> Result<TlsConnector> {
    let mut roots = rustls::RootCertStore::empty();
    match ca_file {
        Some(path) => {
            for cert in
                CertificateDer::pem_file_iter(path).map_err(|e| anyhow::anyhow!("{path}: {e}"))?
            {
                roots.add(cert.map_err(|e| anyhow::anyhow!("{path}: {e}"))?)?;
            }
            if roots.is_empty() {
                return Err(anyhow::anyhow!("{path}: no CA certificates"));
            }
        }
        None => {
            let native = rustls_native_certs::load_native_certs();
            for e in &native.errors {
                tracing::warn!(target: crate::obs::target::MAIN, error=%e, "loading system CA certificates");
            }
            for cert in native.certs {
                let _ = roots.add(cert);
            }
            if roots.is_empty() {
                return Err(anyhow::anyhow!(
                    "no CA certificates found in system trust store"
                ));
            }
        }
    }
    let cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(cfg)))
}
