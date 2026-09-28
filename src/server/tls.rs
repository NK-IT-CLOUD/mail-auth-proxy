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
        *self.current.write().unwrap_or_else(|p| p.into_inner()) = in_use(fresh);
        Ok(())
    }
}

/// The certificate now served; its expiry goes to the metrics.
fn in_use(ck: CertifiedKey) -> Arc<CertifiedKey> {
    // `load_certified_key` never returns an empty chain; the leaf is first.
    let not_after = ck.cert.first().and_then(|c| not_after(c)).unwrap_or(0);
    crate::obs::metrics::set_cert_not_after(not_after);
    Arc::new(ck)
}

/// One DER element: tag, contents and what follows it. Definite lengths of
/// up to four bytes, which is all a certificate uses.
fn der_element(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, b) = b.split_first()?;
    let (&first, b) = b.split_first()?;
    let (len, b) = if first < 0x80 {
        (usize::from(first), b)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 || b.len() < n {
            return None;
        }
        let len = b[..n].iter().fold(0usize, |l, &x| l << 8 | usize::from(x));
        (len, &b[n..])
    };
    (b.len() >= len).then(|| (tag, &b[..len], &b[len..]))
}

/// `notAfter` of an X.509 certificate as Unix seconds (RFC 5280 §4.1:
/// Certificate → tbsCertificate → [version], serialNumber, signature,
/// issuer, validity → notBefore, notAfter). `None` if it does not parse.
fn not_after(der: &[u8]) -> Option<u64> {
    let (0x30, cert, _) = der_element(der)? else {
        return None;
    };
    let (0x30, tbs, _) = der_element(cert)? else {
        return None;
    };
    let (mut tag, _, mut rest) = der_element(tbs)?;
    if tag == 0xa0 {
        // Explicit version; the serial number follows.
        (tag, _, rest) = der_element(rest)?;
    }
    if tag != 0x02 {
        return None;
    }
    let (_, _, rest) = der_element(rest)?; // signature algorithm
    let (_, _, rest) = der_element(rest)?; // issuer
    let (0x30, validity, _) = der_element(rest)? else {
        return None;
    };
    let (_, _, validity) = der_element(validity)?; // notBefore
    let (tag, time, _) = der_element(validity)?;
    let time = std::str::from_utf8(time).ok()?;
    // UTCTime YYMMDDHHMMSSZ (years 1950–2049), GeneralizedTime YYYYMMDDHHMMSSZ.
    let (year, rest) = match tag {
        0x17 => {
            let yy: i64 = time.get(..2)?.parse().ok()?;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, &time[2..])
        }
        0x18 => (time.get(..4)?.parse().ok()?, &time[4..]),
        _ => return None,
    };
    if rest.len() != 11 || !rest.ends_with('Z') || !rest[..10].bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let field = |i: usize| -> i64 { rest[i..i + 2].parse().unwrap_or(0) };
    let (month, day, h, m, s) = (field(0), field(2), field(4), field(6), field(8));
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    // Days since 1970-01-01 of a proleptic Gregorian date (H. Hinnant's
    // days_from_civil).
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    u64::try_from(days * 86_400 + h * 3600 + m * 60 + s).ok()
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
        current: RwLock::new(in_use(load_certified_key(cert, key, &provider)?)),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn cert_until(year: i32, month: u8, day: u8) -> Vec<u8> {
        let mut p = rcgen::CertificateParams::new(vec!["proxy.test".into()]).unwrap();
        p.not_after = rcgen::date_time_ymd(year, month, day);
        let key = rcgen::KeyPair::generate().unwrap();
        p.self_signed(&key).unwrap().der().to_vec()
    }

    #[test]
    fn reads_not_after() {
        // UTCTime before 2050 (including a leap day), GeneralizedTime from 2050.
        assert_eq!(not_after(&cert_until(2028, 2, 29)), Some(1_835_395_200));
        assert_eq!(not_after(&cert_until(2049, 12, 31)), Some(2_524_521_600));
        assert_eq!(not_after(&cert_until(2051, 3, 1)), Some(2_561_241_600));
    }

    #[test]
    fn not_after_of_garbage_is_none() {
        let der = cert_until(2030, 1, 1);
        assert_eq!(not_after(&[]), None);
        assert_eq!(not_after(b"not a certificate"), None);
        // Every truncation fails cleanly instead of panicking.
        for n in 0..der.len() {
            assert_eq!(not_after(&der[..n]), None, "cut at {n}");
        }
        // A length that claims more than there is.
        assert_eq!(not_after(&[0x30, 0x84, 0xff, 0xff, 0xff, 0xff]), None);
    }
}
