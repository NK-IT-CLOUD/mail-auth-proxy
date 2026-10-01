//! TLS material: the client-facing certificates and the backend trust anchors.

use anyhow::Result;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::sync::{Arc, RwLock};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio_rustls::{LazyConfigAcceptor, TlsConnector};

/// The client-facing certificates, each replaceable while the server runs.
///
/// The first is the default: it serves clients that send no SNI. A client
/// that sends one gets the certificate that carries the name (a DNS name in
/// its subjectAltName); a name no certificate carries is refused
/// (`Acceptor::accept`). rustls asks the resolver on every handshake, so a
/// `reload` takes effect for the next connection; established sessions keep
/// the certificate they were opened with.
#[derive(Debug)]
pub(crate) struct CertStore {
    provider: Arc<CryptoProvider>,
    entries: Vec<Entry>,
}

/// One configured certificate and key file.
#[derive(Debug)]
struct Entry {
    cert: String,
    key: String,
    current: RwLock<Arc<Served>>,
}

/// A loaded certificate: what rustls serves and the names SNI selects it by.
#[derive(Debug)]
struct Served {
    key: Arc<CertifiedKey>,
    /// The dNSName entries of the subjectAltName, lowercase and without a
    /// trailing dot; a wildcard as `*.` plus at least two labels.
    names: Vec<String>,
}

impl CertStore {
    /// Load every pair of `tls` (the default first). Any unusable pair fails.
    pub(crate) fn load(tls: &crate::config::Tls) -> Result<CertStore> {
        let provider = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .crypto_provider()
            .clone();
        let entries = tls
            .pairs()
            .enumerate()
            .map(|(i, (_, cert, key))| {
                let served = load_served(cert, key, i == 0, &provider)?;
                Ok(Entry {
                    cert: cert.to_string(),
                    key: key.to_string(),
                    current: RwLock::new(in_use(cert, served)),
                })
            })
            .collect::<Result<_>>()?;
        Ok(CertStore { provider, entries })
    }

    /// Re-read every certificate and key file. A pair that fails keeps the
    /// certificate it had; the others are replaced. The result names each
    /// certificate file with its outcome, in configuration order.
    pub(crate) fn reload(&self) -> Vec<(&str, Result<()>)> {
        self.entries
            .iter()
            .enumerate()
            .map(|(i, e)| {
                let r = load_served(&e.cert, &e.key, i == 0, &self.provider).map(|fresh| {
                    *e.current.write().unwrap_or_else(|p| p.into_inner()) = in_use(&e.cert, fresh);
                });
                (e.cert.as_str(), r)
            })
            .collect()
    }

    /// Set the expiry metric of every certificate, for files registered
    /// with the metrics after the store was loaded (a reload).
    pub(crate) fn record_expiry(&self) {
        for e in &self.entries {
            crate::obs::metrics::set_cert_not_after(&e.cert, expiry(&e.served()));
        }
    }

    /// Every name a client may ask for (SNI), in configuration order.
    pub(crate) fn names(&self) -> Vec<String> {
        self.entries
            .iter()
            .flat_map(|e| e.served().names.clone())
            .collect()
    }

    /// Whether the default certificate carries no DNS name.
    pub(crate) fn default_has_no_names(&self) -> bool {
        self.entries[0].served().names.is_empty()
    }

    /// The certificate for a client that asked for `sni`, if any serves it.
    fn select(&self, sni: Option<&str>) -> Option<Arc<CertifiedKey>> {
        let served: Vec<Arc<Served>> = self.entries.iter().map(Entry::served).collect();
        let names: Vec<&[String]> = served.iter().map(|s| &s.names[..]).collect();
        pick(&names, sni).map(|i| served[i].key.clone())
    }
}

impl Entry {
    fn served(&self) -> Arc<Served> {
        self.current
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }
}

/// A name as SNI compares it: the canonical form (`crate::domain`), a
/// wildcard as `*.` and the canonical rest. A name that is not a valid
/// domain (and so is no name a client can send as SNI) falls back to ASCII
/// lower case without a trailing dot.
fn normalize(name: &str) -> String {
    if let Some(rest) = name.strip_prefix("*.") {
        if let Ok(rest) = crate::domain::canonical(rest) {
            return format!("*.{rest}");
        }
    }
    crate::domain::canonical(name)
        .unwrap_or_else(|_| name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase())
}

/// Which of the certificates with `names` serves `sni`. Without SNI the
/// first (the default). Otherwise the first that carries the name itself,
/// else the first with a wildcard for it: `*.example.org` stands for exactly
/// one leftmost label, so it covers `a.example.org` but neither
/// `example.org` nor `a.b.example.org` (RFC 9525 §6.3, formerly RFC 6125
/// §6.4.3). `None` if no
/// certificate carries the name.
fn pick(names: &[&[String]], sni: Option<&str>) -> Option<usize> {
    let Some(sni) = sni else {
        return (!names.is_empty()).then_some(0);
    };
    let sni = normalize(sni);
    let wildcard = sni
        .split_once('.')
        .filter(|(label, _)| !label.is_empty())
        .map(|(_, parent)| format!("*.{parent}"));
    names
        .iter()
        .position(|n| n.contains(&sni))
        .or_else(|| wildcard.and_then(|w| names.iter().position(|n| n.contains(&w))))
}

/// Whether `names` (of one or more certificates) serve a client asking for
/// `sni`.
pub(crate) fn serves(names: &[String], sni: &str) -> bool {
    pick(&[names], Some(sni)).is_some()
}

/// Whether `cert` and `key` load as a pair, the default certificate or
/// (`default` false) one chosen by SNI.
pub(crate) fn check_pair(cert: &str, key: &str, default: bool) -> Result<()> {
    let provider = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .crypto_provider()
        .clone();
    load_served(cert, key, default, &provider).map(|_| ())
}

/// The DNS names of a certificate: the subjectAltName dNSName entries only
/// (RFC 9525 §2: the subject CN does not identify a service). A wildcard
/// needs two labels after `*.`, so `*.org` covers nothing.
fn dns_names(der: &CertificateDer<'_>) -> Result<Vec<String>> {
    let cert = webpki::EndEntityCert::try_from(der)
        .map_err(|e| anyhow::anyhow!("certificate does not parse: {e}"))?;
    Ok(cert
        .valid_dns_names()
        .map(normalize)
        .filter(|n| {
            n.strip_prefix("*.")
                .is_none_or(|parent| parent.contains('.'))
        })
        .collect())
}

/// Load one pair. A certificate other than the default (`default` false) is
/// only ever chosen by SNI, so it must carry a DNS name.
fn load_served(cert: &str, key: &str, default: bool, provider: &CryptoProvider) -> Result<Served> {
    let ck = load_certified_key(cert, key, provider)?;
    let names = dns_names(ck.end_entity_cert()?).map_err(|e| anyhow::anyhow!("{cert}: {e}"))?;
    if names.is_empty() && !default {
        anyhow::bail!("{cert}: no DNS name in the subjectAltName; only the default certificate (tls.cert) serves clients without SNI");
    }
    Ok(Served {
        key: Arc::new(ck),
        names,
    })
}

/// The certificate now served from the file `cert`; its expiry goes to the
/// metrics.
fn in_use(cert: &str, served: Served) -> Arc<Served> {
    crate::obs::metrics::set_cert_not_after(cert, expiry(&served));
    Arc::new(served)
}

/// `notAfter` of a loaded certificate (Unix seconds), 0 if unknown.
fn expiry(served: &Served) -> u64 {
    // `load_certified_key` never returns an empty chain; the leaf is first.
    served
        .key
        .cert
        .first()
        .and_then(|c| not_after(c))
        .unwrap_or(0)
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
pub(crate) fn not_after(der: &[u8]) -> Option<u64> {
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
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let month_days = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    // Second 60 is a leap second (X.680 time values, RFC 5280 §4.1.2.5).
    if !(1..=12).contains(&month) || !(1..=month_days).contains(&day) || h > 23 || m > 59 || s > 60
    {
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
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.select(hello.server_name())
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

/// The fatal `unrecognized_name` alert (RFC 6066 §3, alert 112) as a
/// plaintext TLS record: content type alert (21), record version 3.3,
/// length 2, level fatal (2), description. Sent before the ServerHello, so
/// it is not encrypted in TLS 1.3 either (RFC 8446 §6).
const UNRECOGNIZED_NAME: [u8; 7] = [21, 3, 3, 0, 2, 2, 112];

/// The fatal `no_application_protocol` alert (RFC 7301 §3.2, alert 120) as
/// a plaintext record, like `UNRECOGNIZED_NAME`.
const NO_APPLICATION_PROTOCOL: [u8; 7] = [21, 3, 3, 0, 2, 2, 120];

/// The protocol IDs of the IANA registry "TLS Application-Layer Protocol
/// Negotiation (ALPN) Protocol IDs" (as of 2026-09-29), byte for byte, without
/// the GREASE values of RFC 8701, which a server must ignore. SMTP has no ID:
/// on a submission listener each of these names another protocol.
const REGISTERED_ALPN: &[&[u8]] = &[
    b"http/0.9",
    b"http/1.0",
    b"http/1.1",
    b"spdy/1",
    b"spdy/2",
    b"spdy/3",
    b"stun.turn",
    b"stun.nat-discovery",
    b"h2",
    b"h2c",
    b"webrtc",
    b"c-webrtc",
    b"ftp",
    b"imap",
    b"pop3",
    b"managesieve",
    b"coap",
    b"co",
    b"xmpp-client",
    b"xmpp-server",
    b"acme-tls/1",
    b"mqtt",
    b"dot",
    b"ntske/1",
    b"sunrpc",
    b"h3",
    b"smb",
    b"irc",
    b"nntp",
    b"nnsp",
    b"doq",
    b"sip/2",
    b"tds/8.0",
    b"dicom",
    b"postgresql",
    b"radius/1.0",
    b"radius/1.1",
    b"netperfmeter/control",
    b"netperfmeter/data",
    b"n-pamp/2",
    b"EoQ",
    b"snifq/1",
];

/// TLS for one listener with the certificates of a `CertStore`.
#[derive(Clone)]
pub(crate) struct Acceptor {
    store: Arc<CertStore>,
    config: Arc<rustls::ServerConfig>,
    /// The listener has no ALPN ID of its own (SMTP): a client that offers
    /// a registered one (`REGISTERED_ALPN`) means another protocol.
    refuse_registered_alpn: bool,
}

impl Acceptor {
    /// The TLS handshake on `io`. A client whose SNI names none of the
    /// certificates is refused with `unrecognized_name` before any
    /// certificate is sent (RFC 6066 §3; RFC 9325 §3.7: the server SHOULD
    /// NOT continue the handshake), so the legacy gate's `sni` and the
    /// OAUTHBEARER `host` check only ever see names of the proxy. A client
    /// without SNI gets the default certificate. On a listener without an
    /// ALPN ID (SMTP), a client that offers an ID of another protocol is
    /// refused first with `no_application_protocol` (RFC 7301 §3.2, RFC 9325
    /// §3.8: ALPACA); no ALPN, or an unregistered value, is accepted and none
    /// is selected.
    pub(crate) async fn accept<IO>(
        &self,
        io: IO,
    ) -> std::io::Result<tokio_rustls::server::TlsStream<IO>>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        let start = LazyConfigAcceptor::new(rustls::server::Acceptor::default(), io).await?;
        if self.refuse_registered_alpn {
            let foreign = start
                .client_hello()
                .alpn()
                .and_then(|mut ids| ids.find(|id| REGISTERED_ALPN.contains(id)))
                .map(|id| String::from_utf8_lossy(id).into_owned());
            if let Some(id) = foreign {
                // A registered ID, so plain printable text in the log line.
                let err = std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("TLS ALPN {id:?} names another protocol"),
                );
                let mut io = start.io;
                let _ = io.write_all(&NO_APPLICATION_PROTOCOL).await;
                let _ = io.shutdown().await;
                return Err(err);
            }
        }
        if let Some(sni) = start.client_hello().server_name() {
            if self.store.select(Some(sni)).is_some() {
                return start.into_stream(self.config.clone()).await;
            }
            // rustls parsed it as a DNS name, so it is safe in a log line.
            let err = std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("TLS server name {sni} is not a name of any configured certificate"),
            );
            let mut io = start.io;
            // Best effort: the connection is closed either way.
            let _ = io.write_all(&UNRECOGNIZED_NAME).await;
            let _ = io.shutdown().await;
            return Err(err);
        }
        start.into_stream(self.config.clone()).await
    }
}

/// A TLS acceptor for one listener with the certificates of `store`. `alpn`
/// is the listener's protocol name (RFC 7301, IANA "TLS ALPN Protocol
/// IDs"): a client that offers ALPN without it is refused in the handshake
/// (`no_application_protocol`), so a TLS session meant for another protocol
/// cannot be redirected to this one (RFC 9325 §3.8, ALPACA). A client that
/// offers no ALPN is accepted. `None` for SMTP, which has no identifier:
/// no ALPN is selected, and a client that offers a registered ID of another
/// protocol is refused (`Acceptor::accept`).
pub(super) fn acceptor(store: &Arc<CertStore>, alpn: Option<&[u8]>) -> Acceptor {
    let mut cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(store.clone());
    cfg.alpn_protocols = alpn.map(|p| vec![p.to_vec()]).unwrap_or_default();
    Acceptor {
        store: store.clone(),
        config: Arc::new(cfg),
        refuse_registered_alpn: alpn.is_none(),
    }
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

    /// The refused ALPN IDs: the registry without GREASE, the protocols an
    /// ALPACA attack would redirect from among them.
    #[test]
    fn registered_alpn_ids() {
        for id in [
            &b"http/0.9"[..],
            b"http/1.0",
            b"http/1.1",
            b"h2",
            b"h2c",
            b"h3",
            b"spdy/1",
            b"spdy/2",
            b"spdy/3",
            b"imap",
            b"pop3",
            b"managesieve",
            b"ftp",
            b"xmpp-client",
            b"xmpp-server",
            b"dot",
            b"doq",
            b"acme-tls/1",
            b"irc",
            b"nntp",
            b"nnsp",
            b"smb",
            b"coap",
            b"mqtt",
            b"sip/2",
            b"postgresql",
        ] {
            assert!(
                REGISTERED_ALPN.contains(&id),
                "{:?}",
                String::from_utf8_lossy(id)
            );
        }
        // GREASE (RFC 8701 §3) is 0x?A 0x?A and must be ignored; nothing for SMTP.
        assert!(!REGISTERED_ALPN
            .iter()
            .any(|id| id.len() == 2 && id[0] == id[1] && id[0] & 0x0f == 0x0a));
        assert!(!REGISTERED_ALPN.iter().any(|id| id.starts_with(b"smtp")));
        let mut sorted = REGISTERED_ALPN.to_vec();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), REGISTERED_ALPN.len());
    }

    fn cert_until(year: i32, month: u8, day: u8) -> Vec<u8> {
        let mut p = rcgen::CertificateParams::new(vec!["proxy.test".into()]).unwrap();
        p.not_after = rcgen::date_time_ymd(year, month, day);
        let key = rcgen::KeyPair::generate().unwrap();
        p.self_signed(&key).unwrap().der().to_vec()
    }

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|n| n.to_string()).collect()
    }

    /// Exact names in any letter case and with a trailing dot; a wildcard
    /// for one label only; an exact name before any wildcard, else the
    /// first certificate in order; without SNI the default.
    #[test]
    fn picks_by_name() {
        let default = names(&["mail.example.org"]);
        let wild = names(&["*.example.net", "*.example.org"]);
        let tenant = names(&["mail.example.net", "imap.example.com"]);
        let second = names(&["imap.example.com"]);
        let certs = [&default[..], &wild, &tenant, &second];
        for (sni, want) in [
            (None, Some(0)),
            (Some("mail.example.org"), Some(0)),
            (Some("MAIL.Example.ORG"), Some(0)),
            (Some("mail.example.org."), Some(0)),
            (Some("imap.example.org"), Some(1)),
            (Some("IMAP.example.net."), Some(1)),
            (Some("mail.example.net"), Some(2)),
            (Some("imap.example.com"), Some(2)),
            (Some("example.net"), None),
            (Some("a.b.example.net"), None),
            (Some(".example.net"), None),
            (Some("other.test"), None),
            (Some(""), None),
        ] {
            assert_eq!(pick(&certs, sni), want, "{sni:?}");
        }
        assert_eq!(pick(&[], None), None);
        assert!(serves(&tenant, "Mail.Example.NET"));
        assert!(!serves(&default, "imap.example.org"));
    }

    fn cert_for(names: &[&str]) -> (rcgen::Certificate, rcgen::KeyPair) {
        let key = rcgen::KeyPair::generate().unwrap();
        let p =
            rcgen::CertificateParams::new(names.iter().map(|n| n.to_string()).collect::<Vec<_>>())
                .unwrap();
        (p.self_signed(&key).unwrap(), key)
    }

    /// The dNSName entries, normalized; IP addresses and a wildcard over a
    /// single label (`*.org`) are no names.
    #[test]
    fn dns_names_of_a_certificate() {
        let (c, _) = cert_for(&["Mail.Example.org", "*.Example.NET", "*.org", "192.0.2.1"]);
        assert_eq!(
            dns_names(c.der()).unwrap(),
            ["mail.example.org", "*.example.net"]
        );
        let (c, _) = cert_for(&[]);
        assert!(dns_names(c.der()).unwrap().is_empty());
        assert!(dns_names(&CertificateDer::from(&b"not a certificate"[..])).is_err());
    }

    /// Write a certificate and key for `names` to `dir/<file>.pem|.key`;
    /// returns the paths and the DER.
    fn write_pair(dir: &std::path::Path, file: &str, names: &[&str]) -> (String, String, Vec<u8>) {
        let (c, k) = cert_for(names);
        let cert = dir.join(format!("{file}.pem")).display().to_string();
        let key = dir.join(format!("{file}.key")).display().to_string();
        std::fs::write(&cert, c.pem()).unwrap();
        std::fs::write(&key, k.serialize_pem()).unwrap();
        (cert, key, c.der().to_vec())
    }

    fn tls_config(pairs: &[(&str, &str)]) -> crate::config::Tls {
        crate::config::Tls {
            cert: pairs[0].0.into(),
            key: pairs[0].1.into(),
            certificates: pairs[1..]
                .iter()
                .map(|(c, k)| crate::config::CertKey {
                    cert: c.to_string(),
                    key: k.to_string(),
                })
                .collect(),
        }
    }

    fn served_der(store: &CertStore, sni: Option<&str>) -> Option<Vec<u8>> {
        store.select(sni).map(|k| k.cert[0].to_vec())
    }

    /// Only the default certificate may be without a DNS name: another one
    /// is chosen by SNI alone.
    #[test]
    fn only_the_default_may_have_no_name() {
        let dir = tempfile::tempdir().unwrap();
        let (c0, k0, _) = write_pair(dir.path(), "a", &["192.0.2.1"]);
        let (c1, k1, _) = write_pair(dir.path(), "b", &["mail.example.org"]);
        let store = CertStore::load(&tls_config(&[(&c0, &k0), (&c1, &k1)])).unwrap();
        assert!(store.default_has_no_names());
        assert_eq!(store.names(), ["mail.example.org"]);
        let e = CertStore::load(&tls_config(&[(&c1, &k1), (&c0, &k0)]))
            .unwrap_err()
            .to_string();
        assert!(e.contains("no DNS name"), "{e}");
        assert!(check_pair(&c0, &k0, true).is_ok());
        assert!(check_pair(&c0, &k0, false).is_err());
        assert!(
            check_pair(&c1, &k0, true).is_err(),
            "key of another certificate"
        );
    }

    /// A reload replaces each pair on its own; an unusable one (unreadable,
    /// or an SNI certificate that lost its names) keeps what it served.
    #[test]
    fn reload_is_per_certificate() {
        let dir = tempfile::tempdir().unwrap();
        let (c0, k0, d0) = write_pair(dir.path(), "a", &["mail.example.org"]);
        let (c1, k1, d1) = write_pair(dir.path(), "b", &["mail.example.net"]);
        let (c2, k2, d2) = write_pair(dir.path(), "c", &["*.example.com"]);
        let store = CertStore::load(&tls_config(&[(&c0, &k0), (&c1, &k1), (&c2, &k2)])).unwrap();
        assert_eq!(served_der(&store, None), Some(d0.clone()));
        assert_eq!(
            served_der(&store, Some("mail.example.net")),
            Some(d1.clone())
        );
        assert_eq!(served_der(&store, Some("x.example.com")), Some(d2.clone()));

        let (_, _, d0_new) = write_pair(dir.path(), "a", &["mail.example.org"]);
        std::fs::write(&c1, "not a certificate").unwrap();
        write_pair(dir.path(), "c", &["192.0.2.1"]);
        let outcome: Vec<(String, bool)> = store
            .reload()
            .into_iter()
            .map(|(c, r)| (c.to_string(), r.is_ok()))
            .collect();
        assert_eq!(outcome, [(c0, true), (c1, false), (c2, false)]);
        assert_eq!(served_der(&store, None), Some(d0_new));
        assert_eq!(served_der(&store, Some("mail.example.net")), Some(d1));
        assert_eq!(served_der(&store, Some("x.example.com")), Some(d2));
        assert_eq!(served_der(&store, Some("other.example")), None);
    }

    #[test]
    fn reads_not_after() {
        // UTCTime before 2050 (including a leap day), GeneralizedTime from 2050.
        assert_eq!(not_after(&cert_until(2028, 2, 29)), Some(1_835_395_200));
        assert_eq!(not_after(&cert_until(2049, 12, 31)), Some(2_524_521_600));
        assert_eq!(not_after(&cert_until(2051, 3, 1)), Some(2_561_241_600));
    }

    /// The time fields are range-checked: hour ≤ 23, minute ≤ 59, second ≤ 60
    /// (a leap second), and the day within its month.
    #[test]
    fn not_after_rejects_impossible_times() {
        let der = cert_until(2030, 1, 1);
        let at = der
            .windows(13)
            .position(|w| w == b"300101000000Z")
            .expect("UTCTime notAfter");
        let with = |time: &[u8; 13]| {
            let mut d = der.clone();
            d[at..at + 13].copy_from_slice(time);
            not_after(&d)
        };
        assert_eq!(with(b"300101000000Z"), Some(1_893_456_000));
        assert_eq!(with(b"300101235960Z"), Some(1_893_456_000 + 86_400));
        assert_eq!(with(b"280229000000Z"), Some(1_835_395_200));
        assert_eq!(
            with(b"000229000000Z"),
            Some(951_782_400),
            "2000 is a leap year"
        );
        for bad in [
            b"300101240000Z",
            b"300101006000Z",
            b"300101000061Z",
            b"300101999999Z",
            b"300231000000Z",
            b"290229000000Z",
            b"300431000000Z",
            b"301131000000Z",
        ] {
            assert_eq!(with(bad), None, "{}", String::from_utf8_lossy(bad));
        }
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
