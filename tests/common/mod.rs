//! Black-box harness: runs the real `mail-auth-proxy` binary against scripted
//! mock backends (Dovecot IMAP, Postfix submission, Pigeonhole ManageSieve)
//! and a local JWKS, and drives it with real TLS clients.
//!
//! Everything a test needs is started per test on port 0 (loopback only), so
//! tests run in parallel without sharing state:
//!
//! - `Pki`: an rcgen CA, the proxy certificate (mail.internal.test,
//!   mail.public.test and the listener IPs) and the backend certificate
//!   (backend.test), written to a temp dir.
//! - `Idp`: a P-256 key served as JWKS over plain http on 127.0.0.1 and a
//!   token minter with Keycloak-like defaults.
//! - `MockBackend`: records what each backend connection carried (PROXY v2
//!   header, XCLIENT, mechanism, decoded login and secret, relayed lines). The
//!   verdict is chosen by the login: `reject…` → rejected, `slowreject…` →
//!   rejected after `SLOW_REJECT`, `stall…` → accepted after `STALL`,
//!   `unavail…` → temporary failure, `garbled…` → SMTP `501` / IMAP `BAD`, anything else →
//!   accepted, then every line is echoed as `ECHO <line>` until the line
//!   `BACKEND-CLOSE`, on which the backend drops the connection. A rejected XOAUTH2
//!   login first gets an error challenge (IMAP `+ <json>`, SMTP `334 <json>`)
//!   that must be answered with an empty line.
//! - `MockDoveadm`: the doveadm HTTP API `user` command (exists / EX_NOUSER
//!   / EX_TEMPFAIL by login prefix), over http or https, for the legacy
//!   gate's account check.
//! - `Proxy`: writes a v2 config, starts the binary, captures its stderr and
//!   finds its listeners in /proc (the config asks for port 0). On drop it is
//!   killed, and every `authresult` line it wrote must match the CrowdSec grok
//!   pattern. `HARNESS_LOGS=1 cargo test -- --nocapture` prints its stderr.
//! - `Client`: TCP from 127.0.0.1 (internal) or 127.0.0.2 (external), TLS
//!   trusting the test CA with SNI mail.internal.test, mail.public.test or
//!   none (connect by IP).
#![allow(dead_code)] // each test binary uses its own subset

use base64::Engine as _;
use std::collections::{HashMap, HashSet};
use std::io::BufRead as _;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::task::JoinHandle;

pub const INTERNAL_SNI: &str = "mail.internal.test";
pub const PUBLIC_SNI: &str = "mail.public.test";
pub const BACKEND_NAME: &str = "backend.test";
/// `server.hostname`: appears in greetings and EHLO replies.
pub const HOSTNAME: &str = "proxy.test";
pub const ISSUER: &str = "https://idp.test/realms/mail";
pub const AUDIENCE: &str = "dovecot";
pub const KID: &str = "harness-key";
/// Default mailbox in minted tokens.
pub const EMAIL: &str = "alice@example.test";

/// Listener addresses of the proxy (port 0 each). Distinct IPs because the
/// config refuses the same listen address twice and so /proc tells them apart.
pub const IMAP_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 10);
pub const SMTP_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 11);
pub const SIEVE_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 12);
pub const METRICS_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);

/// `notAfter` of `Pki::renewed_cert` (2049-12-31T00:00:00Z), Unix seconds.
pub const RENEWED_NOT_AFTER: u64 = 2_524_521_600;
/// `notAfter` of `Pki::proxy_cert`: rcgen's default, 4096-01-01T00:00:00Z.
pub const PROXY_NOT_AFTER: u64 = 67_090_118_400;

/// Longest wait for any single expected event on the wire or in the log.
pub const IO_TIMEOUT: Duration = Duration::from_secs(10);

// ── Encoding helpers ────────────────────────────────────────────────────────

pub fn b64(data: impl AsRef<[u8]>) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

pub fn unb64(s: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .unwrap_or_else(|e| panic!("bad base64 {s:?}: {e}"))
}

fn b64url(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

/// SASL XOAUTH2 initial response (base64).
pub fn xoauth2(user: &str, token: &str) -> String {
    b64(format!("user={user}\x01auth=Bearer {token}\x01\x01"))
}

/// SASL OAUTHBEARER initial response (base64), GS2 authzid `a=<user>`, or
/// none (`n,,`, RFC 5801 §4) for an empty `user`. No `host` (optional, RFC
/// 7628 §3.1): the proxy checks it against the SNI, which the caller picks.
pub fn oauthbearer(user: &str, token: &str) -> String {
    let authzid = if user.is_empty() {
        String::new()
    } else {
        format!("a={user}")
    };
    b64(format!(
        "n,{authzid},\x01port=993\x01auth=Bearer {token}\x01\x01"
    ))
}

/// SASL PLAIN initial response (base64) with an empty authzid.
pub fn plain(user: &str, pass: &str) -> String {
    b64(format!("\0{user}\0{pass}"))
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

// ── PKI ─────────────────────────────────────────────────────────────────────

/// Test CA plus proxy and backend certificates, as files and as rustls configs.
pub struct Pki {
    pub dir: tempfile::TempDir,
    pub ca_file: PathBuf,
    pub proxy_cert: PathBuf,
    pub proxy_key: PathBuf,
    /// A second proxy certificate from the same CA (same names), as files
    /// and DER, for certificate reload tests. It expires at
    /// `RENEWED_NOT_AFTER`, the first one at rcgen's default (4096-01-01).
    pub renewed_cert: PathBuf,
    pub renewed_key: PathBuf,
    pub renewed_der: Vec<u8>,
    /// Client config trusting only the test CA.
    pub client: Arc<rustls::ClientConfig>,
    /// Server config the mock backends present (backend.test).
    pub backend: Arc<rustls::ServerConfig>,
    /// Server config with the proxy's certificate (valid for 127.0.0.1), for
    /// a mock doveadm over https.
    pub proxy_server: Arc<rustls::ServerConfig>,
}

impl Pki {
    pub fn new() -> Pki {
        use rcgen::{
            BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose,
            IsCa, KeyPair, KeyUsagePurpose,
        };
        let dir = tempfile::tempdir().unwrap();

        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "harness test CA");
        ca_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate().unwrap()).unwrap();

        let leaf = |names: Vec<String>| {
            let key = KeyPair::generate().unwrap();
            let mut p = CertificateParams::new(names).unwrap();
            p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
            let cert = p.signed_by(&key, &ca).unwrap();
            (cert, key)
        };
        let (proxy_cert, proxy_key) = leaf(vec![
            INTERNAL_SNI.into(),
            PUBLIC_SNI.into(),
            "127.0.0.1".into(),
            IMAP_IP.to_string(),
            SMTP_IP.to_string(),
            SIEVE_IP.to_string(),
        ]);
        let (renewed_cert, renewed_key) = {
            let key = KeyPair::generate().unwrap();
            let mut p = CertificateParams::new(vec![
                INTERNAL_SNI.to_string(),
                PUBLIC_SNI.into(),
                "127.0.0.1".into(),
                IMAP_IP.to_string(),
                SMTP_IP.to_string(),
                SIEVE_IP.to_string(),
            ])
            .unwrap();
            p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
            p.not_after = rcgen::date_time_ymd(2049, 12, 31); // RENEWED_NOT_AFTER
            (p.signed_by(&key, &ca).unwrap(), key)
        };
        let (backend_cert, backend_key) = leaf(vec![BACKEND_NAME.into()]);

        let write = |name: &str, body: &str| {
            let p = dir.path().join(name);
            std::fs::write(&p, body).unwrap();
            p
        };
        let ca_file = write("ca.pem", &ca.pem());
        // The chain the proxy serves: leaf only (the client trusts the CA).
        let proxy_cert_file = write("proxy.pem", &proxy_cert.pem());
        let proxy_key_file = write("proxy.key", &proxy_key.serialize_pem());
        let renewed_cert_file = write("renewed.pem", &renewed_cert.pem());
        let renewed_key_file = write("renewed.key", &renewed_key.serialize_pem());

        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca.der().clone()).unwrap();
        let client = rustls::ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();

        let backend = rustls::ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![backend_cert.der().clone()],
                rustls::pki_types::PrivateKeyDer::Pkcs8(backend_key.serialize_der().into()),
            )
            .unwrap();

        let proxy_server = rustls::ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![proxy_cert.der().clone()],
                rustls::pki_types::PrivateKeyDer::Pkcs8(proxy_key.serialize_der().into()),
            )
            .unwrap();

        Pki {
            dir,
            ca_file,
            proxy_cert: proxy_cert_file,
            proxy_key: proxy_key_file,
            renewed_cert: renewed_cert_file,
            renewed_key: renewed_key_file,
            renewed_der: renewed_cert.der().to_vec(),
            client: Arc::new(client),
            backend: Arc::new(backend),
            proxy_server: Arc::new(proxy_server),
        }
    }
}

// ── IdP: JWKS over http and token minting ───────────────────────────────────

pub struct Idp {
    pkcs8: Vec<u8>,
    jwks: String,
    pub addr: SocketAddr,
    /// JWKS requests served (startup fetch, refreshes).
    pub fetches: Arc<AtomicUsize>,
    /// Milliseconds the JWKS endpoint waits before answering (a slow IdP).
    pub delay_ms: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl Idp {
    pub async fn start() -> Idp {
        use aws_lc_rs::signature::{EcdsaKeyPair, KeyPair as _, ECDSA_P256_SHA256_FIXED_SIGNING};
        let rng = aws_lc_rs::rand::SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let key =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref()).unwrap();
        // Uncompressed point 0x04 || X || Y, 32 bytes per coordinate.
        let point = key.public_key().as_ref();
        assert_eq!((point.len(), point[0]), (65, 0x04));
        let jwks = serde_json::json!({"keys": [{
            "kty": "EC", "crv": "P-256", "use": "sig", "alg": "ES256", "kid": KID,
            "x": b64url(&point[1..33]), "y": b64url(&point[33..65]),
        }]})
        .to_string();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let fetches = Arc::new(AtomicUsize::new(0));
        let delay_ms = Arc::new(AtomicUsize::new(0));
        let body = jwks.clone();
        let count = fetches.clone();
        let delay = delay_ms.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = listener.accept().await else {
                    continue;
                };
                let body = body.clone();
                let count = count.clone();
                let delay = delay.clone();
                tokio::spawn(async move {
                    // Read the request head; any path gets the JWKS.
                    let mut head = Vec::new();
                    let mut buf = [0u8; 1024];
                    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                        match s.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => head.extend_from_slice(&buf[..n]),
                        }
                    }
                    count.fetch_add(1, Ordering::SeqCst);
                    let wait = delay.load(Ordering::SeqCst) as u64;
                    tokio::time::sleep(Duration::from_millis(wait)).await;
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = s.write_all(resp.as_bytes()).await;
                    let _ = s.shutdown().await;
                });
            }
        });
        Idp {
            pkcs8: pkcs8.as_ref().to_vec(),
            jwks,
            addr,
            fetches,
            delay_ms,
            task,
        }
    }

    pub fn jwks_url(&self) -> String {
        format!(
            "http://{}/realms/mail/protocol/openid-connect/certs",
            self.addr
        )
    }

    /// A valid Keycloak-style access token for `email`.
    pub fn token(&self, email: &str) -> String {
        self.mint(serde_json::json!({ "email": email }))
    }

    /// Mint a token: defaults (iss, aud, exp in 10 min, typ=Bearer, email,
    /// email_verified=true, azp) merged with `overrides`; a `null` override
    /// removes the claim.
    pub fn mint(&self, overrides: serde_json::Value) -> String {
        self.mint_with_kid(KID, overrides)
    }

    pub fn mint_with_kid(&self, kid: &str, overrides: serde_json::Value) -> String {
        let t = now();
        let mut claims = serde_json::json!({
            "iss": ISSUER, "aud": AUDIENCE, "exp": t + 600, "iat": t,
            "typ": "Bearer", "email": EMAIL, "email_verified": true, "azp": "harness",
        });
        let obj = claims.as_object_mut().unwrap();
        for (k, v) in overrides.as_object().expect("overrides must be an object") {
            if v.is_null() {
                obj.remove(k);
            } else {
                obj.insert(k.clone(), v.clone());
            }
        }
        let mut h = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
        h.kid = Some(kid.into());
        jsonwebtoken::encode(
            &h,
            &claims,
            &jsonwebtoken::EncodingKey::from_ec_der(&self.pkcs8),
        )
        .unwrap()
    }
}

impl Idp {
    /// Take the JWKS endpoint down: its port refuses connections from now on.
    pub async fn stop(&self) {
        self.task.abort();
        while !self.task.is_finished() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

impl Drop for Idp {
    fn drop(&mut self) {
        self.task.abort();
    }
}

// ── Line I/O shared by mocks and clients ────────────────────────────────────

/// One line without CR/LF, read byte by byte so nothing past `\n` is
/// consumed (bytes after STARTTLS must stay in the socket). `None` on EOF or
/// error.
async fn read_line_raw<S: AsyncRead + Unpin>(s: &mut S) -> Option<String> {
    let mut line = Vec::new();
    let mut b = [0u8; 1];
    loop {
        match s.read(&mut b).await {
            Ok(0) | Err(_) => return None,
            Ok(_) => {}
        }
        match b[0] {
            b'\n' => return Some(String::from_utf8_lossy(&line).into_owned()),
            b'\r' => {}
            c => line.push(c),
        }
    }
}

// ── Mock backends ───────────────────────────────────────────────────────────

/// A PROXY protocol v2 header as the backend received it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProxyHeader {
    /// Command LOCAL (the proxy's own connection) rather than PROXY.
    pub local: bool,
    pub src: Option<SocketAddr>,
    pub dst: Option<SocketAddr>,
}

/// What one backend connection carried.
#[derive(Clone, Debug, Default)]
pub struct Seen {
    pub proxy_header: Option<ProxyHeader>,
    /// The SMTP XCLIENT line, verbatim.
    pub xclient: Option<String>,
    /// SASL mechanism the proxy used towards the backend.
    pub mech: Option<String>,
    /// Decoded login: XOAUTH2 `user=` or the PLAIN authcid.
    pub login: Option<String>,
    /// PLAIN authzid (must stay empty).
    pub authzid: Option<String>,
    /// The bearer token or the password.
    pub secret: Option<String>,
    /// What the proxy answered to an XOAUTH2 error challenge (empty line
    /// expected).
    pub error_answer: Option<String>,
    /// Lines received after a successful login.
    pub relayed: Vec<String>,
    /// A ManageSieve capability probe (LOGOUT without AUTHENTICATE).
    pub probe: bool,
}

impl Seen {
    /// A connection that was a client's session, not the proxy's own probe.
    pub fn is_session(&self) -> bool {
        !self.proxy_header.as_ref().is_some_and(|h| h.local) && !self.probe
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Imap,
    Smtp,
    Sieve,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Verdict {
    Ok,
    Reject,
    Unavailable,
}

/// How long the mock takes before rejecting a `slowreject…` login, like a
/// backend with an auth failure delay.
pub const SLOW_REJECT: Duration = Duration::from_millis(800);

/// How long the mock hangs before answering a `stall…` login.
pub const STALL: Duration = Duration::from_secs(30);

/// The verdict, after the backend's thinking time.
async fn verdict_after(login: &str) -> Verdict {
    if login.starts_with("slowreject") {
        tokio::time::sleep(SLOW_REJECT).await;
    }
    if login.starts_with("stall") {
        // A backend that hangs after the credential.
        tokio::time::sleep(STALL).await;
    }
    verdict(login)
}

fn verdict(login: &str) -> Verdict {
    if login.starts_with("reject") || login.starts_with("slowreject") {
        Verdict::Reject
    } else if login.starts_with("unavail") {
        Verdict::Unavailable
    } else {
        Verdict::Ok
    }
}

type Log = Arc<Mutex<Vec<Seen>>>;

pub struct MockBackend {
    pub kind: Kind,
    pub addr: SocketAddr,
    seen: Log,
    accept: Mutex<Option<JoinHandle<()>>>,
    /// If set, the mocks answer the auth command itself (`AUTHENTICATE …`,
    /// the bare `AUTH <mech>`) with this line and close, whatever the
    /// credential: `* BYE` for a connection limit, `504` for an unknown
    /// mechanism.
    pub auth_reply: Arc<Mutex<Option<String>>>,
    /// If set, the SMTP mock keeps advertising XCLIENT after an XCLIENT
    /// command, as Postfix does when the announced ADDR is itself in
    /// `smtpd_authorized_xclient_hosts`. Otherwise it stops, as Postfix does
    /// for an ordinary client address.
    pub xclient_sticky: Arc<AtomicBool>,
    /// IMAP: the capability list after login, instead of `IMAP4rev1 IDLE
    /// MOVE`. ManageSieve: one more post-TLS capability line.
    pub login_caps: Arc<Mutex<Option<String>>>,
    /// IMAP: the tagged OK of a login carries no CAPABILITY code; the list
    /// comes as the answer to `P2 CAPABILITY`.
    pub caps_untagged: Arc<AtomicBool>,
    /// IMAP: the greeting does not advertise SASL-IR, and an AUTHENTICATE
    /// with an initial response gets BAD (RFC 4959 §3).
    pub no_sasl_ir: Arc<AtomicBool>,
}

impl MockBackend {
    pub async fn start(kind: Kind, tls: Arc<rustls::ServerConfig>) -> MockBackend {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen: Log = Arc::default();
        let log = seen.clone();
        let auth_reply: Arc<Mutex<Option<String>>> = Arc::default();
        let quirk = auth_reply.clone();
        let xclient_sticky: Arc<AtomicBool> = Arc::default();
        let sticky = xclient_sticky.clone();
        let login_caps: Arc<Mutex<Option<String>>> = Arc::default();
        let caps = login_caps.clone();
        let caps_untagged: Arc<AtomicBool> = Arc::default();
        let untagged = caps_untagged.clone();
        let no_sasl_ir: Arc<AtomicBool> = Arc::default();
        let no_ir = no_sasl_ir.clone();
        let acceptor = tokio_rustls::TlsAcceptor::from(tls);
        let accept = tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    continue;
                };
                let idx = {
                    let mut l = log.lock().unwrap();
                    l.push(Seen::default());
                    l.len() - 1
                };
                let rec = Rec {
                    log: log.clone(),
                    idx,
                    auth_reply: quirk.lock().unwrap().clone(),
                    xclient_sticky: sticky.load(Ordering::SeqCst),
                    login_caps: caps.lock().unwrap().clone(),
                    caps_untagged: untagged.load(Ordering::SeqCst),
                    no_sasl_ir: no_ir.load(Ordering::SeqCst),
                };
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let _ = match kind {
                        Kind::Imap => mock_imap(tcp, acceptor, rec).await,
                        Kind::Smtp => mock_smtp(tcp, acceptor, rec).await,
                        Kind::Sieve => mock_sieve(tcp, acceptor, rec).await,
                    };
                });
            }
        });
        MockBackend {
            kind,
            addr,
            seen,
            accept: Mutex::new(Some(accept)),
            auth_reply,
            xclient_sticky,
            login_caps,
            caps_untagged,
            no_sasl_ir,
        }
    }

    /// Every connection so far, in accept order.
    pub fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }

    /// Client sessions only (without ManageSieve capability probes).
    pub fn sessions(&self) -> Vec<Seen> {
        self.seen().into_iter().filter(Seen::is_session).collect()
    }

    /// Stop listening: from now on the port is closed (connection refused).
    pub async fn shutdown(&self) {
        let task = self.accept.lock().unwrap().take();
        if let Some(t) = task {
            t.abort();
            let _ = t.await;
        }
    }
}

impl Drop for MockBackend {
    fn drop(&mut self) {
        if let Some(t) = self.accept.lock().unwrap().take() {
            t.abort();
        }
    }
}

/// Handle to this connection's record.
struct Rec {
    log: Log,
    idx: usize,
    /// `MockBackend::auth_reply` when the connection was accepted.
    auth_reply: Option<String>,
    /// `MockBackend::xclient_sticky` when the connection was accepted.
    xclient_sticky: bool,
    /// `MockBackend::login_caps` when the connection was accepted.
    login_caps: Option<String>,
    /// `MockBackend::caps_untagged` when the connection was accepted.
    caps_untagged: bool,
    /// `MockBackend::no_sasl_ir` when the connection was accepted.
    no_sasl_ir: bool,
}

impl Rec {
    fn update(&self, f: impl FnOnce(&mut Seen)) {
        f(&mut self.log.lock().unwrap()[self.idx]);
    }
}

const PP2_SIG: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];

/// Consume a PROXY v2 header if the connection starts with one. Waits up to
/// `wait` for the first 16 bytes; a connection that stays silent that long
/// (server-speaks-first protocols without a header) has none.
async fn read_proxy_header(tcp: &mut TcpStream, wait: Duration) -> Option<ProxyHeader> {
    let until = Instant::now() + wait;
    let mut buf = [0u8; 16];
    loop {
        let n = tokio::time::timeout(Duration::from_millis(50), tcp.peek(&mut buf))
            .await
            .unwrap_or(Ok(0))
            .unwrap_or(0);
        if n >= 12 && buf[..12] != PP2_SIG {
            return None;
        }
        if n == 16 {
            break;
        }
        if Instant::now() > until {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    tcp.read_exact(&mut buf).await.ok()?;
    let len = u16::from_be_bytes([buf[14], buf[15]]) as usize;
    let mut body = vec![0u8; len];
    tcp.read_exact(&mut body).await.ok()?;
    let local = buf[12] == 0x20;
    let (src, dst) = if !local && buf[13] == 0x11 && len >= 12 {
        let ip = |b: &[u8]| IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3]));
        let port = |b: &[u8]| u16::from_be_bytes([b[0], b[1]]);
        (
            Some(SocketAddr::new(ip(&body[0..4]), port(&body[8..10]))),
            Some(SocketAddr::new(ip(&body[4..8]), port(&body[10..12]))),
        )
    } else {
        (None, None)
    };
    Some(ProxyHeader { local, src, dst })
}

/// Decode the SASL initial response the proxy sent to a backend.
fn decode_ir(rec: &Rec, mech: &str, ir: &str) -> String {
    let raw = String::from_utf8(unb64(ir)).unwrap();
    let (authzid, login, secret) = if mech.eq_ignore_ascii_case("PLAIN") {
        let mut it = raw.splitn(3, '\0');
        let authzid = it.next().unwrap_or("").to_string();
        let login = it.next().unwrap_or("").to_string();
        let pass = it.next().unwrap_or("").to_string();
        (Some(authzid), login, pass)
    } else {
        let field = |p: &str| {
            raw.split('\x01')
                .find_map(|f| f.strip_prefix(p))
                .unwrap_or("")
                .to_string()
        };
        (None, field("user="), field("auth=Bearer "))
    };
    rec.update(|s| {
        s.mech = Some(mech.to_string());
        s.login = Some(login.clone());
        s.authzid = authzid;
        s.secret = Some(secret);
    });
    login
}

/// After a successful login: record and echo every line as `ECHO <line>`;
/// `BACKEND-CLOSE` drops the connection (no TLS close_notify), as a backend
/// that ends the session.
async fn echo<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S, rec: &Rec) {
    while let Some(l) = read_line_raw(s).await {
        rec.update(|r| r.relayed.push(l.clone()));
        if l == "BACKEND-CLOSE" {
            return;
        }
        if s.write_all(format!("ECHO {l}\r\n").as_bytes())
            .await
            .is_err()
        {
            return;
        }
    }
}

/// Dovecot IMAP on an implicit-TLS port with `haproxy = yes`.
async fn mock_imap(
    mut tcp: TcpStream,
    acceptor: tokio_rustls::TlsAcceptor,
    rec: Rec,
) -> std::io::Result<()> {
    // The proxy speaks first (PROXY header or ClientHello).
    let hdr = read_proxy_header(&mut tcp, IO_TIMEOUT).await;
    rec.update(|s| s.proxy_header = hdr);
    let mut s = acceptor.accept(tcp).await?;
    let sasl_ir = if rec.no_sasl_ir { "" } else { " SASL-IR" };
    s.write_all(
        format!(
            "* OK [CAPABILITY IMAP4rev1{sasl_ir} AUTH=PLAIN AUTH=XOAUTH2] mock dovecot ready\r\n"
        )
        .as_bytes(),
    )
    .await?;
    let Some(line) = read_line_raw(&mut s).await else {
        return Ok(());
    };
    let mut w = line.splitn(4, ' ');
    let (tag, cmd, mech, ir) = (
        w.next().unwrap_or(""),
        w.next().unwrap_or(""),
        w.next().unwrap_or(""),
        w.next().unwrap_or(""),
    );
    assert!(
        cmd.eq_ignore_ascii_case("AUTHENTICATE"),
        "mock imap: {line}"
    );
    let ir = if ir.is_empty() {
        // The response after the empty challenge.
        s.write_all(b"+ \r\n").await?;
        read_line_raw(&mut s).await.unwrap_or_default()
    } else if rec.no_sasl_ir {
        s.write_all(format!("{tag} BAD SASL-IR not advertised\r\n").as_bytes())
            .await?;
        return Ok(());
    } else {
        ir.to_string()
    };
    let login = decode_ir(&rec, mech, &ir);
    if let Some(reply) = &rec.auth_reply {
        s.write_all(format!("{reply}\r\n").as_bytes()).await?;
        return Ok(());
    }
    if login.starts_with("garbled") {
        // The backend could not parse the exchange.
        s.write_all(format!("{tag} BAD Invalid characters in input.\r\n").as_bytes())
            .await?;
        return Ok(());
    }
    let v = verdict_after(&login).await;
    if v == Verdict::Reject && mech.eq_ignore_ascii_case("XOAUTH2") {
        // Dovecot's XOAUTH2 failure: an error challenge first. An empty line
        // gets the tagged NO; `*` aborts the exchange with BAD.
        let json = r#"{"status":"401","schemes":"bearer","scope":"mail"}"#;
        s.write_all(format!("+ {}\r\n", b64(json)).as_bytes())
            .await?;
        let answer = read_line_raw(&mut s).await.unwrap_or_default();
        rec.update(|r| r.error_answer = Some(answer.clone()));
        if !answer.is_empty() {
            s.write_all(format!("{tag} BAD Authentication aborted by client.\r\n").as_bytes())
                .await?;
            return Ok(());
        }
    }
    let caps = rec.login_caps.as_deref().unwrap_or("IMAP4rev1 IDLE MOVE");
    let reply = match v {
        Verdict::Ok if rec.caps_untagged => format!("{tag} OK Logged in"),
        Verdict::Ok => format!("{tag} OK [CAPABILITY {caps}] Logged in"),
        Verdict::Reject => format!("{tag} NO [AUTHENTICATIONFAILED] Authentication failed."),
        Verdict::Unavailable => {
            format!("{tag} NO [UNAVAILABLE] Temporary authentication failure.")
        }
    };
    s.write_all(format!("{reply}\r\n").as_bytes()).await?;
    if verdict(&login) != Verdict::Ok {
        return Ok(());
    }
    if rec.caps_untagged {
        let Some(l) = read_line_raw(&mut s).await else {
            return Ok(());
        };
        rec.update(|r| r.relayed.push(l.clone()));
        if l == "P2 CAPABILITY" {
            s.write_all(
                format!("* CAPABILITY {caps}\r\nP2 OK Capability completed.\r\n").as_bytes(),
            )
            .await?;
        } else {
            s.write_all(format!("ECHO {l}\r\n").as_bytes()).await?;
        }
    }
    echo(&mut s, &rec).await;
    Ok(())
}

/// Postfix's default `line_length_limit`: a longer command line gets `500`.
pub const SMTP_LINE_LIMIT: usize = 2048;
/// Postfix's default `smtpd_sasl_response_limit`: a longer SASL response gets
/// `500`.
pub const SMTP_SASL_RESPONSE_LIMIT: usize = 12288;

/// Postfix submission: STARTTLS, XCLIENT for the proxy, SASL. Command lines
/// are limited to `SMTP_LINE_LIMIT` octets including CRLF; SASL responses
/// after `334` are not.
async fn mock_smtp(
    mut tcp: TcpStream,
    acceptor: tokio_rustls::TlsAcceptor,
    rec: Rec,
) -> std::io::Result<()> {
    tcp.write_all(b"220 backend.test ESMTP mock\r\n").await?;
    let Some(l) = read_line_raw(&mut tcp).await else {
        return Ok(());
    };
    assert!(l.starts_with("EHLO "), "mock smtp: {l}");
    tcp.write_all(b"250-backend.test\r\n250-PIPELINING\r\n250 STARTTLS\r\n")
        .await?;
    let Some(l) = read_line_raw(&mut tcp).await else {
        return Ok(());
    };
    assert_eq!(l, "STARTTLS", "mock smtp");
    tcp.write_all(b"220 2.0.0 Ready to start TLS\r\n").await?;
    let mut s = acceptor.accept(tcp).await?;
    const EHLO: &[u8] =
        b"250-backend.test\r\n250-XCLIENT NAME ADDR PROTO HELO LOGIN\r\n250 AUTH PLAIN LOGIN XOAUTH2\r\n";
    // After XCLIENT the session is the client's: XCLIENT only if its
    // address is authorized too.
    const EHLO_CLIENT: &[u8] = b"250-backend.test\r\n250 AUTH PLAIN LOGIN XOAUTH2\r\n";
    let mut after_xclient = false;
    while let Some(l) = read_line_raw(&mut s).await {
        if l.len() + 2 > SMTP_LINE_LIMIT {
            s.write_all(b"500 5.5.2 Error: command too long\r\n")
                .await?;
            continue;
        }
        let mut w = l.splitn(3, ' ');
        let verb = w.next().unwrap_or("").to_ascii_uppercase();
        match verb.as_str() {
            "EHLO" if after_xclient && !rec.xclient_sticky => s.write_all(EHLO_CLIENT).await?,
            "EHLO" => s.write_all(EHLO).await?,
            "XCLIENT" => {
                rec.update(|r| r.xclient = Some(l.clone()));
                after_xclient = true;
                s.write_all(b"220 backend.test ESMTP mock\r\n").await?;
            }
            "AUTH" => {
                let mech = w.next().unwrap_or("").to_string();
                let mut ir = w.next().unwrap_or("").to_string();
                if let Some(reply) = &rec.auth_reply {
                    s.write_all(format!("{reply}\r\n").as_bytes()).await?;
                    return Ok(());
                }
                if ir.is_empty() {
                    // No initial response: the empty challenge, then the
                    // response on its own line (up to 12288 octets in Postfix).
                    s.write_all(b"334 \r\n").await?;
                    let Some(r) = read_line_raw(&mut s).await else {
                        return Ok(());
                    };
                    if r == "*" {
                        s.write_all(b"501 5.7.0 Authentication aborted\r\n").await?;
                        return Ok(());
                    }
                    if r.len() > SMTP_SASL_RESPONSE_LIMIT {
                        s.write_all(b"500 5.5.6 SASL response too long\r\n").await?;
                        return Ok(());
                    }
                    ir = r;
                }
                let login = decode_ir(&rec, &mech, &ir);
                if login.starts_with("garbled") {
                    // The backend could not parse the exchange: no verdict.
                    s.write_all(b"501 5.5.2 Syntax error in the response\r\n")
                        .await?;
                    return Ok(());
                }
                let v = verdict_after(&login).await;
                if v == Verdict::Reject && mech.eq_ignore_ascii_case("XOAUTH2") {
                    // Dovecot's XOAUTH2 failure through Postfix: an error
                    // challenge the client must answer with an empty line.
                    let json = r#"{"status":"401","schemes":"bearer","scope":"mail"}"#;
                    s.write_all(format!("334 {}\r\n", b64(json)).as_bytes())
                        .await?;
                    let answer = read_line_raw(&mut s).await.unwrap_or_default();
                    rec.update(|r| r.error_answer = Some(answer.clone()));
                    if !answer.is_empty() {
                        s.write_all(b"501 5.7.0 Authentication aborted\r\n").await?;
                        return Ok(());
                    }
                }
                let reply: &[u8] = match v {
                    Verdict::Ok => b"235 2.7.0 Authentication successful\r\n",
                    Verdict::Reject => b"535 5.7.8 Error: authentication failed\r\n",
                    Verdict::Unavailable => b"454 4.7.0 Temporary authentication failure\r\n",
                };
                s.write_all(reply).await?;
                if v == Verdict::Ok {
                    echo(&mut s, &rec).await;
                }
                return Ok(());
            }
            _ => {
                s.write_all(b"502 5.5.2 mock: unexpected command\r\n")
                    .await?
            }
        }
    }
    Ok(())
}

/// Pigeonhole ManageSieve with `haproxy = yes`: STARTTLS, then SASL.
async fn mock_sieve(
    mut tcp: TcpStream,
    acceptor: tokio_rustls::TlsAcceptor,
    rec: Rec,
) -> std::io::Result<()> {
    let hdr = read_proxy_header(&mut tcp, Duration::from_secs(1)).await;
    rec.update(|s| s.proxy_header = hdr);
    tcp.write_all(
        b"\"IMPLEMENTATION\" \"Pigeonhole mock\"\r\n\"SASL\" \"PLAIN XOAUTH2 OAUTHBEARER\"\r\n\"STARTTLS\"\r\n\"VERSION\" \"1.0\"\r\nOK \"mock ready\"\r\n",
    )
    .await?;
    let Some(l) = read_line_raw(&mut tcp).await else {
        return Ok(());
    };
    assert_eq!(l, "STARTTLS", "mock sieve");
    tcp.write_all(b"OK \"Begin TLS negotiation now.\"\r\n")
        .await?;
    let mut s = acceptor.accept(tcp).await?;
    let extra = rec
        .login_caps
        .as_ref()
        .map(|l| format!("{l}\r\n"))
        .unwrap_or_default();
    s.write_all(
        format!("\"IMPLEMENTATION\" \"Pigeonhole mock\"\r\n\"SIEVE\" \"fileinto reject envelope\"\r\n\"NOTIFY\" \"mailto\"\r\n\"SASL\" \"PLAIN XOAUTH2 OAUTHBEARER\"\r\n{extra}\"VERSION\" \"1.0\"\r\nOK \"TLS negotiation successful.\"\r\n").as_bytes(),
    )
    .await?;
    let Some(l) = read_line_raw(&mut s).await else {
        return Ok(());
    };
    if l.eq_ignore_ascii_case("LOGOUT") {
        rec.update(|r| r.probe = true);
        s.write_all(b"OK \"Logout completed.\"\r\n").await?;
        return Ok(());
    }
    // AUTHENTICATE "MECH" "IR" or AUTHENTICATE "MECH" {n+} CRLF IR. Strict
    // like RFC 5804 §4: a quoted string holds at most 1024 octets.
    let q: Vec<&str> = l.splitn(3, '"').collect();
    assert!(
        q.len() == 3 && q[0].trim().eq_ignore_ascii_case("AUTHENTICATE"),
        "mock sieve: {l}"
    );
    let (mech, arg) = (q[1], q[2].trim());
    let ir = if let Some(n) = arg.strip_prefix('{').and_then(|a| a.strip_suffix("+}")) {
        let mut buf = vec![0u8; n.parse().unwrap()];
        s.read_exact(&mut buf).await?;
        assert_eq!(
            read_line_raw(&mut s).await.as_deref(),
            Some(""),
            "mock sieve"
        );
        String::from_utf8(buf).unwrap()
    } else {
        let ir = arg
            .strip_prefix('"')
            .and_then(|a| a.strip_suffix('"'))
            .unwrap_or_else(|| panic!("mock sieve: {l}"));
        if ir.len() > 1024 {
            s.write_all(b"NO \"Quoted string too long\"\r\n").await?;
            return Ok(());
        }
        ir.to_string()
    };
    let login = decode_ir(&rec, mech, &ir);
    if let Some(reply) = &rec.auth_reply {
        s.write_all(format!("{reply}\r\n").as_bytes()).await?;
        return Ok(());
    }
    let v = verdict_after(&login).await;
    let reply: &[u8] = match v {
        Verdict::Ok => b"OK \"Logged in.\"\r\n",
        Verdict::Reject => b"NO \"Authentication failed.\"\r\n",
        Verdict::Unavailable => b"NO (TRYLATER) \"Temporary authentication failure.\"\r\n",
    };
    s.write_all(reply).await?;
    if v == Verdict::Ok {
        echo(&mut s, &rec).await;
    }
    Ok(())
}

// ── Mock doveadm HTTP API ───────────────────────────────────────────────────

/// A Dovecot doveadm HTTP API endpoint (`POST /doveadm/v1`) answering the
/// `user` command as Dovecot 2.4 does: `doveadmResponse` for an existing
/// user, `error` with exitCode 67 (EX_NOUSER) for `missing…` logins, 75
/// (EX_TEMPFAIL) for `tempfail…`. A wrong `X-Dovecot-API` key gets 401.
pub struct MockDoveadm {
    pub addr: SocketAddr,
    pub key: String,
    /// userMask of every authenticated `user` request, in order.
    pub lookups: Arc<Mutex<Vec<String>>>,
    task: Mutex<Option<JoinHandle<()>>>,
}

impl MockDoveadm {
    /// Plain http, or https with `tls` (the proxy certificate, valid for
    /// 127.0.0.1).
    pub async fn start(tls: Option<Arc<rustls::ServerConfig>>) -> MockDoveadm {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let key = "harness-doveadm-key".to_string();
        let lookups: Arc<Mutex<Vec<String>>> = Arc::default();
        let (k, l) = (key.clone(), lookups.clone());
        let acceptor = tls.map(tokio_rustls::TlsAcceptor::from);
        let task = tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    continue;
                };
                let (k, l, acceptor) = (k.clone(), l.clone(), acceptor.clone());
                tokio::spawn(async move {
                    match acceptor {
                        Some(a) => {
                            if let Ok(s) = a.accept(tcp).await {
                                doveadm_request(s, &k, &l).await;
                            }
                        }
                        None => doveadm_request(tcp, &k, &l).await,
                    }
                });
            }
        });
        MockDoveadm {
            addr,
            key,
            lookups,
            task: Mutex::new(Some(task)),
        }
    }

    pub fn url(&self, https: bool) -> String {
        let scheme = if https { "https" } else { "http" };
        format!("{scheme}://{}/doveadm/v1", self.addr)
    }

    pub fn lookups(&self) -> Vec<String> {
        self.lookups.lock().unwrap().clone()
    }

    /// Stop listening: connections are refused from now on.
    pub async fn shutdown(&self) {
        let task = self.task.lock().unwrap().take();
        if let Some(t) = task {
            t.abort();
            let _ = t.await;
        }
    }
}

impl Drop for MockDoveadm {
    fn drop(&mut self) {
        if let Some(t) = self.task.lock().unwrap().take() {
            t.abort();
        }
    }
}

async fn doveadm_request<S: AsyncRead + AsyncWrite + Unpin>(
    mut s: S,
    key: &str,
    lookups: &Mutex<Vec<String>>,
) {
    let mut buf = Vec::new();
    let mut b = [0u8; 4096];
    let head_end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        match s.read(&mut b).await {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&b[..n]),
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let header = |name: &str| {
        head.lines().find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.trim()
                .eq_ignore_ascii_case(name)
                .then(|| v.trim().to_string())
        })
    };
    let len: usize = header("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    while buf.len() < head_end + len {
        match s.read(&mut b).await {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&b[..n]),
        }
    }
    let expected = format!("X-Dovecot-API {}", b64(key));
    let (status, body) = if !head.starts_with("POST /doveadm/v1 ") {
        ("404 Not Found", "unknown path".to_string())
    } else if header("authorization").as_deref() != Some(expected.as_str()) {
        ("401 Unauthorized", "Authentication required".to_string())
    } else {
        let req: serde_json::Value =
            serde_json::from_slice(&buf[head_end..head_end + len]).unwrap_or_default();
        let cmd = &req[0];
        assert_eq!(cmd[0], "user", "doveadm command: {req}");
        assert_eq!(cmd[1]["userdbOnly"], true, "doveadm params: {req}");
        let user = cmd[1]["userMask"].as_str().unwrap_or_default().to_string();
        let tag = cmd[2].clone();
        lookups.lock().unwrap().push(user.clone());
        let answer = if user.starts_with("missing") {
            serde_json::json!([["error", {"type": "exitCode", "exitCode": 67}, tag]])
        } else if user.starts_with("tempfail") {
            serde_json::json!([["error", {"type": "exitCode", "exitCode": 75}, tag]])
        } else {
            serde_json::json!([["doveadmResponse", [{"field": "uid", "value": "1000"}], tag]])
        };
        ("200 OK", answer.to_string())
    };
    let resp = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = s.write_all(resp.as_bytes()).await;
    let _ = s.shutdown().await;
}

// ── The proxy process ───────────────────────────────────────────────────────

/// Knobs a test may change; everything else is the harness default config.
#[derive(Clone, Debug)]
pub struct Opts {
    pub max_preauth_per_ip: usize,
    pub preauth_secs: u64,
    pub idle_secs: u64,
    /// TOML that replaces the default `[password_gate]` section (legacy
    /// rules, `[legacy]`, `[scope]`).
    pub legacy: Option<String>,
    /// Serve `/metrics` (`[metrics] enabled`).
    pub metrics: bool,
    /// `RUST_LOG` of the proxy.
    pub rust_log: &'static str,
    /// `NOTIFY_SOCKET` of the proxy (systemd notification).
    pub notify_socket: Option<PathBuf>,
    /// `submission.xclient` (the mock backend always advertises XCLIENT).
    pub smtp_xclient: bool,
    /// TOML lines added to the harness issuer (`openid_configuration_url`,
    /// `scope`).
    pub issuer_extra: &'static str,
    /// Keys of the `[auth_ratelimit]` section; `None`: the defaults (the
    /// harness sources are loopback, which the defaults exempt).
    pub ratelimit: Option<String>,
    /// The keys of the `[session]` section, if any.
    pub session: Option<String>,
}

impl Default for Opts {
    fn default() -> Self {
        Opts {
            max_preauth_per_ip: 32,
            preauth_secs: 20,
            idle_secs: 10,
            legacy: None,
            metrics: true,
            rust_log: "info",
            notify_socket: None,
            smtp_xclient: true,
            issuer_extra: "",
            ratelimit: None,
            session: None,
        }
    }
}

/// The `[password_gate]` section of the default harness config.
fn default_password_gate() -> String {
    format!(
        "[password_gate]\nenabled = true\nsni = [\"{INTERNAL_SNI}\"]\ninternal_networks = [\"127.0.0.1/32\"]\n"
    )
}

/// One parsed `authresult` log line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthResult {
    pub level: String,
    pub result: String,
    pub proto: String,
    pub scope: String,
    pub mech: String,
    pub user: String,
    pub peer: String,
    pub reason: String,
    pub pwfp: String,
}

/// The grok pattern of the shipped CrowdSec parser
/// (`contrib/crowdsec/parsers/s01-parse/mail-auth-proxy-logs.yaml`),
/// translated to a regex: WORD = `\b\w+\b`, DATA = `.*?`, NOTSPACE = `\S+`,
/// IP = grok's IPV4 | IPV6. Each field is a capture group, in pattern order
/// (1 result … 7 reason).
pub fn grok_regex() -> regex::Regex {
    const PARSER: &str =
        include_str!("../../contrib/crowdsec/parsers/s01-parse/mail-auth-proxy-logs.yaml");
    const IPV4: &str = r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])";
    const IPV6: &str = r"(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}";
    let pattern = PARSER
        .lines()
        .find_map(|l| l.trim().strip_prefix("pattern: '")?.strip_suffix('\''))
        .expect("grok pattern in the CrowdSec parser");
    let token = regex::Regex::new(r"%\{(\w+):\w+\}").unwrap();
    let translated = token.replace_all(pattern, |c: &regex::Captures| match &c[1] {
        "WORD" => r"(\b\w+\b)".to_string(),
        "DATA" => "(.*?)".to_string(),
        "NOTSPACE" => r"(\S+)".to_string(),
        "IP" => format!("({IPV4}|{IPV6})"),
        other => panic!("grok pattern {other} is not translated"),
    });
    regex::Regex::new(&translated).unwrap()
}

/// Strict parser for the full line as the binary writes it. Group 10
/// is the `rule` field, appended after `pwfp`.
fn line_regex() -> regex::Regex {
    regex::Regex::new(
        r#"^\S+Z +(INFO|WARN) authlog: authresult result="([^"]*)" proto="([^"]*)" scope="([^"]*)" mech=(\S*) user=(\S*) peer=(\S+) reason="([^"]*)" pwfp="([^"]*)" rule="([^"]*)"$"#,
    )
    .unwrap()
}

pub struct Proxy {
    child: Child,
    logs: Arc<Mutex<Vec<String>>>,
    pub config: PathBuf,
    pub imap: SocketAddr,
    pub smtp: SocketAddr,
    pub sieve: SocketAddr,
    pub metrics: SocketAddr,
}

impl Proxy {
    /// Write the config, start the binary and wait until all listeners are up.
    pub async fn start(pki: &Pki, idp: &Idp, backends: [&MockBackend; 3], opts: &Opts) -> Proxy {
        let [imap, smtp, sieve] = backends;
        let ca = pki.ca_file.display();
        let backend = |b: &MockBackend, pp: bool| {
            format!(
                "{{ address = \"{}\", verify_name = \"{BACKEND_NAME}\", ca_file = \"{ca}\", proxy_protocol = {pp} }}",
                b.addr
            )
        };
        let config = format!(
            r#"config_version = 2

[server]
hostname = "{HOSTNAME}"

[tls]
cert = "{cert}"
key = "{key}"

[imap]
listen = "{IMAP_IP}:0"
backend = {imap_be}

[submission]
listen = "{SMTP_IP}:0"
backend = {smtp_be}
xclient = {xclient}

[sieve]
listen = "{SIEVE_IP}:0"
backend = {sieve_be}

[oauth]
[[oauth.issuers]]
issuer = "{ISSUER}"
jwks_url = "{jwks}"
audiences = ["{AUDIENCE}"]
token_type = "keycloak"
{issuer_extra}

{legacy}
[limits]
max_preauth_per_ip = {per_ip}

[timeouts]
preauth_secs = {preauth}
idle_secs = {idle}
connect_secs = 3

{session}
{metrics}

{ratelimit}
"#,
            cert = pki.proxy_cert.display(),
            key = pki.proxy_key.display(),
            imap_be = backend(imap, true),
            smtp_be = backend(smtp, false),
            xclient = opts.smtp_xclient,
            sieve_be = backend(sieve, true),
            jwks = idp.jwks_url(),
            issuer_extra = opts.issuer_extra,
            per_ip = opts.max_preauth_per_ip,
            preauth = opts.preauth_secs,
            idle = opts.idle_secs,
            legacy = opts.legacy.clone().unwrap_or_else(default_password_gate),
            session = opts
                .session
                .as_ref()
                .map(|s| format!("[session]\n{s}\n"))
                .unwrap_or_default(),
            metrics = if opts.metrics {
                format!("[metrics]\nlisten = \"{METRICS_IP}:0\"")
            } else {
                format!("[metrics]\nenabled = false\nlisten = \"{METRICS_IP}:0\"")
            },
            ratelimit = opts
                .ratelimit
                .as_ref()
                .map(|r| format!("[auth_ratelimit]\n{r}"))
                .unwrap_or_default(),
        );
        let path = pki.dir.path().join("config.toml");
        std::fs::write(&path, config).unwrap();
        Self::spawn(&path, opts).await
    }

    async fn spawn(config: &Path, opts: &Opts) -> Proxy {
        let metrics = opts.metrics;
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_mail-auth-proxy"));
        if let Some(sock) = &opts.notify_socket {
            cmd.env("NOTIFY_SOCKET", sock);
        }
        let mut child = cmd
            .arg(config)
            .env("RUST_LOG", opts.rust_log)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start mail-auth-proxy");
        let logs: Arc<Mutex<Vec<String>>> = Arc::default();
        let stderr = child.stderr.take().unwrap();
        let sink = logs.clone();
        std::thread::spawn(move || {
            for line in std::io::BufReader::new(stderr).lines() {
                let Ok(line) = line else { break };
                sink.lock().unwrap().push(line);
            }
        });
        let pid = child.id();
        let mut proxy = Proxy {
            child,
            logs,
            config: config.to_path_buf(),
            imap: SocketAddr::from(([0, 0, 0, 0], 0)),
            smtp: SocketAddr::from(([0, 0, 0, 0], 0)),
            sieve: SocketAddr::from(([0, 0, 0, 0], 0)),
            metrics: SocketAddr::from(([0, 0, 0, 0], 0)),
        };
        let until = Instant::now() + IO_TIMEOUT;
        loop {
            if let Ok(Some(status)) = proxy.child.try_wait() {
                panic!(
                    "mail-auth-proxy exited during startup ({status}):\n{}",
                    proxy.logs().join("\n")
                );
            }
            if proxy.log_contains("sieve listener up") {
                let found = listeners(pid);
                let by_ip = |ip: Ipv4Addr| found.iter().copied().find(|a| a.ip() == ip);
                // Without metrics nothing listens on METRICS_IP (it is also
                // the client's address, so no other socket can be mistaken).
                let m = by_ip(METRICS_IP).or((!metrics).then_some(proxy.metrics));
                if let (Some(i), Some(s), Some(v), Some(m)) =
                    (by_ip(IMAP_IP), by_ip(SMTP_IP), by_ip(SIEVE_IP), m)
                {
                    (proxy.imap, proxy.smtp, proxy.sieve, proxy.metrics) = (i, s, v, m);
                    return proxy;
                }
            }
            assert!(
                Instant::now() < until,
                "mail-auth-proxy not ready:\n{}",
                proxy.logs().join("\n")
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    pub fn logs(&self) -> Vec<String> {
        self.logs.lock().unwrap().clone()
    }

    /// Send signal `sig` (`HUP`, `TERM`, …) to the proxy.
    pub fn signal(&self, sig: &str) {
        let status = Command::new("kill")
            .args(["-s", sig, &self.child.id().to_string()])
            .status()
            .expect("run kill");
        assert!(status.success(), "kill -s {sig}");
    }

    /// Wait up to `within` for the proxy to exit; its exit status, or `None`
    /// if it is still running.
    pub async fn wait_exit(&mut self, within: Duration) -> Option<std::process::ExitStatus> {
        let until = Instant::now() + within;
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return Some(status);
            }
            if Instant::now() > until {
                return None;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    pub fn log_contains(&self, needle: &str) -> bool {
        self.logs.lock().unwrap().iter().any(|l| l.contains(needle))
    }

    pub fn count_logs(&self, needle: &str) -> usize {
        self.logs
            .lock()
            .unwrap()
            .iter()
            .filter(|l| l.contains(needle))
            .count()
    }

    /// Wait until at least `n` log lines contain `needle`.
    pub async fn wait_logs(&self, needle: &str, n: usize) {
        let until = Instant::now() + IO_TIMEOUT;
        while self.count_logs(needle) < n {
            assert!(
                Instant::now() < until,
                "waited for {n} log lines with {needle:?}:\n{}",
                self.logs().join("\n")
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    /// Every `authresult` line so far, parsed.
    pub fn authresults(&self) -> Vec<AuthResult> {
        let re = line_regex();
        self.logs()
            .iter()
            .filter(|l| l.contains("authresult"))
            .map(|l| {
                let c = re
                    .captures(l)
                    .unwrap_or_else(|| panic!("unexpected authresult line format: {l}"));
                let g = |i: usize| c[i].to_string();
                AuthResult {
                    level: g(1),
                    result: g(2),
                    proto: g(3),
                    scope: g(4),
                    mech: g(5),
                    user: g(6),
                    peer: g(7),
                    reason: g(8),
                    pwfp: g(9),
                }
            })
            .collect()
    }

    /// The `rule` field of every `authresult` line so far, in order.
    pub fn authresult_rules(&self) -> Vec<String> {
        let re = line_regex();
        self.logs()
            .iter()
            .filter(|l| l.contains("authresult"))
            .map(|l| {
                re.captures(l)
                    .unwrap_or_else(|| panic!("unexpected authresult line format: {l}"))[10]
                    .to_string()
            })
            .collect()
    }

    /// Wait until `n` authresult lines exist and return them.
    pub async fn wait_authresults(&self, n: usize) -> Vec<AuthResult> {
        self.wait_logs("authresult", n).await;
        self.authresults()
    }

    /// All metric samples, keyed `name{labels}`.
    pub async fn metrics(&self) -> HashMap<String, u64> {
        let mut s = TcpStream::connect(self.metrics).await.unwrap();
        s.write_all(b"GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        let mut body = String::new();
        tokio::time::timeout(IO_TIMEOUT, s.read_to_string(&mut body))
            .await
            .expect("metrics scrape timed out")
            .unwrap();
        let body = body.split_once("\r\n\r\n").expect("http response").1;
        body.lines()
            .filter(|l| !l.starts_with('#') && !l.is_empty())
            .filter_map(|l| l.rsplit_once(' '))
            .map(|(k, v)| (k.to_string(), v.parse::<i64>().unwrap_or(0).max(0) as u64))
            .collect()
    }

    /// One metric sample, e.g. `mail_auth_proxy_backend_errors_total{proto="imap"}`.
    pub async fn metric(&self, key: &str) -> u64 {
        *self
            .metrics()
            .await
            .get(key)
            .unwrap_or_else(|| panic!("no metric {key}"))
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let logs = self.logs();
        // HARNESS_LOGS=1 shows the proxy's stderr also for passing tests.
        if std::thread::panicking() || std::env::var_os("HARNESS_LOGS").is_some() {
            eprintln!("---- mail-auth-proxy stderr ----\n{}", logs.join("\n"));
        }
        if std::thread::panicking() {
            return;
        }
        // The log format is an API: every authresult line of every test must
        // match the pattern CrowdSec parses.
        let grok = grok_regex();
        for l in logs.iter().filter(|l| l.contains("authresult")) {
            assert!(
                grok.is_match(l),
                "authresult line breaks the grok pattern: {l}"
            );
        }
    }
}

/// Listening IPv4 TCP sockets of process `pid`, from /proc.
fn listeners(pid: u32) -> Vec<SocketAddr> {
    let mut inodes = HashSet::new();
    if let Ok(dir) = std::fs::read_dir(format!("/proc/{pid}/fd")) {
        for e in dir.flatten() {
            if let Ok(target) = std::fs::read_link(e.path()) {
                let t = target.to_string_lossy();
                if let Some(n) = t.strip_prefix("socket:[").and_then(|r| r.strip_suffix(']')) {
                    inodes.insert(n.to_string());
                }
            }
        }
    }
    let table = std::fs::read_to_string(format!("/proc/{pid}/net/tcp")).unwrap_or_default();
    table
        .lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            // local_address st … inode; st 0A = LISTEN
            if f.len() < 10 || f[3] != "0A" || !inodes.contains(f[9]) {
                return None;
            }
            let (ip, port) = f[1].split_once(':')?;
            let ip = u32::from_str_radix(ip, 16).ok()?;
            let port = u16::from_str_radix(port, 16).ok()?;
            // The kernel prints the network-order address as a host integer.
            Some(SocketAddr::from((Ipv4Addr::from(ip.to_ne_bytes()), port)))
        })
        .collect()
}

// ── Everything together ─────────────────────────────────────────────────────

pub struct Harness {
    pub pki: Pki,
    pub idp: Idp,
    pub imap_be: MockBackend,
    pub smtp_be: MockBackend,
    pub sieve_be: MockBackend,
    pub proxy: Proxy,
}

impl Harness {
    pub async fn start() -> Harness {
        Self::start_with(Opts::default()).await
    }

    pub async fn start_with(opts: Opts) -> Harness {
        Self::start_on(Pki::new(), opts).await
    }

    /// Start with a PKI made beforehand (its CA or directory named in `opts`).
    pub async fn start_on(pki: Pki, opts: Opts) -> Harness {
        let idp = Idp::start().await;
        let imap_be = MockBackend::start(Kind::Imap, pki.backend.clone()).await;
        let smtp_be = MockBackend::start(Kind::Smtp, pki.backend.clone()).await;
        let sieve_be = MockBackend::start(Kind::Sieve, pki.backend.clone()).await;
        let proxy = Proxy::start(&pki, &idp, [&imap_be, &smtp_be, &sieve_be], &opts).await;
        Harness {
            pki,
            idp,
            imap_be,
            smtp_be,
            sieve_be,
            proxy,
        }
    }

    pub fn backend(&self, kind: Kind) -> &MockBackend {
        match kind {
            Kind::Imap => &self.imap_be,
            Kind::Smtp => &self.smtp_be,
            Kind::Sieve => &self.sieve_be,
        }
    }

    /// IMAP: TCP + TLS, greeting read. Returns the client and the greeting.
    pub async fn imap(&self, src: Src, sni: Sni) -> (Client, String) {
        let mut c = Client::connect(self.proxy.imap, src).await;
        c.tls(&self.pki, sni).await;
        let greeting = c.line().await;
        (c, greeting)
    }

    /// SMTP up to the post-TLS EHLO. Returns the client and the EHLO reply.
    pub async fn smtp(&self, src: Src, sni: Sni) -> (Client, Vec<String>) {
        let mut c = Client::connect(self.proxy.smtp, src).await;
        assert_eq!(c.line().await, format!("220 {HOSTNAME} ESMTP"));
        c.send("EHLO client.test").await;
        assert_eq!(
            c.smtp_reply().await,
            vec![format!("250-{HOSTNAME}"), "250 STARTTLS".to_string()]
        );
        c.send("STARTTLS").await;
        assert_eq!(c.line().await, "220 2.0.0 Ready to start TLS");
        c.tls(&self.pki, sni).await;
        c.send("EHLO client.test").await;
        let ehlo = c.smtp_reply().await;
        (c, ehlo)
    }

    /// ManageSieve up to the post-TLS capabilities. Returns the client, the
    /// plaintext greeting and the post-TLS capability lines (both including
    /// their final OK line).
    pub async fn sieve(&self, src: Src, sni: Sni) -> (Client, Vec<String>, Vec<String>) {
        let mut c = Client::connect(self.proxy.sieve, src).await;
        let greeting = c.sieve_response().await;
        c.send("STARTTLS").await;
        assert_eq!(c.line().await, "OK \"Begin TLS negotiation now\"");
        c.tls(&self.pki, sni).await;
        let caps = c.sieve_response().await;
        (c, greeting, caps)
    }

    /// Open a session of `kind` and present `mech` with initial response
    /// `ir` in one command. Returns the client and the proxy's first reply.
    pub async fn auth(
        &self,
        kind: Kind,
        src: Src,
        sni: Sni,
        mech: &str,
        ir: &str,
    ) -> (Client, String) {
        let mut c = self.ready(kind, src, sni).await;
        c.send(&auth_command(kind, mech, ir)).await;
        let reply = c.line().await;
        (c, reply)
    }

    /// Present a token the proxy rejects: the proxy must answer with its
    /// error challenge (RFC 7628 section 3.2.2), which the client completes
    /// with the dummy response of `mech` (section 3.2.3). Returns the client,
    /// the decoded error result and the final reply.
    pub async fn auth_rejected(
        &self,
        kind: Kind,
        src: Src,
        sni: Sni,
        mech: &str,
        ir: &str,
    ) -> (Client, serde_json::Value, String) {
        let (mut c, challenge) = self.auth(kind, src, sni, mech, ir).await;
        let result = error_result(kind, &challenge);
        c.send(&sasl_response(kind, dummy_response(mech))).await;
        let reply = c.line().await;
        (c, result, reply)
    }

    /// A session of `kind` at the point where the client sends its credential.
    pub async fn ready(&self, kind: Kind, src: Src, sni: Sni) -> Client {
        match kind {
            Kind::Imap => self.imap(src, sni).await.0,
            Kind::Smtp => self.smtp(src, sni).await.0,
            Kind::Sieve => self.sieve(src, sni).await.0,
        }
    }

    /// Wait for the `session ended` line of the `n`-th failed session of
    /// `kind` (logged after the handler returned, so after its authresult).
    /// A refused credential logs it at DEBUG, everything else at WARN.
    pub async fn wait_session_ended(&self, kind: Kind, n: usize) -> String {
        let needle = session_ended(kind);
        self.proxy.wait_logs(needle, n).await;
        self.proxy
            .logs()
            .into_iter()
            .filter(|l| l.contains(needle))
            .nth(n - 1)
            .unwrap()
    }

    pub fn sessions_ended(&self, kind: Kind) -> usize {
        self.proxy.count_logs(session_ended(kind))
    }
}

/// The per-protocol prefix of the line a failed session ends with.
pub fn session_ended(kind: Kind) -> &'static str {
    match kind {
        Kind::Imap => "mail_auth_proxy: session ended",
        Kind::Smtp => "mail_auth_proxy: submission session ended",
        Kind::Sieve => "mail_auth_proxy: sieve session ended",
    }
}

/// The client command presenting `mech` with initial response `ir`.
pub fn auth_command(kind: Kind, mech: &str, ir: &str) -> String {
    match kind {
        Kind::Imap => format!("a AUTHENTICATE {mech} {ir}"),
        Kind::Smtp => format!("AUTH {mech} {ir}"),
        Kind::Sieve => format!("AUTHENTICATE \"{mech}\" \"{ir}\""),
    }
}

/// The base64 data of an error challenge line of `kind` (`+ <b64>`,
/// `334 <b64>`, `"<b64>"`); panics on any other line.
pub fn challenge_data(kind: Kind, line: &str) -> &str {
    match kind {
        Kind::Imap => line.strip_prefix("+ "),
        Kind::Smtp => line.strip_prefix("334 "),
        Kind::Sieve => line.strip_prefix('"').and_then(|l| l.strip_suffix('"')),
    }
    .unwrap_or_else(|| panic!("{kind:?}: not an error challenge: {line:?}"))
}

/// The JSON error result an error challenge line of `kind` carries.
pub fn error_result(kind: Kind, line: &str) -> serde_json::Value {
    let raw = unb64(challenge_data(kind, line));
    serde_json::from_slice(&raw)
        .unwrap_or_else(|e| panic!("not JSON {:?}: {e}", String::from_utf8_lossy(&raw)))
}

/// The dummy response (base64) that completes a failed exchange of `mech`:
/// `%x01` for OAUTHBEARER (RFC 7628 section 3.2.3), empty for XOAUTH2.
pub fn dummy_response(mech: &str) -> &'static str {
    if mech.eq_ignore_ascii_case("OAUTHBEARER") {
        "AQ=="
    } else {
        ""
    }
}

/// A SASL client response line of `kind` carrying `data`: as it is for IMAP
/// and SMTP, a quoted string for ManageSieve.
pub fn sasl_response(kind: Kind, data: &str) -> String {
    match kind {
        Kind::Imap | Kind::Smtp => data.to_string(),
        Kind::Sieve => format!("\"{data}\""),
    }
}

impl Kind {
    pub const ALL: [Kind; 3] = [Kind::Imap, Kind::Smtp, Kind::Sieve];

    /// `proto` label in logs and metrics.
    pub fn label(self) -> &'static str {
        match self {
            Kind::Imap => "imap",
            Kind::Smtp => "smtp",
            Kind::Sieve => "sieve",
        }
    }
}

// ── Clients ─────────────────────────────────────────────────────────────────

/// The name the client asks for in its TLS ClientHello.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sni {
    /// `mail.internal.test`, the password endpoint.
    Internal,
    /// `mail.public.test`, the OAuth-only endpoint.
    Public,
    /// Connect by IP address: no SNI at all.
    None,
}

/// Where the client connects from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Src {
    /// 127.0.0.1, inside `internal_networks`.
    Internal,
    /// 127.0.0.2, outside `internal_networks`.
    External,
}

impl Src {
    pub fn ip(self) -> Ipv4Addr {
        match self {
            Src::Internal => Ipv4Addr::new(127, 0, 0, 1),
            Src::External => Ipv4Addr::new(127, 0, 0, 2),
        }
    }

    pub fn scope(self) -> &'static str {
        match self {
            Src::Internal => "internal",
            Src::External => "external",
        }
    }
}

enum Stream {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
    Gone,
}

pub struct Client {
    stream: Stream,
    /// The client's own address (what PROXY/XCLIENT must carry).
    pub local: SocketAddr,
    pub server: SocketAddr,
}

impl Client {
    /// Plain TCP from `src` to `server`.
    pub async fn connect(server: SocketAddr, src: Src) -> Client {
        let sock = TcpSocket::new_v4().unwrap();
        sock.bind(SocketAddr::from((src.ip(), 0))).unwrap();
        let tcp = tokio::time::timeout(IO_TIMEOUT, sock.connect(server))
            .await
            .expect("connect timed out")
            .expect("connect");
        let local = tcp.local_addr().unwrap();
        Client {
            stream: Stream::Plain(tcp),
            local,
            server,
        }
    }

    /// Run the TLS handshake on the plain connection (implicit TLS or after
    /// STARTTLS). Panics if it fails.
    pub async fn tls(&mut self, pki: &Pki, sni: Sni) {
        self.try_tls(pki, sni).await.expect("TLS handshake");
    }

    /// Like `tls`, but a full handshake: no session resumption, so the
    /// server presents its current certificate.
    pub async fn tls_full(&mut self, pki: &Pki, sni: Sni) {
        let mut config = (*pki.client).clone();
        config.resumption = rustls::client::Resumption::disabled();
        self.try_tls_with(Arc::new(config), sni)
            .await
            .expect("TLS handshake");
    }

    pub async fn try_tls(&mut self, pki: &Pki, sni: Sni) -> std::io::Result<()> {
        self.try_tls_with(pki.client.clone(), sni).await
    }

    async fn try_tls_with(
        &mut self,
        client: Arc<rustls::ClientConfig>,
        sni: Sni,
    ) -> std::io::Result<()> {
        let Stream::Plain(tcp) = std::mem::replace(&mut self.stream, Stream::Gone) else {
            panic!("tls on a non-plain stream");
        };
        let name = match sni {
            Sni::Internal => rustls::pki_types::ServerName::try_from(INTERNAL_SNI).unwrap(),
            Sni::Public => rustls::pki_types::ServerName::try_from(PUBLIC_SNI).unwrap(),
            // An IP address as the server name: rustls sends no SNI.
            Sni::None => rustls::pki_types::ServerName::IpAddress(self.server.ip().into()),
        };
        let connector = tokio_rustls::TlsConnector::from(client);
        let tls = tokio::time::timeout(IO_TIMEOUT, connector.connect(name, tcp))
            .await
            .map_err(|_| std::io::Error::other("TLS handshake timed out"))??;
        self.stream = Stream::Tls(Box::new(tls));
        Ok(())
    }

    /// The server's end-entity certificate (DER), after the TLS handshake.
    pub fn peer_cert(&self) -> Vec<u8> {
        let Stream::Tls(s) = &self.stream else {
            panic!("no TLS session");
        };
        s.get_ref().1.peer_certificates().unwrap()[0].to_vec()
    }

    pub async fn send_raw(&mut self, data: &[u8]) {
        let r = match &mut self.stream {
            Stream::Plain(s) => s.write_all(data).await.and(s.flush().await),
            Stream::Tls(s) => s.write_all(data).await.and(s.flush().await),
            Stream::Gone => panic!("stream gone"),
        };
        r.expect("write");
    }

    pub async fn send(&mut self, line: &str) {
        self.send_raw(format!("{line}\r\n").as_bytes()).await;
    }

    /// Next line, or `None` if the peer closed (or reset) the connection.
    pub async fn try_line(&mut self) -> Option<String> {
        let fut = async {
            match &mut self.stream {
                Stream::Plain(s) => read_line_raw(s).await,
                Stream::Tls(s) => read_line_raw(s).await,
                Stream::Gone => None,
            }
        };
        tokio::time::timeout(IO_TIMEOUT, fut)
            .await
            .expect("timed out waiting for a line")
    }

    /// Next line; panics on close.
    pub async fn line(&mut self) -> String {
        self.try_line()
            .await
            .expect("connection closed while a line was expected")
    }

    /// A (multi-line) SMTP reply.
    pub async fn smtp_reply(&mut self) -> Vec<String> {
        let mut out = Vec::new();
        loop {
            let l = self.line().await;
            let last = l.as_bytes().get(3) != Some(&b'-');
            out.push(l);
            if last {
                return out;
            }
        }
    }

    /// ManageSieve lines up to and including the OK/NO/BYE line.
    pub async fn sieve_response(&mut self) -> Vec<String> {
        let mut out = Vec::new();
        loop {
            let l = self.line().await;
            let done = ["OK", "NO", "BYE"].iter().any(|p| l.starts_with(p));
            out.push(l);
            if done {
                return out;
            }
        }
    }

    /// Everything until the peer closes, raw. Panics if it stays open.
    pub async fn read_to_close(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        let fut = async {
            let mut buf = [0u8; 4096];
            loop {
                let n = match &mut self.stream {
                    Stream::Plain(s) => s.read(&mut buf).await,
                    Stream::Tls(s) => s.read(&mut buf).await,
                    Stream::Gone => Ok(0),
                };
                match n {
                    Ok(0) | Err(_) => return,
                    Ok(n) => out.extend_from_slice(&buf[..n]),
                }
            }
        };
        tokio::time::timeout(IO_TIMEOUT, fut)
            .await
            .expect("connection stayed open");
        out
    }

    /// The end of a session of `kind` after a refused credential: SMTP
    /// announces the close with `421` (RFC 5321 §3.8), then the peer closes.
    pub async fn expect_end(&mut self, kind: Kind) {
        if kind == Kind::Smtp {
            assert_eq!(
                self.line().await,
                format!("421 4.7.0 {HOSTNAME} closing connection")
            );
        }
        self.expect_closed().await;
    }

    /// The peer closes without sending anything more.
    pub async fn expect_closed(&mut self) {
        let rest = self.read_to_close().await;
        assert!(
            rest.is_empty(),
            "expected close, got {:?}",
            String::from_utf8_lossy(&rest)
        );
    }
}
