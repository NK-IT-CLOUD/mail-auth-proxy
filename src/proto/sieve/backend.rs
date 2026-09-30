//! ManageSieve backend sessions and the cached backend capabilities.

use super::Upstream;
use crate::auth::{BackendCredential, BackendError, BackendLogin};
use crate::config::BackendTls;
use crate::obs::authlog::sanitize;
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

/// The backend's capabilities over TLS (SIEVE extensions, limits, …),
/// relayed to clients before they authenticate.
///
/// Caching them means an unauthenticated client never causes a backend
/// connection, which would hold a Dovecot login process and a backend TLS
/// session for up to the pre-auth budget per TLS handshake on 4190. Only a
/// cache miss (once per TTL) opens a probe connection, one at a time; after a
/// failed probe the next one waits `PROBE_RETRY`.
#[derive(Default)]
pub struct CapsCache {
    caps: RwLock<Option<(Instant, Arc<Vec<String>>)>>,
    /// Held while a probe runs; the time of the last failed probe.
    probe: tokio::sync::Mutex<Option<Instant>>,
}

/// How long after a failed capability probe the next one may start.
const PROBE_RETRY: Duration = Duration::from_secs(5);

impl CapsCache {
    /// The capabilities of the last successful probe, whatever their age.
    fn any_age(&self) -> Option<Arc<Vec<String>>> {
        let caps = self.caps.read().unwrap_or_else(|p| p.into_inner());
        caps.as_ref().map(|(_, caps)| caps.clone())
    }

    /// The cached capabilities if they are younger than `ttl`.
    fn fresh(&self, ttl: Duration) -> Option<Arc<Vec<String>>> {
        let caps = self.caps.read().unwrap_or_else(|p| p.into_inner());
        caps.as_ref()
            .filter(|(at, _)| at.elapsed() < ttl)
            .map(|(_, caps)| caps.clone())
    }
}

/// Open a backend ManageSieve session up to (and including) the capability
/// list over TLS: after STARTTLS the server sends it again (RFC 5804 §2.2),
/// with implicit TLS it is the greeting.
/// `origin` is `(client, local)` for a client's session, `None` for the
/// capability probe, which is the proxy's own connection.
pub(super) async fn backend_session(
    backend: &BackendConn,
    origin: Option<(SocketAddr, SocketAddr)>,
    tuning: &Tuning,
) -> Result<(TlsStream<TcpStream>, Vec<String>)> {
    const WHAT: &str = "sieve backend";
    // The PROXY header goes first, before the backend's greeting.
    let mut tcp_be = connect::connect(backend, origin, tuning.connect, WHAT).await?;
    if backend.tls_mode == BackendTls::Starttls {
        // Greeting capabilities, then STARTTLS and its OK.
        read_caps_until_ok(&mut tcp_be, tuning.idle).await?;
        tcp_be.write_all(b"STARTTLS\r\n").await?;
        read_caps_until_ok(&mut tcp_be, tuning.idle).await?;
    }
    let mut be = connect::tls(backend, tcp_be, tuning.connect, WHAT).await?;
    let caps = read_caps_until_ok(&mut be, tuning.idle).await?;
    Ok((be, caps))
}

/// The backend's post-TLS capabilities, from the cache (younger than
/// `ttl`) or a probe session.
///
/// One probe at a time: a caller that waited for another's probe finds the
/// cache filled, or its failure. A failed probe counts in `backend_errors`;
/// for `PROBE_RETRY` after it, callers fail without contacting the backend.
pub(super) async fn backend_caps(
    up: &Upstream,
    ttl: Duration,
    tuning: &Tuning,
) -> Result<Arc<Vec<String>>> {
    if let Some(caps) = up.caps.fresh(ttl) {
        return Ok(caps);
    }
    let mut last_failure = up.caps.probe.lock().await;
    if let Some(caps) = up.caps.fresh(ttl) {
        return Ok(caps);
    }
    if let Some(at) = *last_failure {
        if at.elapsed() < PROBE_RETRY {
            return Err(anyhow!(
                "backend capability probe failed {}s ago",
                at.elapsed().as_secs()
            ));
        }
    }
    let pool = &up.pool;
    let (mut be, caps) = match pool
        .open(None, |i| {
            backend_session(&pool.members[i].conn, None, tuning)
        })
        .await
    {
        Ok((v, _)) => v,
        Err(e) => {
            *last_failure = Some(Instant::now());
            crate::obs::metrics::record_backend_error(crate::obs::metrics::Proto::Sieve);
            return Err(e.context("backend capability probe"));
        }
    };
    *last_failure = None;
    // End the probe politely; it carries no credential.
    let _ = tokio::time::timeout(Duration::from_secs(2), async {
        be.write_all(b"LOGOUT\r\n").await?;
        be.flush().await
    })
    .await;
    let caps = Arc::new(caps);
    *up.caps.caps.write().unwrap_or_else(|p| p.into_inner()) = Some((Instant::now(), caps.clone()));
    Ok(caps)
}

/// An active health check of one address: the session up to the
/// capabilities over TLS (a PROXY `LOCAL` header where the backend takes
/// one), then LOGOUT.
pub(crate) async fn check(backend: &BackendConn, tuning: &Tuning) -> Result<()> {
    let (mut be, _) = backend_session(backend, None, tuning).await?;
    let _ = tokio::time::timeout(Duration::from_secs(2), async {
        be.write_all(b"LOGOUT\r\n").await?;
        be.flush().await
    })
    .await;
    Ok(())
}

/// The capabilities to show a client before it authenticates: those every
/// backend its credential can be routed to has (`intersect`). They may
/// differ from the chosen backend's after AUTHENTICATE (RFC 5804 §1.7), so
/// the client can ask again. The backends are asked together. A backend
/// whose probe fails counts with its last list, whatever its age; one that
/// has never answered is left out, since an empty list would take the
/// `SASL` line from every client (unlike SMTP, where the proxy writes AUTH
/// itself). When every probe fails, so does this.
pub(super) async fn caps_for_client(
    backends: &[Arc<Upstream>],
    ttl: Duration,
    tuning: &Tuning,
) -> Result<Vec<String>> {
    let mut probes = tokio::task::JoinSet::new();
    for (i, up) in backends.iter().enumerate() {
        let (up, tuning) = (up.clone(), *tuning);
        probes.spawn(async move {
            let caps = backend_caps(&up, ttl, &tuning).await;
            (i, caps.map_err(|e| (e, up.caps.any_age())))
        });
    }
    let mut lists: Vec<Option<Arc<Vec<String>>>> = vec![None; backends.len()];
    let mut failure = None;
    let mut answered = false;
    while let Some(done) = probes.join_next().await {
        match done {
            Ok((i, Ok(caps))) => {
                answered = true;
                lists[i] = Some(caps);
            }
            Ok((i, Err((e, stale)))) => {
                lists[i] = stale;
                failure = Some(e);
            }
            Err(e) => failure = Some(anyhow!("capability probe: {e}")),
        }
    }
    match failure {
        Some(e) if !answered => Err(e),
        _ => Ok(intersect(&lists.into_iter().flatten().collect::<Vec<_>>())),
    }
}

/// The `"SIEVE"` line of the capabilities every backend that has answered a
/// probe has, whatever the age of its list; `None` while none has.
pub(super) fn sieve_line(backends: &[Arc<Upstream>]) -> Option<String> {
    let lists: Vec<_> = backends.iter().filter_map(|up| up.caps.any_age()).collect();
    intersect(&lists).into_iter().find(|l| is_cap(l, "SIEVE"))
}

/// The capability lines every list has, by name, in the first list's order:
/// the values of `SIEVE` and `NOTIFY` (space-separated extensions, RFC 5804
/// §1.7) narrowed to those all lists have, `MAXREDIRECTS` the smallest,
/// every other capability with the first list's value. No list: nothing.
pub(super) fn intersect(lists: &[Arc<Vec<String>>]) -> Vec<String> {
    let Some((first, rest)) = lists.split_first() else {
        return Vec::new();
    };
    // One backend: its list as it is.
    if rest.is_empty() {
        return first.to_vec();
    }
    let parse = |line: &str| -> Option<(String, Option<String>)> {
        let (name, rest) = super::preauth::unquote_string(line.trim())?;
        let value = super::preauth::unquote_string(rest.trim()).map(|(v, _)| v);
        Some((name, value))
    };
    let mut out = Vec::new();
    for line in first.iter() {
        let Some((name, value)) = parse(line) else {
            continue;
        };
        let others: Option<Vec<Option<String>>> = rest
            .iter()
            .map(|l| {
                l.iter()
                    .filter_map(|x| parse(x))
                    .find(|(n, _)| n.eq_ignore_ascii_case(&name))
                    .map(|(_, v)| v)
            })
            .collect();
        let Some(others) = others else {
            continue;
        };
        let upper = name.to_ascii_uppercase();
        let merged = match (upper.as_str(), &value) {
            ("SIEVE" | "NOTIFY", Some(v)) => {
                let common: Vec<&str> = v
                    .split(' ')
                    .filter(|x| !x.is_empty())
                    .filter(|x| {
                        others.iter().all(|o| {
                            o.as_deref()
                                .is_some_and(|o| o.split(' ').any(|y| y.eq_ignore_ascii_case(x)))
                        })
                    })
                    .collect();
                format!("\"{name}\" \"{}\"", common.join(" "))
            }
            ("MAXREDIRECTS", Some(v)) => {
                let smallest = std::iter::once(v.as_str())
                    .chain(others.iter().filter_map(|o| o.as_deref()))
                    .filter_map(|n| n.parse::<u64>().ok())
                    .min();
                match smallest {
                    Some(n) => format!("\"{name}\" \"{n}\""),
                    None => line.clone(),
                }
            }
            _ => line.clone(),
        };
        out.push(merged);
    }
    out
}

/// The ManageSieve backend login of one client session.
pub(super) struct SieveLogin<'a> {
    pub backends: &'a [Arc<Upstream>],
    pub tuning: &'a Tuning,
    /// `(client, local)`: the client's address and the address it dialed.
    pub origin: (SocketAddr, SocketAddr),
}

impl BackendLogin for SieveLogin<'_> {
    /// The backend connection and its OK line, relayed to the client.
    type Conn = (TlsStream<TcpStream>, String);

    fn name(&self, index: usize) -> &str {
        &self.backends[index].pool.id
    }

    async fn login(
        &self,
        index: usize,
        credential: BackendCredential<'_>,
    ) -> Result<Self::Conn, BackendError> {
        let pool = &self.backends[index].pool;
        // Up to the credential an address that fails gives way to the next.
        let ((be, caps), member) = pool
            .open(Some(credential.account()), |i| {
                backend_session(&pool.members[i].conn, Some(self.origin), self.tuning)
            })
            .await?;
        let result = self
            .authenticate(&pool.members[member].conn, be, &caps, credential)
            .await;
        match &result {
            Ok(_) => pool.session(),
            Err(BackendError::Unavailable(_)) => pool.tempfail(member),
            Err(BackendError::Rejected(_)) => {}
        }
        result
    }
}

impl SieveLogin<'_> {
    /// The login on a session with `backend` that listed `caps`: never
    /// retried on another address.
    async fn authenticate(
        &self,
        backend: &BackendConn,
        mut be: TlsStream<TcpStream>,
        caps: &[String],
        credential: BackendCredential<'_>,
    ) -> Result<(TlsStream<TcpStream>, String), BackendError> {
        let fwd = credential.forward(backend);
        let (mech, response) = (fwd.mech, fwd.response.as_str());
        // A quoted string holds at most 1024 octets (RFC 5804 §4); a longer
        // response (any sizable token) goes as a literal `{n+}`. `concat`
        // sizes the line once; it is zeroized on drop like the response.
        let auth_line = if response.len() <= 1024 {
            Zeroizing::new(["AUTHENTICATE \"", mech, "\" \"", response, "\"\r\n"].concat())
        } else {
            let len = response.len().to_string();
            Zeroizing::new(
                [
                    "AUTHENTICATE \"",
                    mech,
                    "\" {",
                    &len,
                    "+}\r\n",
                    response,
                    "\r\n",
                ]
                .concat(),
            )
        };
        // Checked before the credential is sent.
        if caps.iter().any(|l| is_cap(l, "UNAUTHENTICATE")) {
            return Err(anyhow!(crate::auth::UNAUTHENTICATE_OFFERED).into());
        }
        be.write_all(auth_line.as_bytes()).await?;
        // The backend's reply; it is forwarded verbatim on OK.
        let mut be_reply = read_line(&mut be, self.tuning.idle).await?;
        let mut error_result = None;
        if let (true, Some(answer)) = (is_string(&be_reply), fwd.error_answer()) {
            // The error challenge of a token, a string (RFC 5804 §2.1): the
            // client answers with the mechanism's dummy response (empty for
            // XOAUTH2, `%x01` for OAUTHBEARER), then the server fails the
            // exchange (RFC 7628 §3.2.3).
            let challenge = read_challenge(&mut be, &be_reply, self.tuning.idle).await?;
            error_result = fwd.error_result(&challenge);
            be.write_all(format!("\"{answer}\"\r\n").as_bytes()).await?;
            be_reply = read_line(&mut be, self.tuning.idle).await?;
        }
        match classify_auth_reply(&be_reply) {
            AuthReply::Ok => Ok((be, be_reply)),
            AuthReply::Rejected => {
                Err(crate::auth::rejected_after(be_reply, error_result.as_ref()))
            }
            AuthReply::Unavailable => {
                Err(anyhow!("backend temporarily unavailable: {be_reply}").into())
            }
        }
    }
}

/// A line that starts a ManageSieve string: quoted or a literal (RFC 5804
/// §4), the form of a server challenge.
fn is_string(line: &str) -> bool {
    line.starts_with('"') || line.starts_with('{')
}

/// Longest server challenge read from a literal; an error result is small.
const MAX_CHALLENGE: usize = 4096;

/// The text of a server challenge whose first line is `line`: a quoted
/// string on that line, or a literal `{n}` whose `n` octets and CRLF follow.
pub(crate) async fn read_challenge<S: tokio::io::AsyncRead + Unpin>(
    s: &mut S,
    line: &str,
    idle: Duration,
) -> Result<String> {
    if let Some(n) = line.strip_prefix('{').and_then(|l| l.strip_suffix('}')) {
        let n: usize = n
            .parse()
            .ok()
            .filter(|n| *n <= MAX_CHALLENGE)
            .ok_or_else(|| anyhow!("backend challenge: bad literal {}", sanitize(line)))?;
        let mut buf = vec![0u8; n];
        tokio::time::timeout(idle, tokio::io::AsyncReadExt::read_exact(s, &mut buf))
            .await
            .map_err(|_| anyhow!("backend challenge literal timed out"))??;
        if !read_line(s, idle).await?.is_empty() {
            return Err(anyhow!("backend challenge: text after the literal"));
        }
        return String::from_utf8(buf).map_err(|_| anyhow!("backend challenge: not UTF-8"));
    }
    match super::preauth::unquote_string(line) {
        Some((text, rest)) if rest.trim().is_empty() => Ok(text),
        _ => Err(anyhow!("backend challenge: malformed string")),
    }
}

/// What the backend's reply to `AUTHENTICATE` means.
#[derive(Debug, PartialEq, Eq)]
enum AuthReply {
    Ok,
    /// A verdict on the credential.
    Rejected,
    /// No verdict: an outage.
    Unavailable,
}

/// Classify the reply to `AUTHENTICATE`, case-insensitively.
///
/// - `OK`: logged in.
/// - `NO (TRYLATER)` (RFC 5804 §1.3): a temporary failure, an outage.
/// - `BYE` (RFC 5804 §1.3: the server is closing the connection, e.g. on
///   shutdown or a connection limit): an outage, unless it carries
///   `AUTH-TOO-WEAK` or `TRANSITION-NEEDED`, which judge the credential.
///   Counting an outage as a rejection would feed the rate limit and CrowdSec
///   bans against legitimate users.
/// - Any other `NO` (and anything unexpected): a rejection.
fn classify_auth_reply(reply: &str) -> AuthReply {
    let upper = reply.to_ascii_uppercase();
    if upper.starts_with("OK") {
        AuthReply::Ok
    } else if upper.starts_with("NO (TRYLATER)")
        || (upper.starts_with("BYE")
            && !upper.starts_with("BYE (AUTH-TOO-WEAK)")
            && !upper.starts_with("BYE (TRANSITION-NEEDED)"))
    {
        AuthReply::Unavailable
    } else {
        AuthReply::Rejected
    }
}

/// True if the capability line `line` names capability `name`: its first
/// string, ASCII case-insensitive (`"SASL" "PLAIN"` is `SASL`).
pub(super) fn is_cap(line: &str, name: &str) -> bool {
    line.strip_prefix('"')
        .and_then(|l| l.split_once('"'))
        .is_some_and(|(cap, _)| cap.eq_ignore_ascii_case(name))
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

    fn caps(l: &[&str]) -> Arc<Vec<String>> {
        Arc::new(l.iter().map(|s| s.to_string()).collect())
    }

    /// A backend no one can reach (port 1 on loopback refuses).
    fn unreachable(id: &str) -> BackendConn {
        let cfg = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        BackendConn {
            id: id.into(),
            address: "127.0.0.1:1".into(),
            name: rustls::pki_types::ServerName::try_from("backend.test").unwrap(),
            tls: tokio_rustls::TlsConnector::from(Arc::new(cfg)),
            client_ip: crate::config::ClientIp::None,
            tls_mode: BackendTls::Starttls,
            auth_forward: crate::config::AuthForward::Xoauth2,
            keepalive: Tuning::default().keepalive,
        }
    }

    /// A backend that has never answered a probe is left out: an empty
    /// list would take the SASL line (and every other one) from all
    /// clients. One that answered once keeps counting with its last list.
    /// Nobody answering is a failure.
    #[tokio::test]
    async fn a_backend_that_never_answered_is_left_out() {
        let answered = Arc::new(Upstream {
            pool: crate::pool::Pool::new(
                "one".into(),
                vec![crate::pool::Member {
                    conn: unreachable("one"),
                    health: Arc::default(),
                }],
                crate::config::PoolStrategy::Failover,
                Arc::default(),
                None,
            ),
            caps: Arc::default(),
        });
        *answered.caps.caps.write().unwrap() = Some((
            Instant::now(),
            caps(&[
                "\"SASL\" \"PLAIN\"",
                "\"SIEVE\" \"fileinto\"",
                "\"VERSION\" \"1.0\"",
            ]),
        ));
        let silent = Arc::new(Upstream {
            pool: crate::pool::Pool::new(
                "two".into(),
                vec![crate::pool::Member {
                    conn: unreachable("two"),
                    health: Arc::default(),
                }],
                crate::config::PoolStrategy::Failover,
                Arc::default(),
                None,
            ),
            caps: Arc::default(),
        });
        let tuning = Tuning::default();
        let both = [answered.clone(), silent.clone()];
        let got = caps_for_client(&both, Duration::from_secs(600), &tuning)
            .await
            .unwrap();
        assert_eq!(
            got,
            [
                "\"SASL\" \"PLAIN\"",
                "\"SIEVE\" \"fileinto\"",
                "\"VERSION\" \"1.0\""
            ]
        );
        assert_eq!(sieve_line(&both).as_deref(), Some("\"SIEVE\" \"fileinto\""));
        // Every probe failing is a failure, a stale list notwithstanding.
        assert!(caps_for_client(&both, Duration::ZERO, &tuning)
            .await
            .is_err());
        assert!(
            caps_for_client(std::slice::from_ref(&silent), Duration::ZERO, &tuning)
                .await
                .is_err()
        );
        assert_eq!(sieve_line(&[silent]), None);
    }

    /// Several backends: SIEVE and NOTIFY narrowed to the extensions all
    /// have, MAXREDIRECTS the smallest, a capability one lacks dropped, the
    /// rest from the first; one backend: its list as it is.
    #[test]
    fn capabilities_of_several_backends() {
        let dovecot = caps(&[
            "\"IMPLEMENTATION\" \"Dovecot Pigeonhole\"",
            "\"SIEVE\" \"fileinto reject envelope  vacation\"",
            "\"NOTIFY\" \"mailto\"",
            "\"MAXREDIRECTS\" \"4\"",
            "\"SASL\" \"PLAIN XOAUTH2\"",
            "\"VERSION\" \"1.0\"",
        ]);
        let stalwart = caps(&[
            "\"IMPLEMENTATION\" \"Stalwart\"",
            "\"SIEVE\" \"FILEINTO vacation imap4flags\"",
            "\"MAXREDIRECTS\" \"2\"",
            "\"SASL\" \"OAUTHBEARER\"",
            "\"VERSION\" \"1.0\"",
        ]);
        assert_eq!(
            intersect(&[dovecot.clone(), stalwart]),
            [
                "\"IMPLEMENTATION\" \"Dovecot Pigeonhole\"",
                "\"SIEVE\" \"fileinto vacation\"",
                "\"MAXREDIRECTS\" \"2\"",
                "\"SASL\" \"PLAIN XOAUTH2\"",
                "\"VERSION\" \"1.0\"",
            ]
        );
        assert_eq!(intersect(std::slice::from_ref(&dovecot)), *dovecot);
        assert_eq!(
            intersect(&[dovecot, Arc::default()]),
            Vec::<String>::new(),
            "a backend without a list"
        );
        assert!(intersect(&[]).is_empty());
    }

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

    /// A `BYE` is an outage, not a verdict on the credential.
    #[test]
    fn auth_reply_classification() {
        use AuthReply::*;
        for (reply, want) in [
            ("OK \"Logged in.\"", Ok),
            ("ok", Ok),
            ("NO \"Authentication failed.\"", Rejected),
            (
                "NO (TRYLATER) \"Temporary authentication failure.\"",
                Unavailable,
            ),
            ("BYE \"Server shutting down.\"", Unavailable),
            ("bye \"Too many connections\"", Unavailable),
            ("BYE", Unavailable),
            ("BYE (AUTH-TOO-WEAK) \"x\"", Rejected),
            ("BYE (TRANSITION-NEEDED) \"x\"", Rejected),
            ("garbage", Rejected),
        ] {
            assert_eq!(classify_auth_reply(reply), want, "{reply}");
        }
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

    /// A Pigeonhole capability block through `read_caps_until_ok` and the
    /// relay rule of `sieve::handle` (`rewrite_caps`): SIEVE, IMPLEMENTATION,
    /// NOTIFY and VERSION kept in order, SASL rewritten to what the endpoint
    /// offers, STARTTLS and UNAUTHENTICATE dropped.
    #[tokio::test]
    async fn cap_rewrite_keeps_sieve_rewrites_sasl_drops_starttls() {
        use std::io::Cursor;
        let input = concat!(
            "\"IMPLEMENTATION\" \"Dovecot Pigeonhole\"\r\n",
            "\"SIEVE\" \"fileinto reject envelope vacation\"\r\n",
            "\"NOTIFY\" \"mailto\"\r\n",
            "\"SASL\" \"OAUTHBEARER XOAUTH2 LOGIN PLAIN\"\r\n",
            "\"STARTTLS\"\r\n",
            "\"unauthenticate\"\r\n",
            "\"VERSION\" \"1.0\"\r\n",
            "OK \"TLS negotiation successful.\"\r\n",
        );
        let mut cursor = Cursor::new(input.as_bytes().to_vec());
        let caps = read_caps_until_ok(&mut cursor, Duration::from_secs(30))
            .await
            .unwrap();
        let kept = concat!(
            "\"IMPLEMENTATION\" \"Dovecot Pigeonhole\"\r\n",
            "\"SIEVE\" \"fileinto reject envelope vacation\"\r\n",
            "\"NOTIFY\" \"mailto\"\r\n",
        );
        assert_eq!(
            super::super::rewrite_caps(&caps, false),
            format!("{kept}\"SASL\" \"XOAUTH2 OAUTHBEARER\"\r\n\"VERSION\" \"1.0\"\r\n")
        );
        assert_eq!(
            super::super::rewrite_caps(&caps, true),
            format!("{kept}\"SASL\" \"XOAUTH2 OAUTHBEARER PLAIN\"\r\n\"VERSION\" \"1.0\"\r\n")
        );
    }

    #[test]
    fn capability_names() {
        assert!(is_cap("\"SASL\" \"PLAIN\"", "SASL"));
        assert!(is_cap("\"starttls\"", "STARTTLS"));
        assert!(!is_cap("\"SASLX\" \"PLAIN\"", "SASL"));
        assert!(!is_cap("SASL", "SASL"));
        assert!(!is_cap("\"SASL", "SASL"));
    }
}
