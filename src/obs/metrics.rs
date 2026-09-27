//! Prometheus metrics for the mail authentication proxy.
//!
//! Design constraints (this is a PROD mail auth path):
//! - Zero new dependencies: counters are plain atomics, the `/metrics` endpoint
//!   is a minimal HTTP/1.1 responder over the tokio runtime we already use.
//! - Instrumentation is off the hot path: every hook is a single relaxed
//!   atomic add; nothing here can fail an auth or drop a connection.
//! - The endpoint runs in its own task; a bind failure is logged and the mail
//!   listeners keep serving (see `serve`).

use super::authlog::Reason;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[derive(Clone, Copy)]
pub enum Proto {
    Imap,
    Smtp,
    Sieve,
}

impl Proto {
    /// The `proto` label in metrics and logs.
    pub fn label(self) -> &'static str {
        PROTO_LABELS[self.idx()]
    }

    #[inline]
    fn idx(self) -> usize {
        match self {
            Proto::Imap => 0,
            Proto::Smtp => 1,
            Proto::Sieve => 2,
        }
    }
}

const N_PROTO: usize = 3;
const PROTO_LABELS: [&str; N_PROTO] = ["imap", "smtp", "sieve"];

const N_MECH: usize = 5;
const MECH_LABELS: [&str; N_MECH] = ["xoauth2", "oauthbearer", "plain", "login", "other"];

const N_SCOPE: usize = 2;
const SCOPE_LABELS: [&str; N_SCOPE] = ["internal", "external"];

#[inline]
fn scope_idx(internal: bool) -> usize {
    usize::from(!internal) // internal = 0, external = 1
}

#[inline]
fn mech_idx(mech: &str) -> usize {
    if mech.eq_ignore_ascii_case("XOAUTH2") {
        0
    } else if mech.eq_ignore_ascii_case("OAUTHBEARER") {
        1
    } else if mech.eq_ignore_ascii_case("PLAIN") {
        2
    } else if mech.eq_ignore_ascii_case("LOGIN") {
        3
    } else {
        4
    }
}

// Atomics are not `Copy`; inline `const { .. }` blocks initialise the arrays.
// auth_attempts[proto][scope][mech][result]; result 0 = ok, 1 = fail
static AUTH_ATTEMPTS: [[[[AtomicU64; 2]; N_MECH]; N_SCOPE]; N_PROTO] =
    [const { [const { [const { [const { AtomicU64::new(0) }; 2] }; N_MECH] }; N_SCOPE] }; N_PROTO];
// preauth_aborts[proto][scope]: connections that died BEFORE a credential was
// ever presented (TLS-stack incompatibility, portscan, EOF, unsupported SASL
// mechanism, pre-auth command flood). Counted as failed logins they would
// make portscan noise indistinguishable from a real rejected login; kept
// apart, `auth_attempts_total{result="fail"}` means exactly "a credential was
// evaluated and rejected".
static PREAUTH_ABORTS: [[AtomicU64; N_SCOPE]; N_PROTO] =
    [const { [const { AtomicU64::new(0) }; N_SCOPE] }; N_PROTO];
/// The `reason` label values of `mail_auth_proxy_auth_refusals_total`: every
/// `authresult` reason of a refused credential (not `ok`, not `protocol`).
const REFUSAL_REASONS: [Reason; 8] = [
    Reason::BlockedEndpoint,
    Reason::BadToken,
    Reason::AuthzidMismatch,
    Reason::BackendReject,
    Reason::UnknownDomain,
    Reason::UnknownAccount,
    Reason::Throttled,
    Reason::Oversize,
];
// auth_refusals[proto][reason]: the refused credentials of
// auth_attempts{result="fail"}, split by why. A separate family, so the
// label set of auth_attempts (and the dashboards on it) stays as it is.
static AUTH_REFUSALS: [[AtomicU64; REFUSAL_REASONS.len()]; N_PROTO] =
    [const { [const { AtomicU64::new(0) }; REFUSAL_REASONS.len()] }; N_PROTO];
// token_validate[result]; result 0 = ok, 1 = fail
static TOKEN_VALIDATE: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];
static CONNECTIONS_TOTAL: [AtomicU64; N_PROTO] = [const { AtomicU64::new(0) }; N_PROTO];
static UPSTREAM_FORWARD: [AtomicU64; N_PROTO] = [const { AtomicU64::new(0) }; N_PROTO];
static ACTIVE_CONNECTIONS: [AtomicI64; N_PROTO] = [const { AtomicI64::new(0) }; N_PROTO];
// backend_errors[proto]: backend unreachable or broken while a client waited
// for its auth verdict (outage, not a failed login).
static BACKEND_ERRORS: [AtomicU64; N_PROTO] = [const { AtomicU64::new(0) }; N_PROTO];
// connections_rejected[proto]: dropped at accept by the connection limits.
static CONNECTIONS_REJECTED: [AtomicU64; N_PROTO] = [const { AtomicU64::new(0) }; N_PROTO];

/// Record one auth outcome for `proto` using `mechanism`, tagged by whether the
/// client source was internal (`true`) or external (`false`).
#[inline]
pub fn record_auth(proto: Proto, internal: bool, mechanism: &str, ok: bool) {
    AUTH_ATTEMPTS[proto.idx()][scope_idx(internal)][mech_idx(mechanism)][usize::from(!ok)]
        .fetch_add(1, Ordering::Relaxed);
}

/// Record a refused credential of `proto` with its `authresult` reason.
/// `ok` and `protocol` are not refusals and are ignored.
#[inline]
pub fn record_refusal(proto: Proto, reason: Reason) {
    if let Some(r) = REFUSAL_REASONS.iter().position(|x| *x == reason) {
        AUTH_REFUSALS[proto.idx()][r].fetch_add(1, Ordering::Relaxed);
    }
}

/// Record a connection that aborted BEFORE any credential was presented
/// (pre-auth protocol/TLS failure, portscan, unsupported mechanism). Kept out
/// of `auth_attempts_total` so a rejected login is never confused with scanner
/// noise. The full reason stays in the journal (`authlog`, `reason="protocol"`)
/// for CrowdSec; only the coarse proto/scope split is exposed as a time series.
#[inline]
pub fn record_preauth_abort(proto: Proto, internal: bool) {
    PREAUTH_ABORTS[proto.idx()][scope_idx(internal)].fetch_add(1, Ordering::Relaxed);
}

/// `list` label values of `mail_auth_proxy_legacy_list_errors_total`.
const LIST_LABELS: [&str; 2] = ["users_file", "domains_file"];
// legacy_list_errors[list]: failed re-reads of a legacy list file (missing,
// unreadable or invalid); while failing, the list matches nothing.
static LEGACY_LIST_ERRORS: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];

/// Record a failed re-read of a legacy list file (`users_file` or
/// `domains_file`).
#[inline]
pub fn record_legacy_list_error(list: &str) {
    if let Some(i) = LIST_LABELS.iter().position(|l| *l == list) {
        LEGACY_LIST_ERRORS[i].fetch_add(1, Ordering::Relaxed);
    }
}

/// Record a backend that failed (unreachable, TLS, protocol) during auth.
#[inline]
pub fn record_backend_error(proto: Proto) {
    BACKEND_ERRORS[proto.idx()].fetch_add(1, Ordering::Relaxed);
}

/// Record a connection dropped at accept because a connection limit was hit.
#[inline]
pub fn record_rejected(proto: Proto) {
    CONNECTIONS_REJECTED[proto.idx()].fetch_add(1, Ordering::Relaxed);
}

/// Record one local JWT validation outcome (no remote introspection is done).
#[inline]
pub fn record_token_validate(ok: bool) {
    TOKEN_VALIDATE[usize::from(!ok)].fetch_add(1, Ordering::Relaxed);
}

/// Record that a session was successfully spliced through to its backend.
#[inline]
pub fn record_upstream_forward(proto: Proto) {
    UPSTREAM_FORWARD[proto.idx()].fetch_add(1, Ordering::Relaxed);
}

/// RAII guard: increments the accepted-connection counter and the active-connection
/// gauge on creation, decrements the gauge on drop (runs on every code path).
pub struct ConnGuard(Proto);

impl ConnGuard {
    #[inline]
    pub fn open(proto: Proto) -> ConnGuard {
        CONNECTIONS_TOTAL[proto.idx()].fetch_add(1, Ordering::Relaxed);
        ACTIVE_CONNECTIONS[proto.idx()].fetch_add(1, Ordering::Relaxed);
        ConnGuard(proto)
    }
}

impl Drop for ConnGuard {
    #[inline]
    fn drop(&mut self) {
        ACTIVE_CONNECTIONS[self.0.idx()].fetch_sub(1, Ordering::Relaxed);
    }
}

/// Render the current metric values in Prometheus text exposition format.
fn render() -> String {
    let mut o = String::with_capacity(2048);

    o.push_str("# HELP mail_auth_proxy_build_info Build information.\n");
    o.push_str("# TYPE mail_auth_proxy_build_info gauge\n");
    o.push_str(&format!(
        "mail_auth_proxy_build_info{{version=\"{}\"}} 1\n",
        env!("CARGO_PKG_VERSION")
    ));

    o.push_str("# HELP mail_auth_proxy_auth_attempts_total Auth attempts handled by the proxy (oauth + password).\n");
    o.push_str("# TYPE mail_auth_proxy_auth_attempts_total counter\n");
    for (p, plabel) in PROTO_LABELS.iter().enumerate() {
        for (s, slabel) in SCOPE_LABELS.iter().enumerate() {
            for (m, mlabel) in MECH_LABELS.iter().enumerate() {
                for (r, rlabel) in ["ok", "fail"].iter().enumerate() {
                    let v = AUTH_ATTEMPTS[p][s][m][r].load(Ordering::Relaxed);
                    o.push_str(&format!(
                        "mail_auth_proxy_auth_attempts_total{{proto=\"{plabel}\",scope=\"{slabel}\",mechanism=\"{mlabel}\",result=\"{rlabel}\"}} {v}\n"
                    ));
                }
            }
        }
    }

    o.push_str("# HELP mail_auth_proxy_auth_refusals_total Refused credentials by authresult reason (the fail side of auth_attempts, split by why).\n");
    o.push_str("# TYPE mail_auth_proxy_auth_refusals_total counter\n");
    for (p, plabel) in PROTO_LABELS.iter().enumerate() {
        for (r, reason) in REFUSAL_REASONS.iter().enumerate() {
            let v = AUTH_REFUSALS[p][r].load(Ordering::Relaxed);
            o.push_str(&format!(
                "mail_auth_proxy_auth_refusals_total{{proto=\"{plabel}\",reason=\"{}\"}} {v}\n",
                reason.as_str()
            ));
        }
    }

    o.push_str("# HELP mail_auth_proxy_preauth_aborts_total Connections that failed before a credential was presented (TLS/protocol noise, portscans); NOT rejected logins.\n");
    o.push_str("# TYPE mail_auth_proxy_preauth_aborts_total counter\n");
    for (p, plabel) in PROTO_LABELS.iter().enumerate() {
        for (s, slabel) in SCOPE_LABELS.iter().enumerate() {
            let v = PREAUTH_ABORTS[p][s].load(Ordering::Relaxed);
            o.push_str(&format!(
                "mail_auth_proxy_preauth_aborts_total{{proto=\"{plabel}\",scope=\"{slabel}\"}} {v}\n"
            ));
        }
    }

    o.push_str("# HELP mail_auth_proxy_token_validate_total Local JWT validation outcomes (no remote introspection).\n");
    o.push_str("# TYPE mail_auth_proxy_token_validate_total counter\n");
    for (r, rlabel) in ["ok", "fail"].iter().enumerate() {
        let v = TOKEN_VALIDATE[r].load(Ordering::Relaxed);
        o.push_str(&format!(
            "mail_auth_proxy_token_validate_total{{result=\"{rlabel}\"}} {v}\n"
        ));
    }

    o.push_str("# HELP mail_auth_proxy_connections_total Client connections accepted.\n");
    o.push_str("# TYPE mail_auth_proxy_connections_total counter\n");
    for (p, plabel) in PROTO_LABELS.iter().enumerate() {
        let v = CONNECTIONS_TOTAL[p].load(Ordering::Relaxed);
        o.push_str(&format!(
            "mail_auth_proxy_connections_total{{proto=\"{plabel}\"}} {v}\n"
        ));
    }

    o.push_str("# HELP mail_auth_proxy_backend_errors_total Backend unreachable or failing during auth (outage, not a rejected login).\n");
    o.push_str("# TYPE mail_auth_proxy_backend_errors_total counter\n");
    for (p, plabel) in PROTO_LABELS.iter().enumerate() {
        let v = BACKEND_ERRORS[p].load(Ordering::Relaxed);
        o.push_str(&format!(
            "mail_auth_proxy_backend_errors_total{{proto=\"{plabel}\"}} {v}\n"
        ));
    }

    o.push_str("# HELP mail_auth_proxy_connections_rejected_total Connections dropped at accept by the global or per-IP pre-auth limit.\n");
    o.push_str("# TYPE mail_auth_proxy_connections_rejected_total counter\n");
    for (p, plabel) in PROTO_LABELS.iter().enumerate() {
        let v = CONNECTIONS_REJECTED[p].load(Ordering::Relaxed);
        o.push_str(&format!(
            "mail_auth_proxy_connections_rejected_total{{proto=\"{plabel}\"}} {v}\n"
        ));
    }

    o.push_str("# HELP mail_auth_proxy_legacy_list_errors_total Failed re-reads of a legacy users/domains file; while it fails the list matches nothing.\n");
    o.push_str("# TYPE mail_auth_proxy_legacy_list_errors_total counter\n");
    for (i, label) in LIST_LABELS.iter().enumerate() {
        let v = LEGACY_LIST_ERRORS[i].load(Ordering::Relaxed);
        o.push_str(&format!(
            "mail_auth_proxy_legacy_list_errors_total{{list=\"{label}\"}} {v}\n"
        ));
    }

    o.push_str("# HELP mail_auth_proxy_active_connections Client connections currently open.\n");
    o.push_str("# TYPE mail_auth_proxy_active_connections gauge\n");
    for (p, plabel) in PROTO_LABELS.iter().enumerate() {
        let v = ACTIVE_CONNECTIONS[p].load(Ordering::Relaxed);
        o.push_str(&format!(
            "mail_auth_proxy_active_connections{{proto=\"{plabel}\"}} {v}\n"
        ));
    }

    o.push_str(
        "# HELP mail_auth_proxy_upstream_forward_total Sessions spliced through to a backend.\n",
    );
    o.push_str("# TYPE mail_auth_proxy_upstream_forward_total counter\n");
    for (p, plabel) in PROTO_LABELS.iter().enumerate() {
        let v = UPSTREAM_FORWARD[p].load(Ordering::Relaxed);
        o.push_str(&format!(
            "mail_auth_proxy_upstream_forward_total{{proto=\"{plabel}\"}} {v}\n"
        ));
    }

    o
}

/// The exposition text, for unit tests elsewhere in the crate.
#[cfg(test)]
pub fn render_for_tests() -> String {
    render()
}

/// Serve `/metrics` over a minimal HTTP/1.1 responder on `addr`.
///
/// This owns all of its errors: a bind failure is logged and the task returns,
/// leaving the mail listeners untouched. Per-connection errors are ignored.
pub async fn serve(addr: String) {
    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(target: crate::obs::target::METRICS, %addr, error=%e, "metrics endpoint bind failed; metrics disabled");
            return;
        }
    };
    tracing::info!(target: crate::obs::target::METRICS, %addr, "metrics endpoint up");
    loop {
        match listener.accept().await {
            Ok((sock, _)) => {
                tokio::spawn(async move {
                    let _ = handle_scrape(sock).await;
                });
            }
            Err(e) => {
                tracing::warn!(target: crate::obs::target::METRICS, error=%e, "metrics accept error");
                tokio::time::sleep(crate::server::ACCEPT_BACKOFF).await;
            }
        }
    }
}

/// Deadline for a single scrape. A client that connects and never sends a
/// request (or never drains the response) must not hold the task open.
const SCRAPE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

fn timed_out(what: &str) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        format!("metrics {what} timed out"),
    )
}

async fn handle_scrape(mut sock: tokio::net::TcpStream) -> std::io::Result<()> {
    // Read (and discard) the request head; we serve metrics for any GET.
    let mut buf = [0u8; 1024];
    match tokio::time::timeout(SCRAPE_TIMEOUT, sock.read(&mut buf)).await {
        Ok(r) => {
            r?;
        }
        Err(_) => return Err(timed_out("read")),
    }
    let body = render();
    let resp = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n{}",
        body.len(),
        body
    );
    match tokio::time::timeout(SCRAPE_TIMEOUT, sock.write_all(resp.as_bytes())).await {
        Ok(r) => r?,
        Err(_) => return Err(timed_out("write")),
    }
    let _ = sock.shutdown().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mechanism_bucketing() {
        assert_eq!(mech_idx("XOAUTH2"), 0);
        assert_eq!(mech_idx("xoauth2"), 0);
        assert_eq!(mech_idx("OAUTHBEARER"), 1);
        assert_eq!(mech_idx("PLAIN"), 2);
        assert_eq!(mech_idx("LOGIN"), 3);
        assert_eq!(mech_idx(""), 4);
    }

    #[test]
    fn render_is_valid_exposition_and_reflects_counts() {
        record_auth(Proto::Imap, true, "XOAUTH2", true);
        record_auth(Proto::Smtp, false, "OAUTHBEARER", false);
        record_token_validate(true);
        record_upstream_forward(Proto::Sieve);
        let g = ConnGuard::open(Proto::Imap);

        let out = render();
        // HELP/TYPE headers present for each metric family
        assert!(out.contains("# TYPE mail_auth_proxy_auth_attempts_total counter"));
        assert!(out.contains("# TYPE mail_auth_proxy_active_connections gauge"));
        // Series we just incremented are present and non-zero
        assert!(out.contains("mail_auth_proxy_auth_attempts_total{proto=\"imap\",scope=\"internal\",mechanism=\"xoauth2\",result=\"ok\"} 1"));
        assert!(out.contains("mail_auth_proxy_auth_attempts_total{proto=\"smtp\",scope=\"external\",mechanism=\"oauthbearer\",result=\"fail\"} 1"));
        assert!(out.contains("mail_auth_proxy_upstream_forward_total{proto=\"sieve\"} 1"));
        assert!(out.contains("mail_auth_proxy_active_connections{proto=\"imap\"} 1"));
        assert!(out.contains("mail_auth_proxy_build_info{version="));

        drop(g);
        let out2 = render();
        assert!(out2.contains("mail_auth_proxy_active_connections{proto=\"imap\"} 0"));
    }

    #[test]
    fn refusals_by_reason() {
        record_refusal(Proto::Sieve, Reason::Throttled);
        record_refusal(Proto::Sieve, Reason::Ok);
        record_refusal(Proto::Sieve, Reason::Protocol);
        let out = render();
        assert!(out.contains("# TYPE mail_auth_proxy_auth_refusals_total counter"));
        assert!(out.contains(
            "mail_auth_proxy_auth_refusals_total{proto=\"sieve\",reason=\"throttled\"} 1"
        ));
        assert!(out.contains(
            "mail_auth_proxy_auth_refusals_total{proto=\"imap\",reason=\"authzid_mismatch\"} "
        ));
        assert!(!out.contains("reason=\"ok\"") && !out.contains("reason=\"protocol\""));
    }

    #[test]
    fn preauth_abort_is_separate_from_auth_fail() {
        // A pre-auth abort must land in its own series, never inflate the
        // per-mechanism auth-fail bucket that the "failed logins" panels read.
        record_preauth_abort(Proto::Imap, false);
        let out = render();
        assert!(out.contains("# TYPE mail_auth_proxy_preauth_aborts_total counter"));
        assert!(out
            .contains("mail_auth_proxy_preauth_aborts_total{proto=\"imap\",scope=\"external\"} 1"));
    }
}
