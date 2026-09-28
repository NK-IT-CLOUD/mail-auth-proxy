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
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

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

// Accounts whose live throttle window was dropped because the table was full.
static THROTTLE_EVICTIONS: AtomicU64 = AtomicU64::new(0);

/// Record that the full throttle table dropped an account whose failure
/// window was still running (its count starts over).
#[inline]
pub fn record_throttle_eviction() {
    THROTTLE_EVICTIONS.fetch_add(1, Ordering::Relaxed);
}

// ratelimit_blocks[proto]: connections closed at accept because their
// source is blocked by the auth rate limit.
static RATELIMIT_BLOCKS: [AtomicU64; N_PROTO] = [const { AtomicU64::new(0) }; N_PROTO];
// Blocks started (a source reached the failure threshold).
static RATELIMIT_BANS: AtomicU64 = AtomicU64::new(0);
// Sources blocked right now, as of the last sweep or block.
static RATELIMIT_ACTIVE: AtomicU64 = AtomicU64::new(0);
// Sources dropped from the full rate-limit table while still counted.
static RATELIMIT_EVICTIONS: AtomicU64 = AtomicU64::new(0);

/// Record a connection closed at accept because its source is blocked.
#[inline]
pub fn record_ratelimit_block(proto: Proto) {
    RATELIMIT_BLOCKS[proto.idx()].fetch_add(1, Ordering::Relaxed);
}

/// Record a block that started; `active` is the number of blocked sources.
#[inline]
pub fn record_ratelimit_ban(active: u64) {
    RATELIMIT_BANS.fetch_add(1, Ordering::Relaxed);
    RATELIMIT_ACTIVE.store(active, Ordering::Relaxed);
}

/// Set the number of blocked sources (after a sweep).
#[inline]
pub fn set_ratelimit_active(active: u64) {
    RATELIMIT_ACTIVE.store(active, Ordering::Relaxed);
}

/// Record sources dropped from the full rate-limit table.
#[inline]
pub fn record_ratelimit_evictions(n: u64) {
    RATELIMIT_EVICTIONS.fetch_add(n, Ordering::Relaxed);
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

/// `le` label values of the latency histogram and the same bounds in
/// microseconds: from a local backend (a few ms) up to the connect timeout.
const LATENCY_LE: [&str; 11] = [
    "0.005", "0.01", "0.025", "0.05", "0.1", "0.25", "0.5", "1", "2.5", "5", "10",
];
const LATENCY_US: [u64; 11] = [
    5_000, 10_000, 25_000, 50_000, 100_000, 250_000, 500_000, 1_000_000, 2_500_000, 5_000_000,
    10_000_000,
];

/// A fixed-bucket histogram of atomics. `counts` are per bucket (not
/// cumulative), the last one is `+Inf`; `render` accumulates.
struct Histogram {
    counts: [AtomicU64; LATENCY_US.len() + 1],
    sum_us: AtomicU64,
}

impl Histogram {
    const fn new() -> Histogram {
        Histogram {
            counts: [const { AtomicU64::new(0) }; LATENCY_US.len() + 1],
            sum_us: AtomicU64::new(0),
        }
    }

    #[inline]
    fn observe(&self, d: std::time::Duration) {
        let us = u64::try_from(d.as_micros()).unwrap_or(u64::MAX);
        let i = LATENCY_US.partition_point(|b| *b < us);
        self.counts[i].fetch_add(1, Ordering::Relaxed);
        self.sum_us.fetch_add(us, Ordering::Relaxed);
    }

    /// Append the `_bucket`, `_sum` and `_count` samples of `name` with the
    /// leading `labels` (`proto="imap",`).
    fn render(&self, o: &mut String, name: &str, labels: &str) {
        let mut cum = 0;
        for (i, le) in LATENCY_LE.iter().chain(["+Inf"].iter()).enumerate() {
            cum += self.counts[i].load(Ordering::Relaxed);
            o.push_str(&format!("{name}_bucket{{{labels}le=\"{le}\"}} {cum}\n"));
        }
        let sum = self.sum_us.load(Ordering::Relaxed) as f64 / 1e6;
        let labels = labels.trim_end_matches(',');
        o.push_str(&format!("{name}_sum{{{labels}}} {sum}\n"));
        o.push_str(&format!("{name}_count{{{labels}}} {cum}\n"));
    }
}

// backend_login[proto]: time from the start of the backend connection to its
// accepting the credential, for logins that succeeded.
static BACKEND_LOGIN: [Histogram; N_PROTO] = [const { Histogram::new() }; N_PROTO];

/// Record how long a successful backend login took (connect, TLS, PROXY
/// header or XCLIENT, and the AUTH exchange).
#[inline]
pub fn record_backend_login(proto: Proto, took: std::time::Duration) {
    BACKEND_LOGIN[proto.idx()].observe(took);
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

/// JWKS state of one configured issuer.
struct IssuerStats {
    issuer: String,
    /// Unix time (s) of the last fetch that produced usable keys.
    last_success: AtomicU64,
    /// Fetches that failed or produced no usable key.
    failures: AtomicU64,
}

// The configured issuers, set once at startup; the label set is fixed then.
static ISSUERS: std::sync::OnceLock<Vec<IssuerStats>> = std::sync::OnceLock::new();

/// Register the configured issuers (the `issuer` label values of the JWKS
/// metrics). Only the first call counts.
pub fn register_issuers<'a>(issuers: impl IntoIterator<Item = &'a str>) {
    let _ = ISSUERS.set(
        issuers
            .into_iter()
            .map(|i| IssuerStats {
                issuer: i.to_string(),
                last_success: AtomicU64::new(0),
                failures: AtomicU64::new(0),
            })
            .collect(),
    );
}

/// Record one JWKS fetch of `issuer`: `ok` when it produced usable keys.
/// An issuer that was not registered is ignored.
pub fn record_jwks_fetch(issuer: &str, ok: bool) {
    let Some(s) = ISSUERS
        .get()
        .and_then(|v| v.iter().find(|s| s.issuer == issuer))
    else {
        return;
    };
    if ok {
        s.last_success.store(unix_now(), Ordering::Relaxed);
    } else {
        s.failures.fetch_add(1, Ordering::Relaxed);
    }
}

// notAfter (Unix s) of the client-facing certificate in use; 0 until loaded
// or when it cannot be read.
static CERT_NOT_AFTER: AtomicU64 = AtomicU64::new(0);

/// Record the `notAfter` of the certificate now served (Unix seconds, 0 if
/// unknown).
pub fn set_cert_not_after(unix: u64) {
    CERT_NOT_AFTER.store(unix, Ordering::Relaxed);
}

// Unix time (s) the server started; see `mark_process_start`.
static PROCESS_START: AtomicU64 = AtomicU64::new(0);

/// Seconds since the Unix epoch (0 for a clock before it).
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Record now as `process_start_time_seconds`; called once when the server
/// starts, so a restart shows as a new value.
pub fn mark_process_start() {
    PROCESS_START.store(unix_now(), Ordering::Relaxed);
}

/// A label value escaped for the text exposition format: backslash, double
/// quote and line feed.
fn escape_label(v: &str) -> String {
    let mut o = String::with_capacity(v.len());
    for c in v.chars() {
        match c {
            '\\' => o.push_str("\\\\"),
            '"' => o.push_str("\\\""),
            '\n' => o.push_str("\\n"),
            c => o.push(c),
        }
    }
    o
}

/// Render the current metric values in Prometheus text exposition format.
fn render() -> String {
    let mut o = String::with_capacity(2048);

    o.push_str("# HELP mail_auth_proxy_build_info Build information.\n");
    o.push_str("# TYPE mail_auth_proxy_build_info gauge\n");
    o.push_str(&format!(
        "mail_auth_proxy_build_info{{version=\"{}\",commit=\"{}\"}} 1\n",
        escape_label(env!("CARGO_PKG_VERSION")),
        escape_label(option_env!("MAIL_AUTH_PROXY_COMMIT").unwrap_or("unknown"))
    ));

    o.push_str("# HELP process_start_time_seconds Start time of the process since unix epoch in seconds.\n");
    o.push_str("# TYPE process_start_time_seconds gauge\n");
    o.push_str(&format!(
        "process_start_time_seconds {}\n",
        PROCESS_START.load(Ordering::Relaxed)
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

    o.push_str("# HELP mail_auth_proxy_legacy_throttle_evictions_total Accounts dropped from the full throttle table while their failure window was running.\n");
    o.push_str("# TYPE mail_auth_proxy_legacy_throttle_evictions_total counter\n");
    o.push_str(&format!(
        "mail_auth_proxy_legacy_throttle_evictions_total {}\n",
        THROTTLE_EVICTIONS.load(Ordering::Relaxed)
    ));

    o.push_str("# HELP mail_auth_proxy_ratelimit_blocks_total Connections closed at accept because the source is blocked after too many failed logins.\n");
    o.push_str("# TYPE mail_auth_proxy_ratelimit_blocks_total counter\n");
    for (p, plabel) in PROTO_LABELS.iter().enumerate() {
        let v = RATELIMIT_BLOCKS[p].load(Ordering::Relaxed);
        o.push_str(&format!(
            "mail_auth_proxy_ratelimit_blocks_total{{proto=\"{plabel}\"}} {v}\n"
        ));
    }
    o.push_str("# HELP mail_auth_proxy_ratelimit_bans_total Sources blocked after reaching the failed-login threshold.\n");
    o.push_str("# TYPE mail_auth_proxy_ratelimit_bans_total counter\n");
    o.push_str(&format!(
        "mail_auth_proxy_ratelimit_bans_total {}\n",
        RATELIMIT_BANS.load(Ordering::Relaxed)
    ));
    o.push_str("# HELP mail_auth_proxy_ratelimit_active_blocks Sources blocked now (updated every few seconds).\n");
    o.push_str("# TYPE mail_auth_proxy_ratelimit_active_blocks gauge\n");
    o.push_str(&format!(
        "mail_auth_proxy_ratelimit_active_blocks {}\n",
        RATELIMIT_ACTIVE.load(Ordering::Relaxed)
    ));
    o.push_str("# HELP mail_auth_proxy_ratelimit_evictions_total Sources dropped from the full rate-limit table while counted or blocked.\n");
    o.push_str("# TYPE mail_auth_proxy_ratelimit_evictions_total counter\n");
    o.push_str(&format!(
        "mail_auth_proxy_ratelimit_evictions_total {}\n",
        RATELIMIT_EVICTIONS.load(Ordering::Relaxed)
    ));

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

    o.push_str("# HELP mail_auth_proxy_tls_cert_expiry_timestamp_seconds Unix time the served certificate expires (notAfter); 0 if unreadable.\n");
    o.push_str("# TYPE mail_auth_proxy_tls_cert_expiry_timestamp_seconds gauge\n");
    o.push_str(&format!(
        "mail_auth_proxy_tls_cert_expiry_timestamp_seconds {}\n",
        CERT_NOT_AFTER.load(Ordering::Relaxed)
    ));

    let issuers = ISSUERS.get().map_or(&[][..], |v| &v[..]);
    o.push_str("# HELP mail_auth_proxy_jwks_last_success_timestamp_seconds Unix time of the last JWKS fetch with usable keys, by issuer.\n");
    o.push_str("# TYPE mail_auth_proxy_jwks_last_success_timestamp_seconds gauge\n");
    for s in issuers {
        o.push_str(&format!(
            "mail_auth_proxy_jwks_last_success_timestamp_seconds{{issuer=\"{}\"}} {}\n",
            escape_label(&s.issuer),
            s.last_success.load(Ordering::Relaxed)
        ));
    }
    o.push_str("# HELP mail_auth_proxy_jwks_refresh_failures_total JWKS fetches that failed or had no usable key; the issuer keeps its previous keys.\n");
    o.push_str("# TYPE mail_auth_proxy_jwks_refresh_failures_total counter\n");
    for s in issuers {
        o.push_str(&format!(
            "mail_auth_proxy_jwks_refresh_failures_total{{issuer=\"{}\"}} {}\n",
            escape_label(&s.issuer),
            s.failures.load(Ordering::Relaxed)
        ));
    }

    o.push_str("# HELP mail_auth_proxy_backend_login_duration_seconds Time of successful backend logins: connect, TLS, PROXY/XCLIENT and AUTH.\n");
    o.push_str("# TYPE mail_auth_proxy_backend_login_duration_seconds histogram\n");
    for (p, plabel) in PROTO_LABELS.iter().enumerate() {
        BACKEND_LOGIN[p].render(
            &mut o,
            "mail_auth_proxy_backend_login_duration_seconds",
            &format!("proto=\"{plabel}\","),
        );
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
    serve_on(listener).await;
}

/// Scrapes served at the same time. Prometheus scrapes a target one request
/// at a time, so this covers a redundant pair and a manual check; more
/// connections are closed at accept, unanswered and unlogged, so neither a
/// connection flood nor a scanner grows tasks, memory or the journal.
const MAX_SCRAPES: usize = 4;

/// Largest request head read; a longer one is answered 431.
const MAX_REQUEST_HEAD: usize = 4096;

/// Deadline for the whole request head, and separately for the response. A
/// client that sends its request a byte at a time (or never drains the
/// response) loses its connection after this, whatever it does meanwhile.
const SCRAPE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

async fn serve_on(listener: TcpListener) {
    let slots = Arc::new(Semaphore::new(MAX_SCRAPES));
    loop {
        match listener.accept().await {
            Ok((sock, _)) => {
                let Ok(slot) = slots.clone().try_acquire_owned() else {
                    drop(sock);
                    continue;
                };
                tokio::spawn(async move {
                    let _slot = slot;
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

fn timed_out(what: &str) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        format!("metrics {what} timed out"),
    )
}

async fn handle_scrape(mut sock: TcpStream) -> std::io::Result<()> {
    let mut head = Vec::with_capacity(512);
    let complete = match tokio::time::timeout(SCRAPE_TIMEOUT, read_head(&mut sock, &mut head)).await
    {
        Ok(r) => r?,
        Err(_) => return Err(timed_out("read")),
    };
    let resp = if complete {
        respond(&head)
    } else {
        reply(
            "431 Request Header Fields Too Large",
            "",
            "request head too large\n",
        )
    };
    match tokio::time::timeout(SCRAPE_TIMEOUT, sock.write_all(resp.as_bytes())).await {
        Ok(r) => r?,
        Err(_) => return Err(timed_out("write")),
    }
    let _ = sock.shutdown().await;
    Ok(())
}

/// Read the request head into `head`, up to the empty line that ends it.
/// `false` when it grows past `MAX_REQUEST_HEAD` first; an EOF before the
/// end is an error (nothing is answered).
async fn read_head(sock: &mut TcpStream, head: &mut Vec<u8>) -> std::io::Result<bool> {
    let mut buf = [0u8; 1024];
    loop {
        let n = sock.read(&mut buf).await?;
        if n == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        head.extend_from_slice(&buf[..n]);
        // CRLF, or a bare LF (RFC 9112 §2.2 lets a recipient accept it).
        if head.windows(2).any(|w| w == b"\n\n") || head.windows(3).any(|w| w == b"\n\r\n") {
            return Ok(true);
        }
        if head.len() >= MAX_REQUEST_HEAD {
            return Ok(false);
        }
    }
}

/// The response to a complete request head: the exposition text for
/// `GET /metrics` (with or without a query), 404 for any other path, 405 for
/// another method on `/metrics`, 400 for a request line that is not HTTP/1.x.
fn respond(head: &[u8]) -> String {
    let line = head.split(|&b| b == b'\n').next().unwrap_or_default();
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let mut parts = line.split(|&b| b == b' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return reply("400 Bad Request", "", "bad request\n");
    };
    if version != b"HTTP/1.1" && version != b"HTTP/1.0" {
        return reply("400 Bad Request", "", "bad request\n");
    }
    let path = target.split(|&b| b == b'?').next().unwrap_or_default();
    if path != b"/metrics" {
        return reply("404 Not Found", "", "not found\n");
    }
    if method != b"GET" {
        return reply(
            "405 Method Not Allowed",
            "Allow: GET\r\n",
            "method not allowed\n",
        );
    }
    let body = render();
    format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    )
}

/// A plain-text error response; `extra` is further header lines.
fn reply(status: &str, extra: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         {extra}Connection: close\r\n\r\n{body}",
        body.len()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Status line, headers and body of a response; checks Content-Length.
    fn parse_response(r: &str) -> (&str, Vec<&str>, &str) {
        let (head, body) = r.split_once("\r\n\r\n").unwrap();
        let mut lines = head.split("\r\n");
        let status = lines.next().unwrap();
        let headers: Vec<&str> = lines.collect();
        let len = headers
            .iter()
            .find_map(|h| h.strip_prefix("Content-Length: "))
            .unwrap();
        assert_eq!(len.parse::<usize>().unwrap(), body.len(), "{r}");
        assert!(headers.contains(&"Connection: close"), "{r}");
        (status, headers, body)
    }

    #[test]
    fn routes_only_get_metrics() {
        let ok = respond(b"GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n");
        let (s, h, body) = parse_response(&ok);
        assert_eq!(s, "HTTP/1.1 200 OK");
        assert!(h.contains(&"Content-Type: text/plain; version=0.0.4; charset=utf-8"));
        assert!(body.starts_with("# HELP mail_auth_proxy_"));
        // A query (Prometheus `params`), HTTP/1.0 and bare LF are fine.
        for req in [
            &b"GET /metrics?x=1 HTTP/1.1\r\n\r\n"[..],
            b"GET /metrics HTTP/1.0\r\n\r\n",
            b"GET /metrics HTTP/1.1\n\n",
        ] {
            assert_eq!(parse_response(&respond(req)).0, "HTTP/1.1 200 OK");
        }

        let cases: [(&[u8], &str); 9] = [
            (b"GET / HTTP/1.1\r\n\r\n", "HTTP/1.1 404 Not Found"),
            (b"GET /metricsx HTTP/1.1\r\n\r\n", "HTTP/1.1 404 Not Found"),
            (
                b"GET /../metrics HTTP/1.1\r\n\r\n",
                "HTTP/1.1 404 Not Found",
            ),
            (
                b"POST /metrics HTTP/1.1\r\n\r\n",
                "HTTP/1.1 405 Method Not Allowed",
            ),
            (
                b"HEAD /metrics HTTP/1.1\r\n\r\n",
                "HTTP/1.1 405 Method Not Allowed",
            ),
            (
                b"get /metrics HTTP/1.1\r\n\r\n",
                "HTTP/1.1 405 Method Not Allowed",
            ),
            (b"GET /metrics\r\n\r\n", "HTTP/1.1 400 Bad Request"),
            (b"GET /metrics HTTP/2.0\r\n\r\n", "HTTP/1.1 400 Bad Request"),
            (
                b"GET  /metrics HTTP/1.1\r\n\r\n",
                "HTTP/1.1 400 Bad Request",
            ),
        ];
        for (req, want) in cases {
            let resp = respond(req);
            let (status, headers, body) = parse_response(&resp);
            assert_eq!(status, want, "{}", String::from_utf8_lossy(req));
            // Error bodies are fixed texts: nothing of the request or the
            // process is echoed.
            assert!(!body.contains("mail_auth_proxy"), "{resp}");
            assert_eq!(
                headers.contains(&"Allow: GET"),
                want.contains("405"),
                "{resp}"
            );
        }
    }

    #[test]
    fn histogram_buckets_are_cumulative_and_inclusive() {
        use std::time::Duration;
        let h = Histogram::new();
        h.observe(Duration::from_micros(5_000)); // on the bound: le="0.005"
        h.observe(Duration::from_micros(5_001)); // le="0.01"
        h.observe(Duration::from_secs(3)); // le="5"
        h.observe(Duration::from_secs(60)); // +Inf only
        let mut o = String::new();
        h.render(&mut o, "x", "proto=\"imap\",");
        let get = |k: &str| -> String {
            o.lines()
                .find_map(|l| l.strip_prefix(k).and_then(|r| r.strip_prefix(' ')))
                .unwrap_or_else(|| panic!("{k} in {o}"))
                .to_string()
        };
        assert_eq!(get("x_bucket{proto=\"imap\",le=\"0.005\"}"), "1");
        assert_eq!(get("x_bucket{proto=\"imap\",le=\"0.01\"}"), "2");
        assert_eq!(get("x_bucket{proto=\"imap\",le=\"2.5\"}"), "2");
        assert_eq!(get("x_bucket{proto=\"imap\",le=\"5\"}"), "3");
        assert_eq!(get("x_bucket{proto=\"imap\",le=\"10\"}"), "3");
        assert_eq!(get("x_bucket{proto=\"imap\",le=\"+Inf\"}"), "4");
        assert_eq!(get("x_count{proto=\"imap\"}"), "4");
        assert_eq!(get("x_sum{proto=\"imap\"}"), "63.010001");
    }

    #[test]
    fn label_values_are_escaped() {
        assert_eq!(escape_label("plain"), "plain");
        assert_eq!(escape_label("a\\b\"c\nd"), "a\\\\b\\\"c\\nd");
    }

    /// Text format 0.0.4 checked line by line: every family has one HELP and
    /// one TYPE line before its samples, families are contiguous and appear
    /// once, sample names belong to their family (histograms: `_bucket`,
    /// `_sum`, `_count`), counters end in `_total` and nothing else does, no
    /// series appears twice, label values are quoted and escaped, values
    /// parse as numbers.
    #[test]
    fn exposition_is_well_formed() {
        // An issuer label that needs escaping (the only free-text label).
        let issuer = "https://idp.test/\"realm\"\\x";
        register_issuers([issuer]);
        record_jwks_fetch(issuer, false);
        record_jwks_fetch("https://unregistered.test", false);
        let out = render();
        assert!(out.contains(
            "mail_auth_proxy_jwks_refresh_failures_total{issuer=\"https://idp.test/\\\"realm\\\"\\\\x\"} 1\n"
        ));
        assert!(!out.contains("unregistered"));
        assert!(out.ends_with('\n'));
        let mut families: Vec<(String, String)> = Vec::new();
        let mut series = std::collections::HashSet::new();
        let mut help = None::<String>;
        for line in out.lines() {
            if let Some(rest) = line.strip_prefix("# HELP ") {
                let (name, text) = rest.split_once(' ').unwrap();
                assert!(!text.is_empty() && !text.contains('\\'), "{line}");
                assert!(families.iter().all(|(n, _)| n != name), "{name} twice");
                help = Some(name.to_string());
                continue;
            }
            if let Some(rest) = line.strip_prefix("# TYPE ") {
                let (name, kind) = rest.split_once(' ').unwrap();
                assert_eq!(help.take().as_deref(), Some(name), "TYPE without HELP");
                assert!(["counter", "gauge", "histogram"].contains(&kind), "{line}");
                assert_eq!(kind == "counter", name.ends_with("_total"), "{line}");
                families.push((name.to_string(), kind.to_string()));
                continue;
            }
            assert!(!line.starts_with('#') && !line.is_empty(), "{line:?}");
            let (name, kind) = families.last().expect("sample before TYPE");
            let (key, value) = line.rsplit_once(' ').unwrap();
            assert!(value.parse::<f64>().is_ok(), "{line}");
            let metric = key.split('{').next().unwrap();
            let allowed = if kind == "histogram" {
                ["_bucket", "_sum", "_count"]
                    .iter()
                    .any(|s| metric.strip_suffix(s) == Some(name.as_str()))
            } else {
                metric == name
            };
            assert!(allowed, "{metric} in family {name}");
            assert!(
                metric
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_'),
                "{metric}"
            );
            if let Some(labels) = key.strip_prefix(metric) {
                if !labels.is_empty() {
                    let inner = labels.strip_prefix('{').unwrap().strip_suffix('}').unwrap();
                    // name="value" pairs; a value may hold escaped quotes.
                    let mut rest = inner;
                    while !rest.is_empty() {
                        let (lname, after) = rest.split_once("=\"").unwrap();
                        assert!(lname.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'));
                        let mut end = None;
                        let mut esc = false;
                        for (i, c) in after.char_indices() {
                            match (esc, c) {
                                (true, '\\' | '"' | 'n') => esc = false,
                                (true, _) => panic!("bad escape in {line}"),
                                (false, '\\') => esc = true,
                                (false, '"') => {
                                    end = Some(i);
                                    break;
                                }
                                (false, _) => {}
                            }
                        }
                        let end = end.expect("unterminated label value");
                        rest = after[end + 1..]
                            .strip_prefix(',')
                            .unwrap_or(&after[end + 1..]);
                    }
                }
            }
            assert!(series.insert(key.to_string()), "{key} twice");
        }
        assert!(help.is_none(), "HELP without TYPE");
    }

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

    /// The connection gauge goes back down when the session task panics or
    /// is cancelled (aborted at shutdown), not only on a normal return. Only
    /// this test uses `Proto::Sieve` guards, so the value is its own.
    #[tokio::test]
    async fn active_gauge_survives_panic_and_cancel() {
        let active = || ACTIVE_CONNECTIONS[Proto::Sieve.idx()].load(Ordering::Relaxed);
        assert_eq!(active(), 0);

        let panicked = tokio::spawn(async {
            let _g = ConnGuard::open(Proto::Sieve);
            tokio::task::yield_now().await;
            panic!("session bug");
        });
        assert!(panicked.await.unwrap_err().is_panic());
        assert_eq!(active(), 0);

        let (opened, is_open) = tokio::sync::oneshot::channel();
        let pending = tokio::spawn(async move {
            let _g = ConnGuard::open(Proto::Sieve);
            let _ = opened.send(());
            std::future::pending::<()>().await;
        });
        is_open.await.unwrap();
        assert_eq!(active(), 1);
        pending.abort();
        assert!(pending.await.unwrap_err().is_cancelled());
        assert_eq!(active(), 0);
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
