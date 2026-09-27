//! Observability: auth-outcome log lines and Prometheus metrics.

pub mod authlog;
pub mod metrics;

/// Log targets. They are part of the log format (`RUST_LOG` filters and log
/// parsers select on them), so they are fixed here instead of following the
/// module layout.
pub mod target {
    /// Startup, listeners, backend trust store and IMAP sessions.
    pub const MAIN: &str = "mail_auth_proxy";
    /// JWKS fetching and refreshing.
    pub const TOKEN: &str = "mail_auth_proxy::token";
    /// The post-auth byte relay.
    pub const RELAY: &str = "mail_auth_proxy::proto";
    /// SMTP submission sessions.
    pub const SUBMISSION: &str = "mail_auth_proxy::submission";
    /// ManageSieve sessions.
    pub const SIEVE: &str = "mail_auth_proxy::sieve";
    /// The Prometheus endpoint.
    pub const METRICS: &str = "mail_auth_proxy::metrics";
}
