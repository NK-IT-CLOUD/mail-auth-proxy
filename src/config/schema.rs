//! Schema: the serde types of format 2, their defaults, and what
//! `--print-config` leaves out.

use serde::{Deserialize, Serialize};

pub const CONFIG_VERSION: u32 = 2;

/// Algorithms accepted when an issuer does not restrict them. Symmetric (HS*)
/// algorithms are never accepted: the proxy holds no shared secret.
pub const DEFAULT_ALGORITHMS: &[&str] = &[
    "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384",
];

/// ESMTP extensions advertised after STARTTLS, besides AUTH. The client keeps
/// this view for the whole session (it does not send EHLO again after AUTH),
/// so the list must match what the backend offers. These are Postfix defaults.
pub const DEFAULT_EHLO_EXTENSIONS: &[&str] = &[
    "PIPELINING",
    "ENHANCEDSTATUSCODES",
    "8BITMIME",
    "DSN",
    "SMTPUTF8",
    "CHUNKING",
];

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub config_version: u32,
    #[serde(default)]
    pub server: Server,
    pub tls: Tls,
    pub imap: Imap,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub submission: Option<Submission>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sieve: Option<Sieve>,
    pub oauth: OAuth,
    /// Short form of one legacy rule (`sni` + `internal_networks`). Read only:
    /// after parsing it is translated into `legacy.rules` and `scope`, which
    /// is what `--print-config` shows.
    #[serde(default, skip_serializing)]
    pub password_gate: Option<PasswordGate>,
    /// The internal/external label of logs and metrics.
    #[serde(default, skip_serializing_if = "Scope::is_empty")]
    pub scope: Scope,
    /// The legacy (PLAIN/LOGIN) gate. Without rules every endpoint is
    /// OAuth-only.
    #[serde(default, skip_serializing_if = "Legacy::is_unset")]
    pub legacy: Legacy,
    #[serde(default)]
    pub limits: Limits,
    #[serde(default)]
    pub timeouts: Timeouts,
    #[serde(default)]
    pub metrics: Metrics,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Server {
    /// Name in the protocol greetings, EHLO replies and the backend EHLO.
    #[serde(default = "default_hostname")]
    pub hostname: String,
}

impl Default for Server {
    fn default() -> Self {
        Server {
            hostname: default_hostname(),
        }
    }
}

fn default_hostname() -> String {
    "mail-auth-proxy".into()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Tls {
    /// PEM certificate chain served to clients.
    pub cert: String,
    /// PEM private key.
    pub key: String,
}

/// A backend the proxy logs in to with the client's own credential.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Backend {
    /// `host:port`.
    pub address: String,
    /// Name verified on the backend certificate; default: host of `address`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verify_name: Option<String>,
    /// PEM file with the CA(s) the backend certificate must chain to. Replaces
    /// the system trust store for this backend; default: system store.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_file: Option<String>,
    /// Send a PROXY protocol v2 header with the client's address (IMAP and
    /// ManageSieve backends only). The backend listener must require it.
    #[serde(default)]
    pub proxy_protocol: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Imap {
    /// Implicit-TLS listener, e.g. `0.0.0.0:993`.
    pub listen: String,
    /// Implicit-TLS backend.
    pub backend: Backend,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Submission {
    /// STARTTLS listener, e.g. `0.0.0.0:587`.
    pub listen: String,
    /// STARTTLS backend (Postfix submission).
    pub backend: Backend,
    /// Announce the client address with XCLIENT when the backend offers it.
    #[serde(default)]
    pub xclient: bool,
    /// Extensions advertised after STARTTLS besides AUTH.
    #[serde(default = "default_ehlo_extensions")]
    pub ehlo_extensions: Vec<String>,
}

fn default_ehlo_extensions() -> Vec<String> {
    DEFAULT_EHLO_EXTENSIONS
        .iter()
        .map(|s| s.to_string())
        .collect()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Sieve {
    /// STARTTLS listener, e.g. `0.0.0.0:4190`.
    pub listen: String,
    /// STARTTLS backend (Pigeonhole ManageSieve).
    pub backend: Backend,
    /// How long the backend's capability list is reused.
    #[serde(default = "default_caps_cache_secs")]
    pub capability_cache_secs: u64,
}

fn default_caps_cache_secs() -> u64 {
    600
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OAuth {
    /// Periodic JWKS refresh.
    #[serde(default = "default_refresh_secs")]
    pub refresh_secs: u64,
    /// Clock skew tolerated on `exp` and `nbf`.
    #[serde(default = "default_leeway_secs")]
    pub leeway_secs: u64,
    pub issuers: Vec<Issuer>,
}

fn default_refresh_secs() -> u64 {
    300
}

fn default_leeway_secs() -> u64 {
    60
}

/// How an access token is told apart from other JWTs of the same issuer
/// (ID tokens can carry the same audience).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TokenType {
    /// Claim `typ` = `Bearer` (Keycloak).
    Keycloak,
    /// JWT header `typ` = `at+jwt` (RFC 9068).
    Rfc9068,
    /// No check. Only for IdPs that mark access tokens neither way.
    Any,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Issuer {
    /// Exact `iss` value; keys from `jwks_url` are accepted only with it.
    pub issuer: String,
    /// https URL of the issuer's JWKS (http only for localhost).
    pub jwks_url: String,
    /// Accepted `aud` values; the token must contain at least one.
    pub audiences: Vec<String>,
    /// How access tokens are recognised. No default: the right value depends
    /// on the IdP, and a wrong one either rejects everything or lets ID tokens in.
    pub token_type: TokenType,
    /// Claim that names the mailbox; forwarded to the backend as the login.
    #[serde(default = "default_identity_claim")]
    pub identity_claim: String,
    /// Require `email_verified = true`. Default: on when `identity_claim` is `email`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_email_verified: Option<bool>,
    /// Signature algorithms accepted from this issuer.
    #[serde(default = "default_algorithms")]
    pub allowed_algorithms: Vec<String>,
    /// Use JWKS keys without `alg` with the one algorithm their key type
    /// implies (ES256, ES384, RS256; within `allowed_algorithms`). Off: such
    /// keys are skipped.
    #[serde(default = "default_true")]
    pub infer_key_algorithm: bool,
    /// If not empty, only tokens whose `client_claim` is listed are accepted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_clients: Vec<String>,
    /// Claim naming the OAuth client (`azp` for Keycloak/OIDC, `client_id`, `appid`).
    #[serde(default = "default_client_claim")]
    pub client_claim: String,
}

impl Issuer {
    /// `require_email_verified` with its default applied.
    pub fn requires_email_verified(&self) -> bool {
        self.require_email_verified
            .unwrap_or(self.identity_claim == "email")
    }
}

fn default_identity_claim() -> String {
    "email".into()
}

fn default_algorithms() -> Vec<String> {
    DEFAULT_ALGORITHMS.iter().map(|s| s.to_string()).collect()
}

fn default_true() -> bool {
    true
}

fn default_client_claim() -> String {
    "azp".into()
}

/// The short form of one legacy rule. `enabled`
/// means one rule named `password_gate`: passwords only if the client asked
/// for one of `sni` AND comes from `internal_networks`. The networks also set
/// the scope label when `[scope]` is absent.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PasswordGate {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub sni: Vec<String>,
    #[serde(default)]
    pub internal_networks: Vec<String>,
}

/// Name of the rule the `[password_gate]` short form stands for.
pub const PASSWORD_GATE_RULE: &str = "password_gate";

/// Networks whose clients are labelled `internal` in logs and metrics. A
/// label only: it allows nothing.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    #[serde(default)]
    pub internal_networks: Vec<String>,
}

impl Scope {
    fn is_empty(&self) -> bool {
        self.internal_networks.is_empty()
    }
}

/// How the legacy gate checks that an account exists before a password is
/// forwarded.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AccountCheck {
    /// No check: the backend's verdict alone.
    #[default]
    None,
    /// A userdb lookup over the Dovecot doveadm HTTP API.
    Doveadm,
}

/// Failed backend logins per account before further attempts are refused
/// without asking the backend, for the rest of the window.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Throttle {
    pub failures: u32,
    pub window_secs: u64,
}

/// Legacy mail (PLAIN/LOGIN). No SSO, no token: the backend checks the
/// password. The proxy forwards it only when a rule matches, the domain is
/// allowed and the account exists (each check only when configured).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Legacy {
    /// Domains whose users may use passwords (with `domains_file`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_domains: Vec<String>,
    /// File with one allowed domain per line (`#` comments); re-read when it
    /// changes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domains_file: Option<String>,
    #[serde(default, skip_serializing_if = "is_default")]
    pub account_check: AccountCheck,
    /// doveadm HTTP API endpoint, e.g. `https://mail.example.org:8080/doveadm/v1`
    /// (http only for localhost).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doveadm_url: Option<String>,
    /// File holding the doveadm API key (`doveadm_api_key`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doveadm_key_file: Option<String>,
    /// PEM CA(s) for the doveadm certificate; default: system trust store.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doveadm_ca_file: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub throttle: Option<Throttle>,
    /// Minimum time before a failed legacy login is answered, counted from
    /// the credential. Refusals by the gate also wait as long as the median
    /// recent backend rejection, and both get random jitter, so a refusal
    /// is as slow as a wrong password.
    #[serde(default = "default_failure_delay_ms")]
    pub failure_delay_ms: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<Rule>,
}

impl Default for Legacy {
    fn default() -> Self {
        Legacy {
            allowed_domains: Vec::new(),
            domains_file: None,
            account_check: AccountCheck::None,
            doveadm_url: None,
            doveadm_key_file: None,
            doveadm_ca_file: None,
            throttle: None,
            failure_delay_ms: default_failure_delay_ms(),
            rules: Vec::new(),
        }
    }
}

impl Legacy {
    /// Nothing but defaults: not printed.
    fn is_unset(&self) -> bool {
        self.rules.is_empty() && !self.has_settings()
    }

    /// Any setting besides the rules.
    pub(super) fn has_settings(&self) -> bool {
        !self.allowed_domains.is_empty()
            || self.domains_file.is_some()
            || self.account_check != AccountCheck::None
            || self.doveadm_url.is_some()
            || self.doveadm_key_file.is_some()
            || self.doveadm_ca_file.is_some()
            || self.throttle.is_some()
            || self.failure_delay_ms != default_failure_delay_ms()
    }

    /// A domain gate is configured.
    pub fn has_domain_gate(&self) -> bool {
        !self.allowed_domains.is_empty() || self.domains_file.is_some()
    }
}

/// Dovecot's default `auth_failure_delay` is 2 s; a refusal by the gate
/// should take as long as a wrong password at the backend.
fn default_failure_delay_ms() -> u64 {
    2000
}

fn is_default<T: Default + PartialEq>(v: &T) -> bool {
    *v == T::default()
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// The client-side protocol a rule applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Imap,
    Submission,
    Sieve,
}

/// A password mechanism. `LOGIN` also covers the IMAP LOGIN command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Mechanism {
    Plain,
    Login,
}

/// One legacy rule: passwords are allowed when every given condition holds.
/// An absent condition matches everything.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    /// Unique; logged as `rule="<name>"`.
    pub name: String,
    /// Source networks (CIDR). Required: the source address is the boundary.
    pub networks: Vec<String>,
    /// TLS server names the client must have asked for (case-insensitive).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sni: Option<Vec<String>>,
    /// Allowed logins: `user@domain` or `*@domain`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub users: Option<Vec<String>>,
    /// File with more allowed logins, one per line; re-read when it changes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub users_file: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocols: Option<Vec<Protocol>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mechanisms: Option<Vec<Mechanism>>,
    /// Required to allow public networks without a user restriction.
    #[serde(default, skip_serializing_if = "is_false")]
    pub public: bool,
}

impl Rule {
    /// Restricted to listed users.
    pub fn has_users(&self) -> bool {
        self.users.is_some() || self.users_file.is_some()
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    /// Client connections open at once, all listeners; at most half of them
    /// unauthenticated.
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    /// Unauthenticated connections per source IP.
    #[serde(default = "default_max_preauth_per_ip")]
    pub max_preauth_per_ip: usize,
    /// Commands a client may send before it authenticates.
    #[serde(default = "default_max_preauth_commands")]
    pub max_preauth_commands: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_connections: default_max_connections(),
            max_preauth_per_ip: default_max_preauth_per_ip(),
            max_preauth_commands: default_max_preauth_commands(),
        }
    }
}

fn default_max_connections() -> usize {
    2048
}

fn default_max_preauth_per_ip() -> usize {
    32
}

fn default_max_preauth_commands() -> usize {
    8
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Timeouts {
    /// Total time from accept to a presented credential.
    #[serde(default = "default_preauth_secs")]
    pub preauth_secs: u64,
    /// Longest silence on any single read.
    #[serde(default = "default_idle_secs")]
    pub idle_secs: u64,
    /// Backend TCP connect, TLS handshake and PROXY header, each.
    #[serde(default = "default_connect_secs")]
    pub connect_secs: u64,
}

impl Default for Timeouts {
    fn default() -> Self {
        Timeouts {
            preauth_secs: default_preauth_secs(),
            idle_secs: default_idle_secs(),
            connect_secs: default_connect_secs(),
        }
    }
}

fn default_preauth_secs() -> u64 {
    60
}

fn default_idle_secs() -> u64 {
    30
}

fn default_connect_secs() -> u64 {
    10
}

/// The Prometheus endpoint, an optional feature: off unless `enabled`. A
/// `listen` without `enabled` means enabled.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Metrics {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// e.g. `127.0.0.1:9102`; required when enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen: Option<String>,
}

impl Metrics {
    /// `enabled` with its default applied.
    pub fn is_enabled(&self) -> bool {
        self.enabled.unwrap_or(self.listen.is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::tests::{parse, V2};

    #[test]
    fn minimal_v2_has_safe_defaults() {
        let c = parse(V2).unwrap().config;
        assert_eq!(c.server.hostname, "mail-auth-proxy");
        assert!(
            c.legacy.rules.is_empty(),
            "password access is off unless configured"
        );
        assert!(!c.metrics.is_enabled(), "metrics are off unless configured");
        assert!(c.submission.is_none() && c.sieve.is_none());
        assert_eq!(c.limits.max_connections, 2048);
        assert_eq!(c.timeouts.preauth_secs, 60);
        assert_eq!(c.oauth.issuers[0].identity_claim, "email");
    }

    #[test]
    fn unknown_keys_fail() {
        assert!(parse(&V2.replace("[imap]", "[imap]\nlisten_port = 1")).is_err());
        assert!(parse(&format!("{V2}[password_gate]\nnetworks = []\n")).is_err());
    }

    #[test]
    fn token_type_has_no_default() {
        assert!(parse(&V2.replace("token_type = \"keycloak\"\n", "")).is_err());
    }

    const RULES: &str = r#"
[scope]
internal_networks = ["10.0.0.0/8"]

[legacy]
allowed_domains = ["example.org"]
domains_file = "/etc/mail-auth-proxy/domains"
account_check = "doveadm"
doveadm_url = "https://mail.example.org:8080/doveadm/v1"
doveadm_key_file = "/etc/mail-auth-proxy/doveadm.key"
throttle = { failures = 5, window_secs = 300 }

[[legacy.rules]]
name = "internal"
networks = ["10.0.0.0/8", "192.168.0.0/16"]
sni = ["mail-internal.example.org"]

[[legacy.rules]]
name = "partner-mailflow"
networks = ["198.51.100.7/32"]
users = ["mailflow@example.org"]
protocols = ["imap", "submission"]

[[legacy.rules]]
name = "public-legacy"
networks = ["0.0.0.0/0", "::/0"]
users_file = "/etc/mail-auth-proxy/legacy-users"
mechanisms = ["PLAIN"]
"#;

    /// The target schema's legacy section parses, validates and round-trips.
    #[test]
    fn legacy_rules_parse_and_round_trip() {
        let l = parse(&format!("{V2}{RULES}")).unwrap();
        let c = &l.config;
        assert_eq!(c.legacy.rules.len(), 3);
        assert_eq!(c.legacy.account_check, AccountCheck::Doveadm);
        assert_eq!(c.legacy.failure_delay_ms, 2000);
        assert_eq!(
            c.legacy.rules[1].protocols,
            Some(vec![Protocol::Imap, Protocol::Submission])
        );
        assert_eq!(c.legacy.rules[2].mechanisms, Some(vec![Mechanism::Plain]));
        assert!(l.warnings.is_empty(), "{:?}", l.warnings);
        let printed = toml::to_string(c).unwrap();
        let back = parse(&printed).unwrap();
        assert_eq!(toml::to_string(&back.config).unwrap(), printed);
    }
}
