//! Configuration.
//!
//! The current format is version 2: sectioned, strict (unknown keys are an
//! error), with per-issuer token rules and per-backend TLS. A file without
//! `config_version = 2` is rejected.
//!
//! Everything a misconfiguration could silently weaken fails boot instead:
//! unknown keys, an enabled password gate without SNI or networks, http JWKS,
//! limits of 0.

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
    fn has_settings(&self) -> bool {
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

/// True if every address of `net` is private: RFC 1918, loopback,
/// link-local, or IPv6 ULA. Anything else (including 0.0.0.0/0 and ::/0) is
/// public.
pub fn is_private_net(net: &ipnet::IpNet) -> bool {
    const PRIVATE: &[&str] = &[
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    ];
    PRIVATE
        .iter()
        .filter_map(|p| p.parse::<ipnet::IpNet>().ok())
        .any(|p| p.contains(net))
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

/// A parsed configuration and what validation found. Syntax and schema
/// errors fail `parse` itself; `errors` holds the semantic problems, all of
/// them, so `--check-config` can list them together with file problems.
pub struct Loaded {
    pub config: Config,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}

/// Read, parse and validate `path`.
pub fn load(path: &str) -> anyhow::Result<Loaded> {
    let text = std::fs::read_to_string(path).map_err(|e| anyhow::anyhow!("{path}: {e}"))?;
    parse(&text)
}

/// Parse and validate a configuration text (see `Loaded`).
pub fn parse(text: &str) -> anyhow::Result<Loaded> {
    let raw: toml::Table = toml::from_str(text)?;
    // Checked before the schema, so a file in another format gets this
    // message instead of a list of unknown keys.
    if !raw.contains_key("config_version") {
        anyhow::bail!(
            "config_version is missing: the file must set `config_version = {CONFIG_VERSION}` at the top, before the first [section]"
        );
    }
    let config: Config = toml::from_str(text)?;
    if config.config_version != CONFIG_VERSION {
        anyhow::bail!(
            "config_version {} is not supported (expected {CONFIG_VERSION})",
            config.config_version
        );
    }
    let mut warnings = Vec::new();
    let mut errors = Vec::new();
    config.check(&mut errors, &mut warnings);
    let mut config = config;
    config.normalize();
    Ok(Loaded {
        config,
        warnings,
        errors,
    })
}

impl Loaded {
    /// Fail with every validation error, if there are any.
    pub fn ensure_valid(&self) -> anyhow::Result<()> {
        if self.errors.is_empty() {
            Ok(())
        } else {
            anyhow::bail!("invalid configuration:\n  - {}", self.errors.join("\n  - "))
        }
    }
}

impl Config {
    /// Every check serde cannot express. Collects all problems instead of
    /// stopping at the first, so one `--check-config` run shows them all.
    fn check(&self, errors: &mut Vec<String>, warnings: &mut Vec<String>) {
        let mut err = |m: String| errors.push(m);

        let h = &self.server.hostname;
        if h.is_empty() || h.chars().any(|c| c.is_whitespace() || c.is_control()) {
            err("server.hostname must be one word without spaces or control characters".into());
        }
        if self.tls.cert.is_empty() || self.tls.key.is_empty() {
            err("tls.cert and tls.key are required".into());
        }

        let mut listens = vec![("imap.listen", &self.imap.listen)];
        let mut backends = vec![("imap.backend", &self.imap.backend)];
        if let Some(s) = &self.submission {
            listens.push(("submission.listen", &s.listen));
            backends.push(("submission.backend", &s.backend));
            if s.backend.proxy_protocol {
                err("submission.backend.proxy_protocol is not supported (Postfix gets the client address via xclient)".into());
            }
            for x in &s.ehlo_extensions {
                let bad = x.is_empty()
                    || x.chars().any(|c| c.is_control())
                    || ["AUTH", "STARTTLS"].iter().any(|v| {
                        x.split(' ')
                            .next()
                            .is_some_and(|w| w.eq_ignore_ascii_case(v))
                    });
                if bad {
                    err(format!("submission.ehlo_extensions: {x:?} is not allowed (AUTH and STARTTLS are set by the proxy)"));
                }
            }
        }
        if let Some(s) = &self.sieve {
            listens.push(("sieve.listen", &s.listen));
            backends.push(("sieve.backend", &s.backend));
            if s.capability_cache_secs == 0 {
                err("sieve.capability_cache_secs must be at least 1".into());
            }
        }
        for (name, l) in &listens {
            if l.parse::<std::net::SocketAddr>().is_err() {
                err(format!("{name} = {l:?} must be ip:port"));
            }
        }
        for (i, (a, la)) in listens.iter().enumerate() {
            if listens[..i].iter().any(|(_, lb)| lb == la) {
                err(format!("{a} = {la:?} is used twice"));
            }
        }
        for (name, b) in &backends {
            if !b
                .address
                .rsplit_once(':')
                .is_some_and(|(h, p)| !h.is_empty() && p.parse::<u16>().is_ok())
            {
                err(format!(
                    "{name}.address = {:?} must be host:port",
                    b.address
                ));
            }
            let vname = b
                .verify_name
                .clone()
                .unwrap_or_else(|| crate::wire::connect::host_of(&b.address).to_string());
            if rustls::pki_types::ServerName::try_from(vname.clone()).is_err() {
                err(format!("{name}: {vname:?} is not a valid certificate name"));
            }
        }

        if self.oauth.issuers.is_empty() {
            err("oauth.issuers: at least one issuer is required".into());
        }
        if self.oauth.refresh_secs == 0 {
            err("oauth.refresh_secs must be at least 1".into());
        }
        for (i, iss) in self.oauth.issuers.iter().enumerate() {
            let at = format!("oauth.issuers[{i}]");
            if iss.issuer.is_empty() {
                err(format!("{at}.issuer is empty"));
            }
            if self.oauth.issuers[..i]
                .iter()
                .any(|o| o.issuer == iss.issuer)
            {
                err(format!("{at}.issuer {:?} is listed twice", iss.issuer));
            }
            if let Err(e) = crate::auth::token::check_jwks_url(&iss.jwks_url) {
                err(format!("{at}: {e}"));
            }
            if iss.audiences.is_empty() || iss.audiences.iter().any(String::is_empty) {
                err(format!(
                    "{at}.audiences must list at least one non-empty audience"
                ));
            }
            if iss.identity_claim.is_empty() || iss.client_claim.is_empty() {
                err(format!(
                    "{at}: identity_claim and client_claim must not be empty"
                ));
            }
            if iss.allowed_algorithms.is_empty() {
                err(format!("{at}.allowed_algorithms is empty"));
            }
            for a in &iss.allowed_algorithms {
                if crate::auth::token::parse_alg(a).is_none() {
                    err(format!(
                        "{at}.allowed_algorithms: {a:?} is not supported (RS*, PS*, ES256, ES384)"
                    ));
                }
            }
            if iss.token_type == TokenType::Any {
                warnings.push(format!("{at}: token_type = \"any\" also accepts ID tokens that carry an accepted audience"));
            }
            if iss.identity_claim != "email" && iss.requires_email_verified() {
                warnings.push(format!("{at}: require_email_verified checks the email_verified claim although identity_claim is {:?}", iss.identity_claim));
            }
        }

        if let Some(g) = &self.password_gate {
            if g.enabled {
                if g.sni.is_empty() || g.sni.iter().any(String::is_empty) {
                    err(
                        "password_gate.sni must list the name(s) clients use for password access"
                            .into(),
                    );
                }
                if g.internal_networks.is_empty() {
                    err("password_gate.internal_networks must list the networks allowed to use passwords".into());
                }
                match crate::auth::policy::parse_internal_nets(&g.internal_networks) {
                    Ok(nets) => {
                        for n in nets.iter().filter(|n| n.prefix_len() == 0) {
                            warnings.push(format!("password_gate.internal_networks contains {n}: passwords are accepted from anywhere"));
                        }
                    }
                    Err(e) => err(format!("password_gate.internal_networks: {e:#}")),
                }
            } else {
                if let Err(e) = crate::auth::policy::parse_internal_nets(&g.internal_networks) {
                    err(format!("password_gate.internal_networks: {e:#}"));
                }
                if !g.sni.is_empty() {
                    warnings.push("password_gate is disabled; its sni is ignored (internal_networks still sets the scope label)".into());
                }
            }
            if !self.legacy.rules.is_empty() {
                err("[password_gate] and [[legacy.rules]] cannot be combined: write the password gate as a rule (see --print-config)".into());
            }
        }
        if let Err(e) = crate::auth::policy::parse_internal_nets(&self.scope.internal_networks) {
            err(format!("scope.internal_networks: {e:#}"));
        }
        let gate_on = self.password_gate.as_ref().is_some_and(|g| g.enabled);
        self.legacy.check(gate_on, &mut err, warnings);

        let l = &self.limits;
        if l.max_connections == 0 || l.max_preauth_per_ip == 0 || l.max_preauth_commands == 0 {
            err("limits: max_connections, max_preauth_per_ip and max_preauth_commands must be at least 1".into());
        }
        if l.max_connections > tokio::sync::Semaphore::MAX_PERMITS {
            err(format!(
                "limits.max_connections is larger than {}",
                tokio::sync::Semaphore::MAX_PERMITS
            ));
        }
        let t = &self.timeouts;
        if t.preauth_secs == 0 || t.idle_secs == 0 || t.connect_secs == 0 {
            err("timeouts must be at least 1 second".into());
        }
        match (&self.metrics.listen, self.metrics.is_enabled()) {
            (None, true) => err("metrics.listen is required when metrics.enabled = true".into()),
            (Some(m), enabled) => match m.parse::<std::net::SocketAddr>() {
                Ok(a) if enabled && !a.ip().is_loopback() => warnings.push(format!(
                    "metrics.listen = {m:?} is reachable from the network and has no authentication"
                )),
                Ok(_) => {}
                Err(_) => err(format!("metrics.listen = {m:?} must be ip:port")),
            },
            (None, false) => {}
        }
    }

    /// Replace the short forms by what they mean, so the rest of the program
    /// and `--print-config` see one form: `[password_gate]` becomes one rule
    /// plus the scope label, and defaults that depend on other keys
    /// (`metrics.enabled`) are spelled out.
    fn normalize(&mut self) {
        if let Some(g) = self.password_gate.take() {
            if self.scope.internal_networks.is_empty() {
                self.scope.internal_networks = g.internal_networks.clone();
            }
            if g.enabled && self.legacy.rules.is_empty() {
                // The short form allowed its networks whatever they were;
                // `public` keeps a public entry (a partner's address) valid.
                let public = crate::auth::policy::parse_internal_nets(&g.internal_networks)
                    .map(|nets| nets.iter().any(|n| !is_private_net(n)))
                    .unwrap_or(false);
                self.legacy.rules.push(Rule {
                    name: PASSWORD_GATE_RULE.into(),
                    networks: g.internal_networks,
                    sni: Some(g.sni),
                    users: None,
                    users_file: None,
                    protocols: None,
                    mechanisms: None,
                    public,
                });
            }
        }
        self.metrics.enabled = Some(self.metrics.is_enabled());
    }
}

/// A name that goes into a log field and a metric label unchanged.
fn is_plain_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
}

/// A login or pattern as the rules and files accept it: `user@domain`,
/// `user`, or `*@domain`; no whitespace, control characters or other
/// wildcards.
pub fn check_user_entry(u: &str) -> Result<(), String> {
    let bad = |why: &str| Err(format!("{u:?}: {why}"));
    if u.is_empty() || u.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return bad("empty or contains whitespace/control characters");
    }
    match u.strip_prefix("*@") {
        Some(d) => check_domain_entry(d).map_err(|e| format!("{u:?}: {e}")),
        None if u.contains(['*', '?']) => bad("wildcards are only allowed as *@domain"),
        None => Ok(()),
    }
}

/// A domain as `allowed_domains` and `domains_file` accept it.
pub fn check_domain_entry(d: &str) -> Result<(), String> {
    if d.is_empty()
        || d.chars()
            .any(|c| c.is_whitespace() || c.is_control() || "@*?".contains(c))
    {
        return Err(format!("{d:?} is not a domain name"));
    }
    Ok(())
}

impl Legacy {
    fn check(&self, gate_on: bool, err: &mut impl FnMut(String), warnings: &mut Vec<String>) {
        for d in &self.allowed_domains {
            if let Err(e) = check_domain_entry(d) {
                err(format!("legacy.allowed_domains: {e}"));
            }
        }
        if self.domains_file.as_deref() == Some("") {
            err("legacy.domains_file is empty".into());
        }
        match self.account_check {
            AccountCheck::Doveadm => {
                match self.doveadm_url.as_deref() {
                    None => err(
                        "legacy.doveadm_url is required with account_check = \"doveadm\"".into(),
                    ),
                    Some(u) => {
                        if let Err(e) = check_service_url(u) {
                            err(format!("legacy.doveadm_url: {e}"));
                        }
                    }
                }
                if self.doveadm_key_file.as_deref().is_none_or(str::is_empty) {
                    err(
                        "legacy.doveadm_key_file is required with account_check = \"doveadm\""
                            .into(),
                    );
                }
            }
            AccountCheck::None => {
                if self.doveadm_url.is_some()
                    || self.doveadm_key_file.is_some()
                    || self.doveadm_ca_file.is_some()
                {
                    err("legacy.doveadm_* is set but account_check is not \"doveadm\"".into());
                }
            }
        }
        if let Some(t) = &self.throttle {
            if t.failures == 0 || t.window_secs == 0 {
                err("legacy.throttle: failures and window_secs must be at least 1".into());
            }
        }
        if self.failure_delay_ms > 10_000 {
            err("legacy.failure_delay_ms must be at most 10000".into());
        } else if self.failure_delay_ms == 0 {
            warnings.push("legacy.failure_delay_ms = 0: the reply time may tell a refused account from a wrong password".into());
        }
        if self.rules.is_empty() && !gate_on && self.has_settings() {
            warnings.push(
                "[legacy] has no rules: passwords are not accepted anywhere, its settings have no effect"
                    .into(),
            );
        }

        for (i, r) in self.rules.iter().enumerate() {
            let at = format!("legacy.rules[{i}]");
            if !is_plain_name(&r.name) {
                err(format!(
                    "{at}.name {:?} must be 1-64 characters of A-Z a-z 0-9 . _ -",
                    r.name
                ));
            } else if self.rules[..i].iter().any(|o| o.name == r.name) {
                err(format!("{at}.name {:?} is used twice", r.name));
            }
            let at = format!("legacy.rules[{}]", r.name);
            let nets = if r.networks.is_empty() {
                err(format!("{at}.networks must list at least one network"));
                Vec::new()
            } else {
                match crate::auth::policy::parse_internal_nets(&r.networks) {
                    Ok(n) => n,
                    Err(e) => {
                        err(format!("{at}.networks: {e:#}"));
                        Vec::new()
                    }
                }
            };
            let empty = |what: &str| format!("{at}.{what} is empty; leave it out to match any");
            if r.sni
                .as_ref()
                .is_some_and(|v| v.is_empty() || v.iter().any(String::is_empty))
            {
                err(format!(
                    "{at}.sni must not be empty or contain an empty name"
                ));
            }
            match &r.users {
                Some(v) if v.is_empty() => err(empty("users")),
                Some(v) => {
                    for u in v {
                        if let Err(e) = check_user_entry(u) {
                            err(format!("{at}.users: {e}"));
                        }
                    }
                }
                None => {}
            }
            if r.users_file.as_deref() == Some("") {
                err(format!("{at}.users_file is empty"));
            }
            if r.protocols.as_ref().is_some_and(Vec::is_empty) {
                err(empty("protocols"));
            }
            if r.mechanisms.as_ref().is_some_and(Vec::is_empty) {
                err(empty("mechanisms"));
            }
            let public_nets: Vec<String> = nets
                .iter()
                .filter(|n| !is_private_net(n))
                .map(|n| n.to_string())
                .collect();
            if !public_nets.is_empty() && !r.has_users() {
                if r.public {
                    warnings.push(format!(
                        "{at} accepts passwords of every user from public networks ({})",
                        public_nets.join(", ")
                    ));
                } else {
                    err(format!(
                        "{at}: public networks ({}) without users or users_file need public = true",
                        public_nets.join(", ")
                    ));
                }
            }
        }
    }
}

/// https, or http to the local host only (tests, a local sidecar). The
/// doveadm API key and the lookups must not cross a network in the clear.
pub fn check_service_url(url: &str) -> Result<(), String> {
    let parsed = reqwest::Url::parse(url).map_err(|e| format!("bad url {url:?}: {e}"))?;
    // Credentials belong in the key file, not in a URL that is logged.
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(
            "must not contain user:password@ (the API key goes into doveadm_key_file)".into(),
        );
    }
    let local = matches!(
        parsed.host_str(),
        Some("localhost" | "127.0.0.1" | "[::1]" | "::1")
    );
    match parsed.scheme() {
        "https" => Ok(()),
        "http" if local => Ok(()),
        _ => Err(format!("{url:?} must use https")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse and require validity, like the service does at start.
    fn parse(text: &str) -> anyhow::Result<Loaded> {
        let l = super::parse(text)?;
        l.ensure_valid()?;
        Ok(l)
    }

    /// A flat file of the kind earlier releases read: no `config_version`.
    const FLAT: &str = r#"
listen = "0.0.0.0:993"
tls_cert = "/c.pem"
tls_key = "/k.pem"
backend_addr = "192.0.2.10:10993"
"#;

    const V2: &str = r#"
config_version = 2
[tls]
cert = "/c.pem"
key = "/k.pem"
[imap]
listen = "0.0.0.0:993"
backend = { address = "192.0.2.10:993", verify_name = "mail.example.org" }
[oauth]
[[oauth.issuers]]
issuer = "https://idp.example/realms/mail"
jwks_url = "https://idp.example/realms/mail/certs"
audiences = ["dovecot"]
token_type = "keycloak"
"#;

    /// Only format 2 is read; anything else fails with a message naming the key.
    #[test]
    fn file_without_config_version_is_rejected() {
        for text in [FLAT.to_string(), V2.replace("config_version = 2\n", "")] {
            let e = super::parse(&text).err().unwrap().to_string();
            assert!(e.contains("config_version is missing"), "{e}");
            assert!(e.contains("config_version = 2"), "{e}");
        }
    }

    /// `[password_gate]` becomes one rule plus the scope label (a public /32
    /// keeps it valid through `public`), and the printed form parses back to
    /// the same configuration.
    #[test]
    fn password_gate_prints_as_rule_and_round_trips() {
        let gate = "[password_gate]\nenabled = true\nsni = [\"mail.example.org\"]\ninternal_networks = [\"10.0.0.0/8\", \"198.51.100.7/32\"]\n";
        let c = parse(&format!("{V2}{gate}")).unwrap().config;
        assert!(c.password_gate.is_none());
        assert_eq!(c.legacy.rules.len(), 1);
        let r = &c.legacy.rules[0];
        assert_eq!(r.name, PASSWORD_GATE_RULE);
        assert_eq!(
            r.sni.as_deref(),
            Some(&["mail.example.org".to_string()][..])
        );
        assert_eq!(r.networks, ["10.0.0.0/8", "198.51.100.7/32"]);
        assert!(r.public && !r.has_users());
        assert!(r.protocols.is_none() && r.mechanisms.is_none());
        assert_eq!(c.scope.internal_networks, ["10.0.0.0/8", "198.51.100.7/32"]);
        let printed = toml::to_string(&c).unwrap();
        let back = parse(&printed).unwrap();
        assert_eq!(toml::to_string(&back.config).unwrap(), printed);
    }

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

    /// All problems are reported at once.
    #[test]
    fn validation_collects_every_error() {
        let bad = V2
            .replace("0.0.0.0:993", "993")
            .replace(
                "https://idp.example/realms/mail/certs",
                "http://idp.example/certs",
            )
            .replace("[\"dovecot\"]", "[]")
            + "[password_gate]\nenabled = true\n[limits]\nmax_preauth_per_ip = 0\n";
        let e = parse(&bad).err().unwrap().to_string();
        for needle in [
            "imap.listen",
            "https",
            "audiences",
            "password_gate.sni",
            "internal_networks",
            "limits",
        ] {
            assert!(e.contains(needle), "missing {needle:?} in: {e}");
        }
    }

    #[test]
    fn rejected_details() {
        let with = |extra: &str| parse(&format!("{V2}{extra}"));
        assert!(with("[submission]\nlisten = \"0.0.0.0:587\"\nbackend = { address = \"192.0.2.10:587\", proxy_protocol = true }\n").is_err());
        assert!(with("[submission]\nlisten = \"0.0.0.0:587\"\nbackend = { address = \"192.0.2.10:587\" }\nehlo_extensions = [\"AUTH PLAIN\"]\n").is_err());
        assert!(parse(&V2.replace(
            "token_type = \"keycloak\"",
            "token_type = \"keycloak\"\nallowed_algorithms = [\"HS256\"]"
        ))
        .is_err());
        assert!(parse(&V2.replace("config_version = 2", "config_version = 3")).is_err());
        let w = with("[password_gate]\nenabled = true\nsni = [\"mail.example.org\"]\ninternal_networks = [\"0.0.0.0/0\"]\n").unwrap();
        assert!(w.warnings.iter().any(|x| x.contains("from anywhere")));
    }

    /// Metrics are opt-in: `enabled` needs `listen`; `listen` alone means
    /// enabled; a disabled endpoint with a public address is not warned about.
    #[test]
    fn metrics_opt_in() {
        let with = |m: &str| super::parse(&format!("{V2}[metrics]\n{m}")).unwrap();
        let l = with("enabled = true\n");
        assert!(l
            .errors
            .iter()
            .any(|e| e.contains("metrics.listen is required")));
        let l = with("listen = \"127.0.0.1:9102\"\n");
        assert!(l.errors.is_empty() && l.config.metrics.enabled == Some(true));
        let l = with("enabled = false\nlisten = \"0.0.0.0:9102\"\n");
        assert!(l.errors.is_empty() && !l.config.metrics.is_enabled());
        assert!(l.warnings.is_empty(), "{:?}", l.warnings);
        let l = with("enabled = true\nlisten = \"0.0.0.0:9102\"\n");
        assert!(l.warnings.iter().any(|w| w.contains("no authentication")));
        assert!(!with("").config.metrics.is_enabled());
    }

    /// Errors of `V2` plus `extra`, joined.
    fn errors_with(extra: &str) -> String {
        super::parse(&format!("{V2}{extra}"))
            .map(|l| l.errors.join("\n"))
            .unwrap_or_else(|e| format!("parse: {e}"))
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

    /// Public networks without a user restriction need `public = true`;
    /// private ranges never do.
    #[test]
    fn public_rules_need_public_true() {
        let rule = |nets: &str, extra: &str| {
            format!("[[legacy.rules]]\nname = \"r\"\nnetworks = [{nets}]\n{extra}")
        };
        for nets in [
            r#""0.0.0.0/0""#,
            r#""::/0""#,
            r#""198.51.100.7/32""#,
            r#""10.0.0.0/8", "100.64.0.0/10""#,
            r#""172.15.0.0/16""#,
        ] {
            let e = errors_with(&rule(nets, ""));
            assert!(e.contains("need public = true"), "{nets}: {e}");
            assert!(
                errors_with(&rule(nets, "public = true\n")).is_empty(),
                "{nets}"
            );
            assert!(errors_with(&rule(nets, "users = [\"a@example.org\"]\n")).is_empty());
            assert!(errors_with(&rule(nets, "users_file = \"/u\"\n")).is_empty());
        }
        for nets in [
            r#""10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16""#,
            r#""127.0.0.1/32", "::1/128", "fd00::/8", "fe80::/64", "169.254.0.0/16""#,
        ] {
            assert!(errors_with(&rule(nets, "")).is_empty(), "{nets}");
        }
        let w = super::parse(&format!(
            "{V2}{}",
            rule(r#""0.0.0.0/0""#, "public = true\n")
        ))
        .unwrap()
        .warnings;
        assert!(w
            .iter()
            .any(|w| w.contains("every user from public networks")));
    }

    #[test]
    fn legacy_rules_are_validated() {
        let rule = |body: &str| format!("[[legacy.rules]]\n{body}\n");
        let cases = [
            (rule("networks = [\"10.0.0.0/8\"]"), "missing field `name`"),
            (rule("name = \"a\""), "missing field `networks`"),
            (rule("name = \"a\"\nnetworks = []"), "at least one network"),
            (rule("name = \"a b\"\nnetworks = [\"10.0.0.0/8\"]"), "must be 1-64"),
            (
                rule("name = \"a\"\nnetworks = [\"10.0.0.0/8\"]") + &rule("name = \"a\"\nnetworks = [\"10.0.0.0/8\"]"),
                "used twice",
            ),
            (rule("name = \"a\"\nnetworks = [\"nonsense\"]"), "bad internal_networks CIDR"),
            (rule("name = \"a\"\nnetworks = [\"10.0.0.0/8\"]\nsni = []"), "sni must not be empty"),
            (rule("name = \"a\"\nnetworks = [\"10.0.0.0/8\"]\nusers = []"), "users is empty"),
            (rule("name = \"a\"\nnetworks = [\"10.0.0.0/8\"]\nusers = [\"a*@x\"]"), "wildcards"),
            (rule("name = \"a\"\nnetworks = [\"10.0.0.0/8\"]\nusers = [\"*@\"]"), "not a domain"),
            (rule("name = \"a\"\nnetworks = [\"10.0.0.0/8\"]\nprotocols = []"), "protocols is empty"),
            (rule("name = \"a\"\nnetworks = [\"10.0.0.0/8\"]\nprotocols = [\"pop3\"]"), "unknown variant"),
            (rule("name = \"a\"\nnetworks = [\"10.0.0.0/8\"]\nmechanisms = [\"plain\"]"), "unknown variant"),
            (rule("name = \"a\"\nnetworks = [\"10.0.0.0/8\"]\nmechanisms = []"), "mechanisms is empty"),
            (rule("name = \"a\"\nnetworks = [\"10.0.0.0/8\"]\nport = 1"), "unknown field"),
            (
                "[legacy]\naccount_check = \"doveadm\"\n".to_string(),
                "doveadm_url is required",
            ),
            (
                "[legacy]\naccount_check = \"doveadm\"\ndoveadm_url = \"http://mail.example.org/doveadm/v1\"\ndoveadm_key_file = \"/k\"\n".to_string(),
                "must use https",
            ),
            (
                "[legacy]\ndoveadm_url = \"https://mail.example.org/doveadm/v1\"\n".to_string(),
                "account_check is not",
            ),
            ("[legacy]\naccount_check = \"ldap\"\n".to_string(), "unknown variant"),
            ("[legacy]\nallowed_domains = [\"@x\"]\n".to_string(), "not a domain"),
            ("[legacy]\nthrottle = { failures = 0, window_secs = 1 }\n".to_string(), "at least 1"),
            ("[legacy]\nfailure_delay_ms = 60000\n".to_string(), "at most 10000"),
            ("[scope]\ninternal_networks = [\"x\"]\n".to_string(), "scope.internal_networks"),
            (
                "[password_gate]\nenabled = true\nsni = [\"m.example\"]\ninternal_networks = [\"10.0.0.0/8\"]\n".to_string()
                    + &rule("name = \"a\"\nnetworks = [\"10.0.0.0/8\"]"),
                "cannot be combined",
            ),
        ];
        for (extra, needle) in cases {
            let e = errors_with(&extra);
            assert!(e.contains(needle), "{extra}\n→ {e}");
        }
        assert!(errors_with("[legacy]\naccount_check = \"doveadm\"\ndoveadm_url = \"https://doveadm:secret@mail.example.org/doveadm/v1\"\ndoveadm_key_file = \"/k\"\n").contains("must not contain user:password@"));
        // http is fine for the local host (tests, a sidecar).
        assert!(errors_with("[legacy]\naccount_check = \"doveadm\"\ndoveadm_url = \"http://127.0.0.1:8080/doveadm/v1\"\ndoveadm_key_file = \"/k\"\n").is_empty());
    }

    /// `[password_gate]` short form: one rule plus the scope label; `[scope]`
    /// wins for the label; a disabled gate only labels.
    #[test]
    fn password_gate_short_form() {
        let gate = "[password_gate]\nenabled = true\nsni = [\"m.example\"]\ninternal_networks = [\"10.0.0.0/8\"]\n";
        let c = parse(&format!("{V2}{gate}")).unwrap().config;
        assert_eq!(c.legacy.rules.len(), 1);
        assert!(!c.legacy.rules[0].public);
        assert_eq!(c.scope.internal_networks, ["10.0.0.0/8"]);
        let c = parse(&format!(
            "{V2}{gate}[scope]\ninternal_networks = [\"192.168.0.0/16\"]\n[legacy]\nallowed_domains = [\"example.org\"]\n"
        ))
        .unwrap()
        .config;
        assert_eq!(c.scope.internal_networks, ["192.168.0.0/16"]);
        assert_eq!(c.legacy.rules[0].networks, ["10.0.0.0/8"]);
        assert_eq!(c.legacy.allowed_domains, ["example.org"]);
        let c = parse(&format!(
            "{V2}[password_gate]\ninternal_networks = [\"10.0.0.0/8\"]\n"
        ))
        .unwrap()
        .config;
        assert!(c.legacy.rules.is_empty());
        assert_eq!(c.scope.internal_networks, ["10.0.0.0/8"]);
        // Settings without any rule are pointless: warned.
        let w = super::parse(&format!(
            "{V2}[legacy]\nallowed_domains = [\"example.org\"]\n"
        ))
        .unwrap()
        .warnings;
        assert!(w.iter().any(|w| w.contains("has no rules")), "{w:?}");
    }

    /// A disabled gate still validates its networks (they label the scope).
    #[test]
    fn disabled_gate_still_checks_networks() {
        assert!(parse(&format!(
            "{V2}[password_gate]\ninternal_networks = [\"10.0.0.0/8\"]\n"
        ))
        .is_ok());
        assert!(parse(&format!(
            "{V2}[password_gate]\ninternal_networks = [\"nonsense\"]\n"
        ))
        .is_err());
    }
}
