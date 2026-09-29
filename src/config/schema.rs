//! Schema: the serde types of format 2, their defaults, and what
//! `--print-config` leaves out.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const CONFIG_VERSION: u32 = 2;

/// Algorithms accepted when an issuer does not restrict them. Symmetric (HS*)
/// algorithms are never accepted: the proxy holds no shared secret.
pub const DEFAULT_ALGORITHMS: &[&str] = &[
    "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384",
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
    /// Named backends, referenced by a listener's `backend` or by routes.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub backends: BTreeMap<String, Backend>,
    /// Which backend a credential goes to, by the domain of the identity or
    /// login; the first matching route wins. Without routes each protocol
    /// has the one backend of its section.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routes: Vec<Route>,
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
    #[serde(default)]
    pub auth_ratelimit: AuthRateLimit,
    #[serde(default)]
    pub session: Session,
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
    /// PEM certificate chain of the default certificate: served to clients
    /// without SNI and to those that ask for one of its names.
    pub cert: String,
    /// PEM private key.
    pub key: String,
    /// More certificates, each chosen by the name a client asks for (SNI).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub certificates: Vec<CertKey>,
}

/// A certificate chain and its private key (PEM files).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertKey {
    pub cert: String,
    pub key: String,
}

impl Tls {
    /// Every certificate with the config key it is under (`tls`,
    /// `tls.certificates[0]`, …), the default first.
    pub fn pairs(&self) -> impl Iterator<Item = (String, &str, &str)> {
        std::iter::once(("tls".to_string(), &self.cert[..], &self.key[..])).chain(
            self.certificates
                .iter()
                .enumerate()
                .map(|(i, c)| (format!("tls.certificates[{i}]"), &c.cert[..], &c.key[..])),
        )
    }
}

/// A backend the proxy logs in to with the client's own credential.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
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
    /// SASL mechanism a validated token is forwarded with.
    #[serde(default)]
    pub auth_forward: AuthForward,
    /// How the backend learns the client's address. Default: from the short
    /// forms `proxy_protocol` and `submission.xclient`, else `none`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_ip: Option<ClientIp>,
    /// How the connection to the backend is secured. Default: `implicit` for
    /// IMAP, `starttls` for submission and ManageSieve.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<BackendTls>,
    /// Short form of `client_ip = "proxy_v2"`. Read only: `--print-config`
    /// shows `client_ip`.
    #[serde(default, skip_serializing)]
    pub proxy_protocol: bool,
}

impl Backend {
    /// `client_ip` with its default applied; `xclient` is
    /// `submission.xclient` (false for the other backends).
    pub fn effective_client_ip(&self, xclient: bool) -> ClientIp {
        match self.client_ip {
            Some(c) => c,
            None if xclient => ClientIp::Xclient,
            None if self.proxy_protocol => ClientIp::ProxyV2,
            None => ClientIp::None,
        }
    }
}

/// A listener's backend: a table of its own, or the name of a
/// `[backends.<name>]` entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum BackendRef {
    Name(String),
    Inline(Backend),
}

/// By the TOML type: a string is a name, a table the backend itself (with the
/// table's own error messages, such as an unknown key).
impl<'de> Deserialize<'de> for BackendRef {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        match toml::Value::deserialize(d)? {
            toml::Value::String(name) => Ok(BackendRef::Name(name)),
            table @ toml::Value::Table(_) => Backend::deserialize(table)
                .map(BackendRef::Inline)
                .map_err(serde::de::Error::custom),
            other => Err(serde::de::Error::custom(format!(
                "invalid type: {}, expected a backend table or the name of a [backends] entry",
                other.type_str()
            ))),
        }
    }
}

/// One route: where the credentials of some domains go. Every condition set
/// must hold; an absent one matches everything.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Route {
    /// Unique; in logs.
    pub name: String,
    /// Domains of the identity (OAuth) or the login (password), exact and
    /// ASCII case-insensitive. `"*"` matches every domain and a login
    /// without one.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domains: Vec<String>,
    /// OAuth only: the token's issuer is one of these `oauth.issuers`. A
    /// password matches a route only through `domains`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub issuers: Vec<String>,
    /// The TLS server name the client asked for is one of these.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sni: Vec<String>,
    /// OAuth only: the token's `aud` contains one of these.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub audiences: Vec<String>,
    /// The backend of each protocol the route serves (a `[backends]` name).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub imap: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub submission: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sieve: Option<String>,
}

impl Route {
    /// The backend of `protocol`, if the route serves it.
    pub fn backend(&self, protocol: Protocol) -> Option<&str> {
        match protocol {
            Protocol::Imap => self.imap.as_deref(),
            Protocol::Submission => self.submission.as_deref(),
            Protocol::Sieve => self.sieve.as_deref(),
        }
    }
}

/// A backend as a protocol uses it.
#[derive(Debug, Clone, Copy)]
pub struct UsedBackend<'a> {
    /// The `[backends]` name, or the protocol's section for an inline one.
    pub name: &'a str,
    /// Written as a table in the protocol's section.
    pub inline: bool,
    pub backend: &'a Backend,
}

impl UsedBackend<'_> {
    /// Where it is configured: `imap.backend` or `backends.<name>`.
    pub fn key(&self) -> String {
        if self.inline {
            format!("{}.backend", self.name)
        } else {
            format!("backends.{}", self.name)
        }
    }
}

impl Config {
    /// The listener backend of `protocol`, if its section exists and has one.
    pub fn listener_backend(&self, protocol: Protocol) -> Option<&BackendRef> {
        match protocol {
            Protocol::Imap => self.imap.backend.as_ref(),
            Protocol::Submission => self.submission.as_ref()?.backend.as_ref(),
            Protocol::Sieve => self.sieve.as_ref()?.backend.as_ref(),
        }
    }

    /// Whether the section of `protocol` exists (IMAP always does).
    pub fn has_protocol(&self, protocol: Protocol) -> bool {
        match protocol {
            Protocol::Imap => true,
            Protocol::Submission => self.submission.is_some(),
            Protocol::Sieve => self.sieve.is_some(),
        }
    }

    /// Every backend `protocol` can send a credential to, each once: the
    /// listener's, or else those of the routes that serve the protocol, in
    /// file order. A name without a `[backends]` entry is left out
    /// (validation reports it); so is a protocol without a section.
    pub fn backends_of(&self, protocol: Protocol) -> Vec<UsedBackend<'_>> {
        if !self.has_protocol(protocol) {
            return Vec::new();
        }
        let named = |name: &str| {
            self.backends
                .get_key_value(name)
                .map(|(name, backend)| UsedBackend {
                    name,
                    inline: false,
                    backend,
                })
        };
        match self.listener_backend(protocol) {
            Some(BackendRef::Inline(backend)) => vec![UsedBackend {
                name: protocol.section(),
                inline: true,
                backend,
            }],
            Some(BackendRef::Name(name)) => named(name).into_iter().collect(),
            None => {
                let mut out: Vec<UsedBackend<'_>> = Vec::new();
                for used in self
                    .routes
                    .iter()
                    .filter_map(|r| named(r.backend(protocol)?))
                {
                    if !out.iter().any(|u| u.name == used.name) {
                        out.push(used);
                    }
                }
                out
            }
        }
    }
}

/// The SASL mechanism a validated token is forwarded to the backend with.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthForward {
    /// Google's XOAUTH2 (Dovecot, Postfix through Dovecot SASL).
    #[default]
    Xoauth2,
    /// OAUTHBEARER (RFC 7628).
    Oauthbearer,
}

/// How the backend learns the client's address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientIp {
    /// A PROXY protocol v2 header before anything else; the backend listener
    /// must require it.
    ProxyV2,
    /// The SMTP XCLIENT command (Postfix), submission only.
    Xclient,
    /// Nothing: the backend sees the proxy's address.
    None,
}

/// How the proxy secures its connection to a backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum BackendTls {
    /// Plaintext greeting, then STARTTLS (IMAP RFC 9051 §6.2.1, SMTP RFC
    /// 3207, ManageSieve RFC 5804 §2.2).
    Starttls,
    /// TLS from the first byte (RFC 8314).
    Implicit,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Imap {
    /// Implicit-TLS listener, e.g. `0.0.0.0:993`.
    pub listen: String,
    /// The backend of every login; unset when routes choose it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend: Option<BackendRef>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Submission {
    /// STARTTLS listener, e.g. `0.0.0.0:587`.
    pub listen: String,
    /// Implicit-TLS listener (RFC 8314 §3.3), e.g. `0.0.0.0:465`; optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub implicit_tls_listen: Option<String>,
    /// The backend (Postfix submission); unset when routes choose it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend: Option<BackendRef>,
    /// Short form of `backend.client_ip = "xclient"`. Read only:
    /// `--print-config` shows `client_ip`.
    #[serde(default, skip_serializing)]
    pub xclient: bool,
    /// The EHLO extensions advertised after STARTTLS at most (by keyword);
    /// the reply lists those of them the backend offers and the proxy
    /// handles. Unset: all the proxy handles.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ehlo_extensions: Option<Vec<String>>,
    /// How long the backend's EHLO extensions are reused.
    #[serde(default = "default_caps_cache_secs")]
    pub capability_cache_secs: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Sieve {
    /// STARTTLS listener, e.g. `0.0.0.0:4190`.
    pub listen: String,
    /// The backend (Pigeonhole ManageSieve); unset when routes choose it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend: Option<BackendRef>,
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
    /// If not empty, the identity must be an address in one of these domains
    /// (ASCII case-insensitive): what this issuer may log in to. Without it
    /// the issuer is trusted for every mailbox.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub identity_domains: Vec<String>,
    /// If not empty, only tokens whose `client_claim` is listed are accepted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_clients: Vec<String>,
    /// Claim naming the OAuth client (`azp` for Keycloak/OIDC, `client_id`,
    /// `appid`). Default: by `token_type`, see `client_claim()`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_claim: Option<String>,
    /// https URL of the issuer's OpenID Provider configuration, sent as
    /// `openid-configuration` to a client whose token failed validation
    /// (RFC 7628 section 3.2.2). At most one issuer sets it or `scope`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub openid_configuration_url: Option<String>,
    /// OAuth scope a client needs for mail, sent as `scope` with the
    /// failure (RFC 7628 section 3.2.2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

impl Issuer {
    /// Whether the failure result names this issuer.
    pub fn has_discovery(&self) -> bool {
        self.openid_configuration_url.is_some() || self.scope.is_some()
    }
}

impl Issuer {
    /// `require_email_verified` with its default applied.
    pub fn requires_email_verified(&self) -> bool {
        self.require_email_verified
            .unwrap_or(self.identity_claim == "email")
    }

    /// `client_claim` with its default applied: `client_id` for RFC 9068
    /// access tokens (RFC 9068 §2.2), otherwise `azp` (Keycloak, OIDC).
    pub fn client_claim(&self) -> &str {
        match (&self.client_claim, self.token_type) {
            (Some(c), _) => c,
            (None, TokenType::Rfc9068) => "client_id",
            (None, TokenType::Keycloak | TokenType::Any) => "azp",
        }
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

/// The short form of one legacy rule: `enabled` means one rule named
/// `password_gate`: passwords only if the client asked
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

impl Protocol {
    pub const ALL: [Protocol; 3] = [Protocol::Imap, Protocol::Submission, Protocol::Sieve];

    /// The configuration section, also the name of its inline backend.
    pub fn section(self) -> &'static str {
        match self {
            Protocol::Imap => "imap",
            Protocol::Submission => "submission",
            Protocol::Sieve => "sieve",
        }
    }
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
    /// Authentication attempts per connection (1-10); 1 closes the
    /// connection after the first refused one.
    #[serde(default = "default_max_auth_attempts")]
    pub max_auth_attempts: u32,
    /// Prefix length by which IPv6 sources are grouped for
    /// `max_preauth_per_ip` and the auth rate limit (32-64).
    #[serde(default = "default_ipv6_source_prefix")]
    pub ipv6_source_prefix: u8,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_connections: default_max_connections(),
            max_preauth_per_ip: default_max_preauth_per_ip(),
            max_preauth_commands: default_max_preauth_commands(),
            max_auth_attempts: default_max_auth_attempts(),
            ipv6_source_prefix: default_ipv6_source_prefix(),
        }
    }
}

fn default_ipv6_source_prefix() -> u8 {
    64
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

fn default_max_auth_attempts() -> u32 {
    3
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Timeouts {
    /// Total time from accept to a presented credential.
    #[serde(default = "default_preauth_secs")]
    pub preauth_secs: u64,
    /// Longest silence on any single line read, before the relay starts.
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

/// Blocking of source addresses with too many failed logins: after
/// `failures` counted failures within `window_secs`, new connections from
/// the source are closed at accept for `block_secs`, doubled for each
/// further block up to `max_block_secs`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthRateLimit {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_ratelimit_failures")]
    pub failures: u32,
    #[serde(default = "default_ratelimit_window_secs")]
    pub window_secs: u64,
    #[serde(default = "default_ratelimit_block_secs")]
    pub block_secs: u64,
    /// Longest block after escalation; set it to `block_secs` for none.
    #[serde(default = "default_ratelimit_max_block_secs")]
    pub max_block_secs: u64,
    /// Never block sources inside `scope.internal_networks`.
    #[serde(default)]
    pub exempt_internal: bool,
    /// Sources that are never blocked (CIDR): local relays such as a webmail
    /// server, NAT gateways.
    #[serde(default = "default_ratelimit_exempt_networks")]
    pub exempt_networks: Vec<String>,
}

impl Default for AuthRateLimit {
    fn default() -> Self {
        AuthRateLimit {
            enabled: true,
            failures: default_ratelimit_failures(),
            window_secs: default_ratelimit_window_secs(),
            block_secs: default_ratelimit_block_secs(),
            max_block_secs: default_ratelimit_max_block_secs(),
            exempt_internal: false,
            exempt_networks: default_ratelimit_exempt_networks(),
        }
    }
}

fn default_ratelimit_failures() -> u32 {
    20
}

fn default_ratelimit_window_secs() -> u64 {
    600
}

fn default_ratelimit_block_secs() -> u64 {
    900
}

fn default_ratelimit_max_block_secs() -> u64 {
    86_400
}

/// Loopback: a local webmail or relay logs in for many users.
fn default_ratelimit_exempt_networks() -> Vec<String> {
    vec!["127.0.0.0/8".into(), "::1/128".into()]
}

// ── [session]: the connection after authentication ─────────────────────────

/// TCP keepalive on every client and backend connection, and the optional
/// limits of a logged-in session.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Session {
    /// Silence on a connection before the first keepalive probe.
    #[serde(default = "default_keepalive_idle_secs")]
    pub keepalive_idle_secs: u64,
    /// Time between unanswered probes.
    #[serde(default = "default_keepalive_interval_secs")]
    pub keepalive_interval_secs: u64,
    /// Unanswered probes before the connection is dropped as dead.
    #[serde(default = "default_keepalive_count")]
    pub keepalive_count: u32,
    /// End a logged-in session after this long without a byte in either
    /// direction. Off when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_limit_secs: Option<u64>,
    /// End a logged-in session this long after the login, whatever it does.
    /// Off when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_session_secs: Option<u64>,
}

impl Default for Session {
    fn default() -> Self {
        Session {
            keepalive_idle_secs: default_keepalive_idle_secs(),
            keepalive_interval_secs: default_keepalive_interval_secs(),
            keepalive_count: default_keepalive_count(),
            idle_limit_secs: None,
            max_session_secs: None,
        }
    }
}

/// 10 minutes of silence, then 5 probes a minute apart: a dead peer (a phone
/// that left the network, a crashed host) frees its slot after at most 15
/// minutes, half the 30-minute autologout floor of RFC 9051 section 5.4, so
/// it is gone long before a session limit would be needed. The stack default
/// (Linux: 2 h + 9 x 75 s) holds such a slot for over two hours.
fn default_keepalive_idle_secs() -> u64 {
    600
}

fn default_keepalive_interval_secs() -> u64 {
    60
}

fn default_keepalive_count() -> u32 {
    5
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::tests::{parse, V2};

    #[test]
    fn minimal_v2_has_safe_defaults() {
        let l = parse(&V2.replace("[server]\nhostname = \"proxy.example.org\"\n", "")).unwrap();
        assert_eq!(l.config.server.hostname, "mail-auth-proxy");
        assert!(
            l.warnings.iter().any(|w| w.contains("server.hostname")),
            "the default is no FQDN: {:?}",
            l.warnings
        );
        let c = l.config;
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

    /// The legacy section parses, validates and round-trips.
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
