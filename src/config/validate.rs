//! Validation: every check serde cannot express, and the normalisation of
//! the short forms into what the rest of the program reads.

use super::{AccountCheck, Config, Legacy, Rule, TokenType, PASSWORD_GATE_RULE};
use std::net::{IpAddr, SocketAddr};

/// Upper bound of `oauth.leeway_secs`. The leeway is added to `exp` and
/// subtracted from `nbf` of every token; RFC 7519 sections 4.1.4 and 4.1.5
/// allow "some small leeway, usually no more than a few minutes". A larger
/// value keeps expired tokens valid.
const MAX_LEEWAY_SECS: u64 = 300;

/// Upper bound of `oauth.refresh_secs`. Unknown key ids trigger a refresh on
/// their own, but a key the issuer removes (rotated out or compromised) is
/// dropped only by the periodic refresh: a day at most.
const MAX_REFRESH_SECS: u64 = 86_400;

/// Upper bound of each `timeouts` value. All three bound the phase before
/// authentication, where an hour is already far more than a client or
/// backend needs; larger values let idle connections hold the pre-auth
/// slots, and past 2^63 seconds the deadline overflows the clock.
const MAX_TIMEOUT_SECS: u64 = 3600;

impl Config {
    /// Every check serde cannot express. Collects all problems instead of
    /// stopping at the first, so one `--check-config` run shows them all.
    pub(super) fn check(&self, errors: &mut Vec<String>, warnings: &mut Vec<String>) {
        let mut err = |m: String| errors.push(m);

        if let Err(e) = check_hostname(&self.server.hostname) {
            err(format!("server.hostname = {:?} {e}", self.server.hostname));
        }
        // Empty file paths are reported here only; `server::file_problems`
        // skips them.
        for (name, path) in [("tls.cert", &self.tls.cert), ("tls.key", &self.tls.key)] {
            if path.is_empty() {
                err(format!("{name} is empty"));
            }
        }

        let mut listens = vec![("imap.listen", &self.imap.listen)];
        let mut backends = vec![("imap.backend", &self.imap.backend)];
        if let Some(s) = &self.submission {
            listens.push(("submission.listen", &s.listen));
            backends.push(("submission.backend", &s.backend));
            if s.backend.proxy_protocol {
                err("submission.backend.proxy_protocol is not supported (Postfix gets the client address via xclient)".into());
            }
            let mut keywords: Vec<&str> = Vec::new();
            for x in &s.ehlo_extensions {
                match ehlo_keyword(x) {
                    None => err(format!("submission.ehlo_extensions: {x:?} is not an EHLO line (a keyword of letters, digits and hyphens, then parameters, separated by single spaces; RFC 5321 section 4.1.1.1)")),
                    Some(k) if ["AUTH", "STARTTLS"].iter().any(|v| k.eq_ignore_ascii_case(v)) => {
                        err(format!("submission.ehlo_extensions: {x:?} is not allowed (AUTH and STARTTLS are set by the proxy)"));
                    }
                    Some(k) if keywords.iter().any(|o| o.eq_ignore_ascii_case(k)) => {
                        err(format!("submission.ehlo_extensions: {k:?} is listed twice"));
                    }
                    Some(k) => keywords.push(k),
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
        // The metrics endpoint binds in the same process: include it. Its own
        // `ip:port` check is below.
        let mut bound = listens.clone();
        if let (Some(m), true) = (&self.metrics.listen, self.metrics.is_enabled()) {
            bound.push(("metrics.listen", m));
        }
        for (i, (a, la)) in bound.iter().enumerate() {
            let clash = bound[..i].iter().find(|(_, lb)| {
                lb == la
                    || matches!((la.parse(), lb.parse()), (Ok(x), Ok(y)) if listens_clash(x, y))
            });
            match clash {
                Some((_, lb)) if lb == la => err(format!("{a} = {la:?} is used twice")),
                Some((b, lb)) => err(format!(
                    "{a} = {la:?} clashes with {b} = {lb:?}: a wildcard address takes the port on every address of its family, [::] on IPv4 too"
                )),
                None => {}
            }
        }
        for (name, b) in &backends {
            if b.ca_file.as_deref() == Some("") {
                err(format!("{name}.ca_file is empty"));
            }
            let address_ok = b
                .address
                .rsplit_once(':')
                .is_some_and(|(h, p)| !h.is_empty() && p.parse::<u16>().is_ok());
            if !address_ok {
                err(format!(
                    "{name}.address = {:?} must be host:port",
                    b.address
                ));
            }
            // Without verify_name the name comes from the address; a bad
            // address is reported once, above.
            let vname = match &b.verify_name {
                Some(n) => n.clone(),
                None if address_ok => crate::wire::connect::host_of(&b.address).to_string(),
                None => continue,
            };
            if rustls::pki_types::ServerName::try_from(vname.clone()).is_err() {
                err(format!("{name}: {vname:?} is not a valid certificate name"));
            }
        }

        if self.oauth.issuers.is_empty() {
            err("oauth.issuers: at least one issuer is required".into());
        }
        if self.oauth.refresh_secs == 0 {
            err("oauth.refresh_secs must be at least 1".into());
        } else if self.oauth.refresh_secs > MAX_REFRESH_SECS {
            err(format!(
                "oauth.refresh_secs must be at most {MAX_REFRESH_SECS} (a key removed from the JWKS stays trusted until the next refresh)"
            ));
        }
        if self.oauth.leeway_secs > MAX_LEEWAY_SECS {
            err(format!(
                "oauth.leeway_secs must be at most {MAX_LEEWAY_SECS} (it extends every token past exp; RFC 7519 section 4.1.4)"
            ));
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
            if let Some(url) = &iss.openid_configuration_url {
                match check_openid_configuration_url(url) {
                    Err(e) => err(format!("{at}.openid_configuration_url: {e}")),
                    // OpenID Connect Discovery 1.0 section 4: the document is
                    // at the issuer plus this path.
                    Ok(())
                        if *url
                            != format!(
                                "{}/.well-known/openid-configuration",
                                iss.issuer.trim_end_matches('/')
                            ) =>
                    {
                        warnings.push(format!("{at}.openid_configuration_url is not the issuer followed by /.well-known/openid-configuration"));
                    }
                    Ok(()) => {}
                }
            }
            if let Some(scope) = &iss.scope {
                match check_scope(scope) {
                    Err(e) => err(format!("{at}.scope: {e}")),
                    Ok(()) if scope.contains(' ') => warnings.push(format!(
                        "{at}.scope lists several scopes; RFC 7628 section 3.2.2 recommends one, as some clients do not handle a list"
                    )),
                    Ok(()) => {}
                }
            }
            if iss.has_discovery() && self.oauth.issuers[..i].iter().any(|o| o.has_discovery()) {
                // The result goes to a client whose token was not trusted,
                // so nothing in it can pick the issuer: one for everyone.
                err(format!(
                    "{at}: only one issuer may set openid_configuration_url or scope"
                ));
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
                    // The rule this becomes has `public = true` (see
                    // `normalize`): the same warning as a written rule.
                    Ok(nets) => {
                        for n in nets.iter().filter(|n| !is_private_net(n)) {
                            let anywhere = if n.prefix_len() == 0 {
                                " (from anywhere)"
                            } else {
                                ""
                            };
                            warnings.push(format!("password_gate accepts passwords of every user from the public network {n}{anywhere}"));
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
        for (name, secs) in [
            ("preauth_secs", t.preauth_secs),
            ("idle_secs", t.idle_secs),
            ("connect_secs", t.connect_secs),
        ] {
            if secs > MAX_TIMEOUT_SECS {
                err(format!(
                    "timeouts.{name} must be at most {MAX_TIMEOUT_SECS} seconds"
                ));
            }
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
    pub(super) fn normalize(&mut self) {
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

/// `server.hostname` goes unchanged into the SMTP greeting and EHLO reply,
/// the proxy's EHLO to the backend, the IMAP greeting and the ManageSieve
/// IMPLEMENTATION string. It must be a `Domain` of RFC 5321 section 4.1.2:
/// dot-separated labels of letters, digits and hyphens, no hyphen at either
/// end of a label, 1-63 characters each and 253 in all (RFC 1035 section
/// 2.3.4). An address literal (`[192.0.2.1]`) is not accepted: the EHLO
/// reply (`ehlo-ok-rsp`) takes a Domain only.
fn check_hostname(h: &str) -> Result<(), String> {
    if h.starts_with('[') || h.parse::<IpAddr>().is_ok() {
        return Err("must be a host name; IP addresses and address literals are not allowed (the SMTP EHLO reply takes a domain only, RFC 5321 section 4.1.1.1)".into());
    }
    let label_ok = |l: &str| {
        (1..=63).contains(&l.len())
            && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            && !l.starts_with('-')
            && !l.ends_with('-')
    };
    if h.len() > 253 || !h.split('.').all(label_ok) {
        return Err("must be a host name: labels of 1-63 letters, digits and inner hyphens, separated by dots, at most 253 characters (RFC 5321 section 4.1.2)".into());
    }
    Ok(())
}

/// The keyword of `line` if it is an `ehlo-line` of RFC 5321 section
/// 4.1.1.1: `ehlo-keyword *( SP ehlo-param )`, the keyword
/// `(ALPHA / DIGIT) *(ALPHA / DIGIT / "-")`, each parameter one or more
/// printable ASCII characters except space.
fn ehlo_keyword(line: &str) -> Option<&str> {
    let mut words = line.split(' ');
    let keyword = words.next()?;
    let keyword_ok = keyword.starts_with(|c: char| c.is_ascii_alphanumeric())
        && keyword
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-');
    let params_ok = words.all(|p| !p.is_empty() && p.bytes().all(|b| (b'!'..=b'~').contains(&b)));
    (keyword_ok && params_ok).then_some(keyword)
}

/// Two listeners that cannot both bind: the same port and the same address,
/// or one is a wildcard that covers the other. `[::]` covers IPv4 too,
/// because Linux binds it dual-stack by default (`net.ipv6.bindv6only = 0`).
/// Port 0 asks the kernel for a free port and never clashes.
fn listens_clash(a: SocketAddr, b: SocketAddr) -> bool {
    let (x, y) = (a.ip().to_canonical(), b.ip().to_canonical());
    let covers = |w: IpAddr, o: IpAddr| w.is_unspecified() && (w.is_ipv6() || o.is_ipv4());
    a.port() != 0 && a.port() == b.port() && (x == y || covers(x, y) || covers(y, x))
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
                match self.doveadm_key_file.as_deref() {
                    None => err(
                        "legacy.doveadm_key_file is required with account_check = \"doveadm\""
                            .into(),
                    ),
                    Some("") => err("legacy.doveadm_key_file is empty".into()),
                    Some(_) => {}
                }
                if self.doveadm_ca_file.as_deref() == Some("") {
                    err("legacy.doveadm_ca_file is empty".into());
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

/// The OpenID Provider configuration URL a client is pointed to: https
/// only, also for the local host, since the client fetches it (RFC 7628
/// section 3.2.2, OpenID Connect Discovery 1.0 section 4). No credentials
/// and no fragment.
fn check_openid_configuration_url(url: &str) -> Result<(), String> {
    let parsed = reqwest::Url::parse(url).map_err(|e| format!("bad url {url:?}: {e}"))?;
    if parsed.scheme() != "https" || parsed.host_str().is_none() {
        return Err(format!("{url:?} must be an https URL"));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("must not contain user:password@".into());
    }
    if parsed.fragment().is_some() {
        return Err("must not contain a #fragment".into());
    }
    Ok(())
}

/// An OAuth scope: scope tokens separated by single spaces (RFC 6749
/// section 3.3). The syntax also keeps it free of quotes and backslashes.
fn check_scope(scope: &str) -> Result<(), String> {
    let token_char = |c: char| matches!(c, '\x21' | '\x23'..='\x5b' | '\x5d'..='\x7e');
    if scope
        .split(' ')
        .all(|t| !t.is_empty() && t.chars().all(token_char))
    {
        Ok(())
    } else {
        Err(format!(
            "{scope:?} is not a scope (RFC 6749 section 3.3: tokens of printable ASCII without '\"' and '\\', separated by single spaces)"
        ))
    }
}

#[cfg(test)]
mod tests {
    use crate::config::tests::{parse, V2};
    use crate::config::PASSWORD_GATE_RULE;

    /// Errors of `V2` plus `extra`, joined.
    fn errors_with(extra: &str) -> String {
        crate::config::parse(&format!("{V2}{extra}"))
            .map(|l| l.errors.join("\n"))
            .unwrap_or_else(|e| format!("parse: {e}"))
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
        let with = |m: &str| crate::config::parse(&format!("{V2}[metrics]\n{m}")).unwrap();
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
        let w = crate::config::parse(&format!(
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

    /// `openid_configuration_url` and `scope`: https only, RFC 6749 scope
    /// syntax, one issuer at most; the usual URL and several scopes pass with
    /// a warning.
    #[test]
    fn discovery_fields() {
        const WELL_KNOWN: &str = "https://idp.example/realms/mail/.well-known/openid-configuration";
        let with = |fields: &str| {
            crate::config::parse(&V2.replace(
                "token_type = \"keycloak\"\n",
                &format!("token_type = \"keycloak\"\n{fields}\n"),
            ))
            .unwrap()
        };
        let l = with(&format!(
            "openid_configuration_url = \"{WELL_KNOWN}\"\nscope = \"openid\""
        ));
        assert!(
            l.errors.is_empty() && l.warnings.is_empty(),
            "{:?} {:?}",
            l.errors,
            l.warnings
        );
        let printed = toml::to_string(&l.config).unwrap();
        assert!(
            printed.contains(WELL_KNOWN) && printed.contains("scope = \"openid\""),
            "{printed}"
        );

        for (fields, needle) in [
            (
                "openid_configuration_url = \"http://idp.example/x\"",
                "must be an https URL",
            ),
            // No local exception: the client fetches the document.
            (
                "openid_configuration_url = \"http://127.0.0.1/x\"",
                "must be an https URL",
            ),
            ("openid_configuration_url = \"nonsense\"", "bad url"),
            (
                "openid_configuration_url = \"https://u:p@idp.example/x\"",
                "user:password@",
            ),
            (
                "openid_configuration_url = \"https://idp.example/x#f\"",
                "fragment",
            ),
            ("scope = \"\"", "is not a scope"),
            ("scope = \"a  b\"", "is not a scope"),
            ("scope = \"a\\\"b\"", "is not a scope"),
            ("scope = \"ümlaut\"", "is not a scope"),
        ] {
            let e = with(fields).errors.join("\n");
            assert!(e.contains(needle), "{fields}\n→ {e}");
        }

        let w = with("openid_configuration_url = \"https://idp.example/other\"").warnings;
        assert!(w.iter().any(|w| w.contains(".well-known")), "{w:?}");
        let w = with("scope = \"openid email\"").warnings;
        assert!(w.iter().any(|w| w.contains("several scopes")), "{w:?}");

        let second = "[[oauth.issuers]]\nissuer = \"https://idp2.example\"\njwks_url = \"https://idp2.example/certs\"\naudiences = [\"dovecot\"]\ntoken_type = \"rfc9068\"\n";
        let e = crate::config::parse(&format!(
            "{}{second}scope = \"mail\"\n",
            V2.replace(
                "token_type = \"keycloak\"\n",
                "token_type = \"keycloak\"\nscope = \"mail\"\n",
            )
        ))
        .unwrap()
        .errors
        .join("\n");
        assert!(e.contains("oauth.issuers[1]: only one issuer"), "{e}");
        // One issuer with the fields and one without is fine.
        let l = crate::config::parse(&format!("{V2}{second}scope = \"mail\"\n")).unwrap();
        assert!(l.errors.is_empty(), "{:?}", l.errors);
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
        let w = crate::config::parse(&format!(
            "{V2}[legacy]\nallowed_domains = [\"example.org\"]\n"
        ))
        .unwrap()
        .warnings;
        assert!(w.iter().any(|w| w.contains("has no rules")), "{w:?}");
    }

    /// Errors of a whole configuration text, joined.
    fn errors_of(text: &str) -> String {
        crate::config::parse(text)
            .map(|l| l.errors.join("\n"))
            .unwrap_or_else(|e| format!("parse: {e}"))
    }

    /// The shipped example is valid and gives no warning.
    #[test]
    fn example_config_is_clean() {
        let l = crate::config::parse(include_str!("../../examples/config.example.toml")).unwrap();
        assert!(l.errors.is_empty(), "{:?}", l.errors);
        assert!(l.warnings.is_empty(), "{:?}", l.warnings);
    }

    /// The short form warns like the rule it becomes (`public = true`
    /// without users): once per public network, none for private ones.
    #[test]
    fn password_gate_warns_for_public_networks() {
        let warnings = |nets: &str| {
            crate::config::parse(&format!(
                "{V2}[password_gate]\nenabled = true\nsni = [\"mail.example.org\"]\ninternal_networks = [{nets}]\n"
            ))
            .unwrap()
            .warnings
        };
        let w = warnings(r#""10.0.0.0/8", "198.51.100.0/24", "2001:db8::/32""#);
        assert_eq!(w.len(), 2, "{w:?}");
        for (w, net) in w.iter().zip(["198.51.100.0/24", "2001:db8::/32"]) {
            assert!(w.contains("every user") && w.contains(net), "{w}");
        }
        let w = warnings(r#""0.0.0.0/0""#);
        assert!(
            w.len() == 1 && w[0].contains("every user") && w[0].contains("from anywhere"),
            "{w:?}"
        );
        assert!(warnings(r#""10.0.0.0/8", "fd00::/8", "127.0.0.1/32""#).is_empty());
    }

    /// Leeway, JWKS refresh and timeouts have upper bounds; the bounds
    /// themselves are allowed.
    #[test]
    fn time_values_are_bounded() {
        let oauth = |kv: &str| errors_of(&V2.replace("[oauth]\n", &format!("[oauth]\n{kv}\n")));
        assert!(oauth("leeway_secs = 300").is_empty());
        assert!(oauth("leeway_secs = 0").is_empty());
        for v in ["301", "4000000000"] {
            let e = oauth(&format!("leeway_secs = {v}"));
            assert!(e.contains("leeway_secs must be at most 300"), "{v}: {e}");
        }
        assert!(oauth("refresh_secs = 86400").is_empty());
        let e = oauth("refresh_secs = 86401");
        assert!(e.contains("refresh_secs must be at most 86400"), "{e}");
        for key in ["preauth_secs", "idle_secs", "connect_secs"] {
            assert!(errors_with(&format!("[timeouts]\n{key} = 3600\n")).is_empty());
            for v in ["3601", "9223372036854775807"] {
                let e = errors_with(&format!("[timeouts]\n{key} = {v}\n"));
                assert!(
                    e.contains(&format!("timeouts.{key} must be at most 3600 seconds")),
                    "{key} = {v}: {e}"
                );
            }
        }
    }

    /// `server.hostname` is an RFC 5321 Domain; IP addresses and address
    /// literals are refused.
    #[test]
    fn hostname_is_a_domain() {
        let with = |h: &str| errors_with(&format!("[server]\nhostname = {h:?}\n"));
        let long_label = "a".repeat(63);
        let long_name = format!("{0}.{0}.{0}.{1}", long_label, "a".repeat(61));
        assert_eq!(long_name.len(), 253);
        for ok in [
            "mail-auth-proxy",
            "mail.example.org",
            "MX1.Example.ORG",
            "xn--bcher-kva.example",
            "0mail.example.org",
            long_label.as_str(),
            long_name.as_str(),
        ] {
            assert!(with(ok).is_empty(), "{ok}: {}", with(ok));
        }
        let too_long = format!("a{long_name}");
        for bad in [
            "",
            "mail example",
            "-mail.example.org",
            "mail-.example.org",
            "mail..example.org",
            "mail.example.org.",
            ".example.org",
            "mail_1.example.org",
            "mäil.example.org",
            "mail\"x",
            "192.0.2.1",
            "2001:db8::1",
            "[192.0.2.1]",
            "[IPv6:2001:db8::1]",
            &format!("{long_label}a.example"),
            too_long.as_str(),
        ] {
            assert!(with(bad).contains("server.hostname"), "{bad:?} accepted");
        }
        assert!(with("192.0.2.1").contains("address literals are not allowed"));
    }

    /// Each extension is an `ehlo-line`; keywords are unique and never AUTH
    /// or STARTTLS, in any case.
    #[test]
    fn ehlo_extensions_are_ehlo_lines() {
        let with = |list: &str| {
            errors_with(&format!(
                "[submission]\nlisten = \"0.0.0.0:587\"\nbackend = {{ address = \"192.0.2.10:587\", verify_name = \"mail.example.org\" }}\nehlo_extensions = [{list}]\n"
            ))
        };
        assert!(with(r#""SIZE 10240000", "8BITMIME", "X-EXT a=b c", "DSN", "7X""#).is_empty());
        for bad in [
            r#""""#,
            r#"" ""#,
            r#"" AUTH""#,
            r#""SIZE ""#,
            r#""SIZE  1000""#,
            r#""SIZE\t1000""#,
            r#""-X""#,
            r#""X_Y""#,
            r#""AUTH=PLAIN""#,
            r#""SIZE 100ä""#,
        ] {
            assert!(
                with(bad).contains("is not an EHLO line"),
                "{bad}: {}",
                with(bad)
            );
        }
        for bad in [r#""auth PLAIN""#, r#""StartTLS""#] {
            assert!(with(bad).contains("is not allowed"), "{bad}");
        }
        let e = with(r#""SIZE 1000", "PIPELINING", "size 2000""#);
        assert!(e.contains("\"size\" is listed twice"), "{e}");
    }

    /// Listeners are compared as socket addresses, the metrics endpoint
    /// included: the same port on a covering wildcard clashes.
    #[test]
    fn listeners_clash_by_address() {
        // V2 listens on 0.0.0.0:993.
        let sieve = |listen: &str| {
            format!("[sieve]\nlisten = {listen:?}\nbackend = {{ address = \"192.0.2.10:4190\", verify_name = \"mail.example.org\" }}\n")
        };
        for l in [
            "[::]:993",
            "192.0.2.1:993",
            "[::ffff:192.0.2.1]:993",
            "0.0.0.0:993",
        ] {
            let e = errors_with(&sieve(l));
            assert!(e.contains("sieve.listen"), "{l}: {e}");
        }
        for l in [
            "[::]:4190",
            "[::1]:993",
            "[2001:db8::1]:993",
            "0.0.0.0:4190",
        ] {
            assert!(errors_with(&sieve(l)).is_empty(), "{l}");
        }
        let v6 = V2.replace("0.0.0.0:993", "[::]:993");
        assert!(errors_of(&format!("{v6}{}", sieve("127.0.0.1:993")))
            .contains("clashes with imap.listen"));
        assert!(errors_of(&format!("{v6}{}", sieve("[::1]:993"))).contains("clashes"));
        // Port 0: a free port each.
        let any = V2.replace("0.0.0.0:993", "127.0.0.1:0");
        assert!(errors_of(&format!("{any}{}", sieve("0.0.0.0:0"))).is_empty());
        let e = errors_with("[metrics]\nlisten = \"127.0.0.1:993\"\n");
        assert!(
            e.contains("metrics.listen = \"127.0.0.1:993\" clashes"),
            "{e}"
        );
        assert!(errors_with("[metrics]\nenabled = false\nlisten = \"127.0.0.1:993\"\n").is_empty());
    }

    /// A bad backend address is one error; the certificate name derived from
    /// it is not checked on top. An explicit `verify_name` still is.
    #[test]
    fn bad_backend_address_is_reported_once() {
        let sieve = |backend: &str| {
            errors_with(&format!(
                "[sieve]\nlisten = \"0.0.0.0:4190\"\nbackend = {backend}\n"
            ))
        };
        let e = sieve(r#"{ address = ":4190" }"#);
        assert!(e.contains("must be host:port"), "{e}");
        assert!(!e.contains("certificate name"), "{e}");
        let e = sieve(r#"{ address = ":4190", verify_name = "bad name" }"#);
        assert!(
            e.contains("must be host:port") && e.contains("certificate name"),
            "{e}"
        );
    }

    /// Every file path is checked for the empty string, with one message per
    /// key; `--check-config` then skips the path (tests/legacy_gate.rs).
    #[test]
    fn empty_file_paths_are_errors() {
        let doveadm = "[legacy]\naccount_check = \"doveadm\"\ndoveadm_url = \"https://127.0.0.1/doveadm/v1\"\n";
        let backend = |proto: &str, port: u16| {
            format!("[{proto}]\nlisten = \"0.0.0.0:{port}\"\nbackend = {{ address = \"192.0.2.10:{port}\", ca_file = \"\" }}\n")
        };
        let mut wrong = Vec::new();
        for (text, key) in [
            (V2.replace("\"/c.pem\"", "\"\""), "tls.cert"),
            (V2.replace("\"/k.pem\"", "\"\""), "tls.key"),
            (
                V2.replace("verify_name = ", "ca_file = \"\", verify_name = "),
                "imap.backend.ca_file",
            ),
            (
                format!("{V2}{}", backend("submission", 587)),
                "submission.backend.ca_file",
            ),
            (
                format!("{V2}{}", backend("sieve", 4190)),
                "sieve.backend.ca_file",
            ),
            (
                format!("{V2}{doveadm}doveadm_key_file = \"\"\n"),
                "legacy.doveadm_key_file",
            ),
            (
                format!("{V2}{doveadm}doveadm_key_file = \"/k\"\ndoveadm_ca_file = \"\"\n"),
                "legacy.doveadm_ca_file",
            ),
        ] {
            let errors = crate::config::parse(&text).unwrap().errors;
            if errors != [format!("{key} is empty")] {
                wrong.push(format!("{key}: {errors:?}"));
            }
        }
        assert!(wrong.is_empty(), "{wrong:#?}");
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
