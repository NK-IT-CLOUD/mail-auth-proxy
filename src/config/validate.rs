//! Validation: every check serde cannot express, and the normalisation of
//! the short forms into what the rest of the program reads.

use super::{
    AccountCheck, AccountCheckRef, AuthRateLimit, Backend, BackendRef, BackendTls, ClientIp,
    Config, Legacy, Protocol, Route, Rule, Session, TokenType, PASSWORD_GATE_RULE,
};
use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};

/// Upper bound of `[backends]` entries: every backend is a metric and log
/// label and a refusal-timing pool.
const MAX_BACKENDS: usize = 64;

/// Upper bound of a backend's `addresses`: each is a metric label set and
/// a health state.
const MAX_ADDRESSES: usize = 16;

/// Upper bound of `[[routes]]`: each credential walks them in order.
const MAX_ROUTES: usize = 256;

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

/// Upper bound of `limits.max_auth_attempts`. Every attempt is judged and
/// counted like one on a new connection; the bound keeps a single connection
/// from being a guessing channel of its own between two rate-limit checks.
const MAX_AUTH_ATTEMPTS: u32 = 10;

impl Config {
    /// Every check serde cannot express. Collects all problems instead of
    /// stopping at the first, so one `--check-config` run shows them all.
    pub(super) fn check(&self, errors: &mut Vec<String>, warnings: &mut Vec<String>) {
        let mut err = |m: String| errors.push(m);

        if let Err(e) = check_hostname(&self.server.hostname) {
            err(format!("server.hostname = {:?} {e}", self.server.hostname));
        } else if !self.server.hostname.contains('.') {
            // RFC 5321 §4.1.4: the EHLO domain MUST be the client's primary
            // host name, a fully-qualified domain name (§2.3.5). The proxy
            // sends it to the backend; a single label is syntactically fine.
            warnings.push(format!(
                "server.hostname = {:?} is not a fully-qualified domain name; the proxy sends it in its EHLO to the backend, where RFC 5321 section 4.1.4 requires the primary host name",
                self.server.hostname
            ));
        }
        // Empty file paths are reported here only; `server::file_problems`
        // skips them.
        let mut certs: Vec<(String, &str)> = Vec::new();
        for (at, cert, key) in self.tls.pairs() {
            check_path(&format!("{at}.cert"), Some(cert), &mut err);
            check_path(&format!("{at}.key"), Some(key), &mut err);
            // The file names the certificate in the metrics and the reload log.
            match certs.iter().find(|(_, c)| *c == cert) {
                Some((first, _)) if !cert.is_empty() => {
                    err(format!("{at}.cert = {cert:?} is already {first}.cert"));
                }
                _ => certs.push((at, cert)),
            }
        }

        let mut listens = vec![("imap.listen", &self.imap.listen)];
        if let Some(s) = &self.submission {
            listens.push(("submission.listen", &s.listen));
            if let Some(l) = &s.implicit_tls_listen {
                listens.push(("submission.implicit_tls_listen", l));
            }
            use crate::proto::smtp::ehlo::{ehlo_keyword, RELAYED};
            let mut keywords: Vec<&str> = Vec::new();
            for x in s.ehlo_extensions.iter().flatten() {
                match ehlo_keyword(x) {
                    None => err(format!("submission.ehlo_extensions: {x:?} is not an EHLO line (a keyword of letters, digits and hyphens, then parameters, separated by single spaces; RFC 5321 section 4.1.1.1)")),
                    Some(k) if ["AUTH", "STARTTLS"].iter().any(|v| k.eq_ignore_ascii_case(v)) => {
                        err(format!("submission.ehlo_extensions: {x:?} is not allowed (AUTH and STARTTLS are set by the proxy)"));
                    }
                    Some(k) if keywords.iter().any(|o| o.eq_ignore_ascii_case(k)) => {
                        err(format!("submission.ehlo_extensions: {k:?} is listed twice"));
                    }
                    Some(k) => {
                        keywords.push(k);
                        if !RELAYED.iter().any(|r| r.eq_ignore_ascii_case(k)) {
                            warnings.push(format!("submission.ehlo_extensions: {k:?} is never advertised: the proxy passes on only {} from the backend", RELAYED.join(", ")));
                        } else if k.len() < x.len() {
                            warnings.push(format!("submission.ehlo_extensions: the parameters of {x:?} are ignored: the backend's are advertised"));
                        }
                    }
                }
            }
            if s.capability_cache_secs == 0 {
                err("submission.capability_cache_secs must be at least 1".into());
            }
        }
        if let Some(s) = &self.sieve {
            listens.push(("sieve.listen", &s.listen));
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
            if iss.identity_claim.is_empty() || iss.client_claim().is_empty() {
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
            for d in &iss.identity_domains {
                if d.is_empty()
                    || d.contains('@')
                    || d.chars().any(|c| c.is_whitespace() || c.is_control())
                {
                    err(format!(
                        "{at}.identity_domains: {d:?} is not a domain (no @, whitespace or control characters)"
                    ));
                }
            }
            if self.oauth.issuers.len() > 1 && iss.identity_domains.is_empty() {
                warnings.push(format!("{at}: without identity_domains this issuer can log in to every mailbox, also those of the other issuers' users (OIDC Core section 5.7)"));
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

        self.check_backends(&mut err, warnings);
        self.check_routes(&mut err, warnings);

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
        if !(1..=MAX_AUTH_ATTEMPTS).contains(&l.max_auth_attempts) {
            err(format!(
                "limits.max_auth_attempts must be between 1 and {MAX_AUTH_ATTEMPTS}"
            ));
        } else if l.max_auth_attempts as usize > l.max_preauth_commands {
            warnings.push(format!(
                "limits.max_auth_attempts ({}) is larger than limits.max_preauth_commands ({}): every attempt is a command, so a connection gets at most {} attempts",
                l.max_auth_attempts, l.max_preauth_commands, l.max_preauth_commands
            ));
        }
        // Longer than /64 would give a host with its own /64 (RFC 7934) a
        // separate budget per address again.
        if !(32..=64).contains(&l.ipv6_source_prefix) {
            err("limits.ipv6_source_prefix must be between 32 and 64".into());
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
        self.auth_ratelimit.check(&mut err, warnings);
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
        self.session.check(&mut err, warnings);
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
        // Each backend profile with its defaults spelled out, by the
        // protocol that uses it; the short forms become `client_ip`.
        let xclient = self.submission.as_ref().is_some_and(|s| s.xclient);
        for protocol in Protocol::ALL {
            let names: Vec<String> = self
                .backends_of(protocol)
                .iter()
                .filter(|u| !u.inline)
                .map(|u| u.name.to_owned())
                .collect();
            let inline = match protocol {
                Protocol::Imap => self.imap.backend.as_mut(),
                Protocol::Submission => self.submission.as_mut().and_then(|s| s.backend.as_mut()),
                Protocol::Sieve => self.sieve.as_mut().and_then(|s| s.backend.as_mut()),
            };
            let mut used: Vec<&mut Backend> = match inline {
                Some(BackendRef::Inline(b)) => vec![b],
                _ => Vec::new(),
            };
            used.extend(
                self.backends
                    .iter_mut()
                    .filter(|(n, _)| names.contains(n))
                    .map(|(_, b)| b),
            );
            let xclient = protocol == Protocol::Submission && xclient;
            for b in used {
                b.client_ip = Some(b.effective_client_ip(xclient));
                b.proxy_protocol = false;
                b.tls.get_or_insert(default_tls(protocol));
            }
        }
        if let Some(s) = &mut self.submission {
            s.xclient = false;
        }
    }

    /// The backends: each used one against its protocol, the named ones for
    /// their names and use.
    fn check_backends(&self, err: &mut impl FnMut(String), warnings: &mut Vec<String>) {
        if self.backends.len() > MAX_BACKENDS {
            err(format!("backends: at most {MAX_BACKENDS} backends"));
        }
        for name in self.backends.keys() {
            if !is_plain_name(name) {
                err(format!(
                    "backends.{name}: the name must be 1-64 of A-Z a-z 0-9 . _ -"
                ));
            } else if Protocol::ALL.iter().any(|p| p.section() == name) {
                err(format!(
                    "backends.{name}: the name is reserved for the backend written in [{name}]"
                ));
            }
        }
        let xclient = self.submission.as_ref().is_some_and(|s| s.xclient);
        let mut users: BTreeMap<&str, Protocol> = BTreeMap::new();
        for protocol in Protocol::ALL.into_iter().filter(|p| self.has_protocol(*p)) {
            let section = protocol.section();
            match self.listener_backend(protocol) {
                Some(BackendRef::Name(name)) if !self.backends.contains_key(name) => {
                    err(format!(
                        "{section}.backend = {name:?} names no [backends] entry"
                    ));
                }
                Some(_) if self.routes.iter().any(|r| r.backend(protocol).is_some()) => {
                    err(format!(
                        "{section}.backend and routes with {section} = … cannot be combined: the routes choose the backend"
                    ));
                }
                Some(_) => {}
                None if self.routes.iter().any(|r| r.backend(protocol).is_some()) => {}
                None => err(format!(
                    "{section}.backend is required (or routes with {section} = …)"
                )),
            }
            let submission = protocol == Protocol::Submission;
            // One doveadm for several backends checks every account against
            // one mail system: another's accounts would all be unknown.
            let used = self.backends_of(protocol);
            if used.len() > 1 && self.legacy.account_check == AccountCheck::Doveadm {
                for u in used.iter().filter(|u| u.backend.account_check.is_none()) {
                    warnings.push(format!(
                        "{}: uses legacy.account_check = \"doveadm\" although [{section}] has {} backends; set account_check on each backend",
                        u.key(),
                        used.len()
                    ));
                }
            }
            for used in used {
                if !used.inline {
                    match users.insert(used.name, protocol) {
                        Some(other) if other != protocol => err(format!(
                            "backends.{}: used by {} and {section}; a backend serves one protocol",
                            used.name,
                            other.section()
                        )),
                        _ => {}
                    }
                }
                let key = used.key();
                check_client_ip(
                    &key,
                    used.backend,
                    submission,
                    submission && xclient,
                    err,
                    warnings,
                );
                check_backend_address(&key, used.backend, err);
            }
        }
        for (name, b) in &self.backends {
            if !users.contains_key(name.as_str()) {
                warnings.push(format!(
                    "backends.{name} is not used by any listener or route"
                ));
                check_backend_address(&format!("backends.{name}"), b, err);
            }
        }
    }

    /// The routes: names, conditions, the backends they name, and routes an
    /// earlier one makes unreachable.
    fn check_routes(&self, err: &mut impl FnMut(String), warnings: &mut Vec<String>) {
        if self.routes.len() > MAX_ROUTES {
            err(format!("routes: at most {MAX_ROUTES} routes"));
        }
        for (i, r) in self.routes.iter().enumerate() {
            let at = format!("routes[{i}]");
            if !is_plain_name(&r.name) {
                err(format!(
                    "{at}.name {:?} must be 1-64 of A-Z a-z 0-9 . _ -",
                    r.name
                ));
            } else if self.routes[..i].iter().any(|o| o.name == r.name) {
                err(format!("{at}.name {:?} is used twice", r.name));
            }
            if r.domains.is_empty() && r.issuers.is_empty() {
                err(format!("{at}: set domains or issuers"));
            }
            for d in &r.domains {
                if d == "*" {
                    if r.domains.len() > 1 {
                        err(format!(
                            "{at}.domains: \"*\" matches every domain; list nothing else"
                        ));
                    }
                    if i + 1 != self.routes.len() {
                        err(format!(
                            "{at}.domains: \"*\" only in the last route, the routes after it are never reached"
                        ));
                    }
                } else if let Err(e) = check_domain_entry(d) {
                    err(format!("{at}.domains: {d:?} {e}"));
                }
            }
            for iss in &r.issuers {
                if !self.oauth.issuers.iter().any(|o| o.issuer == *iss) {
                    err(format!(
                        "{at}.issuers: {iss:?} is not an oauth.issuers entry"
                    ));
                }
            }
            if r.sni.iter().chain(&r.audiences).any(String::is_empty) {
                err(format!("{at}: sni and audiences entries must not be empty"));
            }
            let served: Vec<Protocol> = Protocol::ALL
                .into_iter()
                .filter(|p| r.backend(*p).is_some())
                .collect();
            if served.is_empty() {
                err(format!(
                    "{at}: name a backend for imap, submission or sieve"
                ));
            }
            for p in &served {
                let name = r.backend(*p).unwrap_or_default();
                if !self.backends.contains_key(name) {
                    err(format!(
                        "{at}.{} = {name:?} names no [backends] entry",
                        p.section()
                    ));
                }
                if !self.has_protocol(*p) {
                    err(format!("{at}.{0}: there is no [{0}] section", p.section()));
                }
            }
            // An earlier route with the same conditions that serves every
            // protocol of this one takes all its credentials.
            let same = |o: &Route| {
                let set = |v: &[String]| {
                    let mut v: Vec<String> = v.iter().map(|x| x.to_ascii_lowercase()).collect();
                    v.sort();
                    v
                };
                set(&o.issuers) == set(&r.issuers)
                    && set(&o.sni) == set(&r.sni)
                    && set(&o.audiences) == set(&r.audiences)
                    && served.iter().all(|p| o.backend(*p).is_some())
            };
            for d in &r.domains {
                if let Some(o) = self.routes[..i]
                    .iter()
                    .find(|o| same(o) && o.domains.iter().any(|od| od.eq_ignore_ascii_case(d)))
                {
                    err(format!(
                        "{at}: domain {d:?} is already taken by route {:?} with the same conditions",
                        o.name
                    ));
                }
            }
            // Only when every issuer is bounded: otherwise any issuer may
            // vouch for the domain.
            let bounded = self
                .oauth
                .issuers
                .iter()
                .all(|i| !i.identity_domains.is_empty());
            for d in r.domains.iter().filter(|d| *d != "*") {
                let reachable = self.oauth.issuers.iter().any(|iss| {
                    (r.issuers.is_empty() || r.issuers.contains(&iss.issuer))
                        && iss
                            .identity_domains
                            .iter()
                            .any(|x| x.eq_ignore_ascii_case(d))
                });
                if bounded && !reachable {
                    warnings.push(format!(
                        "{at}: no issuer that the route accepts has {d:?} in its identity_domains; only passwords can use it"
                    ));
                }
            }
        }
    }
}

/// An account check: `doveadm` needs its URL and key file, `none` none of
/// the `doveadm_*` keys.
fn check_account(a: AccountCheckRef<'_>, err: &mut impl FnMut(String)) {
    let at = a.at;
    match a.check {
        AccountCheck::Doveadm => {
            match a.url {
                None => err(format!(
                    "{at}.doveadm_url is required with account_check = \"doveadm\""
                )),
                Some(u) => {
                    if let Err(e) = check_service_url(u) {
                        err(format!("{at}.doveadm_url: {e}"));
                    }
                }
            }
            match a.key_file {
                None => err(format!(
                    "{at}.doveadm_key_file is required with account_check = \"doveadm\""
                )),
                key => check_path(&format!("{at}.doveadm_key_file"), key, err),
            }
            check_path(&format!("{at}.doveadm_ca_file"), a.ca_file, err);
        }
        AccountCheck::None => {
            if a.url.is_some() || a.key_file.is_some() || a.ca_file.is_some() {
                err(format!(
                    "{at}.doveadm_* is set but account_check is not \"doveadm\""
                ));
            }
        }
    }
}

/// The protocol's backend TLS when the profile does not say.
fn default_tls(protocol: Protocol) -> BackendTls {
    match protocol {
        Protocol::Imap => BackendTls::Implicit,
        Protocol::Submission | Protocol::Sieve => BackendTls::Starttls,
    }
}

/// `address`, `verify_name`, `ca_file` and the account check of the backend
/// at `key`.
fn check_backend_address(key: &str, b: &Backend, err: &mut impl FnMut(String)) {
    check_path(&format!("{key}.ca_file"), b.ca_file.as_deref(), err);
    match b.account_check_at(key) {
        Some(a) => check_account(a, err),
        None if b.has_doveadm_keys() => err(format!(
            "{key}.doveadm_* is set but account_check is not \"doveadm\""
        )),
        None => {}
    }
    let list: Vec<(String, &str)> = match (b.address.is_empty(), b.addresses.is_empty()) {
        (false, true) => vec![(format!("{key}.address"), b.address.as_str())],
        (true, false) => b
            .addresses
            .iter()
            .enumerate()
            .map(|(i, a)| (format!("{key}.addresses[{i}]"), a.as_str()))
            .collect(),
        (true, true) => {
            err(format!("{key}: set address or addresses"));
            return;
        }
        (false, false) => {
            err(format!("{key}: address and addresses cannot be combined"));
            return;
        }
    };
    if list.len() > MAX_ADDRESSES {
        err(format!("{key}.addresses: at most {MAX_ADDRESSES}"));
    }
    if let Some(secs) = b.health_check_secs {
        if !(1..=MAX_TIMEOUT_SECS).contains(&secs) {
            err(format!(
                "{key}.health_check_secs must be between 1 and {MAX_TIMEOUT_SECS}"
            ));
        }
    }
    for (i, (at, address)) in list.iter().enumerate() {
        if list[..i]
            .iter()
            .any(|(_, o)| o.eq_ignore_ascii_case(address))
        {
            err(format!("{at} = {address:?} is listed twice"));
        }
        let address_ok = address
            .rsplit_once(':')
            .is_some_and(|(h, p)| !h.is_empty() && p.parse::<u16>().is_ok());
        if !address_ok {
            err(format!("{at} = {address:?} must be host:port"));
        }
        // Without verify_name the name comes from each address; a bad
        // address is reported once, above.
        let vname = match &b.verify_name {
            Some(_) if i > 0 => continue,
            Some(n) => n.clone(),
            None if address_ok => crate::wire::connect::host_of(address).to_string(),
            None => continue,
        };
        if rustls::pki_types::ServerName::try_from(vname.clone()).is_err() {
            err(format!("{key}: {vname:?} is not a valid certificate name"));
        }
    }
}

/// `client_ip` of the backend `name` against its short forms
/// (`proxy_protocol`, `submission.xclient`) and its protocol.
fn check_client_ip(
    name: &str,
    b: &Backend,
    submission: bool,
    xclient: bool,
    err: &mut impl FnMut(String),
    warnings: &mut Vec<String>,
) {
    if b.client_ip.is_some() && (b.proxy_protocol || xclient) {
        err(format!(
            "{name}.client_ip cannot be combined with its short form ({})",
            if xclient {
                "submission.xclient"
            } else {
                "proxy_protocol"
            }
        ));
        return;
    }
    if b.proxy_protocol && xclient {
        err(format!(
            "{name}: proxy_protocol and submission.xclient cannot both be set; choose one with client_ip"
        ));
        return;
    }
    match b.effective_client_ip(xclient) {
        ClientIp::Xclient if !submission => err(format!(
            "{name}.client_ip = \"xclient\" is an SMTP extension: submission.backend only"
        )),
        ClientIp::None => warnings.push(format!(
            "{name}: client_ip = \"none\": the backend sees the proxy's address for every client, so its per-address limits, bans and logs treat all clients as one (set client_ip = \"proxy_v2\"{})",
            if submission { " or \"xclient\"" } else { "" }
        )),
        _ => {}
    }
}

/// A name that goes into a log field and a metric label unchanged.
fn is_plain_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
}

/// A configured file path: not empty, and absolute. A relative path would
/// resolve against the working directory, which differs between the service,
/// `--check-config` in a shell and a reload, so the check could pass on a
/// file the service never reads.
fn check_path(name: &str, path: Option<&str>, err: &mut impl FnMut(String)) {
    match path {
        Some("") => err(format!("{name} is empty")),
        Some(p) if !std::path::Path::new(p).is_absolute() => {
            err(format!("{name} = {p:?} must be an absolute path"))
        }
        _ => {}
    }
}

/// `server.hostname` goes unchanged into the SMTP greeting and EHLO reply,
/// the proxy's EHLO to the backend, the IMAP greeting and the ManageSieve
/// IMPLEMENTATION string. It must be a `Domain` of RFC 5321 section 4.1.2:
/// dot-separated labels of letters, digits and hyphens, no hyphen at either
/// end of a label, 1-63 characters each and 253 in all (the 255-octet limit
/// of RFC 1035 section 2.3.4, in text form). An address literal (`[192.0.2.1]`) is not accepted: the EHLO
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
        check_path("legacy.domains_file", self.domains_file.as_deref(), err);
        check_account(self.account_check_ref(), err);
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
            check_path(&format!("{at}.users_file"), r.users_file.as_deref(), err);
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

// ── [session] ───────────────────────────────────────────────────────────────

/// Upper bound of `keepalive_idle_secs` and `keepalive_interval_secs`: the
/// largest value Linux accepts for TCP_KEEPIDLE and TCP_KEEPINTVL
/// (`MAX_TCP_KEEPIDLE`, `MAX_TCP_KEEPINTVL`).
const MAX_KEEPALIVE_SECS: u64 = 32_767;

/// Upper bound of `keepalive_count`: the largest TCP_KEEPCNT Linux accepts
/// (`MAX_TCP_KEEPCNT`).
const MAX_KEEPALIVE_COUNT: u32 = 127;

/// Shortest post-login inactivity limit that IMAP and ManageSieve clients
/// may rely on: RFC 9051 section 5.4 and RFC 5804 section 1.2 require an
/// autologout timer of at least 30 minutes, and IDLE clients re-issue IDLE
/// only every 29 minutes (RFC 9051 section 6.3.13, RFC 2177). A shorter
/// limit breaks such clients but weakens nothing, so it is a warning, not
/// an error.
const MIN_RFC_SESSION_SECS: u64 = 1800;

/// Upper bound of `idle_limit_secs` and `max_session_secs`: 30 days. Longer
/// is the same as off, and past 2^63 seconds the deadline overflows the
/// clock.
const MAX_SESSION_SECS: u64 = 30 * 86_400;

impl Session {
    fn check(&self, err: &mut impl FnMut(String), warnings: &mut Vec<String>) {
        for (name, secs) in [
            ("keepalive_idle_secs", self.keepalive_idle_secs),
            ("keepalive_interval_secs", self.keepalive_interval_secs),
        ] {
            if !(1..=MAX_KEEPALIVE_SECS).contains(&secs) {
                err(format!(
                    "session.{name} must be between 1 and {MAX_KEEPALIVE_SECS} seconds"
                ));
            }
        }
        // RFC 9293 section 3.8.4 (MUST-29): one unanswered probe does not
        // mean a dead connection; probes are bare ACKs and can be lost.
        if !(2..=MAX_KEEPALIVE_COUNT).contains(&self.keepalive_count) {
            err(format!(
                "session.keepalive_count must be between 2 and {MAX_KEEPALIVE_COUNT} (one lost probe must not end a connection; RFC 9293 section 3.8.4)"
            ));
        }
        for (name, secs) in [
            ("idle_limit_secs", self.idle_limit_secs),
            ("max_session_secs", self.max_session_secs),
        ] {
            let Some(secs) = secs else { continue };
            if !(1..=MAX_SESSION_SECS).contains(&secs) {
                err(format!(
                    "session.{name} must be between 1 and {MAX_SESSION_SECS} seconds; leave it out to turn it off"
                ));
            } else if secs < MIN_RFC_SESSION_SECS {
                warnings.push(format!(
                    "session.{name} = {secs} is below 30 minutes: IMAP and ManageSieve clients may count on at least 30 minutes of inactivity after login (RFC 9051 section 5.4, RFC 5804 section 1.2), and IDLE clients re-issue IDLE only every 29 minutes (RFC 9051 section 6.3.13); such sessions are cut"
                ));
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

/// Upper bound of `auth_ratelimit.window_secs` and `block_secs`: a day.
const MAX_RATELIMIT_SECS: u64 = 86_400;

/// Upper bound of `auth_ratelimit.max_block_secs`: a week. An escalated
/// source is remembered that long after its block, which holds table room.
const MAX_RATELIMIT_BLOCK_SECS: u64 = 7 * 86_400;

impl AuthRateLimit {
    fn check(&self, err: &mut impl FnMut(String), warnings: &mut Vec<String>) {
        if self.failures == 0 {
            err("auth_ratelimit.failures must be at least 1".into());
        }
        for (name, secs) in [
            ("window_secs", self.window_secs),
            ("block_secs", self.block_secs),
        ] {
            if secs == 0 || secs > MAX_RATELIMIT_SECS {
                err(format!(
                    "auth_ratelimit.{name} must be between 1 and {MAX_RATELIMIT_SECS} seconds"
                ));
            }
        }
        if self.max_block_secs < self.block_secs || self.max_block_secs > MAX_RATELIMIT_BLOCK_SECS {
            err(format!("auth_ratelimit.max_block_secs must be between block_secs and {MAX_RATELIMIT_BLOCK_SECS} seconds"));
        }
        match crate::auth::policy::parse_internal_nets(&self.exempt_networks) {
            Ok(nets) => {
                for n in nets.iter().filter(|n| !is_private_net(n)) {
                    warnings.push(format!(
                        "auth_ratelimit.exempt_networks: sources in the public network {n} are never blocked"
                    ));
                }
            }
            Err(e) => err(format!("auth_ratelimit.exempt_networks: {e:#}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::config::tests::{parse, V2};
    use crate::config::{Backend, BackendRef, BackendTls, ClientIp, Protocol, PASSWORD_GATE_RULE};

    /// Errors of `V2` plus `extra`, joined.
    /// The inline backend of a listener.
    fn inline(b: &Option<BackendRef>) -> &Backend {
        match b {
            Some(BackendRef::Inline(b)) => b,
            other => panic!("not an inline backend: {other:?}"),
        }
    }

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
        assert!(with("[submission]\nlisten = \"0.0.0.0:587\"\nbackend = { address = \"192.0.2.10:587\", proxy_protocol = true }\nxclient = true\n").is_err());
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

    /// `identity_domains` takes domains only. With several issuers, each one
    /// without it is warned about: it can log in to every mailbox.
    #[test]
    fn issuer_identity_domains() {
        let with = |first: &str, second: &str| {
            let cfg = V2.replace(
                "token_type = \"keycloak\"\n",
                &format!("token_type = \"keycloak\"\n{first}"),
            );
            crate::config::parse(&format!(
                "{cfg}[[oauth.issuers]]\nissuer = \"https://idp2.example\"\njwks_url = \"https://idp2.example/certs\"\naudiences = [\"dovecot\"]\ntoken_type = \"rfc9068\"\n{second}"
            ))
            .unwrap()
        };
        let domains = |d: &str| format!("identity_domains = [\"{d}\"]\n");
        let unbound = |l: &crate::config::Loaded| {
            l.warnings
                .iter()
                .filter(|w| w.contains("without identity_domains"))
                .cloned()
                .collect::<Vec<_>>()
        };
        let l = with(&domains("example.org"), &domains("example.net"));
        assert!(l.errors.is_empty(), "{:?}", l.errors);
        assert!(unbound(&l).is_empty(), "{:?}", l.warnings);
        let l = with(&domains("example.org"), "");
        assert_eq!(unbound(&l).len(), 1, "{:?}", l.warnings);
        assert!(unbound(&l)[0].starts_with("oauth.issuers[1]"));
        assert_eq!(unbound(&with("", "")).len(), 2);
        let one = crate::config::parse(V2).unwrap();
        assert!(unbound(&one).is_empty(), "one issuer: {:?}", one.warnings);
        for bad in ["", "a@example.org", "example .org"] {
            let e = with(&domains(bad), &domains("example.net"))
                .errors
                .join("\n");
            assert!(
                e.contains("oauth.issuers[0].identity_domains"),
                "{bad:?}: {e}"
            );
        }
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

    /// `[[tls.certificates]]` next to the `[tls]` default: every path is
    /// checked under its own key, a certificate file may appear once, and
    /// the printed form keeps the list.
    #[test]
    fn tls_certificates() {
        let with =
            |list: &str| V2.replace("key = \"/k.pem\"\n", &format!("key = \"/k.pem\"\n{list}"));
        let entry = |c: &str, k: &str| format!("[[tls.certificates]]\ncert = {c:?}\nkey = {k:?}\n");

        let text = with(&(entry("/t.pem", "/t.key") + &entry("/w.pem", "/k.pem")));
        let c = parse(&text).unwrap().config;
        let pairs: Vec<_> = c.tls.pairs().collect();
        assert_eq!(
            pairs,
            [
                ("tls".to_string(), "/c.pem", "/k.pem"),
                ("tls.certificates[0]".to_string(), "/t.pem", "/t.key"),
                ("tls.certificates[1]".to_string(), "/w.pem", "/k.pem"),
            ]
        );
        let printed = toml::to_string(&c).unwrap();
        assert!(printed.contains("[[tls.certificates]]"), "{printed}");
        assert_eq!(parse(&printed).unwrap().config.tls.certificates.len(), 2);
        // Without the list the printed form is the one of before.
        let printed = toml::to_string(&parse(V2).unwrap().config).unwrap();
        assert!(!printed.contains("certificates"), "{printed}");

        for (list, want) in [
            (entry("", "/t.key"), "tls.certificates[0].cert is empty"),
            (entry("/t.pem", ""), "tls.certificates[0].key is empty"),
            (
                entry("t.pem", "/t.key"),
                "tls.certificates[0].cert = \"t.pem\" must be an absolute path",
            ),
            (
                entry("/c.pem", "/t.key"),
                "tls.certificates[0].cert = \"/c.pem\" is already tls.cert",
            ),
            (
                entry("/t.pem", "/t.key") + &entry("/t.pem", "/u.key"),
                "tls.certificates[1].cert = \"/t.pem\" is already tls.certificates[0].cert",
            ),
        ] {
            let errors = crate::config::parse(&with(&list)).unwrap().errors;
            assert_eq!(errors, [want], "{list}");
        }
        // Keys are checked per entry: an unknown key is a schema error.
        assert!(crate::config::parse(&with(
            "[[tls.certificates]]\ncert = \"/t.pem\"\nkey = \"/t.key\"\nsni = []\n"
        ))
        .is_err());
        // Both files of an entry are required.
        assert!(crate::config::parse(&with("[[tls.certificates]]\ncert = \"/t.pem\"\n")).is_err());
    }

    /// The shipped examples are valid and give no warning.
    #[test]
    fn example_config_is_clean() {
        for text in [
            include_str!("../../examples/config.example.toml"),
            include_str!("../../examples/config.dovecot-postfix.toml"),
            include_str!("../../examples/config.stalwart.toml"),
        ] {
            let l = crate::config::parse(text).unwrap();
            assert!(l.errors.is_empty(), "{:?}", l.errors);
            assert!(l.warnings.is_empty(), "{:?}", l.warnings);
        }
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

    /// `limits.max_auth_attempts` is 1-10 (default 3); more attempts than
    /// commands is a warning.
    #[test]
    fn auth_attempts_are_bounded() {
        let l = crate::config::parse(V2).unwrap();
        assert_eq!(l.config.limits.max_auth_attempts, 3);
        for v in ["1", "10"] {
            assert!(errors_with(&format!("[limits]\nmax_auth_attempts = {v}\n")).is_empty());
        }
        for v in ["0", "11"] {
            let e = errors_with(&format!("[limits]\nmax_auth_attempts = {v}\n"));
            assert!(
                e.contains("max_auth_attempts must be between 1 and 10"),
                "{v}: {e}"
            );
        }
        let l = crate::config::parse(&format!(
            "{V2}[limits]\nmax_auth_attempts = 5\nmax_preauth_commands = 4\n"
        ))
        .unwrap();
        assert!(l.errors.is_empty(), "{:?}", l.errors);
        assert!(
            l.warnings
                .iter()
                .any(|w| w.contains("max_auth_attempts (5)")),
            "{:?}",
            l.warnings
        );
    }

    /// `server.hostname` is an RFC 5321 Domain; IP addresses and address
    /// literals are refused.
    #[test]
    fn hostname_is_a_domain() {
        let with = |h: &str| {
            crate::config::parse(&V2.replace(
                "hostname = \"proxy.example.org\"",
                &format!("hostname = {h:?}"),
            ))
            .map(|l| l.errors.join("\n"))
            .unwrap_or_else(|e| format!("parse: {e}"))
        };
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

    /// A single-label `server.hostname` is valid but warned about: the
    /// backend EHLO takes the primary host name, an FQDN (RFC 5321 §4.1.4,
    /// §2.3.5).
    #[test]
    fn single_label_hostname_warns() {
        let warnings = |h: &str| {
            parse(&V2.replace(
                "hostname = \"proxy.example.org\"",
                &format!("hostname = {h:?}"),
            ))
            .unwrap()
            .warnings
            .join("\n")
        };
        for single in ["mail-auth-proxy", "localhost", "MX1"] {
            assert!(
                warnings(single).contains("server.hostname"),
                "{single}: {}",
                warnings(single)
            );
        }
        for fqdn in ["mail.example.org", "mx1.example"] {
            assert!(!warnings(fqdn).contains("server.hostname"), "{fqdn}");
        }
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

    /// `submission.ehlo_extensions` narrows the backend's list: a keyword
    /// the proxy never passes on, and parameters, which the backend's
    /// replace, are warned about. Unset, it is left out of the printed
    /// configuration.
    #[test]
    fn ehlo_extensions_warnings() {
        let sub = "[submission]\nlisten = \"0.0.0.0:587\"\nbackend = { address = \"192.0.2.10:587\", verify_name = \"mail.example.org\", client_ip = \"xclient\" }\n";
        let warnings = |extra: &str| {
            let l = crate::config::parse(&format!("{V2}{sub}{extra}")).unwrap();
            assert!(l.errors.is_empty(), "{:?}", l.errors);
            l.warnings
                .into_iter()
                .filter(|w| w.contains("submission."))
                .collect::<Vec<_>>()
        };
        assert!(warnings("").is_empty());
        assert!(warnings("ehlo_extensions = [\"PIPELINING\", \"dsn\"]\n").is_empty());
        let w = warnings("ehlo_extensions = [\"VRFY\", \"SIZE 1000\", \"X-EXT\"]\n");
        assert_eq!(w.len(), 3, "{w:?}");
        assert!(w[0].contains("\"VRFY\" is never advertised"), "{w:?}");
        assert!(
            w[1].contains("parameters of \"SIZE 1000\" are ignored"),
            "{w:?}"
        );
        assert!(w[2].contains("\"X-EXT\" is never advertised"), "{w:?}");
        let e = errors_with(&format!("{sub}capability_cache_secs = 0\n"));
        assert!(
            e.contains("submission.capability_cache_secs must be at least 1"),
            "{e}"
        );
        let l = crate::config::parse(&format!("{V2}{sub}")).unwrap();
        assert_eq!(l.config.submission.as_ref().unwrap().ehlo_extensions, None);
        assert_eq!(l.config.submission.unwrap().capability_cache_secs, 600);
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

    /// `limits.ipv6_source_prefix`: 64 by default, 32-64 allowed.
    #[test]
    fn ipv6_source_prefix_is_bounded() {
        assert_eq!(parse(V2).unwrap().config.limits.ipv6_source_prefix, 64);
        for (prefix, ok) in [
            (32, true),
            (48, true),
            (64, true),
            (31, false),
            (65, false),
            (128, false),
        ] {
            let errors = errors_with(&format!("[limits]\nipv6_source_prefix = {prefix}\n"));
            assert_eq!(errors.is_empty(), ok, "{prefix}: {errors}");
        }
    }

    /// Every file path must be absolute: a relative one resolves against the
    /// working directory, which differs between `--check-config` in a shell
    /// and the service.
    #[test]
    fn relative_file_paths_are_errors() {
        let rel = "\"certs/x.pem\"";
        let doveadm = "[legacy]\naccount_check = \"doveadm\"\ndoveadm_url = \"https://127.0.0.1/doveadm/v1\"\ndoveadm_key_file = \"/k\"\n";
        let rule = "[[legacy.rules]]\nname = \"a\"\nnetworks = [\"10.0.0.0/8\"]\n";
        let mut wrong = Vec::new();
        for (text, key) in [
            (V2.replace("\"/c.pem\"", rel), "tls.cert"),
            (V2.replace("\"/k.pem\"", rel), "tls.key"),
            (V2.replace("\"/k.pem\"", "\"./k.pem\""), "tls.key"),
            (
                V2.replace(
                    "verify_name = ",
                    &format!("ca_file = {rel}, verify_name = "),
                ),
                "imap.backend.ca_file",
            ),
            (
                format!("{V2}{}", doveadm.replace("\"/k\"", rel)),
                "legacy.doveadm_key_file",
            ),
            (
                format!("{V2}{doveadm}doveadm_ca_file = {rel}\n"),
                "legacy.doveadm_ca_file",
            ),
            (
                format!("{V2}[legacy]\ndomains_file = {rel}\n{rule}"),
                "legacy.domains_file",
            ),
            (
                format!("{V2}{rule}users_file = {rel}\n"),
                "legacy.rules[a].users_file",
            ),
        ] {
            let errors = crate::config::parse(&text).unwrap().errors;
            if !(errors.len() == 1
                && errors[0].starts_with(key)
                && errors[0].ends_with("must be an absolute path"))
            {
                wrong.push(format!("{key}: {errors:?}"));
            }
        }
        assert!(wrong.is_empty(), "{wrong:#?}");
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

    /// `[session]`: keepalive on with its defaults, both limits off; the
    /// kernel's ranges and RFC 9293's "not one probe" are errors, limits
    /// below the RFC autologout floor a warning.
    #[test]
    fn session_defaults_bounds_and_rfc_floor() {
        let l = parse(V2).unwrap();
        let s = &l.config.session;
        assert_eq!(
            (
                s.keepalive_idle_secs,
                s.keepalive_interval_secs,
                s.keepalive_count
            ),
            (600, 60, 5)
        );
        assert!(s.idle_limit_secs.is_none() && s.max_session_secs.is_none());
        assert!(!toml::to_string(&l.config).unwrap().contains("idle_limit"));

        for (extra, needle) in [
            (
                "keepalive_idle_secs = 0",
                "keepalive_idle_secs must be between 1 and 32767",
            ),
            (
                "keepalive_interval_secs = 32768",
                "keepalive_interval_secs must be between 1 and 32767",
            ),
            ("keepalive_count = 1", "RFC 9293"),
            (
                "keepalive_count = 128",
                "keepalive_count must be between 2 and 127",
            ),
            ("idle_limit_secs = 0", "idle_limit_secs must be between 1"),
            (
                "max_session_secs = 2592001",
                "max_session_secs must be between 1",
            ),
        ] {
            let e = errors_with(&format!("[session]\n{extra}\n"));
            assert!(e.contains(needle), "{extra}: {e}");
        }

        let l = parse(&format!(
            "{V2}[session]\nidle_limit_secs = 1800\nmax_session_secs = 86400\n"
        ))
        .unwrap();
        assert!(l.warnings.is_empty(), "{:?}", l.warnings);
        let l = parse(&format!(
            "{V2}[session]\nidle_limit_secs = 1799\nmax_session_secs = 600\n"
        ))
        .unwrap();
        assert_eq!(l.warnings.len(), 2, "{:?}", l.warnings);
        assert!(l
            .warnings
            .iter()
            .all(|w| w.contains("RFC 9051 section 5.4")));
    }

    /// The backend profile: defaults are the behaviour of the short forms
    /// (IMAP implicit TLS, submission and ManageSieve STARTTLS, XOAUTH2),
    /// the short forms become `client_ip`, and the printed form parses back
    /// to the same configuration.
    #[test]
    fn backend_profile_defaults_and_short_forms() {
        let text = format!(
            "{}[submission]\nlisten = \"0.0.0.0:587\"\nbackend = {{ address = \"192.0.2.10:587\" }}\nxclient = true\n[sieve]\nlisten = \"0.0.0.0:4190\"\nbackend = {{ address = \"192.0.2.10:4190\", proxy_protocol = true }}\n",
            V2.replace(", client_ip = \"proxy_v2\"", "")
        );
        let l = crate::config::parse(&text).unwrap();
        assert!(l.errors.is_empty(), "{:?}", l.errors);
        let c = &l.config;
        let (imap, sub, sieve) = (
            inline(&c.imap.backend),
            inline(&c.submission.as_ref().unwrap().backend),
            inline(&c.sieve.as_ref().unwrap().backend),
        );
        assert_eq!(imap.client_ip, Some(ClientIp::None));
        assert_eq!(sub.client_ip, Some(ClientIp::Xclient));
        assert_eq!(sieve.client_ip, Some(ClientIp::ProxyV2));
        assert_eq!(imap.tls, Some(BackendTls::Implicit));
        assert_eq!(sub.tls, Some(BackendTls::Starttls));
        assert_eq!(sieve.tls, Some(BackendTls::Starttls));
        for b in [imap, sub, sieve] {
            assert_eq!(b.auth_forward, crate::config::AuthForward::Xoauth2);
            assert!(!b.proxy_protocol);
        }
        assert!(!c.submission.as_ref().unwrap().xclient);
        // Only the IMAP backend is left without the client address.
        let none: Vec<_> = l
            .warnings
            .iter()
            .filter(|w| w.contains("client_ip = \"none\""))
            .collect();
        assert_eq!(none.len(), 1, "{none:?}");
        assert!(none[0].starts_with("imap.backend:"), "{none:?}");
        assert!(none[0].contains("per-address limits"), "{none:?}");
        let printed = toml::to_string(c).unwrap();
        assert!(!printed.contains("proxy_protocol") && !printed.contains("xclient = "));
        let back =
            parse(&printed.replace("client_ip = \"none\"", "client_ip = \"proxy_v2\"")).unwrap();
        assert_eq!(
            toml::to_string(&back.config).unwrap(),
            printed.replace("client_ip = \"none\"", "client_ip = \"proxy_v2\"")
        );
    }

    /// Explicit profile keys parse; `xclient` is for submission only; a key
    /// and its short form cannot be combined.
    #[test]
    fn backend_profile_is_validated() {
        let sub = |backend: &str, extra: &str| {
            format!("[submission]\nlisten = \"0.0.0.0:587\"\nbackend = {{ address = \"192.0.2.10:587\"{backend} }}\n{extra}")
        };
        let l = parse(&format!(
            "{}{}",
            V2.replace(
                "client_ip = \"proxy_v2\"",
                "client_ip = \"proxy_v2\", tls = \"starttls\", auth_forward = \"oauthbearer\""
            ),
            sub(
                ", client_ip = \"proxy_v2\", tls = \"implicit\"",
                "implicit_tls_listen = \"0.0.0.0:465\"\n"
            )
        ))
        .unwrap();
        let c = &l.config;
        assert_eq!(inline(&c.imap.backend).tls, Some(BackendTls::Starttls));
        assert_eq!(
            inline(&c.imap.backend).auth_forward,
            crate::config::AuthForward::Oauthbearer
        );
        let s = c.submission.as_ref().unwrap();
        assert_eq!(inline(&s.backend).client_ip, Some(ClientIp::ProxyV2));
        assert_eq!(inline(&s.backend).tls, Some(BackendTls::Implicit));
        assert_eq!(s.implicit_tls_listen.as_deref(), Some("0.0.0.0:465"));

        for (extra, needle) in [
            (
                V2.replace("\"proxy_v2\"", "\"xclient\""),
                "imap.backend.client_ip = \"xclient\" is an SMTP extension",
            ),
            (
                format!("{V2}{}", sub(", client_ip = \"none\"", "xclient = true\n")),
                "submission.backend.client_ip cannot be combined with its short form (submission.xclient)",
            ),
            (
                V2.replace("\"proxy_v2\"", "\"none\", proxy_protocol = true"),
                "imap.backend.client_ip cannot be combined with its short form (proxy_protocol)",
            ),
            (
                format!("{V2}{}", sub(", proxy_protocol = true", "xclient = true\n")),
                "proxy_protocol and submission.xclient cannot both be set",
            ),
            (
                format!("{V2}{}", sub("", "implicit_tls_listen = \"465\"\n")),
                "submission.implicit_tls_listen = \"465\" must be ip:port",
            ),
            (
                format!("{V2}{}", sub("", "implicit_tls_listen = \"0.0.0.0:587\"\n")),
                "submission.implicit_tls_listen = \"0.0.0.0:587\" is used twice",
            ),
        ] {
            let e = errors_of(&extra);
            assert!(e.contains(needle), "{needle}: {e}");
        }
        for bad in [
            V2.replace("\"proxy_v2\"", "\"proxy\""),
            V2.replace("client_ip = \"proxy_v2\"", "tls = \"none\""),
            V2.replace("client_ip = \"proxy_v2\"", "auth_forward = \"plain\""),
        ] {
            assert!(crate::config::parse(&bad).is_err(), "{bad}");
        }
    }

    /// IMAP without a backend of its own, then `extra`.
    fn routed(extra: &str) -> String {
        format!(
            "{}{extra}",
            V2.replace(
                "backend = { address = \"192.0.2.10:993\", verify_name = \"mail.example.org\", client_ip = \"proxy_v2\" }\n",
                ""
            )
        )
    }

    const TWO_BACKENDS: &str = "[backends.one]\naddress = \"192.0.2.1:993\"\nclient_ip = \"proxy_v2\"\n[backends.two]\naddress = \"192.0.2.2:993\"\nclient_ip = \"proxy_v2\"\n";

    /// Named backends and routes: a valid file, its defaults by protocol,
    /// and the printed form parses back to the same configuration.
    #[test]
    fn routes_and_named_backends() {
        let text = routed(&format!(
            "{TWO_BACKENDS}[[routes]]\nname = \"one\"\ndomains = [\"one.example\"]\nimap = \"one\"\n[[routes]]\nname = \"rest\"\ndomains = [\"*\"]\nimap = \"two\"\n"
        ));
        let l = parse(&text).unwrap();
        assert!(l.warnings.is_empty(), "{:?}", l.warnings);
        let c = &l.config;
        let used: Vec<&str> = c
            .backends_of(Protocol::Imap)
            .iter()
            .map(|u| u.name)
            .collect();
        assert_eq!(used, ["one", "two"]);
        // IMAP's default TLS, filled in by use.
        assert_eq!(c.backends["one"].tls, Some(BackendTls::Implicit));
        let printed = toml::to_string(c).unwrap();
        let again = parse(&printed).unwrap().config;
        assert_eq!(again.routes, c.routes);
        assert_eq!(again.backends, c.backends);
        assert!(again.imap.backend.is_none());
        // A section may name a backend instead.
        let named = parse(&V2
            .replace("backend = { address = \"192.0.2.10:993\", verify_name = \"mail.example.org\", client_ip = \"proxy_v2\" }", "backend = \"one\"")
            .replace("[oauth]", &format!("{TWO_BACKENDS}[oauth]")))
        .unwrap();
        assert_eq!(
            named.config.imap.backend,
            Some(BackendRef::Name("one".into()))
        );
        assert!(
            named
                .warnings
                .iter()
                .any(|w| w.contains("backends.two is not used")),
            "{:?}",
            named.warnings
        );
    }

    #[test]
    fn routes_and_backends_are_validated() {
        let r = |route: &str| routed(&format!("{TWO_BACKENDS}[[routes]]\n{route}\n"));
        for (text, expect) in [
            (routed(""), "imap.backend is required (or routes with imap = …)"),
            (V2.replace("[oauth]", &format!("{TWO_BACKENDS}[[routes]]\nname = \"x\"\ndomains = [\"a.example\"]\nimap = \"one\"\n[oauth]")),
                "imap.backend and routes with imap = … cannot be combined"),
            (V2.replace("backend = { address = \"192.0.2.10:993\", verify_name = \"mail.example.org\", client_ip = \"proxy_v2\" }", "backend = \"nope\""),
                "imap.backend = \"nope\" names no [backends] entry"),
            (r("name = \"x\"\ndomains = [\"a.example\"]\nimap = \"nope\""), "routes[0].imap = \"nope\" names no [backends] entry"),
            (r("name = \"x\"\nimap = \"one\""), "routes[0]: set domains or issuers"),
            (r("name = \"x\"\ndomains = [\"a.example\"]"), "routes[0]: name a backend for imap, submission or sieve"),
            (r("name = \"x y\"\ndomains = [\"a.example\"]\nimap = \"one\""), "routes[0].name \"x y\" must be 1-64"),
            (r("name = \"x\"\ndomains = [\"*\", \"a.example\"]\nimap = \"one\""), "list nothing else"),
            (r("name = \"x\"\ndomains = [\"*\"]\nimap = \"one\"\n[[routes]]\nname = \"y\"\ndomains = [\"a.example\"]\nimap = \"two\""), "only in the last route"),
            (r("name = \"x\"\ndomains = [\"a.example\"]\nimap = \"one\"\n[[routes]]\nname = \"y\"\ndomains = [\"A.example\"]\nimap = \"two\""), "routes[1]: domain \"A.example\" is already taken by route \"x\""),
            (r("name = \"x\"\ndomains = [\"a.example\"]\nimap = \"one\"\n[[routes]]\nname = \"x\"\ndomains = [\"b.example\"]\nimap = \"two\""), "routes[1].name \"x\" is used twice"),
            (r("name = \"x\"\ndomains = [\"a.example\"]\nissuers = [\"https://other\"]\nimap = \"one\""), "routes[0].issuers: \"https://other\" is not an oauth.issuers entry"),
            (r("name = \"x\"\ndomains = [\"a.example\"]\nsieve = \"one\""), "routes[0].sieve: there is no [sieve] section"),
            (r("name = \"x\"\ndomains = [\"a.example\"]\nimap = \"one\"\nsni = [\"\"]"), "sni and audiences entries must not be empty"),
            (routed("[backends.imap]\naddress = \"192.0.2.1:993\"\n[[routes]]\nname = \"x\"\ndomains = [\"a.example\"]\nimap = \"imap\"\n"), "backends.imap: the name is reserved"),
            (routed("[backends.one]\naddress = \"nope\"\n[[routes]]\nname = \"x\"\ndomains = [\"a.example\"]\nimap = \"one\"\n"), "backends.one.address = \"nope\" must be host:port"),
            (routed("[backends.one]\naddress = \"192.0.2.1:993\"\nclient_ip = \"xclient\"\n[[routes]]\nname = \"x\"\ndomains = [\"a.example\"]\nimap = \"one\"\n"), "backends.one.client_ip = \"xclient\" is an SMTP extension"),
        ] {
            let e = errors_of(&text);
            assert!(e.contains(expect), "want {expect:?}, got:\n{e}\nfor:\n{text}");
        }
        // One backend for two protocols.
        let shared = format!(
            "{}[sieve]\nlisten = \"0.0.0.0:4190\"\n[[routes]]\nname = \"x\"\ndomains = [\"a.example\"]\nimap = \"one\"\nsieve = \"one\"\n",
            routed(TWO_BACKENDS)
        );
        assert!(
            errors_of(&shared).contains("backends.one: used by imap and sieve"),
            "{}",
            errors_of(&shared)
        );
        // Different conditions keep a domain reachable in a later route.
        let narrowed = r("name = \"x\"\ndomains = [\"a.example\"]\nsni = [\"mail.example.org\"]\nimap = \"one\"\n[[routes]]\nname = \"y\"\ndomains = [\"a.example\"]\nimap = \"two\"");
        assert_eq!(errors_of(&narrowed), "");
    }

    /// With every issuer bounded, a route domain no accepted issuer vouches
    /// for can serve passwords only.
    #[test]
    fn route_domain_outside_identity_domains_warns() {
        let text = routed(&format!(
            "{TWO_BACKENDS}[[routes]]\nname = \"x\"\ndomains = [\"a.example\"]\nimap = \"one\"\n"
        ))
        .replace(
            "token_type = \"keycloak\"",
            "token_type = \"keycloak\"\nidentity_domains = [\"b.example\"]",
        );
        let l = crate::config::parse(&text).unwrap();
        assert!(l.errors.is_empty(), "{:?}", l.errors);
        assert!(
            l.warnings.iter().any(
                |w| w.contains("routes[0]: no issuer that the route accepts has \"a.example\"")
            ),
            "{:?}",
            l.warnings
        );
    }

    /// A pool: `addresses` instead of `address`, a strategy, active checks;
    /// the printed form parses back.
    #[test]
    fn backend_pools_are_validated() {
        let pool = |keys: &str| {
            V2.replace(
                "backend = { address = \"192.0.2.10:993\", verify_name = \"mail.example.org\", client_ip = \"proxy_v2\" }",
                &format!("backend = {{ {keys}, verify_name = \"mail.example.org\", client_ip = \"proxy_v2\" }}"),
            )
        };
        let good = pool("addresses = [\"192.0.2.10:993\", \"192.0.2.11:993\"], strategy = \"hash\", health_check_secs = 10");
        let l = parse(&good).unwrap();
        let b = inline(&l.config.imap.backend);
        assert_eq!(b.address_list(), ["192.0.2.10:993", "192.0.2.11:993"]);
        assert_eq!(b.strategy, crate::config::PoolStrategy::Hash);
        let again = parse(&toml::to_string(&l.config).unwrap()).unwrap();
        assert_eq!(again.config.imap.backend, l.config.imap.backend);
        for (keys, expect) in [
            (
                "verify_name = \"x\"".to_string(),
                "imap.backend: set address or addresses",
            ),
            (
                "address = \"192.0.2.10:993\", addresses = [\"192.0.2.11:993\"]".into(),
                "address and addresses cannot be combined",
            ),
            (
                "addresses = [\"192.0.2.10:993\", \"192.0.2.10:993\"]".into(),
                "imap.backend.addresses[1] = \"192.0.2.10:993\" is listed twice",
            ),
            (
                "addresses = [\"192.0.2.10:993\", \"nope\"]".into(),
                "imap.backend.addresses[1] = \"nope\" must be host:port",
            ),
            (
                "address = \"192.0.2.10:993\", health_check_secs = 0".into(),
                "imap.backend.health_check_secs must be between 1 and 3600",
            ),
            (
                format!(
                    "addresses = [{}]",
                    (0..17)
                        .map(|i| format!("\"192.0.2.{i}:993\""))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                "imap.backend.addresses: at most 16",
            ),
        ] {
            let text = if keys.starts_with("verify_name") {
                V2.replace("address = \"192.0.2.10:993\", ", "")
            } else {
                pool(&keys)
            };
            let e = errors_of(&text);
            assert!(e.contains(expect), "want {expect:?}, got {e}");
        }
        let bad = pool("addresses = [\"192.0.2.10:993\"], strategy = \"random\"");
        assert!(crate::config::parse(&bad).is_err(), "unknown strategy");
    }

    /// A backend's own account check: `doveadm` needs its URL and key file,
    /// `none` no `doveadm_*`, and `doveadm_*` without `account_check` is an
    /// error; the printed form keeps it.
    #[test]
    fn backend_account_check() {
        let with = |keys: &str| {
            V2.replace(
                "client_ip = \"proxy_v2\" }",
                &format!("client_ip = \"proxy_v2\"{keys} }}"),
            )
        };
        let good = with(", account_check = \"doveadm\", doveadm_url = \"https://127.0.0.1/doveadm/v1\", doveadm_key_file = \"/k\"");
        let l = parse(&good).unwrap();
        let again = parse(&toml::to_string(&l.config).unwrap()).unwrap();
        assert_eq!(again.config.imap.backend, l.config.imap.backend);
        assert!(parse(&with(", account_check = \"none\"")).is_ok());
        // One check for all the addresses of a pool.
        let pool = good.replace(
            "address = \"192.0.2.10:993\"",
            "addresses = [\"192.0.2.10:993\", \"192.0.2.11:993\"]",
        );
        assert!(parse(&pool).is_ok());
        for (keys, expect) in [
            (", account_check = \"doveadm\"", "imap.backend.doveadm_url is required with account_check = \"doveadm\""),
            (", account_check = \"doveadm\", doveadm_url = \"http://mail.example.org/v1\", doveadm_key_file = \"/k\"", "imap.backend.doveadm_url:"),
            (", account_check = \"doveadm\", doveadm_url = \"https://127.0.0.1/v1\", doveadm_key_file = \"k\"", "imap.backend.doveadm_key_file"),
            (", account_check = \"none\", doveadm_url = \"https://127.0.0.1/v1\"", "imap.backend.doveadm_* is set but account_check is not \"doveadm\""),
            (", doveadm_key_file = \"/k\"", "imap.backend.doveadm_* is set but account_check is not \"doveadm\""),
        ] {
            let e = errors_of(&with(keys));
            assert!(e.contains(expect), "want {expect:?}, got {e}");
        }
    }
}
