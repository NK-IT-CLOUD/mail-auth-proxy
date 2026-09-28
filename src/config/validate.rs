//! Validation: every check serde cannot express, and the normalisation of
//! the short forms into what the rest of the program reads.

use super::{AccountCheck, Config, Legacy, Rule, TokenType, PASSWORD_GATE_RULE};

impl Config {
    /// Every check serde cannot express. Collects all problems instead of
    /// stopping at the first, so one `--check-config` run shows them all.
    pub(super) fn check(&self, errors: &mut Vec<String>, warnings: &mut Vec<String>) {
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
