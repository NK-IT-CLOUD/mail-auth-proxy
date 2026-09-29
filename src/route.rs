//! Routes: which backend of a protocol a credential goes to.
//!
//! The key is the domain of the validated identity (OAuth) or of the login
//! (password); the issuer, the audience and the SNI only narrow a route.
//! The SNI is client-chosen, so it never selects a backend on its own: a
//! token replayed to another tenant's backend could open an account there.
//! Routes are checked in file order and the first whose every condition
//! holds wins. Without `[[routes]]` each protocol has one route to the
//! backend of its section.

use crate::config::{self, Protocol};
use crate::obs::metrics::Proto;

/// What a credential offers the routes.
pub struct Key<'a> {
    /// The domain of the validated identity or of the login; `None` when it
    /// has none.
    pub domain: Option<&'a str>,
    /// OAuth: the issuer and the audiences of the validated token; `None`
    /// for a password.
    pub token: Option<(&'a str, &'a [String])>,
    /// The TLS server name the client asked for.
    pub sni: Option<&'a str>,
}

/// A backend chosen for a credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pick<'r> {
    /// Its position in the protocol's backends (`Config::backends_of`).
    pub index: usize,
    /// The route that chose it; empty without `[[routes]]`.
    pub route: &'r str,
}

struct Route {
    name: String,
    /// ASCII lower case.
    domains: Vec<String>,
    /// `"*"`: every domain, also none.
    any_domain: bool,
    issuers: Vec<String>,
    /// ASCII lower case.
    sni: Vec<String>,
    audiences: Vec<String>,
    /// Per protocol (`slot`): the index of its backend.
    backend: [Option<usize>; 3],
}

impl Route {
    fn matches(&self, key: &Key<'_>) -> bool {
        // A route that names no domain is for tokens of its issuers only.
        let domain = self.any_domain
            || match key.domain {
                Some(d) => self.domains.iter().any(|x| x.eq_ignore_ascii_case(d)),
                None => false,
            }
            || (self.domains.is_empty() && key.token.is_some());
        // Issuer and audience are properties of a token; a password is
        // routed by its domain alone.
        let (issuer, audience) = match key.token {
            Some((iss, aud)) => (
                self.issuers.is_empty() || self.issuers.iter().any(|i| i == iss),
                self.audiences.is_empty() || aud.iter().any(|a| self.audiences.contains(a)),
            ),
            None => (true, true),
        };
        let sni = self.sni.is_empty()
            || key.sni.is_some_and(|s| {
                let s = s.strip_suffix('.').unwrap_or(s);
                self.sni.iter().any(|x| x.eq_ignore_ascii_case(s))
            });
        domain && issuer && audience && sni
    }
}

/// The routes of one configuration.
pub struct Router {
    routes: Vec<Route>,
}

fn slot(protocol: Protocol) -> usize {
    match protocol {
        Protocol::Imap => 0,
        Protocol::Submission => 1,
        Protocol::Sieve => 2,
    }
}

/// The configuration protocol of a listener's `Proto`.
pub fn protocol(proto: Proto) -> Protocol {
    match proto {
        Proto::Imap => Protocol::Imap,
        Proto::Smtp => Protocol::Submission,
        Proto::Sieve => Protocol::Sieve,
    }
}

impl Router {
    /// From a validated configuration. Without routes every credential of a
    /// protocol goes to the one backend of its section.
    pub fn new(cfg: &config::Config) -> Router {
        let index = |protocol: Protocol, name: &str| {
            cfg.backends_of(protocol)
                .iter()
                .position(|u| u.name == name)
        };
        let has_routes = Protocol::ALL
            .iter()
            .any(|p| cfg.listener_backend(*p).is_none() && cfg.has_protocol(*p));
        let mut routes: Vec<Route> = if has_routes {
            cfg.routes
                .iter()
                .map(|r| Route {
                    name: r.name.clone(),
                    domains: r
                        .domains
                        .iter()
                        .filter(|d| *d != "*")
                        .map(|d| d.to_ascii_lowercase())
                        .collect(),
                    any_domain: r.domains.iter().any(|d| d == "*"),
                    issuers: r.issuers.clone(),
                    sni: r.sni.iter().map(|s| s.to_ascii_lowercase()).collect(),
                    audiences: r.audiences.clone(),
                    backend: Protocol::ALL.map(|p| {
                        // A protocol with a backend of its own ignores routes.
                        if cfg.listener_backend(p).is_some() {
                            return None;
                        }
                        r.backend(p).and_then(|name| index(p, name))
                    }),
                })
                .collect()
        } else {
            Vec::new()
        };
        // The protocols with a backend of their own: one route, last, that
        // takes every credential (the routes above never serve them).
        let own = Protocol::ALL
            .map(|p| (cfg.listener_backend(p).is_some() && cfg.has_protocol(p)).then_some(0));
        if own.iter().any(Option::is_some) {
            routes.push(Route {
                name: String::new(),
                domains: Vec::new(),
                any_domain: true,
                issuers: Vec::new(),
                sni: Vec::new(),
                audiences: Vec::new(),
                backend: own,
            });
        }
        Router { routes }
    }

    /// The backend of `proto` for `key`: that of the first route that serves
    /// the protocol and whose conditions all hold; `None` when there is none
    /// (an unknown tenant).
    pub fn pick(&self, proto: Proto, key: &Key<'_>) -> Option<Pick<'_>> {
        let s = slot(protocol(proto));
        self.routes.iter().find_map(|r| {
            let index = r.backend[s]?;
            r.matches(key).then_some(Pick {
                index,
                route: &r.name,
            })
        })
    }
}

/// The domain of a login or identity: after its last `@`, if not empty.
pub fn domain_of(login: &str) -> Option<&str> {
    login
        .rsplit_once('@')
        .map(|(_, d)| d)
        .filter(|d| !d.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROUTES: &str = r#"
config_version = 2
[tls]
cert = "/c.pem"
key = "/k.pem"
[imap]
listen = "0.0.0.0:993"
[submission]
listen = "0.0.0.0:587"
backend = { address = "192.0.2.10:587" }
[backends.one]
address = "192.0.2.1:993"
[backends.two]
address = "192.0.2.2:993"
[backends.partner]
address = "192.0.2.3:993"
[backends.catchall]
address = "192.0.2.4:993"
[[routes]]
name = "one"
domains = ["one.example", "One.Example.net"]
imap = "one"
[[routes]]
name = "two"
domains = ["two.example"]
issuers = ["https://idp.example/b"]
sni = ["mail.two.example"]
imap = "two"
[[routes]]
name = "partner"
issuers = ["https://idp.example/b"]
audiences = ["partner"]
imap = "partner"
[[routes]]
name = "rest"
domains = ["*"]
imap = "catchall"
[oauth]
[[oauth.issuers]]
issuer = "https://idp.example/a"
jwks_url = "https://idp.example/a/certs"
audiences = ["mail"]
token_type = "keycloak"
[[oauth.issuers]]
issuer = "https://idp.example/b"
jwks_url = "https://idp.example/b/certs"
audiences = ["mail", "partner"]
token_type = "keycloak"
"#;

    fn router(text: &str) -> (Router, config::Config) {
        let l = config::parse(text).unwrap();
        l.ensure_valid().unwrap();
        (Router::new(&l.config), l.config)
    }

    /// The name of the backend `key` is routed to for IMAP.
    fn imap(r: &(Router, config::Config), key: Key<'_>) -> Option<String> {
        let pick = r.0.pick(Proto::Imap, &key)?;
        Some(r.1.backends_of(Protocol::Imap)[pick.index].name.to_owned())
    }

    fn password<'a>(domain: Option<&'a str>, sni: Option<&'a str>) -> Key<'a> {
        Key {
            domain,
            token: None,
            sni,
        }
    }

    fn token<'a>(
        domain: Option<&'a str>,
        iss: &'a str,
        aud: &'a [String],
        sni: Option<&'a str>,
    ) -> Key<'a> {
        Key {
            domain,
            token: Some((iss, aud)),
            sni,
        }
    }

    /// First match in file order; domains exact and case-insensitive;
    /// issuer, audience and SNI narrow; `*` takes the rest.
    #[test]
    fn first_matching_route_wins() {
        let r = router(ROUTES);
        let mail = ["mail".to_string()];
        let partner = ["partner".to_string()];
        let (a, b) = ("https://idp.example/a", "https://idp.example/b");
        assert_eq!(
            imap(&r, password(Some("ONE.example"), None)).as_deref(),
            Some("one")
        );
        assert_eq!(
            imap(&r, password(Some("one.example.net"), None)).as_deref(),
            Some("one")
        );
        // No subdomains.
        assert_eq!(
            imap(&r, password(Some("x.one.example"), None)).as_deref(),
            Some("catchall")
        );
        // two: the password needs the SNI; the issuer binds only tokens.
        assert_eq!(
            imap(&r, password(Some("two.example"), Some("mail.two.example."))).as_deref(),
            Some("two")
        );
        assert_eq!(
            imap(&r, password(Some("two.example"), None)).as_deref(),
            Some("catchall")
        );
        assert_eq!(
            imap(
                &r,
                token(Some("two.example"), b, &mail, Some("MAIL.two.example"))
            )
            .as_deref(),
            Some("two")
        );
        assert_eq!(
            imap(
                &r,
                token(Some("two.example"), a, &mail, Some("mail.two.example"))
            )
            .as_deref(),
            Some("catchall")
        );
        // partner: no domain, tokens of issuer b with audience partner only.
        assert_eq!(
            imap(&r, token(Some("x.test"), b, &partner, None)).as_deref(),
            Some("partner")
        );
        assert_eq!(
            imap(&r, token(None, b, &partner, None)).as_deref(),
            Some("partner")
        );
        assert_eq!(
            imap(&r, token(None, b, &mail, None)).as_deref(),
            Some("catchall")
        );
        assert_eq!(
            imap(&r, password(Some("x.test"), None)).as_deref(),
            Some("catchall")
        );
        // `*` also takes a login without a domain.
        assert_eq!(imap(&r, password(None, None)).as_deref(), Some("catchall"));
        // Submission has a backend of its own: every credential goes there.
        let pick =
            r.0.pick(Proto::Smtp, &password(Some("one.example"), None))
                .unwrap();
        assert_eq!((pick.index, pick.route), (0, ""));
    }

    /// Without a catch-all a credential whose domain no route serves has no
    /// backend: an unknown tenant.
    #[test]
    fn unknown_tenant_has_no_backend() {
        let text = ROUTES
            .replace(
                "[[routes]]\nname = \"rest\"\ndomains = [\"*\"]\nimap = \"catchall\"\n",
                "",
            )
            .replace("[backends.catchall]\naddress = \"192.0.2.4:993\"\n", "");
        let r = router(&text);
        assert_eq!(imap(&r, password(Some("x.test"), None)), None);
        assert_eq!(imap(&r, password(None, None)), None);
        assert_eq!(
            imap(&r, password(Some("one.example"), None)).as_deref(),
            Some("one")
        );
    }

    /// The inline form and a named listener backend: one backend, every
    /// credential.
    #[test]
    fn without_routes_every_credential_has_the_listener_backend() {
        let text = ROUTES
            .split("[[routes]]")
            .next()
            .unwrap()
            .replace("[imap]\nlisten = \"0.0.0.0:993\"\n", "[imap]\nlisten = \"0.0.0.0:993\"\nbackend = \"two\"\n")
            + "[oauth]\n[[oauth.issuers]]\nissuer = \"https://idp.example/a\"\njwks_url = \"https://idp.example/a/certs\"\naudiences = [\"mail\"]\ntoken_type = \"keycloak\"\n";
        let l = config::parse(&text).unwrap();
        let r = (Router::new(&l.config), l.config);
        for key in [
            password(None, None),
            password(Some("one.example"), Some("x")),
        ] {
            assert_eq!(imap(&r, key).as_deref(), Some("two"));
        }
    }

    #[test]
    fn domains_of_logins() {
        assert_eq!(domain_of("a@b.example"), Some("b.example"));
        assert_eq!(domain_of("a"), None);
        assert_eq!(domain_of("a@"), None);
    }
}
