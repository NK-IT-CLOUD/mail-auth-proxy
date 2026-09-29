//! The running server: shared context, backends, listeners and startup.

mod listener;
mod notify;
mod reload;
pub(crate) mod tls;

pub(crate) use listener::ACCEPT_BACKOFF;

use crate::config;
use crate::obs::metrics;
use crate::proto::imap::Imap;
use crate::proto::sieve::Sieve;
use crate::proto::smtp::Submission;
use crate::wire::Tuning;
use anyhow::{Context, Result};
use ipnet::IpNet;
use rustls::pki_types::ServerName;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::TlsConnector;

/// A backend and how to reach it: address, the name its certificate must
/// carry, and a TLS connector with that backend's trust anchors.
///
/// Every backend hop is TLS-verified — it carries passwords (PLAIN) as well as
/// tokens, so an unverified backend would let a MITM harvest secrets. There is
/// no option to turn verification off.
pub struct BackendConn {
    pub address: String,
    pub name: ServerName<'static>,
    pub tls: TlsConnector,
    pub proxy_protocol: bool,
    /// TCP keepalive of every connection to this backend.
    pub keepalive: crate::wire::Keepalive,
}

impl BackendConn {
    fn new(b: &config::Backend, keepalive: crate::wire::Keepalive) -> Result<BackendConn> {
        let name = b
            .verify_name
            .clone()
            .unwrap_or_else(|| crate::wire::connect::host_of(&b.address).to_string());
        let name = ServerName::try_from(name)
            .map_err(|e| anyhow::anyhow!("{}: bad certificate name: {e}", b.address))?;
        Ok(BackendConn {
            address: b.address.clone(),
            name,
            tls: tls::backend_connector(b.ca_file.as_deref())?,
            proxy_protocol: b.proxy_protocol,
            keepalive,
        })
    }
}

/// What every listener shares, read-only.
pub struct Shared {
    pub validator: Arc<crate::auth::token::Validator>,
    /// The error result a rejected token is answered with (RFC 7628).
    pub error_challenge: crate::auth::discovery::ErrorChallenge,
    /// `scope.internal_networks`, parsed once: the internal/external label
    /// of every connection. A label only; it allows nothing.
    pub nets: Vec<IpNet>,
    /// The legacy (password) gate.
    pub legacy: crate::auth::legacy::Gate,
    /// Name used in greetings and EHLO.
    pub hostname: String,
    pub limits: Arc<crate::limits::Limits>,
    /// Blocking of sources with too many failed logins.
    pub ratelimit: Arc<crate::ratelimit::AuthRateLimit>,
    pub tuning: Tuning,
}

impl Shared {
    /// `(internal, scope label)` of a client address, for logs and metrics.
    pub fn scope(&self, peer: SocketAddr) -> (bool, &'static str) {
        let internal = crate::auth::policy::is_internal(peer.ip(), &self.nets);
        (internal, if internal { "internal" } else { "external" })
    }

    /// The password mechanisms offered on a connection: source address, SNI
    /// and protocol against the legacy rules.
    pub fn password_mechs(
        &self,
        proto: metrics::Proto,
        sni: Option<&str>,
        peer: SocketAddr,
    ) -> crate::auth::legacy::MechSet {
        self.legacy.advertised(proto, peer.ip(), sni)
    }

    pub fn hostname(&self) -> &str {
        &self.hostname
    }
}

/// One listener's context: what all listeners share, plus its protocol's own
/// settings and backend.
pub struct Ctx<P> {
    pub shared: Arc<Shared>,
    pub protocol: P,
}

impl<P> std::ops::Deref for Ctx<P> {
    type Target = Shared;

    fn deref(&self) -> &Shared {
        &self.shared
    }
}

/// Everything built from one configuration: what a connection gets when it
/// is accepted while that configuration is in use, and keeps to its end. A
/// reload builds a new one and swaps it in whole (`reload`).
pub(crate) struct Generation {
    config: config::Config,
    certs: Arc<tls::CertStore>,
    shared: Arc<Shared>,
    imap: Arc<Ctx<Imap>>,
    submission: Option<Arc<Ctx<Submission>>>,
    sieve: Option<Arc<Ctx<Sieve>>>,
}

impl Generation {
    /// Build from `cfg` (validated): certificates, backends, gate, limits,
    /// then the token validator. `prev` is the generation in use on a
    /// reload: what runs across configurations (open connections, rate
    /// limit counts and blocks, throttle, backend capability caches, known
    /// JWKS) is carried over from it. Returns the issuers whose JWKS were
    /// fetched for a reload.
    async fn build(
        cfg: config::Config,
        prev: Option<&Generation>,
    ) -> Result<(Generation, Vec<String>)> {
        let certs = Arc::new(tls::CertStore::load(&cfg.tls)?);
        let nets = crate::auth::policy::parse_internal_nets(&cfg.scope.internal_networks)?;
        let mut legacy = crate::auth::legacy::Gate::new(
            &cfg.legacy,
            std::time::Duration::from_secs(cfg.timeouts.connect_secs),
        )?
        .with_backends(
            [
                Some(metrics::Proto::Imap),
                cfg.submission.as_ref().map(|_| metrics::Proto::Smtp),
                cfg.sieve.as_ref().map(|_| metrics::Proto::Sieve),
            ]
            .into_iter()
            .flatten()
            .map(|p| (p, crate::auth::backend_name(p))),
        );
        let keepalive = keepalive(&cfg.session);
        let imap = Imap {
            acceptor: tls::acceptor(&certs, Some(b"imap")),
            backend: BackendConn::new(&cfg.imap.backend, keepalive)?,
        };
        // The capability caches stay with a backend that stays.
        let submission = cfg
            .submission
            .as_ref()
            .map(|s| -> Result<Submission> {
                let kept = prev
                    .and_then(|p| p.submission.as_ref().zip(p.config.submission.as_ref()))
                    .filter(|(_, old)| old.backend == s.backend)
                    .map(|(ctx, _)| ctx.protocol.ehlo.clone());
                Ok(Submission {
                    acceptor: tls::acceptor(&certs, None),
                    backend: BackendConn::new(&s.backend, keepalive)?,
                    xclient: s.xclient,
                    ehlo_only: s.ehlo_extensions.clone(),
                    ehlo: kept.unwrap_or_default(),
                    caps_ttl: std::time::Duration::from_secs(s.capability_cache_secs),
                })
            })
            .transpose()?;
        let sieve = cfg
            .sieve
            .as_ref()
            .map(|s| -> Result<Sieve> {
                let kept = prev
                    .and_then(|p| p.sieve.as_ref().zip(p.config.sieve.as_ref()))
                    .filter(|(_, old)| old.backend == s.backend)
                    .map(|(ctx, _)| ctx.protocol.caps.clone());
                Ok(Sieve {
                    acceptor: tls::acceptor(&certs, Some(b"managesieve")),
                    backend: BackendConn::new(&s.backend, keepalive)?,
                    caps: kept.unwrap_or_default(),
                    caps_ttl: std::time::Duration::from_secs(s.capability_cache_secs),
                })
            })
            .transpose()?;
        let l = &cfg.limits;
        let (limits, ratelimit) = match prev {
            None => (
                crate::limits::Limits::new(
                    l.max_connections,
                    l.max_preauth_per_ip,
                    l.ipv6_source_prefix,
                ),
                crate::ratelimit::AuthRateLimit::new(
                    &cfg.auth_ratelimit,
                    &nets,
                    l.ipv6_source_prefix,
                )?,
            ),
            Some(p) => {
                legacy.carry_over(&p.shared.legacy);
                (
                    p.shared.limits.reconfigured(
                        l.max_connections,
                        l.max_preauth_per_ip,
                        l.ipv6_source_prefix,
                    ),
                    p.shared.ratelimit.reconfigured(
                        &cfg.auth_ratelimit,
                        &nets,
                        l.ipv6_source_prefix,
                    )?,
                )
            }
        };
        // Last: the only step that may wait for the network.
        let (validator, fetched) = match prev {
            None => (
                crate::auth::token::Validator::new(&cfg.oauth).await?,
                Vec::new(),
            ),
            Some(p) => p.shared.validator.reconfigured(&cfg.oauth).await?,
        };
        let shared = Arc::new(Shared {
            validator: Arc::new(validator),
            error_challenge: crate::auth::discovery::ErrorChallenge::from_config(&cfg.oauth),
            nets,
            legacy,
            hostname: cfg.server.hostname.clone(),
            limits,
            ratelimit: Arc::new(ratelimit),
            tuning: Tuning {
                idle: std::time::Duration::from_secs(cfg.timeouts.idle_secs),
                connect: std::time::Duration::from_secs(cfg.timeouts.connect_secs),
                preauth: std::time::Duration::from_secs(cfg.timeouts.preauth_secs),
                max_preauth_commands: cfg.limits.max_preauth_commands,
                max_auth_attempts: cfg.limits.max_auth_attempts,
                keepalive,
                session_idle: cfg
                    .session
                    .idle_limit_secs
                    .map(std::time::Duration::from_secs),
                max_session: cfg
                    .session
                    .max_session_secs
                    .map(std::time::Duration::from_secs),
            },
        });
        let generation = Generation {
            imap: Arc::new(Ctx {
                shared: shared.clone(),
                protocol: imap,
            }),
            submission: submission.map(|protocol| {
                Arc::new(Ctx {
                    shared: shared.clone(),
                    protocol,
                })
            }),
            sieve: sieve.map(|protocol| {
                Arc::new(Ctx {
                    shared: shared.clone(),
                    protocol,
                })
            }),
            certs,
            shared,
            config: cfg,
        };
        Ok((generation, fetched))
    }

    /// Start what a generation runs while it is in use: the list file
    /// reloader of its gate, the capability probes of its backends (a no-op
    /// while a kept cache is fresh). Needs a Tokio runtime.
    fn start(&self) {
        self.shared.legacy.spawn_reloader();
        if let Some(ctx) = &self.submission {
            tokio::spawn(crate::proto::smtp::probe_at_startup(ctx.clone()));
        }
        if let Some(ctx) = &self.sieve {
            tokio::spawn(crate::proto::sieve::probe_at_startup(ctx.clone()));
        }
    }

    /// Log what the configuration allows: the TLS names and their warnings,
    /// the legacy rules and gate, the auth rate limit.
    fn announce(&self) {
        let cfg = &self.config;
        tracing::info!(target: crate::obs::target::MAIN, names=?self.certs.names(), "TLS server names");
        for w in tls_warnings(cfg, &self.certs) {
            tracing::warn!(target: crate::obs::target::MAIN, "config: {w}");
        }
        if self.shared.legacy.is_off() {
            tracing::info!(target: crate::obs::target::MAIN, "password auth disabled: OAuth only");
        } else {
            for r in &cfg.legacy.rules {
                tracing::info!(target: crate::obs::target::MAIN, rule=%r.name, networks=?r.networks, sni=?r.sni, users=?r.users, users_file=?r.users_file,
                    protocols=?r.protocols, mechanisms=?r.mechanisms, "legacy password rule");
            }
            let l = &cfg.legacy;
            tracing::info!(target: crate::obs::target::MAIN, domain_gate=l.has_domain_gate(), account_check=?l.account_check,
                throttle=?l.throttle, failure_delay_ms=l.failure_delay_ms, "legacy password gate");
        }
        if self.shared.ratelimit.is_enabled() {
            let r = &cfg.auth_ratelimit;
            tracing::info!(target: crate::obs::target::MAIN, failures=r.failures, window_secs=r.window_secs, block_secs=r.block_secs,
                max_block_secs=r.max_block_secs, exempt_internal=r.exempt_internal, exempt_networks=?r.exempt_networks, "auth rate limit");
        } else {
            tracing::info!(target: crate::obs::target::MAIN, "auth rate limit disabled");
        }
    }
}

/// `[session]` keepalive, for client and backend connections alike.
fn keepalive(s: &config::Session) -> crate::wire::Keepalive {
    crate::wire::Keepalive {
        idle: std::time::Duration::from_secs(s.keepalive_idle_secs),
        interval: std::time::Duration::from_secs(s.keepalive_interval_secs),
        count: s.keepalive_count,
    }
}

/// Problems with the files the configuration names (certificate, key, CA
/// files), each reported on its own. Empty paths are skipped: they are
/// configuration errors, reported by validation.
pub fn file_problems(cfg: &config::Config) -> Vec<String> {
    let mut out = Vec::new();
    // Each file on its own first, so a missing cert does not hide a missing
    // key; then each pair on its own, so one bad pair does not hide another.
    for (i, (at, cert, key)) in cfg.tls.pairs().enumerate() {
        let mut readable = true;
        for (name, path) in [("cert", cert), ("key", key)] {
            if path.is_empty() {
                readable = false;
            } else if let Err(e) = std::fs::metadata(path).and_then(|_| std::fs::File::open(path)) {
                out.push(format!("{at}.{name}: {path}: {e}"));
                readable = false;
            }
        }
        if readable {
            if let Err(e) = tls::check_pair(cert, key, i == 0) {
                out.push(format!("{at}: {e:#}"));
            }
        }
    }
    let mut backends = vec![("imap.backend", &cfg.imap.backend)];
    if let Some(s) = &cfg.submission {
        backends.push(("submission.backend", &s.backend));
    }
    if let Some(s) = &cfg.sieve {
        backends.push(("sieve.backend", &s.backend));
    }
    for (name, b) in backends {
        if let Some(ca) = b.ca_file.as_deref().filter(|p| !p.is_empty()) {
            if let Err(e) = tls::backend_connector(Some(ca)) {
                out.push(format!("{name}.ca_file: {e:#}"));
            }
        }
    }
    let lists = cfg
        .legacy
        .rules
        .iter()
        .filter_map(|r| {
            r.users_file.as_ref().map(|f| {
                (
                    format!("legacy.rules[{}].users_file", r.name),
                    f,
                    config::check_user_entry as fn(&str) -> std::result::Result<(), String>,
                )
            })
        })
        .chain(cfg.legacy.domains_file.as_ref().map(|f| {
            (
                "legacy.domains_file".to_string(),
                f,
                config::check_domain_entry as fn(&str) -> std::result::Result<(), String>,
            )
        }));
    for (name, path, check) in lists {
        if path.is_empty() {
            continue;
        }
        let r = std::fs::read_to_string(path)
            .map_err(anyhow::Error::from)
            .and_then(|t| crate::auth::legacy::parse_list(&t, check));
        if let Err(e) = r {
            out.push(format!("{name}: {path}: {e:#}"));
        }
    }
    out.extend(crate::auth::account::file_problems(&cfg.legacy));
    out
}

/// What the certificate files mean for the configuration without making it
/// invalid: a default certificate without a DNS name (clients that send SNI
/// are refused), and legacy rule names (`sni`) that no certificate carries
/// (clients asking for them are refused in the handshake, so the name never
/// matches). Empty if the certificates do not load; `file_problems` reports
/// that.
pub fn file_warnings(cfg: &config::Config) -> Vec<String> {
    match tls::CertStore::load(&cfg.tls) {
        Ok(store) => tls_warnings(cfg, &store),
        Err(_) => Vec::new(),
    }
}

fn tls_warnings(cfg: &config::Config, store: &tls::CertStore) -> Vec<String> {
    let mut out = Vec::new();
    if store.default_has_no_names() {
        out.push(format!(
            "tls.cert: {} has no DNS name in its subjectAltName; it serves clients without SNI only, a client that sends SNI is refused",
            cfg.tls.cert
        ));
    }
    let names = store.names();
    for r in &cfg.legacy.rules {
        for n in r.sni.iter().flatten() {
            if !tls::serves(&names, n) {
                out.push(format!(
                    "legacy.rules[{}].sni: {n:?} is not a name of any configured certificate; a client asking for it is refused in the TLS handshake",
                    r.name
                ));
            }
        }
    }
    out
}

/// How long a shutdown waits for open sessions to end before it closes them.
const SHUTDOWN_DRAIN: std::time::Duration = std::time::Duration::from_secs(10);

/// Everything `--check-config` finds in a loaded configuration: the
/// problems (validation errors and file problems, all of them) and the
/// warnings (validation and certificate files). A reload checks the same.
pub fn check(loaded: &config::Loaded) -> (Vec<String>, Vec<String>) {
    let mut problems = loaded.errors.clone();
    problems.extend(file_problems(&loaded.config));
    let mut warnings = loaded.warnings.clone();
    warnings.extend(file_warnings(&loaded.config));
    (problems, warnings)
}

/// Serve `cfg` (already validated, read from `path`): build the listeners'
/// shared context, fetch the JWKS, start the metrics endpoint and the
/// configured listeners, then serve until SIGTERM or SIGINT.
///
/// SIGHUP reloads the configuration from `path` without touching open
/// connections (`reload`). SIGTERM/SIGINT stop accepting, give open
/// sessions up to `SHUTDOWN_DRAIN` to end, then return. Under systemd
/// (`$NOTIFY_SOCKET`) readiness and shutdown are notified.
pub async fn run(path: String, cfg: config::Config) -> Result<()> {
    // First, before anything slow: SIGHUP's default action terminates the
    // process, and a reload sent during startup must not.
    use tokio::signal::unix::{signal, SignalKind};
    let mut hangup = signal(SignalKind::hangup())?;
    let mut terminate = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    metrics::mark_process_start();
    // The per-process fingerprint keys: without a system RNG the proxy must
    // not start, rather than fail on the first refused login.
    crate::obs::authlog::init_fingerprint_key().context("password fingerprint key")?;
    crate::ratelimit::init_fingerprint_key().context("rate limit fingerprint key")?;
    let (generation, _) = Generation::build(cfg, None).await?;
    metrics::register_certs(generation.config.tls.pairs().map(|(_, cert, _)| cert));
    generation.certs.record_expiry();
    metrics::mark_config_loaded();
    generation.announce();
    generation.start();
    let generation = Arc::new(generation);

    // Optional Prometheus /metrics endpoint. Runs in its own task and owns its
    // errors — a bind failure here must never take down the mail listeners.
    let m = &generation.config.metrics;
    if let Some(addr) = m.listen.clone().filter(|_| m.is_enabled()) {
        tokio::spawn(async move {
            metrics::serve(addr).await;
        });
    }

    // The generation in use: each accept takes it, a reload replaces it.
    let (current, _) = tokio::sync::watch::channel(generation.clone());
    // IdPs rotate signing keys; without a refresh the proxy stops accepting
    // every token minted after a rotation until it is restarted.
    {
        let current = current.subscribe();
        crate::auth::token::Validator::spawn_refresher(move || {
            current.borrow().shared.validator.clone()
        });
    }
    {
        let current = current.subscribe();
        crate::ratelimit::AuthRateLimit::spawn_sweeper(move || {
            current.borrow().shared.ratelimit.clone()
        });
    }

    let (stop, stop_rx) = tokio::sync::watch::channel(false);
    let (alive, mut all_ended) = tokio::sync::mpsc::channel::<()>(1);
    let life = listener::Lifecycle {
        stop: stop_rx,
        alive,
    };

    let cfg = &generation.config;
    let listener = TcpListener::bind(&cfg.imap.listen).await?;
    tracing::info!(target: crate::obs::target::MAIN, listen=%cfg.imap.listen, backend=%cfg.imap.backend.address, "imap listener up");
    listener::spawn_listener(
        listener,
        metrics::Proto::Imap,
        "session ended",
        current.subscribe(),
        |g| Some(g.imap.clone()),
        crate::proto::imap::handle,
        life.clone(),
    );

    if let Some(sub) = &cfg.submission {
        let sub_listener = TcpListener::bind(&sub.listen).await?;
        tracing::info!(target: crate::obs::target::MAIN, listen=%sub.listen, backend=%sub.backend.address, "submission listener up");
        listener::spawn_listener(
            sub_listener,
            metrics::Proto::Smtp,
            "submission session ended",
            current.subscribe(),
            |g| g.submission.clone(),
            crate::proto::smtp::handle,
            life.clone(),
        );
    }

    if let Some(sv) = &cfg.sieve {
        let sieve_listener = TcpListener::bind(&sv.listen).await?;
        tracing::info!(target: crate::obs::target::MAIN, listen=%sv.listen, backend=%sv.backend.address, "sieve listener up");
        listener::spawn_listener(
            sieve_listener,
            metrics::Proto::Sieve,
            "sieve session ended",
            current.subscribe(),
            |g| g.sieve.clone(),
            crate::proto::sieve::handle,
            life.clone(),
        );
    }
    drop(generation);

    drop(life);
    notify::notify(notify::READY);

    // SIGHUPs that arrive during a reload are folded into one more reload.
    let wanted = Arc::new(tokio::sync::Notify::new());
    tokio::spawn(reload::run(path, current, wanted.clone()));
    loop {
        tokio::select! {
            _ = hangup.recv() => wanted.notify_one(),
            _ = terminate.recv() => break,
            _ = interrupt.recv() => break,
        }
    }
    notify::notify(notify::STOPPING);
    tracing::info!(target: crate::obs::target::MAIN, drain_secs = SHUTDOWN_DRAIN.as_secs(), "shutting down: listeners closed, waiting for open sessions");
    let _ = stop.send(true);
    // `None` once every accept loop and session has dropped its sender.
    match tokio::time::timeout(SHUTDOWN_DRAIN, all_ended.recv()).await {
        Ok(_) => tracing::info!(target: crate::obs::target::MAIN, "all sessions ended; exiting"),
        Err(_) => {
            tracing::warn!(target: crate::obs::target::MAIN, drain_secs = SHUTDOWN_DRAIN.as_secs(), "sessions still open after the drain time; closing them")
        }
    }
    Ok(())
}
