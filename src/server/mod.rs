//! The running server: shared context, backends, listeners and startup.

mod listener;
mod notify;
pub(crate) mod tls;

pub(crate) use listener::ACCEPT_BACKOFF;

use crate::config;
use crate::obs::metrics;
use crate::proto::imap::Imap;
use crate::proto::sieve::{CapsCache, Sieve};
use crate::proto::smtp::Submission;
use crate::wire::Tuning;
use anyhow::Result;
use ipnet::IpNet;
use rustls::pki_types::ServerName;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::{TlsAcceptor, TlsConnector};

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
    pub acceptor: TlsAcceptor,
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

/// Everything built from the configuration without network access.
struct Local {
    acceptor: TlsAcceptor,
    certs: Arc<tls::CertStore>,
    nets: Vec<IpNet>,
    legacy: crate::auth::legacy::Gate,
    imap: Imap,
    submission: Option<Submission>,
    sieve: Option<Sieve>,
}

/// Build everything that needs no network: certificates, backends, gate.
fn build_local(cfg: &config::Config) -> Result<Local> {
    let (acceptor, certs) = tls::load_server_tls(&cfg.tls.cert, &cfg.tls.key)?;
    let nets = crate::auth::policy::parse_internal_nets(&cfg.scope.internal_networks)?;
    let legacy = crate::auth::legacy::Gate::new(
        &cfg.legacy,
        std::time::Duration::from_secs(cfg.timeouts.connect_secs),
    )?;
    let keepalive = keepalive(&cfg.session);
    let imap = Imap {
        backend: BackendConn::new(&cfg.imap.backend, keepalive)?,
    };
    let submission = cfg
        .submission
        .as_ref()
        .map(|s| -> Result<Submission> {
            Ok(Submission {
                backend: BackendConn::new(&s.backend, keepalive)?,
                xclient: s.xclient,
                ehlo_extensions: s.ehlo_extensions.clone(),
            })
        })
        .transpose()?;
    let sieve = cfg
        .sieve
        .as_ref()
        .map(|s| -> Result<Sieve> {
            Ok(Sieve {
                backend: BackendConn::new(&s.backend, keepalive)?,
                caps: CapsCache::default(),
                caps_ttl: std::time::Duration::from_secs(s.capability_cache_secs),
            })
        })
        .transpose()?;
    Ok(Local {
        acceptor,
        certs,
        nets,
        legacy,
        imap,
        submission,
        sieve,
    })
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
    // Each file on its own first, so a missing cert does not hide a missing key.
    let mut readable = true;
    for (name, path) in [("tls.cert", &cfg.tls.cert), ("tls.key", &cfg.tls.key)] {
        if path.is_empty() {
            readable = false;
        } else if let Err(e) = std::fs::metadata(path).and_then(|_| std::fs::File::open(path)) {
            out.push(format!("{name}: {path}: {e}"));
            readable = false;
        }
    }
    if readable {
        if let Err(e) = tls::load_server_tls(&cfg.tls.cert, &cfg.tls.key) {
            out.push(format!("tls: {e:#}"));
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

/// How long a shutdown waits for open sessions to end before it closes them.
const SHUTDOWN_DRAIN: std::time::Duration = std::time::Duration::from_secs(10);

/// Serve `cfg` (already validated): build the listeners' shared context,
/// fetch the JWKS, start the metrics endpoint and the configured listeners, then
/// serve until SIGTERM or SIGINT.
///
/// SIGHUP reloads the client certificate and refreshes every JWKS without
/// touching open connections. SIGTERM/SIGINT stop accepting, give open
/// sessions up to `SHUTDOWN_DRAIN` to end, then return. Under systemd
/// (`$NOTIFY_SOCKET`) readiness and shutdown are notified.
pub async fn run(cfg: config::Config) -> Result<()> {
    // First, before anything slow: SIGHUP's default action terminates the
    // process, and a reload sent during startup must not.
    use tokio::signal::unix::{signal, SignalKind};
    let mut hangup = signal(SignalKind::hangup())?;
    let mut terminate = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    metrics::mark_process_start();
    let Local {
        acceptor,
        certs,
        nets,
        legacy,
        imap,
        submission,
        sieve,
    } = build_local(&cfg)?;
    if legacy.is_off() {
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
    legacy.spawn_reloader();
    let ratelimit = Arc::new(crate::ratelimit::AuthRateLimit::new(
        &cfg.auth_ratelimit,
        &nets,
    )?);
    if ratelimit.is_enabled() {
        let r = &cfg.auth_ratelimit;
        tracing::info!(target: crate::obs::target::MAIN, failures=r.failures, window_secs=r.window_secs, block_secs=r.block_secs,
            max_block_secs=r.max_block_secs, exempt_internal=r.exempt_internal, exempt_networks=?r.exempt_networks, "auth rate limit");
    } else {
        tracing::info!(target: crate::obs::target::MAIN, "auth rate limit disabled");
    }
    ratelimit.spawn_sweeper();
    let validator = Arc::new(crate::auth::token::Validator::new(&cfg.oauth).await?);
    // IdPs rotate signing keys; without a refresh the proxy stops accepting
    // every token minted after a rotation until it is restarted.
    validator.clone().spawn_refresher();
    let shared = Arc::new(Shared {
        validator,
        error_challenge: crate::auth::discovery::ErrorChallenge::from_config(&cfg.oauth),
        acceptor,
        nets,
        legacy,
        hostname: cfg.server.hostname.clone(),
        limits: crate::limits::Limits::new(
            cfg.limits.max_connections,
            cfg.limits.max_preauth_per_ip,
        ),
        ratelimit,
        tuning: Tuning {
            idle: std::time::Duration::from_secs(cfg.timeouts.idle_secs),
            connect: std::time::Duration::from_secs(cfg.timeouts.connect_secs),
            preauth: std::time::Duration::from_secs(cfg.timeouts.preauth_secs),
            max_preauth_commands: cfg.limits.max_preauth_commands,
            keepalive: keepalive(&cfg.session),
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

    // Optional Prometheus /metrics endpoint. Runs in its own task and owns its
    // errors — a bind failure here must never take down the mail listeners.
    if let Some(addr) = cfg
        .metrics
        .listen
        .clone()
        .filter(|_| cfg.metrics.is_enabled())
    {
        tokio::spawn(async move {
            metrics::serve(addr).await;
        });
    }

    let (stop, stop_rx) = tokio::sync::watch::channel(false);
    let (alive, mut all_ended) = tokio::sync::mpsc::channel::<()>(1);
    let life = listener::Lifecycle {
        stop: stop_rx,
        alive,
    };

    let listener = TcpListener::bind(&cfg.imap.listen).await?;
    tracing::info!(target: crate::obs::target::MAIN, listen=%cfg.imap.listen, backend=%cfg.imap.backend.address, "imap listener up");
    listener::spawn_listener(
        listener,
        metrics::Proto::Imap,
        "session ended",
        Arc::new(Ctx {
            shared: shared.clone(),
            protocol: imap,
        }),
        crate::proto::imap::handle,
        life.clone(),
    );

    if let Some((sub, protocol)) = cfg.submission.as_ref().zip(submission) {
        let sub_listener = TcpListener::bind(&sub.listen).await?;
        tracing::info!(target: crate::obs::target::MAIN, listen=%sub.listen, backend=%sub.backend.address, "submission listener up");
        listener::spawn_listener(
            sub_listener,
            metrics::Proto::Smtp,
            "submission session ended",
            Arc::new(Ctx {
                shared: shared.clone(),
                protocol,
            }),
            crate::proto::smtp::handle,
            life.clone(),
        );
    }

    if let Some((sv, protocol)) = cfg.sieve.as_ref().zip(sieve) {
        let sieve_listener = TcpListener::bind(&sv.listen).await?;
        tracing::info!(target: crate::obs::target::MAIN, listen=%sv.listen, backend=%sv.backend.address, "sieve listener up");
        listener::spawn_listener(
            sieve_listener,
            metrics::Proto::Sieve,
            "sieve session ended",
            Arc::new(Ctx {
                shared: shared.clone(),
                protocol,
            }),
            crate::proto::sieve::handle,
            life.clone(),
        );
    }

    drop(life);
    notify::notify(notify::READY);

    // The JWKS refresh of the last SIGHUP, if one ran; at most one at a time.
    let mut jwks_refresh: Option<tokio::task::JoinHandle<()>> = None;
    loop {
        tokio::select! {
            _ = hangup.recv() => reload(&certs, &shared.validator, &mut jwks_refresh),
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

/// SIGHUP: re-read the client certificate and refresh every JWKS. Each part
/// keeps what it had when it fails; open connections are not touched. The
/// configuration file itself is not re-read.
///
/// The refresh runs in its own task (a slow IdP can take up to the fetch
/// timeout per issuer), so the signal loop stays free to handle SIGTERM at
/// once; a SIGHUP while one is still running starts no second one.
fn reload(
    certs: &tls::CertStore,
    validator: &Arc<crate::auth::token::Validator>,
    running: &mut Option<tokio::task::JoinHandle<()>>,
) {
    match certs.reload() {
        Ok(()) => tracing::info!(target: crate::obs::target::MAIN, "reload: certificate loaded"),
        Err(e) => {
            tracing::error!(target: crate::obs::target::MAIN, error=%format!("{e:#}"), "reload: certificate unusable; keeping the current one")
        }
    }
    if running.as_ref().is_some_and(|t| !t.is_finished()) {
        tracing::info!(target: crate::obs::target::MAIN, "reload: JWKS refresh already running");
        return;
    }
    let validator = validator.clone();
    *running = Some(tokio::spawn(async move {
        match validator.refresh().await {
            Ok(()) => tracing::info!(target: crate::obs::target::MAIN, "reload: JWKS refreshed"),
            Err(e) => {
                tracing::warn!(target: crate::obs::target::MAIN, error=%e, "reload: JWKS refresh failed; keeping previous keys")
            }
        }
    }));
}
