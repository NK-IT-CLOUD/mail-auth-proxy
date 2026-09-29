//! Rate limit on failed logins per source address.
//!
//! A connection takes a few credentials (`limits.max_auth_attempts`), so a
//! guesser soon opens new connections; the per-account throttle covers passwords
//! only, and only per account (not spraying over many accounts, not token
//! guessing). This counts the refused credentials of each source (an IPv4
//! address, an IPv6 network of `limits.ipv6_source_prefix`, by default /64:
//! `limits::preauth_key`) and, after `failures` within
//! `window`, closes the source's new connections at accept for `block`,
//! doubled for every further block up to `max_block`.
//!
//! - Counted: every refused credential (`authresult` with `result="fail"`
//!   and a credential), whatever the reason. All reasons count alike, so the
//!   attempt that starts a block tells nothing about the account.
//! - Never counted: `protocol` (no credential; a TLS fault on the proxy's
//!   side would otherwise block every client), and an unavailable backend,
//!   account check or JWKS (`KeysStale`): those log no `authresult` at all.
//!   An outage never blocks anyone.
//! - A repeated identical failure (same user and credential within the
//!   window) counts once: a client retrying a stale password or an expired
//!   token does not block its NAT address, and repeating a guess gains an
//!   attacker nothing.
//! - A successful login does not reset the count: one valid account must not
//!   clear the way for guesses at others.
//!
//! A configuration reload keeps every count and block and changes only the
//! settings (`AuthRateLimit::reconfigured`).
//!
//! Bounded: at most `CAPACITY` sources. When full, entries with nothing left
//! to remember go first; if that is not enough, the least valuable ones
//! (unblocked before blocked, oldest first), and only those count as
//! evictions.

use crate::auth::sasl::ClientAuthKind;
use crate::config;
use crate::obs::authlog::Reason;
use crate::obs::metrics::{self, Proto};
use ipnet::IpNet;
use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Largest number of tracked sources.
const CAPACITY: usize = 65_536;

/// A full table is brought down to `CAPACITY - EVICT_BATCH` entries at once,
/// so the scan is paid once per batch of new sources, not once per source.
const EVICT_BATCH: usize = CAPACITY / 64;

/// Fingerprints of the last distinct failures kept per source.
const RECENT: usize = 8;

/// How often expired entries are dropped and the active-blocks gauge is set.
const SWEEP_INTERVAL: Duration = Duration::from_secs(10);

struct Settings {
    failures: u32,
    window: Duration,
    block: Duration,
    max_block: Duration,
}

/// One source's failures and block.
struct Source {
    window_start: Instant,
    /// Distinct failures in the window.
    failures: u32,
    /// Fingerprints of the last distinct failures (a ring, `recent_len` used).
    recent: [u64; RECENT],
    recent_len: usize,
    /// End of the current or last block.
    blocked_until: Option<Instant>,
    /// Blocks in a row; each doubles the next one.
    strikes: u32,
}

impl Source {
    fn new(now: Instant) -> Source {
        Source {
            window_start: now,
            failures: 0,
            recent: [0; RECENT],
            recent_len: 0,
            blocked_until: None,
            strikes: 0,
        }
    }

    fn blocked(&self, now: Instant) -> bool {
        self.blocked_until.is_some_and(|t| now < t)
    }

    /// Anything left to remember: a block, a running window, or a past block
    /// that still escalates the next one.
    fn live(&self, now: Instant, s: &Settings) -> bool {
        (self.failures > 0 && now < self.window_start + s.window)
            || self.blocked_until.is_some_and(|t| now < t + s.max_block)
    }

    /// Eviction order: unblocked before blocked, then by age (window start,
    /// or the end of the block).
    fn rank(&self, now: Instant) -> (bool, Instant) {
        match self.blocked_until {
            Some(t) if now < t => (true, t),
            _ => (false, self.window_start),
        }
    }
}

/// A block that just started.
#[derive(Debug, PartialEq, Eq)]
struct Ban {
    duration: Duration,
    failures: u32,
    strikes: u32,
}

/// The rate limit of one configuration, over the sources table of the
/// process: a configuration reload makes a new one (`reconfigured`) that
/// keeps every running count and block.
pub struct AuthRateLimit {
    /// `None`: disabled.
    settings: Option<Settings>,
    /// Sources that are never counted nor blocked.
    exempt: Vec<IpNet>,
    /// Prefix length IPv6 sources are grouped by (`limits::preauth_key`).
    v6_prefix: u8,
    sources: Arc<Mutex<Sources>>,
}

/// The tracked sources, each under the network it was counted as.
#[derive(Default)]
struct Sources {
    map: HashMap<IpNet, Source>,
    /// The IPv6 prefix lengths of the entries: more than one after a reload
    /// changed `limits.ipv6_source_prefix`, until the older entries expire.
    v6_prefixes: BTreeSet<u8>,
}

/// Whether a refusal reason counts. Exhaustive, so a new reason needs a
/// decision here.
fn counts(reason: Reason) -> bool {
    match reason {
        Reason::Ok | Reason::Protocol => false,
        Reason::BlockedEndpoint
        | Reason::BadToken
        | Reason::AuthzidMismatch
        | Reason::BackendReject
        | Reason::UnknownDomain
        | Reason::UnknownAccount
        | Reason::Throttled
        | Reason::Oversize => true,
    }
}

static FINGERPRINT_KEY: std::sync::OnceLock<aws_lc_rs::hmac::Key> = std::sync::OnceLock::new();

/// Generate the failure fingerprint key now; see
/// `authlog::init_fingerprint_key`.
pub fn init_fingerprint_key() -> anyhow::Result<()> {
    if FINGERPRINT_KEY.get().is_none() {
        let _ = FINGERPRINT_KEY.set(crate::obs::authlog::generate_hmac_key()?);
    }
    Ok(())
}

/// Process-lifetime HMAC key for the failure fingerprints, never persisted.
fn fingerprint_key() -> &'static aws_lc_rs::hmac::Key {
    // Only reached without `init_fingerprint_key` in unit tests.
    FINGERPRINT_KEY
        .get_or_init(|| crate::obs::authlog::generate_hmac_key().expect("fingerprint key"))
}

/// 64-bit keyed fingerprint of a presented credential (user and secret), to
/// recognise a repeated identical attempt without keeping the secret.
fn fingerprint(credential: &ClientAuthKind) -> u64 {
    let (user, secret) = match credential {
        ClientAuthKind::OAuth { user, token } => (user, token),
        ClientAuthKind::Password { user, pass } => (user, pass),
    };
    let mut ctx = aws_lc_rs::hmac::Context::with_key(fingerprint_key());
    // Length-prefixed, so no user/secret split collides with another.
    ctx.update(&(user.len() as u64).to_le_bytes());
    ctx.update(user.as_bytes());
    ctx.update(secret.as_bytes());
    let tag = ctx.sign();
    let mut fp = [0u8; 8];
    fp.copy_from_slice(&tag.as_ref()[..8]);
    u64::from_le_bytes(fp)
}

/// The network a source key stands for, for the log.
fn source_net(key: IpAddr, v6_prefix: u8) -> IpNet {
    let prefix = if key.is_ipv4() { 32 } else { v6_prefix };
    IpNet::new(key, prefix).expect("prefix fits the address family")
}

impl AuthRateLimit {
    /// From a validated configuration; `internal` is `scope.internal_networks`,
    /// `v6_prefix` is `limits.ipv6_source_prefix`.
    pub fn new(
        cfg: &config::AuthRateLimit,
        internal: &[IpNet],
        v6_prefix: u8,
    ) -> anyhow::Result<AuthRateLimit> {
        Self::with_sources(cfg, internal, v6_prefix, Arc::default())
    }

    /// The same, over the sources of `self` (a configuration reload): counts
    /// and blocks go on with the new settings. A source that the new
    /// settings exempt is no longer blocked; a disabled limit drops the
    /// table at the next sweep.
    pub fn reconfigured(
        &self,
        cfg: &config::AuthRateLimit,
        internal: &[IpNet],
        v6_prefix: u8,
    ) -> anyhow::Result<AuthRateLimit> {
        Self::with_sources(cfg, internal, v6_prefix, self.sources.clone())
    }

    fn with_sources(
        cfg: &config::AuthRateLimit,
        internal: &[IpNet],
        v6_prefix: u8,
        sources: Arc<Mutex<Sources>>,
    ) -> anyhow::Result<AuthRateLimit> {
        let mut exempt = crate::auth::policy::parse_internal_nets(&cfg.exempt_networks)?;
        if cfg.exempt_internal {
            exempt.extend_from_slice(internal);
        }
        Ok(AuthRateLimit {
            settings: cfg.enabled.then(|| Settings {
                failures: cfg.failures,
                window: Duration::from_secs(cfg.window_secs),
                block: Duration::from_secs(cfg.block_secs),
                max_block: Duration::from_secs(cfg.max_block_secs),
            }),
            exempt,
            v6_prefix,
            sources,
        })
    }

    pub fn is_enabled(&self) -> bool {
        self.settings.is_some()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Sources> {
        self.sources.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Whether new connections from `peer` are refused.
    pub fn is_blocked(&self, peer: IpAddr) -> bool {
        self.is_blocked_at(peer, Instant::now())
    }

    fn is_blocked_at(&self, peer: IpAddr, now: Instant) -> bool {
        if self.settings.is_none() {
            return false;
        }
        let peer = peer.to_canonical();
        if crate::auth::policy::is_internal(peer, &self.exempt) {
            return false;
        }
        let sources = self.lock();
        let blocked = |net: IpNet| sources.map.get(&net).is_some_and(|s| s.blocked(now));
        if peer.is_ipv4() {
            return blocked(source_net(peer, 32));
        }
        // Under every prefix a source may have been counted by.
        std::iter::once(self.v6_prefix)
            .chain(sources.v6_prefixes.iter().copied())
            .any(|p| blocked(source_net(crate::limits::preauth_key(peer, p), p)))
    }

    /// A credential from `peer` was refused with `reason`. Counts it (unless
    /// the reason or the source is exempt) and logs a block that starts.
    pub fn failure(
        &self,
        proto: Proto,
        scope: &str,
        peer: IpAddr,
        reason: Reason,
        credential: &ClientAuthKind,
    ) {
        if self.settings.is_none() || !counts(reason) {
            return;
        }
        let peer = peer.to_canonical();
        if crate::auth::policy::is_internal(peer, &self.exempt) {
            return;
        }
        let key = crate::limits::preauth_key(peer, self.v6_prefix);
        if let Some(ban) = self.failure_at(key, fingerprint(credential), Instant::now()) {
            tracing::warn!(target: "authlog",
                action = "block", proto = proto.label(), scope, peer = %peer, source = %source_net(key, self.v6_prefix),
                failures = ban.failures, block_secs = ban.duration.as_secs(), strikes = ban.strikes, "ratelimit");
        }
    }

    /// Count a failure with fingerprint `fp` for the source `key`; the block
    /// it starts, if any.
    fn failure_at(&self, key: IpAddr, fp: u64, now: Instant) -> Option<Ban> {
        let s = self.settings.as_ref()?;
        let net = source_net(key, self.v6_prefix);
        let mut sources = self.lock();
        if !sources.map.contains_key(&net) {
            make_room(&mut sources.map, now, s);
            if key.is_ipv6() {
                sources.v6_prefixes.insert(self.v6_prefix);
            }
        }
        let map = &mut sources.map;
        let e = map.entry(net).or_insert_with(|| Source::new(now));
        // Connections opened before the block may still fail; the block
        // already runs.
        if e.blocked(now) {
            return None;
        }
        if e.failures == 0 || now >= e.window_start + s.window {
            e.window_start = now;
            e.failures = 0;
            e.recent_len = 0;
        }
        if e.recent[..e.recent_len].contains(&fp) {
            return None;
        }
        e.recent[e.failures as usize % RECENT] = fp;
        e.recent_len = (e.recent_len + 1).min(RECENT);
        e.failures += 1;
        if e.failures < s.failures {
            return None;
        }
        // Escalation is forgotten once the last block is `max_block` past.
        if e.blocked_until.is_some_and(|t| now >= t + s.max_block) {
            e.strikes = 0;
        }
        let factor = 1u32.checked_shl(e.strikes).unwrap_or(u32::MAX);
        let duration = s.block.saturating_mul(factor).min(s.max_block);
        let ban = Ban {
            duration,
            failures: e.failures,
            strikes: e.strikes + 1,
        };
        e.blocked_until = Some(now + duration);
        e.strikes = e.strikes.saturating_add(1);
        e.failures = 0;
        e.recent_len = 0;
        let active = map.values().filter(|x| x.blocked(now)).count();
        metrics::record_ratelimit_ban(active as u64);
        Some(ban)
    }

    /// Drop what is no longer needed (everything when disabled); set the
    /// active-blocks gauge.
    fn sweep(&self, now: Instant) {
        let mut sources = self.lock();
        match &self.settings {
            Some(s) => sources.map.retain(|_, e| e.live(now, s)),
            None => sources.map.clear(),
        }
        let prefixes = sources
            .map
            .keys()
            .filter(|n| n.addr().is_ipv6())
            .map(IpNet::prefix_len)
            .collect();
        sources.v6_prefixes = prefixes;
        let active = sources.map.values().filter(|e| e.blocked(now)).count();
        metrics::set_ratelimit_active(active as u64);
    }

    /// Start the periodic sweep of the rate limit `current` returns (the one
    /// of the configuration in use). Needs a Tokio runtime.
    pub fn spawn_sweeper(current: impl Fn() -> Arc<AuthRateLimit> + Send + 'static) {
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(SWEEP_INTERVAL);
            loop {
                tick.tick().await;
                current().sweep(Instant::now());
            }
        });
    }
}

/// Make room for one more source in a full table.
fn make_room(map: &mut HashMap<IpNet, Source>, now: Instant, s: &Settings) {
    if map.len() < CAPACITY {
        return;
    }
    map.retain(|_, e| e.live(now, s));
    let target = CAPACITY - EVICT_BATCH;
    if map.len() <= target {
        return;
    }
    let mut order: Vec<((bool, Instant), IpNet)> =
        map.iter().map(|(k, e)| (e.rank(now), *k)).collect();
    let n = map.len() - target;
    order.select_nth_unstable(n - 1);
    for (_, k) in &order[..n] {
        map.remove(k);
    }
    metrics::record_ratelimit_evictions(n as u64);
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    fn cfg(failures: u32, window: u64, block: u64, max_block: u64) -> config::AuthRateLimit {
        config::AuthRateLimit {
            enabled: true,
            failures,
            window_secs: window,
            block_secs: block,
            max_block_secs: max_block,
            exempt_internal: false,
            exempt_networks: Vec::new(),
        }
    }

    fn limit(c: &config::AuthRateLimit) -> AuthRateLimit {
        AuthRateLimit::new(c, &["10.0.0.0/8".parse().unwrap()], 64).unwrap()
    }

    /// The startup check generates the key that fingerprints then use.
    #[test]
    fn startup_generates_the_fingerprint_key() {
        init_fingerprint_key().unwrap();
        let key = FINGERPRINT_KEY.get().expect("key set at startup");
        assert!(std::ptr::eq(key, fingerprint_key()));
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn pw(user: &str, pass: &str) -> ClientAuthKind {
        ClientAuthKind::Password {
            user: user.into(),
            pass: Zeroizing::new(pass.into()),
        }
    }

    /// `n` failures from `peer`, each with a password never used before.
    fn fail(l: &AuthRateLimit, peer: &str, n: usize) {
        static GUESS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        for _ in 0..n {
            let i = GUESS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            l.failure(
                Proto::Imap,
                "external",
                ip(peer),
                Reason::BackendReject,
                &pw("u@x", &format!("guess{i}")),
            );
        }
    }

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    /// `failures` distinct failures within the window block the source for
    /// `block`; afterwards it is free again.
    #[test]
    fn threshold_blocks_until_expiry() {
        let l = limit(&cfg(3, 60, 100, 100));
        let t = Instant::now();
        let k = ip("192.0.2.1");
        assert_eq!(l.failure_at(k, 1, t), None);
        assert_eq!(l.failure_at(k, 2, t), None);
        assert!(!l.is_blocked_at(k, t));
        let ban = l.failure_at(k, 3, t + secs(1)).unwrap();
        assert_eq!(ban.duration, secs(100));
        assert_eq!((ban.failures, ban.strikes), (3, 1));
        assert!(l.is_blocked_at(k, t + secs(100)));
        assert!(!l.is_blocked_at(k, t + secs(101)), "block expired");
        assert!(
            !l.is_blocked_at(ip("192.0.2.2"), t + secs(1)),
            "other source"
        );
    }

    /// Failures older than the window no longer count.
    #[test]
    fn window_restarts_the_count() {
        let l = limit(&cfg(3, 60, 100, 100));
        let t = Instant::now();
        let k = ip("192.0.2.1");
        l.failure_at(k, 1, t);
        l.failure_at(k, 2, t + secs(30));
        assert_eq!(l.failure_at(k, 3, t + secs(60)), None, "new window");
        l.failure_at(k, 4, t + secs(61));
        assert!(l.failure_at(k, 5, t + secs(62)).is_some());
    }

    /// The same failure again (a client retrying a stale password) counts
    /// once; a different user or secret counts.
    #[test]
    fn repeated_identical_failure_counts_once() {
        let l = limit(&cfg(3, 60, 100, 100));
        for _ in 0..10 {
            l.failure(
                Proto::Imap,
                "external",
                ip("192.0.2.1"),
                Reason::BackendReject,
                &pw("u@x", "old"),
            );
        }
        assert!(!l.is_blocked(ip("192.0.2.1")));
        l.failure(
            Proto::Imap,
            "external",
            ip("192.0.2.1"),
            Reason::BackendReject,
            &pw("v@x", "old"),
        );
        l.failure(
            Proto::Smtp,
            "external",
            ip("192.0.2.1"),
            Reason::BadToken,
            &ClientAuthKind::OAuth {
                user: "u@x".into(),
                token: Zeroizing::new("expired.jwt".into()),
            },
        );
        assert!(l.is_blocked(ip("192.0.2.1")), "three distinct failures");
        assert_ne!(fingerprint(&pw("ab", "c")), fingerprint(&pw("a", "bc")));
    }

    /// IPv6 sources count per /64, IPv4-mapped sources as their IPv4 address.
    #[test]
    fn sources_group_like_the_connection_limits() {
        let l = limit(&cfg(2, 60, 100, 100));
        fail(&l, "2001:db8:1:2::1", 1);
        fail(&l, "2001:db8:1:2:ffff::9", 1);
        assert!(l.is_blocked(ip("2001:db8:1:2:abcd::1")), "same /64");
        assert!(!l.is_blocked(ip("2001:db8:1:3::1")), "neighbouring /64");
        fail(&l, "::ffff:192.0.2.7", 1);
        fail(&l, "192.0.2.7", 1);
        assert!(l.is_blocked(ip("192.0.2.7")));
        assert!(l.is_blocked(ip("::ffff:192.0.2.7")));
        assert!(!l.is_blocked(ip("192.0.2.8")), "IPv4 per address");
    }

    /// `limits.ipv6_source_prefix = 48`: failures from anywhere in a /48
    /// count together, and the block covers the /48.
    #[test]
    fn ipv6_sources_group_by_the_configured_prefix() {
        let l = AuthRateLimit::new(&cfg(2, 60, 100, 100), &[], 48).unwrap();
        fail(&l, "2001:db8:1:2::1", 1);
        fail(&l, "2001:db8:1:ffff::9", 1);
        assert!(l.is_blocked(ip("2001:db8:1:abcd::1")), "same /48");
        assert!(!l.is_blocked(ip("2001:db8:2::1")), "neighbouring /48");
        assert_eq!(
            source_net(crate::limits::preauth_key(ip("2001:db8:1:2::1"), 48), 48).to_string(),
            "2001:db8:1::/48"
        );
    }

    /// Each block in a row doubles, up to `max_block`; after a quiet
    /// `max_block` the next block starts short again.
    #[test]
    fn blocks_escalate_and_reset() {
        let l = limit(&cfg(1, 60, 100, 350));
        let t = Instant::now();
        let k = ip("192.0.2.1");
        let mut at = t;
        let mut got = Vec::new();
        for fp in 1..=4 {
            let ban = l.failure_at(k, fp, at).unwrap();
            got.push(ban.duration.as_secs());
            at += ban.duration;
        }
        assert_eq!(got, [100, 200, 350, 350]);
        assert_eq!(l.failure_at(k, 5, at + secs(349)).unwrap().strikes, 5);
        let at = at + secs(349) + secs(350);
        let ban = l.failure_at(k, 6, at + secs(350)).unwrap();
        assert_eq!((ban.duration, ban.strikes), (secs(100), 1));
    }

    /// Only refused credentials count: not `ok`, not `protocol`. (Outages
    /// never get here: they log no authresult.)
    #[test]
    fn only_refusals_count() {
        let l = limit(&cfg(1, 60, 100, 100));
        for reason in [Reason::Ok, Reason::Protocol] {
            l.failure(
                Proto::Imap,
                "external",
                ip("192.0.2.1"),
                reason,
                &pw("u@x", "p"),
            );
        }
        assert!(!l.is_blocked(ip("192.0.2.1")));
        for reason in [
            Reason::BlockedEndpoint,
            Reason::BadToken,
            Reason::AuthzidMismatch,
            Reason::BackendReject,
            Reason::UnknownDomain,
            Reason::UnknownAccount,
            Reason::Throttled,
            Reason::Oversize,
        ] {
            assert!(counts(reason), "{reason:?}");
        }
    }

    #[test]
    fn exempt_sources_and_disabled() {
        let mut c = cfg(1, 60, 100, 100);
        c.exempt_networks = vec!["198.51.100.0/24".into()];
        let l = limit(&c);
        fail(&l, "198.51.100.7", 5);
        assert!(!l.is_blocked(ip("198.51.100.7")), "exempt network");
        fail(&l, "10.1.2.3", 1);
        assert!(l.is_blocked(ip("10.1.2.3")), "internal counts by default");
        c.exempt_internal = true;
        let l = limit(&c);
        fail(&l, "10.1.2.3", 5);
        assert!(!l.is_blocked(ip("10.1.2.3")), "internal exempt");
        c.enabled = false;
        let l = limit(&c);
        fail(&l, "192.0.2.1", 5);
        assert!(!l.is_blocked(ip("192.0.2.1")));
        assert!(l.lock().map.is_empty());
    }

    /// The table stays within `CAPACITY`; a full table drops unblocked
    /// sources before blocked ones, and counts what it drops.
    #[test]
    fn capacity_is_bounded_and_blocks_survive() {
        let l = limit(&cfg(2, 3600, 3600, 3600));
        let t = Instant::now();
        let evictions = || {
            metrics::render_for_tests()
                .lines()
                .find_map(|l| l.strip_prefix("mail_auth_proxy_ratelimit_evictions_total "))
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap()
        };
        let blocked = ip("192.0.2.1");
        l.failure_at(blocked, 1, t);
        l.failure_at(blocked, 2, t);
        let e0 = evictions();
        for i in 0..CAPACITY as u32 + 10 {
            let k = IpAddr::V4(std::net::Ipv4Addr::from(0x0a00_0000 + i));
            l.failure_at(k, 1, t + Duration::from_millis(u64::from(i)));
        }
        let sources = l.lock();
        assert!(sources.map.len() <= CAPACITY);
        assert!(
            sources
                .map
                .get(&source_net(blocked, 64))
                .is_some_and(|s| s.blocked(t)),
            "block kept"
        );
        assert!(
            !sources.map.contains_key(&source_net(ip("10.0.0.0"), 64)),
            "oldest unblocked source dropped"
        );
        drop(sources);
        assert!(l.is_blocked_at(blocked, t));
        assert!(evictions() - e0 >= EVICT_BATCH as u64);
    }

    const V2: &str = r#"
config_version = 2
[server]
hostname = "proxy.example.org"
[tls]
cert = "/c.pem"
key = "/k.pem"
[imap]
listen = "0.0.0.0:993"
backend = { address = "192.0.2.10:993" }
[oauth]
[[oauth.issuers]]
issuer = "https://idp.example/realms/mail"
jwks_url = "https://idp.example/realms/mail/certs"
audiences = ["dovecot"]
token_type = "keycloak"
"#;

    /// On by default; the section is checked and printed.
    #[test]
    fn config_defaults_and_bounds() {
        let l = config::parse(V2).unwrap();
        assert!(l.errors.is_empty() && l.warnings.is_empty());
        let r = &l.config.auth_ratelimit;
        assert!(r.enabled && !r.exempt_internal);
        assert_eq!(
            (r.failures, r.window_secs, r.block_secs, r.max_block_secs),
            (20, 600, 900, 86_400)
        );
        assert_eq!(r.exempt_networks, ["127.0.0.0/8", "::1/128"]);
        let printed = toml::to_string(&l.config).unwrap();
        assert!(printed.contains("[auth_ratelimit]"), "{printed}");

        let with =
            |extra: &str| config::parse(&format!("{V2}[auth_ratelimit]\n{extra}\n")).unwrap();
        for (bad, needle) in [
            ("failures = 0", "failures"),
            ("window_secs = 0", "window_secs"),
            ("block_secs = 86401\nmax_block_secs = 90000", "block_secs"),
            ("max_block_secs = 60", "max_block_secs"),
            ("max_block_secs = 604801", "max_block_secs"),
            ("exempt_networks = [\"nope\"]", "exempt_networks"),
        ] {
            let e = with(bad).errors.join("\n");
            assert!(e.contains(needle), "{bad}: {e}");
        }
        let w = with("exempt_networks = [\"0.0.0.0/0\"]")
            .warnings
            .join("\n");
        assert!(w.contains("never blocked"), "{w}");
        assert!(config::parse(&format!("{V2}[auth_ratelimit]\nlimit = 1\n")).is_err());
        let off = with("enabled = false");
        assert!(off.errors.is_empty() && !off.config.auth_ratelimit.enabled);
    }

    /// A reload keeps every count and block and swaps the settings: the new
    /// threshold applies to the running count, a source the new settings
    /// exempt is free, a block counted under the old IPv6 prefix still holds
    /// until it expires, and a disabled limit blocks nothing and drops the
    /// table at the next sweep.
    #[test]
    fn reconfigured_keeps_counts_and_blocks() {
        let old = limit(&cfg(3, 60, 100, 100));
        let t = Instant::now();
        let v4 = ip("192.0.2.1");
        old.failure_at(v4, 1, t);
        old.failure_at(v4, 2, t);
        let v6 = ip("2001:db8:1:2::1");
        fail(&old, "2001:db8:1:2::1", 3);
        assert!(old.is_blocked(v6));

        let new = old.reconfigured(&cfg(2, 60, 100, 100), &[], 48).unwrap();
        assert!(!new.is_blocked_at(v4, t), "two failures, not yet blocked");
        assert!(
            new.failure_at(v4, 2, t).is_none(),
            "fingerprint seen before"
        );
        assert!(new.failure_at(v4, 3, t).is_some(), "the next one blocks");
        assert!(new.is_blocked_at(v4, t));
        assert!(new.is_blocked(v6), "the /64 block holds under /48");
        assert!(!new.is_blocked(ip("2001:db8:1:3::1")), "not the whole /48");
        fail(&new, "2001:db8:2:1::1", 1);
        fail(&new, "2001:db8:2:2::1", 1);
        assert!(new.is_blocked(ip("2001:db8:2:ffff::1")), "counted per /48");
        new.sweep(Instant::now());
        assert_eq!(new.lock().v6_prefixes, BTreeSet::from([48, 64]));

        let mut exempting = cfg(2, 60, 100, 100);
        exempting.exempt_networks = vec!["192.0.2.0/24".into()];
        let exempt = new.reconfigured(&exempting, &[], 48).unwrap();
        assert!(!exempt.is_blocked_at(v4, t), "now exempt");
        assert!(
            new.is_blocked_at(v4, t),
            "still blocked under the old settings"
        );

        let mut off = cfg(2, 60, 100, 100);
        off.enabled = false;
        let off = new.reconfigured(&off, &[], 48).unwrap();
        assert!(!off.is_blocked(v6));
        off.sweep(Instant::now());
        assert!(off.lock().map.is_empty() && new.lock().map.is_empty());
    }

    /// The sweep drops expired entries and keeps running blocks.
    #[test]
    fn sweep_drops_expired() {
        let l = limit(&cfg(1, 60, 100, 100));
        let t = Instant::now();
        l.failure_at(ip("192.0.2.1"), 1, t);
        let l2 = limit(&cfg(2, 60, 100, 100));
        l2.failure_at(ip("192.0.2.2"), 1, t);
        l.sweep(t + secs(150));
        assert_eq!(l.lock().map.len(), 1, "escalation memory");
        l.sweep(t + secs(201));
        assert!(l.lock().map.is_empty());
        l2.sweep(t + secs(61));
        assert!(l2.lock().map.is_empty());
    }
}
