//! The legacy gate: whether a password (PLAIN/LOGIN) may go to the backend.
//!
//! Legacy mail has no SSO and no token: the backend checks the password. The
//! proxy only decides whether to pass it on, in this order, before any
//! backend contact:
//!
//! 1. a rule matches: source network (the real boundary), SNI (client-chosen,
//!    a convenience), protocol, mechanism, user;
//! 2. the login's domain is allowed (`allowed_domains` ∪ `domains_file`);
//! 3. the account exists (doveadm userdb lookup, cached);
//! 4. the account is not throttled after repeated backend rejections.
//!
//! Each check fails closed. Stages 1 (user part) to 4 answer the client like
//! a wrong password; only the log tells them apart.

use super::account::Doveadm;
use crate::config::{self, Mechanism, Protocol};
use crate::obs::authlog::Reason;
use crate::obs::metrics::Proto;
use anyhow::{anyhow, Context, Result};
use ipnet::IpNet;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime};

/// Password mechanisms offered on one connection.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MechSet {
    pub plain: bool,
    pub login: bool,
}

impl MechSet {
    pub fn any(self) -> bool {
        self.plain || self.login
    }

    /// `mech` as the client spelled it (`LOGIN` also for the IMAP command).
    pub fn allows(self, mech: &str) -> bool {
        match mechanism(mech) {
            Some(Mechanism::Plain) => self.plain,
            Some(Mechanism::Login) => self.login,
            None => false,
        }
    }
}

fn mechanism(mech: &str) -> Option<Mechanism> {
    if mech.eq_ignore_ascii_case("PLAIN") {
        Some(Mechanism::Plain)
    } else if mech.eq_ignore_ascii_case("LOGIN") {
        Some(Mechanism::Login)
    } else {
        None
    }
}

/// Longest login the gate looks at (a mailbox name; RFC 4616 requires
/// servers to accept at least 255 octets).
const MAX_LOGIN: usize = 255;

/// Backend-rejection latencies kept per protocol for refusal timing.
const LATENCY_SAMPLES: usize = 32;
/// Upper bound of the learned refusal time (a slow or stuck backend must not
/// make every refusal wait longer).
const MAX_LEARNED_DELAY: Duration = Duration::from_secs(10);

fn proto_index(p: Proto) -> usize {
    match p {
        Proto::Imap => 0,
        Proto::Smtp => 1,
        Proto::Sieve => 2,
    }
}

/// A uniformly random duration in `[0, span]`.
fn random_up_to(span: Duration) -> Duration {
    let mut b = [0u8; 4];
    if aws_lc_rs::rand::fill(&mut b).is_err() {
        // No randomness: the full span, never shorter than intended.
        return span;
    }
    span.mul_f64(f64::from(u32::from_le_bytes(b)) / f64::from(u32::MAX))
}

fn protocol(p: Proto) -> Protocol {
    match p {
        Proto::Imap => Protocol::Imap,
        Proto::Smtp => Protocol::Submission,
        Proto::Sieve => Protocol::Sieve,
    }
}

/// The domain part of a login, if it has one.
fn domain_of(user: &str) -> Option<&str> {
    user.rsplit_once('@')
        .map(|(_, d)| d)
        .filter(|d| !d.is_empty())
}

/// Does login `user` match list entry `entry`? `*@domain` matches every
/// login of the domain; otherwise the local part must be identical and the
/// domain equal ignoring ASCII case. Case in the local part is not folded:
/// whether `Bob` and `bob` are one account is the backend's business, and
/// folding here could widen a rule to an account it does not name.
fn user_matches(entry: &str, user: &str) -> bool {
    if let Some(d) = entry.strip_prefix("*@") {
        return domain_of(user).is_some_and(|ud| ud.eq_ignore_ascii_case(d));
    }
    match (entry.rsplit_once('@'), user.rsplit_once('@')) {
        (Some((el, ed)), Some((ul, ud))) => el == ul && ed.eq_ignore_ascii_case(ud),
        (None, None) => entry == user,
        _ => false,
    }
}

/// How often the list files are checked for changes.
const FILE_CHECK_INTERVAL: Duration = Duration::from_secs(2);

/// A list file (users or domains), re-read by a background task
/// (`Gate::spawn_reloader`) when its modification time or size changes.
/// Fail-closed: while the file is missing, unreadable or invalid its list is
/// unknown, and the rule or domain gate that uses it matches nothing, so a
/// broken update can never keep a revoked entry alive. At startup such a
/// file is an error.
struct ListFile {
    path: String,
    /// `users_file` or `domains_file`: the metric label.
    kind: ListKind,
    parse: fn(&str) -> Result<(), String>,
    state: RwLock<ListState>,
}

struct ListState {
    /// `None` while the file cannot be used.
    entries: Option<Arc<Vec<String>>>,
    /// The stamp of the loaded file; `None` after a failure, so the next check
    /// reads the file again.
    stamp: Option<(SystemTime, u64, u64)>,
}

/// What tells a changed file apart: modification time, size and (on Unix)
/// inode, so an atomic replace is seen even within one timestamp tick.
fn stamp(path: &str) -> std::io::Result<(SystemTime, u64, u64)> {
    let m = std::fs::metadata(path)?;
    #[cfg(unix)]
    let ino = std::os::unix::fs::MetadataExt::ino(&m);
    #[cfg(not(unix))]
    let ino = 0;
    Ok((m.modified()?, m.len(), ino))
}

/// Parse a list file's text: one entry per line, blank lines and `#`
/// comments ignored.
pub fn parse_list(text: &str, check: fn(&str) -> Result<(), String>) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        check(line).map_err(|e| anyhow!("line {}: {e}", n + 1))?;
        out.push(line.to_string());
    }
    Ok(out)
}

impl ListFile {
    fn load(path: &str, kind: ListKind, parse: fn(&str) -> Result<(), String>) -> Result<ListFile> {
        let st = stamp(path).with_context(|| path.to_string())?;
        let entries = Self::read(path, parse)?;
        Ok(ListFile {
            path: path.to_string(),
            kind,
            parse,
            state: RwLock::new(ListState {
                entries: Some(Arc::new(entries)),
                stamp: Some(st),
            }),
        })
    }

    fn read(path: &str, parse: fn(&str) -> Result<(), String>) -> Result<Vec<String>> {
        let text = std::fs::read_to_string(path).with_context(|| path.to_string())?;
        parse_list(&text, parse).with_context(|| path.to_string())
    }

    /// The current entries; `None` while the file cannot be used. No I/O.
    fn entries(&self) -> Option<Arc<Vec<String>>> {
        self.state
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .entries
            .clone()
    }

    /// Re-read the file if it changed (blocking I/O: run it off the async
    /// workers).
    fn reload(&self) {
        let current = self.state.read().unwrap_or_else(|p| p.into_inner()).stamp;
        let result = stamp(&self.path)
            .with_context(|| self.path.clone())
            .and_then(|s| {
                if Some(s) == current {
                    Ok(None)
                } else {
                    Self::read(&self.path, self.parse).map(|e| Some((s, e)))
                }
            });
        let mut st = self.state.write().unwrap_or_else(|p| p.into_inner());
        match result {
            Ok(None) => {}
            Ok(Some((s, e))) => {
                if st.entries.is_none() {
                    tracing::info!(target: crate::obs::target::MAIN, path=%self.path, entries=e.len(), "legacy list file usable again");
                } else {
                    tracing::info!(target: crate::obs::target::MAIN, path=%self.path, entries=e.len(), "legacy list file reloaded");
                }
                st.entries = Some(Arc::new(e));
                st.stamp = Some(s);
            }
            Err(e) => {
                crate::obs::metrics::record_legacy_list_error(self.kind.label());
                if st.entries.is_some() {
                    tracing::error!(target: crate::obs::target::MAIN, list=self.kind.label(), error=%format!("{e:#}"),
                        "legacy list file unusable; it matches nothing until it is fixed");
                }
                st.entries = None;
                st.stamp = None;
            }
        }
    }

    /// Does any entry satisfy `f`? `false` while the file cannot be used.
    fn any(&self, f: impl Fn(&str) -> bool) -> bool {
        self.entries().is_some_and(|e| e.iter().any(|x| f(x)))
    }

    /// Usable right now.
    fn usable(&self) -> bool {
        self.state
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .entries
            .is_some()
    }
}

#[derive(Clone, Copy, Debug)]
enum ListKind {
    Users,
    Domains,
}

impl ListKind {
    fn label(self) -> &'static str {
        match self {
            ListKind::Users => "users_file",
            ListKind::Domains => "domains_file",
        }
    }
}

struct Rule {
    name: String,
    nets: Vec<IpNet>,
    sni: Option<Vec<String>>,
    users: Option<Vec<String>>,
    users_file: Option<Arc<ListFile>>,
    protocols: Option<Vec<Protocol>>,
    mechanisms: Option<Vec<Mechanism>>,
}

impl Rule {
    /// Network, SNI and protocol: whether this rule applies to a connection.
    fn endpoint(&self, proto: Protocol, peer: IpAddr, sni: Option<&str>) -> bool {
        crate::auth::policy::is_internal(peer, &self.nets)
            && self.sni.as_ref().is_none_or(|names| {
                sni.is_some_and(|s| names.iter().any(|n| s.eq_ignore_ascii_case(n)))
            })
            && self.protocols.as_ref().is_none_or(|p| p.contains(&proto))
    }

    fn mechanism(&self, m: Mechanism) -> bool {
        self.mechanisms.as_ref().is_none_or(|ms| ms.contains(&m))
    }

    /// The rule allows `user`. A `users_file` that cannot be used makes the
    /// whole rule match nobody (its inline `users` included): the intended
    /// list is unknown.
    fn user(&self, user: &str) -> bool {
        if self.users.is_none() && self.users_file.is_none() {
            return true;
        }
        if self.users_file.as_ref().is_some_and(|f| !f.usable()) {
            return false;
        }
        let inline = self.users.iter().flatten().any(|e| user_matches(e, user));
        inline
            || self
                .users_file
                .as_ref()
                .is_some_and(|f| f.any(|e| user_matches(e, user)))
    }
}

/// Per-account failure counting for the throttle. Bounded: at most
/// `THROTTLE_CAPACITY` accounts are tracked.
///
/// Password attempts for one account take turns (`turns`): the next attempt
/// is checked only after the previous one has its backend verdict counted, so
/// parallel connections cannot run more attempts than `failures` allows.
struct Throttle {
    failures: u32,
    window: Duration,
    seen: Mutex<HashMap<String, (u32, Instant)>>,
    /// Accounts with an attempt in flight or waiting.
    turns: Mutex<HashMap<String, TurnSlot>>,
}

/// One account's turn lock and the number of attempts holding or waiting for
/// it; the slot is removed when that number drops to 0.
#[derive(Default)]
struct TurnSlot {
    lock: Arc<tokio::sync::Mutex<()>>,
    claims: usize,
}

const THROTTLE_CAPACITY: usize = 65_536;

/// Accounts a full throttle table drops at once (see `Throttle::make_room`).
const THROTTLE_EVICT_BATCH: usize = THROTTLE_CAPACITY / 64;

impl Throttle {
    fn key(user: &str) -> String {
        user.to_ascii_lowercase()
    }

    fn is_throttled(&self, user: &str) -> bool {
        let mut seen = self.seen.lock().unwrap_or_else(|p| p.into_inner());
        let key = Self::key(user);
        match seen.get(&key) {
            Some((_, start)) if start.elapsed() >= self.window => {
                seen.remove(&key);
                false
            }
            Some((n, _)) => *n >= self.failures,
            None => false,
        }
    }

    fn failure(&self, user: &str) {
        let key = Self::key(user);
        let mut seen = self.seen.lock().unwrap_or_else(|p| p.into_inner());
        if seen.len() >= THROTTLE_CAPACITY && !seen.contains_key(&key) {
            self.make_room(&mut seen);
        }
        let e = seen.entry(key).or_insert((0, Instant::now()));
        if e.1.elapsed() >= self.window {
            *e = (0, Instant::now());
        }
        e.0 = e.0.saturating_add(1);
    }

    /// Bring a full table down to `THROTTLE_CAPACITY - THROTTLE_EVICT_BATCH`:
    /// expired windows first, then the oldest running ones. One scan per
    /// batch of new accounts instead of one per account, all under the lock.
    fn make_room(&self, seen: &mut HashMap<String, (u32, Instant)>) {
        let window = self.window;
        seen.retain(|_, (_, start)| start.elapsed() < window);
        let target = THROTTLE_CAPACITY - THROTTLE_EVICT_BATCH;
        if seen.len() <= target {
            return;
        }
        let n = seen.len() - target;
        let mut order: Vec<(Instant, String)> = seen
            .iter()
            .map(|(k, (_, start))| (*start, k.clone()))
            .collect();
        order.select_nth_unstable(n - 1);
        for (_, k) in &order[..n] {
            seen.remove(k);
            crate::obs::metrics::record_throttle_eviction();
        }
    }

    fn success(&self, user: &str) {
        self.seen
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&Self::key(user));
    }

    /// Waits until no other attempt for `user` is in flight. Cancelling the
    /// wait (the client's time budget ran out) releases the claim as well.
    async fn turn(&self, user: &str) -> Turn<'_> {
        let key = Self::key(user);
        let lock = {
            let mut turns = self.turns.lock().unwrap_or_else(|p| p.into_inner());
            let slot = turns.entry(key.clone()).or_default();
            slot.claims += 1;
            slot.lock.clone()
        };
        let claim = Claim {
            throttle: self,
            key,
        };
        let guard = lock.lock_owned().await;
        Turn(Some((guard, claim)))
    }
}

/// One attempt waiting for or holding an account's turn.
struct Claim<'a> {
    throttle: &'a Throttle,
    key: String,
}

impl Drop for Claim<'_> {
    fn drop(&mut self) {
        let mut turns = self
            .throttle
            .turns
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if let Some(slot) = turns.get_mut(&self.key) {
            slot.claims -= 1;
            if slot.claims == 0 {
                turns.remove(&self.key);
            }
        }
    }
}

/// An account's turn for one password attempt: held from the throttle check
/// until the backend verdict is counted, then dropped (lock first, then claim).
pub struct Turn<'a>(Option<(tokio::sync::OwnedMutexGuard<()>, Claim<'a>)>);

impl Turn<'_> {
    fn none() -> Self {
        Turn(None)
    }
}

impl Drop for Turn<'_> {
    fn drop(&mut self) {
        if let Some((guard, claim)) = self.0.take() {
            drop(guard);
            drop(claim);
        }
    }
}

/// The gate's verdict on one password attempt.
pub enum Verdict<'a> {
    /// Forward the password; `rule` let it through. Keep `turn` until the
    /// backend verdict is reported with `backend_accepted`/`backend_rejected`.
    Pass { rule: &'a str, turn: Turn<'a> },
    /// Refused before the backend. `rule` is the matching rule, or empty
    /// when no rule allows this user.
    Deny { reason: Reason, rule: &'a str },
    /// The account check could not answer: an outage, not a refusal.
    Unavailable(anyhow::Error),
}

/// The configured legacy gate.
pub struct Gate {
    rules: Vec<Rule>,
    /// `None`: no domain gate.
    domains: Option<(HashSet<String>, Option<Arc<ListFile>>)>,
    /// Every list file, for the reload task.
    files: Vec<Arc<ListFile>>,
    /// Recent backend-rejection latencies per protocol, for refusal timing.
    reject_latency: [Mutex<std::collections::VecDeque<Duration>>; 3],
    account: Option<Doveadm>,
    throttle: Option<Throttle>,
    /// Minimum time from the credential to the reply of a failed legacy login.
    pub failure_delay: Duration,
}

impl Gate {
    /// Build the gate from a validated configuration: parse networks, read
    /// the list files and the doveadm key. Any problem aborts startup.
    pub fn new(cfg: &config::Legacy, connect_timeout: Duration) -> Result<Gate> {
        let mut rules = Vec::new();
        for r in &cfg.rules {
            rules.push(Rule {
                name: r.name.clone(),
                nets: crate::auth::policy::parse_internal_nets(&r.networks)?,
                sni: r.sni.clone(),
                users: r.users.clone(),
                users_file: r
                    .users_file
                    .as_deref()
                    .map(|p| {
                        ListFile::load(p, ListKind::Users, config::check_user_entry).map(Arc::new)
                    })
                    .transpose()
                    .context("legacy users_file")?,
                protocols: r.protocols.clone(),
                mechanisms: r.mechanisms.clone(),
            });
        }
        let domains = if cfg.has_domain_gate() {
            let inline = cfg
                .allowed_domains
                .iter()
                .map(|d| d.to_ascii_lowercase())
                .collect();
            let file = cfg
                .domains_file
                .as_deref()
                .map(|p| {
                    ListFile::load(p, ListKind::Domains, config::check_domain_entry).map(Arc::new)
                })
                .transpose()
                .context("legacy domains_file")?;
            Some((inline, file))
        } else {
            None
        };
        let account = match cfg.account_check {
            config::AccountCheck::None => None,
            config::AccountCheck::Doveadm => Some(Doveadm::new(cfg, connect_timeout)?),
        };
        let files = rules
            .iter()
            .filter_map(|r| r.users_file.clone())
            .chain(domains.as_ref().and_then(|(_, f)| f.clone()))
            .collect();
        Ok(Gate {
            rules,
            domains,
            files,
            reject_latency: Default::default(),
            account,
            throttle: cfg.throttle.as_ref().map(|t| Throttle {
                failures: t.failures,
                window: Duration::from_secs(t.window_secs),
                seen: Mutex::new(HashMap::new()),
                turns: Mutex::new(HashMap::new()),
            }),
            failure_delay: Duration::from_millis(cfg.failure_delay_ms),
        })
    }

    /// Start the task that re-reads the list files when they change, with
    /// the file I/O on the blocking pool. Needs a Tokio runtime.
    pub fn spawn_reloader(&self) {
        if self.files.is_empty() {
            return;
        }
        let files = self.files.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(FILE_CHECK_INTERVAL);
            tick.tick().await;
            loop {
                tick.tick().await;
                let files = files.clone();
                let _ = tokio::task::spawn_blocking(move || files.iter().for_each(|f| f.reload()))
                    .await;
            }
        });
    }

    /// The time a failed legacy login is answered after: `failure_delay`,
    /// or the median of the recent backend rejections of this protocol when
    /// that is longer (bounded by `MAX_LEARNED_DELAY`).
    fn failure_time(&self, proto: Proto) -> Duration {
        let samples = self.reject_latency[proto_index(proto)]
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let mut v: Vec<Duration> = samples.iter().copied().collect();
        drop(samples);
        v.sort_unstable();
        let learned = v.get(v.len() / 2).copied().unwrap_or_default();
        self.failure_delay.max(learned.min(MAX_LEARNED_DELAY))
    }

    /// Random extra delay added to every failed legacy reply: a quarter of
    /// the failure time, at least 50 ms, at most 1 s.
    fn jitter(&self, proto: Proto) -> Duration {
        let span =
            (self.failure_time(proto) / 4).clamp(Duration::from_millis(50), Duration::from_secs(1));
        random_up_to(span)
    }

    /// When to answer a login the gate refused (credential read at
    /// `started`): as late as a typical wrong password, plus jitter.
    pub fn refusal_deadline(
        &self,
        proto: Proto,
        started: tokio::time::Instant,
    ) -> tokio::time::Instant {
        started + self.failure_time(proto) + self.jitter(proto)
    }

    /// The backend rejected a password `latency` after the credential was
    /// read: learn the latency, return when to answer (never before
    /// `failure_delay`, plus the same jitter as a refusal).
    pub fn rejected_deadline(
        &self,
        proto: Proto,
        started: tokio::time::Instant,
    ) -> tokio::time::Instant {
        let latency = started.elapsed();
        {
            let mut q = self.reject_latency[proto_index(proto)]
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            if q.len() == LATENCY_SAMPLES {
                q.pop_front();
            }
            q.push_back(latency);
        }
        (started + self.failure_delay).max(tokio::time::Instant::now()) + self.jitter(proto)
    }

    /// No rule at all: every endpoint is OAuth-only.
    pub fn is_off(&self) -> bool {
        self.rules.is_empty()
    }

    /// The password mechanisms to offer on a connection: those of every rule
    /// whose network, SNI and protocol match. Users are checked on the
    /// attempt.
    ///
    /// SASL LOGIN "MUST NOT be advertised or used in any configuration that
    /// prohibits the PLAIN mechanism or plaintext LOGIN (or USER/PASS)
    /// command" (draft-murchison-sasl-login §1). SMTP has no plaintext login
    /// command, so there LOGIN needs PLAIN. In IMAP the LOGIN command is the
    /// same setting as SASL LOGIN, so LOGIN is never offered where the
    /// command is prohibited.
    pub fn advertised(&self, proto: Proto, peer: IpAddr, sni: Option<&str>) -> MechSet {
        let p = protocol(proto);
        let mut set = MechSet::default();
        for r in self.rules.iter().filter(|r| r.endpoint(p, peer, sni)) {
            set.plain |= r.mechanism(Mechanism::Plain);
            set.login |= r.mechanism(Mechanism::Login);
        }
        if matches!(proto, Proto::Smtp) {
            set.login &= set.plain;
        }
        set
    }

    /// Stages 1-4 for a password attempt whose mechanism the connection
    /// offers (`advertised`). Nothing here contacts the mail backend.
    pub async fn check(
        &self,
        proto: Proto,
        peer: IpAddr,
        sni: Option<&str>,
        mech: &str,
        user: &str,
    ) -> Verdict<'_> {
        let proto = protocol(proto);
        // Logins the proxy never looks up or counts: empty, too long for a
        // mailbox name, with control characters, or with more than one `@`
        // (the rule, domain and backend could each split it differently).
        // They also bound the throttle's and the cache's keys.
        if user.is_empty()
            || user.len() > MAX_LOGIN
            || user.chars().any(char::is_control)
            || user.matches('@').nth(1).is_some()
        {
            return Verdict::Deny {
                reason: Reason::UnknownAccount,
                rule: "",
            };
        }
        let Some(m) = mechanism(mech) else {
            return Verdict::Deny {
                reason: Reason::BlockedEndpoint,
                rule: "",
            };
        };
        // 1. The first rule (in configuration order) that allows this login.
        let Some(rule) = self
            .rules
            .iter()
            .find(|r| r.endpoint(proto, peer, sni) && r.mechanism(m) && r.user(user))
        else {
            return Verdict::Deny {
                reason: Reason::BlockedEndpoint,
                rule: "",
            };
        };
        let rule = rule.name.as_str();
        let deny = |reason| Verdict::Deny { reason, rule };
        // 2. Domain.
        if let Some((inline, file)) = &self.domains {
            let ok = domain_of(user).is_some_and(|d| {
                let d = d.to_ascii_lowercase();
                // A domains_file that cannot be used closes the domain gate.
                file.as_ref().is_none_or(|f| f.usable())
                    && (inline.contains(&d)
                        || file
                            .as_ref()
                            .is_some_and(|f| f.any(|e| e.eq_ignore_ascii_case(&d))))
            });
            if !ok {
                return deny(Reason::UnknownDomain);
            }
        }
        // 3. Account.
        if let Some(a) = &self.account {
            match a.exists(user).await {
                Ok(true) => {}
                Ok(false) => return deny(Reason::UnknownAccount),
                Err(e) => return Verdict::Unavailable(e),
            }
        }
        // 4. Throttle, checked in this account's turn.
        let turn = match &self.throttle {
            Some(t) => {
                let turn = t.turn(user).await;
                if t.is_throttled(user) {
                    return deny(Reason::Throttled);
                }
                turn
            }
            None => Turn::none(),
        };
        Verdict::Pass { rule, turn }
    }

    /// The backend rejected the password of `user`.
    pub fn backend_rejected(&self, user: &str) {
        if let Some(t) = &self.throttle {
            t.failure(user);
        }
    }

    /// The backend accepted the password of `user`.
    pub fn backend_accepted(&self, user: &str) {
        if let Some(t) = &self.throttle {
            t.success(user);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Legacy, Rule as CfgRule};

    fn rule(name: &str, nets: &[&str]) -> CfgRule {
        CfgRule {
            name: name.into(),
            networks: nets.iter().map(|s| s.to_string()).collect(),
            sni: None,
            users: None,
            users_file: None,
            protocols: None,
            mechanisms: None,
            public: false,
        }
    }

    fn gate(rules: Vec<CfgRule>) -> Gate {
        gate_with(Legacy {
            rules,
            ..Legacy::default()
        })
    }

    fn gate_with(cfg: Legacy) -> Gate {
        Gate::new(&cfg, Duration::from_secs(1)).unwrap()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    const INTERNAL: &str = "mail.internal.example";

    /// The `[password_gate]` short form as a rule.
    fn short_form() -> Gate {
        let mut r = rule(
            "password_gate",
            &["10.0.0.0/8", "192.168.0.0/16", "127.0.0.0/8", "::1/128"],
        );
        r.sni = Some(vec![INTERNAL.into()]);
        gate(vec![r])
    }

    fn pass(v: Verdict<'_>) -> Option<String> {
        match v {
            Verdict::Pass { rule, .. } => Some(rule.to_string()),
            _ => None,
        }
    }

    fn denied(v: Verdict<'_>) -> Option<(Reason, String)> {
        match v {
            Verdict::Deny { reason, rule } => Some((reason, rule.to_string())),
            _ => None,
        }
    }

    // The attacks the short form must stop.

    #[test]
    fn internal_sni_and_internal_ip_allows() {
        let g = short_form();
        assert!(g
            .advertised(Proto::Imap, ip("10.20.2.22"), Some(INTERNAL))
            .any());
    }

    #[test]
    fn forged_internal_sni_from_external_ip_denies() {
        let g = short_form();
        assert!(!g
            .advertised(Proto::Imap, ip("203.0.113.7"), Some(INTERNAL))
            .any());
    }

    #[test]
    fn public_sni_from_internal_ip_denies() {
        let g = short_form();
        assert!(!g
            .advertised(Proto::Imap, ip("10.20.4.40"), Some("mail.public.example"))
            .any());
    }

    #[test]
    fn missing_sni_denies_when_the_rule_names_one() {
        let g = short_form();
        assert!(!g.advertised(Proto::Imap, ip("10.20.2.22"), None).any());
    }

    #[test]
    fn sni_match_is_case_insensitive() {
        let g = short_form();
        assert!(g
            .advertised(
                Proto::Smtp,
                ip("192.168.0.3"),
                Some("Mail.Internal.EXAMPLE")
            )
            .any());
    }

    #[test]
    fn ipv4_mapped_peer_is_classified_like_ipv4() {
        let g = short_form();
        assert!(g
            .advertised(Proto::Sieve, ip("::ffff:10.20.3.30"), Some(INTERNAL))
            .any());
        assert!(!g
            .advertised(Proto::Sieve, ip("::ffff:203.0.113.5"), Some(INTERNAL))
            .any());
    }

    #[test]
    fn no_rules_offers_nothing() {
        let g = gate(Vec::new());
        assert!(g.is_off());
        assert_eq!(
            g.advertised(Proto::Imap, ip("127.0.0.1"), Some(INTERNAL)),
            MechSet::default()
        );
    }

    #[test]
    fn protocols_and_mechanisms_restrict_the_offer() {
        let mut r = rule("partner", &["198.51.100.7/32"]);
        r.users = Some(vec!["mailflow@example.org".into()]);
        r.protocols = Some(vec![Protocol::Imap, Protocol::Submission]);
        r.mechanisms = Some(vec![Mechanism::Plain]);
        let g = gate(vec![r]);
        let peer = ip("198.51.100.7");
        let imap = g.advertised(Proto::Imap, peer, None);
        assert!(imap.plain && !imap.login);
        assert!(!g.advertised(Proto::Sieve, peer, None).any());
        assert!(!g.advertised(Proto::Imap, ip("198.51.100.8"), None).any());
    }

    #[tokio::test]
    async fn first_matching_rule_wins_and_users_are_checked() {
        let mut partner = rule("partner", &["198.51.100.7/32"]);
        partner.users = Some(vec![
            "mailflow@example.org".into(),
            "*@partner.example".into(),
        ]);
        let internal = rule("internal", &["10.0.0.0/8"]);
        let g = gate(vec![partner, internal]);
        let peer = ip("198.51.100.7");
        let check = |u: &'static str| g.check(Proto::Imap, peer, None, "PLAIN", u);
        assert_eq!(
            pass(check("mailflow@example.org").await).as_deref(),
            Some("partner")
        );
        assert_eq!(
            pass(check("mailflow@EXAMPLE.org").await).as_deref(),
            Some("partner")
        );
        assert_eq!(
            pass(check("anyone@Partner.Example").await).as_deref(),
            Some("partner")
        );
        // The local part is not case-folded, other users are refused.
        for u in [
            "Mailflow@example.org",
            "other@example.org",
            "mailflow",
            "x@sub.partner.example",
        ] {
            assert_eq!(
                denied(check(u).await),
                Some((Reason::BlockedEndpoint, String::new())),
                "{u}"
            );
        }
        assert_eq!(
            pass(
                g.check(Proto::Smtp, ip("10.1.2.3"), None, "login", "x@y")
                    .await
            )
            .as_deref(),
            Some("internal")
        );
    }

    #[tokio::test]
    async fn domain_gate_uses_list_and_file() {
        let dir = tempfile_dir();
        let path = dir.join("domains");
        std::fs::write(
            &path,
            "# relay domains\nfile.example\n\n  Other.Example  \n",
        )
        .unwrap();
        let g = gate_with(Legacy {
            allowed_domains: vec!["Inline.Example".into()],
            domains_file: Some(path.display().to_string()),
            rules: vec![rule("all", &["127.0.0.0/8"])],
            ..Legacy::default()
        });
        let peer = ip("127.0.0.1");
        for u in ["a@inline.example", "a@FILE.example", "a@other.example"] {
            assert!(
                pass(g.check(Proto::Imap, peer, None, "PLAIN", u).await).is_some(),
                "{u}"
            );
        }
        for u in ["a@unknown.example", "nodomain", "a@"] {
            assert_eq!(
                denied(g.check(Proto::Imap, peer, None, "PLAIN", u).await),
                Some((Reason::UnknownDomain, "all".into())),
                "{u}"
            );
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn throttle_counts_backend_rejections_per_account() {
        let g = gate_with(Legacy {
            throttle: Some(config::Throttle {
                failures: 2,
                window_secs: 3600,
            }),
            rules: vec![rule("all", &["127.0.0.0/8"])],
            ..Legacy::default()
        });
        let peer = ip("127.0.0.1");
        let check = |u: &'static str| g.check(Proto::Imap, peer, None, "PLAIN", u);
        g.backend_rejected("bob@example.org");
        assert!(pass(check("bob@example.org").await).is_some());
        g.backend_rejected("BOB@example.org");
        assert_eq!(
            denied(check("bob@example.org").await),
            Some((Reason::Throttled, "all".into()))
        );
        assert!(pass(check("alice@example.org").await).is_some());
        g.backend_accepted("bob@example.org");
        assert!(pass(check("bob@example.org").await).is_some());
    }

    /// Parallel attempts for one account take turns: no more of them reach the
    /// backend than the throttle allows failures, and no turn is left behind.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn throttle_holds_under_parallel_attempts() {
        let g = Arc::new(gate_with(Legacy {
            throttle: Some(config::Throttle {
                failures: 2,
                window_secs: 3600,
            }),
            rules: vec![rule("all", &["127.0.0.0/8"])],
            ..Legacy::default()
        }));
        let tasks: Vec<_> = (0..20)
            .map(|_| {
                let g = g.clone();
                tokio::spawn(async move {
                    match g
                        .check(
                            Proto::Imap,
                            ip("127.0.0.1"),
                            None,
                            "PLAIN",
                            "bob@example.org",
                        )
                        .await
                    {
                        Verdict::Pass { turn, .. } => {
                            tokio::time::sleep(Duration::from_millis(20)).await;
                            g.backend_rejected("bob@example.org");
                            drop(turn);
                            1
                        }
                        _ => 0,
                    }
                })
            })
            .collect();
        let mut passed = 0;
        for t in tasks {
            passed += t.await.unwrap();
        }
        assert_eq!(passed, 2);
        let t = g.throttle.as_ref().unwrap();
        assert!(t.turns.lock().unwrap().is_empty());
    }

    /// An attempt cancelled while it waits for its turn leaves nothing behind.
    #[tokio::test]
    async fn cancelled_wait_releases_its_claim() {
        let t = Throttle {
            failures: 5,
            window: Duration::from_secs(3600),
            seen: Mutex::new(HashMap::new()),
            turns: Mutex::new(HashMap::new()),
        };
        let first = t.turn("a@x").await;
        let waited = tokio::time::timeout(Duration::from_millis(20), t.turn("A@x")).await;
        assert!(
            waited.is_err(),
            "the second attempt must wait for the first"
        );
        assert_eq!(
            t.turns.lock().unwrap().get("a@x").map(|s| s.claims),
            Some(1)
        );
        drop(first);
        assert!(t.turns.lock().unwrap().is_empty());
    }

    #[test]
    fn throttle_window_expires_and_capacity_is_bounded() {
        let t = Throttle {
            failures: 1,
            window: Duration::from_millis(1),
            seen: Mutex::new(HashMap::new()),
            turns: Mutex::new(HashMap::new()),
        };
        t.failure("a@x");
        std::thread::sleep(Duration::from_millis(5));
        assert!(!t.is_throttled("a@x"));
        let t = Throttle {
            failures: 1,
            window: Duration::from_secs(3600),
            seen: Mutex::new(HashMap::new()),
            turns: Mutex::new(HashMap::new()),
        };
        let evictions = || {
            crate::obs::metrics::render_for_tests()
                .lines()
                .find_map(|l| l.strip_prefix("mail_auth_proxy_legacy_throttle_evictions_total "))
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap()
        };
        let e0 = evictions();
        for i in 0..THROTTLE_CAPACITY + 10 {
            t.failure(&format!("u{i}@x"));
        }
        // The first account beyond capacity made room for a whole batch at
        // once (the oldest windows); the next nine needed no scan.
        let len = t.seen.lock().unwrap().len();
        assert_eq!(len, THROTTLE_CAPACITY - THROTTLE_EVICT_BATCH + 10);
        assert!(t.is_throttled(&format!("u{}@x", THROTTLE_CAPACITY + 9)));
        assert!(!t.is_throttled("u0@x"), "oldest window dropped");
        assert!(t.is_throttled(&format!("u{THROTTLE_EVICT_BATCH}@x")));
        // Each live window pushed out is counted.
        assert_eq!(evictions() - e0, THROTTLE_EVICT_BATCH as u64);
        // A full table: another failure of a tracked account evicts nothing.
        for i in 0..THROTTLE_EVICT_BATCH - 10 {
            t.failure(&format!("v{i}@x"));
        }
        assert_eq!(t.seen.lock().unwrap().len(), THROTTLE_CAPACITY);
        t.failure(&format!("u{}@x", THROTTLE_CAPACITY + 9));
        assert_eq!(t.seen.lock().unwrap().len(), THROTTLE_CAPACITY);
        assert_eq!(evictions() - e0, THROTTLE_EVICT_BATCH as u64);
    }

    /// A list file that becomes missing or invalid fails closed: the rule
    /// using it matches nobody (its inline users included) until the file
    /// is fixed; every failed re-read is retried and counted.
    #[tokio::test]
    async fn list_files_reload_and_fail_closed() {
        let dir = tempfile_dir();
        let path = dir.join("users");
        std::fs::write(&path, "a@example.org\n").unwrap();
        let mut r = rule("listed", &["127.0.0.0/8"]);
        r.users = Some(vec!["inline@example.org".into()]);
        r.users_file = Some(path.display().to_string());
        let g = gate(vec![r]);
        let f = g.files[0].clone();
        let peer = ip("127.0.0.1");
        let allowed = |u: &'static str| {
            let g = &g;
            async move { pass(g.check(Proto::Imap, peer, None, "PLAIN", u).await).is_some() }
        };
        assert!(allowed("a@example.org").await && allowed("inline@example.org").await);
        std::fs::write(&path, "a@example.org\nb@example.org\n").unwrap();
        f.reload();
        assert!(allowed("b@example.org").await);

        let errors = || {
            crate::obs::metrics::render_for_tests()
                .lines()
                .find(|l| {
                    l.starts_with("mail_auth_proxy_legacy_list_errors_total{list=\"users_file\"}")
                })
                .and_then(|l| l.rsplit(' ').next()?.parse::<u64>().ok())
                .unwrap()
        };
        let e0 = errors();
        std::fs::write(&path, "bad entry with spaces\n").unwrap();
        f.reload();
        assert!(!f.usable());
        for u in ["a@example.org", "b@example.org", "inline@example.org"] {
            assert!(!allowed(u).await, "{u}: invalid file must fail closed");
        }
        f.reload();
        assert!(errors() >= e0 + 2, "retried and counted every time");
        std::fs::remove_file(&path).unwrap();
        f.reload();
        assert!(
            !allowed("inline@example.org").await,
            "missing file fails closed"
        );
        std::fs::write(&path, "c@example.org\n").unwrap();
        f.reload();
        assert!(allowed("c@example.org").await && allowed("inline@example.org").await);
        assert!(!allowed("a@example.org").await);
        std::fs::remove_file(&path).unwrap();
        assert!(ListFile::load(
            path.to_str().unwrap(),
            ListKind::Users,
            config::check_user_entry
        )
        .is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A broken domains_file closes the domain gate, inline domains included.
    #[tokio::test]
    async fn broken_domains_file_closes_the_domain_gate() {
        let dir = tempfile_dir();
        let path = dir.join("domains");
        std::fs::write(&path, "file.example\n").unwrap();
        let g = gate_with(Legacy {
            allowed_domains: vec!["inline.example".into()],
            domains_file: Some(path.display().to_string()),
            rules: vec![rule("all", &["127.0.0.0/8"])],
            ..Legacy::default()
        });
        let peer = ip("127.0.0.1");
        assert!(pass(
            g.check(Proto::Imap, peer, None, "PLAIN", "a@inline.example")
                .await
        )
        .is_some());
        std::fs::write(&path, "not a domain at all\n").unwrap();
        g.files[0].reload();
        assert_eq!(
            denied(
                g.check(Proto::Imap, peer, None, "PLAIN", "a@inline.example")
                    .await
            ),
            Some((Reason::UnknownDomain, "all".into()))
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Logins the gate never looks at, whatever is configured.
    #[tokio::test]
    async fn oversized_or_control_logins_are_refused() {
        let g = gate(vec![rule("all", &["127.0.0.0/8"])]);
        let peer = ip("127.0.0.1");
        let long = format!("{}@example.org", "a".repeat(250));
        for u in [
            long.as_str(),
            "a\u{7}@example.org",
            "",
            "a@evil.test@example.org",
        ] {
            assert_eq!(
                denied(g.check(Proto::Imap, peer, None, "PLAIN", u).await),
                Some((Reason::UnknownAccount, String::new())),
                "{u:?}"
            );
        }
        assert!(pass(
            g.check(Proto::Imap, peer, None, "PLAIN", "a@example.org")
                .await
        )
        .is_some());
    }

    /// Refusals are padded to the median of the recent backend rejections
    /// of the same protocol (bounded), plus jitter; never below the delay.
    #[tokio::test]
    async fn refusal_time_follows_backend_rejections() {
        let g = gate_with(Legacy {
            failure_delay_ms: 100,
            rules: vec![rule("all", &["127.0.0.0/8"])],
            ..Legacy::default()
        });
        assert_eq!(g.failure_time(Proto::Imap), Duration::from_millis(100));
        for ms in [800, 700, 900] {
            let q = &g.reject_latency[proto_index(Proto::Imap)];
            q.lock().unwrap().push_back(Duration::from_millis(ms));
        }
        assert_eq!(g.failure_time(Proto::Imap), Duration::from_millis(800));
        assert_eq!(
            g.failure_time(Proto::Smtp),
            Duration::from_millis(100),
            "per protocol"
        );
        for _ in 0..4 {
            g.reject_latency[0]
                .lock()
                .unwrap()
                .push_back(Duration::from_secs(3600));
        }
        assert_eq!(g.failure_time(Proto::Imap), MAX_LEARNED_DELAY);
        let now = tokio::time::Instant::now();
        for _ in 0..50 {
            let d = g.refusal_deadline(Proto::Smtp, now) - now;
            assert!(
                d >= Duration::from_millis(100) && d <= Duration::from_millis(150),
                "{d:?}"
            );
        }
        let spread: std::collections::HashSet<_> = (0..20)
            .map(|_| g.refusal_deadline(Proto::Smtp, now))
            .collect();
        assert!(spread.len() > 1, "jitter");
        for _ in 0..40 {
            g.rejected_deadline(Proto::Sieve, now);
        }
        assert_eq!(g.reject_latency[2].lock().unwrap().len(), LATENCY_SAMPLES);
    }

    /// The mechanism is part of the rule: a LOGIN offered by one rule does
    /// not let another rule's users in with LOGIN.
    #[tokio::test]
    async fn mechanism_is_checked_per_rule() {
        let mut plain_all = rule("plain-all", &["127.0.0.0/8"]);
        plain_all.mechanisms = Some(vec![Mechanism::Plain]);
        let mut login_one = rule("login-one", &["127.0.0.0/8"]);
        login_one.mechanisms = Some(vec![Mechanism::Login]);
        login_one.users = Some(vec!["x@example.org".into()]);
        let g = gate(vec![plain_all, login_one]);
        let peer = ip("127.0.0.1");
        assert_eq!(
            g.advertised(Proto::Imap, peer, None),
            MechSet {
                plain: true,
                login: true
            }
        );
        assert_eq!(
            pass(
                g.check(Proto::Imap, peer, None, "LOGIN", "x@example.org")
                    .await
            )
            .as_deref(),
            Some("login-one")
        );
        assert_eq!(
            denied(
                g.check(Proto::Imap, peer, None, "LOGIN", "y@example.org")
                    .await
            ),
            Some((Reason::BlockedEndpoint, String::new()))
        );
        assert_eq!(
            pass(
                g.check(Proto::Imap, peer, None, "PLAIN", "y@example.org")
                    .await
            )
            .as_deref(),
            Some("plain-all")
        );
    }

    /// SMTP offers LOGIN only together with PLAIN; IMAP may offer LOGIN
    /// alone (it is also the LOGIN command).
    #[test]
    fn smtp_login_needs_plain() {
        let mut r = rule("login", &["127.0.0.0/8"]);
        r.mechanisms = Some(vec![Mechanism::Login]);
        let g = gate(vec![r]);
        let peer = ip("127.0.0.1");
        assert!(!g.advertised(Proto::Smtp, peer, None).any());
        let imap = g.advertised(Proto::Imap, peer, None);
        assert!(imap.login && !imap.plain);
    }

    #[test]
    fn user_matching() {
        assert!(user_matches("*@example.org", "x@EXAMPLE.org"));
        assert!(!user_matches("*@example.org", "x@evil.example.org"));
        assert!(!user_matches("*@example.org", "example.org"));
        assert!(user_matches("bob", "bob"));
        assert!(!user_matches("bob", "bob@example.org"));
        assert!(!user_matches("bob@example.org", "bob"));
    }

    fn tempfile_dir() -> std::path::PathBuf {
        static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let d = std::env::temp_dir().join(format!(
            "mailproxy-legacy-{}-{}",
            std::process::id(),
            N.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }
}
