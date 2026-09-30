//! Backend pools: the addresses of one backend, their health, and the choice
//! of an address for a login.
//!
//! A login fails over to the next address only while no credential has been
//! sent: a failed TCP connect, PROXY header, TLS handshake or dialog before
//! the credential. After the credential a temporary failure is an outage of
//! that login, never retried elsewhere: the password would reach a second
//! auth process and its failure counters. Either way an outage is never a
//! failed login.
//!
//! Health is passive, from the logins and probes, and optionally active
//! (`health_check_secs`): `FALL` failures in a row mark an address down,
//! `RISE` successes in a row up again (haproxy's defaults for `fall` and
//! `rise`). Addresses that are down come after those that are up; a down
//! address takes one login at a time as a trial (half-open), others skip it.

use crate::config::PoolStrategy;
use crate::server::BackendConn;
use anyhow::{anyhow, Result};
use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Failures in a row that mark an address down.
pub const FALL: u32 = 3;
/// Successes in a row that mark a down address up again.
pub const RISE: u32 = 2;
/// Addresses one login tries at most.
pub const MAX_TRIES: usize = 3;

/// Where an address failed: the `stage` label of
/// `mail_auth_proxy_backend_address_errors_total`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// TCP connect or the PROXY header.
    Connect,
    /// The TLS handshake, the certificate included.
    Tls,
    /// The dialog before the credential: greeting, STARTTLS, EHLO,
    /// capabilities.
    Greeting,
    /// After the connection was open: no verdict on the credential (a
    /// temporary failure reply, a timeout), or a misconfiguration found then.
    AuthTempfail,
}

impl Stage {
    pub const ALL: [Stage; 4] = [
        Stage::Connect,
        Stage::Tls,
        Stage::Greeting,
        Stage::AuthTempfail,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Stage::Connect => "connect",
            Stage::Tls => "tls",
            Stage::Greeting => "greeting",
            Stage::AuthTempfail => "auth_tempfail",
        }
    }

    fn idx(self) -> usize {
        self as usize
    }
}

/// An error of the connect helpers marked with its stage. Transparent: it
/// shows as the error it wraps, so logs keep their text.
#[derive(Debug)]
pub struct Staged {
    pub stage: Stage,
    pub error: anyhow::Error,
}

impl std::fmt::Display for Staged {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.error, f)
    }
}

impl std::error::Error for Staged {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.error.source()
    }
}

/// `e` marked with `stage`.
pub fn staged(stage: Stage, e: anyhow::Error) -> anyhow::Error {
    anyhow::Error::new(Staged { stage, error: e })
}

/// The stage of a failed attempt: that of the connect helpers, else the
/// dialog before the credential.
fn stage_of(e: &anyhow::Error) -> Stage {
    e.chain()
        .find_map(|c| c.downcast_ref::<Staged>())
        .map_or(Stage::Greeting, |s| s.stage)
}

/// The health of one address; kept across a reload while the backend keeps
/// the address.
#[derive(Debug)]
pub struct Health {
    state: Mutex<State>,
    /// A trial login or check of a down address is running.
    trial: AtomicBool,
    /// Failures by stage.
    errors: [AtomicU64; 4],
}

#[derive(Debug)]
struct State {
    up: bool,
    /// Failures (up) or successes (down) in a row.
    streak: u32,
    /// The last attempt that failed, to order down addresses.
    last_failure: Option<Instant>,
}

impl Default for Health {
    fn default() -> Self {
        Health {
            state: Mutex::new(State {
                up: true,
                streak: 0,
                last_failure: None,
            }),
            trial: AtomicBool::new(false),
            errors: Default::default(),
        }
    }
}

impl Health {
    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn is_up(&self) -> bool {
        self.state().up
    }

    /// Failures counted at `stage`.
    pub fn errors(&self, stage: Stage) -> u64 {
        self.errors[stage.idx()].load(Ordering::Relaxed)
    }

    /// An attempt got through the dialog before the credential.
    pub fn success(&self) {
        let mut s = self.state();
        if s.up {
            s.streak = 0;
        } else {
            s.streak += 1;
            if s.streak >= RISE {
                (s.up, s.streak) = (true, 0);
            }
        }
    }

    /// An attempt failed at `stage`. Only the stages before the credential
    /// count towards `FALL`.
    pub fn failure(&self, stage: Stage) {
        self.errors[stage.idx()].fetch_add(1, Ordering::Relaxed);
        if stage == Stage::AuthTempfail {
            return;
        }
        let mut s = self.state();
        s.last_failure = Some(Instant::now());
        if s.up {
            s.streak += 1;
            if s.streak >= FALL {
                (s.up, s.streak) = (false, 0);
            }
        } else {
            s.streak = 0;
        }
    }

    /// Claim the one trial of a down address; `None` while another runs.
    fn trial(&self) -> Option<Trial<'_>> {
        self.trial
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| Trial(&self.trial))
    }
}

/// A claimed trial; released on drop, also when the attempt is cancelled.
struct Trial<'a>(&'a AtomicBool);

impl Drop for Trial<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// Counters of one backend, kept across a reload while its name stays.
#[derive(Debug, Default)]
pub struct Stats {
    /// Logins or probes that succeeded on another address than the first
    /// they tried.
    pub failovers: AtomicU64,
    /// Sessions spliced to the backend.
    pub sessions: AtomicU64,
}

/// One address of a pool.
pub struct Member {
    pub conn: BackendConn,
    pub health: Arc<Health>,
}

/// A backend with its addresses.
pub struct Pool {
    /// The backend's name.
    pub id: String,
    pub members: Vec<Member>,
    strategy: PoolStrategy,
    /// Round robin: the next start.
    next: AtomicUsize,
    pub stats: Arc<Stats>,
    /// Seconds between active checks of each address.
    pub health_check: Option<std::time::Duration>,
}

/// FNV-1a 64 over `parts`: stable across runs and versions, so a user stays
/// on its address across restarts.
fn fnv(parts: &[&[u8]]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for p in parts {
        for b in *p {
            h ^= u64::from(*b);
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
        // Separator: ("ab","c") and ("a","bc") differ.
        h ^= 0xff;
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

impl Pool {
    pub fn new(
        id: String,
        members: Vec<Member>,
        strategy: PoolStrategy,
        stats: Arc<Stats>,
        health_check: Option<std::time::Duration>,
    ) -> Pool {
        Pool {
            id,
            members,
            strategy,
            next: AtomicUsize::new(0),
            stats,
            health_check,
        }
    }

    /// The members to try for a login, in order: those that are up by the
    /// strategy (`key`: the identity or login, for `hash`), then those that
    /// are down, the longest-failed first.
    fn order(&self, key: Option<&str>) -> Vec<usize> {
        let n = self.members.len();
        let mut up: Vec<usize> = (0..n).filter(|i| self.members[*i].health.is_up()).collect();
        match (self.strategy, key) {
            (PoolStrategy::Hash, Some(key)) => {
                let key = key.to_ascii_lowercase();
                up.sort_by_key(|i| {
                    std::cmp::Reverse(fnv(&[
                        key.as_bytes(),
                        self.members[*i].conn.address.as_bytes(),
                    ]))
                });
            }
            (PoolStrategy::RoundRobin, _) if !up.is_empty() => {
                let start = self.next.fetch_add(1, Ordering::Relaxed) % up.len();
                up.rotate_left(start);
            }
            _ => {}
        }
        let mut down: Vec<(Option<Instant>, usize)> = (0..n)
            .filter(|i| !self.members[*i].health.is_up())
            .map(|i| (self.members[i].health.state().last_failure, i))
            .collect();
        down.sort();
        up.extend(down.into_iter().map(|(_, i)| i));
        up
    }

    /// Run `attempt` (the connection and dialog before the credential, given
    /// the member's index) against the members in order until one succeeds, at most
    /// `MAX_TRIES`. Returns its result and the member's index. A down
    /// member is tried only as a trial no other login runs. Every attempt
    /// feeds the member's health; a success after a failure counts as a
    /// failover. When all fail, the last error; when none could be tried,
    /// an error saying so: an outage either way.
    pub async fn open<T, F, Fut>(&self, key: Option<&str>, mut attempt: F) -> Result<(T, usize)>
    where
        F: FnMut(usize) -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        let mut last = None;
        let mut tried = 0;
        let order = self.order(key);
        for (pos, &i) in order.iter().enumerate() {
            if tried == MAX_TRIES {
                break;
            }
            let m = &self.members[i];
            let _trial = if m.health.is_up() {
                None
            } else {
                match m.health.trial() {
                    Some(t) => Some(t),
                    None => continue,
                }
            };
            tried += 1;
            match attempt(i).await {
                Ok(v) => {
                    m.health.success();
                    if tried > 1 {
                        self.stats.failovers.fetch_add(1, Ordering::Relaxed);
                    }
                    return Ok((v, i));
                }
                Err(e) => {
                    m.health.failure(stage_of(&e));
                    if tried < MAX_TRIES && pos + 1 < order.len() {
                        tracing::warn!(target: crate::obs::target::MAIN, backend=%self.id, address=%m.conn.address, error=%format!("{e:#}"), "backend address failed; trying the next");
                    }
                    last = Some(e);
                }
            }
        }
        Err(last.unwrap_or_else(|| {
            anyhow!(
                "backend {}: every address is down and being tried by another login",
                self.id
            )
        }))
    }

    /// Member `index` answered a login it had opened without a verdict.
    pub fn tempfail(&self, index: usize) {
        if let Some(m) = self.members.get(index) {
            m.health.failure(Stage::AuthTempfail);
        }
    }

    /// A session was spliced to this backend.
    pub fn session(&self) {
        self.stats.sessions.fetch_add(1, Ordering::Relaxed);
    }
}

/// One round of active health checks of `pool`: `check` (the protocol's
/// dialog up to the greeting, without a credential, given the member's
/// index) against each member,
/// feeding its health. A down member's check is its trial, skipped while a
/// login runs one.
pub async fn check_round<F, Fut>(pool: &Pool, check: F)
where
    F: Fn(usize) -> Fut,
    Fut: Future<Output = Result<()>>,
{
    for (i, m) in pool.members.iter().enumerate() {
        let _trial = if m.health.is_up() {
            None
        } else {
            match m.health.trial() {
                Some(t) => Some(t),
                None => continue,
            }
        };
        match check(i).await {
            Ok(()) => m.health.success(),
            Err(e) => {
                tracing::debug!(target: crate::obs::target::MAIN, backend=%pool.id, address=%m.conn.address, error=%format!("{e:#}"), "backend health check failed");
                m.health.failure(stage_of(&e));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn(address: &str) -> BackendConn {
        let cfg = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        BackendConn {
            id: "pool".into(),
            address: address.into(),
            name: rustls::pki_types::ServerName::try_from("backend.test").unwrap(),
            tls: tokio_rustls::TlsConnector::from(Arc::new(cfg)),
            client_ip: crate::config::ClientIp::None,
            tls_mode: crate::config::BackendTls::Implicit,
            auth_forward: crate::config::AuthForward::Xoauth2,
            keepalive: crate::wire::Tuning::default().keepalive,
        }
    }

    fn pool(strategy: PoolStrategy, n: usize) -> Pool {
        let members = (0..n)
            .map(|i| Member {
                conn: conn(&format!("192.0.2.{i}:993")),
                health: Arc::default(),
            })
            .collect();
        Pool::new("pool".into(), members, strategy, Arc::default(), None)
    }

    /// `FALL` failures before the credential mark an address down, `RISE`
    /// successes up again; a success resets the count; failures after the
    /// credential are counted but do not mark it down.
    #[test]
    fn health_falls_and_rises() {
        let h = Health::default();
        for _ in 0..FALL - 1 {
            h.failure(Stage::Connect);
        }
        h.success();
        for _ in 0..FALL - 1 {
            h.failure(Stage::Tls);
        }
        assert!(h.is_up(), "a success reset the count");
        for _ in 0..10 {
            h.failure(Stage::AuthTempfail);
        }
        assert!(
            h.is_up(),
            "a tempfail after the credential is not a down address"
        );
        h.failure(Stage::Greeting);
        assert!(!h.is_up());
        h.success();
        assert!(!h.is_up());
        h.failure(Stage::Connect);
        h.success();
        assert!(!h.is_up(), "rise needs successes in a row");
        h.success();
        assert!(h.is_up());
        assert_eq!(
            Stage::ALL.map(|s| h.errors(s)),
            [FALL as u64, FALL as u64 - 1, 1, 10]
        );
    }

    fn down(p: &Pool, i: usize) {
        for _ in 0..FALL {
            p.members[i].health.failure(Stage::Connect);
        }
    }

    #[test]
    fn order_by_strategy_up_before_down() {
        let p = pool(PoolStrategy::Failover, 3);
        assert_eq!(p.order(Some("a@x")), [0, 1, 2]);
        down(&p, 0);
        assert_eq!(p.order(None), [1, 2, 0]);
        down(&p, 2);
        // The longest-failed down address first.
        assert_eq!(p.order(None), [1, 0, 2]);

        let rr = pool(PoolStrategy::RoundRobin, 3);
        let starts: Vec<usize> = (0..4).map(|_| rr.order(None)[0]).collect();
        assert_eq!(starts, [0, 1, 2, 0]);

        // Hash: a key keeps its address while it is up, keys spread, the
        // case of the key does not matter, and when its address is down the
        // key moves while the others stay.
        let h = pool(PoolStrategy::Hash, 3);
        let first = |k: &str| h.order(Some(k))[0];
        let keys: Vec<String> = (0..60).map(|i| format!("user{i}@example.org")).collect();
        let before: Vec<usize> = keys.iter().map(|k| first(k)).collect();
        assert_eq!(first("User7@Example.org"), before[7]);
        for m in 0..3 {
            assert!(before.contains(&m), "address {m} gets keys");
        }
        down(&h, before[0]);
        for (k, b) in keys.iter().zip(&before) {
            if *b != before[0] {
                assert_eq!(first(k), *b, "{k} stays");
            } else {
                assert_ne!(first(k), *b, "{k} moves");
            }
        }
        // Without a key (a probe) hash is the listed order.
        assert_eq!(pool(PoolStrategy::Hash, 3).order(None), [0, 1, 2]);
    }

    /// A failure before the credential moves to the next address and counts
    /// as a failover when another succeeds; at most `MAX_TRIES` addresses.
    #[tokio::test]
    async fn open_fails_over_and_counts() {
        let p = pool(PoolStrategy::Failover, 4);
        let tried = Mutex::new(Vec::new());
        let (v, i) = p
            .open(None, |i| {
                let address = &p.members[i].conn.address;
                tried.lock().unwrap().push(address.clone());
                let ok = address.ends_with(".2:993");
                async move {
                    if ok {
                        Ok(7)
                    } else {
                        Err(staged(Stage::Connect, anyhow!("refused")))
                    }
                }
            })
            .await
            .unwrap();
        assert_eq!((v, i), (7, 2));
        assert_eq!(tried.lock().unwrap().len(), 3);
        assert_eq!(p.stats.failovers.load(Ordering::Relaxed), 1);
        assert_eq!(p.members[0].health.errors(Stage::Connect), 1);

        let e = p
            .open(Some("k"), |_| async {
                Err::<(), _>(anyhow!("greeting BYE"))
            })
            .await
            .unwrap_err();
        assert_eq!(e.to_string(), "greeting BYE");
        assert_eq!(
            p.members[3].health.errors(Stage::Greeting),
            0,
            "not a fourth try"
        );
    }

    /// When every address is down, one login at a time tries one (the
    /// trial); the others get an outage at once.
    #[tokio::test]
    async fn all_down_one_trial_at_a_time() {
        let p = pool(PoolStrategy::Failover, 1);
        down(&p, 0);
        let hold = p.members[0].health.trial().unwrap();
        let e = p.open(None, |_| async { Ok(()) }).await.unwrap_err();
        assert!(e.to_string().contains("every address is down"), "{e}");
        drop(hold);
        p.open(None, |_| async { Ok(()) }).await.unwrap();
        assert!(!p.members[0].health.is_up(), "one success of RISE");
        p.open(None, |_| async { Ok(()) }).await.unwrap();
        assert!(p.members[0].health.is_up());
    }

    /// The stage marker is transparent in messages.
    #[test]
    fn staged_errors_read_as_before() {
        let e = staged(
            Stage::Tls,
            anyhow::Error::new(std::io::Error::other("bad cert")).context("backend TLS handshake"),
        );
        assert_eq!(format!("{e:#}"), "backend TLS handshake: bad cert");
        assert_eq!(stage_of(&e.context("backend unavailable")), Stage::Tls);
        assert_eq!(stage_of(&anyhow!("x")), Stage::Greeting);
    }
}
