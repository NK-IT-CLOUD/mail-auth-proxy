//! Connection limits applied at accept, before any TLS or protocol work.
//!
//! Without them one host can open sockets until the process runs out of file
//! descriptors, after which `accept` fails on every listener and legitimate
//! users are locked out. Two limits:
//! - a global cap on open client connections (all protocols together), of
//!   which at most half may be unauthenticated — a pre-auth flood from many
//!   addresses cannot take the room that logins need;
//! - a per-source-IP cap on connections that have not authenticated yet. Once
//!   a session authenticates it gives its pre-auth slot back, so many logged-in
//!   sessions from one address (webmail host, NAT'd office) are not affected.
//!   IPv6 sources count per `limits.ipv6_source_prefix`, by default /64
//!   (`preauth_key`).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

/// The source a pre-auth slot is counted against: an IPv4 address (also
/// IPv4-mapped IPv6) as is, an IPv6 address by its first `v6_prefix` bits
/// (1-128). A single host is usually handed a whole /64 (RFC 7934, SLAAC), so
/// counting per /128 would let one host open `max_preauth_per_ip` connections
/// from each of 2^64 addresses; a site usually gets a /48.
pub(crate) fn preauth_key(ip: IpAddr, v6_prefix: u8) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => {
            let mask = u128::MAX << (128 - u32::from(v6_prefix.clamp(1, 128)));
            IpAddr::V6(Ipv6Addr::from(u128::from(v6) & mask))
        }
        v4 => v4,
    }
}

/// Limits in force, over the open connections of the whole process: a
/// configuration reload makes new `Limits` (`reconfigured`) that count the
/// same connections.
pub struct Limits {
    counts: Arc<Counts>,
    max_connections: usize,
    max_preauth_per_ip: usize,
    /// Prefix length IPv6 sources are grouped by (`preauth_key`).
    v6_prefix: u8,
}

/// The open connections, shared by every `Limits` of the process.
#[derive(Default)]
struct Counts {
    total: AtomicUsize,
    preauth_total: AtomicUsize,
    preauth: Mutex<HashMap<IpAddr, usize>>,
}

impl Counts {
    /// Take one of `max` slots of `counter` (`preauth_total` or `total`).
    fn hold(self: &Arc<Self>, preauth: bool, max: usize) -> Option<Held> {
        self.counter(preauth)
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < max).then_some(n + 1)
            })
            .ok()?;
        Some(Held {
            counts: self.clone(),
            preauth,
        })
    }

    fn counter(&self, preauth: bool) -> &AtomicUsize {
        if preauth {
            &self.preauth_total
        } else {
            &self.total
        }
    }
}

/// One slot of `Counts::total` or `Counts::preauth_total`, given back on drop.
struct Held {
    counts: Arc<Counts>,
    preauth: bool,
}

impl Drop for Held {
    fn drop(&mut self) {
        self.counts
            .counter(self.preauth)
            .fetch_sub(1, Ordering::AcqRel);
    }
}

/// Held for the whole connection; frees the global slot on drop.
pub struct ConnPermit {
    _total: Held,
    preauth: Option<PreauthSlot>,
}

struct PreauthSlot {
    counts: Arc<Counts>,
    /// The source key the slot was counted under.
    ip: IpAddr,
    _global: Held,
}

impl Drop for PreauthSlot {
    fn drop(&mut self) {
        let mut map = self
            .counts
            .preauth
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if let Some(n) = map.get_mut(&self.ip) {
            *n -= 1;
            if *n == 0 {
                map.remove(&self.ip);
            }
        }
    }
}

impl ConnPermit {
    /// Give the pre-auth slot back; call once a credential has been accepted.
    pub fn authenticated(&mut self) {
        self.preauth = None;
    }
}

impl Limits {
    pub fn new(max_connections: usize, max_preauth_per_ip: usize, v6_prefix: u8) -> Arc<Limits> {
        Arc::new(Limits {
            counts: Arc::default(),
            max_connections,
            max_preauth_per_ip,
            v6_prefix,
        })
    }

    /// New limits over the same open connections (a configuration reload).
    /// Connections above a lowered limit stay open; new ones are admitted
    /// once the count is below it.
    pub fn reconfigured(
        &self,
        max_connections: usize,
        max_preauth_per_ip: usize,
        v6_prefix: u8,
    ) -> Arc<Limits> {
        Arc::new(Limits {
            counts: self.counts.clone(),
            max_connections,
            max_preauth_per_ip,
            v6_prefix,
        })
    }

    /// Admit a new connection from `ip`, or `None` if a limit is reached.
    pub fn admit(&self, ip: IpAddr) -> Option<ConnPermit> {
        let ip = preauth_key(ip, self.v6_prefix);
        let total = self.counts.hold(false, self.max_connections)?;
        let global = self.counts.hold(true, (self.max_connections / 2).max(1))?;
        {
            let mut map = self
                .counts
                .preauth
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            let n = map.entry(ip).or_insert(0);
            if *n >= self.max_preauth_per_ip {
                return None;
            }
            *n += 1;
        }
        Some(ConnPermit {
            _total: total,
            preauth: Some(PreauthSlot {
                counts: self.counts.clone(),
                ip,
                _global: global,
            }),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn per_ip_limit_counts_only_unauthenticated() {
        let l = Limits::new(100, 2, 64);
        let mut a = l.admit(ip("1.2.3.4")).unwrap();
        let _b = l.admit(ip("1.2.3.4")).unwrap();
        assert!(
            l.admit(ip("1.2.3.4")).is_none(),
            "third pre-auth connection"
        );
        assert!(l.admit(ip("5.6.7.8")).is_some(), "other source unaffected");
        a.authenticated();
        let _c = l.admit(ip("1.2.3.4")).expect("slot freed after auth");
    }

    /// IPv6 sources share one per-IP budget per /64; IPv4 and IPv4-mapped
    /// sources count per address.
    #[test]
    fn per_ip_limit_groups_ipv6_by_64() {
        let l = Limits::new(100, 2, 64);
        let _a = l.admit(ip("2001:db8:1:2::1")).unwrap();
        let _b = l.admit(ip("2001:db8:1:2:ffff:ffff:ffff:ffff")).unwrap();
        assert!(
            l.admit(ip("2001:db8:1:2:abcd::9")).is_none(),
            "third connection from the same /64"
        );
        assert!(
            l.admit(ip("2001:db8:1:3::1")).is_some(),
            "neighbouring /64 unaffected"
        );
        let _c = l.admit(ip("::ffff:192.0.2.1")).unwrap();
        let _d = l.admit(ip("192.0.2.1")).unwrap();
        assert!(
            l.admit(ip("::ffff:192.0.2.1")).is_none(),
            "IPv4-mapped counts as its IPv4 address"
        );
        assert!(
            l.admit(ip("::ffff:192.0.2.2")).is_some(),
            "IPv4 stays per address"
        );
    }

    /// With `ipv6_source_prefix = 48` a whole site shares one budget; IPv4
    /// is unaffected.
    #[test]
    fn per_ip_limit_groups_ipv6_by_the_configured_prefix() {
        let l = Limits::new(100, 2, 48);
        let _a = l.admit(ip("2001:db8:1:2::1")).unwrap();
        let _b = l.admit(ip("2001:db8:1:ffff::1")).unwrap();
        assert!(
            l.admit(ip("2001:db8:1:3::1")).is_none(),
            "third connection from the same /48"
        );
        assert!(
            l.admit(ip("2001:db8:2::1")).is_some(),
            "neighbouring /48 unaffected"
        );
        let _c = l.admit(ip("192.0.2.1")).unwrap();
        assert!(l.admit(ip("192.0.2.1")).is_some(), "IPv4 stays per address");
        assert_eq!(
            preauth_key(ip("2001:db8:1:2:3:4:5:6"), 128),
            ip("2001:db8:1:2:3:4:5:6")
        );
    }

    /// Unauthenticated connections may take at most half of all slots.
    #[test]
    fn preauth_uses_at_most_half_of_the_slots() {
        let l = Limits::new(4, 10, 64);
        let _a = l.admit(ip("1.1.1.1")).unwrap();
        let mut b = l.admit(ip("2.2.2.2")).unwrap();
        assert!(l.admit(ip("3.3.3.3")).is_none(), "pre-auth half is full");
        b.authenticated();
        let _c = l.admit(ip("3.3.3.3")).expect("slot freed by the login");
    }

    /// Reconfigured limits count the connections admitted before: a lowered
    /// limit refuses new ones while the old stay open, a raised one admits
    /// more; slots counted under the old IPv6 prefix are given back.
    #[test]
    fn reconfigured_limits_count_the_open_connections() {
        let old = Limits::new(8, 2, 64);
        let mut a = old.admit(ip("192.0.2.1")).unwrap();
        a.authenticated();
        let b = old.admit(ip("2001:db8:1:2::1")).unwrap();
        let _c = old.admit(ip("2001:db8:1:2::2")).unwrap();

        let lower = old.reconfigured(2, 2, 64);
        assert!(lower.admit(ip("192.0.2.9")).is_none(), "3 open, limit 2");
        assert!(old.admit(ip("192.0.2.9")).is_some(), "old limits unchanged");

        let wider = old.reconfigured(8, 1, 48);
        let _d = wider
            .admit(ip("2001:db8:1:ffff::1"))
            .expect("the /64 slots were counted under another key");
        assert!(wider.admit(ip("2001:db8:1:fffe::1")).is_none(), "1 per /48");
        drop(b);
        assert_eq!(
            old.counts.preauth.lock().unwrap()[&ip("2001:db8:1:2::")],
            1,
            "released under the key it was counted by"
        );
        assert!(wider.admit(ip("192.0.2.2")).is_some());
        drop(a);
        assert_eq!(old.counts.total.load(Ordering::Relaxed), 2, "c and d");
    }

    #[test]
    fn global_limit_and_release_on_drop() {
        let l = Limits::new(2, 10, 64);
        let mut a = l.admit(ip("1.1.1.1")).unwrap();
        a.authenticated();
        let mut b = l.admit(ip("2.2.2.2")).unwrap();
        b.authenticated();
        assert!(l.admit(ip("3.3.3.3")).is_none());
        drop(a);
        assert!(l.admit(ip("3.3.3.3")).is_some());
        assert!(
            l.counts
                .preauth
                .lock()
                .unwrap()
                .get(&ip("1.1.1.1"))
                .is_none(),
            "no stale entry"
        );
    }
}
