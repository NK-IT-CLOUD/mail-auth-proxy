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
use std::sync::{Arc, Mutex};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

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

pub struct Limits {
    total: Arc<Semaphore>,
    preauth_total: Arc<Semaphore>,
    preauth: Mutex<HashMap<IpAddr, usize>>,
    max_preauth_per_ip: usize,
    /// Prefix length IPv6 sources are grouped by (`preauth_key`).
    v6_prefix: u8,
}

/// Held for the whole connection; frees the global slot on drop.
pub struct ConnPermit {
    _total: OwnedSemaphorePermit,
    preauth: Option<PreauthSlot>,
}

struct PreauthSlot {
    limits: Arc<Limits>,
    ip: IpAddr,
    _global: OwnedSemaphorePermit,
}

impl Drop for PreauthSlot {
    fn drop(&mut self) {
        let mut map = self
            .limits
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
            total: Arc::new(Semaphore::new(max_connections)),
            preauth_total: Arc::new(Semaphore::new((max_connections / 2).max(1))),
            preauth: Mutex::new(HashMap::new()),
            max_preauth_per_ip,
            v6_prefix,
        })
    }

    /// Admit a new connection from `ip`, or `None` if a limit is reached.
    pub fn admit(self: &Arc<Self>, ip: IpAddr) -> Option<ConnPermit> {
        let ip = preauth_key(ip, self.v6_prefix);
        let total = self.total.clone().try_acquire_owned().ok()?;
        let global = self.preauth_total.clone().try_acquire_owned().ok()?;
        {
            let mut map = self.preauth.lock().unwrap_or_else(|p| p.into_inner());
            let n = map.entry(ip).or_insert(0);
            if *n >= self.max_preauth_per_ip {
                return None;
            }
            *n += 1;
        }
        Some(ConnPermit {
            _total: total,
            preauth: Some(PreauthSlot {
                limits: self.clone(),
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
            l.preauth.lock().unwrap().get(&ip("1.1.1.1")).is_none(),
            "no stale entry"
        );
    }
}
