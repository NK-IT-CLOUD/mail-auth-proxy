//! Network membership: parsing configured CIDRs and testing a client address
//! against them. The legacy rules (`auth/legacy.rs`) and the scope label use
//! it.
//!
//! The mail proxy is a public edge. SNI is chosen by the client (an attacker
//! can forge it), so the source address is the hard boundary of every legacy
//! rule; NAT/DNAT preserves the real source address for external clients.

use anyhow::{Context, Result};
use ipnet::IpNet;
use std::net::IpAddr;

/// Parse configured CIDRs once at startup. A bad CIDR is a configuration
/// error and aborts boot rather than silently widening/narrowing a rule.
pub fn parse_internal_nets(cidrs: &[String]) -> Result<Vec<IpNet>> {
    cidrs
        .iter()
        .map(|c| {
            c.parse::<IpNet>()
                .with_context(|| format!("bad internal_networks CIDR {c:?}"))
        })
        .collect()
}

/// True iff the source IP is inside `nets`.
pub fn is_internal(peer: IpAddr, nets: &[IpNet]) -> bool {
    // On a dual-stack listener IPv4 clients arrive as ::ffff:a.b.c.d, which no
    // IPv4 CIDR contains; compare the canonical form.
    let peer = peer.to_canonical();
    nets.iter().any(|n| n.contains(&peer))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nets() -> Vec<IpNet> {
        parse_internal_nets(&[
            "10.0.0.0/8".into(),
            "192.168.0.0/16".into(),
            "127.0.0.0/8".into(),
            "::1/128".into(),
        ])
        .unwrap()
    }

    #[test]
    fn membership() {
        for inside in ["10.20.2.22", "192.168.0.3", "127.0.0.1", "::1"] {
            assert!(is_internal(inside.parse().unwrap(), &nets()), "{inside}");
        }
        assert!(!is_internal("203.0.113.7".parse().unwrap(), &nets()));
    }

    #[test]
    fn bad_cidr_is_rejected() {
        assert!(parse_internal_nets(&["not-a-cidr".into()]).is_err());
    }

    /// Dual-stack listeners see IPv4 clients as ::ffff:a.b.c.d.
    #[test]
    fn ipv4_mapped_peer_is_classified_like_ipv4() {
        let internal: IpAddr = "::ffff:10.20.3.30".parse().unwrap();
        let external: IpAddr = "::ffff:203.0.113.5".parse().unwrap();
        assert!(is_internal(internal, &nets()));
        assert!(!is_internal(external, &nets()));
    }
}
