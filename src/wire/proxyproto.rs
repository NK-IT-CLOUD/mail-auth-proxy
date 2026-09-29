//! PROXY protocol v2 header construction.
//!
//! The proxy opens a fresh connection to the backend, so without this header
//! Dovecot logs the proxy's address as `rip=` for every IMAP and ManageSieve
//! session. The header describes the original connection (client → the
//! address it dialed) and must be the first bytes on the backend connection,
//! before the TLS handshake; Dovecot needs `haproxy = yes` on that listener.
//! Writing it is `wire/connect.rs`.
//!
//! Spec: <https://www.haproxy.org/download/2.9/doc/proxy-protocol.txt> §2.2.

use std::net::SocketAddr;

/// The 12-byte v2 signature that opens every header.
const SIG: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];

/// version (0x2) << 4 | command PROXY (0x1).
const VER_CMD_PROXY: u8 = 0x21;

// Address-family + transport-protocol byte.
const AF_INET_STREAM: u8 = 0x11; // TCP over IPv4
const AF_INET6_STREAM: u8 = 0x21; // TCP over IPv6

/// version (0x2) << 4 | command LOCAL (0x0): the proxy's own connection (the
/// ManageSieve capability probe); the backend keeps the socket's real
/// addresses.
const VER_CMD_LOCAL: u8 = 0x20;

/// A PROXY protocol v2 LOCAL header: signature, LOCAL, family UNSPEC, no
/// address block. For connections the proxy makes on its own behalf.
pub fn v2_local_header() -> Vec<u8> {
    let mut out = Vec::with_capacity(16);
    out.extend_from_slice(&SIG);
    out.extend_from_slice(&[VER_CMD_LOCAL, 0x00, 0x00, 0x00]);
    out
}

/// Build a PROXY protocol v2 header describing a TCP connection from `src`
/// (the real client) to `dst` (the address the client connected to).
///
/// `src` and `dst` must share an address family; the accepted client socket and
/// its local address always do, so callers pass the client peer and the
/// listener-side local address of the *same* socket. Returns `None` if the two
/// families differ (defensive — should never happen for one socket).
pub fn v2_header(src: SocketAddr, dst: SocketAddr) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(28);
    out.extend_from_slice(&SIG);
    out.push(VER_CMD_PROXY);

    match (src, dst) {
        (SocketAddr::V4(s), SocketAddr::V4(d)) => {
            out.push(AF_INET_STREAM);
            // Address block length: 4 + 4 + 2 + 2 = 12.
            out.extend_from_slice(&12u16.to_be_bytes());
            out.extend_from_slice(&s.ip().octets());
            out.extend_from_slice(&d.ip().octets());
            out.extend_from_slice(&s.port().to_be_bytes());
            out.extend_from_slice(&d.port().to_be_bytes());
        }
        (SocketAddr::V6(s), SocketAddr::V6(d)) => {
            out.push(AF_INET6_STREAM);
            // Address block length: 16 + 16 + 2 + 2 = 36.
            out.extend_from_slice(&36u16.to_be_bytes());
            out.extend_from_slice(&s.ip().octets());
            out.extend_from_slice(&d.ip().octets());
            out.extend_from_slice(&s.port().to_be_bytes());
            out.extend_from_slice(&d.port().to_be_bytes());
        }
        // Mixed families cannot describe one real socket; refuse rather than
        // emit a malformed header the backend would reject.
        _ => return None,
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    #[test]
    fn ipv4_header_matches_wire_format() {
        let src = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 7), 51344));
        let dst = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 31), 993));
        let h = v2_header(src, dst).unwrap();

        // 12 sig + 1 ver/cmd + 1 fam + 2 len + 12 addr = 28 bytes.
        assert_eq!(h.len(), 28);
        assert_eq!(&h[..12], &SIG);
        assert_eq!(h[12], 0x21); // version 2, PROXY
        assert_eq!(h[13], 0x11); // TCP over IPv4
        assert_eq!(&h[14..16], &12u16.to_be_bytes());
        assert_eq!(&h[16..20], &[203, 0, 113, 7]); // src ip
        assert_eq!(&h[20..24], &[192, 0, 2, 31]); // dst ip
        assert_eq!(&h[24..26], &51344u16.to_be_bytes()); // src port
        assert_eq!(&h[26..28], &993u16.to_be_bytes()); // dst port
    }

    #[test]
    fn ipv6_header_has_36_byte_address_block() {
        let src = SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            40000,
            0,
            0,
        ));
        let dst = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 993, 0, 0));
        let h = v2_header(src, dst).unwrap();

        assert_eq!(h.len(), 16 + 36); // 16-byte fixed prefix + 36-byte addr block
        assert_eq!(h[13], 0x21); // TCP over IPv6
        assert_eq!(&h[14..16], &36u16.to_be_bytes());
        assert_eq!(
            &h[16..32],
            &Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets()
        );
        assert_eq!(&h[32..48], &Ipv6Addr::LOCALHOST.octets());
        assert_eq!(&h[48..50], &40000u16.to_be_bytes());
        assert_eq!(&h[50..52], &993u16.to_be_bytes());
    }

    #[test]
    fn mixed_families_refused() {
        let src = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 7), 1));
        let dst = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 993, 0, 0));
        assert!(v2_header(src, dst).is_none());
    }

    #[test]
    fn local_header_is_16_bytes_with_local_command() {
        let h = v2_local_header();
        assert_eq!(h.len(), 16);
        assert_eq!(&h[..12], &SIG);
        assert_eq!(h[12], 0x20);
        assert_eq!(&h[13..], &[0, 0, 0]);
    }
}
