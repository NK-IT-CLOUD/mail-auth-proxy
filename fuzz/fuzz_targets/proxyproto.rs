//! PROXY protocol v2 headers: the proxy only builds them, so the target
//! parses what `v2_header` emits for arbitrary address pairs and checks it
//! against the spec (haproxy proxy-protocol.txt §2.2).
#![no_main]

use libfuzzer_sys::fuzz_target;
use mail_auth_proxy::fuzz_api::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

const SIG: &[u8; 12] = b"\r\n\r\n\0\r\nQUIT\n";

/// Parse a PROXY v2 header into (source, destination).
fn parse(h: &[u8]) -> (SocketAddr, SocketAddr) {
    assert_eq!(&h[..12], SIG);
    assert_eq!(h[12], 0x21, "version 2, PROXY");
    let len = u16::from_be_bytes([h[14], h[15]]) as usize;
    assert_eq!(h.len(), 16 + len, "length field");
    let a = &h[16..];
    match h[13] {
        0x11 => {
            assert_eq!(len, 12);
            let ip = |o: usize| IpAddr::V4(Ipv4Addr::new(a[o], a[o + 1], a[o + 2], a[o + 3]));
            let port = |o: usize| u16::from_be_bytes([a[o], a[o + 1]]);
            (
                SocketAddr::new(ip(0), port(8)),
                SocketAddr::new(ip(4), port(10)),
            )
        }
        0x21 => {
            assert_eq!(len, 36);
            let ip =
                |o: usize| IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&a[o..o + 16]).unwrap()));
            let port = |o: usize| u16::from_be_bytes([a[o], a[o + 1]]);
            (
                SocketAddr::new(ip(0), port(32)),
                SocketAddr::new(ip(16), port(34)),
            )
        }
        f => panic!("family {f:#x}"),
    }
}

fn addr(d: &[u8], v6: bool) -> SocketAddr {
    let port = u16::from_be_bytes([d[0], d[1]]);
    if v6 {
        let ip = Ipv6Addr::from(<[u8; 16]>::try_from(&d[2..18]).unwrap());
        SocketAddr::new(IpAddr::V6(ip), port)
    } else {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(d[2], d[3], d[4], d[5])), port)
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 37 {
        return;
    }
    let src = addr(&data[1..19], data[0] & 1 != 0);
    let dst = addr(&data[19..37], data[0] & 2 != 0);
    match v2_header(src, dst) {
        Some(h) => {
            // Flow info and scope id are not part of the header.
            let strip = |a: SocketAddr| SocketAddr::new(a.ip(), a.port());
            assert_eq!(parse(&h), (strip(src), strip(dst)));
        }
        None => assert_ne!(src.is_ipv4(), dst.is_ipv4(), "same family refused"),
    }
    let l = v2_local_header();
    assert_eq!(&l[..12], SIG);
    assert_eq!(&l[12..], &[0x20, 0, 0, 0]);
});
