//! The DER walk to a certificate's `notAfter` (`server::tls::not_after`,
//! RFC 5280 §4.1): on raw bytes, and with the fuzz bytes as the time value
//! inside a certificate skeleton so the time parser is reached directly.
#![no_main]

use libfuzzer_sys::fuzz_target;
use mail_auth_proxy::fuzz_api::*;

/// 9999-12-31 plus the largest unchecked day (31), hour, minute and second
/// fields (99 each): no parsed time can lie beyond it.
const LATEST: u64 = 253_402_214_400 + 99 * 3600 + 99 * 60 + 99;

/// One DER element with a definite length.
fn der(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes: Vec<u8> = len
            .to_be_bytes()
            .into_iter()
            .skip_while(|&b| b == 0)
            .collect();
        out.push(0x80 | bytes.len() as u8);
        out.extend(bytes);
    }
    out.extend_from_slice(content);
    out
}

fn check(der: &[u8]) {
    if let Some(t) = tls_not_after(der) {
        assert!(t <= LATEST, "notAfter {t} out of range");
    }
}

fuzz_target!(|data: &[u8]| {
    check(data);

    // Certificate { tbsCertificate { [0] version, serial, signature, issuer,
    // validity { notBefore, notAfter } } }; the first byte picks UTCTime or
    // GeneralizedTime for notAfter, the rest is its value.
    let Some((&sel, time)) = data.split_first() else {
        return;
    };
    let tag = if sel & 1 == 0 { 0x17 } else { 0x18 };
    let validity = [der(0x17, b"250101000000Z"), der(tag, time)].concat();
    let tbs = [
        der(0xa0, &der(0x02, &[2])),
        der(0x02, &[1]),
        der(
            0x30,
            &der(0x06, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]),
        ),
        der(0x30, &[]),
        der(0x30, &validity),
    ]
    .concat();
    let cert = der(0x30, &der(0x30, &tbs));
    check(&cert);

    // A well-formed time must parse: YYMMDDHHMMSSZ / YYYYMMDDHHMMSSZ with a
    // month and day in range, from 1970 on.
    let well_formed = time.last() == Some(&b'Z')
        && time[..time.len() - 1].iter().all(u8::is_ascii_digit)
        && time.len() == if tag == 0x17 { 13 } else { 15 };
    if well_formed {
        let d = |i: usize| u32::from(time[i] - b'0') * 10 + u32::from(time[i + 1] - b'0');
        let (year, m) = if tag == 0x17 {
            let yy = d(0);
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, 2)
        } else {
            (d(0) * 100 + d(2), 4)
        };
        let (month, day) = (d(m), d(m + 2));
        if year >= 1970 && (1..=12).contains(&month) && (1..=31).contains(&day) {
            assert!(tls_not_after(&cert).is_some(), "{time:?} refused");
        }
    }
});
