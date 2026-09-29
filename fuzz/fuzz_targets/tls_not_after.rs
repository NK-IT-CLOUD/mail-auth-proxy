//! The DER walk to a certificate's `notAfter` (`server::tls::not_after`,
//! RFC 5280 §4.1): on raw bytes, and with the fuzz bytes as the time value
//! inside a certificate skeleton so the time parser is reached directly.
#![no_main]

use libfuzzer_sys::fuzz_target;
use mail_auth_proxy::fuzz_api::*;

/// 9999-12-31 23:59:60 (a leap second): no parsed time can lie beyond it.
const LATEST: u64 = 253_402_214_400 + 23 * 3600 + 59 * 60 + 60;

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

    // A well-formed time (YYMMDDHHMMSSZ / YYYYMMDDHHMMSSZ, from 1970 on)
    // parses exactly when its fields are in range: the day within its month
    // (Gregorian leap years), hour ≤ 23, minute ≤ 59, second ≤ 60.
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
        let (month, day, h, min, s) = (d(m), d(m + 2), d(m + 4), d(m + 6), d(m + 8));
        let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
        let month_days = match month {
            2 if leap => 29,
            2 => 28,
            4 | 6 | 9 | 11 => 30,
            _ => 31,
        };
        let valid = (1..=12).contains(&month)
            && (1..=month_days).contains(&day)
            && h <= 23
            && min <= 59
            && s <= 60;
        if year >= 1970 {
            assert_eq!(
                tls_not_after(&cert).is_some(),
                valid,
                "{:?}",
                String::from_utf8_lossy(time)
            );
        }
    }
});
