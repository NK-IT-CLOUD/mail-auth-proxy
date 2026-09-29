//! The protocol line reader against a model: CR dropped, LF ends the line,
//! at most MAX_LINE bytes consumed before the LF, UTF-8, and never a byte
//! read past the LF (no STARTTLS command injection, CVE-2011-0411).
#![no_main]

use libfuzzer_sys::fuzz_target;
use mail_auth_proxy::fuzz_api::*;
use mail_auth_proxy_fuzz::{block_on, Peer};

fuzz_target!(|data: &[u8]| {
    block_on(async {
        let mut peer = Peer::new(data);
        loop {
            let start = peer.consumed();
            let rest = &data[start..];
            let got = read_line(&mut peer, IDLE).await;
            match rest.iter().position(|&b| b == b'\n') {
                Some(nl) if nl <= MAX_LINE => {
                    assert_eq!(peer.consumed(), start + nl + 1, "read past the line feed");
                    let expect: Vec<u8> =
                        rest[..nl].iter().copied().filter(|&b| b != b'\r').collect();
                    match (got, String::from_utf8(expect)) {
                        (Ok(line), Ok(expect)) => {
                            assert_eq!(line, expect);
                            // A verb is the first space-separated word only.
                            let first = line.split(' ').next().unwrap_or("");
                            assert_eq!(
                                verb_is(&line, "STARTTLS"),
                                first.eq_ignore_ascii_case("STARTTLS")
                            );
                        }
                        (Err(LineError::Utf8(_)), Err(_)) => {}
                        (got, expect) => panic!("line {got:?}, model {expect:?}"),
                    }
                }
                Some(_) => {
                    assert!(matches!(got, Err(LineError::TooLong)), "{got:?}");
                    assert_eq!(peer.consumed(), start + MAX_LINE + 1);
                    break;
                }
                None if rest.len() > MAX_LINE => {
                    assert!(matches!(got, Err(LineError::TooLong)), "{got:?}");
                    assert_eq!(peer.consumed(), start + MAX_LINE + 1);
                    break;
                }
                None if rest.is_empty() => {
                    let e = got.expect_err("line at eof");
                    assert!(matches!(e, LineError::Eof) && e.is_eof(), "{e:?}");
                    break;
                }
                None => {
                    let e = got.expect_err("line at eof");
                    assert!(matches!(e, LineError::EofMidLine) && !e.is_eof(), "{e:?}");
                    break;
                }
            }
        }

        // The limit: random inputs that long nearly always hold an LF, so the
        // input without LFs is repeated past MAX_LINE (a CR flood included).
        // Reading 16 KiB byte by byte is slow, so only for every 32nd length.
        let flat: Vec<u8> = data.iter().copied().filter(|&b| b != b'\n').collect();
        if !flat.is_empty() && data.len() % 32 == 1 {
            let long: Vec<u8> = flat.iter().copied().cycle().take(MAX_LINE + 2).collect();
            let mut peer = Peer::new(&long);
            let got = read_line(&mut peer, IDLE).await;
            assert!(matches!(got, Err(LineError::TooLong)), "{got:?}");
            assert_eq!(peer.consumed(), MAX_LINE + 1);
        }

        // A lone `*` (whitespace around it allowed) cancels a SASL exchange.
        let mut peer = Peer::new(data);
        if let Ok(line) = read_sasl_response(&mut peer, IDLE).await {
            assert_ne!(line.trim(), "*");
        }
    });
});
