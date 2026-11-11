//! The command guard of the IMAP and ManageSieve relay after login
//! (`wire::guard`): client and backend octets interleaved in arbitrary
//! chunks. What the guard keeps from the backend (its module comment):
//!
//! - IMAP: until the backend has sent a `+` (no literal confirmed), nothing
//!   is exempt from the check, so no complete line that starts with
//!   `<tag> UNAUTHENTICATE`, `AUTHENTICATE`, `LOGIN`, `STARTTLS` or
//!   `COMPRESS` may reach the backend, wherever the client put it.
//! - ManageSieve: no complete line that starts with `UNAUTHENTICATE`, in
//!   literal data too; no command line that starts with `AUTHENTICATE` or
//!   `STARTTLS` (literal data may contain them).
#![no_main]

use libfuzzer_sys::fuzz_target;
use mail_auth_proxy::fuzz_api::*;

const IMAP_BLOCKED: &[&[u8]] = &[
    b"UNAUTHENTICATE",
    b"AUTHENTICATE",
    b"LOGIN",
    b"STARTTLS",
    b"COMPRESS",
];
const SIEVE_BLOCKED: &[&[u8]] = &[b"UNAUTHENTICATE", b"AUTHENTICATE", b"STARTTLS"];
const SIEVE_IN_DATA: &[&[u8]] = &[b"UNAUTHENTICATE"];

/// The listed word a complete line (without its LF) names for a lenient
/// backend: blanks, for IMAP a tag and blanks, then the word, then a blank,
/// CR or the end.
fn names(line: &[u8], imap: bool, words: &[&'static [u8]]) -> Option<&'static [u8]> {
    let skip = |s: &[u8]| -> usize { s.iter().take_while(|b| **b == b' ' || **b == b'\t').count() };
    let mut s = &line[skip(line)..];
    if imap {
        let tag = s.iter().take_while(|b| **b != b' ' && **b != b'\t').count();
        if tag == 0 || tag == s.len() {
            return None;
        }
        s = &s[tag..];
        s = &s[skip(s)..];
    }
    words.iter().copied().find(|w| {
        s.len() >= w.len()
            && s[..w.len()].eq_ignore_ascii_case(w)
            && matches!(s.get(w.len()), None | Some(b' ' | b'\r' | b'\t'))
    })
}

/// The octet count of a ManageSieve literal marker a command line segment
/// (without its LF) ends with: `{n}` or `{n+}`, then an optional CR
/// (RFC 5804 §4).
fn sieve_marker(seg: &[u8]) -> Option<u64> {
    let s = seg.strip_suffix(b"\r").unwrap_or(seg);
    let s = s.strip_suffix(b"}")?;
    let s = s.strip_suffix(b"+").unwrap_or(s);
    let digits = s.iter().rev().take_while(|b| b.is_ascii_digit()).count();
    if digits == 0 || digits > 19 || s.len() == digits || s[s.len() - digits - 1] != b'{' {
        return None;
    }
    std::str::from_utf8(&s[s.len() - digits..]).ok()?.parse().ok()
}

/// The ManageSieve command lines in what reached the backend, framed as the
/// guard frames them: the command word (optionally after blanks, quotes and
/// a literal marker's `{`), then the rest of the line with quoted strings,
/// ending with a literal marker or not. Literal data is no command line.
fn sieve_command_lines(s: &[u8]) -> Vec<&[u8]> {
    let is_word = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'=');
    let mut lines = Vec::new();
    let mut i = 0;
    while i < s.len() {
        let Some(nl) = s[i..].iter().position(|&b| b == b'\n') else {
            break;
        };
        lines.push(&s[i..i + nl]);
        // The command word; a closing quote after it belongs to it.
        let mut j = i;
        let mut quoted = false;
        while matches!(s[j], b' ' | b'\t' | b'\r' | b'"' | b'{' | b'~') {
            quoted |= s[j] == b'"';
            j += 1;
        }
        while is_word(s[j]) {
            j += 1;
        }
        if quoted && s[j] == b'"' {
            j += 1;
        }
        // The rest of the line, and of the line after each literal.
        loop {
            let Some(nl) = s[j..].iter().position(|&b| b == b'\n') else {
                return lines;
            };
            let seg = &s[j..j + nl];
            let mut quote = 0u8; // 0 outside, 1 inside, 2 after a backslash
            for &b in seg {
                quote = match (quote, b) {
                    (0, b'"') => 1,
                    (1, b'\\') => 2,
                    (1, b'"') => 0,
                    (2, _) => 1,
                    (q, _) => q,
                };
            }
            let end = j + nl + 1;
            match sieve_marker(seg).filter(|_| quote == 0) {
                Some(n) => match usize::try_from(n).ok().and_then(|n| end.checked_add(n)) {
                    Some(k) if k <= s.len() => j = k,
                    _ => return lines,
                },
                None => {
                    i = end;
                    break;
                }
            }
        }
    }
    lines
}

fuzz_target!(|data: &[u8]| {
    let Some((&first, mut rest)) = data.split_first() else {
        return;
    };
    let imap = first & 1 == 0;
    let mut g = Guard::new(if imap {
        GuardDialect::Imap
    } else {
        GuardDialect::Sieve
    });
    let (mut to_server, mut to_client) = (Vec::new(), Vec::new());
    let mut client_pending: Vec<u8> = Vec::new();
    let mut plus_seen = false;
    let mut closed = false;
    // Each chunk: one header octet (direction in the top bit, length in the
    // rest), then that many octets.
    while let Some((&h, r)) = rest.split_first() {
        let n = usize::from(h & 0x7f).min(r.len());
        let (chunk, r) = r.split_at(n);
        rest = r;
        if h & 0x80 == 0 {
            client_pending.extend_from_slice(chunk);
        } else {
            plus_seen |= chunk.contains(&b'+');
            g.on_server(chunk, &mut to_client);
        }
        if let Some(local) = g.take_local() {
            to_client.extend_from_slice(&local);
        }
        while !closed && !client_pending.is_empty() && !g.client_waits() {
            let (used, event) = g.on_client(&client_pending, &mut to_server);
            assert!(used <= client_pending.len());
            client_pending.drain(..used);
            match event {
                GuardEvent::Close(_) => closed = true,
                GuardEvent::Refused(_) => {
                    let local = g.take_local();
                    // Written at once unless a response is being relayed.
                    if let Some(local) = local {
                        to_client.extend_from_slice(&local);
                    }
                }
                GuardEvent::None => {}
            }
            if used == 0 {
                break;
            }
        }
        if closed {
            break;
        }
    }
    let check = |line: &[u8], words: &[&'static [u8]]| {
        if let Some(w) = names(line, imap, words) {
            panic!(
                "relayed {}: {:?}",
                String::from_utf8_lossy(w),
                String::from_utf8_lossy(line)
            );
        }
    };
    if !plus_seen || !imap {
        let mut lines = to_server.split(|&b| b == b'\n');
        // The last piece has no LF: not a command yet.
        lines.next_back();
        let words = if imap { IMAP_BLOCKED } else { SIEVE_IN_DATA };
        for line in lines {
            check(line, words);
        }
    }
    if !imap {
        for line in sieve_command_lines(&to_server) {
            check(line, SIEVE_BLOCKED);
        }
    }
});
