//! The command guard of the IMAP and ManageSieve relay after login
//! (`wire::guard`): client and backend octets interleaved in arbitrary
//! chunks. Until the backend has sent a `+` (IMAP: no literal confirmed),
//! nothing is exempt from the check, so no complete line that starts with
//! `UNAUTHENTICATE` (ManageSieve) or `<tag> UNAUTHENTICATE` (IMAP) may reach
//! the backend, wherever the client put it.
#![no_main]

use libfuzzer_sys::fuzz_target;
use mail_auth_proxy::fuzz_api::*;

/// A complete line (without its LF) that a lenient backend would take for
/// UNAUTHENTICATE: blanks, for IMAP a tag and blanks, then the word, then
/// a blank, CR or the end.
fn names_unauthenticate(line: &[u8], imap: bool) -> bool {
    let skip = |s: &[u8]| -> usize { s.iter().take_while(|b| **b == b' ' || **b == b'\t').count() };
    let mut s = &line[skip(line)..];
    if imap {
        let tag = s.iter().take_while(|b| **b != b' ' && **b != b'\t').count();
        if tag == 0 || tag == s.len() {
            return false;
        }
        s = &s[tag..];
        s = &s[skip(s)..];
    }
    const W: &[u8] = b"UNAUTHENTICATE";
    s.len() >= W.len()
        && s[..W.len()].eq_ignore_ascii_case(W)
        && matches!(s.get(W.len()), None | Some(b' ' | b'\r' | b'\t'))
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
    if !plus_seen || !imap {
        let mut lines = to_server.split(|&b| b == b'\n');
        // The last piece has no LF: not a command yet.
        lines.next_back();
        for line in lines {
            assert!(
                !names_unauthenticate(line, imap),
                "relayed: {:?}",
                String::from_utf8_lossy(line)
            );
        }
    }
});
