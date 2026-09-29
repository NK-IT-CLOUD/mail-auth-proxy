//! ManageSieve `AUTHENTICATE` (RFC 5804 §2.1): quoted mechanism, quoted
//! initial response or literal `{n+}`/`{n}` read from the client, and the
//! quoted-string reader on its own.
#![no_main]

use libfuzzer_sys::fuzz_target;
use mail_auth_proxy::fuzz_api::*;
use mail_auth_proxy_fuzz::{block_on, Peer};

/// Largest literal the parser accepts.
const MAX_LITERAL: usize = 65536;

fn quote(s: &str) -> String {
    let mut q = String::from("\"");
    for c in s.chars() {
        if c == '"' || c == '\\' {
            q.push('\\');
        }
        q.push(c);
    }
    q.push('"');
    q
}

fuzz_target!(|data: &[u8]| {
    // Below MAX_LINE, so the line after a literal is always read to its end
    // (the reader drops an overlong one after MAX_LINE bytes).
    if data.len() >= MAX_LINE {
        return;
    }
    block_on(async {
        // The first line is the command, the rest what the client sends next.
        let mut peer = Peer::new(data);
        let Ok(line) = read_line(&mut peer, IDLE).await else {
            return;
        };
        let r = sieve_parse_authenticate_line(&line, &mut peer).await;
        peer.assert_output_is_crlf_lines();
        if let Ok((_mech, ir)) = &r {
            assert!(verb_is(&line, "AUTHENTICATE"));
            assert!(
                ir.len() <= MAX_LITERAL.max(line.len()),
                "IR of {} bytes",
                ir.len()
            );
            assert!(peer.at_line_boundary(), "took bytes past the credential");
        }
    });

    // A SASL response string (the answer to the RFC 7628 error challenge):
    // quoted, literal or bare, never past its line.
    block_on(async {
        let mut peer = Peer::new(data);
        if let Ok(s) = sieve_read_sasl_string(&mut peer).await {
            assert!(s.len() <= MAX_LITERAL.max(MAX_LINE), "{} bytes", s.len());
            assert!(peer.at_line_boundary(), "took bytes past the response");
        }
    });

    let text = String::from_utf8_lossy(data);
    if let Some((s, rest)) = sieve_unquote_string(&text) {
        assert!(s.len() < text.len() && rest.len() < text.len());
    }
    let q = quote(&text);
    assert_eq!(
        sieve_unquote_string(&format!("{q} tail")).expect("quoted string"),
        (text.to_string(), " tail")
    );
});
