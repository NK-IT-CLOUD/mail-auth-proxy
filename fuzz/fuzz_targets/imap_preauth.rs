//! The IMAP pre-auth dialog (tag, command, CAPABILITY/NOOP/ID/LOGOUT, LOGIN
//! astrings, AUTHENTICATE with SASL-IR or continuation, RFC 9051) on an
//! in-memory client, and the LOGIN astring parser on its own.
#![no_main]

use libfuzzer_sys::fuzz_target;
use mail_auth_proxy::fuzz_api::*;
use mail_auth_proxy_fuzz::{block_on, Peer};

/// An astring as a quoted string (RFC 9051 §4.3).
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
    let Some((&flags, input)) = data.split_first() else {
        return;
    };
    let pw = MechSet {
        plain: flags & 1 != 0,
        login: flags & 2 != 0,
    };
    block_on(async {
        let mut peer = Peer::new(input);
        let r = imap_read_client_auth(&mut peer, pw).await;
        peer.assert_output_is_crlf_lines();
        if let Ok(Some(auth)) = &r {
            assert!(peer.at_line_boundary(), "took bytes past the credential");
            assert!(
                !auth.tag.is_empty() && !auth.tag.contains(' '),
                "tag {:?}",
                auth.tag
            );
            match &auth.kind {
                ClientAuthKind::Password { user, pass } => {
                    assert!(!user.is_empty() && !pass.is_empty(), "empty password field")
                }
                ClientAuthKind::OAuth { token, .. } => assert!(!token.is_empty()),
            }
        }
    });

    // The answer to the RFC 7628 error challenge: prompt out, one line in,
    // classified like the line itself.
    let mech = if flags & 4 != 0 {
        "OAUTHBEARER"
    } else {
        "XOAUTH2"
    };
    block_on(async {
        let mut peer = Peer::new(input);
        let r = discovery_complete_line(&mut peer, "+ eyJzdGF0dXMiOiJpbnZhbGlkX3Rva2VuIn0=", mech)
            .await;
        assert_eq!(peer.output, b"+ eyJzdGF0dXMiOiJpbnZhbGlkX3Rva2VuIn0=\r\n");
        let mut again = Peer::new(input);
        match (r, read_line(&mut again, IDLE).await) {
            (Ok(answer), Ok(line)) => {
                assert_eq!(answer, classify(mech, &line));
                assert!(peer.at_line_boundary(), "took bytes past the answer");
            }
            (Err(_), Err(_)) => {}
            (r, l) => panic!("answer {r:?}, line {l:?}"),
        }
    });

    // LOGIN arguments directly, and the quoting roundtrip.
    let text = String::from_utf8_lossy(input);
    let _ = imap_parse_two_astrings(&text);
    let (u, p) = text.split_once('\0').unwrap_or((&text, ""));
    let (qu, qp) = (quote(u), quote(p));
    let (pu, pp) = imap_parse_two_astrings(&format!("{qu} {qp}")).expect("quoted astrings");
    assert_eq!((pu.as_str(), pp.as_str()), (u, p));
});
