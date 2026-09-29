//! SMTP: the client's `AUTH` command with its credential dialog (RFC 4954),
//! and the backend's (multiline) replies (RFC 5321 §4.2).
#![no_main]

use libfuzzer_sys::fuzz_target;
use mail_auth_proxy::fuzz_api::*;
use mail_auth_proxy_fuzz::{block_on, Peer};

/// Most lines of one backend reply.
const MAX_REPLY_LINES: usize = 64;

fuzz_target!(|data: &[u8]| {
    let Some((&mode, input)) = data.split_first() else {
        return;
    };
    block_on(async {
        let mut peer = Peer::new(input);
        if mode & 1 == 0 {
            // The first line is the AUTH command, the rest the dialog.
            let Ok(line) = read_line(&mut peer, IDLE).await else {
                return;
            };
            let r = smtp_read_auth(&line, &mut peer).await;
            peer.assert_output_is_crlf_lines();
            if let Ok((mech, kind)) = &r {
                assert!(peer.at_line_boundary(), "took bytes past the credential");
                assert!(["XOAUTH2", "OAUTHBEARER", "PLAIN", "LOGIN"]
                    .iter()
                    .any(|m| m.eq_ignore_ascii_case(mech)));
                if let ClientAuthKind::Password { user, pass } = kind {
                    assert!(!user.is_empty() && !pass.is_empty());
                }
            } else {
                // Every refusal is answered with a reply code.
                assert!(peer.output.len() >= 5, "no reply: {:?}", peer.output);
            }
        } else {
            // Replies back to back, as the backend dialog reads them.
            while let Ok((code, lines)) = smtp_read_reply(&mut peer).await {
                assert!(code <= 999);
                assert!(!lines.is_empty() && lines.len() <= MAX_REPLY_LINES);
                assert!(peer.at_line_boundary());
            }
        }
    });
});
