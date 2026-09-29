//! SMTP: the client's `AUTH` command with its credential dialog (RFC 4954),
//! with further attempts after a retryable failure, and the backend's
//! (multiline) replies (RFC 5321 §4.2) with the EHLO extensions taken from
//! them.
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
            // The first line is the AUTH command, the rest the dialog. With
            // mode bit 2, a failure that may be retried is followed by the
            // next AUTH line, up to three attempts, as the listener does.
            let mut attempts = if mode & 2 != 0 { 3 } else { 1 };
            loop {
                let Ok(line) = read_line(&mut peer, IDLE).await else {
                    return;
                };
                let answered = peer.output.len();
                let r = smtp_read_auth(&line, &mut peer).await;
                peer.assert_output_is_crlf_lines();
                attempts -= 1;
                match &r {
                    Ok((mech, kind)) => {
                        assert!(peer.at_line_boundary(), "took bytes past the credential");
                        assert!(["XOAUTH2", "OAUTHBEARER", "PLAIN", "LOGIN"]
                            .iter()
                            .any(|m| m.eq_ignore_ascii_case(mech)));
                        if let ClientAuthKind::Password { user, pass } = kind {
                            assert!(!user.is_empty() && !pass.is_empty());
                        }
                        return;
                    }
                    Err(e) => {
                        // Every refusal is answered with a reply code.
                        assert!(
                            peer.output.len() >= answered + 5,
                            "no reply: {:?}",
                            peer.output
                        );
                        // A retryable failure read its command to the end.
                        if is_retryable(e) {
                            assert!(peer.at_line_boundary(), "retry mid-line");
                        }
                        if attempts == 0 || !is_retryable(e) {
                            return;
                        }
                    }
                }
            }
        } else {
            // Replies back to back, as the backend dialog reads them.
            while let Ok((code, lines)) = smtp_read_reply(&mut peer).await {
                assert!(code <= 999);
                assert!(!lines.is_empty() && lines.len() <= MAX_REPLY_LINES);
                assert!(peer.at_line_boundary());
                // As an EHLO reply: what reaches clients is well-formed,
                // relayed, each keyword once, and a subset of the backend's.
                let ext = &lines[1..];
                let only = (mode & 2 != 0).then(|| lines.clone());
                let shown = smtp_ehlo_advertised(ext, only.as_deref());
                let mut seen: Vec<String> = Vec::new();
                for l in &shown {
                    let k = smtp_ehlo_keyword(l)
                        .expect("an EHLO line")
                        .to_ascii_uppercase();
                    assert!(SMTP_EHLO_RELAYED.contains(&k.as_str()), "{l:?}");
                    assert!(!seen.contains(&k), "{k} twice");
                    assert!(ext.contains(l), "{l:?} not from the backend");
                    seen.push(k);
                }
            }
        }
    });
});
