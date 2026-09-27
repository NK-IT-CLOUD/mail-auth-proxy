//! The ManageSieve `AUTHENTICATE` command: mechanism and initial response in
//! quoted or literal form.

use crate::wire::line::{read_line, verb_is};
use anyhow::{anyhow, Result};
use std::time::Duration;
use tokio::io::AsyncWriteExt;

/// Parse `AUTHENTICATE "<MECH>" "<IR>"` or `AUTHENTICATE "<MECH>" {n+}\r\n<bytes>`.
///
/// Supported forms:
/// - Quoted:  `AUTHENTICATE "XOAUTH2" "<b64>"`
/// - Literal: `AUTHENTICATE "XOAUTH2" {n+}` followed by exactly n bytes on the next read
///
/// The MECH is unquoted from the first quoted-string token.
/// The IR is unquoted from the second token (quoted or literal).
pub(super) async fn parse_authenticate_line<S>(
    line: &str,
    stream: &mut S,
    idle: Duration,
) -> Result<(String, String)>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    if !verb_is(line, "AUTHENTICATE") {
        // Never echo client text into an error: it is logged, and log
        // parsers match `authresult` lines anywhere in a line.
        return Err(anyhow!("expected AUTHENTICATE"));
    }

    // Everything after "AUTHENTICATE "
    let rest = line.get("AUTHENTICATE".len()..).unwrap_or("").trim();

    // Extract first quoted-string: the mechanism
    let (mech, after_mech) =
        unquote_string(rest).ok_or_else(|| anyhow!("AUTHENTICATE: missing quoted mechanism"))?;

    let after_mech = after_mech.trim();
    if after_mech.is_empty() {
        // No initial response — send an empty SASL challenge and read the IR.
        // RFC 5804 §2.1: a challenge is a bare string on its own line. An "OK"
        // prefix is a *command completion* — sending `OK ""` would tell the
        // client its AUTHENTICATE had already succeeded.
        stream.write_all(b"\"\"\r\n").await?;
        let ir = read_line(stream, idle).await?;
        return Ok((mech, ir));
    }

    // IR is either a quoted-string or a literal {n+}
    let ir = if after_mech.starts_with('"') {
        // Quoted form
        let (s, _) = unquote_string(after_mech)
            .ok_or_else(|| anyhow!("AUTHENTICATE: malformed quoted IR"))?;
        s
    } else if after_mech.starts_with('{') {
        // Literal form: {n+} — the n bytes follow on the NEXT read
        let close = after_mech
            .find('}')
            .ok_or_else(|| anyhow!("AUTHENTICATE: malformed literal"))?;
        let count_str = &after_mech[1..close];
        // Strip trailing '+' (non-synchronising literal)
        let count_str = count_str.trim_end_matches('+');
        let n: usize = count_str
            .parse()
            .map_err(|_| anyhow!("AUTHENTICATE: bad literal count"))?;
        if n > 65536 {
            return Err(anyhow!("AUTHENTICATE: literal too large ({n})"));
        }
        // RFC 5804 §4: server sends continuation "OK ..." for non-synchronising literals,
        // but for synchronising ones it must wait.  We send nothing for non-sync (+).
        // Read exactly n bytes.
        use tokio::io::AsyncReadExt;
        let mut buf = vec![0u8; n];
        stream.read_exact(&mut buf).await?;
        // Consume the CRLF terminating the literal octets so it does NOT leak
        // into the post-auth byte relay (otherwise the backend sees a stray
        // empty line → "Unknown command" and all responses shift by one).
        // EOF-tolerant: a client that closes right after the literal is fine.
        let _ = crate::wire::line::read_line(stream, idle).await;
        String::from_utf8(buf).map_err(|e| anyhow!("literal utf8: {e}"))?
    } else {
        return Err(anyhow!("AUTHENTICATE: unrecognised IR form"));
    };

    Ok((mech, ir))
}

/// Unquote the leading `"..."` from `s`.  Returns (content, remainder_after_closing_quote).
/// Handles `\"` escapes inside the string.
fn unquote_string(s: &str) -> Option<(String, &str)> {
    let s = s.strip_prefix('"')?;
    let mut out = String::new();
    let mut chars = s.char_indices();
    loop {
        let (i, c) = chars.next()?;
        match c {
            '"' => {
                let remainder = &s[i + 1..];
                return Some((out, remainder));
            }
            '\\' => {
                let (_, escaped) = chars.next()?;
                out.push(escaped);
            }
            _ => out.push(c),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IDLE: Duration = Duration::from_secs(30);
    use base64::Engine as _;

    /// Quoted-string form: AUTHENTICATE "XOAUTH2" "<b64>"
    #[tokio::test]
    async fn authenticate_quoted_ir() {
        let raw = "user=alice@example.org\x01auth=Bearer TOKEN\x01\x01";
        let b64 = base64::engine::general_purpose::STANDARD.encode(raw);
        let line = format!("AUTHENTICATE \"XOAUTH2\" \"{b64}\"");
        let (mut client, _server) = tokio::io::duplex(4096);
        let (mech, ir) = parse_authenticate_line(&line, &mut client, IDLE)
            .await
            .unwrap();
        assert_eq!(mech, "XOAUTH2");
        assert_eq!(ir, b64);
    }

    /// OAUTHBEARER mechanism accepted in quoted form.
    #[tokio::test]
    async fn authenticate_oauthbearer_quoted() {
        let raw = "n,a=bob@example.org,\x01host=mail\x01port=4190\x01auth=Bearer TK2\x01\x01";
        let b64 = base64::engine::general_purpose::STANDARD.encode(raw);
        let line = format!("AUTHENTICATE \"OAUTHBEARER\" \"{b64}\"");
        let (mut client, _server) = tokio::io::duplex(4096);
        let (mech, ir) = parse_authenticate_line(&line, &mut client, IDLE)
            .await
            .unwrap();
        assert_eq!(mech, "OAUTHBEARER");
        assert_eq!(ir, b64);
    }

    /// Literal form {n+}: IR bytes follow immediately after the command line.
    #[tokio::test]
    async fn authenticate_literal_ir() {
        use tokio::io::AsyncWriteExt;
        let raw = "user=carol@example.org\x01auth=Bearer LIT_TOKEN\x01\x01";
        let b64 = base64::engine::general_purpose::STANDARD.encode(raw);
        let n = b64.len();

        let (mut client_side, mut server_side) = tokio::io::duplex(4096);

        let b64_clone = b64.clone();
        let server_task = tokio::spawn(async move {
            let cmd_line = format!("AUTHENTICATE \"XOAUTH2\" {{{n}+}}");
            parse_authenticate_line(&cmd_line, &mut server_side, IDLE).await
        });

        // Send the literal bytes (no CRLF terminator needed — read_exact reads n bytes)
        client_side.write_all(b64_clone.as_bytes()).await.unwrap();
        // Shut write side so read_exact in server doesn't block forever on duplex
        drop(client_side);

        let (mech, ir) = server_task.await.unwrap().unwrap();
        assert_eq!(mech, "XOAUTH2");
        assert_eq!(ir, b64);
    }

    /// The CRLF terminating a literal must be consumed so it does not leak into
    /// the relay: the backend would take it for an empty command and every
    /// later response would be off by one.
    #[tokio::test]
    async fn authenticate_literal_consumes_trailing_crlf() {
        use tokio::io::AsyncWriteExt;
        let raw = "user=carol@example.org\x01auth=Bearer LIT\x01\x01";
        let b64 = base64::engine::general_purpose::STANDARD.encode(raw);
        let n = b64.len();
        let (mut client_side, mut server_side) = tokio::io::duplex(4096);
        // Full literal form WITH the trailing CRLF, then a following command.
        client_side
            .write_all(format!("{b64}\r\nLISTSCRIPTS\r\n").as_bytes())
            .await
            .unwrap();
        let cmd_line = format!("AUTHENTICATE \"XOAUTH2\" {{{n}+}}");
        let (mech, ir) = parse_authenticate_line(&cmd_line, &mut server_side, IDLE)
            .await
            .unwrap();
        assert_eq!(mech, "XOAUTH2");
        assert_eq!(ir, b64);
        // The trailing CRLF after the literal must have been consumed → the next
        // line read is the real command, not an empty line.
        let next = crate::wire::line::read_line(&mut server_side, IDLE)
            .await
            .unwrap();
        assert_eq!(next, "LISTSCRIPTS");
    }

    /// Oversized literal {99999999+} is rejected before allocation (pre-auth DoS guard).
    #[tokio::test]
    async fn authenticate_literal_too_large_rejected() {
        let (mut server_side, _client_side) = tokio::io::duplex(4096);
        let line = "AUTHENTICATE \"XOAUTH2\" {99999999+}";
        let result = parse_authenticate_line(line, &mut server_side, IDLE).await;
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("too large"),
            "expected 'too large' in error: {msg}"
        );
    }

    /// unquote_string handles basic and escaped characters.
    #[test]
    fn unquote_string_basic() {
        let (s, rest) = unquote_string("\"XOAUTH2\" rest").unwrap();
        assert_eq!(s, "XOAUTH2");
        assert_eq!(rest, " rest");
    }

    #[test]
    fn unquote_string_escaped() {
        let (s, _) = unquote_string("\"foo\\\"bar\"").unwrap();
        assert_eq!(s, "foo\"bar");
    }

    #[test]
    fn unquote_string_none_if_no_quote() {
        assert!(unquote_string("XOAUTH2").is_none());
    }

    /// A quoted mechanism may contain spaces and quotes. It must not reach the
    /// (logged) error text in a form a log parser could take for an authresult line.
    #[tokio::test]
    async fn error_text_does_not_echo_client_input() {
        let evil = r#"authresult result="fail" proto="imap" scope="external" mech=x user=y peer=192.0.2.9 reason="bad_token""#;
        for line in [
            format!("AUTHENTICATE \"PLAIN\" junk {evil}"),
            format!("NOTAUTH {evil}"),
        ] {
            let (mut server_side, _client) = tokio::io::duplex(4096);
            let err = parse_authenticate_line(&line, &mut server_side, IDLE)
                .await
                .unwrap_err()
                .to_string();
            assert!(!err.contains("authresult"), "{err}");
        }
        assert_eq!(
            crate::obs::authlog::sanitize(r#"x" peer=1.2.3.4"#),
            "x??peer?1.2.3.4"
        );
    }
}
