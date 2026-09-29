//! The ManageSieve `AUTHENTICATE` command: mechanism and initial response in
//! quoted or literal form.

use crate::wire::line::{read_client_line, verb_is, LineError};
use anyhow::{anyhow, Result};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use zeroize::Zeroizing;

/// Parse `AUTHENTICATE "<MECH>" "<IR>"` or `AUTHENTICATE "<MECH>" {n+}\r\n<bytes>`.
///
/// Supported forms:
/// - Quoted:  `AUTHENTICATE "XOAUTH2" "<b64>"`
/// - Literal: `AUTHENTICATE "XOAUTH2" {n+}` followed by exactly n bytes on the next read
///
/// The MECH is unquoted from the first quoted-string token.
/// The IR is unquoted from the second token (quoted or literal); it carries
/// the credential and is zeroized on drop. Without one it is `None`: the
/// caller decides whether to ask for it (`read_continuation`).
pub(crate) async fn parse_authenticate_line<S>(
    line: &str,
    stream: &mut S,
    idle: Duration,
) -> Result<(String, Option<Zeroizing<String>>)>
where
    S: tokio::io::AsyncRead + Unpin,
{
    if !verb_is(line, "AUTHENTICATE") {
        // Never echo client text into an error: it is logged, and log
        // parsers match `authresult` lines anywhere in a line.
        return Err(anyhow!("expected AUTHENTICATE"));
    }

    let rest = line.get("AUTHENTICATE".len()..).unwrap_or("").trim();
    let (mech, after_mech) =
        unquote_string(rest).ok_or_else(|| anyhow!("AUTHENTICATE: missing quoted mechanism"))?;

    let after_mech = after_mech.trim();
    if after_mech.is_empty() {
        return Ok((mech, None));
    }

    let ir = if after_mech.starts_with('"') {
        let (s, rest) = unquote_string(after_mech)
            .ok_or_else(|| anyhow!("AUTHENTICATE: malformed quoted IR"))?;
        let s = Zeroizing::new(s);
        if !rest.trim().is_empty() {
            return Err(anyhow!("AUTHENTICATE: text after the initial response"));
        }
        s
    } else if after_mech.starts_with('{') {
        read_literal(stream, after_mech, idle).await?
    } else {
        return Err(anyhow!("AUTHENTICATE: unrecognised IR form"));
    };

    Ok((mech, Some(ir)))
}

/// Ask for the response of an `AUTHENTICATE` without initial response: an
/// empty SASL challenge, then the client's string (`read_sasl_string`). RFC
/// 5804 §2.1: a challenge is a bare string on its own line. An "OK" prefix
/// is a *command completion*: `OK ""` would tell the client its AUTHENTICATE
/// had already succeeded. A response `"*"` cancels the exchange, which the
/// server must answer with NO: an error here.
pub(crate) async fn read_continuation<S>(
    stream: &mut S,
    idle: Duration,
) -> Result<Zeroizing<String>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    stream.write_all(b"\"\"\r\n").await?;
    let response = read_sasl_string(stream, idle).await?;
    if response.as_str() == "*" {
        return Err(anyhow!("client cancelled authentication"));
    }
    Ok(response)
}

/// The optional string argument of a command, `arg` being the rest of the
/// line after the command name: quoted or a literal `{n+}` (RFC 5804 §4),
/// `None` if there is none. Anything after the string is refused.
pub(crate) async fn read_string_arg<S>(
    stream: &mut S,
    arg: &str,
    idle: Duration,
) -> Result<Option<Zeroizing<String>>>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let arg = arg.trim();
    if arg.is_empty() {
        Ok(None)
    } else if arg.starts_with('"') {
        match unquote_string(arg) {
            Some((s, rest)) if rest.trim().is_empty() => Ok(Some(Zeroizing::new(s))),
            _ => Err(anyhow!("malformed quoted string")),
        }
    } else if arg.starts_with('{') {
        Ok(Some(read_literal(stream, arg, idle).await?))
    } else {
        Err(anyhow!("argument is not a string"))
    }
}

/// `s` as a ManageSieve string for a response: quoted (with `"` and `\`
/// escaped) when it fits the 1024 octets of a quoted string and holds no
/// CR, LF or NUL, a literal `{n}` otherwise (RFC 5804 §4).
pub(crate) fn sieve_string(s: &str) -> String {
    if s.len() <= 1024 && !s.contains(['\r', '\n', '\0']) {
        let mut q = String::with_capacity(s.len() + 2);
        q.push('"');
        for c in s.chars() {
            if c == '"' || c == '\\' {
                q.push('\\');
            }
            q.push(c);
        }
        q.push('"');
        q
    } else {
        format!("{{{}}}\r\n{s}", s.len())
    }
}

/// Largest literal accepted from a client.
const MAX_LITERAL: usize = 65536;

/// Read the octets of the literal whose header `{n+}` is all of `header`
/// (the rest of the line); they follow on the next read. They can carry the
/// credential and are zeroized on drop.
///
/// RFC 5804 §4 has clients send only `literal-c2s = "{" number "+}" CRLF
/// *OCTET`: the octets follow at once. The synchronising `{n}` would wait for
/// a continuation ManageSieve does not have, so it is refused like any other
/// malformed header (`{5++}`, text after `}`).
async fn read_literal<S>(stream: &mut S, header: &str, idle: Duration) -> Result<Zeroizing<String>>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let count = header
        .strip_prefix('{')
        .and_then(|h| h.strip_suffix("+}"))
        .filter(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()))
        .ok_or_else(|| anyhow!("AUTHENTICATE: malformed literal"))?;
    let n: usize = count
        .parse()
        .map_err(|_| anyhow!("AUTHENTICATE: literal too large"))?;
    if n > MAX_LITERAL {
        return Err(anyhow!("AUTHENTICATE: literal too large ({n})"));
    }
    use tokio::io::AsyncReadExt;
    let mut buf = Zeroizing::new(vec![0u8; n]);
    stream.read_exact(&mut buf).await?;
    // The octets end the command or response: the CRLF must follow, or it
    // would reach the post-auth relay as an empty command and shift every
    // response by one. Anything else on that line, an overlong one included,
    // is refused, so none of it is relayed. A client that closes right after
    // the octets is fine.
    match read_client_line(stream, idle).await {
        Ok(rest) if rest.is_empty() => {}
        Err(LineError::Eof) => {}
        Ok(_) => return Err(anyhow!("AUTHENTICATE: text after the literal")),
        Err(e) => return Err(anyhow::Error::new(e).context("after the literal")),
    }
    let text = std::str::from_utf8(&buf).map_err(|e| anyhow!("literal utf8: {e}"))?;
    Ok(Zeroizing::new(text.to_owned()))
}

/// Read a SASL client response: one string on its own line, quoted or a
/// literal (RFC 5804 section 2.1). A bare line is taken as it is. The
/// response can carry a credential and is zeroized on drop.
pub(crate) async fn read_sasl_string<S>(stream: &mut S, idle: Duration) -> Result<Zeroizing<String>>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let line = read_client_line(stream, idle).await?;
    let line = line.trim();
    if line.starts_with('"') {
        match unquote_string(line) {
            Some((s, rest)) if rest.trim().is_empty() => Ok(Zeroizing::new(s)),
            Some((s, _)) => {
                drop(Zeroizing::new(s));
                Err(anyhow!("malformed quoted string"))
            }
            None => Err(anyhow!("malformed quoted string")),
        }
    } else if line.starts_with('{') {
        read_literal(stream, line, idle).await
    } else {
        Ok(Zeroizing::new(line.to_owned()))
    }
}

/// Unquote the leading `"..."` from `s`.  Returns (content, remainder_after_closing_quote).
/// Handles `\"` escapes inside the string. The content can be the credential:
/// `out` is sized for all of `s` so that it never reallocates and leaves a
/// partial copy behind, and zeroized if the string is unterminated (the
/// caller zeroizes the result).
pub(crate) fn unquote_string(s: &str) -> Option<(String, &str)> {
    let s = s.strip_prefix('"')?;
    let mut out = Zeroizing::new(String::with_capacity(s.len()));
    let mut chars = s.char_indices();
    loop {
        let (i, c) = chars.next()?;
        match c {
            '"' => {
                let remainder = &s[i + 1..];
                return Some((std::mem::take(&mut *out), remainder));
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
        assert_eq!(ir.as_deref().map(String::as_str), Some(b64.as_str()));
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
        assert_eq!(ir.as_deref().map(String::as_str), Some(b64.as_str()));
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
        assert_eq!(ir.as_deref().map(String::as_str), Some(b64.as_str()));
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
        assert_eq!(ir.as_deref().map(String::as_str), Some(b64.as_str()));
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

    /// A SASL response in each string form; a malformed quoted string fails.
    #[tokio::test]
    async fn sasl_response_string_forms() {
        use std::io::Cursor;
        for (wire, want) in [
            (&b"\"AQ==\"\r\n"[..], Some("AQ==")),
            (b"\"\"\r\n", Some("")),
            (b"\"*\"\r\n", Some("*")),
            (b"{4+}\r\nAQ==\r\n", Some("AQ==")),
            (b"{0+}\r\n\r\n", Some("")),
            (b"AQ==\r\n", Some("AQ==")),
            (b"\"AQ==\r\n", None),
            (b"\"AQ==\" x\r\n", None),
            (b"{99999999+}\r\n", None),
            (b"{99999999999999999999999+}\r\n", None),
            // RFC 5804 §4: only `{n+}` from a client, nothing after it, and
            // only the CRLF after the octets.
            (b"{4}\r\nAQ==\r\n", None),
            (b"{4++}\r\nAQ==\r\n", None),
            (b"{+}\r\n\r\n", None),
            (b"{-1+}\r\n\r\n", None),
            (b"{4+} x\r\nAQ==\r\n", None),
            (b"{4+}x\r\nAQ==\r\n", None),
            (b"{4+}\r\nAQ==x\r\n", None),
            (b"{4+}\r\nAQ==", Some("AQ==")),
        ] {
            let got = read_sasl_string(&mut Cursor::new(wire.to_vec()), IDLE).await;
            assert_eq!(
                got.ok().as_deref().map(String::as_str),
                want,
                "{:?}",
                String::from_utf8_lossy(wire)
            );
        }
    }

    /// The line after a literal's octets is refused when it is overlong, not
    /// dropped: none of it may reach the relay.
    #[tokio::test]
    async fn overlong_line_after_literal_is_refused() {
        use std::io::Cursor;
        let mut wire = b"{4+}\r\nAQ==".to_vec();
        wire.extend(std::iter::repeat_n(b'x', crate::wire::line::MAX_LINE + 1));
        wire.extend_from_slice(b"\r\nLISTSCRIPTS\r\n");
        assert!(read_sasl_string(&mut Cursor::new(wire), IDLE)
            .await
            .is_err());
    }

    /// The response after the empty challenge: quoted, literal or bare, and
    /// `"*"` (or `*`) cancels.
    #[tokio::test]
    async fn continuation_reads_a_string_and_cancel() {
        for (wire, want) in [
            (&b"\"AQ==\"\r\n"[..], Some("AQ==")),
            (b"{4+}\r\nAQ==\r\n", Some("AQ==")),
            (b"AQ==\r\n", Some("AQ==")),
            (b"\"*\"\r\n", None),
            (b"*\r\n", None),
        ] {
            let (mut client, mut server) = tokio::io::duplex(4096);
            client.write_all(wire).await.unwrap();
            let got = read_continuation(&mut server, IDLE).await;
            assert_eq!(
                got.ok().as_deref().map(String::as_str),
                want,
                "{:?}",
                String::from_utf8_lossy(wire)
            );
            let mut challenge = [0u8; 4];
            tokio::io::AsyncReadExt::read_exact(&mut client, &mut challenge)
                .await
                .unwrap();
            assert_eq!(&challenge, b"\"\"\r\n");
        }
    }

    /// Text after a quoted initial response is refused.
    #[tokio::test]
    async fn text_after_quoted_ir_is_refused() {
        let (mut server, _client) = tokio::io::duplex(4096);
        assert!(
            parse_authenticate_line("AUTHENTICATE \"PLAIN\" \"AQ==\" x", &mut server, IDLE)
                .await
                .is_err()
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
