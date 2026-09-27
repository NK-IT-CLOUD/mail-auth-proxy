//! The protocol line reader and the SASL response readers built on it.

use anyhow::{anyhow, Result};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};

/// Longest accepted protocol line.
const MAX_LINE: usize = 16384;

/// True if the command verb of `line` (its first space-separated word) is
/// `verb`, ignoring case. `STARTTLSX` is not `STARTTLS`.
pub fn verb_is(line: &str, verb: &str) -> bool {
    line.split(' ')
        .next()
        .is_some_and(|v| v.eq_ignore_ascii_case(verb))
}

/// Why `read_line` returned no line. The texts end up in the journal.
#[derive(Debug)]
pub enum LineError {
    /// The peer closed at a line boundary.
    Eof,
    /// The peer closed in the middle of a line.
    EofMidLine,
    /// The line exceeds `MAX_LINE` bytes.
    TooLong,
    /// No byte arrived within the idle timeout (seconds).
    Timeout(u64),
    /// The line is not UTF-8.
    Utf8(std::string::FromUtf8Error),
    /// The read failed.
    Io(std::io::Error),
}

impl LineError {
    /// True if the peer closed the connection at a line boundary (with or
    /// without a TLS close_notify), as opposed to a protocol or I/O failure.
    pub fn is_eof(&self) -> bool {
        match self {
            LineError::Eof => true,
            LineError::Io(e) => e.kind() == std::io::ErrorKind::UnexpectedEof,
            _ => false,
        }
    }
}

impl std::fmt::Display for LineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LineError::Eof => f.write_str("eof"),
            LineError::EofMidLine => f.write_str("eof in the middle of a line"),
            LineError::TooLong => f.write_str("line too long"),
            LineError::Timeout(secs) => write!(f, "read timed out after {secs}s"),
            LineError::Utf8(e) => e.fmt(f),
            LineError::Io(e) => e.fmt(f),
        }
    }
}

/// Transparent for the wrapped errors: an error chain shows the cause once.
impl std::error::Error for LineError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            LineError::Utf8(e) => e.source(),
            LineError::Io(e) => e.source(),
            _ => None,
        }
    }
}

/// Read one line, without its CR/LF, waiting at most `idle` for each byte.
pub async fn read_line<S: AsyncRead + Unpin>(
    s: &mut S,
    idle: Duration,
) -> Result<String, LineError> {
    let mut line = Vec::new();
    let mut consumed = 0usize;
    let mut b = [0u8; 1];
    loop {
        // A close with nothing read is `Eof`; a close in the middle of a line
        // is a different error.
        match tokio::time::timeout(idle, s.read(&mut b)).await {
            Ok(Ok(0)) if consumed == 0 => return Err(LineError::Eof),
            Ok(Ok(0)) => return Err(LineError::EofMidLine),
            Ok(Ok(_)) => {}
            Ok(Err(e)) if consumed > 0 && e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Err(LineError::EofMidLine);
            }
            Ok(Err(e)) => return Err(LineError::Io(e)),
            Err(_) => return Err(LineError::Timeout(idle.as_secs())),
        }
        if b[0] == b'\n' {
            break;
        }
        if b[0] != b'\r' {
            line.push(b[0]);
        }
        // Count every byte consumed, not just the retained ones: a peer sending
        // an endless stream of bare CR would otherwise never grow `line` and
        // never trip the limit.
        consumed += 1;
        if consumed > MAX_LINE {
            return Err(LineError::TooLong);
        }
    }
    String::from_utf8(line).map_err(LineError::Utf8)
}

/// Read one SASL client response line. A lone `*` is the client cancelling
/// the exchange (RFC 3501 §6.2.2, RFC 4954 §4) and ends it with an error.
pub async fn read_sasl_response<S: AsyncRead + Unpin>(s: &mut S, idle: Duration) -> Result<String> {
    let line = read_line(s, idle).await?;
    if line.trim() == "*" {
        return Err(anyhow!("client cancelled authentication"));
    }
    Ok(line)
}

/// One step of the SASL LOGIN dialog: send `prompt` (the protocol's
/// continuation prefix plus the base64 challenge, e.g. `+ VXNlcm5hbWU6` or
/// `334 VXNlcm5hbWU6`), then read and base64-decode the reply.
pub async fn sasl_login_step<S>(stream: &mut S, prompt: &str, idle: Duration) -> Result<String>
where
    S: AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt as _;
    stream.write_all(format!("{prompt}\r\n").as_bytes()).await?;
    let line = read_sasl_response(stream, idle).await?;
    decode_login_field(&line)
}

/// Decode one base64 field of the SASL LOGIN dialog.
pub fn decode_login_field(b64: &str) -> Result<String> {
    use base64::Engine as _;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|e| anyhow!("LOGIN base64: {e}"))?;
    String::from_utf8(raw).map_err(|e| anyhow!("LOGIN utf8: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    const IDLE: Duration = Duration::from_secs(30);

    /// A flood of bare CR retains no bytes, so a length check on the retained
    /// buffer alone would never fire. The limit must count consumed bytes.
    #[tokio::test]
    async fn cr_flood_hits_the_line_limit() {
        let mut c = Cursor::new(vec![b'\r'; MAX_LINE + 10]);
        let err = read_line(&mut c, IDLE).await.unwrap_err().to_string();
        assert!(err.contains("line too long"), "got: {err}");
    }

    #[tokio::test]
    async fn overlong_line_is_rejected() {
        let mut c = Cursor::new(vec![b'A'; MAX_LINE + 10]);
        assert!(read_line(&mut c, IDLE).await.is_err());
    }

    #[test]
    fn verb_is_matches_whole_word_only() {
        assert!(verb_is("starttls", "STARTTLS"));
        assert!(verb_is("EHLO client.example", "EHLO"));
        assert!(!verb_is("STARTTLSX", "STARTTLS"));
        assert!(!verb_is("EHLOfoo", "EHLO"));
        assert!(!verb_is("", "QUIT"));
    }

    /// Only a close with nothing sent counts as a clean EOF (health check);
    /// a close in the middle of a line is a protocol error.
    #[tokio::test]
    async fn eof_mid_line_is_not_a_clean_eof() {
        let e = read_line(&mut Cursor::new(Vec::new()), IDLE)
            .await
            .unwrap_err();
        assert!(e.is_eof());
        let e = read_line(&mut Cursor::new(b"A1 NOO".to_vec()), IDLE)
            .await
            .unwrap_err();
        assert!(!e.is_eof(), "{e}");
    }
}
