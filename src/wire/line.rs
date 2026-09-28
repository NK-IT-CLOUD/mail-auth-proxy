//! The protocol line reader and the SASL response readers built on it.

use anyhow::{anyhow, Result};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};
use zeroize::{Zeroize as _, Zeroizing};

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
    /// The line is not UTF-8. Only the position: the bytes may be a credential.
    Utf8(std::str::Utf8Error),
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
/// For backend replies; a client line can carry a credential and is read
/// with `read_client_line`.
pub async fn read_line<S: AsyncRead + Unpin>(
    s: &mut S,
    idle: Duration,
) -> Result<String, LineError> {
    let mut line = read_client_line(s, idle).await?;
    Ok(std::mem::take(&mut *line))
}

/// `read_line` for a client line: a command line (IMAP `LOGIN`, an inline
/// SASL response) or a SASL response can carry a password or token, so the
/// line and every buffer it outgrows are overwritten when dropped.
pub async fn read_client_line<S: AsyncRead + Unpin>(
    s: &mut S,
    idle: Duration,
) -> Result<Zeroizing<String>, LineError> {
    let mut line = Zeroizing::new(Vec::new());
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
            push_zeroizing(&mut line, b[0]);
        }
        // Count every byte consumed, not just the retained ones: a peer sending
        // an endless stream of bare CR would otherwise never grow `line` and
        // never trip the limit.
        consumed += 1;
        if consumed > MAX_LINE {
            return Err(LineError::TooLong);
        }
    }
    // The same allocation moves into the String; on an error the bytes go
    // back into a zeroizing buffer instead of into the error.
    match String::from_utf8(std::mem::take(&mut *line)) {
        Ok(text) => Ok(Zeroizing::new(text)),
        Err(e) => {
            let why = e.utf8_error();
            drop(Zeroizing::new(e.into_bytes()));
            Err(LineError::Utf8(why))
        }
    }
}

/// `Vec::push` that grows by copying into a new buffer and overwriting the
/// old one: a plain push reallocates and frees the old buffer, and with it
/// the line read so far, without clearing it.
fn push_zeroizing(buf: &mut Vec<u8>, byte: u8) {
    if buf.len() == buf.capacity() {
        let mut grown = Vec::with_capacity((buf.capacity() * 2).max(64));
        grown.extend_from_slice(buf);
        buf.zeroize();
        *buf = grown;
    }
    buf.push(byte);
}

/// Read one SASL client response line. A lone `*` is the client cancelling
/// the exchange (RFC 3501 §6.2.2, RFC 4954 §4) and ends it with an error.
pub async fn read_sasl_response<S: AsyncRead + Unpin>(
    s: &mut S,
    idle: Duration,
) -> Result<Zeroizing<String>> {
    let line = read_client_line(s, idle).await?;
    if line.trim() == "*" {
        return Err(anyhow!("client cancelled authentication"));
    }
    Ok(line)
}

/// One step of the SASL LOGIN dialog: send `prompt` (the protocol's
/// continuation prefix plus the base64 challenge, e.g. `+ VXNlcm5hbWU6` or
/// `334 VXNlcm5hbWU6`), then read and base64-decode the reply.
pub async fn sasl_login_step<S>(
    stream: &mut S,
    prompt: &str,
    idle: Duration,
) -> Result<Zeroizing<String>>
where
    S: AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt as _;
    stream.write_all(format!("{prompt}\r\n").as_bytes()).await?;
    let line = read_sasl_response(stream, idle).await?;
    decode_login_field(&line)
}

/// Decode one base64 field of the SASL LOGIN dialog (the username or the
/// password).
pub fn decode_login_field(b64: &str) -> Result<Zeroizing<String>> {
    let raw = crate::auth::sasl::decode_secret_b64(b64).map_err(|e| anyhow!("LOGIN {e}"))?;
    let text = std::str::from_utf8(&raw).map_err(|e| anyhow!("LOGIN utf8: {e}"))?;
    Ok(Zeroizing::new(text.to_owned()))
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

    /// The client line and the SASL values read from the wire are zeroized
    /// on drop (compile-time check on the types).
    #[tokio::test]
    async fn client_lines_are_zeroize_on_drop() {
        fn zeroized<T: zeroize::ZeroizeOnDrop>(_: &T) {}
        let mut c = Cursor::new(b"A1 LOGIN u pw\r\ncHc=\r\n".to_vec());
        zeroized(&read_client_line(&mut c, IDLE).await.unwrap());
        zeroized(&read_sasl_response(&mut c, IDLE).await.unwrap());
        zeroized(&decode_login_field("cHc=").unwrap());
        let (mut client, mut server) = tokio::io::duplex(64);
        tokio::io::AsyncWriteExt::write_all(&mut client, b"cHc=\r\n")
            .await
            .unwrap();
        let pass = sasl_login_step(&mut server, "+", IDLE).await.unwrap();
        zeroized(&pass);
        assert_eq!(*pass, "pw");
    }

    /// A long line crosses several buffer growths and comes back intact; each
    /// growth moves into a fresh buffer instead of reallocating in place.
    #[tokio::test]
    async fn long_line_survives_zeroizing_growth() {
        let body: Vec<u8> = (0..5000u32).map(|i| b'a' + (i % 26) as u8).collect();
        let mut input = body.clone();
        input.extend_from_slice(b"\r\nnext\r\n");
        let mut c = Cursor::new(input);
        assert_eq!(
            read_client_line(&mut c, IDLE).await.unwrap().as_bytes(),
            body
        );
        assert_eq!(read_line(&mut c, IDLE).await.unwrap(), "next");

        let mut buf = Vec::new();
        let mut caps = Vec::new();
        for i in 0..300u32 {
            push_zeroizing(&mut buf, i as u8);
            if caps.last() != Some(&buf.capacity()) {
                caps.push(buf.capacity());
            }
        }
        assert_eq!(caps, [64, 128, 256, 512]);
        assert!(buf.iter().enumerate().all(|(i, &b)| b == i as u8));
    }

    /// A line that is not UTF-8 is an error that carries only the position,
    /// not the bytes (which may be a credential).
    #[tokio::test]
    async fn non_utf8_error_carries_no_bytes() {
        let mut c = Cursor::new(b"A1 LOGIN u p\xffSECRET\r\n".to_vec());
        let e = read_client_line(&mut c, IDLE).await.unwrap_err();
        assert!(matches!(e, LineError::Utf8(_)));
        let text = format!("{e} {e:?}");
        assert!(!text.contains("SECRET") && !text.contains("255"), "{text}");
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
