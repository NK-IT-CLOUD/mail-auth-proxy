//! Shared pieces of the fuzz targets: an in-memory client stream and a
//! runtime to drive the async parsers on it.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A peer that sends `input` and then closes; everything written to it is
/// kept in `output`. Reads never wait, so no timeout ever fires.
pub struct Peer<'a> {
    input: &'a [u8],
    pos: usize,
    pub output: Vec<u8>,
}

impl<'a> Peer<'a> {
    pub fn new(input: &'a [u8]) -> Self {
        Peer {
            input,
            pos: 0,
            output: Vec::new(),
        }
    }

    /// Bytes read so far.
    pub fn consumed(&self) -> usize {
        self.pos
    }

    /// True if the parser stopped right after a line feed, at the start of
    /// the input, or at its end: it never took bytes of a line it did not
    /// finish. After STARTTLS or AUTHENTICATE, bytes read beyond the line
    /// would belong to the next protocol phase (CVE-2011-0411).
    pub fn at_line_boundary(&self) -> bool {
        self.pos == 0 || self.pos == self.input.len() || self.input[self.pos - 1] == b'\n'
    }

    /// Everything written must be CRLF-terminated lines without a bare CR
    /// or LF: client bytes echoed into a reply (a tag) must not split it.
    pub fn assert_output_is_crlf_lines(&self) {
        let out = &self.output;
        assert!(
            out.is_empty() || out.ends_with(b"\r\n"),
            "unterminated reply: {out:?}"
        );
        for (i, &b) in out.iter().enumerate() {
            match b {
                b'\r' => assert_eq!(out.get(i + 1), Some(&b'\n'), "bare CR in reply: {out:?}"),
                b'\n' => assert!(i > 0 && out[i - 1] == b'\r', "bare LF in reply: {out:?}"),
                _ => {}
            }
        }
    }
}

impl AsyncRead for Peer<'_> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let rest = &self.input[self.pos..];
        let n = rest.len().min(buf.remaining());
        buf.put_slice(&rest[..n]);
        self.pos += n;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Peer<'_> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.output.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

thread_local! {
    static RT: tokio::runtime::Runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("tokio runtime");
}

/// Run `fut` to completion on a single-threaded runtime.
pub fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    RT.with(|rt| rt.block_on(fut))
}
