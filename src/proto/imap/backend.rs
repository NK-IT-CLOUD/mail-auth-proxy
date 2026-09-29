//! IMAP backend login: connect, then AUTHENTICATE with the client's own
//! credential and classify the tagged reply.

use crate::auth::{BackendCredential, BackendError, BackendLogin};
use crate::obs::authlog::sanitize;
use crate::server::BackendConn;
use crate::wire::connect;
use crate::wire::{line::read_line, Tuning};
use anyhow::{anyhow, Result};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use zeroize::Zeroizing;

/// Maximum lines read while waiting for the backend's tagged auth reply. A
/// backend that never sends a tagged response (or loops on continuations) must
/// not pin this task forever.
const MAX_AUTH_LINES: usize = 32;

/// Connect and read the greeting. Also returns whether the greeting's
/// capabilities include SASL-IR (without a CAPABILITY code: no).
async fn connect_tls(
    backend: &BackendConn,
    client: SocketAddr,
    local: SocketAddr,
    tuning: &Tuning,
) -> Result<(TlsStream<TcpStream>, bool)> {
    let tcp = connect::connect(backend, Some((client, local)), tuning.connect, "backend").await?;
    let mut stream = connect::tls(backend, tcp, tuning.connect, "backend").await?;
    let greeting = read_line(&mut stream, tuning.idle).await?;
    if !greeting.starts_with("* OK") {
        return Err(anyhow!("backend greeting: {greeting}"));
    }
    let caps = capability_code(&greeting[2..]).unwrap_or_default();
    if offers_unauthenticate(&caps) {
        return Err(anyhow!(crate::auth::UNAUTHENTICATE_OFFERED));
    }
    let sasl_ir = caps.iter().any(|c| c.eq_ignore_ascii_case("SASL-IR"));
    Ok((stream, sasl_ir))
}

/// The capabilities of the `[CAPABILITY …]` response code that starts the
/// text of `resp` (`OK [CAPABILITY …] text`, status first), if it has one.
fn capability_code(resp: &str) -> Option<Vec<&str>> {
    let (_status, text) = resp.split_once(' ')?;
    let code = text.strip_prefix('[')?.split_once(']')?.0;
    let (name, caps) = code.split_once(' ')?;
    name.eq_ignore_ascii_case("CAPABILITY")
        .then(|| caps.split_ascii_whitespace().collect())
}

fn offers_unauthenticate<S: AsRef<str>>(caps: &[S]) -> bool {
    caps.iter()
        .any(|c| c.as_ref().eq_ignore_ascii_case("UNAUTHENTICATE"))
}

/// Ask a logged-in backend for its capabilities (`P2 CAPABILITY`), for a
/// tagged OK without a CAPABILITY code. The exchange is the proxy's own; the
/// client never sees it.
async fn query_capabilities(
    stream: &mut TlsStream<TcpStream>,
    idle: Duration,
) -> Result<Vec<String>> {
    stream.write_all(b"P2 CAPABILITY\r\n").await?;
    let mut caps = Vec::new();
    for _ in 0..MAX_AUTH_LINES {
        let l = read_line(stream, idle).await?;
        if let Some(tagged) = l.strip_prefix("P2 ") {
            if !tagged
                .get(..3)
                .is_some_and(|s| s.eq_ignore_ascii_case("OK "))
            {
                return Err(anyhow!("backend CAPABILITY failed: {l}"));
            }
            return Ok(caps);
        }
        if let Some(list) = l
            .get(..13)
            .filter(|p| p.eq_ignore_ascii_case("* CAPABILITY "))
            .map(|_| &l[13..])
        {
            caps.extend(list.split_ascii_whitespace().map(str::to_string));
        }
    }
    Err(anyhow!(
        "backend sent no tagged CAPABILITY reply within {MAX_AUTH_LINES} lines"
    ))
}

enum AuthReply {
    Ok,
    /// `NO`: the backend's verdict on the credential.
    Rejected,
    /// `NO` with a temporary response code (`TEMPORARY_CODES`, e.g.
    /// Dovecot's passdb is down), `BAD` (the backend did not understand our
    /// well-formed command) or anything unexpected: an outage, not a verdict.
    Unavailable,
}

/// RFC 5530 response codes that name a server-side cause: `UNAVAILABLE` (a
/// subsystem is down), `INUSE` (a lock someone else holds), `SERVERBUG` and
/// `LIMIT` (an implementation limit). A `NO` with one of them is treated as
/// an outage, not a verdict on the credential.
const TEMPORARY_CODES: [&str; 4] = ["[UNAVAILABLE]", "[INUSE]", "[SERVERBUG]", "[LIMIT]"];

/// Classify the tagged reply (tag already stripped), case-insensitively.
///
/// `bad_is_verdict`: a `BAD` answers a password credential the proxy sent
/// unchanged (not its own cancel). The client chose those bytes, so a `BAD`
/// is a rejection, not an outage (see `auth::MAX_PASSWORD`).
fn classify_tagged(reply: &str, bad_is_verdict: bool) -> AuthReply {
    let mut words = reply.splitn(3, ' ');
    let status = words.next().unwrap_or("");
    let code = words.next().unwrap_or("");
    if status.eq_ignore_ascii_case("OK") {
        AuthReply::Ok
    } else if (status.eq_ignore_ascii_case("NO")
        && !TEMPORARY_CODES.iter().any(|c| code.eq_ignore_ascii_case(c)))
        || (bad_is_verdict && status.eq_ignore_ascii_case("BAD"))
    {
        AuthReply::Rejected
    } else {
        AuthReply::Unavailable
    }
}

/// Wait for the tagged reply to `P1 AUTHENTICATE`. On success returns the
/// reply without its tag (`OK [CAPABILITY …] Logged in`), for relaying to the
/// client under its own tag.
///
/// `xoauth2`: the exchange is XOAUTH2, whose failure comes as an error
/// challenge (`+ <base64 JSON>`) that the client answers with an empty line;
/// the server then sends its tagged `NO` (Google "XOAUTH2 mechanism", RFC 7628
/// §3.2.3). Any other continuation is cancelled with `*` (RFC 9051 §6.2.2),
/// which a compliant server answers with `BAD`: an outage, not a verdict.
/// For a password (`xoauth2` false) a tagged `BAD` that is not the answer to
/// such a cancel is a rejection (see `classify_tagged`).
async fn await_auth_ok(
    stream: &mut TlsStream<TcpStream>,
    idle: Duration,
    xoauth2: bool,
) -> Result<String, BackendError> {
    let mut error_challenge_answered = false;
    let mut cancelled = false;
    for _ in 0..MAX_AUTH_LINES {
        let l = read_line(stream, idle).await?;
        // An untagged BYE (connection limit, shutdown) stays an outage: the
        // backend closes whatever the credential; read_line reports the EOF.
        let password_verdict = !xoauth2 && !cancelled;
        if let Some(tagged) = l.strip_prefix("P1 ") {
            match classify_tagged(tagged, password_verdict) {
                AuthReply::Ok => return Ok(tagged.to_string()),
                AuthReply::Rejected => return Err(BackendError::Rejected(l)),
                AuthReply::Unavailable => {
                    return Err(anyhow!("backend temporarily unavailable: {l}").into())
                }
            }
        }
        // A continuation is "+" optionally followed by text — match the bare
        // form too, not just "+ ".
        if l.starts_with('+') {
            if xoauth2 && !error_challenge_answered {
                // A bare CRLF is the empty response, not a cancel.
                error_challenge_answered = true;
                stream.write_all(b"\r\n").await?;
            } else {
                cancelled = true;
                stream.write_all(b"*\r\n").await?;
            }
        }
    }
    Err(anyhow!("backend sent no tagged auth reply within {MAX_AUTH_LINES} lines").into())
}

/// The IMAP backend login of one client session.
pub struct ImapLogin<'a> {
    pub backend: &'a BackendConn,
    pub tuning: &'a Tuning,
    /// The client's address.
    pub peer: SocketAddr,
    /// The address the client dialed, for the PROXY header.
    pub local: SocketAddr,
    /// The client's mechanism, for the log.
    pub mech: &'a str,
}

impl BackendLogin for ImapLogin<'_> {
    /// The backend connection and its tagged OK without the tag.
    type Conn = (TlsStream<TcpStream>, String);

    async fn login(&self, credential: BackendCredential<'_>) -> Result<Self::Conn, BackendError> {
        let xoauth2 = matches!(credential, BackendCredential::Token { .. });
        let (mech, response) = match credential {
            // The same token the client presented, for its verified identity.
            BackendCredential::Token { identity, token } => {
                tracing::info!(target: crate::obs::target::MAIN, peer = %self.peer, user = %sanitize(identity), mech = %self.mech, "oauth validated; proxying to backend");
                ("XOAUTH2", crate::auth::sasl::build_xoauth2(identity, token))
            }
            // The client's own password; the backend validates it (the proxy
            // never holds a master credential). Never log the password.
            BackendCredential::Password { user, pass } => {
                tracing::info!(target: crate::obs::target::MAIN, peer = %self.peer, user = %sanitize(user), mech = %self.mech, "password auth; forwarding to backend");
                ("PLAIN", crate::auth::sasl::build_plain(user, pass))
            }
        };
        let (mut stream, sasl_ir) =
            connect_tls(self.backend, self.peer, self.local, self.tuning).await?;
        if sasl_ir {
            // `concat` sizes the line once; it is zeroized on drop like the
            // response.
            let command =
                Zeroizing::new(["P1 AUTHENTICATE ", mech, " ", &response, "\r\n"].concat());
            stream.write_all(command.as_bytes()).await?;
        } else {
            // RFC 4959 §3: no initial response to a server that does not
            // advertise SASL-IR; the response follows the empty challenge.
            stream
                .write_all(format!("P1 AUTHENTICATE {mech}\r\n").as_bytes())
                .await?;
            let challenge = read_line(&mut stream, self.tuning.idle).await?;
            if !challenge.starts_with('+') {
                // No credential was sent: the backend's configuration, an
                // outage on both paths.
                return Err(anyhow!(
                    "backend refused AUTHENTICATE {mech} before the credential: {challenge}"
                )
                .into());
            }
            stream
                .write_all(Zeroizing::new([&response, "\r\n"].concat()).as_bytes())
                .await?;
        }
        let ok = await_auth_ok(&mut stream, self.tuning.idle, xoauth2).await?;
        // RFC 8437 advertises UNAUTHENTICATE in the authenticated state.
        let unauthenticate = match capability_code(&ok) {
            Some(caps) => offers_unauthenticate(&caps),
            None => {
                offers_unauthenticate(&query_capabilities(&mut stream, self.tuning.idle).await?)
            }
        };
        if unauthenticate {
            return Err(anyhow!(crate::auth::UNAUTHENTICATE_OFFERED).into());
        }
        Ok((stream, ok))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_codes() {
        assert_eq!(
            capability_code("OK [CAPABILITY IMAP4rev1 IDLE] Logged in"),
            Some(vec!["IMAP4rev1", "IDLE"])
        );
        assert_eq!(
            capability_code("OK [capability UNAUTHENTICATE]"),
            Some(vec!["UNAUTHENTICATE"])
        );
        assert_eq!(capability_code("OK Logged in [CAPABILITY X]"), None);
        assert_eq!(capability_code("OK [ALERT] x"), None);
        assert_eq!(capability_code("OK"), None);
        assert!(offers_unauthenticate(&["IMAP4rev1", "unauthenticate"]));
        assert!(!offers_unauthenticate(&["IMAP4rev1", "UNAUTHENTICATEX"]));
    }

    #[test]
    fn tagged_reply_classification() {
        assert!(matches!(
            classify_tagged("OK [CAPABILITY IMAP4rev1] Logged in", false),
            AuthReply::Ok
        ));
        assert!(matches!(
            classify_tagged("ok Logged in", false),
            AuthReply::Ok
        ));
        assert!(matches!(
            classify_tagged("NO [AUTHENTICATIONFAILED] Authentication failed.", false),
            AuthReply::Rejected
        ));
        assert!(matches!(
            classify_tagged("no [authenticationfailed] x", false),
            AuthReply::Rejected
        ));
        assert!(matches!(
            classify_tagged("NO [UNAVAILABLE] Temporary authentication failure.", false),
            AuthReply::Unavailable
        ));
        assert!(matches!(
            classify_tagged("no [unavailable] x", false),
            AuthReply::Unavailable
        ));
        assert!(matches!(
            classify_tagged("BAD Error in IMAP command", false),
            AuthReply::Unavailable
        ));
        // The other temporary RFC 5530 codes are outages too, whatever the
        // credential.
        for code in ["[INUSE]", "[serverbug]", "[LIMIT]"] {
            for password in [false, true] {
                assert!(
                    matches!(
                        classify_tagged(&format!("NO {code} Try again later"), password),
                        AuthReply::Unavailable
                    ),
                    "{code}"
                );
            }
        }
        // A code that is not temporary stays a verdict.
        assert!(matches!(
            classify_tagged("NO [CONTACTADMIN] x", false),
            AuthReply::Rejected
        ));
        // A BAD to a password credential is a verdict; UNAVAILABLE stays an
        // outage.
        assert!(matches!(
            classify_tagged("BAD Error in IMAP command", true),
            AuthReply::Rejected
        ));
        assert!(matches!(
            classify_tagged("NO [UNAVAILABLE] x", true),
            AuthReply::Unavailable
        ));
    }
}
