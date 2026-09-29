//! The SMTP backend: login dialog (STARTTLS or implicit TLS, optional
//! XCLIENT, AUTH) and reply reader.

use crate::auth::sasl::ErrorResult;
use crate::auth::{BackendCredential, BackendError, BackendLogin};
use crate::config::BackendTls;
use crate::server::BackendConn;
use crate::wire::line::{read_line, verb_is};
use crate::wire::{connect, Tuning};
use anyhow::{anyhow, Result};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use zeroize::Zeroizing;

/// The SMTP backend login of one client session.
pub(super) struct SmtpLogin<'a> {
    pub backends: &'a [std::sync::Arc<super::Upstream>],
    pub tuning: &'a Tuning,
    /// Our name in EHLO.
    pub name: &'a str,
    /// The client's address.
    pub peer: SocketAddr,
    /// The address the client dialed, for the PROXY header.
    pub local: SocketAddr,
    /// The client's last greeting after TLS, for XCLIENT.
    pub helo: Option<&'a ClientHelo>,
}

/// The greeting command a client sent after TLS: EHLO or HELO and its
/// argument (RFC 5321 §4.1.1.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHelo {
    pub extended: bool,
    pub name: String,
}

impl ClientHelo {
    /// The greeting of an EHLO or HELO line, `None` for any other line. The
    /// argument is its first word, empty if there is none.
    pub fn parse(line: &str) -> Option<ClientHelo> {
        let mut words = line.split_whitespace();
        let verb = words.next()?;
        let extended = if verb.eq_ignore_ascii_case("EHLO") {
            true
        } else if verb.eq_ignore_ascii_case("HELO") {
            false
        } else {
            return None;
        };
        Some(ClientHelo {
            extended,
            name: words.next().unwrap_or("").to_string(),
        })
    }
}

impl BackendLogin for SmtpLogin<'_> {
    type Conn = TlsStream<TcpStream>;

    fn name(&self, index: usize) -> &str {
        &self.backends[index].conn.id
    }

    async fn login(
        &self,
        index: usize,
        credential: BackendCredential<'_>,
    ) -> Result<Self::Conn, BackendError> {
        let password = matches!(credential, BackendCredential::Password { .. });
        let (be, code, error_result) = self.dialog(&self.backends[index].conn, credential).await?;
        match auth_verdict(code, password) {
            AuthVerdict::Ok => Ok(be),
            // The backend refused the credential (bad password, unknown user,
            // sender-login mismatch).
            AuthVerdict::Rejected => Err(crate::auth::rejected_after(
                code.to_string(),
                error_result.as_ref(),
            )),
            AuthVerdict::Unavailable => {
                Err(anyhow!("backend AUTH failed without a verdict: {code}").into())
            }
        }
    }
}

/// What the final reply to the backend AUTH exchange means.
#[derive(Debug, PartialEq, Eq)]
enum AuthVerdict {
    Ok,
    /// A verdict on the credential.
    Rejected,
    /// No verdict: an outage or a protocol failure.
    Unavailable,
}

/// Classify the reply to the sent credential response (after `334`) of a
/// token (`password` false) or password login. A reply to the bare AUTH
/// line never gets here: it is an outage (`dialog`).
///
/// - `235`: logged in.
/// - `4xx` (e.g. 454 when Postfix's SASL backend is down): temporary, an outage.
/// - `50x` (500–509, the syntax class of RFC 5321 §4.2.1: "command too long",
///   a malformed response, an unknown mechanism): for a token, the backend
///   did not understand the exchange and never judged the credential; counting
///   it as a rejection would feed CrowdSec bans against legitimate users. For
///   a password it is a rejection: the client chose the credential bytes (see
///   `auth::MAX_PASSWORD`).
/// - Any other `5xx` (535, 534, 554, …): a rejection.
/// - Anything else (a stray `334`, `2xx`): a protocol failure, an outage.
fn auth_verdict(code: u16, password: bool) -> AuthVerdict {
    match code {
        235 => AuthVerdict::Ok,
        500..=509 if password => AuthVerdict::Rejected,
        500..=509 => AuthVerdict::Unavailable,
        510..=599 => AuthVerdict::Rejected,
        _ => AuthVerdict::Unavailable,
    }
}

/// Connect to the submission backend and secure the connection as its
/// `tls` says: STARTTLS reads the plaintext greeting, sends `EHLO <name>`
/// and STARTTLS (RFC 3207) before the handshake; implicit TLS (RFC 8314
/// §3.3) reads the greeting over TLS. Then `EHLO <name>` over TLS. Returns
/// the TLS stream and the lines of that EHLO reply (without the code, the
/// first being the backend's name). `origin` is `(client, local)` for a
/// client's session, `None` for the proxy's own EHLO probe (see
/// `connect::connect`).
pub(super) async fn connect_ehlo(
    backend: &BackendConn,
    origin: Option<(SocketAddr, SocketAddr)>,
    tuning: &Tuning,
    name: &str,
) -> Result<(TlsStream<TcpStream>, Vec<String>)> {
    const WHAT: &str = "submission backend";
    let mut tcp_be = connect::connect(backend, origin, tuning.connect, WHAT).await?;
    let mut be = match backend.tls_mode {
        BackendTls::Starttls => {
            expect_greeting(&mut tcp_be, tuning.idle).await?;
            tcp_be
                .write_all(format!("EHLO {name}\r\n").as_bytes())
                .await?;
            let (code, lines) = read_smtp_reply(&mut tcp_be, tuning.idle).await?;
            if code != 250 {
                return Err(anyhow!("backend EHLO code {code}"));
            }
            if !lines.iter().any(|l| verb_is(l, "STARTTLS")) {
                return Err(anyhow!("backend did not advertise STARTTLS"));
            }
            tcp_be.write_all(b"STARTTLS\r\n").await?;
            let (code, _) = read_smtp_reply(&mut tcp_be, tuning.idle).await?;
            if code != 220 {
                return Err(anyhow!("backend STARTTLS code {code}"));
            }
            connect::tls(backend, tcp_be, tuning.connect, WHAT).await?
        }
        BackendTls::Implicit => {
            let mut be = connect::tls(backend, tcp_be, tuning.connect, WHAT).await?;
            expect_greeting(&mut be, tuning.idle).await?;
            be
        }
    };

    be.write_all(format!("EHLO {name}\r\n").as_bytes()).await?;
    let (code, ehlo_lines) = read_smtp_reply(&mut be, tuning.idle).await?;
    if code != 250 {
        return Err(anyhow!("backend post-TLS EHLO code {code}"));
    }
    Ok((be, ehlo_lines))
}

/// Read the backend's greeting; anything but `220` is an error.
async fn expect_greeting<S: AsyncRead + Unpin>(s: &mut S, idle: Duration) -> Result<()> {
    let (code, _) = read_smtp_reply(s, idle).await?;
    if code != 220 {
        return Err(anyhow!("backend greeting code {code}"));
    }
    Ok(())
}

impl SmtpLogin<'_> {
    /// `connect_ehlo`, optional XCLIENT, then AUTH with the client's own
    /// credential (never a master password). Returns the final AUTH reply
    /// code and the OAUTHBEARER error result, if there was one.
    async fn dialog(
        &self,
        backend: &BackendConn,
        credential: BackendCredential<'_>,
    ) -> Result<(TlsStream<TcpStream>, u16, Option<ErrorResult>)> {
        let (mut be, ehlo_lines) = connect_ehlo(
            backend,
            Some((self.peer, self.local)),
            self.tuning,
            self.name,
        )
        .await?;
        let xclient = backend.client_ip == crate::config::ClientIp::Xclient;

        // XCLIENT (optional): Postfix then logs and stamps the real client
        // address. Only when configured and advertised; a backend that does
        // not authorize this proxy never advertises it.
        //
        // A backend that advertises XCLIENT to a proxy configured without it
        // would let the client, after the splice, send its own
        // `XCLIENT LOGIN=<other> ADDR=…` on the proxy's authorization (Postfix
        // accepts XCLIENT from an authorized host until ADDR is sent). Fail
        // closed before any credential is sent: an outage.
        let offers_xclient = ehlo_lines.iter().any(|l| verb_is(l, "XCLIENT"));
        if !xclient && offers_xclient {
            return Err(anyhow!(
                "backend advertises XCLIENT to this proxy but submission.backend.client_ip is not \"xclient\": \
                 an authenticated client could send its own XCLIENT; set client_ip = \"xclient\" \
                 or remove the proxy from Postfix smtpd_authorized_xclient_hosts"
            ));
        }
        if xclient && offers_xclient {
            let advertised = ehlo_lines
                .iter()
                .find(|l| verb_is(l, "XCLIENT"))
                .map_or("", String::as_str);
            be.write_all(xclient_line(advertised, self.peer, self.helo).as_bytes())
                .await?;
            // Postfix answers XCLIENT with a fresh 220 greeting and resets the
            // session state, so the SMTP conversation must restart with EHLO.
            let (code, _) = read_smtp_reply(&mut be, self.tuning.idle).await?;
            if code != 220 {
                return Err(anyhow!("backend XCLIENT code {code}"));
            }
            be.write_all(format!("EHLO {}\r\n", self.name).as_bytes())
                .await?;
            let (code, lines) = read_smtp_reply(&mut be, self.tuning.idle).await?;
            if code != 250 {
                return Err(anyhow!("backend post-XCLIENT EHLO code {code}"));
            }
            // Postfix re-evaluates smtpd_authorized_xclient_hosts against the
            // announced ADDR. A client whose own address is authorized would
            // keep the right to send XCLIENT after the splice: the same
            // impersonation as above, so fail closed the same way.
            if lines.iter().any(|l| verb_is(l, "XCLIENT")) {
                return Err(anyhow!(
                    "backend still advertises XCLIENT after XCLIENT ADDR=<client>: the client's \
                     address is authorized for XCLIENT, so it could send its own; remove it from \
                     Postfix smtpd_authorized_xclient_hosts"
                ));
            }
        }

        let fwd = credential.forward(backend);
        let mech = fwd.mech;
        // The response goes after the `334` challenge, never on the AUTH line:
        // RFC 4954 §4 forbids an initial response that pushes the command past
        // the server's line limit (512 octets in RFC 5321, 2048 in Postfix's
        // default `line_length_limit`), and a bearer token easily does. Postfix
        // accepts 12288 octets for a SASL response.
        be.write_all(format!("AUTH {mech}\r\n").as_bytes()).await?;
        let (code, _) = read_smtp_reply(&mut be, self.tuning.idle).await?;
        if code != 334 {
            // No credential was sent yet: 503 (AUTH not enabled), 504
            // (unknown mechanism) or any other reply here is the backend's
            // configuration, never a verdict, on both paths.
            return Err(anyhow!(
                "backend refused AUTH {mech} before the credential: {code}"
            ));
        }
        be.write_all(Zeroizing::new([fwd.response.as_str(), "\r\n"].concat()).as_bytes())
            .await?;
        let (mut code, lines) = read_smtp_reply(&mut be, self.tuning.idle).await?;
        let mut error_result = None;
        if let (334, Some(answer)) = (code, fwd.error_answer()) {
            // The error challenge of a token (`334 <base64 JSON>`): the client
            // answers with the mechanism's dummy response (empty for XOAUTH2,
            // `%x01` for OAUTHBEARER) and the server then sends its final
            // failure reply (Google "XOAUTH2 mechanism", RFC 7628 §3.2.3).
            error_result = fwd.error_result(lines.first().map_or("", String::as_str));
            be.write_all(format!("{answer}\r\n").as_bytes()).await?;
            code = read_smtp_reply(&mut be, self.tuning.idle).await?.0;
        }
        Ok((be, code, error_result))
    }
}

/// Longest SMTP command line (RFC 5321 §4.5.3.1.4), CRLF included; XCLIENT
/// must fit it (Postfix XCLIENT_README, note 1).
const MAX_COMMAND: usize = 512;

/// The XCLIENT command for the client at `peer` with greeting `helo`,
/// `advertised` being the backend's `XCLIENT` EHLO line (its attribute
/// names).
///
/// NAME and ADDR are always sent. NAME must be explicit: attributes the
/// command omits keep the value the session already had, so an ADDR-only
/// XCLIENT would pin the proxy's own hostname onto the real client's IP in
/// `client=` and in the Received header. The proxy does no reverse lookup,
/// so the value is the spec's placeholder for "not available". HELO, PROTO
/// and PORT (the client's EHLO or HELO name, which of the two, its source
/// port) are sent where advertised, so the backend's Received header names
/// the client's greeting, not the proxy's (RFC 5321 §4.4); the backend keeps
/// them across the proxy's own EHLO that follows. Values are xtext (RFC
/// 3461 §4). A HELO name that would push the command past `MAX_COMMAND` or
/// is longer than 255 characters is sent as `[UNAVAILABLE]`.
fn xclient_line(advertised: &str, peer: SocketAddr, helo: Option<&ClientHelo>) -> String {
    let offered = |attr: &str| {
        advertised
            .split_whitespace()
            .skip(1)
            .any(|a| a.eq_ignore_ascii_case(attr))
    };
    // IPv4-mapped (::ffff:a.b.c.d) is announced as the IPv4 address it is.
    let addr = match peer.ip().to_canonical() {
        std::net::IpAddr::V4(v4) => format!("ADDR={v4}"),
        std::net::IpAddr::V6(v6) => format!("ADDR=IPV6:{v6}"),
    };
    let mut fixed = Vec::new();
    if let Some(h) = helo.filter(|_| offered("PROTO")) {
        fixed.push(format!(
            "PROTO={}",
            if h.extended { "ESMTP" } else { "SMTP" }
        ));
    }
    if offered("PORT") {
        fixed.push(format!("PORT={}", peer.port()));
    }
    fixed.push("NAME=[UNAVAILABLE]".into());
    fixed.push(addr);
    let tail = fixed.join(" ");
    let helo = helo.filter(|_| offered("HELO")).map(|h| {
        let name = xtext(&h.name);
        // "XCLIENT " + "HELO=" + name + " " + tail + CRLF
        if h.name.is_empty() || h.name.len() > 255 || 15 + name.len() + tail.len() > MAX_COMMAND {
            "[UNAVAILABLE]".to_string()
        } else {
            name
        }
    });
    match helo {
        Some(h) => format!("XCLIENT HELO={h} {tail}\r\n"),
        None => format!("XCLIENT {tail}\r\n"),
    }
}

/// `s` as xtext (RFC 3461 §4): `!` to `~` as they are except `+` and `=`,
/// every other byte as `+` and two upper-case hex digits.
fn xtext(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if (b'!'..=b'~').contains(&b) && b != b'+' && b != b'=' {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("+{b:02X}"));
        }
    }
    out
}

/// Most lines accepted in one SMTP reply. An EHLO reply has a dozen or so; a
/// backend that never ends a reply must not grow it without bound.
const MAX_REPLY_LINES: usize = 64;

/// Reads an SMTP reply that may span multiple `NNN-...` lines ending with
/// `NNN ...`; more than `MAX_REPLY_LINES` lines are an error.
pub(crate) async fn read_smtp_reply<S: AsyncRead + Unpin>(
    s: &mut S,
    idle: Duration,
) -> Result<(u16, Vec<String>)> {
    let mut lines = Vec::new();
    let mut code: u16;
    loop {
        if lines.len() == MAX_REPLY_LINES {
            return Err(anyhow!("backend reply longer than {MAX_REPLY_LINES} lines"));
        }
        let l = read_line(s, idle).await?;
        // Byte-safe: never slice a String on a non-char-boundary (would panic).
        let b = l.as_bytes();
        if b.len() < 4 {
            return Err(anyhow!("short smtp reply: {l}"));
        }
        code = std::str::from_utf8(&b[..3])
            .ok()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| anyhow!("bad smtp code: {l}"))?;
        let cont = b[3] == b'-';
        lines.push(l.get(4..).unwrap_or("").to_string());
        if !cont {
            break;
        }
    }
    Ok((code, lines))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[tokio::test]
    async fn multiline_smtp_reply() {
        let mut c = Cursor::new(b"250-mail hi\r\n250-PIPELINING\r\n250 AUTH XOAUTH2\r\n".to_vec());
        let (code, lines) = read_smtp_reply(&mut c, Duration::from_secs(30))
            .await
            .unwrap();
        assert_eq!(code, 250);
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[2], "AUTH XOAUTH2");
    }

    /// A reply that never ends is an error after MAX_REPLY_LINES lines.
    #[tokio::test]
    async fn smtp_reply_is_bounded() {
        let reply = |n: usize| "250-x\r\n".repeat(n - 1) + "250 y\r\n";
        let mut ok = Cursor::new(reply(MAX_REPLY_LINES).into_bytes());
        let (_, lines) = read_smtp_reply(&mut ok, Duration::from_secs(30))
            .await
            .unwrap();
        assert_eq!(lines.len(), MAX_REPLY_LINES);
        let mut long = Cursor::new(reply(MAX_REPLY_LINES + 1).into_bytes());
        assert!(read_smtp_reply(&mut long, Duration::from_secs(30))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn non_ascii_smtp_reply_rejected_not_panic() {
        // A multi-byte char straddling byte index 3 must NOT panic; reject cleanly.
        let mut c = Cursor::new("25é OK\r\n".as_bytes().to_vec());
        assert!(read_smtp_reply(&mut c, Duration::from_secs(30))
            .await
            .is_err());
    }

    #[test]
    fn auth_reply_classification() {
        for password in [false, true] {
            assert_eq!(auth_verdict(235, password), AuthVerdict::Ok);
            for code in [535, 534, 554, 530] {
                assert_eq!(
                    auth_verdict(code, password),
                    AuthVerdict::Rejected,
                    "{code}"
                );
            }
            for code in [454, 421, 334, 250] {
                assert_eq!(
                    auth_verdict(code, password),
                    AuthVerdict::Unavailable,
                    "{code}"
                );
            }
        }
        for code in [500, 501, 504] {
            assert_eq!(
                auth_verdict(code, false),
                AuthVerdict::Unavailable,
                "{code}"
            );
            assert_eq!(auth_verdict(code, true), AuthVerdict::Rejected, "{code}");
        }
    }

    /// HELO, PROTO and PORT go into XCLIENT only where the backend lists
    /// them; NAME and ADDR always, last. The HELO name is xtext; one that
    /// would not fit the 512-octet command is `[UNAVAILABLE]`.
    #[test]
    fn xclient_attributes() {
        let v4: SocketAddr = "192.0.2.7:40123".parse().unwrap();
        let ehlo = ClientHelo::parse("EHLO client.example").unwrap();
        let all = "XCLIENT NAME ADDR PROTO HELO PORT LOGIN";
        assert_eq!(
            xclient_line(all, v4, Some(&ehlo)),
            "XCLIENT HELO=client.example PROTO=ESMTP PORT=40123 NAME=[UNAVAILABLE] ADDR=192.0.2.7\r\n"
        );
        assert_eq!(
            xclient_line("XCLIENT NAME ADDR", v4, Some(&ehlo)),
            "XCLIENT NAME=[UNAVAILABLE] ADDR=192.0.2.7\r\n"
        );
        assert_eq!(
            xclient_line(all, v4, None),
            "XCLIENT PORT=40123 NAME=[UNAVAILABLE] ADDR=192.0.2.7\r\n"
        );
        let helo = ClientHelo::parse("helo [198.51.100.1]").unwrap();
        let v6: SocketAddr = "[2001:db8::5]:587".parse().unwrap();
        assert_eq!(
            xclient_line("XCLIENT name addr proto helo", v6, Some(&helo)),
            "XCLIENT HELO=[198.51.100.1] PROTO=SMTP NAME=[UNAVAILABLE] ADDR=IPV6:2001:db8::5\r\n"
        );
        let odd = ClientHelo::parse("EHLO a+b=cé").unwrap();
        assert!(xclient_line(all, v4, Some(&odd)).starts_with("XCLIENT HELO=a+2Bb+3Dc+C3+A9 "));
        for name in ["", &"x".repeat(256), &"\u{1}".repeat(200)] {
            let h = ClientHelo {
                extended: true,
                name: name.to_string(),
            };
            let line = xclient_line(all, v6, Some(&h));
            assert!(line.starts_with("XCLIENT HELO=[UNAVAILABLE] "), "{line}");
        }
        let longest = ClientHelo {
            extended: true,
            name: "\u{1}".repeat(128),
        };
        assert!(xclient_line(all, v6, Some(&longest)).len() <= MAX_COMMAND);
        assert_eq!(ClientHelo::parse("MAIL FROM:<a@b>"), None);
        assert_eq!(ClientHelo::parse("EHLO").unwrap().name, "");
    }

    #[tokio::test]
    async fn single_smtp_reply() {
        let mut c = Cursor::new(b"235 2.7.0 OK\r\n".to_vec());
        let (code, lines) = read_smtp_reply(&mut c, Duration::from_secs(30))
            .await
            .unwrap();
        assert_eq!(code, 235);
        assert_eq!(lines, vec!["2.7.0 OK".to_string()]);
    }
}
