//! SMTP submission listener: plaintext dialog up to STARTTLS, post-TLS
//! dialog up to AUTH, gate, credential check and backend login, then a byte
//! relay.

pub(crate) mod backend;
pub(crate) mod preauth;

use crate::auth::discovery::{self, Answer};
use crate::auth::sasl::Discovery;
use crate::auth::{self, refused};
use crate::limits::ConnPermit;
use crate::obs::metrics::Proto;
use crate::server::{BackendConn, Ctx};
use crate::wire::deadline_at;
use crate::wire::line::{read_client_line, verb_is};
use anyhow::{anyhow, Result};
use backend::{ClientHelo, SmtpLogin};
use preauth::read_smtp_auth;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

/// The submission listener's own settings.
pub struct Submission {
    /// TLS after STARTTLS; SMTP has no ALPN identifier.
    pub acceptor: crate::server::tls::Acceptor,
    pub backend: BackendConn,
    /// Announce the client address with XCLIENT when the backend offers it.
    pub xclient: bool,
    /// Extensions advertised after STARTTLS besides AUTH.
    pub ehlo_extensions: Vec<String>,
}

pub async fn handle(
    mut tcp: TcpStream,
    peer: SocketAddr,
    ctx: Arc<Ctx<Submission>>,
    mut permit: ConnPermit,
) -> Result<()> {
    let _conn = crate::obs::metrics::ConnGuard::open(crate::obs::metrics::Proto::Smtp);
    let name = ctx.hostname();
    let (internal, scope) = ctx.scope(peer);
    // One pre-auth budget from the greeting to the credential, across the
    // plaintext dialog, the TLS handshake and the post-TLS dialog (see
    // `Tuning::preauth`).
    let tuning = &ctx.tuning;
    let preauth_until = tokio::time::Instant::now() + tuning.preauth;

    // Greeting, then EHLO (tolerating NOOP/RSET) up to STARTTLS. AUTH is
    // refused until STARTTLS: no credential crosses in the clear.
    let starttls = deadline_at(preauth_until, tuning.preauth, "submission pre-TLS", async {
        tcp.write_all(format!("220 {name} ESMTP\r\n").as_bytes())
            .await?;
        let mut cmds = 0usize;
        loop {
            cmds += 1;
            if cmds > tuning.max_preauth_commands {
                tcp.write_all(b"421 4.7.0 Too many commands before STARTTLS\r\n")
                    .await?;
                return Err(anyhow!("submission: pre-TLS command limit reached"));
            }
            let line = read_client_line(&mut tcp, tuning.idle).await?;
            if verb_is(&line, "EHLO") {
                // No AUTH before STARTTLS (RFC 4954 section 4: no plaintext
                // password mechanisms without it). An AUTH here is answered 530.
                tcp.write_all(format!("250-{name}\r\n250 STARTTLS\r\n").as_bytes())
                    .await?;
            } else if verb_is(&line, "NOOP") {
                tcp.write_all(b"250 2.0.0 OK\r\n").await?;
            } else if verb_is(&line, "STARTTLS") {
                // RFC 3207 §4: STARTTLS takes no parameters.
                if line.trim_end().len() > "STARTTLS".len() {
                    tcp.write_all(b"501 5.5.4 Syntax error (no parameters allowed)\r\n")
                        .await?;
                    continue;
                }
                tcp.write_all(b"220 2.0.0 Ready to start TLS\r\n").await?;
                return Ok(true);
            } else if verb_is(&line, "QUIT") {
                tcp.write_all(b"221 2.0.0 Bye\r\n").await?;
                return Ok(false);
            } else if is_command(&line) {
                // RFC 3207 §4: every command other than NOOP, EHLO, STARTTLS
                // or QUIT gets 530 until TLS; AUTH included (RFC 4954 §4).
                tcp.write_all(b"530 5.7.0 Must issue STARTTLS first\r\n")
                    .await?;
            } else {
                tcp.write_all(b"500 5.5.1 Command not recognized\r\n")
                    .await?;
            }
        }
    })
    .await;
    // No credential was presented: a pre-auth abort.
    let starttls = match starttls {
        Ok(v) => v,
        Err(e) => {
            crate::obs::metrics::record_preauth_abort(crate::obs::metrics::Proto::Smtp, internal);
            return Err(e);
        }
    };
    if !starttls {
        return Ok(());
    }

    let mut client_tls = match deadline_at(
        preauth_until,
        tuning.preauth,
        "submission TLS handshake",
        async { Ok(ctx.protocol.acceptor.accept(tcp).await?) },
    )
    .await
    {
        Ok(c) => c,
        Err(e) => {
            crate::obs::metrics::record_preauth_abort(crate::obs::metrics::Proto::Smtp, internal);
            return Err(e);
        }
    };

    // The TLS session ends with close_notify whichever way the dialog
    // ends (RFC 8314 §3.4); the relay closes its own.
    let result: Result<()> = async {
        // SNI and source address decide which password mechanisms the legacy
        // rules offer; none means OAuth only.
        let sni = client_tls.get_ref().1.server_name().map(|s| s.to_string());
        let pw_mechs = ctx.password_mechs(Proto::Smtp, sni.as_deref(), peer);
        let session = auth::Session {
            proto: Proto::Smtp,
            peer,
            internal,
            scope,
            sni: sni.as_deref(),
            pw_mechs,
            preauth_until,
        };

        // The EHLO reply after TLS: no STARTTLS, password mechanisms only as far
        // as the legacy gate offers them.
        let extensions: String = ctx
            .protocol
            .ehlo_extensions
            .iter()
            .map(|x| format!("250-{x}\r\n"))
            .collect();
        let ehlo_reply = format!(
            "250-{name}\r\n{extensions}250 AUTH XOAUTH2 OAUTHBEARER{}{}\r\n",
            if pw_mechs.plain { " PLAIN" } else { "" },
            if pw_mechs.login { " LOGIN" } else { "" },
        );
        // The post-TLS dialog until AUTH arrives. Clients may send EHLO more than
        // once (and NOOP/RSET in between); only AUTH ends this phase. The SASL
        // continuation reads (AUTH LOGIN's two 334 round-trips, AUTH PLAIN
        // without an initial response) run inside the same budget: they are
        // client-paced too. `Ok(None)` is a clean QUIT.
        // The client's last EHLO or HELO after TLS, for XCLIENT.
        let mut helo: Option<ClientHelo> = None;
        let authed = match deadline_at(
            preauth_until,
            tuning.preauth,
            "submission post-TLS",
            async {
                let mut cmds = 0usize;
                loop {
                    cmds += 1;
                    if cmds > tuning.max_preauth_commands {
                        client_tls
                            .write_all(b"421 4.7.0 Too many commands before AUTH\r\n")
                            .await?;
                        client_tls.flush().await?;
                        return Err(anyhow!("submission: post-TLS command limit reached"));
                    }
                    let line = read_client_line(&mut client_tls, tuning.idle).await?;
                    if let Some(h) = ClientHelo::parse(&line) {
                        helo = Some(h);
                    }
                    if verb_is(&line, "EHLO") {
                        client_tls.write_all(ehlo_reply.as_bytes()).await?;
                    } else if verb_is(&line, "HELO") {
                        // HELO takes a one-line reply without extensions
                        // (RFC 5321 §4.1.1.1).
                        client_tls
                            .write_all(format!("250 {name}\r\n").as_bytes())
                            .await?;
                    } else if verb_is(&line, "AUTH") {
                        // One AUTH per connection (anti-guessing): a refused one
                        // is answered, then the connection is closed with 421.
                        let challenge = ctx.error_challenge.base64();
                        return match read_smtp_auth(
                            &line,
                            &mut client_tls,
                            pw_mechs,
                            challenge,
                            tuning.idle,
                        )
                        .await
                        {
                            Ok(v) => Ok(Some(v)),
                            Err(e) => {
                                let _ = client_tls.write_all(closing(name).as_bytes()).await;
                                Err(e)
                            }
                        };
                    } else if verb_is(&line, "NOOP") || verb_is(&line, "RSET") {
                        client_tls.write_all(b"250 2.0.0 OK\r\n").await?;
                    } else if verb_is(&line, "QUIT") {
                        client_tls.write_all(b"221 2.0.0 Bye\r\n").await?;
                        return Ok(None);
                    } else if verb_is(&line, "STARTTLS") {
                        client_tls
                            .write_all(b"503 5.5.1 TLS already active\r\n")
                            .await?;
                    } else if is_command(&line) {
                        // RFC 4954 §6: before AUTH, every command other than
                        // AUTH, EHLO, HELO, NOOP, RSET or QUIT gets 530.
                        client_tls
                            .write_all(b"530 5.7.0 Authentication required\r\n")
                            .await?;
                    } else {
                        client_tls
                            .write_all(b"500 5.5.1 Command not recognized\r\n")
                            .await?;
                    }
                }
            },
        )
        .await
        {
            Ok(v) => v,
            Err(e) => {
                // Answered already; recorded like a blocked password.
                if let Some(w) = e.downcast_ref::<auth::Withheld>() {
                    let _ = client_tls.flush().await;
                    return Err(auth::withheld(&ctx, &session, w));
                }
                // Answered with the error result already.
                if let Some(d) = e.downcast_ref::<Discovery>() {
                    auth::discovery(&session, d);
                    let _ = client_tls.flush().await;
                    return Err(refused(format!("{e:#}")));
                }
                // No credential was presented (EOF, total timeout, command flood,
                // unparsable AUTH): a `protocol` record and a pre-auth abort.
                crate::obs::authlog::AuthEvent {
                    proto: crate::obs::metrics::Proto::Smtp,
                    scope,
                    mech: "other",
                    user: "",
                    peer: peer.ip(),
                    reason: crate::obs::authlog::Reason::Protocol,
                    pwfp: "",
                    rule: "",
                }
                .record();
                crate::obs::metrics::record_preauth_abort(crate::obs::metrics::Proto::Smtp, internal);
                let _ = client_tls.flush().await;
                return Err(e);
            }
        };
        let (mech, kind, host) = match authed {
            Some(v) => v,
            None => return Ok(()),
        };

        // Gate, token validation and backend login (connect, STARTTLS, AUTH with
        // the client's own credential).
        let login = SmtpLogin {
            backend: &ctx.protocol.backend,
            tuning,
            name,
            xclient: ctx.protocol.xclient,
            peer,
            helo: helo.as_ref(),
        };
        const INVALID: &str = "535 5.7.8 Authentication credentials invalid";
        let outcome = auth::authorize(&ctx, &session, &mech, &kind, host.as_deref(), &login).await;
        // The credential is not needed after the login: dropping it zeroizes it
        // before the splice, which can last for hours.
        drop(kind);
        let (reply, error) = match outcome {
            auth::Outcome::Ok {
                conn: mut be,
                identity,
            } => {
                permit.authenticated();
                client_tls
                    .write_all(b"235 2.7.0 Authentication successful\r\n")
                    .await?;
                tracing::info!(target: crate::obs::target::SUBMISSION, user=%crate::obs::authlog::sanitize(&identity), mech=%mech, "submission auth ok; splicing");
                crate::wire::splice(&mut client_tls, &mut be, Proto::Smtp, &ctx.tuning).await;
                return Ok(());
            }
            auth::Outcome::Blocked => (
                "504 5.5.4 password authentication not available on this endpoint",
                refused(format!(
                    "password auth blocked on OAuth-only endpoint (scope={scope})"
                )),
            ),
            // RFC 7628 section 3.2.2: the error result as a `334` challenge,
            // then the failure once the client has answered it (section 3.2.3).
            auth::Outcome::BadToken(e) => {
                let prompt = format!("334 {}", ctx.error_challenge.base64());
                let answer =
                    discovery::complete_line(&mut client_tls, &prompt, &mech, preauth_until, tuning)
                        .await;
                (
                    preauth::error_result_reply(&answer),
                    refused(format!("token rejected: {e}{}", Answer::note(&answer))),
                )
            }
            auth::Outcome::WrongAuthzid => (
                INVALID,
                refused("authorization identity differs from the token's identity"),
            ),
            // Refused by the legacy gate: the same answer as a wrong password.
            auth::Outcome::Denied => (INVALID, refused("password refused by the legacy gate")),
            auth::Outcome::Rejected(code) => {
                (INVALID, refused(format!("backend AUTH rejected: {code}")))
            }
            // Any failure talking to Postfix before its AUTH verdict, or a reply
            // without a verdict, is answered 454 so the client retries later
            // instead of seeing a silently closed connection.
            auth::Outcome::Unavailable(e) => (
                "454 4.7.0 Temporary authentication failure",
                e.context("backend unavailable"),
            ),
        };
        let _ = client_tls
            .write_all(format!("{reply}\r\n{}", closing(name)).as_bytes())
            .await;
        let _ = client_tls.flush().await;
        Err(error)
    }
    .await;
    crate::wire::close(&mut client_tls).await;
    result
}

/// True if `line` is an SMTP command the proxy recognises (RFC 5321 §4.1,
/// RFC 3030 BDAT, RFC 4954 AUTH, RFC 3207 STARTTLS); an unrecognised one gets
/// `500` (RFC 5321 §4.2.4).
fn is_command(line: &str) -> bool {
    [
        "EHLO", "HELO", "MAIL", "RCPT", "DATA", "BDAT", "RSET", "VRFY", "EXPN", "HELP", "NOOP",
        "QUIT", "AUTH", "STARTTLS",
    ]
    .iter()
    .any(|v| verb_is(line, v))
}

/// The reply before the proxy closes a connection after a refused AUTH. The
/// proxy takes one AUTH per connection, and RFC 5321 §3.8 lets a server
/// close only after QUIT, a timeout, or a 421.
fn closing(name: &str) -> String {
    format!("421 4.7.0 {name} closing connection\r\n")
}
