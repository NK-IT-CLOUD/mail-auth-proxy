//! SMTP submission listeners: the plaintext dialog up to STARTTLS (587) or
//! implicit TLS (465), then the dialog over TLS up to AUTH, gate, credential
//! check and backend login, then a byte relay.

pub(crate) mod backend;
pub mod ehlo;
pub(crate) mod preauth;

use crate::auth::discovery::{self, Answer};
use crate::auth::sasl::Discovery;
use crate::auth::{self, refused};
use crate::limits::ConnPermit;
use crate::obs::metrics::{Listener, Proto};
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
use tokio_rustls::server::TlsStream;

/// The submission listener's own settings.
pub struct Submission {
    /// TLS after STARTTLS and on the implicit-TLS listener; SMTP has no
    /// ALPN identifier.
    pub acceptor: crate::server::tls::Acceptor,
    /// Every backend a credential can be routed to (`route::Pick::index`).
    pub backends: Vec<Arc<Upstream>>,
    /// `submission.ehlo_extensions`: the keywords the EHLO reply may list
    /// at most; `None`: every one of `ehlo::RELAYED`.
    pub ehlo_only: Option<Vec<String>>,
    /// How long the backends' EHLO extensions are reused.
    pub caps_ttl: std::time::Duration,
}

/// A submission backend and its post-TLS EHLO extensions; a reload that
/// keeps the backend keeps them.
pub struct Upstream {
    pub conn: BackendConn,
    pub ehlo: Arc<ehlo::EhloCache>,
}

/// Probe the backends' EHLO extensions once at startup, so the first
/// clients need not wait for a probe. A failure is logged and counted like
/// any failed probe and does not stop the start.
pub async fn probe_at_startup(ctx: Arc<Ctx<Submission>>) {
    let sub = &ctx.protocol;
    for up in &sub.backends {
        if let Err(e) =
            ehlo::backend_extensions(up, sub.caps_ttl, &ctx.tuning, ctx.hostname()).await
        {
            tracing::warn!(target: crate::obs::target::SUBMISSION, backend=%up.conn.id, error=%format!("{e:#}"), "submission backend EHLO extensions not available at startup");
        }
    }
}

/// The STARTTLS listener (port 587): the plaintext dialog up to STARTTLS,
/// then the TLS dialog.
pub async fn handle(
    mut tcp: TcpStream,
    peer: SocketAddr,
    ctx: Arc<Ctx<Submission>>,
    permit: ConnPermit,
) -> Result<()> {
    let _conn = crate::obs::metrics::ConnGuard::open(crate::obs::metrics::Proto::Smtp);
    crate::obs::metrics::record_listener_connection(Listener::Submission);
    let name = ctx.hostname();
    // The address the client dialed, for a PROXY header to the backend.
    let local = tcp.local_addr().unwrap_or(peer);
    let (internal, _) = ctx.scope(peer);
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

    let client_tls = accept_tls(tcp, &ctx, preauth_until, internal).await?;
    serve(
        client_tls,
        Conn {
            peer,
            local,
            listener: Listener::Submission,
            preauth_until,
        },
        ctx,
        permit,
    )
    .await
}

/// The implicit-TLS listener (port 465, RFC 8314 §3.3): the TLS handshake
/// first, then the greeting and the same dialog as after STARTTLS.
pub async fn handle_implicit(
    tcp: TcpStream,
    peer: SocketAddr,
    ctx: Arc<Ctx<Submission>>,
    permit: ConnPermit,
) -> Result<()> {
    let _conn = crate::obs::metrics::ConnGuard::open(Proto::Smtp);
    crate::obs::metrics::record_listener_connection(Listener::Submissions);
    let local = tcp.local_addr().unwrap_or(peer);
    let (internal, _) = ctx.scope(peer);
    let preauth_until = tokio::time::Instant::now() + ctx.tuning.preauth;
    let client_tls = accept_tls(tcp, &ctx, preauth_until, internal).await?;
    serve(
        client_tls,
        Conn {
            peer,
            local,
            listener: Listener::Submissions,
            preauth_until,
        },
        ctx,
        permit,
    )
    .await
}

/// The TLS handshake with the client, within the pre-auth budget; a failure
/// is a pre-auth abort.
async fn accept_tls(
    tcp: TcpStream,
    ctx: &Ctx<Submission>,
    preauth_until: tokio::time::Instant,
    internal: bool,
) -> Result<TlsStream<TcpStream>> {
    let tuning = &ctx.tuning;
    match deadline_at(
        preauth_until,
        tuning.preauth,
        "submission TLS handshake",
        async { Ok(ctx.protocol.acceptor.accept(tcp).await?) },
    )
    .await
    {
        Ok(c) => Ok(c),
        Err(e) => {
            crate::obs::metrics::record_preauth_abort(Proto::Smtp, internal);
            Err(e)
        }
    }
}

/// The client connection a TLS dialog runs for.
struct Conn {
    peer: SocketAddr,
    /// The address the client dialed, for a PROXY header to the backend.
    local: SocketAddr,
    listener: Listener,
    /// End of the pre-auth budget, counted from the accept.
    preauth_until: tokio::time::Instant,
}

/// The dialog over TLS up to AUTH, gate, credential check and backend
/// login, then the relay. On the implicit-TLS listener it starts with the
/// greeting; after STARTTLS the client speaks first (RFC 3207 §4.2).
async fn serve(
    mut client_tls: TlsStream<TcpStream>,
    conn: Conn,
    ctx: Arc<Ctx<Submission>>,
    mut permit: ConnPermit,
) -> Result<()> {
    let Conn {
        peer,
        local,
        listener,
        preauth_until,
    } = conn;
    let name = ctx.hostname();
    let (internal, scope) = ctx.scope(peer);
    let tuning = &ctx.tuning;
    // The TLS session ends with close_notify whichever way the dialog
    // ends (RFC 8314 §3.4); the relay closes its own.
    let result: Result<()> = async {
        if listener == Listener::Submissions {
            deadline_at(preauth_until, tuning.preauth, "submission greeting", async {
                client_tls
                    .write_all(format!("220 {name} ESMTP\r\n").as_bytes())
                    .await?;
                Ok(())
            })
            .await?;
        }
        // SNI and source address decide which password mechanisms the legacy
        // rules offer; none means OAuth only.
        let sni = client_tls.get_ref().1.server_name().map(|s| s.to_string());
        let pw_mechs = ctx.password_mechs(Proto::Smtp, sni.as_deref(), peer);
        let session = auth::Session {
            proto: Proto::Smtp,
            listener,
            peer,
            internal,
            scope,
            sni: sni.as_deref(),
            pw_mechs,
            preauth_until,
        };

        // The EHLO reply after TLS: the backend's extensions as far as the
        // proxy handles them (`ehlo::RELAYED`), no STARTTLS, password
        // mechanisms only as far as the legacy gate offers them. Built at the
        // first EHLO and kept for the connection: the client keeps its view
        // for the whole session.
        let mut ehlo_reply: Option<String> = None;
        // The post-TLS dialog until AUTH arrives. Clients may send EHLO more than
        // once (and NOOP/RSET in between); only AUTH ends this phase. The SASL
        // continuation reads (AUTH LOGIN's two 334 round-trips, AUTH PLAIN
        // without an initial response) run inside the same budget: they are
        // client-paced too. After a refused AUTH the dialog goes on, up to
        // `limits.max_auth_attempts` attempts (RFC 4954 §4), each judged and
        // counted on its own; the last is followed by 421 and the close.
        // The client's last EHLO or HELO after TLS, for XCLIENT.
        let mut helo: Option<ClientHelo> = None;
        let mut attempts = auth::Attempts::new(tuning.max_auth_attempts);
        let mut cmds = 0usize;
        loop {
            // An AUTH command was read: a failure is answered, and one that
            // ends the session is followed by 421.
            let mut auth_command = false;
            // `Ok(None)` is a clean QUIT.
            let authed = deadline_at(
                preauth_until,
                tuning.preauth,
                "submission post-TLS",
                async {
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
                            if ehlo_reply.is_none() {
                                let extensions =
                                    ehlo::for_client(&ctx.protocol, tuning, name).await;
                                ehlo_reply = Some(ehlo_reply_text(name, &extensions, pw_mechs));
                            }
                            let reply = ehlo_reply.as_deref().unwrap_or_default();
                            client_tls.write_all(reply.as_bytes()).await?;
                        } else if verb_is(&line, "HELO") {
                            // HELO takes a one-line reply without extensions
                            // (RFC 5321 §4.1.1.1).
                            client_tls
                                .write_all(format!("250 {name}\r\n").as_bytes())
                                .await?;
                        } else if verb_is(&line, "AUTH") {
                            auth_command = true;
                            let challenge = ctx.error_challenge.base64();
                            return read_smtp_auth(
                                &line,
                                &mut client_tls,
                                pw_mechs,
                                challenge,
                                tuning.idle,
                            )
                            .await
                            .map(Some);
                        } else if verb_is(&line, "NOOP") || verb_is(&line, "RSET") {
                            client_tls.write_all(b"250 2.0.0 OK\r\n").await?;
                        } else if verb_is(&line, "QUIT") {
                            client_tls.write_all(b"221 2.0.0 Bye\r\n").await?;
                            return Ok(None);
                        } else if verb_is(&line, "STARTTLS") {
                            client_tls
                                .write_all(b"503 5.5.1 TLS already active\r\n")
                                .await?;
                        } else if verb_is(&line, "BDAT") {
                            // RFC 3030 §2: the chunk that follows must be
                            // read and discarded. The proxy does not read
                            // mail data before AUTH: it closes, so the chunk
                            // is never taken for commands.
                            client_tls
                                .write_all(
                                    format!(
                                        "530 5.7.0 Authentication required\r\n{}",
                                        closing(name)
                                    )
                                    .as_bytes(),
                                )
                                .await?;
                            client_tls.flush().await?;
                            return Err(anyhow!("BDAT before AUTH"));
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
            .await;
            let (mech, kind, host) = match authed {
                Ok(Some(v)) => v,
                Ok(None) => return Ok(()),
                Err(e) => {
                    let next = if let Some(w) = e.downcast_ref::<auth::Withheld>() {
                        // Answered already; recorded like a blocked password.
                        let error = auth::withheld(&ctx, &session, w);
                        attempts.refused(&session, error, true)
                    } else if let Some(d) = e.downcast_ref::<Discovery>() {
                        // Answered with the error result already.
                        auth::discovery(&session, d);
                        attempts.refused(&session, refused(format!("{e:#}")), true)
                    } else if e.is::<auth::Retryable>() {
                        // Answered already, without a credential.
                        attempts.refused(&session, e, false)
                    } else {
                        // No further credential (EOF, total timeout, command
                        // flood, a failed read in AUTH): a `protocol` record
                        // unless the client gave up after a refusal.
                        Err(attempts.ended(&session, e))
                    };
                    if let Err(e) = next {
                        if auth_command {
                            let _ = client_tls.write_all(closing(name).as_bytes()).await;
                        }
                        let _ = client_tls.flush().await;
                        return Err(e);
                    }
                    continue;
                }
            };
            if auth::source_blocked(&ctx, &session) {
                return Err(auth::blocked_source());
            }

            // Gate, token validation and backend login (connect, STARTTLS, AUTH with
            // the client's own credential).
            let login = SmtpLogin {
                backends: &ctx.protocol.backends,
                tuning,
                name,
                peer,
                local,
                helo: helo.as_ref(),
            };
            const INVALID: &str = "535 5.7.8 Authentication credentials invalid";
            let outcome =
                auth::authorize(&ctx, &session, &mech, &kind, host.as_deref(), &login).await;
            // The credential is not needed after the login: dropping it zeroizes it
            // before the splice, which can last for hours.
            drop(kind);
            let unavailable = matches!(outcome, auth::Outcome::Unavailable(_));
            let (reply, error) = match outcome {
                auth::Outcome::Ok {
                    conn: mut be,
                    identity,
                    issuer,
                } => {
                    permit.authenticated();
                    client_tls
                        .write_all(b"235 2.7.0 Authentication successful\r\n")
                        .await?;
                    tracing::info!(target: crate::obs::target::SUBMISSION, user=%crate::obs::authlog::sanitize(&identity), mech=%mech, issuer=%issuer.as_deref().unwrap_or(""), "submission auth ok; splicing");
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
                    let answer = discovery::complete_line(
                        &mut client_tls,
                        &prompt,
                        &mech,
                        preauth_until,
                        tuning,
                    )
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
            // An outage ends the session: another attempt would meet it too.
            let ended = if unavailable {
                Err(error)
            } else {
                attempts.refused(&session, error, true)
            };
            match ended {
                Ok(()) => {
                    client_tls
                        .write_all(format!("{reply}\r\n").as_bytes())
                        .await?;
                }
                Err(error) => {
                    let _ = client_tls
                        .write_all(format!("{reply}\r\n{}", closing(name)).as_bytes())
                        .await;
                    let _ = client_tls.flush().await;
                    return Err(error);
                }
            }
        }
    }
    .await;
    crate::wire::close(&mut client_tls).await;
    result
}

/// The EHLO reply after STARTTLS: the server name, `extensions` and the
/// AUTH line with the password mechanisms `pw` offers.
fn ehlo_reply_text(name: &str, extensions: &[String], pw: crate::auth::legacy::MechSet) -> String {
    let extensions: String = extensions.iter().map(|x| format!("250-{x}\r\n")).collect();
    format!(
        "250-{name}\r\n{extensions}250 AUTH XOAUTH2 OAUTHBEARER{}{}\r\n",
        if pw.plain { " PLAIN" } else { "" },
        if pw.login { " LOGIN" } else { "" },
    )
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

/// The reply before the proxy closes a connection after a refused AUTH (the
/// last attempt, or an outage). RFC 5321 §3.8 lets a server close only after
/// QUIT, a timeout, or a 421.
fn closing(name: &str) -> String {
    format!("421 4.7.0 {name} closing connection\r\n")
}
