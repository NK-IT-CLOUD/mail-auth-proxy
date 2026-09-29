//! SMTP submission listener: plaintext dialog up to STARTTLS, post-TLS
//! dialog up to AUTH, gate, credential check and backend login, then a byte
//! relay.

mod backend;
mod preauth;

use crate::auth::discovery::{self, Answer};
use crate::auth::{self, refused};
use crate::limits::ConnPermit;
use crate::obs::metrics::Proto;
use crate::server::{BackendConn, Ctx};
use crate::wire::deadline_at;
use crate::wire::line::{read_client_line, verb_is};
use anyhow::{anyhow, Result};
use backend::SmtpLogin;
use preauth::read_smtp_auth;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

/// The submission listener's own settings.
pub struct Submission {
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
    // `internal`/`scope` tag metrics + logs so we can see intern-vs-extern auth outcomes.
    let (internal, scope) = ctx.scope(peer);
    // One budget from the greeting to the credential: plaintext dialog, TLS
    // handshake and post-TLS dialog together. A per-read idle deadline alone
    // can be reset forever by a drip-feeding client, and separate budgets per
    // phase would add up.
    let tuning = &ctx.tuning;
    let preauth_until = tokio::time::Instant::now() + tuning.preauth;

    // ── Front: plaintext preamble until STARTTLS ──────────────────────────────

    // Step 1+2+3: greeting, then read EHLO (tolerating NOOP/RSET) and reply
    // capabilities. AUTH is refused until STARTTLS (creds must never cross
    // plaintext).
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
                // RFC 3207 §4.2: do not advertise AUTH before the session is
                // encrypted, so a client can never be tempted to send
                // credentials in the clear. An AUTH here is still answered 530.
                tcp.write_all(format!("250-{name}\r\n250 STARTTLS\r\n").as_bytes())
                    .await?;
            } else if verb_is(&line, "HELO") {
                // HELO takes a one-line reply without extensions (RFC 5321 §4.1.1.1).
                tcp.write_all(format!("250 {name}\r\n").as_bytes()).await?;
            } else if ["MAIL", "RCPT", "DATA", "BDAT"]
                .iter()
                .any(|v| verb_is(&line, v))
            {
                tcp.write_all(b"530 5.7.0 Must issue STARTTLS first\r\n")
                    .await?;
            } else if verb_is(&line, "NOOP") || verb_is(&line, "RSET") {
                tcp.write_all(b"250 OK\r\n").await?;
            } else if verb_is(&line, "AUTH") {
                tcp.write_all(b"530 5.7.0 Must issue STARTTLS first\r\n")
                    .await?;
            } else if verb_is(&line, "STARTTLS") {
                tcp.write_all(b"220 2.0.0 Ready to start TLS\r\n").await?;
                return Ok(true);
            } else if verb_is(&line, "QUIT") {
                tcp.write_all(b"221 2.0.0 Bye\r\n").await?;
                return Ok(false);
            } else {
                tcp.write_all(b"502 5.5.1 Command not recognized\r\n")
                    .await?;
            }
        }
    })
    .await;
    // No credential was ever presented on these paths: pre-auth abort only.
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

    // TLS upgrade — client side
    let mut client_tls = match deadline_at(
        preauth_until,
        tuning.preauth,
        "submission TLS handshake",
        async { Ok(ctx.acceptor.accept(tcp).await?) },
    )
    .await
    {
        Ok(c) => c,
        Err(e) => {
            crate::obs::metrics::record_preauth_abort(crate::obs::metrics::Proto::Smtp, internal);
            return Err(e);
        }
    };

    // SNI + source IP decide whether password auth is offered. External clients
    // (public mail.dev) and forged-SNI attackers get OAuth-only.
    let sni = client_tls.get_ref().1.server_name().map(|s| s.to_string());
    let pw_mechs = ctx.password_mechs(Proto::Smtp, sni.as_deref(), peer);

    // ── Front: post-TLS dialog ────────────────────────────────────────────────

    // Step 5: read EHLO after TLS, send capabilities without STARTTLS. Password
    // mechanisms are advertised only as far as the legacy gate offers them.
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
    // Step 5+6: run the post-TLS dialogue until AUTH arrives. Clients may send
    // EHLO more than once (and NOOP/RSET in between); only AUTH ends this phase.
    // The SASL continuation reads (AUTH LOGIN's two 334 round-trips, AUTH PLAIN
    // with no inline IR) run inside the same budget: they are client-paced too.
    // The block is also the single exit for every way this phase can end without
    // a credential, so those outcomes land in preauth_aborts rather than
    // inflating auth_attempts{result="fail"}. `Ok(None)` is a clean QUIT.
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
                if verb_is(&line, "EHLO") {
                    client_tls.write_all(ehlo_reply.as_bytes()).await?;
                } else if verb_is(&line, "HELO") {
                    client_tls
                        .write_all(format!("250 {name}\r\n").as_bytes())
                        .await?;
                } else if ["MAIL", "RCPT", "DATA", "BDAT"]
                    .iter()
                    .any(|v| verb_is(&line, v))
                {
                    client_tls
                        .write_all(b"530 5.7.0 Authentication required\r\n")
                        .await?;
                } else if verb_is(&line, "AUTH") {
                    return Ok(Some(
                        read_smtp_auth(&line, &mut client_tls, tuning.idle).await?,
                    ));
                } else if verb_is(&line, "NOOP") || verb_is(&line, "RSET") {
                    client_tls.write_all(b"250 OK\r\n").await?;
                } else if verb_is(&line, "QUIT") {
                    client_tls.write_all(b"221 2.0.0 Bye\r\n").await?;
                    return Ok(None);
                } else {
                    client_tls
                        .write_all(b"502 5.5.1 Command not recognized\r\n")
                        .await?;
                }
            }
        },
    )
    .await
    {
        Ok(v) => v,
        Err(e) => {
            // The client went away before presenting a credential (EOF, total
            // timeout, command flood, unparsable AUTH). Detail to the journal
            // for CrowdSec; count it as a pre-auth abort, never an auth fail.
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
    let (mech, kind) = match authed {
        Some(v) => v,
        None => return Ok(()),
    };

    // Step 6b+7: gate, token validation and backend login (connect,
    // STARTTLS, AUTH with the client's own credential).
    let session = auth::Session {
        proto: Proto::Smtp,
        peer,
        internal,
        scope,
        sni: sni.as_deref(),
        pw_mechs,
    };
    let login = SmtpLogin {
        backend: &ctx.protocol.backend,
        tuning,
        name,
        xclient: ctx.protocol.xclient,
        peer,
    };
    // Every failure answers the client, then ends the session with an error
    // for the journal. The answer is best effort: a client that is already
    // gone must not replace the reason (an outage's cause above all) with a
    // write error.
    const INVALID: &str = "535 5.7.8 Authentication credentials invalid";
    let outcome = auth::authorize(&ctx, &session, &mech, &kind, &login).await;
    // The credential is not needed after the login: dropping it zeroizes it
    // before the splice, which can last for hours.
    drop(kind);
    let (reply, error) = match outcome {
        auth::Outcome::Ok {
            conn: mut be,
            identity,
        } => {
            // Step B6: success — tell client and splice
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
        // An abort (`*`) or undecodable answer is a 501 (RFC 4954 section
        // 4); anything else, and a client that does not answer, gets 535.
        auth::Outcome::BadToken(e) => {
            let prompt = format!("334 {}", ctx.error_challenge.base64());
            let answer =
                discovery::complete_line(&mut client_tls, &prompt, &mech, preauth_until, tuning)
                    .await;
            let reply = match answer {
                Ok(Answer::Cancelled | Answer::Undecodable) => {
                    "501 5.5.2 Invalid or cancelled authentication response"
                }
                _ => INVALID,
            };
            (
                reply,
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
        .write_all(format!("{reply}\r\n").as_bytes())
        .await;
    let _ = client_tls.flush().await;
    Err(error)
}
