//! IMAPS listener: implicit TLS, pre-auth dialog, gate, credential check and
//! backend login, then a byte relay.

mod backend;
pub(crate) mod preauth;

use crate::auth::discovery::{self, Answer};
use crate::auth::token::TokenError;
use crate::auth::{self, refused, sasl};
use crate::limits;
use crate::obs::metrics;
use crate::server::{BackendConn, Ctx};
use crate::wire;
use anyhow::Result;
use preauth::read_client_auth;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

/// The IMAP listener's own settings.
pub struct Imap {
    /// TLS with ALPN `imap`.
    pub acceptor: crate::server::tls::Acceptor,
    pub backend: BackendConn,
}

pub async fn handle(
    tcp: TcpStream,
    peer: SocketAddr,
    ctx: Arc<Ctx<Imap>>,
    mut permit: limits::ConnPermit,
) -> Result<()> {
    let _conn = metrics::ConnGuard::open(metrics::Proto::Imap);
    // The address the client dialed, for the PROXY header; `peer` as the
    // fallback keeps both ends in one address family.
    let local = tcp.local_addr().unwrap_or(peer);
    let (internal, scope) = ctx.scope(peer);
    // One budget for TLS handshake + pre-auth dialog together.
    let tuning = &ctx.tuning;
    let preauth_until = tokio::time::Instant::now() + tuning.preauth;
    let mut client =
        match wire::deadline_at(preauth_until, tuning.preauth, "imap TLS handshake", async {
            Ok(ctx.protocol.acceptor.accept(tcp).await?)
        })
        .await
        {
            Ok(c) => c,
            Err(e) => {
                metrics::record_preauth_abort(metrics::Proto::Imap, internal);
                return Err(e);
            }
        };
    // The TLS session ends with close_notify whichever way the dialog
    // ends (RFC 8314 §3.4); the relay closes its own.
    let result: Result<()> = async {
        // Source IP + SNI (client-requested name) decide which password
        // mechanisms the legacy gate offers on this connection; none → OAuth-only.
        let sni = client.get_ref().1.server_name().map(|s| s.to_string());
        let pw_mechs = ctx.password_mechs(metrics::Proto::Imap, sni.as_deref(), peer);
        let session = auth::Session {
            proto: metrics::Proto::Imap,
            peer,
            internal,
            scope,
            sni: sni.as_deref(),
            pw_mechs,
            preauth_until,
        };
        // Up to `limits.max_auth_attempts` attempts (RFC 9051 §6.2.2 lets
        // the client try again after NO), each judged and counted on its own.
        let mut attempts = auth::Attempts::new(tuning.max_auth_attempts);
        let mut cmds = 0usize;
        loop {
            let (tag, mech, is_password, outcome) = match wire::deadline_at(
                preauth_until,
                tuning.preauth,
                "imap pre-auth",
                read_client_auth(&mut client, pw_mechs, ctx.hostname(), tuning, &mut cmds),
            )
            .await
            {
                Ok(Some(auth)) => {
                    if auth::source_blocked(&ctx, &session) {
                        return Err(auth::blocked_source());
                    }
                    let login = backend::ImapLogin {
                        backend: &ctx.protocol.backend,
                        tuning,
                        peer,
                        local,
                        mech: &auth.mech,
                    };
                    let is_password = matches!(auth.kind, sasl::ClientAuthKind::Password { .. });
                    let host = auth.host.as_deref();
                    let outcome =
                        auth::authorize(&ctx, &session, &auth.mech, &auth.kind, host, &login).await;
                    // The credential is not needed after the login: dropping it
                    // zeroizes it before the splice, which can last for hours.
                    drop(auth.kind);
                    (auth.tag, auth.mech, is_password, outcome)
                }
                // LOGOUT, or a disconnect right after the greeting, before
                // authenticating: a clean end, e.g. a monitoring probe.
                Ok(None) => return Ok(()),
                Err(e) => {
                    // Answered already; recorded like a blocked password.
                    if let Some(w) = e.downcast_ref::<auth::Withheld>() {
                        let error = auth::withheld(&ctx, &session, w);
                        attempts.refused(&session, error, true)?;
                        continue;
                    }
                    // Answered already, without a credential.
                    if e.is::<auth::Retryable>() {
                        attempts.refused(&session, e, false)?;
                        continue;
                    }
                    // Answered with the error result like a rejected token.
                    if let Some(d) = e.downcast_ref::<sasl::Discovery>() {
                        auth::discovery(&session, d);
                        let asked = auth::Outcome::BadToken(TokenError::Invalid(d.to_string()));
                        (d.tag.clone(), d.mech.clone(), false, asked)
                    } else {
                        // No further credential: a `protocol` record unless
                        // the client gave up after a refusal.
                        return Err(attempts.ended(&session, e));
                    }
                }
            };
            let tag = &tag;
            let unavailable = matches!(outcome, auth::Outcome::Unavailable(_));
            let (reply, error) = match outcome {
                auth::Outcome::Ok {
                    conn: (mut be, logged_in),
                    ..
                } => {
                    permit.authenticated();
                    // Relay the backend's own tagged OK under the client's tag: its
                    // CAPABILITY response code is what the client may cache for the
                    // session (RFC 9051 section 7.1), so it must list the backend's real
                    // post-login capabilities.
                    client
                        .write_all(format!("{tag} {logged_in}\r\n").as_bytes())
                        .await?;
                    wire::splice(&mut client, &mut be, metrics::Proto::Imap, tuning).await;
                    return Ok(());
                }
                auth::Outcome::Blocked => (
                    format!("{tag} NO password authentication not available on this endpoint"),
                    refused(format!(
                        "password auth blocked on OAuth-only endpoint (scope={scope})"
                    )),
                ),
                // RFC 7628 section 3.2.2: the error result as a continuation, then
                // the failure once the client has answered it (section 3.2.3). Fixed
                // texts: the reason stays in the journal, not on the wire. An abort
                // (`*`) or undecodable answer is a tagged BAD (RFC 9051 section
                // 6.2.2); anything else, and a client that does not answer, gets NO.
                auth::Outcome::BadToken(e) => {
                    let prompt = format!("+ {}", ctx.error_challenge.base64());
                    let answer = discovery::complete_line(
                        &mut client,
                        &prompt,
                        &mech,
                        preauth_until,
                        tuning,
                    )
                    .await;
                    let reply = match answer {
                        Ok(Answer::Cancelled | Answer::Undecodable) => {
                            format!("{tag} BAD AUTHENTICATE failed: invalid or cancelled response")
                        }
                        _ => format!("{tag} NO [AUTHENTICATIONFAILED] Authentication failed"),
                    };
                    (
                        reply,
                        refused(format!("token rejected: {e}{}", Answer::note(&answer))),
                    )
                }
                // RFC 5530: the credential is fine, the requested authorisation
                // identity is not.
                auth::Outcome::WrongAuthzid => (
                    format!("{tag} NO [AUTHORIZATIONFAILED] Authorization failed"),
                    refused("authorization identity differs from the token's identity"),
                ),
                // Refused by the legacy gate: the same answer as a wrong password, so
                // the client cannot tell the cases apart.
                auth::Outcome::Denied => (
                    format!("{tag} NO [AUTHENTICATIONFAILED] backend rejected credentials"),
                    refused("password refused by the legacy gate"),
                ),
                auth::Outcome::Rejected(reply) => {
                    let what = if is_password { "credentials" } else { "token" };
                    (
                        format!("{tag} NO [AUTHENTICATIONFAILED] backend rejected {what}"),
                        refused(format!("backend auth rejected: {reply}")),
                    )
                }
                // RFC 5530 UNAVAILABLE tells the client to retry later rather than to
                // discard its credential.
                auth::Outcome::Unavailable(e) => (
                    format!("{tag} NO [UNAVAILABLE] Backend temporarily unavailable"),
                    e.context("backend unavailable"),
                ),
            };
            let _ = client.write_all(format!("{reply}\r\n").as_bytes()).await;
            // rustls buffers; without a flush the answer is lost when the stream is
            // dropped.
            let _ = client.flush().await;
            // An outage ends the session: another attempt would meet it too.
            if unavailable {
                return Err(error);
            }
            attempts.refused(&session, error, true)?;
        }
    }
    .await;
    crate::wire::close(&mut client).await;
    result
}
