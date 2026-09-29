//! IMAPS listener: implicit TLS, pre-auth dialog, gate, credential check and
//! backend login, then a byte relay.

mod backend;
pub(crate) mod preauth;

use crate::auth::discovery::{self, Answer};
use crate::auth::{self, refused, sasl};
use crate::limits;
use crate::obs::{authlog, metrics};
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
    pub backend: BackendConn,
}

pub async fn handle(
    tcp: TcpStream,
    peer: SocketAddr,
    ctx: Arc<Ctx<Imap>>,
    mut permit: limits::ConnPermit,
) -> Result<()> {
    let _conn = metrics::ConnGuard::open(metrics::Proto::Imap);
    // The address the client dialed (post-DNAT local addr of this socket). Used
    // only as the PROXY protocol destination; falls back to `peer` so the two
    // ends always share an address family if the lookup ever fails.
    let local = tcp.local_addr().unwrap_or(peer);
    let (internal, scope) = ctx.scope(peer);
    // One budget for TLS handshake + pre-auth dialog together.
    let tuning = &ctx.tuning;
    let preauth_until = tokio::time::Instant::now() + tuning.preauth;
    let mut client =
        match wire::deadline_at(preauth_until, tuning.preauth, "imap TLS handshake", async {
            Ok(ctx.acceptor.accept(tcp).await?)
        })
        .await
        {
            Ok(c) => c,
            Err(e) => {
                metrics::record_preauth_abort(metrics::Proto::Imap, internal);
                return Err(e);
            }
        };
    // Source IP + SNI (client-requested name) decide which password
    // mechanisms the legacy gate offers on this connection; none → OAuth-only.
    let sni = client.get_ref().1.server_name().map(|s| s.to_string());
    let pw_mechs = ctx.password_mechs(metrics::Proto::Imap, sni.as_deref(), peer);
    let auth = match wire::deadline_at(
        preauth_until,
        tuning.preauth,
        "imap pre-auth",
        read_client_auth(&mut client, pw_mechs, ctx.hostname(), tuning),
    )
    .await
    {
        Ok(Some(a)) => a,
        // LOGOUT, or a disconnect right after the greeting, before
        // authenticating: a clean end, e.g. a monitoring probe.
        Ok(None) => return Ok(()),
        Err(e) => {
            // Pre-auth failure: the client never presented a credential (TLS
            // stack mismatch, portscan, EOF, unsupported mechanism). Keep the
            // detail in the journal for CrowdSec, but count it as a pre-auth
            // abort — NOT an auth fail — so the "failed logins" metric stays
            // truthful.
            authlog::AuthEvent {
                proto: metrics::Proto::Imap,
                scope,
                mech: "other",
                user: "",
                peer: peer.ip(),
                reason: authlog::Reason::Protocol,
                pwfp: "",
                rule: "",
            }
            .record();
            metrics::record_preauth_abort(metrics::Proto::Imap, internal);
            return Err(e);
        }
    };

    let session = auth::Session {
        proto: metrics::Proto::Imap,
        peer,
        internal,
        scope,
        sni: sni.as_deref(),
        pw_mechs,
    };
    let login = backend::ImapLogin {
        backend: &ctx.protocol.backend,
        tuning,
        peer,
        local,
        mech: &auth.mech,
    };
    let is_password = matches!(auth.kind, sasl::ClientAuthKind::Password { .. });
    let tag = &auth.tag;
    // Every failure answers the client, then ends the session with an error
    // for the journal. The answer is best effort: a client that is already
    // gone must not replace the reason (an outage's cause above all) with a
    // write error.
    let outcome = auth::authorize(&ctx, &session, &auth.mech, &auth.kind, &login).await;
    // The credential is not needed after the login: dropping it zeroizes it
    // before the splice, which can last for hours.
    drop(auth.kind);
    let (reply, error) = match outcome {
        auth::Outcome::Ok {
            conn: (mut be, logged_in),
            ..
        } => {
            permit.authenticated();
            // Relay the backend's own tagged OK under the client's tag: its
            // CAPABILITY response code is what the client may cache for the
            // session (RFC 3501 §7.1), so it must list the backend's real
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
            let answer =
                discovery::complete_line(&mut client, &prompt, &auth.mech, preauth_until, tuning)
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
    Err(error)
}
