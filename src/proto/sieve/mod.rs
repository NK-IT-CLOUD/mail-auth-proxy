//! ManageSieve listener: capability greeting up to STARTTLS, cached backend
//! capabilities, AUTHENTICATE, gate, credential check and backend login, then
//! a byte relay.

mod backend;
pub(crate) mod preauth;

pub use backend::CapsCache;

use crate::auth::discovery::{self, Answer};
use crate::auth::{self, refused};
use crate::limits::ConnPermit;
use crate::obs::metrics::Proto;
use crate::server::{BackendConn, Ctx};
use crate::wire::deadline_at;
use crate::wire::line::{read_client_line, verb_is};
use anyhow::{anyhow, Result};
use backend::{backend_caps, SieveLogin};
use preauth::{parse_authenticate_line, read_sasl_string};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::Instant;

/// ManageSieve capability greeting before TLS (RFC 5804 §1.7).
///
/// The SASL list is empty: AUTHENTICATE is refused until STARTTLS, and a
/// client must never be invited to send a bearer token or password in the
/// clear (RFC 7628 §3). RFC 5804 §1.7 allows an empty list when STARTTLS is
/// offered. `sieve` is the backend's `"SIEVE"` line if it is known.
fn caps_plain(name: &str, sieve: Option<&str>) -> String {
    let sieve = sieve.map(|l| format!("{l}\r\n")).unwrap_or_default();
    format!("\"IMPLEMENTATION\" \"{name}\"\r\n\"SASL\" \"\"\r\n{sieve}\"STARTTLS\"\r\n\"VERSION\" \"1.0\"\r\nOK \"ready\"\r\n")
}

/// A SASL challenge line (RFC 5804 section 2.1): a quoted string, or a
/// literal when the base64 data exceeds the 1024 octets a quoted string may
/// hold (section 4). Base64 needs no escaping.
fn sieve_challenge(b64: &str) -> String {
    if b64.len() <= 1024 {
        format!("\"{b64}\"\r\n")
    } else {
        format!("{{{}}}\r\n{b64}\r\n", b64.len())
    }
}

/// Post-TLS SASL lines, chosen by the legacy gate (source address, SNI,
/// protocol). LOGIN is never offered: the proxy has no SASL LOGIN challenge
/// dialog for ManageSieve, only PLAIN.
const SASL_OAUTH_ONLY: &[u8] = b"\"SASL\" \"XOAUTH2 OAUTHBEARER\"\r\n";
const SASL_FULL: &[u8] = b"\"SASL\" \"XOAUTH2 OAUTHBEARER PLAIN\"\r\n";

/// The ManageSieve listener's own settings and capability cache.
pub struct Sieve {
    pub backend: BackendConn,
    pub caps: CapsCache,
    /// How long cached backend capabilities are relayed.
    pub caps_ttl: std::time::Duration,
}

pub async fn handle(
    mut tcp: TcpStream,
    peer: SocketAddr,
    ctx: Arc<Ctx<Sieve>>,
    mut permit: ConnPermit,
) -> Result<()> {
    let _conn = crate::obs::metrics::ConnGuard::open(crate::obs::metrics::Proto::Sieve);
    // The address the client dialed, for the PROXY header; `peer` as the
    // fallback keeps both ends in one address family.
    let local = tcp.local_addr().unwrap_or(peer);
    let (internal, scope) = ctx.scope(peer);
    // One pre-auth budget across the plaintext dialog, the TLS handshake and
    // AUTHENTICATE (see `Tuning::preauth`).
    let tuning = &ctx.tuning;
    let preauth_until = Instant::now() + tuning.preauth;

    // Capability greeting, then only STARTTLS or LOGOUT: AUTHENTICATE gets
    // ENCRYPT-NEEDED, everything else NO.
    let starttls = deadline_at(preauth_until, tuning.preauth, "sieve pre-TLS", async {
        let greeting = caps_plain(ctx.hostname(), ctx.protocol.caps.sieve_line().as_deref());
        tcp.write_all(greeting.as_bytes()).await?;
        let mut cmds = 0usize;
        loop {
            cmds += 1;
            if cmds > tuning.max_preauth_commands {
                tcp.write_all(b"NO \"Too many commands before STARTTLS\"\r\n")
                    .await?;
                return Err(anyhow!("sieve: pre-TLS command limit reached"));
            }
            let line = read_client_line(&mut tcp, tuning.idle).await?;
            if verb_is(&line, "STARTTLS") {
                tcp.write_all(b"OK \"Begin TLS negotiation now\"\r\n")
                    .await?;
                return Ok(true);
            } else if verb_is(&line, "LOGOUT") {
                tcp.write_all(b"OK \"Bye\"\r\n").await?;
                return Ok(false);
            } else if verb_is(&line, "AUTHENTICATE") {
                // RFC 5804 §1.3: ENCRYPT-NEEDED tells the client to STARTTLS.
                tcp.write_all(b"NO (ENCRYPT-NEEDED) \"STARTTLS required\"\r\n")
                    .await?;
            } else {
                tcp.write_all(b"NO \"Command not permitted before STARTTLS\"\r\n")
                    .await?;
            }
        }
    })
    .await;
    // No credential was presented: a pre-auth abort.
    let starttls = match starttls {
        Ok(v) => v,
        Err(e) => {
            crate::obs::metrics::record_preauth_abort(crate::obs::metrics::Proto::Sieve, internal);
            return Err(e);
        }
    };
    if !starttls {
        return Ok(());
    }

    let mut client_tls = match deadline_at(
        preauth_until,
        tuning.preauth,
        "sieve TLS handshake",
        async { Ok(ctx.acceptor.accept(tcp).await?) },
    )
    .await
    {
        Ok(c) => c,
        Err(e) => {
            crate::obs::metrics::record_preauth_abort(crate::obs::metrics::Proto::Sieve, internal);
            return Err(e);
        }
    };

    // Source IP + SNI decide whether password auth is offered — same legacy
    // rules as IMAP/SMTP. External clients and forged-SNI attackers stay
    // OAuth-only unless a rule names their network.
    let sni = client_tls.get_ref().1.server_name().map(|s| s.to_string());
    let pw_mechs = crate::auth::legacy::MechSet {
        plain: ctx.password_mechs(Proto::Sieve, sni.as_deref(), peer).plain,
        login: false,
    };

    // Relay the backend's post-TLS capabilities, rewriting SASL to what
    // this endpoint allows and dropping STARTTLS (already done).
    let be_caps = match deadline_at(
        preauth_until,
        tuning.preauth,
        "sieve backend capabilities",
        backend_caps(&ctx.protocol, tuning),
    )
    .await
    {
        Ok(c) => c,
        Err(e) => {
            let _ = client_tls
                .write_all(b"BYE \"Service temporarily unavailable\"\r\n")
                .await;
            let _ = client_tls.flush().await;
            return Err(e);
        }
    };
    let mut caps = String::new();
    for cap_line in be_caps.iter() {
        let upper = cap_line.to_ascii_uppercase();
        if upper.starts_with("\"STARTTLS\"") {
            continue;
        }
        if upper.starts_with("\"SASL\"") {
            let line: &[u8] = if pw_mechs.plain {
                SASL_FULL
            } else {
                SASL_OAUTH_ONLY
            };
            caps.push_str(std::str::from_utf8(line).unwrap_or_default());
        } else {
            caps.push_str(cap_line);
            caps.push_str("\r\n");
        }
    }
    client_tls.write_all(caps.as_bytes()).await?;
    client_tls
        .write_all(b"OK \"TLS negotiation successful.\"\r\n")
        .await?;

    // Read commands until AUTHENTICATE and parse the credential, inside the
    // pre-auth budget. RFC 5804 allows CAPABILITY, NOOP and LOGOUT before
    // authenticating. Every other way this ends without a credential is a
    // pre-auth abort; LOGOUT is a clean end.
    let (mech, kind) = match deadline_at(
        preauth_until,
        tuning.preauth,
        "sieve post-TLS auth",
        async {
            let mut cmds = 0usize;
            let line = loop {
                cmds += 1;
                if cmds > tuning.max_preauth_commands {
                    client_tls
                        .write_all(b"BYE \"Too many commands before AUTHENTICATE\"\r\n")
                        .await?;
                    return Err(anyhow!("sieve: post-TLS command limit reached"));
                }
                let line = read_client_line(&mut client_tls, tuning.idle).await?;
                if verb_is(&line, "CAPABILITY") {
                    client_tls.write_all(caps.as_bytes()).await?;
                    client_tls
                        .write_all(b"OK \"Capability completed.\"\r\n")
                        .await?;
                } else if verb_is(&line, "NOOP") {
                    client_tls.write_all(b"OK \"NOOP completed.\"\r\n").await?;
                } else if verb_is(&line, "LOGOUT") {
                    client_tls
                        .write_all(b"OK \"Logout completed.\"\r\n")
                        .await?;
                    client_tls.flush().await?;
                    return Ok(None);
                } else {
                    break line;
                }
            };
            let (mech, ir) =
                match parse_authenticate_line(&line, &mut client_tls, tuning.idle).await {
                    Ok(v) => v,
                    Err(e) => {
                        // Best effort: the client may already be gone.
                        let _ = client_tls
                            .write_all(b"NO \"Invalid AUTHENTICATE\"\r\n")
                            .await;
                        return Err(e);
                    }
                };
            let kind = match mech.to_ascii_uppercase().as_str() {
                "XOAUTH2" | "OAUTHBEARER" => crate::auth::sasl::parse_sasl(&mech, &ir)
                    .map(|c| crate::auth::sasl::ClientAuthKind::OAuth {
                        user: c.user,
                        token: c.token,
                    })
                    .map_err(|e| anyhow!("sasl parse: {e}")),
                "PLAIN" => crate::auth::sasl::parse_plain(&ir)
                    .map(|(user, pass)| crate::auth::sasl::ClientAuthKind::Password { user, pass })
                    .map_err(|e| anyhow!("plain parse: {e}")),
                _ => {
                    client_tls
                        .write_all(b"NO \"Authentication mechanism not supported\"\r\n")
                        .await?;
                    return Err(anyhow!(
                        "unsupported sieve mechanism {}",
                        crate::obs::authlog::sanitize(&mech)
                    ));
                }
            };
            match kind {
                Ok(k) => Ok(Some((mech, k))),
                Err(e) => {
                    client_tls
                        .write_all(b"NO \"Invalid authentication response\"\r\n")
                        .await?;
                    Err(e)
                }
            }
        },
    )
    .await
    {
        Ok(Some(v)) => v,
        Ok(None) => return Ok(()),
        Err(e) => {
            // No credential was presented (EOF, timeout, unparsable
            // AUTHENTICATE): a `protocol` record and a pre-auth abort.
            crate::obs::authlog::AuthEvent {
                proto: crate::obs::metrics::Proto::Sieve,
                scope,
                mech: "other",
                user: "",
                peer: peer.ip(),
                reason: crate::obs::authlog::Reason::Protocol,
                pwfp: "",
                rule: "",
            }
            .record();
            crate::obs::metrics::record_preauth_abort(crate::obs::metrics::Proto::Sieve, internal);
            let _ = client_tls.flush().await;
            return Err(e);
        }
    };

    // Gate, token validation and backend login. The backend is contacted
    // only with a credential that passed the local checks.
    let session = auth::Session {
        proto: Proto::Sieve,
        peer,
        internal,
        scope,
        sni: sni.as_deref(),
        pw_mechs,
    };
    let login = SieveLogin {
        backend: &ctx.protocol.backend,
        tuning,
        origin: (peer, local),
    };
    const FAILED: &str = "NO \"Authentication failed\"";
    let outcome = auth::authorize(&ctx, &session, &mech, &kind, &login).await;
    // The credential is not needed after the login: dropping it zeroizes it
    // before the splice, which can last for hours.
    drop(kind);
    let (reply, error) = match outcome {
        auth::Outcome::Ok {
            conn: (mut be, be_reply),
            identity,
        } => {
            permit.authenticated();
            client_tls.write_all(be_reply.as_bytes()).await?;
            client_tls.write_all(b"\r\n").await?;
            tracing::info!(target: crate::obs::target::SIEVE, user=%crate::obs::authlog::sanitize(&identity), mech=%mech, "sieve auth ok; splicing");
            crate::wire::splice(&mut client_tls, &mut be, Proto::Sieve, &ctx.tuning).await;
            return Ok(());
        }
        auth::Outcome::Blocked => (
            "NO \"password authentication not available on this endpoint\"",
            refused(format!(
                "password auth blocked on OAuth-only endpoint (scope={scope})"
            )),
        ),
        // RFC 7628 section 3.2.2: the error result as a challenge string,
        // then the failure once the client has answered it (section 3.2.3).
        // Every ending, an abort (`"*"`, RFC 5804 section 2.1) included,
        // is a NO.
        auth::Outcome::BadToken(e) => {
            let answer = deadline_at(preauth_until, tuning.preauth, "error challenge", async {
                client_tls
                    .write_all(sieve_challenge(ctx.error_challenge.base64()).as_bytes())
                    .await?;
                client_tls.flush().await?;
                read_sasl_string(&mut client_tls, tuning.idle).await
            })
            .await
            .map(|s| discovery::classify(&mech, &s));
            (
                FAILED,
                refused(format!("token rejected: {e}{}", Answer::note(&answer))),
            )
        }
        auth::Outcome::WrongAuthzid => (
            "NO \"Authorization failed\"",
            refused("authorization identity differs from the token's identity"),
        ),
        // Refused by the legacy gate: the same answer as a wrong password.
        auth::Outcome::Denied => (FAILED, refused("password refused by the legacy gate")),
        auth::Outcome::Rejected(reply) => {
            (FAILED, refused(format!("backend auth rejected: {reply}")))
        }
        // Outage, not a verdict on the credential (see BackendError).
        auth::Outcome::Unavailable(e) => (
            "NO (TRYLATER) \"Service temporarily unavailable\"",
            e.context("backend unavailable"),
        ),
    };
    let _ = client_tls
        .write_all(format!("{reply}\r\n").as_bytes())
        .await;
    let _ = client_tls.flush().await;
    Err(error)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Before TLS no mechanism is offered; the backend's SIEVE line is
    /// included once it is known.
    #[test]
    fn plaintext_greeting_offers_no_mechanism() {
        let g = caps_plain("proxy.test", None);
        assert!(g.contains("\"SASL\" \"\"\r\n"), "{g}");
        assert!(!g.contains("OAUTH") && !g.contains("PLAIN"), "{g}");
        assert!(!g.contains("\"SIEVE\""), "{g}");
        let g = caps_plain("proxy.test", Some("\"SIEVE\" \"fileinto\""));
        assert!(g.contains("\"SIEVE\" \"fileinto\"\r\n"), "{g}");
    }

    /// Quoted up to the 1024-octet limit of a quoted string, a literal beyond.
    #[test]
    fn challenge_is_quoted_or_literal() {
        assert_eq!(sieve_challenge("eyJ9"), "\"eyJ9\"\r\n");
        let at_limit = "A".repeat(1024);
        assert_eq!(sieve_challenge(&at_limit), format!("\"{at_limit}\"\r\n"));
        let long = "A".repeat(1025);
        assert_eq!(sieve_challenge(&long), format!("{{1025}}\r\n{long}\r\n"));
    }

    /// The password-gated SASL line advertises PLAIN, never LOGIN; the
    /// OAuth-only line no password mechanism.
    #[test]
    fn sasl_capability_lines_match_gate() {
        let full = std::str::from_utf8(SASL_FULL).unwrap();
        assert!(full.contains("PLAIN"));
        assert!(!full.contains("LOGIN"));
        let oauth_only = std::str::from_utf8(SASL_OAUTH_ONLY).unwrap();
        assert!(!oauth_only.contains("PLAIN"));
        assert!(!oauth_only.contains("LOGIN"));
    }
}
