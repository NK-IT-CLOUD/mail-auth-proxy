//! ManageSieve listener: capability greeting up to STARTTLS, cached backend
//! capabilities, AUTHENTICATE, gate, credential check and backend login, then
//! a byte relay.

pub(crate) mod backend;
pub(crate) use backend::check;
pub(crate) mod preauth;

pub use backend::CapsCache;

use crate::auth::discovery::{self, Answer};
use crate::auth::sasl::{Discovery, Mechanism};
use crate::auth::token::TokenError;
use crate::auth::{self, refused};
use crate::limits::ConnPermit;
use crate::obs::metrics::Proto;
use crate::server::Ctx;
use crate::wire::deadline_at;
use crate::wire::line::{read_client_line, verb_is};
use anyhow::{anyhow, Context as _, Result};
use backend::{backend_caps, caps_for_client, sieve_line, SieveLogin};
use preauth::{
    parse_authenticate_line, read_continuation, read_sasl_string, read_string_arg, sieve_string,
};
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

/// The reply to `NOOP` (`line`, its string argument read from `stream` if
/// it is a literal). With an argument the OK carries it as the TAG response
/// code (RFC 5804 §2.13); a malformed argument gets NO. A broken connection
/// shows at the next read.
async fn noop<S>(line: &str, stream: &mut S, idle: std::time::Duration) -> String
where
    S: tokio::io::AsyncRead + Unpin,
{
    let arg = line.get("NOOP".len()..).unwrap_or("");
    match read_string_arg(stream, arg, idle).await {
        Ok(None) => "OK \"NOOP completed.\"\r\n".to_string(),
        Ok(Some(tag)) => format!("OK (TAG {}) \"Done\"\r\n", sieve_string(&tag)),
        Err(_) => "NO \"Invalid NOOP argument\"\r\n".to_string(),
    }
}

/// Post-TLS SASL lines, chosen by the legacy gate (source address, SNI,
/// protocol). LOGIN is never offered: the proxy has no SASL LOGIN challenge
/// dialog for ManageSieve, only PLAIN.
const SASL_OAUTH_ONLY: &[u8] = b"\"SASL\" \"XOAUTH2 OAUTHBEARER\"\r\n";
const SASL_FULL: &[u8] = b"\"SASL\" \"XOAUTH2 OAUTHBEARER PLAIN\"\r\n";

/// The post-TLS capability lines for the client (each with CRLF, without
/// the final OK) from the backend's: SASL rewritten to what this endpoint
/// offers (`plain`: the legacy gate allows PLAIN), STARTTLS dropped (already
/// done) and UNAUTHENTICATE dropped (the proxy does not offer it; after the
/// login the relay's guard keeps it from the backend, see `wire::guard`).
fn rewrite_caps(be_caps: &[String], plain: bool) -> String {
    let mut caps = String::new();
    for cap_line in be_caps {
        if backend::is_cap(cap_line, "STARTTLS") || backend::is_cap(cap_line, "UNAUTHENTICATE") {
            continue;
        }
        if backend::is_cap(cap_line, "SASL") {
            let line = if plain { SASL_FULL } else { SASL_OAUTH_ONLY };
            caps.push_str(std::str::from_utf8(line).unwrap_or_default());
        } else {
            caps.push_str(cap_line);
            caps.push_str("\r\n");
        }
    }
    caps
}

/// The ManageSieve listener's own settings and capability cache.
pub struct Sieve {
    /// TLS after STARTTLS with ALPN `managesieve`.
    pub acceptor: crate::server::tls::Acceptor,
    /// Every backend a credential can be routed to (`route::Pick::index`).
    pub backends: Vec<Arc<Upstream>>,
    /// How long cached backend capabilities are relayed.
    pub caps_ttl: std::time::Duration,
}

/// A ManageSieve backend and its capabilities; a reload that keeps the
/// backend keeps them.
pub struct Upstream {
    pub pool: crate::pool::Pool,
    pub caps: Arc<CapsCache>,
}

/// Probe the backend's capabilities once at startup, so the first
/// greetings need not wait for a probe. A failure is logged and counted
/// like any failed probe and does not stop the start; the next greeting
/// after the retry spacing probes again (D-SIEVE-1).
pub async fn probe_at_startup(ctx: Arc<Ctx<Sieve>>) {
    let sieve = &ctx.protocol;
    for up in &sieve.backends {
        if let Err(e) = backend_caps(up, sieve.caps_ttl, &ctx.tuning).await {
            tracing::warn!(target: crate::obs::target::SIEVE, backend=%up.pool.id, error=%format!("{e:#}"), "sieve backend capabilities not available at startup");
        }
    }
}

pub async fn handle(
    mut tcp: TcpStream,
    peer: SocketAddr,
    ctx: Arc<Ctx<Sieve>>,
    mut permit: ConnPermit,
) -> Result<()> {
    let _conn = crate::obs::metrics::ConnGuard::open(crate::obs::metrics::Proto::Sieve);
    crate::obs::metrics::record_listener_connection(crate::obs::metrics::Listener::Sieve);
    // The address the client dialed, for the PROXY header; `peer` as the
    // fallback keeps both ends in one address family.
    let local = tcp.local_addr().unwrap_or(peer);
    let (internal, scope) = ctx.scope(peer);
    // One pre-auth budget across the plaintext dialog, the TLS handshake and
    // AUTHENTICATE (see `Tuning::preauth`).
    let tuning = &ctx.tuning;
    let preauth_until = Instant::now() + tuning.preauth;

    // Capability greeting, then STARTTLS, LOGOUT, CAPABILITY (the greeting
    // again) and NOOP (RFC 5804 §2); AUTHENTICATE gets ENCRYPT-NEEDED,
    // everything else NO.
    let starttls = deadline_at(preauth_until, tuning.preauth, "sieve pre-TLS", async {
        // The greeting must list SIEVE (RFC 5804 §1.7). Right after startup
        // no probe has run yet: the first clients wait for one (a single
        // probe for all of them).
        let (backends, ttl) = (&ctx.protocol.backends, ctx.protocol.caps_ttl);
        let mut sieve = sieve_line(backends);
        if sieve.is_none() && caps_for_client(backends, ttl, tuning).await.is_ok() {
            sieve = sieve_line(backends);
        }
        let greeting = caps_plain(ctx.hostname(), sieve.as_deref());
        tcp.write_all(greeting.as_bytes()).await?;
        let mut cmds = 0usize;
        loop {
            cmds += 1;
            if cmds > tuning.max_preauth_commands {
                // RFC 5804 §1.2: BYE when the server closes the connection.
                tcp.write_all(b"BYE \"Too many commands before STARTTLS\"\r\n")
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
            } else if verb_is(&line, "CAPABILITY") {
                tcp.write_all(greeting.as_bytes()).await?;
            } else if verb_is(&line, "NOOP") {
                let reply = noop(&line, &mut tcp, tuning.idle).await;
                tcp.write_all(reply.as_bytes()).await?;
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
        async { Ok(ctx.protocol.acceptor.accept(tcp).await?) },
    )
    .await
    {
        Ok(c) => c,
        Err(e) => {
            crate::obs::metrics::record_preauth_abort(crate::obs::metrics::Proto::Sieve, internal);
            return Err(e);
        }
    };

    // The TLS session ends with close_notify whichever way the dialog
    // ends (RFC 8314 §3.4); the relay closes its own.
    let result: Result<()> = async {
            // Source IP + SNI decide whether password auth is offered — same legacy
            // rules as IMAP/SMTP. External clients and forged-SNI attackers stay
            // OAuth-only unless a rule names their network.
            let sni = client_tls.get_ref().1.server_name().map(|s| s.to_string());
            let pw_mechs = crate::auth::legacy::MechSet {
                plain: ctx.password_mechs(Proto::Sieve, sni.as_deref(), peer).plain,
                login: false,
            };
            let session = auth::Session {
                proto: Proto::Sieve,
                listener: crate::obs::metrics::Listener::Sieve,
                peer,
                internal,
                scope,
                sni: sni.as_deref(),
                pw_mechs,
                preauth_until,
            };

            // Relay the backend's post-TLS capabilities, rewriting SASL to what
            // this endpoint allows and dropping STARTTLS (already done).
            let be_caps = match deadline_at(
                preauth_until,
                tuning.preauth,
                "sieve backend capabilities",
                caps_for_client(&ctx.protocol.backends, ctx.protocol.caps_ttl, tuning),
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
            let caps = rewrite_caps(&be_caps, pw_mechs.plain);
            client_tls.write_all(caps.as_bytes()).await?;
            client_tls
                .write_all(b"OK \"TLS negotiation successful.\"\r\n")
                .await?;

            // Read commands until AUTHENTICATE and parse the credential, inside the
            // pre-auth budget. RFC 5804 allows CAPABILITY, NOOP and LOGOUT before
            // authenticating. After a NO the client may try again (RFC 5804
            // §2.1), up to `limits.max_auth_attempts` attempts, each judged and
            // counted on its own. Every other way this ends without a credential
            // is a pre-auth abort; LOGOUT is a clean end.
            let mut attempts = auth::Attempts::new(tuning.max_auth_attempts);
            let mut cmds = 0usize;
            loop {
            let (mech, outcome) = match deadline_at(
                preauth_until,
                tuning.preauth,
                "sieve post-TLS auth",
                async {
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
                            let reply = noop(&line, &mut client_tls, tuning.idle).await;
                            client_tls.write_all(reply.as_bytes()).await?;
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
                    // No SASL LOGIN dialog for ManageSieve: PLAIN is its password
                    // mechanism.
                    let password = match Mechanism::parse(&mech) {
                        Some(Mechanism::XOAuth2 | Mechanism::OAuthBearer) => false,
                        Some(Mechanism::Plain) => true,
                        Some(Mechanism::Login) | None => {
                            client_tls
                                .write_all(b"NO \"Authentication mechanism not supported\"\r\n")
                                .await?;
                            return Err(auth::answered(anyhow!(
                                "unsupported sieve mechanism {}",
                                crate::obs::authlog::sanitize(&mech)
                            )));
                        }
                    };
                    let ir = match ir {
                        Some(ir) => ir,
                        // Never ask for a password the endpoint does not take.
                        None if password && !pw_mechs.plain => {
                            client_tls
                                .write_all(
                                    b"NO \"password authentication not available on this endpoint\"\r\n",
                                )
                                .await?;
                            return Err(anyhow::Error::new(auth::Withheld {
                                mech,
                                user: String::new(),
                            }));
                        }
                        None => match read_continuation(&mut client_tls, tuning.idle).await {
                            Ok(ir) => ir,
                            Err(e) => {
                                let _ = client_tls
                                    .write_all(b"NO \"Invalid authentication response\"\r\n")
                                    .await;
                                // A cancel ends the exchange cleanly; a malformed
                                // string may leave its octets unread.
                                return Err(if e.is::<crate::auth::sasl::BadResponse>() {
                                    auth::answered(e)
                                } else {
                                    e
                                });
                            }
                        },
                    };
                    let kind = if password {
                        crate::auth::sasl::parse_plain(&ir)
                            .map(|(user, pass)| {
                                (
                                    crate::auth::sasl::ClientAuthKind::Password { user, pass },
                                    None,
                                )
                            })
                            .map_err(|e| anyhow!("plain parse: {e}"))
                    } else {
                        crate::auth::sasl::parse_sasl(&mech, &ir)
                            .map(|c| {
                                let kind = crate::auth::sasl::ClientAuthKind::OAuth {
                                    user: c.user,
                                    token: c.token,
                                };
                                (kind, c.host)
                            })
                            .context("sasl parse")
                    };
                    match kind {
                        Ok((k, host)) => Ok(Some((mech, k, host))),
                        // Answered below with the error result.
                        Err(e) if e.is::<Discovery>() => Err(e),
                        Err(e) => {
                            client_tls
                                .write_all(b"NO \"Invalid authentication response\"\r\n")
                                .await?;
                            Err(auth::answered(e))
                        }
                    }
                },
            )
            .await
            {
                // Gate, token validation and backend login. The backend is
                // contacted only with a credential that passed the local checks.
                Ok(Some((mech, kind, host))) => {
                    if auth::source_blocked(&ctx, &session) {
                        return Err(auth::blocked_source());
                    }
                    let login = SieveLogin {
                        backends: &ctx.protocol.backends,
                        tuning,
                        origin: (peer, local),
                    };
                    let outcome =
                        auth::authorize(&ctx, &session, &mech, &kind, host.as_deref(), &login).await;
                    // The credential is not needed after the login: dropping it
                    // zeroizes it before the splice, which can last for hours.
                    drop(kind);
                    (mech, outcome)
                }
                Ok(None) => return Ok(()),
                Err(e) => {
                    // Answered already; recorded like a blocked password.
                    if let Some(w) = e.downcast_ref::<auth::Withheld>() {
                        let error = auth::withheld(&ctx, &session, w);
                        if let Err(e) = attempts.refused(&session, error, true) {
                            let _ = client_tls.flush().await;
                            return Err(e);
                        }
                        continue;
                    }
                    // Answered already, without a credential.
                    if e.is::<auth::Retryable>() {
                        if let Err(e) = attempts.refused(&session, e, false) {
                            let _ = client_tls.flush().await;
                            return Err(e);
                        }
                        continue;
                    }
                    // Answered with the error result like a rejected token.
                    if let Some(d) = e.downcast_ref::<Discovery>() {
                        auth::discovery(&session, d);
                        let asked = auth::Outcome::BadToken(TokenError::Invalid(d.to_string()));
                        (d.mech.clone(), asked)
                    } else {
                        // No further credential (EOF, timeout, unparsable
                        // AUTHENTICATE): a `protocol` record unless the client
                        // gave up after a refusal.
                        let _ = client_tls.flush().await;
                        return Err(attempts.ended(&session, e));
                    }
                }
            };

            const FAILED: &str = "NO \"Authentication failed\"";
            let unavailable = matches!(outcome, auth::Outcome::Unavailable(_));
            let (reply, error) = match outcome {
                auth::Outcome::Ok {
                    conn: (mut be, be_reply),
                    identity,
                    issuer,
                } => {
                    permit.authenticated();
                    client_tls.write_all(be_reply.as_bytes()).await?;
                    client_tls.write_all(b"\r\n").await?;
                    tracing::info!(target: crate::obs::target::SIEVE, user=%crate::obs::authlog::sanitize(&identity), mech=%mech, issuer=%issuer.as_deref().unwrap_or(""), "sieve auth ok; splicing");
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
            // An outage ends the session: another attempt would meet it too.
            if unavailable {
                return Err(error);
            }
            attempts.refused(&session, error, true)?;
        }
    }
    .await;
    crate::wire::close(&mut client_tls).await;
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    /// NOOP with a string argument echoes it as the TAG response code (RFC
    /// 5804 §2.13), escaped; a literal argument is read; anything malformed
    /// gets NO.
    #[tokio::test]
    async fn noop_tag() {
        use std::io::Cursor;
        let idle = std::time::Duration::from_secs(30);
        for (line, rest, want) in [
            ("NOOP", "", "OK \"NOOP completed.\"\r\n"),
            ("noop \"x-42\"", "", "OK (TAG \"x-42\") \"Done\"\r\n"),
            ("NOOP \"a\\\"b\"", "", "OK (TAG \"a\\\"b\") \"Done\"\r\n"),
            ("NOOP {3+}", "a\\b\r\n", "OK (TAG \"a\\\\b\") \"Done\"\r\n"),
            ("NOOP x", "", "NO \"Invalid NOOP argument\"\r\n"),
            ("NOOP \"x\" y", "", "NO \"Invalid NOOP argument\"\r\n"),
            ("NOOP {3}", "abc\r\n", "NO \"Invalid NOOP argument\"\r\n"),
        ] {
            let mut s = Cursor::new(rest.as_bytes().to_vec());
            assert_eq!(noop(line, &mut s, idle).await, want, "{line}");
        }
        let long = "x".repeat(1025);
        assert_eq!(sieve_string(&long), format!("{{1025}}\r\n{long}"));
        assert_eq!(sieve_string("a\r\nb"), "{4}\r\na\r\nb");
    }

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
