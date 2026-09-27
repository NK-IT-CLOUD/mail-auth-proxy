//! Authentication: the legacy (password) gate, token validation, SASL
//! parsing, and `authorize`, the one path every protocol takes from a
//! presented credential to a logged-in backend connection.

pub mod account;
pub mod legacy;
pub mod policy;
pub mod sasl;
pub mod token;

use crate::obs::authlog::{self, AuthEvent, Reason};
use crate::obs::metrics::{self, Proto};
use crate::server::Shared;
use crate::wire::line::LineError;
use sasl::ClientAuthKind;
use std::future::Future;
use std::net::SocketAddr;
use token::TokenError;

/// Why a backend login failed.
#[derive(Debug)]
pub enum BackendError {
    /// The backend answered the credential with a rejection (its reply line):
    /// a real authentication verdict.
    Rejected(String),
    /// Anything else (connect, TLS, protocol, a temporary-failure reply): the
    /// backend is unavailable. This must not be counted or logged as a failed
    /// login: during an outage that would feed CrowdSec bans against
    /// legitimate users.
    Unavailable(anyhow::Error),
}

impl std::fmt::Display for BackendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BackendError::Rejected(reply) => write!(f, "backend auth rejected: {reply}"),
            BackendError::Unavailable(e) => std::fmt::Display::fmt(e, f),
        }
    }
}

/// Transparent for `Unavailable`: an error chain shows the cause once.
impl std::error::Error for BackendError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            BackendError::Rejected(_) => None,
            BackendError::Unavailable(e) => e.source(),
        }
    }
}

impl From<anyhow::Error> for BackendError {
    fn from(e: anyhow::Error) -> Self {
        BackendError::Unavailable(e)
    }
}

impl From<std::io::Error> for BackendError {
    fn from(e: std::io::Error) -> Self {
        BackendError::Unavailable(e.into())
    }
}

impl From<LineError> for BackendError {
    fn from(e: LineError) -> Self {
        BackendError::Unavailable(e.into())
    }
}

/// Why a session ended after its credential was refused (blocked, denied,
/// bad token, wrong authzid, rejected by the backend). The `authresult` line
/// has already recorded the refusal, so the listener logs the session end
/// at debug instead of a second warning.
#[derive(Debug)]
pub struct Refused(String);

/// The session-ending error for a refusal, with its detail for the debug log.
pub fn refused(why: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(Refused(why.into()))
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Refused {}

/// What the backend is asked to log in with.
pub enum BackendCredential<'a> {
    /// A validated token, forwarded as XOAUTH2 for `identity`, the token's
    /// verified identity claim.
    Token { identity: &'a str, token: &'a str },
    /// The client's password, forwarded as PLAIN; the backend validates it.
    Password { user: &'a str, pass: &'a str },
}

/// A protocol's backend login with the client's own credential (never a
/// master credential).
pub trait BackendLogin {
    /// The logged-in backend connection, plus whatever the protocol relays
    /// from the backend's reply.
    type Conn;

    fn login(
        &self,
        credential: BackendCredential<'_>,
    ) -> impl Future<Output = Result<Self::Conn, BackendError>> + Send;
}

/// Largest password the proxy forwards. Longer ones are refused before the
/// legacy gate like a wrong password (`oversize`): a backend could answer an
/// oversized credential with a protocol error instead of a verdict (Postfix
/// `500` beyond `smtpd_sasl_response_limit`), and an instant retry-later for
/// accounts that pass the gate, next to a delayed rejection for those that do
/// not, would tell them apart.
pub const MAX_PASSWORD: usize = 1024;

/// Largest bearer token the proxy validates; a longer one is a `bad_token`.
pub const MAX_TOKEN: usize = 16384;

/// The facts about a connection that decide and label an auth attempt.
pub struct Session<'a> {
    pub proto: Proto,
    pub peer: SocketAddr,
    /// Source inside `scope.internal_networks`.
    pub internal: bool,
    /// `internal` / `external`, for logs and metrics.
    pub scope: &'static str,
    /// The TLS server name the client asked for.
    pub sni: Option<&'a str>,
    /// The password mechanisms the legacy gate offers on this connection
    /// (network + SNI + protocol).
    pub pw_mechs: legacy::MechSet,
}

/// How `authorize` ended. Logging and metrics are done; the protocol only
/// answers the client.
pub enum Outcome<C> {
    /// Logged in as `identity`.
    Ok { conn: C, identity: String },
    /// A password on a connection that offers no password mechanism (or not
    /// this one). It was not forwarded.
    Blocked,
    /// The legacy gate refused the password (user not allowed, unknown
    /// domain or account, throttled). It was not forwarded; the client must
    /// get the same answer as for `Rejected`.
    Denied,
    /// The token failed validation; the backend was not contacted.
    BadToken(TokenError),
    /// The token is valid, but the client asked to act as another identity
    /// (its SASL authorisation identity). The backend was not contacted.
    WrongAuthzid,
    /// The backend rejected the credential (its reply).
    Rejected(String),
    /// The backend (or the account check) is unavailable; not a failed login.
    Unavailable(anyhow::Error),
}

/// Gate, token validation and backend login for one presented credential,
/// with exactly one `authresult` line and the matching metrics.
///
/// OAuth (the SSO gate): the token is validated locally; a failure is
/// `bad_token` with the client's SASL user and the backend is not contacted
/// (an unknown `kid` is an outage instead when the last on-demand JWKS
/// refresh failed);
/// a client SASL user (authzid) that names another identity than the
/// token's is `authzid_mismatch`, also without backend contact; otherwise the
/// backend's verdict under the token's identity claim.
///
/// Legacy (PLAIN/LOGIN, no SSO): the backend checks the password; the proxy
/// only forwards it through the legacy gate:
///
/// - a mechanism the connection does not offer: `blocked_endpoint`, answered
///   as "not available here";
/// - refused by the gate (`blocked_endpoint` for a user no rule allows,
///   `unknown_domain`, `unknown_account`, `throttled`) or by the backend
///   (`backend_reject`): the same answer to the client. A refusal is
///   answered as late as a typical backend rejection (the larger of
///   `legacy.failure_delay_ms` and the median of the recent rejection
///   latencies of the protocol), a rejection no earlier than
///   `failure_delay_ms`; both get the same random jitter, so neither text nor
///   timing tells the cases apart;
/// - the backend's `ok`, logged with the rule that let the password through.
///
/// An unavailable backend or account check: no `authresult` line and no
/// failed attempt, only `backend_errors`. On the password path it is answered
/// no earlier than a refusal (same deadline and jitter); on the token path
/// at once, since the gate there is the token, not the account.
pub async fn authorize<B: BackendLogin>(
    ctx: &Shared,
    s: &Session<'_>,
    mech: &str,
    credential: &ClientAuthKind,
    backend: &B,
) -> Outcome<B::Conn> {
    let event = |user: &str, reason: Reason, pwfp: &str, rule: &str| {
        AuthEvent {
            proto: s.proto,
            scope: s.scope,
            mech,
            user,
            peer: s.peer.ip(),
            reason,
            pwfp,
            rule,
        }
        .record();
        metrics::record_auth(s.proto, s.internal, mech, reason == Reason::Ok);
        metrics::record_refusal(s.proto, reason);
    };
    match credential {
        ClientAuthKind::OAuth { user, token } => {
            let validated = if token.len() > MAX_TOKEN {
                Err(TokenError::Invalid(format!(
                    "token larger than {MAX_TOKEN} bytes"
                )))
            } else {
                ctx.validator.validate_fresh(token).await
            };
            let identity = match validated {
                Ok(email) => {
                    metrics::record_token_validate(true);
                    email
                }
                // The keys could not be checked for the token's kid: no
                // verdict on the token, so not a failed login.
                Err(e @ TokenError::KeysStale) => {
                    metrics::record_backend_error(s.proto);
                    return Outcome::Unavailable(anyhow::Error::new(e).context("token keys"));
                }
                Err(e) => {
                    metrics::record_token_validate(false);
                    event(user, Reason::BadToken, "", "");
                    return Outcome::BadToken(e);
                }
            };
            if !sasl::authzid_allowed(user, &identity) {
                // RFC 4422 §3.6: not authorised to act as the requested
                // authzid. Logged with the identity the client asked for.
                event(user, Reason::AuthzidMismatch, "", "");
                return Outcome::WrongAuthzid;
            }
            let login = BackendCredential::Token {
                identity: &identity,
                token,
            };
            match backend.login(login).await {
                Ok(conn) => {
                    event(&identity, Reason::Ok, "", "");
                    metrics::record_upstream_forward(s.proto);
                    Outcome::Ok { conn, identity }
                }
                Err(BackendError::Rejected(reply)) => {
                    event(&identity, Reason::BackendReject, "", "");
                    Outcome::Rejected(reply)
                }
                Err(BackendError::Unavailable(e)) => {
                    metrics::record_backend_error(s.proto);
                    Outcome::Unavailable(e)
                }
            }
        }
        ClientAuthKind::Password { user, pass } => {
            let started = tokio::time::Instant::now();
            // The credential of a refused password was parsed only to log the
            // attempt (who, from where, which password fingerprint) for CrowdSec.
            let pwfp = authlog::pw_fingerprint(Some(pass));
            if !s.pw_mechs.allows(mech) {
                event(user, Reason::BlockedEndpoint, &pwfp, "");
                return Outcome::Blocked;
            }
            let gate = &ctx.legacy;
            if pass.len() > MAX_PASSWORD {
                // Before the gate, so the answer does not depend on the
                // account; answered like any refusal.
                event(user, Reason::Oversize, &pwfp, "");
                tokio::time::sleep_until(gate.refusal_deadline(s.proto, started)).await;
                return Outcome::Denied;
            }
            let rule = match gate.check(s.proto, s.peer.ip(), s.sni, mech, user).await {
                legacy::Verdict::Pass { rule } => rule,
                legacy::Verdict::Deny { reason, rule } => {
                    event(user, reason, &pwfp, rule);
                    tokio::time::sleep_until(gate.refusal_deadline(s.proto, started)).await;
                    return Outcome::Denied;
                }
                legacy::Verdict::Unavailable(e) => {
                    metrics::record_backend_error(s.proto);
                    // Padded like a refusal: an instant retry-later would
                    // tell accounts that reach the check from those the
                    // gate refuses earlier.
                    tokio::time::sleep_until(gate.refusal_deadline(s.proto, started)).await;
                    return Outcome::Unavailable(e.context("legacy account check"));
                }
            };
            match backend
                .login(BackendCredential::Password { user, pass })
                .await
            {
                Ok(conn) => {
                    gate.backend_accepted(user);
                    event(user, Reason::Ok, "", rule);
                    metrics::record_upstream_forward(s.proto);
                    Outcome::Ok {
                        conn,
                        identity: user.clone(),
                    }
                }
                Err(BackendError::Rejected(reply)) => {
                    let answer_at = gate.rejected_deadline(s.proto, started);
                    gate.backend_rejected(user);
                    event(user, Reason::BackendReject, &pwfp, rule);
                    tokio::time::sleep_until(answer_at).await;
                    Outcome::Rejected(reply)
                }
                Err(BackendError::Unavailable(e)) => {
                    metrics::record_backend_error(s.proto);
                    // Only accounts that passed the gate get here: padded
                    // like a refusal, so the timing does not tell them apart.
                    tokio::time::sleep_until(gate.refusal_deadline(s.proto, started)).await;
                    Outcome::Unavailable(e)
                }
            }
        }
    }
}
