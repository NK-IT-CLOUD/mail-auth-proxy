//! Authentication: the legacy (password) gate, token validation, SASL
//! parsing, and `authorize`, the one path every protocol takes from a
//! presented credential to a logged-in backend connection.

pub mod account;
pub mod discovery;
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

/// The outage of a backend that offers `UNAUTHENTICATE` (RFC 8437, RFC 5804
/// §2.14.1). The relay is blind: a client that logged in with a token could
/// return to the unauthenticated state and try passwords for any account
/// directly against the backend, past the password gate and the rate limit.
pub const UNAUTHENTICATE_OFFERED: &str = "backend offers UNAUTHENTICATE (RFC 8437): a client \
     could leave its login and try passwords past the password gate; disable it on the backend";

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
/// not, would tell them apart. For the same reason a protocol error answering
/// a password (IMAP `BAD`, SMTP `50x`) counts as a rejection; with this cap
/// that is defence in depth.
pub const MAX_PASSWORD: usize = 1024;

/// Largest bearer token the proxy validates; a longer one is a `bad_token`.
pub const MAX_TOKEN: usize = 16384;

/// The backend a protocol's credentials go to, by name: each protocol has
/// one, named after the section that configures it. Keys the refusal timing
/// of the legacy gate (`legacy::Gate::with_backends`).
pub fn backend_name(proto: Proto) -> &'static str {
    match proto {
        Proto::Imap => "imap",
        Proto::Smtp => "submission",
        Proto::Sieve => "sieve",
    }
}

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
    /// End of the connection's pre-auth budget (`Tuning::preauth`). Token
    /// validation, the legacy gate and the backend login must finish by
    /// then; the padding of a refused password may run past it.
    pub preauth_until: tokio::time::Instant,
}

/// A backend login that must finish within the pre-auth budget; one that
/// does not is an outage.
async fn within_budget<C>(
    ctx: &Shared,
    s: &Session<'_>,
    login: impl Future<Output = Result<C, BackendError>>,
) -> Result<C, BackendError> {
    tokio::time::timeout_at(s.preauth_until, login)
        .await
        .unwrap_or_else(|_| {
            Err(BackendError::Unavailable(budget_used_up(
                ctx,
                "the backend login",
            )))
        })
}

/// The pre-auth budget ran out during `what`: an outage, not a verdict.
fn budget_used_up(ctx: &Shared, what: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "pre-auth budget of {}s used up during {what}",
        ctx.tuning.preauth.as_secs()
    )
}

/// The `authresult` line of an attempt, its metrics and the rate limit.
#[allow(clippy::too_many_arguments)]
fn record(
    ctx: &Shared,
    s: &Session<'_>,
    mech: &str,
    credential: &ClientAuthKind,
    user: &str,
    reason: Reason,
    pwfp: &str,
    rule: &str,
) {
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
    ctx.ratelimit
        .failure(s.proto, s.scope, s.peer.ip(), reason, credential);
}

/// A password mechanism the connection does not offer, chosen without an
/// initial response that carries the password. The client is refused at once
/// instead of being asked for a password that would never be used. `user` is
/// the login if the client sent it (SASL LOGIN initial response).
#[derive(Debug)]
pub struct Withheld {
    pub mech: String,
    pub user: String,
}

impl std::fmt::Display for Withheld {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "password mechanism {} not offered on this connection",
            authlog::sanitize(&self.mech)
        )
    }
}

impl std::error::Error for Withheld {}

/// Record a `Withheld` attempt like a password `authorize` blocks
/// (`blocked_endpoint`), without a password fingerprint, and return the
/// session-ending error.
pub fn withheld(ctx: &Shared, s: &Session<'_>, w: &Withheld) -> anyhow::Error {
    let credential = ClientAuthKind::Password {
        user: w.user.clone(),
        pass: Default::default(),
    };
    record(
        ctx,
        s,
        &w.mech,
        &credential,
        &w.user,
        Reason::BlockedEndpoint,
        "",
        "",
    );
    refused(format!(
        "password auth blocked on OAuth-only endpoint (scope={})",
        s.scope
    ))
}

/// Record a discovery request (an OAuth response with an empty `auth`
/// value, RFC 7628 §4.3). It carries no credential, so the `authresult` line
/// is `protocol`, with the mechanism and the SASL user the client named,
/// and it is no failed attempt: neither the auth metrics nor the rate limit
/// count it. The protocol answers it with the error result, like a rejected
/// token.
pub fn discovery(s: &Session<'_>, d: &sasl::Discovery) {
    AuthEvent {
        proto: s.proto,
        scope: s.scope,
        mech: &d.mech,
        user: &d.user,
        peer: s.peer.ip(),
        reason: Reason::Protocol,
        pwfp: "",
        rule: "",
    }
    .record();
}

/// An authentication command that ended without a credential (an
/// unsupported mechanism, a cancelled or undecodable response, one that holds
/// no valid credential). It was answered and read to its end, so the client
/// may try again on the same connection. Attached as context (`answered`).
#[derive(Debug)]
pub struct Retryable;

impl std::fmt::Display for Retryable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("authentication attempt without a credential")
    }
}

/// `e`, the answered failure of an authentication command, marked
/// `Retryable` unless reading or writing the client failed: after a read
/// error, a timeout or an oversized line the position in the client's data
/// is lost, and the connection must end.
pub fn answered(e: anyhow::Error) -> anyhow::Error {
    if e.chain()
        .any(|c| c.is::<LineError>() || c.is::<std::io::Error>())
    {
        e
    } else {
        e.context(Retryable)
    }
}

/// The authentication attempts of one connection, at most
/// `limits.max_auth_attempts`. Each attempt is judged, logged and counted by
/// the rate limit on its own, like one on a new connection, within the
/// connection's one pre-auth budget.
pub struct Attempts {
    left: u32,
    /// A credential (or a discovery request) was presented.
    presented: bool,
    /// Why the last refused attempt failed.
    last: Option<anyhow::Error>,
}

impl Attempts {
    pub fn new(max: u32) -> Attempts {
        Attempts {
            left: max.max(1),
            presented: false,
            last: None,
        }
    }

    /// An attempt was refused and answered; `error` says why, `presented`
    /// whether it carried a credential or a discovery request. A `Retryable`
    /// one without is logged here as `protocol`. `Ok` if the client may try
    /// again, else the error that ends the session.
    pub fn refused(
        &mut self,
        s: &Session<'_>,
        error: anyhow::Error,
        presented: bool,
    ) -> Result<(), anyhow::Error> {
        if !presented {
            no_credential(s);
        }
        self.presented |= presented;
        self.left = self.left.saturating_sub(1);
        if self.left == 0 {
            self.abort_if_nothing_presented(s);
            return Err(error);
        }
        self.last = Some(error);
        Ok(())
    }

    /// The dialog ended with `e` before another credential (a close, a
    /// timeout, a command flood, a malformed command). A close at a line
    /// boundary after a refused attempt is the client giving up: the session
    /// ends with that refusal and no further line. Anything else is logged
    /// as `protocol`. Either way the connection is a pre-auth abort if no
    /// credential was ever presented.
    pub fn ended(&mut self, s: &Session<'_>, e: anyhow::Error) -> anyhow::Error {
        let clean_close = e
            .chain()
            .any(|c| c.downcast_ref::<LineError>().is_some_and(LineError::is_eof));
        self.abort_if_nothing_presented(s);
        match self.last.take() {
            Some(last) if clean_close => last,
            _ => {
                no_credential(s);
                e
            }
        }
    }

    fn abort_if_nothing_presented(&self, s: &Session<'_>) {
        if !self.presented {
            metrics::record_preauth_abort(s.proto, s.internal);
        }
    }
}

/// The `protocol` line of an attempt or a dialog that presented no
/// credential. Not a failed login: neither the auth metrics nor the rate
/// limit count it.
fn no_credential(s: &Session<'_>) {
    AuthEvent {
        proto: s.proto,
        scope: s.scope,
        mech: "other",
        user: "",
        peer: s.peer.ip(),
        reason: Reason::Protocol,
        pwfp: "",
        rule: "",
    }
    .record();
}

/// True if the rate limit blocked the source after the connection was
/// accepted (by this connection's failures or another's). The credential is
/// then not judged: the connection closes without an answer, like one the
/// block refuses at accept.
pub fn source_blocked(ctx: &Shared, s: &Session<'_>) -> bool {
    let blocked = ctx.ratelimit.is_blocked(s.peer.ip());
    if blocked {
        metrics::record_ratelimit_block(s.proto);
    }
    blocked
}

/// The session-ending error of a blocked source (`source_blocked`).
pub fn blocked_source() -> anyhow::Error {
    refused("source blocked by the auth rate limit, credential not judged")
}

/// How `authorize` ended. Logging and metrics are done; the protocol only
/// answers the client, then ends a failed session with an error for the
/// journal. The answer is best effort: a client that is already gone must not
/// replace the reason (an outage's cause above all) with a write error.
pub enum Outcome<C> {
    /// Logged in as `identity`. `issuer`: the configured issuer whose key
    /// verified the token; `None` for a password.
    Ok {
        conn: C,
        identity: String,
        issuer: Option<String>,
    },
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
/// `host` is the OAUTHBEARER `host` of the response, if any.
///
/// OAuth (the SSO gate): an OAUTHBEARER `host` that is not the SNI name is
/// `bad_token`; the token is validated locally; a failure is
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
/// Token validation, the account check and the backend login run within the
/// pre-auth budget; one that does not finish by `Session::preauth_until` is
/// unavailable.
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
    host: Option<&str>,
    backend: &B,
) -> Outcome<B::Conn> {
    let event = |user: &str, reason: Reason, pwfp: &str, rule: &str| {
        record(ctx, s, mech, credential, user, reason, pwfp, rule)
    };
    match credential {
        ClientAuthKind::OAuth { user, token } => {
            // RFC 7628 §3.2: a `host` the server also knows by other means
            // MUST match. With SNI the server knows the name the client
            // connected to; without, it does not (an IP address, an alias),
            // and `port` differs behind NAT or a load balancer. A mismatch
            // is refused like any rejected token.
            let wrong_host = host
                .zip(s.sni)
                .filter(|(host, sni)| !sasl::host_matches(host, sni));
            let validated = if let Some((host, sni)) = wrong_host {
                Err(TokenError::Invalid(format!(
                    "OAUTHBEARER host {} is not the server name {} (RFC 7628 §3.2)",
                    authlog::sanitize(host),
                    authlog::sanitize(sni)
                )))
            } else if token.len() > MAX_TOKEN {
                Err(TokenError::Invalid(format!(
                    "token larger than {MAX_TOKEN} bytes"
                )))
            } else {
                // In a task of its own: a JWKS refresh the budget cuts short
                // still completes and records its result, so the spacing of
                // on-demand refreshes holds while an IdP is slow.
                let validator = ctx.validator.clone();
                let token = zeroize::Zeroizing::new(String::from(token.as_str()));
                let validation =
                    tokio::spawn(async move { validator.validate_fresh(&token).await });
                match tokio::time::timeout_at(s.preauth_until, validation).await {
                    Ok(Ok(validated)) => validated,
                    Ok(Err(e)) => {
                        metrics::record_backend_error(s.proto);
                        return Outcome::Unavailable(
                            anyhow::Error::new(e).context("token validation"),
                        );
                    }
                    Err(_) => {
                        metrics::record_backend_error(s.proto);
                        return Outcome::Unavailable(budget_used_up(ctx, "token validation"));
                    }
                }
            };
            let token::Validated { identity, issuer } = match validated {
                Ok(validated) => {
                    metrics::record_token_validate(true);
                    validated
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
            let login_started = tokio::time::Instant::now();
            match within_budget(ctx, s, backend.login(login)).await {
                Ok(conn) => {
                    metrics::record_backend_login(s.proto, login_started.elapsed());
                    event(&identity, Reason::Ok, "", "");
                    metrics::record_upstream_forward(s.proto);
                    Outcome::Ok {
                        conn,
                        identity,
                        issuer: Some(issuer),
                    }
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
            let backend_name = backend_name(s.proto);
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
                tokio::time::sleep_until(gate.refusal_deadline(s.proto, None, started)).await;
                return Outcome::Denied;
            }
            let check = tokio::time::timeout_at(
                s.preauth_until,
                gate.check(s.proto, s.peer.ip(), s.sni, mech, user),
            )
            .await
            .unwrap_or_else(|_| {
                legacy::Verdict::Unavailable(budget_used_up(ctx, "the legacy account check"))
            });
            let (rule, turn) = match check {
                legacy::Verdict::Pass { rule, turn } => (rule, turn),
                legacy::Verdict::Deny {
                    reason,
                    rule,
                    for_backend,
                } => {
                    event(user, reason, &pwfp, rule);
                    let backend = for_backend.then_some(backend_name);
                    tokio::time::sleep_until(gate.refusal_deadline(s.proto, backend, started))
                        .await;
                    return Outcome::Denied;
                }
                legacy::Verdict::Unavailable(e) => {
                    metrics::record_backend_error(s.proto);
                    // Padded like a refusal: an instant retry-later would
                    // tell accounts that reach the check from those the
                    // gate refuses earlier.
                    tokio::time::sleep_until(gate.refusal_deadline(
                        s.proto,
                        Some(backend_name),
                        started,
                    ))
                    .await;
                    return Outcome::Unavailable(e.context("legacy account check"));
                }
            };
            let login_started = tokio::time::Instant::now();
            match within_budget(
                ctx,
                s,
                backend.login(BackendCredential::Password { user, pass }),
            )
            .await
            {
                Ok(conn) => {
                    metrics::record_backend_login(s.proto, login_started.elapsed());
                    gate.backend_accepted(user);
                    drop(turn);
                    event(user, Reason::Ok, "", rule);
                    metrics::record_upstream_forward(s.proto);
                    Outcome::Ok {
                        conn,
                        identity: user.clone(),
                        issuer: None,
                    }
                }
                Err(BackendError::Rejected(reply)) => {
                    let answer_at = gate.rejected_deadline(s.proto, backend_name, started);
                    gate.backend_rejected(user);
                    drop(turn);
                    event(user, Reason::BackendReject, &pwfp, rule);
                    tokio::time::sleep_until(answer_at).await;
                    Outcome::Rejected(reply)
                }
                Err(BackendError::Unavailable(e)) => {
                    drop(turn);
                    metrics::record_backend_error(s.proto);
                    // Only accounts that passed the gate get here: padded
                    // like a refusal, so the timing does not tell them apart.
                    tokio::time::sleep_until(gate.refusal_deadline(
                        s.proto,
                        Some(backend_name),
                        started,
                    ))
                    .await;
                    Outcome::Unavailable(e)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A failure the client caused with a complete command may be followed
    /// by another attempt; one that broke the read of the client's data may
    /// not.
    #[test]
    fn answered_marks_only_complete_exchanges() {
        assert!(answered(anyhow::anyhow!("unsupported mechanism")).is::<Retryable>());
        assert!(answered(anyhow::Error::new(sasl::BadResponse("cancel"))).is::<Retryable>());
        for e in [
            anyhow::Error::new(LineError::TooLong),
            anyhow::Error::new(LineError::Timeout(30)),
            anyhow::Error::new(LineError::Eof).context("sasl"),
            anyhow::Error::new(std::io::Error::other("reset")).context("write"),
        ] {
            let e = answered(e);
            assert!(!e.is::<Retryable>(), "{e:#}");
        }
    }
}
