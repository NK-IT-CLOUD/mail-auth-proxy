//! Entry points for the fuzz targets in `fuzz/`. Compiled only with
//! `--cfg fuzzing` (set by cargo-fuzz), never in a release build: thin
//! wrappers that make the pre-auth parsers reachable from outside the crate.
//! Not an API; see CONTRIBUTING.md, "Fuzzing".

use anyhow::Result;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use zeroize::Zeroizing;

pub use crate::auth::discovery::{classify, Answer, ErrorChallenge};
pub use crate::auth::legacy::MechSet;
pub use crate::auth::sasl::{
    authzid_allowed, build_plain, build_xoauth2, parse_plain, parse_sasl, ClientAuthKind, SaslCreds,
};
pub use crate::auth::token::{TokenError, Validator};
pub use crate::proto::imap::preauth::ClientAuth;
pub use crate::wire::line::{
    decode_login_field, read_client_line, read_line, read_sasl_response, verb_is, LineError,
};
pub use crate::wire::proxyproto::{ipv4_if_mapped, v2_header, v2_local_header};

/// Longest accepted protocol line (`wire::line`).
pub const MAX_LINE: usize = crate::wire::line::MAX_LINE;

/// The idle timeout the wrappers pass. In-memory streams never wait.
pub const IDLE: Duration = Duration::from_secs(30);

/// The IMAP pre-auth dialog up to a credential, with a further attempt
/// after each one that failed without a credential and may be retried, as
/// the listener does, up to the default attempt limit.
pub async fn imap_read_client_auth<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    pw: MechSet,
) -> Result<Option<ClientAuth>> {
    let tuning = crate::wire::Tuning::default();
    let mut cmds = 0;
    let mut attempts = tuning.max_auth_attempts;
    loop {
        let r =
            crate::proto::imap::preauth::read_client_auth(stream, pw, "fuzz", &tuning, &mut cmds)
                .await;
        attempts -= 1;
        match r {
            Err(e) if attempts > 0 && e.is::<crate::auth::Retryable>() => continue,
            r => return r,
        }
    }
}

/// The two astrings of an IMAP `LOGIN` command.
pub fn imap_parse_two_astrings(rest: &str) -> Result<(String, Zeroizing<String>)> {
    crate::proto::imap::preauth::parse_two_astrings(rest)
}

/// A ManageSieve `AUTHENTICATE` line; a literal, or the response to the
/// empty challenge without an initial response, is read from `stream`.
pub async fn sieve_parse_authenticate_line<S: AsyncRead + AsyncWrite + Unpin>(
    line: &str,
    stream: &mut S,
) -> Result<(String, Zeroizing<String>)> {
    use crate::proto::sieve::preauth;
    let (mech, ir) = preauth::parse_authenticate_line(line, stream, IDLE).await?;
    let ir = match ir {
        Some(ir) => ir,
        None => preauth::read_continuation(stream, IDLE).await?,
    };
    Ok((mech, ir))
}

/// The leading ManageSieve quoted string of `s` and the rest after it.
pub fn sieve_unquote_string(s: &str) -> Option<(String, &str)> {
    crate::proto::sieve::preauth::unquote_string(s)
}

/// An SMTP `AUTH` line and its credential dialog.
pub async fn smtp_read_auth<S: AsyncRead + AsyncWrite + Unpin>(
    line: &str,
    stream: &mut S,
) -> Result<(String, ClientAuthKind)> {
    let pw = MechSet {
        plain: true,
        login: true,
    };
    let challenge = ErrorChallenge::new(None, None);
    crate::proto::smtp::preauth::read_smtp_auth(line, stream, pw, challenge.base64(), IDLE)
        .await
        .map(|(mech, kind, _host)| (mech, kind))
}

/// True if the client may follow the failed attempt `e` with another.
pub fn is_retryable(e: &anyhow::Error) -> bool {
    e.is::<crate::auth::Retryable>()
}

/// The extensions relayed from the backend's EHLO reply.
pub const SMTP_EHLO_RELAYED: &[&str] = crate::proto::smtp::ehlo::RELAYED;

/// The keyword of an EHLO line, `None` if it is none.
pub fn smtp_ehlo_keyword(line: &str) -> Option<&str> {
    crate::proto::smtp::ehlo::ehlo_keyword(line)
}

/// The EHLO lines advertised to clients from the backend's extension lines.
pub fn smtp_ehlo_advertised(backend: &[String], only: Option<&[String]>) -> Vec<String> {
    crate::proto::smtp::ehlo::advertised(backend, only)
}

/// One (possibly multiline) SMTP reply from the backend.
pub async fn smtp_read_reply<S: AsyncRead + Unpin>(stream: &mut S) -> Result<(u16, Vec<String>)> {
    crate::proto::smtp::backend::read_smtp_reply(stream, IDLE).await
}

/// A validator with Keycloak rules for `issuer`/`audience` and the keys of `jwks`.
pub fn token_validator(jwks: serde_json::Value, issuer: &str, audience: &str) -> Result<Validator> {
    use crate::auth::token::Policy;
    Validator::from_parts(vec![(jwks, Policy::keycloak(issuer, audience))])
}

/// The unverified `iss` of a token.
pub fn token_unverified_iss(token: &str) -> Vec<String> {
    crate::auth::token::unverified_iss(token)
}

/// The claim checks after the signature, with Keycloak rules and a header of
/// type `typ`. `claims` is JSON; `None` if it is no JSON object.
pub fn token_check_claims(claims: &[u8], typ: Option<&str>) -> Option<Result<String, TokenError>> {
    let claims: serde_json::Map<String, serde_json::Value> = serde_json::from_slice(claims).ok()?;
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
    header.typ = typ.map(str::to_string);
    let policy = crate::auth::token::Policy::keycloak("https://sso.example.org", "mail");
    Some(crate::auth::token::check_claims(&claims, &header, &policy))
}

/// `notAfter` of a DER certificate as Unix seconds (`server::tls`).
pub fn tls_not_after(der: &[u8]) -> Option<u64> {
    crate::server::tls::not_after(der)
}

/// Send the RFC 7628 error challenge `prompt` and classify the answer line.
pub async fn discovery_complete_line<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    prompt: &str,
    mech: &str,
) -> Result<Answer> {
    let tuning = crate::wire::Tuning::default();
    let until = tokio::time::Instant::now() + tuning.preauth;
    crate::auth::discovery::complete_line(stream, prompt, mech, until, &tuning).await
}

/// A ManageSieve SASL response string: quoted, literal or a bare line.
pub async fn sieve_read_sasl_string<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> Result<Zeroizing<String>> {
    crate::proto::sieve::preauth::read_sasl_string(stream, IDLE).await
}
