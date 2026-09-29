use anyhow::{anyhow, Result};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Header, Validation};
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use crate::config::TokenType;

/// How long to wait for a JWKS endpoint. Without this a hung IdP would block
/// startup indefinitely (and, in the refresher, pin a task forever).
const JWKS_TIMEOUT: Duration = Duration::from_secs(10);

/// Minimum spacing of on-demand refreshes triggered by an unknown `kid`. A
/// freshly rotated key is accepted within seconds instead of after the next
/// periodic refresh, while random kids cannot turn the proxy into a request
/// amplifier against the IdP.
const UNKNOWN_KID_REFETCH_INTERVAL: Duration = Duration::from_secs(30);

/// Largest accepted JWKS document.
const MAX_JWKS_BYTES: usize = 256 * 1024;

/// Why a token was not accepted. The texts end up in the journal and never
/// contain token content: the `kid` and the claims are attacker-chosen, and a
/// newline in them would forge extra log lines.
#[derive(Debug)]
pub enum TokenError {
    /// Signed with a key id no configured issuer publishes, according to the
    /// last on-demand JWKS refresh of the issuer the token claims (or the
    /// token claims no configured issuer).
    UnknownKid,
    /// Signed with a key id the proxy does not know, and the last on-demand
    /// JWKS refresh (made for this token, or less than
    /// `UNKNOWN_KID_REFETCH_INTERVAL` ago) failed for the issuer the token
    /// claims. No verdict on the token: the key may have been rotated in
    /// since. An outage.
    KeysStale,
    /// Invalid: malformed, bad signature, or a claim check failed.
    Invalid(String),
}

impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TokenError::UnknownKid => f.write_str("unknown kid"),
            TokenError::KeysStale => f.write_str("unknown kid; JWKS refresh failed"),
            TokenError::Invalid(why) => f.write_str(why),
        }
    }
}

impl std::error::Error for TokenError {}

/// A `TokenError::Invalid` with a formatted text.
macro_rules! invalid {
    ($($arg:tt)*) => {
        TokenError::Invalid(format!($($arg)*))
    };
}

/// JWKS must come over https; plain http only from the local host (tests,
/// a local IdP sidecar). A MITM on the JWKS fetch can mint any token.
pub fn check_jwks_url(url: &str) -> Result<()> {
    let parsed = reqwest::Url::parse(url).map_err(|e| anyhow!("bad jwks url {url}: {e}"))?;
    let local = matches!(
        parsed.host_str(),
        Some("localhost" | "127.0.0.1" | "[::1]" | "::1")
    );
    match parsed.scheme() {
        "https" => Ok(()),
        "http" if local => Ok(()),
        _ => Err(anyhow!("jwks url {url} must use https")),
    }
}

/// Supported signature algorithms. No HS*: the proxy holds no shared secret,
/// and accepting one would reopen algorithm confusion.
pub fn parse_alg(alg: &str) -> Option<Algorithm> {
    match alg {
        "ES256" => Some(Algorithm::ES256),
        "ES384" => Some(Algorithm::ES384),
        "RS256" => Some(Algorithm::RS256),
        "RS384" => Some(Algorithm::RS384),
        "RS512" => Some(Algorithm::RS512),
        "PS256" => Some(Algorithm::PS256),
        "PS384" => Some(Algorithm::PS384),
        "PS512" => Some(Algorithm::PS512),
        _ => None,
    }
}

/// The token rules of one issuer (compiled from `config::Issuer`).
pub struct Policy {
    issuer: String,
    jwks_url: String,
    audiences: Vec<String>,
    token_type: TokenType,
    identity_claim: String,
    require_email_verified: bool,
    allowed: Vec<Algorithm>,
    /// Use keys without `alg` with the one algorithm their type implies.
    infer_key_algorithm: bool,
    allowed_clients: Vec<String>,
    client_claim: String,
}

impl Policy {
    fn from_config(i: &crate::config::Issuer) -> Result<Policy> {
        let allowed = i
            .allowed_algorithms
            .iter()
            .map(|a| parse_alg(a).ok_or_else(|| anyhow!("unsupported algorithm {a}")))
            .collect::<Result<Vec<_>>>()?;
        Ok(Policy {
            issuer: i.issuer.clone(),
            jwks_url: i.jwks_url.clone(),
            audiences: i.audiences.clone(),
            token_type: i.token_type,
            identity_claim: i.identity_claim.clone(),
            require_email_verified: i.requires_email_verified(),
            allowed,
            infer_key_algorithm: i.infer_key_algorithm,
            allowed_clients: i.allowed_clients.clone(),
            client_claim: i.client_claim.clone(),
        })
    }

    /// Keycloak rules for `issuer` with one audience.
    #[cfg(any(test, fuzzing))]
    pub(crate) fn keycloak(issuer: &str, audience: &str) -> Policy {
        Policy {
            issuer: issuer.into(),
            jwks_url: String::new(),
            audiences: vec![audience.into()],
            token_type: TokenType::Keycloak,
            identity_claim: "email".into(),
            require_email_verified: true,
            allowed: crate::config::DEFAULT_ALGORITHMS
                .iter()
                .filter_map(|a| parse_alg(a))
                .collect(),
            infer_key_algorithm: true,
            allowed_clients: Vec::new(),
            client_claim: "azp".into(),
        }
    }
}

/// A signing key together with **the issuer that published it**.
///
/// The binding is the point: validating a token against a key without pinning
/// the issuer *that key came from* lets a token signed by realm B claim
/// `iss` of realm A, as long as A is in some global allow-list. Both realms
/// then collapse into one trust domain.
#[derive(Clone)]
struct KeyEntry {
    key: DecodingKey,
    policy: Arc<Policy>,
    /// Built once per key at JWKS load, not per auth.
    validation: Validation,
}

/// The validation rules for a key published under `policy`.
///
/// jsonwebtoken only compares `iss`/`aud` when the claim is present, so both
/// must also be listed as required — otherwise a token minted for any other
/// client of the realm (no audience mapper → no `aud`) passes.
fn validation_for(alg: Algorithm, policy: &Policy, leeway: u64) -> Validation {
    let mut v = Validation::new(alg);
    v.set_required_spec_claims(&["exp", "iss", "aud"]);
    v.validate_exp = true;
    v.validate_nbf = true;
    v.leeway = leeway;
    v.set_issuer(&[&policy.issuer]);
    v.set_audience(&policy.audiences);
    v
}

/// kid -> the keys published under it.
type KeyMap = HashMap<String, Vec<KeyEntry>>;

pub struct Validator {
    /// kid -> keys published under that kid. A `Vec` because two issuers may
    /// legitimately use the same kid (or omit it, falling back to "default");
    /// each candidate is tried against its *own* issuer, so a collision can
    /// never widen what is accepted.
    ///
    /// The lock only guards swapping the map: a validation clones the `Arc`
    /// and decodes without holding it, so a panic while decoding a hostile
    /// token cannot poison the lock and take OAuth down until a restart.
    keys: RwLock<Arc<KeyMap>>,
    /// One per configured issuer; also the list the refresh walks.
    policies: Vec<Arc<Policy>>,
    leeway: u64,
    refresh_interval: Duration,
    /// Reused for every refresh (connection pool, TLS config).
    client: reqwest::Client,
    /// Serialises every JWKS refresh, periodic and on-demand, so an older
    /// snapshot can never overwrite a newer one. Holds the time of the last
    /// on-demand refresh and the issuers whose JWKS failed in it; tokens that
    /// arrive during a refresh wait here and re-check before fetching.
    last_kid_refetch: tokio::sync::Mutex<Option<(std::time::Instant, Vec<String>)>>,
}

async fn fetch_jwks(client: &reqwest::Client, url: &str) -> Result<Value> {
    let resp = client.get(url).send().await?.error_for_status()?;
    if resp
        .content_length()
        .is_some_and(|n| n > MAX_JWKS_BYTES as u64)
    {
        return Err(anyhow!("JWKS larger than {MAX_JWKS_BYTES} bytes"));
    }
    // Read in chunks so a body without Content-Length is capped too.
    let mut resp = resp;
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        if body.len() + chunk.len() > MAX_JWKS_BYTES {
            return Err(anyhow!("JWKS larger than {MAX_JWKS_BYTES} bytes"));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(serde_json::from_slice(&body)?)
}

impl Validator {
    /// The current key map. Poison-tolerant: the lock is held only to clone
    /// or swap the `Arc`, which cannot leave the map half-written.
    fn snapshot(&self) -> Arc<KeyMap> {
        self.keys.read().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// Replace the key map.
    fn set_keys(&self, keys: KeyMap) {
        *self.keys.write().unwrap_or_else(|p| p.into_inner()) = Arc::new(keys);
    }

    /// Load every issuer's JWKS. Fail-closed: an issuer that is unreachable
    /// or publishes no usable key at boot aborts startup rather than coming up
    /// unable to validate that realm's tokens. The periodic refresh is the part
    /// that tolerates a partial outage.
    pub async fn new(oauth: &crate::config::OAuth) -> Result<Validator> {
        if oauth.issuers.is_empty() {
            return Err(anyhow!("no issuers configured"));
        }
        let mut policies = Vec::new();
        for i in &oauth.issuers {
            check_jwks_url(&i.jwks_url)?;
            policies.push(Arc::new(Policy::from_config(i)?));
        }
        crate::obs::metrics::register_issuers(policies.iter().map(|p| p.issuer.as_str()));
        let v = Validator {
            keys: RwLock::default(),
            policies,
            leeway: oauth.leeway_secs,
            refresh_interval: Duration::from_secs(oauth.refresh_secs),
            // No redirects: a redirect could leave https; a JWKS URL is final.
            client: reqwest::Client::builder()
                .timeout(JWKS_TIMEOUT)
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
            last_kid_refetch: tokio::sync::Mutex::new(None),
        };
        let (keys, failed) = v.fetch_all().await;
        if !failed.is_empty() {
            return Err(anyhow!(
                "JWKS unavailable at startup for: {}",
                failed.join(", ")
            ));
        }
        if keys.is_empty() {
            return Err(anyhow!("no sig keys in any JWKS"));
        }
        v.set_keys(keys);
        Ok(v)
    }

    /// Fetch every configured JWKS. Sources are independent: a source that
    /// fails is reported but does not discard the ones that succeeded, so one
    /// unreachable IdP cannot take the other realm's keys down with it.
    /// Returns the keys plus the issuers that failed.
    async fn fetch_all(&self) -> (HashMap<String, Vec<KeyEntry>>, Vec<String>) {
        let mut keys: HashMap<String, Vec<KeyEntry>> = HashMap::new();
        let mut failed = Vec::new();
        for policy in &self.policies {
            let issuer = &policy.issuer;
            match fetch_jwks(&self.client, &policy.jwks_url).await {
                Ok(jwks) => {
                    // Staged, so a JWKS that fails half-way leaves none of its
                    // keys in the map (refresh would add the previous keys on
                    // top).
                    let mut staged = HashMap::new();
                    match Self::merge_jwks_keys(&jwks, policy, self.leeway, &mut staged) {
                        // A realm that publishes zero usable keys is treated as
                        // failed: replacing its keys with nothing would lock
                        // that realm's users out until the next refresh.
                        Ok(()) if staged.is_empty() => {
                            tracing::warn!(target: crate::obs::target::TOKEN, %issuer, "JWKS has no usable signing keys");
                            failed.push(issuer.clone());
                        }
                        Ok(()) => {
                            crate::obs::metrics::record_jwks_fetch(issuer, true);
                            for (kid, entries) in staged {
                                keys.entry(kid).or_default().extend(entries);
                            }
                        }
                        Err(e) => {
                            tracing::warn!(target: crate::obs::target::TOKEN, %issuer, error = %e, "parsing JWKS");
                            failed.push(issuer.clone());
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(target: crate::obs::target::TOKEN, %issuer, url = %policy.jwks_url, error = %e, "fetching JWKS");
                    failed.push(issuer.clone());
                }
            }
            // Any of the three failures above pushed this issuer.
            if failed.last() == Some(issuer) {
                crate::obs::metrics::record_jwks_fetch(issuer, false);
            }
        }
        (keys, failed)
    }

    /// Re-fetch the JWKS and merge the result in.
    ///
    /// Issuers that failed keep the keys they already had, so a transient
    /// outage at one IdP neither disarms the proxy nor silently drops the other
    /// realm. Issuers that succeeded are fully replaced, which is what makes a
    /// key *revocation* take effect.
    pub async fn refresh(&self) -> Result<()> {
        let _serial = self.last_kid_refetch.lock().await;
        self.refresh_locked().await.0
    }

    /// The refresh itself; the caller holds `last_kid_refetch`. Also returns
    /// the issuers whose JWKS failed (all of them when nothing usable came
    /// back, since `fetch_all` counts a source without usable keys as failed).
    async fn refresh_locked(&self) -> (Result<()>, Vec<String>) {
        let (fresh, failed) = self.fetch_all().await;
        let result = self.merge_refreshed(fresh, &failed);
        (result, failed)
    }

    /// Install a refresh result: issuers that failed keep their previous keys.
    fn merge_refreshed(
        &self,
        mut fresh: HashMap<String, Vec<KeyEntry>>,
        failed: &[String],
    ) -> Result<()> {
        if fresh.is_empty() {
            // Mirrors the `keys.is_empty()` guard in `new()`: a JWKS response
            // parsed fine but published zero keys (or every source failed) is
            // as dangerous as a fetch failure — replacing the map would lock
            // every OAuth client out until the next refresh. Keep what we had.
            return Err(anyhow!(
                "JWKS refresh produced no usable keys ({} of {} sources failed); keeping previous keys",
                failed.len(), self.policies.len()
            ));
        }
        if !failed.is_empty() {
            // Carry over only the entries belonging to the failed issuers.
            let prev = self.snapshot();
            for (kid, entries) in prev.iter() {
                for e in entries.iter().filter(|e| failed.contains(&e.policy.issuer)) {
                    fresh.entry(kid.clone()).or_default().push(e.clone());
                }
            }
        }
        let n = fresh.len();
        self.set_keys(fresh);
        tracing::debug!(target: crate::obs::target::TOKEN, kids = n, failed = failed.len(), "JWKS refreshed");
        if failed.is_empty() {
            Ok(())
        } else {
            Err(anyhow!(
                "{} of {} JWKS sources failed; kept their previous keys",
                failed.len(),
                self.policies.len()
            ))
        }
    }

    /// Spawn the periodic refresher. Errors are logged, never fatal.
    pub fn spawn_refresher(self: Arc<Self>) {
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(self.refresh_interval);
            tick.tick().await; // the first tick fires immediately; we just loaded
            loop {
                tick.tick().await;
                if let Err(e) = self.refresh().await {
                    tracing::warn!(target: crate::obs::target::TOKEN, error = %e, "JWKS refresh failed; keeping previous keys");
                }
            }
        });
    }

    /// Merge the signing keys of one JWKS into `keys`, tagging each with the
    /// issuer (policy) that published it.
    ///
    /// The algorithm is always the key's, never the token header's: a key
    /// with `alg` gets exactly that one (if the issuer allows it); a key
    /// without `alg` (RFC 7517 makes it optional) gets the one algorithm its
    /// type implies — ES256 for P-256, ES384 for P-384, RS256 (the OIDC
    /// default) for RSA — if the issuer's `allowed_algorithms` contain it.
    /// Never more than one: RFC 8725 §3.1 requires each key to be used with
    /// exactly one algorithm.
    fn merge_jwks_keys(
        jwks: &Value,
        policy: &Arc<Policy>,
        leeway: u64,
        keys: &mut HashMap<String, Vec<KeyEntry>>,
    ) -> Result<()> {
        for k in jwks["keys"]
            .as_array()
            .ok_or_else(|| anyhow!("jwks.keys missing"))?
        {
            // RFC 7517 §4.2: `use` is optional. Absent means unrestricted, so
            // only skip keys that explicitly declare a non-signing use.
            if let Some(u) = k["use"].as_str() {
                if u != "sig" {
                    continue;
                }
            }
            let kid = k["kid"].as_str().unwrap_or("default").to_string();
            let kty = k["kty"].as_str();
            let candidates: Vec<Algorithm> = match k["alg"].as_str() {
                Some(a) => match parse_alg(a) {
                    Some(alg) => vec![alg],
                    None => continue, // unknown or symmetric algorithm
                },
                None if !policy.infer_key_algorithm => continue,
                None => match (kty, k["crv"].as_str()) {
                    (Some("EC"), Some("P-256")) => vec![Algorithm::ES256],
                    (Some("EC"), Some("P-384")) => vec![Algorithm::ES384],
                    (Some("RSA"), _) => vec![Algorithm::RS256],
                    _ => continue,
                },
            };
            let algs: Vec<Algorithm> = candidates
                .into_iter()
                .filter(|a| policy.allowed.contains(a))
                .collect();
            if algs.is_empty() {
                continue;
            }
            let key = match kty {
                Some("EC") => DecodingKey::from_ec_components(
                    k["x"].as_str().ok_or_else(|| anyhow!("EC x"))?,
                    k["y"].as_str().ok_or_else(|| anyhow!("EC y"))?,
                )?,
                Some("RSA") => DecodingKey::from_rsa_components(
                    k["n"].as_str().ok_or_else(|| anyhow!("RSA n"))?,
                    k["e"].as_str().ok_or_else(|| anyhow!("RSA e"))?,
                )?,
                _ => continue,
            };
            let entries = keys.entry(kid).or_default();
            for alg in algs {
                entries.push(KeyEntry {
                    key: key.clone(),
                    policy: policy.clone(),
                    validation: validation_for(alg, policy, leeway),
                });
            }
        }
        Ok(())
    }

    /// Build a Validator from already-parsed JWKS values. Used in tests.
    #[cfg(any(test, fuzzing))]
    pub(crate) fn from_parts(parts: Vec<(Value, Policy)>) -> Result<Validator> {
        let mut keys = HashMap::new();
        let mut policies = Vec::new();
        for (v, policy) in parts {
            let policy = Arc::new(policy);
            Self::merge_jwks_keys(&v, &policy, 60, &mut keys)?;
            policies.push(policy);
        }
        if keys.is_empty() {
            return Err(anyhow!("no sig keys in JWKS"));
        }
        Ok(Validator {
            keys: RwLock::new(Arc::new(keys)),
            policies,
            leeway: 60,
            refresh_interval: Duration::from_secs(300),
            client: {
                // main() installs the provider in production.
                let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
                reqwest::Client::new()
            },
            last_kid_refetch: tokio::sync::Mutex::new(None),
        })
    }

    /// Keycloak rules for each (JWKS, issuer), one audience. Used in tests.
    #[cfg(test)]
    pub fn from_jwks_values(jwks: &[(Value, &str)], audience: &str) -> Result<Validator> {
        Self::from_parts(
            jwks.iter()
                .map(|(v, iss)| (v.clone(), Policy::keycloak(iss, audience)))
                .collect(),
        )
    }

    /// Like `validate`, but a token with an unknown `kid` triggers one JWKS
    /// refresh (at most every `UNKNOWN_KID_REFETCH_INTERVAL`) and a retry, so
    /// tokens signed right after a key rotation are accepted.
    ///
    /// A kid still unknown is `UnknownKid` (a verdict) when the last
    /// on-demand refresh succeeded for the issuer the token claims, whether
    /// made for this token or skipped for the spacing: a flood of random kids
    /// stays `bad_token` for CrowdSec, also while another issuer is down.
    /// When that issuer's refresh failed it is `KeysStale` (an outage): the
    /// key may have been rotated in while its IdP was unreachable.
    pub async fn validate_fresh(&self, token: &str) -> Result<String, TokenError> {
        let first = self.validate(token);
        if !matches!(first, Err(TokenError::UnknownKid)) {
            return first;
        }
        // Serialise on-demand refreshes. A task that waited here may find the
        // key already loaded by the refresh it waited for.
        let mut last = self.last_kid_refetch.lock().await;
        let again = self.validate(token);
        if !matches!(again, Err(TokenError::UnknownKid)) {
            return again;
        }
        // The issuer the token claims, unverified: it only picks whose
        // refresh result decides between verdict and outage, it is never
        // trusted. Absent or not configured: a verdict. An array `iss` (which
        // validation accepts when it contains the issuer) is an outage if any
        // of its entries failed.
        let claimed = unverified_iss(token);
        let stale = |failed: &[String]| {
            if claimed.iter().any(|iss| failed.contains(iss)) {
                TokenError::KeysStale
            } else {
                TokenError::UnknownKid
            }
        };
        if let Some((t, failed)) = &*last {
            if t.elapsed() < UNKNOWN_KID_REFETCH_INTERVAL {
                return Err(stale(failed));
            }
        }
        let (refreshed, failed) = self.refresh_locked().await;
        if let Err(re) = &refreshed {
            tracing::warn!(target: crate::obs::target::TOKEN, error = %re, "JWKS refresh for unknown kid");
        }
        let verdict = match self.validate(token) {
            Err(TokenError::UnknownKid) => Err(stale(&failed)),
            other => other,
        };
        *last = Some((std::time::Instant::now(), failed));
        verdict
    }

    /// Validate `token` and return its verified identity (the issuer's
    /// `identity_claim`, by default `email`).
    pub fn validate(&self, token: &str) -> Result<String, TokenError> {
        // serde puts the offending header value into its error text; that value
        // is attacker-chosen, so the detail is dropped.
        let header = decode_header(token).map_err(|_| invalid!("malformed header"))?;
        let kid = header.kid.clone().unwrap_or_else(|| "default".into());
        let keys = self.snapshot();
        let entries = keys.get(&kid).ok_or(TokenError::UnknownKid)?;
        let mut last: Option<jsonwebtoken::errors::Error> = None;
        for e in entries {
            // Algorithm and issuer come from the stored key, never from the
            // token: no algorithm confusion (alg=none, HS256 forgery), no
            // issuer borrowed from another realm (see `KeyEntry`).
            match decode::<Map<String, Value>>(token, &e.key, &e.validation) {
                Ok(data) => return check_claims(&data.claims, &header, &e.policy),
                Err(err) => last = Some(err),
            }
        }
        Err(match last {
            Some(e) => invalid!("{}", error_kind(e.kind())),
            None => invalid!("no usable key for kid"),
        })
    }
}

/// The issuers the `iss` claim of `token` names, without any verification:
/// the string, or every string in an array; empty if the payload does not
/// decode or has no such claim. Only for choosing whose refresh result
/// applies to an unknown kid; never for trusting the token.
pub(crate) fn unverified_iss(token: &str) -> Vec<String> {
    use base64::Engine as _;
    let claims: Option<Value> = token.split('.').nth(1).and_then(|payload| {
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .ok()?;
        serde_json::from_slice(&bytes).ok()
    });
    match claims.as_ref().and_then(|c| c.get("iss")) {
        Some(Value::String(iss)) => vec![iss.clone()],
        Some(Value::Array(all)) => all
            .iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect(),
        _ => Vec::new(),
    }
}

/// Name of a validation failure without its payload: JSON and UTF-8 errors
/// quote token content, which is attacker-chosen and ends up in the journal.
fn error_kind(k: &jsonwebtoken::errors::ErrorKind) -> String {
    use jsonwebtoken::errors::ErrorKind;
    match k {
        ErrorKind::Json(_) => "malformed claims".into(),
        ErrorKind::Utf8(_) | ErrorKind::Base64(_) => "malformed encoding".into(),
        other => format!("{other:?}"),
    }
}

/// The issuer's rules on a correctly signed token that jsonwebtoken does not
/// check itself. Returns the identity forwarded to the backend.
pub(crate) fn check_claims(
    claims: &Map<String, Value>,
    header: &Header,
    policy: &Policy,
) -> Result<String, TokenError> {
    let text = |name: &str| claims.get(name).and_then(Value::as_str);
    let is_access_token = match policy.token_type {
        TokenType::Keycloak => text("typ").is_some_and(|t| t.eq_ignore_ascii_case("Bearer")),
        TokenType::Rfc9068 => header.typ.as_deref().is_some_and(|t| {
            t.eq_ignore_ascii_case("at+jwt") || t.eq_ignore_ascii_case("application/at+jwt")
        }),
        TokenType::Any => true,
    };
    if !is_access_token {
        return Err(invalid!("not an access token"));
    }
    if policy.require_email_verified && claims.get("email_verified") != Some(&Value::Bool(true)) {
        return Err(invalid!("email not verified"));
    }
    if !policy.allowed_clients.is_empty()
        && !text(&policy.client_claim)
            .is_some_and(|c| policy.allowed_clients.iter().any(|a| a == c))
    {
        return Err(invalid!("client not allowed"));
    }
    let id = text(&policy.identity_claim).ok_or_else(|| invalid!("identity claim missing"))?;
    // The identity becomes the backend login and is written into the SASL
    // exchange: one word, no whitespace or control bytes. An email must also
    // be one plain address.
    let mut plausible = !id.is_empty()
        && id.len() <= 254
        && !id.chars().any(|ch| ch.is_whitespace() || ch.is_control());
    if policy.identity_claim == "email" {
        plausible &= id.split('@').count() == 2 && id.split('@').all(|p| !p.is_empty());
    }
    if !plausible {
        return Err(invalid!("identity claim is not a plain login"));
    }
    Ok(id.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use serde_json::json;

    const ISS_A: &str = "https://sso.example.org/realms/example.org";
    const ISS_B: &str = "https://id.example.org/realms/other";

    fn validator_with(jwks: serde_json::Value, issuer: &str, aud: &str) -> Validator {
        Validator::from_jwks_values(&[(jwks, issuer)], aud).unwrap()
    }

    /// Mint a token with the given key, kid and claims. `email_verified` and
    /// `typ` default to what a Keycloak access token carries unless the test
    /// sets them.
    fn mint(priv_pem: &str, kid: &str, mut claims: serde_json::Value) -> String {
        let obj = claims.as_object_mut().unwrap();
        obj.entry("email_verified").or_insert(json!(true));
        obj.entry("typ").or_insert(json!("Bearer"));
        mint_raw(priv_pem, kid, &claims)
    }

    /// Mint exactly the given claims.
    fn mint_raw(priv_pem: &str, kid: &str, claims: &serde_json::Value) -> String {
        let mut h = Header::new(Algorithm::ES256);
        h.kid = Some(kid.into());
        encode(
            &h,
            claims,
            &EncodingKey::from_ec_pem(priv_pem.as_bytes()).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn accepts_valid_and_extracts_email() {
        let (priv_pem, jwks) = test_es256_keypair("kid1");
        let v = validator_with(jwks, ISS_A, "dovecot");
        let tok = mint(
            &priv_pem,
            "kid1",
            json!({"iss":ISS_A,"aud":"dovecot","exp":4102444800usize,"email":"alice@example.org"}),
        );
        assert_eq!(v.validate(&tok).unwrap(), "alice@example.org");
    }

    /// A panic while the key lock is held (poisoning it) does not stop
    /// validation, refresh or key replacement.
    #[test]
    fn poisoned_key_lock_keeps_validating() {
        let (priv_pem, jwks) = test_es256_keypair("kid1");
        let v = Arc::new(validator_with(jwks, ISS_A, "dovecot"));
        let tok = mint(
            &priv_pem,
            "kid1",
            json!({"iss":ISS_A,"aud":"dovecot","exp":4102444800usize,"email":"alice@example.org"}),
        );
        let w = v.clone();
        let poisoner = std::thread::spawn(move || {
            let _guard = w.keys.write().unwrap();
            panic!("poison the key lock");
        });
        assert!(poisoner.join().is_err());
        assert!(v.keys.is_poisoned());
        assert_eq!(v.validate(&tok).unwrap(), "alice@example.org");
        let keys = (*v.snapshot()).clone();
        v.set_keys(keys);
        assert_eq!(v.validate(&tok).unwrap(), "alice@example.org");
    }

    #[test]
    fn rejects_wrong_audience() {
        let (priv_pem, jwks) = test_es256_keypair("kid1");
        let v = validator_with(jwks, ISS_A, "dovecot");
        let tok = mint(
            &priv_pem,
            "kid1",
            json!({"iss":ISS_A,"aud":"someoneelse","exp":4102444800usize,"email":"nk@x"}),
        );
        assert!(v.validate(&tok).is_err());
    }

    #[test]
    fn rejects_expired_token() {
        let (priv_pem, jwks) = test_es256_keypair("kid1");
        let v = validator_with(jwks, ISS_A, "dovecot");
        // exp in the past (Unix epoch 1 = 1970-01-01T00:00:01Z)
        let tok = mint(
            &priv_pem,
            "kid1",
            json!({"iss":ISS_A,"aud":"dovecot","exp":1usize,"email":"nk@x"}),
        );
        assert!(v.validate(&tok).is_err());
    }

    #[test]
    fn rejects_wrong_issuer() {
        let (priv_pem, jwks) = test_es256_keypair("kid1");
        let v = validator_with(jwks, ISS_A, "dovecot");
        let tok = mint(
            &priv_pem,
            "kid1",
            json!({"iss":"https://evil-iss","aud":"dovecot","exp":4102444800usize,"email":"nk@x"}),
        );
        assert!(v.validate(&tok).is_err());
    }

    #[test]
    fn multi_issuer_accepts_second_issuer() {
        let (pem_a, jwks_a) = test_es256_keypair("kid-a");
        let (pem_b, jwks_b) = test_es256_keypair("kid-b");
        let v =
            Validator::from_jwks_values(&[(jwks_a, ISS_A), (jwks_b, ISS_B)], "dovecot").unwrap();
        let _ = pem_a;
        let tok = mint(
            &pem_b,
            "kid-b",
            json!({"iss":ISS_B,"aud":"dovecot","exp":4102444800usize,"email":"user@other.example"}),
        );
        assert_eq!(v.validate(&tok).unwrap(), "user@other.example");
    }

    #[test]
    fn multi_issuer_rejects_unlisted_issuer() {
        let (pem_b, jwks_b) = test_es256_keypair("kid-b");
        let v = Validator::from_jwks_values(&[(jwks_b, ISS_B)], "dovecot").unwrap();
        let tok = mint(
            &pem_b,
            "kid-b",
            json!({"iss":"https://evil.example.com/realms/attacker","aud":"dovecot",
                   "exp":4102444800usize,"email":"attacker@evil"}),
        );
        assert!(v.validate(&tok).is_err());
    }

    /// The cross-realm case: a token signed with realm B's key but claiming
    /// realm A's issuer must be rejected. With a flat kid->key map and a global
    /// issuer allow-list this passes validation, collapsing both realms into a
    /// single trust domain.
    #[test]
    fn rejects_issuer_borrowed_from_another_realm() {
        let (pem_a, jwks_a) = test_es256_keypair("kid-a");
        let (pem_b, jwks_b) = test_es256_keypair("kid-b");
        let _ = pem_a;
        let v =
            Validator::from_jwks_values(&[(jwks_a, ISS_A), (jwks_b, ISS_B)], "dovecot").unwrap();
        // signed by B's key, but claims to come from A
        let tok = mint(
            &pem_b,
            "kid-b",
            json!({"iss":ISS_A,"aud":"dovecot","exp":4102444800usize,"email":"victim@example.org"}),
        );
        assert!(
            v.validate(&tok).is_err(),
            "token signed by realm B must not be accepted as realm A"
        );
    }

    /// Two realms publishing the same kid must both keep working, and each is
    /// still pinned to its own issuer.
    #[test]
    fn colliding_kid_across_realms_keeps_both_usable() {
        let (pem_a, jwks_a) = test_es256_keypair("shared");
        let (pem_b, jwks_b) = test_es256_keypair("shared");
        let v =
            Validator::from_jwks_values(&[(jwks_a, ISS_A), (jwks_b, ISS_B)], "dovecot").unwrap();

        let tok_a = mint(
            &pem_a,
            "shared",
            json!({"iss":ISS_A,"aud":"dovecot","exp":4102444800usize,"email":"a@x"}),
        );
        let tok_b = mint(
            &pem_b,
            "shared",
            json!({"iss":ISS_B,"aud":"dovecot","exp":4102444800usize,"email":"b@x"}),
        );
        assert_eq!(v.validate(&tok_a).unwrap(), "a@x");
        assert_eq!(v.validate(&tok_b).unwrap(), "b@x");

        // ...and the cross claim still fails for a colliding kid.
        let cross = mint(
            &pem_b,
            "shared",
            json!({"iss":ISS_A,"aud":"dovecot","exp":4102444800usize,"email":"b@x"}),
        );
        assert!(
            v.validate(&cross).is_err(),
            "cross-realm claim must fail even on a shared kid"
        );
    }

    /// RFC 7517 §4.2: `use` is optional. A key without it must still be usable.
    #[test]
    fn key_without_use_member_is_accepted() {
        let (priv_pem, mut jwks) = test_es256_keypair("kid1");
        jwks["keys"][0].as_object_mut().unwrap().remove("use");
        let v = validator_with(jwks, ISS_A, "dovecot");
        let tok = mint(
            &priv_pem,
            "kid1",
            json!({"iss":ISS_A,"aud":"dovecot","exp":4102444800usize,"email":"nk@x"}),
        );
        assert_eq!(v.validate(&tok).unwrap(), "nk@x");
    }

    /// A key explicitly marked for encryption must not be used to verify.
    #[test]
    fn key_with_enc_use_is_skipped() {
        let (_pem, mut jwks) = test_es256_keypair("kid1");
        jwks["keys"][0]["use"] = json!("enc");
        assert!(Validator::from_jwks_values(&[(jwks, ISS_A)], "dovecot").is_err());
    }

    #[test]
    fn unknown_kid_is_rejected() {
        let (priv_pem, jwks) = test_es256_keypair("kid1");
        let v = validator_with(jwks, ISS_A, "dovecot");
        // Simulates a Keycloak key rotation before a refresh has happened.
        let tok = mint(
            &priv_pem,
            "kid-rotated",
            json!({"iss":ISS_A,"aud":"dovecot","exp":4102444800usize,"email":"nk@x"}),
        );
        let err = v.validate(&tok).unwrap_err().to_string();
        assert!(err.contains("unknown kid"), "got: {err}");
    }

    fn claims() -> serde_json::Value {
        json!({"iss":ISS_A,"aud":"dovecot","exp":4102444800usize,"email":"nk@x"})
    }

    /// A token for another client of the realm carries no `aud` at all; it
    /// must not pass just because there is nothing to compare.
    #[test]
    fn rejects_token_without_audience() {
        let (priv_pem, jwks) = test_es256_keypair("kid1");
        let v = validator_with(jwks, ISS_A, "dovecot");
        let mut c = claims();
        c.as_object_mut().unwrap().remove("aud");
        assert!(v.validate(&mint(&priv_pem, "kid1", c)).is_err());
    }

    #[test]
    fn rejects_token_without_issuer() {
        let (priv_pem, jwks) = test_es256_keypair("kid1");
        let v = validator_with(jwks, ISS_A, "dovecot");
        let mut c = claims();
        c.as_object_mut().unwrap().remove("iss");
        assert!(v.validate(&mint(&priv_pem, "kid1", c)).is_err());
    }

    #[test]
    fn rejects_token_not_yet_valid() {
        let (priv_pem, jwks) = test_es256_keypair("kid1");
        let v = validator_with(jwks, ISS_A, "dovecot");
        let mut c = claims();
        c["nbf"] = json!(4102444000usize);
        assert!(v.validate(&mint(&priv_pem, "kid1", c)).is_err());
    }

    #[test]
    fn rejects_unverified_email() {
        let (priv_pem, jwks) = test_es256_keypair("kid1");
        let v = validator_with(jwks, ISS_A, "dovecot");
        let mut c = claims();
        c["email_verified"] = json!(false);
        assert!(v.validate(&mint(&priv_pem, "kid1", c.clone())).is_err());
        c.as_object_mut().unwrap().remove("email_verified");
        c["typ"] = json!("Bearer");
        assert!(
            v.validate(&mint_raw(&priv_pem, "kid1", &c)).is_err(),
            "missing email_verified"
        );
    }

    /// A Keycloak ID token can carry `aud=dovecot` too; only access tokens open a mailbox.
    #[test]
    fn rejects_id_token() {
        let (priv_pem, jwks) = test_es256_keypair("kid1");
        let v = validator_with(jwks, ISS_A, "dovecot");
        let mut c = claims();
        c["typ"] = json!("ID");
        assert!(v.validate(&mint(&priv_pem, "kid1", c.clone())).is_err());
        c.as_object_mut().unwrap().remove("typ");
        c["email_verified"] = json!(true);
        assert!(
            v.validate(&mint_raw(&priv_pem, "kid1", &c)).is_err(),
            "missing typ"
        );
    }

    /// The kid is attacker-chosen: a newline in it must never reach the
    /// error text, which ends up in the journal (log line forgery).
    #[test]
    fn error_text_never_echoes_the_kid() {
        let (priv_pem, jwks) = test_es256_keypair("kid1");
        let v = validator_with(jwks, ISS_A, "dovecot");
        let evil = "x\nFAKE authresult result=ok";
        let err = v
            .validate(&mint(&priv_pem, evil, claims()))
            .unwrap_err()
            .to_string();
        assert!(!err.contains('\n') && !err.contains("FAKE"), "got: {err}");
    }

    /// A realm whose JWKS suddenly publishes no usable key keeps its old keys.
    #[test]
    fn empty_jwks_counts_as_failed_source() {
        let (_pem, jwks) = test_es256_keypair("kid1");
        let mut staged = HashMap::new();
        let p = Arc::new(Policy::keycloak(ISS_A, "dovecot"));
        Validator::merge_jwks_keys(&json!({"keys": []}), &p, 60, &mut staged).unwrap();
        assert!(staged.is_empty());
        Validator::merge_jwks_keys(&jwks, &p, 60, &mut staged).unwrap();
        assert_eq!(staged.len(), 1);
    }

    /// Header and claim values are attacker-chosen and must not reach the
    /// error text, where a log parser could read them as an authresult line.
    #[test]
    fn error_text_never_echoes_header_or_claims() {
        use base64::Engine as _;
        let (priv_pem, jwks) = test_es256_keypair("kid1");
        let v = validator_with(jwks, ISS_A, "dovecot");
        let forged = r#"x authresult result="ok" peer=192.0.2.9"#;
        let b64 = |s: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(s);
        let bad_header = format!(
            "{}.{}.sig",
            b64(&format!(r#"{{"alg":"{}"}}"#, forged.replace('"', "\\\""))),
            b64("{}")
        );
        let err = v.validate(&bad_header).unwrap_err().to_string();
        assert!(!err.contains("authresult"), "header: {err}");
        let mut c = claims();
        c["email_verified"] = json!(forged);
        let err = v
            .validate(&mint(&priv_pem, "kid1", c))
            .unwrap_err()
            .to_string();
        assert!(!err.contains("authresult"), "claims: {err}");
    }

    #[test]
    fn rejects_email_that_is_not_a_plain_address() {
        let (priv_pem, jwks) = test_es256_keypair("kid1");
        let v = validator_with(jwks, ISS_A, "dovecot");
        for bad in ["nk@x\r\nA1 LOGOUT", "a b@x", "no-at-sign", "a@b@c", "@x"] {
            let mut c = claims();
            c["email"] = json!(bad);
            assert!(v.validate(&mint(&priv_pem, "kid1", c)).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn jwks_url_must_be_https_except_localhost() {
        assert!(check_jwks_url("https://idp.example/certs").is_ok());
        assert!(check_jwks_url("http://127.0.0.1:8080/certs").is_ok());
        assert!(check_jwks_url("http://idp.example/certs").is_err());
    }

    /// An unknown kid triggers one on-demand refresh, then none for 30 s.
    /// The verdict follows the last refresh: failed (the test validator has
    /// no reachable JWKS) → `KeysStale`, also while the next one is skipped;
    /// succeeded → `UnknownKid`, also while skipped.
    #[tokio::test]
    async fn unknown_kid_refetch_is_rate_limited() {
        let (priv_pem, jwks) = test_es256_keypair("kid1");
        let v = validator_with(jwks, ISS_A, "dovecot");
        let tok = mint(&priv_pem, "kid-new", claims());
        assert!(
            matches!(v.validate_fresh(&tok).await, Err(TokenError::KeysStale)),
            "refresh failed"
        );
        let first = v
            .last_kid_refetch
            .lock()
            .await
            .clone()
            .expect("refresh attempted");
        assert_eq!(first.1, [ISS_A], "recorded as failed");
        assert!(
            matches!(v.validate_fresh(&tok).await, Err(TokenError::KeysStale)),
            "skipped after a failed refresh"
        );
        assert_eq!(
            *v.last_kid_refetch.lock().await,
            Some(first),
            "no second refresh within 30 s"
        );
        // Skipped after a successful refresh: a verdict, not an outage.
        *v.last_kid_refetch.lock().await = Some((std::time::Instant::now(), Vec::new()));
        assert!(
            matches!(v.validate_fresh(&tok).await, Err(TokenError::UnknownKid)),
            "skipped after a successful refresh"
        );
        // A known kid never touches the refresh path.
        assert!(v
            .validate_fresh(&mint(&priv_pem, "kid1", claims()))
            .await
            .is_ok());
    }

    /// Serve `jwks` over plain http on 127.0.0.1 (any path); returns the URL.
    async fn serve_jwks(jwks: serde_json::Value) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let body = jwks.to_string();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = listener.accept().await {
                let body = body.clone();
                tokio::spawn(async move {
                    let mut head = Vec::new();
                    let mut buf = [0u8; 1024];
                    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                        match s.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => head.extend_from_slice(&buf[..n]),
                        }
                    }
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = s.write_all(resp.as_bytes()).await;
                    let _ = s.shutdown().await;
                });
            }
        });
        format!("http://{addr}/certs")
    }

    /// Two issuers, B's JWKS down: an unknown kid is an outage only for a
    /// token that claims B. One claiming A, or no configured issuer, stays a
    /// verdict, so a random-kid flood stays visible while B is down.
    #[tokio::test]
    async fn unknown_kid_outage_follows_the_claimed_issuer() {
        let (pem_a, jwks_a) = test_es256_keypair("kid-a");
        let (_pem_b, jwks_b) = test_es256_keypair("kid-b");
        let mut a = policy(ISS_A);
        a.jwks_url = serve_jwks(jwks_a.clone()).await;
        let mut b = policy(ISS_B);
        b.jwks_url = "http://127.0.0.1:1/certs".into();
        let v = Validator::from_parts(vec![(jwks_a, a), (jwks_b, b)]).unwrap();
        let claiming = |iss: Option<&str>| {
            let mut c = claims();
            match iss {
                Some(i) => c["iss"] = json!(i),
                None => {
                    c.as_object_mut().unwrap().remove("iss");
                }
            }
            mint(&pem_a, "kid-random", c)
        };
        let claiming_all = |iss: &[&str]| {
            let mut c = claims();
            c["iss"] = json!(iss);
            mint(&pem_a, "kid-random", c)
        };
        // The refresh runs: A succeeds, B fails.
        assert!(matches!(
            v.validate_fresh(&claiming(Some(ISS_A))).await,
            Err(TokenError::UnknownKid)
        ));
        assert_eq!(v.last_kid_refetch.lock().await.as_ref().unwrap().1, [ISS_B]);
        // Skipped for the spacing: decided by the same result.
        assert!(matches!(
            v.validate_fresh(&claiming(Some(ISS_B))).await,
            Err(TokenError::KeysStale)
        ));
        assert!(matches!(
            v.validate_fresh(&claiming(Some(ISS_A))).await,
            Err(TokenError::UnknownKid)
        ));
        for iss in [None, Some("https://unknown.example/realms/x")] {
            assert!(
                matches!(
                    v.validate_fresh(&claiming(iss)).await,
                    Err(TokenError::UnknownKid)
                ),
                "{iss:?}"
            );
        }
        // An array `iss`: an outage if any configured entry failed.
        for (iss, stale) in [
            (&[ISS_A, "https://unknown.example/realms/x"][..], false),
            (&[ISS_A, ISS_B][..], true),
            (&[ISS_B][..], true),
            (&[][..], false),
        ] {
            let got = v.validate_fresh(&claiming_all(iss)).await;
            assert_eq!(
                matches!(got, Err(TokenError::KeysStale)),
                stale,
                "{iss:?}: {got:?}"
            );
            assert!(
                matches!(got, Err(TokenError::KeysStale | TokenError::UnknownKid)),
                "{iss:?}: {got:?}"
            );
        }
        // A refresh made for a token claiming B.
        *v.last_kid_refetch.lock().await = None;
        assert!(matches!(
            v.validate_fresh(&claiming(Some(ISS_B))).await,
            Err(TokenError::KeysStale)
        ));
        // A's key kept working throughout.
        assert!(v
            .validate_fresh(&mint(&pem_a, "kid-a", claims()))
            .await
            .is_ok());
    }

    fn policy(issuer: &str) -> Policy {
        Policy::keycloak(issuer, "dovecot")
    }

    /// RFC 9068 mode checks the header `typ`, not the Keycloak claim.
    #[test]
    fn rfc9068_token_type_checks_the_header() {
        let (priv_pem, jwks) = test_es256_keypair("kid1");
        let mut p = policy(ISS_A);
        p.token_type = TokenType::Rfc9068;
        let v = Validator::from_parts(vec![(jwks, p)]).unwrap();
        let mut c = claims();
        c["email_verified"] = json!(true);
        let mut h = Header::new(Algorithm::ES256);
        h.kid = Some("kid1".into());
        let key = EncodingKey::from_ec_pem(priv_pem.as_bytes()).unwrap();
        h.typ = Some("at+jwt".into());
        assert_eq!(v.validate(&encode(&h, &c, &key).unwrap()).unwrap(), "nk@x");
        h.typ = Some("JWT".into());
        assert!(
            v.validate(&encode(&h, &c, &key).unwrap()).is_err(),
            "plain JWT is not an access token"
        );
    }

    /// Another identity claim, no email_verified requirement, client allowlist.
    #[test]
    fn identity_claim_and_client_allowlist() {
        let (priv_pem, jwks) = test_es256_keypair("kid1");
        let mut p = policy(ISS_A);
        p.identity_claim = "preferred_username".into();
        p.require_email_verified = false;
        p.allowed_clients = vec!["webmail".into()];
        let v = Validator::from_parts(vec![(jwks, p)]).unwrap();
        let base = json!({"iss":ISS_A,"aud":"dovecot","exp":4102444800usize,"typ":"Bearer",
                          "preferred_username":"alice","azp":"webmail"});
        assert_eq!(
            v.validate(&mint_raw(&priv_pem, "kid1", &base)).unwrap(),
            "alice"
        );
        let mut other = base.clone();
        other["azp"] = json!("someapp");
        assert!(
            v.validate(&mint_raw(&priv_pem, "kid1", &other)).is_err(),
            "client not listed"
        );
        let mut spaced = base.clone();
        spaced["preferred_username"] = json!("a b");
        assert!(
            v.validate(&mint_raw(&priv_pem, "kid1", &spaced)).is_err(),
            "identity must be one word"
        );
        let mut none = base.clone();
        none.as_object_mut().unwrap().remove("preferred_username");
        assert!(
            v.validate(&mint_raw(&priv_pem, "kid1", &none)).is_err(),
            "identity claim missing"
        );
    }

    /// A JWKS key without `alg` gets the algorithm its curve implies.
    #[test]
    fn ec_key_without_alg_is_inferred() {
        let (priv_pem, mut jwks) = test_es256_keypair("kid1");
        jwks["keys"][0].as_object_mut().unwrap().remove("alg");
        let v = validator_with(jwks, ISS_A, "dovecot");
        assert_eq!(
            v.validate(&mint(&priv_pem, "kid1", claims())).unwrap(),
            "nk@x"
        );
    }

    /// An RSA key without `alg` is used with RS256 only (RFC 8725 §3.1: one
    /// key, one algorithm), and only if the issuer allows RS256.
    #[test]
    fn rsa_key_without_alg_is_rs256_only() {
        use aws_lc_rs::encoding::{AsDer, Pkcs8V1Der};
        use aws_lc_rs::signature::KeyPair as _;
        use base64::Engine as _;
        let rsa = aws_lc_rs::rsa::KeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048).unwrap();
        let der: Pkcs8V1Der = rsa.as_der().unwrap();
        // jsonwebtoken takes the PKCS#8 PEM and extracts the PKCS#1 key itself.
        let priv_pem = pkcs8_pem(der.as_ref());
        let b64u = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
        let public = rsa.public_key();
        let jwks = json!({"keys":[{"kty":"RSA","use":"sig","kid":"r1",
            "n": b64u(public.modulus().big_endian_without_leading_zero()),
            "e": b64u(public.exponent().big_endian_without_leading_zero())}]});
        // Every supported algorithm allowed: still one key entry, RS256.
        let v = Validator::from_parts(vec![(jwks.clone(), policy(ISS_A))]).unwrap();
        assert_eq!(v.snapshot()["r1"].len(), 1);
        let key = EncodingKey::from_rsa_pem(priv_pem.as_bytes()).unwrap();
        let mut c = claims();
        c["email_verified"] = json!(true);
        c["typ"] = json!("Bearer");
        let token = |alg| {
            let mut h = Header::new(alg);
            h.kid = Some("r1".into());
            encode(&h, &c, &key).unwrap()
        };
        assert_eq!(v.validate(&token(Algorithm::RS256)).unwrap(), "nk@x");
        for alg in [
            Algorithm::RS384,
            Algorithm::RS512,
            Algorithm::PS256,
            Algorithm::PS384,
            Algorithm::PS512,
        ] {
            assert!(v.validate(&token(alg)).is_err(), "{alg:?} accepted");
        }
        // An issuer without RS256 gets no usable key from it.
        let mut p = policy(ISS_A);
        p.allowed = vec![Algorithm::PS256];
        assert!(Validator::from_parts(vec![(jwks, p)]).is_err());
    }

    /// A key whose declared `alg` the issuer does not allow is not loaded.
    #[test]
    fn key_with_disallowed_alg_is_skipped() {
        let (_pem, jwks) = test_es256_keypair("kid1");
        let mut p = policy(ISS_A);
        p.allowed = vec![Algorithm::RS256];
        assert!(Validator::from_parts(vec![(jwks, p)]).is_err());
    }

    /// With inference off, keys without `alg` are skipped.
    #[test]
    fn key_without_alg_is_skipped_when_inference_is_off() {
        let (_pem, mut jwks) = test_es256_keypair("kid1");
        jwks["keys"][0].as_object_mut().unwrap().remove("alg");
        let mut p = policy(ISS_A);
        p.infer_key_algorithm = false;
        assert!(Validator::from_parts(vec![(jwks, p)]).is_err());
    }

    /// PEM-wrap a PKCS#8 private key (the form jsonwebtoken's `from_*_pem` take).
    fn pkcs8_pem(der: &[u8]) -> String {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD.encode(der);
        let body: Vec<&str> = b64
            .as_bytes()
            .chunks(64)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect();
        format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            body.join("\n")
        )
    }

    fn test_es256_keypair(kid: &str) -> (String, serde_json::Value) {
        use aws_lc_rs::signature::{EcdsaKeyPair, KeyPair as _, ECDSA_P256_SHA256_FIXED_SIGNING};
        use base64::Engine as _;
        let rng = aws_lc_rs::rand::SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let key =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref()).unwrap();
        // Uncompressed SEC1 point 0x04 || X || Y, each coordinate fixed-width
        // 32 bytes as JWK requires (RFC 7518 §6.2.1.2).
        let point = key.public_key().as_ref();
        assert_eq!(point.len(), 65);
        assert_eq!(point[0], 0x04);
        let b64u = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
        let jwks = serde_json::json!({"keys":[{"kty":"EC","crv":"P-256","use":"sig","alg":"ES256","kid":kid,
            "x": b64u(&point[1..33]), "y": b64u(&point[33..65])}]});
        (pkcs8_pem(pkcs8.as_ref()), jwks)
    }
}
