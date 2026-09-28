//! Account check for the legacy gate: does a login exist in Dovecot's
//! userdb? Asked over the doveadm HTTP API (Dovecot 2.4):
//!
//! - `POST <doveadm_url>` (the `/doveadm/v1` endpoint) with
//!   `Authorization: X-Dovecot-API <base64(doveadm_api_key)>` and
//!   `Content-Type: application/json`;
//! - body `[["user", {"userMask": "<login>", "userdbOnly": true}, "<tag>"]]`
//!   (the `doveadm user -u <login>` command);
//! - answer `[["doveadmResponse", …, "<tag>"]]`: the user exists;
//!   `[["error", {"type": "exitCode", "exitCode": 67}, "<tag>"]]`: EX_NOUSER,
//!   the user does not exist. Anything else (another exit code such as 75
//!   EX_TEMPFAIL, an HTTP error, a timeout) is an outage.
//!
//! Sources: <https://doc.dovecot.org/2.4.5/core/admin/doveadm.html#http-api>,
//! the `user` command in <https://doc.dovecot.org/2.4.5/core/summaries/doveadm.html>
//! and `cmd_user` in dovecot/core 2.4.5 `src/doveadm/doveadm-auth.c`.
//!
//! A user mask with `*` or `?` makes doveadm list every matching user, so
//! such logins are never sent: they count as unknown accounts.

use crate::config;
use anyhow::{anyhow, Context, Result};
use base64::Engine as _;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How long an existing account is remembered.
const POSITIVE_TTL: Duration = Duration::from_secs(120);
/// How long a missing account is remembered (a new account may wait this
/// long before legacy logins work).
const NEGATIVE_TTL: Duration = Duration::from_secs(30);
/// Cached logins at most.
const CACHE_CAPACITY: usize = 10_000;
/// Largest doveadm answer read.
const MAX_BODY: usize = 64 * 1024;
/// doveadm exit code EX_NOUSER (sysexits.h): the user does not exist.
const EX_NOUSER: i64 = 67;
/// Longest login sent to doveadm.
const MAX_LOGIN: usize = 255;

pub struct Doveadm {
    client: reqwest::Client,
    url: String,
    /// `X-Dovecot-API <base64 key>`, marked sensitive (kept out of debug
    /// output and HTTP/2 header compression tables).
    authorization: reqwest::header::HeaderValue,
    cache: Mutex<HashMap<String, (bool, Instant)>>,
}

impl Doveadm {
    pub fn new(cfg: &config::Legacy, timeout: Duration) -> Result<Doveadm> {
        let url = cfg
            .doveadm_url
            .clone()
            .ok_or_else(|| anyhow!("legacy.doveadm_url is missing"))?;
        config::check_service_url(&url).map_err(|e| anyhow!("legacy.doveadm_url: {e}"))?;
        let key_file = cfg
            .doveadm_key_file
            .as_deref()
            .ok_or_else(|| anyhow!("legacy.doveadm_key_file is missing"))?;
        let key = read_key(key_file)?;
        // No redirects: the key must reach exactly the configured endpoint.
        let mut builder = reqwest::Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none());
        if let Some(ca) = &cfg.doveadm_ca_file {
            builder = builder.tls_certs_only(read_ca(ca)?);
        }
        Ok(Doveadm {
            client: builder.build()?,
            url,
            authorization: {
                let mut v = reqwest::header::HeaderValue::from_str(&format!(
                    "X-Dovecot-API {}",
                    base64::engine::general_purpose::STANDARD.encode(key)
                ))?;
                v.set_sensitive(true);
                v
            },
            cache: Mutex::new(HashMap::new()),
        })
    }

    /// Whether `login` exists. `Err` is an outage (never cached).
    pub async fn exists(&self, login: &str) -> Result<bool> {
        if login.is_empty()
            || login.len() > MAX_LOGIN
            || login
                .chars()
                .any(|c| c.is_control() || c == '*' || c == '?')
        {
            return Ok(false);
        }
        if let Some(hit) = self.cached(login) {
            return Ok(hit);
        }
        let found = self.lookup(login).await?;
        self.remember(login, found);
        Ok(found)
    }

    fn cached(&self, login: &str) -> Option<bool> {
        let cache = self.cache.lock().unwrap_or_else(|p| p.into_inner());
        cache.get(login).and_then(|(found, at)| {
            let ttl = if *found { POSITIVE_TTL } else { NEGATIVE_TTL };
            (at.elapsed() < ttl).then_some(*found)
        })
    }

    fn remember(&self, login: &str, found: bool) {
        let mut cache = self.cache.lock().unwrap_or_else(|p| p.into_inner());
        if cache.len() >= CACHE_CAPACITY {
            cache.retain(|_, (f, at)| at.elapsed() < if *f { POSITIVE_TTL } else { NEGATIVE_TTL });
            if cache.len() >= CACHE_CAPACITY {
                cache.clear();
            }
        }
        cache.insert(login.to_string(), (found, Instant::now()));
    }

    async fn lookup(&self, login: &str) -> Result<bool> {
        let body = serde_json::json!([["user", {"userMask": login, "userdbOnly": true}, "u"]]);
        let resp = self
            .client
            .post(&self.url)
            .header(reqwest::header::AUTHORIZATION, self.authorization.clone())
            .json(&body)
            .send()
            .await
            .context("doveadm request")?;
        let status = resp.status();
        if status != reqwest::StatusCode::OK {
            return Err(anyhow!("doveadm answered HTTP {status}"));
        }
        let mut resp = resp;
        let mut raw = Vec::new();
        while let Some(chunk) = resp.chunk().await.context("doveadm response")? {
            if raw.len() + chunk.len() > MAX_BODY {
                return Err(anyhow!("doveadm response larger than {MAX_BODY} bytes"));
            }
            raw.extend_from_slice(&chunk);
        }
        parse_user_response(&raw)
    }
}

/// Interpret a doveadm `user` answer: `Ok(true)` exists, `Ok(false)`
/// EX_NOUSER, `Err` anything else.
pub fn parse_user_response(raw: &[u8]) -> Result<bool> {
    let v: serde_json::Value =
        serde_json::from_slice(raw).context("doveadm response is not JSON")?;
    let first = v
        .as_array()
        .and_then(|a| a.first())
        .and_then(|r| r.as_array())
        .ok_or_else(|| anyhow!("doveadm response is not a list of results"))?;
    match first.first().and_then(|k| k.as_str()) {
        Some("doveadmResponse") => Ok(true),
        Some("error") => {
            let code = first.get(1).and_then(|e| e.get("exitCode")).and_then(|c| {
                c.as_i64()
                    .or_else(|| c.as_str().and_then(|s| s.parse().ok()))
            });
            match code {
                Some(EX_NOUSER) => Ok(false),
                other => Err(anyhow!("doveadm user failed (exitCode {other:?})")),
            }
        }
        other => Err(anyhow!("unexpected doveadm result {other:?}")),
    }
}

fn read_key(path: &str) -> Result<String> {
    let key = std::fs::read_to_string(path).with_context(|| path.to_string())?;
    let key = key.trim().to_string();
    if key.is_empty() || key.chars().any(|c| c.is_control()) {
        return Err(anyhow!("{path}: no usable API key"));
    }
    Ok(key)
}

fn read_ca(path: &str) -> Result<Vec<reqwest::Certificate>> {
    let pem = std::fs::read(path).with_context(|| path.to_string())?;
    let certs = reqwest::Certificate::from_pem_bundle(&pem).with_context(|| path.to_string())?;
    if certs.is_empty() {
        return Err(anyhow!("{path}: no CA certificates"));
    }
    Ok(certs)
}

/// File problems of the account check (key and CA file), for
/// `--check-config`. An empty path is a configuration error, reported by
/// validation, and skipped here.
pub fn file_problems(cfg: &config::Legacy) -> Vec<String> {
    let mut out = Vec::new();
    if cfg.account_check != config::AccountCheck::Doveadm {
        return out;
    }
    if let Some(k) = cfg.doveadm_key_file.as_deref().filter(|p| !p.is_empty()) {
        if let Err(e) = read_key(k) {
            out.push(format!("legacy.doveadm_key_file: {e:#}"));
        }
    }
    if let Some(ca) = cfg.doveadm_ca_file.as_deref().filter(|p| !p.is_empty()) {
        if let Err(e) = read_ca(ca) {
            out.push(format!("legacy.doveadm_ca_file: {e:#}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The documented answers (doc.dovecot.org 2.4.5, "HTTP API").
    #[test]
    fn user_responses() {
        assert!(parse_user_response(
            br#"[["doveadmResponse",[{"field":"uid","value":"8001"}],"u"]]"#
        )
        .unwrap());
        assert!(
            !parse_user_response(br#"[["error",{"type":"exitCode","exitCode":67},"u"]]"#).unwrap()
        );
        for outage in [
            &br#"[["error",{"type":"exitCode","exitCode":75},"u"]]"#[..],
            br#"[["error",{"type":"unAuthorized","exitCode":0},"u"]]"#,
            br#"[["error",{"type":"internalError"},"u"]]"#,
            br#"[]"#,
            br#"{"x":1}"#,
            b"not json",
        ] {
            assert!(
                parse_user_response(outage).is_err(),
                "{}",
                String::from_utf8_lossy(outage)
            );
        }
    }
}
