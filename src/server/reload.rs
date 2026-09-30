//! SIGHUP: read the configuration file again and hand it to new connections.
//!
//! The new file must pass the checks of `--check-config` and may change
//! nothing that binds a socket (`config::plan`). Then a new `Generation` is
//! built next to the one in use, carrying over what runs across
//! configurations, and swapped in whole: a connection accepted from then on
//! gets the new one, a connection already open keeps the one it was accepted
//! with until it ends. Nothing is closed. When anything fails, the
//! configuration in use stays as it is.
//!
//! Every SIGHUP also re-reads the certificate files and refreshes the JWKS:
//! a successful reload loads the certificates anew; after a failed one each
//! certificate of the configuration in use is re-read on its own (renewed
//! files are served even while the configuration file is broken).

use super::{check, tls, Generation};
use crate::config;
use crate::obs::metrics;
use anyhow::{anyhow, Result};
use std::sync::Arc;
use tokio::sync::{watch, Notify};

/// Reload on every notification of `wanted`, one at a time; notifications
/// during a reload make one more.
pub(super) async fn run(
    path: String,
    current: watch::Sender<Arc<Generation>>,
    wanted: Arc<Notify>,
) {
    // The JWKS refresh of the last SIGHUP, if one ran; at most one at a time.
    let mut jwks_refresh: Option<tokio::task::JoinHandle<()>> = None;
    loop {
        wanted.notified().await;
        match reload(&path, &current).await {
            Ok(()) => metrics::record_config_reload(true),
            Err(e) => {
                metrics::record_config_reload(false);
                // One line: a TOML error spans several.
                let error = crate::obs::authlog::escape(&format!("{e:#}"));
                tracing::error!(target: crate::obs::target::MAIN, path=%path, error=%error,
                    "reload: configuration not loaded; the one in use stays");
                let certs = current.borrow().certs.clone();
                reload_certificates(&certs);
            }
        }
        let validator = current.borrow().shared.validator.clone();
        refresh_jwks(validator, &mut jwks_refresh);
    }
}

/// Read, check and take over the configuration at `path`.
async fn reload(path: &str, current: &watch::Sender<Arc<Generation>>) -> Result<()> {
    let loaded = config::load(path)?;
    let (problems, warnings) = check(&loaded);
    for w in &warnings {
        tracing::warn!(target: crate::obs::target::MAIN, "config: {w}");
    }
    if !problems.is_empty() {
        return Err(anyhow!("invalid configuration: {}", problems.join("; ")));
    }
    let old = current.borrow().clone();
    let plan = config::plan(&old.config, &loaded.config);
    if !plan.restart_required.is_empty() {
        return Err(anyhow!(
            "changed {}: needs a restart",
            plan.restart_required.join(", ")
        ));
    }
    let (new, fetched) = Generation::build(loaded.config, Some(&old)).await?;
    let replaced = old.clone();
    drop(old);
    // The metric label sets follow the configuration in use.
    metrics::register_certs(new.config.tls.pairs().map(|(_, cert, _)| cert));
    new.register_backends();
    new.certs.record_expiry();
    metrics::register_issuers(new.config.oauth.issuers.iter().map(|i| i.issuer.as_str()));
    for issuer in &fetched {
        metrics::record_jwks_fetch(issuer, true);
    }
    for (_, cert, _) in new.config.tls.pairs() {
        tracing::info!(target: crate::obs::target::MAIN, cert=%cert, "reload: certificate loaded");
    }
    new.announce();
    new.start();
    current.send_replace(Arc::new(new));
    replaced.retire();
    tracing::info!(target: crate::obs::target::MAIN, path=%path, changed=?plan.changed,
        "reload: configuration loaded; new connections use it, open ones keep theirs");
    Ok(())
}

/// Re-read each certificate of the configuration in use on its own: one
/// that fails keeps what it had.
fn reload_certificates(certs: &tls::CertStore) {
    for (cert, r) in certs.reload() {
        match r {
            Ok(()) => {
                tracing::info!(target: crate::obs::target::MAIN, cert=%cert, "reload: certificate loaded")
            }
            Err(e) => {
                tracing::error!(target: crate::obs::target::MAIN, cert=%cert, error=%format!("{e:#}"), "reload: certificate unusable; keeping the current one")
            }
        }
    }
}

/// Refresh every JWKS of `validator` in a task of its own (a slow IdP can
/// take up to the fetch timeout per issuer); while one still runs, no second
/// one starts.
fn refresh_jwks(
    validator: Arc<crate::auth::token::Validator>,
    running: &mut Option<tokio::task::JoinHandle<()>>,
) {
    if running.as_ref().is_some_and(|t| !t.is_finished()) {
        tracing::info!(target: crate::obs::target::MAIN, "reload: JWKS refresh already running");
        return;
    }
    *running = Some(tokio::spawn(async move {
        match validator.refresh().await {
            Ok(()) => tracing::info!(target: crate::obs::target::MAIN, "reload: JWKS refreshed"),
            Err(e) => {
                tracing::warn!(target: crate::obs::target::MAIN, error=%e, "reload: JWKS refresh failed; keeping previous keys")
            }
        }
    }));
}
