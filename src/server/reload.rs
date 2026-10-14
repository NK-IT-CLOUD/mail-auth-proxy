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
//! Every SIGHUP also re-reads the certificate files, the metrics endpoint's
//! certificate and bearer token, and refreshes the JWKS: a successful reload
//! loads them anew; after a failed one each certificate and the token of the
//! configuration in use is re-read on its own (renewed files are served even
//! while the configuration file is broken), and one that fails keeps what it
//! had.

use super::{check, tls, Generation};
use crate::config;
use crate::obs::metrics;
use anyhow::{anyhow, Result};
use std::sync::Arc;
use tokio::sync::{watch, Notify};

/// The metrics endpoint's `Access`, when the endpoint runs.
type MetricsAccess = Option<watch::Sender<Arc<metrics::Access>>>;

/// Reload on every notification of `wanted`, one at a time; notifications
/// during a reload make one more.
pub(super) async fn run(
    path: String,
    current: watch::Sender<Arc<Generation>>,
    metrics_access: MetricsAccess,
    wanted: Arc<Notify>,
) {
    // The JWKS refresh of the last SIGHUP, if one ran; at most one at a time.
    let mut jwks_refresh: Option<tokio::task::JoinHandle<()>> = None;
    loop {
        wanted.notified().await;
        match reload(&path, &current, &metrics_access).await {
            Ok(()) => metrics::record_config_reload(true),
            Err(e) => {
                metrics::record_config_reload(false);
                // One line: a TOML error spans several.
                let error = crate::obs::authlog::escape(&format!("{e:#}"));
                tracing::error!(target: crate::obs::target::MAIN, path=%path, error=%error,
                    "reload: configuration not loaded; the one in use stays");
                let in_use = current.borrow().clone();
                reload_certificates(&in_use.certs);
                if let Some(access) = &metrics_access {
                    reload_metrics_files(&in_use.config.metrics, access);
                }
            }
        }
        let validator = current.borrow().shared.validator.clone();
        refresh_jwks(validator, &mut jwks_refresh);
    }
}

/// Read, check and take over the configuration at `path`.
async fn reload(
    path: &str,
    current: &watch::Sender<Arc<Generation>>,
    metrics_access: &MetricsAccess,
) -> Result<()> {
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
    // The endpoint (`metrics.enabled`) is the same in both (`plan`).
    let access = match metrics_access {
        Some(_) => Some(super::metrics_access(&new.config.metrics)?),
        None => None,
    };
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
    if let (Some(tx), Some(access)) = (metrics_access, access) {
        let m = &new.config.metrics;
        if let Some((cert, _)) = m.tls_pair() {
            tracing::info!(target: crate::obs::target::MAIN, cert=%cert, "reload: metrics certificate loaded");
        }
        if let Some(file) = &m.bearer_token_file {
            tracing::info!(target: crate::obs::target::MAIN, file=%file, "reload: metrics bearer token loaded");
        }
        tx.send_replace(Arc::new(access));
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

/// Re-read the metrics endpoint's certificate and token of the
/// configuration in use (`m`), each on its own: one that fails keeps what it
/// had.
fn reload_metrics_files(m: &config::Metrics, access: &watch::Sender<Arc<metrics::Access>>) {
    let in_use = access.borrow().clone();
    if let Some(tls) = &in_use.tls {
        for (cert, r) in tls.store().reload() {
            match r {
                Ok(()) => {
                    tracing::info!(target: crate::obs::target::MAIN, cert=%cert, "reload: metrics certificate loaded")
                }
                Err(e) => {
                    tracing::error!(target: crate::obs::target::MAIN, cert=%cert, error=%format!("{e:#}"), "reload: metrics certificate unusable; keeping the current one")
                }
            }
        }
    }
    let Some(file) = &m.bearer_token_file else {
        return;
    };
    match metrics::read_token(file) {
        Ok(token) => {
            access.send_replace(Arc::new(metrics::Access {
                tls: in_use.tls.clone(),
                token: Some(token),
            }));
            tracing::info!(target: crate::obs::target::MAIN, file=%file, "reload: metrics bearer token loaded");
        }
        Err(e) => {
            tracing::error!(target: crate::obs::target::MAIN, file=%file, error=%format!("{e:#}"), "reload: metrics bearer token unusable; keeping the current one")
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
