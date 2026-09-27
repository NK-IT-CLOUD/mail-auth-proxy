//! The accept loop shared by all listeners.

use super::Ctx;
use crate::limits;
use crate::obs::{authlog, metrics};
use anyhow::Result;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};

/// Pause after a failed `accept()` so a persistent error (fd exhaustion) does
/// not spin the loop at full speed.
pub(crate) const ACCEPT_BACKOFF: std::time::Duration = std::time::Duration::from_millis(100);

/// What ties the listeners and sessions to the server's lifetime.
#[derive(Clone)]
pub(super) struct Lifecycle {
    /// Becomes `true` at shutdown: stop accepting and close the port.
    pub stop: watch::Receiver<bool>,
    /// Held by every accept loop and session; the server's receiver sees
    /// the channel close when the last one is dropped.
    pub alive: mpsc::Sender<()>,
}

/// Accept on `listener` until shutdown, one task per admitted connection. A
/// transient accept error (EMFILE, ECONNABORTED) is logged and retried,
/// never fatal.
pub(super) fn spawn_listener<P, F, Fut>(
    listener: TcpListener,
    proto: metrics::Proto,
    ended: &'static str,
    ctx: Arc<Ctx<P>>,
    handler: F,
    life: Lifecycle,
) where
    P: Send + Sync + 'static,
    F: Fn(TcpStream, SocketAddr, Arc<Ctx<P>>, limits::ConnPermit) -> Fut + Copy + Send + 'static,
    Fut: Future<Output = Result<()>> + Send + 'static,
{
    let Lifecycle { mut stop, alive } = life;
    tokio::spawn(async move {
        loop {
            let accepted = tokio::select! {
                a = listener.accept() => a,
                // Shutdown: dropping the listener closes the port.
                _ = stop.wait_for(|s| *s) => break,
            };
            match accepted {
                Ok((tcp, peer)) => {
                    let Some(permit) = ctx.limits.admit(peer.ip().to_canonical()) else {
                        metrics::record_rejected(proto);
                        tracing::debug!(target: crate::obs::target::MAIN, %peer, "{ended}: connection limit reached, closing");
                        continue;
                    };
                    let ctx = ctx.clone();
                    let alive = alive.clone();
                    tokio::spawn(async move {
                        let _alive = alive;
                        if let Err(e) = handler(tcp, peer, ctx, permit).await {
                            // The whole chain (`{:#}`), so an outage keeps its
                            // cause. Error texts can carry client input; escape it.
                            let error = authlog::escape(&format!("{e:#}"));
                            if e.is::<crate::auth::Refused>() {
                                // The authresult line already recorded it.
                                tracing::debug!(target: crate::obs::target::MAIN, %peer, error=%error, "{}", ended);
                            } else {
                                tracing::warn!(target: crate::obs::target::MAIN, %peer, error=%error, "{}", ended);
                            }
                        }
                    });
                }
                Err(e) => {
                    tracing::error!(target: crate::obs::target::MAIN, error=%e, "{ended}: accept error");
                    tokio::time::sleep(ACCEPT_BACKOFF).await;
                }
            }
        }
    });
}
