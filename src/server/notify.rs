//! systemd service notification (`sd_notify`): one datagram to the socket in
//! `$NOTIFY_SOCKET`, without libsystemd. Outside systemd (no variable) it
//! does nothing. With `Type=notify` systemd considers the service started
//! only after `READY=1`, that is, after the JWKS were loaded and every
//! listener is bound.

use std::os::unix::net::UnixDatagram;

/// The service is up: every listener accepts connections.
pub(super) const READY: &str = "READY=1";
/// The service is shutting down.
pub(super) const STOPPING: &str = "STOPPING=1";

/// Send `state` to the service manager, if there is one. Failures are
/// logged, never fatal.
pub(super) fn notify(state: &str) {
    let Some(path) = std::env::var_os("NOTIFY_SOCKET") else {
        return;
    };
    let sent = UnixDatagram::unbound().and_then(|sock| {
        use std::os::unix::ffi::OsStrExt;
        match path.as_bytes().strip_prefix(b"@") {
            // An abstract socket name (Linux).
            Some(name) => {
                use std::os::linux::net::SocketAddrExt;
                let addr = std::os::unix::net::SocketAddr::from_abstract_name(name)?;
                sock.send_to_addr(state.as_bytes(), &addr)
            }
            None => sock.send_to(state.as_bytes(), &path),
        }
    });
    if let Err(e) = sent {
        tracing::warn!(target: crate::obs::target::MAIN, error=%e, state, "systemd notification failed");
    }
}
