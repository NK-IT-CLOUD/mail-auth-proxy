//! OAuth2 authentication proxy for IMAP, SMTP submission and ManageSieve in front
//! of Dovecot/Postfix. The binary (`src/main.rs`) parses the command line and
//! calls [`server::run`]; see `docs/architecture.md` for the architecture.

mod auth;
pub mod config;
#[cfg(fuzzing)]
#[doc(hidden)]
pub mod fuzz_api;
mod limits;
mod obs;
mod pool;
mod proto;
mod ratelimit;
mod route;
pub mod server;
mod wire;

/// `X.Y.Z (commit <sha12>)`. The commit comes from `MAIL_AUTH_PROXY_COMMIT` at build
/// time (set by `packaging/build.sh`); a plain `cargo build` prints `commit unknown`.
pub fn version() -> String {
    format!(
        "{} (commit {})",
        env!("CARGO_PKG_VERSION"),
        option_env!("MAIL_AUTH_PROXY_COMMIT").unwrap_or("unknown")
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn version_format() {
        let v = super::version();
        let (semver, rest) = v.split_once(' ').unwrap();
        assert_eq!(semver, env!("CARGO_PKG_VERSION"));
        let commit = rest
            .strip_prefix("(commit ")
            .and_then(|r| r.strip_suffix(')'))
            .unwrap();
        match option_env!("MAIL_AUTH_PROXY_COMMIT") {
            Some(c) => {
                assert_eq!(commit, c);
                assert!(c.len() == 12 && c.bytes().all(|b| b.is_ascii_hexdigit()));
            }
            None => assert_eq!(commit, "unknown"),
        }
    }
}
