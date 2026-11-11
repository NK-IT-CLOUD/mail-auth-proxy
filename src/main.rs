use anyhow::Result;
use mail_auth_proxy::{config, server};

/// Default configuration path (the packaged location).
const DEFAULT_CONFIG: &str = "/etc/mail-auth-proxy/config.toml";

/// Log filter without `RUST_LOG`: the proxy's own targets (`mail_auth_proxy`
/// and below, which includes the `config:` warnings of this binary, and the
/// `authresult` lines on `authlog`) at `info`, every other target at `error`.
/// The dependencies' lines can carry client text the proxy never escaped
/// (rustls logs a rejected SNI value), and log parsers read the same stream.
const DEFAULT_LOG_FILTER: &str = "error,mail_auth_proxy=info,authlog=info";

const USAGE: &str = "usage: mail-auth-proxy [-t | --check-config | --print-config] [CONFIG]
       mail-auth-proxy --version
       mail-auth-proxy -h | --help

  CONFIG           configuration file (default /etc/mail-auth-proxy/config.toml)
  -t, --check-config
                   validate CONFIG, load its certificates and CA files, then exit
  --print-config   print the effective configuration
  --version        print the version
  -h, --help       print this usage";

enum Mode {
    Run,
    Check,
    Print,
}

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .ok();
    // Logs go to journald or stderr: ANSI escapes would break the `authresult`
    // fields that log parsers match (CrowdSec), so colour is always off.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(DEFAULT_LOG_FILTER)),
        )
        .with_ansi(false)
        // stderr, so --print-config output on stdout stays clean TOML.
        .with_writer(std::io::stderr)
        .init();

    let mut mode = Mode::Run;
    let mut path = None;
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "-t" | "--check-config" => mode = Mode::Check,
            "--print-config" => mode = Mode::Print,
            "--version" => {
                println!("mail-auth-proxy {}", mail_auth_proxy::version());
                return Ok(());
            }
            "-h" | "--help" => {
                println!("{USAGE}");
                return Ok(());
            }
            a if a.starts_with('-') || path.is_some() => {
                eprintln!("{USAGE}");
                std::process::exit(2);
            }
            a => path = Some(a.to_string()),
        }
    }
    let path = path.unwrap_or_else(|| DEFAULT_CONFIG.into());
    let loaded = config::load(&path)?;
    match mode {
        Mode::Print => {
            for w in &loaded.warnings {
                tracing::warn!("config: {w}");
            }
            print!("{}", toml::to_string(&loaded.config)?);
            loaded.ensure_valid()?;
            return Ok(());
        }
        Mode::Check => {
            // Validation errors and file errors together, all of them.
            let (problems, warnings) = server::check(&loaded);
            for w in &warnings {
                tracing::warn!("config: {w}");
            }
            if problems.is_empty() {
                println!("{path}: configuration OK ({} warning(s)); JWKS reachability is checked at start and reload",
                    warnings.len());
                return Ok(());
            }
            eprintln!(
                "{path}: invalid configuration:\n  - {}",
                problems.join("\n  - ")
            );
            std::process::exit(1);
        }
        Mode::Run => {
            for w in &loaded.warnings {
                tracing::warn!("config: {w}");
            }
            loaded.ensure_valid()?
        }
    }
    server::run(path, loaded.config).await
}

#[cfg(test)]
mod tests {
    use super::DEFAULT_LOG_FILTER;
    use std::sync::{Arc, Mutex};

    /// The lines the default filter lets through, written as in `main`.
    fn logged(emit: impl FnOnce()) -> String {
        let buf = Arc::new(Mutex::new(Vec::new()));
        let sink = buf.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::new(DEFAULT_LOG_FILTER))
            .with_ansi(false)
            .with_writer(move || Sink(sink.clone()))
            .finish();
        tracing::subscriber::with_default(subscriber, emit);
        let out = buf.lock().unwrap().clone();
        String::from_utf8(out).unwrap()
    }

    struct Sink(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Sink {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn default_filter_passes_own_targets_and_drops_foreign_warnings() {
        let out = logged(|| {
            tracing::info!(target: "authlog", "authresult result=\"ok\"");
            // `obs::target::MAIN` and one below it.
            tracing::info!(target: "mail_auth_proxy", "own info");
            tracing::info!(target: "mail_auth_proxy::token", "token info");
            tracing::debug!(target: "mail_auth_proxy", "own debug");
            // The `config:` warnings of this binary carry no explicit target.
            tracing::warn!("config: own warning");
            tracing::warn!(target: "rustls::msgs::handshake", "Illegal SNI extension");
            tracing::error!(target: "rustls::conn", "foreign error");
        });
        assert!(out.contains("authresult result=\"ok\""), "{out}");
        assert!(out.contains("own info"), "{out}");
        assert!(out.contains("token info"), "{out}");
        assert!(out.contains("config: own warning"), "{out}");
        assert!(out.contains("foreign error"), "{out}");
        assert!(!out.contains("own debug"), "{out}");
        assert!(!out.contains("Illegal SNI"), "{out}");
    }
}
