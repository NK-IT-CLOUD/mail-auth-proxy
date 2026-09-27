use anyhow::Result;
use mail_auth_proxy::{config, server};

/// Default configuration path (the packaged location).
const DEFAULT_CONFIG: &str = "/etc/mail-auth-proxy/config.toml";

const USAGE: &str = "usage: mail-auth-proxy [--check-config | --print-config] [CONFIG]
       mail-auth-proxy --version

  CONFIG           configuration file (default /etc/mail-auth-proxy/config.toml)
  --check-config   validate CONFIG, load its certificates and CA files, then exit
  --print-config   print the effective configuration
  --version        print the version";

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
    // Logs go to journald/stderr, never a TTY. ANSI colour escapes corrupt the
    // fixed `authresult` field format that CrowdSec and Wazuh parse (field names
    // wrapped in \x1b[..m), so disable colour deterministically here rather than
    // relying on a NO_COLOR env override at deploy time.
    tracing_subscriber::fmt()
        // Without RUST_LOG the authresult lines must still be written.
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_ansi(false)
        // stderr, so --print-config output on stdout stays clean TOML.
        .with_writer(std::io::stderr)
        .init();

    let mut mode = Mode::Run;
    let mut path = None;
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--check-config" => mode = Mode::Check,
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
    for w in &loaded.warnings {
        tracing::warn!("config: {w}");
    }
    match mode {
        Mode::Print => {
            print!("{}", toml::to_string(&loaded.config)?);
            loaded.ensure_valid()?;
            return Ok(());
        }
        Mode::Check => {
            // Validation errors and file errors together, all of them.
            let mut problems = loaded.errors.clone();
            problems.extend(server::file_problems(&loaded.config));
            if problems.is_empty() {
                println!("{path}: configuration OK ({} warning(s)); JWKS reachability is checked at start",
                    loaded.warnings.len());
                return Ok(());
            }
            eprintln!(
                "{path}: invalid configuration:\n  - {}",
                problems.join("\n  - ")
            );
            std::process::exit(1);
        }
        Mode::Run => loaded.ensure_valid()?,
    }
    server::run(loaded.config).await
}
