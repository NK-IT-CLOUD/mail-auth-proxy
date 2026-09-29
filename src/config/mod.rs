//! Configuration.
//!
//! The format is version 2: sectioned, strict (unknown keys are an
//! error), with per-issuer token rules and per-backend TLS. A file without
//! `config_version = 2` is rejected.
//!
//! Everything a misconfiguration could silently weaken fails boot instead:
//! unknown keys, an enabled password gate without SNI or networks, http JWKS,
//! limits of 0.
//!
//! `schema` holds the types and defaults (what a file may say and how
//! `--print-config` shows it), `validate` the checks serde cannot express and
//! the normalisation of short forms. `parse` runs them in that order.
//! `reload` compares a new configuration with the one in use (SIGHUP).

mod reload;
mod schema;
mod validate;

pub use reload::{plan, Plan};
pub use schema::*;
pub use validate::{check_domain_entry, check_service_url, check_user_entry, is_private_net};

/// A parsed configuration and what validation found. Syntax and schema
/// errors fail `parse` itself; `errors` holds the semantic problems, all of
/// them, so `--check-config` can list them together with file problems.
pub struct Loaded {
    pub config: Config,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}

/// Read, parse and validate `path`.
pub fn load(path: &str) -> anyhow::Result<Loaded> {
    let text = std::fs::read_to_string(path).map_err(|e| anyhow::anyhow!("{path}: {e}"))?;
    parse(&text)
}

/// Parse and validate a configuration text (see `Loaded`).
pub fn parse(text: &str) -> anyhow::Result<Loaded> {
    let raw: toml::Table = toml::from_str(text)?;
    // Checked before the schema, so a file in another format gets this
    // message instead of a list of unknown keys.
    if !raw.contains_key("config_version") {
        anyhow::bail!(
            "config_version is missing: the file must set `config_version = {CONFIG_VERSION}` at the top, before the first [section]"
        );
    }
    let config: Config = toml::from_str(text)?;
    if config.config_version != CONFIG_VERSION {
        anyhow::bail!(
            "config_version {} is not supported (expected {CONFIG_VERSION})",
            config.config_version
        );
    }
    let mut warnings = Vec::new();
    let mut errors = Vec::new();
    config.check(&mut errors, &mut warnings);
    let mut config = config;
    config.normalize();
    Ok(Loaded {
        config,
        warnings,
        errors,
    })
}

impl Loaded {
    /// Fail with every validation error, if there are any.
    pub fn ensure_valid(&self) -> anyhow::Result<()> {
        if self.errors.is_empty() {
            Ok(())
        } else {
            anyhow::bail!("invalid configuration:\n  - {}", self.errors.join("\n  - "))
        }
    }
}

/// Fixtures shared by the tests of `schema` and `validate`.
#[cfg(test)]
mod tests {
    use super::*;

    /// Parse and require validity, like the service does at start.
    pub(super) fn parse(text: &str) -> anyhow::Result<Loaded> {
        let l = super::parse(text)?;
        l.ensure_valid()?;
        Ok(l)
    }

    /// A flat file without sections and without `config_version`.
    const FLAT: &str = r#"
listen = "0.0.0.0:993"
tls_cert = "/c.pem"
tls_key = "/k.pem"
backend_addr = "192.0.2.10:10993"
"#;

    pub(super) const V2: &str = r#"
config_version = 2
[server]
hostname = "proxy.example.org"
[tls]
cert = "/c.pem"
key = "/k.pem"
[imap]
listen = "0.0.0.0:993"
backend = { address = "192.0.2.10:993", verify_name = "mail.example.org", client_ip = "proxy_v2" }
[oauth]
[[oauth.issuers]]
issuer = "https://idp.example/realms/mail"
jwks_url = "https://idp.example/realms/mail/certs"
audiences = ["dovecot"]
token_type = "keycloak"
"#;

    /// Only format 2 is read; anything else fails with a message naming the key.
    #[test]
    fn file_without_config_version_is_rejected() {
        for text in [FLAT.to_string(), V2.replace("config_version = 2\n", "")] {
            let e = super::parse(&text).err().unwrap().to_string();
            assert!(e.contains("config_version is missing"), "{e}");
            assert!(e.contains("config_version = 2"), "{e}");
        }
    }
}
