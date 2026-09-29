//! What a reload (SIGHUP) can take over: a new configuration compared with
//! the one in use.

use super::Config;

/// The difference between the configuration in use and a new one.
#[derive(Debug, PartialEq, Eq)]
pub struct Plan {
    /// Keys whose change needs a restart (they bind a socket at startup).
    /// Not empty: the reload is refused as a whole.
    pub restart_required: Vec<&'static str>,
    /// Top-level sections that differ, for the log.
    pub changed: Vec<String>,
}

/// Compare the configuration in use `old` with `new`; both validated.
///
/// Restart-only: the listener addresses (`imap.listen`, `submission.listen`,
/// `sieve.listen`), whether `[submission]` and `[sieve]` exist (a listener
/// more or less), and the metrics endpoint (`metrics.enabled`,
/// `metrics.listen`). Everything else is taken over by a reload.
pub fn plan(old: &Config, new: &Config) -> Plan {
    let mut restart_required = Vec::new();
    if old.imap.listen != new.imap.listen {
        restart_required.push("imap.listen");
    }
    let listeners = [
        (
            "submission",
            "submission.listen",
            old.submission.as_ref().map(|s| &s.listen),
            new.submission.as_ref().map(|s| &s.listen),
        ),
        (
            "sieve",
            "sieve.listen",
            old.sieve.as_ref().map(|s| &s.listen),
            new.sieve.as_ref().map(|s| &s.listen),
        ),
    ];
    for (section, key, old, new) in listeners {
        match (old, new) {
            (Some(a), Some(b)) if a != b => restart_required.push(key),
            (Some(_), None) | (None, Some(_)) => restart_required.push(section),
            _ => {}
        }
    }
    let (om, nm) = (&old.metrics, &new.metrics);
    if om.is_enabled() != nm.is_enabled() {
        restart_required.push("metrics.enabled");
    } else if om.is_enabled() && om.listen != nm.listen {
        restart_required.push("metrics.listen");
    }
    Plan {
        restart_required,
        changed: changed_sections(old, new),
    }
}

/// The top-level keys whose printed value differs (`--print-config` form),
/// in name order.
fn changed_sections(old: &Config, new: &Config) -> Vec<String> {
    let table = |c: &Config| toml::Table::try_from(c).unwrap_or_default();
    let (old, new) = (table(old), table(new));
    let mut keys: Vec<&String> = old.keys().chain(new.keys()).collect();
    keys.sort();
    keys.dedup();
    keys.into_iter()
        .filter(|k| old.get(*k) != new.get(*k))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::tests::{parse, V2};

    fn plan_for(old: &str, new: &str) -> Plan {
        plan(&parse(old).unwrap().config, &parse(new).unwrap().config)
    }

    const SUB: &str =
        "[submission]\nlisten = \"0.0.0.0:587\"\nbackend = { address = \"192.0.2.10:587\" }\n";
    const SIEVE: &str =
        "[sieve]\nlisten = \"0.0.0.0:4190\"\nbackend = { address = \"192.0.2.10:4190\" }\n";

    #[test]
    fn same_configuration_changes_nothing() {
        let text = format!("{V2}{SUB}{SIEVE}");
        assert_eq!(
            plan_for(&text, &text),
            Plan {
                restart_required: vec![],
                changed: vec![]
            }
        );
    }

    /// Everything but the listeners and the metrics endpoint is reloadable,
    /// backends included; the log names the sections.
    #[test]
    fn reloadable_changes_name_their_sections() {
        let old = format!("{V2}{SUB}");
        let new = format!(
            "{}{}[limits]\nmax_auth_attempts = 5\n[legacy]\nfailure_delay_ms = 10\n",
            V2.replace("proxy.example.org", "mx.example.org")
                .replace("192.0.2.10:993", "192.0.2.11:993"),
            SUB.replace("192.0.2.10:587", "192.0.2.11:587")
        );
        let p = plan_for(&old, &new);
        assert!(p.restart_required.is_empty(), "{p:?}");
        assert_eq!(
            p.changed,
            ["imap", "legacy", "limits", "server", "submission"]
        );
    }

    #[test]
    fn listeners_and_metrics_need_a_restart() {
        let base = format!("{V2}{SUB}[metrics]\nlisten = \"127.0.0.1:9102\"\n");
        for (new, key) in [
            (base.replace("0.0.0.0:993", "0.0.0.0:1993"), "imap.listen"),
            (
                base.replace("0.0.0.0:587", "127.0.0.1:587"),
                "submission.listen",
            ),
            (base.replace(SUB, ""), "submission"),
            (format!("{base}{SIEVE}"), "sieve"),
            (
                base.replace("127.0.0.1:9102", "127.0.0.1:9103"),
                "metrics.listen",
            ),
            (
                base.replace("[metrics]\n", "[metrics]\nenabled = false\n"),
                "metrics.enabled",
            ),
        ] {
            assert_eq!(plan_for(&base, &new).restart_required, [key], "{new}");
        }
        let with_sieve = format!("{base}{SIEVE}");
        assert_eq!(
            plan_for(
                &with_sieve,
                &with_sieve.replace("0.0.0.0:4190", "0.0.0.0:2000")
            )
            .restart_required,
            ["sieve.listen"]
        );
        // A disabled endpoint binds nothing: its address may change.
        let off = V2.to_string() + "[metrics]\nenabled = false\nlisten = \"127.0.0.1:9102\"\n";
        assert!(plan_for(&off, &off.replace("9102", "9103"))
            .restart_required
            .is_empty());
    }
}
