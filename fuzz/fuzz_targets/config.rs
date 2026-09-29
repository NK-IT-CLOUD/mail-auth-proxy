//! The configuration parser (`config::parse`: TOML, schema, validation,
//! normalisation) and the reload comparison (`config::plan`). A valid
//! configuration printed with `--print-config` must parse again to a valid
//! one that a reload finds unchanged. An input with a line `#---` holds two
//! configurations: when both are valid, the comparison must be symmetric and
//! find changes exactly when their printed forms differ.
#![no_main]

use libfuzzer_sys::fuzz_target;
use mail_auth_proxy::config;

fn valid(text: &str) -> Option<config::Config> {
    let loaded = config::parse(text).ok()?;
    loaded.ensure_valid().ok()?;
    Some(loaded.config)
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Some((a, b)) = text.split_once("\n#---\n") {
        let (Some(a), Some(b)) = (valid(a), valid(b)) else {
            return;
        };
        let (ab, ba) = (config::plan(&a, &b), config::plan(&b, &a));
        fn sorted(v: &[&'static str]) -> Vec<&'static str> {
            let mut v = v.to_vec();
            v.sort_unstable();
            v
        }
        assert_eq!(sorted(&ab.restart_required), sorted(&ba.restart_required));
        assert_eq!(ab.changed, ba.changed);
        let same = toml::to_string(&a).unwrap() == toml::to_string(&b).unwrap();
        assert_eq!(ab.changed.is_empty(), same, "{:?}", ab.changed);
        if same {
            assert!(ab.restart_required.is_empty(), "{:?}", ab.restart_required);
        }
        return;
    }
    let Some(config) = valid(text) else {
        return;
    };
    let printed = toml::to_string(&config).expect("print-config");
    let again = config::parse(&printed).expect("printed config parses");
    assert!(
        again.errors.is_empty(),
        "printed config invalid: {:?}\n{printed}",
        again.errors
    );
    let plan = config::plan(&config, &again.config);
    assert!(
        plan.restart_required.is_empty() && plan.changed.is_empty(),
        "printed config differs on reload: {plan:?}"
    );
});
