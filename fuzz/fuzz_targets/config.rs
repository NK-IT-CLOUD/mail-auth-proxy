//! The configuration parser (`config::parse`: TOML, schema, validation,
//! normalisation). A valid configuration printed with `--print-config` must
//! parse again to a valid one.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(loaded) = mail_auth_proxy::config::parse(text) else {
        return;
    };
    if loaded.ensure_valid().is_err() {
        return;
    }
    let printed = toml::to_string(&loaded.config).expect("print-config");
    let again = mail_auth_proxy::config::parse(&printed).expect("printed config parses");
    assert!(
        again.errors.is_empty(),
        "printed config invalid: {:?}\n{printed}",
        again.errors
    );
});
