//! Command line: `-t` is the short form of `--check-config`.

use std::process::Command;

fn run(flag: &str) -> (Option<i32>, String) {
    let example = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/config.example.toml");
    let out = Command::new(env!("CARGO_BIN_EXE_mail-auth-proxy"))
        .arg(flag)
        .arg(example)
        .output()
        .unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.code(), text)
}

#[test]
fn short_t_checks_the_config_like_check_config() {
    let long = run("--check-config");
    // The example points at certificate files that do not exist here, so the
    // check lists them and exits 1; running the proxy would fail differently.
    assert_eq!(long.0, Some(1), "{}", long.1);
    assert!(long.1.contains("invalid configuration"), "{}", long.1);
    assert_eq!(run("-t"), long);
}
