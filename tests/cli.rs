//! Command line: `-t` is the short form of `--check-config`; the usage text.

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

/// `-h` and `--help` print the usage on stdout with status 0, an unknown
/// option on stderr with status 2; the usage names every form it accepts.
#[test]
fn usage_lists_every_option() {
    for flag in ["-h", "--help", "--bogus"] {
        let out = Command::new(env!("CARGO_BIN_EXE_mail-auth-proxy"))
            .arg(flag)
            .output()
            .unwrap();
        let (code, text) = if flag == "--bogus" {
            (2, String::from_utf8_lossy(&out.stderr).into_owned())
        } else {
            (0, String::from_utf8_lossy(&out.stdout).into_owned())
        };
        assert_eq!(out.status.code(), Some(code), "{flag}: {text}");
        for form in [
            "-t, --check-config",
            "--print-config",
            "--version",
            "-h, --help",
            "mail-auth-proxy -h | --help",
        ] {
            assert!(text.contains(form), "{flag}: {form:?} missing in\n{text}");
        }
    }
}
