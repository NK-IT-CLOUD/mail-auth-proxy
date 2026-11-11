//! Command line: `-t` is the short form of `--check-config`; `--online`
//! fetches the JWKS as a start does; the usage text.

mod common;
use common::*;

use std::process::Command;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

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
            "--online",
            "exit status:",
            "--print-config",
            "--version",
            "-h, --help",
            "mail-auth-proxy -h | --help",
        ] {
            assert!(text.contains(form), "{flag}: {form:?} missing in\n{text}");
        }
    }
}

// ── --check-config --online ─────────────────────────────────────────────────

const PARTNER: &str = "https://partner.test/realms/mail";

/// A valid configuration whose issuers fetch their JWKS from `jwks`
/// (`ISSUER` first, then `PARTNER`), written to the PKI's directory.
fn online_config(pki: &Pki, jwks: &[String]) -> std::path::PathBuf {
    let mut text = format!(
        "config_version = 2\n[server]\nhostname = \"{HOSTNAME}\"\n[tls]\ncert = \"{}\"\nkey = \"{}\"\n[imap]\nlisten = \"127.0.0.10:0\"\nbackend = {{ address = \"127.0.0.1:1\", verify_name = \"{BACKEND_NAME}\", ca_file = \"{}\" }}\n[oauth]\n",
        pki.proxy_cert.display(),
        pki.proxy_key.display(),
        pki.ca_file.display()
    );
    for (issuer, url) in [ISSUER, PARTNER].iter().zip(jwks) {
        text.push_str(&format!(
            "[[oauth.issuers]]\nissuer = \"{issuer}\"\njwks_url = \"{url}\"\naudiences = [\"{AUDIENCE}\"]\ntoken_type = \"keycloak\"\n"
        ));
    }
    let path = pki.dir.path().join("online.toml");
    std::fs::write(&path, text).unwrap();
    path
}

/// The binary with `args`, run off the runtime so the mock JWKS endpoints
/// keep serving: exit status, stdout, stderr.
async fn run_args(args: &[&str]) -> (Option<i32>, String, String) {
    let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
    let out = tokio::task::spawn_blocking(move || {
        Command::new(env!("CARGO_BIN_EXE_mail-auth-proxy"))
            .args(&args)
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// A JWKS endpoint on 127.0.0.1 that answers every request with `body`.
async fn serve_jwks(body: &'static str) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut buf = [0u8; 1024];
                while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => head.extend_from_slice(&buf[..n]),
                    }
                }
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = s.write_all(resp.as_bytes()).await;
                let _ = s.shutdown().await;
            });
        }
    });
    format!("http://{addr}/certs")
}

/// A local port nothing listens on: its JWKS fetch is refused.
async fn closed_url() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    format!("http://{addr}/certs")
}

/// With every JWKS usable, `--online` passes with status 0 and fetched
/// each of them; without it nothing is fetched and the line points to it.
#[tokio::test]
async fn online_check_passes_when_every_jwks_loads() {
    let pki = Pki::new();
    let (a, b) = (Idp::start().await, Idp::start().await);
    let path = online_config(&pki, &[a.jwks_url(), b.jwks_url()]);
    let path = path.to_str().unwrap();

    let (code, out, err) = run_args(&["--check-config", path]).await;
    assert_eq!(code, Some(0), "{out}{err}");
    assert!(out.contains("with --online"), "{out}");
    assert_eq!(a.fetches.load(std::sync::atomic::Ordering::SeqCst), 0);

    for flags in [["--check-config", "--online"], ["--online", "-t"]] {
        let (code, out, err) = run_args(&[flags[0], flags[1], path]).await;
        assert_eq!(code, Some(0), "{flags:?}: {out}{err}");
        assert!(out.contains("JWKS of every issuer loaded"), "{out}");
    }
    assert_eq!(a.fetches.load(std::sync::atomic::Ordering::SeqCst), 2);
    assert_eq!(b.fetches.load(std::sync::atomic::Ordering::SeqCst), 2);
}

/// An issuer whose JWKS cannot be fetched, or holds no usable signing key:
/// status 3 and one line naming that issuer and the reason, printed once
/// (not also logged); the issuer whose JWKS loads is not named.
#[tokio::test]
async fn online_check_names_each_issuer_without_usable_jwks() {
    let pki = Pki::new();
    let idp = Idp::start().await;
    let refused = closed_url().await;
    let empty = serve_jwks(r#"{"keys":[]}"#).await;
    for (urls, reason) in [
        (
            vec![idp.jwks_url(), refused.clone()],
            format!("{PARTNER}: fetching {refused}: "),
        ),
        (
            vec![idp.jwks_url(), empty.clone()],
            format!("{PARTNER}: the JWKS has no usable signing keys"),
        ),
    ] {
        let path = online_config(&pki, &urls);
        let (code, out, err) = run_args(&["-t", "--online", path.to_str().unwrap()]).await;
        let text = format!("{out}{err}");
        assert_eq!(code, Some(3), "{text}");
        assert!(text.contains("configuration valid"), "{text}");
        assert!(
            text.contains(&format!("  - {reason}")),
            "{reason:?} missing in\n{text}"
        );
        assert_eq!(text.matches(PARTNER).count(), 1, "{text}");
        assert!(!text.contains(&format!("{ISSUER}:")), "{text}");
    }

    // Both down: both named.
    let path = online_config(&pki, &[refused.clone(), empty]);
    let (code, out, err) = run_args(&["-t", "--online", path.to_str().unwrap()]).await;
    assert_eq!(code, Some(3), "{out}{err}");
    assert!(
        err.contains(&format!("  - {ISSUER}: fetching {refused}: ")),
        "{err}"
    );
    assert!(
        err.contains(&format!("  - {PARTNER}: the JWKS has no usable")),
        "{err}"
    );
}

/// An invalid configuration fails with status 1 as without `--online`, and
/// no JWKS is fetched for it: a missing certificate, and a file that does
/// not parse.
#[tokio::test]
async fn online_check_of_an_invalid_config_fails_offline() {
    let pki = Pki::new();
    let idp = Idp::start().await;
    let path = online_config(&pki, &[idp.jwks_url()]);
    let valid = std::fs::read_to_string(&path).unwrap();
    let cert = pki.proxy_cert.display().to_string();
    for (text, expect) in [
        (
            valid.replace(&cert, "/nonexistent/cert.pem"),
            "invalid configuration",
        ),
        (format!("{valid}unknown_key = 1\n"), "unknown field"),
    ] {
        std::fs::write(&path, text).unwrap();
        let (code, out, err) =
            run_args(&["--check-config", "--online", path.to_str().unwrap()]).await;
        assert_eq!(code, Some(1), "{out}{err}");
        assert!(err.contains(expect), "{expect:?} missing in\n{err}");
    }
    assert_eq!(idp.fetches.load(std::sync::atomic::Ordering::SeqCst), 0);
}

/// `--online` belongs to the check: alone or with `--print-config` it is a
/// usage error (status 2, the usage on stderr).
#[tokio::test]
async fn online_without_check_config_is_a_usage_error() {
    let pki = Pki::new();
    let idp = Idp::start().await;
    let path = online_config(&pki, &[idp.jwks_url()]);
    let path = path.to_str().unwrap();
    for args in [
        vec!["--online"],
        vec!["--online", path],
        vec!["--print-config", "--online", path],
    ] {
        let (code, out, err) = run_args(&args).await;
        assert_eq!(code, Some(2), "{args:?}: {out}{err}");
        assert!(err.starts_with("usage: "), "{args:?}: {err}");
    }
    assert_eq!(idp.fetches.load(std::sync::atomic::Ordering::SeqCst), 0);
}
