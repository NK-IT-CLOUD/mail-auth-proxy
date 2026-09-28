//! The SMTP `AUTH` command: mechanism check and credential dialog.

use crate::wire::line::{read_sasl_response, sasl_login_step};
use anyhow::{anyhow, Result};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use zeroize::Zeroizing;

/// Parse `AUTH <MECH> [<IR>]` (already-read line) and gather the credential.
/// Returns the mechanism name and a classified `ClientAuthKind`. Never logs
/// secrets. Every error path answers the client (501/504) before returning.
pub(super) async fn read_smtp_auth<S>(
    line: &str,
    stream: &mut S,
    idle: Duration,
) -> Result<(String, crate::auth::sasl::ClientAuthKind)>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut parts = line.splitn(3, ' ');
    if !parts.next().is_some_and(|v| v.eq_ignore_ascii_case("AUTH")) {
        stream
            .write_all(b"503 5.5.1 Expected AUTH command\r\n")
            .await?;
        return Err(anyhow!("expected AUTH"));
    }
    let Some(mech) = parts.next().filter(|m| !m.is_empty()).map(str::to_string) else {
        stream
            .write_all(b"501 5.5.4 Syntax: AUTH mechanism [initial-response]\r\n")
            .await?;
        return Err(anyhow!("no mechanism in AUTH"));
    };
    let inline = parts
        .next()
        .filter(|s| !s.is_empty())
        .map(|s| Zeroizing::new(s.to_owned()));
    if !matches!(
        mech.to_ascii_uppercase().as_str(),
        "XOAUTH2" | "OAUTHBEARER" | "PLAIN" | "LOGIN"
    ) {
        stream
            .write_all(b"504 5.5.4 Unrecognized authentication type\r\n")
            .await?;
        return Err(anyhow!(
            "unsupported mechanism {}",
            crate::obs::authlog::sanitize(&mech)
        ));
    }
    // Always parse the credential (even password mechs on an OAuth-only endpoint):
    // the handler logs the attempt then enforces the SNI+source-IP block.
    match read_smtp_credential(stream, &mech, inline, idle).await {
        Ok(kind) => Ok((mech, kind)),
        Err(e) => {
            // Undecodable, empty or cancelled response. Best effort: the
            // client may already be gone.
            let _ = stream
                .write_all(b"501 5.5.2 Invalid or cancelled authentication response\r\n")
                .await;
            Err(e)
        }
    }
}

async fn read_smtp_credential<S>(
    stream: &mut S,
    mech: &str,
    inline: Option<Zeroizing<String>>,
    idle: Duration,
) -> Result<crate::auth::sasl::ClientAuthKind>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    Ok(match mech.to_ascii_uppercase().as_str() {
        "PLAIN" => {
            let ir = smtp_ir(stream, inline, idle).await?;
            let (user, pass) =
                crate::auth::sasl::parse_plain(&ir).map_err(|e| anyhow!("plain parse: {e}"))?;
            crate::auth::sasl::ClientAuthKind::Password { user, pass }
        }
        "LOGIN" => {
            // `AUTH LOGIN <b64user>` carries the username; asking for it again
            // would make the client answer with the password (see proto/imap/preauth.rs).
            let mut user = match inline {
                Some(ir) => crate::wire::line::decode_login_field(&ir)?,
                None => sasl_login_step(stream, "334 VXNlcm5hbWU6", idle).await?, // base64("Username:")
            };
            let pass = sasl_login_step(stream, "334 UGFzc3dvcmQ6", idle).await?; // base64("Password:")
            if user.is_empty() || pass.is_empty() {
                return Err(anyhow!("LOGIN empty field"));
            }
            crate::auth::sasl::ClientAuthKind::Password {
                user: std::mem::take(&mut *user),
                pass,
            }
        }
        _ => {
            let ir = smtp_ir(stream, inline, idle).await?;
            let creds =
                crate::auth::sasl::parse_sasl(mech, &ir).map_err(|e| anyhow!("sasl parse: {e}"))?;
            crate::auth::sasl::ClientAuthKind::OAuth {
                user: creds.user,
                token: creds.token,
            }
        }
    })
}

/// SASL-IR for SMTP: inline if present, else send `334 \r\n` and read one line.
async fn smtp_ir<S>(
    stream: &mut S,
    inline: Option<Zeroizing<String>>,
    idle: Duration,
) -> Result<Zeroizing<String>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    match inline {
        Some(ir) => Ok(ir),
        None => {
            stream.write_all(b"334 \r\n").await?;
            read_sasl_response(stream, idle).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::Tuning;
    use base64::Engine as _;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn smtp_auth_xoauth2_inline() {
        let raw = "user=alice@example.org\x01auth=Bearer TOKEN\x01\x01";
        let ir = base64::engine::general_purpose::STANDARD.encode(raw);
        let (mut client, mut _server) = tokio::io::duplex(4096);
        let line = format!("AUTH XOAUTH2 {ir}");
        let (mech, kind) = read_smtp_auth(&line, &mut client, Tuning::default().idle)
            .await
            .unwrap();
        assert_eq!(mech, "XOAUTH2");
        match kind {
            crate::auth::sasl::ClientAuthKind::OAuth { user, token } => {
                assert_eq!(user, "alice@example.org");
                assert_eq!(*token, "TOKEN");
            }
            _ => panic!("expected OAuth"),
        }
    }

    #[tokio::test]
    async fn smtp_auth_plain_inline() {
        let ir = base64::engine::general_purpose::STANDARD.encode("\0bob@example.org\0pw");
        let (mut client, mut _server) = tokio::io::duplex(4096);
        let line = format!("AUTH PLAIN {ir}");
        let (mech, kind) = read_smtp_auth(&line, &mut client, Tuning::default().idle)
            .await
            .unwrap();
        assert_eq!(mech, "PLAIN");
        match kind {
            crate::auth::sasl::ClientAuthKind::Password { user, pass } => {
                assert_eq!(user, "bob@example.org");
                assert_eq!(*pass, "pw");
            }
            _ => panic!("expected Password"),
        }
    }

    #[tokio::test]
    async fn smtp_auth_login_two_step() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let t = tokio::spawn(async move {
            read_smtp_auth("AUTH LOGIN", &mut server, Tuning::default().idle).await
        });
        let mut buf = [0u8; 64];
        let n = client.read(&mut buf).await.unwrap();
        assert!(std::str::from_utf8(&buf[..n])
            .unwrap()
            .contains("334 VXNlcm5hbWU6"));
        client
            .write_all(
                format!(
                    "{}\r\n",
                    base64::engine::general_purpose::STANDARD.encode("carol@x")
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let n = client.read(&mut buf).await.unwrap();
        assert!(std::str::from_utf8(&buf[..n])
            .unwrap()
            .contains("334 UGFzc3dvcmQ6"));
        client
            .write_all(
                format!(
                    "{}\r\n",
                    base64::engine::general_purpose::STANDARD.encode("hunter2")
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let (mech, kind) = t.await.unwrap().unwrap();
        assert_eq!(mech, "LOGIN");
        match kind {
            crate::auth::sasl::ClientAuthKind::Password { user, pass } => {
                assert_eq!(user, "carol@x");
                assert_eq!(*pass, "hunter2");
            }
            _ => panic!("expected Password"),
        }
    }

    #[tokio::test]
    async fn smtp_plain_parses_for_handler_enforcement() {
        // read_smtp_auth always parses PLAIN (so the handler can log the attempt);
        // the OAuth-only block is enforced by the handler, not here.
        let ir = base64::engine::general_purpose::STANDARD.encode("\0bob@example.invalid\0pw");
        let (_client, mut server) = tokio::io::duplex(4096);
        let line = format!("AUTH PLAIN {ir}");
        let (mech, kind) = read_smtp_auth(&line, &mut server, Tuning::default().idle)
            .await
            .unwrap();
        assert_eq!(mech, "PLAIN");
        match kind {
            crate::auth::sasl::ClientAuthKind::Password { user, pass } => {
                assert_eq!(user, "bob@example.invalid");
                assert_eq!(*pass, "pw");
            }
            _ => panic!("expected Password (parsed for logging)"),
        }
    }

    /// Undecodable responses and a bare AUTH get an SMTP reply, not a silent close.
    #[tokio::test]
    async fn smtp_auth_errors_are_answered() {
        for line in ["AUTH", "AUTH PLAIN !!notbase64!!", "AUTH XOAUTH2 Zm9v"] {
            let (mut client, mut server) = tokio::io::duplex(4096);
            assert!(
                read_smtp_auth(line, &mut server, Tuning::default().idle)
                    .await
                    .is_err(),
                "{line}"
            );
            drop(server);
            let mut out = String::new();
            client.read_to_string(&mut out).await.unwrap();
            assert!(out.starts_with("501 "), "{line}: {out}");
        }
    }

    /// `AUTH LOGIN <b64user>`: only the password is asked for. Asking for the
    /// username again would make clients send the password as the username.
    #[tokio::test]
    async fn smtp_auth_login_with_initial_response() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let line = format!(
            "AUTH LOGIN {}",
            base64::engine::general_purpose::STANDARD.encode("dave@x")
        );
        let t = tokio::spawn(async move {
            read_smtp_auth(&line, &mut server, Tuning::default().idle).await
        });
        let mut buf = [0u8; 64];
        let n = client.read(&mut buf).await.unwrap();
        assert!(
            std::str::from_utf8(&buf[..n])
                .unwrap()
                .starts_with("334 UGFzc3dvcmQ6"),
            "must prompt for the password"
        );
        client
            .write_all(
                format!(
                    "{}\r\n",
                    base64::engine::general_purpose::STANDARD.encode("s3cret")
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        match t.await.unwrap().unwrap().1 {
            crate::auth::sasl::ClientAuthKind::Password { user, pass } => {
                assert_eq!(user, "dave@x");
                assert_eq!(*pass, "s3cret");
            }
            _ => panic!("expected Password"),
        }
    }
}
