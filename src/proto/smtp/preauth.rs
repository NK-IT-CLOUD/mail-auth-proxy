//! The SMTP `AUTH` command: mechanism check and credential dialog.

use crate::auth::discovery::{self, Answer};
use crate::auth::legacy::MechSet;
use crate::auth::sasl::{Discovery, Mechanism};
use crate::auth::Withheld;
use crate::wire::line::{
    initial_response, is_bad_response, read_client_line, read_sasl_response, sasl_login_step,
};
use anyhow::{anyhow, Context as _, Result};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use zeroize::Zeroizing;

/// Parse `AUTH <MECH> [<IR>]` (already-read line) and gather the credential.
/// Returns the mechanism name, a classified `ClientAuthKind` and the
/// OAUTHBEARER `host`, if any. Never logs
/// secrets. Every error path answers the client (501, 503, 504 or 535)
/// before returning. A password mechanism `pw` does not offer never prompts for the
/// password: 504 and the error `Withheld` (RFC 4954 §4). An OAuth response
/// with an empty `auth` value (RFC 7628 §4.3) gets the error result
/// `challenge` (base64) as a `334`, then the failure once the client has
/// answered it, and ends as the error `Discovery`.
pub(crate) async fn read_smtp_auth<S>(
    line: &str,
    stream: &mut S,
    pw: MechSet,
    challenge: &str,
    idle: Duration,
) -> Result<(String, crate::auth::sasl::ClientAuthKind, Option<String>)>
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
    let inline = initial_response(parts.next());
    let Some(m) = Mechanism::parse(&mech) else {
        stream
            .write_all(b"504 5.5.4 Unrecognized authentication type\r\n")
            .await?;
        return Err(anyhow!(
            "unsupported mechanism {}",
            crate::obs::authlog::sanitize(&mech)
        ));
    };
    // Parsed also where passwords are not offered, so `auth::authorize` can
    // log and refuse it.
    match read_smtp_credential(stream, &mech, m, inline, pw, idle).await {
        Ok((kind, host)) => Ok((mech, kind, host)),
        Err(e) if e.is::<Withheld>() => {
            stream
                .write_all(b"504 5.5.4 password authentication not available on this endpoint\r\n")
                .await?;
            Err(e)
        }
        Err(e) if e.is::<Discovery>() => {
            stream
                .write_all(format!("334 {challenge}\r\n").as_bytes())
                .await?;
            stream.flush().await?;
            let answer = read_client_line(stream, idle)
                .await
                .map(|l| discovery::classify(&mech, &l))
                .map_err(anyhow::Error::new);
            let _ = stream
                .write_all(format!("{}\r\n", error_result_reply(&answer)).as_bytes())
                .await;
            Err(e.context(format!("discovery{}", Answer::note(&answer))))
        }
        // Not base64 or cancelled: 501 (RFC 4954 §4). Best effort: the
        // client may already be gone.
        Err(e) if is_bad_response(&e) => {
            let _ = stream
                .write_all(b"501 5.5.2 Invalid or cancelled authentication response\r\n")
                .await;
            Err(e)
        }
        // Decodes, but holds no valid credential: a failed authentication.
        Err(e) => {
            let _ = stream
                .write_all(b"535 5.7.8 Authentication credentials invalid\r\n")
                .await;
            Err(e)
        }
    }
}

/// The final reply after the error result (RFC 7628 §3.2.3): an abort (`*`)
/// or an undecodable answer is a 501 (RFC 4954 §4); anything else, and a
/// client that does not answer, gets 535.
pub(crate) fn error_result_reply(answer: &Result<Answer>) -> &'static str {
    match answer {
        Ok(Answer::Cancelled | Answer::Undecodable) => {
            "501 5.5.2 Invalid or cancelled authentication response"
        }
        _ => "535 5.7.8 Authentication credentials invalid",
    }
}

async fn read_smtp_credential<S>(
    stream: &mut S,
    mech: &str,
    m: Mechanism,
    inline: Option<Zeroizing<String>>,
    pw: MechSet,
    idle: Duration,
) -> Result<(crate::auth::sasl::ClientAuthKind, Option<String>)>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let withheld = |user: String| {
        anyhow::Error::new(Withheld {
            mech: mech.to_string(),
            user,
        })
    };
    let kind = match m {
        Mechanism::Plain => {
            if !pw.plain && inline.as_ref().is_none_or(|ir| ir.is_empty()) {
                return Err(withheld(String::new()));
            }
            let ir = smtp_ir(stream, inline, idle).await?;
            let (user, pass) = crate::auth::sasl::parse_plain(&ir).context("plain parse")?;
            crate::auth::sasl::ClientAuthKind::Password { user, pass }
        }
        Mechanism::Login => {
            // `AUTH LOGIN <b64user>` carries the username; asking for it again
            // would make the client answer with the password (see proto/imap/preauth.rs).
            let mut user = match inline {
                Some(ir) => crate::wire::line::decode_login_field(&ir)?,
                None if !pw.login => return Err(withheld(String::new())),
                None => sasl_login_step(stream, "334 VXNlcm5hbWU6", idle).await?, // base64("Username:")
            };
            if !pw.login {
                return Err(withheld(std::mem::take(&mut *user)));
            }
            let pass = sasl_login_step(stream, "334 UGFzc3dvcmQ6", idle).await?; // base64("Password:")
            if user.is_empty() || pass.is_empty() {
                return Err(anyhow!("LOGIN empty field"));
            }
            crate::auth::sasl::ClientAuthKind::Password {
                user: std::mem::take(&mut *user),
                pass,
            }
        }
        Mechanism::XOAuth2 | Mechanism::OAuthBearer => {
            let ir = smtp_ir(stream, inline, idle).await?;
            let creds = crate::auth::sasl::parse_sasl(mech, &ir).context("sasl parse")?;
            let kind = crate::auth::sasl::ClientAuthKind::OAuth {
                user: creds.user,
                token: creds.token,
            };
            return Ok((kind, creds.host));
        }
    };
    Ok((kind, None))
}

/// The initial response: inline if present (empty for `=`), else send
/// `334 \r\n` and read one line.
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

    const BOTH: MechSet = MechSet {
        plain: true,
        login: true,
    };

    #[tokio::test]
    async fn smtp_auth_xoauth2_inline() {
        let raw = "user=alice@example.org\x01auth=Bearer TOKEN\x01\x01";
        let ir = base64::engine::general_purpose::STANDARD.encode(raw);
        let (mut client, mut _server) = tokio::io::duplex(4096);
        let line = format!("AUTH XOAUTH2 {ir}");
        let (mech, kind, _) =
            read_smtp_auth(&line, &mut client, BOTH, "e30=", Tuning::default().idle)
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
        let (mech, kind, _) =
            read_smtp_auth(&line, &mut client, BOTH, "e30=", Tuning::default().idle)
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
            read_smtp_auth(
                "AUTH LOGIN",
                &mut server,
                BOTH,
                "e30=",
                Tuning::default().idle,
            )
            .await
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
        let (mech, kind, _) = t.await.unwrap().unwrap();
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
        let ir = base64::engine::general_purpose::STANDARD.encode("\0bob@example.invalid\0pw");
        let (_client, mut server) = tokio::io::duplex(4096);
        let line = format!("AUTH PLAIN {ir}");
        let (mech, kind, _) =
            read_smtp_auth(&line, &mut server, BOTH, "e30=", Tuning::default().idle)
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
        // 501 for a syntax error, a response that is not base64 or a
        // cancel; 535 for one that decodes but holds no credential (RFC
        // 4954 §4), `=` (the empty response) included.
        for (line, code) in [
            ("AUTH", "501 "),
            ("AUTH PLAIN !!notbase64!!", "501 "),
            ("AUTH XOAUTH2 Zm9v", "535 "),
            ("AUTH PLAIN =", "535 "),
            ("AUTH XOAUTH2 =", "535 "),
        ] {
            let (mut client, mut server) = tokio::io::duplex(4096);
            assert!(
                read_smtp_auth(line, &mut server, BOTH, "e30=", Tuning::default().idle)
                    .await
                    .is_err(),
                "{line}"
            );
            drop(server);
            let mut out = String::new();
            client.read_to_string(&mut out).await.unwrap();
            assert!(out.starts_with(code), "{line}: {out}");
        }
    }

    /// `AUTH LOGIN <b64user>`: only the password is asked for.
    #[tokio::test]
    async fn smtp_auth_login_with_initial_response() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let line = format!(
            "AUTH LOGIN {}",
            base64::engine::general_purpose::STANDARD.encode("dave@x")
        );
        let t = tokio::spawn(async move {
            read_smtp_auth(&line, &mut server, BOTH, "e30=", Tuning::default().idle).await
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
