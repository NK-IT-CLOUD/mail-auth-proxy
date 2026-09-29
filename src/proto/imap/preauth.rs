//! The IMAP pre-auth dialog: greeting, CAPABILITY/NOOP/ID/LOGOUT, and the
//! credential of a LOGIN or AUTHENTICATE command.

use crate::auth::legacy::MechSet;
use crate::wire::line::{read_client_line, read_sasl_response, sasl_login_step};
use crate::wire::Tuning;
use anyhow::{anyhow, Result};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

/// The pre-auth capabilities. OAuth mechanisms always; PLAIN/LOGIN only as
/// far as the legacy gate offers them on this connection. LOGINDISABLED
/// (RFC 3501 §6.2.3) tells clients not to try the LOGIN command, which counts
/// as the LOGIN mechanism.
fn capabilities(pw: MechSet) -> String {
    let mut caps = String::from("IMAP4rev1 IMAP4rev2 SASL-IR");
    if !pw.login {
        caps.push_str(" LOGINDISABLED");
    }
    caps.push_str(" AUTH=XOAUTH2 AUTH=OAUTHBEARER");
    if pw.plain {
        caps.push_str(" AUTH=PLAIN");
    }
    if pw.login {
        caps.push_str(" AUTH=LOGIN");
    }
    caps
}

pub struct ClientAuth {
    pub tag: String,
    pub mech: String,
    pub kind: crate::auth::sasl::ClientAuthKind,
}

/// Read the client's pre-auth dialog up to a credential. `pw` only decides
/// what is advertised; a password sent anyway is still parsed, so
/// `auth::authorize` can log and refuse it.
///
/// RFC 3501 requires CAPABILITY/NOOP/LOGOUT to work in NOT-AUTHENTICATED state,
/// and stock clients (Python imaplib) send an explicit CAPABILITY before
/// authenticating and use the LOGIN *command* (not the SASL LOGIN mechanism).
/// The loop is bounded so an unauthenticated peer can't hold the slot.
///
/// `Ok(None)`: LOGOUT, or a close right after the greeting — a clean end, not
/// a failure. Every refusal is answered; a read error or timeout is not.
/// `name` is the server name shown in the greeting.
pub async fn read_client_auth<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    pw: MechSet,
    name: &str,
    tuning: &Tuning,
) -> Result<Option<ClientAuth>> {
    let caps = capabilities(pw);
    stream
        .write_all(format!("* OK [CAPABILITY {caps}] {name} ready\r\n").as_bytes())
        .await?;
    for n in 0..tuning.max_preauth_commands {
        let line = match read_client_line(stream, tuning.idle).await {
            Ok(l) => l,
            // Connect, read the greeting, disconnect: a health check or port
            // probe, not a failed login.
            Err(e) if n == 0 && e.is_eof() => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let mut parts = line.splitn(3, ' ');
        let tag = parts.next().unwrap_or("").to_string();
        let Some(cmd) = parts.next().filter(|c| !tag.is_empty() && !c.is_empty()) else {
            stream.write_all(b"* BAD expected: tag command\r\n").await?;
            return Err(anyhow!("line without tag and command"));
        };
        let rest = parts.next().unwrap_or("");
        match cmd.to_ascii_uppercase().as_str() {
            "CAPABILITY" => {
                stream
                    .write_all(
                        format!("* CAPABILITY {caps}\r\n{tag} OK CAPABILITY completed\r\n")
                            .as_bytes(),
                    )
                    .await?;
            }
            "NOOP" => {
                stream
                    .write_all(format!("{tag} OK NOOP completed\r\n").as_bytes())
                    .await?;
            }
            "ID" => {
                stream
                    .write_all(format!("* ID NIL\r\n{tag} OK ID completed\r\n").as_bytes())
                    .await?;
            }
            "LOGOUT" => {
                stream
                    .write_all(
                        format!("* BYE {name} signing off\r\n{tag} OK LOGOUT completed\r\n")
                            .as_bytes(),
                    )
                    .await?;
                stream.flush().await?;
                return Ok(None);
            }
            "LOGIN" => {
                let (user, pass) = match parse_two_astrings(rest) {
                    Ok(up) => up,
                    Err(e) => {
                        stream
                            .write_all(format!("{tag} BAD LOGIN arguments\r\n").as_bytes())
                            .await?;
                        return Err(anyhow!("LOGIN parse: {e}"));
                    }
                };
                if user.is_empty() || pass.is_empty() {
                    stream
                        .write_all(format!("{tag} NO LOGIN empty field\r\n").as_bytes())
                        .await?;
                    return Err(anyhow!("LOGIN empty field"));
                }
                return Ok(Some(ClientAuth {
                    tag,
                    mech: "LOGIN".into(),
                    kind: crate::auth::sasl::ClientAuthKind::Password { user, pass },
                }));
            }
            "AUTHENTICATE" => {
                let mut aparts = rest.splitn(2, ' ');
                let Some(mech) = aparts.next().filter(|m| !m.is_empty()).map(str::to_string) else {
                    stream
                        .write_all(
                            format!("{tag} BAD AUTHENTICATE needs a mechanism\r\n").as_bytes(),
                        )
                        .await?;
                    return Err(anyhow!("no mechanism"));
                };
                let inline_ir = aparts.next().map(|s| Zeroizing::new(s.to_owned()));
                let kind = match mech.to_ascii_uppercase().as_str() {
                    "XOAUTH2" | "OAUTHBEARER" | "PLAIN" | "LOGIN" => {
                        match read_sasl_credential(stream, &mech, inline_ir, tuning.idle).await {
                            Ok(k) => k,
                            Err(e) => {
                                // Best effort: the client may already be gone.
                                let _ = stream.write_all(format!("{tag} BAD AUTHENTICATE failed: invalid or cancelled response\r\n").as_bytes()).await;
                                let _ = stream.flush().await;
                                return Err(e);
                            }
                        }
                    }
                    _ => {
                        stream
                            .write_all(
                                format!("{tag} NO unsupported SASL mechanism\r\n").as_bytes(),
                            )
                            .await?;
                        return Err(anyhow!(
                            "unsupported mechanism {}",
                            crate::obs::authlog::sanitize(&mech)
                        ));
                    }
                };
                return Ok(Some(ClientAuth { tag, mech, kind }));
            }
            _ => {
                stream
                    .write_all(
                        format!("{tag} NO command not supported before authentication\r\n")
                            .as_bytes(),
                    )
                    .await?;
                return Err(anyhow!(
                    "unsupported pre-auth command: {}",
                    crate::obs::authlog::sanitize(cmd)
                ));
            }
        }
    }
    stream
        .write_all(b"* BYE too many commands before authentication\r\n")
        .await?;
    Err(anyhow!("too many pre-auth commands"))
}

/// Gather the credential of an `AUTHENTICATE <mech>` whose mechanism is known
/// to be supported.
async fn read_sasl_credential<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    mech: &str,
    inline_ir: Option<Zeroizing<String>>,
    idle: Duration,
) -> Result<crate::auth::sasl::ClientAuthKind> {
    Ok(match mech.to_ascii_uppercase().as_str() {
        "PLAIN" => {
            let ir = read_ir(stream, inline_ir, idle).await?;
            let (user, pass) =
                crate::auth::sasl::parse_plain(&ir).map_err(|e| anyhow!("plain parse: {e}"))?;
            crate::auth::sasl::ClientAuthKind::Password { user, pass }
        }
        "LOGIN" => {
            // Base64 challenge dialog. A client may send the username as the
            // initial response (`AUTHENTICATE LOGIN <b64user>`); asking for it
            // again would make it answer with the password, which would then
            // be taken — and logged — as the username.
            let mut user = match inline_ir.filter(|s| !s.is_empty()) {
                Some(ir) => crate::wire::line::decode_login_field(&ir)?,
                None => sasl_login_step(stream, "+ VXNlcm5hbWU6", idle).await?, // base64("Username:")
            };
            let pass = sasl_login_step(stream, "+ UGFzc3dvcmQ6", idle).await?; // base64("Password:")
            if user.is_empty() || pass.is_empty() {
                return Err(anyhow!("LOGIN empty field"));
            }
            crate::auth::sasl::ClientAuthKind::Password {
                user: std::mem::take(&mut *user),
                pass,
            }
        }
        _ => {
            let ir = read_ir(stream, inline_ir, idle).await?;
            let creds =
                crate::auth::sasl::parse_sasl(mech, &ir).map_err(|e| anyhow!("sasl parse: {e}"))?;
            crate::auth::sasl::ClientAuthKind::OAuth {
                user: creds.user,
                token: creds.token,
            }
        }
    })
}

/// Parse the two astring arguments of a LOGIN command: each is either a bare
/// atom or a quoted string with `\"`/`\\` escapes. IMAP literals (`{n}`) are
/// not supported. The second argument is the password: both are built in
/// buffers sized for the whole line (no reallocation leaves a partial copy)
/// and zeroized on drop, also on a parse error.
pub(crate) fn parse_two_astrings(rest: &str) -> Result<(String, Zeroizing<String>)> {
    let mut chars = rest.trim().chars().peekable();
    let mut out: Vec<Zeroizing<String>> = Vec::with_capacity(2);
    while out.len() < 2 {
        while matches!(chars.peek(), Some(' ')) {
            chars.next();
        }
        match chars.peek() {
            Some('"') => {
                chars.next();
                let mut s = Zeroizing::new(String::with_capacity(rest.len()));
                loop {
                    match chars.next() {
                        Some('\\') => {
                            s.push(chars.next().ok_or_else(|| anyhow!("dangling escape"))?)
                        }
                        Some('"') => break,
                        Some(c) => s.push(c),
                        None => return Err(anyhow!("unterminated quoted string")),
                    }
                }
                out.push(s);
            }
            Some('{') => return Err(anyhow!("IMAP literals not supported")),
            Some(_) => {
                let mut s = Zeroizing::new(String::with_capacity(rest.len()));
                while let Some(&c) = chars.peek() {
                    if c == ' ' {
                        break;
                    }
                    s.push(c);
                    chars.next();
                }
                out.push(s);
            }
            None => return Err(anyhow!("missing argument")),
        }
    }
    let pass = out.remove(1);
    Ok((std::mem::take(&mut *out[0]), pass))
}

/// Return the SASL-IR: use the inline value if present, else send `+ \r\n` and read one line.
async fn read_ir<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    inline: Option<Zeroizing<String>>,
    idle: Duration,
) -> Result<Zeroizing<String>> {
    match inline {
        Some(ir) if !ir.is_empty() => Ok(ir),
        _ => {
            stream.write_all(b"+ \r\n").await?;
            read_sasl_response(stream, idle).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOTH: MechSet = MechSet {
        plain: true,
        login: true,
    };

    /// The two capability lines of the password-gate short form are pinned;
    /// a rule that offers one mechanism offers only that one.
    #[test]
    fn capability_lines() {
        assert_eq!(
            capabilities(MechSet::default()),
            "IMAP4rev1 IMAP4rev2 SASL-IR LOGINDISABLED AUTH=XOAUTH2 AUTH=OAUTHBEARER"
        );
        assert_eq!(
            capabilities(BOTH),
            "IMAP4rev1 IMAP4rev2 SASL-IR AUTH=XOAUTH2 AUTH=OAUTHBEARER AUTH=PLAIN AUTH=LOGIN"
        );
        let plain = MechSet {
            plain: true,
            login: false,
        };
        assert_eq!(
            capabilities(plain),
            "IMAP4rev1 IMAP4rev2 SASL-IR LOGINDISABLED AUTH=XOAUTH2 AUTH=OAUTHBEARER AUTH=PLAIN"
        );
    }
    use base64::Engine as _;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn reads_sasl_ir_authenticate() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let ir = crate::auth::sasl::build_xoauth2("alice@example.org", "TKN");
        // OAuth must work even on the OAuth-only endpoint (no password mechanism).
        let server_task = tokio::spawn(async move {
            read_client_auth(&mut server, MechSet::default(), "test", &Tuning::default()).await
        });
        // read greeting
        let mut buf = [0u8; 256];
        let n = client.read(&mut buf).await.unwrap();
        assert!(std::str::from_utf8(&buf[..n]).unwrap().starts_with("* OK"));
        client
            .write_all(format!("A1 AUTHENTICATE XOAUTH2 {}\r\n", ir.as_str()).as_bytes())
            .await
            .unwrap();
        let auth = server_task.await.unwrap().unwrap().unwrap();
        assert_eq!(auth.tag, "A1");
        match auth.kind {
            crate::auth::sasl::ClientAuthKind::OAuth { user, token } => {
                assert_eq!(user, "alice@example.org");
                assert_eq!(*token, "TKN");
            }
            _ => panic!("expected OAuth"),
        }
    }

    #[tokio::test]
    async fn reads_plain_ir() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let ir = base64::engine::general_purpose::STANDARD.encode("\0alice@example.org\0pw123");
        let t = tokio::spawn(async move {
            read_client_auth(&mut server, BOTH, "test", &Tuning::default()).await
        });
        let mut buf = [0u8; 256];
        let n = client.read(&mut buf).await.unwrap();
        assert!(std::str::from_utf8(&buf[..n])
            .unwrap()
            .contains("AUTH=PLAIN"));
        client
            .write_all(format!("B1 AUTHENTICATE PLAIN {ir}\r\n").as_bytes())
            .await
            .unwrap();
        let auth = t.await.unwrap().unwrap().unwrap();
        match auth.kind {
            crate::auth::sasl::ClientAuthKind::Password { user, pass } => {
                assert_eq!(user, "alice@example.org");
                assert_eq!(*pass, "pw123");
            }
            _ => panic!("expected Password"),
        }
    }

    #[tokio::test]
    async fn reads_login_two_step() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let t = tokio::spawn(async move {
            read_client_auth(&mut server, BOTH, "test", &Tuning::default()).await
        });
        let mut buf = [0u8; 256];
        let _ = client.read(&mut buf).await.unwrap(); // greeting
        client
            .write_all(b"C1 AUTHENTICATE LOGIN\r\n")
            .await
            .unwrap();
        let n = client.read(&mut buf).await.unwrap();
        assert!(std::str::from_utf8(&buf[..n])
            .unwrap()
            .contains("VXNlcm5hbWU6"));
        client
            .write_all(
                format!(
                    "{}\r\n",
                    base64::engine::general_purpose::STANDARD.encode("bob@x")
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let n = client.read(&mut buf).await.unwrap();
        assert!(std::str::from_utf8(&buf[..n])
            .unwrap()
            .contains("UGFzc3dvcmQ6"));
        client
            .write_all(
                format!(
                    "{}\r\n",
                    base64::engine::general_purpose::STANDARD.encode("secret")
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let auth = t.await.unwrap().unwrap().unwrap();
        match auth.kind {
            crate::auth::sasl::ClientAuthKind::Password { user, pass } => {
                assert_eq!(user, "bob@x");
                assert_eq!(*pass, "secret");
            }
            _ => panic!("expected Password"),
        }
    }

    #[tokio::test]
    async fn oauth_only_greeting_omits_password_but_still_parses() {
        // OAuth-only endpoint: PLAIN/LOGIN are not advertised, a PLAIN
        // attempt is still parsed (see `read_client_auth`).
        let (mut client, mut server) = tokio::io::duplex(4096);
        let ir = base64::engine::general_purpose::STANDARD.encode("\0bob@example.invalid\0pw");
        let t = tokio::spawn(async move {
            read_client_auth(&mut server, MechSet::default(), "test", &Tuning::default()).await
        });
        let mut buf = [0u8; 256];
        let n = client.read(&mut buf).await.unwrap();
        let greeting = std::str::from_utf8(&buf[..n]).unwrap();
        assert!(
            !greeting.contains("AUTH=PLAIN"),
            "PLAIN must not be advertised: {greeting}"
        );
        assert!(
            !greeting.contains("AUTH=LOGIN"),
            "LOGIN must not be advertised: {greeting}"
        );
        assert!(
            greeting.contains("AUTH=XOAUTH2"),
            "OAuth must still be advertised: {greeting}"
        );
        client
            .write_all(format!("D1 AUTHENTICATE PLAIN {ir}\r\n").as_bytes())
            .await
            .unwrap();
        let auth = t.await.unwrap().unwrap().unwrap();
        match auth.kind {
            crate::auth::sasl::ClientAuthKind::Password { user, pass } => {
                assert_eq!(user, "bob@example.invalid");
                assert_eq!(*pass, "pw");
            }
            _ => panic!("expected Password (parsed for logging)"),
        }
    }

    #[tokio::test]
    async fn capability_command_then_login_command() {
        // Python imaplib flow: explicit CAPABILITY command, then the LOGIN
        // *command* with a quoted password.
        let (mut client, mut server) = tokio::io::duplex(4096);
        let t = tokio::spawn(async move {
            read_client_auth(&mut server, BOTH, "test", &Tuning::default()).await
        });
        let mut buf = [0u8; 512];
        let _ = client.read(&mut buf).await.unwrap(); // greeting
        client.write_all(b"E1 CAPABILITY\r\n").await.unwrap();
        let n = client.read(&mut buf).await.unwrap();
        let resp = std::str::from_utf8(&buf[..n]).unwrap();
        assert!(
            resp.contains("* CAPABILITY IMAP4rev1"),
            "untagged CAPABILITY expected: {resp}"
        );
        assert!(resp.contains("E1 OK"), "tagged OK expected: {resp}");
        client
            .write_all(b"E2 LOGIN mailflow@dev.example.org \"p\\\"a ss\\\\w\"\r\n")
            .await
            .unwrap();
        let auth = t.await.unwrap().unwrap().unwrap();
        assert_eq!(auth.tag, "E2");
        assert_eq!(auth.mech, "LOGIN");
        match auth.kind {
            crate::auth::sasl::ClientAuthKind::Password { user, pass } => {
                assert_eq!(user, "mailflow@dev.example.org");
                assert_eq!(*pass, "p\"a ss\\w");
            }
            _ => panic!("expected Password"),
        }
    }

    #[tokio::test]
    async fn unknown_preauth_command_rejected() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let t = tokio::spawn(async move {
            read_client_auth(&mut server, MechSet::default(), "test", &Tuning::default()).await
        });
        let mut buf = [0u8; 256];
        let _ = client.read(&mut buf).await.unwrap(); // greeting
        client.write_all(b"F1 SELECT INBOX\r\n").await.unwrap();
        let n = client.read(&mut buf).await.unwrap();
        assert!(std::str::from_utf8(&buf[..n]).unwrap().starts_with("F1 NO"));
        assert!(t.await.unwrap().is_err());
    }

    #[test]
    fn parse_two_astrings_variants() {
        assert_eq!(
            parse_two_astrings("user pw").unwrap(),
            ("user".into(), String::from("pw").into())
        );
        assert_eq!(
            parse_two_astrings("\"u ser\" \"p w\"").unwrap(),
            ("u ser".into(), String::from("p w").into())
        );
        assert!(parse_two_astrings("onlyone").is_err());
        assert!(parse_two_astrings("user {5}").is_err());
        assert!(parse_two_astrings("user \"unterminated").is_err());
    }

    #[tokio::test]
    async fn logout_before_auth_is_a_clean_end() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let t = tokio::spawn(async move {
            read_client_auth(&mut server, MechSet::default(), "test", &Tuning::default()).await
        });
        let mut buf = [0u8; 512];
        let _ = client.read(&mut buf).await.unwrap(); // greeting
        client.write_all(b"L1 LOGOUT\r\n").await.unwrap();
        assert!(t.await.unwrap().unwrap().is_none());
    }

    /// A lone "*" cancels the exchange; the client must get a tagged reply.
    #[tokio::test]
    async fn cancelled_authenticate_gets_a_tagged_reply() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let t = tokio::spawn(async move {
            read_client_auth(&mut server, MechSet::default(), "test", &Tuning::default()).await
        });
        let mut buf = [0u8; 512];
        let _ = client.read(&mut buf).await.unwrap(); // greeting
        client
            .write_all(b"X1 AUTHENTICATE XOAUTH2\r\n")
            .await
            .unwrap();
        let n = client.read(&mut buf).await.unwrap();
        assert!(std::str::from_utf8(&buf[..n]).unwrap().starts_with("+"));
        client.write_all(b"*\r\n").await.unwrap();
        assert!(t.await.unwrap().is_err());
        let n = client.read(&mut buf).await.unwrap();
        assert!(std::str::from_utf8(&buf[..n])
            .unwrap()
            .starts_with("X1 BAD"));
    }

    #[tokio::test]
    async fn tag_without_command_gets_bad() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let t = tokio::spawn(async move {
            read_client_auth(&mut server, MechSet::default(), "test", &Tuning::default()).await
        });
        let mut buf = [0u8; 512];
        let _ = client.read(&mut buf).await.unwrap(); // greeting
        client.write_all(b"A1\r\n").await.unwrap();
        assert!(t.await.unwrap().is_err());
        let n = client.read(&mut buf).await.unwrap();
        assert!(std::str::from_utf8(&buf[..n]).unwrap().starts_with("* BAD"));
    }

    /// `AUTHENTICATE LOGIN <b64user>`: only the password is asked for.
    #[tokio::test]
    async fn authenticate_login_with_initial_response() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let t = tokio::spawn(async move {
            read_client_auth(&mut server, BOTH, "test", &Tuning::default()).await
        });
        let mut buf = [0u8; 512];
        let _ = client.read(&mut buf).await.unwrap(); // greeting
        client
            .write_all(
                format!(
                    "L2 AUTHENTICATE LOGIN {}\r\n",
                    base64::engine::general_purpose::STANDARD.encode("erin@x")
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let n = client.read(&mut buf).await.unwrap();
        assert!(
            std::str::from_utf8(&buf[..n])
                .unwrap()
                .starts_with("+ UGFzc3dvcmQ6"),
            "must prompt for the password"
        );
        client
            .write_all(
                format!(
                    "{}\r\n",
                    base64::engine::general_purpose::STANDARD.encode("pw9")
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        match t.await.unwrap().unwrap().unwrap().kind {
            crate::auth::sasl::ClientAuthKind::Password { user, pass } => {
                assert_eq!(user, "erin@x");
                assert_eq!(*pass, "pw9");
            }
            _ => panic!("expected Password"),
        }
    }

    /// Connect, read the greeting, close: a health check, not a failed login.
    #[tokio::test]
    async fn disconnect_after_greeting_is_a_clean_end() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let t = tokio::spawn(async move {
            read_client_auth(&mut server, MechSet::default(), "test", &Tuning::default()).await
        });
        let mut buf = [0u8; 512];
        let n = client.read(&mut buf).await.unwrap();
        assert!(std::str::from_utf8(&buf[..n])
            .unwrap()
            .contains("LOGINDISABLED"));
        drop(client);
        assert!(t.await.unwrap().unwrap().is_none());
    }
}
