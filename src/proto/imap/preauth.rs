//! The IMAP pre-auth dialog: greeting, CAPABILITY/NOOP/ID/LOGOUT, and the
//! credential of a LOGIN or AUTHENTICATE command.

use crate::auth::legacy::MechSet;
use crate::auth::sasl::{Discovery, Mechanism};
use crate::auth::Withheld;
use crate::wire::line::{
    initial_response, is_bad_response, read_client_line, read_sasl_response, sasl_login_step,
};
use crate::wire::Tuning;
use anyhow::Context as _;
use anyhow::{anyhow, Result};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

/// The pre-auth capabilities. OAuth mechanisms always; PLAIN/LOGIN only as
/// far as the legacy gate offers them on this connection. LOGINDISABLED
/// (RFC 3501 §6.2.3) tells clients not to try the LOGIN command, which counts
/// as the LOGIN mechanism. ID is answered, so it is advertised (RFC 2971 §3).
/// IMAP4rev2 is not: whether the backend speaks it shows only in its own
/// list after login, which the client is sent (RFC 9051 §6.2.2 allows the
/// lists to differ).
fn capabilities(pw: MechSet) -> String {
    let mut caps = String::from("IMAP4rev1 SASL-IR ID");
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
    /// OAUTHBEARER `host`, if the client sent one.
    pub host: Option<String>,
}

/// Read the client's pre-auth dialog up to a credential. `pw` decides what
/// is advertised; a password sent anyway is still parsed, so
/// `auth::authorize` can log and refuse it, but a mechanism `pw` does not
/// offer never prompts for one: the answer is a tagged NO and the error
/// `Withheld`. An OAuth response with an empty `auth` value is the error
/// `Discovery`, unanswered: the caller answers it with the error result.
///
/// RFC 3501 requires CAPABILITY/NOOP/LOGOUT to work in NOT-AUTHENTICATED state,
/// and stock clients (Python imaplib) send an explicit CAPABILITY before
/// authenticating and use the LOGIN *command* (not the SASL LOGIN mechanism).
/// The loop is bounded so an unauthenticated peer can't hold the slot.
///
/// `Ok(None)`: LOGOUT, or a close right after the greeting — a clean end, not
/// a failure. Every refusal is answered; a read error or timeout is not. An
/// authentication command that failed without a credential and may be
/// followed by another is marked `auth::Retryable`.
/// `name` is the server name shown in the greeting. `cmds` counts the
/// commands of the connection across calls; the greeting goes out on the
/// first call (`cmds` 0).
pub async fn read_client_auth<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    pw: MechSet,
    name: &str,
    tuning: &Tuning,
    cmds: &mut usize,
) -> Result<Option<ClientAuth>> {
    let caps = capabilities(pw);
    if *cmds == 0 {
        stream
            .write_all(format!("* OK [CAPABILITY {caps}] {name} ready\r\n").as_bytes())
            .await?;
    }
    while *cmds < tuning.max_preauth_commands {
        *cmds += 1;
        let line = match read_client_line(stream, tuning.idle).await {
            Ok(l) => l,
            // Connect, read the greeting, disconnect: a health check or port
            // probe, not a failed login.
            Err(e) if *cmds == 1 && e.is_eof() => return Ok(None),
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
                let (user, pass) = match read_login_args(stream, rest, pw, tuning.idle).await {
                    Ok(up) => up,
                    Err(e) => {
                        let reply = if e.is::<Withheld>() {
                            "NO password authentication not available on this endpoint"
                        } else {
                            "BAD LOGIN arguments"
                        };
                        // Best effort: the client may already be gone.
                        let _ = stream
                            .write_all(format!("{tag} {reply}\r\n").as_bytes())
                            .await;
                        let _ = stream.flush().await;
                        return Err(if e.is::<Withheld>() {
                            e
                        } else {
                            anyhow!("LOGIN parse: {e}")
                        });
                    }
                };
                if user.is_empty() || pass.is_empty() {
                    stream
                        .write_all(format!("{tag} NO LOGIN empty field\r\n").as_bytes())
                        .await?;
                    return Err(crate::auth::answered(anyhow!("LOGIN empty field")));
                }
                return Ok(Some(ClientAuth {
                    tag,
                    mech: "LOGIN".into(),
                    kind: crate::auth::sasl::ClientAuthKind::Password { user, pass },
                    host: None,
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
                    return Err(crate::auth::answered(anyhow!("no mechanism")));
                };
                let inline_ir = initial_response(aparts.next());
                let Some(m) = Mechanism::parse(&mech) else {
                    stream
                        .write_all(format!("{tag} NO unsupported SASL mechanism\r\n").as_bytes())
                        .await?;
                    return Err(crate::auth::answered(anyhow!(
                        "unsupported mechanism {}",
                        crate::obs::authlog::sanitize(&mech)
                    )));
                };
                let (kind, host) = match read_sasl_credential(
                    stream,
                    &mech,
                    m,
                    inline_ir,
                    pw,
                    tuning.idle,
                )
                .await
                {
                    Ok(k) => k,
                    // A discovery request: `imap::handle` answers it with the
                    // error result and needs the tag.
                    Err(e) if e.is::<Discovery>() => {
                        let d = e.downcast_ref::<Discovery>().map(|d| Discovery {
                            mech: d.mech.clone(),
                            user: d.user.clone(),
                            tag,
                        });
                        return Err(d.map_or(e, anyhow::Error::new));
                    }
                    Err(e) => {
                        // RFC 9051 §6.2.2: BAD for a response that is not
                        // base64 or a cancel, NO for one that decodes but
                        // holds no valid credential.
                        let reply = if e.is::<Withheld>() {
                            "NO password authentication not available on this endpoint"
                        } else if is_bad_response(&e) {
                            "BAD AUTHENTICATE failed: invalid or cancelled response"
                        } else {
                            "NO [AUTHENTICATIONFAILED] Authentication failed"
                        };
                        // Best effort: the client may already be gone.
                        let _ = stream
                            .write_all(format!("{tag} {reply}\r\n").as_bytes())
                            .await;
                        let _ = stream.flush().await;
                        return Err(if e.is::<Withheld>() {
                            e
                        } else {
                            crate::auth::answered(e)
                        });
                    }
                };
                return Ok(Some(ClientAuth {
                    tag,
                    mech,
                    kind,
                    host,
                }));
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

/// Gather the credential of an `AUTHENTICATE <mech>` (`m`, as the client
/// spelled it), and the OAUTHBEARER `host`. A password mechanism `pw` does
/// not offer is never asked for its password: `Withheld` unless the initial
/// response carries it.
async fn read_sasl_credential<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    mech: &str,
    m: Mechanism,
    inline_ir: Option<Zeroizing<String>>,
    pw: MechSet,
    idle: Duration,
) -> Result<(crate::auth::sasl::ClientAuthKind, Option<String>)> {
    let withheld = |user: String| {
        anyhow::Error::new(Withheld {
            mech: mech.to_string(),
            user,
        })
    };
    let kind = match m {
        Mechanism::Plain => {
            if !pw.plain && inline_ir.as_ref().is_none_or(|ir| ir.is_empty()) {
                return Err(withheld(String::new()));
            }
            let ir = read_ir(stream, inline_ir, idle).await?;
            let (user, pass) = crate::auth::sasl::parse_plain(&ir).context("plain parse")?;
            crate::auth::sasl::ClientAuthKind::Password { user, pass }
        }
        Mechanism::Login => {
            // Base64 challenge dialog. A client may send the username as the
            // initial response (`AUTHENTICATE LOGIN <b64user>`); asking for it
            // again would make it answer with the password, which would then
            // be taken — and logged — as the username.
            let mut user = match inline_ir {
                Some(ir) => crate::wire::line::decode_login_field(&ir)?,
                None if !pw.login => return Err(withheld(String::new())),
                None => sasl_login_step(stream, "+ VXNlcm5hbWU6", idle).await?, // base64("Username:")
            };
            if !pw.login {
                return Err(withheld(std::mem::take(&mut *user)));
            }
            let pass = sasl_login_step(stream, "+ UGFzc3dvcmQ6", idle).await?; // base64("Password:")
            if user.is_empty() || pass.is_empty() {
                return Err(anyhow!("LOGIN empty field"));
            }
            crate::auth::sasl::ClientAuthKind::Password {
                user: std::mem::take(&mut *user),
                pass,
            }
        }
        Mechanism::XOAuth2 | Mechanism::OAuthBearer => {
            let ir = read_ir(stream, inline_ir, idle).await?;
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

/// One LOGIN argument at the start of `s` after any spaces (RFC 9051 §9
/// `astring`).
enum Astring<'a> {
    /// An atom or a quoted string (`\"`/`\\` escapes), and the rest of `s`.
    Value(Zeroizing<String>, &'a str),
    /// The header of a literal, `{n}` or the non-synchronising `{n+}`
    /// (RFC 9051 §4.3). It ends the line; the octets follow on the stream.
    Literal { len: usize, sync: bool },
}

/// Largest literal accepted in LOGIN. Longer logins and passwords than the
/// proxy forwards still fit, so they are refused like a wrong password.
const MAX_LOGIN_LITERAL: usize = crate::wire::line::MAX_LINE;

/// Parse the next LOGIN argument of `s`. A value is built in a buffer sized
/// for the whole line (no reallocation leaves a partial copy) and zeroized
/// on drop, also on a parse error.
fn next_astring(s: &str) -> Result<Astring<'_>> {
    // No IMAP string holds a NUL (RFC 9051 §4.3), and the backend gets the
    // credential as PLAIN, where NUL separates the fields.
    if s.contains('\0') {
        return Err(anyhow!("NUL in LOGIN arguments"));
    }
    let s = s.trim_start_matches(' ');
    let mut chars = s.char_indices().peekable();
    match chars.peek() {
        Some((_, '"')) => {
            chars.next();
            let mut v = Zeroizing::new(String::with_capacity(s.len()));
            loop {
                match chars.next() {
                    Some((_, '\\')) => {
                        v.push(chars.next().ok_or_else(|| anyhow!("dangling escape"))?.1)
                    }
                    Some((i, '"')) => return Ok(Astring::Value(v, &s[i + 1..])),
                    Some((_, c)) => v.push(c),
                    None => return Err(anyhow!("unterminated quoted string")),
                }
            }
        }
        Some((_, '{')) => {
            let (len, sync) = s
                .strip_prefix('{')
                .and_then(|h| h.strip_suffix('}'))
                .map(|h| match h.strip_suffix('+') {
                    Some(n) => (n, false),
                    None => (h, true),
                })
                .filter(|(n, _)| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
                .ok_or_else(|| anyhow!("malformed literal header"))?;
            let len = len
                .parse::<usize>()
                .ok()
                .filter(|&n| n <= MAX_LOGIN_LITERAL)
                .ok_or_else(|| anyhow!("literal larger than {MAX_LOGIN_LITERAL} bytes"))?;
            Ok(Astring::Literal { len, sync })
        }
        Some(_) => {
            let end = s.find(' ').unwrap_or(s.len());
            let mut v = Zeroizing::new(String::with_capacity(s.len()));
            v.push_str(&s[..end]);
            Ok(Astring::Value(v, &s[end..]))
        }
        None => Err(anyhow!("missing argument")),
    }
}

/// Parse the two astring arguments of a LOGIN command that holds no literal.
/// The second argument is the password, zeroized on drop. For the unit tests
/// and the fuzz target; the listener reads LOGIN with `read_login_args`.
#[cfg(any(test, fuzzing))]
pub(crate) fn parse_two_astrings(rest: &str) -> Result<(String, Zeroizing<String>)> {
    let Astring::Value(mut user, rest) = next_astring(rest.trim())? else {
        return Err(anyhow!("literal in LOGIN arguments"));
    };
    let Astring::Value(pass, _) = next_astring(rest)? else {
        return Err(anyhow!("literal in LOGIN arguments"));
    };
    Ok((std::mem::take(&mut *user), pass))
}

/// Read the two arguments of a LOGIN command, `rest` being the line after
/// the command name: atoms, quoted strings or literals (RFC 9051 §6.2.3). A
/// synchronising literal `{n}` is asked for with a `+` continuation, a
/// non-synchronising `{n+}` follows at once; the line after its octets
/// continues the command. Where the connection offers no LOGIN (`pw`), a
/// synchronising literal is not asked for: the error is `Withheld`, as for
/// a password mechanism the connection does not offer.
async fn read_login_args<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    rest: &str,
    pw: MechSet,
    idle: Duration,
) -> Result<(String, Zeroizing<String>)> {
    let mut line = Zeroizing::new(rest.trim().to_owned());
    let mut pos = 0;
    let mut args: Vec<Zeroizing<String>> = Vec::with_capacity(2);
    while args.len() < 2 {
        match next_astring(&line[pos..])? {
            Astring::Value(v, after) => {
                pos = line.len() - after.len();
                args.push(v);
            }
            Astring::Literal { len, sync } => {
                if sync {
                    if !pw.login {
                        let user = args.first().map(|u| u.to_string()).unwrap_or_default();
                        return Err(anyhow::Error::new(Withheld {
                            mech: "LOGIN".into(),
                            user,
                        }));
                    }
                    stream.write_all(b"+ Ready for literal data\r\n").await?;
                    stream.flush().await?;
                }
                args.push(read_literal(stream, len, idle).await?);
                line = read_client_line(stream, idle).await?;
                pos = 0;
            }
        }
    }
    let pass = args.pop().unwrap_or_default();
    let user = args.pop().unwrap_or_default();
    Ok((user.to_string(), pass))
}

/// Read the `len` octets of a LOGIN literal, waiting at most `idle` for each
/// read. They can carry the password and are zeroized on drop; a NUL is
/// refused as in a quoted string.
async fn read_literal<S: AsyncRead + Unpin>(
    stream: &mut S,
    len: usize,
    idle: Duration,
) -> Result<Zeroizing<String>> {
    use tokio::io::AsyncReadExt as _;
    let mut buf = Zeroizing::new(vec![0u8; len]);
    let mut filled = 0;
    while filled < len {
        match tokio::time::timeout(idle, stream.read(&mut buf[filled..])).await {
            Ok(Ok(0)) => return Err(anyhow!("eof in a literal")),
            Ok(Ok(n)) => filled += n,
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => return Err(anyhow!("literal read timed out after {}s", idle.as_secs())),
        }
    }
    if buf.contains(&0) {
        return Err(anyhow!("NUL in a literal"));
    }
    let text = std::str::from_utf8(&buf).map_err(|e| anyhow!("literal utf8: {e}"))?;
    Ok(Zeroizing::new(text.to_owned()))
}

/// Return the SASL-IR: use the inline value if present (empty for `=`), else
/// send `+ \r\n` and read one line.
async fn read_ir<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    inline: Option<Zeroizing<String>>,
    idle: Duration,
) -> Result<Zeroizing<String>> {
    match inline {
        Some(ir) => Ok(ir),
        None => {
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
            "IMAP4rev1 SASL-IR ID LOGINDISABLED AUTH=XOAUTH2 AUTH=OAUTHBEARER"
        );
        assert_eq!(
            capabilities(BOTH),
            "IMAP4rev1 SASL-IR ID AUTH=XOAUTH2 AUTH=OAUTHBEARER AUTH=PLAIN AUTH=LOGIN"
        );
        let plain = MechSet {
            plain: true,
            login: false,
        };
        assert_eq!(
            capabilities(plain),
            "IMAP4rev1 SASL-IR ID LOGINDISABLED AUTH=XOAUTH2 AUTH=OAUTHBEARER AUTH=PLAIN"
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
            read_client_auth(
                &mut server,
                MechSet::default(),
                "test",
                &Tuning::default(),
                &mut 0,
            )
            .await
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
            read_client_auth(&mut server, BOTH, "test", &Tuning::default(), &mut 0).await
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
            read_client_auth(&mut server, BOTH, "test", &Tuning::default(), &mut 0).await
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
            read_client_auth(
                &mut server,
                MechSet::default(),
                "test",
                &Tuning::default(),
                &mut 0,
            )
            .await
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
            read_client_auth(&mut server, BOTH, "test", &Tuning::default(), &mut 0).await
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
            read_client_auth(
                &mut server,
                MechSet::default(),
                "test",
                &Tuning::default(),
                &mut 0,
            )
            .await
        });
        let mut buf = [0u8; 256];
        let _ = client.read(&mut buf).await.unwrap(); // greeting
        client.write_all(b"F1 SELECT INBOX\r\n").await.unwrap();
        let n = client.read(&mut buf).await.unwrap();
        assert!(std::str::from_utf8(&buf[..n]).unwrap().starts_with("F1 NO"));
        assert!(t.await.unwrap().is_err());
    }

    /// A failed AUTHENTICATE, or a LOGIN with an empty field, may be
    /// followed by another attempt; the next call goes on without a second
    /// greeting and counts commands across calls. An unparsable LOGIN, whose
    /// end the proxy cannot be sure of, may not.
    #[tokio::test]
    async fn retryable_failures_and_the_next_attempt() {
        for (line, retry) in [
            (&b"a AUTHENTICATE FOO\r\n"[..], true),
            (b"a AUTHENTICATE\r\n", true),
            (b"a AUTHENTICATE PLAIN !!\r\n", true),
            (b"a AUTHENTICATE PLAIN =\r\n", true),
            (b"a LOGIN \"\" pw\r\n", true),
            (b"a LOGIN user \"unterminated\r\n", false),
            (b"a SELECT INBOX\r\n", false),
        ] {
            let what = String::from_utf8_lossy(line).trim().to_string();
            let (mut client, mut server) = tokio::io::duplex(4096);
            client.write_all(line).await.unwrap();
            client.write_all(b"b LOGIN user pw\r\n").await.unwrap();
            let mut cmds = 0;
            let e = read_client_auth(&mut server, BOTH, "test", &Tuning::default(), &mut cmds)
                .await
                .err()
                .expect("an error");
            assert_eq!(e.is::<crate::auth::Retryable>(), retry, "{what}: {e:#}");
            if retry {
                let next =
                    read_client_auth(&mut server, BOTH, "test", &Tuning::default(), &mut cmds)
                        .await;
                assert_eq!(password(next), ("user".into(), "pw".into()), "{what}");
                assert_eq!(cmds, 2, "{what}");
            }
            drop(server);
            let mut out = String::new();
            client.read_to_string(&mut out).await.unwrap();
            assert_eq!(out.matches("* OK [CAPABILITY").count(), 1, "{what}: {out}");
        }
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
        assert!(parse_two_astrings("user \"p\0w\"").is_err());
        assert!(parse_two_astrings("us\0er pw").is_err());
        assert!(parse_two_astrings("user \"unterminated").is_err());
    }

    /// Drive `read_client_auth` with `input` after the greeting; returns
    /// the result and everything the server wrote after the greeting.
    async fn login_dialog(pw: MechSet, input: &[u8]) -> (Result<Option<ClientAuth>>, String) {
        let (mut client, mut server) = tokio::io::duplex(1 << 16);
        let t = tokio::spawn(async move {
            read_client_auth(&mut server, pw, "test", &Tuning::default(), &mut 0).await
        });
        let mut greeting = [0u8; 512];
        let _ = client.read(&mut greeting).await.unwrap();
        client.write_all(input).await.unwrap();
        let r = t.await.unwrap();
        drop(client.shutdown().await);
        let mut out = Vec::new();
        let _ = client.read_to_end(&mut out).await;
        (r, String::from_utf8(out).unwrap())
    }

    fn password(r: Result<Option<ClientAuth>>) -> (String, String) {
        match r.unwrap().unwrap().kind {
            crate::auth::sasl::ClientAuthKind::Password { user, pass } => (user, pass.to_string()),
            _ => panic!("expected Password"),
        }
    }

    /// LOGIN takes literals (RFC 9051 §6.2.3, §9 `astring`): a synchronising
    /// `{n}` gets a `+` continuation, a non-synchronising `{n+}` none; the
    /// octets may hold spaces, quotes and CRLF, and the command continues on
    /// the line after them.
    #[tokio::test]
    async fn login_with_literals() {
        let (r, out) = login_dialog(BOTH, b"a LOGIN bob@x {6}\r\np w\"\r\\\r\n").await;
        assert_eq!(password(r), ("bob@x".into(), "p w\"\r\\".into()));
        assert_eq!(out, "+ Ready for literal data\r\n");

        let (r, out) = login_dialog(BOTH, b"a LOGIN {5+}\r\nbob@x {3+}\r\npw1\r\n").await;
        assert_eq!(password(r), ("bob@x".into(), "pw1".into()));
        assert_eq!(out, "");

        let (r, out) = login_dialog(BOTH, b"a LOGIN {5}\r\nbob@x \"pw 2\"\r\n").await;
        assert_eq!(password(r), ("bob@x".into(), "pw 2".into()));
        assert_eq!(out, "+ Ready for literal data\r\n");
    }

    /// Where the connection offers no LOGIN, a synchronising literal is not
    /// asked for: the command is refused at once. A non-synchronising one has
    /// been sent anyway and is parsed, like a quoted password.
    #[tokio::test]
    async fn login_literal_on_oauth_only_endpoint() {
        let (r, out) = login_dialog(MechSet::default(), b"a LOGIN bob@x {3}\r\n").await;
        let Err(e) = r else {
            panic!("expected an error")
        };
        let w = e.downcast_ref::<Withheld>().expect("withheld");
        assert_eq!((w.mech.as_str(), w.user.as_str()), ("LOGIN", "bob@x"));
        assert_eq!(
            out,
            "a NO password authentication not available on this endpoint\r\n"
        );

        let (r, _) = login_dialog(MechSet::default(), b"a LOGIN bob@x {3+}\r\npw1\r\n").await;
        assert_eq!(password(r), ("bob@x".into(), "pw1".into()));
    }

    /// Malformed or oversized literal headers, a NUL in the octets and text
    /// after a header are refused with BAD, without a continuation.
    #[tokio::test]
    async fn login_bad_literals() {
        for input in [
            &b"a LOGIN bob@x {16385}\r\n"[..],
            b"a LOGIN bob@x {3++}\r\n",
            b"a LOGIN bob@x {}\r\n",
            b"a LOGIN bob@x {3} x\r\n",
            b"a LOGIN bob@x {3+}\r\np\0w\r\n",
        ] {
            let (r, out) = login_dialog(BOTH, input).await;
            assert!(r.is_err(), "{input:?}");
            assert_eq!(out, "a BAD LOGIN arguments\r\n", "{input:?}");
        }
    }

    #[tokio::test]
    async fn logout_before_auth_is_a_clean_end() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let t = tokio::spawn(async move {
            read_client_auth(
                &mut server,
                MechSet::default(),
                "test",
                &Tuning::default(),
                &mut 0,
            )
            .await
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
            read_client_auth(
                &mut server,
                MechSet::default(),
                "test",
                &Tuning::default(),
                &mut 0,
            )
            .await
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
            read_client_auth(
                &mut server,
                MechSet::default(),
                "test",
                &Tuning::default(),
                &mut 0,
            )
            .await
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
            read_client_auth(&mut server, BOTH, "test", &Tuning::default(), &mut 0).await
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
            read_client_auth(
                &mut server,
                MechSet::default(),
                "test",
                &Tuning::default(),
                &mut 0,
            )
            .await
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
