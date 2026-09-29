//! The password gate, end to end, per protocol:
//! {SNI internal, public, none} × {source 127.0.0.1, 127.0.0.2} × mechanism.
//!
//! Pinned: OAuth (valid token) is accepted in every cell; a password only with
//! the internal SNI from the internal source. Everywhere else the password is
//! answered with the documented rejection, logged as `blocked_endpoint` with a
//! fingerprint, counted as a failed attempt, and never reaches the backend.
//! SASL LOGIN is refused there before the password is asked for, so its
//! record has no fingerprint (and no login without an initial response).
//! The advertised mechanisms follow the same rule in every cell.

mod common;
use common::*;

const SNIS: [Sni; 3] = [Sni::Internal, Sni::Public, Sni::None];
const SRCS: [Src; 2] = [Src::Internal, Src::External];
/// What the client names in XOAUTH2 `user=` / OAUTHBEARER `a=`: the
/// token's identity in another case, which is the same mailbox.
fn claimed(user: &str) -> String {
    user.to_ascii_uppercase()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mech {
    /// SASL PLAIN with initial response.
    Plain,
    /// IMAP `LOGIN user pass` command.
    LoginCmd,
    /// SASL LOGIN, username and password prompted.
    Login,
    /// SASL LOGIN with the username as initial response.
    LoginIr,
    Xoauth2,
    Oauthbearer,
}

impl Mech {
    fn is_password(self) -> bool {
        !matches!(self, Mech::Xoauth2 | Mech::Oauthbearer)
    }
    /// `mech=` in the authresult line (as the client spelled it).
    fn logged(self) -> &'static str {
        match self {
            Mech::Plain => "PLAIN",
            Mech::LoginCmd | Mech::Login | Mech::LoginIr => "LOGIN",
            Mech::Xoauth2 => "XOAUTH2",
            Mech::Oauthbearer => "OAUTHBEARER",
        }
    }
    /// The `mechanism` metric label.
    fn metric(self) -> String {
        self.logged().to_ascii_lowercase()
    }
    /// What the proxy uses towards the backend.
    fn backend(self) -> &'static str {
        if self.is_password() {
            "PLAIN"
        } else {
            "XOAUTH2"
        }
    }
}

struct Cell {
    proto: &'static str,
    sni: Sni,
    src: Src,
    mech: Mech,
}

impl Cell {
    fn id(&self) -> String {
        format!(
            "{}-{:?}-{:?}-{:?}",
            self.proto, self.sni, self.src, self.mech
        )
        .to_ascii_lowercase()
    }
    fn password_allowed(&self) -> bool {
        self.sni == Sni::Internal && self.src == Src::Internal
    }
    fn accepted(&self) -> bool {
        !self.mech.is_password() || self.password_allowed()
    }
    /// SASL LOGIN where it is not offered: refused before the password
    /// prompt.
    fn withheld(&self) -> bool {
        !self.accepted() && matches!(self.mech, Mech::Login | Mech::LoginIr)
    }
    /// Login for password cells, token email for OAuth cells.
    fn user(&self) -> String {
        format!("{}@example.test", self.id())
    }
    fn password(&self) -> String {
        format!("pw-{}", self.id())
    }
    fn attempts_key(&self, ok: bool) -> String {
        format!(
            "mail_auth_proxy_auth_attempts_total{{proto=\"{}\",scope=\"{}\",mechanism=\"{}\",result=\"{}\"}}",
            self.proto,
            self.src.scope(),
            self.mech.metric(),
            if ok { "ok" } else { "fail" }
        )
    }
}

/// Everything around one cell that is the same for every protocol: the
/// authresult line, the metric, and what the backend saw.
async fn check_cell(h: &Harness, kind: Kind, cell: &Cell, before: &Before, client: &Client) {
    let ars = h.proxy.wait_authresults(before.authresults + 1).await;
    assert_eq!(
        ars.len(),
        before.authresults + 1,
        "{}: one record",
        cell.id()
    );
    let ar = ars.last().unwrap();
    let ok = cell.accepted();
    let expected = AuthResult {
        level: if ok { "INFO" } else { "WARN" }.into(),
        result: if ok { "ok" } else { "fail" }.into(),
        proto: cell.proto.into(),
        // The scope follows the source alone, whatever the SNI.
        scope: cell.src.scope().into(),
        mech: cell.mech.logged().into(),
        user: if cell.withheld() && cell.mech == Mech::Login {
            String::new()
        } else {
            cell.user()
        },
        peer: cell.src.ip().to_string(),
        reason: if ok { "ok" } else { "blocked_endpoint" }.into(),
        pwfp: ar.pwfp.clone(),
    };
    assert_eq!(ar, &expected, "{}", cell.id());
    if ok || cell.withheld() {
        assert_eq!(ar.pwfp, "", "{}", cell.id());
    } else {
        assert!(
            ar.pwfp.len() == 16 && ar.pwfp.chars().all(|c| c.is_ascii_hexdigit()),
            "{}: pwfp {:?}",
            cell.id(),
            ar.pwfp
        );
    }

    let key = cell.attempts_key(ok);
    assert_eq!(
        h.proxy.metric(&key).await,
        before.metric(&key) + 1,
        "{}: {key}",
        cell.id()
    );

    let be = h.backend(kind);
    let sessions = be.sessions();
    if ok {
        assert_eq!(sessions.len(), before.sessions + 1, "{}", cell.id());
        let s = sessions.last().unwrap();
        assert_eq!(
            s.mech.as_deref(),
            Some(cell.mech.backend()),
            "{}",
            cell.id()
        );
        // The backend login is the token's email or the client's login, never
        // the SASL user an OAuth client claims.
        assert_eq!(
            s.login.as_deref(),
            Some(cell.user().as_str()),
            "{}",
            cell.id()
        );
        if cell.mech.is_password() {
            assert_eq!(s.authzid.as_deref(), Some(""), "{}", cell.id());
            assert_eq!(s.secret.as_deref(), Some(cell.password().as_str()));
        }
        match kind {
            Kind::Imap | Kind::Sieve => {
                let hdr = s.proxy_header.as_ref().expect("PROXY v2 header");
                assert!(!hdr.local, "{}", cell.id());
                assert_eq!(hdr.src, Some(client.local), "{}", cell.id());
                assert_eq!(hdr.dst, Some(client.server), "{}", cell.id());
            }
            Kind::Smtp => {
                assert_eq!(s.proxy_header, None);
                assert_eq!(
                    s.xclient.as_deref(),
                    Some(format!("XCLIENT NAME=[UNAVAILABLE] ADDR={}", cell.src.ip()).as_str()),
                    "{}",
                    cell.id()
                );
            }
        }
    } else {
        // A blocked password never reaches the backend, in any form.
        assert_eq!(sessions.len(), before.sessions, "{}", cell.id());
        let pw = cell.password();
        let user = cell.user();
        for s in be.seen() {
            assert_ne!(s.secret.as_deref(), Some(pw.as_str()), "{}", cell.id());
            assert_ne!(s.login.as_deref(), Some(user.as_str()), "{}", cell.id());
        }
    }
}

struct Before {
    authresults: usize,
    sessions: usize,
    metrics: std::collections::HashMap<String, u64>,
}

impl Before {
    async fn take(h: &Harness, kind: Kind) -> Before {
        Before {
            authresults: h.proxy.authresults().len(),
            sessions: h.backend(kind).sessions().len(),
            metrics: h.proxy.metrics().await,
        }
    }
    fn metric(&self, key: &str) -> u64 {
        self.metrics[key]
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn imap_gate_matrix() {
    let h = Harness::start().await;
    let mechs = [
        Mech::Plain,
        Mech::LoginCmd,
        Mech::Login,
        Mech::LoginIr,
        Mech::Xoauth2,
        Mech::Oauthbearer,
    ];
    for sni in SNIS {
        for src in SRCS {
            for mech in mechs {
                let cell = Cell {
                    proto: "imap",
                    sni,
                    src,
                    mech,
                };
                let before = Before::take(&h, Kind::Imap).await;
                let (mut c, greeting) = h.imap(src, sni).await;
                let caps = if cell.password_allowed() {
                    "IMAP4rev1 IMAP4rev2 SASL-IR ID AUTH=XOAUTH2 AUTH=OAUTHBEARER AUTH=PLAIN AUTH=LOGIN"
                } else {
                    "IMAP4rev1 IMAP4rev2 SASL-IR ID LOGINDISABLED AUTH=XOAUTH2 AUTH=OAUTHBEARER"
                };
                assert_eq!(
                    greeting,
                    format!("* OK [CAPABILITY {caps}] {HOSTNAME} ready"),
                    "{}",
                    cell.id()
                );
                c.send("c0 CAPABILITY").await;
                assert_eq!(c.line().await, format!("* CAPABILITY {caps}"));
                assert_eq!(c.line().await, "c0 OK CAPABILITY completed");

                let (user, pw) = (cell.user(), cell.password());
                let token = h.idp.token(&user);
                match mech {
                    Mech::Plain => {
                        c.send(&format!("a AUTHENTICATE PLAIN {}", plain(&user, &pw)))
                            .await
                    }
                    Mech::LoginCmd => c.send(&format!("a LOGIN {user} \"{pw}\"")).await,
                    Mech::Login => {
                        c.send("a AUTHENTICATE LOGIN").await;
                        if !cell.withheld() {
                            assert_eq!(c.line().await, "+ VXNlcm5hbWU6");
                            c.send(&b64(&user)).await;
                            assert_eq!(c.line().await, "+ UGFzc3dvcmQ6");
                            c.send(&b64(&pw)).await;
                        }
                    }
                    Mech::LoginIr => {
                        c.send(&format!("a AUTHENTICATE LOGIN {}", b64(&user)))
                            .await;
                        if !cell.withheld() {
                            assert_eq!(c.line().await, "+ UGFzc3dvcmQ6");
                            c.send(&b64(&pw)).await;
                        }
                    }
                    Mech::Xoauth2 => {
                        c.send(&format!(
                            "a AUTHENTICATE XOAUTH2 {}",
                            xoauth2(&claimed(&user), &token)
                        ))
                        .await
                    }
                    Mech::Oauthbearer => {
                        c.send(&format!(
                            "a AUTHENTICATE OAUTHBEARER {}",
                            oauthbearer(&claimed(&user), &token)
                        ))
                        .await
                    }
                }
                if cell.accepted() {
                    // The backend's own tagged OK, under the client's tag.
                    assert_eq!(
                        c.line().await,
                        "a OK [CAPABILITY IMAP4rev1 IDLE MOVE] Logged in"
                    );
                    c.send("a2 NOOP").await;
                    assert_eq!(c.line().await, "ECHO a2 NOOP", "{}", cell.id());
                } else {
                    assert_eq!(
                        c.line().await,
                        "a NO password authentication not available on this endpoint",
                        "{}",
                        cell.id()
                    );
                    c.expect_closed().await;
                }
                check_cell(&h, Kind::Imap, &cell, &before, &c).await;
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn smtp_gate_matrix() {
    let h = Harness::start().await;
    let mechs = [
        Mech::Plain,
        Mech::Login,
        Mech::LoginIr,
        Mech::Xoauth2,
        Mech::Oauthbearer,
    ];
    for sni in SNIS {
        for src in SRCS {
            for mech in mechs {
                let cell = Cell {
                    proto: "smtp",
                    sni,
                    src,
                    mech,
                };
                let before = Before::take(&h, Kind::Smtp).await;
                let (mut c, ehlo) = h.smtp(src, sni).await;
                let auth = if cell.password_allowed() {
                    "250 AUTH XOAUTH2 OAUTHBEARER PLAIN LOGIN"
                } else {
                    "250 AUTH XOAUTH2 OAUTHBEARER"
                };
                assert_eq!(
                    ehlo,
                    [
                        &format!("250-{HOSTNAME}"),
                        "250-PIPELINING",
                        "250-ENHANCEDSTATUSCODES",
                        "250-8BITMIME",
                        "250-DSN",
                        "250-SMTPUTF8",
                        "250-CHUNKING",
                        auth
                    ],
                    "{}",
                    cell.id()
                );

                let (user, pw) = (cell.user(), cell.password());
                let token = h.idp.token(&user);
                match mech {
                    Mech::Plain => c.send(&format!("AUTH PLAIN {}", plain(&user, &pw))).await,
                    Mech::Login => {
                        c.send("AUTH LOGIN").await;
                        if !cell.withheld() {
                            assert_eq!(c.line().await, "334 VXNlcm5hbWU6");
                            c.send(&b64(&user)).await;
                            assert_eq!(c.line().await, "334 UGFzc3dvcmQ6");
                            c.send(&b64(&pw)).await;
                        }
                    }
                    Mech::LoginIr => {
                        c.send(&format!("AUTH LOGIN {}", b64(&user))).await;
                        if !cell.withheld() {
                            assert_eq!(c.line().await, "334 UGFzc3dvcmQ6");
                            c.send(&b64(&pw)).await;
                        }
                    }
                    Mech::Xoauth2 => {
                        c.send(&format!(
                            "AUTH XOAUTH2 {}",
                            xoauth2(&claimed(&user), &token)
                        ))
                        .await
                    }
                    Mech::Oauthbearer => {
                        c.send(&format!(
                            "AUTH OAUTHBEARER {}",
                            oauthbearer(&claimed(&user), &token)
                        ))
                        .await
                    }
                    Mech::LoginCmd => unreachable!(),
                }
                if cell.accepted() {
                    assert_eq!(c.line().await, "235 2.7.0 Authentication successful");
                    c.send("NOOP").await;
                    assert_eq!(c.line().await, "ECHO NOOP", "{}", cell.id());
                } else {
                    assert_eq!(
                        c.line().await,
                        "504 5.5.4 password authentication not available on this endpoint",
                        "{}",
                        cell.id()
                    );
                    c.expect_end(Kind::Smtp).await;
                }
                check_cell(&h, Kind::Smtp, &cell, &before, &c).await;
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sieve_gate_matrix() {
    let h = Harness::start().await;
    // ManageSieve has no LOGIN mechanism.
    let mechs = [Mech::Plain, Mech::Xoauth2, Mech::Oauthbearer];
    for sni in SNIS {
        for src in SRCS {
            for mech in mechs {
                let cell = Cell {
                    proto: "sieve",
                    sni,
                    src,
                    mech,
                };
                let before = Before::take(&h, Kind::Sieve).await;
                let (mut c, greeting, caps) = h.sieve(src, sni).await;
                // Before TLS the greeting offers no mechanism anywhere, and
                // lists the backend's SIEVE line, the first session's too
                // (RFC 5804 §1.7).
                let implementation = format!("\"IMPLEMENTATION\" \"{HOSTNAME}\"");
                let expected = [
                    implementation.as_str(),
                    "\"SASL\" \"\"",
                    "\"SIEVE\" \"fileinto reject envelope\"",
                    "\"STARTTLS\"",
                    "\"VERSION\" \"1.0\"",
                    "OK \"ready\"",
                ];
                assert_eq!(greeting, expected, "{}", cell.id());
                // After TLS: the backend's capabilities, STARTTLS dropped and
                // SASL rewritten by the gate.
                let sasl = if cell.password_allowed() {
                    "\"SASL\" \"XOAUTH2 OAUTHBEARER PLAIN\""
                } else {
                    "\"SASL\" \"XOAUTH2 OAUTHBEARER\""
                };
                assert_eq!(
                    caps,
                    [
                        "\"IMPLEMENTATION\" \"Pigeonhole mock\"",
                        "\"SIEVE\" \"fileinto reject envelope\"",
                        "\"NOTIFY\" \"mailto\"",
                        sasl,
                        "\"VERSION\" \"1.0\"",
                        "OK \"TLS negotiation successful.\"",
                    ],
                    "{}",
                    cell.id()
                );

                let (user, pw) = (cell.user(), cell.password());
                let token = h.idp.token(&user);
                let (name, ir) = match mech {
                    Mech::Plain => ("PLAIN", plain(&user, &pw)),
                    Mech::Xoauth2 => ("XOAUTH2", xoauth2(&claimed(&user), &token)),
                    Mech::Oauthbearer => ("OAUTHBEARER", oauthbearer(&claimed(&user), &token)),
                    _ => unreachable!(),
                };
                c.send(&format!("AUTHENTICATE \"{name}\" \"{ir}\"")).await;
                if cell.accepted() {
                    // The backend's reply line, verbatim.
                    assert_eq!(c.line().await, "OK \"Logged in.\"");
                    c.send("NOOP").await;
                    assert_eq!(c.line().await, "ECHO NOOP", "{}", cell.id());
                } else {
                    assert_eq!(
                        c.line().await,
                        "NO \"password authentication not available on this endpoint\"",
                        "{}",
                        cell.id()
                    );
                    c.expect_closed().await;
                }
                check_cell(&h, Kind::Sieve, &cell, &before, &c).await;
            }
        }
    }
    // The capability probe ran once (cache), as the proxy's own connection.
    let probes: Vec<_> = h.sieve_be.seen().into_iter().filter(|s| s.probe).collect();
    assert_eq!(probes.len(), 1);
    assert_eq!(
        probes[0].proxy_header,
        Some(ProxyHeader {
            local: true,
            src: None,
            dst: None
        })
    );
}

/// Before STARTTLS ManageSieve offers no mechanism and refuses AUTHENTICATE
/// with ENCRYPT-NEEDED; the credential never reaches the backend and the
/// session can still upgrade.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sieve_authenticate_before_tls_needs_encryption() {
    let h = Harness::start().await;
    let token = h.idp.token(EMAIL);
    let mut c = Client::connect(h.proxy.sieve, Src::External).await;
    let greeting = c.sieve_response().await;
    assert!(
        greeting.contains(&"\"SASL\" \"\"".to_string()),
        "{greeting:?}"
    );
    c.send(&format!(
        "AUTHENTICATE \"XOAUTH2\" \"{}\"",
        xoauth2(EMAIL, &token)
    ))
    .await;
    assert_eq!(c.line().await, "NO (ENCRYPT-NEEDED) \"STARTTLS required\"");
    c.send("STARTTLS").await;
    assert_eq!(c.line().await, "OK \"Begin TLS negotiation now\"");
    c.tls(&h.pki, Sni::Public).await;
    c.sieve_response().await;
    assert!(h.sieve_be.sessions().is_empty());
    assert!(h.proxy.authresults().is_empty());
}
