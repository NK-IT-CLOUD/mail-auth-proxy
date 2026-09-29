//! Protocol and RFC conformance of the client and backend dialogs.

mod common;
use common::*;

fn backend_errors(kind: Kind) -> String {
    format!(
        "mail_auth_proxy_backend_errors_total{{proto=\"{}\"}}",
        kind.label()
    )
}

fn retry_later(kind: Kind) -> &'static str {
    match kind {
        Kind::Imap => "a NO [UNAVAILABLE] Backend temporarily unavailable",
        Kind::Smtp => "454 4.7.0 Temporary authentication failure",
        Kind::Sieve => "NO (TRYLATER) \"Service temporarily unavailable\"",
    }
}

/// A token login to a backend that offers UNAUTHENTICATE (RFC 8437, RFC
/// 5804 §2.14.1) is an outage with a clear journal line: after the splice
/// the client could leave its login and try passwords past the gate.
async fn expect_unauthenticate_outage(h: &Harness, kind: Kind, n: usize) {
    let (mut c, reply) = h
        .auth(
            kind,
            Src::External,
            Sni::Public,
            "XOAUTH2",
            &xoauth2(EMAIL, &h.idp.token(EMAIL)),
        )
        .await;
    assert_eq!(reply, retry_later(kind), "{kind:?}");
    c.expect_end(kind).await;
    let line = h.wait_session_ended(kind, n).await;
    assert!(line.contains("backend offers UNAUTHENTICATE"), "{line}");
    assert!(h.proxy.authresults().is_empty(), "{kind:?}");
    assert_eq!(h.proxy.metric(&backend_errors(kind)).await, n as u64);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn imap_backend_with_unauthenticate_is_outage() {
    let h = Harness::start().await;
    // In the CAPABILITY code of the tagged OK.
    *h.imap_be.login_caps.lock().unwrap() = Some("IMAP4rev1 IDLE UNAUTHENTICATE".into());
    expect_unauthenticate_outage(&h, Kind::Imap, 1).await;
    // In the answer to the proxy's own CAPABILITY, for an OK without code.
    h.imap_be
        .caps_untagged
        .store(true, std::sync::atomic::Ordering::SeqCst);
    expect_unauthenticate_outage(&h, Kind::Imap, 2).await;
    // Without it the login goes through; the proxy's CAPABILITY exchange is
    // not relayed to the client.
    *h.imap_be.login_caps.lock().unwrap() = None;
    let (mut c, reply) = h
        .auth(
            Kind::Imap,
            Src::External,
            Sni::Public,
            "XOAUTH2",
            &xoauth2(EMAIL, &h.idp.token(EMAIL)),
        )
        .await;
    assert_eq!(reply, "a OK Logged in");
    c.send("b NOOP").await;
    assert_eq!(c.line().await, "ECHO b NOOP");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sieve_backend_with_unauthenticate_is_outage() {
    let h = Harness::start().await;
    *h.sieve_be.login_caps.lock().unwrap() = Some("\"UNAUTHENTICATE\"".into());
    // Not relayed to the client.
    let (_c, _greeting, caps) = h.sieve(Src::External, Sni::Public).await;
    assert!(caps.iter().any(|l| l.starts_with("\"SIEVE\"")), "{caps:?}");
    assert!(
        !caps.iter().any(|l| l.contains("UNAUTHENTICATE")),
        "{caps:?}"
    );
    expect_unauthenticate_outage(&h, Kind::Sieve, 1).await;
    // The credential never reached the backend.
    assert!(h.sieve_be.sessions().iter().all(|s| s.login.is_none()));
}

/// A ManageSieve `BYE` in answer to `AUTHENTICATE` (shutdown, connection
/// limit; RFC 5804 §1.3) is an outage on both paths: retry-later, no
/// authresult line, a backend error, and the account throttle is not charged.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sieve_bye_is_outage() {
    let h = Harness::start_with(Opts {
        legacy: Some(
            "[legacy]\nthrottle = { failures = 1, window_secs = 3600 }\n[[legacy.rules]]\nname = \"all\"\nnetworks = [\"127.0.0.0/8\"]\n".into(),
        ),
        ..Opts::default()
    })
    .await;
    *h.sieve_be.auth_reply.lock().unwrap() = Some("BYE \"Too many connections\"".into());
    let token = h.idp.token(EMAIL);
    for (n, (src, sni, mech, ir)) in [
        (
            Src::External,
            Sni::Public,
            "XOAUTH2",
            xoauth2(EMAIL, &token),
        ),
        (
            Src::Internal,
            Sni::Internal,
            "PLAIN",
            plain("bob@example.test", "pw"),
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let (mut c, reply) = h.auth(Kind::Sieve, src, sni, mech, &ir).await;
        assert_eq!(reply, "NO (TRYLATER) \"Service temporarily unavailable\"");
        c.expect_closed().await;
        let line = h.wait_session_ended(Kind::Sieve, n + 1).await;
        assert!(line.contains("Too many connections"), "{line}");
        assert!(h.proxy.authresults().is_empty(), "{mech}");
        assert_eq!(
            h.proxy.metric(&backend_errors(Kind::Sieve)).await,
            n as u64 + 1
        );
    }
    // Not throttled: the next login of the account goes through.
    *h.sieve_be.auth_reply.lock().unwrap() = None;
    let (_c, reply) = h
        .auth(
            Kind::Sieve,
            Src::Internal,
            Sni::Internal,
            "PLAIN",
            &plain("bob@example.test", "pw"),
        )
        .await;
    assert_eq!(reply, "OK \"Logged in.\"");
}

/// Connect, present `mech`/`ir` and expect an outage because the pre-auth
/// budget (2 s) ran out: retry-later well before the IdP's or backend's own
/// timeout (10 s), and no authresult line.
async fn expect_budget_outage(h: &Harness, kind: Kind, src: Src, sni: Sni, mech: &str, ir: &str) {
    let ended = h.sessions_ended(kind);
    let started = std::time::Instant::now();
    let (mut c, reply) = h.auth(kind, src, sni, mech, ir).await;
    assert_eq!(reply, retry_later(kind), "{kind:?} {mech}");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "{kind:?} {mech}: answered after {:?}",
        started.elapsed()
    );
    c.expect_end(kind).await;
    let line = h.wait_session_ended(kind, ended + 1).await;
    assert!(line.contains("pre-auth budget of 2s used up"), "{line}");
    assert!(h.proxy.authresults().is_empty(), "{kind:?} {mech}");
}

/// Token validation (with the JWKS refresh an unknown kid triggers) and the
/// backend login run inside the pre-auth budget. A slow IdP or a backend
/// that hangs after the credential must not hold pre-auth slots beyond it,
/// and running out is an outage, not a failed login.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authorize_runs_within_the_preauth_budget() {
    let h = Harness::start_with(Opts {
        preauth_secs: 2,
        legacy: Some("[[legacy.rules]]\nname = \"all\"\nnetworks = [\"127.0.0.0/8\"]\n".into()),
        ..Opts::default()
    })
    .await;
    // The refresh for an unknown kid hangs until the JWKS fetch times out.
    h.idp
        .delay_ms
        .store(15_000, std::sync::atomic::Ordering::SeqCst);
    let rotated = h.idp.mint_with_kid("rotated", serde_json::json!({}));
    for kind in Kind::ALL {
        expect_budget_outage(
            &h,
            kind,
            Src::External,
            Sni::Public,
            "XOAUTH2",
            &xoauth2(EMAIL, &rotated),
        )
        .await;
    }
    // The refresh the budget cut short was not restarted per connection.
    assert_eq!(h.idp.fetches.load(std::sync::atomic::Ordering::SeqCst), 2);

    // A backend that hangs after the credential, on both paths.
    let token = h.idp.token("stall@example.test");
    for kind in Kind::ALL {
        expect_budget_outage(
            &h,
            kind,
            Src::External,
            Sni::Public,
            "XOAUTH2",
            &xoauth2("stall@example.test", &token),
        )
        .await;
        expect_budget_outage(
            &h,
            kind,
            Src::Internal,
            Sni::Internal,
            "PLAIN",
            &plain("stall-pw@example.test", "pw"),
        )
        .await;
    }
    for kind in Kind::ALL {
        assert_eq!(h.proxy.metric(&backend_errors(kind)).await, 3, "{kind:?}");
    }
}

/// A password mechanism the endpoint does not offer, chosen without the
/// password in an initial response, is refused at once: the proxy never
/// sends a continuation (`+`, `334`, `""`) that asks for a password it would
/// not use. Logged as `blocked_endpoint` without a fingerprint, with the
/// login if the client sent it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oauth_only_endpoint_never_prompts_for_a_password() {
    let h = Harness::start().await;
    let login_ir = b64("eve@example.test");
    let cases = [
        (Kind::Imap, "a AUTHENTICATE PLAIN", "PLAIN", ""),
        (Kind::Imap, "a AUTHENTICATE LOGIN", "LOGIN", ""),
        (
            Kind::Imap,
            &*format!("a AUTHENTICATE LOGIN {login_ir}"),
            "LOGIN",
            "eve@example.test",
        ),
        (Kind::Smtp, "AUTH PLAIN", "PLAIN", ""),
        (Kind::Smtp, "AUTH LOGIN", "LOGIN", ""),
        (
            Kind::Smtp,
            &*format!("AUTH LOGIN {login_ir}"),
            "LOGIN",
            "eve@example.test",
        ),
        (Kind::Sieve, "AUTHENTICATE \"PLAIN\"", "PLAIN", ""),
    ];
    for (n, (kind, cmd, mech, user)) in cases.into_iter().enumerate() {
        let mut c = h.ready(kind, Src::External, Sni::Public).await;
        c.send(cmd).await;
        let want = match kind {
            Kind::Imap => "a NO password authentication not available on this endpoint",
            Kind::Smtp => "504 5.5.4 password authentication not available on this endpoint",
            Kind::Sieve => "NO \"password authentication not available on this endpoint\"",
        };
        assert_eq!(c.line().await, want, "{cmd}");
        let ars = h.proxy.wait_authresults(n + 1).await;
        let ar = &ars[n];
        assert_eq!(
            (
                ar.proto.as_str(),
                ar.reason.as_str(),
                ar.mech.as_str(),
                ar.user.as_str(),
                ar.pwfp.as_str()
            ),
            (kind.label(), "blocked_endpoint", mech, user, ""),
            "{cmd}"
        );
    }
    // Where PLAIN is offered, the continuation still asks for it.
    let mut c = h.ready(Kind::Imap, Src::Internal, Sni::Internal).await;
    c.send("a AUTHENTICATE PLAIN").await;
    assert_eq!(c.line().await, "+ ");
}

/// ManageSieve `AUTHENTICATE` without initial response (RFC 5804 §2.1): the
/// client answers the empty challenge with a string, quoted or literal, and
/// `"*"` cancels with NO. Client literals are `{n+}` only (§4); `{n}` and
/// anything after the header or after the octets are refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sieve_continuation_and_literals() {
    let h = Harness::start().await;
    let ir = xoauth2(EMAIL, &h.idp.token(EMAIL));
    for response in [format!("\"{ir}\""), format!("{{{}+}}\r\n{ir}", ir.len())] {
        let mut c = h.ready(Kind::Sieve, Src::External, Sni::Public).await;
        c.send("AUTHENTICATE \"XOAUTH2\"").await;
        assert_eq!(c.line().await, "\"\"");
        c.send(&response).await;
        assert_eq!(c.line().await, "OK \"Logged in.\"", "{response:.8}");
        c.send("NOOP").await;
        assert_eq!(c.line().await, "ECHO NOOP");
    }

    let mut c = h.ready(Kind::Sieve, Src::External, Sni::Public).await;
    c.send("AUTHENTICATE \"XOAUTH2\"").await;
    assert_eq!(c.line().await, "\"\"");
    c.send("\"*\"").await;
    assert!(c.line().await.starts_with("NO "));
    c.expect_closed().await;

    let n = ir.len();
    for bad in [
        format!("AUTHENTICATE \"XOAUTH2\" {{{n}}}\r\n{ir}"),
        format!("AUTHENTICATE \"XOAUTH2\" {{{n}++}}\r\n{ir}"),
        format!("AUTHENTICATE \"XOAUTH2\" {{{n}+}} x\r\n{ir}"),
        format!("AUTHENTICATE \"XOAUTH2\" {{{n}+}}\r\n{ir} NOOP"),
    ] {
        let mut c = h.ready(Kind::Sieve, Src::External, Sni::Public).await;
        c.send(&bad).await;
        assert_eq!(c.line().await, "NO \"Invalid AUTHENTICATE\"", "{bad:.30}");
        c.expect_closed().await;
    }
    // Only the two good logins reached the backend.
    assert_eq!(h.sieve_be.sessions().len(), 2);
    let ars = h.proxy.authresults();
    assert_eq!(
        ars.iter().map(|a| a.reason.as_str()).collect::<Vec<_>>(),
        ["ok", "ok", "protocol", "protocol", "protocol", "protocol", "protocol"]
    );
}

/// The ManageSieve greeting must list SIEVE (RFC 5804 §1.7), also for the
/// first clients after startup, and a cold cache is filled by one probe,
/// however many clients arrive at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sieve_first_greeting_lists_sieve_with_one_probe() {
    let h = Harness::start().await;
    let session = || async {
        let mut c = Client::connect(h.proxy.sieve, Src::External).await;
        let greeting = c.sieve_response().await;
        assert!(
            greeting
                .iter()
                .any(|l| l == "\"SIEVE\" \"fileinto reject envelope\""),
            "{greeting:?}"
        );
        c.send("STARTTLS").await;
        assert_eq!(c.line().await, "OK \"Begin TLS negotiation now\"");
        c.tls(&h.pki, Sni::Public).await;
        let caps = c.sieve_response().await;
        assert_eq!(caps.last().unwrap(), "OK \"TLS negotiation successful.\"");
    };
    tokio::join!(
        session(),
        session(),
        session(),
        session(),
        session(),
        session()
    );
    let probes = h.sieve_be.seen().iter().filter(|s| s.probe).count();
    assert_eq!(probes, 1);
}

/// Malformed SASL responses are refused before the gate and never reach the
/// backend: a NUL in the PLAIN password (RFC 4616 §2), an OAUTHBEARER GS2
/// header with channel binding (RFC 7628 §3.1, RFC 5801), and a XOAUTH2
/// `user=` with control characters.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_sasl_responses_are_refused() {
    let h = Harness::start().await;
    let token = h.idp.token(EMAIL);
    let cases = [
        (
            Src::Internal,
            Sni::Internal,
            "PLAIN",
            b64("\0bob@example.test\0pw\0x"),
        ),
        (
            Src::External,
            Sni::Public,
            "OAUTHBEARER",
            b64(format!(
                "p=tls-unique,a={EMAIL},\x01auth=Bearer {token}\x01\x01"
            )),
        ),
        (
            Src::External,
            Sni::Public,
            "XOAUTH2",
            xoauth2(&format!("{EMAIL}\x1b[2J"), &token),
        ),
    ];
    for (n, (src, sni, mech, ir)) in cases.into_iter().enumerate() {
        let (mut c, reply) = h.auth(Kind::Imap, src, sni, mech, &ir).await;
        assert!(
            reply.starts_with("a BAD ") || reply.starts_with("a NO "),
            "{mech}: {reply}"
        );
        c.expect_closed().await;
        let ar = &h.proxy.wait_authresults(n + 1).await[n];
        assert_eq!(ar.reason, "protocol", "{mech}");
    }
    assert!(h.imap_be.seen().is_empty(), "backend contacted");
}

/// SMTP takes one AUTH per connection. After a refused one the proxy
/// announces the close with 421 (RFC 5321 §3.8: a server closes only after
/// QUIT, a timeout or a 421), whatever the refusal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn smtp_closes_with_421_after_a_refused_auth() {
    let h = Harness::start().await;
    let closing = format!("421 4.7.0 {HOSTNAME} closing connection");
    let wrong_pw = format!("AUTH PLAIN {}", plain("reject@example.test", "pw"));
    for (src, sni, cmd, reply) in [
        (
            Src::Internal,
            Sni::Internal,
            wrong_pw.as_str(),
            "535 5.7.8 Authentication credentials invalid",
        ),
        (
            Src::External,
            Sni::Public,
            "AUTH PLAIN",
            "504 5.5.4 password authentication not available on this endpoint",
        ),
        (
            Src::External,
            Sni::Public,
            "AUTH XOAUTH2 !!",
            "501 5.5.2 Invalid or cancelled authentication response",
        ),
    ] {
        let mut c = h.ready(Kind::Smtp, src, sni).await;
        c.send(cmd).await;
        assert_eq!(c.line().await, reply, "{cmd}");
        assert_eq!(c.line().await, closing, "{cmd}");
        c.expect_closed().await;
    }
}

/// ManageSieve before authentication allows CAPABILITY and NOOP, also before
/// STARTTLS (RFC 5804 §2); NOOP with an argument answers with the TAG
/// response code (§2.13).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sieve_capability_and_noop_tag() {
    let h = Harness::start().await;
    let mut c = Client::connect(h.proxy.sieve, Src::External).await;
    let greeting = c.sieve_response().await;
    c.send("CAPABILITY").await;
    assert_eq!(c.sieve_response().await, greeting);
    c.send("NOOP \"pre-tls\"").await;
    assert_eq!(c.line().await, "OK (TAG \"pre-tls\") \"Done\"");
    c.send("STARTTLS").await;
    assert_eq!(c.line().await, "OK \"Begin TLS negotiation now\"");
    c.tls(&h.pki, Sni::Public).await;
    c.sieve_response().await;
    c.send("NOOP \"STARTTLS-SYNC-42\"").await;
    assert_eq!(c.line().await, "OK (TAG \"STARTTLS-SYNC-42\") \"Done\"");
    c.send("NOOP").await;
    assert_eq!(c.line().await, "OK \"NOOP completed.\"");
}

/// The ManageSieve backend login sends a response longer than a quoted
/// string may be (1024 octets, RFC 5804 §4) as a literal `{n+}`; the mock
/// refuses a longer quoted string, as a strict server would.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sieve_long_token_goes_to_the_backend_as_literal() {
    let h = Harness::start().await;
    let token = h.idp.mint(serde_json::json!({
        "email": "long@example.test",
        "pad": "x".repeat(1500),
    }));
    let (mut c, reply) = h
        .auth(
            Kind::Sieve,
            Src::External,
            Sni::Public,
            "XOAUTH2",
            &xoauth2("long@example.test", &token),
        )
        .await;
    assert_eq!(reply, "OK \"Logged in.\"");
    c.send("NOOP").await;
    assert_eq!(c.line().await, "ECHO NOOP");
    let s = h.sieve_be.sessions().pop().unwrap();
    assert_eq!(s.secret.as_deref(), Some(token.as_str()));
}

/// `=` is an empty initial response (RFC 4959 §3, RFC 4954 §4), not
/// undecodable base64 and no reason to prompt. A response that is not base64
/// or a cancel gets IMAP BAD / SMTP 501; one that decodes but holds no valid
/// credential IMAP NO / SMTP 535 (RFC 9051 §6.2.2, RFC 4954 §4).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn empty_initial_response_and_no_versus_bad() {
    let h = Harness::start().await;
    let no_bearer = b64("user=bob@example.test\x01\x01");
    for (kind, cmd, want) in [
        (
            Kind::Imap,
            "a AUTHENTICATE PLAIN =",
            "a NO [AUTHENTICATIONFAILED] Authentication failed",
        ),
        (
            Kind::Imap,
            &*format!("a AUTHENTICATE XOAUTH2 {no_bearer}"),
            "a NO [AUTHENTICATIONFAILED] Authentication failed",
        ),
        (
            Kind::Imap,
            "a AUTHENTICATE XOAUTH2 !!",
            "a BAD AUTHENTICATE failed: invalid or cancelled response",
        ),
        (
            Kind::Smtp,
            "AUTH XOAUTH2 =",
            "535 5.7.8 Authentication credentials invalid",
        ),
        (
            Kind::Smtp,
            &*format!("AUTH XOAUTH2 {no_bearer}"),
            "535 5.7.8 Authentication credentials invalid",
        ),
        (
            Kind::Smtp,
            "AUTH XOAUTH2 !!",
            "501 5.5.2 Invalid or cancelled authentication response",
        ),
    ] {
        let mut c = h.ready(kind, Src::Internal, Sni::Internal).await;
        c.send(cmd).await;
        assert_eq!(c.line().await, want, "{cmd}");
        c.expect_end(kind).await;
    }
}

/// An OAuth response with an empty `auth` value is how a client asks which
/// IdP and scope to use (RFC 7628 §4.3): it gets the error result like a
/// rejected token, is recorded as `protocol` (no credential) with its
/// mechanism and user, and counts neither as a failed attempt nor in the
/// rate limit (here: one failure would block).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn empty_auth_is_a_discovery_request() {
    let h = Harness::start_with(Opts {
        issuer_extra: "openid_configuration_url = \"https://idp.test/realms/mail/.well-known/openid-configuration\"\nscope = \"openid\"",
        ratelimit: Some(
            "failures = 1\nwindow_secs = 60\nblock_secs = 60\nexempt_networks = []\n".into(),
        ),
        ..Opts::default()
    })
    .await;
    let failed = |kind: Kind| match kind {
        Kind::Imap => "a NO [AUTHENTICATIONFAILED] Authentication failed",
        Kind::Smtp => "535 5.7.8 Authentication credentials invalid",
        Kind::Sieve => "NO \"Authentication failed\"",
    };
    let mut n = 0;
    for kind in Kind::ALL {
        for (mech, ir) in [
            (
                "OAUTHBEARER",
                b64(format!(
                    "n,a={EMAIL},\x01host=proxy.test\x01port=993\x01auth=\x01\x01"
                )),
            ),
            (
                "XOAUTH2",
                b64(format!("user={EMAIL}\x01auth=Bearer \x01\x01")),
            ),
        ] {
            let (mut c, challenge) = h.auth(kind, Src::External, Sni::Public, mech, &ir).await;
            let result = error_result(kind, &challenge);
            assert_eq!(result["status"], "invalid_token", "{kind:?} {mech}");
            assert_eq!(result["scope"], "openid", "{kind:?} {mech}");
            c.send(&sasl_response(kind, dummy_response(mech))).await;
            assert_eq!(c.line().await, failed(kind), "{kind:?} {mech}");
            c.expect_end(kind).await;
            n += 1;
            let ar = &h.proxy.wait_authresults(n).await[n - 1];
            assert_eq!(
                (ar.reason.as_str(), ar.mech.as_str(), ar.user.as_str()),
                ("protocol", mech, EMAIL),
                "{kind:?}"
            );
        }
    }
    // Not blocked, and no failed attempt counted.
    assert_eq!(h.proxy.count_logs("authlog: ratelimit"), 0);
    let attempts: u64 = h
        .proxy
        .metrics()
        .await
        .iter()
        .filter(|(k, _)| k.starts_with("mail_auth_proxy_auth_attempts_total"))
        .map(|(_, v)| v)
        .sum();
    assert_eq!(attempts, 0);
    let (_c, reply) = h
        .auth(
            Kind::Imap,
            Src::External,
            Sni::Public,
            "XOAUTH2",
            &xoauth2(EMAIL, &h.idp.token(EMAIL)),
        )
        .await;
    assert_eq!(reply, "a OK [CAPABILITY IMAP4rev1 IDLE MOVE] Logged in");
}

/// RFC 7628 §3.2: the OAUTHBEARER `host` must match what the server knows,
/// here the SNI name (ASCII case-insensitive, trailing dot ignored). A
/// mismatch is refused exactly like a rejected token (same error result and
/// failure, `bad_token`); without SNI there is nothing to compare with.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oauthbearer_host_must_match_the_sni() {
    let h = Harness::start().await;
    let token = h.idp.token(EMAIL);
    let ir = |host: &str| {
        b64(format!(
            "n,,\x01host={host}\x01port=993\x01auth=Bearer {token}\x01\x01"
        ))
    };
    let accepted = |kind: Kind| match kind {
        Kind::Imap => "a OK [CAPABILITY IMAP4rev1 IDLE MOVE] Logged in",
        Kind::Smtp => "235 2.7.0 Authentication successful",
        Kind::Sieve => "OK \"Logged in.\"",
    };
    let failed = |kind: Kind| match kind {
        Kind::Imap => "a NO [AUTHENTICATIONFAILED] Authentication failed",
        Kind::Smtp => "535 5.7.8 Authentication credentials invalid",
        Kind::Sieve => "NO \"Authentication failed\"",
    };
    let mut n = 0;
    for kind in Kind::ALL {
        for (sni, host) in [
            (Sni::Public, "MAIL.public.test"),
            (Sni::Public, "mail.public.test."),
            (Sni::None, "anything.example"),
        ] {
            let (_c, reply) = h
                .auth(kind, Src::External, sni, "OAUTHBEARER", &ir(host))
                .await;
            assert_eq!(reply, accepted(kind), "{kind:?} {host}");
            n += 1;
        }
        let (mut c, challenge) = h
            .auth(
                kind,
                Src::External,
                Sni::Public,
                "OAUTHBEARER",
                &ir(INTERNAL_SNI),
            )
            .await;
        assert_eq!(error_result(kind, &challenge)["status"], "invalid_token");
        c.send(&sasl_response(kind, dummy_response("OAUTHBEARER")))
            .await;
        assert_eq!(c.line().await, failed(kind), "{kind:?}");
        c.expect_end(kind).await;
        n += 1;
        let ar = &h.proxy.wait_authresults(n).await[n - 1];
        assert_eq!(ar.reason, "bad_token", "{kind:?}");
    }
}

/// The IMAP ID command is answered before login, so the ID capability is
/// advertised (RFC 2971 §3).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn imap_advertises_id() {
    let h = Harness::start().await;
    let (mut c, greeting) = h.imap(Src::External, Sni::Public).await;
    assert!(greeting.contains(" SASL-IR ID "), "{greeting}");
    c.send("i ID NIL").await;
    assert_eq!(c.line().await, "* ID NIL");
    assert_eq!(c.line().await, "i OK ID completed");
}

/// An IMAP backend that does not advertise SASL-IR gets no initial
/// response (RFC 4959 §3): the credential follows its empty challenge.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn imap_backend_without_sasl_ir_gets_no_initial_response() {
    let h = Harness::start().await;
    h.imap_be
        .no_sasl_ir
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let token = h.idp.token(EMAIL);
    for (src, sni, mech, ir, secret) in [
        (
            Src::External,
            Sni::Public,
            "XOAUTH2",
            xoauth2(EMAIL, &token),
            token.as_str(),
        ),
        (
            Src::Internal,
            Sni::Internal,
            "PLAIN",
            plain("bob@example.test", "pw"),
            "pw",
        ),
    ] {
        let (mut c, reply) = h.auth(Kind::Imap, src, sni, mech, &ir).await;
        assert_eq!(
            reply, "a OK [CAPABILITY IMAP4rev1 IDLE MOVE] Logged in",
            "{mech}"
        );
        c.send("b NOOP").await;
        assert_eq!(c.line().await, "ECHO b NOOP");
        let s = h.imap_be.sessions().pop().unwrap();
        assert_eq!(s.secret.as_deref(), Some(secret), "{mech}");
    }
}
