//! Certificates by SNI (RFC 6066 §3): the certificate that carries the
//! requested name, a wildcard for exactly one label (RFC 6125 §6.4.3), the
//! default certificate without SNI, `unrecognized_name` for any other name
//! (RFC 9325 §3.7), and reload and expiry per certificate.

mod common;
use common::*;

const TENANT: &str = "mail.tenant.test";
/// `notAfter` of the wildcard certificate (2040-01-01T00:00:00Z).
const WILDCARD_NOT_AFTER: u64 = 2_208_988_800;
/// How the rustls client reports the alert `unrecognized_name` it received.
const UNRECOGNIZED: &str = "received fatal alert: UnrecognisedName";

/// A proxy with two certificates besides the default: `mail.tenant.test`
/// and `*.wild.test`.
async fn start() -> (Harness, Issued, Issued) {
    let pki = Pki::new();
    let tenant = pki.issue("tenant", &[TENANT], None);
    let wildcard = pki.issue("wildcard", &["*.wild.test"], Some((2040, 1, 1)));
    let opts = Opts {
        tls_certificates: vec![
            (tenant.cert.clone(), tenant.key.clone()),
            (wildcard.cert.clone(), wildcard.key.clone()),
        ],
        ..Opts::default()
    };
    (Harness::start_on(pki, opts).await, tenant, wildcard)
}

/// A connection of `kind` at the point where TLS starts (implicit TLS, or
/// after STARTTLS).
async fn before_tls(h: &Harness, kind: Kind) -> Client {
    match kind {
        Kind::Imap => Client::connect(h.proxy.imap, Src::External).await,
        Kind::Smtp => {
            let mut c = Client::connect(h.proxy.smtp, Src::External).await;
            c.line().await;
            c.send("STARTTLS").await;
            assert_eq!(c.line().await, "220 2.0.0 Ready to start TLS");
            c
        }
        Kind::Sieve => {
            let mut c = Client::connect(h.proxy.sieve, Src::External).await;
            c.sieve_response().await;
            c.send("STARTTLS").await;
            assert_eq!(c.line().await, "OK \"Begin TLS negotiation now\"");
            c
        }
    }
}

/// The certificate the proxy serves to `sni` on `kind`, or the handshake
/// error.
async fn served(h: &Harness, kind: Kind, sni: Sni) -> std::io::Result<Vec<u8>> {
    let mut c = before_tls(h, kind).await;
    c.try_tls(&h.pki, sni).await?;
    Ok(c.peer_cert())
}

fn expiry(cert: &std::path::Path) -> String {
    format!(
        "mail_auth_proxy_tls_cert_expiry_timestamp_seconds{{cert=\"{}\"}}",
        cert.display()
    )
}

/// Each listener serves the certificate that carries the requested name, in
/// any letter case; a wildcard stands for one label; without SNI, and for
/// the default certificate's own names, the default.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sni_selects_the_certificate() {
    let (h, tenant, wildcard) = start().await;
    for kind in Kind::ALL {
        for (sni, want) in [
            (Sni::Name(TENANT), &tenant.der),
            (Sni::Name("MAIL.Tenant.TEST"), &tenant.der),
            (Sni::Name("imap.wild.test"), &wildcard.der),
            (Sni::Name("SMTP.WILD.test"), &wildcard.der),
            (Sni::Public, &h.pki.proxy_der),
            (Sni::Internal, &h.pki.proxy_der),
            (Sni::None, &h.pki.proxy_der),
        ] {
            let got = served(&h, kind, sni).await.unwrap();
            assert!(got == *want, "{kind:?} {sni:?}: wrong certificate");
        }
    }
    // A session on a selected certificate works end to end.
    let token = h.idp.token(EMAIL);
    let (_c, reply) = h
        .auth(
            Kind::Imap,
            Src::External,
            Sni::Name(TENANT),
            "XOAUTH2",
            &xoauth2(EMAIL, &token),
        )
        .await;
    assert!(reply.starts_with("a OK"), "{reply}");
}

/// A name that no certificate carries ends the handshake with the fatal
/// alert `unrecognized_name` before any certificate is sent: a wildcard
/// covers neither its parent nor two labels, and the backend never sees
/// the connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unknown_names_are_refused() {
    let (h, _, _) = start().await;
    for kind in Kind::ALL {
        for name in ["other.test", "wild.test", "a.b.wild.test", "tenant.test"] {
            let e = served(&h, kind, Sni::Name(name)).await.unwrap_err();
            assert!(e.to_string().contains(UNRECOGNIZED), "{kind:?} {name}: {e}");
        }
        let line = h.wait_session_ended(kind, 1).await;
        assert!(
            line.contains("TLS server name other.test is not a name of any configured certificate"),
            "{line}"
        );
        assert!(h.backend(kind).sessions().is_empty(), "{kind:?}");
    }
}

/// The same with the single certificate of the `[tls] cert` form: a client
/// asking for another name is refused instead of getting that certificate.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unknown_name_is_refused_with_one_certificate() {
    let h = Harness::start().await;
    for kind in Kind::ALL {
        let e = served(&h, kind, Sni::Name("other.test")).await.unwrap_err();
        assert!(e.to_string().contains(UNRECOGNIZED), "{kind:?}: {e}");
        assert!(served(&h, kind, Sni::None).await.unwrap() == h.pki.proxy_der);
    }
}

/// Every certificate has its own expiry series (label `cert`, the file).
/// SIGHUP reloads each certificate on its own: a renewed one is served from
/// the next handshake on, an unusable one keeps what it had (ERROR with its
/// file), and neither affects the other.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reload_and_expiry_per_certificate() {
    let (h, tenant, wildcard) = start().await;
    let m = h.proxy.metrics().await;
    let series: Vec<_> = m
        .keys()
        .filter(|k| k.starts_with("mail_auth_proxy_tls_cert_expiry_timestamp_seconds"))
        .collect();
    assert_eq!(series.len(), 3, "{series:?}");
    assert_eq!(m[&expiry(&h.pki.proxy_cert)], PROXY_NOT_AFTER);
    assert_eq!(m[&expiry(&tenant.cert)], PROXY_NOT_AFTER);
    assert_eq!(m[&expiry(&wildcard.cert)], WILDCARD_NOT_AFTER);

    let renewed = h
        .pki
        .issue("tenant-renewed", &[TENANT], Some((2049, 12, 31)));
    std::fs::copy(&renewed.cert, &tenant.cert).unwrap();
    std::fs::copy(&renewed.key, &tenant.key).unwrap();
    std::fs::write(&wildcard.cert, "not a certificate").unwrap();
    h.proxy.signal("HUP");
    h.proxy
        .wait_logs("reload: certificate unusable; keeping the current one", 1)
        .await;
    h.proxy.wait_logs("reload: certificate loaded", 2).await;
    let refused: Vec<String> = h
        .proxy
        .logs()
        .into_iter()
        .filter(|l| l.contains("reload: certificate unusable"))
        .collect();
    assert!(
        refused.len() == 1
            && refused[0].contains(" ERROR ")
            && refused[0].contains(&format!("cert={}", wildcard.cert.display())),
        "{refused:?}"
    );

    let m = h.proxy.metrics().await;
    assert_eq!(m[&expiry(&h.pki.proxy_cert)], PROXY_NOT_AFTER);
    assert_eq!(m[&expiry(&tenant.cert)], RENEWED_NOT_AFTER);
    assert_eq!(m[&expiry(&wildcard.cert)], WILDCARD_NOT_AFTER);

    let full = |sni: Sni| {
        let h = &h;
        async move {
            let mut c = Client::connect(h.proxy.imap, Src::External).await;
            c.tls_full(&h.pki, sni).await;
            c.peer_cert()
        }
    };
    assert!(full(Sni::Name(TENANT)).await == renewed.der);
    assert!(full(Sni::Name("imap.wild.test")).await == wildcard.der);
    assert!(full(Sni::None).await == h.pki.proxy_der);
}

fn check_config(pki: &Pki, tls: &str, extra: &str) -> (bool, String) {
    let cfg = format!(
        r#"config_version = 2
[server]
hostname = "{HOSTNAME}"
[tls]
{tls}
[imap]
listen = "127.0.0.10:0"
backend = {{ address = "127.0.0.1:1", verify_name = "{BACKEND_NAME}", ca_file = "{}" }}
[oauth]
[[oauth.issuers]]
issuer = "{ISSUER}"
jwks_url = "https://idp.test/certs"
audiences = ["{AUDIENCE}"]
token_type = "keycloak"
{extra}"#,
        pki.ca_file.display()
    );
    let path = pki.dir.path().join("check.toml");
    std::fs::write(&path, cfg).unwrap();
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_mail-auth-proxy"))
        .arg("-t")
        .arg(&path)
        .output()
        .unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.success(), text)
}

fn pair(cert: &std::path::Path, key: &std::path::Path) -> String {
    format!(
        "cert = \"{}\"\nkey = \"{}\"\n",
        cert.display(),
        key.display()
    )
}

/// `-t` loads every pair and names the one at fault; a certificate other
/// than the default must carry a DNS name (only SNI selects it). A default
/// without one, and a legacy rule name no certificate carries, are warnings.
#[test]
fn check_config_checks_every_certificate() {
    let pki = Pki::new();
    let tenant = pki.issue("tenant", &[TENANT], None);
    let nameless = pki.issue("nameless", &[], None);
    let default = pair(&pki.proxy_cert, &pki.proxy_key);
    let extra = |p: &str| format!("{default}[[tls.certificates]]\n{p}");

    let (ok, out) = check_config(&pki, &extra(&pair(&tenant.cert, &tenant.key)), "");
    assert!(ok, "{out}");
    assert!(out.contains("configuration OK (0 warning(s))"), "{out}");

    let missing = pki.dir.path().join("missing.pem");
    let two = format!(
        "{}[[tls.certificates]]\n{}",
        extra(&pair(&missing, &tenant.key)),
        pair(&nameless.cert, &nameless.key)
    );
    let (ok, out) = check_config(&pki, &two, "");
    assert!(!ok, "{out}");
    assert!(
        out.contains(&format!("tls.certificates[0].cert: {}", missing.display())),
        "{out}"
    );
    assert!(
        out.contains("tls.certificates[1]: ") && out.contains("no DNS name"),
        "{out}"
    );

    // A key that belongs to another certificate.
    let (ok, out) = check_config(&pki, &extra(&pair(&tenant.cert, &pki.proxy_key)), "");
    assert!(!ok && out.contains("tls.certificates[0]: "), "{out}");

    // The same file twice would give two series with one label.
    let (ok, out) = check_config(&pki, &extra(&default), "");
    assert!(
        !ok && out.contains("tls.certificates[0].cert = ") && out.contains("is already tls.cert"),
        "{out}"
    );

    let rule = "[[legacy.rules]]\nname = \"office\"\nnetworks = [\"10.0.0.0/8\"]\nsni = [\"mail.other.test\"]\n";
    let (ok, out) = check_config(&pki, &pair(&nameless.cert, &nameless.key), rule);
    assert!(ok, "{out}");
    assert!(out.contains("configuration OK (2 warning(s))"), "{out}");
    assert!(
        out.contains("tls.cert: ") && out.contains("has no DNS name in its subjectAltName"),
        "{out}"
    );
    assert!(
        out.contains("legacy.rules[office].sni: \"mail.other.test\" is not a name of any configured certificate"),
        "{out}"
    );
}
