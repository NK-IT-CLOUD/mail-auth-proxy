//! The failure result of the OAuth mechanisms (RFC 7628 section 3.2.2) and
//! the client's answer that completes it (section 3.2.3).
//!
//! A client whose token failed validation gets a JSON error result as a SASL
//! challenge, answers it with a dummy response (OAUTHBEARER `%x01`, XOAUTH2
//! an empty one) or an abort, and only then gets the final failure. The
//! result names the IdP a client can get a token from.
//!
//! The result is built once from the configuration and is the same for
//! every rejected token: the token was not trusted, so nothing in it (its
//! `iss` least of all) may choose what the client is told, and the answer
//! must not tell one cause of the rejection from another.

use crate::config::OAuth;
use crate::wire::line::read_client_line;
use crate::wire::Tuning;
use base64::Engine;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

/// The base64 error result sent as the challenge after a rejected token.
pub struct ErrorChallenge(String);

impl ErrorChallenge {
    /// `{"status":"invalid_token"}` plus `scope` and `openid-configuration`
    /// when given (both optional in RFC 7628 section 3.2.2).
    pub fn new(openid_configuration: Option<&str>, scope: Option<&str>) -> Self {
        let mut json = String::from(r#"{"status":"invalid_token""#);
        for (key, value) in [
            ("scope", scope),
            ("openid-configuration", openid_configuration),
        ] {
            if let Some(v) = value {
                json.push_str(&format!(",\"{key}\":{}", serde_json::Value::from(v)));
            }
        }
        json.push('}');
        ErrorChallenge(base64::engine::general_purpose::STANDARD.encode(json))
    }

    /// From the one issuer that sets `openid_configuration_url` or `scope`
    /// (validation allows one at most); without one, the status alone.
    pub fn from_config(oauth: &OAuth) -> Self {
        let issuer = oauth.issuers.iter().find(|i| i.has_discovery());
        ErrorChallenge::new(
            issuer.and_then(|i| i.openid_configuration_url.as_deref()),
            issuer.and_then(|i| i.scope.as_deref()),
        )
    }

    /// The challenge data, base64.
    pub fn base64(&self) -> &str {
        &self.0
    }
}

/// The client's answer to the error challenge.
#[derive(Debug, PartialEq, Eq)]
pub enum Answer {
    /// The dummy response: `%x01` for OAUTHBEARER, empty for XOAUTH2.
    Dummy,
    /// Decodes, but is not the dummy (another mechanism's dummy, a new
    /// credential). Ends the same way: the exchange has failed.
    Unexpected,
    /// `*`: the client aborted the exchange (RFC 4422 section 3.5).
    Cancelled,
    /// Not base64. IMAP and SMTP answer it like an abort (RFC 9051
    /// section 6.2.2, RFC 4954 section 4).
    Undecodable,
}

impl Answer {
    /// Suffix for the session-end detail in the journal.
    pub fn note(answer: &anyhow::Result<Answer>) -> String {
        match answer {
            Ok(Answer::Dummy) => String::new(),
            Ok(Answer::Unexpected) => {
                "; the answer to the error challenge was not the dummy".into()
            }
            Ok(Answer::Cancelled) => "; the client cancelled at the error challenge".into(),
            Ok(Answer::Undecodable) => "; the answer to the error challenge was not base64".into(),
            Err(e) => format!("; no answer to the error challenge: {e:#}"),
        }
    }
}

/// IMAP and SMTP: send `prompt` (`+ <challenge>`, `334 <challenge>`), read
/// the answer line and classify it for `mech`. Runs inside the pre-auth
/// budget that ends at `until`, each read bounded by the idle timeout. The
/// answer can carry a credential (a client that resends its AUTHENTICATE
/// line), so the line is zeroized on drop.
pub async fn complete_line<S>(
    stream: &mut S,
    prompt: &str,
    mech: &str,
    until: tokio::time::Instant,
    tuning: &Tuning,
) -> anyhow::Result<Answer>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let line = crate::wire::deadline_at(until, tuning.preauth, "error challenge", async {
        stream.write_all(format!("{prompt}\r\n").as_bytes()).await?;
        stream.flush().await?;
        Ok(read_client_line(stream, tuning.idle).await?)
    })
    .await?;
    Ok(classify(mech, &line))
}

/// Classify the answer `response` (the client's base64 line, or the
/// contents of a ManageSieve string) to the error challenge of `mech`.
pub fn classify(mech: &str, response: &str) -> Answer {
    let response = response.trim();
    if response == "*" {
        return Answer::Cancelled;
    }
    let Ok(data) = base64::engine::general_purpose::STANDARD.decode(response) else {
        return Answer::Undecodable;
    };
    let dummy: &[u8] = if mech.eq_ignore_ascii_case("OAUTHBEARER") {
        b"\x01"
    } else {
        b""
    };
    if data == dummy {
        Answer::Dummy
    } else {
        Answer::Unexpected
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decoded(c: &ErrorChallenge) -> serde_json::Value {
        let raw = base64::engine::general_purpose::STANDARD
            .decode(c.base64())
            .unwrap();
        serde_json::from_slice(&raw).unwrap()
    }

    #[test]
    fn status_alone_without_configuration() {
        let c = ErrorChallenge::new(None, None);
        assert_eq!(c.base64(), "eyJzdGF0dXMiOiJpbnZhbGlkX3Rva2VuIn0=");
        assert_eq!(decoded(&c), serde_json::json!({"status": "invalid_token"}));
    }

    #[test]
    fn scope_and_openid_configuration() {
        let url = "https://idp.example.org/realms/mail/.well-known/openid-configuration";
        let c = ErrorChallenge::new(Some(url), Some("openid"));
        assert_eq!(
            decoded(&c),
            serde_json::json!({"status": "invalid_token", "scope": "openid", "openid-configuration": url})
        );
        // JSON escaping, although validation never lets a quote through.
        let c = ErrorChallenge::new(Some("https://x.example/\"}"), None);
        assert_eq!(decoded(&c)["openid-configuration"], "https://x.example/\"}");
    }

    #[test]
    fn answers() {
        use Answer::*;
        for (mech, response, want) in [
            ("OAUTHBEARER", "AQ==", Dummy),
            ("oauthbearer", "AQ==", Dummy),
            ("OAUTHBEARER", "", Unexpected),
            ("XOAUTH2", "", Dummy),
            ("XOAUTH2", "AQ==", Unexpected),
            ("XOAUTH2", "dXNlcj0=", Unexpected),
            ("OAUTHBEARER", "*", Cancelled),
            ("XOAUTH2", " * ", Cancelled),
            ("XOAUTH2", "a AUTHENTICATE XOAUTH2 dXNlcj0=", Undecodable),
            ("OAUTHBEARER", "AQ", Undecodable),
            ("OAUTHBEARER", "\"AQ==\"", Undecodable),
        ] {
            assert_eq!(classify(mech, response), want, "{mech} {response:?}");
        }
    }
}
