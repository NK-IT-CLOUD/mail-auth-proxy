//! The extensions advertised in the EHLO reply after STARTTLS: the backend's
//! own, as far as the proxy handles them, from a cached probe of the backend.

use super::{Submission, Upstream};
use crate::server::BackendConn;
use crate::wire::Tuning;
use anyhow::{anyhow, Result};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::time::Instant;

/// The extensions passed on from the backend's EHLO reply. The client keeps
/// the list for the whole session (it does not send EHLO again after AUTH)
/// and uses it against the backend through the blind relay, so each one must
/// work there and in the proxy's own dialog before AUTH:
///
/// - PIPELINING (RFC 2920): the proxy reads its commands one line at a time
///   and keeps what the client sends after AUTH for the backend.
/// - SIZE (RFC 1870), 8BITMIME (RFC 6152), SMTPUTF8 (RFC 6531), DSN (RFC
///   3461): parameters of MAIL and RCPT, which reach the backend only after
///   AUTH. SIZE keeps the backend's limit.
/// - ENHANCEDSTATUSCODES (RFC 2034): the proxy's own replies carry them.
/// - CHUNKING (RFC 3030): BDAT reaches the backend only after AUTH. Before
///   AUTH the proxy answers BDAT with 530 and closes, so its chunk is never
///   read as commands.
///
/// Everything else is left out: AUTH and STARTTLS are the proxy's own;
/// XCLIENT and XFORWARD are the proxy's authorisation at the backend; VRFY,
/// EXPN and ETRN are commands submission clients do not need; any other
/// extension the proxy has not been checked against.
pub const RELAYED: &[&str] = &[
    "PIPELINING",
    "SIZE",
    "8BITMIME",
    "SMTPUTF8",
    "DSN",
    "ENHANCEDSTATUSCODES",
    "CHUNKING",
];

/// The keyword of an EHLO line (RFC 5321 §4.1.1.1: `ehlo-keyword *( SP
/// ehlo-param )`), or `None` if the line is not one: a keyword of letters,
/// digits and hyphens that does not start with a hyphen, then parameters of
/// printable ASCII, separated by single spaces.
pub fn ehlo_keyword(line: &str) -> Option<&str> {
    let mut words = line.split(' ');
    let keyword = words.next()?;
    let keyword_ok = keyword.starts_with(|c: char| c.is_ascii_alphanumeric())
        && keyword
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-');
    let params_ok = words.all(|p| !p.is_empty() && p.bytes().all(|b| (b'!'..=b'~').contains(&b)));
    (keyword_ok && params_ok).then_some(keyword)
}

/// The EHLO lines to advertise from the backend's extension lines
/// `backend`: those whose keyword is in `RELAYED` and, if `only` is set
/// (`submission.ehlo_extensions`), among its keywords; each keyword once,
/// with the backend's parameters, in the backend's order. A line that is not
/// an EHLO line is dropped.
pub fn advertised(backend: &[String], only: Option<&[String]>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in backend {
        let Some(keyword) = ehlo_keyword(line) else {
            continue;
        };
        let same = |k: &str| k.eq_ignore_ascii_case(keyword);
        let wanted = RELAYED.iter().any(|k| same(k))
            && only.is_none_or(|o| o.iter().filter_map(|l| ehlo_keyword(l)).any(same))
            && !out.iter().filter_map(|l| ehlo_keyword(l)).any(same);
        if wanted {
            out.push(line.clone());
        }
    }
    out
}

/// The backend's post-TLS EHLO extension lines from the last successful
/// probe, and the probe's single-flight lock.
///
/// Caching them means an unauthenticated client causes a backend connection
/// only on a cache miss, once per TTL, one probe at a time; after a failed
/// probe the next one waits `PROBE_RETRY`.
#[derive(Default)]
pub struct EhloCache {
    lines: RwLock<Option<(Instant, Arc<Vec<String>>)>>,
    /// Held while a probe runs; the time of the last failed probe.
    probe: tokio::sync::Mutex<Option<Instant>>,
}

/// How long after a failed probe the next one may start.
const PROBE_RETRY: Duration = Duration::from_secs(5);

impl EhloCache {
    /// The lines of the last successful probe if younger than `ttl`, or of
    /// any age (`ttl` `None`).
    fn cached(&self, ttl: Option<Duration>) -> Option<Arc<Vec<String>>> {
        let lines = self.lines.read().unwrap_or_else(|p| p.into_inner());
        lines
            .as_ref()
            .filter(|(at, _)| ttl.is_none_or(|ttl| at.elapsed() < ttl))
            .map(|(_, l)| l.clone())
    }
}

/// Connect to the backend as the proxy itself, read its post-TLS EHLO reply
/// and end with QUIT. Returns the extension lines (without the name line).
async fn probe(backend: &BackendConn, tuning: &Tuning, name: &str) -> Result<Vec<String>> {
    let (mut be, mut lines) = super::backend::connect_ehlo(backend, None, tuning, name).await?;
    // End the probe politely; it carries no credential.
    let _ = tokio::time::timeout(Duration::from_secs(2), async {
        be.write_all(b"QUIT\r\n").await?;
        be.flush().await
    })
    .await;
    if lines.is_empty() {
        return Err(anyhow!("backend EHLO reply without lines"));
    }
    lines.remove(0);
    Ok(lines)
}

/// The backend's post-TLS EHLO extension lines, from the cache (younger
/// than `ttl`) or a probe.
///
/// One probe at a time: a caller that waited for another's probe finds the
/// cache filled, or its failure. A failed probe counts in `backend_errors`;
/// for `PROBE_RETRY` after it, callers do not contact the backend.
pub(super) async fn backend_extensions(
    up: &Upstream,
    ttl: Duration,
    tuning: &Tuning,
    name: &str,
) -> Result<Arc<Vec<String>>> {
    if let Some(lines) = up.ehlo.cached(Some(ttl)) {
        return Ok(lines);
    }
    let mut last_failure = up.ehlo.probe.lock().await;
    if let Some(lines) = up.ehlo.cached(Some(ttl)) {
        return Ok(lines);
    }
    if let Some(at) = *last_failure {
        if at.elapsed() < PROBE_RETRY {
            return Err(anyhow!(
                "backend EHLO probe failed {}s ago",
                at.elapsed().as_secs()
            ));
        }
    }
    let lines = match probe(&up.conn, tuning, name).await {
        Ok(l) => Arc::new(l),
        Err(e) => {
            *last_failure = Some(Instant::now());
            crate::obs::metrics::record_backend_error(crate::obs::metrics::Proto::Smtp);
            return Err(e.context("backend EHLO probe"));
        }
    };
    *last_failure = None;
    *up.ehlo.lines.write().unwrap_or_else(|p| p.into_inner()) =
        Some((Instant::now(), lines.clone()));
    Ok(lines)
}

/// The extension lines of one backend for a client: `backend_extensions`,
/// or when no probe succeeds those of the last successful one, whatever
/// their age; when none has, none.
async fn lines_for(up: &Upstream, ttl: Duration, tuning: &Tuning, name: &str) -> Arc<Vec<String>> {
    match backend_extensions(up, ttl, tuning, name).await {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!(target: crate::obs::target::SUBMISSION, backend=%up.conn.id, error=%format!("{e:#}"), "submission backend EHLO extensions not available, advertising the last known ones");
            up.ehlo.cached(None).unwrap_or_default()
        }
    }
}

/// The extension lines to advertise to a client (`advertised`): those every
/// backend the client's credential can be routed to offers (`intersect`),
/// because a client does not send EHLO again after AUTH and uses the list
/// against whichever backend it ends up on. A backend without a list (no
/// probe has succeeded) offers none: fewer extensions are always safe, the
/// client then uses none of them (D-SMTP-3). The backends are asked
/// together, so one that is down delays the reply by one probe at most.
pub(super) async fn for_client(sub: &Submission, tuning: &Tuning, name: &str) -> Vec<String> {
    let mut probes = tokio::task::JoinSet::new();
    for (i, up) in sub.backends.iter().enumerate() {
        let (up, ttl, tuning, name) = (up.clone(), sub.caps_ttl, *tuning, name.to_owned());
        probes.spawn(async move { (i, lines_for(&up, ttl, &tuning, &name).await) });
    }
    let mut lists = vec![Arc::default(); sub.backends.len()];
    while let Some(done) = probes.join_next().await {
        if let Ok((i, lines)) = done {
            lists[i] = lines;
        }
    }
    advertised(&intersect(&lists), sub.ehlo_only.as_deref())
}

/// The EHLO lines every list has, by keyword, in the first list's order and
/// with its parameters, except SIZE (RFC 1870): the smallest limit, where no
/// parameter or 0 means no limit. No list: nothing.
pub fn intersect(lists: &[Arc<Vec<String>>]) -> Vec<String> {
    let Some((first, rest)) = lists.split_first() else {
        return Vec::new();
    };
    // One backend: its list as it is.
    if rest.is_empty() {
        return first.to_vec();
    }
    let find = |list: &Arc<Vec<String>>, keyword: &str| {
        list.iter()
            .find(|l| ehlo_keyword(l).is_some_and(|k| k.eq_ignore_ascii_case(keyword)))
            .cloned()
    };
    let mut out = Vec::new();
    for line in first.iter() {
        let Some(keyword) = ehlo_keyword(line) else {
            continue;
        };
        let Some(others) = rest
            .iter()
            .map(|l| find(l, keyword))
            .collect::<Option<Vec<_>>>()
        else {
            continue;
        };
        if keyword.eq_ignore_ascii_case("SIZE") {
            // RFC 1870 §4: no parameter, or 0, is no fixed limit.
            let limit = |l: &str| {
                l.split(' ')
                    .nth(1)
                    .and_then(|p| p.parse::<u64>().ok())
                    .filter(|n| *n > 0)
            };
            let smallest = std::iter::once(line.as_str())
                .chain(others.iter().map(String::as_str))
                .filter_map(limit)
                .min();
            out.push(match smallest {
                Some(n) => format!("{keyword} {n}"),
                None => keyword.to_string(),
            });
        } else {
            out.push(line.clone());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(l: &[&str]) -> Vec<String> {
        l.iter().map(|s| s.to_string()).collect()
    }

    /// Several backends: the keywords all have, in the first's order with
    /// its parameters, SIZE the smallest limit (none or 0: no limit); one
    /// backend: its list as it is; one without a list: nothing.
    #[test]
    fn extensions_of_several_backends() {
        let postfix = Arc::new(lines(&[
            "PIPELINING",
            "SIZE 10240000",
            "DSN",
            "CHUNKING",
            "8BITMIME",
        ]));
        let other = Arc::new(lines(&["8BITMIME", "size 0", "PIPELINING", "CHUNKING"]));
        let small = Arc::new(lines(&["SIZE 1000", "PIPELINING", "8BITMIME", "CHUNKING"]));
        assert_eq!(
            intersect(&[postfix.clone(), other.clone()]),
            lines(&["PIPELINING", "SIZE 10240000", "CHUNKING", "8BITMIME"])
        );
        assert_eq!(
            intersect(&[postfix.clone(), other.clone(), small]),
            lines(&["PIPELINING", "SIZE 1000", "CHUNKING", "8BITMIME"])
        );
        let unlimited = Arc::new(lines(&["SIZE", "PIPELINING"]));
        assert_eq!(
            intersect(&[unlimited, other]),
            lines(&["SIZE", "PIPELINING"])
        );
        assert_eq!(intersect(std::slice::from_ref(&postfix)), *postfix);
        assert!(intersect(&[postfix, Arc::default()]).is_empty());
    }

    /// Postfix's default list after TLS for an authorised proxy: only the
    /// relayed extensions pass, with the backend's parameters and order.
    #[test]
    fn only_relayed_extensions_pass() {
        let postfix = lines(&[
            "PIPELINING",
            "SIZE 10240000",
            "VRFY",
            "ETRN",
            "AUTH PLAIN LOGIN",
            "AUTH=PLAIN LOGIN",
            "ENHANCEDSTATUSCODES",
            "8BITMIME",
            "DSN",
            "SMTPUTF8",
            "CHUNKING",
            "XCLIENT NAME ADDR PROTO HELO",
            "XFORWARD NAME ADDR PROTO HELO",
            "STARTTLS",
            "BINARYMIME",
        ]);
        assert_eq!(
            advertised(&postfix, None),
            lines(&[
                "PIPELINING",
                "SIZE 10240000",
                "ENHANCEDSTATUSCODES",
                "8BITMIME",
                "DSN",
                "SMTPUTF8",
                "CHUNKING"
            ])
        );
    }

    /// `submission.ehlo_extensions` narrows the list by keyword; its
    /// parameters do not replace the backend's; what the backend does not
    /// offer is never advertised.
    #[test]
    fn configured_list_narrows() {
        let be = lines(&["size 5000", "PIPELINING", "DSN"]);
        let only = lines(&["SIZE 1", "PIPELINING", "CHUNKING"]);
        assert_eq!(
            advertised(&be, Some(&only)),
            lines(&["size 5000", "PIPELINING"])
        );
        assert!(advertised(&be, Some(&[])).is_empty());
    }

    /// Malformed and repeated lines from the backend are dropped.
    #[test]
    fn malformed_and_repeated_lines_are_dropped() {
        let be = lines(&[
            "PIPELINING",
            "pipelining",
            "SIZE  1",
            "-DSN",
            "8BITMIME\u{7f}",
            "",
            "SMTPUTF8 x\u{e9}",
            "DSN",
        ]);
        assert_eq!(advertised(&be, None), lines(&["PIPELINING", "DSN"]));
    }

    #[test]
    fn ehlo_keyword_syntax() {
        assert_eq!(ehlo_keyword("SIZE 10240000"), Some("SIZE"));
        assert_eq!(ehlo_keyword("X-FOO a=b"), Some("X-FOO"));
        for bad in ["", " SIZE", "-X", "SIZE ", "SIZE  1", "A_B", "SIZE \t"] {
            assert_eq!(ehlo_keyword(bad), None, "{bad:?}");
        }
    }
}
