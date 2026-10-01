//! The canonical form of a domain name, the one form every comparison of
//! domains uses: the configuration's lists, the list files, the routes, the
//! issuers' `identity_domains`, the domain of a login or token identity, and
//! TLS server names against configured names.
//!
//! UTS #46 ToASCII (IDNA, RFC 5890/5891) turns U-labels into A-labels
//! (Punycode) and maps case, so `Exämple.ORG` and `xn--exmple-cua.org` are one
//! domain; one trailing dot (the DNS root) is dropped. Flags:
//!
//! - Nontransitional processing (the only mode of the `idna` crate, as in
//!   current browsers): `ß`, `ς`, ZWJ and ZWNJ stay distinct, so `faß.de` and
//!   `fass.de`, two registrable domains, never become one.
//! - UseSTD3ASCIIRules (`AsciiDenyList::STD3`): letters, digits and hyphens
//!   only, the syntax of an SMTP domain (RFC 5321 §4.1.2); no underscore.
//! - CheckHyphens for the first and last position only: RFC 5321 forbids a
//!   hyphen there; `--` in the third and fourth position occurs in real names
//!   and is allowed.
//! - VerifyDNSLength: labels of 1-63 octets, at most 253 in all, no empty
//!   label.
//!
//! Only the domain is canonical. The local part of a login is compared as
//! written, and the login the backend gets stays byte for byte what the client
//! sent: what an address means is the mail server's business.

use idna::uts46::{AsciiDenyList, DnsLength, Hyphens, Uts46};

/// The canonical form of `name`, or why it is not a domain name.
pub fn canonical(name: &str) -> Result<String, String> {
    let bare = name.strip_suffix('.').unwrap_or(name);
    if bare.is_empty() {
        return Err(format!("{name:?} is not a domain name"));
    }
    Uts46::new()
        .to_ascii(
            bare.as_bytes(),
            AsciiDenyList::STD3,
            Hyphens::CheckFirstLast,
            DnsLength::Verify,
        )
        .map(|d| d.into_owned())
        .map_err(|_| format!("{name:?} is not a valid domain name (IDNA, UTS #46)"))
}

/// The canonical domain of a login or identity (after its last `@`), if it
/// has a valid one.
pub fn of_login(login: &str) -> Option<String> {
    let (_, domain) = login.rsplit_once('@')?;
    canonical(domain).ok()
}

/// One key per account for counting and placement: the local part in ASCII
/// lower case and the canonical domain, so the spellings of one address
/// (`Bob@Exämple.org`, `bob@xn--exmple-cua.org.`) share it. A login without a
/// valid domain is its lower-case self.
pub fn account_key(login: &str) -> String {
    match login.rsplit_once('@') {
        Some((local, domain)) => match canonical(domain) {
            Ok(d) => format!("{}@{d}", local.to_ascii_lowercase()),
            Err(_) => login.to_ascii_lowercase(),
        },
        None => login.to_ascii_lowercase(),
    }
}

/// Whether two names are the same domain; a name that is not one matches
/// nothing.
pub fn same(a: &str, b: &str) -> bool {
    matches!((canonical(a), canonical(b)), (Ok(a), Ok(b)) if a == b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_forms() {
        for (input, want) in [
            ("example.org", "example.org"),
            ("Example.ORG", "example.org"),
            ("example.org.", "example.org"),
            ("Exämple.ORG.", "xn--exmple-cua.org"),
            ("xn--exmple-cua.org", "xn--exmple-cua.org"),
            ("XN--EXMPLE-CUA.ORG", "xn--exmple-cua.org"),
            ("bücher.example", "xn--bcher-kva.example"),
            // Fullwidth letters are compatibility variants of ASCII: the
            // same domain (UTS #46 mapping).
            ("ｅｘａｍｐｌｅ.org", "example.org"),
            // Real names with -- in the third and fourth position.
            ("r3---sn-abc.example", "r3---sn-abc.example"),
            ("localhost", "localhost"),
        ] {
            assert_eq!(canonical(input).as_deref(), Ok(want), "{input}");
        }
    }

    /// Nontransitional: two registrable domains stay two.
    #[test]
    fn distinct_domains_stay_distinct() {
        assert_eq!(canonical("faß.de").unwrap(), "xn--fa-hia.de");
        assert_eq!(canonical("fass.de").unwrap(), "fass.de");
        // A Cyrillic а is not a Latin a.
        assert_ne!(canonical("exаmple.org").unwrap(), "example.org");
    }

    #[test]
    fn invalid_names() {
        let long_label = format!("{}.org", "a".repeat(64));
        let long_name = format!("{}org", "abcdefghi.".repeat(26));
        assert!(long_name.len() > 253);
        for bad in [
            "",
            ".",
            "example..org",
            "example.org..",
            "-example.org",
            "example-.org",
            "exa_mple.org",
            "exa mple.org",
            "user@example.org",
            "*.example.org",
            "xn--a.org",
            long_label.as_str(),
            long_name.as_str(),
        ] {
            assert!(canonical(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn logins_and_keys() {
        assert_eq!(
            of_login("MAIL@Exämple.ORG.").as_deref(),
            Some("xn--exmple-cua.org")
        );
        assert_eq!(of_login("mail"), None);
        assert_eq!(of_login("mail@"), None);
        assert_eq!(of_login("mail@exa_mple.org"), None);
        assert_eq!(account_key("Bob@Exämple.org"), "bob@xn--exmple-cua.org");
        assert_eq!(
            account_key("bob@xn--exmple-cua.org."),
            "bob@xn--exmple-cua.org"
        );
        assert_eq!(account_key("Bob"), "bob");
        assert!(same("Exämple.org.", "xn--exmple-cua.org"));
        assert!(!same("example.org", "exa_mple.org"));
    }
}
