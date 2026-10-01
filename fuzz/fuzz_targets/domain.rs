//! The canonical form of domain names (`crate::domain`): what any input
//! becomes, or that it is refused, without a panic.
#![no_main]

use libfuzzer_sys::fuzz_target;
use mail_auth_proxy::fuzz_api::*;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(c) = domain_canonical(text) {
        // ASCII letters, digits, hyphens and dots; lower case; no trailing
        // dot; within the DNS length.
        assert!(!c.is_empty() && c.len() <= 253, "{c:?}");
        assert!(c
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.'));
        assert!(!c.ends_with('.') && !c.starts_with('.'), "{c:?}");
        // A fixed point: the canonical form is its own canonical form.
        assert_eq!(domain_canonical(&c).as_deref(), Ok(c.as_str()));
    }
    // Every login has a key, without a panic.
    let _ = domain_account_key(text);
});
