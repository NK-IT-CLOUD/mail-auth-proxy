# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `-t`, short form of `--check-config`.
- Metric `process_start_time_seconds`: start time of the process, so restarts show in
  Prometheus.
- Metric `mail_auth_proxy_backend_login_duration_seconds` (histogram by `proto`): how
  long successful backend logins take, from connect to the backend's OK.
- Metrics `mail_auth_proxy_jwks_last_success_timestamp_seconds` and
  `mail_auth_proxy_jwks_refresh_failures_total` by `issuer`: a JWKS that can no longer
  be fetched was only visible as a journal warning while the proxy kept the old keys.
- Metric `mail_auth_proxy_tls_cert_expiry_timestamp_seconds`: `notAfter` of the
  certificate the proxy serves, so an expiring certificate or a renewal without
  `SIGHUP` can be alerted on.
- Metric `mail_auth_proxy_legacy_throttle_evictions_total`: accounts the full throttle
  table dropped while their failure window was running.
- Issuer keys `openid_configuration_url` and `scope`: the IdP's discovery document and
  the scope a client needs, sent in the RFC 7628 error result for a rejected token so
  that clients without a preset IdP can find one. At most one issuer sets them.
- `[auth_ratelimit]`: a source address (IPv4 address, IPv6 /64) with too many refused
  credentials has its new connections closed at accept, before TLS, for a time that
  doubles with every further block. Keys `enabled`, `failures` (20), `window_secs` (600),
  `block_secs` (900), `max_block_secs` (86400), `exempt_internal` (false) and
  `exempt_networks` (loopback). A block logs one `ratelimit` line on the `authlog`
  target; metrics `mail_auth_proxy_ratelimit_blocks_total`, `…_bans_total`,
  `…_active_blocks` and `…_evictions_total`. See
  [architecture: failed-login rate limit](docs/architecture.md#failed-login-rate-limit).

### Changed
- A token that fails validation (`bad_token`) is no longer refused at once, also
  without the new keys. The client first gets the JSON error result as a SASL
  challenge (IMAP `+`, SMTP `334`, ManageSieve string; RFC 7628 §3.2.2) and must answer
  it with `%x01` (OAUTHBEARER) or an empty response (XOAUTH2), after which the usual
  failure follows (§3.2.3). An abort (`*`) or undecodable answer gets IMAP `BAD` or
  SMTP `501`. The result is `{"status":"invalid_token"}` plus the configured keys, the
  same for every rejected token. The round trip counts against the pre-auth budget;
  the `authresult` line is unchanged. Clients or scripts that expect the failure reply
  right after `AUTHENTICATE`/`AUTH` must answer the challenge first.
- Failed logins now block their source by default: after 20 distinct refused
  credentials within 10 minutes (tokens or passwords, any account) the address is
  closed at accept for 15 minutes, repeated blocks up to 24 hours. Only loopback is
  exempt. Add webmail servers, NAT gateways and other addresses through which many
  users log in to `auth_ratelimit.exempt_networks` (or set `exempt_internal = true`),
  or set `enabled = false` to keep the previous behaviour. Backend outages and
  connections without a credential do not count, and a rejected token counts once
  despite its error-result round trip; the `authresult` line is unchanged.
- `mail_auth_proxy_build_info` has a second label, `commit` (the value of
  `mail-auth-proxy --version`). Queries selecting on `version` keep working; recording
  rules or alerts that list the exact label set of the series need `commit` added.
- The metrics endpoint answers only `GET /metrics` with the exposition text; another
  path is answered 404, another method 405, a malformed request 400 and a request
  head over 4 KiB 431. Scrape configurations with another `metrics_path` must use
  `/metrics`. At most 4 scrapes are served at a time (more connections are closed
  at accept), and the 10 s deadline now covers the whole request head instead of a
  single read.
- Configurations that were accepted before and are now rejected:
  - `oauth.leeway_secs` above 300, `oauth.refresh_secs` above 86400 (a key removed
    from the JWKS stays trusted until the next refresh), or a `timeouts` value above
    3600 (larger values hold pre-authentication slots, and past 2^63 s the deadline
    overflows the clock);
  - `server.hostname` that is not an RFC 5321 host name: underscores, non-ASCII,
    empty labels, a trailing dot, a hyphen at either end of a label, labels over 63 or
    names over 253 characters, IP addresses and address literals;
  - `submission.ehlo_extensions` entries that are not an RFC 5321 `ehlo-line` (empty,
    leading, trailing or double spaces, a keyword with other characters than letters,
    digits and hyphens) or repeat a keyword;
  - listeners that take the same port on overlapping addresses: `[::]:993` with
    `0.0.0.0:993`, a wildcard with a concrete address of its family, and the metrics
    endpoint on a mail listener's port.
- `--check-config` reports an empty `users_file` or `domains_file` and a backend
  `address` without host once, without a follow-up file or certificate-name error.
- Every file path is checked the same way: an empty `tls.cert`, `tls.key`, backend
  `ca_file`, `legacy.doveadm_key_file` or `legacy.doveadm_ca_file` is now a validation
  error `<key> is empty`, reported once. Before, an empty backend `ca_file` or
  `doveadm_ca_file` passed validation and failed only as a file error at start, and the
  other three were reported twice (validation and file error); `tls.cert and tls.key are
  required` is now one message per key.

### Security
- `oauth.leeway_secs` had no upper bound, so a large value kept expired tokens valid.
  It is now limited to 300 s (RFC 7519 §4.1.4: "usually no more than a few minutes").
- `[password_gate]` with a public network in `internal_networks` accepts passwords of
  every user from that network (the rule it stands for has `public = true`), but only
  `0.0.0.0/0` gave a warning. Every public network now gives the same warning as a
  written rule with `public = true`.
- `submission.ehlo_extensions` entries with a leading space (`" AUTH"`) passed the
  check for `AUTH` and `STARTTLS`. Entries must now be EHLO lines (see Changed).
- Passwords, bearer tokens and the lines and SASL responses carrying them are
  overwritten in memory when dropped (`zeroize`), including the buffers a line outgrew
  while being read and a half-decoded base64 response. The credential is dropped right
  after the backend login instead of living until the session ends. Copies inside
  rustls, `jsonwebtoken`, the kernel and swap are not covered; see
  [architecture: credentials in memory](docs/architecture.md#credentials-in-memory).
- Base64 decoding errors of a SASL response no longer name the offending character:
  the text reached the journal and could show one character of the encoded
  credential.

## [0.1.1] - 2026-09-28

### Security
- Parallel password attempts for one account could all pass the legacy throttle
  before the first backend rejection was counted, so more than `failures` guesses fit
  into one window. Attempts for the same account now take turns (CWE-362).

## [0.1.0] - 2026-09-27

### Added
- Initial public release.

[Unreleased]: https://github.com/NK-IT-CLOUD/mail-auth-proxy/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/NK-IT-CLOUD/mail-auth-proxy/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/NK-IT-CLOUD/mail-auth-proxy/releases/tag/v0.1.0
