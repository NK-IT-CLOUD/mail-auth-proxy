# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.1] - 2026-09-29

### Added
- `limits.ipv6_source_prefix` (default 64, 32-64): the prefix length by which IPv6
  sources are grouped for `max_preauth_per_ip` and the auth rate limit; 48 treats a
  whole site as one source.
- Metric `mail_auth_proxy_jwks_keys_skipped_total` by `issuer`: JWKS keys skipped because
  a member was missing or undecodable, counted on every fetch. Such a key was visible
  only as a journal warning.

### Changed
- A `server.hostname` that is a single label, the default `mail-auth-proxy` included,
  gives a configuration warning: the backend EHLO takes a fully-qualified host name
  (RFC 5321 §4.1.4).
- `oauth.issuers[].client_claim` defaults to `client_id` for `token_type = "rfc9068"`
  (RFC 9068 §2.2); `keycloak` and `any` keep `azp`. An RFC 9068 issuer with
  `allowed_clients` that relied on `azp` must now set `client_claim = "azp"`.
- Relative file paths in the configuration (`tls.cert`, `tls.key`, `ca_file`,
  `domains_file`, `doveadm_key_file`, `doveadm_ca_file`, `users_file`) are a validation
  error: they resolved against the working directory, so `--check-config` in a shell
  could pass on files the service never reads. Use absolute paths.
- The HELP text of `mail_auth_proxy_ratelimit_active_blocks` names the update interval:
  every 10 s and when a block starts.

### Fixed
- A token whose JWS header has a `crit` parameter is refused: the proxy understands no
  JWS extension (RFC 7515 §4.1.11).
- A token whose `iss` claim is an array is refused; `iss` is a string (RFC 7519 §4.1.1).
- A JWK with missing or undecodable members is skipped with a warning instead of
  discarding the issuer's whole JWKS (RFC 7517 §5).
- The JWKS of all issuers are fetched concurrently at startup, on refresh and on an
  unknown `kid`: with several unreachable IdPs a refresh, and every token waiting on
  it, took one 10-second timeout per issuer.
- The password and rate-limit fingerprint keys are generated at startup: without a
  system RNG the proxy now refuses to start instead of panicking in every session that
  logs a refused login.
- A JWKS response is used only with a 2xx status; a redirect carrying a JWKS body was
  accepted.
- `mail_auth_proxy_tls_cert_expiry_timestamp_seconds` is 0 for a certificate whose
  `notAfter` has an impossible hour, minute, second or day (such as 31 April) instead of
  a date rolled over into the next day or month.
- A full legacy throttle table drops the oldest 1024 accounts at once instead of one per
  new failing account, so the table scan under the lock is no longer paid on every new
  account; a failure of an account already tracked evicts nothing.
- ManageSieve: a backend `BYE` in answer to `AUTHENTICATE` (shutdown, connection limit)
  is an outage, not a `backend_reject`; it no longer counts in the rate limit or for
  CrowdSec (RFC 5804 §1.3).
- A backend that offers `UNAUTHENTICATE` (RFC 8437, RFC 5804 §2.14.1) gets no login: an
  outage with a journal line that names it, since a client could otherwise leave its
  login and try passwords past the password gate. ManageSieve no longer relays the
  capability.
- Token validation (including a JWKS refresh for an unknown `kid`), the legacy account
  check and the backend login now run inside the pre-auth budget (`preauth_secs`); a
  slow IdP or a hanging backend no longer holds pre-auth slots beyond it. Running out is
  an outage (retry later), not a failed login.
- A password mechanism the endpoint does not offer, chosen without an initial response,
  is refused at once (IMAP `NO`, SMTP `504 5.5.4`, ManageSieve `NO`) instead of prompting
  for a password that would never be used. It is logged as `blocked_endpoint` without
  `pwfp` (and with the login only if the client sent it as SASL LOGIN initial response).
- ManageSieve `AUTHENTICATE` without initial response reads the client's answer as a
  string (quoted, literal or bare) and takes `"*"` as a cancel (RFC 5804 §2.1); a
  quoted response was passed to the base64 decoder with its quotes, so such logins
  failed. Client literals must be `{n+}` with nothing after the header or after the
  octets (RFC 5804 §4); `{n}`, `{n++}` and trailing text are refused.
- ManageSieve: the greeting lists the backend's `SIEVE` capability from the first
  connection after startup on (RFC 5804 §1.7); while the capability cache is cold the
  greeting waits for the probe. Probes run one at a time (clients that arrive together
  share one), a failed probe counts in `mail_auth_proxy_backend_errors_total{proto="sieve"}`
  and the next one waits 5 s.
- SASL parsing is strict where the RFCs are: a NUL in a PLAIN password (RFC 4616 §2), in
  a SASL LOGIN field or in the IMAP `LOGIN` arguments is refused; the OAUTHBEARER GS2
  header must be `n,` or `y,` with an optional `a=` authzid whose `=2C`/`=3D` are decoded
  (RFC 7628 §3.1, RFC 5801 §4), `p=` channel binding is refused; a XOAUTH2 `user=` or
  OAUTHBEARER authzid longer than 255 bytes or with control characters is refused. All
  of these end as `protocol`, before the gate and the backend.
- SMTP: after a refused `AUTH` (the proxy takes one per connection) the close is
  announced with `421 4.7.0 <hostname> closing connection` after the refusal (RFC 5321
  §3.8).
- ManageSieve: `CAPABILITY` and `NOOP` work before STARTTLS too (RFC 5804 §2), and
  `NOOP` with an argument answers with the `TAG` response code (§2.13).
- ManageSieve backend login: a SASL response longer than 1024 octets (any sizable
  token) is sent as a literal `{n+}` instead of an over-long quoted string (RFC 5804
  §4).
- IMAP backend login: the SASL initial response is only sent when the backend's
  greeting advertises `SASL-IR`; otherwise the response follows the backend's empty
  challenge (RFC 4959 §3).
- IMAP: the pre-auth capabilities list `ID`, which the proxy answers (RFC 2971 §3).
- IMAP and SMTP: an initial response `=` is the empty response (RFC 4959 §3, RFC 4954
  §4), not undecodable base64. A SASL response that decodes but holds no valid
  credential now gets `NO [AUTHENTICATIONFAILED]` / `535 5.7.8` instead of `BAD` /
  `501`, which stay for responses that are not base64 and for a cancel (RFC 9051
  §6.2.2, RFC 4954 §4).
- An OAuth response with an empty `auth` value (`auth=`, or `Bearer` without a token) is
  a discovery request (RFC 7628 §4.3): it gets the error result with `scope` and
  `openid-configuration` like a rejected token instead of a syntax error. It carries no
  credential, so its `authresult` line is `reason="protocol"` (with the mechanism and
  the SASL user), and it counts neither as a failed attempt nor in the rate limit.
- OAUTHBEARER: a `host` in the client response must match the TLS server name (SNI),
  ASCII case-insensitive (RFC 7628 §3.2); a mismatch is refused like any rejected token
  (`bad_token`). Without SNI, and for `port`, nothing is compared.
- `systemctl reload` failed on minimal systems without procps (/bin/kill); the packages
  now depend on it (procps for the deb, util-linux-core for the rpm).
- An upgrade with a locally changed `/etc/mail-auth-proxy/config.toml` stopped at dpkg's
  conffile question whenever the shipped example had changed, and unattended-upgrades
  skipped it. The config is no longer a conffile: the package ships the example as
  `/usr/share/mail-auth-proxy/config.example.toml`, creates `config.toml` from it on
  install where none exists and never changes an existing one. Upgrading from a release
  that shipped it as conffile keeps the file unchanged, without a question (rpm: no
  `.rpmnew`; a changed config is still kept as `.rpmsave` on removal).

### Security
- The packaged unit sets `LimitCORE=0`: the service writes no core dumps, which could
  hold tokens, passwords and the TLS key. Before, only the soft limit was 0 and the
  hard limit unlimited.

## [0.2.0] - 2026-09-29

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
- `[session]` section. `idle_limit_secs` closes a logged-in session after that long
  without a byte in either direction; `max_session_secs` closes it that long after the
  login, which bounds how long a session outlives a revoked token or a locked account.
  Both are off by default and warn below 30 minutes (RFC 9051 §5.4, RFC 5804 §1.2). The
  connection is closed without `BYE`/`421`, since the relay cannot tell where a
  response ends.
- Metric `mail_auth_proxy_sessions_ended_total{proto,reason}`: why logged-in sessions
  ended (`client_close`, `backend_close`, `idle_limit`, `max_session`, `error`).

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
- TCP keepalive is on for every client and backend connection (`session.keepalive_*`,
  default 600 s idle, 60 s interval, 5 probes). A peer that vanished without closing
  (a phone that left the network) now frees its `max_connections` slot after at most
  15 minutes of silence instead of holding it until the backend ends the session.

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

[Unreleased]: https://github.com/NK-IT-CLOUD/mail-auth-proxy/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/NK-IT-CLOUD/mail-auth-proxy/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/NK-IT-CLOUD/mail-auth-proxy/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/NK-IT-CLOUD/mail-auth-proxy/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/NK-IT-CLOUD/mail-auth-proxy/releases/tag/v0.1.0
