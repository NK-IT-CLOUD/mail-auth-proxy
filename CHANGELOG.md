# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.0] - 2026-10-01

### Added
- Log lines when a backend address changes state: `WARN backend address down` (with the
  stage and error of the failure that took it down) and `INFO backend address up`, once
  per change. At startup, `legacy account check of a backend` names each backend with an
  `account_check` of its own.
- Backend pools: `addresses` (up to 16) instead of `address`, with `strategy = "failover"`
  (default: the first address that is up), `"hash"` (a rendezvous hash of the identity or
  login keeps a user on one address) or `"round_robin"`. A login moves to the next address
  only while no credential has been sent (connect, PROXY header, TLS, greeting, STARTTLS,
  EHLO, capabilities; at most 3 addresses); a temporary failure after the credential is an
  outage of that login, never retried elsewhere. Outages stay outages: retry-later, no
  `authresult` line. A move to the next address logs
  `WARN … backend address failed; trying the next` with `backend=` and `address=`.
- Health per address: 3 failures in a row mark it down, 2 successes up again, from the
  logins and probes and, with `health_check_secs`, from active checks (the dialog up to the
  greeting, no credential). Down addresses come last and take one login or check at a time.
  Health and counters are kept across a reload.
- Metrics `mail_auth_proxy_backend_up{backend,address}`,
  `mail_auth_proxy_backend_address_errors_total{backend,address,stage}`,
  `mail_auth_proxy_backend_failovers_total{backend}` and
  `mail_auth_proxy_backend_sessions_total{proto,backend}`; label values come from the
  configuration only.
- The account check per backend: `account_check = "none" | "doveadm"` with the backend's
  own `doveadm_url`, `doveadm_key_file` and `doveadm_ca_file`. A password routed to the
  backend is checked that way; a backend without its own uses `[legacy]`'s. A protocol with
  several backends where one inherits `legacy.account_check = "doveadm"` gives a warning.
  `--check-config` and a reload read each backend's doveadm key and CA file.

## [0.4.0] - 2026-09-29

### Added
- A profile per backend (`imap.backend`, `submission.backend`, `sieve.backend`), every key
  reloadable:
  - `tls = "starttls" | "implicit"`: how the proxy secures its connection to the backend.
    IMAP can now use STARTTLS (RFC 9051 §6.2.1: the capabilities are asked anew over
    TLS), submission and ManageSieve implicit TLS (RFC 8314). The EHLO and capability
    probes take the same way. Defaults as before: IMAP implicit, the others STARTTLS.
  - `auth_forward = "xoauth2" | "oauthbearer"`: the mechanism a validated token is
    forwarded with, whichever the client used. OAUTHBEARER (RFC 7628 §3.1) carries the
    verified identity as GS2 authzid and the backend's name and port. A failure's error
    result is answered with `%x01` (§3.2.3); a `status` of `invalid_request` is an outage,
    not a failed login. Default `xoauth2`, as before.
  - `client_ip = "proxy_v2" | "xclient" | "none"`: how the backend learns the client
    address. The submission backend can now take a PROXY v2 header (with a `LOCAL` header
    on the EHLO probe); `xclient` is refused on the other backends. A backend with `none`,
    set or by default, gives a configuration warning: it sees every client as the proxy.
- `submission.implicit_tls_listen`: a second submission listener with implicit TLS (port
  465, RFC 8314 §3.3), next to STARTTLS on `submission.listen`, with the same dialog,
  gate and backend. Adding, moving or removing it needs a restart.
- The `authresult` line gets a last field `listener` (`imap`, `submission`,
  `submissions`, `sieve`), and `mail_auth_proxy_listener_connections_total{listener}` and
  `mail_auth_proxy_listener_auth_attempts_total{listener,result}` split connections and
  auth attempts by listener. Existing fields, families and labels are unchanged.
- Example configurations `examples/config.dovecot-postfix.toml` and
  `examples/config.stalwart.toml` (the latter untested, from the Stalwart documentation).
- ALPACA hardening for SMTP (RFC 9325 §3.8, RFC 7301 §3.2): on both submission
  listeners a client that offers an ALPN ID of another protocol from the IANA registry
  (`http/1.1`, `h2`, `imap`, …; GREASE values excepted) is refused before the ServerHello
  with the fatal alert `no_application_protocol` (120); the session-end line says
  `TLS ALPN "<id>" names another protocol`. Without ALPN, or with unregistered values,
  nothing changes and no protocol is selected.
- Fuzz target `backend_auth`: the backend's OAUTHBEARER error result, the ManageSieve
  challenge string, the OAUTHBEARER build/parse roundtrip.
- Named backends and routes: one endpoint in front of several mail systems.
  `[backends.<name>]` holds a backend profile; a protocol section names it
  (`backend = "<name>"`) or `[[routes]]` choose it per credential. A route takes the
  domains of the validated identity (OAuth) or of the login (password), optionally
  narrowed by the token's `issuers` and `audiences` and the client's `sni`; the first
  matching route in file order wins, `domains = ["*"]` takes the rest. The SNI never
  selects a backend on its own. A credential no route takes is refused as
  `unknown_domain` without backend contact (a password with the wrong-password reply and
  delay), with a `WARN … no route for the login's domain` line and
  `mail_auth_proxy_route_misses_total{proto}`. Routes and backends are reloadable; a
  backend that stays keeps its capability cache and refusal timing. The inline
  `backend = { … }` keeps its meaning.
- The `authresult` line gets a last field `backend`: the name of the backend the
  credential was sent to (the section name for an inline backend), empty when none was.
  Earlier fields are unchanged.
- With several backends behind a protocol, the SMTP EHLO reply after TLS lists only the
  extensions every submission backend offers, with the smallest `SIZE`, and the
  ManageSieve capabilities before AUTHENTICATE are those all its backends have (`SIEVE`
  and `NOTIFY` narrowed, `MAXREDIRECTS` the smallest). The backends are probed together.

### Changed
- The refusal timing of the legacy gate learns the rejection latencies per backend
  instead of per protocol. A refusal by the account check or the throttle waits like a
  wrong password at the backend the login goes to; a refusal before it (size, rule,
  domain, no route) waits for the slowest backend of the protocol. With one backend per protocol
  the timing is the same as before; the change keeps refusals and wrong passwords alike
  once a protocol has several backends.
- The `submission auth ok` and `sieve auth ok` log lines, and the IMAP lines `oauth
  validated; proxying to backend` and `password auth; forwarding to backend`, name the
  issuer of the token (`issuer=`, empty for a password).
- The startup lines `imap listener up` and the others name every backend of the protocol
  (`backends=[<name>=<address>, …]` instead of `backend=<address>`); the IMAP login lines
  carry `backend=`.
- `backend.proxy_protocol` and `submission.xclient` are short forms of `client_ip`;
  `--print-config` shows `client_ip`. `submission.backend.proxy_protocol = true` is now
  accepted (it was an error); combining a short form with `client_ip`, or both short
  forms, is an error.
- The ManageSieve backend login answers an error challenge to a forwarded token (a
  string instead of a verdict line) and reads the verdict after it; before, the challenge
  line was taken as a rejection and the backend connection dropped.
- The log line of a submission backend that advertises XCLIENT to a proxy not set to use
  it names `submission.backend.client_ip` instead of `submission.xclient`.

### Fixed
- The usage text (`-h`, `--help`, an unknown option) lists `-h` and `--help`.

## [0.3.0] - 2026-09-29

### Added
- `SIGHUP` (`systemctl reload`) reloads the configuration file without closing any
  connection. The file passes the checks of `--check-config` (warnings logged) and is
  taken over as a whole: legacy rules, `[legacy]`, users and domains files, issuers
  (a new issuer's JWKS is fetched by the reload), `[limits]`, `[auth_ratelimit]`,
  `[timeouts]`, `[session]`, `[scope]`, `server.hostname`, the certificates in `[tls]`
  and `[[tls.certificates]]`, the backends and the submission and sieve settings.
  Connections accepted afterwards use the new configuration; open ones keep the one they
  were accepted with until they end. Rate-limit counts and blocks, the legacy throttle,
  the backends' cached capabilities and the keys of issuers that stay are carried over.
  A change of a listener address, a listener added or removed, or of the metrics
  endpoint needs a restart: such a file, and one that is invalid, is refused as a whole
  with one `ERROR reload: configuration not loaded …` line, and the configuration in use
  stays. Package upgrades still restart the service (a new binary).
- `mail_auth_proxy_config_reload_total{result="ok|error"}` and
  `mail_auth_proxy_config_last_reload_success_timestamp_seconds` (set at startup and by
  each successful reload).
- IMAP `LOGIN` takes its user name and password as literals (RFC 9051 §6.2.3, §9): a
  synchronising `{n}` after a `+ ` continuation, a non-synchronising `{n+}` at once, up
  to 16384 octets each. A password a client sends as a literal (for example one with
  8-bit characters) was refused with `BAD`. Where the connection offers no LOGIN, a
  synchronising literal is refused with `NO` before the continuation.
- XCLIENT to the submission backend carries the client's post-TLS EHLO or HELO name
  (`HELO=`), `PROTO=ESMTP` or `SMTP` and the client's source port (`PORT=`), each where
  the backend lists it, so its `Received:` header names the client's greeting instead
  of the proxy's (RFC 5321 §4.4). `smtpd_helo_restrictions` on the submission service
  now apply to the client's name.
- `oauth.issuers[].identity_domains`: the domains an issuer may log in to. A token whose
  identity is not an address in one of them is a `bad_token`. With more than one issuer,
  each issuer without it gives a configuration warning: every issuer could otherwise log
  in to every other issuer's mailboxes (OIDC Core §5.7).
- ALPN on the IMAP and ManageSieve listeners (`imap`, `managesieve`, RFC 7301): a client
  that offers ALPN without the listener's identifier is refused in the TLS handshake, so
  a TLS session meant for another service cannot be redirected to them (RFC 9325 §3.8,
  ALPACA). Clients without ALPN are unaffected; SMTP has no identifier and ignores it.
- Certificates by SNI (RFC 6066 §3): `[[tls.certificates]]` (`cert`, `key`) next to the
  `[tls]` default. A client gets the certificate that carries the name it asks for, an
  exact subjectAltName DNS name first, then a wildcard for one leftmost label (RFC 9525
  §6.3); a client without SNI gets `tls.cert`. `SIGHUP` reloads each certificate on its
  own; `--check-config` loads every pair and warns about a `legacy.rules[].sni` name no
  certificate carries. The `[tls] cert`/`key` form is unchanged.

### Changed
- `SIGHUP` re-reads the configuration file as well as the certificates and the JWKS.
  After a refused reload each certificate is still re-read on its own as before, so a
  renewal works while the configuration file is broken. The series of
  `mail_auth_proxy_jwks_*` and `mail_auth_proxy_tls_cert_expiry_timestamp_seconds`
  follow the issuers and certificate files of the configuration in use.
- A source added to `auth_ratelimit.exempt_networks` (or covered by `exempt_internal`)
  is no longer blocked, also when its block started before.
- A client that asks (SNI) for a name that no configured certificate carries is refused
  in the TLS handshake with the fatal alert `unrecognized_name` (RFC 9325 §3.7); it got
  the one certificate before. The accepted names are the subjectAltName DNS names of the
  certificates. Clients without SNI are unaffected.
- `mail_auth_proxy_tls_cert_expiry_timestamp_seconds` has the label `cert` (the
  certificate file), one series per certificate. With one certificate there is still one
  series, now labelled; a query or an exact series match on the unlabelled series must
  be adjusted, and with several certificates an alert takes the earliest (`min`).
- The EHLO reply after STARTTLS lists the submission backend's own extensions instead of
  a static list (RFC 5321 §4.2.4), as far as the proxy handles each one: PIPELINING,
  SIZE (with the backend's limit, advertised now), 8BITMIME, SMTPUTF8, DSN,
  ENHANCEDSTATUSCODES and CHUNKING; never XCLIENT, XFORWARD, VRFY, ETRN or unknown
  ones. The proxy reads them with a probe connection of its own, at startup and then at
  most once per `submission.capability_cache_secs` (new, default 600), one at a time;
  failed probes count in `backend_errors_total{proto="smtp"}`, and the last list stays
  in use. `submission.ehlo_extensions` is now optional and narrows the list by keyword:
  existing lists keep working, their parameters are ignored and keywords the proxy
  never passes on give a warning.
- `BDAT` before AUTH is answered with `530`, then `421` and the close: its chunk was
  read as commands (RFC 3030 §2).
- A connection takes up to `limits.max_auth_attempts` authentication attempts (new,
  default 3, 1-10) instead of one (RFC 9051 §6.2.2, RFC 4954 §4, RFC 5804 §2.1), so
  clients that fall back from one mechanism to another on the same connection (Python
  `smtplib` from PLAIN to LOGIN, Thunderbird) or retry with a refreshed token no longer
  lose it. Each attempt gets its own `authresult` line (format unchanged), counts for
  the rate limit and passes the legacy gate and the refusal timing like one on a new
  connection; the pre-auth budget and `max_preauth_commands` span all of them. A source
  the rate limit blocks while the connection is open is closed at its next credential,
  before it is judged. After an outage, the last attempt, an unknown command or a
  malformed one, the connection closes as before. Set 1 for the old behaviour.
- The ManageSieve backend's capabilities are probed once at startup, so the first
  greetings no longer wait for a probe. A failure there is logged and counted in
  `mail_auth_proxy_backend_errors_total{proto="sieve"}`; the start goes on.
- IMAP advertises `IMAP4rev1` without `IMAP4rev2` before login. The proxy does not know
  whether the backend speaks IMAP4rev2; after login the backend's own list is relayed as
  before, with `IMAP4rev2` where the backend offers it. Dovecot enables IMAP4rev2 only
  with `imap4rev2_enable`.

### Fixed
- Client lines are read without arming the idle timer for every byte that has already
  arrived. A long line (a 10 KB password) took several times longer to read than to
  receive, and under CPU load its refusal came measurably later than that of a short
  wrong password.
- SMTP replies before authentication: before TLS every command other than NOOP, EHLO,
  STARTTLS and QUIT gets `530 5.7.0` (RFC 3207 §4; HELO and RSET got `250`), STARTTLS
  with parameters `501 5.5.4`; after TLS and before AUTH `530 5.7.0` for every command
  other than AUTH, EHLO, HELO, NOOP, RSET and QUIT (RFC 4954 §6) and `503 5.5.1` for
  STARTTLS; an unrecognised command `500 5.5.1` instead of `502` (RFC 5321 §4.2.4);
  `250 2.0.0 OK` with an enhanced status code for NOOP and RSET (RFC 2034 §4).
- A JWK whose `key_ops` does not include `verify` is skipped like one with a `use` other
  than `sig` (RFC 7517 §4.3).
- The PROXY v2 header carries IPv4-mapped IPv6 addresses (a dual-stack listener) as
  TCP over IPv4, so the backend logs `192.0.2.7`, not `::ffff:192.0.2.7`.
- ManageSieve answers the pre-TLS command limit with `BYE` instead of `NO` before it
  closes the connection (RFC 5804 §1.2), as after TLS.
- A client and local address of different families, which cannot be put in one PROXY
  header, fail the backend connection as an outage. The connection went ahead without
  the header, which the backend refuses or logs with the proxy's address.
- A TLS session the proxy ends before the relay (a refused credential, an outage, a
  pre-authentication timeout, LOGOUT or QUIT) ends with a TLS close_notify (RFC 8314
  §3.4). The connection was dropped without one, which clients report as a truncated
  session.

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

[Unreleased]: https://github.com/NK-IT-CLOUD/mail-auth-proxy/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/NK-IT-CLOUD/mail-auth-proxy/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/NK-IT-CLOUD/mail-auth-proxy/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/NK-IT-CLOUD/mail-auth-proxy/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/NK-IT-CLOUD/mail-auth-proxy/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/NK-IT-CLOUD/mail-auth-proxy/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/NK-IT-CLOUD/mail-auth-proxy/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/NK-IT-CLOUD/mail-auth-proxy/releases/tag/v0.1.0
