# Operations

Logging, metrics, signals and troubleshooting. Where this document and the code disagree, the code wins.

## Logging

Output goes to stderr through `tracing-subscriber` in fmt format, with ANSI colours turned off.

The level comes from `RUST_LOG`. It defaults to `info` when unset, which writes every `authresult` line. The shipped systemd unit sets `RUST_LOG=info` explicitly.

### The `authresult` line

One line per evaluated credential, target `authlog`. Its field names, order and quoting,
the log targets, and the metric names below are a public interface: they change only
in a release that says so in the changelog.

```
2026-09-26T21:29:56.642346Z  WARN authlog: authresult result="fail" proto="imap" scope="internal" mech=XOAUTH2 user=evil?FAKE?authresult?result??ok??user?root peer=127.0.0.1 reason="bad_token" pwfp="" rule="" listener="imap"
2026-09-26T21:28:26.004745Z  WARN authlog: authresult result="fail" proto="smtp" scope="internal" mech=PLAIN user=carol@example.test peer=127.0.0.1 reason="backend_reject" pwfp="f52419d665460b37" rule="internal" listener="submissions"
2026-09-26T21:31:02.118204Z  WARN authlog: authresult result="fail" proto="imap" scope="external" mech=PLAIN user=a@gone.test peer=198.51.100.7 reason="unknown_domain" pwfp="5d0f1c7a92b3e416" rule="partner" listener="imap"
2026-09-26T21:33:30.946119Z  WARN authlog: authresult result="fail" proto="imap" scope="external" mech=other user= peer=127.0.0.4 reason="protocol" pwfp="" rule="" listener="imap"
```

Successful outcomes are logged at `INFO` and failures at `WARN`. The field order is fixed; new fields are only appended at the end, so patterns anchored on the earlier fields keep matching. Quoting is mixed: string literals are Debug-quoted, while `mech`, `user` and `peer` are Display-formatted and unquoted.

| Field | Values / meaning |
|---|---|
| `result` | `"ok"` or `"fail"` |
| `proto` | `"imap"`, `"smtp"`, `"sieve"` |
| `scope` | `"internal"` if the source IP is in `scope.internal_networks` (regardless of SNI), else `"external"` |
| `mech` | the mechanism as the client spelled it (e.g. `xoauth2`), passed through `sanitize`. `LOGIN` covers both the IMAP LOGIN command and SASL LOGIN. `other` for `protocol` records. |
| `user` | `ok`: the validated identity (OAuth) or the client-supplied login (password). `bad_token`, `authzid_mismatch`: the client-supplied SASL user (XOAUTH2 `user=`, OAUTHBEARER `a=`, possibly empty for `bad_token`). `blocked_endpoint`, `unknown_domain`, `unknown_account`, `throttled`, `oversize`: the client's login. `backend_reject`: the email (OAuth) or the client's login. Empty for `protocol`. |
| `peer` | the client IP, without port; an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`, from a dual-stack listener) is logged as the IPv4 address |
| `reason` | `ok`; `bad_token` (JWT rejected locally); `authzid_mismatch` (valid token, but the client's XOAUTH2 `user=` / OAUTHBEARER `a=` names another identity; the backend is not contacted); `blocked_endpoint` (password with a mechanism the connection does not offer, or a user no legacy rule allows); `unknown_domain`, `unknown_account`, `throttled` ([legacy gate](architecture.md#legacy-gate)); `oversize` (a password over 1024 bytes, refused before the legacy gate); `backend_reject` (the backend rejected the credential: IMAP/ManageSieve `NO`, SMTP `510` to `599`; an unreachable backend or a reply without a verdict writes no record); `protocol` (the connection ended before a credential: EOF, timeout, unknown command, unsupported mech, SASL parse error, command limit). |
| `rule` | the legacy rule that decided a password attempt (`ok`, `backend_reject`, `unknown_domain`, `unknown_account`, `throttled`); `""` for OAuth, `protocol`, `oversize`, when no rule applies (`blocked_endpoint`), and for `unknown_account` of an invalid login (empty, over 255 bytes, or with control characters). The `[password_gate]` short form is the rule `password_gate`. |
| `listener` | the listener the client connected to: `"imap"`, `"submission"` (STARTTLS, `submission.listen`), `"submissions"` (implicit TLS, `submission.implicit_tls_listen`), `"sieve"`. The last field of the line |
| `pwfp` | 16 hex chars: the first 64 bits of HMAC-SHA256(password) under a random key generated per process. Set only for failed password credentials (`blocked_endpoint`, `unknown_domain`, `unknown_account`, `throttled`, `oversize`, `backend_reject`), otherwise `""`. It can be compared only within one process lifetime. |

`sanitize()` keeps `[A-Za-z0-9@._+-]`, turns every other character into `?`, and truncates to 64 characters.

When a `protocol` record is written:

- **IMAP:** for every pre-auth error after the TLS handshake. A TLS handshake failure, `LOGOUT`, and a disconnect right after the greeting (health check) write no record.
- **SMTP and Sieve:** only for failures after TLS. Failures before TLS and TLS failures write no record. A failed Sieve capability probe or SMTP EHLO probe writes no record.
- **Per attempt:** every authentication attempt that ends without a credential (an unsupported mechanism, a cancelled or undecodable response) writes one, also when the client tries again on the same connection. A client that closes the connection after a refused attempt writes none.

### Other log lines

- `mail_auth_proxy: session ended peer=<ip:port> error=<escaped text>`, with the prefix `submission session ended` or `sieve session ended` for the other protocols, when a session ends with an error. The error is the whole cause chain, e.g. `backend unavailable: backend temporarily unavailable: P1 NO [UNAVAILABLE] …`, `backend unavailable: Connection refused (os error 111)`, `read timed out after 30s`, `imap pre-auth: pre-auth budget of 60s used up`, `invalid peer certificate: UnknownIssuer`, `TLS server name mail.example.com is not a name of any configured certificate`, `TLS ALPN "http/1.1" names another protocol` (submission). Control characters are escaped, but printable client text can appear.
  - At `WARN` for outages and pre-auth failures.
  - At `DEBUG` when the credential was refused (blocked, denied, bad token, wrong authzid, backend rejection), because the `authresult` line already records it. The precise reason is only here, e.g. `token rejected: InvalidAudience`, `token rejected: unknown kid`, `email not verified`, `not an access token`, `malformed claims`, `ExpiredSignature`, `ImmatureSignature`, `MissingRequiredClaim("aud")`, `backend auth rejected: …`; see it with `RUST_LOG=info,mail_auth_proxy=debug`.
- `INFO`:
  - `oauth validated; proxying to backend peer=… user=<email> mech=… issuer=<issuer>` (IMAP)
  - `password auth; forwarding to backend peer=… user=<login> mech=… issuer=` (IMAP; `issuer` empty for a password)
  - `submission auth ok; splicing user=… mech=… issuer=…`
  - `sieve auth ok; splicing user=… mech=… issuer=…` (`issuer`: the configured issuer whose key verified the token, empty for a password)
  - `session closed by limit proto=… reason="idle_limit"|"max_session" secs=…` when a `[session]` limit ended a logged-in session
- Startup, at `INFO`:
  - `legacy password rule rule=<name> networks=[…] sni=… users=… users_file=… protocols=… mechanisms=…` per rule and `legacy password gate domain_gate=… account_check=… throttle=… failure_delay_ms=…`, or `password auth disabled: OAuth only`.
  - `auth rate limit failures=… window_secs=… block_secs=… max_block_secs=… exempt_internal=… exempt_networks=[…]`, or `auth rate limit disabled`.
  - `legacy list file reloaded` when a users or domains file changes; `ERROR … legacy list file unusable; it matches nothing until it is fixed` when it becomes missing or invalid, and `legacy list file usable again` when it is fixed.
  - `imap listener up`, `submission listener up`, `submission implicit-TLS listener up`, `sieve listener up` (with `listen=` and `backend=`)
  - `TLS server names names=[…]`: every name a client may ask for with SNI ([configuration.md](configuration.md#tls-server-names)).
  - After `SIGHUP`: `reload: configuration loaded; new connections use it, open ones keep theirs path=<file> changed=[<section>, …]` (the top-level sections that differ; after it the startup lines on TLS names, legacy rules and the rate limit again), or `ERROR reload: configuration not loaded; the one in use stays path=<file> error=…` with the reason on one line (a TOML error, `invalid configuration: <problem>; <problem>`, `changed <key>: needs a restart`, `JWKS unavailable for: <issuer>`). Then `reload: certificate loaded cert=<file>` per certificate (after a refused reload: `ERROR reload: certificate unusable; keeping the current one cert=<file> error=…` for one that fails), and `reload: JWKS refreshed` (or `reload: JWKS refresh already running`; `WARN reload: JWKS refresh failed; keeping previous keys` on failure)
  - `shutting down: listeners closed, waiting for open sessions drain_secs=10`, then `all sessions ended; exiting` or `WARN sessions still open after the drain time; closing them`
  - `metrics endpoint up`
- `WARN`:
  - `authlog: ratelimit action="block" proto="<proto>" scope="<internal|external>" peer=<ip> source=<cidr> failures=<n> block_secs=<n> strikes=<n>` when a source is blocked ([architecture.md](architecture.md#failed-login-rate-limit)): `proto`, `scope` and `peer` of the failure that reached the threshold, `source` the blocked address or IPv6 network of `limits.ipv6_source_prefix` (`198.51.100.7/32`, `2001:db8:1:2::/64`), `failures` the counted failures, `block_secs` the length of this block, `strikes` the number of blocks in a row (1 for the first). One line per block, on the `authlog` target like the `authresult` line, but not an `authresult` line: parsers anchored on `authresult result=` do not see it. The connections closed during the block are counted in `mail_auth_proxy_ratelimit_blocks_total` and logged only at `DEBUG`, so a blocked source cannot fill the journal.
  - `config: …` at startup, on a reload and with `--check-config`, one line per warning: a `server.hostname` that is not fully qualified; a `submission.ehlo_extensions` entry the proxy never advertises or with parameters; an issuer without `identity_domains` when there are several issuers; `token_type = "any"`; `require_email_verified` with an `identity_claim` other than `email`; an `openid_configuration_url` that is not the issuer followed by `/.well-known/openid-configuration`; an issuer `scope` with several scopes; a public network in `[password_gate]` (one line each); `[password_gate]` disabled but `sni` set; a legacy rule that accepts every user from public networks; a backend with `client_ip = "none"` (it sees only the proxy's address); `[legacy]` settings without any rule; `failure_delay_ms = 0`; `limits.max_auth_attempts` larger than `limits.max_preauth_commands`; `metrics.listen` not on loopback; a public network in `auth_ratelimit.exempt_networks`; `session.idle_limit_secs` or `session.max_session_secs` below 30 minutes; a default certificate without a DNS name; a `legacy.rules[].sni` name that no certificate carries.
  - `…: TCP keepalive not set` (client, with `peer=`) or `… backend: TCP keepalive not set` (with `backend=`): the socket option was refused; the connection continues without keepalive.
  - `fetching JWKS …`, `parsing JWKS …`, `JWKS has no usable signing keys`, `skipping unusable JWK` (a key with a missing or undecodable member, with `issuer=` and `kid=`), `JWKS refresh failed; keeping previous keys`, `JWKS refresh for unknown kid` (the refresh an unknown `kid` triggered failed)
  - `submission backend EHLO extensions not available at startup`, `sieve backend capabilities not available at startup` (the first probe of the backend failed; the start goes on), `submission backend EHLO extensions not available, advertising the last known ones` (a later probe failed)
  - `loading system CA certificates`
  - `metrics accept error`
  - `systemd notification failed`
- `ERROR`:
  - `metrics endpoint bind failed; metrics disabled`
  - `…: accept error` (the listener waits 100 ms and keeps accepting)
- `DEBUG`:
  - `…: connection limit reached, closing` for a connection closed at accept by a limit
  - `…: source blocked after failed logins, closing` for a connection closed at accept by the failed-login rate limit
  - `relay ended with an error` when the byte relay after login ends with an I/O error
  - `JWKS refreshed kids=… failed=…` after each periodic refresh

## Prometheus metrics

Metrics are off by default. They are on with `metrics.enabled = true` or when only `metrics.listen` is set. `metrics.listen` then serves a minimal HTTP/1.1 responder without authentication, so keep it on loopback or a management network (`--check-config` warns about any other address). Only `GET /metrics` gets the exposition text (`Content-Type: text/plain; version=0.0.4`); another path is answered 404, another method 405, a request line that is not HTTP/1.x 400, a request head over 4 KiB 431, each with `Connection: close`. At most 4 scrapes are served at a time, further connections are closed at accept; the request head and the response each have 10 s. The endpoint logs neither requests nor refusals. Every series is present from the start, so `rate()` and `increase()` work from the first scrape: counters and gauges at 0, the timestamps (`process_start_time_seconds`, the configuration load time, the JWKS success time, the certificate expiry) set during startup. No label carries a user, an address or other client input; `issuer` and `cert` come from the configuration in use: a reload that adds an issuer or certificate adds its series, one that removes it removes them.

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `mail_auth_proxy_build_info` | gauge | `version`, `commit` (12 hex digits, `unknown` for a plain `cargo build`) | always 1 |
| `process_start_time_seconds` | gauge | | start time of the process, Unix seconds |
| `mail_auth_proxy_config_reload_total` | counter | `result` (ok, error) | configuration reloads (`SIGHUP`): `ok` when the new configuration is in use, `error` when it was refused and the previous one stays ([signals](#signals-and-service-manager)). Alert on `increase(…{result="error"}[1h]) > 0`: the file on disk is not what runs. |
| `mail_auth_proxy_config_last_reload_success_timestamp_seconds` | gauge | | Unix time the configuration in use was loaded: at startup, then at each successful reload |
| `mail_auth_proxy_auth_attempts_total` | counter | `proto` (imap, smtp, sieve), `scope` (internal, external), `mechanism` (xoauth2, oauthbearer, plain, login, other), `result` (ok, fail) | a credential was evaluated. `fail` counts every refused credential, one per `authresult` line with reason `bad_token`, `authzid_mismatch`, `blocked_endpoint`, `unknown_domain`, `unknown_account`, `throttled`, `oversize` or `backend_reject`. Backend and account-check outages (no `authresult` line) and `protocol` (counted in `mail_auth_proxy_preauth_aborts_total`) are not counted. |
| `mail_auth_proxy_auth_refusals_total` | counter | `proto`, `reason` (`blocked_endpoint`, `bad_token`, `authzid_mismatch`, `backend_reject`, `unknown_domain`, `unknown_account`, `throttled`, `oversize`) | a refused credential, by the `reason` of its `authresult` line ([above](#the-authresult-line)). The sum over `reason` equals the `fail` side of `mail_auth_proxy_auth_attempts_total`. |
| `mail_auth_proxy_preauth_aborts_total` | counter | `proto`, `scope` | the connection ended before a credential was presented. Not counted: a clean `LOGOUT`/`QUIT`, an IMAP client that disconnects right after the greeting (a health check), Sieve capability-probe and SMTP EHLO-probe failures. |
| `mail_auth_proxy_token_validate_total` | counter | `result` (ok, fail) | local JWT validations |
| `mail_auth_proxy_connections_total` | counter | `proto` | connections admitted past the limits |
| `mail_auth_proxy_listener_connections_total` | counter | `listener` (imap, submission, submissions, sieve) | `connections_total` split by listener: `submission` is the STARTTLS listener, `submissions` the implicit-TLS one (`submission.implicit_tls_listen`); both are `proto="smtp"` in the other families |
| `mail_auth_proxy_listener_auth_attempts_total` | counter | `listener`, `result` (ok, fail) | `auth_attempts_total` split by listener; the sum over `listener` equals the sum over `proto`, `scope` and `mechanism` there |
| `mail_auth_proxy_connections_rejected_total` | counter | `proto` | connections closed at accept by a limit |
| `mail_auth_proxy_backend_errors_total` | counter | `proto` | backend or legacy account check (doveadm) unreachable or failing while a client waited for its verdict (outage, not a failed login); also a failed ManageSieve capability probe or SMTP EHLO probe |
| `mail_auth_proxy_legacy_list_errors_total` | counter | `list` (users_file, domains_file) | failed re-reads of a legacy list file; while it fails, the list matches nothing |
| `mail_auth_proxy_legacy_throttle_evictions_total` | counter | | accounts dropped from the full throttle table (65,536 accounts), oldest first and up to 1,024 at a time, while their failure window was still running; their count starts over. Rising means failed passwords for that many distinct accounts within one window, a spraying volume that dilutes the per-account throttle. |
| `mail_auth_proxy_ratelimit_blocks_total` | counter | `proto` | connections closed at accept because their source is blocked by the failed-login rate limit (not in `connections_rejected_total`) |
| `mail_auth_proxy_ratelimit_bans_total` | counter | | blocks started: a source reached `auth_ratelimit.failures` |
| `mail_auth_proxy_ratelimit_active_blocks` | gauge | | sources blocked now; set when a block starts and by a sweep every 10 s, so an ended block leaves it up to 10 s later |
| `mail_auth_proxy_ratelimit_evictions_total` | counter | | sources dropped from the full rate-limit table (65,536 sources) while they still had failures, a block or its escalation to remember. Rising means failed logins from that many distinct sources at once, a volume the rate limit cannot track per source |
| `mail_auth_proxy_active_connections` | gauge | `proto` | admitted connections currently open |
| `mail_auth_proxy_tls_cert_expiry_timestamp_seconds` | gauge | `cert` (the file of `tls.cert` and of each `tls.certificates` entry) | `notAfter` of the certificate in use from that file, Unix seconds; follows a `SIGHUP` reload, stays when the reload of that certificate is refused; 0 if it cannot be read. The series of a file removed from the configuration by a reload disappears. With several certificates, alert on the earliest: `min(…) - time()`, in Zabbix the Prometheus pattern with the function `min`. Alert on `… - time() < 14 * 86400`: a renewed file that was never reloaded still shows the old date. |
| `mail_auth_proxy_jwks_last_success_timestamp_seconds` | gauge | `issuer` (each `oauth.issuers` entry) | Unix time of the last JWKS fetch of the issuer that produced usable keys: at startup, periodic, on `SIGHUP`, or for an unknown `kid`. Alert when it is older than a few `oauth.refresh_secs`: the proxy still validates with the previous keys, but misses a key rotation. |
| `mail_auth_proxy_jwks_refresh_failures_total` | counter | `issuer` | JWKS fetches of the issuer that failed (unreachable, HTTP error, oversized, not parsable) or had no usable signing key |
| `mail_auth_proxy_jwks_keys_skipped_total` | counter | `issuer` | keys in the issuer's JWKS that were skipped because a member was missing or undecodable (such as an EC key without `y`), counted on every fetch that returns them; the other keys of the set are used. Keys skipped by design (a `use` other than `sig`, an algorithm or key type the issuer does not allow) are not counted. A steady rise means the IdP publishes a broken key; tokens signed with it fail. |
| `mail_auth_proxy_upstream_forward_total` | counter | `proto` | sessions spliced to a backend |
| `mail_auth_proxy_sessions_ended_total` | counter | `proto`, `reason` (`client_close`, `backend_close`, `idle_limit`, `max_session`, `error`) | a logged-in session ended. `client_close` and `backend_close`: that side closed first, with or without TLS close_notify (LOGOUT, QUIT, Dovecot's autologout, a client going away). `idle_limit`, `max_session`: `[session]` ended it. `error`: a read or write failed, e.g. a reset or a peer dropped by TCP keepalive or the retransmission timeout. The sum over `reason` catches up with `upstream_forward_total` as sessions end. |
| `mail_auth_proxy_backend_login_duration_seconds` | histogram | `proto`, `le` (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, +Inf) | time of each successful backend login, from the start of the backend connection (TCP, TLS, PROXY header or XCLIENT) to the backend's OK. Rejected logins are not included: their time includes the backend's own failure delay. |

## Signals and service manager

| Signal | Effect |
|---|---|
| `SIGHUP` | Reload the configuration file, the certificates and the JWKS, without closing any connection (below). |
| `SIGTERM`, `SIGINT` | Shutdown: every listener closes at once and new connections are refused. Open sessions, including relayed ones, may continue for up to 10 s; then the process closes whatever is still open and exits with status 0. |

The signal handlers are installed first at startup, so a `SIGHUP` during startup does not end the process.

Under systemd, when `$NOTIFY_SOCKET` is set (`Type=notify`), the proxy sends `READY=1` from its main process once the JWKS are loaded and every listener is bound, and `STOPPING=1` when a shutdown starts. Without the variable nothing is sent.

The shipped unit uses `Type=notify`, so `systemctl start` returns only when the proxy accepts connections and fails if it never gets there. Its `ExecReload=/bin/kill -HUP $MAINPID` makes `systemctl reload mail-auth-proxy` send the `SIGHUP` reload below.

### Reload (`SIGHUP`)

1. The configuration file (the path the service was started with) is read and checked
   like `--check-config`: every validation error, every certificate, key, CA, list and
   doveadm key file. Warnings are logged as `config: …`.
2. It is compared with the configuration in use. A change of a listener address, a
   listener added or removed (`[submission]`, `[sieve]`) or of the metrics endpoint needs
   a restart; such a file is refused as a whole.
3. The new configuration is built next to the one in use: certificates, backends, legacy
   gate, limits, rate limit, timeouts, session limits and issuers. An issuer that stays
   (same `issuer` and `jwks_url`) keeps its keys; a new issuer's JWKS is fetched, and one
   without usable keys refuses the reload.
4. It replaces the one in use in a single step. Every connection accepted from then on
   uses it; every connection already open keeps the configuration it was accepted with
   until it ends. No connection is closed, and there is no moment without legacy rules or
   limits. Open connections, rate-limit counts and blocks, the legacy throttle and the
   cached capabilities of a backend that stays are carried over
   ([configuration.md](configuration.md#reload)).
5. The result is logged (`reload: configuration loaded …` or `ERROR reload: configuration
   not loaded …`) and counted in `mail_auth_proxy_config_reload_total{result}`.
6. Certificates: after a successful reload the new configuration's certificates are the
   ones just loaded (`reload: certificate loaded` per file). After a refused one each
   certificate of the configuration in use is re-read on its own, so a renewed
   certificate is served even while the configuration file is broken: one that cannot be
   loaded, does not belong together, or (in `tls.certificates`) no longer carries a DNS
   name is logged at `ERROR` with its file and keeps its current certificate. New
   handshakes get the new certificate; open connections and resumed TLS sessions keep
   the one they were established with.
7. Every JWKS of the configuration in use is refreshed in the background (like the
   periodic refresh). A `SIGHUP` while a refresh still runs starts no second one.

`SIGHUP`s that arrive during a reload are folded into one more reload after it. `SIGTERM`
is handled at once meanwhile.

A connection opened before a reload is judged by the rules it was accepted with: a
stricter legacy rule, a removed issuer or a lower limit reaches it only if it reconnects.
Before login that lasts at most `timeouts.preauth_secs`. After login the proxy checks no
credential again (the session relays bytes), and the `[session]` limits it was accepted
with apply. To end open sessions after a change, restart the service or end them at the
backend (`doveadm kick`).

### Configuration change or package update

- **Configuration change** (`config.toml`, a certificate, a users or domains file):
  `mail-auth-proxy --check-config /etc/mail-auth-proxy/config.toml`, then
  `systemctl reload mail-auth-proxy`, and check the journal for
  `reload: configuration loaded` (or the `ERROR` line): `systemctl reload` returns once
  the signal is sent, not when the reload is done. A change the reload refuses as
  restart-only needs `systemctl restart mail-auth-proxy`. The users and domains files are
  also re-read by themselves within seconds of a change.
- **Package update** (a new binary): a restart. The package does it itself for a running
  service, after checking the configuration ([INSTALL.md](../INSTALL.md#5-upgrade)); a
  reload would keep the old binary running.

## Log-based blocking

The proxy itself has its connection limits, the per-account throttle of the legacy gate
and the [failed-login rate limit](architecture.md#failed-login-rate-limit), which blocks a
source on this proxy for a while. A log-based blocker adds longer bans, bans at the
firewall, and detection across services and hosts. Feed it the `authresult` lines; the
`ratelimit` line is separate and not counted as a failed login. The parser and
five scenarios in [contrib/crowdsec](../contrib/crowdsec/) cover brute force, password
spraying (many accounts from one address), password probing on OAuth-only endpoints, slow guessing and honeypot
account names. Whitelist your own management networks there.

## Troubleshooting

Most causes only show up in the `DEBUG` line of the session. Run the proxy with
`RUST_LOG=info,mail_auth_proxy=debug` (for example with `systemctl edit mail-auth-proxy`
and an `Environment=` line) while you look for them, and switch back afterwards.

| Symptom | Where to look | Common cause |
|---|---|---|
| The service does not start | `journalctl -u mail-auth-proxy`; `mail-auth-proxy --check-config <file>` | invalid key or value (all are listed), including a relative file path; a JWKS unreachable or without usable key at start; no system RNG (`password fingerprint key`); a listener address in use; certificate, key or config not readable by group `mail-auth-proxy` |
| SMTP clients are shown no extensions (no `SIZE`, `PIPELINING`, …) after STARTTLS, or an outdated list | `WARN … submission backend EHLO extensions not available` | the proxy's EHLO probe of the submission backend fails; until one succeeds the last list is used, before the first none. Check the backend as for failing logins |
| Every login ends with a retry-later reply; `mail_auth_proxy_backend_errors_total` rises | `WARN … session ended … error=` | `client_ip = "proxy_v2"` against a backend listener that does not expect the header (Dovecot without `haproxy = yes`, the proxy missing from `haproxy_trusted_networks`), or the other way round; a backend `tls` that does not match the backend port (`implicit` against a STARTTLS port gives a TLS error, `starttls` against an implicit-TLS port a greeting timeout or garbage); `refused the OAUTHBEARER request as invalid_request`: the backend could not use the OAUTHBEARER message (`auth_forward`); `invalid peer certificate: UnknownIssuer` (backend CA not in the system store: set `ca_file`); `NotValidForName` (set `verify_name`); backend down |
| OAuth logins fail with `reason="bad_token"` | `DEBUG … token rejected: …` | `InvalidAudience`: the mail audience is missing from the token (audience mapper); `not an access token`: wrong `token_type` or an ID token was sent; `email not verified`; `unknown kid`: the key is not in the JWKS even after a refresh (if the last on-demand refresh failed for the issuer the token claims, the client gets retry-later instead and the journal `WARN … unknown kid; JWKS refresh failed`); `identity outside the issuer's identity_domains`: the identity's domain is not in that issuer's `identity_domains`; `client not allowed`: the `client_claim` (`azp`, or `client_id` for `token_type = "rfc9068"`) not in `allowed_clients`; `ExpiredSignature`: client clock or token lifetime |
| OAuth logins fail with `reason="authzid_mismatch"` | client account settings | the client's user name is neither the token's identity nor its local part |
| OAuth logins fail with `reason="backend_reject"` | backend log | the backend does not accept the token: issuer not in its list, key or client missing from its local validation keys, token larger than the backend's SASL limit (see [backend guide](backend-dovecot-postfix.md)) |
| Password clients get "not available on this endpoint" | `reason="blocked_endpoint"`, `rule=""` | no legacy rule matches: the source address is not in `networks` (NAT or a load balancer in front), the client sends no or another SNI than the rule's `sni` (connecting by IP address sends none), protocol or mechanism not listed |
| Password logins fail slowly with `unknown_domain` / `unknown_account` / `throttled` | `authresult` `reason` and `rule` | domain not in `allowed_domains`/`domains_file`; account not found by doveadm; account throttled after recent failures |
| Every IMAP or ManageSieve login gets retry-later | `WARN … session ended … error=` naming `UNAUTHENTICATE` | the backend offers `UNAUTHENTICATE` (RFC 8437); disable it there ([SECURITY.md](../SECURITY.md#operator-responsibilities)) |
| Logins get retry-later under load or with a slow IdP | `WARN … session ended … error=` with `pre-auth budget of <n>s used up during …` | token validation (a JWKS refresh), the account check or the backend login did not finish within `timeouts.preauth_secs` from the accept |
| Password logins get retry-later although the backend is up | `WARN … session ended … error=` with the account check | doveadm HTTP API unreachable, wrong key, TLS not trusted (`doveadm_ca_file`) |
| All clients of one address get connection failures (no greeting, no TLS) for minutes or hours | `WARN authlog: ratelimit … source=<cidr>`; `mail_auth_proxy_ratelimit_blocks_total` | the failed-login rate limit blocked the address: many users behind one NAT or webmail server with wrong passwords, or an attacker sharing it. Add the address to `auth_ratelimit.exempt_networks` (or set `exempt_internal`) and reload: an exempt source is free at once, the blocks of other sources run on. A restart clears all blocks |
| A password rule suddenly matches nobody | `ERROR … legacy list file unusable` | a `users_file` or `domains_file` became unreadable or invalid; fix it, it is re-read within seconds |
| The backend logs the proxy's address instead of the client's | backend log; `WARN config: … client_ip = "none"` | `client_ip` is `none`; or `client_ip = "xclient"` but the proxy is not in `smtpd_authorized_xclient_hosts`: Postfix does not advertise `XCLIENT` and the step is skipped silently |
| Every submission login gets `454` retry-later | `WARN … backend advertises XCLIENT to this proxy but submission.backend.client_ip is not "xclient"` | the proxy is in `smtpd_authorized_xclient_hosts` but the backend's `client_ip` is not `xclient`; set it or remove the proxy from that list |
| Submission logins from some clients get `454` retry-later | `WARN … backend still advertises XCLIENT after XCLIENT ADDR=<client>` | the client's own address is in `smtpd_authorized_xclient_hosts` (e.g. a whole network listed); list only the proxy |
| A client fails with `unrecognized_name` ("unrecognised name", "SSL alert 112") | `WARN … session ended … TLS server name … is not a name of any configured certificate` | the client asks for a name that no certificate carries: add it to a certificate (or a `[[tls.certificates]]` entry) and reload, or have the client use a configured name |
| A client reports a connection loss after a wrong password | | `limits.max_auth_attempts` attempts used up, or the rate limit blocked the source; the client must reconnect (see [protocols](protocols.md#surprising-and-client-incompatible-behaviour)) |
| New certificate not served | `reload: certificate loaded` / `ERROR reload: certificate unusable` | `SIGHUP` not sent after renewal, or the new files are not readable by the service group |
| A configuration change has no effect | `ERROR reload: configuration not loaded … error=…`; `mail_auth_proxy_config_reload_total{result="error"}` | the reload was refused and the previous configuration runs on: fix what `error=` names (`mail-auth-proxy --check-config` lists every problem) and reload again; `changed <key>: needs a restart`: restart instead. Without an `ERROR` line: no `SIGHUP` was sent, or the client still uses a connection opened before the reload |
