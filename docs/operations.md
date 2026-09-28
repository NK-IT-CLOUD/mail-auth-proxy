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
2026-09-26T21:29:56.642346Z  WARN authlog: authresult result="fail" proto="imap" scope="internal" mech=XOAUTH2 user=evil?FAKE?authresult?result??ok??user?root peer=127.0.0.1 reason="bad_token" pwfp="" rule=""
2026-09-26T21:28:26.004745Z  WARN authlog: authresult result="fail" proto="smtp" scope="internal" mech=PLAIN user=carol@example.test peer=127.0.0.1 reason="backend_reject" pwfp="f52419d665460b37" rule="internal"
2026-09-26T21:31:02.118204Z  WARN authlog: authresult result="fail" proto="imap" scope="external" mech=PLAIN user=a@gone.test peer=198.51.100.7 reason="unknown_domain" pwfp="5d0f1c7a92b3e416" rule="partner"
2026-09-26T21:33:30.946119Z  WARN authlog: authresult result="fail" proto="imap" scope="external" mech=other user= peer=127.0.0.4 reason="protocol" pwfp="" rule=""
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
| `pwfp` | 16 hex chars: the first 64 bits of HMAC-SHA256(password) under a random key generated per process. Set only for failed password credentials (`blocked_endpoint`, `unknown_domain`, `unknown_account`, `throttled`, `oversize`, `backend_reject`), otherwise `""`. It can be compared only within one process lifetime. |

`sanitize()` keeps `[A-Za-z0-9@._+-]`, turns every other character into `?`, and truncates to 64 characters.

When a `protocol` record is written:

- **IMAP:** for every pre-auth error after the TLS handshake. A TLS handshake failure, `LOGOUT`, and a disconnect right after the greeting (health check) write no record.
- **SMTP and Sieve:** only for failures after TLS. Failures before TLS and TLS failures write no record. A failed Sieve capability probe writes no record.

### Other log lines

- `mail_auth_proxy: session ended peer=<ip:port> error=<escaped text>`, with the prefix `submission session ended` or `sieve session ended` for the other protocols, when a session ends with an error. The error is the whole cause chain, e.g. `backend unavailable: backend temporarily unavailable: P1 NO [UNAVAILABLE] …`, `backend unavailable: Connection refused (os error 111)`, `read timed out after 30s`, `imap pre-auth: pre-auth budget of 60s used up`, `invalid peer certificate: UnknownIssuer`. Control characters are escaped, but printable client text can appear.
  - At `WARN` for outages and pre-auth failures.
  - At `DEBUG` when the credential was refused (blocked, denied, bad token, wrong authzid, backend rejection), because the `authresult` line already records it. The precise reason is only here, e.g. `token rejected: InvalidAudience`, `token rejected: unknown kid`, `email not verified`, `not an access token`, `malformed claims`, `ExpiredSignature`, `ImmatureSignature`, `MissingRequiredClaim("aud")`, `backend auth rejected: …`; see it with `RUST_LOG=info,mail_auth_proxy=debug`.
- `INFO`:
  - `oauth validated; proxying to backend peer=… user=<email> mech=…` (IMAP)
  - `password auth; forwarding to backend peer=… user=<login> mech=…` (IMAP)
  - `submission auth ok; splicing user=… mech=…`
  - `sieve auth ok; splicing user=… mech=…`
- Startup, at `INFO`:
  - `legacy password rule rule=<name> networks=[…] sni=… users=… users_file=… protocols=… mechanisms=…` per rule and `legacy password gate domain_gate=… account_check=… throttle=… failure_delay_ms=…`, or `password auth disabled: OAuth only`.
  - `legacy list file reloaded` when a users or domains file changes; `ERROR … legacy list file unusable; it matches nothing until it is fixed` when it becomes missing or invalid, and `legacy list file usable again` when it is fixed.
  - `imap listener up`, `submission listener up`, `sieve listener up` (with `listen=` and `backend=`)
  - `reload: certificate loaded`, `reload: JWKS refreshed` (or `reload: JWKS refresh already running`) after `SIGHUP` (`ERROR reload: certificate unusable; keeping the current one`, `WARN reload: JWKS refresh failed; keeping previous keys` on failure)
  - `shutting down: listeners closed, waiting for open sessions drain_secs=10`, then `all sessions ended; exiting` or `WARN sessions still open after the drain time; closing them`
  - `metrics endpoint up`
- `WARN`:
  - `config: …` at startup and with `--check-config`, one line per warning: `token_type = "any"`; `require_email_verified` with an `identity_claim` other than `email`; a `/0` network in `[password_gate]`; `[password_gate]` disabled but `sni` set; a legacy rule that accepts every user from public networks; `[legacy]` settings without any rule; `failure_delay_ms = 0`; `metrics.listen` not on loopback.
  - `fetching JWKS …`, `parsing JWKS …`, `JWKS has no usable signing keys`, `JWKS refresh failed; keeping previous keys`, `JWKS refresh for unknown kid` (the refresh an unknown `kid` triggered failed)
  - `loading system CA certificates`
  - `metrics accept error`
  - `systemd notification failed`
- `ERROR`:
  - `metrics endpoint bind failed; metrics disabled`
  - `…: accept error` (the listener waits 100 ms and keeps accepting)
- `DEBUG`:
  - `…: connection limit reached, closing` for a connection closed at accept by a limit
  - `relay ended with an error` when the byte relay after login ends with an I/O error
  - `JWKS refreshed kids=… failed=…` after each periodic refresh

## Prometheus metrics

Metrics are off by default. They are on with `metrics.enabled = true` or when only `metrics.listen` is set. `metrics.listen` then serves a minimal HTTP/1.1 responder without authentication, so keep it on loopback or a management network (`--check-config` warns about any other address). Only `GET /metrics` gets the exposition text (`Content-Type: text/plain; version=0.0.4`); another path is answered 404, another method 405, a request line that is not HTTP/1.x 400, a request head over 4 KiB 431, each with `Connection: close`. At most 4 scrapes are served at a time, further connections are closed at accept; the request head and the response each have 10 s. The endpoint logs neither requests nor refusals. Every series is present from the start, so `rate()` and `increase()` work from the first scrape: counters and gauges at 0, the timestamps (`process_start_time_seconds`, the JWKS success time, the certificate expiry) set during startup. No label carries a user, an address or other client input; `issuer` comes from the configuration.

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `mail_auth_proxy_build_info` | gauge | `version`, `commit` (12 hex digits, `unknown` for a plain `cargo build`) | always 1 |
| `process_start_time_seconds` | gauge | | start time of the process, Unix seconds |
| `mail_auth_proxy_auth_attempts_total` | counter | `proto` (imap, smtp, sieve), `scope` (internal, external), `mechanism` (xoauth2, oauthbearer, plain, login, other), `result` (ok, fail) | a credential was evaluated. `fail` counts every refused credential, one per `authresult` line with reason `bad_token`, `authzid_mismatch`, `blocked_endpoint`, `unknown_domain`, `unknown_account`, `throttled`, `oversize` or `backend_reject`. Backend and account-check outages (no `authresult` line) and `protocol` (counted in `mail_auth_proxy_preauth_aborts_total`) are not counted. |
| `mail_auth_proxy_auth_refusals_total` | counter | `proto`, `reason` (`blocked_endpoint`, `bad_token`, `authzid_mismatch`, `backend_reject`, `unknown_domain`, `unknown_account`, `throttled`, `oversize`) | a refused credential, by the `reason` of its `authresult` line ([above](#the-authresult-line)). The sum over `reason` equals the `fail` side of `mail_auth_proxy_auth_attempts_total`. |
| `mail_auth_proxy_preauth_aborts_total` | counter | `proto`, `scope` | the connection ended before a credential was presented. Not counted: a clean `LOGOUT`/`QUIT`, an IMAP client that disconnects right after the greeting (a health check), Sieve capability-probe failures. |
| `mail_auth_proxy_token_validate_total` | counter | `result` (ok, fail) | local JWT validations |
| `mail_auth_proxy_connections_total` | counter | `proto` | connections admitted past the limits |
| `mail_auth_proxy_connections_rejected_total` | counter | `proto` | connections closed at accept by a limit |
| `mail_auth_proxy_backend_errors_total` | counter | `proto` | backend or legacy account check (doveadm) unreachable or failing while a client waited for its verdict (outage, not a failed login) |
| `mail_auth_proxy_legacy_list_errors_total` | counter | `list` (users_file, domains_file) | failed re-reads of a legacy list file; while it fails, the list matches nothing |
| `mail_auth_proxy_legacy_throttle_evictions_total` | counter | | accounts dropped from the full throttle table (65,536 accounts) while their failure window was still running; their count starts over. Rising means failed passwords for that many distinct accounts within one window, a spraying volume that dilutes the per-account throttle. |
| `mail_auth_proxy_active_connections` | gauge | `proto` | admitted connections currently open |
| `mail_auth_proxy_tls_cert_expiry_timestamp_seconds` | gauge | | `notAfter` of the client-facing certificate in use, Unix seconds; follows a `SIGHUP` reload, stays when a reload is refused; 0 if it cannot be read. Alert on `… - time() < 14 * 86400`: a renewed file that was never reloaded still shows the old date. |
| `mail_auth_proxy_jwks_last_success_timestamp_seconds` | gauge | `issuer` (each `oauth.issuers` entry) | Unix time of the last JWKS fetch of the issuer that produced usable keys: at startup, periodic, on `SIGHUP`, or for an unknown `kid`. Alert when it is older than a few `oauth.refresh_secs`: the proxy still validates with the previous keys, but misses a key rotation. |
| `mail_auth_proxy_jwks_refresh_failures_total` | counter | `issuer` | JWKS fetches of the issuer that failed (unreachable, HTTP error, oversized, not parsable) or had no usable signing key |
| `mail_auth_proxy_upstream_forward_total` | counter | `proto` | sessions spliced to a backend |
| `mail_auth_proxy_backend_login_duration_seconds` | histogram | `proto`, `le` (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, +Inf) | time of each successful backend login, from the start of the backend connection (TCP, TLS, PROXY header or XCLIENT) to the backend's OK. Rejected logins are not included: their time includes the backend's own failure delay. |

## Signals and service manager

| Signal | Effect |
|---|---|
| `SIGHUP` | Reload the TLS certificate and key, and refresh every JWKS in the background (like the periodic refresh). The configuration file is **not** re-read; a configuration change needs a restart. New handshakes get the new certificate; open connections and resumed TLS sessions keep the one they were established with. A certificate or key that cannot be loaded, or a pair that does not belong together, is logged at `ERROR` and the current certificate stays. A `SIGHUP` while a refresh still runs starts no second one, and `SIGTERM` is handled at once meanwhile. |
| `SIGTERM`, `SIGINT` | Shutdown: every listener closes at once and new connections are refused. Open sessions, including relayed ones, may continue for up to 10 s; then the process closes whatever is still open and exits with status 0. |

The signal handlers are installed first at startup, so a `SIGHUP` during startup does not end the process.

Under systemd, when `$NOTIFY_SOCKET` is set (`Type=notify`), the proxy sends `READY=1` from its main process once the JWKS are loaded and every listener is bound, and `STOPPING=1` when a shutdown starts. Without the variable nothing is sent.

The shipped unit uses `Type=notify`, so `systemctl start` returns only when the proxy accepts connections and fails if it never gets there. Its `ExecReload=/bin/kill -HUP $MAINPID` makes `systemctl reload mail-auth-proxy` send the `SIGHUP` reload above.

## Log-based blocking

Apart from its connection limits and the per-account throttle of the legacy gate, the
proxy blocks nothing. Feed the `authresult` lines to a log-based blocker. The parser and
five scenarios in [contrib/crowdsec](../contrib/crowdsec/) cover brute force, password
spraying (many accounts from one address), password probing on OAuth-only endpoints, slow guessing and honeypot
account names. Whitelist your own management networks there.

## Troubleshooting

Most causes only show up in the `DEBUG` line of the session. Run the proxy with
`RUST_LOG=info,mail_auth_proxy=debug` (for example with `systemctl edit mail-auth-proxy`
and an `Environment=` line) while you look for them, and switch back afterwards.

| Symptom | Where to look | Common cause |
|---|---|---|
| The service does not start | `journalctl -u mail-auth-proxy`; `mail-auth-proxy --check-config <file>` | invalid key or value (all are listed); a JWKS unreachable or without usable key at start; a listener address in use; certificate, key or config not readable by group `mail-auth-proxy` |
| Every login ends with a retry-later reply; `mail_auth_proxy_backend_errors_total` rises | `WARN … session ended … error=` | `proxy_protocol = true` against a Dovecot listener without `haproxy = yes`, or the proxy missing from `haproxy_trusted_networks`; `invalid peer certificate: UnknownIssuer` (backend CA not in the system store: set `ca_file`); `NotValidForName` (set `verify_name`); backend down |
| OAuth logins fail with `reason="bad_token"` | `DEBUG … token rejected: …` | `InvalidAudience`: the mail audience is missing from the token (audience mapper); `not an access token`: wrong `token_type` or an ID token was sent; `email not verified`; `unknown kid`: the key is not in the JWKS even after a refresh (if the last on-demand refresh failed for the issuer the token claims, the client gets retry-later instead and the journal `WARN … unknown kid; JWKS refresh failed`); `client not allowed`: `azp` not in `allowed_clients`; `ExpiredSignature`: client clock or token lifetime |
| OAuth logins fail with `reason="authzid_mismatch"` | client account settings | the client's user name is neither the token's identity nor its local part |
| OAuth logins fail with `reason="backend_reject"` | backend log | the backend does not accept the token: issuer not in its list, key or client missing from its local validation keys, token larger than the backend's SASL limit (see [backend guide](backend-dovecot-postfix.md)) |
| Password clients get "not available on this endpoint" | `reason="blocked_endpoint"`, `rule=""` | no legacy rule matches: the source address is not in `networks` (NAT or a load balancer in front), the client sends no or another SNI than the rule's `sni` (connecting by IP address sends none), protocol or mechanism not listed |
| Password logins fail slowly with `unknown_domain` / `unknown_account` / `throttled` | `authresult` `reason` and `rule` | domain not in `allowed_domains`/`domains_file`; account not found by doveadm; account throttled after recent failures |
| Password logins get retry-later although the backend is up | `WARN … session ended … error=` with the account check | doveadm HTTP API unreachable, wrong key, TLS not trusted (`doveadm_ca_file`) |
| A password rule suddenly matches nobody | `ERROR … legacy list file unusable` | a `users_file` or `domains_file` became unreadable or invalid; fix it, it is re-read within seconds |
| Postfix logs the proxy's address instead of the client's | Postfix log | `submission.xclient = true` but the proxy is not in `smtpd_authorized_xclient_hosts`: Postfix does not advertise `XCLIENT` and the step is skipped silently |
| Every submission login gets `454` retry-later | `WARN … backend advertises XCLIENT to this proxy but submission.xclient = false` | the proxy is in `smtpd_authorized_xclient_hosts` but `submission.xclient` is off; set it to `true` or remove the proxy from that list |
| Submission logins from some clients get `454` retry-later | `WARN … backend still advertises XCLIENT after XCLIENT ADDR=<client>` | the client's own address is in `smtpd_authorized_xclient_hosts` (e.g. a whole network listed); list only the proxy |
| A client reports a connection loss after a wrong password | | one authentication attempt per connection; the client must reconnect (see [protocols](protocols.md#surprising-and-client-incompatible-behaviour)) |
| New certificate not served | `reload: certificate loaded` / `ERROR reload: certificate unusable` | `SIGHUP` not sent after renewal, or the new files are not readable by the service group |
