# Configuration reference

The file is TOML, format version 2. A commented example is
[examples/config.example.toml](../examples/config.example.toml); the package installs it as
`/etc/mail-auth-proxy/config.toml` with all password settings commented out.

## Command line

```
mail-auth-proxy [-t | --check-config | --print-config] [CONFIG]
mail-auth-proxy --version
mail-auth-proxy -h | --help
```

| Argument | Effect |
|---|---|
| `CONFIG` | configuration file, default `/etc/mail-auth-proxy/config.toml` |
| `-t`, `--check-config` | validate the file and exit: every problem at once, including unreadable certificates, keys and CA files, the legacy users and domains files and the doveadm key and CA file; JWKS reachability is not checked. Exit status 0 when valid, 1 otherwise. |
| `--print-config` | print the effective configuration as TOML on stdout (defaults filled in, `[password_gate]` shown as the rule it stands for); exits non-zero after printing if the file is invalid |
| `--version` | print `mail-auth-proxy X.Y.Z (commit <sha12>)`; `commit unknown` for a plain `cargo build` |
| `-h`, `--help` | print the usage on stdout and exit with status 0 |

An unknown option or a second `CONFIG` argument prints the usage on stderr and exits with
status 2.

Warnings (settings that are allowed but weaken something) are logged as `config: …` at
`WARN`, both at startup and with `--check-config`; the list is in
[operations.md](operations.md#other-log-lines).

## Validation

The file is strict. Startup fails, and `--check-config` reports, when:

- a key is unknown or misspelled, or `config_version = 2` is missing;
- a required value is missing or empty, a listener is not `ip:port`, a backend is not
  `host:port` or its certificate name is invalid;
- a file path is set to `""`: `tls.cert`, `tls.key`, a backend `ca_file`, `users_file`,
  `domains_file`, `doveadm_key_file` or `doveadm_ca_file` (`<key> is empty`;
  `--check-config` reports it once, without a file error on top);
- two listeners (the metrics endpoint included, when enabled) take the same port on the
  same address, or one of them on a wildcard address that covers the other: `0.0.0.0`
  covers every IPv4 address, `[::]` every address because Linux binds it dual-stack
  (`net.ipv6.bindv6only = 0`), so `[::]:993` and `0.0.0.0:993` clash. Port 0 never
  clashes;
- `server.hostname` is not a host name (see the key below);
- a JWKS URL or `doveadm_url` is not `https://` (plain `http://` is allowed only for
  `localhost`, `127.0.0.1` and `::1`), or `doveadm_url` contains `user:password@`;
- a legacy rule has no `networks`, an empty list, a duplicate or invalid name, or public
  networks without `users`/`users_file` and without `public = true`;
- `[password_gate]` is enabled without `sni` or networks, or combined with
  `[[legacy.rules]]`;
- a limit, timeout, `refresh_secs`, `capability_cache_secs` or throttle value is 0;
  `leeway_secs` is above 300, `refresh_secs` above 86400, a timeout above 3600 or
  `failure_delay_ms` above 10000;
- `submission.backend.proxy_protocol` is set, or a `submission.ehlo_extensions` entry is
  not an EHLO line, repeats a keyword or is `AUTH` or `STARTTLS`;
- an issuer is listed twice, has no audience, or lists an unsupported algorithm;
- `openid_configuration_url` is not `https://` or contains `user:password@` or a
  fragment, `scope` is not an RFC 6749 scope, or more than one issuer sets
  `openid_configuration_url` or `scope` (the error result goes to a client whose token
  was not trusted, so it names one IdP for everyone);
- `doveadm_*` keys are set without `account_check = "doveadm"`, or are missing with it;
- `auth_ratelimit.failures`, `window_secs` or `block_secs` is 0, `window_secs` or
  `block_secs` is above 86400, `max_block_secs` is below `block_secs` or above 604800, or
  an `exempt_networks` entry is not a CIDR.

Startup also fails when a JWKS is unreachable or has no usable key, or a listener cannot
bind.

## File permissions

The service runs as the system user `mail-auth-proxy` in the group `mail-auth-proxy`. The
configuration, the TLS key, the doveadm key file and the legacy list files must be readable
by that group and by nobody else, for example `root:mail-auth-proxy` mode `0640`
(directories `0750`).

## Sections

| Section | Purpose |
|---|---|
| `[server]` | the name used in greetings and EHLO |
| `[tls]` | certificate and key served to clients |
| `[imap]`, `[submission]`, `[sieve]` | listener and backend per protocol; `[imap]` is required, omit `[submission]` or `[sieve]` to disable them |
| `[oauth]`, `[[oauth.issuers]]` | JWKS refresh and clock skew; one entry per issuer with its token rules |
| `[[legacy.rules]]` | legacy passwords: which source networks, names, protocols, mechanisms and users may use them |
| `[legacy]` | settings of the legacy gate: allowed domains, account check, throttle, failure delay |
| `[password_gate]` | short form of one legacy rule |
| `[scope]` | networks labelled `internal` in logs and metrics (a label only) |
| `[limits]`, `[timeouts]` | connection limits and pre-authentication deadlines |
| `[metrics]` | optional Prometheus endpoint |
| `[auth_ratelimit]` | blocking of source addresses with too many failed logins (on by default) |
| `[session]` | TCP keepalive of every connection; optional idle and lifetime limits after login |

## Keys

A backend (`imap.backend`, `submission.backend`, `sieve.backend`) is a table with the
backend `.…` keys below, written inline (`backend = { address = "…" }`) or as
`[imap.backend]`.

| Key | Type | Default | Effect |
|---|---|---|---|
| `config_version` | integer | required | must be `2`, set at the top before the first `[section]`; a file without it fails with `config_version is missing: the file must set config_version = 2 …` |
| `server.hostname` | string | `mail-auth-proxy` | name in the IMAP/SMTP/Sieve greetings, EHLO replies and the backend EHLO. A host name as SMTP defines it (RFC 5321 §4.1.2): labels of letters, digits and hyphens separated by dots, 1-63 characters each without a hyphen at either end, at most 253 in all, no trailing dot. IP addresses and address literals (`[192.0.2.1]`) are refused, because the EHLO reply takes a domain only |
| `tls.cert`, `tls.key` | path | required | PEM chain and key served for every SNI |
| `imap.listen` | `ip:port` | required | implicit-TLS listener |
| `imap.backend` | backend | required | implicit-TLS IMAP backend |
| `submission.listen` | `ip:port` | section optional | STARTTLS listener; omit the section to disable SMTP |
| `submission.backend` | backend | required in section | STARTTLS backend (Postfix); `proxy_protocol` is not supported here |
| `submission.xclient` | bool | `false` | send XCLIENT if the backend advertises it. With `false`, a backend that advertises XCLIENT to the proxy is a misconfiguration: every login is an outage (454) until the key is set or the proxy is removed from `smtpd_authorized_xclient_hosts`, because the client could otherwise send its own XCLIENT after login |
| `submission.ehlo_extensions` | array | Postfix defaults | advertised after STARTTLS besides AUTH (not `AUTH`/`STARTTLS`, in any case). Each entry is an EHLO line (RFC 5321 §4.1.1.1): a keyword of letters, digits and hyphens that does not start with a hyphen, then optional parameters of printable ASCII, all separated by single spaces; each keyword once (case-insensitive); default `PIPELINING`, `ENHANCEDSTATUSCODES`, `8BITMIME`, `DSN`, `SMTPUTF8`, `CHUNKING`. The client keeps this list for the whole session, so it must match what the backend offers. |
| `sieve.listen` | `ip:port` | section optional | STARTTLS listener; omit the section to disable ManageSieve |
| `sieve.backend` | backend | required in section | STARTTLS ManageSieve backend |
| `sieve.capability_cache_secs` | integer | 600 | reuse of the backend capability list; ≥ 1 |
| backend `.address` | `host:port` | required | where to connect |
| backend `.verify_name` | string | host of `address` | name verified on the backend certificate |
| backend `.ca_file` | path | system store | PEM CAs the backend certificate must chain to; replaces the system store for this backend |
| backend `.proxy_protocol` | bool | `false` | PROXY v2 header with the client address (IMAP, Sieve) |
| `oauth.refresh_secs` | integer | 300 | periodic JWKS refresh; 1-86400. Unknown key ids trigger a refresh sooner, but a key removed from the JWKS is dropped only by this one |
| `oauth.leeway_secs` | integer | 60 | clock skew on `exp`/`nbf`; 0-300 (RFC 7519 §4.1.4 allows a small leeway, "usually no more than a few minutes") |
| `oauth.issuers[].issuer` | string | required | exact `iss`; keys from this issuer's JWKS are accepted only with it |
| `oauth.issuers[].jwks_url` | URL | required | https (http only for localhost) |
| `oauth.issuers[].audiences` | array | required | the token's `aud` must contain one |
| `oauth.issuers[].token_type` | `keycloak` \| `rfc9068` \| `any` | required | access-token marker: claim `typ=Bearer`, header `typ=at+jwt`, or none (warning) |
| `oauth.issuers[].identity_claim` | string | `email` | claim forwarded to the backend as the login; one word, and one plain address for `email` |
| `oauth.issuers[].require_email_verified` | bool | on for `email` | require `email_verified = true` |
| `oauth.issuers[].allowed_algorithms` | array | RS256/384/512, PS256/384/512, ES256, ES384 | keys are used only with these |
| `oauth.issuers[].infer_key_algorithm` | bool | `true` | a JWKS key without `alg` is used with the one algorithm its type implies (ES256 for P-256, ES384 for P-384, RS256 for RSA); off: such keys are skipped |
| `oauth.issuers[].allowed_clients` | array | empty (any) | accepted values of `client_claim` |
| `oauth.issuers[].client_claim` | string | `azp` | claim naming the OAuth client |
| `oauth.issuers[].openid_configuration_url` | URL | unset | https only (also for `localhost`), no `user:password@`, no fragment. Sent as `openid-configuration` in the error result a client gets for a rejected token (RFC 7628 §3.2.2), so it can find the IdP. Warning when it is not `<issuer>/.well-known/openid-configuration` |
| `oauth.issuers[].scope` | string | unset | sent as `scope` in the same error result: the scope a client must request for mail. RFC 6749 scope tokens separated by single spaces; several scopes give a warning (RFC 7628 recommends one) |
| `scope.internal_networks` | array of CIDR | empty (default: the `[password_gate]` networks) | label `scope=internal` in logs and metrics; allows nothing |
| `legacy.rules[].name` | string | required | unique, 1-64 of `A-Z a-z 0-9 . _ -`; logged as `rule=` |
| `legacy.rules[].networks` | array of CIDR | required | client source networks; the rule's security boundary |
| `legacy.rules[].sni` | array | any SNI (also none) | names the client must have asked for |
| `legacy.rules[].users` | array | any user | `user@domain` (local part exact, domain case-insensitive) or `*@domain` |
| `legacy.rules[].users_file` | path | none | more `users` entries, one per line, `#` comments; re-read on change |
| `legacy.rules[].protocols` | `imap` \| `submission` \| `sieve` | all | protocols the rule applies to |
| `legacy.rules[].mechanisms` | `PLAIN` \| `LOGIN` | both | `LOGIN` also covers the IMAP LOGIN command |
| `legacy.rules[].public` | bool | `false` | required when `networks` contain a public range (anything but RFC 1918, loopback, link-local, ULA; `0.0.0.0/0` and `::/0` included) and the rule has no `users`/`users_file`; gives a warning |
| `legacy.allowed_domains` | array | none | domains whose logins may use passwords |
| `legacy.domains_file` | path | none | more allowed domains, one per line, `#` comments; re-read on change |
| `legacy.account_check` | `none` \| `doveadm` | `none` | check that the account exists before the password is forwarded |
| `legacy.doveadm_url` | URL | required with `doveadm` | doveadm HTTP API endpoint (`…/doveadm/v1`); https, http only for localhost; no `user:password@` |
| `legacy.doveadm_key_file` | path | required with `doveadm` | file with the `doveadm_api_key` |
| `legacy.doveadm_ca_file` | path | system store | PEM CAs for the doveadm certificate |
| `legacy.throttle` | `{ failures, window_secs }` | off | per account: after `failures` backend rejections within `window_secs`, refuse locally until the window ends; both ≥ 1 |
| `legacy.failure_delay_ms` | integer | 2000 | minimum time from credential to a failed legacy reply (refusals also follow the median backend-rejection latency; jitter added); ≤ 10000, 0 gives a warning |
| `password_gate.enabled` | bool | `false` | short form: one rule `password_gate` |
| `password_gate.sni` | array | required when enabled | the rule's `sni` |
| `password_gate.internal_networks` | array of CIDR | required when enabled | the rule's `networks` (with `public = true` if one is public), and the scope label when `[scope]` is absent, even with the gate off; every public network gives the same warning as a rule with `public = true`; not combinable with `[[legacy.rules]]` |
| `limits.max_connections` | integer | 2048 | global cap, at most half unauthenticated; ≥ 1 |
| `limits.max_preauth_per_ip` | integer | 32 | unauthenticated connections per IP; ≥ 1. IPv4 (also IPv4-mapped) counts per address, IPv6 per /64 (one host usually holds a whole /64) |
| `limits.max_preauth_commands` | integer | 8 | commands before authentication; ≥ 1 |
| `timeouts.preauth_secs` | integer | 60 | accept to credential, in total; 1-3600 |
| `timeouts.idle_secs` | integer | 30 | silence on any single read; 1-3600 |
| `timeouts.connect_secs` | integer | 10 | backend connect, TLS handshake, PROXY header; 1-3600 |
| `metrics.enabled` | bool | `false`; `true` if only `listen` is set | serve the Prometheus endpoint |
| `metrics.listen` | `ip:port` | required when enabled | Prometheus endpoint, no authentication (warning if not loopback); must not clash with a mail listener |
| `auth_ratelimit.enabled` | bool | `true` | block sources with too many failed logins ([architecture.md](architecture.md#failed-login-rate-limit)) |
| `auth_ratelimit.failures` | integer | 20 | counted failures of one source (IPv4 address, IPv6 /64) that start a block; ≥ 1. A repeated identical credential counts once |
| `auth_ratelimit.window_secs` | integer | 600 | window in which the failures are counted, from the first one; 1-86400 |
| `auth_ratelimit.block_secs` | integer | 900 | length of the first block; 1-86400 |
| `auth_ratelimit.max_block_secs` | integer | 86400 | each further block of the same source doubles up to this; `block_secs` to 604800. Equal to `block_secs`: no escalation |
| `auth_ratelimit.exempt_internal` | bool | `false` | never count sources in `scope.internal_networks` |
| `auth_ratelimit.exempt_networks` | array of CIDR | `["127.0.0.0/8", "::1/128"]` | sources that are never counted, e.g. a webmail server or a NAT gateway through which many users log in; a public network gives a warning. An empty list exempts nothing, not even loopback |
| `session.keepalive_idle_secs` | integer | 600 | TCP keepalive on every client and backend connection, from accept or connect: silence before the first probe; 1-32767 (the Linux maximum) |
| `session.keepalive_interval_secs` | integer | 60 | time between unanswered probes; 1-32767 |
| `session.keepalive_count` | integer | 5 | unanswered probes before the kernel drops the connection; 2-127 (RFC 9293 §3.8.4: one lost probe must not end a connection). With the defaults a dead peer is dropped after at most 15 minutes of silence |
| `session.idle_limit_secs` | integer | off | after login: close the session after this long without a byte in either direction; 1-2592000. Below 1800 gives a warning: IMAP and ManageSieve clients may rely on at least 30 minutes (RFC 9051 §5.4, RFC 5804 §1.2), and IDLE clients re-issue IDLE only every 29 minutes (RFC 9051 §6.3.13) |
| `session.max_session_secs` | integer | off | after login: close the session this long after the login, busy or not; 1-2592000; below 1800 gives the same warning |

Environment: `RUST_LOG` (log filter, default `info`; see [operations.md](operations.md#logging)).

How the legacy keys act together is described in [architecture.md](architecture.md#legacy-gate),
the token keys in [architecture.md](architecture.md#oauth-token-validation), and a worked
Keycloak example in [idp-keycloak.md](idp-keycloak.md).
