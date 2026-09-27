# Configuration reference

The file is TOML, format version 2. A commented example is
[examples/config.example.toml](../examples/config.example.toml); the package installs it as
`/etc/mail-auth-proxy/config.toml` with all password settings commented out.

## Command line

```
mail-auth-proxy [--check-config | --print-config] [CONFIG]
mail-auth-proxy --version
mail-auth-proxy -h | --help
```

| Argument | Effect |
|---|---|
| `CONFIG` | configuration file, default `/etc/mail-auth-proxy/config.toml` |
| `--check-config` | validate the file and exit: every problem at once, including unreadable certificates, keys and CA files, the legacy users and domains files and the doveadm key and CA file; JWKS reachability is not checked. Exit status 0 when valid, 1 otherwise. |
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
- a required value is missing or empty, a listener is not `ip:port` or used twice, a
  backend is not `host:port` or its certificate name is invalid;
- a JWKS URL or `doveadm_url` is not `https://` (plain `http://` is allowed only for
  `localhost`, `127.0.0.1` and `::1`), or `doveadm_url` contains `user:password@`;
- a legacy rule has no `networks`, an empty list, a duplicate or invalid name, or public
  networks without `users`/`users_file` and without `public = true`;
- `[password_gate]` is enabled without `sni` or networks, or combined with
  `[[legacy.rules]]`;
- a limit, timeout, `refresh_secs`, `capability_cache_secs` or throttle value is 0, or
  `failure_delay_ms` is above 10000;
- `submission.backend.proxy_protocol` is set, or `submission.ehlo_extensions` contains
  `AUTH` or `STARTTLS`;
- an issuer is listed twice, has no audience, or lists an unsupported algorithm;
- `doveadm_*` keys are set without `account_check = "doveadm"`, or are missing with it.

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

## Keys

A backend (`imap.backend`, `submission.backend`, `sieve.backend`) is a table with the
backend `.…` keys below, written inline (`backend = { address = "…" }`) or as
`[imap.backend]`.

| Key | Type | Default | Effect |
|---|---|---|---|
| `config_version` | integer | required | must be `2`, set at the top before the first `[section]`; a file without it fails with `config_version is missing: the file must set config_version = 2 …` |
| `server.hostname` | string | `mail-auth-proxy` | name in the IMAP/SMTP/Sieve greetings, EHLO replies and the backend EHLO; one word |
| `tls.cert`, `tls.key` | path | required | PEM chain and key served for every SNI |
| `imap.listen` | `ip:port` | required | implicit-TLS listener |
| `imap.backend` | backend | required | implicit-TLS IMAP backend |
| `submission.listen` | `ip:port` | section optional | STARTTLS listener; omit the section to disable SMTP |
| `submission.backend` | backend | required in section | STARTTLS backend (Postfix); `proxy_protocol` is not supported here |
| `submission.xclient` | bool | `false` | send XCLIENT if the backend advertises it. With `false`, a backend that advertises XCLIENT to the proxy is a misconfiguration: every login is an outage (454) until the key is set or the proxy is removed from `smtpd_authorized_xclient_hosts`, because the client could otherwise send its own XCLIENT after login |
| `submission.ehlo_extensions` | array | Postfix defaults | advertised after STARTTLS besides AUTH (not `AUTH`/`STARTTLS`); default `PIPELINING`, `ENHANCEDSTATUSCODES`, `8BITMIME`, `DSN`, `SMTPUTF8`, `CHUNKING`. The client keeps this list for the whole session, so it must match what the backend offers. |
| `sieve.listen` | `ip:port` | section optional | STARTTLS listener; omit the section to disable ManageSieve |
| `sieve.backend` | backend | required in section | STARTTLS ManageSieve backend |
| `sieve.capability_cache_secs` | integer | 600 | reuse of the backend capability list; ≥ 1 |
| backend `.address` | `host:port` | required | where to connect |
| backend `.verify_name` | string | host of `address` | name verified on the backend certificate |
| backend `.ca_file` | path | system store | PEM CAs the backend certificate must chain to; replaces the system store for this backend |
| backend `.proxy_protocol` | bool | `false` | PROXY v2 header with the client address (IMAP, Sieve) |
| `oauth.refresh_secs` | integer | 300 | periodic JWKS refresh; ≥ 1 |
| `oauth.leeway_secs` | integer | 60 | clock skew on `exp`/`nbf` |
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
| `password_gate.internal_networks` | array of CIDR | required when enabled | the rule's `networks` (with `public = true` if one is public), and the scope label when `[scope]` is absent, even with the gate off; `0.0.0.0/0` gives a warning; not combinable with `[[legacy.rules]]` |
| `limits.max_connections` | integer | 2048 | global cap, at most half unauthenticated; ≥ 1 |
| `limits.max_preauth_per_ip` | integer | 32 | unauthenticated connections per IP; ≥ 1. IPv4 (also IPv4-mapped) counts per address, IPv6 per /64 (one host usually holds a whole /64) |
| `limits.max_preauth_commands` | integer | 8 | commands before authentication; ≥ 1 |
| `timeouts.preauth_secs` | integer | 60 | accept to credential, in total; ≥ 1 |
| `timeouts.idle_secs` | integer | 30 | silence on any single read; ≥ 1 |
| `timeouts.connect_secs` | integer | 10 | backend connect, TLS handshake, PROXY header; ≥ 1 |
| `metrics.enabled` | bool | `false`; `true` if only `listen` is set | serve the Prometheus endpoint |
| `metrics.listen` | `ip:port` | required when enabled | Prometheus endpoint, no authentication (warning if not loopback) |

Environment: `RUST_LOG` (log filter, default `info`; see [operations.md](operations.md#logging)).

How the legacy keys act together is described in [architecture.md](architecture.md#legacy-gate),
the token keys in [architecture.md](architecture.md#oauth-token-validation), and a worked
Keycloak example in [idp-keycloak.md](idp-keycloak.md).
