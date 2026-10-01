# Configuration reference

The file is TOML, format version 2. A commented example is
[examples/config.example.toml](../examples/config.example.toml); the package installs it as
`/usr/share/mail-auth-proxy/config.example.toml` and, where no config exists yet, copies it
to `/etc/mail-auth-proxy/config.toml`, with all password settings commented out.

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
`WARN`, at startup, on a reload and with `--check-config`; the list is in
[operations.md](operations.md#other-log-lines).

## Validation

The file is strict. Startup fails, and `--check-config` reports, when:

- a key is unknown or misspelled, or `config_version = 2` is missing;
- a required value is missing or empty, a listener is not `ip:port`, a backend address is
  not `host:port` or its certificate name is invalid;
- a backend sets neither `address` nor `addresses`, or both, lists more than 16
  `addresses` or one of them twice, or sets `health_check_secs` outside 1-3600;
- a file path is set to `""`: `tls.cert`, `tls.key`, `tls.certificates[].cert`/`.key`, a backend `ca_file`, `users_file`,
  `domains_file`, `doveadm_key_file` or `doveadm_ca_file` (`<key> is empty`;
  `--check-config` reports it once, without a file error on top);
- two listeners (the metrics endpoint included, when enabled) take the same port on the
  same address, or one of them on a wildcard address that covers the other: `0.0.0.0`
  covers every IPv4 address, `[::]` every address because Linux binds it dual-stack
  (`net.ipv6.bindv6only = 0`), so `[::]:993` and `0.0.0.0:993` clash. Port 0 never
  clashes;
- `server.hostname` is not a host name (see the key below);
- the same certificate file is configured twice (`tls.cert` and `tls.certificates[].cert`
  together): it names the certificate in the metrics and the reload log;
- a file path (`tls.cert`, `tls.key`, `tls.certificates[]`, a backend's `ca_file`,
  `doveadm_key_file` and `doveadm_ca_file`, `legacy.domains_file`,
  `legacy.doveadm_key_file`, `legacy.doveadm_ca_file`, `legacy.rules[].users_file`) is
  empty or not absolute: a relative path would depend on the working directory;
- a JWKS URL or `doveadm_url` is not `https://` (plain `http://` is allowed only for
  `localhost`, `127.0.0.1` and `::1`), or `doveadm_url` contains `user:password@`;
- a legacy rule has no `networks`, an empty list, a duplicate or invalid name, or public
  networks without `users`/`users_file` and without `public = true`;
- `[password_gate]` is enabled without `sni` or networks, or combined with
  `[[legacy.rules]]`;
- a limit, timeout, `refresh_secs`, `capability_cache_secs` or throttle value is 0;
  `leeway_secs` is above 300, `refresh_secs` above 86400, a timeout above 3600,
  `failure_delay_ms` above 10000, `max_auth_attempts` outside 1-10, `ipv6_source_prefix`
  outside 32-64, or a `[session]` value outside its range ([Keys](#keys));
- a network (`scope.internal_networks`, a rule's `networks`,
  `password_gate.internal_networks`) is not a CIDR, or an `identity_domains`,
  `allowed_domains` or `users` entry is not a domain or login;
- a backend sets `client_ip` together with its short form (`proxy_protocol`, or
  `submission.xclient` for the submission backend), the submission backend sets both
  short forms, or `client_ip = "xclient"` is set on the IMAP or ManageSieve backend
  (XCLIENT is an SMTP extension); a backend whose `client_ip` is `none`, set or by default,
  is a warning;
- a protocol section has neither a `backend` nor a route that serves it, or both; a
  `backend` name or a route's `imap`/`submission`/`sieve` names no `[backends]` entry; a
  `[backends]` entry is used by two protocols, is named `imap`, `submission` or `sieve`
  (the names of the inline backends), or has an invalid name; more than 64 backends or
  256 routes; a route without `domains` and `issuers`, without a backend, with a
  duplicate or invalid name, an invalid domain, `"*"` next to another domain or in a route
  that is not the last, an issuer that is not an `oauth.issuers` entry, an empty `sni` or
  `audiences` entry, a backend for a protocol without its section, or a domain an earlier
  route with the same conditions already takes. A `[backends]` entry that nothing uses,
  and a route domain that no accepted issuer has in its `identity_domains` while every
  issuer sets them, are warnings ([Routes](#routes));
- a `submission.ehlo_extensions` entry is not an EHLO line, repeats a keyword or is `AUTH`
  or `STARTTLS` (an entry the proxy never advertises, or one with parameters, is a
  warning);
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
bind. A reload fails the same way for the JWKS of an issuer it adds ([Reload](#reload)).

## Reload

`systemctl reload mail-auth-proxy` (`SIGHUP`) reads the file again and checks it like
`--check-config`, warnings included. Every key can change this way except those that bind
a socket at startup:

- `imap.listen`, `submission.listen`, `submission.implicit_tls_listen` (added, removed or
  changed), `sieve.listen`;
- whether `[submission]` and `[sieve]` exist (a listener more or less);
- `metrics.enabled` and, while it is on, `metrics.listen`.

A file that changes one of them is refused as a whole with
`changed <key>: needs a restart`; restart the service for it. A file that does not parse,
fails validation, names a file that cannot be read, or adds an issuer whose JWKS cannot
be fetched is refused as well. A refused reload changes nothing: the configuration in use
stays complete, and the log says why ([operations.md](operations.md#signals-and-service-manager)).

A reload that succeeds applies to every connection accepted afterwards. A connection that
is already open keeps the configuration it was accepted with until it ends, and is never
closed by a reload: a stricter legacy rule, a lower limit or a shorter timeout does not
reach it. Before login that is at most `timeouts.preauth_secs`; after login no rule is
checked any more, and `[session]` limits apply as they were at its accept.

What runs across configurations is kept: open connections count against the new limits,
failed-login counts and blocks go on under the new `[auth_ratelimit]` settings (a source
the new settings exempt is free at once), the legacy throttle keeps its counts, a backend
that stays (same name and settings) keeps its cached capabilities and its learned
refusal timing, a backend that keeps its name keeps its counters and the health of each
address it keeps, and an issuer that stays (same `issuer` and
`jwks_url`) keeps its keys, read under its new rules. The JWKS of a new issuer is fetched
by the reload.

## File permissions

The service runs as the system user `mail-auth-proxy` in the group `mail-auth-proxy`. The
configuration, the TLS key, the doveadm key file and the legacy list files must be readable
by that group and by nobody else, for example `root:mail-auth-proxy` mode `0640`
(directories `0750`).

## Sections

| Section | Purpose |
|---|---|
| `[server]` | the name used in greetings and EHLO |
| `[tls]`, `[[tls.certificates]]` | the default certificate and key, and more certificates chosen by SNI |
| `[imap]`, `[submission]`, `[sieve]` | listener(s) and backend with its profile (`tls`, `client_ip`, `auth_forward`) per protocol; `[imap]` is required, omit `[submission]` or `[sieve]` to disable them (a restart, not a reload) |
| `[backends.<name>]` | named backends, for a section's `backend = "<name>"` or for routes |
| `[[routes]]` | which backend a credential goes to, by the domain of its identity or login ([Routes](#routes)) |
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

A backend is a table with the backend `.…` keys below: a section's own, written inline
(`backend = { address = "…" }`) or as `[imap.backend]`, or a named one,
`[backends.<name>]`, which the section names (`backend = "<name>"`) or routes choose. The column Reload says whether `systemctl reload` takes a change of the
key over (`yes`) or it needs a restart ([Reload](#reload)).

| Key | Type | Default | Reload | Effect |
|---|---|---|---|---|
| `config_version` | integer | required | — | must be `2`, set at the top before the first `[section]`; a file without it fails with `config_version is missing: the file must set config_version = 2 …` |
| `server.hostname` | string | `mail-auth-proxy` | yes | name in the IMAP/SMTP/Sieve greetings, EHLO replies and the backend EHLO. A host name as SMTP defines it (RFC 5321 §4.1.2): labels of letters, digits and hyphens separated by dots, 1-63 characters each without a hyphen at either end, at most 253 in all, no trailing dot. IP addresses and address literals (`[192.0.2.1]`) are refused, because the EHLO reply takes a domain only. A single label, the default included, gives a warning: the backend EHLO takes the fully-qualified primary host name (RFC 5321 §4.1.4, §2.3.5) |
| `tls.cert`, `tls.key` | path | required | yes | PEM chain and key of the default certificate: served to clients without SNI and to those that ask for one of its DNS names |
| `tls.certificates[].cert`, `.key` | path | none | yes | more certificates (`[[tls.certificates]]`, one table each), each served to clients that ask for one of its DNS names. Each must carry at least one DNS name ([TLS server names](#tls-server-names)) |
| `imap.listen` | `ip:port` | required | restart | implicit-TLS listener |
| `imap.backend` | backend or name | required without routes | yes | IMAP backend (`tls` default `implicit`): a table, or the name of a `[backends]` entry. Not with routes that serve IMAP |
| `submission.listen` | `ip:port` | section optional | restart | STARTTLS listener; omit the section to disable SMTP |
| `submission.implicit_tls_listen` | `ip:port` | unset | restart | a second submission listener with implicit TLS (port 465, RFC 8314 §3.3): TLS from the first byte, then the greeting and the same dialog, gate and backend as the STARTTLS listener. Logs and metrics tell the two apart (`listener`) |
| `submission.backend` | backend or name | required in section without routes | yes | submission backend (`tls` default `starttls`), as for `imap.backend` |
| `submission.xclient` | bool | `false` | yes | short form of `client_ip = "xclient"` on every submission backend; `--print-config` shows `client_ip` |
| `submission.ehlo_extensions` | array | unset | yes | the most the EHLO reply after STARTTLS may list, by keyword. The reply lists the extensions the proxy handles (`PIPELINING`, `SIZE`, `8BITMIME`, `SMTPUTF8`, `DSN`, `ENHANCEDSTATUSCODES`, `CHUNKING`) that every submission backend offers in its own EHLO reply, with the first backend's parameters and the smallest `SIZE` ([routes](#routes)); this list narrows them further. Each entry is an EHLO line (RFC 5321 §4.1.1.1): a keyword of letters, digits and hyphens that does not start with a hyphen, then optional parameters of printable ASCII, all separated by single spaces; each keyword once (case-insensitive); not `AUTH` or `STARTTLS`. Parameters are ignored (warning), as is a keyword the proxy never passes on (warning). |
| `submission.capability_cache_secs` | integer | 600 | yes | reuse of each backend's EHLO extensions, read by a probe connection; ≥ 1 |
| `sieve.listen` | `ip:port` | section optional | restart | STARTTLS listener; omit the section to disable ManageSieve |
| `sieve.backend` | backend or name | required in section without routes | yes | ManageSieve backend (`tls` default `starttls`), as for `imap.backend` |
| `sieve.capability_cache_secs` | integer | 600 | yes | reuse of each backend's capability list; ≥ 1 |
| `backends.<name>` | backend | none | yes | a named backend; the name (1-64 of `A-Z a-z 0-9 . _ -`, not `imap`, `submission` or `sieve`) is logged as `backend=` and used for the refusal timing. Serves the one protocol that names it; its `tls` default is that protocol's |
| `routes[].name` | string | required | yes | unique, 1-64 of `A-Z a-z 0-9 . _ -` |
| `routes[].domains` | array | none | yes | domains of the identity (OAuth) or login (password), exact in canonical form ([Domain names](#domain-names)), no subdomains; `"*"` alone, in the last route only, takes every domain and a login without one |
| `routes[].issuers` | array | any | yes | OAuth: the issuer of the token is one of these `oauth.issuers[].issuer`. A route with `issuers` and without `domains` takes tokens of those issuers whatever the identity, and no password |
| `routes[].sni` | array | any | yes | the name the client asked for (SNI) is one of these; without SNI the route does not match |
| `routes[].audiences` | array | any | yes | OAuth: the token's `aud` contains one of these, binding a token to the backend it was issued for |
| `routes[].imap`, `.submission`, `.sieve` | name | none | yes | the `[backends]` entry of each protocol the route serves |
| backend `.address` | `host:port` | required, or `addresses` | yes | where to connect |
| backend `.addresses` | array of `host:port` | none | yes | several addresses of one backend, a pool ([Backend pools](#backend-pools)); at most 16, each once; not together with `address` |
| backend `.strategy` | `failover` \| `hash` \| `round_robin` | `failover` | yes | how a login's address is chosen from `addresses`: the first that is up in the listed order; by a rendezvous hash of the identity or login (local part in lower case, domain in canonical form, [Domain names](#domain-names)), so a user stays on one address while it is up; or in turn |
| backend `.health_check_secs` | integer | off | yes | active health checks: every that many seconds (1-3600) each address gets the dialog of a login up to the greeting and capabilities, without a credential (with a PROXY `LOCAL` header where the backend takes one) |
| backend `.verify_name` | string | host of each address | yes | name verified on the backend certificate |
| backend `.ca_file` | path | system store | yes | PEM CAs the backend certificate must chain to; replaces the system store for this backend |
| backend `.tls` | `starttls` \| `implicit` | `implicit` for IMAP, `starttls` for submission and ManageSieve | yes | how the proxy secures its connection to the backend. `starttls`: the plaintext greeting, then STARTTLS (IMAP RFC 9051 §6.2.1, SMTP RFC 3207, ManageSieve RFC 5804 §2.2); what the backend offered before TLS is discarded and asked again over TLS. `implicit`: TLS from the first byte (RFC 8314). Either way the certificate is verified. The EHLO and capability probes take the same way |
| backend `.auth_forward` | `xoauth2` \| `oauthbearer` | `xoauth2` | yes | the SASL mechanism a validated token is forwarded with, whatever the client used. `oauthbearer` (RFC 7628): the verified identity as GS2 authzid, the backend's `verify_name` (or the host of the address it connects to) as `host` and that address's port as `port`. Passwords always go as PLAIN |
| backend `.client_ip` | `proxy_v2` \| `xclient` \| `none` | from the short forms, else `none` | yes | how the backend learns the client address: a PROXY protocol v2 header before anything else (the backend listener must require it; the proxy's own probe connections send a LOCAL header), the SMTP XCLIENT command (submission only, sent when the backend advertises it), or nothing. With `none` the backend sees the proxy's address for every client: its per-address rate limits, bans and logs treat all clients as one, and a ban there locks everyone out; warning. A submission backend that advertises XCLIENT to the proxy while `client_ip` is not `xclient` is a misconfiguration: every login is an outage (454) until it is set or the proxy is removed from `smtpd_authorized_xclient_hosts`, because the client could otherwise send its own XCLIENT after login |
| backend `.proxy_protocol` | bool | `false` | yes | short form of `client_ip = "proxy_v2"`; `--print-config` shows `client_ip` |
| backend `.account_check` | `none` \| `doveadm` | that of `[legacy]` | yes | the legacy gate's account check for passwords routed to this backend: none, or a doveadm userdb lookup with this backend's `doveadm_url`, `doveadm_key_file` and `doveadm_ca_file` (the same rules as the `legacy.doveadm_*` keys), one for all the backend's `addresses`. With several backends behind a protocol, one that inherits `legacy.account_check = "doveadm"` gives a warning: that doveadm would judge the other mail systems' accounts too |
| backend `.doveadm_url`, `.doveadm_key_file`, `.doveadm_ca_file` | | none | yes | as `legacy.doveadm_*`, for the backend's own `account_check = "doveadm"` |
| `oauth.refresh_secs` | integer | 300 | yes | periodic JWKS refresh; 1-86400. Unknown key ids trigger a refresh sooner, but a key removed from the JWKS is dropped only by this one |
| `oauth.leeway_secs` | integer | 60 | yes | clock skew on `exp`/`nbf`; 0-300 (RFC 7519 §4.1.4 allows a small leeway, "usually no more than a few minutes") |
| `oauth.issuers[].issuer` | string | required | yes | exact `iss`; keys from this issuer's JWKS are accepted only with it |
| `oauth.issuers[].jwks_url` | URL | required | yes | https (http only for localhost) |
| `oauth.issuers[].audiences` | array | required | yes | the token's `aud` must contain one |
| `oauth.issuers[].token_type` | `keycloak` \| `rfc9068` \| `any` | required | yes | access-token marker: claim `typ=Bearer`, header `typ=at+jwt`, or none (warning) |
| `oauth.issuers[].identity_claim` | string | `email` | yes | claim forwarded to the backend as the login; one word, and one plain address for `email` |
| `oauth.issuers[].require_email_verified` | bool | on for `email` | yes | require `email_verified = true` |
| `oauth.issuers[].allowed_algorithms` | array | RS256/384/512, PS256/384/512, ES256, ES384 | yes | keys are used only with these |
| `oauth.issuers[].infer_key_algorithm` | bool | `true` | yes | a JWKS key without `alg` is used with the one algorithm its type implies (ES256 for P-256, ES384 for P-384, RS256 for RSA); off: such keys are skipped |
| `oauth.issuers[].allowed_clients` | array | empty (any) | yes | accepted values of `client_claim` |
| `oauth.issuers[].identity_domains` | array | empty (any) | yes | the domains this issuer may log in to: the identity must be an address in one of them (canonical form, [Domain names](#domain-names), no subdomains), otherwise the token is a `bad_token`. With more than one issuer, each issuer without it gives a configuration warning, because it can log in to the other issuers' mailboxes |
| `oauth.issuers[].client_claim` | string | `client_id` for `token_type = "rfc9068"` (RFC 9068 §2.2), otherwise `azp` | yes | claim naming the OAuth client |
| `oauth.issuers[].openid_configuration_url` | URL | unset | yes | https only (also for `localhost`), no `user:password@`, no fragment. Sent as `openid-configuration` in the error result a client gets for a rejected token (RFC 7628 §3.2.2), so it can find the IdP. Warning when it is not `<issuer>/.well-known/openid-configuration` |
| `oauth.issuers[].scope` | string | unset | yes | sent as `scope` in the same error result: the scope a client must request for mail. RFC 6749 scope tokens separated by single spaces; several scopes give a warning (RFC 7628 recommends one) |
| `scope.internal_networks` | array of CIDR | empty (default: the `[password_gate]` networks) | yes | label `scope=internal` in logs and metrics; allows nothing |
| `legacy.rules[].name` | string | required | yes | unique, 1-64 of `A-Z a-z 0-9 . _ -`; logged as `rule=` |
| `legacy.rules[].networks` | array of CIDR | required | yes | client source networks; the rule's security boundary |
| `legacy.rules[].sni` | array | any SNI (also none) | yes | names the client must have asked for; each should be a name of a configured certificate ([TLS server names](#tls-server-names)) |
| `legacy.rules[].users` | array | any user | yes | `user@domain` (local part exact, domain in canonical form) or `*@domain` |
| `legacy.rules[].users_file` | path | none | yes | more `users` entries, one per line, `#` comments; re-read on change |
| `legacy.rules[].protocols` | `imap` \| `submission` \| `sieve` | all | yes | protocols the rule applies to |
| `legacy.rules[].mechanisms` | `PLAIN` \| `LOGIN` | both | yes | `LOGIN` also covers the IMAP LOGIN command |
| `legacy.rules[].public` | bool | `false` | yes | required when `networks` contain a public range (anything but RFC 1918, loopback, link-local, ULA; `0.0.0.0/0` and `::/0` included) and the rule has no `users`/`users_file`; gives a warning |
| `legacy.allowed_domains` | array | none | yes | domains whose logins may use passwords; [Domain names](#domain-names) |
| `legacy.domains_file` | path | none | yes | more allowed domains, one per line, `#` comments; re-read on change |
| `legacy.account_check` | `none` \| `doveadm` | `none` | yes | check that the account exists before the password is forwarded; for every backend that sets no `account_check` of its own |
| `legacy.doveadm_url` | URL | required with `doveadm` | yes | doveadm HTTP API endpoint (`…/doveadm/v1`); https, http only for localhost; no `user:password@` |
| `legacy.doveadm_key_file` | path | required with `doveadm` | yes | file with the `doveadm_api_key` |
| `legacy.doveadm_ca_file` | path | system store | yes | PEM CAs for the doveadm certificate |
| `legacy.throttle` | `{ failures, window_secs }` | off | yes | per account: after `failures` backend rejections within `window_secs`, refuse locally until the window ends; both ≥ 1 |
| `legacy.failure_delay_ms` | integer | 2000 | yes | minimum time from credential to a failed legacy reply (refusals also follow the median backend-rejection latency; jitter added); ≤ 10000, 0 gives a warning |
| `password_gate.enabled` | bool | `false` | yes | short form: one rule `password_gate` |
| `password_gate.sni` | array | required when enabled | yes | the rule's `sni` |
| `password_gate.internal_networks` | array of CIDR | required when enabled | yes | the rule's `networks` (with `public = true` if one is public), and the scope label when `[scope]` is absent, even with the gate off; every public network gives the same warning as a rule with `public = true`; not combinable with `[[legacy.rules]]` |
| `limits.max_connections` | integer | 2048 | yes | global cap, at most half unauthenticated; ≥ 1 |
| `limits.max_preauth_per_ip` | integer | 32 | yes | unauthenticated connections per IP; ≥ 1. IPv4 (also IPv4-mapped) counts per address, IPv6 per `limits.ipv6_source_prefix` (one host usually holds a whole /64) |
| `limits.ipv6_source_prefix` | integer | 64 | yes | prefix length by which IPv6 sources are grouped for `max_preauth_per_ip` and `[auth_ratelimit]`; 32-64. 48 makes a whole site (a typical /48 assignment) one source, so an attacker cannot rotate through its /64s |
| `limits.max_preauth_commands` | integer | 8 | yes | commands before authentication; ≥ 1 |
| `limits.max_auth_attempts` | integer | 3 | yes | authentication attempts per connection, 1-10; 1 closes after the first refusal. Each is judged, logged and counted by the rate limit on its own; warns when larger than `max_preauth_commands` |
| `timeouts.preauth_secs` | integer | 60 | yes | accept to credential, in total; 1-3600 |
| `timeouts.idle_secs` | integer | 30 | yes | silence on any single read; 1-3600 |
| `timeouts.connect_secs` | integer | 10 | yes | backend connect, TLS handshake, PROXY header; 1-3600 |
| `metrics.enabled` | bool | `false`; `true` if only `listen` is set | restart | serve the Prometheus endpoint |
| `metrics.listen` | `ip:port` | required when enabled | restart | Prometheus endpoint, no authentication (warning if not loopback); must not clash with a mail listener |
| `auth_ratelimit.enabled` | bool | `true` | yes | block sources with too many failed logins ([architecture.md](architecture.md#failed-login-rate-limit)) |
| `auth_ratelimit.failures` | integer | 20 | yes | counted failures of one source (IPv4 address, IPv6 network of `limits.ipv6_source_prefix`, by default /64) that start a block; ≥ 1. A repeated identical credential counts once |
| `auth_ratelimit.window_secs` | integer | 600 | yes | window in which the failures are counted, from the first one; 1-86400 |
| `auth_ratelimit.block_secs` | integer | 900 | yes | length of the first block; 1-86400 |
| `auth_ratelimit.max_block_secs` | integer | 86400 | yes | each further block of the same source doubles up to this; `block_secs` to 604800. Equal to `block_secs`: no escalation |
| `auth_ratelimit.exempt_internal` | bool | `false` | yes | never count sources in `scope.internal_networks` |
| `auth_ratelimit.exempt_networks` | array of CIDR | `["127.0.0.0/8", "::1/128"]` | yes | sources that are never counted, e.g. a webmail server or a NAT gateway through which many users log in; a public network gives a warning. An empty list exempts nothing, not even loopback |
| `session.keepalive_idle_secs` | integer | 600 | yes | TCP keepalive on every client and backend connection, from accept or connect: silence before the first probe; 1-32767 (the Linux maximum) |
| `session.keepalive_interval_secs` | integer | 60 | yes | time between unanswered probes; 1-32767 |
| `session.keepalive_count` | integer | 5 | yes | unanswered probes before the kernel drops the connection; 2-127 (RFC 9293 §3.8.4: one lost probe must not end a connection). With the defaults a dead peer is dropped after at most 15 minutes of silence |
| `session.idle_limit_secs` | integer | off | yes | after login: close the session after this long without a byte in either direction; 1-2592000. Below 1800 gives a warning: IMAP and ManageSieve clients may rely on at least 30 minutes (RFC 9051 §5.4, RFC 5804 §1.2), and IDLE clients re-issue IDLE only every 29 minutes (RFC 9051 §6.3.13) |
| `session.max_session_secs` | integer | off | yes | after login: close the session this long after the login, busy or not; 1-2592000; below 1800 gives the same warning |

## Routes

Without `[[routes]]` each protocol has the one backend of its section. With routes, a
protocol whose section has no `backend` sends each credential to the backend of the first
route, in file order, that serves the protocol and whose conditions all hold:

- the domain of the validated identity (OAuth) or of the login (password) is in
  `domains`, or `domains` is `["*"]`, or the route has no `domains` and the credential is
  a token of one of its `issuers`;
- a token's issuer is in `issuers` and its `aud` contains one of `audiences`, where set
  (a password is routed by its domain alone);
- the client's SNI is in `sni`, where set.

The SNI only narrows a route, never picks one: it is chosen by the client, and a token
sent to another tenant's backend could open an account there. `identity_domains` stays
the issuers' trust boundary; routes only decide where an identity lives.

A credential that no route takes is refused like an unknown domain: the `authresult`
reason is `unknown_domain`, the reply that of a wrong password (for passwords with the
same delay) or of a token the backend rejected, and the backend is not contacted. A
`WARN … no route for the login's domain` line names the domain, and
`mail_auth_proxy_route_misses_total` counts it. For passwords the route is looked up after
the domain gate and before the account check.

Before the credential the client sees capabilities that must hold for whichever backend it
is routed to: the SMTP EHLO reply lists the extensions that every submission backend
offers, with the smallest `SIZE`; the ManageSieve capabilities are those all ManageSieve
backends have, `SIEVE` and `NOTIFY` narrowed to their common extensions and
`MAXREDIRECTS` the smallest. For SMTP a backend that has never answered a probe offers
nothing; for ManageSieve it is left out until it answers (after AUTHENTICATE the client
gets its own backend's list, RFC 5804 §1.7), since an empty list would drop the `SASL`
line for everyone. IMAP
shows the proxy's own list before login and the backend's after it.

```toml
[imap]
listen = "0.0.0.0:993"

[backends.dovecot]
address = "192.0.2.10:993"
client_ip = "proxy_v2"

[backends.stalwart]
address = "192.0.2.20:993"
auth_forward = "oauthbearer"
client_ip = "proxy_v2"

[[routes]]
name = "example"
domains = ["example.org", "example.net"]
imap = "dovecot"

[[routes]]
name = "partner"
domains = ["partner.example"]
issuers = ["https://sso.partner.example/realms/mail"]
imap = "stalwart"
```

## Backend pools

A backend with `addresses` is a pool of servers that serve the same mailboxes with the same
configuration; the capability caches are kept per backend, not per address. Each login
takes the addresses in the order of `strategy`, those that are down after those that are
up, the longest-failed first:

- **Before the credential** (TCP connect, PROXY header, TLS handshake, greeting, STARTTLS,
  EHLO, capabilities) an address that fails gives way to the next, at most 3 addresses per
  login, all within the pre-auth budget. A login that succeeds on another address than the
  first it tried counts in `mail_auth_proxy_backend_failovers_total`.
- **After the credential** a reply without a verdict (IMAP `NO [UNAVAILABLE]`, SMTP `4xx`,
  ManageSieve `NO (TRYLATER)`, a timeout) ends the login as an outage: the credential goes
  to one server once, never to a second one. It counts as `auth_tempfail` for the address.
- An outage is never a failed login: the client gets the retry-later reply, no `authresult`
  line is written, and `mail_auth_proxy_backend_errors_total` counts it.

Health is kept per address. 3 failures in a row before the credential mark an address
down, 2 successes in a row up again (haproxy's defaults for `fall` and `rise`). The
logins and the SMTP and ManageSieve capability probes are the checks; with
`health_check_secs` the proxy also checks every address on its own. A down address is
tried only after all that are up have failed, and by one login or check at a time; when
every address is down and each is being tried, a login gets the retry-later reply at once.
Without active checks a standby that came back shows as down until a login needs it.

The account check belongs to the backend, not to an address: one `account_check` and one
`doveadm_url` for all its addresses, which serve the same mailboxes from one userdb. The
doveadm endpoint is not part of the pool: it is neither failed over nor health-checked, and
while it is unreachable password logins to the backend are outages.

A reload keeps the health of each address the backend keeps, and the counters of a backend
that keeps its name.

```toml
[backends.store]
addresses = ["192.0.2.10:993", "192.0.2.11:993"]
strategy = "hash"                  # users stay on one server
health_check_secs = 10
verify_name = "imap.example.org"
client_ip = "proxy_v2"
```

## Domain names

Every domain is compared in one canonical form: `allowed_domains`, `domains_file`, the
domains of `users` and `users_file`, `routes[].domains`, `identity_domains`, the `sni` lists
of rules, routes and `[password_gate]`, the domain of a login or token identity, the
OAUTHBEARER `host` and the TLS server name. The form is UTS #46 ToASCII (IDNA, RFC 5890,
RFC 5891): Unicode labels become A-labels (Punycode), letters lower case, one trailing dot
dropped. So `Exämple.ORG.`, `exämple.org` and `xn--exmple-cua.org` are one domain, in the
configuration, in a list file and in a login alike.

- A configured name that has no canonical form (an underscore, a label over 63 octets, a
  name over 253, an empty label, a hyphen at either end of a label, invalid Punycode) is a
  validation error under its key; in a list file it makes the file invalid, which closes
  its rule or the domain gate as any invalid entry does.
- A login whose domain has none matches no domain: the domain gate refuses it as
  `unknown_domain`, no `users` entry with a domain and no route takes it.
- Only the domain is canonical. The local part is compared as written (case included,
  except in the `authzid` check, the throttle and the `hash` pool strategy, which fold it), and the login the backend
  gets, like the one in the log, stays byte for byte what the client sent: whether two
  spellings are one mailbox is the mail server's decision.
- The throttle counts, and the `hash` pool strategy chooses, per account in the form
  `local part in lower case @ canonical domain`, so the spellings of one address share one
  count and one address.

## TLS server names

The names a client may ask for with SNI (RFC 6066 §3) are the DNS names in the
subjectAltName of the configured certificates; there is no separate list. For a client
that sends SNI the proxy serves:

1. the first certificate (`tls.cert`, then `tls.certificates` in order) that carries the
   name itself;
2. else the first one with a wildcard for it: `*.example.org` covers exactly one leftmost
   label, so `imap.example.org` but neither `example.org` nor `a.b.example.org`
   (RFC 9525 §6.3). A wildcard needs two labels after `*.`; `*.org` covers nothing.

Names compare in canonical form ([Domain names](#domain-names)): letter case and a trailing
dot do not matter, a configured U-label equals the client's A-label. The subject CN is not a
name (RFC 9525 §2), nor is an IP address in the subjectAltName.

A client that sends no SNI (it connected by IP address) gets the default certificate
`tls.cert`. A client that asks for a name no certificate carries is refused in the
handshake with the fatal alert `unrecognized_name`, before any certificate is sent
(RFC 9325 §3.7: the server SHOULD NOT continue). So `legacy.rules[].sni` and the
OAUTHBEARER `host` check only ever see names of the proxy.

`--check-config` loads every pair and reports each unusable one under its own key, and a
certificate in `tls.certificates` without a DNS name (only SNI selects it). It warns when
the default certificate has no DNS name (then every client that sends SNI is refused) and
when a `legacy.rules[].sni` name is carried by no certificate (a client asking for it is
refused, so the rule never matches with it). At startup the log line `TLS server names`
lists every name.

```toml
[tls]
cert = "/etc/mail-auth-proxy/tls/example.org.pem"      # mail.example.org, no SNI
key = "/etc/mail-auth-proxy/tls/example.org.key"

[[tls.certificates]]
cert = "/etc/mail-auth-proxy/tls/example.net.pem"      # mail.example.net
key = "/etc/mail-auth-proxy/tls/example.net.key"

[[tls.certificates]]
cert = "/etc/mail-auth-proxy/tls/wildcard.pem"         # *.example.com
key = "/etc/mail-auth-proxy/tls/wildcard.key"
```

Environment: `RUST_LOG` (log filter, default `info`; see [operations.md](operations.md#logging)).

How the legacy keys act together is described in [architecture.md](architecture.md#legacy-gate),
the token keys in [architecture.md](architecture.md#oauth-token-validation), and a worked
Keycloak example in [idp-keycloak.md](idp-keycloak.md).
