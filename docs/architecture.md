# Architecture

This document covers the parts every protocol shares. The per-protocol dialogs are in [protocols.md](protocols.md), every configuration key in [configuration.md](configuration.md), and logs, metrics and signals in [operations.md](operations.md). It is written from the source in `src/` and checked with the black-box tests in `tests/`; where it and the code disagree, the code wins.

The proxy terminates client TLS for three protocols and runs each protocol's dialog only until the client presents a credential. It then decides whether that credential may be used, logs in to the backend (Dovecot or Postfix) with the client's own credential, and relays bytes without interpreting them. It never holds a master credential. OAuth bearer tokens are validated locally against JWKS keys, never by introspection at the IdP.

| Protocol | Client side | Backend side |
|---|---|---|
| IMAP | implicit TLS on `imap.listen` | implicit TLS to `imap.backend`, optional PROXY protocol v2 |
| SMTP submission | plaintext + STARTTLS on `submission.listen` | plaintext + STARTTLS to `submission.backend`, optional XCLIENT |
| ManageSieve | plaintext + STARTTLS on `sieve.listen` | plaintext + STARTTLS to `sieve.backend`, optional PROXY protocol v2 |

## Request flow

```
client ──TLS──▶ mail-auth-proxy ─────────────────────────────TLS (verified)──▶ backend
                 1. accept: failed-login block of the source, connection limits
                 2. TLS handshake, SNI noted
                 3. greeting / capabilities: OAuth mechanisms always, PLAIN/LOGIN only
                    where a legacy rule matches source address, SNI and protocol
                 4. read AUTHENTICATE / AUTH / LOGIN (one attempt per connection)
                 5a. OAuth: validate the JWT locally ──────── JWKS (cached, refreshed) ◀── IdP
                 5b. password: legacy gate (rule, domain, account check, throttle)
                 6. connect to the backend, pass the client address (PROXY v2 / XCLIENT),
                    log in with the same token (as XOAUTH2) or the same password (as PLAIN)
                 7. relay the backend's verdict; on success relay bytes until either side closes
```

Each connection is one tokio task. Connections share only the JWKS key set, the server certificate, the ManageSieve capability cache, the legacy gate's caches and counters, the connection limits, the failed-login counters and the metrics. Trust boundaries and the threat model are in [SECURITY.md](../SECURITY.md#trust-boundaries).

## Startup

- The configuration is validated before anything else; an error aborts the start, and warnings are logged. File paths (`tls.cert`, `tls.key`, `ca_file`, `domains_file`, `doveadm_key_file`, `doveadm_ca_file`, `users_file`) must be absolute: a relative path would resolve against the working directory, so `--check-config` in a shell could pass on files the service never reads. A relative path is a validation error.
- The two per-process HMAC keys, for the password fingerprint (`pwfp`) and for the rate limit's fingerprints of repeated credentials, are generated from the system RNG before the certificate, the JWKS and the listeners. Without a system RNG the proxy refuses to start. The keys are never written anywhere; a restart makes new ones.

## Client TLS

- rustls with the aws-lc-rs provider. TLS 1.2 and TLS 1.3 use rustls' default cipher suites. There is no ALPN and no client-certificate authentication.
- One certificate chain (`tls.cert`, `tls.key`) is served for every SNI name. A legacy rule with `sni` is only usable if that certificate covers both the public name and the rule's names.
- The SNI is read after the handshake and used only by the legacy rules ([legacy gate](#legacy-gate)). A client that sends no SNI matches only rules without `sni`. Clients that connect by IP address never send SNI.

## Line reading

Every line read before authentication, from the client and from the backend, goes through the same reader:

- It reads byte by byte up to `\n`, drops `\r`, and requires valid UTF-8. Invalid UTF-8 closes the connection.
- A line may be at most 16384 bytes, counting every byte consumed, bare CRs included. A longer line closes the connection.
- Each single read has an idle timeout of `timeouts.idle_secs` (default 30 s).

The reader never reads past `\n`, so bytes a client pipelines after `STARTTLS` stay in the socket, are fed to the TLS acceptor, and make the handshake fail. This closes the STARTTLS command-injection class (CVE-2011-0411); a black-box test covers it.

## Legacy gate

OAuth and legacy logins take separate paths. OAuth (XOAUTH2, OAUTHBEARER) depends only on local token validation ([OAuth token validation](#oauth-token-validation)); nothing in this section applies to it. Legacy logins (PLAIN, SASL LOGIN, the IMAP LOGIN command) carry a password that only the backend checks; the proxy decides whether to pass it on. Without `[[legacy.rules]]` every endpoint is OAuth-only.

### Offered mechanisms

On each connection, PLAIN and LOGIN are advertised as far as at least one rule matches the connection:

```
rule matches a connection  ⇔  source IP ∈ networks (IPv4-mapped IPv6 canonicalised first)
                              AND  (no sni  OR  SNI equals one of sni, ASCII case-insensitive, exact)
                              AND  (no protocols  OR  protocol ∈ protocols)
offered mechanisms         =  union of the matching rules' mechanisms (default PLAIN and LOGIN)
```

IMAP advertises `LOGINDISABLED` whenever LOGIN is not offered (the LOGIN command counts as the LOGIN mechanism). ManageSieve never offers LOGIN. SMTP offers LOGIN only together with PLAIN (draft-murchison-sasl-login §1).

### Checks on a password attempt

A password the client has sent is always parsed, even when its mechanism is not advertised, so the attempt can be logged with a password fingerprint: the IMAP `LOGIN` command and a PLAIN initial response carry it. A mechanism the connection does not offer is never asked for its password: without an initial response (SASL LOGIN: after the username in the initial response) it is refused at once as `blocked_endpoint`, without `pwfp`. The checks then run in this order, all before any backend contact:

| Step | Check | Refused as |
|---|---|---|
| 0 | the connection offers this mechanism | `blocked_endpoint`, reply "not available on this endpoint" |
| | the password is at most 1024 bytes | `oversize` |
| | the login is not empty, at most 255 bytes, has no control characters and at most one `@` | `unknown_account` |
| 1 | a rule matches connection, mechanism and user (`users`, `users_file`: `user@domain` or `*@domain`; the local part is compared exactly, the domain ignoring ASCII case). The first matching rule in file order decides and is logged. | `blocked_endpoint` |
| 2 | the login's domain is in `allowed_domains` ∪ `domains_file` (only if either is set; a login without `@domain` fails) | `unknown_domain` |
| 3 | the account exists (`account_check = "doveadm"`) | `unknown_account` |
| 4 | the account is not throttled (`throttle`) | `throttled` |
| | the backend checks the password; a protocol error in direct answer to the password (SMTP `500` to `509` after the response to `334`, IMAP tagged `BAD`) also counts as a rejection; a reply to the bare SMTP `AUTH` line, an IMAP `* BYE` or a ManageSieve `BYE` (other than `AUTH-TOO-WEAK`, `TRANSITION-NEEDED`) is an outage | `backend_reject` |

The size cap and the protocol-error rule close an enumeration oracle. A backend may answer a crafted password with a protocol error (Postfix does beyond `smtpd_sasl_response_limit`, 12288 octets), and it only ever sees passwords of accounts that passed the gate. An immediate retry-later there, next to a delayed refusal for the other accounts, would tell the two groups apart.

### Refusal replies and timing

The size check, steps 1 to 4 and a wrong password all give the client the protocol's wrong-password reply, and their timing is made alike:

- A refusal by the gate is answered after the larger of `legacy.failure_delay_ms` (default 2000, Dovecot's default `auth_failure_delay`) and the median latency of the last 32 backend rejections of the same protocol (capped at 10 s), counted from the credential.
- A backend rejection is answered no earlier than `failure_delay_ms` after the credential.
- Both get the same random jitter: up to a quarter of that time, at least 50 ms, at most 1 s.
- An outage on the password path (account check or backend unavailable) is answered with retry-later no earlier than a refusal, with the same jitter. Outages only reach accounts that passed the earlier steps, so an instant answer would identify them.

The log still keeps the cases apart (`reason`, `rule`).

Keep the backend's own failure delay enabled behind the proxy (Dovecot `auth_failure_delay`): it slows down guessing at the backend, and the proxy pads its refusals to it. After a start, until the proxy has seen backend rejections of a protocol, refusals use `failure_delay_ms` alone, so set it close to the backend's delay.

### Account check

A userdb lookup over the Dovecot doveadm HTTP API (Dovecot 2.4): `POST <doveadm_url>` with `Authorization: X-Dovecot-API <base64 of the API key>` and `[["user", {"userMask": "<login>", "userdbOnly": true}, "u"]]`. `doveadmResponse` means the user exists; `error` with `exitCode` 67 (EX_NOUSER) means it does not.

Any other answer, an HTTP error, a TLS failure or a timeout (`timeouts.connect_secs`) is an outage: the client gets the retry-later reply, `mail_auth_proxy_backend_errors_total` counts it, no `authresult` line is written and the password is not forwarded.

- Answers are cached (existing 120 s, missing 30 s, at most 10 000 logins); outages are not cached.
- Logins containing `*` or `?` are never sent (doveadm would list matching users) and count as unknown.
- TLS is verified against the system store or `doveadm_ca_file`. Plain http is allowed only to localhost. A URL with `user:password@` is refused; the key belongs in `doveadm_key_file`. The Authorization header is marked sensitive.

Sources: doc.dovecot.org 2.4.5 "Doveadm → HTTP API" and the `user` command in "All Doveadm Commands".

### Throttle

Each backend rejection counts against the account for `window_secs` from its first failure. The key is the login folded to ASCII lower case, so `Bob@x` and `bob@x` share one counter. Once `failures` is reached, further attempts are refused without asking the backend until the window ends. A successful login resets the count. Password attempts for one account take turns: the next one is checked only after the previous one has its backend verdict counted, so parallel connections cannot run more attempts than `failures` allows. Correct passwords wait at most for one backend answer; nothing is refused because of parallel logins. At most 65 536 accounts are tracked. When a new account finds the table full, expired entries are dropped first, then the oldest running ones, down to 1,024 below the limit, so the scan under the lock runs once per 1,024 new accounts; the running windows dropped are counted in `mail_auth_proxy_legacy_throttle_evictions_total`. Only rejections of existing accounts are counted, so unknown names do not fill the table.

### User and domain files

`users_file` and `domains_file` hold one entry per line; blank lines and lines starting with `#` are ignored. They are read at startup; an unreadable or invalid file aborts startup and fails `--check-config`. A background task re-reads a file when its modification time, size or inode changes, checked every 2 seconds.

A file that becomes missing, unreadable or invalid **fails closed**: a rule with that `users_file` matches nobody (its inline `users` included), and a broken `domains_file` closes the domain gate (inline `allowed_domains` included). This is logged at `ERROR`, counted in `mail_auth_proxy_legacy_list_errors_total`, and retried on every check until the file is fixed, so a broken update can never keep a revoked entry alive.

### Login names

The gate compares the login the client sent and assumes the backend uses that same login as the account name. An `auth_username_format` that strips the domain or otherwise maps several logins to one account breaks this: the domain gate, user lists and throttle then see a different name than the backend.

### Scope label

A source IP in `scope.internal_networks` counts as `scope=internal`, whatever the SNI and the rules. The label feeds logs and metrics and grants nothing.

### `[password_gate]`

`[password_gate]` (`enabled`, `sni`, `internal_networks`) is the short form of one rule named `password_gate` with those networks and names (all protocols, mechanisms and users), plus the scope label from `internal_networks` when `[scope]` is absent. It can be combined with `[legacy]` settings (domains, account check, throttle) but not with `[[legacy.rules]]`. `--print-config` shows the rule form.

## SASL mechanisms

| Mechanism | Client → proxy | Proxy → backend |
|---|---|---|
| `XOAUTH2` | `user=<u>^Aauth=Bearer <jwt>^A^A`. The scheme `Bearer` is case-insensitive and `user=` must not be empty. | `XOAUTH2` rebuilt as `user=<validated identity claim>^Aauth=Bearer <same jwt>^A^A` |
| `OAUTHBEARER` | GS2 header `n,a=<authzid>,` or `y,…` (the authzid is optional: `n,,`; `=2C` and `=3D` in it stand for `,` and `=`; `p=` channel binding is refused), then `^A`-separated fields with `auth=Bearer <jwt>`. A `host=` must match the TLS server name when the client sent SNI (RFC 7628 §3.2; ASCII case-insensitive, a trailing dot ignored), otherwise the token counts as rejected (`bad_token`). `port=` is ignored. | converted to `XOAUTH2` as above |
| `PLAIN` | `authzid\0authcid\0passwd`. User and password must be non-empty, and the password must not contain a NUL (RFC 4616 §2). The login is the authcid; a non-empty authzid must equal it, otherwise the exchange fails (acting as another user is not supported). | `PLAIN` rebuilt as `\0<login>\0<passwd>` (empty authzid) |
| `LOGIN` | Two base64 prompts (`Username:`, `Password:`). An initial response on the AUTH line is the username; then only the password is asked for. Neither field may contain a NUL. IMAP and SMTP only. | sent as `PLAIN` |

A SASL user the client names (XOAUTH2 `user=`, OAUTHBEARER `a=`) longer than 255 bytes or with control characters makes the response malformed. An OAuth response whose `auth` value is empty (`auth=`, or `Bearer` without a token) is a discovery request (RFC 7628 §4.3): it gets the error result of a rejected token ([protocols](protocols.md#oauth-error-result)), is logged as `protocol` and counts as no failed login.

For OAuth, the login forwarded to the backend is always the token's `identity_claim` (default `email`). The username the client supplies (XOAUTH2 `user=`, OAUTHBEARER `a=`, the SASL authorisation identity) is logged when validation fails. Once the token is valid, that username must be empty, name the same identity, or be its local part without a domain (ASCII case-insensitive). Any other name fails the exchange with `authzid_mismatch` before the backend is contacted (RFC 4422 §3.6).

### Credentials in memory

Passwords, bearer tokens and the SASL responses that carry them are held in buffers that are overwritten with zeros when they are dropped (the [`zeroize`](https://crates.io/crates/zeroize) crate):

- every client line before authentication (an IMAP `LOGIN` line or an `AUTHENTICATE`/`AUTH` line can carry the credential), including the buffers it outgrew while being read;
- the SASL response lines, their base64-decoded bytes (also when decoding fails half-way), the unquoted ManageSieve response and literal;
- the parsed password or token;
- the `XOAUTH2` or `PLAIN` response rebuilt for the backend, in raw and base64 form, and the command line that carries it.

The credential is dropped right after the backend login, before the session is relayed. Types that hold one print `<redacted>` in `Debug`, and error texts name neither the credential nor a byte of its base64 encoding; the log keeps only the keyed password fingerprint (`pwfp`).

This narrows how long a credential stays in the proxy's heap. It does not remove every copy, and some are out of the proxy's reach:

- the TLS libraries: rustls keeps decrypted client data and the plaintext written to the backend in its own buffers, and tokio's TLS stream and the kernel's socket buffers hold them before encryption and after decryption;
- token validation: `jsonwebtoken` and the crypto library decode the token's parts into their own buffers; the password fingerprint is an HMAC computed inside aws-lc;
- the operating system: memory can be swapped to disk or end up in a core dump unless swap is encrypted or disabled and core dumps are off for the service;
- the compiler can keep copies in registers or on the stack, which `zeroize` does not reach.

The user name is not treated as a secret and is not zeroized.

## OAuth token validation

Validation is local; the proxy makes no introspection or userinfo call. A token over 16384 bytes is a `bad_token` without validation. A token whose JWS header has a `crit` member is a `bad_token` too: the proxy understands no JWS extension (RFC 7515 §4.1.11). Validation, with any JWKS refresh it waits for, must finish within the pre-auth budget; a validation that runs out is an outage (retry-later). The refresh itself still completes and records its result, so the 30 s spacing below holds while an IdP is slow.

1. Key selection. The `kid` from the JWT header is looked up. A token without `kid` uses the key id `"default"`, which also matches JWKS keys that have no `kid`. An unknown `kid` triggers one refresh of all JWKS and a second lookup. These on-demand refreshes happen at most every 30 s and are serialised with the periodic refresh, so an older snapshot never overwrites a newer one; tokens arriving during a refresh wait for it. If the key is still unknown, the result of the last on-demand refresh decides (this one, or the one less than 30 s ago that made this one wait):
   - It succeeded for the issuer the token claims in `iss`, or the token claims no configured issuer: the token is rejected as `bad_token`. A flood of random `kid`s therefore stays visible to CrowdSec, also while another issuer's JWKS is down.
   - It failed for that issuer: the answer is retry-later (an outage, no `authresult` line), because a key rotated in while the IdP was unreachable must not look like a forged token.

   The `iss` is read unverified here, only to pick the refresh result. An `iss` that is not a string (an array is invalid anyway, step 4) counts as no configured issuer.
2. Algorithm pinned to the key. The algorithm comes from the JWKS key, never from the token header. A key with `alg` is used with exactly that algorithm. A key without `alg` is used with the one algorithm its type implies (ES256 for P-256, ES384 for P-384, RS256 for RSA), or skipped when the issuer sets `infer_key_algorithm = false`. Every key therefore has exactly one algorithm (RFC 8725 §3.1). Either way only the issuer's `allowed_algorithms` count. An RSA key used with another algorithm must say so in its `alg`. Keys are skipped when their algorithm is not allowed, when `kty` is not `EC`/`RSA`, or when they declare a `use` other than `sig` (a missing `use` is accepted). `alg=none` and HS* forgeries fail.
3. Issuer bound to the key. Each `[[oauth.issuers]]` entry pairs one `issuer` with its `jwks_url`, and each key is accepted only with the `iss` of the issuer whose JWKS published it. A realm-B key cannot sign a token that claims realm A. If several issuers publish the same `kid`, each candidate key is tried against its own issuer.
4. Required claims: `iss`, `aud`, `exp`. `iss` must be a string (RFC 7519 §4.1.1); an array is refused. `aud` may be a string or an array and must contain one of the issuer's `audiences`.
5. Time checks: `exp` is checked, and `nbf` when present. The leeway is `oauth.leeway_secs` (default 60 s), so a token is still accepted up to 60 s after `exp` and up to 60 s before `nbf`.
6. Issuer rules:
   - Access tokens only, per `token_type`. `keycloak`: the claim `typ` equals `Bearer` (case-insensitive), so ID tokens (`typ=ID`) and tokens without `typ` fail. `rfc9068`: the JWT header `typ` is `at+jwt` or `application/at+jwt`. `any`: no check.
   - `email_verified` must be the JSON boolean `true` when `require_email_verified` is on (default for `identity_claim = "email"`). Missing, `false` or the string `"true"` fail.
   - With `allowed_clients` set, the `client_claim` must be one of them. It defaults to `client_id` for `token_type = "rfc9068"` (RFC 9068 §2.2) and to `azp` otherwise.
7. Identity: the `identity_claim` (default `email`). It must be a string of at most 254 characters without whitespace or control characters; for `email` also exactly one `@` with non-empty local part and domain. It is forwarded to the backend as the login.

JWKS handling:

- The JWKS of all issuers are fetched in parallel, each with a 10 s timeout, at startup, on every refresh and for an unknown `kid`. One round therefore takes at most one fetch timeout, however many IdPs are down, and so does the wait of a token that needs it.
- At startup, if any configured JWKS is unreachable, unparsable, or has no usable key, **the proxy refuses to start**.
- It refreshes all JWKS every `oauth.refresh_secs` (default 300 s). An issuer whose refresh succeeds has its keys fully replaced, which is how key revocation takes effect. An issuer whose refresh fails keeps its previous keys.
- A key with missing or undecodable members is skipped with a warning (RFC 7517 §5) and counted in `mail_auth_proxy_jwks_keys_skipped_total`; the other keys of the set are used. Only a set without any usable key fails.
- A signing key published after the last refresh is picked up by the unknown-`kid` refresh (step 1), so it is accepted within seconds. Random `kid`s cannot cause more than one refresh per 30 s.
- JWKS URLs must use `https://`; plain `http://` is accepted only for `localhost`, `127.0.0.1` and `::1`. Only a 2xx response is used: another status, a redirect (never followed), or a body over 256 KiB fails the fetch.
- TLS for JWKS fetches uses rustls-platform-verifier, that is, the system trust store.

## Backend TLS

- Each backend has its own trust anchors: the CAs in its `ca_file`, or the system store (`rustls-native-certs`, which also honours `SSL_CERT_FILE`/`SSL_CERT_DIR`). Certificate verification cannot be turned off.
- The name verified is the backend's `verify_name`, or the host part of its `address`.
- TCP connect and TLS handshake each have a `timeouts.connect_secs` timeout (default 10 s).

## PROXY protocol v2 and XCLIENT

- With `proxy_protocol = true` on the IMAP or Sieve backend, the proxy writes a binary PROXY v2 header (command `PROXY`, `TCP4` or `TCP6`) as the first bytes of that backend connection, before TLS.
  - The source is the client address and the destination is the local address the client connected to. IPv4-mapped addresses are *not* canonicalised here.
  - The ManageSieve capability probe ([protocols: ManageSieve after TLS](protocols.md#managesieve-after-tls)) is the proxy's own connection and sends a PROXY v2 `LOCAL` header (no addresses).
  - The backend listener must require the header (Dovecot `haproxy = yes`); switch both settings together.
- SMTP never sends PROXY protocol. With `submission.xclient = true` it sends `XCLIENT NAME=[UNAVAILABLE] ADDR=<ipv4>` or `ADDR=IPV6:<ipv6>` after the backend's post-TLS EHLO, but only if the backend advertises `XCLIENT`; otherwise the step is skipped silently. With `submission.xclient = false`, a backend that advertises `XCLIENT` is an outage and no credential is sent. The same applies when the `EHLO` after the proxy's `XCLIENT` still lists it, because the client's own address would then be authorized for it.

## After authentication

Once the backend accepts the credential, the proxy relays bytes both ways with `tokio::io::copy_bidirectional` until either side closes, without interpreting them. The credential is dropped (and zeroized) before the relay starts.

- **TCP keepalive** is on for every client connection from `accept()` and every backend connection from `connect()`: after `session.keepalive_idle_secs` (600 s) of silence the kernel probes every `session.keepalive_interval_secs` (60 s) and drops the connection after `session.keepalive_count` (5) unanswered probes. A peer that vanished without a FIN or RST (a phone that left the network, a crashed host) is found after at most 15 minutes of silence; the failed read ends the relay and frees the `max_connections` slot. A connection with unacknowledged data is not probed; it ends by the kernel's retransmission timeout instead.
- **`session.idle_limit_secs`** (off by default) closes a session after that long without a byte in either direction. Reads and writes both count, so a client that slowly drains a large response is not idle, and neither is an IDLE session whose client re-issues IDLE or whose backend sends updates. Below 30 minutes `--check-config` warns: RFC 9051 §5.4 and RFC 5804 §1.2 let clients rely on 30 minutes of post-login inactivity, and IDLE clients re-issue IDLE only every 29 minutes (RFC 9051 §6.3.13). SMTP's 5-minute server timeout (RFC 5321 §4.5.3.2.7) is lower, and Postfix enforces its own.
- **`session.max_session_secs`** (off by default) closes a session that long after the login, busy or not. It bounds how long a session outlives the credential it was opened with, for example after the account was locked in the directory or the IdP.
- When a limit ends a session, the proxy closes both TLS streams (close_notify, then FIN), within 2 s. It sends no `* BYE`, `BYE` or `421` of its own: the relay does not know where a response ends (an IMAP or ManageSieve literal, an SMTP multi-line reply), and a line injected into a literal would become part of the client's data. Clients see a closed connection and reconnect ([standards: D-GEN-3](standards.md#d-gen-3-no-bye-or-421-when-a-session-limit-ends-a-session)).
- The session does not end at the token's `exp`. IMAP, SMTP and ManageSieve have no re-authentication within a session (IMAP AUTHENTICATE only in the Not Authenticated state, RFC 9051 §6.2.2; a second SMTP AUTH is refused, RFC 4954 §4), so an access token that lives a few minutes would cut every IDLE session that often, below the 30-minute floor above, and a password session has no `exp` at all. `session.max_session_secs` is the bound for both kinds of credential.
- Each end is counted in `mail_auth_proxy_sessions_ended_total{proto,reason}` ([operations](operations.md#prometheus-metrics)).

There is no per-user or per-IP limit on logged-in sessions.

## Connection limits

Limits are checked at `accept()`, before TLS:

| Limit | Default | Scope |
|---|---|---|
| `limits.max_connections` | 2048 | open client connections across all three listeners |
| unauthenticated share | `max(max_connections / 2, 1)` | unauthenticated connections across all listeners and all IPs |
| `limits.max_preauth_per_ip` | 32 | unauthenticated connections per source IP (IPv6: per network of `limits.ipv6_source_prefix`, default /64), **shared across IMAP, SMTP and Sieve** |

- A connection over any limit is closed at once, with no protocol greeting, no `421` and no `BYE`. It is counted in `mail_auth_proxy_connections_rejected_total{proto}`.
- The per-IP slot and the unauthenticated-share slot are released once the backend accepts the credential. An authenticated session counts only against `max_connections`, so many logged-in sessions from one IP (a webmail host, a NAT) do not exhaust the per-IP limit.

## Failed-login rate limit

`[auth_ratelimit]` blocks a source address that presents too many refused credentials. A session takes one credential, so a guesser opens a new connection for each attempt; the per-account throttle covers passwords only, and only per account. The rate limit also covers token guessing, scanners and password spraying over many accounts, without a log-based blocker.

- **Source:** an IPv4 address (also IPv4-mapped), or an IPv6 network whose prefix length `limits.ipv6_source_prefix` sets (32 to 64, default 64), as for `limits.max_preauth_per_ip`. One host usually holds a whole /64; with 48, a site that rotates through its /64s stays one source.
- **Counted:** every refused credential, one per `authresult` line with `result="fail"` and a credential: `bad_token`, `authzid_mismatch`, `blocked_endpoint`, `unknown_domain`, `unknown_account`, `throttled`, `oversize`, `backend_reject`. All reasons count alike, so the attempt that starts a block tells nothing about the account; `throttled` counts for the same reason (it occurs only for accounts that exist).
- **Not counted:** `protocol` (no credential: a TLS or certificate fault on the proxy's side would otherwise block every client), and every outage: an unavailable backend or account check, or token keys that could not be checked. Outages write no `authresult` line and never block anyone.
- **Repeats:** a credential identical to one of the source's last 8 failures in the window (same user and same password or token) counts once. A client retrying a stale password or an expired token does not block its address, and repeating a guess gains nothing. The comparison uses a keyed 64-bit fingerprint; the secret is not kept.
- **Successful logins** do not reset the count: one valid account must not clear the way for guesses at others.
- **Block:** after `failures` counted failures within `window_secs` (a window starts with the first failure), new connections from the source are closed at accept for `block_secs`, on every listener. Each further block of the same source doubles, up to `max_block_secs`; the escalation is forgotten once the last block ended `max_block_secs` ago. Failures of connections opened before the block do not extend it.
- **Exempt:** sources in `exempt_networks` (default: loopback), and with `exempt_internal = true` also sources in `scope.internal_networks`. They are not counted at all.
- **Memory:** at most 65,536 sources. A full table first drops entries with nothing left to remember, then the least valuable 1,024 (unblocked before blocked, oldest first); they are counted in `mail_auth_proxy_ratelimit_evictions_total`. Entries are also swept every 10 s.

A blocked connection is closed like one over a connection limit: before TLS, with no greeting, no `421`, no `554` and no `BYE`. RFC 5321 (section 3.1: `554` instead of the greeting) and RFC 9051 (section 7.1.5: `BYE` as the greeting) allow a server to turn a connection away with a reply, but on the implicit-TLS IMAP port that reply needs a full TLS handshake per blocked connection, and a distinct reply would tell a guesser that it was blocked and how fast it may go. A client behind a blocked address sees a connection failure, the same as with a firewall-based ban.

The block does not change the reply timing of the credentials before it: a refusal is answered as late as before ([Refusal replies and timing](#refusal-replies-and-timing)), and the count is the same for every reason, so neither the block nor its timing tells whether an account exists.

The block starts with one `ratelimit` log line ([operations: other log lines](operations.md#other-log-lines)); every closed connection counts in `mail_auth_proxy_ratelimit_blocks_total{proto}`, not in `connections_rejected_total`. Sessions that were logged in before the block keep running.

To keep observing attacks on a legacy rule open to public networks, as a honeypot, set `enabled = false` or a high `failures`; the `authresult` lines then keep coming for every attempt.

## Timeouts

| Setting | Default | Applies to |
|---|---|---|
| `timeouts.idle_secs` | 30 s | every single `read_line` read (idle), on client and backend |
| `timeouts.preauth_secs` | 60 s total | from accept to the backend's verdict: TLS handshake, plaintext dialog, SASL, token validation (with a JWKS refresh), the legacy account check and the backend login. Activity does not reset it, so drip-feeding does not help. |
| `timeouts.connect_secs` | 10 s | backend TCP connect; backend TLS handshake; writing the PROXY header |
| `limits.max_preauth_commands` | 8 | commands before a credential (per phase for SMTP and Sieve) |
| JWKS fetch (fixed) | 10 s | per URL; all URLs are fetched in parallel |
| `oauth.refresh_secs` | 300 s | periodic JWKS refresh of all URLs |
| `sieve.capability_cache_secs` | 600 s | backend post-TLS capabilities |
| metrics scrape (fixed) | 10 s, 4 at a time | the whole request head, and the response, each; a fifth connection is closed at accept |
| backend auth reply (fixed) | at most 32 lines | IMAP `P1` reply; each line within the idle timeout |
| `session.keepalive_idle_secs`, `_interval_secs`, `_count` | 600 s, 60 s, 5 | TCP keepalive of every client and backend connection, from accept or connect ([after authentication](#after-authentication)) |
| `session.idle_limit_secs` | off | after login: no byte in either direction |
| `session.max_session_secs` | off | after login: time since the login |
| session close (fixed) | 2 s | closing both TLS streams after a session limit |
| shutdown drain (fixed) | 10 s | after SIGTERM/SIGINT, how long open sessions may continue ([operations: signals](operations.md#signals-and-service-manager)) |

The pre-auth budget also covers token validation, the account check and the backend phase (connect, greeting, AUTH verdict); the connect and idle timeouts bound each step within it. A credential whose check or backend login runs out of budget gets the retry-later reply: an outage (`mail_auth_proxy_backend_errors_total`), not a failed login. Only the padding of a refused password may end after the budget.

A timeout closes the connection silently, with no `* BYE` and no `421`.
