# Architecture

How the proxy works: the building blocks every protocol shares. The per-protocol dialogs are in [protocols.md](protocols.md), every configuration key in [configuration.md](configuration.md), logs, metrics and signals in [operations.md](operations.md). This document is written from the source in `src/` and checked with the black-box tests in `tests/`; where it and the code disagree, the code wins.

mail-auth-proxy is an authentication proxy for mail. It terminates client TLS for three protocols, runs each protocol's dialog only up to the point where the client presents a credential, decides whether that credential may be used, logs in to a backend (Dovecot and Postfix) with the client's own credential, and then relays bytes without interpreting them. It never holds a master credential. OAuth bearer tokens are validated locally against JWKS keys and are never introspected at the IdP.

| Protocol | Client side | Backend side |
|---|---|---|
| IMAP | implicit TLS on `imap.listen` | implicit TLS to `imap.backend`, optional PROXY protocol v2 |
| SMTP submission | plaintext + STARTTLS on `submission.listen` | plaintext + STARTTLS to `submission.backend`, optional XCLIENT |
| ManageSieve | plaintext + STARTTLS on `sieve.listen` | plaintext + STARTTLS to `sieve.backend`, optional PROXY protocol v2 |

## Request flow

```
client ──TLS──▶ mail-auth-proxy ─────────────────────────────TLS (verified)──▶ backend
                 1. accept: connection limits
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

Each connection is one tokio task. Connections share only the JWKS key set, the server certificate,
the ManageSieve capability cache, the legacy gate's caches and counters, the connection
limits and the metrics.
The trust boundaries and the threat model are in [SECURITY.md](../SECURITY.md#trust-boundaries).

## Client TLS

- rustls with the aws-lc-rs provider. TLS 1.2 and TLS 1.3 use rustls' default cipher suites. There is no ALPN and no client-certificate authentication.
- A single certificate chain (`tls.cert`, `tls.key`) is served for every SNI name. For a legacy rule with `sni` to be usable, that certificate must cover both the public name and the rule's names.
- The SNI the client sent is read after the handshake and used only by the legacy rules ([legacy gate](#legacy-gate)). A client that sends no SNI matches only rules without `sni`. Clients that connect by IP address never send SNI.

## Line reading

Every protocol read before authentication, on both the client and the backend side, uses the same reader:

- It reads byte-by-byte up to `\n`, drops `\r`, and requires valid UTF-8. Invalid UTF-8 is an error and closes the connection.
- A line may be at most 16384 bytes, counting every byte consumed including bare CRs. A longer line closes the connection.
- Each single read has an idle timeout of `timeouts.idle_secs` (default 30 s).

Because the reader never reads past `\n`, bytes a client pipelines after `STARTTLS` stay in the socket. They are then fed to the TLS acceptor, and the handshake fails. This closes the STARTTLS command-injection class (CVE-2011-0411), which the harness verified.

## Legacy gate

OAuth mail and legacy mail are separate paths. OAuth (XOAUTH2, OAUTHBEARER) is gated by
local token validation ([OAuth token validation](#oauth-token-validation)) and is not affected by anything here. Legacy mail
(PLAIN, SASL LOGIN, the IMAP LOGIN command) has no SSO and no token: the backend checks
the password. The proxy only decides whether to pass it on. Without `[[legacy.rules]]`
every endpoint is OAuth-only.

**Offer.** On each connection PLAIN and LOGIN are advertised as far as at least one rule
matches the connection:

```
rule matches a connection  ⇔  source IP ∈ networks (IPv4-mapped IPv6 canonicalised first)
                              AND  (no sni  OR  SNI equals one of sni, ASCII case-insensitive, exact)
                              AND  (no protocols  OR  protocol ∈ protocols)
offered mechanisms         =  union of the matching rules' mechanisms (default PLAIN and LOGIN)
```

IMAP advertises `LOGINDISABLED` whenever LOGIN is not offered (the LOGIN command counts
as the LOGIN mechanism). ManageSieve never offers LOGIN. SMTP offers LOGIN only together
with PLAIN (draft-murchison-sasl-login §1).

**Attempt.** A password credential is always parsed first, even when it is not advertised,
so that the attempt can be logged with a password fingerprint. Then, in this order and
before any backend contact:

| Step | Check | Refused as |
|---|---|---|
| 0 | the connection offers this mechanism | `blocked_endpoint`, reply "not available on this endpoint" |
| — | the password is at most 1024 bytes | `oversize` |
| — | the login is not empty, at most 255 bytes, has no control characters and at most one `@` | `unknown_account` |
| 1 | a rule matches connection, mechanism and user (`users`, `users_file`: `user@domain` or `*@domain`; the local part is compared exactly, the domain ignoring ASCII case). The first matching rule in file order decides and is logged. | `blocked_endpoint` |
| 2 | the login's domain is in `allowed_domains` ∪ `domains_file` (only if either is set; a login without `@domain` fails) | `unknown_domain` |
| 3 | the account exists (`account_check = "doveadm"`) | `unknown_account` |
| 4 | the account is not throttled (`throttle`) | `throttled` |
| — | the backend checks the password; a protocol error in direct answer to the password (SMTP `500`–`509` after the response to `334`, IMAP tagged `BAD`) also counts as a rejection; a reply to the bare SMTP `AUTH` line or an IMAP `* BYE` is an outage | `backend_reject` |

The size cap and the protocol-error rule close an enumeration oracle: a backend may answer
a crafted password (Postfix beyond `smtpd_sasl_response_limit`, 12288 octets) with a protocol
error, and only for accounts that passed the gate; an immediate retry-later there, next to a
delayed refusal for the others, would tell the two apart. Tokens have their own cap: one
over 16384 bytes is a `bad_token` without validation.

The size check, steps 1 to 4 and a wrong password give the client **the same reply** (the protocol's
wrong-password reply), and the timing is made alike:

- A refusal by the gate is answered after the larger of `legacy.failure_delay_ms`
  (default 2000, Dovecot's default `auth_failure_delay`) and the median latency of the
  last 32 backend rejections of the same protocol (capped at 10 s), counted from the
  credential.
- A backend rejection is answered no earlier than `failure_delay_ms` after the
  credential.
- Both get the same random jitter: up to a quarter of that time, at least 50 ms, at most
  1 s.
- An outage on the password path (account check or backend unavailable) is answered with
  retry-later no earlier than a refusal, with the same jitter: it only happens to accounts
  that passed the earlier steps, so an instant answer would tell them apart.

So neither the text nor the timing tells the cases apart. Keep the backend's own failure
delay on behind the proxy (Dovecot `auth_failure_delay`): it slows down guessing at the
backend, and the proxy pads its refusals to it. Until the proxy has seen backend
rejections of a protocol (after a start), refusals use `failure_delay_ms` alone, so set it
close to the backend's delay. The log keeps the cases apart (`reason`, `rule`).

- **Account check:** a userdb lookup over the Dovecot doveadm HTTP API (Dovecot 2.4):
  `POST <doveadm_url>` with `Authorization: X-Dovecot-API <base64 of the API key>` and
  `[["user", {"userMask": "<login>", "userdbOnly": true}, "u"]]`. `doveadmResponse` means
  the user exists; `error` with `exitCode` 67 (EX_NOUSER) means it does not. Any other
  answer, an HTTP error, a TLS failure or a timeout (`timeouts.connect_secs`) is an
  **outage**: the client gets the retry-later reply, `mail_auth_proxy_backend_errors_total`
  counts it, no `authresult` line is written and the password is not forwarded. Answers
  are cached (existing 120 s, missing 30 s, at most 10 000 logins); outages are not cached.
  Logins containing `*` or `?` are never sent (doveadm would list matching users) and count
  as unknown. TLS is verified against the system store or `doveadm_ca_file`; plain http
  only to localhost; a URL with `user:password@` is refused (the key belongs in
  `doveadm_key_file`). The Authorization header is marked sensitive. Sources: doc.dovecot.org 2.4.5 "Doveadm → HTTP API" and the `user`
  command in "All Doveadm Commands".
- **Throttle:** each backend rejection counts against the account (the key is the login
  folded to ASCII lower case, so `Bob@x` and `bob@x` share one counter) for `window_secs` from its first failure; at `failures` further
  attempts are refused without asking the backend until the window ends. A successful
  login resets the count. At most 65 536 accounts are tracked (expired entries first, then
  the oldest). Only rejections of existing accounts are counted, so unknown names do not
  fill the table.
- **Files:** `users_file` and `domains_file` hold one entry per line; blank lines and lines
  starting with `#` are ignored. They are read at startup (an unreadable or invalid file
  aborts startup and fails `--check-config`) and re-read by a background task when their
  modification time, size or inode changes, checked every 2 seconds. A file that becomes
  missing, unreadable or invalid **fails closed**: a rule with that `users_file` matches
  nobody (its inline `users` included), a broken `domains_file` closes the domain gate
  (inline `allowed_domains` included). This is logged at `ERROR`, counted in
  `mail_auth_proxy_legacy_list_errors_total`, and retried on every check until the file is
  fixed, so a broken update can never keep a revoked entry alive.
- **Login names:** the gate compares the login the client sent. It assumes the backend
  uses that same login as the account name (identity-preserving: no
  `auth_username_format` that strips the domain or otherwise maps several logins to one
  account); otherwise the domain gate, user lists and throttle see a different name than
  the backend.
- **Scope label:** a source IP in `scope.internal_networks` counts as `scope=internal`,
  whatever the SNI and the rules. The label feeds logs and metrics and allows nothing.

`[password_gate]` (`enabled`, `sni`, `internal_networks`) is the short form of one
rule named `password_gate` with those networks and names (all protocols and mechanisms,
all users), plus the scope label from `internal_networks` when `[scope]` is absent. It can
be combined with `[legacy]` settings (domains, account check, throttle) but not with
`[[legacy.rules]]`. `--print-config` shows the rule form.

## SASL mechanisms

| Mechanism | Client → proxy | Proxy → backend |
|---|---|---|
| `XOAUTH2` | `user=<u>^Aauth=Bearer <jwt>^A^A`. The scheme `Bearer` is case-insensitive and `user=` must not be empty. | `XOAUTH2` rebuilt as `user=<validated identity claim>^Aauth=Bearer <same jwt>^A^A` |
| `OAUTHBEARER` | GS2 header `n,a=<authzid>,` (the authzid is optional: `n,,`), then `^A`-separated fields with `auth=Bearer <jwt>`. `host=` and `port=` are ignored. | **converted to `XOAUTH2`** as above |
| `PLAIN` | `authzid\0authcid\0passwd`. User and password must be non-empty. The login is the authcid; a non-empty authzid must equal it, otherwise the exchange fails (acting as another user is not supported). | `PLAIN` rebuilt as `\0<login>\0<passwd>` (empty authzid) |
| `LOGIN` | Two base64 prompts (`Username:`, `Password:`). An initial response on the AUTH line is the username; then only the password is asked for. IMAP and SMTP only. | sent as `PLAIN` |

For OAuth, the mailbox identity forwarded to the backend is always the token's `identity_claim` (default `email`). The username the client supplies (XOAUTH2 `user=`, OAUTHBEARER `a=`, the SASL authorisation identity) is logged for a failed validation, and once the token is valid it must be empty, name that same identity, or be its local part without a domain (ASCII case-insensitive). Naming anyone else fails the exchange (RFC 4422 §3.6) with `authzid_mismatch` before the backend is contacted: acting as another user is not supported.

## OAuth token validation

Validation is local: no introspection call and no userinfo call is made.

1. **Key selection.** The `kid` from the JWT header is looked up. A token without `kid` uses the key id `"default"`, which also matches JWKS keys that have no `kid`. An unknown `kid` triggers one refresh of all JWKS (at most every 30 s, serialised with the periodic refresh, so an older snapshot never overwrites a newer one; tokens arriving during a refresh wait for it) and a second lookup; if the key is still unknown, the verdict follows the last on-demand refresh (this one, or the one less than 30 s ago that made this one wait): if that refresh succeeded for the issuer the token claims in `iss` (read unverified, only to pick the refresh result; for an array `iss`, any configured issuer in it that failed makes it an outage), or the token claims no configured issuer, it is rejected (`bad_token`, so a flood of random `kid`s stays visible to CrowdSec, also while another issuer's JWKS is down); if it failed for that issuer, the answer is retry-later (an outage, no `authresult` line), since a key rotated in while the IdP was unreachable must not look like a forged token.
2. **Algorithm pinned to the key.** The algorithm comes from the JWKS key, never from the token header. A key with `alg` is used with exactly that algorithm; a key without `alg` with the one algorithm its type implies (ES256 for P-256, ES384 for P-384, RS256 for RSA), so every key has exactly one algorithm (RFC 8725 §3.1). Either way only the issuer's `allowed_algorithms` count. An RSA key used with another algorithm must say so in its `alg`. Keys are skipped when nothing remains, when `kty` is not `EC`/`RSA`, or when they declare a `use` other than `sig` (a missing `use` is accepted). `alg=none` and HS* forgeries fail.
3. **Issuer bound to the key.** Each key is accepted only with the `iss` of the issuer whose JWKS published it. Each `[[oauth.issuers]]` entry pairs one `issuer` with its `jwks_url`. A realm-B key cannot sign a token that claims realm A. If several issuers publish the same `kid`, each candidate key is tried against its own issuer.
4. **Required claims:** `iss`, `aud`, `exp`. `aud` may be a string or an array and must contain one of the issuer's `audiences`.
5. **Time checks:** `exp` is checked, and `nbf` is checked when present. The leeway is `oauth.leeway_secs` (default **60 s**), so a token is still accepted up to 60 s after `exp` and up to 60 s before `nbf`.
6. **Issuer rules:**
   - **Access token only**, per `token_type`: `keycloak` — claim `typ` equals `Bearer` (case-insensitive), so ID tokens (`typ=ID`) and tokens without `typ` fail; `rfc9068` — JWT header `typ` is `at+jwt` or `application/at+jwt`; `any` — no check.
   - `email_verified` must be the JSON boolean `true` when `require_email_verified` is on (default for `identity_claim = "email"`). Missing, `false` or the string `"true"` fail.
   - With `allowed_clients` set, the `client_claim` (default `azp`) must be one of them.
7. **Identity:** the `identity_claim` (default `email`). It must be a string of at most 254 characters without whitespace or control characters; for `email` also exactly one `@` with non-empty local part and domain. It is forwarded to the backend as the login.

JWKS handling:

- The proxy fetches every JWKS at startup with a 10 s timeout. If any configured JWKS is unreachable, unparsable, or has no usable key, **the proxy refuses to start**.
- It refreshes all JWKS every `oauth.refresh_secs` (default **300 s**). An issuer whose refresh succeeds has its keys fully replaced, which is how key revocation takes effect. An issuer whose refresh fails keeps its previous keys.
- A signing key published after the last refresh is picked up by the unknown-`kid` refresh (step 1 above), so it is accepted within seconds; random `kid`s cannot cause more than one refresh per 30 s.
- JWKS URLs must use `https://`; plain `http://` is accepted only for `localhost`, `127.0.0.1` and `::1`. A non-2xx status, a redirect, or a body over 256 KiB fails the fetch.
- TLS for JWKS fetches uses rustls-platform-verifier, that is, the system trust store.

## Backend TLS

- Each backend has its own trust anchors: the CAs in its `ca_file`, or the system store (`rustls-native-certs`, which also honours `SSL_CERT_FILE`/`SSL_CERT_DIR`). Certificate verification can never be turned off.
- The name verified is the backend's `verify_name`, or the host part of its `address`.
- TCP connect and TLS handshake each have a `timeouts.connect_secs` timeout (default 10 s).

## PROXY protocol v2 and XCLIENT

- With `proxy_protocol = true` on the IMAP or Sieve backend, the proxy writes a binary PROXY v2 header (command `PROXY`, `TCP4` or `TCP6`) as the first bytes of that backend connection, before TLS.
  - The source is the client address and the destination is the local address the client connected to. IPv4-mapped addresses are *not* canonicalised here.
  - The ManageSieve capability probe ([protocols: ManageSieve after TLS](protocols.md#managesieve-after-tls)) is the proxy's own connection and sends a PROXY v2 `LOCAL` header (no addresses).
  - The backend listener must be set up to require the header (Dovecot `haproxy = yes`), and the two settings must be switched together.
- SMTP never sends PROXY protocol. With `submission.xclient = true`, it sends `XCLIENT NAME=[UNAVAILABLE] ADDR=<ipv4>` or `ADDR=IPV6:<ipv6>` after the backend's post-TLS EHLO, but only if the backend advertises `XCLIENT`. If the backend does not, the step is skipped silently. With `submission.xclient = false` a backend that advertises `XCLIENT` is an outage (no credential is sent), and so is one whose `EHLO` after the proxy's `XCLIENT` still lists it (the client's own address is authorized).

## After authentication

Once the backend accepts the credential, the proxy relays bytes both ways with `tokio::io::copy_bidirectional` until either side closes. In this phase there is **no idle timeout, no TCP keepalive, and no per-user or per-IP session limit**. How long a session lives is up to the client and the backend (for example, Dovecot's autologout).

## Connection limits

Limits are checked at `accept()`, before TLS:

| Limit | Default | Scope |
|---|---|---|
| `limits.max_connections` | 2048 | open client connections across all three listeners |
| unauthenticated share | `max(max_connections / 2, 1)` | unauthenticated connections across all listeners and all IPs |
| `limits.max_preauth_per_ip` | 32 | unauthenticated connections per source IP (IPv6: per /64), **shared across IMAP, SMTP and Sieve** |

- A connection over any limit is closed at once, with no protocol greeting, no `421` and no `BYE`. It is counted in `mail_auth_proxy_connections_rejected_total{proto}`.
- The per-IP slot and the unauthenticated-share slot are released once the backend accepts the credential. Many logged-in sessions from one IP (a webmail host, a NAT) therefore count only against `max_connections`.
- Session authenticated but still open: counts against `max_connections` only.

## Timeouts

| Setting | Default | Applies to |
|---|---|---|
| `timeouts.idle_secs` | 30 s | every single `read_line` read (idle), on client and backend |
| `timeouts.preauth_secs` | 60 s total | from accept to credential: TLS handshake, plaintext dialog, SASL. It is **not** reset by activity, so drip-feeding does not help. |
| `timeouts.connect_secs` | 10 s | backend TCP connect; backend TLS handshake; writing the PROXY header |
| `limits.max_preauth_commands` | 8 | commands before a credential (per phase for SMTP and Sieve) |
| JWKS fetch (fixed) | 10 s | per URL |
| `oauth.refresh_secs` | 300 s | periodic JWKS refresh, all URLs one after another |
| `sieve.capability_cache_secs` | 600 s | backend post-TLS capabilities |
| metrics scrape (fixed) | 10 s | read and write each |
| backend auth reply (fixed) | at most 32 lines | IMAP `P1` reply; each line within the idle timeout |
| shutdown drain (fixed) | 10 s | after SIGTERM/SIGINT, how long open sessions may continue ([operations: signals](operations.md#signals-and-service-manager)) |

The backend phase (connect, greeting, AUTH verdict) is *not* covered by the pre-auth budget. It is bounded by the connect and idle timeouts for each step.

A timeout closes the connection silently. There is no `* BYE` and no `421`.
