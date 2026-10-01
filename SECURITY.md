# Security policy

## Supported versions

Only the latest release receives security fixes. Upgrade older releases.

## Security model

The proxy sits on a public edge in front of an IMAP, ManageSieve and SMTP submission
backend (for example Dovecot and Postfix). It terminates client TLS, decides how a client
may authenticate, logs in to the backend with the client's **own** credential and then
relays the session (IMAP and ManageSieve through a command guard, invariant 4). It never holds a master password or any other credential of its own.

### Trust boundaries

```
 mail client ──(1)──▶ mail-auth-proxy ──(2)──▶ backend (Dovecot, Postfix)
                          │
                          └──(3)──▶ identity provider (JWKS over HTTPS)
```

1. **Client ↔ proxy: untrusted.** Everything a client sends before authentication is
   attacker-controlled: TLS ClientHello and SNI, commands, SASL data, tokens, passwords,
   and the timing of all of it. The source address is trusted only as far as the network
   in front of the proxy preserves it (no SNAT, no load balancer that hides it).
2. **Proxy ↔ backend: trusted, authenticated by TLS.** The backend is verified against its
   configured name and trust anchors. It is trusted to validate the forwarded token or
   password itself and to answer truthfully; its replies are still parsed defensively.
   The PROXY v2 header and XCLIENT (`client_ip`) make the backend trust the client address
   the proxy reports, so the backend must accept them only from the proxy's address. A
   STARTTLS backend (`tls = "starttls"`) is verified the same way; its plaintext greeting
   and capabilities are discarded once TLS is up. An OAUTHBEARER error result from the
   backend (`auth_forward = "oauthbearer"`) is parsed with a size limit and decides only
   between a rejection and an outage.
3. **Proxy ↔ identity provider: trusted for keys.** The JWKS is fetched over HTTPS,
   verified against the system trust store, and defines which tokens are valid for its
   issuer. Whoever can change a JWKS (or the trust store) can mint tokens for that issuer.
4. **Operator: trusted.** The configuration file, the certificate and key, the key and
   list files and the host are trusted. A misconfiguration is out of scope, but the
   configuration check refuses the combinations that silently weaken the model.

### Threat model

| Threat | Mitigation |
|---|---|
| Forged or foreign tokens (`alg=none`, HS*, key confusion, a key of one realm signing for another, ID tokens, expired tokens) | local validation: algorithm from the key, key bound to its issuer, required `iss`/`aud`/`exp`, access-token marker, `email_verified` |
| A valid token used for another mailbox | the backend login is the token's identity claim; a different SASL user name is refused |
| Password guessing and spraying from the internet | no password mechanism unless a legacy rule matches the source network; per-account throttle; a failed-login rate limit per source address; `authresult` lines with keyed password fingerprints for log-based blocking |
| Token guessing and scanning with new connections per attempt | a failed-login rate limit per source address (IPv4 address; IPv6 network of `limits.ipv6_source_prefix`, by default /64) that closes a blocked source's connections at accept, and an open one at its next credential; at most `limits.max_auth_attempts` attempts per connection |
| Account and domain enumeration | refusals and wrong passwords get the same reply and similar timing (see [Hardening](#hardening)) |
| Resource exhaustion before login | connection caps, per-IP cap on unauthenticated connections, one pre-authentication time budget, command, line, literal, token and password size limits |
| STARTTLS command injection | nothing is read ahead of the TLS switch, so plaintext pipelined after `STARTTLS` cannot reach the encrypted session |
| Log injection | client text escaped or reduced to a fixed character set in every log field |
| A rogue or intercepted backend | backend TLS always verified; no option to disable it |
| An authenticated SMTP client sending its own `XCLIENT` to impersonate another user | the proxy never relays into a session in which the backend still offers `XCLIENT`. A backend that advertises it while the submission backend's `client_ip` is not `xclient`, or still advertises it after the proxy's own `XCLIENT` (the client's address is itself authorized), is treated as misconfigured, and the login fails as an outage |
| A logged-in client returning to the unauthenticated state (`UNAUTHENTICATE`, RFC 8437, RFC 5804 §2.14.1) or presenting a second credential, to try passwords directly at the backend | the relay's command guard keeps these commands from the backend whatever it offers or does, and takes `UNAUTHENTICATE` out of the capabilities it relays (invariant 4) |
| Bans of legitimate users during an outage | outages are answered with retry-later and never logged as failed logins |
| One issuer asserting identities that belong to another | `oauth.issuers[].identity_domains`: an issuer logs in only to addresses in its domains. Without it, all issuers share one identity namespace, so an account name valid at issuer A can be asserted by issuer B; with more than one issuer the configuration warns about each issuer without it ([D-JWT-3](docs/standards.md#d-jwt-3-identity-namespace-across-issuers)) |

### Invariants

- **Domains compare in one canonical form** (UTS #46 ToASCII, nontransitional, lower case,
  no trailing dot) on both sides of every comparison: the domain gate, the users of a rule,
  routes, `identity_domains`, server names. A Unicode spelling in a login cannot slip past a
  list written in Punycode or the other way round, and neither can a capital letter or a
  trailing dot. Lookalikes from other scripts (a Cyrillic `а` for a Latin `a`) are other
  code points and so other domains: they match nothing they were not configured for.
  Nontransitional processing keeps `ß` and `ς` distinct, so two registrable domains never
  become one. The login itself reaches the backend unchanged.

1. **OAuth mail and legacy mail are separate paths.** OAuth (XOAUTH2/OAUTHBEARER) is
   gated by local token validation (invariant 2). Legacy mail (PLAIN/LOGIN) has no SSO:
   the backend checks the password, and the proxy forwards it only through the legacy
   gate, which fails closed and runs before any backend contact:
   - a `[[legacy.rules]]` entry must match the source network (required), the SNI (if
     set), protocol, mechanism and user;
   - the login's domain must be allowed;
   - a route must take the login's domain;
   - the account must exist (doveadm lookup, by the account check of the backend the
     login goes to or of `[legacy]`);
   - the account must not be throttled.

   Without rules every endpoint is OAuth-only. SNI is chosen by the client and can be
   forged (among the names of the configured certificates; any other name is refused in
   the handshake); the source address is the real boundary. A password refused anywhere is parsed
   only to log the attempt (with a keyed fingerprint, never in clear) and is never
   forwarded. Refusals and wrong passwords get the same reply and padded timing (see
   [Hardening](#hardening)), so the proxy does not reveal which accounts or domains
   exist. A users or domains file that becomes missing or invalid fails closed (its rule
   or the domain gate matches nothing). An unavailable account check is an outage (retry
   later), never a refusal.
2. **OAuth tokens are validated before anything reaches the backend.** Locally, against
   each issuer's JWKS:
   - the signature algorithm comes from the JWKS key, never from the token header
     (`alg=none` and HS* are rejected; a key without `alg` is used only with the
     one algorithm its type implies (RS256 for RSA, ES256/ES384 for P-256/P-384), within
     `allowed_algorithms`);
   - each key is accepted only for the issuer that published it, so several realms on
     one endpoint cannot vouch for each other;
   - `iss`, `aud` and `exp` are required, `nbf` is checked, and the issuer's rules for
     access tokens (`token_type`), `email_verified`, allowed clients and the identity
     claim are applied.

   The same token is then replayed to the backend, which must validate it too.
3. **Every backend hop is TLS-verified** against the backend's `verify_name` and trust
   anchors (system store or `ca_file`). There is no option to disable verification.
4. **A logged-in session stays logged in as the credential the proxy judged.** After
   the login the IMAP and ManageSieve relay passes the client's commands through a
   guard that keeps these from the backend, whatever the backend offers or does:
   - IMAP: `UNAUTHENTICATE` (RFC 8437), `AUTHENTICATE` and `LOGIN` (a second
     credential), `STARTTLS` and `COMPRESS` (either would turn the rest of the stream
     into bytes the guard cannot read);
   - ManageSieve: `UNAUTHENTICATE` (RFC 5804 §2.14.1), `AUTHENTICATE`, `STARTTLS`.

   The guard frames the client stream as the backend does (lines, quoted strings,
   literals) and lets octets pass unchecked only where the backend has shown that it
   reads them as literal data: an IMAP literal after the backend's `+` (non-synchronising
   literals are passed on as synchronising ones for this). ManageSieve has no such
   confirmation, so its literal data is checked line by line for `UNAUTHENTICATE`. A
   backend answer the framing does not expect makes IMAP check every line for the rest
   of the session. A blocked command at a sure command position is answered by the
   proxy (`<tag> BAD`, `NO`); anywhere else the session ends (`reason="blocked"` in
   `mail_auth_proxy_sessions_ended_total`). `UNAUTHENTICATE` and `COMPRESS=…` (IMAP),
   `"UNAUTHENTICATE"` and `"STARTTLS"` (ManageSieve) are taken out of the capabilities
   the proxy relays. SMTP has no such command: a second `AUTH` must be refused by the
   backend (RFC 4954 §4; Postfix answers `503 5.5.1 Error: already authenticated`).

### Hardening

- Pre-authentication limits: a global connection cap (at most half unauthenticated), a
  per-source-IP cap on unauthenticated connections, one total time budget from accept to
  the backend's verdict (token validation, account check and backend login included; a
  slow IdP or backend holds a slot no longer, and running out is an outage), a command
  limit, line and literal size limits.
- Failed-login rate limit (on by default): a source with too many refused credentials is
  closed at accept, before TLS, for a growing time. Every refusal reason counts alike and
  refusal timing is unchanged, so a block does not reveal whether an account exists;
  outages and pre-auth aborts never count; the table is bounded.
- Size caps: a password over 1024 bytes and a token over 16384 bytes are refused without
  further processing (`oversize`, `bad_token`); a JWKS response over 256 KiB fails the
  fetch; a line is at most 16384 bytes, a ManageSieve literal at most 64 KiB.
- Refusal timing: a refusal by the legacy gate is answered after the larger of
  `failure_delay_ms` and the median of the last 32 rejections of the backend the login
  goes to (at most 10 s); a backend rejection no earlier than `failure_delay_ms`; both with the
  same random jitter; a password-path outage (retry-later) no earlier than a refusal.
  OAuth failures are not delayed.
- Client-controlled text never reaches error texts or log fields unescaped. The
  `authresult` line (target `authlog`) has a fixed format intended for log-based blocking
  (e.g. CrowdSec, Wazuh).
- JWKS trust: JWKS URLs must be `https://` (plain `http` only to localhost) and are
  verified against the system trust store; a redirect or non-2xx status fails the
  fetch; a failed refresh keeps the previous keys. An unknown `kid` triggers at most one
  refresh per 30 s. It is an outage (retry-later) only if the last such refresh failed
  for the issuer the token claims (unverified `iss`, used for nothing else), otherwise a
  `bad_token`.
- Strict configuration: unknown keys, an incomplete password gate or legacy rule, a rule
  open to public networks for every user without `public = true`, non-https JWKS or
  doveadm URLs, or zero limits abort startup.
- Configuration reload (`SIGHUP`): the new file passes the same checks as at startup and
  replaces the configuration in use in one step, or is refused as a whole and changes
  nothing. A connection sees either the whole old or the whole new configuration, never
  a mix and never a moment without legacy rules or limits; rate-limit blocks and the
  throttle survive it.

### Operator responsibilities

- **Real client addresses.** The legacy rules rely on the source address. Behind a load
  balancer or SNAT every client looks like the balancer, and a rule for its network would
  open for the whole internet. Run the proxy where it sees real client addresses (routing
  or DNAT), or configure no legacy rules.
- **doveadm HTTP API.** Dovecot warns never to expose it to untrusted networks. Give the
  proxy a dedicated `doveadm_api_key`, reach it over TLS (`doveadm_ca_file` for an
  internal CA), and restrict the listener to the proxy's address at the network level.
  Keep the key file readable only by the service.
- **Failure delay.** Keep the backend's own failure delay on behind the proxy (Dovecot
  `auth_failure_delay`, default 2 s) and set `legacy.failure_delay_ms` close to it. Right
  after a start, before the proxy has seen any backend rejection, it pads refusals to
  `failure_delay_ms` alone.
- **Identity-preserving logins.** The legacy gate checks the login the client sent. The
  backend must use that same login as the account name (no `auth_username_format` that
  strips the domain or folds several logins onto one account); otherwise domain gate, user
  lists and throttle judge a different name than the backend authenticates. The throttle
  folds the local part to lower case and takes the domain in canonical form, so the
  spellings of one login share one counter.
- **Backend validation.** The backend (e.g. Dovecot `oauth2` passdb) must validate tokens
  itself. The proxy's check is a filter in front of it and does not replace it.
- **Client address at the backend.** With `client_ip = "none"` the backend sees every
  client as the proxy's address: its own per-address limits and bans then act on all
  users at once, and its logs cannot tell clients apart. Prefer `proxy_v2` or `xclient`
  and restrict the backend listener to the proxy; the proxy warns about `none`.
- **No second SMTP login at the backend.** The submission backend must refuse `AUTH`
  after a successful one (RFC 4954 §4), as Postfix does; the proxy relays SMTP after the
  login without looking at it. IMAP and ManageSieve need nothing of the kind: the relay
  keeps `UNAUTHENTICATE` and a second login from the backend (invariant 4), so a backend
  that offers `UNAUTHENTICATE`, such as Stalwart, can be used.
- **Audiences.** Give the mail audience only to mail clients. Any token with an accepted
  audience, issuer and identity opens that mailbox.
- **`token_type = "any"`** also accepts ID tokens that carry an accepted audience; use it
  only for IdPs that mark access tokens neither way.
- **Metrics** have no authentication; bind them to loopback or a management network.
- **Shared source addresses.** The failed-login rate limit counts per address (IPv6 per
  network of `limits.ipv6_source_prefix`, by default /64). Everyone behind one NAT,
  webmail server or IPv6 network shares that count, so one guesser there can block the
  others; a shorter prefix such as 48 widens that group. Put such relays you trust into
  `auth_ratelimit.exempt_networks`; the default exempts only loopback.
- **Session lifetime.** A revoked token, or an account locked in the directory or the
  IdP, does not end an open session: the credential is checked once, at login. Set
  `session.max_session_secs` to bound how long such a session lives on (off by default),
  or end it at the backend (for example `doveadm kick`). TCP keepalive frees the slots
  of dead peers; `session.idle_limit_secs` is off by default. There is no per-user
  session limit.
- **Trust store.** JWKS fetches trust the system CA store (backends use it too unless
  `ca_file` is set). Keep it limited to CAs you trust to vouch for your identity
  provider.
- **Certificates.** Send the proxy `SIGHUP` after a renewal and check the log: a
  certificate that fails to load is logged with its file and the old one stays in use
  ([INSTALL.md](INSTALL.md#certificates)).
- **Tightening by reload.** A reload that makes a rule stricter (a legacy rule removed or
  narrowed, an issuer removed, a lower limit) applies to connections accepted after it.
  A connection opened before keeps the rules it was accepted with: before login for at
  most `timeouts.preauth_secs`, after login until it ends, since a logged-in session is
  never checked again. To cut off open sessions at once, restart the service or end them
  at the backend (`doveadm kick`). Check the journal or
  `mail_auth_proxy_config_reload_total{result="error"}` after each reload: a refused
  reload leaves the previous configuration in use.

### Offering legacy passwords to the internet

A rule with public networks turns the proxy into a password target. If you need it:

- **Opt-in users.** Prefer `users` / `users_file` (or a per-user opt-in in the backend,
  e.g. a Dovecot passdb filter on a directory group) over `public = true` for everyone.
- **Separate passwords.** Give legacy clients application-specific passwords that differ
  from the SSO password. A guessed or phished legacy password then does not open the SSO
  account and can be revoked on its own.
- **Log-based blocking.** Feed the `authresult` lines (`reason`, `rule`, `pwfp`) to
  CrowdSec or a similar tool; `pwfp` shows the same password sprayed from many addresses.
- **Rate limit.** `[auth_ratelimit]` blocks a guessing source for a while. To watch the
  attempts on such a rule rather than cut them short, disable it or raise `failures`;
  the `authresult` lines then record every attempt.
- **Throttle.** `throttle` stops guessing against one account without asking the backend.
  It also lets anyone lock that account's legacy logins for `window_secs` by failing on
  purpose (OAuth logins are not affected); choose the window with that in mind.
- **Mechanisms and protocols.** Restrict such rules to `mechanisms = ["PLAIN"]` and the
  protocols that are needed.

### Out of scope

- A compromised identity provider or backend.
- Denial of service by volume beyond the built-in connection limits.
- Password strength, and brute-force blocking beyond the per-account throttle and the
  per-source rate limit of this process: firewall bans, bans across hosts or services, and
  distributed guessing from many addresses (use the `authresult` log with a blocking
  tool).

## Reporting a vulnerability

**Do not open public GitHub issues for security vulnerabilities.** Report them privately,
either through GitHub's private vulnerability reporting ("Report a vulnerability" on the
repository's Security tab) or by email to security@nk-it.cloud.

Include the version (`mail-auth-proxy --version`), the relevant configuration without
secrets, and steps or a test that shows the problem.

We acknowledge a report within 7 days and aim to publish a fix within 90 days,
coordinating the disclosure date with the reporter.

## Release signing key

Releases are signed with `0B58 3E99 144D CD9B 5A34  D96B E52C 6D1E FB67 927B`
(`packaging/release-signing-key.asc`). A signature from any other key is not ours.

The signatures are made with its signing subkey
`0D72 6F06 8A40 BCFA 0969  4354 3CC7 3E4D 1408 EDCA`, which expires on 2028-09-26; the
primary key expires on 2029-09-26.
