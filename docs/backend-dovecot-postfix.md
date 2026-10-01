# Backend: Dovecot 2.4 and Postfix

How to set up Dovecot (IMAP, ManageSieve, SASL for Postfix) and Postfix (submission)
behind mail-auth-proxy. The settings below are taken from a working installation
(Dovecot 2.4.5 with Pigeonhole 2.4.5, Postfix with Dovecot SASL, one Keycloak realm per
issuer) and translated to example names. Anything that was not checked against that
installation is marked **not verified**.

Example values used throughout:

| Name | Value |
|---|---|
| proxy address, as the backend sees it | `192.0.2.20` |
| backend host | `192.0.2.10`, certificate name `imap.example.org` |
| issuer | `https://sso.example.org/realms/mail` |
| mail audience | `mail` |

## What the backend must do

The proxy validates every token before it contacts the backend, then logs in with the
same token (as the backend's `auth_forward` mechanism, `XOAUTH2` by default, also when
the client used `OAUTHBEARER`) or the same password (always as `PLAIN`). The backend
therefore needs:

1. TLS on every listener the proxy uses, with a certificate for the name the proxy
   verifies (`verify_name`, or the host part of each address). The proxy verifies it against
   the system trust store or the backend's `ca_file`; verification cannot be turned off.
2. An `oauth2` passdb that validates the token **itself**. The proxy's check is a filter
   in front of the backend, not a replacement for it.
3. The real client address (`client_ip`): PROXY protocol v2 for IMAP and ManageSieve,
   XCLIENT for Postfix submission. Without it (`client_ip = "none"`, a configuration
   warning), the backend logs and rate-limits by the proxy's address.
4. Only if the legacy gate is used: a passdb for passwords, and optionally the doveadm
   HTTP API for the account check.

## Dovecot

### Mechanisms and TLS

```
auth_mechanisms = xoauth2 oauthbearer plain login
ssl = required
ssl_server_cert_file = /etc/ssl/mail/fullchain.pem
ssl_server_key_file = /etc/ssl/mail/privkey.pem
```

`plain login` are needed only for the legacy gate and for Postfix SASL with passwords.
`xoauth2` is what the proxy sends by default; with `auth_forward = "oauthbearer"` on a
backend it sends `oauthbearer` instead (RFC 7628, with the backend's name and port as
`host` and `port`). The working installation uses `xoauth2`; the `oauthbearer` path
against Dovecot is **not verified**.
Keep Dovecot's `auth_failure_delay` at its default (2 s) or set it explicitly; the proxy
pads its own refusals to it (`legacy.failure_delay_ms`).

### Listeners with PROXY protocol v2

Use dedicated listeners for the proxy, so that direct clients and the proxy never share
a port. A listener with `haproxy = yes` requires the PROXY header from every connection,
and Dovecot accepts the header only from `haproxy_trusted_networks`.

```
protocols = imap sieve lmtp
haproxy_trusted_networks = 192.0.2.20/32

service imap-login {
  inet_listener imaps-proxy {
    port = 10993
    ssl = yes          # implicit TLS after the PROXY header
    haproxy = yes
  }
}

service managesieve-login {
  inet_listener sieve-proxy {
    port = 14190
    haproxy = yes      # STARTTLS; ssl = required enforces it
  }
}
```

Matching proxy configuration:

```toml
[imap]
listen = "0.0.0.0:993"
backend = { address = "192.0.2.10:10993", verify_name = "imap.example.org", client_ip = "proxy_v2" }

[sieve]
listen = "0.0.0.0:4190"
backend = { address = "192.0.2.10:14190", verify_name = "imap.example.org", client_ip = "proxy_v2" }
```

The IMAP backend uses implicit TLS and the ManageSieve backend STARTTLS, the defaults.
With `tls = "starttls"` the IMAP backend is reached on a listener without implicit TLS,
upgraded with `STARTTLS`; that path is **not verified** against Dovecot.

`client_ip = "proxy_v2"` (short form `proxy_protocol = true`) on the proxy and
`haproxy = yes` on the listener must be switched
together: a header sent to a listener that does not expect it, or a listener that expects
one and does not get it, makes every login fail with a retry-later reply
(`mail_auth_proxy_backend_errors_total` rises). The ManageSieve capability probe and the
active health checks (`health_check_secs`) the proxy runs on its own behalf send a PROXY
v2 `LOCAL` header, which Dovecot accepts on the same listener.

### OAuth2 passdb with local JWKS validation

Dovecot validates the forwarded token locally, with public keys from a dictionary:

```
oauth2 {
  introspection_mode = local
  issuers = https://sso.example.org/realms/mail
  username_attribute = email
  oauth2_local_validation {
    dict fs {
      fs posix {
        prefix = /etc/dovecot/oauth2-keys/
      }
    }
  }
}

passdb oauth2 {
  mechanisms_filter = xoauth2 oauthbearer
}
```

- `issuers` lists every issuer the proxy accepts (space-separated).
- `username_attribute` must name the same claim as the proxy's `identity_claim`
  (default `email`); the proxy sends that claim's value as the XOAUTH2 `user=` (with
  `auth_forward = "oauthbearer"`: as the GS2 authzid `a=`).
- Dovecot looks up keys as `<azp>/<alg>/<kid>` below the prefix, one PEM public key per
  file (`azp` of a token without that claim: `default`; `/` and `%` in a path component
  escaped as `%2f` and `%25`). Dovecot rejects a client ID that has no directory there,
  even though the proxy accepted the token.
- Dovecot does not fetch a JWKS itself. The working installation fills the directory with
  a small timer job that fetches every issuer's JWKS, converts each key to PEM and writes
  it once per client ID it serves (for example `thunderbird/RS256/<kid>`). Add every mail
  client's ID to that job.
- Keys are cached in memory; after a key is removed, Dovecot needs a restart to forget it.
- The working installation also sets `client_id` in the `oauth2` block. Whether Dovecot
  compares it with the token's `aud` in local mode is **not verified**; the proxy checks
  `aud` against the issuer's `audiences` in any case.

Size limit: Dovecot's login processes accept a SASL response of at most 8192 bytes of
base64 (source of Dovecot 2.4.5, `LOGIN_MAX_AUTH_BUF_SIZE`). XOAUTH2 base64 is about 4/3 ×
(token + 40 bytes), so tokens above about 6 KB fail at the backend with a
`backend_reject`. Keycloak access tokens without group or role lists are 1 to 1.5 KB.
Keep large claims (groups, roles) out of mail tokens.

### Passwords (legacy gate only)

Any passdb that checks the password works (for example `passdb ldap` with `bind = yes`).
The login the client sent must be the account name the backend authenticates: no
`auth_username_format` that strips the domain or folds several logins onto one account,
because the legacy gate judges the login the client sent.

### Account check over the doveadm HTTP API (optional, not verified)

`legacy.account_check = "doveadm"` asks Dovecot whether an account exists before a password
is forwarded. The working installation does not use it, so this part is **not verified**
against a live Dovecot; it follows the Dovecot 2.4 documentation and is covered by the
proxy's tests against a mock API.

```
doveadm_api_key = <a long random key, only for the proxy>
service doveadm {
  inet_listener http {
    port = 8080
    ssl = yes
  }
}
```

```toml
[legacy]
account_check = "doveadm"
doveadm_url = "https://imap.example.org:8080/doveadm/v1"
doveadm_key_file = "/etc/mail-auth-proxy/doveadm.key"   # root:mail-auth-proxy 0640
# doveadm_ca_file = "/etc/mail-auth-proxy/doveadm-ca.pem"
```

With several mail systems behind the proxy, set `account_check` and the `doveadm_*` keys
on each backend instead: a backend's own check replaces the one of `[legacy]` for the
logins routed to it ([configuration](configuration.md#keys)).

Dovecot warns never to expose the doveadm API to untrusted networks: allow the port only
from the proxy's address at the network level.

### SASL for Postfix

```
service auth {
  unix_listener /var/spool/postfix/private/auth {
    mode = 0660
    user = postfix
    group = postfix
  }
}
```

Postfix then offers what `auth_mechanisms` lists and passes XOAUTH2 through to the
`oauth2` passdb.

## Postfix submission

`master.cf`:

```
submission inet  n       -       y       -       -       smtpd
  -o syslog_name=postfix/submission
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_sasl_type=dovecot
  -o smtpd_sasl_path=private/auth
  -o smtpd_relay_restrictions=permit_sasl_authenticated,reject
  -o smtpd_recipient_restrictions=permit_sasl_authenticated,reject
  -o smtpd_authorized_xclient_hosts=192.0.2.20
  -o line_length_limit=16384
```

Matching proxy configuration:

```toml
[submission]
listen = "0.0.0.0:587"
implicit_tls_listen = "0.0.0.0:465"        # optional: implicit TLS for clients (RFC 8314)
backend = { address = "192.0.2.10:587", verify_name = "imap.example.org", client_ip = "xclient" }
```

`implicit_tls_listen` is the proxy's own second listener; both listeners use the same
backend and need nothing on the Postfix side.

### STARTTLS or implicit TLS

With the default `tls = "starttls"` the backend must offer `STARTTLS` in its first EHLO
reply (`smtpd_tls_security_level = encrypt` or `may`). A Postfix `smtps` service with
`-o smtpd_tls_wrappermode=yes` (port 465) is reached with `tls = "implicit"` on the
backend instead. The working installation uses STARTTLS on 587; the implicit-TLS path
against Postfix is **not verified**.

### XCLIENT

List only the proxy in `smtpd_authorized_xclient_hosts`. Postfix advertises `XCLIENT`
only to those hosts; the proxy then sends `XCLIENT HELO=<client's EHLO name> PROTO=ESMTP PORT=<client port>
NAME=[UNAVAILABLE] ADDR=<client>` (HELO, PROTO and PORT as far as Postfix lists them), and
Postfix logs and applies its restrictions with the client's address; the `Received:` header
names the client's EHLO name. `smtpd_helo_restrictions` on the submission service now see
the client's name, as without the proxy. If the proxy is not
listed, Postfix does not advertise `XCLIENT`, the proxy skips the step silently and
Postfix sees the proxy's address.

The proxy refuses the reverse case. A backend that advertises `XCLIENT` while its
`client_ip` is not `xclient` would let the logged-in client send its own `XCLIENT LOGIN=…`, so the
proxy answers every login there with a temporary failure and logs the misconfiguration.
It does the same when a client's own address is in `smtpd_authorized_xclient_hosts`
(Postfix still advertises `XCLIENT` after the proxy's).

Instead of XCLIENT, the submission backend can take a PROXY v2 header
(`client_ip = "proxy_v2"` on the proxy, `-o smtpd_upstream_proxy_protocol=haproxy` on a
service only the proxy reaches; version 2 needs Postfix 3.5 or later). The header carries
only addresses, not the client's EHLO name, and the proxy's own EHLO probe sends a `LOCAL`
header. This path is **not verified** against Postfix; XCLIENT is what the working
installation uses. Do not list the proxy in `smtpd_authorized_xclient_hosts` then: a
backend that offers XCLIENT to a proxy without `client_ip = "xclient"` gets no logins.

### Sender checks and EHLO

`smtpd_sender_login_maps` with `reject_authenticated_sender_login_mismatch` work as
without the proxy, because the SASL login is the token's identity.

The proxy answers the client's EHLO itself, with the extensions this service offers
after STARTTLS as far as the proxy handles them (PIPELINING, SIZE, 8BITMIME, SMTPUTF8,
DSN, ENHANCEDSTATUSCODES, CHUNKING). It reads them with a connection of its own, at
startup and then at most every `submission.capability_cache_secs`, and ends it with
`QUIT`; Postfix logs it as a connection from the proxy without AUTH. Keywords removed
per client address after XCLIENT (`smtpd_discard_ehlo_keyword_address_maps`) are not
seen: remove them for the proxy's address too, or leave them out with
`submission.ehlo_extensions`.

### `line_length_limit`

The proxy sends `AUTH XOAUTH2` (or `AUTH OAUTHBEARER`) without an initial response and the token on its own line,
which Postfix limits by `smtpd_sasl_response_limit` (12288 octets), not by
`line_length_limit` (default 2048). The working installation raises `line_length_limit`
to 16384 on the submission service; whether the default is enough behind the proxy is
**not verified** there. Clients that connect to Postfix directly and send the token as an
initial response on the `AUTH` line need the higher value.

## Checking the setup

From the proxy host, with the backend's CA if it is not in the system store:

```bash
# Postfix: STARTTLS and XCLIENT offered to the proxy
openssl s_client -starttls smtp -connect 192.0.2.10:587 -servername imap.example.org -verify_return_error -crlf
#   then type: EHLO proxy.example.org   (XCLIENT must be listed)
```

Then log in through the proxy with a mail client and check the proxy's
`authresult result="ok"` line, the backend's login log (the client's address, not the
proxy's) and `mail_auth_proxy_backend_errors_total` (unchanged).
