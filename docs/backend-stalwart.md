# Backend: Stalwart (untested)

> [!WARNING]
> Untested. This page and [examples/config.stalwart.toml](../examples/config.stalwart.toml)
> are written from the Stalwart documentation; the proxy has not run against a Stalwart
> server yet. Stalwart becomes a supported backend after a live test.

Stalwart serves IMAP, submission and ManageSieve itself, validates OAuth access tokens
against an OpenID Connect provider and takes the client address as a PROXY protocol
header. The proxy logs in with the client's own token as OAUTHBEARER.

## What Stalwart must do

1. **Validate the token itself.** A directory of type OIDC
   ([stalw.art/docs/auth/backend/oidc](https://stalw.art/docs/auth/backend/oidc)):
   `issuerUrl` is the proxy's `issuer`; `requireAudience` (default `stalwart`) must be one
   of the proxy's `audiences`; `claimUsername` (default `preferred_username`) should name
   the proxy's `identity_claim`, so the proxy logs the account Stalwart logs in. Stalwart
   takes the token as OAUTHBEARER; the documentation mentions XOAUTH2 as well.
2. **Take the client address from the proxy only.** Stalwart reads PROXY protocol v1 and
   v2 from the networks in `proxyTrustedNetworks` (server-wide) or a listener's
   `overrideProxyTrustedNetworks`
   ([stalw.art/docs/server/reverse-proxy/proxy-protocol](https://stalw.art/docs/server/reverse-proxy/proxy-protocol)).
   Stalwart has no XCLIENT, so submission uses `client_ip = "proxy_v2"` too.
3. **Listeners for the proxy**, reachable only from it (NetworkListener,
   [stalw.art/docs/ref/object/network-listener](https://stalw.art/docs/ref/object/network-listener):
   `protocol` `imap`, `smtp`, `manageSieve`; `tlsImplicit`), with a certificate for the
   name the proxy verifies (`verify_name`).

```json
{"name": "imaptls-proxy", "protocol": "imap", "bind": {"[::]:10993": true},
 "tlsImplicit": true, "overrideProxyTrustedNetworks": {"192.0.2.20/32": true}}
{"name": "submissions-proxy", "protocol": "smtp", "bind": {"[::]:10465": true},
 "tlsImplicit": true, "overrideProxyTrustedNetworks": {"192.0.2.20/32": true}}
{"name": "sieve-proxy", "protocol": "manageSieve", "bind": {"[::]:14190": true},
 "tlsImplicit": true, "overrideProxyTrustedNetworks": {"192.0.2.20/32": true}}
```

`192.0.2.20` is the proxy's address as Stalwart sees it.

## Proxy side

Each backend gets the Stalwart profile: `tls = "implicit"` (or `starttls` for a listener
without `tlsImplicit`), `client_ip = "proxy_v2"`, `auth_forward = "oauthbearer"`. The
whole file is [examples/config.stalwart.toml](../examples/config.stalwart.toml).

```toml
[imap.backend]
address = "192.0.2.30:10993"
verify_name = "mail.example.org"
tls = "implicit"
client_ip = "proxy_v2"
auth_forward = "oauthbearer"
```

## Open points for the live test

- **UNAUTHENTICATE.** Stalwart offers RFC 8437 (IMAP UNAUTHENTICATE) after the login,
  with no switch to turn it off
  ([stalw.art/docs/development/rfcs](https://stalw.art/docs/development/rfcs)), and
  takes it on ManageSieve too. This does not stand in the way: the proxy takes the
  capability out of what it relays and answers the command itself, so it never reaches
  Stalwart, offered or not ([protocols](protocols.md#imap-and-managesieve-after-login)).
- The `LOCAL` PROXY header of the proxy's own ManageSieve and EHLO probes.
- The OAUTHBEARER error result Stalwart sends for a rejected token, and whether it checks
  the GS2 authzid, `host` and `port` the proxy sends.
- ManageSieve over implicit TLS as the proxy's backend (the client side stays STARTTLS).
