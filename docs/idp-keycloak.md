# Identity provider: Keycloak

How to set up Keycloak so that mail clients get access tokens the proxy (and the Dovecot
`oauth2` passdb behind it) accept, and the matching `[[oauth.issuers]]` entry. The client
and scope settings below were read from a working installation (Keycloak 26, several mail
clients in one realm) and translated to example names; the proxy-side semantics come from
the code (see [architecture.md](architecture.md#oauth-token-validation)).

Example values:

| Name | Value |
|---|---|
| Keycloak base URL | `https://sso.example.org` |
| realm | `mail` |
| mail audience | `mail` |
| mail clients | `thunderbird`, `webmail` |

## What the proxy checks

For each token, against the issuer entry whose JWKS holds the signing key:

| Token part | Requirement | Keycloak source |
|---|---|---|
| signature | a key from the issuer's JWKS, algorithm from the key, within `allowed_algorithms` | realm keys (`/realms/<realm>/protocol/openid-connect/certs`) |
| `iss` | equals `issuer` exactly | `https://sso.example.org/realms/mail` |
| `aud` | contains one of `audiences` | audience mapper (below) |
| `exp`, `nbf` | valid, with `oauth.leeway_secs` (default 60 s) | access token lifespan |
| `typ` claim | `Bearer` (`token_type = "keycloak"`) | set by Keycloak on access tokens; ID tokens carry `ID` |
| `email` | one plain address (the default `identity_claim`) | `email` client scope |
| `email_verified` | JSON `true` (default when the identity is `email`) | `email` client scope, the user's "Email verified" flag |
| `azp` | one of `allowed_clients`, if set | the client ID |

## Realm

One realm per issuer. The issuer URL is `https://sso.example.org/realms/mail`; it must be
exactly what Keycloak puts into `iss`, so set the realm's frontend URL (or the server's
hostname) to the public name clients use.

Users need an email address with "Email verified" on, otherwise their tokens fail with
`email not verified` in the proxy's debug log.

## Mail audience

The proxy and the backend accept a token only if `aud` contains the mail audience. Give
that audience only to mail clients: any token with it opens the user's mailbox.

1. Create a client scope `mail` (protocol OpenID Connect) with a mapper of type
   *Audience*: *Included Client Audience* `mail` (a client with that ID that stands for
   the mail backend and has every flow switched off), *Add to access token* on, *Add to ID
   token* off. This is the form of the working installation; *Included Custom Audience*
   `mail` needs no extra client but was **not verified** there.
2. Add the client scope `mail` as a *Default* client scope to each mail client, and to
   no other client.

## Mail clients

For each mail client (Thunderbird, a mobile app, a webmail that logs in on behalf of the
user), create an OpenID Connect client:

| Setting | Value |
|---|---|
| Client authentication | off (public client) for desktop and mobile apps; a webmail server may be confidential |
| Standard flow | on |
| Direct access grants | off (no password grant) |
| Implicit flow | off |
| Service accounts | off |
| Proof Key for Code Exchange method | `S256` (Advanced tab) |
| Valid redirect URIs | exactly what the client application uses; see its documentation |
| Default client scopes | `basic`, `email`, `mail` (plus `profile`, `roles` as needed) |
| Always use lightweight access token | off: a lightweight token leaves out claims such as `email` and `email_verified` |
| Full scope allowed | off, unless the client needs realm roles |

Keep group and role lists out of mail tokens: the Dovecot backend rejects SASL responses
above 8 KB of base64. With Dovecot local validation, each client ID also needs its key
directory on the backend. Both are described in
[backend-dovecot-postfix.md](backend-dovecot-postfix.md#oauth2-passdb-with-local-jwks-validation).

## Proxy configuration

```toml
[oauth]
refresh_secs = 300      # periodic JWKS refresh; an unknown kid triggers one sooner
leeway_secs = 60

[[oauth.issuers]]
issuer = "https://sso.example.org/realms/mail"
jwks_url = "https://sso.example.org/realms/mail/protocol/openid-connect/certs"
audiences = ["mail"]
token_type = "keycloak"
identity_claim = "email"            # default
require_email_verified = true       # default for identity_claim = "email"
allowed_algorithms = ["ES256", "ES384", "RS256", "RS384", "RS512"]
infer_key_algorithm = false         # Keycloak publishes "alg" on its keys
allowed_clients = ["thunderbird", "webmail"]   # optional: only these azp values
client_claim = "azp"                # default
```

- `token_type = "keycloak"` is required for Keycloak: it keeps ID tokens (which can carry
  the same audience) out. `rfc9068` expects the JWT header `typ = at+jwt`, which Keycloak
  does not set by default.
- Keycloak's JWKS also lists encryption keys (`use = enc`); the proxy skips them.
- `allowed_algorithms` should list what the realm's active and passive signing keys use.
  A key rotation in Keycloak is picked up by the unknown-`kid` refresh within seconds.
- Several realms (for example one per tenant) are several `[[oauth.issuers]]` entries.
  Each key is accepted only for the realm that published it, so one realm's keys cannot
  sign tokens for another.
- The mail client's user name must be empty, the token's `email`, or its local part;
  anything else is refused as `authzid_mismatch`.

Dovecot needs the same issuers in its `oauth2 { issuers = … }` list
([backend guide](backend-dovecot-postfix.md)).

## Checking a token

Decode an access token of a mail client (for example from the client's debug log, or one
obtained with the authorization-code flow in a test tool) and compare it with the table
above: `iss`, `aud` containing `mail`, `typ` = `Bearer`, `azp` = the client ID, `email`
and `email_verified: true`. A failed login shows the exact reason in the proxy's debug
log (`token rejected: …`, see [operations.md](operations.md#troubleshooting)).
