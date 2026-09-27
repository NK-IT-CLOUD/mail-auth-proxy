# Documentation

| Document | For | Content |
|---|---|---|
| [../INSTALL.md](../INSTALL.md) | operators | packages, verifying downloads, first configuration, permissions, certificates, start, upgrade, removal |
| [configuration.md](configuration.md) | operators | command line, validation, every configuration key with default and effect |
| [backend-dovecot-postfix.md](backend-dovecot-postfix.md) | operators | Dovecot 2.4 (oauth2 passdb, PROXY v2 listeners, ManageSieve, doveadm API) and Postfix submission (XCLIENT, Dovecot SASL) behind the proxy |
| [idp-keycloak.md](idp-keycloak.md) | operators | Keycloak realm, mail audience, mail clients, the matching `[[oauth.issuers]]` entry |
| [operations.md](operations.md) | operators | logs and the `authresult` line, metrics, signals, log-based blocking, troubleshooting |
| [architecture.md](architecture.md) | operators, developers | request flow, client and backend TLS, legacy gate, SASL, token validation, PROXY/XCLIENT, limits, timeouts |
| [protocols.md](protocols.md) | developers, client authors | IMAP, SMTP submission and ManageSieve dialogs, replies per outcome, sequence diagrams, client incompatibilities |
| [standards.md](standards.md) | developers | conformance to the RFCs, deviation by deviation |
| [../SECURITY.md](../SECURITY.md) | everyone | trust boundaries, threat model, operator duties, reporting a vulnerability |
| [../CONTRIBUTING.md](../CONTRIBUTING.md) | contributors | source layout, build and checks, rules for changes, pull requests |
| [../contrib/crowdsec/README.md](../contrib/crowdsec/README.md) | operators | CrowdSec parser and scenarios for the `authresult` line |
| [../CHANGELOG.md](../CHANGELOG.md) | everyone | changes per release |

All documents describe the current version. Where a document and the code disagree, the
code wins; please report the difference.
