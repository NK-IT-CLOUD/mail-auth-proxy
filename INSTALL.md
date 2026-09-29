# Installing mail-auth-proxy

The proxy is one static binary for Linux on x86_64 (`x86_64-unknown-linux-musl`, no
runtime dependencies besides the system CA store) with a systemd unit. Packages are
published for Debian/Ubuntu (APT repository) and RHEL-compatible systems (RPM release
asset). Releases, packages and the release signing key are at
<https://github.com/NK-IT-CLOUD/mail-auth-proxy/releases>. Building from source is
described in [CONTRIBUTING.md](CONTRIBUTING.md#building-and-testing).

Before you start, set up the backend and the identity provider:
[docs/backend-dovecot-postfix.md](docs/backend-dovecot-postfix.md) and
[docs/idp-keycloak.md](docs/idp-keycloak.md).

## 1. Install the package

### Debian, Ubuntu (APT repository)

Download the repository key and compare its fingerprint before you add the repository:

```bash
sudo install -d -m755 /etc/apt/keyrings
curl -fsSL https://apt.nk-it.cloud/gpg.key \
  | sudo gpg --batch --yes --dearmor -o /etc/apt/keyrings/nk-it-cloud.gpg
gpg --show-keys /etc/apt/keyrings/nk-it-cloud.gpg
```

> **APT repository key:** `A66E 54ED 9E75 BF3D E610  2ED5 AE60 35D7 D6D3 1EB4` (rsa4096)

If the fingerprint matches, add the repository and install:

```bash
echo "deb [signed-by=/etc/apt/keyrings/nk-it-cloud.gpg] https://apt.nk-it.cloud/apt stable main" \
  | sudo tee /etc/apt/sources.list.d/nk-it-cloud.list
sudo apt update
sudo apt install mail-auth-proxy
```

The key signs the repository index, and APT checks that signature on every update.

### RHEL-compatible systems (RPM)

There is no DNF repository. Download the RPM, the checksum files and the release key from
the [release page](https://github.com/NK-IT-CLOUD/mail-auth-proxy/releases) and verify them
(next section). The RPM header is also signed with the release signing key; import the key
into the RPM database once, so that `dnf` checks that signature (`gpgcheck`) on install:

```bash
sudo rpm --import release-signing-key.asc
rpm -K mail-auth-proxy-X.Y.Z-1.x86_64.rpm        # expect "digests signatures OK"
sudo dnf install ./mail-auth-proxy-X.Y.Z-1.x86_64.rpm
```

### What the package installs

| Path | What |
|---|---|
| `/usr/bin/mail-auth-proxy` | the binary |
| `/etc/mail-auth-proxy/config.toml` | your configuration: created from the example on install where none exists, never changed by an upgrade, `root:mail-auth-proxy` `0640` |
| `/usr/share/mail-auth-proxy/config.example.toml` | the example configuration of the installed version |
| `/etc/mail-auth-proxy/` | directory `root:mail-auth-proxy` `0750` |
| `/usr/lib/systemd/system/mail-auth-proxy.service` | the unit |
| `/usr/lib/sysusers.d/mail-auth-proxy.conf` | the system user and group `mail-auth-proxy` (created on install, no login; an existing group of that name is reused) |
| `/usr/share/doc/mail-auth-proxy/` | README, changelog and the third-party license notices (`THIRD-PARTY-NOTICES.html`) |
| `/usr/share/doc/mail-auth-proxy/copyright` | the license (`.deb`) |
| `/usr/share/licenses/mail-auth-proxy/LICENSE` | the license (`.rpm`) |
| `/usr/share/doc/mail-auth-proxy/crowdsec/` | CrowdSec parser and scenarios as examples, not activated ([contrib/crowdsec](contrib/crowdsec/README.md)) |

The service is **not** enabled or started on install.

### Release archive (`.tar.gz`)

For other distributions each release also has a `.tar.gz` with the static binary, the
README, the changelog, the license, the third-party license notices
(`THIRD-PARTY-NOTICES.html`), the example configuration and the systemd unit. It has no
installer: copy the files into place yourself and create the system user and group
`mail-auth-proxy` without a login shell (see the table above for paths and modes).

## 2. Verify a download

Each release publishes, next to the `.deb`, `.rpm` and `.tar.gz`:

- `SHA256SUMS`: the SHA-256 of every asset,
- `SHA256SUMS.asc`: a detached GPG signature of `SHA256SUMS` made with the release
  signing key.

The release signing key `release-signing-key.asc` is attached to every release and is
`packaging/release-signing-key.asc` in the repository. [SECURITY.md](SECURITY.md) lists
its fingerprint as well.

> **Release signing key:** `0B58 3E99 144D CD9B 5A34  D96B E52C 6D1E FB67 927B`
> (ed25519, `Norbert Krucky (mail-auth-proxy release signing) <developers@nk-it.cloud>`)

```bash
gpg --import release-signing-key.asc
gpg --fingerprint developers@nk-it.cloud   # compare with the fingerprint above
gpg --verify SHA256SUMS.asc SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS
```

The last two commands must succeed ("Good signature" from the release key, and `OK` for every
file you downloaded).

## 3. Configure

Edit `/etc/mail-auth-proxy/config.toml`. The shipped file is commented and OAuth-only;
every key is described in [docs/configuration.md](docs/configuration.md). A minimal
configuration:

```toml
config_version = 2

[server]
hostname = "mail.example.org"

[tls]
cert = "/etc/mail-auth-proxy/tls/fullchain.pem"
key = "/etc/mail-auth-proxy/tls/privkey.pem"

[imap]
listen = "0.0.0.0:993"
backend = { address = "192.0.2.10:10993", verify_name = "imap.example.org", client_ip = "proxy_v2" }

[[oauth.issuers]]
issuer = "https://sso.example.org/realms/mail"
jwks_url = "https://sso.example.org/realms/mail/protocol/openid-connect/certs"
audiences = ["mail"]
token_type = "keycloak"
```

Add `[submission]` and `[sieve]` for SMTP submission and ManageSieve. Password logins
(`[[legacy.rules]]`) stay off until you add a rule; read
[SECURITY.md](SECURITY.md#offering-legacy-passwords-to-the-internet) first.

### Permissions

The service runs as the unprivileged system user `mail-auth-proxy` in the group
`mail-auth-proxy`, with `CAP_NET_BIND_SERVICE` as its only capability. Everything it
reads must be readable by that group and by nobody else:

```bash
sudo install -d -o root -g mail-auth-proxy -m 0750 /etc/mail-auth-proxy/tls
sudo chown root:mail-auth-proxy /etc/mail-auth-proxy/config.toml
sudo chmod 0640 /etc/mail-auth-proxy/config.toml
```

The same applies to the TLS key, a doveadm key file and legacy users/domains files.

### Certificates

The certificates must together cover every name clients use: the public name and, if you
use `sni` in a legacy rule, those names too. One certificate (`tls.cert`) is enough;
further ones (`[[tls.certificates]]`) are chosen by the name the client asks for (SNI). A
client that asks for a name none of them carries is refused in the TLS handshake
([configuration.md](docs/configuration.md#tls-server-names)).

After a renewal, copy the new files into place with the same owner and mode and send the
process `SIGHUP`:

```bash
sudo systemctl reload mail-auth-proxy    # sends SIGHUP
journalctl -u mail-auth-proxy -n 5    # expect "reload: certificate loaded" per certificate
```

`SIGHUP` re-reads the configuration file, every certificate and key, and refreshes every
JWKS without closing open connections ([operations.md](docs/operations.md#reload-sighup)).
A certificate that fails to load is logged at `ERROR` with its file and the old one stays
in use; the other certificates are reloaded. For certbot, a deploy hook can run these commands.

Backend certificates are always verified, against the system trust store or the CAs in
the backend's `ca_file`.

## 4. Check and start

```bash
sudo mail-auth-proxy --check-config /etc/mail-auth-proxy/config.toml   # lists every problem at once
sudo mail-auth-proxy --print-config /etc/mail-auth-proxy/config.toml   # effective configuration
sudo systemctl enable --now mail-auth-proxy
journalctl -u mail-auth-proxy -n 20
```

`--check-config` run as root does not see permission problems; the package's upgrade
script runs it with the service's credentials. To do the same by hand:

```bash
sudo systemd-run --wait --pipe --quiet -p User=mail-auth-proxy -p Group=mail-auth-proxy \
  /usr/bin/mail-auth-proxy --check-config /etc/mail-auth-proxy/config.toml
```

At start the proxy fetches every JWKS; if one is unreachable or has no usable key, it
refuses to start. A successful start logs `imap listener up` (and `submission`/`sieve`)
with the listen and backend addresses. Test with a mail client and look for
`authresult result="ok"` in the journal.

A later change to `config.toml` takes effect with a reload, without closing open
connections: check the file, reload, and look for the result in the journal.

```bash
sudo mail-auth-proxy --check-config /etc/mail-auth-proxy/config.toml
sudo systemctl reload mail-auth-proxy
journalctl -u mail-auth-proxy -n 20    # expect "reload: configuration loaded"
```

New connections use the new configuration, open ones keep theirs until they end. A change
of a listener address, a listener added or removed, or of the metrics endpoint is refused
by the reload (`ERROR … changed <key>: needs a restart`) and needs
`systemctl restart mail-auth-proxy`. A file the reload refuses as invalid changes nothing;
fix it and reload again ([configuration.md](docs/configuration.md#reload)).

## 5. Upgrade

With APT: `sudo apt update && sudo apt upgrade`. With RPM: verify the new RPM and
`dnf install` it as above. Read the [changelog](CHANGELOG.md) before upgrading.

On upgrade the package restarts a **running** service only if the configuration passes
`--check-config` with the service's credentials; otherwise the old process keeps running
and a warning is printed. A stopped service stays stopped. Your `config.toml` is not a
conffile: an upgrade never changes it and asks nothing, so unattended upgrades work. Compare
it with `/usr/share/mail-auth-proxy/config.example.toml` for new settings. (Releases up to
0.2.0 shipped `config.toml` as conffile; upgrading from them keeps your file as it is, and
`dpkg` lists it as an obsolete conffile.)

An upgrade replaces the binary, so it needs this restart; `systemctl reload` would keep
the old binary running. A configuration change needs only a reload ([4](#4-check-and-start)).

On `SIGTERM` (stop, restart) the proxy stops accepting and gives open sessions 10 s to
finish; clients reconnect after that.

## 6. Remove

```bash
sudo apt remove mail-auth-proxy     # keeps /etc/mail-auth-proxy
sudo apt purge mail-auth-proxy      # also removes the configuration
sudo dnf remove mail-auth-proxy     # RPM
```

Removal stops and disables the service. Purge removes `config.toml`; the directory
`/etc/mail-auth-proxy` is removed only if nothing else is left in it. `dnf remove` keeps a
`config.toml` you changed as `config.toml.rpmsave`.

The user and group `mail-auth-proxy` stay, because files you created may belong to them.
When nothing uses them any more, delete them with `sudo userdel mail-auth-proxy` (and
`sudo groupdel mail-auth-proxy` if the group is left).
