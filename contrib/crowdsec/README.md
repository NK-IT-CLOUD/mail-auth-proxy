# CrowdSec parser and scenarios

A parser for the `authresult` log line (see [docs/operations.md](../../docs/operations.md#the-authresult-line))
and five scenarios that ban attacking source IPs with the CrowdSec engine and a bouncer.

| File | Name | Fires when | Bucket | `blackhole` |
|---|---|---|---|---|
| `scenarios/mail-auth-proxy-bf.yaml` | `mail-auth-proxy/bf` | failed logins from one **external** IP (bad tokens, `authzid_mismatch`, refused, oversized or rejected passwords; not `protocol`) | leaky, capacity 10, leakspeed 20 s | 5 min |
| `scenarios/mail-auth-proxy-user-enum.yaml` | `mail-auth-proxy/user-enum` | many **different** accounts tried with passwords from one **external** IP | leaky, 5 distinct accounts, leakspeed 1 min | 10 min |
| `scenarios/mail-auth-proxy-password-probe.yaml` | `mail-auth-proxy/password-probe` | passwords sent from an **external** IP where the proxy does not offer them (`blocked_endpoint`) | leaky, capacity 3, leakspeed 1 min | 10 min |
| `scenarios/mail-auth-proxy-slow-bf.yaml` | `mail-auth-proxy/slow-bf` | slow password guessing from an **external** IP | leaky, capacity 2, leakspeed 1 h | 2 h |
| `scenarios/mail-auth-proxy-honeypot-users.yaml` | `mail-auth-proxy/honeypot-users` | a failed password login from an **external** IP with a role or test account name (`admin@`, `postmaster@`, `test@`, …) | trigger | 24 h |

`internal` and `external` are the proxy's `scope` field: internal means the source is in
`scope.internal_networks`. All five scenarios count external sources only.

A leaky bucket holds `capacity` events per source IP and drains one event every
`leakspeed`; the event that finds the bucket full overflows it and raises the alert. For
`bf` that is the 11th counted failure while 10 are still in the bucket: 11 failures within
20 seconds always overflow, and a steady rate above one failure per 20 seconds overflows
after a while. For `slow-bf` it is a third failure while two are pending, for example
three failures within one hour.

`blackhole` is how long the scenario stays silent for the same source after it fired. It
is not the ban length. The ban length comes from the decision profile in the CrowdSec
`profiles.yaml` (the default profile bans an IP for 4 h). To lengthen repeated bans, set
a `duration_expr` in that profile, for example:

```yaml
duration_expr: Sprintf('%dh', (GetDecisionsCount(Alert.GetValue()) + 1) * 4)
```

Internal clients are not banned by these scenarios. Inside `scope.internal_networks` the
protection is the proxy itself: the legacy gate (rules, domains, account check) and the
per-account throttle (`legacy.throttle`). If external traffic reaches the proxy through a
shared address (NAT, a webmail server, a load balancer that does not pass the client
address), all its users share one bucket; whitelist such addresses with a CrowdSec
whitelist parser or add them to `scope.internal_networks`.

Buckets are per address. An IPv6 source is one bucket per /128, so an attacker who rotates
addresses within a /64 is not caught by the per-IP buckets; the hub scenarios behave the
same way.

The honeypot list contains names such as `mail`, `test`, `user` and `admin`. Remove every
name that is a real login on your server.

## Install

The proxy logs to the journal; the parser matches the program name `mail-auth-proxy`, which
is the name under the packaged systemd unit. If the proxy runs under another name (another
unit, a container, a renamed binary), check with `cscli explain` below that the lines are
parsed and adjust the parser filter or `SyslogIdentifier=`.

The package ships these files (not activated) under `/usr/share/doc/mail-auth-proxy/crowdsec/`;
run the commands below from that directory or from `contrib/crowdsec/` in the repository.

```bash
sudo install -m 0644 parsers/s01-parse/mail-auth-proxy-logs.yaml /etc/crowdsec/parsers/s01-parse/
sudo install -m 0644 scenarios/mail-auth-proxy-*.yaml /etc/crowdsec/scenarios/
sudo install -m 0644 acquis/mail-auth-proxy.yaml /etc/crowdsec/acquis.d/
sudo systemctl reload crowdsec
sudo cscli parsers list | grep mail-auth-proxy
sudo cscli scenarios list | grep mail-auth-proxy
```

The parser needs `crowdsecurity/syslog-logs` and `crowdsecurity/dateparse-enrich`, which a
default CrowdSec installation has. A bouncer (for example `crowdsec-firewall-bouncer`) turns
decisions into blocks. Whitelist your own management networks with a CrowdSec whitelist
parser, so that a misconfigured internal client cannot lock them out.

Check that live lines are parsed:

```bash
sudo cscli explain --dsn "journalctl://filters=_SYSTEMD_UNIT=mail-auth-proxy.service" --type syslog
```

## Tests

The directory `contrib/crowdsec/.tests/` in the
[source repository](https://github.com/NK-IT-CLOUD/mail-auth-proxy) (not part of the
package) holds [`cscli hubtest`](https://doc.crowdsec.net/docs/cscli/cscli_hubtest) cases: one
for the parser (every documented reason, lines without the optional `pwfp` and `rule`
fields, IPv6, injected text in the user field, lines that must not match) and one per
scenario, each with negative cases (internal sources, successful logins, repeated single
account, attempts too slow to count). To run them, copy the files into a checkout of
[crowdsecurity/hub](https://github.com/crowdsecurity/hub):

```bash
HUB=/path/to/hub
mkdir -p $HUB/parsers/s01-parse/mail-auth-proxy $HUB/scenarios/mail-auth-proxy
cp parsers/s01-parse/*.yaml $HUB/parsers/s01-parse/mail-auth-proxy/
cp scenarios/*.yaml $HUB/scenarios/mail-auth-proxy/
cp -r .tests/* $HUB/.tests/
cd $HUB && cscli hubtest run --all --clean
```

## Design notes

The scenarios follow the mail scenarios on the CrowdSec hub:

- `crowdsecurity/exim-bf` and `exim-user-bf`: one bucket per IP and one for distinct accounts per IP.
- `Guezli/postfix-sasl-bf`: a slow bucket for distributed guessing that stays below the fast thresholds.
- `Guezli/postfix-honeypot-users`: an instant ban for role account names; the list here leaves
  out names that are often real logins (`contact`, `info`, `support`, `sales`, `noreply`).
- `melite/dovecot-time-based-bf`: detection of evenly spaced, evasive attempts by median
  interval. Not included; the slow bucket covers the common case.

Unlike log-based scenarios for Dovecot or Postfix, these see the proxy's decision itself:
refused passwords (`blocked_endpoint`, `unknown_domain`, `unknown_account`, `throttled`,
`oversize`) never reach the mail server, and a backend outage is never logged as a failed
login, so an outage cannot turn into bans.

The password scenarios (`user-enum`, `slow-bf`, `honeypot-users`) count the password reasons:
`blocked_endpoint`, `unknown_domain`, `unknown_account`, `throttled`, `oversize` (a password
over 1024 bytes) and `backend_reject`. `authzid_mismatch` (a valid token whose XOAUTH2
`user=` / OAUTHBEARER `a=` names another user) is an OAuth failure: only `bf` counts it,
like `bad_token`.
