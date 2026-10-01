# Contributing

Bug reports, fixes and documentation improvements are welcome. Security problems do not
belong in the issue tracker: report them as described in [SECURITY.md](SECURITY.md).

## How the project is run

The project has a single maintainer who reviews and merges every change and decides what
goes in. There is no commercial support and no response-time promise for issues or pull
requests.

Development happens in a private canonical repository. GitHub carries its public part:
the files listed in `packaging/public-files.txt`, published with the release tags.
Internal planning notes and a maintainer file stay private, so the GitHub history is not
a copy of the canonical one. Pull requests on GitHub are welcome. An accepted change is
applied in the canonical repository with you credited as author and reaches GitHub with
the next publication; the pull request is then closed with a link to the commit.

The project is MIT-licensed. By contributing you agree that your contribution is licensed
under the same terms.

## Use of AI tools

Parts of the code and of the documentation were written with the help of AI coding
assistants and reviewed by the maintainer. Every change, whoever or whatever wrote it,
needs tests for the behaviour it changes, must pass all checks below, and is read line by
line by the maintainer. If you used an AI tool for a contribution, say so in the pull
request.

## Source layout

A single crate with a library (`src/lib.rs`) and a thin binary (`src/main.rs`).

| Path | What |
|---|---|
| `src/main.rs` | command line, logging setup, `--check-config` / `--print-config` |
| `src/config/` | configuration format 2: loading (`mod.rs`), schema and defaults (`schema.rs`), validation, warnings and normalisation (`validate.rs`), the comparison a reload makes (`reload.rs`) |
| `src/server/` | startup, listeners and accept loop, configuration reload (`reload.rs`), TLS material, signals, systemd notification |
| `src/limits.rs` | connection limits at accept |
| `src/ratelimit.rs` | the failed-login rate limit (`[auth_ratelimit]`) |
| `src/route.rs` | the routes: which backend of a protocol a credential goes to (`[[routes]]`) |
| `src/pool.rs` | backend pools: address health, the order of addresses for a login, failover before the credential, active health check rounds |
| `src/proto/imap/`, `smtp/`, `sieve/` | per protocol: pre-auth dialog (`preauth.rs`), session handler (`mod.rs`), backend login (`backend.rs`); SMTP EHLO extensions from the backend probe (`smtp/ehlo.rs`) |
| `src/auth/token.rs` | JWKS fetching and refresh, local JWT validation |
| `src/auth/legacy.rs`, `account.rs` | the legacy (password) gate, doveadm account check |
| `src/auth/sasl.rs`, `policy.rs`, `mod.rs` | SASL parsing and rebuilding, network matching, the decision shared by all protocols |
| `src/wire/` | line reader, deadlines, backend connect, PROXY protocol v2, byte relay |
| `src/obs/` | the `authresult` log line and Prometheus metrics |
| `tests/` | black-box tests: the real binary against mock Dovecot/Postfix/Pigeonhole backends, a local JWKS and a mock doveadm API (`tests/common/`) |
| `examples/config.example.toml` | example configuration; the package ships it in `/usr/share/mail-auth-proxy/` and creates `config.toml` from it on install |
| `packaging/` | systemd unit, sysusers.d, nfpm manifest, maintainer scripts, hermetic build, package smoke test and systemd start test |
| `packaging/public-files.txt`, `public-tree.sh`, `leak-gate*.sh` | release tooling: the list of public paths, the script that builds the public tree from it, and the leak gate (with its self-test) that checks a tree or commit range before publication |
| `contrib/crowdsec/` | CrowdSec parser and scenarios with `cscli hubtest` cases |
| `fuzz/` | cargo-fuzz targets for the pre-auth parsers, their seed corpus and dictionaries (a crate of its own, see [Fuzzing](#fuzzing)) |
| `docs/` | user documentation ([index](docs/README.md)) |

## Building and testing

The toolchain is pinned in `rust-toolchain.toml` (rustup installs it on first use). The
minimum supported Rust version (MSRV) is 1.88. Building needs a C compiler for aws-lc-rs;
there is no OpenSSL dependency.

```bash
cargo build --release --locked
```

Before sending a change, run what CI runs:

```bash
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cargo +1.88.0 check --locked --all-targets     # MSRV
cargo deny check                               # advisories, licenses, sources (cargo-deny 0.20)
```

`cargo test` starts the real binary many times on loopback ports; it needs no network
access and no root. `HARNESS_LOGS=1 cargo test -- --nocapture` prints the proxy's log of
each test.

If you change `contrib/crowdsec/`, run its hubtest cases as described in
[contrib/crowdsec/README.md](contrib/crowdsec/README.md#tests). Release packages are built by
`packaging/build.sh` in a digest-pinned container; you do not need it for a change.

## Fuzzing

`fuzz/` holds [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) (libFuzzer) targets
for everything that parses bytes from a client or backend before a login. It is a crate
of its own with its own `Cargo.lock` and workspace: `cargo build`, `cargo test`,
`cargo deny` and the main `Cargo.lock` never include it. cargo-fuzz builds the library
with `--cfg fuzzing`, which compiles `src/fuzz_api.rs`, a set of thin wrappers that make
the internal parsers reachable; a normal build does not contain it.

Setup (cargo-fuzz needs a nightly compiler; `rust-toolchain.toml` stays as it is):

```bash
rustup toolchain install nightly --profile minimal
cargo install cargo-fuzz --locked
```

| Target | Code | Checked besides "no panic" |
|---|---|---|
| `sasl` | `auth/sasl.rs`: XOAUTH2, OAUTHBEARER (RFC 7628), PLAIN (RFC 4616), LOGIN fields, base64 | build/parse roundtrips, token and user never span `^A` fields, the authzid rule |
| `line` | `wire/line.rs`: the line reader, SASL cancel, `verb_is` | result equals a model; at most `MAX_LINE` bytes (the input without LFs, repeated past the limit); nothing read past the LF (STARTTLS injection, CVE-2011-0411) |
| `proxyproto` | `wire/proxyproto.rs` (builds headers only) | the header parses back to the addresses (PROXY v2 §2.2) |
| `imap_preauth` | `proto/imap/preauth.rs`: tag, command, LOGIN astrings (atoms, quoted strings, literals `{n}` and `{n+}`), AUTHENTICATE | replies are CRLF lines; nothing read past the credential line; quoting roundtrip |
| `sieve_preauth` | `proto/sieve/preauth.rs`: quoted strings, literals `{n+}` (RFC 5804) | literal limit; nothing read past the credential line; quoting roundtrip |
| `smtp` | `proto/smtp/preauth.rs` (AUTH), `proto/smtp/backend.rs` (replies, RFC 5321 §4.2) | every refusal is answered; reply line limit |
| `token` | `auth/token.rs`: unverified `iss`, header and payload decoding, claim checks | no token without a valid signature passes; the identity is one plain address; error texts carry no control characters |
| `config` | `config::parse`, `config::plan` (the reload comparison) | a valid configuration printed with `--print-config` parses again, is valid and compares as unchanged; two configurations separated by a line `#---` compare symmetrically, with changes exactly when their printed forms differ |
| `backend_auth` | `auth/sasl.rs`: the backend's OAUTHBEARER error result (RFC 7628 §3.2.2) and the forwarded OAUTHBEARER response; `proto/sieve/backend.rs`: the ManageSieve challenge string (RFC 5804 §4) | a status that reaches a log line is a short plain word; nothing read past the challenge; a literal challenge at most 4096 octets; build/parse roundtrip of the forwarded response |
| `tls_not_after` | `server/tls.rs`: the DER walk to a certificate's `notAfter` (RFC 5280 §4.1) | on raw bytes and as the time value in a certificate skeleton: never a time past year 9999, every well-formed time from 1970 on parses |

Run a target from `fuzz/`. New inputs go to the first directory; keep it outside the
repository so the checked-in seed corpus stays small:

```bash
cd fuzz
cargo +nightly fuzz run sasl /tmp/corpus-sasl corpus/sasl -- \
    -dict=dict/sasl.dict -max_total_time=600 -rss_limit_mb=1024
```

`proxyproto` has no dictionary. The workflow `.github/workflows/fuzz.yml` runs every
target for 60 seconds once a week (Saturday 03:00 UTC) and on manual start; it is not
part of the CI of pushes and pull requests. A crash is written to
`fuzz/artifacts/<target>/`; `cargo +nightly fuzz tmin <target> <file>` minimises it.
Every crash becomes a normal regression test in `src/` or `tests/` before it is fixed.

`fuzz/corpus/<target>/` holds a few seed inputs derived from the unit tests (only
`example.org` names and documentation addresses); `fuzz/dict/` the protocol keywords.
Add a seed when a new syntax is supported. `fuzz/target`, `fuzz/artifacts` and
`fuzz/coverage` are not checked in.

## Rules for changes

Review checks these first.

1. **OAuth and passwords are separate paths.** OAuth logins pass on local token
   validation only; passwords pass only through the legacy gate, before any backend
   contact and failing closed ([SECURITY.md](SECURITY.md#invariants)). Nothing in the
   OAuth path may open the password path or the other way round. Every refusal must look
   like a wrong password to the client (same reply, same timing); an outage must never be
   logged as a failed login.
2. **No credential of its own.** The proxy logs in with the client's own token or
   password: no master user, no shared secret, no impersonation. Backend TLS is always
   verified, and there is no switch to turn that off.
3. **The public interface is API.** The `authresult` log line (field names, order,
   quoting, reason values), log targets, metric names and labels, configuration keys, the
   command line and exit codes are used by log parsers, dashboards and scripts. Changing
   them needs a changelog entry and, before 1.0, at least a minor version. New
   `authresult` fields go at the end.
4. **Security-relevant code gets tests that fail without the change.** For the token
   check, the legacy gate, SASL parsing, the protocol dialogs and limits, add a black-box
   test in `tests/` (or a unit test for pure parsing) and check that it fails when the
   fix is reverted.
5. **No `unsafe`, few dependencies.** The code contains no `unsafe`. A new dependency
   needs a reason, must pass `cargo deny`, and must not bring in `openssl` or `ring`.
6. **Docs follow the code.** A change in behaviour updates the matching page under
   `docs/` in the same pull request. Public docs describe the current behaviour only;
   history goes into [CHANGELOG.md](CHANGELOG.md).

## Pull requests

- One topic per pull request, with a description of what changes and why.
- Commit messages: imperative summary line (`fix(sieve): …`, `feat(config): …`,
  `docs: …`), body with the reason.
- All checks above pass. Say which tests you added.
