# Contributing

Bug reports, fixes and documentation improvements are welcome. Security problems do not
belong in the issue tracker: report them as described in [SECURITY.md](SECURITY.md).

## How the project is run

- **One maintainer.** The project has a single maintainer who reviews and merges every
  change and decides what goes in. There is no commercial support and no response-time
  promise for issues or pull requests.
- **Canonical repository and GitHub.** Development happens in a private repository.
  GitHub carries the public part of it: the files listed in
  `packaging/public-files.txt`, published with the release tags. Internal planning notes
  and a maintainer file stay private, so the GitHub history is not a copy of the
  canonical one. Pull requests on GitHub are welcome: accepted changes are applied in the
  canonical repository with you credited as author, and reach GitHub with the next
  publication. The pull request is then closed with a link to the commit.
- **License.** The project is MIT-licensed; by contributing you agree that your
  contribution is licensed under the same terms.

## Use of AI tools

Parts of the code and of the documentation were written with the help of AI coding
assistants and reviewed by the maintainer. The same rules apply to every change,
whoever or whatever wrote it: it needs tests for the behaviour it changes, it must pass
all checks below, and the maintainer must understand and review every line. If you used
an AI tool for a contribution, say so in the pull request.

## Source layout

A single crate with a library (`src/lib.rs`) and a thin binary (`src/main.rs`).

| Path | What |
|---|---|
| `src/main.rs` | command line, logging setup, `--check-config` / `--print-config` |
| `src/config.rs` | configuration format 2: schema, validation, warnings, normalisation |
| `src/server/` | startup, listeners and accept loop, TLS material, signals, systemd notification |
| `src/limits.rs` | connection limits at accept |
| `src/proto/imap/`, `smtp/`, `sieve/` | per protocol: pre-auth dialog (`preauth.rs`), session handler (`mod.rs`), backend login (`backend.rs`) |
| `src/auth/token.rs` | JWKS fetching and refresh, local JWT validation |
| `src/auth/legacy.rs`, `account.rs` | the legacy (password) gate, doveadm account check |
| `src/auth/sasl.rs`, `policy.rs`, `mod.rs` | SASL parsing and rebuilding, network matching, the decision shared by all protocols |
| `src/wire/` | line reader, deadlines, backend connect, PROXY protocol v2, byte relay |
| `src/obs/` | the `authresult` log line and Prometheus metrics |
| `tests/` | black-box tests: the real binary against mock Dovecot/Postfix/Pigeonhole backends, a local JWKS and a mock doveadm API (`tests/common/`) |
| `examples/config.example.toml` | example configuration, shipped as the package's config file |
| `packaging/` | systemd unit, sysusers.d, nfpm manifest, maintainer scripts, hermetic build, package smoke test and systemd start test |
| `packaging/public-files.txt`, `public-tree.sh`, `leak-gate*.sh` | release tooling: the list of public paths, the script that builds the public tree from it, and the leak gate (with its self-test) that checks a tree or commit range before publication |
| `contrib/crowdsec/` | CrowdSec parser and scenarios with `cscli hubtest` cases |
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

## Rules for changes

These hold for every change and are what review checks first.

1. **OAuth and passwords are separate paths.** OAuth logins are gated by local token
   validation only. A password is forwarded only when a legacy rule matches source
   network, SNI, protocol, mechanism and user, and the domain, account and throttle checks
   pass, all before any backend contact and failing closed. Nothing in the OAuth path may
   open the password path or the other way round. Every refusal must look like a wrong
   password to the client (same reply, same timing); an outage must never be logged as a
   failed login.
2. **No credential of its own.** The proxy logs in with the client's own token or
   password. No master user, no shared secret, no impersonation; backend TLS is always
   verified and there is no switch to turn that off.
3. **The public interface is API.** The `authresult` log line (field names, order,
   quoting, reason values), log targets, metric names and labels, configuration keys, the
   command line and exit codes are used by log parsers, dashboards and scripts. Changing
   them needs a changelog entry and, before 1.0, at least a minor version. New
   `authresult` fields go at the end.
4. **Security-relevant code gets tests that fail without the change.** For the token
   check, the legacy gate, SASL parsing, the protocol dialogs and limits, add a black-box
   test in `tests/` (or a unit test for pure parsing), and check that it fails when the
   fix is reverted.
5. **No `unsafe`.** The code contains none; keep it that way. New dependencies need a
   reason, must pass `cargo deny`, and must not bring in `openssl` or `ring`.
6. **Docs follow the code.** A change in behaviour updates the matching page under
   `docs/` in the same pull request. Public docs describe the current behaviour only;
   history goes into [CHANGELOG.md](CHANGELOG.md).

## Pull requests

- One topic per pull request, with a description of what changes and why.
- Commit messages: imperative summary line (`fix(sieve): …`, `feat(config): …`,
  `docs: …`), body with the reason.
- All checks above green. Say which tests you added.
