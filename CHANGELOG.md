# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] - 2026-09-28

### Security
- Parallel password attempts for one account could all pass the legacy throttle
  before the first backend rejection was counted, so more than `failures` guesses fit
  into one window. Attempts for the same account now take turns (CWE-362).

## [0.1.0] - 2026-09-27

### Added
- Initial public release.

[Unreleased]: https://github.com/NK-IT-CLOUD/mail-auth-proxy/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/NK-IT-CLOUD/mail-auth-proxy/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/NK-IT-CLOUD/mail-auth-proxy/releases/tag/v0.1.0
