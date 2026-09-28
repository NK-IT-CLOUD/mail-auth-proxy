# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Metric `process_start_time_seconds`: start time of the process, so restarts show in
  Prometheus.
- Metric `mail_auth_proxy_backend_login_duration_seconds` (histogram by `proto`): how
  long successful backend logins take, from connect to the backend's OK.
- Metrics `mail_auth_proxy_jwks_last_success_timestamp_seconds` and
  `mail_auth_proxy_jwks_refresh_failures_total` by `issuer`: a JWKS that can no longer
  be fetched was only visible as a journal warning while the proxy kept the old keys.
- Metric `mail_auth_proxy_tls_cert_expiry_timestamp_seconds`: `notAfter` of the
  certificate the proxy serves, so an expiring certificate or a renewal without
  `SIGHUP` can be alerted on.
- Metric `mail_auth_proxy_legacy_throttle_evictions_total`: accounts the full throttle
  table dropped while their failure window was running.

### Changed
- `mail_auth_proxy_build_info` has a second label, `commit` (the value of
  `mail-auth-proxy --version`). Queries selecting on `version` keep working; recording
  rules or alerts that list the exact label set of the series need `commit` added.
- The metrics endpoint answers only `GET /metrics` with the exposition text; another
  path is answered 404, another method 405, a malformed request 400 and a request
  head over 4 KiB 431. Scrape configurations with another `metrics_path` must use
  `/metrics`. At most 4 scrapes are served at a time (more connections are closed
  at accept), and the 10 s deadline now covers the whole request head instead of a
  single read.

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
