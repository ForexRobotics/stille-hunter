# Changelog

All notable changes to stille-hunter are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
While the version is `0.x`, minor bumps may include breaking changes; see
[RELEASING.md](RELEASING.md).

## [Unreleased]

## [0.1.0] - 2026-11-12

First tagged release. A self-contained leak-canary tool: plant realistic fake
records, then find them if they surface in a breach or public leak. Read-only
and search-only — it never touches anyone else's systems.

### Added
- **Canary generator** (`stille-hunter generate`) with a pluggable `CanaryType`
  architecture — add a type by dropping a module in `stille_hunter/types/`.
  - `member` — full fake member records: locale-consistent names, addresses,
    phones and email domains (`--locale jp|us|gb|ca`), test-BIN card numbers
    that can never be charged, no CVV or national IDs, adults only, with a
    unique token woven through email / user id / password hash.
  - `aws_key` — inert AWS access-key pairs (`AKIA...`), token embedded in the
    tail so they can never collide with a real key.
  - `api_token` — inert service tokens shaped like GitHub / OpenAI / Stripe /
    Slack / generic credentials (`--provider`, `--mix`) (issue #1).
- **Leak checker** (`stille-hunter check`) with a pluggable `CheckSource`
  architecture and a secret ledger mapping each token back to where it was
  planted.
  - `hibp` — looks canary emails up in Have I Been Pwned breaches.
  - `github` — searches public code on GitHub for leaked secret markers
    (keys, tokens, hashes).
  - `null` — reference stub.
  - `Canary.extra` carries type-specific markers so non-member canaries
    (aws_key, api_token, ...) are searchable.
- Two detection paths: **inbox** (catch-all mail on a self-domain) and
  **search** (looking tokens up in leak sources).
- Packaged as an installable `pip`-ready project (src layout, zero runtime
  dependencies, `stille-hunter` CLI entry point), with a pytest suite.
- Apache-2.0 license; DCO sign-off contribution workflow (`DCO`,
  `CONTRIBUTING.md`); project overview and "human-directed, AI-built" diagrams.

[Unreleased]: https://github.com/ForexRobotics/stille-hunter/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/ForexRobotics/stille-hunter/releases/tag/v0.1.0
