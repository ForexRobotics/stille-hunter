# Changelog

All notable changes to stille-hunter are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
While the version is `0.x`, minor bumps may include breaking changes; see
[RELEASING.md](RELEASING.md).

## [Unreleased]

### Added
- Database-ready output for any canary type (#20):
  - `--format sql` writes `INSERT` statements (`--dialect mysql|postgres`,
    `--table`); `--format json` writes a JSON array for framework seeders such
    as Laravel's `DB::table()->insert()`.
  - `--columns field=column,...` selects and renames fields to match a schema.
  - `--table` is recorded in the ledger as where the rows were planted.
  - `--ledger-out` writes the ledger to its own path (e.g. private storage),
    so it does not land next to seeded data inside an app.
  - Seeded output never carries anything that marks the rows as canaries.
- `db_dump` canary type: plausible table rows with a searchable reference
  code (e.g. `CUS-A3F8C10421`) that also appears in a free-text note; the
  `github` source searches it as `marker` (#20, formerly #4).

### Changed
- `docs/ledger-format.md` documents every type's ledger fields.

## [0.2.0] - 2026-11-16

### Added
- New canary types, all inert and found by searching:
  - `azure_credential` — Azure service-principal client ID, tenant ID and a
    client secret in the current Entra format (#5).
  - `mcp_config` — an MCP `mcpServers` config block for the GitHub or Slack
    server with a fake token; only official `@modelcontextprotocol`
    packages are referenced (#2).
  - `kubeconfig` — a complete kubeconfig with a bootstrap-format token whose
    id is the canary token, a private-address server and a fake CA blob (#3).
- The `github` source also searches `azure_client_id`.
- CI on every pull request and push to `main`: ruff lint, the test suite on
  Python 3.10–3.14, and a DCO sign-off check on pull requests (#7).
- ruff configuration in `pyproject.toml` with an explicitly pinned rule set
  (E, F, W, I, B; line length 100), and ruff in the `dev` extra.
- Publishing to PyPI: pushing a `vX.Y.Z` tag checks the tag against the
  version, runs the tests, publishes with Trusted Publishing (no stored
  token), and creates the GitHub Release from the changelog (#6).
- Releases are announced on Discord when a `DISCORD_WEBHOOK` secret is set:
  version, release notes (trimmed to Discord's limit) and links, with
  mentions disabled.
- Dependabot keeps the pinned GitHub Actions up to date.
- README badges, and PyPI classifiers for supported Python versions.

### Changed
- Minimum supported Python is now 3.10. Python 3.9 reached end of life in
  October 2025 and is no longer available on current CI runners.
- Code tidied to pass the lint rules: sorted imports, shorter lines, a shared
  helper for North American phone numbers, and an unused variable removed.
  No behaviour change.
- GitHub Actions pinned to full commit SHAs and runners pinned to
  `ubuntu-24.04`, so neither can change what CI runs without a review.
- README images and links are absolute URLs, so they also work on PyPI.
- `tools/release.ps1` now stops after pushing the tag; the publish workflow
  creates the GitHub Release once the PyPI upload has succeeded.

### Fixed
- `api_token --provider` help named a non-existent `random` choice; the
  option for mixing providers is `--mix`.
- `tools/release.ps1` read `CHANGELOG.md` in the Windows code page, which
  would have turned non-ASCII characters into mojibake on release; it now
  reads and writes UTF-8 explicitly.

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

[Unreleased]: https://github.com/ForexRobotics/stille-hunter/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/ForexRobotics/stille-hunter/releases/tag/v0.2.0
[0.1.0]: https://github.com/ForexRobotics/stille-hunter/releases/tag/v0.1.0
