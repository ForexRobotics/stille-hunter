# Roadmap

Where stille-hunter is heading. This is a direction, not a promise: order and
scope may change as we learn. Each item is tracked as an issue under the
matching [milestone](https://github.com/ForexRobotics/stille-hunter/milestones).

Everything here stays inside the project's fixed limits: read-only,
search-only, self-contained. No hacking back, no downloading or keeping leaked
data, no touching anyone else's systems.

## v0.1 — the detection loop (released)

Pluggable canary types (`member`, `aws_key`, `api_token`) and check sources
(`hibp`, `github`), tied together by a secret ledger. Plant a canary, search
for it, trace a hit back to where it was planted.

## v0.2 — more things to plant

- New canary types: `mcp_config`, `azure_credential`, `kubeconfig`, `db_dump`.
- Publish to PyPI (`pip install stille-hunter`).
- CI: run the test suite and check DCO sign-off on every pull request.

## v0.3 — more places to look, and tell me when it hits

- New free sources: GitLab code search, public paste sites.
- Notifications when a canary is found (email, webhook for Slack / Discord).
- A guide for running `check` unattended (cron, GitHub Actions).

Goal: plant, forget, and get told when something leaks.

## v0.4 — inbox detection as a first-class path

- `stille-hunter inbox`: match mail received on your catch-all against the
  ledger, so the inbox path is handled by the tool, not by hand.
- The inbox domain is **yours to choose**: any domain you control, passed with
  `--self-domain` at generation time and read from config when matching.
  A domain unrelated to your organisation's name is harder to spot as a trap.
- A setup guide for the catch-all (DNS and mail).
- German locale (`--locale de`) for member records.

## v0.5 — tools for running it day to day

- Ledger management: list canaries by where they were planted, retire and
  rotate them.
- Hit history and a summary report.

## v1.0 — a stable contract

- Freeze the ledger format and the `CanaryType` / `CheckSource` plugin
  contracts as the public API.
- Traditional Chinese (Taiwan) locale (`--locale zh-TW`).
- Complete user and plugin-author documentation.

## Proprietary sources (separate package)

Sources whose value depends on not being public — dark-web crawling,
commercial threat-feed matching — ship separately and plug into the same
`CheckSource` contract. The open-source tool never depends on them.

## Not planned

Tokens that "phone home" when opened or used (beacons on someone else's
machine reporting to an external server). That is a different, well-served
technique; stille-hunter finds what has leaked by looking for it.
