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

## v0.2 — more things to plant (released)

- New canary types: `mcp_config`, `azure_credential`, `kubeconfig`.
- Publish to PyPI (`pip install stille-hunter`).
- CI: run the test suite and check DCO sign-off on every pull request.

## v0.3 — tell me when it hits (released)

- Notifications when a canary is found, or when a source fails (email, and a
  webhook for Slack / Discord / anything else).
- A guide for running `check` unattended (cron, Windows Task Scheduler,
  GitHub Actions).
- SQL and JSON output that drop straight into a database (plain SQL and a
  Laravel seeder path), and a `db_dump` canary type built on them.

Goal: plant, forget, and get told when something leaks.

## v0.4 — a report of every run (released)

- `check --report`: one self-contained HTML page (light and dark) and/or JSON
  for each run - hits without canary values, how each source fared and what
  it covered, and which canaries were checked.
- Sources can say what a run covered (`CheckSource.stats`).
- Several ledgers checked together in one run: one notification, one report.

Goal: see at a glance that the check ran, what it covered, and what it found.

## v0.5 — inbox detection as a first-class path (released as 0.5.1)

- `stille-hunter inbox`: match mail received on your catch-all against the
  ledger, so the inbox path is handled by the tool, not by hand.
- The inbox domain is **yours to choose**: any domain you control, passed with
  `--self-domain` at generation time and read from config when matching.
  A domain unrelated to your organisation's name is harder to spot as a trap.
- A setup guide for the catch-all (DNS and mail).
- German locale (`--locale de`) for member records.

## v0.6 — tools for running it day to day (released)

- Ledger management: list canaries by where they were planted, retire and
  rotate them.
- Hit history across runs and a summary report, built on the per-run JSON
  report.

## v1.0 — a stable contract

- Freeze the ledger format and the `CanaryType` / `CheckSource` plugin
  contracts as the public API.
- Traditional Chinese (Taiwan) locale (`--locale tw`, also `zh-TW`).
- Complete user and plugin-author documentation.

## More places to look (not yet scheduled)

Every source must be an official or public lookup that never downloads leaked
data. Research for v0.3 found that paste sites offer no such search, and that
GitLab's code search cannot span all of GitLab.com. What remains:

- A web search source using the Brave Search API, covering paste sites and the
  open web as far as the engine has indexed them (paid per query).
- A source for your own GitLab - a self-managed instance or your groups - to
  find canaries copied into your own repositories before they leak further.

## Proprietary sources (separate package)

Sources whose value depends on not being public — dark-web crawling,
commercial threat-feed matching — ship separately and plug into the same
`CheckSource` contract. The open-source tool never depends on them.

## Not planned

Tokens that "phone home" when opened or used (beacons on someone else's
machine reporting to an external server). That is a different, well-served
technique; stille-hunter finds what has leaked by looking for it.
