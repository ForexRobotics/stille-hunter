# Releasing stille-hunter

## Versioning policy (Semantic Versioning)

stille-hunter uses [SemVer](https://semver.org/): **MAJOR.MINOR.PATCH**.

- **PATCH** (`0.1.0` -> `0.1.1`): bug fixes, doc fixes, no behaviour change for
  existing users.
- **MINOR** (`0.1.0` -> `0.2.0`): new backwards-compatible features — a new
  canary type or check source, a new locale, a new CLI flag.
- **MAJOR** (`0.x` -> `1.0.0`): the first stable public contract. While the
  version is `0.x`, the API and CLI may still change; a breaking change bumps
  **MINOR** (not MAJOR) and is called out in the changelog under that version.

The ledger format and the `CanaryType` / `CheckSource` plugin contracts are the
things to treat as the public API — changing them in an incompatible way is the
signal for a breaking bump.

## Single source of truth

The version lives in **one** place:

    src/stille_hunter/__init__.py   ->   __version__ = "X.Y.Z"

`pyproject.toml` reads it dynamically (hatchling), so never edit the version in
two places. Confirm what the build sees with:

    python -c "import stille_hunter; print(stille_hunter.__version__)"

## Cutting a release

`tools/release.ps1` is a **Windows maintainer helper** (PowerShell) that does
the local half of the flow (bump, changelog date, sign-off commit, tag, push).
It is a convenience only — on Linux/macOS, or if you prefer, use the
manual steps below, which are the portable source of truth. The script contains
no secrets; it only drives `git` and `gh`.

    powershell -ExecutionPolicy Bypass -File .\tools\release.ps1 -Part patch
    #                                                             -Part minor
    #                                                             -Part major
    #   or an explicit version:  -Version 0.2.0
    #   preview only (no changes):  add -DryRun

What it does, in order:

1. Reads the current `__version__`, computes the next one (or uses `-Version`).
2. Writes it back to `src/stille_hunter/__init__.py`.
3. Moves the `## [Unreleased]` notes in `CHANGELOG.md` into a new
   `## [X.Y.Z] - <today>` section and refreshes the compare links.
4. Runs the test suite (`pytest`) — aborts the release if anything fails.
5. `git commit -s -m "Release vX.Y.Z"`, `git tag vX.Y.Z`, then pushes the
   commit and the tag.

Pushing the tag hands over to GitHub Actions (see [Publishing](#publishing)).

### Manual equivalent

If you'd rather not use the script:

1. Add notes under `## [Unreleased]` in `CHANGELOG.md` as you merge changes.
2. Bump `__version__` in `src/stille_hunter/__init__.py`.
3. Move the Unreleased notes into a dated `## [X.Y.Z]` section; update the
   `[Unreleased]` / `[X.Y.Z]` compare links at the bottom.
4. `pytest` (must pass).
5. `git commit -s -m "Release vX.Y.Z"`
6. `git tag vX.Y.Z && git push && git push origin vX.Y.Z`

## Publishing

Pushing a `vX.Y.Z` tag starts `.github/workflows/publish.yml`, which:

1. checks that the tag matches `__version__` (a mismatch stops the release),
2. runs the tests and builds the sdist and wheel,
3. publishes to PyPI with **Trusted Publishing** — GitHub proves its identity
   to PyPI with a short-lived OIDC token, so no PyPI token is stored anywhere,
4. creates the GitHub Release, using this version's CHANGELOG section as notes,
5. announces the release on Discord, if a webhook is configured (below).

Watch it at <https://github.com/ForexRobotics/stille-hunter/actions/workflows/publish.yml>.
If a step fails before the PyPI upload, nothing is published: fix it, delete
the tag (`git push --delete origin vX.Y.Z`, `git tag -d vX.Y.Z`) and tag again.
A version that reached PyPI can never be uploaded again — release a new
patch version instead.

### One-time setup

- **PyPI**: at <https://pypi.org/manage/account/publishing/>, add a pending
  publisher with project name `stille-hunter`, owner `ForexRobotics`,
  repository `stille-hunter`, workflow `publish.yml`, environment `pypi`.
  The first successful run creates the project; after that the publisher is
  permanent.
- **GitHub**: the `pypi` environment is created automatically on the first run.
  Optionally restrict it to `v*` tags under Settings -> Environments -> pypi.
- **Discord** (optional): in the announcement channel, Edit Channel ->
  Integrations -> Webhooks -> New Webhook -> Copy Webhook URL, then store it
  as a repository secret (gh prompts for the value, so it stays out of your
  shell history):

      gh secret set DISCORD_WEBHOOK --repo ForexRobotics/stille-hunter

  Without the secret the announce step is skipped. The webhook URL lets anyone
  post to the channel: keep it only in the secret, never in a file.
