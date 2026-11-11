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

The helper script does the whole flow (bump, changelog date, sign-off commit,
tag, push, GitHub release):

    powershell -ExecutionPolicy Bypass -File .\release.ps1 -Part patch
    #                                                       -Part minor
    #                                                       -Part major
    #   or an explicit version:  -Version 0.2.0

What it does, in order:

1. Reads the current `__version__`, computes the next one (or uses `-Version`).
2. Writes it back to `src/stille_hunter/__init__.py`.
3. Moves the `## [Unreleased]` notes in `CHANGELOG.md` into a new
   `## [X.Y.Z] - <today>` section and refreshes the compare links.
4. Runs the test suite (`pytest`) — aborts the release if anything fails.
5. `git commit -s -m "Release vX.Y.Z"`, `git tag vX.Y.Z`, `git push && git push --tags`.
6. `gh release create vX.Y.Z` using that version's changelog section as the notes.

### Manual equivalent

If you'd rather not use the script:

1. Add notes under `## [Unreleased]` in `CHANGELOG.md` as you merge changes.
2. Bump `__version__` in `src/stille_hunter/__init__.py`.
3. Move the Unreleased notes into a dated `## [X.Y.Z]` section; update the
   `[Unreleased]` / `[X.Y.Z]` compare links at the bottom.
4. `pytest` (must pass).
5. `git commit -s -m "Release vX.Y.Z"`
6. `git tag vX.Y.Z && git push && git push --tags`
7. `gh release create vX.Y.Z --notes-file <section>` (or paste the notes).

## PyPI (later)

Not published to PyPI yet. When ready:

    python -m build
    python -m twine upload dist/*

Tag first, then upload the built artifacts for that tag, so the PyPI release and
the git tag always match.
