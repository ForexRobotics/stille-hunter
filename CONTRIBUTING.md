# Contributing to stille-hunter

Thanks for your interest in contributing. stille-hunter is **human-directed,
AI-built** — contributions from people and from AI assistants are both welcome,
and every change goes through the same gate: a pull request, CI, and human
review before merge.

## The one hard rule: sign off your commits (DCO)

Every commit must be signed off under the [Developer Certificate of
Origin](DCO) (DCO 1.1). Signing off certifies that you have the right to submit
the change under this project's license (Apache-2.0).

Add the sign-off automatically with the `-s` flag:

```bash
git commit -s -m "Your message"
```

This appends a line to the commit message:

```
Signed-off-by: Your Name <your.email@example.com>
```

- The name and email become part of the public, permanent git history.
- The name must be a real identity (a person, or an organization you may sign
  for) — not an anonymous handle.
- If you forgot to sign off, amend the last commit with
  `git commit --amend -s`, or for several commits
  `git rebase --signoff HEAD~<n>`.

Sign off with your own real name and email. Maintainers contributing on behalf
of Forex Robotics Co., Ltd. sign off under their personal name with a company
email, e.g. `Signed-off-by: Jane Doe <jane@forexrobotics.jp>`.

## What stille-hunter will and won't accept

stille-hunter sets a quiet trap and waits. Keep contributions inside that line:

- **Defensive and read-only.** Code may generate canaries you plant yourself,
  and look your own canaries up in public or authorized sources. It must never
  log into places it isn't authorized for, download or store leaked data, or
  reach into anyone else's systems.
- **Standard library first.** The public package has no third-party runtime
  dependencies. A new dependency needs a clear reason and will be discussed in
  the PR.
- **New leak sources are plugins.** Add a source by subclassing `CheckSource`
  and registering it (see `src/stille_hunter/sources/`). The frame shouldn't
  need to change.
- **The ledger stays secret.** Never commit a ledger, a real `config.json`, or
  seeded data. `.gitignore` already excludes them — keep it that way.

## Pull request flow

1. Fork and branch.
2. Make your change. Keep it focused.
3. Run the checks locally:
   ```bash
   pip install -e ".[dev]"
   ruff check .
   pytest
   ```
4. Commit with `-s` (DCO sign-off), push, and open a pull request.
5. CI runs ruff + tests; a human reviews and merges.

## Questions

Open an issue. For anything touching what counts as "defensive," err on the
side of asking first.
