# Plugin author guide

stille-hunter has two kinds of plugin:

- a **canary type** (`CanaryType`) decides *what* gets planted - a member
  record, a key, a token, a config file;
- a **check source** (`CheckSource`) decides *where to look* for planted
  canaries - a breach index, a code search, your own mailbox.

The engine never changes to add either. This guide covers both contracts,
how plugins are found, and how to test and ship one. What is guaranteed to
stay stable is listed in [stability.md](stability.md).

## The limits every plugin keeps

These are not style advice. A plugin that breaks one will not be accepted
here, and should not be built on this tool elsewhere.

- **Read-only, search-only.** A source only *looks up* your own canaries in
  places that are public or that you are authorized to query. It never logs in
  where it is not authorized, never exploits anything, never touches anyone
  else's systems beyond the lookup itself.
- **Never download or keep leaked data.** A source reports *that* and *where*
  a canary appeared - a URL, a breach name, a mailbox - and nothing of the
  leaked material. No dumps, no pages, no message bodies.
- **Self-contained.** No phoning home, no beacons that report from someone
  else's machine. stille-hunter finds leaks by looking for them.
- **Canaries are inert.** A generated secret authenticates to nothing and a
  card number charges nothing. Nothing real is put at risk by planting it.
- **No real people.** Fictional names and addresses only, adults only, no
  national IDs, no CVVs.
- **Never print canary values where they do not belong.** Reports, history,
  notifications and `stats` carry record ids and seed tags, never the values.
- **Standard library first.** The core has no runtime dependencies; a plugin
  in this repository should not add one without a strong reason.

## How plugins are found

1. **Modules in a known package.** Every module in `stille_hunter/types/` and
   `stille_hunter/sources/` (and `stille_hunter_pro.types` / `.sources` when
   installed) is imported, so its `@register_type` / `@register` runs. This is
   the route for plugins contributed to this repository.
2. **Entry points.** Any installed distribution can declare modules under the
   groups `stille_hunter.types` and `stille_hunter.sources`. Installing the
   package is enough:

   ```toml
   # pyproject.toml of your package
   [project.entry-points."stille_hunter.types"]
   env_secret = "my_package.env_secret"

   [project.entry-points."stille_hunter.sources"]
   internal_search = "my_package.internal_search"
   ```

A plugin that fails to import is reported as a warning and skipped; the
others still load. `stille-hunter generate --list-types` and
`stille-hunter check --list-sources` show what was found.

## Writing a canary type

```python
# my_package/env_secret.py
from __future__ import annotations

import secrets
from typing import Iterable

from stille_hunter.generate import CanaryType, new_token, register_type


@register_type
class EnvSecretType(CanaryType):
    name = "env_secret"
    description = "A .env line with an inert webhook signing secret."

    def add_arguments(self, parser):
        parser.add_argument("--var", default="WEBHOOK_SECRET",
                            help="Variable name to write (default: WEBHOOK_SECRET).")

    def generate(self, args, count: int) -> Iterable[dict]:
        for _ in range(count):
            token = new_token()
            secret = f"whsec_{secrets.token_hex(12)}{token}"   # token woven into the tail
            yield {
                "record_id": token,
                "env_line": f"{args.var}={secret}",
                "_detect": "search",
                "_ledger": {"env_secret": secret},
            }
```

```bash
stille-hunter generate --type env_secret --var STRIPE_WEBHOOK_SECRET --count 3 --tag ci-env
```

**The contract**

| member | meaning |
|---|---|
| `name` | unique type name (`--type`). Registering a second type with the same name is an error. |
| `description` | one line for `--list-types`. |
| `add_arguments(parser)` | add *this type's* options to the `generate` parser. The engine adds `--count`, `--tag`, `--format`, `--table`, `--dialect`, `--columns`, `--out`, `--ledger-out`; do not reuse those names. |
| `generate(args, count)` | yield `count` records (dicts). |

**Each record**

- `record_id` - **required**. Use `new_token()` (6 hex characters) and weave it
  into the markers, so any one marker found in a leak traces back to its row.
- the **plantable fields** - everything without a leading `_` is written to the
  seeded output, in the order you give. Make them look like the real thing and
  carry **no** sign of being a canary (no "canary", "test", "fake" ...).
- `_detect` - `"search"` (default) or `"inbox"` for an address on the user's
  own domain (`--self-domain`), caught by `inbox`.
- `_ledger` - the **markers**: `{kind: value}` for each value a source may look
  up. The engine writes them to the ledger with `record_id`, `seed_tag`,
  `detect`, `type`, `table` and `created_at`. Use field names that say what the
  value is (`env_secret`, `aws_access_key_id`); a context value worth keeping
  (a region, a provider) may go here too.

Helpers: `new_token()`, `weighted_choice(options, weights)` for realistic
mixes, both from `stille_hunter.generate`. Use `secrets` for randomness.

**Making it searchable.** A source searches the marker kinds it supports. The
`github` source searches a fixed list of secret-looking kinds by default; to
include a new kind, list the kinds in its config:
`"github": {"markers": ["aws_access_key_id", "api_token", "env_secret"]}`.

## Writing a check source

```python
# my_package/internal_search.py
from __future__ import annotations

import json
import urllib.parse
import urllib.request
from typing import Iterable

from stille_hunter.check import Canary, CheckSource, Hit, register


@register
class InternalSearchSource(CheckSource):
    """Look canaries up in our own log-search API (read-only, and we are
    authorized to query it)."""
    name = "internal_search"
    supports = ("email", "env_secret")

    def available(self):
        if not self.config.get("url") or not self.config.get("token"):
            return False, 'needs "url" and "token" under "internal_search"'
        return True, ""

    def check(self, canaries: list[Canary]) -> Iterable[Hit]:
        work = [(c, kind, value) for c in canaries
                for kind, value in c.tokens().items() if kind in self.supports]
        self.stats = {"queries": len(work)}
        for i, (c, kind, value) in enumerate(work):
            self.progress(i, len(work), f"searching {kind}")
            for location in self._search(value):
                yield Hit(canary=c, source=self.name, token_kind=kind,
                          token=value, location=location)
        self.progress(len(work), len(work))

    def _search(self, term: str) -> list[str]:
        url = self.config["url"] + "?" + urllib.parse.urlencode({"q": term})
        req = urllib.request.Request(url, headers={
            "Authorization": f"Bearer {self.config['token']}",
            "User-Agent": "stille-hunter internal_search"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            return [hit["link"] for hit in json.load(resp)["hits"]]
```

```bash
stille-hunter check ledgers/*.ledger.jsonl --sources internal_search --config ~/.stille/config.json
```

with `"internal_search": {"url": "https://logs.internal.example/api/search", "token": "..."}`
in the config.

**The contract**

| member | meaning |
|---|---|
| `name` | unique source name (`--sources`). |
| `supports` | the marker kinds this source can look up. `--list-sources` shows it; reports count only these as "checked". |
| `__init__(**config)` | receives the config section under the source's name as `self.config`. If you override it, call `super().__init__(**config)` - it also sets `self.stats` and `self.progress`. |
| `available()` | `(ok, reason)`. Return `(False, "...")` when something required is missing (an API key); the source is skipped with that reason. Keep it cheap - no network. |
| `check(canaries)` | look the batch up and **yield** a `Hit` per match. |
| `self.stats` | short facts about what the run covered (`{"pages read": 12}`), shown as given in reports. Scalars only, never values. |
| `self.progress(done, total, note)` | call it as you go in a slow source, so an interactive run does not look frozen. |

**`Canary`** (what you receive): `record_id`, `seed_tag`, `detect`, `locale`,
`email`, `user_id`, `password_hash`, `extra` (the type's other markers), and
`tokens()` - every non-empty marker as `{kind: value}`. Retired canaries never
reach a source.

**`Hit`** (what you yield): `canary`, `source`, `token_kind`, `token` (the
matched value; it goes to `--out` only, never to reports, history or
notifications), `location` (where it was found: a URL, a breach name),
`detail` (short extra context - never leaked content), and `found_at`
(defaults to now; set it when the source knows better, as `inbox` does with
the message date).

**Errors.** A miss is not an error: yield nothing. Raise only on a hard
failure (bad credentials, the service down); the frame catches it, reports
the source as failed with your message, keeps the hits you already yielded,
and runs the other sources. Unattended runs notify on such failures, so make
the message say what to fix.

**Being a good client.** Respect the service's rate limits (pace calls with a
`min_interval` config value, as `hibp` and `github` do, and honour
`Retry-After`), send a `User-Agent` that names the tool, and set timeouts.

## Testing a plugin

Register it, run it, and assert on what comes back - no network:

```python
from stille_hunter import check
from stille_hunter.check import Canary


def test_internal_search_finds_a_marker(monkeypatch):
    import my_package.internal_search as mod
    monkeypatch.setattr(mod.InternalSearchSource, "_search",
                        lambda self, term: ["https://logs.internal.example/x"]
                        if term.endswith("abc123") else [])
    c = Canary("abc123", "ci-env", "search", "", "", "", "",
               {"env_secret": "whsec_00abc123"})
    hits, skipped = check.run_check([c], ["internal_search"],
                                    {"internal_search": {"url": "u", "token": "t"}},
                                    show_progress=False)
    assert [h.location for h in hits] == ["https://logs.internal.example/x"]
```

For a canary type, check the safety properties, not only the shape: the token
is in every marker, nothing in the seeded fields marks the row as a canary,
values are inert (wrong checksum, private address, test BIN ...).

## Contributing or shipping separately

- **Here** - a type or source useful to everyone and within the limits above:
  add a module under `src/stille_hunter/types/` or `sources/`, with tests and a
  line in the README table, and open a pull request (see
  [CONTRIBUTING.md](../CONTRIBUTING.md); every commit is signed off).
- **Separately** - something specific to your organisation, or with
  dependencies: put it in your own package and declare an entry point. Pin a
  compatible range, e.g. `stille-hunter>=1.0,<2`: the contracts above hold for
  all of 1.x.
