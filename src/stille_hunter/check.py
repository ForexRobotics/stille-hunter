#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""stille-hunter: leak-matcher skeleton (`stille check`).

Reads a canary ledger (produced by canary_gen.py) and checks each canary's
tokens against one or more *sources*. A source is any place a leaked record
might surface: Have I Been Pwned, public code search, a paste site, a threat
feed, and so on.

This file is the PLUGGABLE FRAME only. It does the parts every source shares —
load the ledger, pick which tokens to look for, fan out to the registered
sources, collect hits, report them — and leaves the actual lookups to small
plugins that implement one method. A real source (HIBP, GitHub, ...) is added
by subclassing CheckSource and registering it; the frame does not change.

Design notes (stille-hunter principles):
  * Read-only, search-only. A source may only *look up* a token in a public or
    authorized place. It never logs in anywhere it shouldn't, never downloads
    or stores leaked data, never touches anyone else's system beyond a lookup.
  * detect flag decides eligibility. Canaries flagged detect=inbox are caught
    by catch-all mail, not here; by default `check` only looks at detect=search
    canaries. --include-inbox overrides (e.g. to also search for self-domain
    addresses that may have leaked).
  * A source gets TOKENS to look for, not raw records. The only things worth
    searching are the unique markers: record_id, the email, the user_id, and
    the password_hash. Everything else in a record is filler.
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable


# ---------------------------------------------------------------------------
#  Data carried through the pipeline
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Canary:
    """One ledger entry, reduced to what a source needs."""
    record_id: str
    seed_tag: str
    detect: str          # "inbox" | "search"
    locale: str
    email: str
    user_id: str
    password_hash: str

    def tokens(self) -> dict[str, str]:
        """The searchable markers for this canary, keyed by kind."""
        return {
            "email": self.email,
            "user_id": self.user_id,
            "password_hash": self.password_hash,
            "record_id": self.record_id,
        }


@dataclass
class Hit:
    """A source found a canary token somewhere it shouldn't be."""
    canary: Canary
    source: str          # source name, e.g. "hibp"
    token_kind: str      # which marker matched, e.g. "email"
    token: str           # the matched value
    location: str        # where it was found (URL, breach name, ...)
    detail: str = ""     # free-form extra context
    found_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return {
            "record_id": self.canary.record_id,
            "seed_tag": self.canary.seed_tag,
            "locale": self.canary.locale,
            "source": self.source,
            "token_kind": self.token_kind,
            "token": self.token,
            "location": self.location,
            "detail": self.detail,
            "found_at": self.found_at,
        }


# ---------------------------------------------------------------------------
#  The plugin contract
# ---------------------------------------------------------------------------
class CheckSource:
    """Base class for a leak source. Subclass and implement check().

    A source must be side-effect-free beyond read-only lookups: no login to
    places you aren't authorized for, no downloading or storing leaked data,
    no touching third-party systems beyond the lookup itself.
    """
    name: str = "base"
    #: which token kinds this source can meaningfully search for
    supports: tuple[str, ...] = ("email", "user_id", "password_hash", "record_id")

    def __init__(self, **config):
        self.config = config
        # The frame sets this to a callable(done:int, total:int, note:str).
        # A slow source should call self.progress(i, n, "...") as it goes so
        # the run doesn't look frozen. Default is a no-op.
        self.progress = lambda done, total, note="": None

    def available(self) -> tuple[bool, str]:
        """Return (ok, reason). A source that needs an API key it doesn't have
        returns (False, "...") and is skipped with that reason reported."""
        return True, ""

    def check(self, canaries: list[Canary]) -> Iterable[Hit]:
        """Look the canaries up and yield a Hit for each match found.

        Receives the whole batch so a source can use bulk endpoints (e.g. HIBP
        domain search, a single query of many tokens) instead of one call per
        canary. Must not raise for an individual miss; raise only on a hard
        failure (network/auth), which the frame catches and reports per-source.
        """
        raise NotImplementedError


# ---------------------------------------------------------------------------
#  Source registry  (real sources register themselves here)
# ---------------------------------------------------------------------------
_REGISTRY: dict[str, type[CheckSource]] = {}


def register(cls: type[CheckSource]) -> type[CheckSource]:
    """Decorator: add a CheckSource subclass to the registry by its .name."""
    if not getattr(cls, "name", None) or cls.name == "base":
        raise ValueError("a CheckSource must set a unique .name")
    if cls.name in _REGISTRY:
        raise ValueError(f"duplicate source name: {cls.name}")
    _REGISTRY[cls.name] = cls
    return cls


# Sources live in the stille_hunter.sources subpackage and register themselves
# when imported (see load_plugins). Proprietary sources ship as a separate
# package, stille_hunter_pro.sources, discovered the same way.


# ---------------------------------------------------------------------------
#  Ledger loading
# ---------------------------------------------------------------------------
def load_ledger(path: str, include_inbox: bool) -> list[Canary]:
    canaries: list[Canary] = []
    is_csv = path.endswith(".csv")
    with open(path, encoding="utf-8", newline="") as f:
        rows: Iterable[dict]
        if is_csv:
            import csv
            rows = csv.DictReader(f)
        else:
            rows = (json.loads(line) for line in f if line.strip())
        for r in rows:
            detect = r.get("detect", "search")
            if detect == "inbox" and not include_inbox:
                continue
            canaries.append(Canary(
                record_id=r["record_id"],
                seed_tag=r.get("seed_tag", ""),
                detect=detect,
                locale=r.get("locale", ""),
                email=r.get("email", ""),
                user_id=r.get("user_id", ""),
                password_hash=r.get("password_hash", ""),
            ))
    return canaries


# ---------------------------------------------------------------------------
#  Runner
# ---------------------------------------------------------------------------
def run_check(canaries: list[Canary], source_names: list[str],
              source_config: dict, show_progress: bool = True
              ) -> tuple[list[Hit], list[tuple[str, str]]]:
    """Return (hits, skipped) where skipped is [(source_name, reason)]."""
    hits: list[Hit] = []
    skipped: list[tuple[str, str]] = []
    for name in source_names:
        cls = _REGISTRY.get(name)
        if cls is None:
            skipped.append((name, "no such source registered"))
            continue
        src = cls(**source_config.get(name, {}))
        ok, reason = src.available()
        if not ok:
            skipped.append((name, reason or "unavailable"))
            continue
        if show_progress:
            def _report(done, total, note="", _n=name):
                msg = f"\r  [{_n}] {done}/{total} {note}".ljust(60)
                sys.stderr.write(msg)
                sys.stderr.flush()
                if done >= total:
                    sys.stderr.write("\n")
            src.progress = _report
        # only hand a source the token kinds it supports
        eligible = [c for c in canaries if src.supports]
        try:
            hits.extend(src.check(eligible))
        except Exception as e:  # a hard failure in one source must not kill the run
            skipped.append((name, f"error: {e}"))
    return hits, skipped


def load_plugins(packages=("stille_hunter.sources", "stille_hunter_pro.sources")
                 ) -> list[str]:
    """Import every module in each source package so its @register'd sources
    attach themselves. Returns a list of load problems (empty = clean).

    Importing a source module runs its @register at import time. The public
    sources live in stille_hunter.sources; proprietary ones, when installed,
    in stille_hunter_pro.sources — both discovered the same way. A package
    that isn't installed (e.g. the pro one) is skipped silently.
    """
    import importlib
    import pkgutil
    problems: list[str] = []
    for pkg_name in packages:
        try:
            pkg = importlib.import_module(pkg_name)
        except ImportError:
            continue  # package not installed (fine for the optional pro one)
        for mod in pkgutil.iter_modules(pkg.__path__):
            if mod.name.startswith("_"):
                continue
            try:
                importlib.import_module(f"{pkg_name}.{mod.name}")
            except Exception as e:
                problems.append(f"{pkg_name}.{mod.name}: {e}")
    return problems


def main(argv=None):
    # Discover sources from the stille_hunter.sources package (and the pro
    # package if installed). Importing each registers it.
    plugin_problems = load_plugins()

    p = argparse.ArgumentParser(
        description="Check canary ledgers against leak sources (stille-hunter).")
    p.add_argument("ledger", nargs="?",
                   help="Path to a canary ledger (.jsonl or .csv). "
                        "Not needed with --list-sources.")
    p.add_argument("--sources", default="null",
                   help="Comma-separated source names. Registered: "
                        + ",".join(sorted(_REGISTRY)) + " (default: null)")
    p.add_argument("--include-inbox", action="store_true",
                   help="Also check detect=inbox canaries (normally caught by "
                        "catch-all mail, not searched here).")
    p.add_argument("--config", help="Optional JSON file of per-source config "
                                    '(e.g. {"hibp": {"api_key": "..."}}).')
    p.add_argument("--out", help="Write hits as JSONL to this path (default: stdout summary).")
    p.add_argument("--list-sources", action="store_true",
                   help="List registered sources and exit.")
    args = p.parse_args(argv)

    for prob in plugin_problems:
        sys.stderr.write(f"WARNING: could not load source plugin {prob}\n")

    if args.list_sources:
        for name in sorted(_REGISTRY):
            cls = _REGISTRY[name]
            print(f"{name:12} supports={','.join(cls.supports)}")
        return

    if not args.ledger:
        p.error("a ledger path is required (or use --list-sources)")

    source_config = {}
    if args.config:
        try:
            with open(args.config, encoding="utf-8") as f:
                source_config = json.load(f)
        except FileNotFoundError:
            sys.stderr.write(f"ERROR: config file not found: {args.config}\n")
            sys.exit(2)
        except json.JSONDecodeError as e:
            sys.stderr.write(f"ERROR: config file is not valid JSON ({args.config}): {e}\n")
            sys.exit(2)

    try:
        canaries = load_ledger(args.ledger, args.include_inbox)
    except FileNotFoundError:
        sys.stderr.write(f"ERROR: ledger not found: {args.ledger}\n")
        sys.exit(2)
    source_names = [s.strip() for s in args.sources.split(",") if s.strip()]

    hits, skipped = run_check(canaries, source_names, source_config)

    inbox_held = sum(1 for _ in ())  # (informational; inbox excluded at load)
    print(f"checked {len(canaries)} canaries against {len(source_names)} "
          f"source(s): {len(hits)} hit(s)")
    for name, reason in skipped:
        print(f"  source '{name}' skipped: {reason}")

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            for h in hits:
                f.write(json.dumps(h.to_dict(), ensure_ascii=False) + "\n")
        if hits:
            print(f"  wrote {len(hits)} hit(s) to {args.out}")
    else:
        for h in hits:
            print(f"  HIT {h.canary.record_id} [{h.source}] {h.token_kind}="
                  f"{h.token} @ {h.location}")

    # non-zero exit when something leaked, so cron/CI can alert on it
    sys.exit(1 if hits else 0)


if __name__ == "__main__":
    main()
