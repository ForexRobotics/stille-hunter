#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""stille-hunter: canary generator engine.

Generates fake-but-realistic canaries to seed as leak tripwires. WHAT kind of
canary is produced is a plugin — a CanaryType. The engine here only ties the
pieces together: pick a type, let it generate records, and write the two output
files (the seeded data you plant, and the secret ledger that maps each canary's
token back to where you planted it).

Canary TYPES are the mirror image of check SOURCES: a type subclasses
CanaryType and registers itself, and the engine never changes to add one.
Built-in types live in stille_hunter.types; proprietary ones ship as
stille_hunter_pro.types and are discovered the same way.

Design principles (every type must honour these):
  * Everything stays on your own turf. This only *generates* data; it never
    touches anyone else's system.
  * A canary must be realistic but inert — it can never authenticate, charge,
    or resolve to anything real, and it carries a unique token so a leak can be
    traced back to where it was planted.
  * No real PII of real people, no minors, no national-ID / card-CVV storage.

Every record carries two bookkeeping markers the engine adds to the ledger:
  * detect = "inbox"  -> caught by a catch-all you control (fast, active)
  * detect = "search" -> found by searching leak sources (the default)
"""
from __future__ import annotations

import argparse
import csv
import json
import secrets
import sys
from datetime import datetime, timezone
from typing import Iterable


# ---------------------------------------------------------------------------
#  Shared helpers (used by the engine and by type plugins)
# ---------------------------------------------------------------------------
def new_token() -> str:
    """A short, unique, URL/identifier-safe canary token (6 hex chars)."""
    return secrets.token_hex(3)


def weighted_choice(options, weights):
    r = secrets.randbelow(sum(weights))
    upto = 0
    for opt, w in zip(options, weights):
        upto += w
        if r < upto:
            return opt
    return options[-1]


# ---------------------------------------------------------------------------
#  The plugin contract
# ---------------------------------------------------------------------------
class CanaryType:
    """Base class for a kind of canary. Subclass, implement, and @register_type.

    A type owns everything specific to its shape: the CLI options it needs, how
    it builds one seeded record, and which fields go into the ledger as
    searchable markers. The engine stays generic.
    """
    #: unique type name, e.g. "member", "aws_key"
    name: str = "base"
    #: one-line description for --list-types
    description: str = ""

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        """Register this type's own CLI options on the generate parser.

        Common options (--count, --tag, --format, --out) are added by the
        engine; a type only adds what is specific to it (e.g. --locale)."""
        return

    def generate(self, args, count: int) -> Iterable[dict]:
        """Yield `count` records. Each record is a dict with:
          * the plantable fields (what gets written to the seeded file), plus
          * "_detect": "inbox" | "search" for this record, and
          * "_ledger": {marker_name: value, ...} — the searchable tokens to
            record in the ledger (email, user_id, key id, hash, record_id...).
        The engine strips the "_"-prefixed keys from the seeded output and
        writes "_ledger" (plus record_id/seed_tag/detect) to the ledger.
        Every record MUST include "record_id"."""
        raise NotImplementedError


# ---------------------------------------------------------------------------
#  Type registry
# ---------------------------------------------------------------------------
_TYPES: dict[str, type[CanaryType]] = {}


def register_type(cls: type[CanaryType]) -> type[CanaryType]:
    if not getattr(cls, "name", None) or cls.name == "base":
        raise ValueError("a CanaryType must set a unique .name")
    if cls.name in _TYPES:
        raise ValueError(f"duplicate canary type: {cls.name}")
    _TYPES[cls.name] = cls
    return cls


def load_type_plugins(packages=("stille_hunter.types", "stille_hunter_pro.types")
                      ) -> list[str]:
    """Import every module in each type package so it self-registers."""
    import importlib
    import pkgutil
    problems: list[str] = []
    for pkg_name in packages:
        try:
            pkg = importlib.import_module(pkg_name)
        except ImportError:
            continue
        for mod in pkgutil.iter_modules(pkg.__path__):
            if mod.name.startswith("_"):
                continue
            try:
                importlib.import_module(f"{pkg_name}.{mod.name}")
            except Exception as e:
                problems.append(f"{pkg_name}.{mod.name}: {e}")
    return problems


# ---------------------------------------------------------------------------
#  Output
# ---------------------------------------------------------------------------
def _seeded_view(rec: dict) -> dict:
    """The record as planted: drop the engine's bookkeeping keys."""
    return {k: v for k, v in rec.items() if not k.startswith("_")}


def _ledger_row(rec: dict, seed_tag: str) -> dict:
    row = {
        "record_id": rec["record_id"],
        "seed_tag": seed_tag,
        "detect": rec.get("_detect", "search"),
    }
    # the type's declared searchable markers
    row.update(rec.get("_ledger", {}))
    row["created_at"] = datetime.now(timezone.utc).isoformat()
    return row


def write_jsonl(records, seed_tag, sf, lf):
    for rec in records:
        sf.write(json.dumps(_seeded_view(rec), ensure_ascii=False) + "\n")
        lf.write(json.dumps(_ledger_row(rec, seed_tag), ensure_ascii=False) + "\n")


def write_csv(records, seed_tag, sf, lf):
    records = list(records)
    if not records:
        return
    sw = csv.DictWriter(sf, fieldnames=list(_seeded_view(records[0]).keys()))
    sw.writeheader()
    lw = csv.DictWriter(lf, fieldnames=list(_ledger_row(records[0], seed_tag).keys()))
    lw.writeheader()
    for rec in records:
        sw.writerow(_seeded_view(rec))
        lw.writerow(_ledger_row(rec, seed_tag))


# ---------------------------------------------------------------------------
#  CLI
# ---------------------------------------------------------------------------
def main(argv=None):
    load_type_plugins()

    # Two-stage parse: first just --type (and the always-available flags), then
    # let the chosen type add its own options.
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("--type", default="member")
    pre.add_argument("--list-types", action="store_true")
    known, _ = pre.parse_known_args(argv)

    if known.list_types:
        for name in sorted(_TYPES):
            print(f"{name:12} {_TYPES[name].description}")
        return

    if known.type not in _TYPES:
        sys.stderr.write(
            f"ERROR: unknown canary type '{known.type}'. "
            f"Available: {', '.join(sorted(_TYPES))}\n")
        sys.exit(2)

    canary_type = _TYPES[known.type]()

    p = argparse.ArgumentParser(
        description="Generate leak canaries (stille-hunter).")
    p.add_argument("--type", default="member",
                   help="Canary type: " + ", ".join(sorted(_TYPES)) + " (default: member)")
    p.add_argument("--list-types", action="store_true",
                   help="List available canary types and exit.")
    p.add_argument("--count", type=int, default=10)
    p.add_argument("--tag", default="default",
                   help="Seed tag: where these canaries will be planted.")
    p.add_argument("--format", default="jsonl", choices=["jsonl", "csv"])
    p.add_argument("--out", default="canary_seeded")
    canary_type.add_arguments(p)   # the type's own options
    args = p.parse_args(argv)

    try:
        recs = list(canary_type.generate(args, args.count))
    except ValueError as e:
        sys.stderr.write(f"ERROR: {e}\n")
        sys.exit(2)

    ext = args.format
    seeded_path, ledger_path = f"{args.out}.{ext}", f"{args.out}.ledger.{ext}"
    inbox_n = sum(1 for r in recs if r.get("_detect") == "inbox")

    with open(seeded_path, "w", encoding="utf-8", newline="") as sf, \
         open(ledger_path, "w", encoding="utf-8", newline="") as lf:
        (write_jsonl if ext == "jsonl" else write_csv)(recs, args.tag, sf, lf)

    detail = (f"({inbox_n} inbox-detect, {len(recs)-inbox_n} search-only)"
              if inbox_n else "(search-only)")
    print(f"wrote {len(recs)} {known.type} canaries {detail}:")
    print(f"  seeded data : {seeded_path}  (plant this in your DB/export)")
    print(f"  ledger      : {ledger_path}")
    print("  !! The ledger is the token -> seed-location map. Move it OUT of this")
    print("     directory to private storage. NEVER commit it, and NEVER plant it")
    print("     anywhere a leak could expose it — it unmasks every canary at once.")


if __name__ == "__main__":
    main()
