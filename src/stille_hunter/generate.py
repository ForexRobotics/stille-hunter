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
import os
import secrets
import sys
from datetime import datetime, timezone
from typing import Iterable

from . import output


# ---------------------------------------------------------------------------
#  Shared helpers (used by the engine and by type plugins)
# ---------------------------------------------------------------------------
def new_token() -> str:
    """A short, unique, URL/identifier-safe canary token (6 hex chars)."""
    return secrets.token_hex(3)


def weighted_choice(options, weights):
    r = secrets.randbelow(sum(weights))
    upto = 0
    for opt, w in zip(options, weights, strict=True):
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
    """Import every module in each type package so it self-registers, then
    every module declared under the ``stille_hunter.types`` entry-point group
    (how a third-party package ships a type). Returns load problems."""
    from . import _plugins
    return (_plugins.load_packages(packages)
            + _plugins.load_entry_points(_plugins.TYPE_GROUP))


# ---------------------------------------------------------------------------
#  Output
# ---------------------------------------------------------------------------
def _seeded_view(rec: dict) -> dict:
    """The record as planted: drop the engine's bookkeeping keys."""
    return {k: v for k, v in rec.items() if not k.startswith("_")}


def _ledger_row(rec: dict, seed_tag: str, table: str | None = None,
                type_name: str = "") -> dict:
    row = {
        "record_id": rec["record_id"],
        "seed_tag": seed_tag,
        "detect": rec.get("_detect", "search"),
    }
    if type_name:
        row["type"] = type_name   # which CanaryType made it (used by `ledger rotate`)
    # the type's declared searchable markers
    row.update(rec.get("_ledger", {}))
    if table:
        row["table"] = table   # where the rows were planted (not searched for)
    row["created_at"] = datetime.now(timezone.utc).isoformat()
    return row


def write_jsonl(rows: list[dict], f) -> None:
    for row in rows:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")


def write_csv(rows: list[dict], f) -> None:
    if not rows:
        return
    w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
    w.writeheader()
    for row in rows:
        w.writerow(row)


#: --format -> (seeded file extension, ledger extension)
FORMATS = {
    "jsonl": ("jsonl", "jsonl"),
    "csv": ("csv", "csv"),
    "json": ("json", "jsonl"),   # a JSON array, e.g. for a Laravel seeder
    "sql": ("sql", "jsonl"),     # INSERT statements
}


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
        width = max(map(len, _TYPES))
        for name in sorted(_TYPES):
            print(f"{name:{width}}  {_TYPES[name].description}")
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
    p.add_argument("--format", default="jsonl", choices=list(FORMATS),
                   help="jsonl (default), csv, json (a JSON array, e.g. for a Laravel "
                        "seeder), or sql (INSERT statements; needs --table).")
    p.add_argument("--table", default=None,
                   help="Table the rows will be planted in. Required for --format sql; "
                        "recorded in the ledger with any format.")
    p.add_argument("--dialect", default="mysql", choices=list(output.DIALECTS),
                   help="SQL dialect for --format sql (default: mysql).")
    p.add_argument("--columns", default=None,
                   help="Select and rename seeded fields, in order: "
                        "'field=column,field2=column2' (a bare 'field' keeps its name).")
    p.add_argument("--out", default="canary_seeded",
                   help="Seeded file path without extension (default: canary_seeded).")
    p.add_argument("--ledger-out", default=None,
                   help="Where to write the ledger (default: next to the seeded file). "
                        "Keep it outside any app or repository; missing folders are created.")
    canary_type.add_arguments(p)   # the type's own options
    args = p.parse_args(argv)

    try:
        if args.format == "sql" and not args.table:
            raise ValueError("--format sql needs --table")
        table = output.check_table(args.table) if args.table else None
        pairs = output.parse_columns(args.columns) if args.columns else None
        recs = list(canary_type.generate(args, args.count))
        seeded = [output.apply_columns(_seeded_view(r), pairs) for r in recs]
    except ValueError as e:
        sys.stderr.write(f"ERROR: {e}\n")
        sys.exit(2)
    ledger = [_ledger_row(r, args.tag, table, known.type) for r in recs]

    seeded_ext, ledger_ext = FORMATS[args.format]
    seeded_path = f"{args.out}.{seeded_ext}"
    ledger_path = (os.path.expanduser(args.ledger_out) if args.ledger_out
                   else f"{args.out}.ledger.{ledger_ext}")
    if os.path.dirname(ledger_path):
        os.makedirs(os.path.dirname(ledger_path), exist_ok=True)
    inbox_n = sum(1 for r in recs if r.get("_detect") == "inbox")

    with open(seeded_path, "w", encoding="utf-8", newline="") as sf:
        if args.format == "sql":
            output.write_sql(seeded, table, args.dialect, sf)
        elif args.format == "json":
            output.write_json_array(seeded, sf)
        elif args.format == "csv":
            write_csv(seeded, sf)
        else:
            write_jsonl(seeded, sf)
    with open(ledger_path, "w", encoding="utf-8", newline="") as lf:
        (write_csv if ledger_ext == "csv" else write_jsonl)(ledger, lf)

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
