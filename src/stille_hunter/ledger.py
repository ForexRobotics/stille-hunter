# SPDX-License-Identifier: Apache-2.0
"""Ledger management: list, retire and rotate planted canaries.

    stille-hunter ledger list   ~/.stille/ledgers/*.ledger.jsonl
    stille-hunter ledger retire ~/.stille/ledgers/www.ledger.jsonl --tag www-members
    stille-hunter ledger rotate ~/.stille/ledgers/www.ledger.jsonl --tag www-members \\
        --out new_canaries [generate options...]

A canary is **retired** by stamping `retired_at` (and an optional
`retired_reason`) on its ledger row. The row stays - it is still the record of
what was planted where, and old hits stay explainable - but `check` and `inbox`
skip it. **Rotating** a seed tag generates a fresh batch of the same type and
size for it and retires the old one, in that order: if generating fails,
nothing is retired.

`list` never prints canary values - only counts per seed tag.
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import os
import sys
import tempfile
from collections import Counter, defaultdict
from datetime import datetime, timezone

#: ledger marker field -> canary type, for ledgers written before rows had "type"
_MARKER_TYPES = (
    ("marker", "db_dump"),
    ("aws_access_key_id", "aws_key"),
    ("azure_client_id", "azure_credential"),
    ("mcp_token", "mcp_config"),
    ("kube_token", "kubeconfig"),
    ("api_token", "api_token"),
    ("password_hash", "member"),
    ("user_id", "member"),
)


def row_type(row: dict) -> str:
    """The canary type of a ledger row: its `type`, else inferred from markers."""
    if row.get("type"):
        return str(row["type"])
    for field, name in _MARKER_TYPES:
        if row.get(field):
            return name
    return "unknown"


def is_retired(row: dict) -> bool:
    return bool(row.get("retired_at"))


# ---------------------------------------------------------------------------
#  Reading and writing whole ledgers (all fields kept as they are)
# ---------------------------------------------------------------------------
def read_rows(path: str) -> list[dict]:
    path = os.path.expanduser(path)
    with open(path, encoding="utf-8", newline="") as f:
        if path.endswith(".csv"):
            return [dict(r) for r in csv.DictReader(f)]
        return [json.loads(line) for line in f if line.strip()]


def _dump(rows: list[dict], csv_format: bool) -> str:
    buf = io.StringIO()
    if csv_format:
        fields: list[str] = []
        for r in rows:
            fields.extend(k for k in r if k not in fields)
        w = csv.DictWriter(buf, fieldnames=fields, restval="")
        w.writeheader()
        for r in rows:
            w.writerow(r)
    else:
        for r in rows:
            buf.write(json.dumps(r, ensure_ascii=False) + "\n")
    return buf.getvalue()


def write_rows(path: str, rows: list[dict]) -> None:
    """Rewrite a ledger atomically, keeping its permissions (0600 when new)."""
    path = os.path.expanduser(path)
    try:
        mode = os.stat(path).st_mode & 0o777
    except FileNotFoundError:
        mode = 0o600
    folder = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(prefix=".ledger-", dir=folder)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as f:
            f.write(_dump(rows, path.endswith(".csv")))
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def retire(rows: list[dict], *, tags=(), ids=(), reason: str = "") -> int:
    """Stamp matching active rows as retired, in place. Returns how many."""
    tags, ids = set(tags), set(ids)
    stamp, n = _now(), 0
    for r in rows:
        if is_retired(r):
            continue
        if r.get("seed_tag") in tags or r.get("record_id") in ids:
            r["retired_at"] = stamp
            if reason:
                r["retired_reason"] = reason
            n += 1
    return n


def summary(rows: list[dict]) -> list[dict]:
    """Counts per seed tag - never values."""
    by_tag: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        by_tag[r.get("seed_tag") or "(none)"].append(r)
    out = []
    for tag in sorted(by_tag):
        group = by_tag[tag]
        active = [r for r in group if not is_retired(r)]
        created = sorted(r.get("created_at", "")[:10] for r in group if r.get("created_at"))
        out.append({
            "seed_tag": tag,
            "canaries": len(group),
            "active": len(active),
            "retired": len(group) - len(active),
            "types": dict(Counter(row_type(r) for r in active or group)),
            "inbox": sum(r.get("detect") == "inbox" for r in active),
            "tables": sorted({r["table"] for r in group if r.get("table")}),
            "created": [created[0], created[-1]] if created else [],
        })
    return out


# ---------------------------------------------------------------------------
#  Rotation
# ---------------------------------------------------------------------------
def _has(opts: list[str], flag: str) -> bool:
    return any(o == flag or o.startswith(flag + "=") for o in opts)


def _opt_value(opts: list[str], flag: str) -> str | None:
    """The value given to `flag` in an option list (last one wins)."""
    value = None
    for i, o in enumerate(opts):
        if o == flag and i + 1 < len(opts):
            value = opts[i + 1]
        elif o.startswith(flag + "="):
            value = o.split("=", 1)[1]
    return value


def rotation_plan(rows: list[dict], tag: str, gen_opts: list[str]) -> list[str]:
    """generate options for a replacement batch of `tag` (without --out/--ledger-out).

    Same type and number of active canaries; carries over the locale, the inbox
    domain and the table when the old batch had one and gen_opts does not say
    otherwise."""
    active = [r for r in rows if r.get("seed_tag") == tag and not is_retired(r)]
    if not active:
        raise ValueError(f"no active canaries with seed tag '{tag}'")
    types = Counter(row_type(r) for r in active)
    if _has(gen_opts, "--type"):
        argv = []
    elif len(types) == 1 and "unknown" not in types:
        argv = ["--type", next(iter(types))]
    else:
        raise ValueError(f"seed tag '{tag}' mixes types ({', '.join(sorted(types))}); "
                         "pass --type and --count for the replacement")
    if not _has(gen_opts, "--count"):
        argv += ["--count", str(len(active))]
    argv += ["--tag", tag]
    kind = next(iter(types))
    locales = {r.get("locale") for r in active if r.get("locale")}
    if kind in ("member", "db_dump") and len(locales) == 1 and not _has(gen_opts, "--locale"):
        argv += ["--locale", locales.pop()]
    domains = Counter(r["email"].rsplit("@", 1)[1] for r in active
                      if r.get("detect") == "inbox" and "@" in r.get("email", ""))
    if kind == "member" and domains and not _has(gen_opts, "--self-domain"):
        argv += ["--self-domain", domains.most_common(1)[0][0]]
    tables = {r.get("table") for r in active if r.get("table")}
    if len(tables) == 1 and not _has(gen_opts, "--table"):
        argv += ["--table", tables.pop()]
    return argv + list(gen_opts)


def rotate(path: str, tag: str, out: str, gen_opts: list[str], reason: str = "") -> dict:
    """Generate a replacement batch for `tag`, then retire the old one.

    The new rows are appended to the same ledger. Returns what happened."""
    import contextlib

    from . import generate
    rows = read_rows(path)
    plan = rotation_plan(rows, tag, gen_opts)
    fmt = _opt_value(plan, "--format") or "jsonl"
    seeded_ext, ledger_ext = generate.FORMATS.get(fmt, ("jsonl", "jsonl"))
    folder = tempfile.mkdtemp(prefix="stille-rotate-")
    new_ledger = os.path.join(folder, f"new.ledger.{ledger_ext}")
    try:
        try:
            # generate's own summary would name the temporary ledger; keep it quiet
            with contextlib.redirect_stdout(io.StringIO()):
                generate.main(plan + ["--out", out, "--ledger-out", new_ledger])
        except SystemExit as e:          # generate reports its own usage errors
            if e.code not in (None, 0):
                raise ValueError("generating the replacement failed") from e
        added = read_rows(new_ledger)
    finally:
        for name in os.listdir(folder):
            os.unlink(os.path.join(folder, name))
        os.rmdir(folder)
    retired = retire(rows, tags=[tag], reason=reason or "rotated")
    write_rows(path, rows + added)
    return {"retired": retired, "added": len(added), "generate": plan,
            "seeded": f"{out}.{seeded_ext}"}


# ---------------------------------------------------------------------------
#  CLI: stille-hunter ledger ...
# ---------------------------------------------------------------------------
def _cmd_list(args) -> int:
    report = []
    for path in args.ledger:
        rows = read_rows(path)
        report.append({"ledger": os.path.basename(path), "tags": summary(rows)})
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0
    for item in report:
        print(item["ledger"])
        for t in item["tags"]:
            if not args.all and not t["active"]:
                continue
            types = ", ".join(f"{k} {v}" for k, v in t["types"].items())
            extra = []
            if t["retired"]:
                extra.append(f"{t['retired']} retired")
            if t["inbox"]:
                extra.append(f"{t['inbox']} inbox")
            if t["tables"]:
                extra.append("table " + ", ".join(t["tables"]))
            if t["created"]:
                extra.append("created " + " .. ".join(dict.fromkeys(t["created"])))
            print(f"  {t['seed_tag']}: {t['active']} active ({types})"
                  + (f"; {'; '.join(extra)}" if extra else ""))
    return 0


def _cmd_retire(args) -> int:
    if not args.tag and not args.id:
        raise ValueError("say what to retire: --tag and/or --id")
    rows = read_rows(args.ledger)
    n = retire(rows, tags=args.tag, ids=args.id, reason=args.reason or "")
    if args.dry_run:
        print(f"would retire {n} canar{'y' if n == 1 else 'ies'} in {args.ledger}")
        return 0
    if n:
        write_rows(args.ledger, rows)
    print(f"retired {n} canar{'y' if n == 1 else 'ies'} in {args.ledger}")
    return 0


def _cmd_rotate(args, gen_opts: list[str]) -> int:
    if args.dry_run:
        plan = rotation_plan(read_rows(args.ledger), args.tag, gen_opts)
        print("would run: stille-hunter generate " + " ".join(plan)
              + f" --out {args.out}")
        print(f"then retire the active '{args.tag}' canaries in {args.ledger}")
        return 0
    res = rotate(args.ledger, args.tag, args.out, gen_opts, args.reason or "")
    print(f"rotated '{args.tag}': {res['added']} new canaries added to {args.ledger}, "
          f"{res['retired']} retired")
    print(f"  seeded data : {res['seeded']}  (plant this, then delete the file)")
    print("  then remove the old canaries from where they were planted")
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="stille-hunter ledger",
                                description="Manage canary ledgers: list, retire, rotate.")
    sub = p.add_subparsers(dest="cmd", required=True)

    pl = sub.add_parser("list", help="Canaries per seed tag (counts only, never values).")
    pl.add_argument("ledger", nargs="+")
    pl.add_argument("--all", action="store_true", help="Also show fully retired seed tags.")
    pl.add_argument("--json", action="store_true")

    pr = sub.add_parser("retire", help="Retire canaries so check and inbox skip them.")
    pr.add_argument("ledger")
    pr.add_argument("--tag", action="append", default=[], help="Seed tag (repeatable).")
    pr.add_argument("--id", action="append", default=[], metavar="RECORD_ID",
                    help="One canary's record_id (repeatable).")
    pr.add_argument("--reason", help="Why, kept in the ledger (e.g. 'table dropped').")
    pr.add_argument("--dry-run", action="store_true")

    po = sub.add_parser("rotate",
                        help="Generate a replacement batch for a seed tag, then retire the "
                             "old one. Other options are passed to generate.")
    po.add_argument("ledger")
    po.add_argument("--tag", required=True)
    po.add_argument("--out", default="canary_seeded",
                    help="Seeded file for the new batch, without extension.")
    po.add_argument("--reason", help="Kept in the ledger (default: rotated).")
    po.add_argument("--dry-run", action="store_true")

    args, extra = p.parse_known_args(argv)
    if extra and args.cmd != "rotate":
        p.error(f"unrecognized arguments: {' '.join(extra)}")
    for flag in ("--out", "--ledger-out", "--tag"):
        if args.cmd == "rotate" and _has(extra, flag):
            p.error(f"{flag} is set by rotate itself")
    try:
        if args.cmd == "list":
            code = _cmd_list(args)
        elif args.cmd == "retire":
            code = _cmd_retire(args)
        else:
            code = _cmd_rotate(args, extra)
    except FileNotFoundError as e:
        sys.stderr.write(f"ERROR: ledger not found: {e.filename}\n")
        code = 2
    except (ValueError, json.JSONDecodeError) as e:
        sys.stderr.write(f"ERROR: {e}\n")
        code = 2
    sys.exit(code)
