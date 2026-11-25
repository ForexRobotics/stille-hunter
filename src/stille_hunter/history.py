# SPDX-License-Identifier: Apache-2.0
"""Hit history across runs, and a summary of it.

    stille-hunter check ledgers/*.ledger.jsonl --sources hibp --history ~/.stille/history.jsonl
    stille-hunter history ~/.stille/history.jsonl --days 30          # text
    stille-hunter history ~/.stille/history.jsonl --days 30 --json   # for scripts

`check --history PATH` (and `inbox --history PATH`) appends **one JSON line per
run**: when it ran, the version, the ledgers, each source's outcome, and the
hits - which canary, which marker kind, which source, where and when. It is
built from the same data as the per-run report and follows the same rule:
**never a canary value, never leaked content.** Seed tags say where canaries
are planted, so the file is written readable by its owner only.

`stille-hunter history` summarises it over a period: runs and failures per
source, hits per seed tag and per source, and per canary when it was first and
last seen and whether it is new in the period. A daily check finds the same
leak every day; telling a new leak from a known one is the point.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone

#: format version of one history line
SCHEMA = 1


def entry(rep: dict) -> dict:
    """One history line from a run's report dict (see report.build)."""
    return {
        "schema": SCHEMA,
        "started_at": rep["started_at"],
        "finished_at": rep["finished_at"],
        "version": rep["version"],
        "ledgers": list(rep.get("ledgers") or []),
        "canaries": rep["summary"]["canaries"],
        "sources": [{k: s.get(k) for k in ("name", "status", "reason", "hits")}
                    for s in rep.get("sources") or []],
        # report hits already leave the matched value out
        "hits": [{k: h.get(k) for k in ("record_id", "seed_tag", "source", "token_kind",
                                        "location", "detail", "found_at")}
                 for h in rep.get("hits") or []],
    }


def append(path: str, line: dict) -> None:
    """Append one line; the file is created readable by its owner only."""
    path = os.path.expanduser(path)
    if os.path.dirname(path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as f:
        f.write(json.dumps(line, ensure_ascii=False) + "\n")


def load(path: str) -> list[dict]:
    """All lines of a history file; a torn or foreign line is skipped."""
    out = []
    with open(os.path.expanduser(path), encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except ValueError:
                continue
            if isinstance(item, dict) and "started_at" in item:
                out.append(item)
    return out


def _when(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _day(dt: datetime | None) -> str:
    return dt.astimezone(timezone.utc).date().isoformat() if dt else ""


def summarise(entries: list[dict], *, days: int | None = 30, now: datetime | None = None,
              retired: set[str] | None = None) -> dict:
    """The summary as a plain dict (the --json form).

    `days` None or 0 means the whole history. `retired` is a set of record_ids
    to mark as retired (from the ledger); their hits stay in the history."""
    now = now or datetime.now(timezone.utc)
    start = now - timedelta(days=days) if days else None
    retired = retired or set()

    def in_window(dt):
        return dt is not None and (start is None or dt >= start)

    runs = [e for e in entries if in_window(_when(e.get("started_at")))]
    per_source: dict[str, dict] = {}
    for e in runs:
        for s in e.get("sources") or []:
            st = per_source.setdefault(s.get("name") or "?", {
                "runs": 0, "ok": 0, "error": 0, "skipped": 0, "hits": 0, "last_problem": ""})
            st["runs"] += 1
            status = s.get("status")
            if status in ("ok", "error", "skipped"):
                st[status] += 1
            st["hits"] += int(s.get("hits") or 0)
            if status in ("error", "skipped") and s.get("reason"):
                st["last_problem"] = str(s["reason"])[:200]

    # every hit ever seen, to tell new canaries from known ones
    canaries: dict[str, dict] = {}
    for e in entries:
        run_at = _when(e.get("started_at"))
        for h in e.get("hits") or []:
            rid = h.get("record_id")
            if not rid:
                continue
            seen = _when(h.get("found_at")) or run_at
            c = canaries.setdefault(rid, {"record_id": rid, "seed_tag": h.get("seed_tag", ""),
                                          "first": None, "last": None, "hits": 0,
                                          "sources": set(), "kinds": set()})
            if seen:
                c["first"] = min(filter(None, (c["first"], seen)))
                c["last"] = max(filter(None, (c["last"], seen)))
            if in_window(run_at):
                c["hits"] += 1
                c["sources"].add(h.get("source") or "?")
                c["kinds"].add(h.get("token_kind") or "?")

    by_tag: Counter = Counter()
    by_source: Counter = Counter()
    for e in runs:
        for h in e.get("hits") or []:
            by_tag[h.get("seed_tag") or "(none)"] += 1
            by_source[h.get("source") or "?"] += 1

    rows = []
    for c in canaries.values():
        if not c["hits"]:
            continue                      # not seen in this period
        rows.append({
            "record_id": c["record_id"],
            "seed_tag": c["seed_tag"],
            "first_seen": _day(c["first"]),
            "last_seen": _day(c["last"]),
            "hits": c["hits"],
            "sources": sorted(c["sources"]),
            "markers": sorted(c["kinds"]),
            "new_in_period": bool(c["first"] and in_window(c["first"])),
            "retired": c["record_id"] in retired,
        })
    rows.sort(key=lambda r: (not r["new_in_period"], r["first_seen"], r["record_id"]))

    started = [_when(e.get("started_at")) for e in runs]
    return {
        "tool": "stille-hunter",
        "period": {"days": days or None, "from": _day(start) if start else "",
                   "to": _day(now)},
        "runs": {"count": len(runs),
                 "first": _day(min(started)) if started else "",
                 "last": _day(max(started)) if started else ""},
        "sources": dict(sorted(per_source.items())),
        "hits": {"count": sum(by_tag.values()),
                 "canaries": len(rows),
                 "new_canaries": sum(r["new_in_period"] for r in rows),
                 "by_seed_tag": dict(by_tag.most_common()),
                 "by_source": dict(by_source.most_common())},
        "canaries": rows,
    }


def to_text(s: dict) -> str:
    p = s["period"]
    span = f"last {p['days']} days ({p['from']} .. {p['to']})" if p["days"] else "all history"
    lines = [f"stille-hunter history: {span}"]
    r = s["runs"]
    lines.append(f"runs: {r['count']}" + (f"  ({r['first']} .. {r['last']})" if r["count"] else ""))
    if s["sources"]:
        lines.append("sources:")
        width = max(map(len, s["sources"]))
        for name, st in s["sources"].items():
            parts = [f"{st['runs']} runs", f"{st['ok']} ok"]
            if st["error"]:
                parts.append(f"{st['error']} error")
            if st["skipped"]:
                parts.append(f"{st['skipped']} skipped")
            tail = f"  (last problem: {st['last_problem']})" if st["last_problem"] else ""
            lines.append(f"  {name:{width}}  {', '.join(parts)}{tail}")
    h = s["hits"]
    if not h["count"]:
        lines.append("hits: none")
        return "\n".join(lines) + "\n"
    noun = "canary" if h["canaries"] == 1 else "canaries"
    lines.append(f"hits: {h['count']} on {h['canaries']} {noun}"
                 f"  ({h['new_canaries']} new in this period)")
    lines.append("  by seed tag: " + ", ".join(f"{k} {v}" for k, v in h["by_seed_tag"].items()))
    lines.append("  by source:   " + ", ".join(f"{k} {v}" for k, v in h["by_source"].items()))
    lines.append("canaries:")
    tag_w = max(len(c["seed_tag"] or "-") for c in s["canaries"])
    for c in s["canaries"]:
        mark = "NEW " if c["new_in_period"] else "    "
        note = "  (retired)" if c["retired"] else ""
        lines.append(f"  {mark}{c['record_id']}  {(c['seed_tag'] or '-'):{tag_w}}  "
                     f"first {c['first_seen']}  last {c['last_seen']}  "
                     f"hits {c['hits']}  via {', '.join(c['sources'])}{note}")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
#  CLI: stille-hunter history
# ---------------------------------------------------------------------------
def main(argv=None):
    p = argparse.ArgumentParser(
        prog="stille-hunter history",
        description="Summarise a history file written by `check --history`.")
    p.add_argument("path", help="History file (JSON lines).")
    p.add_argument("--days", type=int, default=30,
                   help="Period to summarise, in days (default 30; 0 = everything).")
    p.add_argument("--json", action="store_true", help="Print JSON instead of text.")
    args = p.parse_args(argv)
    if args.days < 0:
        p.error("--days must be 0 or more")
    try:
        entries = load(args.path)
    except FileNotFoundError:
        sys.stderr.write(f"ERROR: history not found: {args.path}\n")
        sys.exit(2)
    summary = summarise(entries, days=args.days)
    if args.json:
        print(json.dumps(summary, ensure_ascii=False, indent=2))
    else:
        sys.stdout.write(to_text(summary))
