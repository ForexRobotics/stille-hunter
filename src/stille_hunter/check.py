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

from . import history, notify, report


# ---------------------------------------------------------------------------
#  Data carried through the pipeline
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Canary:
    """One ledger entry, reduced to what a source needs.

    The member-type fields (email/user_id/password_hash) are kept as named
    attributes for convenience and may be empty for non-member canaries. Any
    other ledger markers a canary type recorded (aws_access_key_id, api_token,
    ...) ride along in `extra`, so a source can search whatever a given canary
    actually carries without the frame knowing every type."""
    record_id: str
    seed_tag: str
    detect: str          # "inbox" | "search"
    locale: str
    email: str
    user_id: str
    password_hash: str
    extra: dict = field(default_factory=dict)

    def tokens(self) -> dict[str, str]:
        """All searchable markers for this canary, keyed by kind (named fields
        plus any type-specific markers in `extra`, empties dropped)."""
        out = {
            "email": self.email,
            "user_id": self.user_id,
            "password_hash": self.password_hash,
            "record_id": self.record_id,
        }
        out.update(self.extra)
        return {k: v for k, v in out.items() if v}


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
        # Short facts about what this run covered, e.g. {"pages read": 12,
        # "sites unreachable": 1}, shown as given in `check --report`. Fill
        # it in check(). Never put canary values or leaked content here.
        self.stats: dict[str, object] = {}
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
    """Active canaries of a ledger. Rows stamped `retired_at` (see
    `stille-hunter ledger retire`) are skipped."""
    canaries: list[Canary] = []
    is_csv = path.endswith(".csv")
    with open(path, encoding="utf-8", newline="") as f:
        rows: Iterable[dict]
        if is_csv:
            import csv
            rows = csv.DictReader(f)
        else:
            rows = (json.loads(line) for line in f if line.strip())
        # ledger keys the frame handles itself; everything else is a
        # type-specific marker and goes into Canary.extra.
        # Bookkeeping fields (type, table, retirement) are context, never markers.
        known = {"record_id", "seed_tag", "detect", "locale", "email",
                 "user_id", "password_hash", "created_at", "type", "table",
                 "retired_at", "retired_reason"}
        for r in rows:
            if r.get("retired_at"):
                continue
            detect = r.get("detect", "search")
            if detect == "inbox" and not include_inbox:
                continue
            extra = {k: v for k, v in r.items() if k not in known and v}
            canaries.append(Canary(
                record_id=r["record_id"],
                seed_tag=r.get("seed_tag", ""),
                detect=detect,
                locale=r.get("locale", ""),
                email=r.get("email", ""),
                user_id=r.get("user_id", ""),
                password_hash=r.get("password_hash", ""),
                extra=extra,
            ))
    return canaries


# ---------------------------------------------------------------------------
#  Runner
# ---------------------------------------------------------------------------
@dataclass
class SourceResult:
    """How one source fared in a run (for reports)."""
    name: str
    status: str          # "ok" | "skipped" | "error"
    reason: str = ""
    hits: int = 0
    seconds: float = 0.0
    stats: dict = field(default_factory=dict)


def _safe_stats(stats) -> dict:
    """Keep only short scalar facts from a source's stats."""
    out = {}
    if isinstance(stats, dict):
        for k, v in list(stats.items())[:20]:
            if isinstance(v, (bool, int, float)) or (isinstance(v, str) and len(v) <= 200):
                out[str(k)[:60]] = v
    return out


def run_check(canaries: list[Canary], source_names: list[str],
              source_config: dict, show_progress: bool = True,
              results: list[SourceResult] | None = None,
              ) -> tuple[list[Hit], list[tuple[str, str]]]:
    """Return (hits, skipped) where skipped is [(source_name, reason)].

    Pass a list as `results` to also receive one SourceResult per source."""
    import time
    hits: list[Hit] = []
    skipped: list[tuple[str, str]] = []
    record = results.append if results is not None else (lambda r: None)
    for name in source_names:
        cls = _REGISTRY.get(name)
        if cls is None:
            skipped.append((name, "no such source registered"))
            record(SourceResult(name, "skipped", "no such source registered"))
            continue
        src = cls(**source_config.get(name, {}))
        ok, reason = src.available()
        if not ok:
            skipped.append((name, reason or "unavailable"))
            record(SourceResult(name, "skipped", reason or "unavailable"))
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
        start, found = time.monotonic(), []
        try:
            for hit in src.check(eligible):
                found.append(hit)
            status, why = "ok", ""
        except Exception as e:  # a hard failure in one source must not kill the run
            skipped.append((name, f"error: {e}"))
            status, why = "error", str(e)
        hits.extend(found)       # hits found before a failure are kept
        record(SourceResult(name, status, why, len(found),
                            round(time.monotonic() - start, 1),
                            _safe_stats(getattr(src, "stats", {}))))
    return hits, skipped


def load_plugins(packages=("stille_hunter.sources", "stille_hunter_pro.sources")
                 ) -> list[str]:
    """Import every module in each source package so its @register'd sources
    attach themselves. Returns a list of load problems (empty = clean).

    Importing a source module runs its @register at import time. The public
    sources live in stille_hunter.sources; proprietary ones, when installed,
    in stille_hunter_pro.sources — both discovered the same way. A package
    that isn't installed (e.g. the pro one) is skipped silently.
    Third-party packages declare sources under the ``stille_hunter.sources``
    entry-point group instead; those are loaded too.
    """
    from . import _plugins
    return (_plugins.load_packages(packages)
            + _plugins.load_entry_points(_plugins.SOURCE_GROUP))


def _searched_kinds(results: list[SourceResult]) -> set[str]:
    """Marker kinds that the sources which actually ran can search for."""
    kinds: set[str] = set()
    for r in results:
        cls = _REGISTRY.get(r.name)
        if cls is not None and r.status != "skipped":
            kinds.update(cls.supports)
    return kinds


def main(argv=None):
    # Discover sources from the stille_hunter.sources package (and the pro
    # package if installed). Importing each registers it.
    plugin_problems = load_plugins()

    p = argparse.ArgumentParser(
        description="Check canary ledgers against leak sources (stille-hunter).")
    p.add_argument("ledger", nargs="*",
                   help="Canary ledger(s) (.jsonl or .csv); several are checked "
                        "together in one run. Not needed with --list-sources.")
    p.add_argument("--sources", default="null",
                   help="Comma-separated source names. Registered: "
                        + ",".join(sorted(_REGISTRY)) + " (default: null)")
    p.add_argument("--include-inbox", action="store_true",
                   help="Also check detect=inbox canaries (normally caught by "
                        "catch-all mail, not searched here).")
    p.add_argument("--config", help="Optional JSON file of per-source config "
                                    '(e.g. {"hibp": {"api_key": "..."}}).')
    p.add_argument("--out", help="Write hits as JSONL to this path (default: stdout summary).")
    p.add_argument("--report", action="append", default=[], metavar="PATH",
                   help="Write a report of this run: PATH ending in .html (one "
                        "self-contained page) or .json. Repeatable. Never "
                        "contains canary values.")
    p.add_argument("--report-title", metavar="TEXT",
                   help="Title for --report (default: this host's name).")
    p.add_argument("--history", metavar="PATH",
                   help="Append one line for this run to a history file (JSON lines; "
                        "no canary values). Summarise it with `stille-hunter history`.")
    p.add_argument("--list-sources", action="store_true",
                   help="List registered sources and exit.")
    p.add_argument("--no-notify", action="store_true",
                   help="Do not send notifications for this run, even if configured.")
    p.add_argument("--notify-test", action="store_true",
                   help="Send a test message to the channels under \"notify\" in "
                        "--config, then exit. No ledger needed.")
    args = p.parse_args(argv)

    for prob in plugin_problems:
        sys.stderr.write(f"WARNING: could not load source plugin {prob}\n")

    if args.list_sources:
        width = max(map(len, _REGISTRY))
        for name in sorted(_REGISTRY):
            cls = _REGISTRY[name]
            print(f"{name:{width}}  supports={','.join(cls.supports)}")
        return

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
    notify_cfg = source_config.get("notify") or {}

    if args.notify_test:
        if not notify.channels(notify_cfg):
            sys.stderr.write('ERROR: no "notify" webhook or email in the config\n')
            sys.exit(2)
        problems = notify.notify_test(notify_cfg)
        for prob in problems:
            sys.stderr.write(f"ERROR: notification failed: {prob}\n")
        if not problems:
            print(f"test notification sent via {', '.join(notify.channels(notify_cfg))}")
        sys.exit(1 if problems else 0)

    if not args.ledger:
        p.error("a ledger path is required (or use --list-sources / --notify-test)")
    sys.exit(execute(args, source_config, fail=p.error))


def execute(args, source_config: dict, *, fail=None) -> int:
    """Run a check and do everything after it: print, --out, --report, notify.

    Shared by `check` and `inbox`. `args` needs: ledger (list of paths),
    sources (comma-separated names), include_inbox, out, report (list),
    report_title and no_notify; `history` (a path) is optional. Returns the
    exit code: 1 when something was found, else 0."""
    def _fail(msg):
        if fail is not None:
            fail(msg)
        sys.stderr.write(f"ERROR: {msg}\n")
        sys.exit(2)

    notify_cfg = source_config.get("notify") or {}
    for path in args.report:
        if report.report_format(path) is None:
            _fail(f"--report path must end in .html or .json: {path}")

    canaries = []
    for path in args.ledger:
        try:
            canaries.extend(load_ledger(path, args.include_inbox))
        except FileNotFoundError:
            sys.stderr.write(f"ERROR: ledger not found: {path}\n")
            sys.exit(2)
    source_names = [s.strip() for s in args.sources.split(",") if s.strip()]

    started = datetime.now(timezone.utc)
    results: list[SourceResult] = []
    hits, skipped = run_check(canaries, source_names, source_config, results=results)
    finished = datetime.now(timezone.utc)

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

    history_path = getattr(args, "history", None)
    rep = None
    if args.report or history_path:
        rep = report.build(canaries=canaries, source_names=source_names, hits=hits,
                           results=results, started=started, finished=finished,
                           ledgers=args.ledger, title=args.report_title or "",
                           searched=_searched_kinds(results))
    if history_path:
        try:
            history.append(history_path, history.entry(rep))
        except OSError as e:
            sys.stderr.write(f"WARNING: could not append to history {history_path}: {e}\n")
    if args.report:
        for path in args.report:
            try:
                report.write(path, rep)
                print(f"  wrote report to {path}")
            except OSError as e:
                sys.stderr.write(f"WARNING: could not write report {path}: {e}\n")

    if notify_cfg and not args.no_notify:
        sent, problems = notify.notify_run(notify_cfg, hits, skipped,
                                           len(canaries), source_names)
        for prob in problems:
            sys.stderr.write(f"WARNING: notification failed: {prob}\n")
        if sent and not problems:
            print(f"  notified via {', '.join(notify.channels(notify_cfg))}")

    # non-zero exit when something leaked, so cron/CI can alert on it
    return 1 if hits else 0


if __name__ == "__main__":
    main()
