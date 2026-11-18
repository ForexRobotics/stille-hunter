# SPDX-License-Identifier: Apache-2.0
"""Report of one `check` run: JSON for scripts, one self-contained HTML page for people.

    stille-hunter check ledger.jsonl --sources hibp,github --report run.html --report run.json

What a report holds: when the run happened, which canaries were checked
(counts by seed tag and marker kind), how each source fared (ok / skipped /
error, hits, time, and the short facts it reports about what it covered) and
the hits - **without the matched canary value**, the same rule as
notifications. Seed tags say where canaries are planted, so keep reports
private; they are written readable by their owner only.

The HTML page has no external assets or scripts and follows the viewer's
light or dark setting.
"""
from __future__ import annotations

import html
import json
import os
import socket
from collections import Counter
from datetime import datetime, timezone

from . import __version__
from ._logo import ICON_PNG_BASE64

FORMATS = {".html": "html", ".htm": "html", ".json": "json"}


def report_format(path: str) -> str | None:
    return FORMATS.get(os.path.splitext(path)[1].lower())


def build(*, canaries, source_names, hits, results, started: datetime,
          finished: datetime, ledgers=(), title: str = "", searched=None) -> dict:
    """The report as a plain dict (the JSON form).

    `ledgers` are the ledger paths (only file names are kept). `searched`, if
    given, limits the marker counts to the kinds the run's sources search for,
    so metadata such as a token's provider is not counted as a marker."""
    if isinstance(ledgers, str):
        ledgers = [ledgers]
    kinds: Counter = Counter()
    for c in canaries:
        kinds.update(k for k in c.tokens() if searched is None or k in searched)
    tags = Counter(c.seed_tag or "(none)" for c in canaries)
    sources = [{"name": r.name, "status": r.status, "reason": r.reason, "hits": r.hits,
                "seconds": r.seconds, "stats": dict(r.stats)} for r in results]
    hit_rows = [{k: v for k, v in h.to_dict().items() if k != "token"} for h in hits]
    return {
        "tool": "stille-hunter",
        "version": __version__,
        "title": title or socket.gethostname(),
        "started_at": started.astimezone(timezone.utc).isoformat(timespec="seconds"),
        "finished_at": finished.astimezone(timezone.utc).isoformat(timespec="seconds"),
        "duration_seconds": round((finished - started).total_seconds(), 1),
        "ledgers": [os.path.basename(p) for p in ledgers],
        "summary": {
            "canaries": len(canaries),
            "sources": len(source_names),
            "hits": len(hits),
            "canaries_hit": len({h.canary.record_id for h in hits}),
            "sources_ok": sum(r.status == "ok" for r in results),
            "sources_failed": sum(r.status == "error" for r in results),
            "sources_skipped": sum(r.status == "skipped" for r in results),
        },
        "canaries": {"by_seed_tag": dict(tags.most_common()),
                     "by_marker": dict(kinds.most_common())},
        "sources": sources,
        "hits": hit_rows,
    }


# ---------------------------------------------------------------------------
#  HTML
# ---------------------------------------------------------------------------
_CSS = """
:root{--bg:#f6f7f9;--card:#fff;--fg:#1d2330;--muted:#5d6678;--line:#e3e6ec;
--ok:#2f6f4f;--bad:#b4232a;--warn:#b8860b;--skip:#50607a;--bar:#50607a;--track:#e3e6ec}
@media (prefers-color-scheme:dark){:root{--bg:#12151b;--card:#1b2029;--fg:#e6e9ef;
--muted:#9aa3b5;--line:#2c3340;--ok:#5fb58a;--bad:#ff6b6b;--warn:#e0b44c;--skip:#8d9bb5;
--bar:#8d9bb5;--track:#2c3340}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.55 system-ui,-apple-system,"Segoe UI","Hiragino Sans","Noto Sans JP",sans-serif}
main{max-width:1000px;margin:0 auto;padding:28px 16px 40px}
h1{font-size:24px;margin:0 0 4px}
header{display:flex;gap:16px;align-items:center}
.logo{width:56px;height:56px;flex:none}
h2{font-size:14px;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);margin:0 0 12px}
.muted{color:var(--muted)}
.pills{display:flex;flex-wrap:wrap;gap:8px;margin:14px 0 18px}
.pill{border:1.5px solid currentColor;border-radius:999px;padding:2px 12px;font-size:13px}
.pill b{font-weight:700}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px 20px;
margin:0 0 16px;overflow-x:auto}
.status{font-size:18px;font-weight:600}
.status.ok{color:var(--ok)} .status.bad{color:var(--bad)} .status.warn{color:var(--warn)}
table{border-collapse:collapse;width:100%;min-width:640px;font-size:14px}
th{text-align:left;color:var(--muted);font-weight:600;padding:6px 8px;
border-bottom:1px solid var(--line)}
td{padding:8px;border-bottom:1px solid var(--line);vertical-align:top;overflow-wrap:anywhere}
.nw{white-space:nowrap}
code{font:13px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.tag{display:inline-block;white-space:nowrap;color:#fff;border-radius:6px;padding:0 8px;
font-size:12px;font-weight:600}
.tag.ok{background:var(--ok)} .tag.error{background:var(--bad)} .tag.skipped{background:var(--skip)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:20px}
.row{display:grid;grid-template-columns:minmax(90px,38%) 1fr 48px;gap:10px;align-items:center;
margin:6px 0;font-size:13px}
.lbl{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.track{background:var(--track);border-radius:4px;height:10px;overflow:hidden}
.fill{display:block;height:100%;background:var(--bar)}
.val{text-align:right;font-variant-numeric:tabular-nums}
footer{text-align:center;font-size:12px;color:var(--muted);margin-top:24px}
"""


def _e(value) -> str:
    return html.escape("" if value is None else str(value))


def _bars(counts: dict) -> str:
    if not counts:
        return "<p class='muted'>none</p>"
    top = max(counts.values()) or 1
    return "".join(
        f"<div class='row'><span class='lbl' title='{_e(k)}'>{_e(k)}</span>"
        f"<span class='track'><span class='fill' style='width:{round(100 * v / top)}%'>"
        f"</span></span><span class='val'>{v}</span></div>"
        for k, v in counts.items())


def _ledgers(names: list) -> str:
    if not names:
        return "ledger: -"
    if len(names) <= 3:
        return ("ledger: " if len(names) == 1 else "ledgers: ") + _e(", ".join(names))
    return f"<span title='{_e(', '.join(names))}'>{len(names)} ledgers</span>"


def _stats(stats: dict) -> str:
    return " · ".join(f"{_e(k)}: <b>{_e(v)}</b>" for k, v in stats.items())


def to_html(rep: dict) -> str:
    s = rep["summary"]
    if s["hits"]:
        status = (f"<p class='status bad'>{s['canaries_hit']} canar"
                  f"{'y' if s['canaries_hit'] == 1 else 'ies'} surfaced "
                  f"({s['hits']} hit{'s' if s['hits'] != 1 else ''}). "
                  "Act on the seed tags below.</p>")
    elif s["sources_failed"]:
        status = ("<p class='status warn'>No canary found, but some sources failed: "
                  "the check was incomplete.</p>")
    else:
        status = "<p class='status ok'>No canary found.</p>"

    pills = (
        f"<span class='pill' style='color:var(--{'bad' if s['hits'] else 'ok'})'>"
        f"hits: <b>{s['hits']}</b></span>"
        f"<span class='pill' style='color:var(--muted)'>canaries: <b>{s['canaries']}</b></span>"
        f"<span class='pill' style='color:var(--ok)'>sources ok: <b>{s['sources_ok']}</b></span>"
        f"<span class='pill' style='color:var(--{'bad' if s['sources_failed'] else 'muted'})'>"
        f"failed: <b>{s['sources_failed']}</b></span>"
        f"<span class='pill' style='color:var(--muted)'>skipped: "
        f"<b>{s['sources_skipped']}</b></span>")

    if rep["hits"]:
        hit_rows = "".join(
            f"<tr><td><code>{_e(h['record_id'])}</code></td><td>{_e(h['seed_tag'])}</td>"
            f"<td>{_e(h['source'])}</td><td>{_e(h['token_kind'])}</td>"
            f"<td>{_e(h['location'])}<div class='muted'>{_e(h['detail'])}</div></td>"
            f"<td class='nw'>{_e(h['found_at'][:19].replace('T', ' '))}</td></tr>"
            for h in rep["hits"])
        hits = ("<table><tr><th>Record</th><th>Seed tag</th><th>Source</th><th>Marker</th>"
                f"<th>Where</th><th>Found (UTC)</th></tr>{hit_rows}</table>"
                "<p class='muted' style='font-size:13px'>Canary values are never written to "
                "reports; look the record up in your ledger.</p>")
    else:
        hits = "<p class='muted'>No hits in this run.</p>"

    src_rows = "".join(
        f"<tr><td>{_e(r['name'])}</td><td><span class='tag {_e(r['status'])}'>"
        f"{_e(r['status'])}</span></td><td>{r['hits']}</td><td class='nw'>{r['seconds']}s</td>"
        f"<td>{_stats(r['stats'])}"
        + (f"<div class='muted'>{_e(r['reason'])}</div>" if r["reason"] else "")
        + "</td></tr>" for r in rep["sources"])

    c = rep["canaries"]
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>stille-hunter report - {_e(rep['title'])}</title>
<style>{_CSS}</style></head><body><main>
<header><img class="logo" alt="stille-hunter" src="data:image/png;base64,{ICON_PNG_BASE64}">
<div><h1>stille-hunter &mdash; {_e(rep['title'])}</h1>
<div class="muted">{_e(rep['started_at'][:16].replace('T', ' '))} UTC
&middot; {rep['duration_seconds']}s
&middot; {_ledgers(rep['ledgers'])} &middot; v{_e(rep['version'])}</div></div>
</header>
<div class="pills">{pills}</div>
<section class="card">{status}</section>
<section class="card"><h2>Hits</h2>{hits}</section>
<section class="card"><h2>Sources</h2>
<table><tr><th>Source</th><th>Status</th><th>Hits</th><th>Time</th><th>Covered</th></tr>
{src_rows}</table></section>
<section class="card"><h2>What was checked</h2><div class="grid">
<div><p class="muted">Canaries by seed tag</p>{_bars(c['by_seed_tag'])}</div>
<div><p class="muted">Markers searched for (canaries carrying each)</p>{_bars(c['by_marker'])}</div>
</div></section>
<footer>stille-hunter &middot; leak-canary report &middot; Apache-2.0 &middot;
<a href="https://github.com/ForexRobotics/stille-hunter" style="color:inherit">source</a></footer>
</main></body></html>
"""


def write(path: str, rep: dict) -> None:
    """Write the report in the format its extension names, readable by its owner only."""
    fmt = report_format(path)
    if fmt is None:
        raise ValueError(f"report path must end in .html or .json: {path}")
    text = (json.dumps(rep, ensure_ascii=False, indent=2) + "\n") if fmt == "json" else to_html(rep)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    os.chmod(path, 0o600)        # also when the file already existed
