# SPDX-License-Identifier: Apache-2.0
"""Tests for `check --history` and `stille-hunter history`."""
import json
import os
import stat
from datetime import datetime, timedelta, timezone

import pytest

from stille_hunter import check, history
from stille_hunter.check import CheckSource, Hit

SECRET = "sakura.watanabe.75ebaa@hotmail.com"
NOW = datetime(2026, 11, 25, 12, 0, tzinfo=timezone.utc)


class _Finds(CheckSource):
    name = "test_hist_finds"
    supports = ("email",)

    def check(self, canaries):
        for c in canaries:
            if c.email:
                yield Hit(canary=c, source=self.name, token_kind="email", token=c.email,
                          location="https://paste.example/abc")


class _Breaks(CheckSource):
    name = "test_hist_breaks"

    def check(self, canaries):
        yield from ()
        raise RuntimeError("API key expired")


@pytest.fixture(autouse=True)
def _sources():
    for cls in (_Finds, _Breaks):
        check._REGISTRY[cls.name] = cls
    yield
    for cls in (_Finds, _Breaks):
        check._REGISTRY.pop(cls.name, None)


def _ledger(tmp_path):
    p = tmp_path / "www.ledger.jsonl"
    rows = [{"record_id": "75ebaa", "seed_tag": "www-members", "detect": "search",
             "email": SECRET, "password_hash": "ab" * 32},
            {"record_id": "f16746", "seed_tag": "ci-secrets", "detect": "search",
             "aws_access_key_id": "AKIAF16746EXAMPLE00"}]
    p.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    return str(p)


def _run(argv):
    from stille_hunter.cli import main
    with pytest.raises(SystemExit) as e:
        main(argv)
    return e.value.code


def test_check_appends_one_line_per_run_without_values(tmp_path):
    hist = tmp_path / "state" / "history.jsonl"
    led = _ledger(tmp_path)
    for _ in range(2):
        _run(["check", led, "--sources", "test_hist_finds,test_hist_breaks",
              "--history", str(hist)])
    text = hist.read_text(encoding="utf-8")
    lines = [json.loads(x) for x in text.splitlines()]
    assert len(lines) == 2
    assert SECRET not in text and "sakura" not in text and "AKIA" not in text
    line = lines[0]
    assert line["schema"] == history.SCHEMA and line["ledgers"] == ["www.ledger.jsonl"]
    assert line["hits"][0]["record_id"] == "75ebaa" and "token" not in line["hits"][0]
    assert {s["name"]: s["status"] for s in line["sources"]} == {
        "test_hist_finds": "ok", "test_hist_breaks": "error"}
    if os.name == "posix":
        assert stat.S_IMODE(os.stat(hist).st_mode) == 0o600


def _line(days_ago, hits, sources=None):
    at = (NOW - timedelta(days=days_ago)).isoformat()
    return {"schema": 1, "started_at": at, "finished_at": at, "version": "x",
            "ledgers": ["a"], "canaries": 5,
            "sources": sources or [{"name": "hibp", "status": "ok", "reason": "", "hits": 1}],
            "hits": [{"record_id": rid, "seed_tag": tag, "source": src, "token_kind": "email",
                      "location": "l", "detail": "", "found_at": at}
                     for rid, tag, src in hits]}


def _history():
    old = ("aaa111", "crm-export", "hibp")       # known since 60 days ago
    new = ("bbb222", "www-members", "inbox")     # first seen 3 days ago
    return [
        _line(60, [old]),
        _line(10, [old], [{"name": "hibp", "status": "error", "reason": "HTTP 503",
                           "hits": 0}]),
        _line(3, [old, new]),
        _line(1, [old, new]),
    ]


def test_summary_tells_new_from_known():
    s = history.summarise(_history(), days=30, now=NOW, retired={"aaa111"})
    assert s["runs"]["count"] == 3                       # the 60-day-old run is outside
    assert s["sources"]["hibp"]["error"] == 1
    assert s["sources"]["hibp"]["last_problem"] == "HTTP 503"
    assert s["hits"]["count"] == 5 and s["hits"]["new_canaries"] == 1
    assert s["hits"]["by_seed_tag"] == {"crm-export": 3, "www-members": 2}
    rows = {r["record_id"]: r for r in s["canaries"]}
    assert rows["bbb222"]["new_in_period"] is True
    assert rows["aaa111"]["new_in_period"] is False      # first seen before the period
    assert rows["aaa111"]["first_seen"] == (NOW - timedelta(days=60)).date().isoformat()
    assert rows["aaa111"]["retired"] is True
    assert s["canaries"][0]["record_id"] == "bbb222"     # new ones first


def test_summary_whole_history_and_text():
    s = history.summarise(_history(), days=0, now=NOW)
    assert s["runs"]["count"] == 4 and s["hits"]["new_canaries"] == 2
    text = history.to_text(history.summarise(_history(), days=30, now=NOW))
    assert "NEW bbb222" in text and "last problem: HTTP 503" in text
    assert "1 new in this period" in text


def test_cli_history_text_and_json(tmp_path, capsys):
    path = tmp_path / "h.jsonl"
    lines = _history()
    for line in lines:                                   # re-date relative to real now
        delta = NOW - datetime.fromisoformat(line["started_at"])
        at = (datetime.now(timezone.utc) - delta).isoformat()
        line["started_at"] = line["finished_at"] = at
        for h in line["hits"]:
            h["found_at"] = at
    path.write_text("".join(json.dumps(x) + "\n" for x in lines) + "{torn\n",
                    encoding="utf-8")
    assert history.main([str(path), "--days", "30"]) is None
    assert "hits: 5 on 2 canaries" in capsys.readouterr().out
    history.main([str(path), "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data["hits"]["new_canaries"] == 1 and data["period"]["days"] == 30


def test_cli_history_missing_file(tmp_path):
    assert _run(["history", str(tmp_path / "nope.jsonl")]) == 2
