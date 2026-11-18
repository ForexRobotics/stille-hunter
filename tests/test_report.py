# SPDX-License-Identifier: Apache-2.0
"""Tests for `check --report`: per-source results, stats, and no canary values."""
import json
import os
import stat

import pytest

from stille_hunter import check
from stille_hunter.check import CheckSource, Hit, SourceResult, run_check

SECRET = "sakura.watanabe.75ebaa@hotmail.com"


class _Finds(CheckSource):
    name = "test_finds"
    supports = ("email",)

    def check(self, canaries):
        self.stats = {"pages read": 3, "long": "x" * 500, "nested": {"no": 1}}
        for c in canaries:
            if not c.email:
                continue
            yield Hit(canary=c, source=self.name, token_kind="email", token=c.email,
                      location="https://paste.example/abc", detail="<b>pasted</b>")


class _Breaks(CheckSource):
    name = "test_breaks"

    def check(self, canaries):
        self.stats = {"queries": 1}
        yield from ()
        raise RuntimeError("API key expired")


class _Off(CheckSource):
    name = "test_off"

    def available(self):
        return False, "no API key configured"


@pytest.fixture(autouse=True)
def _sources():
    for cls in (_Finds, _Breaks, _Off):
        check._REGISTRY[cls.name] = cls
    yield
    for cls in (_Finds, _Breaks, _Off):
        check._REGISTRY.pop(cls.name, None)


def _ledger(tmp_path):
    p = tmp_path / "www.ledger.jsonl"
    rows = [{"record_id": "75ebaa", "seed_tag": "www-members", "detect": "search",
             "email": SECRET, "user_id": "sakura75ebaa", "password_hash": "ab" * 32},
            {"record_id": "f16746", "seed_tag": "ci-secrets", "detect": "search",
             "aws_access_key_id": "AKIAF16746EXAMPLE00"}]
    p.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    return str(p)


def test_run_check_reports_each_source(tmp_path):
    canaries = check.load_ledger(_ledger(tmp_path), include_inbox=False)
    results: list[SourceResult] = []
    hits, skipped = run_check(canaries, ["test_finds", "test_breaks", "test_off", "nope"],
                              {}, show_progress=False, results=results)
    assert len(hits) == 1
    assert [(r.name, r.status, r.hits) for r in results] == [
        ("test_finds", "ok", 1), ("test_breaks", "error", 0),
        ("test_off", "skipped", 0), ("nope", "skipped", 0)]
    assert results[0].stats == {"pages read": 3}          # long / nested values dropped
    assert results[1].reason == "API key expired" and results[1].stats == {"queries": 1}
    # the old return value is unchanged
    assert ("test_breaks", "error: API key expired") in skipped


def test_cli_writes_html_and_json_without_canary_values(tmp_path, capsys):
    html_path, json_path = tmp_path / "run.html", tmp_path / "run.json"
    with pytest.raises(SystemExit) as e:
        check.main([_ledger(tmp_path), "--sources", "test_finds,test_breaks,test_off",
                    "--report", str(html_path), "--report", str(json_path),
                    "--report-title", "www01 <prod>"])
    assert e.value.code == 1                                # a hit
    rep = json.loads(json_path.read_text(encoding="utf-8"))
    assert rep["title"] == "www01 <prod>" and rep["ledger"] == "www.ledger.jsonl"
    assert rep["summary"] == {"canaries": 2, "sources": 3, "hits": 1, "canaries_hit": 1,
                              "sources_ok": 1, "sources_failed": 1, "sources_skipped": 1}
    assert rep["canaries"]["by_seed_tag"] == {"www-members": 1, "ci-secrets": 1}
    assert rep["canaries"]["by_marker"]["record_id"] == 2
    (hit,) = rep["hits"]
    assert "token" not in hit and hit["seed_tag"] == "www-members"

    page = html_path.read_text(encoding="utf-8")
    assert "1 canary surfaced" in page and "API key expired" in page
    assert "www01 &lt;prod&gt;" in page and "&lt;b&gt;pasted&lt;/b&gt;" in page   # escaped
    assert "<script" not in page and "http://" not in page.replace(
        "https://github.com/ForexRobotics/stille-hunter", "")
    for path in (html_path, json_path):
        text = path.read_text(encoding="utf-8")
        assert SECRET not in text and "AKIAF16746" not in text and "ab" * 32 not in text
        if os.name == "posix":
            assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert f"wrote report to {html_path}" in capsys.readouterr().out


def test_clean_run_says_so(tmp_path):
    out = tmp_path / "r.html"
    with pytest.raises(SystemExit) as e:
        check.main([_ledger(tmp_path), "--sources", "null", "--report", str(out)])
    assert e.value.code == 0
    assert "No canary found." in out.read_text(encoding="utf-8")


def test_failed_source_is_flagged_as_incomplete(tmp_path):
    out = tmp_path / "r.html"
    with pytest.raises(SystemExit):
        check.main([_ledger(tmp_path), "--sources", "test_breaks", "--report", str(out)])
    assert "the check was incomplete" in out.read_text(encoding="utf-8")


def test_bad_report_extension_is_refused_before_running(tmp_path):
    with pytest.raises(SystemExit) as e:
        check.main([_ledger(tmp_path), "--sources", "test_finds", "--report", "r.txt"])
    assert e.value.code == 2
