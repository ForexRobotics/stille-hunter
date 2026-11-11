# SPDX-License-Identifier: Apache-2.0
"""Tests for the check frame: ledger loading, extras, and source plumbing."""
import json

from stille_hunter.check import load_ledger, load_plugins, _REGISTRY


def _write_ledger(tmp_path, rows):
    p = tmp_path / "x.ledger.jsonl"
    p.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    return str(p)


def test_member_markers_load(tmp_path):
    path = _write_ledger(tmp_path, [{
        "record_id": "abc123", "seed_tag": "t", "detect": "search",
        "locale": "jp", "email": "a@b.com", "user_id": "u1",
        "password_hash": "deadbeef", "created_at": "2026-01-01T00:00:00Z",
    }])
    c = load_ledger(path, include_inbox=False)[0]
    toks = c.tokens()
    assert toks["email"] == "a@b.com"
    assert toks["password_hash"] == "deadbeef"
    assert c.extra == {}   # member has no type-specific extras


def test_aws_key_extras_load(tmp_path):
    path = _write_ledger(tmp_path, [{
        "record_id": "f16746", "seed_tag": "t", "detect": "search",
        "aws_access_key_id": "AKIA...F16746",
        "aws_secret_access_key": "secretf16746blob",
        "region": "ap-northeast-1", "created_at": "2026-01-01T00:00:00Z",
    }])
    c = load_ledger(path, include_inbox=False)[0]
    assert c.extra["aws_access_key_id"] == "AKIA...F16746"
    assert c.extra["aws_secret_access_key"] == "secretf16746blob"
    # named member fields are empty for an aws_key canary
    assert c.email == ""
    # tokens() merges named + extra, drops empties
    assert "aws_access_key_id" in c.tokens()
    assert "email" not in c.tokens()


def test_inbox_excluded_by_default(tmp_path):
    path = _write_ledger(tmp_path, [
        {"record_id": "1", "detect": "inbox", "email": "i@d.com"},
        {"record_id": "2", "detect": "search", "email": "s@d.com"},
    ])
    assert len(load_ledger(path, include_inbox=False)) == 1
    assert len(load_ledger(path, include_inbox=True)) == 2


def test_github_marker_selection(tmp_path):
    load_plugins()
    gh = _REGISTRY["github"](token="x")
    path = _write_ledger(tmp_path, [{
        "record_id": "f16746", "seed_tag": "t", "detect": "search",
        "aws_access_key_id": "AKIA...F16746",
        "aws_secret_access_key": "secretf16746",
    }])
    c = load_ledger(path, include_inbox=False)[0]
    markers = gh._markers(c)
    # searches the secret-looking markers it carries
    assert "aws_access_key_id" in markers
    assert "aws_secret_access_key" in markers
    assert "record_id" in markers   # record_id is in the default searchable set
