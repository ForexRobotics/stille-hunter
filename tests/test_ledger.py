# SPDX-License-Identifier: Apache-2.0
"""Tests for `stille-hunter ledger`: list, retire, rotate."""
import json
import os
import stat

import pytest

from stille_hunter import ledger
from stille_hunter.check import load_ledger
from stille_hunter.cli import main

DOMAIN = "quiet-harbour.net"


def _run(argv):
    with pytest.raises(SystemExit) as e:
        main(argv)
    return e.value.code


def _generate(tmp_path, *opts, name="www"):
    path = tmp_path / f"{name}.ledger.jsonl"
    main(["generate", "--out", str(tmp_path / f"{name}_seed"), "--ledger-out", str(path),
          *opts])
    os.chmod(path, 0o600)
    return str(path)


def test_generate_records_the_type(tmp_path):
    rows = ledger.read_rows(_generate(tmp_path, "--type", "aws_key", "--count", "2",
                                      "--tag", "ci"))
    assert {r["type"] for r in rows} == {"aws_key"}


def test_row_type_is_inferred_for_old_ledgers():
    assert ledger.row_type({"marker": "CUS-A"}) == "db_dump"
    assert ledger.row_type({"email": "a@b", "password_hash": "x"}) == "member"
    assert ledger.row_type({"kube_token": "t"}) == "kubeconfig"
    assert ledger.row_type({"type": "api_token", "email": "x"}) == "api_token"
    assert ledger.row_type({"email": "a@b"}) == "unknown"


def test_retire_by_tag_and_id_and_check_skips_them(tmp_path, capsys):
    path = _generate(tmp_path, "--count", "4", "--tag", "www-members")
    other = ledger.read_rows(path)[0]["record_id"]
    _generate(tmp_path, "--count", "2", "--tag", "crm", name="crm")
    assert _run(["ledger", "retire", path, "--id", other, "--reason", "test"]) == 0
    rows = ledger.read_rows(path)
    gone = [r for r in rows if r.get("retired_at")]
    assert [r["record_id"] for r in gone] == [other] and gone[0]["retired_reason"] == "test"
    assert len(load_ledger(path, include_inbox=True)) == 3        # check skips it
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600            # permissions kept

    assert _run(["ledger", "retire", path, "--tag", "www-members", "--dry-run"]) == 0
    assert "would retire 3" in capsys.readouterr().out
    assert len(load_ledger(path, include_inbox=True)) == 3        # dry run changed nothing
    assert _run(["ledger", "retire", path, "--tag", "www-members"]) == 0
    assert load_ledger(path, include_inbox=True) == []
    assert _run(["ledger", "retire", path]) == 2                   # nothing named


def test_list_shows_counts_never_values(tmp_path, capsys):
    path = _generate(tmp_path, "--count", "5", "--tag", "www-members", "--locale", "de",
                     "--self-domain", DOMAIN, "--self-ratio", "1")
    rows = ledger.read_rows(path)
    ledger.retire(rows, ids=[rows[0]["record_id"]])
    ledger.write_rows(path, rows)
    capsys.readouterr()
    assert _run(["ledger", "list", path]) == 0
    out = capsys.readouterr().out
    assert "www-members: 4 active (member 4); 1 retired; 4 inbox" in out
    assert all(r["email"] not in out and r["record_id"] not in out for r in rows)
    assert _run(["ledger", "list", path, "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data[0]["tags"][0]["active"] == 4


def test_rotate_replaces_a_batch_and_keeps_its_settings(tmp_path, capsys):
    path = _generate(tmp_path, "--count", "6", "--tag", "www-members", "--locale", "de",
                     "--self-domain", DOMAIN, "--self-ratio", "0.5", "--table", "members")
    old_ids = {r["record_id"] for r in ledger.read_rows(path)}
    out = tmp_path / "new_seed"
    assert _run(["ledger", "rotate", path, "--tag", "www-members", "--out", str(out)]) == 0
    rows = ledger.read_rows(path)
    old = [r for r in rows if r["record_id"] in old_ids]
    new = [r for r in rows if r["record_id"] not in old_ids]
    assert len(old) == 6 and all(r["retired_reason"] == "rotated" for r in old)
    assert len(new) == 6 and not any(r.get("retired_at") for r in new)
    assert {r["locale"] for r in new} == {"de"} and {r["table"] for r in new} == {"members"}
    assert {r["seed_tag"] for r in new} == {"www-members"}
    inbox = [r for r in new if r["detect"] == "inbox"]
    assert inbox and all(r["email"].endswith("@" + DOMAIN) for r in inbox)
    assert (tmp_path / "new_seed.jsonl").exists()
    assert {c.record_id for c in load_ledger(path, include_inbox=True)} == \
        {r["record_id"] for r in new}
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_rotate_passes_generate_options_and_dry_run(tmp_path, capsys):
    path = _generate(tmp_path, "--count", "3", "--tag", "ci", "--type", "api_token")
    capsys.readouterr()
    assert _run(["ledger", "rotate", path, "--tag", "ci", "--count", "5",
                 "--provider", "github", "--dry-run"]) == 0
    said = capsys.readouterr().out
    assert "--type api_token" in said and "--count 5" in said and "--provider github" in said
    assert not any(r.get("retired_at") for r in ledger.read_rows(path))


def test_failed_generation_retires_nothing(tmp_path):
    path = _generate(tmp_path, "--count", "3", "--tag", "www-members")
    before = ledger.read_rows(path)
    code = _run(["ledger", "rotate", path, "--tag", "www-members", "--out",
                 str(tmp_path / "x"), "--self-ratio", "7"])              # invalid ratio
    assert code == 2
    assert ledger.read_rows(path) == before


def test_rotate_refuses_mixed_types_and_unknown_tags(tmp_path):
    path = tmp_path / "mixed.ledger.jsonl"
    path.write_text(json.dumps({"record_id": "a1", "seed_tag": "t", "aws_access_key_id": "K"})
                    + "\n" + json.dumps({"record_id": "b2", "seed_tag": "t", "marker": "M"})
                    + "\n", encoding="utf-8")
    assert _run(["ledger", "rotate", str(path), "--tag", "t", "--dry-run"]) == 2
    assert _run(["ledger", "rotate", str(path), "--tag", "nope", "--dry-run"]) == 2


def test_csv_ledger_round_trip(tmp_path):
    path = tmp_path / "c.ledger.csv"
    main(["generate", "--format", "csv", "--count", "2", "--tag", "csvtag",
          "--out", str(tmp_path / "c"), "--ledger-out", str(path)])
    assert _run(["ledger", "rotate", str(path), "--tag", "csvtag", "--format", "csv",
                 "--out", str(tmp_path / "c2")]) == 0
    rows = ledger.read_rows(str(path))
    assert len(rows) == 4 and sum(bool(r.get("retired_at")) for r in rows) == 2
    assert len(load_ledger(str(path), include_inbox=True)) == 2


def test_history_marks_retired_canaries(tmp_path, capsys):
    path = _generate(tmp_path, "--count", "1", "--tag", "t")
    rid = ledger.read_rows(path)[0]["record_id"]
    hist = tmp_path / "h.jsonl"
    from datetime import datetime, timezone
    at = datetime.now(timezone.utc).isoformat()
    hist.write_text(json.dumps({"started_at": at, "sources": [], "hits": [
        {"record_id": rid, "seed_tag": "t", "source": "hibp", "found_at": at}]}) + "\n",
        encoding="utf-8")
    _run(["ledger", "retire", path, "--id", rid])
    capsys.readouterr()
    from stille_hunter.history import main as history_main
    history_main([str(hist), "--ledger", path])
    assert "(retired)" in capsys.readouterr().out
