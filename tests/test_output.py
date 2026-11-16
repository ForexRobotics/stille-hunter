# SPDX-License-Identifier: Apache-2.0
"""Tests for database-ready output: column mapping, SQL, JSON, db_dump."""
import json
import re
import sqlite3

import pytest

from stille_hunter import generate, output


# ---- column mapping and table names ---------------------------------------
def test_parse_columns_renames_and_keeps_order():
    pairs = output.parse_columns("user_id, full_name=name ,email")
    assert pairs == [("user_id", "user_id"), ("full_name", "name"), ("email", "email")]
    row = {"email": "e", "full_name": "n", "user_id": "u", "points": 1}
    assert list(output.apply_columns(row, pairs).items()) == [
        ("user_id", "u"), ("name", "n"), ("email", "e")]


@pytest.mark.parametrize("spec", ["", "a=b=c", "a;drop", "a=b,c=b", "1abc"])
def test_parse_columns_rejects_bad_specs(spec):
    with pytest.raises(ValueError):
        output.parse_columns(spec)


def test_apply_columns_names_missing_field():
    with pytest.raises(ValueError, match="nope"):
        output.apply_columns({"a": 1}, [("nope", "x")])


@pytest.mark.parametrize("table", ["customers", "app.members", "_t1"])
def test_check_table_accepts_plain_names(table):
    assert output.check_table(table) == table


@pytest.mark.parametrize("table", ["a.b.c", "x; DROP TABLE y", "t`", 'a"b', "", "1t"])
def test_check_table_rejects_anything_else(table):
    with pytest.raises(ValueError):
        output.check_table(table)


# ---- SQL literals ----------------------------------------------------------
def test_sql_quotes_and_escapes_per_dialect():
    row = {"name": "O'Brien", "path": "a\\b", "n": 3, "flag": True, "gone": None}
    my = output.sql_insert(row, "app.t", "mysql")
    pg = output.sql_insert(row, "app.t", "postgres")
    assert my.startswith("INSERT INTO `app`.`t` (`name`, `path`, `n`, `flag`, `gone`)")
    assert pg.startswith('INSERT INTO "app"."t" ("name", "path", "n", "flag", "gone")')
    assert "'O''Brien'" in my and "'O''Brien'" in pg
    assert "'a\\\\b'" in my          # MySQL: backslash is an escape character
    assert "'a\\b'" in pg            # PostgreSQL: backslash is literal
    assert my.endswith("3, TRUE, NULL);") and pg.endswith("3, TRUE, NULL);")


def _db_dump_rows(n=20, locale="jp"):
    generate.load_type_plugins()
    t = generate._TYPES["db_dump"]()
    args = type("A", (), {"locale": locale})()
    recs = list(t.generate(args, n))
    return recs, [generate._seeded_view(r) for r in recs]


@pytest.mark.parametrize("dialect", output.DIALECTS)
def test_generated_sql_runs_and_round_trips(dialect):
    # SQLite accepts both backtick and double-quote identifiers, so it can run
    # either dialect's statements (no backslashes occur in generated rows).
    recs, rows = _db_dump_rows(locale="jp")
    rows.append(dict(rows[0], record_id="zzzzzz", note="it's O'Brien's"))
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE customers (record_id, ref_code, full_name, email, "
               "phone, note, created_at)")
    for row in rows:
        db.execute(output.sql_insert(row, "customers", dialect))
    got = db.execute("SELECT record_id, ref_code, full_name, note FROM customers "
                     "ORDER BY rowid").fetchall()
    assert len(got) == len(rows)
    assert [g[0] for g in got] == [r["record_id"] for r in rows]
    assert got[0][2] == rows[0]["full_name"]          # Japanese text intact
    assert got[-1][3] == "it's O'Brien's"


# ---- db_dump type ----------------------------------------------------------
def test_db_dump_marker_is_searchable_and_woven_in():
    recs, _ = _db_dump_rows(locale="us")
    for r in recs:
        ref = r["ref_code"]
        assert re.fullmatch(r"[A-Z]{3}-[0-9A-F]{6}\d{4}", ref)
        assert ref[4:10] == r["record_id"].upper()
        assert ref in r["note"]
        assert r["record_id"] in r["email"]
        assert r["_ledger"]["marker"] == ref and r["_detect"] == "search"


# ---- engine: formats, table, and no give-away marks -------------------------
def _run(tmp_path, *argv):
    out = tmp_path / "seeded"
    generate.main([*argv, "--out", str(out)])
    return out


def test_sql_format_needs_table(tmp_path):
    with pytest.raises(SystemExit) as e:
        _run(tmp_path, "--type", "db_dump", "--format", "sql")
    assert e.value.code == 2


def test_sql_and_json_outputs_and_ledger_table(tmp_path):
    out = _run(tmp_path, "--type", "db_dump", "--count", "5", "--format", "sql",
               "--table", "customers", "--tag", "crm-prod")
    sql = (tmp_path / "seeded.sql").read_text(encoding="utf-8")
    assert sql.count("INSERT INTO `customers`") == 5
    ledger = [json.loads(x) for x in
              (tmp_path / "seeded.ledger.jsonl").read_text(encoding="utf-8").splitlines()]
    assert all(r["table"] == "customers" and r["seed_tag"] == "crm-prod" for r in ledger)

    _run(tmp_path, "--type", "member", "--count", "3", "--format", "json",
         "--columns", "user_id,full_name=name,email")
    rows = json.loads((tmp_path / "seeded.json").read_text(encoding="utf-8"))
    assert len(rows) == 3 and list(rows[0]) == ["user_id", "name", "email"]
    assert out  # path returned


@pytest.mark.parametrize("fmt", ["sql", "json", "jsonl", "csv"])
def test_seeded_output_never_reveals_it_is_a_canary(tmp_path, fmt):
    _run(tmp_path, "--type", "db_dump", "--count", "5", "--format", fmt,
         "--table", "customers")
    seeded = next(p for p in tmp_path.iterdir()
                  if p.name.startswith("seeded.") and ".ledger." not in p.name)
    text = seeded.read_text(encoding="utf-8").lower()
    for give_away in ("stille", "canary", "honeytoken", "seed_tag"):
        assert give_away not in text, f"{fmt} output contains '{give_away}'"


def test_ledger_out_writes_ledger_elsewhere(tmp_path):
    private = tmp_path / "private" / "ledgers" / "x.ledger.jsonl"   # folders don't exist yet
    out = tmp_path / "app" / "seeded"
    (tmp_path / "app").mkdir()
    generate.main(["--type", "db_dump", "--count", "2", "--format", "json",
                   "--out", str(out), "--ledger-out", str(private)])
    assert private.exists() and len(private.read_text().splitlines()) == 2
    assert sorted(p.name for p in (tmp_path / "app").iterdir()) == ["seeded.json"]
