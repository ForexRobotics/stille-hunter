# SPDX-License-Identifier: Apache-2.0
"""Seeded-output helpers: column mapping, SQL INSERTs, and JSON for seeders.

These turn generated canary records into something that drops straight into a
database - plain SQL to run with your own client, or a JSON array a framework
seeder (e.g. Laravel's DB::table()->insert()) can load. The tool itself never
connects to a database.

Nothing written here may reveal that the rows are canaries: no header comment,
no tool name, no marker. If a seeded file leaks, it must look like ordinary
data, or the trap is exposed.
"""
from __future__ import annotations

import json
import re

_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
DIALECTS = ("mysql", "postgres")


def parse_columns(spec: str) -> list[tuple[str, str]]:
    """Parse --columns 'field=column,field2=column2' into [(field, column), ...].

    A bare 'field' keeps its own name as the column. Order is preserved and
    becomes the column order of the output."""
    pairs: list[tuple[str, str]] = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        field, _, column = part.partition("=")
        field, column = field.strip(), (column.strip() or field.strip())
        if not _IDENT_RE.fullmatch(field) or not _IDENT_RE.fullmatch(column):
            raise ValueError(f"--columns: '{part}' is not field=column with plain names")
        pairs.append((field, column))
    if not pairs:
        raise ValueError("--columns is empty")
    columns = [c for _, c in pairs]
    if len(set(columns)) != len(columns):
        raise ValueError("--columns maps two fields to the same column")
    return pairs


def apply_columns(row: dict, pairs: list[tuple[str, str]] | None) -> dict:
    """Select and rename fields of one seeded row according to the mapping."""
    if not pairs:
        return row
    missing = [f for f, _ in pairs if f not in row]
    if missing:
        raise ValueError(f"--columns: no field(s) {', '.join(missing)}; "
                         f"available: {', '.join(row)}")
    return {column: row[field] for field, column in pairs}


def check_table(table: str) -> str:
    """Validate a table name: 'name' or 'schema.name', plain identifiers only."""
    parts = table.split(".")
    if not 1 <= len(parts) <= 2 or not all(_IDENT_RE.fullmatch(p) for p in parts):
        raise ValueError(f"--table '{table}' must be a plain name or schema.name")
    return table


def _quote_ident(name: str, dialect: str) -> str:
    q = "`" if dialect == "mysql" else '"'
    return ".".join(f"{q}{part}{q}" for part in name.split("."))


def _literal(value, dialect: str) -> str:
    if value is None:
        return "NULL"
    if isinstance(value, bool):
        return "TRUE" if value else "FALSE"
    if isinstance(value, (int, float)):
        return repr(value)
    s = str(value)
    if dialect == "mysql":
        # MySQL treats backslash as an escape character in string literals
        # (unless NO_BACKSLASH_ESCAPES is set); PostgreSQL does not.
        s = s.replace("\\", "\\\\")
    return "'" + s.replace("'", "''") + "'"


def sql_insert(row: dict, table: str, dialect: str) -> str:
    """One INSERT statement for one row."""
    cols = ", ".join(_quote_ident(c, dialect) for c in row)
    vals = ", ".join(_literal(v, dialect) for v in row.values())
    return f"INSERT INTO {_quote_ident(table, dialect)} ({cols}) VALUES ({vals});"


def write_sql(rows: list[dict], table: str, dialect: str, f) -> None:
    for row in rows:
        f.write(sql_insert(row, table, dialect) + "\n")


def write_json_array(rows: list[dict], f) -> None:
    json.dump(rows, f, ensure_ascii=False, indent=2)
    f.write("\n")
