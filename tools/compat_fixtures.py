#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Write compatibility fixtures for the current release.

Run once per release, from the repository root, with the release's code
installed (`pip install -e .`):

    python tools/compat_fixtures.py

It generates a small ledger of every canary type (member also as CSV) into
tests/compat/ledgers/v<version>/, using this version's own generator, then
replaces secret-looking marker values with "REDACTED-<field>-<record_id>" so
the files are not mistaken for real secrets. tests/test_compat.py then checks
that every later release still reads them. Commit the new folder.
"""
from __future__ import annotations

import contextlib
import csv
import io
import json
import os
import sys
import tempfile

SECRET_FIELDS = {"aws_access_key_id", "aws_secret_access_key", "api_token",
                 "azure_client_secret", "mcp_token", "kube_token"}


def _redact(path: str) -> None:
    if path.endswith(".csv"):
        with open(path, encoding="utf-8", newline="") as f:
            rows = list(csv.DictReader(f))
    else:
        with open(path, encoding="utf-8") as f:
            rows = [json.loads(line) for line in f if line.strip()]
    for r in rows:
        for k in SECRET_FIELDS & r.keys():
            r[k] = f"REDACTED-{k}-{r['record_id']}"
    with open(path, "w", encoding="utf-8", newline="") as f:
        if path.endswith(".csv"):
            w = csv.DictWriter(f, fieldnames=list(rows[0]))
            w.writeheader()
            w.writerows(rows)
        else:
            f.write("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows))


def main() -> int:
    from stille_hunter import __version__
    from stille_hunter.generate import _TYPES, load_type_plugins
    from stille_hunter.generate import main as generate
    load_type_plugins(("stille_hunter.types",))          # public types only
    out = os.path.join("tests", "compat", "ledgers", f"v{__version__}")
    if os.path.exists(out):
        sys.stderr.write(f"{out} exists already; remove it first to regenerate\n")
        return 2
    os.makedirs(out)
    tag = f"compat-v{__version__}"
    with tempfile.TemporaryDirectory() as tmp:
        for t in sorted(_TYPES):
            opts = ["--type", t, "--count", "3", "--tag", tag]
            if t == "member":
                opts += ["--self-domain", "quiet-harbour.net", "--self-ratio", "0.5",
                         "--table", "members"]
            if t == "db_dump":
                opts += ["--table", "customers"]
            for fmt in (("jsonl", "csv") if t == "member" else ("jsonl",)):
                ext = "csv" if fmt == "csv" else "jsonl"
                target = os.path.join(out, f"{t}.{ext}")
                with contextlib.redirect_stdout(io.StringIO()):
                    generate(opts + ["--format", fmt, "--out", os.path.join(tmp, f"{t}-{fmt}"),
                                     "--ledger-out", target])
                _redact(target)
    print(f"wrote {len(os.listdir(out))} fixtures to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
