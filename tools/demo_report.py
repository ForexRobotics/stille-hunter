#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Write the demo report shown in the README (docs/img/report-*.png).

    python tools/demo_report.py demo-report.html

Everything in it is made up: example.com hosts, an "ExampleShop" breach and a
github.example URL. It uses the installed version's report code, so the page
shows the current version. To refresh the README pictures, open the file in a
browser 1000 px wide and take a full-page screenshot at 2x in dark and light
mode (e.g. with Playwright), saved as docs/img/report-dark.png and
docs/img/report-light.png.
"""
from __future__ import annotations

import secrets
import sys
from datetime import datetime, timedelta, timezone

from stille_hunter import report
from stille_hunter.check import Canary, Hit, SourceResult


def _canary(record_id: str, tag: str) -> Canary:
    return Canary(record_id, tag, "search", "jp", f"demo.{record_id}@example.com",
                  f"demo{record_id}", "ab" * 32, {})


def build() -> dict:
    canaries = ([_canary("a4558e", "www-members")]
                + [_canary(secrets.token_hex(3), "www-members") for _ in range(39)]
                + [_canary("a968c4", "crm-customers")]
                + [_canary(secrets.token_hex(3), "crm-customers") for _ in range(24)]
                + [_canary(secrets.token_hex(3), "ci-secrets") for _ in range(6)])
    started = datetime.now(timezone.utc).replace(hour=6, minute=14, second=0, microsecond=0)
    finished = started + timedelta(seconds=161)
    found = (started + timedelta(seconds=162)).isoformat()
    hits = [
        Hit(canary=canaries[0], source="hibp", token_kind="email", token="",
            location="ExampleShop (breach 2026-10)",
            detail="listed in HIBP breach 'ExampleShop'", found_at=found),
        Hit(canary=canaries[40], source="github", token_kind="password_hash", token="",
            location="https://github.example/demo-user/demo-repo/blob/main/users.sql",
            detail="code search match", found_at=found),
    ]
    results = [SourceResult("hibp", "ok", "", 1, 42.3, {"emails checked": 65}),
               SourceResult("github", "ok", "", 1, 18.0, {"queries": 72})]
    return report.build(
        canaries=canaries, source_names=["hibp", "github"], hits=hits, results=results,
        started=started, finished=finished, title="web01.example.com",
        ledgers=["www-members.ledger.jsonl", "crm-customers.ledger.jsonl",
                 "ci-secrets.ledger.jsonl"],
        searched={"email", "password_hash", "record_id"})


def main(argv: list[str]) -> int:
    if len(argv) != 1 or not argv[0].endswith(".html"):
        sys.stderr.write("usage: python tools/demo_report.py OUT.html\n")
        return 2
    report.write(argv[0], build())
    print(f"wrote {argv[0]}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
