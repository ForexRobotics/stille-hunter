# SPDX-License-Identifier: Apache-2.0
"""Tests for inbox detection: recipient headers only, mbox / Maildir / IMAP."""
import json
import mailbox
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from email.utils import format_datetime

import pytest

from stille_hunter import check, inbox

DOMAIN = "quiet-harbour.net"
A = f"sabine.weber.401d98@{DOMAIN}"      # inbox canary
B = f"kenta.sato.9c2e11@{DOMAIN}"        # inbox canary, never written to
S = "jonas.koch.77aa01@gmail.com"         # a search canary on free mail


def _ledger(tmp_path):
    rows = [
        {"record_id": "401d98", "seed_tag": "www-members", "detect": "inbox", "email": A},
        {"record_id": "9c2e11", "seed_tag": "crm-export", "detect": "inbox", "email": B},
        {"record_id": "77aa01", "seed_tag": "www-members", "detect": "search", "email": S},
    ]
    path = tmp_path / "trap.ledger.jsonl"
    path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    return str(path)


def _msg(to, *, days_ago=1, sender="offers@spam-blast.biz", body="hello",
         extra=None):
    m = EmailMessage()
    m["From"] = sender
    m["To"] = to
    m["Subject"] = "You have won"
    m["Date"] = format_datetime(datetime.now(timezone.utc) - timedelta(days=days_ago))
    for k, v in (extra or {}).items():
        m[k] = v
    m.set_content(body)
    return m


def _messages():
    return [
        _msg(A, days_ago=3),                                        # plain hit
        _msg("undisclosed-recipients:;", days_ago=1, sender="x@phish.example.org",
             extra={"Delivered-To": A}),                            # catch-all delivery
        _msg(f"Sabine.Weber.401D98+promo@{DOMAIN.upper()}", days_ago=2),  # rewritten
        _msg(f"someone@{DOMAIN}", body=f"forward this to {B}"),     # B only in the body
        _msg(S),                                                    # free mail: not ours
        _msg(A, days_ago=90),                                       # outside --days 30
    ]


def _mbox(tmp_path):
    path = tmp_path / "catchall.mbox"
    box = mailbox.mbox(str(path))
    for m in _messages():
        box.add(m)
    box.flush()
    box.close()
    return str(path)


def _canaries(tmp_path):
    return check.load_ledger(_ledger(tmp_path), include_inbox=True)


def test_parse_headers_reads_recipient_headers_only():
    env = inbox.parse_headers(_msg("x@a.net", body=f"mail {A}",
                                   extra={"X-Original-To": A}).as_bytes())
    assert env.recipients == sorted(["x@a.net", A])     # body address not included
    assert env.sender_domain == "spam-blast.biz" and env.date is not None


def test_matcher_uses_inbox_domains_and_tokens(tmp_path):
    m = inbox.Matcher(_canaries(tmp_path))
    assert m.domains == {DOMAIN}                        # derived from inbox canaries
    assert m.match(A).record_id == "401d98"
    assert m.match(f"SABINE.weber.401d98+x@{DOMAIN}").record_id == "401d98"
    assert m.match(S) is None                           # not an inbox domain
    assert m.match(f"nobody@{DOMAIN}") is None


def test_scan_mbox_aggregates_per_canary(tmp_path):
    messages = inbox.read_mbox(_mbox(tmp_path))
    found, read = inbox.scan(messages, inbox.Matcher(_canaries(tmp_path)),
                             since=inbox.since_from(30))
    assert set(found) == {"401d98"}                     # B was only in a body
    info = found["401d98"]
    assert info["messages"] == 3 and read == 5          # the 90-day-old one is skipped
    assert info["senders"] == {"spam-blast.biz", "phish.example.org"}
    assert info["first"] < info["last"]


def test_maildir_reader(tmp_path):
    md = mailbox.Maildir(str(tmp_path / "Maildir"))
    for m in _messages():
        md.add(m)
    found, _ = inbox.scan(inbox.read_maildir(str(tmp_path / "Maildir")),
                          inbox.Matcher(_canaries(tmp_path)))
    assert found["401d98"]["messages"] == 4             # no --days: all four


class FakeIMAP:
    """Records calls; serves header bytes only."""
    calls: list = []

    def __init__(self, host, port, timeout=None):
        FakeIMAP.calls = [("connect", host, port)]

    def login(self, user, password):
        self.calls.append(("login", user, password))

    def select(self, folder, readonly=False):
        self.calls.append(("select", folder, readonly))
        return "OK", [b"6"]

    def search(self, charset, criteria):
        self.calls.append(("search", criteria))
        return "OK", [b"1 2 3"]

    def fetch(self, ids, what):
        self.calls.append(("fetch", ids, what))
        heads = [_msg(A), _msg(f"x@{DOMAIN}", extra={"X-Original-To": A}), _msg(S)]
        data = []
        for i, m in enumerate(heads, 1):
            raw = b"".join(f"{k}: {v}\r\n".encode() for k, v in m.items()) + b"\r\n"
            data += [(f"{i} (BODY[HEADER.FIELDS (TO)] {{{len(raw)}}}".encode(), raw), b")"]
        return "OK", data

    def store(self, *a):                                 # must never be called
        raise AssertionError("inbox must not change the mailbox")

    def logout(self):
        self.calls.append(("logout",))


def test_imap_is_read_only_and_headers_only(tmp_path, monkeypatch):
    import imaplib
    monkeypatch.setattr(imaplib, "IMAP4_SSL", FakeIMAP)
    cfg = {"host": "imap.provider.net", "user": "trap", "password": "pw",
           "folder": "Catch All"}
    envs = list(inbox.read_imap(cfg, since=inbox.since_from(30)))
    found, _ = inbox.scan(envs, inbox.Matcher(_canaries(tmp_path)))
    assert found["401d98"]["messages"] == 2
    calls = FakeIMAP.calls
    assert ("select", '"Catch All"', True) in calls      # readonly
    search = next(c for c in calls if c[0] == "search")
    assert search[1].startswith("SINCE ")
    fetch = next(c for c in calls if c[0] == "fetch")
    assert "BODY.PEEK[HEADER.FIELDS" in fetch[2] and "TEXT" not in fetch[2]
    assert calls[-1] == ("logout",)


def test_source_availability():
    from stille_hunter.sources.inbox import InboxSource
    assert InboxSource().available()[0] is False
    assert InboxSource(mbox="a", maildir="b").available()[0] is False
    ok, why = InboxSource(imap={"host": "h"}).available()
    assert not ok and "password" in why
    assert InboxSource(mbox="a").available() == (True, "")


def test_cli_inbox_end_to_end(tmp_path, capsys):
    from stille_hunter.cli import main
    rep = tmp_path / "r.json"
    with pytest.raises(SystemExit) as e:
        main(["inbox", _ledger(tmp_path), "--mbox", _mbox(tmp_path), "--days", "30",
              "--report", str(rep)])
    assert e.value.code == 1                            # something was found
    out = capsys.readouterr().out
    assert "1 hit(s)" in out and "401d98" in out
    text = rep.read_text(encoding="utf-8")
    data = json.loads(text)
    assert A not in text and "sabine" not in text      # report never shows the address
    assert any(s.get("name") == "inbox" and s.get("status") == "ok"
               for s in data.get("sources", []))


def test_cli_inbox_needs_a_mailbox(tmp_path):
    from stille_hunter.cli import main
    with pytest.raises(SystemExit) as e:
        main(["inbox", _ledger(tmp_path)])
    assert e.value.code == 2
