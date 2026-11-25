# SPDX-License-Identifier: Apache-2.0
"""stille-hunter inbox: match mail received on your catch-all against the ledger.

Canaries generated with `--self-domain` get addresses on a domain you control
(detect=inbox). Nobody has a reason to write to them - so when mail arrives
for one, that address has leaked, and the ledger says where it was planted.

This module reads a mailbox you own and matches **recipient addresses only**:

  * mbox file, Maildir folder, or an IMAP mailbox (opened read-only; headers are
    fetched with BODY.PEEK so nothing is marked as read).
  * Only the address headers, Date and From are parsed. Message bodies are
    never fetched from IMAP and never kept from mbox / Maildir.
  * What is reported per canary: how many messages, first and last date, and
    the sender domains. No subjects, no content.

The matching runs as the `inbox` check source, so `stille-hunter inbox` gets
the same output, report and notifications as `check`.
"""
from __future__ import annotations

import argparse
import email.parser
import email.utils
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from typing import Iterable, Iterator

#: headers that can carry the real recipient on a catch-all
RECIPIENT_HEADERS = ("To", "Cc", "Delivered-To", "X-Original-To", "Envelope-To",
                     "X-Envelope-To")
_FETCH = ("(BODY.PEEK[HEADER.FIELDS (" + " ".join(h.upper() for h in RECIPIENT_HEADERS)
          + " DATE FROM)])")
_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct",
           "Nov", "Dec")
_HEX6 = re.compile(r"(?=([0-9a-f]{6}))")
PASSWORD_ENV = "STILLE_IMAP_PASSWORD"


# ---------------------------------------------------------------------------
#  Header parsing (never the body)
# ---------------------------------------------------------------------------
class Envelope:
    """What one message tells us: recipients, date, sender domain."""
    __slots__ = ("recipients", "date", "sender_domain")

    def __init__(self, recipients: list[str], date: datetime | None, sender_domain: str):
        self.recipients = recipients
        self.date = date
        self.sender_domain = sender_domain


def parse_headers(raw: bytes) -> Envelope:
    msg = email.parser.BytesHeaderParser().parsebytes(raw, headersonly=True)
    values = []
    for h in RECIPIENT_HEADERS:
        values.extend(str(v) for v in (msg.get_all(h) or []))
    recipients = sorted({a.strip().lower() for _, a in email.utils.getaddresses(values)
                         if a and "@" in a})
    date = None
    if msg.get("Date"):
        try:
            date = email.utils.parsedate_to_datetime(str(msg["Date"]))
            if date.tzinfo is None:
                date = date.replace(tzinfo=timezone.utc)
        except (TypeError, ValueError, IndexError):
            date = None
    senders = [a for _, a in email.utils.getaddresses([str(msg.get("From") or "")]) if "@" in a]
    sender_domain = senders[0].rsplit("@", 1)[1].lower() if senders else ""
    return Envelope(recipients, date, sender_domain)


# ---------------------------------------------------------------------------
#  Mailbox readers
# ---------------------------------------------------------------------------
def read_mbox(path: str) -> Iterator[Envelope]:
    import mailbox
    box = mailbox.mbox(os.path.expanduser(path), create=False)
    try:
        for key in box.iterkeys():
            yield parse_headers(box.get_bytes(key))
    finally:
        box.close()


def read_maildir(path: str) -> Iterator[Envelope]:
    import mailbox
    box = mailbox.Maildir(os.path.expanduser(path), factory=None, create=False)
    for key in box.iterkeys():
        yield parse_headers(box.get_bytes(key))


def _imap_date(d: datetime) -> str:
    return f"{d.day:02d}-{_MONTHS[d.month - 1]}-{d.year}"


def read_imap(cfg: dict, since: datetime | None = None, *, timeout: float = 60
              ) -> Iterator[Envelope]:
    """Read-only IMAP: SELECT with readonly, fetch header fields with PEEK."""
    import imaplib
    host = cfg.get("host")
    if not host:
        raise ValueError('imap needs "host"')
    ssl = cfg.get("ssl", True) is not False
    port = int(cfg.get("port") or (993 if ssl else 143))
    password = cfg.get("password") or os.environ.get(PASSWORD_ENV, "")
    if ssl:
        conn = imaplib.IMAP4_SSL(host, port, timeout=timeout)
    else:
        conn = imaplib.IMAP4(host, port, timeout=timeout)
    try:
        if not ssl and cfg.get("starttls", True) is not False:
            conn.starttls()
        conn.login(cfg.get("user", ""), password)
        folder = cfg.get("folder") or "INBOX"
        typ, _ = conn.select(f'"{folder}"' if " " in folder else folder, readonly=True)
        if typ != "OK":
            raise RuntimeError(f"cannot open IMAP folder {folder!r}")
        typ, data = conn.search(None, f"SINCE {_imap_date(since)}" if since else "ALL")
        if typ != "OK":
            raise RuntimeError("IMAP search failed")
        ids = (data[0] or b"").split()
        for i in range(0, len(ids), 200):
            typ, data = conn.fetch(b",".join(ids[i:i + 200]), _FETCH)
            if typ != "OK":
                raise RuntimeError("IMAP fetch failed")
            for item in data:
                if isinstance(item, tuple) and len(item) > 1:
                    yield parse_headers(item[1])
    finally:
        try:
            conn.logout()
        except Exception:
            pass


def mailbox_kind(cfg: dict) -> list[str]:
    return [k for k in ("mbox", "maildir", "imap") if cfg.get(k)]


def read_mailbox(cfg: dict, since: datetime | None) -> tuple[Iterable[Envelope], str]:
    """(messages, where) for the one mailbox configured in `cfg`."""
    kind = mailbox_kind(cfg)[0]
    if kind == "mbox":
        return read_mbox(cfg["mbox"]), f"mbox {cfg['mbox']}"
    if kind == "maildir":
        return read_maildir(cfg["maildir"]), f"maildir {cfg['maildir']}"
    imap = cfg["imap"]
    return read_imap(imap, since), f"imap {imap.get('host')}/{imap.get('folder') or 'INBOX'}"


# ---------------------------------------------------------------------------
#  Matching
# ---------------------------------------------------------------------------
class Matcher:
    """Recipient address -> canary, for canaries on the inbox domain(s)."""

    def __init__(self, canaries, domains: Iterable[str] = ()):
        domains = {d.lower().strip() for d in domains if d}
        mine = [c for c in canaries if c.email and "@" in c.email]
        if not domains:   # default: the domains of the ledger's inbox canaries
            domains = {c.email.rsplit("@", 1)[1].lower() for c in mine if c.detect == "inbox"}
        self.domains = domains
        watched = [c for c in mine if c.email.rsplit("@", 1)[1].lower() in domains]
        self.by_email = {c.email.lower(): c for c in watched}
        self.by_token = {c.record_id.lower(): c for c in watched}

    def match(self, address: str):
        address = address.lower()
        local, _, domain = address.rpartition("@")
        if domain not in self.domains:
            return None
        if address in self.by_email:
            return self.by_email[address]
        # the token survives even if the local part was rewritten (case, +tag)
        for token in _HEX6.findall(local):
            if token in self.by_token:
                return self.by_token[token]
        return None


def scan(messages: Iterable[Envelope], matcher: Matcher, since: datetime | None = None
         ) -> tuple[dict, int]:
    """Aggregate matches per canary. Returns ({record_id: info}, messages read)."""
    found: dict[str, dict] = {}
    read = 0
    for env in messages:
        if since and env.date and env.date < since:
            continue
        read += 1
        for addr in env.recipients:
            c = matcher.match(addr)
            if c is None:
                continue
            info = found.setdefault(c.record_id, {"canary": c, "address": c.email,
                                                  "messages": 0, "first": None,
                                                  "last": None, "senders": set()})
            info["messages"] += 1
            if env.date:
                info["first"] = min(filter(None, (info["first"], env.date)))
                info["last"] = max(filter(None, (info["last"], env.date)))
            if env.sender_domain:
                info["senders"].add(env.sender_domain)
            break           # one canary per message is enough
    return found, read


def since_from(days) -> datetime | None:
    if days in (None, "", 0):
        return None
    return datetime.now(timezone.utc) - timedelta(days=int(days))


# ---------------------------------------------------------------------------
#  CLI: stille-hunter inbox
# ---------------------------------------------------------------------------
def main(argv=None):
    from . import check
    check.load_plugins()

    p = argparse.ArgumentParser(
        prog="stille-hunter inbox",
        description="Match mail received on your catch-all against canary ledgers. "
                    "Reads recipient headers only; message contents are never kept.")
    p.add_argument("ledger", nargs="+", help="Canary ledger(s) (.jsonl or .csv).")
    src = p.add_mutually_exclusive_group()
    src.add_argument("--mbox", metavar="PATH", help="Read an mbox file.")
    src.add_argument("--maildir", metavar="PATH", help="Read a Maildir folder.")
    src.add_argument("--imap", metavar="HOST", help="Read an IMAP mailbox (read-only).")
    p.add_argument("--imap-user", metavar="USER")
    p.add_argument("--imap-port", type=int, metavar="PORT")
    p.add_argument("--imap-folder", metavar="NAME", help="Default: INBOX.")
    p.add_argument("--domain", action="append", default=[], metavar="DOMAIN",
                   help="Your inbox domain (repeatable). Default: from the config, "
                        "else the domains of the ledger's inbox canaries.")
    p.add_argument("--days", type=int, metavar="N",
                   help="Only mail from the last N days.")
    p.add_argument("--config", help='JSON config; mailbox settings go under "inbox", '
                                    'notifications under "notify".')
    p.add_argument("--out", help="Write hits as JSONL to this path.")
    p.add_argument("--report", action="append", default=[], metavar="PATH",
                   help="Write a report (.html or .json). Repeatable.")
    p.add_argument("--report-title", metavar="TEXT")
    p.add_argument("--no-notify", action="store_true")
    args = p.parse_args(argv)

    config = {}
    if args.config:
        try:
            with open(args.config, encoding="utf-8") as f:
                config = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            p.error(f"cannot read config {args.config}: {e}")
    inbox_cfg = dict(config.get("inbox") or {})
    if args.mbox or args.maildir or args.imap:
        for k in ("mbox", "maildir", "imap"):
            inbox_cfg.pop(k, None)
    if args.mbox:
        inbox_cfg["mbox"] = args.mbox
    if args.maildir:
        inbox_cfg["maildir"] = args.maildir
    if args.imap or args.imap_user or args.imap_port or args.imap_folder:
        imap = dict(inbox_cfg.get("imap") or {})
        for key, val in (("host", args.imap), ("user", args.imap_user),
                         ("port", args.imap_port), ("folder", args.imap_folder)):
            if val:
                imap[key] = val
        inbox_cfg["imap"] = imap
    if args.domain:
        inbox_cfg["domain"] = args.domain
    if args.days is not None:
        inbox_cfg["days"] = args.days
    if not mailbox_kind(inbox_cfg):
        p.error('no mailbox: pass --mbox, --maildir or --imap, or set one under '
                '"inbox" in --config')
    config["inbox"] = inbox_cfg

    run = argparse.Namespace(ledger=args.ledger, sources="inbox", include_inbox=True,
                             out=args.out, report=args.report,
                             report_title=args.report_title, no_notify=args.no_notify)
    sys.exit(check.execute(run, config, fail=p.error))
