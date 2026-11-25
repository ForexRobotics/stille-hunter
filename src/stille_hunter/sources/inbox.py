# SPDX-License-Identifier: Apache-2.0
"""Check source: inbox - mail received on your own catch-all.

Matches recipient addresses in a mailbox you own (mbox, Maildir or IMAP,
read-only) against the ledger's canary addresses. Headers only; message
contents are never fetched from IMAP and never kept. See stille_hunter.inbox
and `stille-hunter inbox`.

Config (under "inbox"), exactly one mailbox:

    {"inbox": {"domain": "your-trap-domain.net",
               "imap": {"host": "imap.provider.net", "user": "trap@...",
                        "password": "...", "folder": "INBOX"},
               "days": 30}}

or "mbox": "/path/to/mbox", or "maildir": "/path/to/Maildir". The IMAP password
may come from the STILLE_IMAP_PASSWORD environment variable instead.
"""
from __future__ import annotations

import os
from typing import Iterable

from .. import inbox
from ..check import Canary, CheckSource, Hit, register


@register
class InboxSource(CheckSource):
    name = "inbox"
    supports = ("email",)

    def available(self) -> tuple[bool, str]:
        kinds = inbox.mailbox_kind(self.config)
        if not kinds:
            return False, 'no mailbox configured (set "mbox", "maildir" or "imap" under "inbox")'
        if len(kinds) > 1:
            return False, f"configure only one mailbox, not {' and '.join(kinds)}"
        if kinds == ["imap"]:
            imap = self.config["imap"]
            if not isinstance(imap, dict) or not imap.get("host"):
                return False, 'imap needs "host"'
            if not (imap.get("password") or os.environ.get(inbox.PASSWORD_ENV)):
                return False, f'imap needs "password" or the {inbox.PASSWORD_ENV} variable'
        return True, ""

    def check(self, canaries: list[Canary]) -> Iterable[Hit]:
        domains = self.config.get("domain") or []
        if isinstance(domains, str):
            domains = [domains]
        matcher = inbox.Matcher(canaries, domains)
        since = inbox.since_from(self.config.get("days"))
        messages, where = inbox.read_mailbox(self.config, since)
        found, read = inbox.scan(messages, matcher, since)
        self.stats = {"messages read": read, "canary addresses watched": len(matcher.by_email),
                      "inbox domains": ", ".join(sorted(matcher.domains))[:200]}
        for info in found.values():
            first, last = info["first"], info["last"]
            senders = sorted(info["senders"])
            detail = f"{info['messages']} message(s)"
            if first:
                detail += f", first {first.date().isoformat()}"
            if senders:
                more = f" (+{len(senders) - 5})" if len(senders) > 5 else ""
                detail += f", from {', '.join(senders[:5])}{more}"
            kw = {"found_at": last.isoformat()} if last else {}
            yield Hit(canary=info["canary"], source=self.name, token_kind="email",
                      token=info["address"], location=where, detail=detail, **kw)
