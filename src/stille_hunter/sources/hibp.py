# SPDX-License-Identifier: Apache-2.0
"""stille-hunter check source: Have I Been Pwned (HIBP).

Looks up each canary email against HIBP's breachedAccount endpoint. A canary
address is freshly minted, so it only ever shows up here AFTER a breach that
happens post-seeding and includes the canary — which is exactly the signal we
want. Expect zero hits right after seeding; that is normal.

Needs a HIBP API key (Core tier and up). Without one the source reports itself
unavailable and is skipped — the rest of the run is unaffected.

Read-only and lookup-only: this only queries whether an address we generated
appears in a breach. It downloads no breach data and touches nothing else.

API notes (v3):
  GET https://haveibeenpwned.com/api/v3/breachedAccount/{url-encoded-email}
  headers: hibp-api-key: <key>,  user-agent: <app identifier>
  200 -> JSON array of breaches (pwned)
  404 -> not found (NOT an error; address not breached)
  401 -> bad/missing key
  429 -> rate limited; honour the retry-after header (seconds)
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Iterable

from ..check import CheckSource, Hit, Canary, register

_API = "https://haveibeenpwned.com/api/v3/breachedAccount/"
_DEFAULT_UA = "stille-hunter (leak-canary self-check; +https://github.com/)"


@register
class HibpSource(CheckSource):
    name = "hibp"
    # HIBP only knows about email addresses.
    supports = ("email",)

    def __init__(self, **config):
        super().__init__(**config)
        self.api_key = config.get("api_key") or ""
        self.user_agent = config.get("user_agent") or _DEFAULT_UA
        # seconds between requests; Core 1 is 10 rpm -> ~6s. Default is safe.
        self.min_interval = float(config.get("min_interval", 6.5))
        # include unverified breaches? HIBP default is to include them.
        self.include_unverified = bool(config.get("include_unverified", True))

    def available(self) -> tuple[bool, str]:
        if not self.api_key:
            return False, "HIBP API key required (set config hibp.api_key)"
        return True, ""

    def _lookup(self, email: str) -> list[dict] | None:
        """Return list of breaches (possibly empty) or None on 404/not-breached."""
        q = urllib.parse.quote(email, safe="")
        url = f"{_API}{q}?truncateResponse=false"
        if not self.include_unverified:
            url += "&IncludeUnverified=false"
        req = urllib.request.Request(url, headers={
            "hibp-api-key": self.api_key,
            "user-agent": self.user_agent,
            "Accept": "application/json",
        })
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None  # not breached — the common, healthy case
            if e.code == 429:
                retry = int(e.headers.get("retry-after", "10")) + 1
                time.sleep(retry)
                return self._lookup(email)  # one retry after honoring the wait
            if e.code == 401:
                raise RuntimeError("HIBP rejected the API key (401)") from e
            if e.code == 403:
                raise RuntimeError("HIBP rejected the user-agent (403)") from e
            raise RuntimeError(f"HIBP HTTP {e.code}") from e

    def check(self, canaries: list[Canary]) -> Iterable[Hit]:
        emails_seen = set()
        targets = [c for c in canaries if c.email and c.email not in emails_seen
                   and not emails_seen.add(c.email)]
        total = len(targets)
        for i, c in enumerate(targets):
            self.progress(i, total, f"querying {c.email}")
            if i > 0:
                time.sleep(self.min_interval)  # stay under the rate limit
            breaches = self._lookup(c.email)
            if breaches:
                names = ", ".join(b.get("Name", "?") for b in breaches)
                yield Hit(
                    canary=c, source=self.name, token_kind="email",
                    token=c.email,
                    location=f"HIBP breach(es): {names}",
                    detail=f"{len(breaches)} breach(es)",
                )
        self.progress(total, total, "done")
