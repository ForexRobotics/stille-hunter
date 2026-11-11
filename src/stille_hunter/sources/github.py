# SPDX-License-Identifier: Apache-2.0
"""stille-hunter check source: GitHub code search.

Looks up each canary's secret-looking markers in public code on GitHub. If a
planted credential (an aws_key, api_token, password hash, ...) shows up in a
public repo, it leaked — and the ledger says which seeded location it came
from. The classic case: a developer commits a config or .env that still has a
seeded canary in it.

Needs a GitHub token (any PAT; code search requires authentication). Without
one the source reports itself unavailable and is skipped.

Read-only and lookup-only: this only queries GitHub's public code-search index
for strings we generated. It clones nothing and stores nothing.

API notes:
  GET https://api.github.com/search/code?q=<term>
  headers: Authorization: Bearer <token>, Accept: application/vnd.github+json,
           X-GitHub-Api-Version: <date>, User-Agent: <app>
  200 -> {"total_count": N, "items": [{"html_url", "path", "repository": {...}}]}
  403/429 with X-RateLimit-Remaining: 0 -> rate limited (10 req/min for code search)
  401 -> bad token;  422 -> invalid query
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Iterable

from ..check import CheckSource, Hit, Canary, register

_API = "https://api.github.com/search/code"
_DEFAULT_UA = "stille-hunter (leak-canary self-check)"
_API_VERSION = "2022-11-28"

# Which ledger markers are worth searching on GitHub. Secret-looking, unique
# strings only — not email/user_id, which produce noise. The ledger for a
# member record also carries password_hash; for aws_key it carries the key id
# and secret; api_token etc. carry their token. We search whatever of these a
# given ledger row happens to have.
_SEARCHABLE = (
    "aws_access_key_id",
    "aws_secret_access_key",
    "api_token",
    "mcp_token",
    "kube_token",
    "azure_client_secret",
    "password_hash",
    "record_id",
)


@register
class GithubSource(CheckSource):
    name = "github"
    supports = ("record_id", "password_hash")  # informational; see _markers()

    def __init__(self, **config):
        super().__init__(**config)
        self.token = config.get("token") or ""
        self.user_agent = config.get("user_agent") or _DEFAULT_UA
        # code search is 10 req/min -> ~6.5s between calls is safe
        self.min_interval = float(config.get("min_interval", 6.5))
        # which marker kinds to search; override via config if wanted
        self.markers = tuple(config.get("markers", _SEARCHABLE))

    def available(self) -> tuple[bool, str]:
        if not self.token:
            return False, "GitHub token required (set config github.token)"
        return True, ""

    def _markers(self, c: Canary) -> dict[str, str]:
        """The secret-looking (marker_kind -> value) pairs worth searching for
        this canary: the configured kinds, taken from its named fields and its
        type-specific extras, empties dropped."""
        all_markers = c.tokens()   # named fields + extra, non-empty
        return {k: v for k, v in all_markers.items() if k in self.markers}

    def _search(self, term: str) -> list[dict]:
        q = urllib.parse.quote(f'"{term}"', safe="")
        url = f"{_API}?q={q}&per_page=10"
        req = urllib.request.Request(url, headers={
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": _API_VERSION,
            "User-Agent": self.user_agent,
        })
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data.get("items", [])
        except urllib.error.HTTPError as e:
            if e.code in (403, 429):
                remaining = e.headers.get("X-RateLimit-Remaining")
                if remaining == "0":
                    reset = e.headers.get("X-RateLimit-Reset")
                    wait = 10
                    if reset:
                        wait = max(10, int(reset) - int(time.time()) + 1)
                    time.sleep(min(wait, 70))
                    return self._search(term)  # one retry after the window
                raise RuntimeError(f"GitHub {e.code} (abuse/secondary limit)") from e
            if e.code == 401:
                raise RuntimeError("GitHub rejected the token (401)") from e
            if e.code == 422:
                return []  # query not valid for this term; treat as no hit
            raise RuntimeError(f"GitHub HTTP {e.code}") from e

    def check(self, canaries: list[Canary]) -> Iterable[Hit]:
        # de-dupe the actual strings we search, so repeated markers cost once
        seen_terms: set[str] = set()
        work: list[tuple[Canary, str, str]] = []
        for c in canaries:
            for kind, val in self._markers(c).items():
                if val not in seen_terms:
                    seen_terms.add(val)
                    work.append((c, kind, val))

        total = len(work)
        for i, (c, kind, term) in enumerate(work):
            self.progress(i, total, f"searching {kind}")
            if i > 0:
                time.sleep(self.min_interval)
            items = self._search(term)
            for it in items:
                repo = (it.get("repository") or {}).get("full_name", "?")
                yield Hit(
                    canary=c, source=self.name, token_kind=kind, token=term,
                    location=it.get("html_url", f"github:{repo}"),
                    detail=f"in {repo}/{it.get('path', '?')}",
                )
        self.progress(total, total, "done")
