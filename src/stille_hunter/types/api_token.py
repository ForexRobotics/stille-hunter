# SPDX-License-Identifier: Apache-2.0
"""Canary type: api_token — a fake service API token / personal access token.

Produces a single secret-looking token shaped like a real service credential
(a GitHub PAT, an OpenAI key, a Stripe secret key, a Slack bot token, ...), to
seed into .env files, config, CI/CD variables, notebooks, or anywhere a leaked
token would plausibly sit. If the token later shows up in public code, a paste,
or a dump, searching for its unique embedded token finds it — and the ledger
tells you which seeded location it came from.

API tokens are the single most common secret committed to public repos by
mistake, which makes them the highest-value search canary for the GitHub
code-search source.

The token is INERT: it authenticates to nothing. It keeps the real prefix (so
it looks genuine and is greppable the same way) but the body is random with our
6-hex token woven into the tail, so it can never collide with a real
credential. This is a SEARCH canary (detect=search): stille-hunter finds the
string where it leaked. It does NOT phone home when "used".

Reference shapes (prefix + random body, lengths chosen to match the real ones):
  * github  : ghp_ + 36 base62        (classic personal access token)
  * openai  : sk-  + 48 base62        (API secret key)
  * stripe  : sk_live_ + 24 base62    (live secret key)
  * slack   : xoxb- + 12 digits + '-' + 24 base62   (bot token)
  * generic : 40 hex                  (unlabelled bearer token)
"""
from __future__ import annotations

import argparse
import secrets
from typing import Iterable

from ..generate import CanaryType, register_type, new_token

_B62 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
_HEX = "0123456789abcdef"
_DIGITS = "0123456789"

_PROVIDERS = ("github", "openai", "stripe", "slack", "generic")


def _rand(alphabet: str, n: int) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(n))


def _embed(body: str, token: str) -> str:
    """Weave the canary token into the tail of a random body, keeping length."""
    keep = body[: len(body) - len(token)]
    return keep + token


def _build(provider: str, token: str) -> str:
    """Return a realistic, inert token for `provider` with `token` embedded."""
    if provider == "github":
        return "ghp_" + _embed(_rand(_B62, 36), token)
    if provider == "openai":
        return "sk-" + _embed(_rand(_B62, 48), token)
    if provider == "stripe":
        return "sk_live_" + _embed(_rand(_B62, 24), token)
    if provider == "slack":
        return "xoxb-" + _rand(_DIGITS, 12) + "-" + _embed(_rand(_B62, 24), token)
    # generic: 40-hex bearer token
    return _embed(_rand(_HEX, 40), token)


@register_type
class ApiTokenType(CanaryType):
    name = "api_token"
    description = "Fake service API/access token (inert; found by searching for its token)."

    def add_arguments(self, p: argparse.ArgumentParser) -> None:
        p.add_argument("--provider", default="github", choices=_PROVIDERS,
                       help="Token shape to mimic (default: github). "
                            "'random' mixes providers across the batch.")
        p.add_argument("--mix", action="store_true",
                       help="Ignore --provider and pick a random provider per "
                            "token, for a realistic mixed .env/secret store.")

    def generate(self, args, count: int) -> Iterable[dict]:
        for _ in range(count):
            provider = (secrets.choice(_PROVIDERS) if args.mix else args.provider)
            yield self._one(provider)

    def _one(self, provider: str) -> dict:
        token = new_token()                 # 6 hex chars, e.g. 'a3f8c1'
        api_token = _build(provider, token)
        return {
            "record_id": token,
            "provider": provider,
            "api_token": api_token,
            "_detect": "search",   # no catch-all for a token; found by searching
            "_ledger": {
                "provider": provider,
                "api_token": api_token,
            },
        }
