# SPDX-License-Identifier: Apache-2.0
"""Canary type: aws_key — a fake AWS access-key pair.

Produces an AWS access-key-ID + secret-access-key pair shaped like the real
thing, to seed into config files, .env files, CI variables, notebooks, or
anywhere a leaked credential would plausibly sit. If the pair later shows up in
a public repo, paste, or breach dump, searching for its unique token finds it —
and the ledger tells you which seeded location it came from.

The pair is INERT: it authenticates to nothing. The access-key ID embeds our
token in its tail so it can never collide with a real AWS key, and the secret
is random. This is a SEARCH canary (detect=search): stille-hunter finds the
string where it leaked. It does NOT phone home when "used" — that active style
needs an external beacon service and is out of scope for stille-hunter.

Reference shapes:
  * Access key ID: a prefix (AKIA for long-term IAM user keys) + 16 base32-ish
    chars, 20 total, uppercase letters and digits.
  * Secret access key: 40 chars, base64-ish (A-Za-z0-9+/).
"""
from __future__ import annotations

import argparse
import secrets
from typing import Iterable

from ..generate import CanaryType, register_type, new_token

# AWS key-ID prefixes. AKIA = long-term IAM user access key (the kind that most
# often gets committed by mistake). Others exist but AKIA is the realistic pick.
_ID_PREFIXES = ["AKIA"]
_ID_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"   # base32 alphabet, AWS-like
_SECRET_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def _rand(alphabet: str, n: int) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(n))


@register_type
class AwsKeyType(CanaryType):
    name = "aws_key"
    description = "Fake AWS access-key pair (inert; found by searching for its token)."

    def add_arguments(self, p: argparse.ArgumentParser) -> None:
        p.add_argument("--prefix", default="AKIA", choices=_ID_PREFIXES,
                       help="Access-key-ID prefix (AKIA = IAM user long-term key).")
        p.add_argument("--region", default=None,
                       help="Optional AWS region to record alongside (e.g. ap-northeast-1).")

    def generate(self, args, count: int) -> Iterable[dict]:
        for _ in range(count):
            yield self._one(args.prefix, args.region)

    def _one(self, prefix: str, region) -> dict:
        token = new_token()                       # 6 hex chars, e.g. 'a3f8c1'
        token_uc = token.upper()                  # fits the uppercase ID alphabet

        # Access-key ID: prefix(4) + body to total 20 chars, with the token
        # embedded in the tail so it is unique and recoverable by search.
        body_len = 20 - len(prefix) - len(token_uc)
        access_key_id = prefix + _rand(_ID_ALPHABET, body_len) + token_uc

        # Secret access key: 40 chars, token embedded too (search can match
        # either the ID or the secret).
        sec_body = _rand(_SECRET_ALPHABET, 40 - len(token))
        secret_access_key = sec_body[:17] + token + sec_body[17:]

        rec = {
            "record_id": token,
            "aws_access_key_id": access_key_id,
            "aws_secret_access_key": secret_access_key,
            "_detect": "search",   # no catch-all for a key; found by searching
            "_ledger": {
                "aws_access_key_id": access_key_id,
                "aws_secret_access_key": secret_access_key,
            },
        }
        if region:
            rec["region"] = region
            rec["_ledger"]["region"] = region
        return rec
