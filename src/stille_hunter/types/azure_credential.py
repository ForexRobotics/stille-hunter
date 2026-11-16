# SPDX-License-Identifier: Apache-2.0
"""Canary type: azure_credential - a fake Azure service-principal credential.

Produces the trio that identifies an Azure (Microsoft Entra ID) service
principal - application (client) ID, tenant ID and client secret - shaped like
the real thing, to seed into config files, .env files, CI variables, or the
JSON that `az ad sp create-for-rbac` prints and people paste into repos. If the
credential later shows up in public code, a paste or a dump, searching for it
finds it, and the ledger says which seeded location it came from.

The credential is INERT: the IDs are random GUIDs that belong to no tenant or
application, and the secret authenticates to nothing. Our 6-hex canary token
is woven into the end of the secret. This is a SEARCH canary
(detect=search). It does NOT fire when someone tries to log in with it: that
active style needs an external beacon and is out of scope for stille-hunter.

Reference shapes:
  * client ID / tenant ID: GUIDs.
  * client secret (current format): 40 chars - 3 chars, a digit, "Q~",
    then 34 chars from [A-Za-z0-9_~.-].
Because the secret has the real format, secret scanners (GitHub's included)
recognise it. That is the point of a realistic canary; if you plant one in a
repository you push to GitHub yourself, push protection may ask you to confirm.
"""
from __future__ import annotations

import secrets
import uuid
from typing import Iterable

from ..generate import CanaryType, new_token, register_type

_SECRET_ALPHABET = ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
                    "0123456789_~.-")
_DIGITS = "0123456789"

# Plausible service-principal display names.
_SP_NAMES = [
    "sp-backup-prod", "sp-cicd-deploy", "sp-terraform", "sp-data-pipeline",
    "sp-monitoring", "sp-github-actions", "sp-aks-cluster", "sp-storage-sync",
    "sp-app-prod", "sp-reporting",
]


def _rand(alphabet: str, n: int) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(n))


def _client_secret(token: str) -> str:
    """40-char Entra client secret in the current format, token at the end."""
    head = _rand(_SECRET_ALPHABET.replace("-", ""), 3) + secrets.choice(_DIGITS) + "Q~"
    tail = _rand(_SECRET_ALPHABET, 34 - len(token)) + token
    return head + tail


@register_type
class AzureCredentialType(CanaryType):
    name = "azure_credential"
    description = ("Fake Azure service-principal credential: client ID, tenant ID, "
                   "secret (inert).")

    def generate(self, args, count: int) -> Iterable[dict]:
        for _ in range(count):
            yield self._one()

    def _one(self) -> dict:
        token = new_token()
        client_id = str(uuid.uuid4())
        tenant = str(uuid.uuid4())
        secret = _client_secret(token)
        return {
            "record_id": token,
            "display_name": secrets.choice(_SP_NAMES),
            "azure_client_id": client_id,
            "azure_tenant_id": tenant,
            "azure_client_secret": secret,
            "_detect": "search",
            "_ledger": {
                "azure_client_id": client_id,
                "azure_tenant_id": tenant,
                "azure_client_secret": secret,
            },
        }
