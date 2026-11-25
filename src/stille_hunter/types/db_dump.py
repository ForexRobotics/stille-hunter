# SPDX-License-Identifier: Apache-2.0
"""Canary type: db_dump - marker rows to plant in a database table.

Database dumps are one of the most common leak artefacts. This type emits
plain, plausible rows - name, email, phone, a reference code and a free-text
note - meant to sit in a customers / accounts / tickets style table. If a dump
of that table surfaces in public code or a paste, searching for the reference
code finds it, and the ledger says which table it was planted in.

Pair it with the database-ready output formats:

    stille-hunter generate --type db_dump --format sql --table customers
    stille-hunter generate --type db_dump --format json   # e.g. a Laravel seeder

The reference code is the searchable marker: a common-looking prefix, our
6-hex canary token in upper case, and four digits (e.g. CUS-A3F8C10421). It
appears in its own column and again inside the note, the way a reference
number is copied into a comment. The email carries the token as well, so the
hibp source can check it too. This is a SEARCH canary (detect=search).
"""
from __future__ import annotations

import argparse
import secrets
from datetime import datetime, timedelta
from typing import Iterable

from ..generate import CanaryType, new_token, register_type, weighted_choice
from .member import locale_choices, resolve_locale

_PREFIXES = ["CUS", "ACC", "MEM", "REF", "TKT"]

_NOTES_EN = [
    "Migrated from the legacy CRM ({ref}).",
    "Customer asked for a copy of the last invoice. Ref {ref}.",
    "Support ticket {ref} closed after a callback.",
    "Address updated by phone, see {ref}.",
    "Duplicate account merged into {ref}.",
    "Refund issued, reference {ref}.",
]
_NOTES_JA = [
    "旧システムから移行（{ref}）",
    "請求書の再発行依頼あり。参照番号 {ref}",
    "問い合わせ {ref} は折り返し連絡で対応完了",
    "電話にて住所変更を受付（{ref}）",
    "重複アカウントを {ref} に統合",
    "返金処理済み。管理番号 {ref}",
]


_NOTES_DE = [
    "Aus dem alten CRM übernommen ({ref}).",
    "Kunde bat um eine Kopie der letzten Rechnung. Ref. {ref}.",
    "Supportfall {ref} nach Rückruf geschlossen.",
    "Adresse telefonisch geändert, siehe {ref}.",
    "Doppeltes Konto zusammengeführt in {ref}.",
    "Erstattung veranlasst, Referenz {ref}.",
]
_NOTES_TW = [
    "由舊系統移轉（{ref}）",
    "客戶要求補寄最近一期帳單。參考編號 {ref}",
    "客服案件 {ref} 已於回電後結案",
    "電話受理地址變更（{ref}）",
    "重複帳號已合併至 {ref}",
    "已完成退款，管理編號 {ref}",
]
_NOTES = {"jp": _NOTES_JA, "de": _NOTES_DE, "tw": _NOTES_TW}


def _ref_code(token: str) -> str:
    return f"{secrets.choice(_PREFIXES)}-{token.upper()}{secrets.randbelow(10000):04d}"


@register_type
class DbDumpType(CanaryType):
    name = "db_dump"
    description = "Plausible table rows with a searchable reference code, for DB planting."

    def add_arguments(self, p: argparse.ArgumentParser) -> None:
        p.add_argument("--locale", default="jp", choices=locale_choices(),
                       help="Locale for names, phones and email domains (default: jp).")

    def generate(self, args, count: int) -> Iterable[dict]:
        prof = resolve_locale(args.locale)
        notes = _NOTES.get(prof.code, _NOTES_EN)
        for _ in range(count):
            yield self._one(prof, notes)

    def _one(self, prof, notes) -> dict:
        token = new_token()
        full_name, rfirst, rlast = prof.name_fn()
        domain = weighted_choice([d for d, _ in prof.freemail],
                                 [w for _, w in prof.freemail])
        email = f"{rfirst}.{rlast}.{token}@{domain}"
        ref = _ref_code(token)
        created = datetime.now() - timedelta(days=secrets.randbelow(3 * 365) + 30,
                                             seconds=secrets.randbelow(86400))
        return {
            "record_id": token,
            "ref_code": ref,
            "full_name": full_name,
            "email": email,
            "phone": prof.phone_fn(),
            "note": secrets.choice(notes).format(ref=ref),
            "created_at": created.strftime("%Y-%m-%d %H:%M:%S"),
            "_detect": "search",
            "_ledger": {
                "locale": prof.code,
                "email": email,
                "marker": ref,
            },
        }
