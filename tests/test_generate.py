# SPDX-License-Identifier: Apache-2.0
"""Minimal tests for the canary generator: the invariants that matter for
safety and realism. Run with: pytest
"""
import datetime

from stille_hunter import generate as g


def _records(n, locale="jp", self_domain=None, self_ratio=0.4):
    prof = g._LOCALES[locale]
    return list(g.generate(n, prof, "test", "mixed", False, self_domain, self_ratio))


def test_adults_only():
    today = datetime.date.today()
    for rec in _records(200):
        born = datetime.date.fromisoformat(rec.birthdate)
        age = (today - born).days // 365
        assert 20 <= age <= 75, f"age {age} out of range"


def test_cards_fail_luhn_by_default():
    def luhn_ok(num):
        d = [int(c) for c in num][::-1]
        t = sum((x * 2 - 9 if x * 2 > 9 else x * 2) if i % 2 else x
                for i, x in enumerate(d))
        return t % 10 == 0
    for rec in _records(100):
        assert not luhn_ok(rec.card_number), "default cards must fail Luhn"


def test_token_woven_into_markers():
    for rec in _records(50):
        tok = rec.record_id
        assert tok in rec.email
        assert tok[:4] in rec.user_id


def test_locale_consistency_gb_postcode_matches_city():
    allowed = {c: set(a) for c, a in g._GB_CITIES}
    for rec in _records(100, locale="gb"):
        # address ends with "City AREA.. .."
        tail = rec.address.rsplit(",", 1)[-1].strip()
        city = tail.rsplit(" ", 2)[0]
        area = "".join(ch for ch in tail.split(" ")[-2] if ch.isalpha())
        assert area in allowed[city], f"{area} not valid for {city}"


def test_detect_flag_split():
    recs = _records(200, self_domain="alerts.example-corp.jp", self_ratio=0.5)
    inbox = [r for r in recs if r._detect == "inbox"]
    search = [r for r in recs if r._detect == "search"]
    assert inbox and search, "both detect modes should appear"
    for r in inbox:
        assert r.email.endswith("@alerts.example-corp.jp")
