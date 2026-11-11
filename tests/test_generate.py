# SPDX-License-Identifier: Apache-2.0
"""Tests for canary types: the invariants that matter for safety and realism.
Run with: pytest
"""
import argparse
import datetime

from stille_hunter.generate import load_type_plugins, _TYPES
from stille_hunter.types import member as member_mod


def _make(type_name, **overrides):
    """Instantiate a type and run its generate() with default-ish args."""
    load_type_plugins()
    t = _TYPES[type_name]()
    p = argparse.ArgumentParser()
    t.add_arguments(p)
    # build an args namespace from the parser defaults, then apply overrides
    args = p.parse_args([])
    for k, v in overrides.items():
        setattr(args, k, v)
    return list(t.generate(args, overrides.pop("count", 100)))


# ---- member type ----------------------------------------------------------
def test_member_adults_only():
    today = datetime.date.today()
    for rec in _make("member", locale="jp", count=200):
        born = datetime.date.fromisoformat(rec["birthdate"])
        age = (today - born).days // 365
        assert 20 <= age <= 75, f"age {age} out of range"


def test_member_cards_fail_luhn_by_default():
    def luhn_ok(num):
        d = [int(c) for c in num][::-1]
        t = sum((x * 2 - 9 if x * 2 > 9 else x * 2) if i % 2 else x
                for i, x in enumerate(d))
        return t % 10 == 0
    for rec in _make("member", locale="jp", count=100):
        assert not luhn_ok(rec["card_number"]), "default cards must fail Luhn"


def test_member_token_woven_into_markers():
    for rec in _make("member", locale="jp", count=50):
        tok = rec["record_id"]
        assert tok in rec["email"]
        assert tok[:4] in rec["user_id"]
        assert rec["_ledger"]["email"] == rec["email"]


def test_member_gb_postcode_matches_city():
    allowed = {c: set(a) for c, a in member_mod._GB_CITIES}
    for rec in _make("member", locale="gb", count=100):
        tail = rec["address"].rsplit(",", 1)[-1].strip()
        city = tail.rsplit(" ", 2)[0]
        area = "".join(ch for ch in tail.split(" ")[-2] if ch.isalpha())
        assert area in allowed[city], f"{area} not valid for {city}"


def test_member_ca_postal_matches_province():
    # first letter of the postal code must match the province's FSA letter
    # postal code's first letter is tied to the CITY (an FSA letter), not just
    # the province (several cities in one province can have different letters).
    city_letter = {c[0]: c[2] for c in member_mod._CA_CITIES}
    for rec in _make("member", locale="ca", count=100):
        # "<num> <street>, <City>, <PROV> A1A 1A1"
        city = rec["address"].split(",")[1].strip()
        postal = rec["address"].rsplit(",", 1)[-1].split()[1]
        assert postal[0] == city_letter[city], f"{postal} wrong for {city}"


def test_member_detect_flag_split():
    recs = _make("member", locale="jp", count=200,
                 self_domain="alerts.acme-corp.jp", self_ratio=0.5)
    inbox = [r for r in recs if r["_detect"] == "inbox"]
    search = [r for r in recs if r["_detect"] == "search"]
    assert inbox and search, "both detect modes should appear"
    for r in inbox:
        assert r["email"].endswith("@alerts.acme-corp.jp")


# ---- aws_key type ---------------------------------------------------------
def test_aws_key_shape_and_token():
    for rec in _make("aws_key", count=50):
        kid = rec["aws_access_key_id"]
        sec = rec["aws_secret_access_key"]
        assert len(kid) == 20 and kid.startswith("AKIA")
        assert len(sec) == 40
        assert rec["record_id"].upper() in kid
        assert rec["record_id"] in sec
        assert rec["_detect"] == "search"


# ---- api_token type -------------------------------------------------------
def test_api_token_prefix_and_token_woven():
    prefixes = {"github": "ghp_", "openai": "sk-", "stripe": "sk_live_",
                "slack": "xoxb-"}
    for provider, prefix in prefixes.items():
        for rec in _make("api_token", provider=provider, count=25):
            tok = rec["api_token"]
            assert tok.startswith(prefix), f"{provider}: {tok}"
            assert rec["record_id"] in tok, "canary token must be recoverable"
            assert rec["_detect"] == "search"
            # the searchable marker is recorded under the name the github
            # source looks for
            assert rec["_ledger"]["api_token"] == tok


def test_api_token_mix_spreads_providers():
    seen = {rec["provider"] for rec in _make("api_token", mix=True, count=200)}
    assert len(seen) >= 3, f"--mix should vary providers, saw {seen}"
