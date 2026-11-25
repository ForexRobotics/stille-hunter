# SPDX-License-Identifier: Apache-2.0
"""Tests for canary types: the invariants that matter for safety and realism.
Run with: pytest
"""
import argparse
import datetime

from stille_hunter.generate import _TYPES, load_type_plugins
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


def test_member_de_postcode_matches_city():
    allowed = {c: set(p) for c, p in member_mod._DE_CITIES}
    for rec in _make("member", locale="de", count=200):
        # "<Straße> <Nr>, <PLZ> <Stadt>"
        plz, city = rec["address"].rsplit(",", 1)[-1].strip().split(" ", 1)
        assert len(plz) == 5 and plz.isdigit(), plz
        assert plz[:2] in allowed[city], f"{plz} not valid for {city}"


def test_member_de_markers_are_ascii_and_phone_is_german():
    for rec in _make("member", locale="de", count=200):
        assert rec["locale"] == "de"
        local = rec["email"].split("@", 1)[0]
        assert local.isascii() and rec["user_id"].isascii()     # ü -> ue, ß -> ss
        assert rec["record_id"] in local
        assert rec["phone"].startswith("+49 1")
        digits = rec["phone"].replace("+49 ", "").replace(" ", "")
        assert digits.isdigit() and 10 <= len(digits) <= 11
    domains = {r["email"].split("@", 1)[1] for r in _make("member", locale="de", count=300)}
    assert domains & {"web.de", "gmx.de", "t-online.de"}     # a German mix, not a US one


def test_db_dump_de_notes_are_german():
    from stille_hunter.types import db_dump
    for rec in _make("db_dump", locale="de", count=30):
        ref = rec["_ledger"]["marker"]
        assert rec["_ledger"]["locale"] == "de"
        assert rec["note"] in {t.format(ref=ref) for t in db_dump._NOTES_DE}


def test_member_tw_postal_code_matches_district():
    allowed = {(c, d): code for c, d, code in member_mod._TW_DISTRICTS}
    for rec in _make("member", locale="tw", count=200):
        addr = rec["address"]
        postal = addr[:3]
        match = [k for k, code in allowed.items() if addr[3:].startswith(k[0] + k[1])]
        assert match, addr
        assert allowed[match[0]] == postal, f"{postal} wrong for {match[0]}"
        assert "號" in addr


def test_member_tw_names_phone_and_ascii_markers():
    for rec in _make("member", locale="tw", count=200):
        assert rec["locale"] == "tw"
        assert " " not in rec["full_name"] and 2 <= len(rec["full_name"]) <= 4
        local = rec["email"].split("@", 1)[0]
        assert local.isascii() and rec["user_id"].isascii()
        assert rec["record_id"] in local
        head, mid, tail = rec["phone"].split("-")
        assert head.startswith("09") and len(head) == 4 and len(mid) == 3 and len(tail) == 3


def test_zh_tw_is_an_alias_of_tw():
    recs = _make("member", locale="zh-TW", count=5)
    assert {r["locale"] for r in recs} == {"tw"}
    from stille_hunter.types import db_dump
    for rec in _make("db_dump", locale="zh-TW", count=10):
        assert rec["_ledger"]["locale"] == "tw"
        assert rec["note"] in {t.format(ref=rec["ref_code"]) for t in db_dump._NOTES_TW}


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


# ---- azure_credential type ------------------------------------------------
def test_azure_credential_shape_and_token():
    import re
    import uuid
    secret_re = re.compile(r"[A-Za-z0-9_~.]{3}\dQ~[A-Za-z0-9_~.-]{34}")
    for rec in _make("azure_credential", count=50):
        uuid.UUID(rec["azure_client_id"])
        uuid.UUID(rec["azure_tenant_id"])
        sec = rec["azure_client_secret"]
        assert secret_re.fullmatch(sec), sec
        assert sec.endswith(rec["record_id"])
        assert rec["_detect"] == "search"
        assert rec["_ledger"]["azure_client_secret"] == sec
        assert rec["_ledger"]["azure_client_id"] == rec["azure_client_id"]


# ---- mcp_config type ------------------------------------------------------
def test_mcp_config_is_valid_json_with_token():
    import json
    for server, prefix, env_var in (("github", "ghp_", "GITHUB_PERSONAL_ACCESS_TOKEN"),
                                    ("slack", "xoxb-", "SLACK_BOT_TOKEN")):
        for rec in _make("mcp_config", server=server, count=20):
            cfg = json.loads(rec["mcp_config"])
            entry = cfg["mcpServers"][server]
            assert entry["env"][env_var] == rec["mcp_token"]
            assert rec["mcp_token"].startswith(prefix)
            assert rec["record_id"] in rec["mcp_token"]
            assert rec["_ledger"]["mcp_token"] == rec["mcp_token"]
            assert rec["_detect"] == "search"


def test_mcp_config_only_uses_official_scoped_packages():
    # an invented or unscoped package name could be registered by anyone and
    # then run by whoever copies a leaked config
    import json
    for rec in _make("mcp_config", mix=True, count=50):
        args = json.loads(rec["mcp_config"])["mcpServers"][rec["mcp_server"]]["args"]
        packages = [a for a in args if not a.startswith("-")]
        assert packages and all(p.startswith("@modelcontextprotocol/") for p in packages)


# ---- kubeconfig type ------------------------------------------------------
def test_kubeconfig_token_server_and_ca():
    import base64
    import ipaddress
    import re
    from urllib.parse import urlparse
    for rec in _make("kubeconfig", count=50):
        kc = rec["kubeconfig"]
        tok = rec["kube_token"]
        # bootstrap-token format, and its id part IS the canary token
        assert re.fullmatch(r"[a-z0-9]{6}\.[a-z0-9]{16}", tok)
        assert tok.split(".")[0] == rec["record_id"]
        assert f"    token: {tok}\n" in kc
        # server is a private address: never a real, reachable cluster
        server = re.search(r"^    server: (\S+)$", kc, re.M).group(1)
        url = urlparse(server)
        assert url.scheme == "https" and url.port == 6443
        assert ipaddress.ip_address(url.hostname).is_private
        # CA data decodes to a PEM-shaped block
        ca = re.search(r"certificate-authority-data: (\S+)", kc).group(1)
        pem = base64.b64decode(ca).decode()
        assert pem.startswith("-----BEGIN CERTIFICATE-----\n")
        assert pem.rstrip().endswith("-----END CERTIFICATE-----")
        assert "current-context: " in kc and rec["cluster_name"] in kc
        assert rec["_ledger"]["kube_token"] == tok
        assert rec["_detect"] == "search"
