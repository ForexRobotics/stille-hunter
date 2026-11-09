#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""stille-hunter: canary record generator.

Generates realistic-looking but entirely fake user-profile records to seed
into databases, files, or exports as leak canaries. Each record carries a
unique token woven into its user_id, email local-part, and password hash, so
that if the record later surfaces in a leak search you can tell which seeded
location it came from.

Design principles (see project memory / stille-hunter docs):
  * Everything stays on your own turf. This only *generates* data; it never
    touches anyone else's system.
  * Credit-card numbers use card-network *test* BIN ranges and (by default)
    a deliberately INVALID Luhn check digit, so they can never clear a real
    payment and can never collide with a live card.
  * No CVV (storing CVV violates PCI DSS; a real-looking dump wouldn't have it).
  * No national-ID / passport / driver-license numbers.
  * Members are always adults (20-75). We never generate minor PII, even fake.

Locales are *regional profiles*: --locale picks a bundle of name pool, address
generator, phone format and free-mail domain weights, so a US record looks US
all the way through. Add a country by adding one LocaleProfile; the engine is
locale-agnostic.

Email domains:
  * Self domain (--self-domain, one you control): mail to these can be caught
    with a catch-all, so a leak-user actually *touching* the address can be
    detected, on top of search hits. These records are flagged detect=inbox.
  * Free-mail domains: realistic filler. Nobody controls these for us, so they
    are SEARCH-HIT ONLY (detect=search). The unique token is always embedded
    in the local-part so it can't collide with a real address.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import secrets
import sys
from dataclasses import dataclass, asdict, field
from datetime import datetime, timedelta, timezone
from typing import Callable, Iterator

# ============================================================================
#  Name / place data per locale
# ============================================================================

# --- Japanese ---------------------------------------------------------------
_JP_SEI = [
    ("佐藤", "sato"), ("鈴木", "suzuki"), ("高橋", "takahashi"), ("田中", "tanaka"),
    ("伊藤", "ito"), ("渡辺", "watanabe"), ("山本", "yamamoto"), ("中村", "nakamura"),
    ("小林", "kobayashi"), ("加藤", "kato"), ("吉田", "yoshida"), ("山田", "yamada"),
    ("佐々木", "sasaki"), ("山口", "yamaguchi"), ("松本", "matsumoto"), ("井上", "inoue"),
    ("木村", "kimura"), ("林", "hayashi"), ("清水", "shimizu"), ("斎藤", "saito"),
    ("山崎", "yamazaki"), ("森", "mori"), ("阿部", "abe"), ("池田", "ikeda"),
    ("橋本", "hashimoto"), ("山下", "yamashita"), ("石川", "ishikawa"), ("中島", "nakajima"),
    ("前田", "maeda"), ("藤田", "fujita"), ("後藤", "goto"), ("小川", "ogawa"),
    ("岡田", "okada"), ("村上", "murakami"), ("長谷川", "hasegawa"), ("近藤", "kondo"),
    ("石井", "ishii"), ("前川", "maekawa"), ("坂本", "sakamoto"), ("遠藤", "endo"),
    ("青木", "aoki"), ("藤井", "fujii"), ("西村", "nishimura"), ("福田", "fukuda"),
    ("太田", "ota"), ("三浦", "miura"), ("岡本", "okamoto"), ("松田", "matsuda"),
    ("中川", "nakagawa"), ("中野", "nakano"),
]
_JP_MEI_M = [
    ("翔太", "shota"), ("大翔", "hiroto"), ("蓮", "ren"), ("悠真", "yuma"),
    ("樹", "itsuki"), ("直樹", "naoki"), ("健一", "kenichi"), ("拓也", "takuya"),
    ("大和", "yamato"), ("颯太", "sota"), ("陽翔", "haruto"), ("湊", "minato"),
    ("悠斗", "yuto"), ("大輝", "daiki"), ("海斗", "kaito"), ("雄太", "yuta"),
    ("健太", "kenta"), ("亮", "ryo"), ("誠", "makoto"), ("翔", "sho"),
]
_JP_MEI_F = [
    ("美咲", "misaki"), ("陽菜", "hina"), ("結衣", "yui"), ("葵", "aoi"),
    ("さくら", "sakura"), ("彩", "aya"), ("美月", "mizuki"), ("凛", "rin"),
    ("結菜", "yuna"), ("莉子", "riko"), ("愛", "ai"), ("遥", "haruka"),
    ("七海", "nanami"), ("美羽", "miu"), ("琴音", "kotone"), ("千尋", "chihiro"),
    ("麻衣", "mai"), ("愛美", "manami"), ("舞", "mai"), ("恵", "megumi"),
]
_JP_ADDR_PREFIX = [
    "東京都新宿区西新宿", "東京都渋谷区道玄坂", "大阪府大阪市北区梅田",
    "神奈川県横浜市西区みなとみらい", "愛知県名古屋市中区栄",
    "福岡県福岡市博多区博多駅前", "北海道札幌市中央区大通西",
    "栃木県宇都宮市馬場通り", "兵庫県神戸市中央区三宮町",
    "京都府京都市中京区烏丸通", "宮城県仙台市青葉区一番町",
]

# --- English given/family names (shared by US & GB) -------------------------
_EN_FIRST = [
    "James", "Mary", "John", "Patricia", "Robert", "Jennifer", "Michael",
    "Linda", "David", "Elizabeth", "William", "Barbara", "Richard", "Susan",
    "Joseph", "Jessica", "Thomas", "Sarah", "Charles", "Karen", "Daniel",
    "Emily", "Matthew", "Emma", "Anthony", "Olivia", "Mark", "Sophia",
    "Paul", "Grace", "Andrew", "Chloe", "Joshua", "Hannah", "Ryan", "Lucy",
    "Jack", "Amelia", "Harry", "Isla",
]
_EN_LAST = [
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller",
    "Davis", "Wilson", "Anderson", "Taylor", "Thomas", "Moore", "Jackson",
    "Martin", "Lee", "Thompson", "White", "Harris", "Clark", "Lewis",
    "Walker", "Hall", "Allen", "Young", "King", "Wright", "Scott", "Green",
    "Baker", "Adams", "Nelson", "Hill", "Campbell", "Mitchell", "Roberts",
    "Carter", "Evans", "Turner", "Parker",
]

# --- US places --------------------------------------------------------------
_US_CITIES = [
    ("New York", "NY"), ("Los Angeles", "CA"), ("Chicago", "IL"),
    ("Houston", "TX"), ("Phoenix", "AZ"), ("Philadelphia", "PA"),
    ("San Antonio", "TX"), ("San Diego", "CA"), ("Dallas", "TX"),
    ("Austin", "TX"), ("Seattle", "WA"), ("Denver", "CO"),
    ("Boston", "MA"), ("Portland", "OR"), ("Atlanta", "GA"),
    ("Miami", "FL"), ("Columbus", "OH"), ("Nashville", "TN"),
]
_US_STREETS = ["Main St", "Oak Ave", "Maple Ave", "Elm St", "Cedar Ln",
               "Washington St", "Lake Ave", "Park Blvd", "2nd St", "Sunset Blvd"]

# --- UK places --------------------------------------------------------------
# (city, [real postcode-area codes for that city]) so the postcode matches the
# city instead of being geographically nonsensical.
_GB_CITIES = [
    ("London", ["SW", "SE", "NW", "N", "E", "W", "EC", "WC"]),
    ("Manchester", ["M"]),
    ("Birmingham", ["B"]),
    ("Leeds", ["LS"]),
    ("Glasgow", ["G"]),
    ("Liverpool", ["L"]),
    ("Bristol", ["BS"]),
    ("Sheffield", ["S"]),
    ("Edinburgh", ["EH"]),
    ("Cardiff", ["CF"]),
    ("Nottingham", ["NG"]),
    ("Newcastle", ["NE"]),
    ("Brighton", ["BN"]),
    ("Leicester", ["LE"]),
]
_GB_STREETS = ["High St", "Station Rd", "Church Ln", "Victoria Rd",
               "Kings Rd", "Queens Rd", "Mill Ln", "Park Rd", "York Rd"]

_RANKS = ["bronze", "silver", "gold", "platinum"]
_RANK_WEIGHTS = [50, 30, 15, 5]
_STATUS = ["active", "active", "active", "suspended", "dormant"]

# --- free-mail domain weights per locale ------------------------------------
_FREEMAIL_JP = [
    ("gmail.com", 40), ("yahoo.co.jp", 18), ("icloud.com", 10),
    ("outlook.com", 6), ("hotmail.com", 5), ("me.com", 2),
    ("docomo.ne.jp", 5), ("au.com", 3), ("ezweb.ne.jp", 2),
    ("softbank.ne.jp", 3), ("nifty.com", 2), ("so-net.ne.jp", 2),
    ("biglobe.ne.jp", 2), ("ocn.ne.jp", 2),
]
_FREEMAIL_US = [
    ("gmail.com", 45), ("yahoo.com", 15), ("icloud.com", 12),
    ("outlook.com", 8), ("hotmail.com", 7), ("aol.com", 5),
    ("live.com", 3), ("comcast.net", 3), ("me.com", 2),
]
_FREEMAIL_GB = [
    ("gmail.com", 42), ("outlook.com", 12), ("hotmail.co.uk", 10),
    ("yahoo.co.uk", 10), ("icloud.com", 10), ("btinternet.com", 6),
    ("live.co.uk", 4), ("sky.com", 3),
]

# ============================================================================
#  Locale profiles
# ============================================================================

def _jp_name():
    sei_k, sei_r = secrets.choice(_JP_SEI)
    mei_k, mei_r = secrets.choice(_JP_MEI_M if secrets.randbelow(2) else _JP_MEI_F)
    return f"{sei_k} {mei_k}", mei_r, sei_r  # display, romaji_first, romaji_last

def _en_name():
    first = secrets.choice(_EN_FIRST)
    last = secrets.choice(_EN_LAST)
    return f"{first} {last}", first.lower(), last.lower()

def _jp_address():
    return (secrets.choice(_JP_ADDR_PREFIX) +
            f"{secrets.randbelow(9)+1}-{secrets.randbelow(30)+1}-{secrets.randbelow(9999)+1}")

def _us_address():
    city, state = secrets.choice(_US_CITIES)
    num = secrets.randbelow(9900) + 100
    street = secrets.choice(_US_STREETS)
    zip5 = f"{secrets.randbelow(90000)+10000}"
    return f"{num} {street}, {city}, {state} {zip5}"

def _gb_address():
    city, areas = secrets.choice(_GB_CITIES)
    num = secrets.randbelow(250) + 1
    street = secrets.choice(_GB_STREETS)
    # postcode area now matches the city (e.g. Glasgow -> G, Cardiff -> CF).
    # Still only plausible-looking, not guaranteed to be a real delivery point.
    area = secrets.choice(areas)
    pc = (f"{area}{secrets.randbelow(20)+1} "
          f"{secrets.randbelow(9)+1}"
          f"{secrets.choice('ABDEFGHJLNPQRSTUWXYZ')}"
          f"{secrets.choice('ABDEFGHJLNPQRSTUWXYZ')}")
    return f"{num} {street}, {city} {pc}"

def _jp_phone():
    return f"080-{secrets.randbelow(9000)+1000}-{secrets.randbelow(9000)+1000}"

def _us_phone():
    area = secrets.randbelow(800) + 200
    return f"+1 ({area}) {secrets.randbelow(900)+100}-{secrets.randbelow(9000)+1000}"

def _gb_phone():
    return f"+44 7{secrets.randbelow(900)+100} {secrets.randbelow(900000)+100000}"


@dataclass
class LocaleProfile:
    code: str
    name_fn: Callable[[], tuple]
    address_fn: Callable[[], str]
    phone_fn: Callable[[], str]
    freemail: list


_LOCALES = {
    "jp": LocaleProfile("jp", _jp_name, _jp_address, _jp_phone, _FREEMAIL_JP),
    "us": LocaleProfile("us", _en_name, _us_address, _us_phone, _FREEMAIL_US),
    "gb": LocaleProfile("gb", _en_name, _gb_address, _gb_phone, _FREEMAIL_GB),
}

# ============================================================================
#  Cards
# ============================================================================
_TEST_BINS = {
    "visa":       ["400000", "411111", "424242"],
    "mastercard": ["510510", "555555", "520000"],
    "amex":       ["340000", "370000"],
    "jcb":        ["353011", "356600"],
}
_CARD_LEN = {"visa": 16, "mastercard": 16, "amex": 15, "jcb": 16}


def _luhn_check_digit(num_without_check: str) -> int:
    digits = [int(c) for c in num_without_check][::-1]
    total = 0
    for i, d in enumerate(digits):
        if i % 2 == 0:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return (10 - (total % 10)) % 10


def _make_card(brand: str, valid_luhn: bool) -> str:
    brand = brand.lower()
    length = _CARD_LEN[brand]
    bin_prefix = secrets.choice(_TEST_BINS[brand])
    body = "".join(str(secrets.randbelow(10)) for _ in range(length - len(bin_prefix) - 1))
    base = bin_prefix + body
    check = _luhn_check_digit(base)
    if not valid_luhn:
        check = (check + 1) % 10
    return base + str(check)


# ============================================================================
#  Record assembly
# ============================================================================
def _token() -> str:
    return secrets.token_hex(3)


def _fake_password_hash(token: str) -> str:
    return hashlib.sha256(f"stille:{token}:{secrets.token_hex(8)}".encode()).hexdigest()


def _weighted_choice(options, weights):
    r = secrets.randbelow(sum(weights))
    upto = 0
    for opt, w in zip(options, weights):
        upto += w
        if r < upto:
            return opt
    return options[-1]


def _rand_date(start_days_ago: int, end_days_ago: int) -> datetime:
    span = max(start_days_ago - end_days_ago, 1)
    return datetime.now(timezone.utc) - timedelta(days=end_days_ago + secrets.randbelow(span))


def _build_userid(first: str, last: str, token: str) -> str:
    style = secrets.randbelow(4)
    if style == 0:
        base = f"{first}.{last}"
    elif style == 1:
        base = f"{first}{last}"
    elif style == 2:
        base = f"{first[0]}{last}"
    else:
        base = f"{last}_{first}"
    return f"{base}{token[:4]}"


@dataclass
class CanaryRecord:
    record_id: str
    user_id: str
    full_name: str
    email: str
    password_hash: str
    phone: str
    birthdate: str
    address: str
    locale: str
    card_brand: str
    card_number: str
    card_expiry: str
    member_rank: str
    points: int
    status: str
    registered_at: str
    last_login: str
    _canary: bool = True
    _seed_tag: str = ""
    _detect: str = "search"


def _pick_domain(self_domain, self_ratio, freemail):
    if self_domain and secrets.randbelow(1000) < int(self_ratio * 1000):
        return self_domain, "inbox"
    return _weighted_choice([d for d, _ in freemail], [w for _, w in freemail]), "search"


def make_record(prof: LocaleProfile, seed_tag, brand, valid_luhn,
                self_domain, self_ratio) -> CanaryRecord:
    token = _token()
    full_name, rfirst, rlast = prof.name_fn()
    user_id = _build_userid(rfirst, rlast, token)
    domain, detect = _pick_domain(self_domain, self_ratio, prof.freemail)
    email = f"{rfirst}.{rlast}.{token}@{domain}"

    age_days = (20 * 365) + secrets.randbelow((75 - 20) * 365)
    birth = datetime.now() - timedelta(days=age_days)
    reg = _rand_date(365 * 3, 60)
    last = _rand_date(60, 0)
    exp_year = datetime.now().year + secrets.randbelow(4) + 1

    return CanaryRecord(
        record_id=token,
        user_id=user_id,
        full_name=full_name,
        email=email,
        password_hash=_fake_password_hash(token),
        phone=prof.phone_fn(),
        birthdate=birth.strftime("%Y-%m-%d"),
        address=prof.address_fn(),
        locale=prof.code,
        card_brand=brand,
        card_number=_make_card(brand, valid_luhn),
        card_expiry=f"{secrets.randbelow(12)+1:02d}/{str(exp_year)[2:]}",
        member_rank=_weighted_choice(_RANKS, _RANK_WEIGHTS),
        points=secrets.randbelow(50000),
        status=secrets.choice(_STATUS),
        registered_at=reg.strftime("%Y-%m-%d"),
        last_login=last.strftime("%Y-%m-%dT%H:%M:%S%z"),
        _seed_tag=seed_tag,
        _detect=detect,
    )


def generate(count, prof, seed_tag, brand, valid_luhn,
             self_domain, self_ratio) -> Iterator[CanaryRecord]:
    for _ in range(count):
        b = secrets.choice(["visa", "mastercard", "amex", "jcb"]) if brand == "mixed" else brand
        yield make_record(prof, seed_tag, b, valid_luhn, self_domain, self_ratio)


# ============================================================================
#  Output
# ============================================================================
def _seeded_view(rec: CanaryRecord) -> dict:
    d = asdict(rec)
    for k in ("_canary", "_seed_tag", "_detect"):
        d.pop(k, None)
    return d


def _ledger_row(rec: CanaryRecord) -> dict:
    return {
        "record_id": rec.record_id, "seed_tag": rec._seed_tag,
        "detect": rec._detect, "locale": rec.locale, "email": rec.email,
        "user_id": rec.user_id, "password_hash": rec.password_hash,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


def write_jsonl(records, sf, lf):
    for rec in records:
        sf.write(json.dumps(_seeded_view(rec), ensure_ascii=False) + "\n")
        lf.write(json.dumps(_ledger_row(rec), ensure_ascii=False) + "\n")


def write_csv(records, sf, lf):
    records = list(records)
    if not records:
        return
    sw = csv.DictWriter(sf, fieldnames=list(_seeded_view(records[0]).keys()))
    sw.writeheader()
    lw = csv.DictWriter(lf, fieldnames=list(_ledger_row(records[0]).keys()))
    lw.writeheader()
    for rec in records:
        sw.writerow(_seeded_view(rec))
        lw.writerow(_ledger_row(rec))


def main(argv=None):
    p = argparse.ArgumentParser(
        description="Generate leak-canary user records (stille-hunter).")
    p.add_argument("--count", type=int, default=10)
    p.add_argument("--locale", default="jp", choices=sorted(_LOCALES.keys()),
                   help="Regional profile: name, address, phone and domain mix.")
    p.add_argument("--self-domain",
                   help="A domain you control (catch-all). Records on it get detect=inbox.")
    p.add_argument("--self-ratio", type=float, default=0.4)
    p.add_argument("--tag", default="default")
    p.add_argument("--brand", default="mixed",
                   choices=["mixed", "visa", "mastercard", "amex", "jcb"])
    p.add_argument("--luhn", default="invalid", choices=["valid", "invalid"])
    p.add_argument("--format", default="jsonl", choices=["jsonl", "csv"])
    p.add_argument("--out", default="canary_seeded")
    args = p.parse_args(argv)

    if not 0.0 <= args.self_ratio <= 1.0:
        sys.stderr.write("ERROR: --self-ratio must be between 0 and 1\n")
        sys.exit(2)
    if args.self_domain:
        if not re.fullmatch(r"[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+", args.self_domain) \
                or any(t in args.self_domain.lower() for t in ("example", "yourdomain", "placeholder", "ドメイン")):
            sys.stderr.write(
                f"ERROR: --self-domain '{args.self_domain}' is not a real domain you "
                "control. Pass a domain whose mail you can receive, or omit it for "
                "free-mail-only (search-detect) canaries.\n")
            sys.exit(2)

    prof = _LOCALES[args.locale]
    ext = args.format
    seeded_path, ledger_path = f"{args.out}.{ext}", f"{args.out}.ledger.{ext}"

    recs = list(generate(args.count, prof, args.tag, args.brand,
                         args.luhn == "valid", args.self_domain, args.self_ratio))
    inbox_n = sum(1 for r in recs if r._detect == "inbox")

    with open(seeded_path, "w", encoding="utf-8", newline="") as sf, \
         open(ledger_path, "w", encoding="utf-8", newline="") as lf:
        (write_jsonl if ext == "jsonl" else write_csv)(recs, sf, lf)

    print(f"wrote {len(recs)} {args.locale} canary records "
          f"({inbox_n} inbox-detect, {len(recs)-inbox_n} search-only):")
    print(f"  seeded data : {seeded_path}  (plant this in your DB/export)")
    print(f"  ledger      : {ledger_path}")
    print("  !! The ledger is the token -> seed-location map. Move it OUT of this")
    print("     directory to private storage. NEVER commit it, and NEVER plant it")
    print("     anywhere a leak could expose it — it unmasks every canary at once.")
    if args.self_domain:
        print(f"  note: set a catch-all on {args.self_domain} so inbox-detect works.")


if __name__ == "__main__":
    main()
