# SPDX-License-Identifier: Apache-2.0
"""Canary type: member — a fake but realistic member/user account record.

A full profile (name, address, phone, card, password hash, ...) built to look
like one row in a real customer database, so an attacker who exfiltrates the DB
believes it. The unique token is woven into email, user_id and password_hash.

Locales are regional profiles: --locale picks a bundle of name pool, address
generator, phone format and free-mail domain weights, so a US record looks US
all the way through. Add a country by adding one LocaleProfile.

Safety: test-BIN card numbers with an invalid Luhn by default (never charge,
never collide with a live card), no CVV, no national IDs, adults only (20-75).
"""
from __future__ import annotations

import argparse
import hashlib
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable, Iterable

from ..generate import CanaryType, new_token, register_type, weighted_choice

# --self-domain must look like a real domain and not a docs placeholder.
_DOMAIN_RE = (r"[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?"
              r"(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+")
_PLACEHOLDER_HINTS = ("example", "yourdomain", "placeholder", "ドメイン")

# ============================================================================
#  Name / place data per locale
# ============================================================================
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

_GB_CITIES = [
    ("London", ["SW", "SE", "NW", "N", "E", "W", "EC", "WC"]),
    ("Manchester", ["M"]), ("Birmingham", ["B"]), ("Leeds", ["LS"]),
    ("Glasgow", ["G"]), ("Liverpool", ["L"]), ("Bristol", ["BS"]),
    ("Sheffield", ["S"]), ("Edinburgh", ["EH"]), ("Cardiff", ["CF"]),
    ("Nottingham", ["NG"]), ("Newcastle", ["NE"]), ("Brighton", ["BN"]),
    ("Leicester", ["LE"]),
]
_GB_STREETS = ["High St", "Station Rd", "Church Ln", "Victoria Rd",
               "Kings Rd", "Queens Rd", "Mill Ln", "Park Rd", "York Rd"]

# --- Canada -----------------------------------------------------------------
# (city, province, [forward-sortation-area first letters valid for it]) so the
# postal code's first letter matches the province, like real Canadian codes.
_CA_CITIES = [
    ("Toronto", "ON", "M"), ("Ottawa", "ON", "K"), ("Mississauga", "ON", "L"),
    ("Montreal", "QC", "H"), ("Quebec City", "QC", "G"),
    ("Vancouver", "BC", "V"), ("Victoria", "BC", "V"),
    ("Calgary", "AB", "T"), ("Edmonton", "AB", "T"),
    ("Winnipeg", "MB", "R"), ("Halifax", "NS", "B"),
    ("Saskatoon", "SK", "S"), ("Regina", "SK", "S"),
]
_CA_STREETS = ["Main St", "King St", "Queen St", "Bay St", "Yonge St",
               "Maple Ave", "Oak St", "Cedar Rd", "Lakeshore Blvd"]

# --- Germany ----------------------------------------------------------------
# (display form, ASCII form for email / user id). Umlauts and ß are spelled out
# the way Germans do in addresses (ä->ae, ö->oe, ü->ue, ß->ss).
_DE_FIRST = [
    ("Lukas", "lukas"), ("Leon", "leon"), ("Finn", "finn"), ("Jonas", "jonas"),
    ("Paul", "paul"), ("Felix", "felix"), ("Maximilian", "maximilian"),
    ("Tobias", "tobias"), ("Stefan", "stefan"), ("Thomas", "thomas"),
    ("Michael", "michael"), ("Andreas", "andreas"), ("Jürgen", "juergen"),
    ("Sebastian", "sebastian"), ("Florian", "florian"), ("Niklas", "niklas"),
    ("Mia", "mia"), ("Emma", "emma"), ("Hannah", "hannah"), ("Sophia", "sophia"),
    ("Lena", "lena"), ("Anna", "anna"), ("Laura", "laura"), ("Julia", "julia"),
    ("Katrin", "katrin"), ("Sabine", "sabine"), ("Claudia", "claudia"),
    ("Jana", "jana"), ("Lea", "lea"), ("Marie", "marie"), ("Sarah", "sarah"),
    ("Jörg", "joerg"),
]
_DE_LAST = [
    ("Müller", "mueller"), ("Schmidt", "schmidt"), ("Schneider", "schneider"),
    ("Fischer", "fischer"), ("Weber", "weber"), ("Meyer", "meyer"),
    ("Wagner", "wagner"), ("Becker", "becker"), ("Schulz", "schulz"),
    ("Hoffmann", "hoffmann"), ("Schäfer", "schaefer"), ("Koch", "koch"),
    ("Bauer", "bauer"), ("Richter", "richter"), ("Klein", "klein"),
    ("Wolf", "wolf"), ("Schröder", "schroeder"), ("Neumann", "neumann"),
    ("Schwarz", "schwarz"), ("Zimmermann", "zimmermann"), ("Braun", "braun"),
    ("Krüger", "krueger"), ("Hofmann", "hofmann"), ("Hartmann", "hartmann"),
    ("Lange", "lange"), ("Schmitt", "schmitt"), ("Werner", "werner"),
    ("Krause", "krause"), ("Meier", "meier"), ("Lehmann", "lehmann"),
    ("Groß", "gross"), ("Köhler", "koehler"),
]
# (city, [first two digits of its postcodes]) so the PLZ fits the city.
_DE_CITIES = [
    ("Berlin", ["10", "12", "13"]), ("Hamburg", ["20", "21", "22"]),
    ("München", ["80", "81"]), ("Köln", ["50", "51"]),
    ("Frankfurt am Main", ["60"]), ("Stuttgart", ["70"]),
    ("Düsseldorf", ["40"]), ("Leipzig", ["04"]), ("Dortmund", ["44"]),
    ("Essen", ["45"]), ("Bremen", ["28"]), ("Dresden", ["01"]),
    ("Hannover", ["30"]), ("Nürnberg", ["90"]),
]
_DE_STREETS = ["Hauptstraße", "Bahnhofstraße", "Schulstraße", "Gartenstraße",
               "Dorfstraße", "Bergstraße", "Lindenstraße", "Kirchstraße",
               "Goethestraße", "Schillerstraße", "Am Markt", "Waldweg"]

# --- Taiwan -----------------------------------------------------------------
# (characters, romanization as on Taiwanese passports, without the hyphen).
# Names are written without a space: 陳志明.
_TW_SURNAME = [
    ("陳", "chen"), ("林", "lin"), ("黃", "huang"), ("張", "chang"), ("李", "li"),
    ("王", "wang"), ("吳", "wu"), ("劉", "liu"), ("蔡", "tsai"), ("楊", "yang"),
    ("許", "hsu"), ("鄭", "cheng"), ("謝", "hsieh"), ("郭", "kuo"), ("洪", "hung"),
    ("曾", "tseng"), ("邱", "chiu"), ("廖", "liao"), ("賴", "lai"), ("周", "chou"),
]
_TW_GIVEN = [
    ("志明", "chihming"), ("家豪", "chiahao"), ("俊傑", "chunchieh"), ("冠宇", "kuanyu"),
    ("宗翰", "tsunghan"), ("承恩", "chengen"), ("建宏", "chienhung"), ("志偉", "chihwei"),
    ("柏翰", "pohan"), ("彥廷", "yenting"), ("怡君", "yichun"), ("雅婷", "yating"),
    ("佩珊", "peishan"), ("淑芬", "shufen"), ("美玲", "meiling"), ("欣怡", "hsinyi"),
    ("詩涵", "shihhan"), ("宜蓁", "yichen"), ("思妤", "ssuyu"), ("雅雯", "yawen"),
]
# (city, district, 3-digit postal code of that district)
_TW_DISTRICTS = [
    ("台北市", "中正區", "100"), ("台北市", "中山區", "104"), ("台北市", "大安區", "106"),
    ("台北市", "信義區", "110"), ("台北市", "內湖區", "114"), ("新北市", "板橋區", "220"),
    ("新北市", "新店區", "231"), ("基隆市", "仁愛區", "200"), ("新竹市", "東區", "300"),
    ("桃園市", "桃園區", "330"), ("台中市", "北區", "404"), ("台中市", "西屯區", "407"),
    ("台南市", "東區", "701"), ("高雄市", "苓雅區", "802"), ("高雄市", "前鎮區", "806"),
]
_TW_ROADS = ["中山路", "中正路", "民生路", "復興路", "光復路", "建國路", "和平路",
             "自由路", "民權路", "成功路"]
_TW_SECTIONS = ["", "", "一段", "二段", "三段"]

_RANKS = ["bronze", "silver", "gold", "platinum"]
_RANK_WEIGHTS = [50, 30, 15, 5]
_STATUS = ["active", "active", "active", "suspended", "dormant"]

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
_FREEMAIL_CA = [
    ("gmail.com", 44), ("yahoo.ca", 12), ("icloud.com", 12),
    ("outlook.com", 8), ("hotmail.com", 8), ("hotmail.ca", 4),
    ("live.ca", 3), ("shaw.ca", 3), ("rogers.com", 3), ("bell.net", 3),
]
_FREEMAIL_TW = [
    ("gmail.com", 50), ("yahoo.com.tw", 18), ("hotmail.com", 9), ("outlook.com", 6),
    ("icloud.com", 6), ("msa.hinet.net", 6), ("pchome.com.tw", 3),
]
_FREEMAIL_DE = [
    ("gmail.com", 30), ("web.de", 18), ("gmx.de", 16), ("gmx.net", 6),
    ("t-online.de", 10), ("outlook.de", 4), ("hotmail.de", 3),
    ("yahoo.de", 4), ("icloud.com", 5), ("freenet.de", 2), ("posteo.de", 2),
]


# ============================================================================
#  Locale profiles
# ============================================================================
def _jp_name():
    sei_k, sei_r = secrets.choice(_JP_SEI)
    mei_k, mei_r = secrets.choice(_JP_MEI_M if secrets.randbelow(2) else _JP_MEI_F)
    return f"{sei_k} {mei_k}", mei_r, sei_r

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
    return f"{num} {secrets.choice(_US_STREETS)}, {city}, {state} {secrets.randbelow(90000)+10000}"

def _gb_address():
    city, areas = secrets.choice(_GB_CITIES)
    num = secrets.randbelow(250) + 1
    area = secrets.choice(areas)
    pc = (f"{area}{secrets.randbelow(20)+1} {secrets.randbelow(9)+1}"
          f"{secrets.choice('ABDEFGHJLNPQRSTUWXYZ')}{secrets.choice('ABDEFGHJLNPQRSTUWXYZ')}")
    return f"{num} {secrets.choice(_GB_STREETS)}, {city} {pc}"

def _ca_address():
    city, prov, fsa_letter = secrets.choice(_CA_CITIES)
    num = secrets.randbelow(9900) + 100
    # Canadian postal code: A1A 1A1, first letter tied to the province.
    letters = "ABCEGHJKLMNPRSTVWXYZ"
    pc = (f"{fsa_letter}{secrets.randbelow(10)}{secrets.choice(letters)} "
          f"{secrets.randbelow(10)}{secrets.choice(letters)}{secrets.randbelow(10)}")
    return f"{num} {secrets.choice(_CA_STREETS)}, {city}, {prov} {pc}"

def _de_name():
    first, rfirst = secrets.choice(_DE_FIRST)
    last, rlast = secrets.choice(_DE_LAST)
    return f"{first} {last}", rfirst, rlast

def _de_address():
    city, prefixes = secrets.choice(_DE_CITIES)
    plz = f"{secrets.choice(prefixes)}{secrets.randbelow(1000):03d}"
    return f"{secrets.choice(_DE_STREETS)} {secrets.randbelow(150)+1}, {plz} {city}"

def _tw_name():
    sur, rsur = secrets.choice(_TW_SURNAME)
    given, rgiven = secrets.choice(_TW_GIVEN)
    return f"{sur}{given}", rgiven, rsur

def _tw_address():
    city, district, postal = secrets.choice(_TW_DISTRICTS)
    floor = f"{secrets.randbelow(12) + 2}樓" if secrets.randbelow(2) else ""
    return (f"{postal}{city}{district}{secrets.choice(_TW_ROADS)}"
            f"{secrets.choice(_TW_SECTIONS)}{secrets.randbelow(300) + 1}號{floor}")

def _tw_phone():
    """Taiwanese mobile: 09xx-xxx-xxx."""
    return (f"09{secrets.randbelow(100):02d}-{secrets.randbelow(900) + 100}-"
            f"{secrets.randbelow(900) + 100}")

def _jp_phone():
    return f"080-{secrets.randbelow(9000)+1000}-{secrets.randbelow(9000)+1000}"

def _nanp_phone():
    """North American Numbering Plan number (shared by US and Canada)."""
    area = secrets.randbelow(800) + 200
    exchange = secrets.randbelow(900) + 100
    line = secrets.randbelow(9000) + 1000
    return f"+1 ({area}) {exchange}-{line}"

def _us_phone():
    return _nanp_phone()

def _gb_phone():
    return f"+44 7{secrets.randbelow(900)+100} {secrets.randbelow(900000)+100000}"

def _ca_phone():
    return _nanp_phone()

def _de_phone():
    """German mobile: +49 15x / 16x / 17x and a 7-8 digit subscriber number."""
    prefix = secrets.choice(["151", "152", "157", "160", "162", "170", "171",
                             "172", "175", "176", "177", "179"])
    digits = 8 if prefix.startswith("15") else 7
    return f"+49 {prefix} {secrets.randbelow(9 * 10**(digits-1)) + 10**(digits-1)}"


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
    "ca": LocaleProfile("ca", _en_name, _ca_address, _ca_phone, _FREEMAIL_CA),
    "de": LocaleProfile("de", _de_name, _de_address, _de_phone, _FREEMAIL_DE),
    "tw": LocaleProfile("tw", _tw_name, _tw_address, _tw_phone, _FREEMAIL_TW),
}
#: other spellings accepted by --locale
LOCALE_ALIASES = {"zh-TW": "tw", "zh-tw": "tw"}


def locale_choices() -> list[str]:
    return sorted(_LOCALES) + sorted(k for k in LOCALE_ALIASES if k != "zh-tw")


def resolve_locale(code: str) -> LocaleProfile:
    return _LOCALES[LOCALE_ALIASES.get(code, code)]

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


def _fake_password_hash(token: str) -> str:
    return hashlib.sha256(f"stille:{token}:{secrets.token_hex(8)}".encode()).hexdigest()


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


# ============================================================================
#  The canary type
# ============================================================================
@register_type
class MemberType(CanaryType):
    name = "member"
    description = "Fake customer/member account record (name, address, card, ...)."

    def add_arguments(self, p: argparse.ArgumentParser) -> None:
        p.add_argument("--locale", default="jp", choices=locale_choices(),
                       help="Regional profile: name, address, phone and domain mix "
                            "(zh-TW is the same as tw).")
        p.add_argument("--self-domain",
                       help="A domain you control (catch-all). Records on it get detect=inbox.")
        p.add_argument("--self-ratio", type=float, default=0.4)
        p.add_argument("--brand", default="mixed",
                       choices=["mixed", "visa", "mastercard", "amex", "jcb"])
        p.add_argument("--luhn", default="invalid", choices=["valid", "invalid"])

    def generate(self, args, count: int) -> Iterable[dict]:
        if not 0.0 <= args.self_ratio <= 1.0:
            raise ValueError("--self-ratio must be between 0 and 1")
        if args.self_domain:
            looks_real = re.fullmatch(_DOMAIN_RE, args.self_domain)
            is_placeholder = any(t in args.self_domain.lower() for t in _PLACEHOLDER_HINTS)
            if not looks_real or is_placeholder:
                raise ValueError(
                    f"--self-domain '{args.self_domain}' is not a real domain you "
                    "control. Pass a domain whose mail you can receive, or omit it "
                    "for free-mail-only (search-detect) canaries.")

        prof = resolve_locale(args.locale)
        for _ in range(count):
            brand = (secrets.choice(["visa", "mastercard", "amex", "jcb"])
                     if args.brand == "mixed" else args.brand)
            yield self._one(prof, brand, args.luhn == "valid",
                            args.self_domain, args.self_ratio)

    def _one(self, prof, brand, valid_luhn, self_domain, self_ratio) -> dict:
        token = new_token()
        full_name, rfirst, rlast = prof.name_fn()
        user_id = _build_userid(rfirst, rlast, token)

        if self_domain and secrets.randbelow(1000) < int(self_ratio * 1000):
            domain, detect = self_domain, "inbox"
        else:
            domain = weighted_choice([d for d, _ in prof.freemail],
                                     [w for _, w in prof.freemail])
            detect = "search"
        email = f"{rfirst}.{rlast}.{token}@{domain}"

        age_days = (20 * 365) + secrets.randbelow((75 - 20) * 365)
        birth = datetime.now() - timedelta(days=age_days)
        reg = _rand_date(365 * 3, 60)
        last = _rand_date(60, 0)
        exp_year = datetime.now().year + secrets.randbelow(4) + 1
        pw_hash = _fake_password_hash(token)

        return {
            # plantable fields (seeded output)
            "record_id": token,
            "user_id": user_id,
            "full_name": full_name,
            "email": email,
            "password_hash": pw_hash,
            "phone": prof.phone_fn(),
            "birthdate": birth.strftime("%Y-%m-%d"),
            "address": prof.address_fn(),
            "locale": prof.code,
            "card_brand": brand,
            "card_number": _make_card(brand, valid_luhn),
            "card_expiry": f"{secrets.randbelow(12)+1:02d}/{str(exp_year)[2:]}",
            "member_rank": weighted_choice(_RANKS, _RANK_WEIGHTS),
            "points": secrets.randbelow(50000),
            "status": secrets.choice(_STATUS),
            "registered_at": reg.strftime("%Y-%m-%d"),
            "last_login": last.strftime("%Y-%m-%dT%H:%M:%S%z"),
            # engine bookkeeping
            "_detect": detect,
            "_ledger": {
                "locale": prof.code,
                "email": email,
                "user_id": user_id,
                "password_hash": pw_hash,
            },
        }
