"""
Offline knowledge distilled from phishing_pot samples (sample-1..99).

Consumed by brands / headers / content / urls analyzers. No network I/O.
Patterns observed in the pot that previously under-scored (info/low):

- Free-mail From (gmail) + bank/tax display ([BB], IRPF) + PDF annex
- Crypto brand display (Binance, MetaMask, Coinbase, Kraken, CoinDesk, OKX)
  on unrelated domains
- Homoglyph / invisible Unicode in display names (Cyrillic lookalikes,
  variation selectors) to evade keyword filters
- Long display-name lures packing the full CTA into the From name
- BR tax-refund copy (crédito IR / IRPF / protocolo + anexo)
- Crypto withdraw / cancel-transaction pressure
- Consumer URL shorteners as sole CTA
- Tech-support brand abuse (Geek Squad) from free mail
- NL/EN romance / adult-dating CTA spam with campaign trackers
- Pot 99..500: FR energy/credit aides spam, casino bonuses, crypto airdrops,
  freemail invoice/PayPal, BB resgate without brackets, brand claims only in body,
  zero-width letter spacing obfuscation, advance-fee "OUR REF" letters
- Pot 501..2500: BB Informe/Ourocard freemail+PDF, Electrum/Trust/Phantom wallet
  update lures, OpenAI/Proton/Dropbox brand spoofs, ANTAI amende + CPF formation FR,
  DE casino Willkommensbonus, IMF-MoneyGram payout, doc-share/e-sign lures,
  From-display-only casino/brand signals, stricter crypto domain label matching
"""

from __future__ import annotations

import re
import unicodedata

# Consumer free-mail providers — brand claims from these are almost never legit.
FREE_MAIL_DOMAINS = frozenset(
    {
        "gmail.com",
        "googlemail.com",
        "hotmail.com",
        "outlook.com",
        "live.com",
        "msn.com",
        "yahoo.com",
        "yahoo.com.br",
        "ymail.com",
        "aol.com",
        "icloud.com",
        "me.com",
        "mac.com",
        "proton.me",
        "protonmail.com",
        "mail.com",
        "gmx.com",
        "gmx.net",
        "yandex.com",
        "yandex.ru",
        "zoho.com",
    }
)

URL_SHORTENERS = frozenset(
    {
        "bit.ly",
        "bitly.com",
        "t.co",
        "tinyurl.com",
        "shorturl.at",
        "goo.gl",
        "ow.ly",
        "rebrand.ly",
        "is.gd",
        "cutt.ly",
        "tiny.cc",
        "buff.ly",
        "rb.gy",
    }
)

# Confusable Latin ← Cyrillic / Greek used in crypto brand spoofs in the pot.
_HOMOGLYPH_MAP = str.maketrans(
    {
        "а": "a",  # Cyrillic
        "е": "e",
        "о": "o",
        "р": "p",
        "с": "c",
        "у": "y",
        "х": "x",
        "і": "i",
        "ї": "i",
        "ј": "j",
        "ѕ": "s",
        "һ": "h",
        "ԁ": "d",
        "ց": "g",
        "ո": "n",
        "κ": "k",  # Greek
        "ο": "o",
        "ρ": "p",
        "υ": "y",
        "χ": "x",
        "Α": "A",
        "В": "B",
        "Е": "E",
        "К": "K",
        "М": "M",
        "Н": "H",
        "О": "O",
        "Р": "P",
        "С": "C",
        "Т": "T",
        "Х": "X",
    }
)

_INVISIBLE_CATS = frozenset({"Cf", "Mn", "Me"})
_INVISIBLE_ORD = frozenset(
    {
        *range(0x200B, 0x200F + 1),
        *range(0x202A, 0x202E + 1),
        *range(0x2060, 0x206F + 1),
        *range(0xFE00, 0xFE0F + 1),
        *range(0xE0100, 0xE01EF + 1),
        0xFEFF,
        0x00AD,
        0x180E,
    }
)

_CYRILLIC = re.compile(r"[\u0400-\u04FF\u0500-\u052F]")
_LATIN = re.compile(r"[A-Za-z]")
_GREEK = re.compile(r"[\u0370-\u03FF]")


def is_free_mail(domain: str) -> bool:
    d = (domain or "").lower().strip()
    if not d:
        return False
    if d in FREE_MAIL_DOMAINS:
        return True
    return any(d.endswith("." + free) for free in FREE_MAIL_DOMAINS)


def is_url_shortener(host: str) -> bool:
    h = (host or "").lower().strip().strip(".")
    if not h:
        return False
    if h in URL_SHORTENERS:
        return True
    # subdomain of a shortener
    return any(h.endswith("." + s) for s in URL_SHORTENERS)


def strip_invisible(text: str) -> str:
    out: list[str] = []
    for ch in text or "":
        o = ord(ch)
        if o in _INVISIBLE_ORD:
            continue
        if unicodedata.category(ch) in _INVISIBLE_CATS and o > 127:
            continue
        out.append(ch)
    return "".join(out)


def normalize_for_match(text: str) -> str:
    """NFKC + drop invisibles + map common homoglyphs → ASCII-ish for token search."""
    if not text:
        return ""
    t = unicodedata.normalize("NFKC", text)
    t = strip_invisible(t)
    t = t.translate(_HOMOGLYPH_MAP)
    return t


def has_invisible_unicode(text: str) -> bool:
    for ch in text or "":
        o = ord(ch)
        if o in _INVISIBLE_ORD:
            return True
        # Variation selectors / tag characters often abused in pot display names.
        if 0xE0000 <= o <= 0xE007F:
            return True
    return False


def has_mixed_script_homoglyph(text: str) -> bool:
    """Latin letters mixed with Cyrillic/Greek in the same display/subject string."""
    if not text:
        return False
    cleaned = strip_invisible(text)
    has_latin = bool(_LATIN.search(cleaned))
    has_cyr = bool(_CYRILLIC.search(cleaned))
    has_greek = bool(_GREEK.search(cleaned))
    return has_latin and (has_cyr or has_greek)


_ZWSP_SPACED = re.compile(
    r"(?:[A-Za-zÀ-ÿ][\u200b\u200c\u200d\ufeff\u00ad]){5,}"
)


def has_zwsp_letter_spacing(text: str) -> bool:
    """True when letters are broken up with zero-width chars (filter evasion)."""
    if not text:
        return False
    return bool(_ZWSP_SPACED.search(text))
