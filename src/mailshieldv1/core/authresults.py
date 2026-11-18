"""Parse Authentication-Results / ARC-Authentication-Results (offline)."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from email.message import EmailMessage
from typing import Any

_RESULT_RE = re.compile(
    r"\b(spf|dkim|dmarc)=(pass|fail|softfail|neutral|none|temperror|permerror)\b",
    re.IGNORECASE,
)
_COMPAUTH_RE = re.compile(r"\bcompauth=(pass|fail|softpass|none)\b", re.IGNORECASE)
# authserv-id is the first token before ';' (RFC 8601).
_AUTHSERV_RE = re.compile(r"^\s*([^;\s]+)", re.IGNORECASE)


@dataclass
class AuthResults:
    spf: str = "missing"
    dkim: str = "missing"
    dmarc: str = "missing"
    compauth: str = "missing"
    raw: str = ""
    present: bool = False
    authserv_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def strong_pass(self) -> bool:
        """MTA-asserted pass signal strong enough to soften ESP marketing FPs."""
        if self.compauth == "fail":
            return False
        if self.dmarc == "pass":
            return True
        return self.spf == "pass" and self.dkim == "pass"

    @property
    def any_fail(self) -> bool:
        """Hard authentication failures (policy fail / permanent error)."""
        if self.compauth == "fail":
            return True
        return any(x in {"fail", "permerror"} for x in (self.spf, self.dkim, self.dmarc))

    @property
    def weak(self) -> bool:
        """Unauthenticated or unreliable auth — typical of forged phishing drops."""
        if self.any_fail:
            return True
        if self.dkim in {"none", "missing"} and self.spf in {
            "temperror",
            "none",
            "missing",
            "neutral",
            "softfail",
        }:
            return True
        if self.spf == "temperror" or self.dmarc == "temperror":
            return True
        if self.dkim == "none" and self.dmarc != "pass":
            return True
        return False


def _authserv_id(header: str) -> str:
    m = _AUTHSERV_RE.match(header.strip())
    return (m.group(1) if m else "").lower()


def _matches_authserv(header: str, expected: str) -> bool:
    got = _authserv_id(header)
    want = expected.lower().strip()
    if not want:
        return True
    return got == want or got.endswith("." + want) or want.endswith("." + got)


def _parse_blob(blob: str, *, authserv: str = "") -> AuthResults:
    found = {m.group(1).lower(): m.group(2).lower() for m in _RESULT_RE.finditer(blob)}
    comp = _COMPAUTH_RE.search(blob)
    return AuthResults(
        spf=found.get("spf", "missing"),
        dkim=found.get("dkim", "missing"),
        dmarc=found.get("dmarc", "missing"),
        compauth=(comp.group(1).lower() if comp else "missing"),
        raw=blob[:1000],
        present=True,
        authserv_id=authserv or _authserv_id(blob),
    )


def _pick_header(headers: list[str], authserv_id: str | None) -> str | None:
    """Prefer the topmost (first) header; optionally require matching authserv-id."""
    if not headers:
        return None
    if not authserv_id:
        return str(headers[0])
    for h in headers:
        if _matches_authserv(str(h), authserv_id):
            return str(h)
    return None


def parse_auth_results(
    msg: EmailMessage,
    *,
    authserv_id: str | None = None,
) -> AuthResults:
    """
    Parse auth results from the receiving MTA.

    Uses only the topmost ``Authentication-Results`` header (first in the message).
    ``ARC-Authentication-Results`` is a fallback when no AR header exists — never
    mixed with AR. When ``authserv_id`` is set, headers from other servers are ignored.
    """
    ar_headers = [str(h) for h in (msg.get_all("Authentication-Results") or [])]
    chosen = _pick_header(ar_headers, authserv_id)
    if chosen is not None:
        return _parse_blob(chosen, authserv=_authserv_id(chosen))

    # No usable Authentication-Results → ARC fallback only (do not merge with AR).
    if ar_headers and authserv_id:
        # AR present but none matched expected authserv-id → do not fall through to ARC
        # of a different trust domain; treat as missing.
        return AuthResults()

    arc_headers = [str(h) for h in (msg.get_all("ARC-Authentication-Results") or [])]
    chosen_arc = _pick_header(arc_headers, authserv_id)
    if chosen_arc is None:
        return AuthResults()
    return _parse_blob(chosen_arc, authserv=_authserv_id(chosen_arc))
