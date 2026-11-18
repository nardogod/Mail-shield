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


@dataclass
class AuthResults:
    spf: str = "missing"
    dkim: str = "missing"
    dmarc: str = "missing"
    compauth: str = "missing"
    raw: str = ""
    present: bool = False

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


def parse_auth_results(msg: EmailMessage) -> AuthResults:
    headers: list[str] = []
    for name in ("Authentication-Results", "ARC-Authentication-Results"):
        headers.extend(msg.get_all(name, []) or [])
    if not headers:
        return AuthResults()
    blob = " ".join(str(h) for h in headers)
    found = {m.group(1).lower(): m.group(2).lower() for m in _RESULT_RE.finditer(blob)}
    comp = _COMPAUTH_RE.search(blob)
    return AuthResults(
        spf=found.get("spf", "missing"),
        dkim=found.get("dkim", "missing"),
        dmarc=found.get("dmarc", "missing"),
        compauth=(comp.group(1).lower() if comp else "missing"),
        raw=blob[:1000],
        present=True,
    )
