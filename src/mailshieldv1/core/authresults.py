"""Parse Authentication-Results / ARC-Authentication-Results (offline)."""

from __future__ import annotations

import os
import re
from contextvars import ContextVar
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

# Lower rank = worse (security: keep the worst result per mechanism).
_RESULT_RANK = {
    "fail": 0,
    "permerror": 1,
    "softfail": 2,
    "temperror": 3,
    "neutral": 4,
    "none": 5,
    "softpass": 6,
    "pass": 7,
    "missing": 8,
}

_AUTHSERV_CTX: ContextVar[str | None] = ContextVar("mailshield_authserv_id", default=None)


def resolve_authserv_id(explicit: str | None = None) -> str | None:
    """CLI/explicit wins, else MAILSHIELD_AUTHSERV_ID env, else None."""
    if explicit is not None and str(explicit).strip():
        return str(explicit).strip()
    env = os.environ.get("MAILSHIELD_AUTHSERV_ID", "").strip()
    return env or None


def current_authserv_id() -> str | None:
    """Authserv-id for this analyze() call (context) or process env."""
    ctx = _AUTHSERV_CTX.get()
    if ctx is not None and str(ctx).strip():
        return str(ctx).strip()
    return resolve_authserv_id(None)


def set_authserv_id(authserv_id: str | None):
    """Bind authserv-id for nested analyzers during ``analyze()``."""
    return _AUTHSERV_CTX.set(authserv_id)


def reset_authserv_id(token) -> None:
    _AUTHSERV_CTX.reset(token)


@dataclass
class AuthResults:
    spf: str = "missing"
    dkim: str = "missing"
    dmarc: str = "missing"
    compauth: str = "missing"
    raw: str = ""
    present: bool = False
    authserv_id: str = ""
    trusted: bool = False

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        # Properties used by SIEM / HTML — only meaningful when trusted.
        data["strong_pass"] = self.strong_pass
        data["any_fail"] = self.any_fail
        data["weak"] = self.weak
        return data

    @property
    def strong_pass(self) -> bool:
        """MTA-asserted pass — only when authserv-id was confirmed (trusted)."""
        if not self.trusted:
            return False
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
        """Unauthenticated or unreliable auth — typical of forged phishing drops.

        Untrusted Authentication-Results (no confirmed authserv-id) are treated as
        weak even when they claim pass — otherwise a forged attacker header would
        suppress weak-auth escalation and score *better* than no header at all.
        """
        if self.present and not self.trusted:
            return True
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


def _worse(a: str, b: str) -> str:
    return a if _RESULT_RANK.get(a, 99) <= _RESULT_RANK.get(b, 99) else b


def _authserv_id(header: str) -> str:
    m = _AUTHSERV_RE.match(header.strip())
    if not m:
        return ""
    tok = m.group(1).lower()
    # Outlook-style headers often start with "spf=pass" — not an authserv-id.
    if "=" in tok or tok in {"spf", "dkim", "dmarc", "compauth", "arc"}:
        return ""
    return tok


def _matches_authserv(header: str, expected: str) -> bool:
    got = _authserv_id(header)
    want = expected.lower().strip()
    if not want or not got:
        return False
    return got == want or got.endswith("." + want) or want.endswith("." + got)


def _parse_blob(blob: str, *, authserv: str = "", trusted: bool = False) -> AuthResults:
    found: dict[str, str] = {}
    for m in _RESULT_RE.finditer(blob):
        mech = m.group(1).lower()
        status = m.group(2).lower()
        prev = found.get(mech)
        found[mech] = status if prev is None else _worse(prev, status)

    compauth = "missing"
    for m in _COMPAUTH_RE.finditer(blob):
        status = m.group(1).lower()
        compauth = status if compauth == "missing" else _worse(compauth, status)

    return AuthResults(
        spf=found.get("spf", "missing"),
        dkim=found.get("dkim", "missing"),
        dmarc=found.get("dmarc", "missing"),
        compauth=compauth,
        raw=blob[:1000],
        present=True,
        authserv_id=authserv or _authserv_id(blob),
        trusted=trusted,
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
    mixed with AR.

    ``strong_pass`` (score softening) is True only when ``authserv_id`` is provided
    (argument, context, or ``MAILSHIELD_AUTHSERV_ID``) **and** matches the header.
    Without a confirmed authserv-id, pass results are still surfaced but never trusted
    for softening — a forged ``attacker; spf=pass…`` cannot zero the verdict.
    """
    expected = resolve_authserv_id(authserv_id)
    ar_headers = [str(h) for h in (msg.get_all("Authentication-Results") or [])]
    chosen = _pick_header(ar_headers, expected)
    if chosen is not None:
        # Trusted only when the operator named an authserv-id and it matched.
        trusted = bool(expected) and _matches_authserv(chosen, expected)
        return _parse_blob(chosen, authserv=_authserv_id(chosen), trusted=trusted)

    # No usable Authentication-Results → ARC fallback only (do not merge with AR).
    if ar_headers and expected:
        # AR present but none matched expected authserv-id → do not fall through to ARC.
        return AuthResults()

    arc_headers = [str(h) for h in (msg.get_all("ARC-Authentication-Results") or [])]
    chosen_arc = _pick_header(arc_headers, expected)
    if chosen_arc is None:
        return AuthResults()
    trusted = bool(expected) and _matches_authserv(chosen_arc, expected)
    return _parse_blob(chosen_arc, authserv=_authserv_id(chosen_arc), trusted=trusted)
