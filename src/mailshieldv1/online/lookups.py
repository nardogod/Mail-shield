"""Optional online enrichments. Off by default. Requires network + dnspython."""

from __future__ import annotations

import concurrent.futures
from typing import Any

from mailshieldv1.core.domains import IGNORE_URL_DOMAINS, is_esp

# Fallback when the OS resolver is slow/blocked for TXT (common on corp DNS).
_PUBLIC_NS = ["1.1.1.1", "8.8.8.8"]


def _resolver(timeout: float, nameservers: list[str] | None = None) -> Any:
    try:
        import dns.resolver  # type: ignore
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "Online mode needs dnspython. Install: pip install 'mailshieldv1[online]'"
        ) from exc

    resolver = dns.resolver.Resolver(configure=nameservers is None)
    resolver.lifetime = timeout
    resolver.timeout = max(2.0, min(timeout, timeout / 2 if timeout >= 4 else timeout))
    if nameservers:
        resolver.nameservers = list(nameservers)
    return resolver


def _dns_txt(name: str, timeout: float = 8.0) -> list[str]:
    last_exc: Exception | None = None
    # 1) OS resolver  2) public DNS fallback on timeout / SERVFAIL-ish failures
    for nameservers in (None, _PUBLIC_NS):
        try:
            resolver = _resolver(timeout, nameservers)
            answer = resolver.resolve(name, "TXT")
            out: list[str] = []
            for rdata in answer:
                text = b"".join(rdata.strings).decode("utf-8", errors="replace")
                out.append(text)
            return out
        except RuntimeError:
            raise
        except Exception as exc:  # noqa: BLE001 — DNS errors are expected
            last_exc = exc
            # Only fall back on timeout / no-answer style problems.
            if type(exc).__name__ in {"NXDOMAIN", "YXDOMAIN"}:
                return [f"error:{type(exc).__name__}"]
            if type(exc).__name__ not in {
                "LifetimeTimeout",
                "Timeout",
                "NoNameservers",
                "NoAnswer",
            }:
                return [f"error:{type(exc).__name__}"]
            continue
    name = type(last_exc).__name__ if last_exc else "DNSError"
    return [f"error:{name}"]


def _spf_records(txts: list[str]) -> list[str]:
    """Keep SPF policy rows; fall back to raw TXT when none match."""
    spf = [t for t in txts if t.lower().startswith("v=spf1")]
    if spf:
        return spf
    return txts


def _dmarc_records(txts: list[str]) -> list[str]:
    dmarc = [t for t in txts if "v=dmarc1" in t.lower()]
    if dmarc:
        return dmarc
    return txts


def _resolve_host(host: str, timeout: float = 8.0) -> dict[str, Any]:
    """Resolve A/AAAA without mutating process-wide socket defaults."""
    if not host:
        return {"host": host, "ok": False, "error": "empty"}

    import socket

    def _lookup() -> list[tuple]:
        return socket.getaddrinfo(host, None)

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            infos = pool.submit(_lookup).result(timeout=timeout)
        addrs = sorted({i[4][0] for i in infos})
        return {"host": host, "ok": True, "addresses": addrs[:10]}
    except concurrent.futures.TimeoutError:
        return {"host": host, "ok": False, "error": "timeout"}
    except OSError as exc:
        return {"host": host, "ok": False, "error": str(exc)}


def _worth_resolving(domain: str) -> bool:
    d = (domain or "").lower()
    if not d or d in IGNORE_URL_DOMAINS or is_esp(d):
        return False
    return True


def enrich_online(
    *,
    from_domain: str,
    url_domains: list[str],
    timeout: float = 8.0,
) -> dict[str, Any]:
    """Live DNS TXT for SPF/DMARC + A/AAAA resolution. No HTTP fetches."""
    result: dict[str, Any] = {
        "enabled": True,
        "from_domain": from_domain,
        "spf_txt": [],
        "dmarc_txt": [],
        "resolutions": [],
        "notes": [
            "Online checks are live DNS lookups only (no URL fetching).",
            "TXT presence is not a full SPF/DKIM cryptographic validation.",
            f"DNS timeout budget per query: {timeout:.0f}s "
            "(retries via 1.1.1.1/8.8.8.8 if the OS resolver times out on TXT).",
        ],
    }
    if from_domain:
        raw_spf = _dns_txt(from_domain, timeout=timeout)
        raw_dmarc = _dns_txt(f"_dmarc.{from_domain}", timeout=timeout)
        result["spf_txt"] = _spf_records(raw_spf)
        result["dmarc_txt"] = _dmarc_records(raw_dmarc)
        result["resolutions"].append(_resolve_host(from_domain, timeout=timeout))
    for domain in url_domains[:8]:
        if domain and domain != from_domain and _worth_resolving(domain):
            result["resolutions"].append(_resolve_host(domain, timeout=timeout))
    return result
