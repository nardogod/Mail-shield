"""Analyst pivot link tests."""

from __future__ import annotations

from mailshieldv1 import analyze, to_html
from mailshieldv1.report.pivots import build_pivots, host_of


def test_host_of() -> None:
    assert host_of("https://WWW.Evil.Example/path") == "evil.example"


def test_pivots_dedupe_by_host() -> None:
    urls = [
        "https://track.example/a",
        "https://track.example/b",
        "https://track.example/c",
        "https://cdn.example/x.png",
    ]
    groups = build_pivots("Alice <a@brand.example>", urls)
    titles = [g.title for g in groups]
    assert titles == ["Message / sender domain", "Host", "Host"]
    hosts = [g.target for g in groups if g.title == "Host"]
    assert hosts == ["track.example", "cdn.example"]
    track = next(g for g in groups if g.target == "track.example")
    labels = [x.label for x in track.links]
    assert labels == [
        "DomainTools WHOIS",
        "VirusTotal domain",
        "urlscan.io",
        "dnstwist.it",
        "PhishTank",
        "MXToolbox SuperTool",
    ]
    assert len(track.items) == 3
    assert track.item_links and track.item_links[0][0].label == "VirusTotal URL"


def test_shortener_gets_per_url_unshorten() -> None:
    groups = build_pivots("Alice <a@brand.example>", ["https://bit.ly/abc123"])
    bitly = next(g for g in groups if g.target == "bit.ly")
    assert bitly.emphasize_unshorten is True
    assert "DomainTools WHOIS" in [x.label for x in bitly.links]
    assert bitly.item_links and bitly.item_links[0][0].label == "Unshorten.it"
    assert "bit.ly" in bitly.item_links[0][0].url
    assert any(x.label == "VirusTotal URL" for x in bitly.item_links[0])


def test_html_contains_pivot_section() -> None:
    raw = (
        b"From: a@brand.example\r\n"
        b"Subject: hi\r\n"
        b"Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\r\n"
        b"\r\n"
        b"Click https://bit.ly/testhit and https://track.example/1 "
        b"https://track.example/2\r\n"
    )
    page = to_html(analyze(raw))
    assert "Analyst pivots" in page
    assert "Unshorten.it" in page
    assert 'rel="noopener noreferrer"' in page
    assert "whois.domaintools.com" in page
    assert page.count("DomainTools WHOIS") >= 2  # sender + hosts
    # track.example domain tools once, not once per URL path
    assert page.count("whois.domaintools.com/track.example") == 1
