"""Received hop parsing and analyzer tests."""

from __future__ import annotations

from pathlib import Path

from mailshieldv1 import analyze, to_html

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "samples" / "phishing" / "hops_chain.eml"


def test_hops_newest_first() -> None:
    report = analyze(SAMPLE.read_bytes())
    assert len(report.hops) == 3
    assert report.hops[0]["index"] == 0
    assert "mailbox.acme.example" in report.hops[0]["by_host"]
    assert report.hops[-1]["index"] == 2
    assert "forged-internal" in report.hops[-1]["from_host"]
    rules = {f.rule_id for f in report.findings}
    assert "HOP-MAP" in rules
    hop_map = next(f for f in report.findings if f.rule_id == "HOP-MAP")
    assert "last_by=" in hop_map.evidence
    assert "claimed_origin=" in hop_map.evidence


def test_hops_html_practical_and_collapsible() -> None:
    page = to_html(analyze(SAMPLE.read_bytes()))
    assert "Received path" in page
    assert "Last hop (trust this first)" in page
    assert "First seen sending host" in page
    assert "Check first:" in page
    assert "<details class=\"section\"" in page
    assert "Raw Received lines" in page
    assert "mailbox.acme.example" in page
    # Path must include the oldest from= host, not drop it via by=-only logic.
    marker = 'class="hop-path">'
    assert marker in page
    path_snip = page[page.index(marker) : page.index(marker) + 220]
    assert "forged-internal.victim.example" in path_snip


def test_path_keeps_external_from_host() -> None:
    from mailshieldv1.report.html_report import _path_nodes

    hops = [
        {
            "index": 0,
            "from_host": "mx.example",
            "by_host": "mailbox.example",
            "with_protocol": "esmtp",
            "raw": "",
        },
        {
            "index": 1,
            "from_host": "smtp-out.evil.example",
            "by_host": "mx.example",
            "with_protocol": "esmtp",
            "raw": "",
        },
    ]
    nodes = _path_nodes(hops)
    assert nodes[0] == "smtp-out.evil.example"
    assert nodes[-1] == "mailbox.example"


def test_no_received_finding() -> None:
    raw = b"From: a@example.com\r\nSubject: x\r\n\r\nbody\r\n"
    report = analyze(raw)
    assert report.hops == []
    assert any(f.rule_id == "HOP-NONE" for f in report.findings)
