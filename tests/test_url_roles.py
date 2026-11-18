"""URL role classification tests — pixels are kept, not dropped."""

from __future__ import annotations

from email.message import EmailMessage

from mailshieldv1 import analyze, to_html
from mailshieldv1.core.url_roles import classify_url


def test_tracking_pixel_classified_not_dropped() -> None:
    item = classify_url(
        "https://facilita.intevia.com.br/api/email/customer/tracking/abc",
        source="img",
    )
    assert item.role == "tracking_pixel"
    assert "analytics" in item.sender_purpose.lower() or "opened" in item.sender_purpose.lower()


def test_markup_namespace() -> None:
    item = classify_url("http://www.w3.org/1999/xhtml", source="body_text")
    assert item.role == "markup_namespace"


def test_report_groups_urls_in_html() -> None:
    msg = EmailMessage()
    msg["From"] = "a@example.com"
    msg["Subject"] = "x"
    msg.set_content(
        "<html xmlns='http://www.w3.org/1999/xhtml'><body>"
        "<img src='https://track.example/email/customer/tracking/1'/>"
        "<a href='https://pay.example/login'>Go</a>"
        "<a href='https://list.example/unsubscribe'>out</a>"
        "</body></html>",
        subtype="html",
    )
    report = analyze(msg.as_bytes())
    roles = {u["role"] for u in report.url_items}
    assert "tracking_pixel" in roles
    assert "cta_action" in roles
    assert "unsubscribe" in roles
    assert "markup_namespace" in roles
    # Nothing dropped relative to urls list
    assert len(report.url_items) == len(report.urls)
    page = to_html(report)
    assert "URLs by sender purpose" in page
    assert "Tracking / telemetry" in page
    assert "Call to action" in page
