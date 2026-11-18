"""Ingest helpers: watched folders and IMAP pull → .eml → analyze."""

from mailshieldv1.ingest.pipeline import analyze_and_write, render_report

__all__ = ["analyze_and_write", "render_report"]
