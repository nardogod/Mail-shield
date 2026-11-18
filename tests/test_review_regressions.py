"""Regressions for review findings (socket timeout, lure cache reload)."""

from __future__ import annotations

import socket

from mailshieldv1.analyzers import content as content_mod
from mailshieldv1.core.knowledge_store import reload_knowledge
from mailshieldv1.online.lookups import _resolve_host


def test_resolve_host_does_not_mutate_default_socket_timeout() -> None:
    previous = socket.getdefaulttimeout()
    socket.setdefaulttimeout(12.0)
    try:
        _resolve_host("example.com", timeout=2.0)
        assert socket.getdefaulttimeout() == 12.0
    finally:
        socket.setdefaulttimeout(previous)


def test_reload_knowledge_clears_compiled_lures() -> None:
    first = content_mod._compiled()
    second = content_mod._compiled()
    assert first is second
    reload_knowledge()
    third = content_mod._compiled()
    assert third is not first
