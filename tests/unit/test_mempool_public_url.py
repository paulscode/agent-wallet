# SPDX-License-Identifier: MIT
"""The dashboard's user-facing mempool link resolver.

Links must point at a URL the user's browser can follow — never an
orchestrator-internal backend host such as ``mempool-rdts.embassy``.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from app.core.config import settings
from app.dashboard.routes import _resolve_mempool_public_url


def _resolve(public: str, server: str) -> str:
    with (
        patch.object(settings, "mempool_public_url", public),
        patch.object(settings, "lnd_mempool_url", server),
    ):
        return _resolve_mempool_public_url()


@pytest.mark.parametrize(
    "server_url",
    [
        "http://mempool-rdts.embassy:8999",  # StartOS 0.3.x internal hostname
        "http://mempool.startos:8999",  # StartOS 0.4.x internal hostname
        "http://mempool:8080",  # docker-compose service name (dot-less)
        "http://127.0.0.1:8999",  # loopback
        "http://localhost:8999",
        "http://deadbeef.onion",  # needs Tor; not a normal-browser link
    ],
)
def test_internal_or_unreachable_backend_falls_back_to_public(server_url: str) -> None:
    # When the configured backend is not browser-reachable and no explicit
    # public URL is set, links fall back to the public explorer rather than
    # leaking an unresolvable internal host.
    assert _resolve("", server_url) == "https://mempool.space"


@pytest.mark.parametrize(
    "server_url",
    [
        "https://mempool.space",
        "https://mempool.example.com",
        "http://192.168.1.50:8080",  # LAN address — a same-network user can reach it
        "http://10.0.0.5:8080",
    ],
)
def test_user_reachable_backend_is_used(server_url: str) -> None:
    assert _resolve("", server_url) == server_url.rstrip("/")


def test_explicit_public_url_always_wins() -> None:
    # An operator-set public URL is honored even when the backend is internal,
    # including an onion address (onion dashboard users).
    assert (
        _resolve("http://myonionmempoolxyz.onion", "http://mempool-rdts.embassy:8999")
        == "http://myonionmempoolxyz.onion"
    )


def test_trailing_slash_normalized() -> None:
    assert _resolve("https://mempool.example.com/", "") == "https://mempool.example.com"
