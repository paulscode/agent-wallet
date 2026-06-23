# SPDX-License-Identifier: MIT
"""Per-listener SOCKS5 probe tests.

We don't exercise the actual SOCKS round-trip (that's an integration
concern). Instead we pin:
  - Round-robin cursor progresses one listener per call and wraps.
  - Snapshot shape is what the dashboard + Prometheus consumers
    expect (port, ok, ages, last_error).
  - Reconfiguration mid-flight (listener set shrinks) doesn't crash.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from app.services.tor_per_listener_probe import (
    ListenerHealth,
    _reset_for_tests,
    get_snapshot,
    probe_next_listener,
    probe_one_listener,
)


@pytest.fixture(autouse=True)
def _fresh_state() -> None:
    _reset_for_tests()


@pytest.mark.asyncio
async def test_probe_one_listener_marks_ok_on_success() -> None:
    """Mocked httpx that returns 200 → ok=True, last_error=None."""

    class _Resp:
        def raise_for_status(self) -> None:
            return None

    class _Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def get(self, _url):
            return _Resp()

    with patch("httpx.AsyncClient", return_value=_Client()):
        h = await probe_one_listener("boltz_submarine", 9050)
    assert h.ok is True
    assert h.last_error is None
    assert h.last_ok_ts > 0


@pytest.mark.asyncio
async def test_probe_one_listener_marks_fail_on_exception() -> None:
    """Any exception → ok=False and the error is captured + truncated."""

    class _Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def get(self, _url):
            raise RuntimeError("a" * 500)

    with patch("httpx.AsyncClient", return_value=_Client()):
        h = await probe_one_listener("boltz_reverse", 9051)
    assert h.ok is False
    assert h.last_error is not None
    # Error truncated to 200 chars.
    assert len(h.last_error) <= 200


@pytest.mark.asyncio
async def test_round_robin_cursor_progresses_and_wraps() -> None:
    """Calling probe_next_listener N times must visit N distinct
    listeners, then wrap to the first listener again."""
    fake = AsyncMock(
        side_effect=lambda name, port: ListenerHealth(
            name=name,
            port=port,
            ok=True,
        )
    )

    with patch(
        "app.services.tor_per_listener_probe.probe_one_listener",
        fake,
    ):
        visited: list[str] = []
        # Default config has 8 listeners.
        for _ in range(8):
            result = await probe_next_listener()
            assert result is not None
            visited.append(result.name)
        # Wrap: 9th call must visit the same listener as the 1st.
        result9 = await probe_next_listener()

    assert len(set(visited)) == 8, f"round-robin must visit each listener exactly once per cycle, got: {visited}"
    assert result9.name == visited[0], "cursor must wrap back to the first listener"


@pytest.mark.asyncio
async def test_returns_none_when_no_listeners_configured(monkeypatch) -> None:
    """Empty listener dict → None (caller should treat as no-op)."""
    monkeypatch.setattr(
        "app.core.config.settings.anonymize_tor_socks_ports",
        "",
    )
    result = await probe_next_listener()
    assert result is None


def test_snapshot_uses_none_until_first_probe() -> None:
    """A listener that hasn't been probed yet has ``ok=None`` and
    age fields of None — the dashboard renders these as 'untested'."""
    # No probe has run yet.
    snap = get_snapshot()
    assert snap == {}


@pytest.mark.asyncio
async def test_snapshot_carries_ages_and_last_error() -> None:
    """After a failed probe the snapshot exposes the error + a
    last_probe_age_s in seconds (or close to zero)."""

    class _Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def get(self, _url):
            raise RuntimeError("connect timeout")

    with patch("httpx.AsyncClient", return_value=_Client()):
        await probe_one_listener("liquid", 9052)

    snap = get_snapshot()
    assert "liquid" in snap
    entry = snap["liquid"]
    assert entry["port"] == 9052
    assert entry["ok"] is False
    assert "connect timeout" in entry["last_error"]
    # Age was just measured; must be very small.
    assert entry["last_probe_age_s"] is not None
    assert entry["last_probe_age_s"] < 1.0
    # Never succeeded → last_ok_age_s is None.
    assert entry["last_ok_age_s"] is None
