# SPDX-License-Identifier: MIT
"""Tests for ``app.services.bolt12.path_diagnostics``.

Exercises:

* ``_extract_inbound_max_htlc`` — node1/node2 orientation logic.
* ``collect_channel_drift_snapshot`` — happy-path + missing-edge + zero-balance.
* ``run_drift_check`` — alert emission above the ratio threshold.

These are unit-level: a fake LNDService stub provides
``list_channels``, ``get_info``, and ``get_channel_edge``.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from app.services.bolt12.path_diagnostics import (
    _extract_inbound_max_htlc,
    collect_channel_drift_snapshot,
    run_drift_check,
)


def _edge(*, node1: str, node2: str, node1_max: int | None, node2_max: int | None) -> dict:
    """Build a fake LND graph-edge response."""

    def _policy(max_msat):
        if max_msat is None:
            return None
        return {
            "max_htlc_msat": str(max_msat),
            "min_htlc": "1000",
            "fee_base_msat": "1000",
            "fee_rate_milli_msat": "150",
            "time_lock_delta": 40,
        }

    return {
        "channel_id": "1234",
        "node1_pub": node1,
        "node2_pub": node2,
        "capacity": "150000",
        "node1_policy": _policy(node1_max),
        "node2_policy": _policy(node2_max),
    }


# ── _extract_inbound_max_htlc ────────────────────────────────


def test_extract_inbound_max_htlc_peer_is_node1():
    """When the peer is node1, the inbound policy is node1_policy
    (peer forwarding to us)."""
    edge = _edge(
        node1="02_peer",
        node2="03_ours",
        node1_max=60_000_000,
        node2_max=99_999_000,
    )
    out = _extract_inbound_max_htlc(
        edge,
        our_pubkey="03_ours",
        peer_pubkey="02_peer",
    )
    assert out == 60_000_000


def test_extract_inbound_max_htlc_peer_is_node2():
    """When the peer is node2 (lexicographically later), inbound
    policy flips to node2_policy."""
    edge = _edge(
        node1="01_ours",
        node2="04_peer",
        node1_max=11_111_000,
        node2_max=22_222_000,
    )
    out = _extract_inbound_max_htlc(
        edge,
        our_pubkey="01_ours",
        peer_pubkey="04_peer",
    )
    assert out == 22_222_000


def test_extract_inbound_max_htlc_returns_none_for_unknown_pair():
    edge = _edge(
        node1="aa",
        node2="bb",
        node1_max=1_000_000,
        node2_max=2_000_000,
    )
    # We don't appear in the edge — no policy applies.
    assert (
        _extract_inbound_max_htlc(
            edge,
            our_pubkey="cc",
            peer_pubkey="dd",
        )
        is None
    )


def test_extract_inbound_max_htlc_handles_missing_policy():
    edge = _edge(node1="aa", node2="bb", node1_max=None, node2_max=1_000)
    assert _extract_inbound_max_htlc(edge, our_pubkey="bb", peer_pubkey="aa") is None


def test_extract_inbound_max_htlc_handles_zero_and_blank():
    """LND surfaces missing values as ``"0"`` or empty strings.
    Both must coerce to None (we shouldn't divide by 0 downstream)."""
    edge = {
        "node1_pub": "aa",
        "node2_pub": "bb",
        "node1_policy": {"max_htlc_msat": "0"},
        "node2_policy": {"max_htlc_msat": ""},
    }
    assert _extract_inbound_max_htlc(edge, our_pubkey="bb", peer_pubkey="aa") is None
    assert _extract_inbound_max_htlc(edge, our_pubkey="aa", peer_pubkey="bb") is None


# ── collect_channel_drift_snapshot ───────────────────────────


class _FakeLnd:
    """Minimal stub matching what path_diagnostics calls."""

    def __init__(self, channels, info, edges):
        self.get_channels = AsyncMock(return_value=(channels, None))
        self.get_info = AsyncMock(return_value=(info, None))
        # edges keyed on chan_id
        self._edges = edges

    async def get_channel_edge(self, chan_id):
        return self._edges.get(chan_id, (None, "not found")), None if chan_id in self._edges else "not found"


@pytest.mark.asyncio
async def test_snapshot_sorts_worst_offender_first():
    """The snapshot must surface the highest-ratio channel first
    so operators see the over-claim immediately at the top."""
    lnd = _FakeLnd(
        channels=[
            {
                "chan_id": "low_drift",
                "remote_pubkey": "02_peer_a",
                "peer_alias": "PeerA",
                "capacity": 150_000,
                "local_balance": 36_500,
                "remote_balance": 112_500,
                "active": True,
            },
            {
                "chan_id": "high_drift",
                "remote_pubkey": "02_peer_b",
                "peer_alias": "PeerB",
                "capacity": 60_000,
                "local_balance": 40_000,
                "remote_balance": 20_000,
                "active": True,
            },
        ],
        info={"identity_pubkey": "03_ours"},
        edges={
            "low_drift": _edge(
                node1="02_peer_a",
                node2="03_ours",
                node1_max=133_650_000,
                node2_max=0,
            ),
            "high_drift": _edge(
                node1="02_peer_b",
                node2="03_ours",
                node1_max=60_000_000,
                node2_max=0,
            ),
        },
    )
    # Patch get_channel_edge to use proper signature.
    lnd.get_channel_edge = AsyncMock(
        side_effect=lambda cid: (lnd._edges[cid], None),
    )

    rows = await collect_channel_drift_snapshot(lnd)
    assert len(rows) == 2
    # high_drift has ratio 60000 / 20000 = 3.0x → top
    # low_drift has ratio 133650 / 112500 = 1.188x → bottom
    assert rows[0].chan_id == "high_drift"
    assert rows[0].ratio_advertised_to_receivable == pytest.approx(3.0, rel=1e-3)
    assert rows[1].chan_id == "low_drift"
    assert rows[1].ratio_advertised_to_receivable == pytest.approx(1.188, rel=1e-3)


@pytest.mark.asyncio
async def test_snapshot_handles_zero_remote_balance():
    """A fully-spent channel (remote_balance=0) must yield
    ``ratio=None`` rather than ``inf`` / divide-by-zero."""
    lnd = _FakeLnd(
        channels=[
            {
                "chan_id": "empty",
                "remote_pubkey": "02_peer",
                "peer_alias": "P",
                "capacity": 150_000,
                "local_balance": 150_000,
                "remote_balance": 0,
                "active": True,
            }
        ],
        info={"identity_pubkey": "03_ours"},
        edges={},
    )
    lnd.get_channel_edge = AsyncMock(
        return_value=(
            _edge(
                node1="02_peer",
                node2="03_ours",
                node1_max=60_000_000,
                node2_max=0,
            ),
            None,
        ),
    )

    rows = await collect_channel_drift_snapshot(lnd)
    assert len(rows) == 1
    assert rows[0].ratio_advertised_to_receivable is None
    # ``gossiped_inbound_max_htlc_sat`` is still populated.
    assert rows[0].gossiped_inbound_max_htlc_sat == 60_000


@pytest.mark.asyncio
async def test_snapshot_handles_missing_edge_gracefully():
    """A channel whose graph edge fails to fetch (e.g., private
    channel without -option_scid_alias) must surface with
    ``gossiped_inbound_max_htlc_sat=None`` and ``ratio=None``
    rather than blowing up the whole snapshot."""
    lnd = _FakeLnd(
        channels=[
            {
                "chan_id": "ghost",
                "remote_pubkey": "02_peer",
                "peer_alias": "Ghost",
                "capacity": 30_000,
                "local_balance": 15_000,
                "remote_balance": 15_000,
                "active": True,
            }
        ],
        info={"identity_pubkey": "03_ours"},
        edges={},
    )
    lnd.get_channel_edge = AsyncMock(return_value=(None, "edge not found"))

    rows = await collect_channel_drift_snapshot(lnd)
    assert len(rows) == 1
    assert rows[0].gossiped_inbound_max_htlc_sat is None
    assert rows[0].ratio_advertised_to_receivable is None


@pytest.mark.asyncio
async def test_snapshot_returns_empty_on_get_channels_failure():
    lnd = MagicMock()
    lnd.get_channels = AsyncMock(return_value=(None, "LND unreachable"))
    rows = await collect_channel_drift_snapshot(lnd)
    assert rows == []


# ── run_drift_check ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_drift_check_alerts_above_threshold(monkeypatch, caplog):
    """When at least one channel exceeds the alert ratio, the
    summary's ``alerted`` count is positive and a WARN log line
    is emitted."""
    import logging

    lnd = _FakeLnd(
        channels=[
            {
                "chan_id": "alert_me",
                "remote_pubkey": "02_peer",
                "peer_alias": "PeerHigh",
                "capacity": 60_000,
                "local_balance": 40_000,
                "remote_balance": 20_000,
                "active": True,
            }
        ],
        info={"identity_pubkey": "03_ours"},
        edges={},
    )
    lnd.get_channel_edge = AsyncMock(
        return_value=(
            _edge(
                node1="02_peer",
                node2="03_ours",
                node1_max=60_000_000,
                node2_max=0,
            ),
            None,
        ),
    )

    # Stub _audit_inbound to avoid touching the audit log DB.
    audit_calls: list = []

    async def _spy_audit(*args, **kwargs):
        audit_calls.append((args, kwargs))

    monkeypatch.setattr(
        "app.services.bolt12.responder._audit_inbound",
        _spy_audit,
    )

    with caplog.at_level(logging.WARNING, logger="app.services.bolt12.path_diagnostics"):
        summary = await run_drift_check(lnd, alert_ratio=1.5)

    assert summary["scanned"] == 1
    assert summary["alerted"] == 1
    assert summary["max_ratio"] == pytest.approx(3.0, rel=1e-3)

    # WARN log mentions the drift ratio.
    msgs = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
    assert any("3.0" in m and "1.50x" in m for m in msgs)

    # Audit row was emitted with the diagnostic action.
    assert len(audit_calls) == 1
    _args, kwargs = audit_calls[0]
    assert kwargs["action"] == "bolt12_htlc_max_drift_detected"
    assert kwargs["details"]["chan_id"] == "alert_me"
    assert kwargs["details"]["ratio"] == pytest.approx(3.0, rel=1e-3)


@pytest.mark.asyncio
async def test_drift_check_silent_below_threshold(monkeypatch, caplog):
    """A channel with ratio < threshold must NOT emit an audit
    row or a WARN log line."""
    import logging

    lnd = _FakeLnd(
        channels=[
            {
                "chan_id": "fine",
                "remote_pubkey": "02_peer",
                "peer_alias": "PeerOK",
                "capacity": 150_000,
                "local_balance": 36_500,
                "remote_balance": 112_500,
                "active": True,
            }
        ],
        info={"identity_pubkey": "03_ours"},
        edges={},
    )
    lnd.get_channel_edge = AsyncMock(
        return_value=(
            _edge(
                node1="02_peer",
                node2="03_ours",
                node1_max=133_650_000,
                node2_max=0,
            ),
            None,
        ),
    )

    audit_calls: list = []

    async def _spy_audit(*args, **kwargs):
        audit_calls.append((args, kwargs))

    monkeypatch.setattr(
        "app.services.bolt12.responder._audit_inbound",
        _spy_audit,
    )

    with caplog.at_level(logging.WARNING, logger="app.services.bolt12.path_diagnostics"):
        summary = await run_drift_check(lnd, alert_ratio=1.5)

    # 133650 / 112500 = 1.188x — under threshold.
    assert summary["alerted"] == 0
    assert summary["max_ratio"] == pytest.approx(1.188, rel=1e-3)
    assert audit_calls == []
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]


# ── Celery wrapper smoke test ──────────────────────────────


@pytest.mark.asyncio
async def test_run_check_bolt12_path_drift_calls_run_drift_check(monkeypatch):
    """The Celery task's async impl forwards the settings-configured
    alert ratio to ``run_drift_check`` and returns the summary."""
    from app.core.config import settings as cfg
    from app.tasks import boltz_tasks

    monkeypatch.setattr(cfg, "bolt12_htlc_max_drift_ratio_alert", 2.0)

    spy_calls: list = []

    async def _spy(lnd, *, alert_ratio):
        spy_calls.append({"alert_ratio": alert_ratio})
        return {"scanned": 5, "alerted": 1, "max_ratio": 3.0}

    monkeypatch.setattr(
        "app.services.bolt12.path_diagnostics.run_drift_check",
        _spy,
    )

    # Stub LND constructor to avoid network init.
    closed = {"n": 0}

    class _FakeLND:
        async def close(self):
            closed["n"] += 1

    monkeypatch.setattr(
        "app.services.lnd_service.LNDService",
        _FakeLND,
    )

    out = await boltz_tasks._run_check_bolt12_path_drift()
    assert out == {"scanned": 5, "alerted": 1, "max_ratio": 3.0}
    assert spy_calls == [{"alert_ratio": 2.0}]
    assert closed["n"] == 1  # LND client closed after the check
