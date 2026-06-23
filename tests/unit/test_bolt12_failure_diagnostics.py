# SPDX-License-Identifier: MIT
"""Tests for ``app.services.bolt12.failure_diagnostics`` (the
settle-watchdog enrichment that compares encoded-vs-current intro
policy and dumps LND's HTLC view of the invoice).
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

# ── Pure helper: peer-side policy extractor ────────────────────


def test_extract_peer_side_policy_picks_node1_when_peer_is_node1():
    from app.services.bolt12.failure_diagnostics import (
        _extract_peer_side_policy,
    )

    peer = "02aa" + "00" * 31
    ours = "03bb" + "00" * 31
    edge = {
        "node1_pub": peer,
        "node2_pub": ours,
        "node1_policy": {
            "fee_base_msat": "1100",
            "fee_rate_milli_msat": "1500",
            "time_lock_delta": 80,
            "min_htlc": "1000",
            "max_htlc_msat": "100000000",
            "disabled": False,
            "last_update": 1718000000,
        },
        "node2_policy": {"fee_base_msat": "0"},  # should NOT be returned
    }
    out = _extract_peer_side_policy(
        edge,
        our_pubkey=ours,
        peer_pubkey=peer,
    )
    assert out is not None
    assert out["fee_base_msat"] == "1100"
    assert out["fee_rate_milli_msat"] == "1500"
    assert out["max_htlc_msat"] == "100000000"


def test_extract_peer_side_policy_picks_node2_when_peer_is_node2():
    from app.services.bolt12.failure_diagnostics import (
        _extract_peer_side_policy,
    )

    peer = "02aa" + "00" * 31
    ours = "03bb" + "00" * 31
    edge = {
        "node1_pub": ours,
        "node2_pub": peer,
        "node1_policy": {"fee_base_msat": "0"},  # NOT returned
        "node2_policy": {"fee_base_msat": "2200"},
    }
    out = _extract_peer_side_policy(
        edge,
        our_pubkey=ours,
        peer_pubkey=peer,
    )
    assert out is not None
    assert out["fee_base_msat"] == "2200"


def test_extract_peer_side_policy_computes_last_update_age_s():
    """``last_update_age_s`` is the strongest single signal of a
    policy-update race: a sub-minute value means the intro
    re-broadcast its policy moments before the HTLC arrived. Must
    be derived from the gossiped ``last_update`` epoch and be
    deterministic given an injected ``now_epoch``."""
    from app.services.bolt12.failure_diagnostics import (
        _extract_peer_side_policy,
    )

    peer = "02aa" + "00" * 31
    ours = "03bb" + "00" * 31
    edge = {
        "node1_pub": peer,
        "node2_pub": ours,
        "node1_policy": {
            "fee_base_msat": "1100",
            "last_update": 1718000000,
        },
        "node2_policy": {},
    }
    out = _extract_peer_side_policy(
        edge,
        our_pubkey=ours,
        peer_pubkey=peer,
        now_epoch=1718000045.0,
    )
    assert out is not None
    assert out["last_update"] == 1718000000
    assert out["last_update_age_s"] == 45


def test_extract_peer_side_policy_age_is_none_when_last_update_missing():
    from app.services.bolt12.failure_diagnostics import (
        _extract_peer_side_policy,
    )

    peer = "02aa" + "00" * 31
    ours = "03bb" + "00" * 31
    edge = {
        "node1_pub": peer,
        "node2_pub": ours,
        "node1_policy": {"fee_base_msat": "1100"},  # no last_update
        "node2_policy": {},
    }
    out = _extract_peer_side_policy(
        edge,
        our_pubkey=ours,
        peer_pubkey=peer,
        now_epoch=1718000045.0,
    )
    assert out is not None
    assert out["last_update"] is None
    assert out["last_update_age_s"] is None


def test_extract_peer_side_policy_age_clamped_to_zero_for_future_update():
    """Defensive: if the gossiped ``last_update`` is somehow in the
    future (clock skew), report age=0 rather than negative."""
    from app.services.bolt12.failure_diagnostics import (
        _extract_peer_side_policy,
    )

    peer = "02aa" + "00" * 31
    ours = "03bb" + "00" * 31
    edge = {
        "node1_pub": peer,
        "node2_pub": ours,
        "node1_policy": {"last_update": 1718000100},
        "node2_policy": {},
    }
    out = _extract_peer_side_policy(
        edge,
        our_pubkey=ours,
        peer_pubkey=peer,
        now_epoch=1718000000.0,
    )
    assert out is not None
    assert out["last_update_age_s"] == 0


def test_extract_peer_side_policy_returns_none_on_mismatch():
    """If neither node-pub corresponds to the requested peer, we
    refuse to guess — returning None signals to the caller that the
    edge isn't usable for this comparison."""
    from app.services.bolt12.failure_diagnostics import (
        _extract_peer_side_policy,
    )

    edge = {
        "node1_pub": "02cc" + "00" * 31,
        "node2_pub": "02dd" + "00" * 31,
        "node1_policy": {"fee_base_msat": "100"},
        "node2_policy": {"fee_base_msat": "200"},
    }
    assert (
        _extract_peer_side_policy(
            edge,
            our_pubkey="03bb" + "00" * 31,
            peer_pubkey="02aa" + "00" * 31,
        )
        is None
    )


# ── Pure helper: encoded-vs-current diff ───────────────────────


def test_diff_encoded_vs_current_omits_matching_fields():
    """Fields that match must NOT appear in the divergence dict —
    audit-row noise reduction."""
    from app.services.bolt12.failure_diagnostics import (
        _diff_encoded_vs_current,
    )

    comparisons = [
        ("fee_base_msat", 1100, "1100"),
        ("fee_rate_milli_msat", 1206, "1206"),
        ("min_htlc", 1100, "1100"),
        ("max_htlc_msat", 133650000, "133650000"),
    ]
    assert _diff_encoded_vs_current(comparisons=comparisons) == {}


def test_diff_encoded_vs_current_surfaces_divergent_fields():
    """The classic Megalithic-policy-update-race scenario: encoded
    ppm=1206 vs current ppm=1500 must surface as a divergence
    keyed by the LND wire field name."""
    from app.services.bolt12.failure_diagnostics import (
        _diff_encoded_vs_current,
    )

    comparisons = [
        ("fee_base_msat", 1100, "1100"),
        ("fee_rate_milli_msat", 1206, "1500"),  # diverged
        ("min_htlc", 1100, "1100"),
        ("max_htlc_msat", 133650000, "133650000"),
    ]
    diff = _diff_encoded_vs_current(comparisons=comparisons)
    assert diff == {
        "fee_rate_milli_msat": {"encoded": 1206, "current": 1500},
    }


def test_diff_encoded_vs_current_skips_when_encoded_is_none():
    """Legacy invoice rows minted before the encoded-triplet ships
    have ``encoded_*`` fields = None. These rows must NOT produce
    false-positive divergence flags — we just don't have the data
    to compare. The reader sees ``encoded`` block of Nones and
    knows the row is legacy."""
    from app.services.bolt12.failure_diagnostics import (
        _diff_encoded_vs_current,
    )

    comparisons = [
        ("fee_base_msat", None, "1100"),
        ("fee_rate_milli_msat", None, "1500"),
        ("min_htlc", None, "1100"),
        ("max_htlc_msat", None, "133650000"),
    ]
    diff = _diff_encoded_vs_current(comparisons=comparisons)
    assert diff == {}


def test_diff_encoded_vs_current_skips_when_current_is_none():
    """When gossip lookup failed (e.g., LND breaker open during
    the diagnostic query) we don't have the right-hand side of
    the comparison. Flagging would attribute every field's drift
    to a query failure → mislead the reader. Skip instead."""
    from app.services.bolt12.failure_diagnostics import (
        _diff_encoded_vs_current,
    )

    comparisons = [
        ("fee_base_msat", 1100, None),
        ("fee_rate_milli_msat", 1206, None),
        ("min_htlc", 1100, None),
        ("max_htlc_msat", 133650000, None),
    ]
    diff = _diff_encoded_vs_current(comparisons=comparisons)
    assert diff == {}


def test_diff_encoded_vs_current_flags_max_htlc_drift():
    """``max_htlc_msat`` is the field MOST likely to drift between
    mint and HTLC arrival — it tracks Megalithic's channel balance,
    which changes constantly. A drift here is the strongest
    candidate for "Ocean's HTLC failed because Megalithic's
    advertised max dropped below the path amount between mint and
    forward.\""""
    from app.services.bolt12.failure_diagnostics import (
        _diff_encoded_vs_current,
    )

    comparisons = [
        ("fee_base_msat", 1100, "1100"),
        ("fee_rate_milli_msat", 1206, "1206"),
        ("min_htlc", 1100, "1100"),
        # Megalithic dropped advertised max from 133M → 2M between
        # mint and HTLC arrival.
        ("max_htlc_msat", 133650000, "2000000"),
    ]
    diff = _diff_encoded_vs_current(comparisons=comparisons)
    assert diff == {
        "max_htlc_msat": {"encoded": 133650000, "current": 2000000},
    }


# ── End-to-end: query_intro_policy_now ─────────────────────────


@pytest.mark.asyncio
async def test_query_intro_policy_now_returns_chan_and_policy():
    """Happy path — channel exists with the intro, edge fetch
    succeeds, peer-side policy extracted."""
    from app.services.bolt12.failure_diagnostics import (
        query_intro_policy_now,
    )

    intro = "02a98c86ef366ce2" + "00" * 25
    ours = "0312" + "00" * 31

    lnd = MagicMock()
    lnd.get_info = AsyncMock(
        return_value=({"identity_pubkey": ours}, None),
    )
    lnd.get_channels = AsyncMock(
        return_value=(
            [{"chan_id": "104276", "remote_pubkey": intro}],
            None,
        ),
    )
    lnd.get_channel_edge = AsyncMock(
        return_value=(
            {
                "node1_pub": intro,
                "node2_pub": ours,
                "node1_policy": {
                    "fee_base_msat": "1100",
                    "fee_rate_milli_msat": "1206",
                    "time_lock_delta": 80,
                    "min_htlc": "1100",
                    "max_htlc_msat": "133650000",
                },
                "node2_policy": {},
            },
            None,
        ),
    )

    out = await query_intro_policy_now(lnd, intro_pubkey=intro)
    assert out is not None
    assert out["chan_id"] == "104276"
    assert out["policy"]["fee_rate_milli_msat"] == "1206"


@pytest.mark.asyncio
async def test_query_intro_policy_now_returns_none_when_intro_not_peer():
    """For multi-hop blinded paths the intro isn't a direct peer.
    We can't query a non-peer's outbound policy via /v1/graph/edge
    on OUR channels, so the helper returns None — caller records
    'gossip unavailable' rather than guessing."""
    from app.services.bolt12.failure_diagnostics import (
        query_intro_policy_now,
    )

    lnd = MagicMock()
    lnd.get_info = AsyncMock(
        return_value=({"identity_pubkey": "0312" + "00" * 31}, None),
    )
    lnd.get_channels = AsyncMock(
        return_value=(
            [{"chan_id": "104276", "remote_pubkey": "02zz" + "00" * 31}],
            None,
        ),
    )

    out = await query_intro_policy_now(
        lnd,
        intro_pubkey="02aa" + "00" * 31,
    )
    assert out is None
    # get_channel_edge should NOT have been called when no channel
    # matches — wasted Tor round-trip otherwise.
    assert not lnd.get_channel_edge.called if hasattr(lnd, "get_channel_edge") else True


@pytest.mark.asyncio
async def test_query_invoice_htlc_state_trims_to_diagnostic_fields():
    """LND returns plenty of custom-record/encrypted-payload junk on
    each HTLC; we only want the discrimination signal (state,
    amt_msat, cltv, chan_id) so audit rows stay readable."""
    from app.services.bolt12.failure_diagnostics import (
        query_invoice_htlc_state,
    )

    lnd = MagicMock()
    lnd._request = AsyncMock(
        return_value=(
            {
                "state": "OPEN",
                "amt_paid_msat": "0",
                "htlcs": [
                    {
                        "state": "CANCELED",
                        "amt_msat": "4058000",
                        "accept_time": "100",
                        "resolve_time": "101",
                        "expiry_height": 953700,
                        "chan_id": "104276",
                        "htlc_index": "7",
                        # Junk fields we DON'T want to leak into the
                        # audit row.
                        "custom_records": {"5482373484": "deadbeef"},
                        "mpp_total_amt_msat": "4058000",
                    }
                ],
            },
            None,
        ),
    )
    out = await query_invoice_htlc_state(lnd, payment_hash_hex="ab" * 32)
    assert out is not None
    assert out["state"] == "OPEN"
    assert len(out["htlcs"]) == 1
    h = out["htlcs"][0]
    assert h["state"] == "CANCELED"
    assert h["amt_msat"] == "4058000"
    assert h["chan_id"] == "104276"
    # Trimmed.
    assert "custom_records" not in h
    assert "mpp_total_amt_msat" not in h


@pytest.mark.asyncio
async def test_query_invoice_htlc_state_returns_none_on_error():
    from app.services.bolt12.failure_diagnostics import (
        query_invoice_htlc_state,
    )

    lnd = MagicMock()
    lnd._request = AsyncMock(return_value=(None, "not_found"))
    out = await query_invoice_htlc_state(lnd, payment_hash_hex="ab" * 32)
    assert out is None


# ── End-to-end: collect_path_policy_drift ──────────────────────


@pytest.mark.asyncio
async def test_collect_path_policy_drift_emits_per_intro_comparison():
    """One path → one entry with encoded triplet, current policy,
    and the field-level divergence keyed by LND wire field name."""
    from app.services.bolt12.failure_diagnostics import (
        collect_path_policy_drift,
    )

    intro = "02a98c86ef366ce2" + "00" * 25
    ours = "0312" + "00" * 31

    summary = {
        "paths": [
            {
                "intro_pubkey": intro,
                "encoded_base_fee_msat": 1100,
                "encoded_proportional_fee_rate": 1206,
                "encoded_total_cltv_delta": 201,
                "encoded_htlc_min_msat": 1100,
                "htlc_max_msat_advertised": 133650000,
            }
        ]
    }

    lnd = MagicMock()
    lnd.get_info = AsyncMock(
        return_value=({"identity_pubkey": ours}, None),
    )
    lnd.get_channels = AsyncMock(
        return_value=(
            [{"chan_id": "104276", "remote_pubkey": intro}],
            None,
        ),
    )
    lnd.get_channel_edge = AsyncMock(
        return_value=(
            {
                "node1_pub": intro,
                "node2_pub": ours,
                "node1_policy": {
                    "fee_base_msat": "1100",
                    "fee_rate_milli_msat": "1500",  # diverged
                    "time_lock_delta": 80,  # intentionally != 201
                    "min_htlc": "1100",
                    "max_htlc_msat": "133650000",
                },
                "node2_policy": {},
            },
            None,
        ),
    )

    out = await collect_path_policy_drift(lnd, summary)
    assert len(out) == 1
    entry = out[0]
    assert entry["intro_pubkey"] == intro
    assert entry["encoded"] == {
        "base_fee_msat": 1100,
        "proportional_fee_rate": 1206,
        "total_cltv_delta": 201,  # path-aggregate — surfaced
        "htlc_min_msat": 1100,
        "htlc_max_msat_advertised": 133650000,
    }
    assert entry["current"]["chan_id"] == "104276"
    # Only fee_rate appears in divergence:
    #  - total_cltv_delta is NOT auto-flagged (path-aggregate vs
    #    per-hop comparison is semantically wrong, would always
    #    false-positive)
    #  - other fields match
    assert entry["divergence"] == {
        "fee_rate_milli_msat": {"encoded": 1206, "current": 1500},
    }


@pytest.mark.asyncio
async def test_collect_path_policy_drift_legacy_row_no_false_divergence():
    """Legacy invoice rows minted before the encoded-triplet ships
    have a summary WITHOUT the ``encoded_*`` fields. The drift
    helper must still run cleanly: the ``encoded`` block reports
    None for missing fields, the ``current`` block carries the
    real gossip values, and ``divergence`` is empty — we don't
    have the data to compare, so we don't pretend we do."""
    from app.services.bolt12.failure_diagnostics import (
        collect_path_policy_drift,
    )

    intro = "02a98c86ef366ce2" + "00" * 25
    ours = "0312" + "00" * 31

    legacy_summary = {
        "paths": [
            {
                "intro_pubkey": intro,
                "real_hops": 1,
                "htlc_max_msat_advertised": 133650000,
                "htlc_max_msat_clamped": 111335000,
                "terminal_peer_pubkey": intro,
                # NOTE: no encoded_* keys — this row was written
                # before the diagnostic enrichment shipped.
            }
        ]
    }

    lnd = MagicMock()
    lnd.get_info = AsyncMock(
        return_value=({"identity_pubkey": ours}, None),
    )
    lnd.get_channels = AsyncMock(
        return_value=(
            [{"chan_id": "104276", "remote_pubkey": intro}],
            None,
        ),
    )
    lnd.get_channel_edge = AsyncMock(
        return_value=(
            {
                "node1_pub": intro,
                "node2_pub": ours,
                "node1_policy": {
                    "fee_base_msat": "1100",
                    "fee_rate_milli_msat": "1500",
                    "min_htlc": "1100",
                    "max_htlc_msat": "133650000",  # matches advertised
                },
                "node2_policy": {},
            },
            None,
        ),
    )

    out = await collect_path_policy_drift(lnd, legacy_summary)
    assert len(out) == 1
    entry = out[0]
    # Encoded block reflects the missing data faithfully.
    assert entry["encoded"]["base_fee_msat"] is None
    assert entry["encoded"]["proportional_fee_rate"] is None
    assert entry["encoded"]["htlc_min_msat"] is None
    # htlc_max_msat_advertised IS present on legacy summaries.
    assert entry["encoded"]["htlc_max_msat_advertised"] == 133650000
    # Current gossip is recorded.
    assert entry["current"]["policy"]["fee_rate_milli_msat"] == "1500"
    # Divergence is empty: fee_base/rate/min_htlc skipped because
    # encoded is None; max_htlc_msat matches → no flag.
    assert entry["divergence"] == {}


@pytest.mark.asyncio
async def test_collect_path_policy_drift_subtracts_safety_margin_before_divergence():
    """2026-06-14: when the mint applied a safety margin, the
    encoded fields exceed gossip by the margin amount. The
    divergence comparison must subtract the margin before
    flagging drift, otherwise every audit row would falsely flag
    the deliberate over-quote as a policy-update race."""
    from app.services.bolt12.failure_diagnostics import (
        collect_path_policy_drift,
    )

    intro = "02a98c86ef366ce2" + "00" * 25
    ours = "0312" + "00" * 31

    # Path was minted with ppm=5000 from gossip, then padded +1000
    # → encoded final value = 6000.
    summary = {
        "paths": [
            {
                "intro_pubkey": intro,
                "encoded_base_fee_msat": 1000,
                "encoded_proportional_fee_rate": 6000,  # post-margin
                "encoded_htlc_min_msat": 1000,
                "htlc_max_msat_advertised": 148_500_000,
                "safety_margin_ppm_applied": 1000,
                "safety_margin_base_msat_applied": 0,
            }
        ]
    }

    lnd = MagicMock()
    lnd.get_info = AsyncMock(
        return_value=({"identity_pubkey": ours}, None),
    )
    lnd.get_channels = AsyncMock(
        return_value=(
            [{"chan_id": "104276", "remote_pubkey": intro}],
            None,
        ),
    )
    # Gossip unchanged at 5000 ppm.
    lnd.get_channel_edge = AsyncMock(
        return_value=(
            {
                "node1_pub": intro,
                "node2_pub": ours,
                "node1_policy": {
                    "fee_base_msat": "1000",
                    "fee_rate_milli_msat": "5000",
                    "min_htlc": "1000",
                    "max_htlc_msat": "148500000",
                },
                "node2_policy": {},
            },
            None,
        ),
    )

    out = await collect_path_policy_drift(lnd, summary)
    assert len(out) == 1
    entry = out[0]
    # Encoded values match gossip after subtracting the margin →
    # divergence MUST be empty, not falsely flagged.
    assert entry["divergence"] == {}
    # The margin is surfaced separately so the reader knows what
    # the comparison subtracted.
    assert entry["safety_margin_ppm_applied"] == 1000
    assert entry["safety_margin_base_msat_applied"] == 0


@pytest.mark.asyncio
async def test_collect_path_policy_drift_flags_drift_above_margin():
    """If gossip moves further than the margin absorbs, the
    diagnostic correctly flags real drift. Scenario: minted with
    ppm=5000+1000 margin=6000, but Megalithic gossip jumped to
    6500 by the time of the failure. Excess drift = 500 ppm above
    what the margin can absorb → divergence."""
    from app.services.bolt12.failure_diagnostics import (
        collect_path_policy_drift,
    )

    intro = "02a98c86ef366ce2" + "00" * 25
    ours = "0312" + "00" * 31

    summary = {
        "paths": [
            {
                "intro_pubkey": intro,
                "encoded_base_fee_msat": 1000,
                "encoded_proportional_fee_rate": 6000,
                "encoded_htlc_min_msat": 1000,
                "htlc_max_msat_advertised": 148_500_000,
                "safety_margin_ppm_applied": 1000,
                "safety_margin_base_msat_applied": 0,
            }
        ]
    }

    lnd = MagicMock()
    lnd.get_info = AsyncMock(
        return_value=({"identity_pubkey": ours}, None),
    )
    lnd.get_channels = AsyncMock(
        return_value=(
            [{"chan_id": "104276", "remote_pubkey": intro}],
            None,
        ),
    )
    lnd.get_channel_edge = AsyncMock(
        return_value=(
            {
                "node1_pub": intro,
                "node2_pub": ours,
                "node1_policy": {
                    "fee_base_msat": "1000",
                    "fee_rate_milli_msat": "6500",  # gossip moved
                    "min_htlc": "1000",
                    "max_htlc_msat": "148500000",
                },
                "node2_policy": {},
            },
            None,
        ),
    )

    out = await collect_path_policy_drift(lnd, summary)
    entry = out[0]
    # encoded ppm 6000, margin 1000 → effective compare value 5000
    # vs gossip 6500 → flag a 1500 ppm divergence (real drift
    # beyond what the margin absorbs).
    assert entry["divergence"] == {
        "fee_rate_milli_msat": {"encoded": 5000, "current": 6500},
    }


@pytest.mark.asyncio
async def test_collect_path_policy_drift_returns_empty_on_missing_summary():
    """Defensive: malformed/None summaries (legacy rows) must not
    crash the watchdog."""
    from app.services.bolt12.failure_diagnostics import (
        collect_path_policy_drift,
    )

    lnd = MagicMock()
    assert await collect_path_policy_drift(lnd, None) == []
    assert await collect_path_policy_drift(lnd, {"paths": None}) == []
    assert await collect_path_policy_drift(lnd, {}) == []


@pytest.mark.asyncio
async def test_collect_path_policy_drift_skips_path_entries_without_intro_pubkey():
    """A path entry whose ``intro_pubkey`` is None or empty cannot
    be looked up — skip it silently rather than emit a per-intro
    drift entry with no identifier (which would make the audit
    row ambiguous about which intro the comparison is for)."""
    from app.services.bolt12.failure_diagnostics import (
        collect_path_policy_drift,
    )

    lnd = MagicMock()
    lnd.get_info = AsyncMock(return_value=({"identity_pubkey": "ab"}, None))
    summary = {
        "paths": [
            {"intro_pubkey": None, "encoded_base_fee_msat": 1100},
            {"intro_pubkey": "", "encoded_base_fee_msat": 1100},
            {"encoded_base_fee_msat": 1100},  # key missing
        ]
    }
    out = await collect_path_policy_drift(lnd, summary)
    assert out == []
    # And we never touched get_channels/get_channel_edge — no
    # wasted Tor round-trips for unidentifiable intros.
    assert not lnd.get_channels.called if hasattr(lnd, "get_channels") and hasattr(lnd.get_channels, "called") else True
