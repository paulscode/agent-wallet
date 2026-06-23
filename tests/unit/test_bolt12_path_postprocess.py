# SPDX-License-Identifier: MIT
"""Tests for the BOLT 12 path post-processing pipeline.

Each section pins one stage of the pipeline:

* clamp_path_htlc_max — htlc_max ≤ live remote_balance
* path_meets_amount — drop undersized
* probe_path_liveness — light reachability check
* select_diverse_paths — one path per intro
* PathBreakerRegistry — half-open per-intro breaker
* postprocess_blinded_paths — end-to-end pipeline order
"""

from __future__ import annotations

import base64
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.services.bolt12.path_postprocess import (
    PathBreakerRegistry,
    _pigeonhole_pair_paths_to_channels,
    annotate_path_metadata,
    apply_breaker_filter,
    build_paths_summary,
    clamp_path_htlc_max,
    get_path_breaker,
    path_meets_amount,
    postprocess_blinded_paths,
    select_diverse_paths,
)


@pytest.fixture(autouse=True)
def _reset_module_breaker():
    """The breaker is a module-level singleton; reset before and
    after each test so judgments don't leak across the suite."""
    get_path_breaker().reset_for_tests()
    yield
    get_path_breaker().reset_for_tests()


def _b64hex(hex_str: str) -> str:
    return base64.b64encode(bytes.fromhex(hex_str)).decode()


def _make_path(
    *,
    intro_hex: str,
    real_hops: int = 2,
    base_fee_msat: int = 1000,
    ppm: int = 150,
    cltv_delta: int = 80,
    htlc_min_msat: int = 1000,
    htlc_max_msat: int = 50_000_000,
) -> dict:
    blinded_hops = [{"blinded_node": "aa"}] * (real_hops + 1)
    return {
        "blinded_path": {
            "introduction_node": _b64hex(intro_hex),
            "blinded_hops": blinded_hops,
        },
        "base_fee_msat": base_fee_msat,
        "proportional_fee_rate": ppm,
        "total_cltv_delta": cltv_delta,
        "htlc_min_msat": htlc_min_msat,
        "htlc_max_msat": htlc_max_msat,
    }


# ── clamp ────────────────────────────────────────────


def test_clamp_uses_terminal_channel_when_intro_is_our_peer_real_hops_1():
    """1-hop blinded path where intro = our peer → clamp to that
    channel's remote_balance, not the max-of-all-channels fallback."""
    path = _make_path(
        intro_hex="03aaaaaa" + "00" * 28,
        real_hops=1,
        htlc_max_msat=60_000_000,
    )
    annotate_path_metadata(path)
    channels = [
        {
            "remote_pubkey": "03aaaaaa" + "00" * 28,
            "remote_balance": 20000,
            "gossiped_inbound_max_htlc_msat": 59_400_000,
        },
        {
            "remote_pubkey": "03bbbbbb" + "00" * 28,
            "remote_balance": 112459,
            "gossiped_inbound_max_htlc_msat": 148_500_000,
        },
    ]
    clamp_path_htlc_max(
        path,
        channels,
        our_pubkey="03000000" + "00" * 30,
        safety_buffer_ppm=10_000,
    )
    # 20000 - (20000 * 10000 // 1_000_000) = 20000 - 200 = 19800 sat
    # = 19_800_000 msat, rounded down to the 1_000_000 msat disclosure bucket.
    assert path["htlc_max_msat"] == 19_000_000
    assert path["_htlc_max_msat_advertised"] == 60_000_000
    assert path["_terminal_peer_pubkey"] == "03aaaaaa" + "00" * 28


def test_clamp_falls_back_to_max_channel_when_terminal_unknown():
    """2-hop path where intro is NOT our direct peer AND the
    htlc_max doesn't match a unique channel → conservative cap is
    the max-channel remote_balance."""
    path = _make_path(
        # Advertised 200M msat so that the 112459 sat conservative
        # fallback actually clamps (vs. just being kept).
        intro_hex="03cccccc" + "00" * 27,
        real_hops=2,
        htlc_max_msat=200_000_000,  # doesn't match either channel's gossip
    )
    annotate_path_metadata(path)
    channels = [
        {
            "remote_pubkey": "03aaaaaa" + "00" * 28,
            "remote_balance": 20000,
            "gossiped_inbound_max_htlc_msat": 59_400_000,
        },
        {
            "remote_pubkey": "03bbbbbb" + "00" * 28,
            "remote_balance": 112459,
            "gossiped_inbound_max_htlc_msat": 148_500_000,
        },
    ]
    clamp_path_htlc_max(
        path,
        channels,
        our_pubkey="03000000" + "00" * 30,
        safety_buffer_ppm=10_000,
    )
    # Conservative-permissive fallback: max remote_balance × (1 - 0.01)
    # = 112459 - 1124 = 111335 sat → 111_335_000 msat, rounded down to the
    # 1_000_000 msat disclosure bucket.
    assert path["htlc_max_msat"] == 111_000_000
    assert path["_terminal_peer_pubkey"] is None


def test_clamp_does_not_raise_above_advertised():
    """If the live balance is LARGER than what LND advertised,
    we keep LND's number — never raise the cap."""
    path = _make_path(
        intro_hex="03aaaaaa" + "00" * 28,
        real_hops=1,
        htlc_max_msat=10_000_000,
    )
    annotate_path_metadata(path)
    channels = [
        {
            "remote_pubkey": "03aaaaaa" + "00" * 28,
            "remote_balance": 999_999,  # huge live receivable
            "gossiped_inbound_max_htlc_msat": 10_000_000,
        },
    ]
    clamp_path_htlc_max(
        path,
        channels,
        our_pubkey="03000000" + "00" * 30,
        safety_buffer_ppm=10_000,
    )
    # Advertised 10M msat, live cap 999_999 * 1000 * 0.99 ≈ 989M
    # → clamp keeps 10M.
    assert path["htlc_max_msat"] == 10_000_000


def test_clamp_buckets_disclosed_value_to_hide_exact_balance():
    """The clamped htlc_max is rounded down to a coarse bucket so a payer
    reading the invoice back cannot recover the wallet's exact receivable
    balance — only the bucket floor."""
    path = _make_path(
        intro_hex="03aaaaaa" + "00" * 28,
        real_hops=1,
        htlc_max_msat=60_000_000,
    )
    annotate_path_metadata(path)
    channels = [
        {
            "remote_pubkey": "03aaaaaa" + "00" * 28,
            "remote_balance": 4_321,  # an exact, "leaky" balance
            "gossiped_inbound_max_htlc_msat": 59_400_000,
        },
    ]
    clamp_path_htlc_max(
        path,
        channels,
        our_pubkey="03000000" + "00" * 30,
        safety_buffer_ppm=10_000,
    )
    # Live cap ≈ 4_321 - 43 = 4_278 sat = 4_278_000 msat; the disclosed value
    # is rounded down to the 1_000_000 msat bucket and never reveals 4_278_000.
    disclosed = path["htlc_max_msat"]
    assert disclosed == 4_000_000
    assert disclosed % 1_000_000 == 0
    # Still a safe routing upper bound (never advertises more than the cap).
    assert disclosed <= 4_278_000


def test_clamp_below_one_bucket_is_marked_for_drop():
    """A channel whose live capacity is below one disclosure bucket must not
    advertise htlc_max_msat=0; it is marked so the pipeline drops it."""
    path = _make_path(
        intro_hex="03aaaaaa" + "00" * 28,
        real_hops=1,
        htlc_max_msat=60_000_000,
    )
    annotate_path_metadata(path)
    channels = [
        {
            "remote_pubkey": "03aaaaaa" + "00" * 28,
            "remote_balance": 500,  # 500 sat < 1000 sat (1_000_000 msat) bucket
            "gossiped_inbound_max_htlc_msat": 59_400_000,
        },
    ]
    clamp_path_htlc_max(
        path,
        channels,
        our_pubkey="03000000" + "00" * 30,
        safety_buffer_ppm=10_000,
    )
    assert path["htlc_max_msat"] == 0
    assert path.get("_clamped_below_bucket") is True


# ── gossip-policy refresh ──────────────────────────


@pytest.mark.asyncio
async def test_refresh_path_policy_overwrites_stale_fees():
    """LND's path-builder encodes ppm=1206 from its stale
    per-channel cache while gossip already reflects ppm=5000. The
    refresh stage must overwrite the path's encoded fees with the
    current gossiped values so the BOLT 12 invoice the payer reads
    carries the correct fee budget."""
    from app.services.bolt12.path_postprocess import (
        refresh_path_policy_from_gossip,
    )

    intro_hex = "02a98c86ef366ce2" + "00" * 25
    ours = "03000000" + "00" * 30
    path = _make_path(
        intro_hex=intro_hex,
        real_hops=1,
        base_fee_msat=1100,
        ppm=1206,
        htlc_min_msat=1100,
        htlc_max_msat=133_650_000,
    )
    annotate_path_metadata(path)

    channels = [{"remote_pubkey": intro_hex, "chan_id": "104276"}]
    fake_lnd = MagicMock()
    fake_lnd.get_channel_edge = AsyncMock(
        return_value=(
            {
                "node1_pub": intro_hex,
                "node2_pub": ours,
                "node1_policy": {
                    "fee_base_msat": "1000",
                    "fee_rate_milli_msat": "5000",  # the killer divergence
                    "min_htlc": "1000",
                    "max_htlc_msat": "148500000",
                    "time_lock_delta": 144,
                },
                "node2_policy": {},
            },
            None,
        )
    )

    diff = await refresh_path_policy_from_gossip(
        path,
        fake_lnd,
        our_pubkey=ours,
        channels=channels,
    )
    assert diff == {
        "base_fee_msat": {"old": 1100, "new": 1000},
        "proportional_fee_rate": {"old": 1206, "new": 5000},
        "htlc_min_msat": {"old": 1100, "new": 1000},
        "htlc_max_msat": {"old": 133_650_000, "new": 148_500_000},
    }
    # Path was MUTATED in place — the values the BOLT 12 invoice
    # serialiser reads (encode_invoice_paths) reflect the refresh.
    assert path["base_fee_msat"] == 1000
    assert path["proportional_fee_rate"] == 5000
    assert path["htlc_min_msat"] == 1000
    assert path["htlc_max_msat"] == 148_500_000
    # CLTV is NOT touched — path-aggregate cannot be reconstructed
    # from per-hop gossip without LND's internal padding constant.
    assert path["total_cltv_delta"] == 80


@pytest.mark.asyncio
async def test_refresh_path_policy_no_op_when_values_match():
    """When gossip matches what LND encoded, no mutation, no log,
    empty diff. Hot path on every mint when the intro's policy is
    stable."""
    from app.services.bolt12.path_postprocess import (
        refresh_path_policy_from_gossip,
    )

    intro_hex = "02aa" + "00" * 31
    ours = "03000000" + "00" * 30
    path = _make_path(
        intro_hex=intro_hex,
        real_hops=1,
        base_fee_msat=1000,
        ppm=5000,
        htlc_min_msat=1000,
        htlc_max_msat=148_500_000,
    )
    annotate_path_metadata(path)

    fake_lnd = MagicMock()
    fake_lnd.get_channel_edge = AsyncMock(
        return_value=(
            {
                "node1_pub": intro_hex,
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
        )
    )

    diff = await refresh_path_policy_from_gossip(
        path,
        fake_lnd,
        our_pubkey=ours,
        channels=[{"remote_pubkey": intro_hex, "chan_id": "X"}],
    )
    assert diff == {}
    assert path["proportional_fee_rate"] == 5000


@pytest.mark.asyncio
async def test_refresh_path_policy_skipped_for_multi_hop_paths():
    """For real_hops>=2 the encoded fees are an aggregate across
    multiple hops; one hop's gossip can't reconstruct it. Must
    skip rather than corrupt the aggregate by overwriting with
    one hop's policy."""
    from app.services.bolt12.path_postprocess import (
        refresh_path_policy_from_gossip,
    )

    intro_hex = "02aa" + "00" * 31
    path = _make_path(
        intro_hex=intro_hex,
        real_hops=2,
        base_fee_msat=1100,
        ppm=1206,
    )
    annotate_path_metadata(path)
    assert path["_real_hops"] == 2  # sanity

    fake_lnd = MagicMock()
    # Must NOT call into LND for a multi-hop path.
    fake_lnd.get_channel_edge = AsyncMock(
        side_effect=AssertionError("refresh should be skipped"),
    )

    diff = await refresh_path_policy_from_gossip(
        path,
        fake_lnd,
        our_pubkey="03" + "00" * 32,
        channels=[{"remote_pubkey": intro_hex, "chan_id": "X"}],
    )
    assert diff == {}
    assert path["base_fee_msat"] == 1100  # unmodified


@pytest.mark.asyncio
async def test_refresh_path_policy_skipped_when_intro_not_a_peer():
    """If the intro isn't in our channels list (i.e., not a direct
    peer), we can't look up its policy via /v1/graph/edge on OUR
    channels. Skip cleanly."""
    from app.services.bolt12.path_postprocess import (
        refresh_path_policy_from_gossip,
    )

    intro_hex = "02aa" + "00" * 31
    path = _make_path(intro_hex=intro_hex, real_hops=1)
    annotate_path_metadata(path)

    fake_lnd = MagicMock()
    fake_lnd.get_channel_edge = AsyncMock(
        side_effect=AssertionError("must not be called"),
    )
    # channels list has a DIFFERENT peer, not the intro.
    channels = [{"remote_pubkey": "02ff" + "00" * 31, "chan_id": "X"}]

    diff = await refresh_path_policy_from_gossip(
        path,
        fake_lnd,
        our_pubkey="03" + "00" * 32,
        channels=channels,
    )
    assert diff == {}


@pytest.mark.asyncio
async def test_refresh_path_policy_degrades_gracefully_on_lnd_error():
    """Tor blip / breaker open / LND restart at the mint moment —
    the refresh stage must NOT block the mint. Path stays as LND
    returned it (possibly stale), but at least we ship SOMETHING."""
    from app.services.bolt12.path_postprocess import (
        refresh_path_policy_from_gossip,
    )

    intro_hex = "02aa" + "00" * 31
    path = _make_path(
        intro_hex=intro_hex,
        real_hops=1,
        ppm=1206,
    )
    annotate_path_metadata(path)

    fake_lnd = MagicMock()
    fake_lnd.get_channel_edge = AsyncMock(
        side_effect=RuntimeError("LND breaker open"),
    )

    diff = await refresh_path_policy_from_gossip(
        path,
        fake_lnd,
        our_pubkey="03" + "00" * 32,
        channels=[{"remote_pubkey": intro_hex, "chan_id": "X"}],
    )
    assert diff == {}
    # Path unchanged; mint can proceed.
    assert path["proportional_fee_rate"] == 1206


@pytest.mark.asyncio
async def test_refresh_path_policy_partial_when_gossip_misses_fields():
    """If gossip has only some fields (e.g., min_htlc missing),
    refresh only the present ones. Don't blank out a path field
    just because gossip didn't return it."""
    from app.services.bolt12.path_postprocess import (
        refresh_path_policy_from_gossip,
    )

    intro_hex = "02aa" + "00" * 31
    ours = "03" + "00" * 32
    path = _make_path(
        intro_hex=intro_hex,
        real_hops=1,
        base_fee_msat=1100,
        ppm=1206,
        htlc_min_msat=1100,
        htlc_max_msat=100_000_000,
    )
    annotate_path_metadata(path)

    fake_lnd = MagicMock()
    fake_lnd.get_channel_edge = AsyncMock(
        return_value=(
            {
                "node1_pub": intro_hex,
                "node2_pub": ours,
                "node1_policy": {
                    "fee_rate_milli_msat": "5000",
                    # min_htlc, max_htlc_msat, fee_base_msat absent.
                },
                "node2_policy": {},
            },
            None,
        )
    )

    diff = await refresh_path_policy_from_gossip(
        path,
        fake_lnd,
        our_pubkey=ours,
        channels=[{"remote_pubkey": intro_hex, "chan_id": "X"}],
    )
    assert diff == {
        "proportional_fee_rate": {"old": 1206, "new": 5000},
    }
    # Other fields untouched.
    assert path["base_fee_msat"] == 1100
    assert path["htlc_min_msat"] == 1100
    assert path["htlc_max_msat"] == 100_000_000


# ── PAYINFO safety margin ─────────────────────────


def test_apply_payinfo_safety_margin_pads_ppm():
    """Gossip refresh sets ppm=5000, but the intro actually
    deducts a higher ppm at forward time. The margin stage must
    pad ppm above the refreshed value so the payer over-quotes."""
    from app.services.bolt12.path_postprocess import (
        apply_payinfo_safety_margin,
    )

    path = _make_path(
        intro_hex="02aa" + "00" * 31,
        real_hops=1,
        base_fee_msat=1000,
        ppm=5000,  # post-refresh values
    )
    annotate_path_metadata(path)
    diff = apply_payinfo_safety_margin(
        path,
        margin_ppm=1000,
        margin_base_msat=0,
    )
    # Encoded value now exceeds gossip by the margin → payer
    # budgets MORE → the intro's undisclosed extra fits inside.
    assert path["proportional_fee_rate"] == 6000
    assert path["base_fee_msat"] == 1000  # base untouched
    assert diff["proportional_fee_rate"] == {
        "old": 5000,
        "new": 6000,
        "margin": 1000,
    }
    # Stamped on the path for the watchdog diagnostic to subtract.
    assert path["_safety_margin_ppm_applied"] == 1000
    assert path["_safety_margin_base_msat_applied"] == 0


def test_apply_payinfo_safety_margin_pads_both_ppm_and_base():
    """Both margins fire when both are configured."""
    from app.services.bolt12.path_postprocess import (
        apply_payinfo_safety_margin,
    )

    path = _make_path(
        intro_hex="02aa" + "00" * 31,
        real_hops=1,
        base_fee_msat=1000,
        ppm=5000,
    )
    annotate_path_metadata(path)
    apply_payinfo_safety_margin(
        path,
        margin_ppm=500,
        margin_base_msat=2500,
    )
    assert path["proportional_fee_rate"] == 5500
    assert path["base_fee_msat"] == 3500
    assert path["_safety_margin_ppm_applied"] == 500
    assert path["_safety_margin_base_msat_applied"] == 2500


def test_apply_payinfo_safety_margin_kill_switch():
    """Setting both margins to 0 stamps zeros and does nothing.
    Operator opt-out path — the stage still runs but applies
    nothing, so the audit row can distinguish 'legacy row, no
    stage ever ran' from 'row that recorded margin deliberately
    0'."""
    from app.services.bolt12.path_postprocess import (
        apply_payinfo_safety_margin,
    )

    path = _make_path(
        intro_hex="02aa" + "00" * 31,
        real_hops=1,
        base_fee_msat=1100,
        ppm=1206,
    )
    annotate_path_metadata(path)
    diff = apply_payinfo_safety_margin(
        path,
        margin_ppm=0,
        margin_base_msat=0,
    )
    assert diff == {}
    assert path["proportional_fee_rate"] == 1206  # unchanged
    assert path["base_fee_msat"] == 1100  # unchanged
    # But still stamped so summary records "0 was deliberate".
    assert path["_safety_margin_ppm_applied"] == 0
    assert path["_safety_margin_base_msat_applied"] == 0


def test_apply_payinfo_safety_margin_negative_values_treated_as_zero():
    """Defensive: a misconfigured setting (e.g., -1) clamps to 0
    rather than reducing fees. We never want to under-quote the
    payer."""
    from app.services.bolt12.path_postprocess import (
        apply_payinfo_safety_margin,
    )

    path = _make_path(
        intro_hex="02aa" + "00" * 31,
        real_hops=1,
        base_fee_msat=1000,
        ppm=5000,
    )
    annotate_path_metadata(path)
    apply_payinfo_safety_margin(
        path,
        margin_ppm=-1000,
        margin_base_msat=-2000,
    )
    assert path["proportional_fee_rate"] == 5000  # unchanged
    assert path["base_fee_msat"] == 1000  # unchanged


@pytest.mark.asyncio
async def test_pipeline_refresh_then_margin_then_clamp(monkeypatch):
    """End-to-end pipeline check. The BOLT 12 invoice that ships
    to the payer must carry (gossip-refreshed fee + safety
    margin). Pins the stage ordering: refresh → margin →
    pigeonhole → clamp."""
    from app.core.config import settings

    monkeypatch.setattr(settings, "bolt12_drop_undersized_paths", False)
    monkeypatch.setattr(settings, "bolt12_path_diversity_enforce", False)
    monkeypatch.setattr(settings, "bolt12_path_breaker_enabled", False)
    monkeypatch.setattr(settings, "bolt12_probe_paths_before_mint", False)
    monkeypatch.setattr(
        settings,
        "bolt12_blinded_path_refresh_policy_from_gossip",
        True,
    )
    monkeypatch.setattr(
        settings,
        "bolt12_blinded_path_payinfo_safety_margin_ppm",
        1000,
    )
    monkeypatch.setattr(
        settings,
        "bolt12_blinded_path_payinfo_safety_margin_base_msat",
        0,
    )

    intro_hex = "02a98c86ef366ce2" + "00" * 25
    ours = "03000000" + "00" * 30
    # LND's stale view: ppm=1206
    path = _make_path(
        intro_hex=intro_hex,
        real_hops=1,
        base_fee_msat=1100,
        ppm=1206,
        htlc_min_msat=1100,
        htlc_max_msat=133_650_000,
    )
    channels = [
        {
            "remote_pubkey": intro_hex,
            "chan_id": "1042763633773182977",
            "remote_balance": 200_000,
        }
    ]

    fake_lnd = MagicMock()
    fake_lnd.get_channel_edge = AsyncMock(
        return_value=(
            {
                "node1_pub": intro_hex,
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
        )
    )

    out = await postprocess_blinded_paths(
        [path],
        amount_msat=4_169_000,
        lnd=fake_lnd,
        channels=channels,
        our_pubkey=ours,
        max_paths=8,
    )
    p = out.paths[0]
    # ppm: 1206 (stale) → 5000 (refresh) → 6000 (+ 1000 margin)
    assert p["proportional_fee_rate"] == 6000
    # base: 1100 (stale) → 1000 (refresh) → 1000 (+ 0 margin)
    assert p["base_fee_msat"] == 1000
    # margin stamped so the watchdog diagnostic can subtract
    assert p["_safety_margin_ppm_applied"] == 1000
    assert p["_safety_margin_base_msat_applied"] == 0
    # Summary surfaces both the encoded (post-margin) value AND
    # the margin so failure_diagnostics can isolate a real gossip
    # change from the deliberate over-quote.
    s = out.summary["paths"][0]
    assert s["encoded_proportional_fee_rate"] == 6000
    assert s["safety_margin_ppm_applied"] == 1000
    assert s["safety_margin_base_msat_applied"] == 0


@pytest.mark.asyncio
async def test_pipeline_round_trip_through_encode_and_decode(monkeypatch):
    """End-to-end serialization regression.

    Exercises the full stage chain on a representative scenario:

    * LND returns stale path (ppm=1206, base=1100, htlc_max=133.65M)
    * Gossip says current (ppm=5000, base=1000, htlc_max=148.5M)
    * Refresh stage overwrites the stale fields
    * Margin stage pads ppm by 1000 → 6000
    * Clamp narrows htlc_max to live remote_balance headroom
    * ``encode_invoice_paths`` serializes the mutated path into
      BOLT 12 TLV records
    * ``decode_invoice_paths`` parses them back

    Asserts that the BOLT 12 invoice TLV (what the payer reads)
    carries the post-pipeline values, not LND's original
    pre-pipeline values. This locks in the contract across every
    stage: if anyone refactors and accidentally breaks the chain
    (e.g., introduces a re-read after encode, a mutation that
    doesn't take, a clamp that mishandles the refreshed value),
    this test fails immediately.
    """
    from app.core.config import settings
    from app.services.bolt12.lnd_paths import (
        decode_invoice_paths,
        encode_invoice_paths,
    )

    monkeypatch.setattr(settings, "bolt12_drop_undersized_paths", False)
    monkeypatch.setattr(settings, "bolt12_path_diversity_enforce", False)
    monkeypatch.setattr(settings, "bolt12_path_breaker_enabled", False)
    monkeypatch.setattr(settings, "bolt12_probe_paths_before_mint", False)
    monkeypatch.setattr(
        settings,
        "bolt12_blinded_path_refresh_policy_from_gossip",
        True,
    )
    monkeypatch.setattr(
        settings,
        "bolt12_blinded_path_payinfo_safety_margin_ppm",
        1000,
    )
    monkeypatch.setattr(
        settings,
        "bolt12_blinded_path_payinfo_safety_margin_base_msat",
        0,
    )

    intro_hex = "02a98c86ef366ce2" + "00" * 25
    ours = "03000000" + "00" * 30

    # LND's return shape — including the blinded_path inner dict so
    # encode_invoice_paths can serialize it.
    path = {
        "blinded_path": {
            "introduction_node": _b64hex(intro_hex),
            "blinding_point": _b64hex("02" + "00" * 32),
            "blinded_hops": [
                {
                    "blinded_node": _b64hex("02" + "11" * 32),
                    "encrypted_data": _b64hex("00" * 32),
                },
                {
                    "blinded_node": _b64hex("02" + "22" * 32),
                    "encrypted_data": _b64hex("00" * 32),
                },
            ],
        },
        # Stale values: what LND's cache returned at mint time.
        "base_fee_msat": 1100,
        "proportional_fee_rate": 1206,
        "total_cltv_delta": 201,
        "htlc_min_msat": 1100,
        "htlc_max_msat": 133_650_000,
        "features": "",
    }
    channels = [
        {
            "remote_pubkey": intro_hex,
            "chan_id": "1042763633773182977",
            "remote_balance": 200_000,
            "gossiped_inbound_max_htlc_msat": 148_500_000,
        }
    ]

    fake_lnd = MagicMock()
    fake_lnd.get_channel_edge = AsyncMock(
        return_value=(
            {
                "node1_pub": intro_hex,
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
        )
    )

    out = await postprocess_blinded_paths(
        [path],
        amount_msat=4_238_000,
        lnd=fake_lnd,
        channels=channels,
        our_pubkey=ours,
        max_paths=8,
    )
    assert len(out.paths) == 1

    # Now go through the production serialization path.
    paths_bytes, blindedpay_bytes = encode_invoice_paths(out.paths)
    decoded = decode_invoice_paths(paths_bytes, blindedpay_bytes)
    assert len(decoded) == 1
    d = decoded[0]

    # The BOLT 12 invoice TLV (what the payer reads) carries the
    # POST-pipeline values: refresh→margin→clamp.
    # NOTE: the decoder normalises u64 fields to strings to match
    # LND's REST-JSON convention; u32 + u16 fields stay int.
    assert int(d["base_fee_msat"]) == 1000, "base_fee should be the refreshed gossip value (no base margin)"
    assert d["proportional_fee_rate"] == 6000, "ppm should be gossip 5000 + safety margin 1000"
    # htlc_max was refreshed 133.65M → 148.5M, then clamped to
    # 200_000 sat × (1 - 1%) = 198_000 sat = 198_000_000 msat
    # ceiling. Refreshed 148.5M is below the clamp ceiling, so the
    # refreshed value survives unmodified.
    assert int(d["htlc_max_msat"]) == 148_500_000
    assert int(d["htlc_min_msat"]) == 1000
    # CLTV is NEVER refreshed (path-aggregate vs per-hop) — passes
    # through unchanged.
    assert d["total_cltv_delta"] == 201
    # And the blinded path itself round-trips intact.
    inner = d["blinded_path"]
    import base64 as _b64

    assert _b64.b64decode(inner["introduction_node"]).hex() == intro_hex
    assert len(inner["blinded_hops"]) == 2


@pytest.mark.asyncio
async def test_pipeline_margin_runs_even_when_refresh_off(monkeypatch):
    """The margin is independent of the refresh: it pads whatever
    fee values LND returned (or refresh set, if enabled). Operator
    flipping refresh off must still get margin protection."""
    from app.core.config import settings

    monkeypatch.setattr(settings, "bolt12_drop_undersized_paths", False)
    monkeypatch.setattr(settings, "bolt12_path_diversity_enforce", False)
    monkeypatch.setattr(settings, "bolt12_path_breaker_enabled", False)
    monkeypatch.setattr(settings, "bolt12_probe_paths_before_mint", False)
    monkeypatch.setattr(
        settings,
        "bolt12_blinded_path_refresh_policy_from_gossip",
        False,  # refresh OFF
    )
    monkeypatch.setattr(
        settings,
        "bolt12_blinded_path_payinfo_safety_margin_ppm",
        1000,
    )
    monkeypatch.setattr(
        settings,
        "bolt12_blinded_path_payinfo_safety_margin_base_msat",
        0,
    )

    intro_hex = "02aa" + "00" * 31
    path = _make_path(
        intro_hex=intro_hex,
        real_hops=1,
        base_fee_msat=1100,
        ppm=1206,
    )

    fake_lnd = MagicMock()
    out = await postprocess_blinded_paths(
        [path],
        amount_msat=4_169_000,
        lnd=fake_lnd,
        channels=[
            {
                "remote_pubkey": intro_hex,
                "chan_id": "X",
                "remote_balance": 200_000,
            }
        ],
        our_pubkey="03" + "00" * 32,
        max_paths=8,
    )
    # ppm 1206 (no refresh) + 1000 margin = 2206
    assert out.paths[0]["proportional_fee_rate"] == 2206
    assert out.paths[0]["_safety_margin_ppm_applied"] == 1000


# ── drop undersized ─────────────────────────────


def test_path_meets_amount_rejects_undersized_htlc_max():
    p = {"htlc_max_msat": 3_000_000, "htlc_min_msat": 1000}
    assert path_meets_amount(p, amount_msat=3_345_000) is False


def test_path_meets_amount_accepts_exact_match():
    p = {"htlc_max_msat": 3_345_000, "htlc_min_msat": 1000}
    assert path_meets_amount(p, amount_msat=3_345_000) is True


def test_path_meets_amount_rejects_oversized_min():
    p = {"htlc_max_msat": 100_000_000, "htlc_min_msat": 5_000_000}
    assert path_meets_amount(p, amount_msat=3_345_000) is False


# ── diversity ───────────────────────────────────


def test_select_diverse_paths_one_per_intro_prefers_cheaper():
    """Two paths sharing an intro: keep the cheaper one. Two
    distinct intros: keep both."""
    p_a_cheap = _make_path(intro_hex="03ddffaa" + "00" * 27, base_fee_msat=1000, ppm=150)
    p_a_expensive = _make_path(intro_hex="03ddffaa" + "00" * 27, base_fee_msat=2000, ppm=200)
    p_b = _make_path(intro_hex="03ddffbb" + "00" * 27, base_fee_msat=1500, ppm=180)
    for p in (p_a_cheap, p_a_expensive, p_b):
        annotate_path_metadata(p)

    out = select_diverse_paths(
        [p_a_expensive, p_a_cheap, p_b],
        amount_msat=3_345_000,
        max_count=8,
    )
    assert len(out) == 2  # one per intro
    intros = {p["_intro_pubkey_hex"] for p in out}
    assert intros == {
        "03ddffaa" + "00" * 27,
        "03ddffbb" + "00" * 27,
    }
    # The kept intro_a path is the cheaper one.
    intro_a_kept = next(p for p in out if p["_intro_pubkey_hex"].startswith("03ddffaa"))
    assert intro_a_kept is p_a_cheap


def test_select_diverse_paths_respects_max_count():
    """If diverse intros > max_count, truncate by fee."""
    paths = [_make_path(intro_hex=f"030{i}" + "dd" + "00" * 28, base_fee_msat=1000 * i) for i in range(1, 6)]
    for p in paths:
        annotate_path_metadata(p)
    out = select_diverse_paths(paths, amount_msat=1_000_000, max_count=2)
    assert len(out) == 2
    # Cheapest 2: i=1 (1000 msat base) and i=2 (2000 msat base).
    fees = [p["base_fee_msat"] for p in out]
    assert fees == [1000, 2000]


# ── breaker ────────────────────────────────────


def test_breaker_opens_after_consecutive_failures(monkeypatch):
    """Default failures_to_open=2: first failure leaves closed,
    second opens the breaker."""
    from app.core.config import settings

    monkeypatch.setattr(settings, "bolt12_path_breaker_failures_to_open", 2)
    monkeypatch.setattr(settings, "bolt12_path_breaker_initial_cooldown_s", 600)

    b = PathBreakerRegistry()
    b.record_failure("intro_xyz")
    assert not b.is_open("intro_xyz")
    b.record_failure("intro_xyz")
    assert b.is_open("intro_xyz")


def test_breaker_closes_on_success_resets_history():
    """A successful settle fully resets the breaker state for
    this intro — failure count back to zero."""
    b = PathBreakerRegistry()
    b.record_failure("intro_xyz")
    b.record_failure("intro_xyz")
    assert b.is_open("intro_xyz")

    b.record_success("intro_xyz")
    assert not b.is_open("intro_xyz")
    # And subsequent first failure does NOT immediately reopen
    # (history was reset).
    b.record_failure("intro_xyz")
    assert not b.is_open("intro_xyz")


def test_breaker_half_open_after_cooldown(monkeypatch):
    """After the cooldown elapses, ``is_open`` transitions the
    state to half_open lazily and returns False (the path can be
    probed)."""
    import time

    from app.core.config import settings

    monkeypatch.setattr(settings, "bolt12_path_breaker_failures_to_open", 1)
    monkeypatch.setattr(settings, "bolt12_path_breaker_initial_cooldown_s", 60)

    b = PathBreakerRegistry()
    b.record_failure("intro_xyz")
    assert b.is_open("intro_xyz")

    # Fake "60 seconds later": is_open should return False AND
    # the state machine should be in half_open.
    base = time.monotonic()
    assert not b.is_open("intro_xyz", now=base + 120)
    snap = b.snapshot()
    assert snap["intro_xyz"]["state"] == "half_open"


def test_breaker_failure_during_half_open_reopens_with_doubled_cooldown(
    monkeypatch,
):
    """Half-open → failure → re-open with cooldown × 2 (capped)."""
    import time

    from app.core.config import settings

    monkeypatch.setattr(settings, "bolt12_path_breaker_failures_to_open", 1)
    monkeypatch.setattr(settings, "bolt12_path_breaker_initial_cooldown_s", 100)
    monkeypatch.setattr(settings, "bolt12_path_breaker_cooldown_cap_s", 86_400)

    b = PathBreakerRegistry()
    b.record_failure("intro_xyz")
    # Force into half_open via cooldown lookup.
    base = time.monotonic()
    b.is_open("intro_xyz", now=base + 200)
    # Now record another failure while half-open.
    b.record_failure("intro_xyz")
    snap = b.snapshot()
    assert snap["intro_xyz"]["state"] == "open"
    # Cooldown doubled.
    # The exact remaining depends on time, but it should be > 0
    # and close to the new cooldown of 200s (100 × 2).
    assert snap["intro_xyz"]["cooldown_s_remaining"] > 100


def test_apply_breaker_filter_reorders_does_not_drop(monkeypatch):
    """Deprioritised paths come LAST in the returned list. They
    are NOT excluded — better to advertise a marginal path than
    to silently drop the whole invoice."""
    from app.core.config import settings

    monkeypatch.setattr(settings, "bolt12_path_breaker_enabled", True)
    monkeypatch.setattr(settings, "bolt12_path_breaker_failures_to_open", 1)
    monkeypatch.setattr(settings, "bolt12_path_breaker_initial_cooldown_s", 600)

    b = get_path_breaker()
    b.reset_for_tests()
    b.record_failure("babbaa")

    p_bad = _make_path(intro_hex="babbaa")
    p_good = _make_path(intro_hex="a00daa")
    annotate_path_metadata(p_bad)
    annotate_path_metadata(p_good)
    p_bad["_intro_pubkey_hex"] = "babbaa"
    p_good["_intro_pubkey_hex"] = "a00daa"

    out = apply_breaker_filter([p_bad, p_good])
    assert len(out) == 2  # neither dropped
    assert out[0] is p_good  # good ones come first
    assert out[1] is p_bad

    b.reset_for_tests()


# ── Pipeline end-to-end ──────────────────────────────────────


@pytest.mark.asyncio
async def test_pipeline_refresh_then_clamp_uses_refreshed_htlc_max(monkeypatch):
    """End-to-end pipeline check: the
    refresh stage runs BEFORE the clamp, so the clamp's
    ``_htlc_max_msat_advertised`` captures the gossip-corrected
    value (not LND's stale one) and downstream consumers see the
    fresh fees in the summary.

    This pins the stage ordering: refresh → pigeonhole → clamp.
    """
    from app.core.config import settings

    monkeypatch.setattr(settings, "bolt12_drop_undersized_paths", False)
    monkeypatch.setattr(settings, "bolt12_path_diversity_enforce", False)
    monkeypatch.setattr(settings, "bolt12_path_breaker_enabled", False)
    monkeypatch.setattr(settings, "bolt12_probe_paths_before_mint", False)
    monkeypatch.setattr(
        settings,
        "bolt12_blinded_path_refresh_policy_from_gossip",
        True,
    )
    # Isolate this test from the margin stage — it pins the
    # refresh+clamp interaction. Margin behaviour has its own
    # dedicated test.
    monkeypatch.setattr(
        settings,
        "bolt12_blinded_path_payinfo_safety_margin_ppm",
        0,
    )
    monkeypatch.setattr(
        settings,
        "bolt12_blinded_path_payinfo_safety_margin_base_msat",
        0,
    )

    intro_hex = "02a98c86ef366ce2" + "00" * 25
    ours = "03000000" + "00" * 30

    # LND's stale view: ppm=1206, htlc_max=133.65M
    path = _make_path(
        intro_hex=intro_hex,
        real_hops=1,
        base_fee_msat=1100,
        ppm=1206,
        htlc_min_msat=1100,
        htlc_max_msat=133_650_000,
    )
    channels = [
        {
            "remote_pubkey": intro_hex,
            "chan_id": "1042763633773182977",
            "remote_balance": 200_000,  # plenty
            "gossiped_inbound_max_htlc_msat": 148_500_000,
        },
    ]

    fake_lnd = MagicMock()
    fake_lnd.get_channel_edge = AsyncMock(
        return_value=(
            {
                "node1_pub": intro_hex,
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
        )
    )

    out = await postprocess_blinded_paths(
        [path],
        amount_msat=4_132_000,
        lnd=fake_lnd,
        channels=channels,
        our_pubkey=ours,
        max_paths=8,
    )
    assert len(out.paths) == 1
    p = out.paths[0]
    # Fees refreshed BEFORE the BOLT 12 invoice would be serialised.
    assert p["base_fee_msat"] == 1000
    assert p["proportional_fee_rate"] == 5000
    assert p["htlc_min_msat"] == 1000
    # htlc_max was refreshed 133.65M → 148.5M, then clamp ran:
    # 200_000 sat * (1 - 1%) ≈ 198_000 sat = 198_000_000 msat.
    # Refreshed 148.5M < clamp ceiling, so the refreshed value wins.
    assert p["htlc_max_msat"] == 148_500_000
    # The clamp's "_htlc_max_msat_advertised" diagnostic captures
    # the POST-refresh value (what we actually advertised), not
    # LND's pre-refresh 133.65M.
    assert p["_htlc_max_msat_advertised"] == 148_500_000
    # Summary surfaces the encoded triplet that the watchdog
    # diagnostic will compare against gossip on a future failure.
    s = out.summary["paths"][0]
    assert s["encoded_base_fee_msat"] == 1000
    assert s["encoded_proportional_fee_rate"] == 5000
    assert s["htlc_max_msat_advertised"] == 148_500_000


@pytest.mark.asyncio
async def test_pipeline_refresh_disabled_by_setting(monkeypatch):
    """When the setting is off, LND's returned values pass through
    unchanged — operators retain the kill-switch."""
    from app.core.config import settings

    monkeypatch.setattr(settings, "bolt12_drop_undersized_paths", False)
    monkeypatch.setattr(settings, "bolt12_path_diversity_enforce", False)
    monkeypatch.setattr(settings, "bolt12_path_breaker_enabled", False)
    monkeypatch.setattr(settings, "bolt12_probe_paths_before_mint", False)
    monkeypatch.setattr(
        settings,
        "bolt12_blinded_path_refresh_policy_from_gossip",
        False,
    )
    # Isolate from the margin stage — this test pins ONLY the
    # refresh kill-switch.
    monkeypatch.setattr(
        settings,
        "bolt12_blinded_path_payinfo_safety_margin_ppm",
        0,
    )
    monkeypatch.setattr(
        settings,
        "bolt12_blinded_path_payinfo_safety_margin_base_msat",
        0,
    )

    intro_hex = "02a98c86ef366ce2" + "00" * 25
    ours = "03000000" + "00" * 30

    path = _make_path(
        intro_hex=intro_hex,
        real_hops=1,
        base_fee_msat=1100,
        ppm=1206,
    )
    channels = [
        {
            "remote_pubkey": intro_hex,
            "chan_id": "X",
            "remote_balance": 200_000,
            "gossiped_inbound_max_htlc_msat": 148_500_000,
        }
    ]

    fake_lnd = MagicMock()
    # Refresh disabled → get_channel_edge must NOT be called.
    fake_lnd.get_channel_edge = AsyncMock(
        side_effect=AssertionError("refresh kill-switch broken"),
    )

    out = await postprocess_blinded_paths(
        [path],
        amount_msat=4_132_000,
        lnd=fake_lnd,
        channels=channels,
        our_pubkey=ours,
        max_paths=8,
    )
    assert out.paths[0]["proportional_fee_rate"] == 1206


@pytest.mark.asyncio
async def test_pipeline_clamps_drops_undersized_and_dedupes_intros(monkeypatch):
    """Three paths in, fully postprocessed: one is undersized
    (dropped), two share an intro (deduped), one diverse path
    remains for each unique intro."""
    from app.core.config import settings

    monkeypatch.setattr(settings, "bolt12_drop_undersized_paths", True)
    monkeypatch.setattr(settings, "bolt12_path_diversity_enforce", True)
    monkeypatch.setattr(settings, "bolt12_path_breaker_enabled", False)
    monkeypatch.setattr(settings, "bolt12_probe_paths_before_mint", False)
    # Pin margins to 0 so this test focuses on clamp + drop +
    # diversity; margin behaviour is covered by dedicated tests.
    monkeypatch.setattr(
        settings,
        "bolt12_blinded_path_payinfo_safety_margin_ppm",
        0,
    )
    monkeypatch.setattr(
        settings,
        "bolt12_blinded_path_payinfo_safety_margin_base_msat",
        0,
    )

    # Path 0: clamped to 19800000 msat (under-sized for 30M request → dropped)
    # Path 1: clamped to 111334000 msat → kept (cheaper of intro_a's two)
    # Path 2: through intro_a (more expensive) — dropped by diversity
    paths = [
        _make_path(intro_hex="03eeffaa" + "00" * 23, real_hops=1, htlc_max_msat=50_000_000),
        _make_path(intro_hex="03ddffaa" + "00" * 27, real_hops=2, htlc_max_msat=150_000_000, base_fee_msat=1000),
        _make_path(intro_hex="03ddffaa" + "00" * 27, real_hops=2, htlc_max_msat=150_000_000, base_fee_msat=5000),
    ]
    channels = [
        {
            "remote_pubkey": "03eeffaa" + "00" * 23,
            "remote_balance": 20000,
            "gossiped_inbound_max_htlc_msat": 50_000_000,
        },
        {
            "remote_pubkey": "03bbbbbb" + "00" * 28,
            "remote_balance": 112459,
            "gossiped_inbound_max_htlc_msat": 150_000_000,
        },
    ]

    fake_lnd = MagicMock()
    out = await postprocess_blinded_paths(
        paths,
        amount_msat=30_000_000,  # 30k sat
        lnd=fake_lnd,
        channels=channels,
        our_pubkey="03000000" + "00" * 30,
        max_paths=8,
    )
    # The 50M-advertised path clamps to 20000*0.99 = 19800 sat = 19800000 msat
    # which is < 30M request → dropped.
    # The two paths sharing intro_a → deduped to the cheaper one.
    assert len(out.paths) == 1
    assert out.paths[0]["_intro_pubkey_hex"] == "03ddffaa" + "00" * 27
    assert out.paths[0]["base_fee_msat"] == 1000
    # Summary populated for the surviving path.
    assert len(out.summary["paths"]) == 1
    assert out.summary["paths"][0]["htlc_max_msat_clamped"] > 30_000_000


@pytest.mark.asyncio
async def test_pipeline_never_blocks_mint_on_failure(monkeypatch):
    """If the pipeline blows up internally, the responder
    fallback returns the raw paths. The pipeline should never
    bubble an exception into the mint hot path."""
    from app.core.config import settings

    monkeypatch.setattr(settings, "bolt12_drop_undersized_paths", True)

    # Pass a clearly-malformed channels list. The pipeline still
    # finishes (best-effort), but the clamp falls back to a
    # bare clamp (no channel matched).
    paths = [_make_path(intro_hex="03dd" + "00" * 30)]
    fake_lnd = MagicMock()
    out = await postprocess_blinded_paths(
        paths,
        amount_msat=1000,
        lnd=fake_lnd,
        channels=[],
        our_pubkey="",
        max_paths=8,
    )
    # At least one path made it through.
    assert out.paths


# ── build_paths_summary shape ────────────────────────────────


# ── Pigeonhole pairing ────────────────────────────────────────


def test_pigeonhole_pairs_2_paths_to_2_channels_by_fee_and_balance(monkeypatch):
    """Two-path / two-channel topology:
    Path 0 (cheap, 1101 base_fee) ↔ small channel (17,049 sat).
    Path 1 (expensive, 2202 base_fee) ↔ big channel (112,459 sat).
    After pairing, clamp can correctly identify each path's
    terminal channel and clamp accurately."""
    from app.core.config import settings

    monkeypatch.setattr(settings, "bolt12_path_pigeonhole_pairing_enabled", True)

    p_cheap = _make_path(
        intro_hex="03aa00aa" + "00" * 28,
        real_hops=2,
        base_fee_msat=1101,
        ppm=2423,
        htlc_max_msat=60_000_000,
    )
    p_exp = _make_path(
        intro_hex="03bb00bb" + "00" * 28,
        real_hops=2,
        base_fee_msat=2202,
        ppm=2308,
        htlc_max_msat=133_650_000,
    )
    annotate_path_metadata(p_cheap)
    annotate_path_metadata(p_exp)

    channels = [
        {
            "chan_id": "small_ch",
            "remote_pubkey": "031cec00" + "00" * 28,
            "remote_balance": 20000,
            "active": True,
            "gossiped_inbound_max_htlc_msat": 59_400_000,
        },
        {
            "chan_id": "big_ch",
            "remote_pubkey": "02a98c00" + "00" * 28,
            "remote_balance": 112459,
            "active": True,
            "gossiped_inbound_max_htlc_msat": 148_500_000,
        },
    ]

    _pigeonhole_pair_paths_to_channels(
        [p_cheap, p_exp],
        channels,
        amount_msat=3_345_000,
    )
    assert p_cheap["_presumed_terminal_channel"]["chan_id"] == "small_ch"
    assert p_exp["_presumed_terminal_channel"]["chan_id"] == "big_ch"


def test_pigeonhole_no_op_when_counts_mismatch(monkeypatch):
    """1 path + 2 channels OR 3 paths + 2 channels → no pairing.
    Falls back to strategies B/C in _identify_terminal_channel."""
    from app.core.config import settings

    monkeypatch.setattr(settings, "bolt12_path_pigeonhole_pairing_enabled", True)

    p = _make_path(intro_hex="03aa00aa" + "00" * 28, real_hops=2)
    annotate_path_metadata(p)

    channels = [
        {
            "chan_id": "c1",
            "remote_pubkey": "031cec00" + "00" * 28,
            "remote_balance": 20000,
            "active": True,
        },
        {
            "chan_id": "c2",
            "remote_pubkey": "02a98c00" + "00" * 28,
            "remote_balance": 112459,
            "active": True,
        },
    ]
    _pigeonhole_pair_paths_to_channels([p], channels, amount_msat=3_345_000)
    assert "_presumed_terminal_channel" not in p


def test_pigeonhole_ignores_inactive_channels(monkeypatch):
    """Inactive channels are excluded from the pairing pool. If
    only N-1 channels are active and there are N paths, no
    pairing fires."""
    from app.core.config import settings

    monkeypatch.setattr(settings, "bolt12_path_pigeonhole_pairing_enabled", True)

    p0 = _make_path(intro_hex="03aa00aa" + "00" * 28, base_fee_msat=1000)
    p1 = _make_path(intro_hex="03bb00bb" + "00" * 28, base_fee_msat=2000)
    annotate_path_metadata(p0)
    annotate_path_metadata(p1)

    channels = [
        {
            "chan_id": "c_inactive",
            "remote_pubkey": "031cec00" + "00" * 28,
            "remote_balance": 20000,
            "active": False,
        },
        {
            "chan_id": "c_active",
            "remote_pubkey": "02a98c00" + "00" * 28,
            "remote_balance": 112459,
            "active": True,
        },
    ]
    _pigeonhole_pair_paths_to_channels(
        [p0, p1],
        channels,
        amount_msat=3_345_000,
    )
    # 2 paths, 1 active channel → no pairing.
    assert "_presumed_terminal_channel" not in p0
    assert "_presumed_terminal_channel" not in p1


def test_pigeonhole_disabled_setting_skips_pairing(monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "bolt12_path_pigeonhole_pairing_enabled", False)

    p0 = _make_path(intro_hex="03aa00aa" + "00" * 28, base_fee_msat=1000)
    annotate_path_metadata(p0)
    channels = [
        {
            "chan_id": "c1",
            "remote_pubkey": "031cec00" + "00" * 28,
            "remote_balance": 20000,
            "active": True,
        },
    ]
    _pigeonhole_pair_paths_to_channels([p0], channels, amount_msat=1000)
    assert "_presumed_terminal_channel" not in p0


def test_all_intros_open_returns_false_for_empty_list():
    """Empty path list → False ("nothing's known-bad", not "all bad").
    The adaptive-depth fallback relies on this to NOT trigger when
    the primary mint produced no paths at all."""
    from app.services.bolt12.path_postprocess import all_intros_open

    assert all_intros_open([]) is False


def test_all_intros_open_returns_true_when_all_intros_opened(monkeypatch):
    """When every path's intro is in the breaker's open state,
    the helper returns True. This drives Option B-adaptive's
    decision to retry at the alternative depth."""
    from app.core.config import settings
    from app.services.bolt12.path_postprocess import (
        all_intros_open,
        get_path_breaker,
    )

    monkeypatch.setattr(settings, "bolt12_path_breaker_enabled", True)
    monkeypatch.setattr(settings, "bolt12_path_breaker_failures_to_open", 1)

    breaker = get_path_breaker()
    breaker.reset_for_tests()
    breaker.record_failure("intro_aaa")
    breaker.record_failure("intro_bbb")

    paths = [
        {"_intro_pubkey_hex": "intro_aaa"},
        {"_intro_pubkey_hex": "intro_bbb"},
    ]
    assert all_intros_open(paths) is True

    # Mixed open + closed → not all open.
    paths_mixed = [
        {"_intro_pubkey_hex": "intro_aaa"},
        {"_intro_pubkey_hex": "intro_ccc"},  # never failed
    ]
    assert all_intros_open(paths_mixed) is False

    breaker.reset_for_tests()


def test_all_intros_open_false_when_breaker_disabled(monkeypatch):
    """Operators who disable the breaker via setting should
    not get adaptive-depth fallback either; the helper returns
    False so the responder stays at primary depth."""
    from app.core.config import settings
    from app.services.bolt12.path_postprocess import (
        all_intros_open,
        get_path_breaker,
    )

    breaker = get_path_breaker()
    breaker.reset_for_tests()
    breaker.record_failure("intro_aaa")
    breaker.record_failure("intro_aaa")

    monkeypatch.setattr(settings, "bolt12_path_breaker_enabled", False)
    assert all_intros_open([{"_intro_pubkey_hex": "intro_aaa"}]) is False
    breaker.reset_for_tests()


def test_pigeonhole_skips_real_hops_1_paths_strategy_b_wins(monkeypatch):
    """When a path is ``real_hops==1`` AND intro IS one of our
    peers, the intro is the terminal hop and Strategy B can
    identify it directly. Pigeonhole must NOT pre-stamp a wrong
    channel that would override Strategy B's accurate match.

    Topology: 2 paths with real_hops=1, intros mapping to our 2
    direct peers. Pigeonhole must skip both, letting Strategy B
    identify each path's terminal as the intro's own channel."""
    from app.core.config import settings

    monkeypatch.setattr(settings, "bolt12_path_pigeonhole_pairing_enabled", True)

    # Path 0: intro=big channel; path 1: intro=small channel.
    p_meg_intro = _make_path(
        intro_hex="02a98c00" + "00" * 28,
        real_hops=1,
        base_fee_msat=1000,
        ppm=100,
        htlc_max_msat=133_650_000,
    )
    p_pcode_intro = _make_path(
        intro_hex="031cec00" + "00" * 28,
        real_hops=1,
        base_fee_msat=2000,
        ppm=200,
        htlc_max_msat=60_000_000,
    )
    annotate_path_metadata(p_meg_intro)
    annotate_path_metadata(p_pcode_intro)

    channels = [
        {
            "chan_id": "ch_pcode",
            "remote_pubkey": "031cec00" + "00" * 28,
            "remote_balance": 20000,
            "active": True,
            "gossiped_inbound_max_htlc_msat": 59_400_000,
        },
        {
            "chan_id": "ch_meg",
            "remote_pubkey": "02a98c00" + "00" * 28,
            "remote_balance": 112459,
            "active": True,
            "gossiped_inbound_max_htlc_msat": 148_500_000,
        },
    ]

    _pigeonhole_pair_paths_to_channels(
        [p_meg_intro, p_pcode_intro],
        channels,
        amount_msat=3_354_000,
    )
    # Pigeonhole should NOT have stamped either path — Strategy B
    # will handle them.
    assert "_presumed_terminal_channel" not in p_meg_intro
    assert "_presumed_terminal_channel" not in p_pcode_intro

    # Now run clamp and verify Strategy B picks the intro's own
    # channel for each path.
    for p in (p_meg_intro, p_pcode_intro):
        clamp_path_htlc_max(
            p,
            channels,
            our_pubkey="03ff" + "00" * 30,
            safety_buffer_ppm=10_000,
        )
    # Path with big-channel intro → terminal=big channel
    # 112459 - 1124 = 111335 sat → bucketed down to 111_000_000 msat
    assert p_meg_intro["_terminal_peer_pubkey"] == "02a98c00" + "00" * 28
    assert p_meg_intro["htlc_max_msat"] == 111_000_000

    # Path with small-channel intro → terminal=small channel
    # 20000 - 200 = 19800 sat → bucketed down to 19_000_000 msat
    assert p_pcode_intro["_terminal_peer_pubkey"] == "031cec00" + "00" * 28
    assert p_pcode_intro["htlc_max_msat"] == 19_000_000


def test_pigeonhole_then_clamp_pins_2026_06_06_topology(monkeypatch):
    """End-to-end: pigeonhole pairs each path, then clamp uses
    Strategy A to clamp accurately. Path 0 advertised 60,000 sat
    gets clamped to the small channel's ~19,800 sat."""
    from app.core.config import settings

    monkeypatch.setattr(settings, "bolt12_path_pigeonhole_pairing_enabled", True)

    p_cheap = _make_path(
        intro_hex="03aa00aa" + "00" * 28,
        real_hops=2,
        base_fee_msat=1101,
        ppm=2423,
        htlc_max_msat=60_000_000,
    )
    p_exp = _make_path(
        intro_hex="03bb00bb" + "00" * 28,
        real_hops=2,
        base_fee_msat=2202,
        ppm=2308,
        htlc_max_msat=133_650_000,
    )
    annotate_path_metadata(p_cheap)
    annotate_path_metadata(p_exp)

    channels = [
        {
            "chan_id": "small_ch",
            "remote_pubkey": "031cec00" + "00" * 28,
            "remote_balance": 20000,
            "active": True,
            "gossiped_inbound_max_htlc_msat": 59_400_000,
        },
        {
            "chan_id": "big_ch",
            "remote_pubkey": "02a98c00" + "00" * 28,
            "remote_balance": 112459,
            "active": True,
            "gossiped_inbound_max_htlc_msat": 148_500_000,
        },
    ]

    _pigeonhole_pair_paths_to_channels(
        [p_cheap, p_exp],
        channels,
        amount_msat=3_345_000,
    )
    for p in (p_cheap, p_exp):
        clamp_path_htlc_max(
            p,
            channels,
            our_pubkey="03ff" + "00" * 30,
            safety_buffer_ppm=10_000,
        )

    # Path 0 (cheap, paired to small_ch with 20000 sat) clamped:
    # 20000 - 200 = 19800 sat = 19,800,000 msat, bucketed down to 19_000_000.
    assert p_cheap["htlc_max_msat"] == 19_000_000
    assert p_cheap["_htlc_max_msat_advertised"] == 60_000_000
    assert p_cheap["_terminal_peer_pubkey"] == "031cec00" + "00" * 28

    # Path 1 (expensive, paired to big_ch with 112459 sat) clamped:
    # 112459 - 1124 = 111335 sat = 111,335,000 msat, bucketed down to 111_000_000.
    assert p_exp["htlc_max_msat"] == 111_000_000
    assert p_exp["_htlc_max_msat_advertised"] == 133_650_000
    assert p_exp["_terminal_peer_pubkey"] == "02a98c00" + "00" * 28


@pytest.mark.asyncio
async def test_pipeline_returns_empty_when_drop_filters_all(monkeypatch):
    """When every path's clamped htlc_max is below the requested
    amount, the pipeline returns an empty path list. The
    responder's wrapper detects this and reverts to raw — but
    the pipeline itself correctly reports zero paths."""
    from app.core.config import settings

    monkeypatch.setattr(settings, "bolt12_drop_undersized_paths", True)
    monkeypatch.setattr(settings, "bolt12_path_diversity_enforce", False)
    monkeypatch.setattr(settings, "bolt12_path_breaker_enabled", False)
    monkeypatch.setattr(settings, "bolt12_probe_paths_before_mint", False)

    # Single tiny channel; advertised 50M, clamped to ~17M.
    paths = [
        _make_path(
            intro_hex="03aaaaaa" + "00" * 28,
            real_hops=1,
            htlc_max_msat=50_000_000,
        ),
    ]
    channels = [
        {
            "remote_pubkey": "03aaaaaa" + "00" * 28,
            "remote_balance": 20000,
            "gossiped_inbound_max_htlc_msat": 50_000_000,
        },
    ]
    fake_lnd = MagicMock()

    out = await postprocess_blinded_paths(
        paths,
        amount_msat=30_000_000,  # 30k sat — bigger than clamped cap
        lnd=fake_lnd,
        channels=channels,
        our_pubkey="03000000" + "00" * 30,
        max_paths=8,
    )
    # All paths dropped — pipeline correctly reports zero.
    assert out.paths == []
    assert out.summary["paths"] == []
    # drops diagnostic reflects the filter chain.
    assert out.drops["starting"] == 1
    assert out.drops["after_undersized_drop"] == 0


def test_breaker_half_open_single_probe_concurrent_safety(monkeypatch):
    """One half-open intro receives one probationary probe;
    concurrent mints arriving before the probe resolves see the
    intro as open (deprioritised). This prevents N parallel
    mints from all using a still-suspect intro."""
    import time

    from app.core.config import settings

    monkeypatch.setattr(settings, "bolt12_path_breaker_failures_to_open", 1)
    monkeypatch.setattr(settings, "bolt12_path_breaker_initial_cooldown_s", 100)

    b = PathBreakerRegistry()
    b.record_failure("intro_xyz")
    base = time.monotonic()

    # First check after cooldown — claims the probe.
    first = b.is_open("intro_xyz", now=base + 200)
    assert first is False  # the probationary probe goes through

    # Second concurrent check before record_failure / _success
    # comes back — must see "open" so this mint deprioritises.
    second = b.is_open("intro_xyz", now=base + 201)
    assert second is True

    # When record_success comes back, the latch clears and the
    # breaker fully closes.
    b.record_success("intro_xyz")
    assert b.is_open("intro_xyz") is False
    snap = b.snapshot()
    assert snap["intro_xyz"]["state"] == "closed"


def test_breaker_half_open_latch_clears_on_failure_too(monkeypatch):
    """If the probationary probe FAILS (record_failure called),
    the latch clears and the breaker re-opens with doubled
    cooldown — but a future cooldown-elapse-then-probe cycle
    still works."""
    import time

    from app.core.config import settings

    monkeypatch.setattr(settings, "bolt12_path_breaker_failures_to_open", 1)
    monkeypatch.setattr(settings, "bolt12_path_breaker_initial_cooldown_s", 100)
    monkeypatch.setattr(settings, "bolt12_path_breaker_cooldown_cap_s", 86_400)

    b = PathBreakerRegistry()
    b.record_failure("intro_xyz")
    base = time.monotonic()

    # Cooldown elapses → probe claimed.
    b.is_open("intro_xyz", now=base + 200)
    snap = b.snapshot()
    assert snap["intro_xyz"]["probationary_probe_in_flight"] is True

    # Probe fails → re-opens with doubled cooldown, latch
    # cleared.
    b.record_failure("intro_xyz")
    snap = b.snapshot()
    assert snap["intro_xyz"]["state"] == "open"
    assert snap["intro_xyz"]["probationary_probe_in_flight"] is False


def test_build_paths_summary_includes_clamp_diagnostic_fields():
    path = _make_path(intro_hex="03dd" + "00" * 30, htlc_max_msat=50_000_000)
    annotate_path_metadata(path)
    path["_htlc_max_msat_advertised"] = 50_000_000
    path["htlc_max_msat"] = 16_878_000
    path["_terminal_peer_pubkey"] = "03ee" + "00" * 30

    out = build_paths_summary([path])
    assert out["paths"][0]["intro_pubkey"] == "03dd" + "00" * 30
    assert out["paths"][0]["htlc_max_msat_advertised"] == 50_000_000
    assert out["paths"][0]["htlc_max_msat_clamped"] == 16_878_000
    assert out["paths"][0]["terminal_peer_pubkey"] == "03ee" + "00" * 30
