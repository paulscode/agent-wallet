# SPDX-License-Identifier: MIT
"""items 18, 45, 54, 81 — cooperative-claim helpers.

Coverage:
* :func:`await_cooperative_signature` — bounded retry, raises
  :class:`CooperativeSignatureTimeoutError` on budget exhaustion.
* :func:`assert_claim_feerate_sane` — accepts in-band, refuses outliers.
* :func:`validate_cooperative_claim_tx` — round-trip a hand-built
  compliant tx; flip individual fields to verify each violation path.
* :func:`mpp_caps_tier_at_weak` — K=1-fallback predicate.
"""

from __future__ import annotations

import asyncio

import pytest

from app.core.config import settings
from app.services.anonymize.cooperative_claim import (
    ClaimTxValidationError,
    CooperativeSignatureTimeoutError,
    MppFallbackOutcome,
    assert_claim_feerate_sane,
    await_cooperative_signature,
    mpp_caps_tier_at_weak,
    validate_cooperative_claim_tx,
)

# ── item 18 — coop-sig timeout helper ─────────────────────────────


@pytest.mark.asyncio
async def test_await_cooperative_signature_returns_on_first_success() -> None:
    async def _ok() -> str:
        return "partial-sig-bytes"

    out = await await_cooperative_signature(_ok, timeout_s=1.0, max_attempts=3)
    assert out == "partial-sig-bytes"


@pytest.mark.asyncio
async def test_await_cooperative_signature_retries_then_succeeds() -> None:
    attempts = {"n": 0}

    async def _flaky() -> str:
        attempts["n"] += 1
        if attempts["n"] < 3:
            raise RuntimeError("circuit broke")
        return "ok"

    out = await await_cooperative_signature(_flaky, timeout_s=1.0, max_attempts=3)
    assert out == "ok"
    assert attempts["n"] == 3


@pytest.mark.asyncio
async def test_await_cooperative_signature_raises_on_budget_exhaustion() -> None:
    async def _always_timeout() -> str:
        await asyncio.sleep(10)
        return "never"

    with pytest.raises(CooperativeSignatureTimeoutError, match="3 attempts"):
        await await_cooperative_signature(_always_timeout, timeout_s=0.05, max_attempts=3)


@pytest.mark.asyncio
async def test_await_cooperative_signature_invokes_failure_hook() -> None:
    failures = []

    async def _bad() -> str:
        raise RuntimeError("oops")

    def _on_fail(n, exc):
        failures.append((n, type(exc).__name__))

    with pytest.raises(CooperativeSignatureTimeoutError):
        await await_cooperative_signature(_bad, timeout_s=1.0, max_attempts=2, on_attempt_failure=_on_fail)
    assert failures == [(1, "RuntimeError"), (2, "RuntimeError")]


# ── item 81 — feerate sanity gate ─────────────────────────────────


def test_feerate_sane_accepts_inside_band(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_claim_feerate_tolerance_lo", 0.6)
    monkeypatch.setattr(settings, "anonymize_claim_feerate_tolerance_hi", 1.5)
    out = assert_claim_feerate_sane(
        operator_id="op-a",
        quoted_sat_per_vb=10.0,
        economy_sat_per_vb=10.0,
    )
    assert out.accepted is True
    assert out.reason is None


def test_feerate_sane_rejects_below_floor(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_claim_feerate_tolerance_lo", 0.6)
    monkeypatch.setattr(settings, "anonymize_claim_feerate_tolerance_hi", 1.5)
    out = assert_claim_feerate_sane(
        operator_id="op-a",
        quoted_sat_per_vb=4.0,
        economy_sat_per_vb=10.0,
    )
    assert out.accepted is False
    assert "outside sanity band" in (out.reason or "")
    assert out.lower_bound == pytest.approx(6.0)
    assert out.upper_bound == pytest.approx(15.0)


def test_feerate_sane_rejects_above_ceiling(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_claim_feerate_tolerance_lo", 0.6)
    monkeypatch.setattr(settings, "anonymize_claim_feerate_tolerance_hi", 1.5)
    out = assert_claim_feerate_sane(
        operator_id="op-a",
        quoted_sat_per_vb=20.0,
        economy_sat_per_vb=10.0,
    )
    assert out.accepted is False


# ── item 54 — MPP-K cap ───────────────────────────────────────────


def test_mpp_caps_at_weak_when_fallback_to_k1() -> None:
    assert mpp_caps_tier_at_weak(MppFallbackOutcome(requested_k=3, executed_k=1))
    assert mpp_caps_tier_at_weak(MppFallbackOutcome(requested_k=2, executed_k=1))


def test_mpp_does_not_cap_when_executed_matches_requested() -> None:
    assert not mpp_caps_tier_at_weak(MppFallbackOutcome(requested_k=3, executed_k=3))


def test_mpp_does_not_cap_when_requested_was_one() -> None:
    """A deliberate K=1 (not a fallback) is fine."""
    assert not mpp_caps_tier_at_weak(MppFallbackOutcome(requested_k=1, executed_k=1))


# ── item 45 — claim-tx validator ─────────────────────────────────


def _build_valid_claim_tx(
    *,
    output_value_sat: int = 249_400,
    spk_hex: str = "5120" + "00" * 32,  # P2TR push (0x51 + 0x20 + 32 bytes)
    n_locktime: int = 0,
    n_inputs: int = 1,
    n_outputs: int = 1,
    n_sequence: int = 0xFFFFFFFD,
    n_version: int = 2,
) -> str:
    spk = bytes.fromhex(spk_hex)
    tx = b""
    tx += n_version.to_bytes(4, "little")
    # Legacy serialization (no witness marker) for simplicity.
    tx += bytes([n_inputs])
    for _ in range(n_inputs):
        tx += b"\x00" * 32
        tx += (0).to_bytes(4, "little")
        tx += b"\x00"  # script_sig length 0
        tx += n_sequence.to_bytes(4, "little")
    tx += bytes([n_outputs])
    for _ in range(n_outputs):
        tx += output_value_sat.to_bytes(8, "little")
        tx += bytes([len(spk)])
        tx += spk
    tx += n_locktime.to_bytes(4, "little")
    return tx.hex()


_DEST_SPK_HEX = "5120" + "00" * 32  # canonical P2TR-shaped script
_DEST_BAND = (249_000, 250_000)


def test_validator_accepts_compliant_claim_tx() -> None:
    tx = _build_valid_claim_tx(output_value_sat=249_400, spk_hex=_DEST_SPK_HEX)
    validate_cooperative_claim_tx(
        tx_hex=tx,
        expected_output_script_hex=_DEST_SPK_HEX,
        expected_output_band_sat=_DEST_BAND,
    )


def test_validator_rejects_wrong_output_script() -> None:
    tx = _build_valid_claim_tx(spk_hex="0014" + "11" * 20)  # P2WPKH instead of P2TR
    with pytest.raises(ClaimTxValidationError, match="scriptPubKey"):
        validate_cooperative_claim_tx(
            tx_hex=tx,
            expected_output_script_hex=_DEST_SPK_HEX,
            expected_output_band_sat=_DEST_BAND,
        )


def test_validator_rejects_output_outside_band() -> None:
    tx = _build_valid_claim_tx(output_value_sat=100, spk_hex=_DEST_SPK_HEX)
    with pytest.raises(ClaimTxValidationError, match="outside band"):
        validate_cooperative_claim_tx(
            tx_hex=tx,
            expected_output_script_hex=_DEST_SPK_HEX,
            expected_output_band_sat=_DEST_BAND,
        )


def test_validator_rejects_multi_input() -> None:
    tx = _build_valid_claim_tx(n_inputs=2, spk_hex=_DEST_SPK_HEX)
    with pytest.raises(ClaimTxValidationError, match="exactly 1 input"):
        validate_cooperative_claim_tx(
            tx_hex=tx,
            expected_output_script_hex=_DEST_SPK_HEX,
            expected_output_band_sat=_DEST_BAND,
        )


def test_validator_rejects_multi_output() -> None:
    tx = _build_valid_claim_tx(n_outputs=2, spk_hex=_DEST_SPK_HEX)
    with pytest.raises(ClaimTxValidationError, match="exactly 1 output"):
        validate_cooperative_claim_tx(
            tx_hex=tx,
            expected_output_script_hex=_DEST_SPK_HEX,
            expected_output_band_sat=_DEST_BAND,
        )


def test_validator_rejects_wrong_n_sequence() -> None:
    tx = _build_valid_claim_tx(n_sequence=0xFFFFFFFE, spk_hex=_DEST_SPK_HEX)
    with pytest.raises(ClaimTxValidationError, match="envelope policy"):
        validate_cooperative_claim_tx(
            tx_hex=tx,
            expected_output_script_hex=_DEST_SPK_HEX,
            expected_output_band_sat=_DEST_BAND,
        )


def test_validator_enforces_locktime_when_provided() -> None:
    tx = _build_valid_claim_tx(n_locktime=12345, spk_hex=_DEST_SPK_HEX)
    with pytest.raises(ClaimTxValidationError, match="envelope policy"):
        validate_cooperative_claim_tx(
            tx_hex=tx,
            expected_output_script_hex=_DEST_SPK_HEX,
            expected_output_band_sat=_DEST_BAND,
            expected_n_locktime=99999,
        )


# ── MPP-K resolver + min_executed_chunks helpers ────────────────


def test_resolve_mpp_k_reads_frozen_pipeline_value() -> None:
    """Reverse-leg routing reads K via this single helper, never directly."""
    from app.services.anonymize.cooperative_claim import resolve_mpp_k

    assert resolve_mpp_k({"reverse_payment_chunks_k_requested": 4}) == 4


def test_resolve_mpp_k_defaults_to_one_for_legacy_session() -> None:
    """A pre-K-freeze session pipeline returns K=1 so routing does not stall."""
    from app.services.anonymize.cooperative_claim import resolve_mpp_k

    assert resolve_mpp_k({}) == 1
    assert resolve_mpp_k({"other_field": "x"}) == 1


def test_resolve_mpp_k_none_pipeline_returns_one() -> None:
    from app.services.anonymize.cooperative_claim import resolve_mpp_k

    assert resolve_mpp_k(None) == 1


def test_resolve_mpp_k_rejects_bad_types_with_safe_fallback() -> None:
    """Garbage value coerces to 1 rather than raising at the route call site."""
    from app.services.anonymize.cooperative_claim import resolve_mpp_k

    assert resolve_mpp_k({"reverse_payment_chunks_k_requested": "garbage"}) == 1
    assert resolve_mpp_k({"reverse_payment_chunks_k_requested": -5}) == 1


def test_resolve_mpp_k_clamps_zero_to_one() -> None:
    from app.services.anonymize.cooperative_claim import resolve_mpp_k

    assert resolve_mpp_k({"reverse_payment_chunks_k_requested": 0}) == 1


def test_min_executed_chunks_strong_demands_full_range_max(monkeypatch) -> None:
    from app.services.anonymize.cooperative_claim import (
        min_executed_chunks_for_target_tier,
    )

    monkeypatch.setattr(settings, "anonymize_reverse_mpp_chunks_range_max", 4)
    assert min_executed_chunks_for_target_tier("strong") == 4


def test_min_executed_chunks_moderate_floors_at_two(monkeypatch) -> None:
    """Moderate needs ≥ 2 chunks (K=1 fallback caps at weak)."""
    from app.services.anonymize.cooperative_claim import (
        min_executed_chunks_for_target_tier,
    )

    monkeypatch.setattr(settings, "anonymize_reverse_mpp_k_min_executed", 1)
    assert min_executed_chunks_for_target_tier("moderate") == 2
    monkeypatch.setattr(settings, "anonymize_reverse_mpp_k_min_executed", 3)
    assert min_executed_chunks_for_target_tier("moderate") == 3


def test_min_executed_chunks_weak_admits_one() -> None:
    from app.services.anonymize.cooperative_claim import (
        min_executed_chunks_for_target_tier,
    )

    assert min_executed_chunks_for_target_tier("weak") == 1
