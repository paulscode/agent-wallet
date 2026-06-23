# SPDX-License-Identifier: MIT
"""Ext-onchain deposit address + amount-lock + dwell timer."""

from __future__ import annotations

import time

import pytest

from app.core.config import settings
from app.services.anonymize.ext_onchain_deposit import (
    is_deposit_amount_locked,
    is_dwell_elapsed,
    issue_ext_onchain_deposit_address,
)

# ── address binding ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_issue_address_binds_inputs_into_instruction() -> None:
    out = await issue_ext_onchain_deposit_address(
        bin_amount_sat=250_000,
        expiry_unix_s=1_000.0,
        derivation_index=42,
        address="bcrt1ptest",
    )
    assert out.amount_sat == 250_000
    assert out.expiry_unix_s == 1_000.0
    assert out.derivation_index == 42
    assert out.address == "bcrt1ptest"


@pytest.mark.asyncio
async def test_issue_address_rejects_non_positive_amount() -> None:
    with pytest.raises(ValueError):
        await issue_ext_onchain_deposit_address(
            bin_amount_sat=0,
            expiry_unix_s=1_000.0,
            derivation_index=0,
            address="bcrt1ptest",
        )


@pytest.mark.asyncio
async def test_issue_address_rejects_empty_address() -> None:
    with pytest.raises(ValueError):
        await issue_ext_onchain_deposit_address(
            bin_amount_sat=250_000,
            expiry_unix_s=1_000.0,
            derivation_index=0,
            address="",
        )


# ── amount lock ─────────────────────────────────────────────────────


def test_amount_lock_accepts_exact_match() -> None:
    assert (
        is_deposit_amount_locked(
            deposited_sat=250_000,
            expected_bin_amount_sat=250_000,
        )
        is True
    )


def test_amount_lock_rejects_off_by_one_at_zero_tolerance() -> None:
    assert (
        is_deposit_amount_locked(
            deposited_sat=249_999,
            expected_bin_amount_sat=250_000,
        )
        is False
    )


def test_amount_lock_admits_within_tolerance() -> None:
    assert (
        is_deposit_amount_locked(
            deposited_sat=249_990,
            expected_bin_amount_sat=250_000,
            tolerance_sat=10,
        )
        is True
    )


def test_amount_lock_rejects_outside_tolerance() -> None:
    assert (
        is_deposit_amount_locked(
            deposited_sat=249_989,
            expected_bin_amount_sat=250_000,
            tolerance_sat=10,
        )
        is False
    )


def test_amount_lock_rejects_negative_deposit() -> None:
    assert (
        is_deposit_amount_locked(
            deposited_sat=-1,
            expected_bin_amount_sat=250_000,
        )
        is False
    )


def test_amount_lock_rejects_zero_expected() -> None:
    assert (
        is_deposit_amount_locked(
            deposited_sat=250_000,
            expected_bin_amount_sat=0,
        )
        is False
    )


# ── dwell ───────────────────────────────────────────────────────────


def test_dwell_elapsed_returns_false_inside_window(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_ext_deposit_min_dwell_s", 7200)
    now = time.time()
    assert (
        is_dwell_elapsed(
            deposit_observed_at_unix_s=now - 100,
            now_unix_s=now,
        )
        is False
    )


def test_dwell_elapsed_returns_true_past_window(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_ext_deposit_min_dwell_s", 60)
    now = time.time()
    assert (
        is_dwell_elapsed(
            deposit_observed_at_unix_s=now - 120,
            now_unix_s=now,
        )
        is True
    )


def test_dwell_explicit_override(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_ext_deposit_min_dwell_s", 99999)
    now = time.time()
    # Override beats the settings default.
    assert (
        is_dwell_elapsed(
            deposit_observed_at_unix_s=now - 60,
            now_unix_s=now,
            min_dwell_s=30,
        )
        is True
    )


def test_dwell_handles_clock_backwards() -> None:
    """Clock went backwards (deposit_observed_at_unix_s > now) — we
    treat elapsed as zero so a clock blip can't release the UTXO."""
    now = time.time()
    assert (
        is_dwell_elapsed(
            deposit_observed_at_unix_s=now + 100,
            now_unix_s=now,
            min_dwell_s=60,
        )
        is False
    )
