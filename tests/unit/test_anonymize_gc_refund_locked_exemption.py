# SPDX-License-Identifier: MIT
"""Tests for the ``anonymize_refund_locked`` retention exemption in
``app.services.anonymize.gc``.

Exempts the operator-visible refund-lockdown audit row from the
GC event-collapse pass for a bounded horizon so operators can
still investigate refund flows after the destination retention
window has lapsed.
"""

from __future__ import annotations

from app.core.config import settings


def test_hard_horizon_auto_doubles_destination_retention(monkeypatch) -> None:
    from app.services.anonymize.gc import refund_locked_event_hard_horizon_days

    monkeypatch.setattr(
        settings,
        "anonymize_refund_locked_event_hard_horizon_days",
        0,
    )
    monkeypatch.setattr(settings, "anonymize_destination_retention_days", 7)
    assert refund_locked_event_hard_horizon_days() == 14


def test_hard_horizon_explicit_override(monkeypatch) -> None:
    from app.services.anonymize.gc import refund_locked_event_hard_horizon_days

    monkeypatch.setattr(
        settings,
        "anonymize_refund_locked_event_hard_horizon_days",
        30,
    )
    monkeypatch.setattr(settings, "anonymize_destination_retention_days", 7)
    assert refund_locked_event_hard_horizon_days() == 30


def test_refund_locked_event_exempt_when_unspent_and_within_horizon(
    monkeypatch,
) -> None:
    from app.services.anonymize.gc import is_refund_locked_event_exempt

    monkeypatch.setattr(
        settings,
        "anonymize_refund_locked_event_hard_horizon_days",
        0,
    )
    monkeypatch.setattr(settings, "anonymize_destination_retention_days", 7)
    assert (
        is_refund_locked_event_exempt(
            event_kind="anonymize_refund_locked",
            refund_utxo_spent=False,
            event_age_days=10.0,
        )
        is True
    )


def test_refund_locked_event_not_exempt_once_spent(monkeypatch) -> None:
    from app.services.anonymize.gc import is_refund_locked_event_exempt

    monkeypatch.setattr(
        settings,
        "anonymize_refund_locked_event_hard_horizon_days",
        0,
    )
    monkeypatch.setattr(settings, "anonymize_destination_retention_days", 7)
    assert (
        is_refund_locked_event_exempt(
            event_kind="anonymize_refund_locked",
            refund_utxo_spent=True,
            event_age_days=2.0,
        )
        is False
    )


def test_refund_locked_event_not_exempt_past_hard_horizon(monkeypatch) -> None:
    from app.services.anonymize.gc import is_refund_locked_event_exempt

    monkeypatch.setattr(
        settings,
        "anonymize_refund_locked_event_hard_horizon_days",
        0,
    )
    monkeypatch.setattr(settings, "anonymize_destination_retention_days", 7)
    # 14-day horizon; 20 days old = past horizon.
    assert (
        is_refund_locked_event_exempt(
            event_kind="anonymize_refund_locked",
            refund_utxo_spent=False,
            event_age_days=20.0,
        )
        is False
    )


def test_unrelated_event_kinds_not_exempt() -> None:
    """Only ``anonymize_refund_locked`` is exempt; other rows collapse normally."""
    from app.services.anonymize.gc import is_refund_locked_event_exempt

    assert (
        is_refund_locked_event_exempt(
            event_kind="hop_attempt_started",
            refund_utxo_spent=False,
            event_age_days=2.0,
        )
        is False
    )
