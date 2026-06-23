# SPDX-License-Identifier: MIT
"""/ items 14 + 51 — Tor diversity + bootstrap.

Pure-helper coverage for the exit-relay diversity predicate and the
bootstrap-status decision; the actual control-port client lands with
the supervisor.
"""

from __future__ import annotations

import pytest

from app.core.config import settings
from app.services.anonymize.tor import (
    CircuitExitInfo,
    TorBootstrapStatus,
    assert_exit_relay_diversity,
    is_tor_bootstrap_ready,
)


def _ci(
    *,
    cid: str = "100",
    fp: str = "F" * 40,
    ip: str = "203.0.113.1",
    asn: str | None = None,
    country: str | None = None,
) -> CircuitExitInfo:
    return CircuitExitInfo(
        circuit_id=cid,
        exit_fingerprint=fp,
        exit_ip=ip,
        asn=asn,
        country=country,
    )


# ── item 14 ───────────────────────────────────────────────────────


def test_distinct_asn_passes(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_require_exit_diversity", "asn")
    assert_exit_relay_diversity(
        _ci(asn="AS65001"),
        _ci(asn="AS65002"),
    )  # no raise


def test_same_asn_rejects(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_require_exit_diversity", "asn")
    with pytest.raises(ValueError, match="diversity key"):
        assert_exit_relay_diversity(
            _ci(asn="AS65001"),
            _ci(asn="AS65001"),
        )


def test_falls_back_to_slash16_when_no_asn(monkeypatch) -> None:
    """Without ASN data, two circuits in the same /16 collide."""
    monkeypatch.setattr(settings, "anonymize_require_exit_diversity", "asn")
    with pytest.raises(ValueError):
        assert_exit_relay_diversity(
            _ci(ip="203.0.113.1"),
            _ci(ip="203.0.113.42"),
        )


def test_different_slash16_passes(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_require_exit_diversity", "asn")
    assert_exit_relay_diversity(
        _ci(ip="203.0.113.1"),
        _ci(ip="198.51.100.42"),
    )


def test_country_mode_compares_country_code(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_require_exit_diversity", "country")
    assert_exit_relay_diversity(
        _ci(country="DE", asn="AS1"),
        _ci(country="NL", asn="AS1"),  # same ASN, different country → pass
    )
    with pytest.raises(ValueError):
        assert_exit_relay_diversity(
            _ci(country="DE"),
            _ci(country="DE"),
        )


def test_off_mode_disables_check(monkeypatch) -> None:
    """``off`` ⇒ helper never raises (and the scorer surfaces the cap)."""
    monkeypatch.setattr(settings, "anonymize_require_exit_diversity", "off")
    assert_exit_relay_diversity(
        _ci(asn="AS65001"),
        _ci(asn="AS65001"),
    )


def test_explicit_mode_overrides_settings(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_require_exit_diversity", "off")
    with pytest.raises(ValueError):
        assert_exit_relay_diversity(
            _ci(asn="AS1"),
            _ci(asn="AS1"),
            mode="asn",
        )


def test_ipv6_falls_back_to_slash64(monkeypatch) -> None:
    """Two IPv6 addresses sharing the first 64 bits collide."""
    monkeypatch.setattr(settings, "anonymize_require_exit_diversity", "asn")
    with pytest.raises(ValueError):
        assert_exit_relay_diversity(
            _ci(ip="2001:db8:0001:1::1"),
            _ci(ip="2001:db8:0001:1:dead:beef::"),
        )


def test_ipv6_distinct_slash64_passes(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_require_exit_diversity", "asn")
    # Different /64 — first 4 colon-separated parts differ.
    assert_exit_relay_diversity(
        _ci(ip="2001:db8:0001::1"),
        _ci(ip="2001:db8:0002::1"),
    )


# ── item 51 — bootstrap-status decision ───────────────────────────


def test_bootstrap_ready_requires_all_three() -> None:
    assert (
        is_tor_bootstrap_ready(
            TorBootstrapStatus(
                control_port_reachable=True,
                bootstrap_phase_progress=100,
                circuit_established=True,
            )
        )
        is True
    )


@pytest.mark.parametrize(
    "control_ok,progress,circuit_ok",
    [
        (False, 100, True),  # control port unreachable
        (True, 99, True),  # bootstrap not done
        (True, 100, False),  # no circuit yet
        (False, 0, False),  # cold start
    ],
)
def test_bootstrap_not_ready_until_all_satisfied(
    control_ok: bool,
    progress: int,
    circuit_ok: bool,
) -> None:
    status = TorBootstrapStatus(
        control_port_reachable=control_ok,
        bootstrap_phase_progress=progress,
        circuit_established=circuit_ok,
    )
    assert is_tor_bootstrap_ready(status) is False
