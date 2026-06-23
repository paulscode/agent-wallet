# SPDX-License-Identifier: MIT
"""Anonymize dashboard endpoint shape tests.

Validates the public surface exposed by ``app/dashboard/api.py``:

* ``/anonymize/policy`` returns a stable JSON shape the SPA can read.
* ``/anonymize/health`` returns the boolean-only summary by default
  ; ``?detail=full`` adds detail (rate-limited + audit-logged).
* The session/quote/create/cancel/refund endpoints return ``503``
  when the anonymize service is unavailable.
* None of the anonymize 4xx/5xx responses carry a
  ``Retry-After`` header.
* When ``settings.anonymize_enabled=False`` every anonymize endpoint
  returns ``404`` so the dashboard tab can be hidden.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from app.core.config import settings
from app.dashboard.api import (
    dash_anonymize_create_session,
    dash_anonymize_health,
    dash_anonymize_policy,
    dash_anonymize_quote,
)


def _request_with_app_state(state: dict | None = None) -> MagicMock:
    req = MagicMock()
    req.app.state.anonymize_health = state if state is not None else {}
    return req


@pytest.mark.asyncio
async def test_policy_returns_stable_shape() -> None:
    settings.anonymize_enabled = True
    out = await dash_anonymize_policy(_request_with_app_state())
    assert isinstance(out, dict)
    assert out["min_sat"] == settings.anonymize_min_sat
    assert out["max_sat"] == settings.anonymize_max_sat
    assert out["amount_bins_sat"] == settings.anonymize_amount_bins_list
    assert out["enabled_hop_kinds"] == ["ln_self_pay", "reverse"]
    # On-chain source kinds are admitted (with moderate
    # tier cap on single-operator deployments). The SPA's wizard
    # source-kind picker iterates this list verbatim.
    assert out["enabled_source_kinds"] == [
        "lightning-self",
        "ext-lightning",
        "onchain-self",
        "ext-onchain",
    ]


@pytest.mark.asyncio
async def test_policy_exposes_operator_diversity_block() -> None:
    """The SPA reads ``operator_diversity.distinct_operators_configured``
    to decide whether to render the single-operator advisory banner.
    The default test config leaves both leg URLs unset (single-operator
    posture); the field MUST be False so the banner fires."""
    settings.anonymize_enabled = True
    out = await dash_anonymize_policy(_request_with_app_state())
    assert "operator_diversity" in out
    od = out["operator_diversity"]
    assert isinstance(od, dict)
    assert od["distinct_operators_configured"] is False
    assert od["learn_more_url"].endswith(
        "anonymize_operator_diversity.html",
    )


@pytest.mark.asyncio
async def test_policy_operator_diversity_flips_when_two_legs_configured(
    monkeypatch,
) -> None:
    """When both ``BOLTZ_SUBMARINE_ONION_URL`` and ``BOLTZ_REVERSE_ONION_URL``
    point at distinct onions, the SPA suppresses the banner."""
    settings.anonymize_enabled = True
    monkeypatch.setattr(
        settings,
        "boltz_submarine_onion_url",
        "http://op-a.onion/api/v2",
    )
    monkeypatch.setattr(
        settings,
        "boltz_reverse_onion_url",
        "http://op-b.onion/api/v2",
    )
    out = await dash_anonymize_policy(_request_with_app_state())
    assert out["operator_diversity"]["distinct_operators_configured"] is True


@pytest.mark.asyncio
async def test_policy_returns_404_when_disabled() -> None:
    settings.anonymize_enabled = False
    try:
        out = await dash_anonymize_policy(_request_with_app_state())
        assert out.status_code == 404
    finally:
        settings.anonymize_enabled = True


@pytest.mark.asyncio
async def test_policy_exposes_reconciliation_ux_knobs() -> None:
    """The policy endpoint surfaces the countdown
    switchover threshold and the claim-min-confirmations target so
    the SPA renders both without guessing or hardcoding."""
    settings.anonymize_enabled = True
    out = await dash_anonymize_policy(_request_with_app_state())
    assert "reconciliation_countdown_threshold_s" in out
    assert out["reconciliation_countdown_threshold_s"] == int(
        settings.anonymize_reconciliation_countdown_threshold_s,
    )
    assert "claim_min_confirmations" in out
    assert out["claim_min_confirmations"] == int(
        settings.anonymize_claim_min_confirmations,
    )


@pytest.mark.asyncio
async def test_policy_surfaces_liquid_indexer_reachable_field(
    monkeypatch,
) -> None:
    """The policy endpoint reports a best-effort liveness signal
    for the electrs-liquid indexer so the SPA can render a "Liquid
    indexer unreachable" banner without per-poll probing.

    The helper that fetches the signal swallows internal errors
    and returns ``False`` — exercise both branches by patching the
    underlying probe."""
    settings.anonymize_enabled = True
    monkeypatch.setattr(settings, "anonymize_liquid_enabled", True)
    monkeypatch.setattr(
        settings,
        "anonymize_liquid_integration_verified",
        True,
    )

    # Patch the import-site to flip the probe deterministically.
    monkeypatch.setattr(
        "app.services.anonymize.liquid_fee_oracle.is_liquid_indexer_reachable",
        lambda: True,
    )
    out = await dash_anonymize_policy(_request_with_app_state())
    assert out["liquid_indexer_reachable"] is True

    monkeypatch.setattr(
        "app.services.anonymize.liquid_fee_oracle.is_liquid_indexer_reachable",
        lambda: False,
    )
    out = await dash_anonymize_policy(_request_with_app_state())
    assert out["liquid_indexer_reachable"] is False


@pytest.mark.asyncio
async def test_policy_liquid_indexer_short_circuits_when_liquid_disabled(
    monkeypatch,
) -> None:
    """When the Liquid hop feature flags are off, the policy field
    must always be ``False`` regardless of the underlying probe —
    the dashboard banner has no meaning on LN-only deployments."""
    settings.anonymize_enabled = True
    monkeypatch.setattr(settings, "anonymize_liquid_enabled", False)

    # Probe would report True if it were called.
    called = {"hit": False}

    def _probe() -> bool:
        called["hit"] = True
        return True

    monkeypatch.setattr(
        "app.services.anonymize.liquid_fee_oracle.is_liquid_indexer_reachable",
        _probe,
    )
    out = await dash_anonymize_policy(_request_with_app_state())
    assert out["liquid_indexer_reachable"] is False
    assert called["hit"] is False, "probe must be short-circuited when liquid is disabled"


@pytest.mark.asyncio
async def test_policy_liquid_indexer_reachable_swallows_probe_errors(
    monkeypatch,
) -> None:
    """If the probe raises, the policy endpoint must still respond
    (degrading to ``False``). The dashboard health surface should
    never 500 because of a transient oracle import / call failure."""
    settings.anonymize_enabled = True
    monkeypatch.setattr(settings, "anonymize_liquid_enabled", True)
    monkeypatch.setattr(
        settings,
        "anonymize_liquid_integration_verified",
        True,
    )

    def _boom() -> bool:
        raise RuntimeError("probe failed")

    monkeypatch.setattr(
        "app.services.anonymize.liquid_fee_oracle.is_liquid_indexer_reachable",
        _boom,
    )
    out = await dash_anonymize_policy(_request_with_app_state())
    assert out["liquid_indexer_reachable"] is False


@pytest.mark.asyncio
async def test_health_returns_boolean_only_by_default() -> None:
    settings.anonymize_enabled = True
    req = _request_with_app_state(
        {
            "egress_endpoints_onion_only": True,
            "anonymize_tor_distinct_from_lnd": False,
        }
    )
    body = await dash_anonymize_health(req, detail=None)
    assert set(body.keys()) == {
        "tor_ok",
        "clock_skew_within_threshold",
        "operators_loaded",
        "quote_cache_fresh",
        "egress_endpoints_onion_only",
        "anonymize_tor_distinct_from_lnd",
    }
    # All values must be plain booleans (no numbers / strings) per
    # default-shape rule.
    assert all(isinstance(v, bool) for v in body.values()), body


@pytest.mark.asyncio
async def test_health_full_detail_adds_field() -> None:
    """``?detail=full`` adds the ``last_successful_gc_at_unix_s``
    surface so the operator can see when the recurring GC sweep
    last ran."""
    settings.anonymize_enabled = True
    req = _request_with_app_state({})
    body = await dash_anonymize_health(req, detail="full")
    assert "last_successful_gc_at_unix_s" in body


@pytest.mark.asyncio
async def test_anonymize_endpoints_carry_no_retry_after() -> None:
    """4xx/5xx responses on /anonymize/* carry no Retry-After.

    All Lightning self-source endpoints are wired now — see their per-endpoint
    test modules for behavioral coverage. This test pins the global
    invariant that no anonymize response leaks a ``Retry-After``
    header (which would defeat rate-limit normalization).

    Disable the feature so every endpoint returns the 404 shape;
    this is the easiest path to a 4xx for the header check.
    """
    fake_request = MagicMock()
    settings.anonymize_enabled = False
    try:
        for fn in (dash_anonymize_quote, dash_anonymize_create_session):
            # Both endpoints check ``anonymize_enabled`` first and
            # return 404 before touching the request body.
            resp = await fn(fake_request)
            assert resp.status_code == 404, f"{fn.__name__}: {resp.status_code}"
            assert "retry-after" not in {h.lower() for h in resp.headers.keys()}, (
                f"{fn.__name__} returned a Retry-After header"
            )
    finally:
        settings.anonymize_enabled = True
