# SPDX-License-Identifier: MIT
"""On-chain inbound pre-flight gate for anonymize session creation.

Mirrors the Braiins on-chain deposit inbound gate
(``test_braiins_deposit_service.TestInboundPreflightGate``). An
on-chain anonymize source funds via a submarine swap, which needs THIS
node to RECEIVE the bin amount over Lightning from the provider — so an
inbound-starved node can't complete it. The gate catches that at create
time, before any funds move. Tier 2 (routability probe) is intentionally
NOT ported (its Boltz egress would breach the isolation invariant), so
there is nothing here that mirrors ``TestRoutabilityProbe``.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from cryptography.fernet import Fernet

from app.core.config import settings
from app.services.anonymize.inbound_preflight import (
    inbound_preflight,
    source_requires_inbound_preflight,
)

_REGTEST_P2TR = "bcrt1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqc8gma6"

_DASHBOARD_JS = Path(__file__).resolve().parents[2] / "app" / "dashboard" / "static" / "dashboard.js"


def _lnd_with_inbound(total: int, largest: int) -> AsyncMock:
    lnd = AsyncMock()
    lnd.inbound_capacity = AsyncMock(
        return_value=(
            {
                "total_receivable_sats": total,
                "largest_channel_receivable_sats": largest,
            },
            None,
        )
    )
    return lnd


_ENABLED = SimpleNamespace(anonymize_inbound_preflight_enabled=True)
_DISABLED = SimpleNamespace(anonymize_inbound_preflight_enabled=False)


# ── source-kind gating ───────────────────────────────────────────────


def test_source_requires_inbound_preflight_onchain_kinds() -> None:
    assert source_requires_inbound_preflight("onchain-self") is True
    assert source_requires_inbound_preflight("ext-onchain") is True


def test_source_requires_inbound_preflight_ln_kinds() -> None:
    assert source_requires_inbound_preflight("lightning-self") is False
    assert source_requires_inbound_preflight("ext-lightning") is False
    assert source_requires_inbound_preflight("nonsense") is False


# ── Tier-1 capacity gate ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_refused_when_inbound_insufficient() -> None:
    lnd = _lnd_with_inbound(total=10_000, largest=10_000)
    refusal, warning = await inbound_preflight(
        receive_sats=1_000_000,
        lnd=lnd,
        settings_obj=_ENABLED,
    )
    assert refusal is not None
    assert "inbound_insufficient" in refusal
    assert warning is None


@pytest.mark.asyncio
async def test_allowed_full_capacity_no_warning() -> None:
    lnd = _lnd_with_inbound(total=100_000_000, largest=100_000_000)
    refusal, warning = await inbound_preflight(
        receive_sats=1_000_000,
        lnd=lnd,
        settings_obj=_ENABLED,
    )
    assert refusal is None
    assert warning is None


@pytest.mark.asyncio
async def test_mpp_warning_when_no_single_channel_covers() -> None:
    # Total covers the amount, but no single channel does → advisory
    # warning, not a refusal (the provider generally pays via MPP).
    lnd = _lnd_with_inbound(total=5_000_000, largest=500_000)
    refusal, warning = await inbound_preflight(
        receive_sats=1_000_000,
        lnd=lnd,
        settings_obj=_ENABLED,
    )
    assert refusal is None
    assert warning is not None
    assert "relies on MPP" in warning


@pytest.mark.asyncio
async def test_margin_blocks_when_just_below_amount_plus_headroom() -> None:
    # total == receive exactly: fails the ``receive + margin`` floor.
    lnd = _lnd_with_inbound(total=1_000_000, largest=1_000_000)
    refusal, _warning = await inbound_preflight(
        receive_sats=1_000_000,
        lnd=lnd,
        settings_obj=_ENABLED,
    )
    assert refusal is not None


@pytest.mark.asyncio
async def test_skipped_on_lnd_error_allows() -> None:
    lnd = AsyncMock()
    lnd.inbound_capacity = AsyncMock(return_value=(None, "lnd unreachable"))
    refusal, warning = await inbound_preflight(
        receive_sats=1_000_000,
        lnd=lnd,
        settings_obj=_ENABLED,
    )
    # Best-effort — a transient LND error must NOT block a session.
    assert refusal is None
    assert warning is None


@pytest.mark.asyncio
async def test_disabled_by_setting_short_circuits() -> None:
    lnd = _lnd_with_inbound(total=0, largest=0)
    refusal, warning = await inbound_preflight(
        receive_sats=1_000_000,
        lnd=lnd,
        settings_obj=_DISABLED,
    )
    assert refusal is None
    assert warning is None
    # Disabled → LND is never consulted.
    lnd.inbound_capacity.assert_not_called()


@pytest.mark.asyncio
async def test_non_positive_amount_allows() -> None:
    lnd = _lnd_with_inbound(total=0, largest=0)
    refusal, warning = await inbound_preflight(
        receive_sats=0,
        lnd=lnd,
        settings_obj=_ENABLED,
    )
    assert refusal is None
    assert warning is None
    lnd.inbound_capacity.assert_not_called()


# ── endpoint wiring (on-chain create refuses on low inbound) ──────────


@pytest.fixture
def _quote_keyset(monkeypatch):
    monkeypatch.setattr(
        settings,
        "anonymize_quote_token_hmac_key_fernet",
        Fernet.generate_key().decode("ascii"),
    )


@pytest.fixture(autouse=True)
def _reset_service():
    from app.services.anonymize.service import reset_anonymize_service

    reset_anonymize_service()
    yield
    reset_anonymize_service()


def _mock_request(*, body: dict | None, cookie: str = "preflight") -> MagicMock:
    raw = json.dumps(body).encode("utf-8") if body is not None else b""
    req = MagicMock()
    req.body = AsyncMock(return_value=raw)
    req.cookies = {"dashboard_session": cookie}
    req.app.state.anonymize_health = {
        "egress_endpoints_onion_only": True,
        "operator_registry_size": 1,
        "tor_bootstrap_ready": True,
    }
    req.client = MagicMock()
    req.client.host = "127.0.0.1"
    return req


@pytest.mark.asyncio
async def test_create_refuses_onchain_when_inbound_insufficient(
    db_session,
    _quote_keyset,
    monkeypatch,
) -> None:
    """End-to-end wiring: an on-chain-sourced create whose node lacks
    inbound to receive the bin amount is refused with the byte-pinned
    generic 429 (no reason leak) — before any funds move."""
    from app.dashboard.api import (
        dash_anonymize_create_session,
        dash_anonymize_quote,
    )
    from app.services.anonymize.responses import (
        creation_unavailable_body_bytes,
    )

    settings.anonymize_enabled = True
    # Pin both Boltz onion URLs so the on-chain quote skips the
    # operator-selection / live-probe path (needs no registry/network).
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
    # Node can't receive the bin amount over Lightning.
    mock_lnd = MagicMock()
    mock_lnd.inbound_capacity = AsyncMock(
        return_value=(
            {
                "total_receivable_sats": 10_000,
                "largest_channel_receivable_sats": 10_000,
            },
            None,
        )
    )
    monkeypatch.setattr("app.services.lnd_service.lnd_service", mock_lnd)

    quote = await dash_anonymize_quote(
        _mock_request(
            body={
                "source_kind": "onchain-self",
                "destination_address": _REGTEST_P2TR,
                "requested_amount_sat": 250_000,
            },
            cookie="preflight",
        )
    )
    assert isinstance(quote, dict), f"onchain quote returned {quote}"

    resp = await dash_anonymize_create_session(
        _mock_request(
            body={"quote_token": quote["quote_token"]},
            cookie="preflight",
        ),
        db=db_session,
    )
    assert resp.status_code == 429
    assert resp.body == creation_unavailable_body_bytes()
    mock_lnd.inbound_capacity.assert_awaited()


@pytest.mark.asyncio
async def test_create_refuses_ext_onchain_before_deriving_address(
    db_session,
    _quote_keyset,
    monkeypatch,
) -> None:
    """The gate must run BEFORE the ext-onchain deposit-address
    derivation, so a refused session never burns a wallet address."""
    from app.dashboard.api import (
        dash_anonymize_create_session,
        dash_anonymize_quote,
    )

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
    mock_lnd = MagicMock()
    mock_lnd.inbound_capacity = AsyncMock(
        return_value=(
            {
                "total_receivable_sats": 10_000,
                "largest_channel_receivable_sats": 10_000,
            },
            None,
        )
    )
    # Spy: a refused session must NOT derive a deposit address.
    mock_lnd.new_address = AsyncMock(return_value=({"address": "bcrt1qshouldnotbecalled"}, None))
    monkeypatch.setattr("app.services.lnd_service.lnd_service", mock_lnd)

    quote = await dash_anonymize_quote(
        _mock_request(
            body={
                "source_kind": "ext-onchain",
                "destination_address": _REGTEST_P2TR,
                "requested_amount_sat": 250_000,
            },
            cookie="preflight",
        )
    )
    assert isinstance(quote, dict), f"ext-onchain quote returned {quote}"

    resp = await dash_anonymize_create_session(
        _mock_request(
            body={"quote_token": quote["quote_token"]},
            cookie="preflight",
        ),
        db=db_session,
    )
    assert resp.status_code == 429
    mock_lnd.new_address.assert_not_called()


# ── Dashboard surfaces for the pre-lockup AR reason ──────────────────
#
# Static-analysis pins (the SPA isn't headless-testable here) for the
# ``inbound_insufficient_at_lockup`` reconciliation reason, so a future
# edit to dashboard.js can't silently drop one of the surfaces.

_REASON = "inbound_insufficient_at_lockup"


def test_dashboard_reason_in_label_known_and_cancellable_maps() -> None:
    js = _DASHBOARD_JS.read_text(encoding="utf-8")
    # Friendly label, known set, cancellable set all carry the reason.
    assert f"{_REASON}:" in js, "reason missing a _anonymizeReasonLabel entry"
    assert js.count(f"{_REASON}: true") >= 2, "reason must be in both the known and cancellable JS sets"


def test_dashboard_primary_action_is_cancel_not_retry() -> None:
    """The on-chain funding step has no legal AR→FUNDING resume edge, so
    "Try again" can never succeed. The primary action for this reason
    MUST route to ``reconcile_cancel`` (a working action), not fall
    through to the ``reconcile_retry`` default."""
    js = _DASHBOARD_JS.read_text(encoding="utf-8")
    # The primary-action branch for this reason returns reconcile_cancel.
    pattern = re.compile(
        r"reason === '" + re.escape(_REASON) + r"'\s*\)\s*\{\s*"
        r"return \{label: 'Cancel', kind: 'reconcile_cancel'\}",
    )
    assert pattern.search(js), (
        "primary action for inbound_insufficient_at_lockup must be "
        "reconcile_cancel (it can't be retried — AR→FUNDING is illegal)"
    )
