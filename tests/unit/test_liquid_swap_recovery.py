# SPDX-License-Identifier: MIT
"""Unit tests for the Liquid swap recovery orchestrator + endpoints.

Covers ``app.services.anonymize.liquid_swap_recovery`` and the three
dashboard endpoints under
``/dashboard/api/anonymize/sessions/{session_id}/liquid-recovery/``.

The orchestrator's subprocess runners + operator-registry lookup are
monkey-patched so no JS or signed-registry artefacts are needed.
"""

from __future__ import annotations

from typing import Any, Optional
from uuid import uuid4

import pytest
from fastapi.responses import JSONResponse
from sqlalchemy import select

from app.core.config import settings
from app.dashboard.api import (
    dash_anonymize_liquid_cooperative_refund,
    dash_anonymize_liquid_unilateral_claim,
    dash_anonymize_liquid_unilateral_refund,
)
from app.models.anonymize_session import (
    AnonymizeSession,
    AnonymizeSessionEvent,
    AnonymizeStatus,
)
from app.services.anonymize import liquid_swap_recovery as recovery_mod
from app.services.anonymize.liquid_address import LiquidNetwork
from app.services.anonymize.liquid_claim_subprocess import LiquidClaimResult
from app.services.anonymize.liquid_ct import LBTC_ASSET_ID_MAINNET
from app.services.anonymize.liquid_refund_subprocess import LiquidRefundResult
from app.services.anonymize.liquid_swap_state_persistence import (
    persist_session_swap_state,
)

_REVERSE_SWAP_ID = "boltz-reverse-swap-aaa"
_SUBMARINE_SWAP_ID = "boltz-submarine-swap-bbb"
_CT_ADDR = "lq1qtestctaddr"


@pytest.fixture(autouse=True)
def _enable_anonymize(monkeypatch):
    monkeypatch.setattr(settings, "anonymize_enabled", True)
    # Pin the orchestrator's network/asset resolution so the tests
    # don't depend on bitcoin_network env (the regtest default has
    # no built-in L-BTC asset id).
    monkeypatch.setattr(
        recovery_mod,
        "resolve_liquid_network",
        lambda: LiquidNetwork.MAINNET,
    )
    monkeypatch.setattr(
        recovery_mod,
        "resolve_liquid_btc_asset_id",
        lambda: LBTC_ASSET_ID_MAINNET,
    )


def _swap_tree() -> dict[str, Any]:
    return {
        "swap_tree_claim_leaf": "51" * 16,
        "swap_tree_refund_leaf": "52" * 16,
    }


def _leg1_state(session_id) -> dict[str, Any]:
    return {
        "leg": "ln_to_lbtc",
        "session_id": str(session_id),
        "lockup_tx_hex": "aa" * 100,
        "preimage_hex": "11" * 32,
        "claim_private_key_hex": "22" * 32,
        "refund_public_key_hex": "03" + "33" * 32,
        "blinding_privkey_hex": "44" * 32,
        "session_ct_address": _CT_ADDR,
        "timeout_block_height": 200,
        **_swap_tree(),
    }


def _leg2_state(session_id) -> dict[str, Any]:
    return {
        "leg": "lbtc_to_ln",
        "session_id": str(session_id),
        "lock_tx_hex": "bb" * 100,
        "claim_public_key_hex": "02" + "55" * 32,
        "refund_private_key_hex": "66" * 32,
        "blinding_privkey_hex": "77" * 32,
        "timeout_block_height": 300,
        **_swap_tree(),
    }


async def _seed_session(
    db_session,
    *,
    reverse_op: Optional[str] = "boltz-canonical",
    submarine_op: Optional[str] = "boltz-canonical",
    include_leg1: bool = True,
    include_leg2: bool = True,
) -> AnonymizeSession:
    sess = AnonymizeSession(
        id=uuid4(),
        status=AnonymizeStatus.AWAITING_RECONCILIATION.value,
        source_kind="ext-lightning",
        requested_amount_sat=100_000,
        bin_amount_sat=100_000,
        pipeline_json={"uses_liquid": True},
        quote_hmac=b"x" * 32,
        destination_address_enc=b"ct" * 16,
        destination_script_type="p2tr",
        pipeline_schema_version=10,
        destination_address_blake2b_keyed=b"\xab" * 32,
        destination_reuse_key_generation=0,
        liquid_reverse_operator_id=reverse_op,
        liquid_submarine_operator_id=submarine_op,
    )
    pj = dict(sess.pipeline_json or {})
    if include_leg1:
        pj["liquid_ln_to_lbtc_swap_id"] = _REVERSE_SWAP_ID
    if include_leg2:
        pj["liquid_lbtc_to_ln_swap_id"] = _SUBMARINE_SWAP_ID
    sess.pipeline_json = pj
    db_session.add(sess)
    await db_session.flush()

    swap_state: dict[str, dict[str, Any]] = {}
    if include_leg1:
        swap_state[_REVERSE_SWAP_ID] = _leg1_state(sess.id)
    if include_leg2:
        swap_state[_SUBMARINE_SWAP_ID] = _leg2_state(sess.id)
    persist_session_swap_state(sess, swap_state)
    await db_session.commit()
    return sess


def _patch_operator(monkeypatch, url: Optional[str] = "http://op.onion") -> None:
    monkeypatch.setattr(
        recovery_mod,
        "resolve_operator_url_from_registry",
        lambda _op_id: url,
    )


def _patch_subprocesses(
    monkeypatch,
    *,
    refund_txid: str = "fe" * 32,
    claim_txid: str = "fd" * 32,
):
    captured: dict[str, Any] = {}

    async def _fake_refund(request):
        captured["refund_request"] = request
        return LiquidRefundResult(
            refund_tx_hex="de" * 50,
            txid=refund_txid,
            mode=request.mode,
            raw_stdout_redacted=b"",
            raw_stderr_redacted=b"",
        )

    async def _fake_claim(request):
        captured["claim_request"] = request
        return LiquidClaimResult(
            claim_tx_hex="ad" * 50,
            txid=claim_txid,
            raw_stdout_redacted=b"",
            raw_stderr_redacted=b"",
        )

    monkeypatch.setattr(
        recovery_mod,
        "run_liquid_refund_subprocess",
        _fake_refund,
    )
    monkeypatch.setattr(
        recovery_mod,
        "run_liquid_claim_subprocess",
        _fake_claim,
    )
    return captured


# ── Orchestrator-level tests ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_cooperative_refund_drives_subprocess(
    db_session,
    monkeypatch,
) -> None:
    sess = await _seed_session(db_session)
    _patch_operator(monkeypatch)
    captured = _patch_subprocesses(monkeypatch)

    result = await recovery_mod.cooperative_refund_submarine_leg(session=sess)
    assert result.leg == recovery_mod.LEG_SUBMARINE
    assert result.boltz_swap_id == _SUBMARINE_SWAP_ID
    assert result.mode == "cooperative"
    assert result.operator_id == "boltz-canonical"
    req = captured["refund_request"]
    assert req.mode == "cooperative"
    assert req.swap_id == _SUBMARINE_SWAP_ID
    assert req.boltz_url == "http://op.onion"
    # Refund destination falls back to the leg-1 session_ct_address.
    assert req.refund_address == _CT_ADDR


@pytest.mark.asyncio
async def test_unilateral_refund_passes_mode_and_omits_claim_pub(
    db_session,
    monkeypatch,
) -> None:
    sess = await _seed_session(db_session)
    _patch_operator(monkeypatch)
    captured = _patch_subprocesses(monkeypatch)

    result = await recovery_mod.unilateral_refund_submarine_leg(session=sess)
    assert result.mode == "unilateral"
    req = captured["refund_request"]
    assert req.mode == "unilateral"
    assert req.claim_public_key_hex is None


@pytest.mark.asyncio
async def test_unilateral_claim_targets_reverse_leg(
    db_session,
    monkeypatch,
) -> None:
    sess = await _seed_session(db_session)
    _patch_operator(monkeypatch)
    captured = _patch_subprocesses(monkeypatch)

    result = await recovery_mod.unilateral_claim_reverse_leg(session=sess)
    assert result.leg == recovery_mod.LEG_REVERSE
    assert result.boltz_swap_id == _REVERSE_SWAP_ID
    req = captured["claim_request"]
    assert req.mode == "unilateral"
    assert req.swap_id == _REVERSE_SWAP_ID
    assert req.destination_address == _CT_ADDR


@pytest.mark.asyncio
async def test_state_missing_when_pipeline_swap_id_absent(
    db_session,
    monkeypatch,
) -> None:
    sess = await _seed_session(db_session, include_leg2=False)
    _patch_operator(monkeypatch)
    _patch_subprocesses(monkeypatch)

    with pytest.raises(recovery_mod.LiquidRecoveryStateMissingError):
        await recovery_mod.cooperative_refund_submarine_leg(session=sess)


@pytest.mark.asyncio
async def test_operator_missing_raises_for_cooperative_path(
    db_session,
    monkeypatch,
) -> None:
    sess = await _seed_session(db_session, submarine_op=None)
    monkeypatch.setattr(
        recovery_mod,
        "resolve_operator_url_from_registry",
        lambda _op_id: None,
    )
    _patch_subprocesses(monkeypatch)

    with pytest.raises(recovery_mod.LiquidRecoveryOperatorMissingError):
        await recovery_mod.cooperative_refund_submarine_leg(session=sess)


@pytest.mark.asyncio
async def test_unilateral_path_tolerates_missing_operator(
    db_session,
    monkeypatch,
) -> None:
    """Unilateral mode doesn't need a reachable operator; the JS
    script broadcasts via the wallet's own electrs-liquid."""
    sess = await _seed_session(db_session, submarine_op=None)
    monkeypatch.setattr(
        recovery_mod,
        "resolve_operator_url_from_registry",
        lambda _op_id: None,
    )
    captured = _patch_subprocesses(monkeypatch)

    result = await recovery_mod.unilateral_refund_submarine_leg(session=sess)
    assert result.mode == "unilateral"
    assert captured["refund_request"].boltz_url == ""


# ── Endpoint-level tests ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_endpoint_cooperative_refund_emits_audit(
    db_session,
    monkeypatch,
) -> None:
    sess = await _seed_session(db_session)
    _patch_operator(monkeypatch)
    _patch_subprocesses(monkeypatch)

    payload = await dash_anonymize_liquid_cooperative_refund(
        session_id=str(sess.id),
        db=db_session,
    )
    assert payload["session_id"] == str(sess.id)
    assert payload["mode"] == "cooperative"
    assert payload["boltz_swap_id"] == _SUBMARINE_SWAP_ID

    events = (
        (await db_session.execute(select(AnonymizeSessionEvent).where(AnonymizeSessionEvent.session_id == sess.id)))
        .scalars()
        .all()
    )
    kinds = [e.kind for e in events]
    assert "liquid_swap_cooperative_refund_initiated" in kinds


@pytest.mark.asyncio
async def test_endpoint_unilateral_claim_emits_audit(
    db_session,
    monkeypatch,
) -> None:
    sess = await _seed_session(db_session)
    _patch_operator(monkeypatch)
    _patch_subprocesses(monkeypatch)

    payload = await dash_anonymize_liquid_unilateral_claim(
        session_id=str(sess.id),
        db=db_session,
    )
    assert payload["mode"] == "unilateral"
    assert payload["boltz_swap_id"] == _REVERSE_SWAP_ID

    events = (
        (await db_session.execute(select(AnonymizeSessionEvent).where(AnonymizeSessionEvent.session_id == sess.id)))
        .scalars()
        .all()
    )
    kinds = [e.kind for e in events]
    assert "liquid_swap_unilateral_claim_initiated" in kinds


@pytest.mark.asyncio
async def test_endpoint_unilateral_refund_returns_structured_payload(
    db_session,
    monkeypatch,
) -> None:
    sess = await _seed_session(db_session)
    _patch_operator(monkeypatch)
    _patch_subprocesses(monkeypatch)

    payload = await dash_anonymize_liquid_unilateral_refund(
        session_id=str(sess.id),
        db=db_session,
    )
    assert payload["mode"] == "unilateral"
    assert payload["leg"] == "submarine"
    assert payload["boltz_swap_id"] == _SUBMARINE_SWAP_ID
    assert payload["operator_id"] == "boltz-canonical"


@pytest.mark.asyncio
async def test_endpoint_404_when_anonymize_disabled(
    db_session,
    monkeypatch,
) -> None:
    monkeypatch.setattr(settings, "anonymize_enabled", False)
    resp = await dash_anonymize_liquid_cooperative_refund(
        session_id=str(uuid4()),
        db=db_session,
    )
    assert isinstance(resp, JSONResponse)
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_endpoint_409_when_state_missing(
    db_session,
    monkeypatch,
) -> None:
    sess = await _seed_session(db_session, include_leg2=False)
    _patch_operator(monkeypatch)
    _patch_subprocesses(monkeypatch)

    resp = await dash_anonymize_liquid_cooperative_refund(
        session_id=str(sess.id),
        db=db_session,
    )
    assert isinstance(resp, JSONResponse)
    assert resp.status_code == 409


@pytest.mark.asyncio
async def test_endpoint_502_on_subprocess_failure(
    db_session,
    monkeypatch,
) -> None:
    sess = await _seed_session(db_session)
    _patch_operator(monkeypatch)

    async def _boom(_req):
        raise RuntimeError("electrs-liquid unreachable")

    monkeypatch.setattr(
        recovery_mod,
        "run_liquid_refund_subprocess",
        _boom,
    )

    resp = await dash_anonymize_liquid_cooperative_refund(
        session_id=str(sess.id),
        db=db_session,
    )
    assert isinstance(resp, JSONResponse)
    assert resp.status_code == 502
