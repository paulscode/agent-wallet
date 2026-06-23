# SPDX-License-Identifier: MIT
"""Error-path coverage for the cold-storage operator-recovery endpoints.

The happy paths + initiate/cancel basics live in
``tests/integration/test_endpoints.py``. This module targets the
operator-driven recovery surface — cooperative-claim, unilateral-claim,
and bump-fee — whose failure branches were otherwise unexercised:

* the spend-scope guard (403 for a non-spend key),
* malformed ``swap_id`` (400) and not-found / wrong-owner (404),
* query validation (422) on the bump-fee parameters,
* upstream Boltz/LND failures mapped to 4xx vs 502,
* the per-payment spend limit (429) on a fee bump.

Tests drive the live FastAPI app and mock only the service layer
(``boltz_service`` / ``lnd_service``) so the request->response contract
— status code + error body — is what is asserted.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID, uuid4

import pytest


def _owned_swap(key_id: str) -> MagicMock:
    """A swap row owned by ``key_id`` with the fields the response
    serializer / audit logger read."""
    swap = MagicMock()
    swap.id = uuid4()
    swap.api_key_id = UUID(key_id)
    swap.boltz_swap_id = "boltz-recover"
    swap.claim_txid = None
    swap.lockup_txid = None
    swap.recovery_count = 0
    swap.timeout_block_height = 850_000
    return swap


# ── Scope guard (spend key required) ────────────────────────────────


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "suffix",
    [
        "cooperative-claim",
        "unilateral-claim",
        "bump-fee?sat_per_vbyte=5",
    ],
)
async def test_recovery_endpoints_require_spend_scope(client, db_session, suffix) -> None:
    """A monitor-scope key may read swaps but must not drive any
    value-moving recovery action; the spend-key dependency rejects it
    with 403."""
    from app.core.security import generate_api_key, hash_api_key
    from app.models.api_key import APIKey

    raw = generate_api_key()
    db_session.add(
        APIKey(
            id=uuid4(),
            name="monitor",
            key_hash=hash_api_key(raw),
            scope="monitor",
            is_active=True,
        )
    )
    await db_session.commit()

    resp = await client.post(
        f"/v1/cold-storage/swaps/{uuid4()}/{suffix}",
        headers={"Authorization": f"Bearer {raw}"},
    )
    assert resp.status_code == 403


# ── Malformed swap id (400) ─────────────────────────────────────────


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "suffix",
    [
        "cooperative-claim",
        "unilateral-claim",
        "bump-fee?sat_per_vbyte=5",
        "cancel",
    ],
)
async def test_recovery_endpoints_reject_non_uuid_swap_id(authed_client, suffix) -> None:
    """A non-UUID path segment is rejected with 400 + the documented
    detail before any service call."""
    client, _raw, _key_id = authed_client
    resp = await client.post(f"/v1/cold-storage/swaps/not-a-uuid/{suffix}")
    assert resp.status_code == 400
    assert resp.json()["detail"] == "Invalid swap ID format"


# ── Not found / cross-tenant (404) ──────────────────────────────────


@pytest.mark.asyncio
async def test_cooperative_claim_unknown_swap_is_404(authed_client) -> None:
    """A well-formed id that resolves no row returns 404 'Swap not
    found'."""
    client, _raw, _key_id = authed_client
    with patch(
        "app.services.boltz_service.boltz_service.get_swap_by_id",
        new_callable=AsyncMock,
        return_value=None,
    ):
        resp = await client.post(f"/v1/cold-storage/swaps/{uuid4()}/cooperative-claim")
    assert resp.status_code == 404
    assert resp.json()["detail"] == "Swap not found"


@pytest.mark.asyncio
async def test_unilateral_claim_other_tenant_swap_is_404(authed_client) -> None:
    """A swap owned by another key must be indistinguishable from a
    missing one: 404, never 403 (no cross-tenant existence leak)."""
    client, _raw, _key_id = authed_client
    foreign = MagicMock()
    foreign.api_key_id = uuid4()  # not the caller's key
    with patch(
        "app.services.boltz_service.boltz_service.get_swap_by_id",
        new_callable=AsyncMock,
        return_value=foreign,
    ):
        resp = await client.post(f"/v1/cold-storage/swaps/{uuid4()}/unilateral-claim")
    assert resp.status_code == 404
    assert resp.json()["detail"] == "Swap not found"


# ── Upstream failures → 502 / 4xx ───────────────────────────────────


@pytest.mark.asyncio
async def test_cooperative_claim_boltz_failure_is_502(authed_client) -> None:
    """When the cooperative-claim retry returns an error string the
    endpoint maps it to 502 (sanitized upstream failure)."""
    client, _raw, key_id = authed_client
    swap = _owned_swap(key_id)
    with (
        patch(
            "app.services.boltz_service.boltz_service.get_swap_by_id",
            new_callable=AsyncMock,
            return_value=swap,
        ),
        patch(
            "app.services.boltz_service.boltz_service.retry_cooperative_claim",
            new_callable=AsyncMock,
            return_value=(None, "boltz refused to co-sign"),
        ),
    ):
        resp = await client.post(f"/v1/cold-storage/swaps/{swap.id}/cooperative-claim")
    assert resp.status_code == 502
    assert resp.json()["detail"]


@pytest.mark.asyncio
async def test_unilateral_claim_safety_check_is_400(authed_client) -> None:
    """A unilateral claim attempted before the lockup timeout has
    passed is a caller-side safety violation: the 'timeout has not
    passed' error string is mapped to 400, not a generic 502."""
    client, _raw, key_id = authed_client
    swap = _owned_swap(key_id)
    with (
        patch(
            "app.services.boltz_service.boltz_service.get_swap_by_id",
            new_callable=AsyncMock,
            return_value=swap,
        ),
        patch(
            "app.services.boltz_service.boltz_service.retry_unilateral_claim",
            new_callable=AsyncMock,
            return_value=(None, "lockup timeout has not passed yet"),
        ),
    ):
        resp = await client.post(f"/v1/cold-storage/swaps/{swap.id}/unilateral-claim")
    # The 400 (vs 502) status is the load-bearing assertion: the
    # endpoint routes safety-check failures to 4xx. The detail is
    # sanitized so the raw upstream string is not echoed back.
    assert resp.status_code == 400
    assert resp.json()["detail"]


@pytest.mark.asyncio
async def test_unilateral_claim_upstream_error_is_502(authed_client) -> None:
    """A non-safety error (e.g. a chain-backend failure) from the
    unilateral claim maps to 502."""
    client, _raw, key_id = authed_client
    swap = _owned_swap(key_id)
    with (
        patch(
            "app.services.boltz_service.boltz_service.get_swap_by_id",
            new_callable=AsyncMock,
            return_value=swap,
        ),
        patch(
            "app.services.boltz_service.boltz_service.retry_unilateral_claim",
            new_callable=AsyncMock,
            return_value=(None, "chain backend unreachable"),
        ),
    ):
        resp = await client.post(f"/v1/cold-storage/swaps/{swap.id}/unilateral-claim")
    assert resp.status_code == 502
    assert resp.json()["detail"]


# ── bump-fee query validation (422) ─────────────────────────────────


@pytest.mark.asyncio
async def test_bump_fee_requires_sat_per_vbyte(authed_client) -> None:
    """``sat_per_vbyte`` is a required query param; omitting it fails
    request validation with 422."""
    client, _raw, _key_id = authed_client
    resp = await client.post(f"/v1/cold-storage/swaps/{uuid4()}/bump-fee")
    assert resp.status_code == 422
    assert any(err["loc"][-1] == "sat_per_vbyte" for err in resp.json()["detail"])


@pytest.mark.asyncio
@pytest.mark.parametrize("rate", [0, 1001])
async def test_bump_fee_rejects_out_of_range_rate(authed_client, rate) -> None:
    """``sat_per_vbyte`` is bounded 1..1000; values outside the range
    are rejected with 422."""
    client, _raw, _key_id = authed_client
    resp = await client.post(
        f"/v1/cold-storage/swaps/{uuid4()}/bump-fee",
        params={"sat_per_vbyte": rate},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_bump_fee_rejects_unknown_target(authed_client) -> None:
    """``target`` is pattern-constrained to claim|lockup; anything
    else fails validation with 422."""
    client, _raw, _key_id = authed_client
    resp = await client.post(
        f"/v1/cold-storage/swaps/{uuid4()}/bump-fee",
        params={"sat_per_vbyte": 5, "target": "bogus"},
    )
    assert resp.status_code == 422


# ── bump-fee business-rule failures ─────────────────────────────────


@pytest.mark.asyncio
async def test_bump_fee_claim_without_txid_is_400(authed_client) -> None:
    """A claim-target bump on a swap that never broadcast a claim has
    nothing to bump → 400 with an explanatory detail."""
    client, _raw, key_id = authed_client
    swap = _owned_swap(key_id)
    swap.claim_txid = None
    with (
        patch(
            "app.services.boltz_service.boltz_service.get_swap_by_id",
            new_callable=AsyncMock,
            return_value=swap,
        ),
        patch(
            "app.api.cold_storage.check_payment_limits",
            new_callable=AsyncMock,
            return_value=(True, None, None),
        ),
    ):
        resp = await client.post(
            f"/v1/cold-storage/swaps/{swap.id}/bump-fee",
            params={"sat_per_vbyte": 5, "target": "claim"},
        )
    assert resp.status_code == 400
    assert "nothing to bump" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_bump_fee_exceeding_spend_limit_is_429(authed_client) -> None:
    """A fee bump charges its bounded budget against the velocity
    limiter; a rejected reservation surfaces as 429 with the limiter's
    message."""
    client, _raw, key_id = authed_client
    swap = _owned_swap(key_id)
    swap.claim_txid = "ab" * 32
    with (
        patch(
            "app.services.boltz_service.boltz_service.get_swap_by_id",
            new_callable=AsyncMock,
            return_value=swap,
        ),
        patch(
            "app.api.cold_storage.check_payment_limits",
            new_callable=AsyncMock,
            return_value=(False, "daily spend limit exceeded", None),
        ),
    ):
        resp = await client.post(
            f"/v1/cold-storage/swaps/{swap.id}/bump-fee",
            params={"sat_per_vbyte": 5, "target": "claim"},
        )
    assert resp.status_code == 429
    assert resp.json()["detail"] == "daily spend limit exceeded"


@pytest.mark.asyncio
async def test_bump_fee_lnd_error_is_502_and_rolls_back(authed_client) -> None:
    """When LND's BumpFee returns an error the endpoint rolls back the
    spend reservation and maps the failure to 502."""
    client, _raw, key_id = authed_client
    swap = _owned_swap(key_id)
    swap.claim_txid = "cd" * 32
    reservation = object()
    with (
        patch(
            "app.services.boltz_service.boltz_service.get_swap_by_id",
            new_callable=AsyncMock,
            return_value=swap,
        ),
        patch(
            "app.api.cold_storage.check_payment_limits",
            new_callable=AsyncMock,
            return_value=(True, None, reservation),
        ),
        patch(
            "app.api.cold_storage.rollback_payment_limits",
            new_callable=AsyncMock,
        ) as mock_rollback,
        patch(
            "app.services.lnd_service.lnd_service.bump_fee",
            new_callable=AsyncMock,
            return_value=(None, "insufficient wallet funds for CPFP"),
        ),
    ):
        resp = await client.post(
            f"/v1/cold-storage/swaps/{swap.id}/bump-fee",
            params={"sat_per_vbyte": 5, "target": "claim"},
        )
    assert resp.status_code == 502
    assert resp.json()["detail"]
    mock_rollback.assert_awaited_once_with(reservation)


# ── initiate validation (422) ───────────────────────────────────────


@pytest.mark.asyncio
async def test_initiate_rejects_invalid_destination_address(authed_client) -> None:
    """The destination address is validated against the configured
    network; a malformed address fails Pydantic validation with 422
    before any swap is created."""
    client, _raw, _key_id = authed_client
    resp = await client.post(
        "/v1/cold-storage/initiate",
        json={"amount_sats": 100_000, "destination_address": "not-a-bitcoin-address"},
    )
    assert resp.status_code == 422
    assert any(err["loc"][-1] == "destination_address" for err in resp.json()["detail"])


@pytest.mark.asyncio
async def test_initiate_rejects_out_of_range_routing_fee_percent(authed_client) -> None:
    """``routing_fee_limit_percent`` is bounded 0.1..10.0; a value
    above the ceiling is rejected with 422."""
    client, _raw, _key_id = authed_client
    resp = await client.post(
        "/v1/cold-storage/initiate",
        json={
            "amount_sats": 100_000,
            "destination_address": "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080",
            "routing_fee_limit_percent": 50.0,
        },
    )
    assert resp.status_code == 422
    assert any(err["loc"][-1] == "routing_fee_limit_percent" for err in resp.json()["detail"])
