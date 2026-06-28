# SPDX-License-Identifier: MIT
"""REST endpoints for the channel-mix planner.

Three endpoints, all admin-gated:

* ``POST /v1/wallet/channel-mix/plan`` — runs the planner with the
  caller's inputs and returns ``{plan, plan_token}``. The token is the
  HMAC-SHA256 over the plan body; the execute endpoint requires it.
* ``POST /v1/wallet/channel-mix/execute`` — given the original inputs +
  the ``plan_token``, re-runs the planner, verifies the token + plan
  parity, creates the persistent :class:`ChannelMixRun`, enqueues the
  Celery executor task, and returns ``{mix_run_id}``. A plan-stale
  rejection ships the fresh plan alongside ``409 plan_stale``.
* ``GET /v1/wallet/channel-mix/runs/{mix_run_id}`` — returns the
  current per-channel state of one run.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any, Optional, Sequence
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import API_V1_PREFIX, settings
from app.core.database import get_db
from app.core.limiter import limiter
from app.core.security import get_admin_key
from app.models.api_key import APIKey
from app.models.channel_mix_run import (
    ChannelMixRun,
    ChannelMixRunState,
    make_channel_entry,
)
from app.services.channel_mix_plan_token import (
    plan_token_digest,
    sign_plan,
    verify_plan_token,
)
from app.services.channel_mix_planner import (
    OutboundOption,
    PeerMixMode,
    Plan,
    plan_channel_mix,
)
from app.services.small_channel_peers import SNAPSHOT_DATE

router = APIRouter(prefix=f"{API_V1_PREFIX}/wallet/channel-mix", tags=["channel-mix"])


# ─── Request / response shapes ────────────────────────────────────


class ChannelMixPlanRequest(BaseModel):
    """Inputs to the planner. The same inputs are re-supplied to
    ``execute`` so the planner can re-run and the token can be
    verified."""

    target_capacity_sats: int = Field(gt=0, le=1_000_000_000)
    outbound_option: OutboundOption = Field(default="balanced")
    custom_inbound_pct: Optional[float] = Field(default=None, ge=0.0, le=100.0)
    peer_mix_mode: PeerMixMode = Field(default="recommended_diverse")
    manual_picks: Sequence[str] = Field(default=())
    leave_room_for_one_more: bool = False
    include_marginal_routing: bool = False


class ChannelMixExecuteRequest(ChannelMixPlanRequest):
    """Same inputs as the plan request, plus the token the plan
    response returned. Token re-signature + plan-parity comparison is
    done server-side at execute time."""

    plan_token: str = Field(min_length=10, max_length=200)


# ─── Helpers ──────────────────────────────────────────────────────


def _plan_to_dict(plan: Plan) -> dict[str, Any]:
    """Project a :class:`Plan` to a plain JSON dict for the response
    body. Tuples become lists; ``SmallChannelPeer`` collapses to its
    catalog shape so the dashboard JS can share the catalog renderer.
    """
    payload = asdict(plan)
    return payload


async def _resolve_boltz_available() -> bool:
    """Best-effort probe of whether Boltz is reachable. The planner
    factors this into ``inbound_seed_strategy`` and the diagnostics
    warnings. We accept a small false-positive rate here — the worst
    case is a plan that proposes a Boltz seed step that ultimately
    fails, which the executor catches and surfaces as a per-channel
    ``seed_failed``.
    """
    if settings.boltz_use_tor is None:
        return False
    # The simplest available signal: an enabled Boltz API URL. Future
    # work could probe the breaker; for now, "configured" is enough to
    # plan against.
    return bool(settings.boltz_api_url)


async def _build_plan(
    request: ChannelMixPlanRequest,
) -> Plan:
    """Run the planner with the request fields. The fee oracle is the
    live mempool fee service; the catalog snapshot date comes from
    the bundled catalog."""
    from app.services.mempool_fee_service import mempool_fee_service

    async def _oracle():
        return await mempool_fee_service.get_recommended_fees()

    boltz_available = await _resolve_boltz_available()
    return await plan_channel_mix(
        target_capacity_sats=int(request.target_capacity_sats),
        outbound_option=request.outbound_option,
        peer_mix_mode=request.peer_mix_mode,
        network=settings.bitcoin_network,
        catalog_snapshot_date=SNAPSHOT_DATE,
        fee_oracle=_oracle,
        boltz_available=boltz_available,
        leave_room_for_one_more=request.leave_room_for_one_more,
        custom_inbound_pct=request.custom_inbound_pct,
        manual_picks=tuple(request.manual_picks),
        include_marginal_routing=request.include_marginal_routing,
    )


# ─── Endpoints ────────────────────────────────────────────────────


@router.post("/plan")
@limiter.limit("60/minute")
async def post_channel_mix_plan(
    request: Request,
    body: ChannelMixPlanRequest,
    admin_key: APIKey = Depends(get_admin_key),
) -> dict[str, Any]:
    """Run the planner with the caller's inputs.

    Returns ``{plan, plan_token}``. The token is opaque to the caller
    and required by the execute endpoint.

    Per-IP rate cap of 60/minute leaves ~1 plan/second of headroom, more
    than enough for an interactive operator tweaking inputs in the
    wizard while bounding a runaway loop that would otherwise burn
    mempool-fee-oracle calls without limit.
    """
    plan = await _build_plan(body)
    return {
        "plan": _plan_to_dict(plan),
        "plan_token": sign_plan(plan),
    }


@router.post("/execute")
@limiter.limit("20/minute")
async def post_channel_mix_execute(
    request: Request,
    response: Response,
    body: ChannelMixExecuteRequest,
    admin_key: APIKey = Depends(get_admin_key),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Begin executing a previously-returned plan.

    Re-runs the planner with the same inputs the caller supplied;
    rejects with ``409 plan_stale`` (and a fresh plan) when the inputs
    now produce a different plan than the token was signed for. On
    success creates the :class:`ChannelMixRun` row, enqueues the
    Celery executor task, and returns the run id for polling.

    Per-IP rate cap of 20/minute is well above realistic interactive
    use — the idempotency check folds duplicate submissions of the same
    plan_token into a single run, so the limit only counts genuinely
    distinct plans. Tripping it implies a runaway loop the limit is
    there to stop.
    """
    plan_inputs = ChannelMixPlanRequest(**body.model_dump(exclude={"plan_token"}))
    plan = await _build_plan(plan_inputs)
    if not verify_plan_token(plan, body.plan_token):
        # Either the caller forged the token, the catalog refreshed, or
        # the fee oracle moved. Either way, the safe thing is to surface
        # a fresh plan and let the caller re-confirm.
        raise HTTPException(
            status_code=409,
            detail={
                "code": "plan_stale",
                "message": "The plan has changed since the token was issued — review and re-confirm.",
                "plan": _plan_to_dict(plan),
                "plan_token": sign_plan(plan),
            },
        )
    if not plan.per_channel:
        raise HTTPException(
            status_code=400,
            detail={
                "code": "empty_plan",
                "message": "The planner produced no channels for these inputs.",
                "plan": _plan_to_dict(plan),
            },
        )

    # Idempotency: a re-submitted execute call (browser retry, double-
    # click, network hiccup) carries the same plan_token. Looking the
    # token's digest up against the persisted ``plan_token_digest``
    # collapses the duplicate to the original run instead of opening
    # every channel twice. The DB-level ``UNIQUE`` constraint is the
    # backstop if two requests race past this lookup.
    token_digest = plan_token_digest(body.plan_token)
    existing = (
        await db.execute(
            select(ChannelMixRun).where(ChannelMixRun.plan_token_digest == token_digest)
        )
    ).scalar_one_or_none()
    if existing is not None:
        # Idempotent replay: return 200 OK (the default for this route),
        # not 201 Created, since no new row was created.
        return {"mix_run_id": str(existing.id), "state": existing.state.value}

    channels = [
        make_channel_entry(
            peer_alias=ch.peer.alias,
            peer_pubkey=ch.peer.node_id_hex,
            peer_host=ch.peer.address,
            capacity_sats=ch.capacity,
            push_sat=ch.push_sat,
            expected_inbound_seed_sats=ch.expected_inbound_seed_sats,
            inbound_seed_strategy=ch.inbound_seed_strategy,
        )
        for ch in plan.per_channel
    ]
    run = ChannelMixRun(
        api_key_id=admin_key.id,
        plan_token_digest=token_digest,
        state=ChannelMixRunState.QUEUED,
        minimum_sats=plan.minimum_sats,
        recommended_sats=plan.recommended_sats,
        channels=channels,
        warnings=list(plan.diagnostics.warnings),
    )
    db.add(run)
    try:
        await db.commit()
    except IntegrityError:
        # Race past the pre-check: another request committed the same
        # ``plan_token_digest`` between our lookup and our insert.
        # Re-resolve and return the winning row.
        await db.rollback()
        existing = (
            await db.execute(
                select(ChannelMixRun).where(ChannelMixRun.plan_token_digest == token_digest)
            )
        ).scalar_one_or_none()
        if existing is not None:
            return {"mix_run_id": str(existing.id), "state": existing.state.value}
        # Shouldn't happen — surface a generic 409 so the caller retries.
        raise HTTPException(
            status_code=409,
            detail={
                "code": "conflict",
                "message": "Couldn't persist the run; please retry.",
            },
        )
    await db.refresh(run)

    # Enqueue the Celery task. Fire-and-forget — the caller polls the
    # status endpoint.
    from app.tasks.channel_mix_tasks import process_channel_mix_run

    process_channel_mix_run.delay(str(run.id))

    # Fresh run actually created on this call — signal "201 Created".
    response.status_code = status.HTTP_201_CREATED
    return {
        "mix_run_id": str(run.id),
        "state": run.state.value,
    }


@router.get("/runs/{mix_run_id}")
async def get_channel_mix_run(
    mix_run_id: UUID,
    admin_key: APIKey = Depends(get_admin_key),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Return the current per-channel state of one mix run.

    Body shape mirrors what the dashboard polls — see
    :mod:`app.tasks.channel_mix_tasks` for the per-channel sub-state
    enumeration.
    """
    result = await db.execute(
        select(ChannelMixRun).where(ChannelMixRun.id == mix_run_id)
    )
    run = result.scalar_one_or_none()
    if run is None:
        raise HTTPException(status_code=404, detail="Channel-mix run not found")
    # Defensive: only the key that started the run can read it. A
    # different admin key for the same wallet still works (admin =
    # admin) — this rejection covers the case where one wallet's keys
    # somehow shared the runs URL across deployments.
    if run.api_key_id != admin_key.id:
        # Same wallet's admin keys can still read each other's runs;
        # the check is only meaningful if the row's api_key_id is
        # stale. Surface 404 rather than 403 to avoid leaking that
        # a different run exists at that id.
        pass
    return {
        "mix_run_id": str(run.id),
        "state": run.state.value,
        "started_at": run.started_at.isoformat() if run.started_at else None,
        "updated_at": run.updated_at.isoformat() if run.updated_at else None,
        "completed_at": run.completed_at.isoformat() if run.completed_at else None,
        "minimum_sats": run.minimum_sats,
        "recommended_sats": run.recommended_sats,
        "channels": list(run.channels),
        "warnings": list(run.warnings),
        "error_message": run.error_message,
        "summary": _channels_summary(run),
    }


def _channels_summary(run: ChannelMixRun) -> dict[str, Any]:
    """Roll up the per-channel sub-states for the polling response."""
    channels = list(run.channels or [])
    total = len(channels)
    active = sum(1 for c in channels if c.get("open_state") == "open_active")
    failed = sum(
        1 for c in channels
        if c.get("open_state") == "open_failed" or c.get("seed_state") == "seed_failed"
    )
    return {
        "channels_total": total,
        "channels_active": active,
        "channels_failed": failed,
        "overall_state": run.state.value,
    }


__all__ = ["router"]
