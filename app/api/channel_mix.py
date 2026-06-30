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

import hashlib
from dataclasses import asdict
from typing import Any, Literal, Optional, Sequence
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import API_V1_PREFIX, settings
from app.core.database import get_db
from app.core.limiter import limiter
from app.core.security import get_admin_key
from app.models.api_key import APIKey
from app.models.channel_mix_run import (
    BOOTSTRAP_ROUND_TERMINAL_STATES,
    TERMINAL_RUN_STATES,
    ChannelMixRun,
    ChannelMixRunState,
    finalize_run,
    make_channel_entry,
)
from app.services.channel_mix_plan_token import (
    plan_token_digest,
    sign_plan,
    verify_plan_token,
)
from app.services.channel_mix_planner import (
    BootstrapPlan,
    OutboundOption,
    PeerMixMode,
    Plan,
    plan_channel_mix,
)
from app.services.small_channel_peers import SNAPSHOT_DATE

# Run states that mean "a capital-consuming loop is in flight" — the
# one-active-run guard (plan §6a) refuses to start a second run while any
# of these exist, so two loops can't race the same UTXO set.
_NON_TERMINAL_RUN_STATES = (
    ChannelMixRunState.QUEUED,
    ChannelMixRunState.IN_PROGRESS,
    ChannelMixRunState.AWAITING_FUNDS,
)

# Fixed signed-64-bit key for the Postgres transaction-advisory lock that
# serializes the one-active-run guard's check-then-insert critical section
# (recovery plan §2). The wallet is a single node, so "one active run" is
# global — one constant key. Derived from a literal so it's stable across
# restarts and impossible to collide with another subsystem's lock.
_CHANNEL_MIX_EXECUTE_LOCK_KEY = int.from_bytes(
    hashlib.sha256(b"agent-wallet/channel-mix-execute").digest()[:8],
    "big",
    signed=True,
)


async def _acquire_execute_lock(db: AsyncSession) -> None:
    """Serialize concurrent ``execute`` calls so the one-active-run guard
    is atomic (recovery plan §2).

    Acquires a Postgres transaction-advisory lock held to transaction end
    (the request's commit/rollback in ``get_db`` teardown): the second
    waiter only proceeds after the first commits, so its ``_active_run``
    lookup reliably sees the first run and returns ``resumed`` instead of
    inserting a second active run. A SQLAlchemy transaction is already
    open by the time this is called (prior read queries ran), so the
    statement joins it. No-op on SQLite (tests) — advisory locks don't
    exist there, and tests run executes sequentially, so the
    application-level ``_active_run`` check already suffices.
    """
    if db.get_bind().dialect.name == "postgresql":
        await db.execute(
            text("SELECT pg_advisory_xact_lock(:k)"),
            {"k": _CHANNEL_MIX_EXECUTE_LOCK_KEY},
        )


router = APIRouter(prefix=f"{API_V1_PREFIX}/wallet/channel-mix", tags=["channel-mix"])


# ─── Request / response shapes ────────────────────────────────────


class ChannelMixPlanRequest(BaseModel):
    """Inputs to the planner. The same inputs are re-supplied to
    ``execute`` so the planner can re-run and the token can be
    verified."""

    # ``target_capacity_sats`` is required for the parallel planner and
    # ignored for bootstrap (which sizes from deposit / target inbound).
    target_capacity_sats: Optional[int] = Field(default=None, gt=0, le=1_000_000_000)
    outbound_option: OutboundOption = Field(default="balanced")
    custom_inbound_pct: Optional[float] = Field(default=None, ge=0.0, le=100.0)
    peer_mix_mode: PeerMixMode = Field(default="recommended_diverse")
    manual_picks: Sequence[str] = Field(default=())
    leave_room_for_one_more: bool = False
    include_marginal_routing: bool = False

    # ── Bootstrap (capital-efficient inbound) inputs ──
    # ``mode="bootstrap"`` selects the sequential open→drain→recycle
    # planner/executor. ``bootstrap_input_kind`` picks the framing:
    # ``target`` (default — "I want ~X receivable") or ``deposit``
    # ("I have X to start").
    mode: Literal["parallel", "bootstrap"] = "parallel"
    bootstrap_input_kind: Literal["target", "deposit"] = "target"
    bootstrap_target_inbound_sats: Optional[int] = Field(
        default=None, ge=0, le=1_000_000_000
    )
    bootstrap_deposit_sats: Optional[int] = Field(
        default=None, ge=0, le=1_000_000_000
    )
    # Off by default: one final round that converts the un-drainable
    # residual to inbound via push_sat (permanently spent — plan §11.5).
    bootstrap_final_push_round: bool = False


class ChannelMixExecuteRequest(ChannelMixPlanRequest):
    """Same inputs as the plan request, plus the token the plan
    response returned. Token re-signature + plan-parity comparison is
    done server-side at execute time."""

    plan_token: str = Field(min_length=10, max_length=200)


class ChannelMixRunStopRequest(BaseModel):
    """Body for the run-stop endpoint. ``force=false`` (default) is the
    cooperative "stop after this round" request; ``force=true`` cancels
    the run immediately (recovery plan §1)."""

    force: bool = False


# ─── Helpers ──────────────────────────────────────────────────────


def _plan_to_dict(plan: "Plan | BootstrapPlan") -> dict[str, Any]:
    """Project a :class:`Plan` or :class:`BootstrapPlan` to a plain JSON
    dict for the response body. Tuples become lists; ``SmallChannelPeer``
    collapses to its catalog shape so the dashboard JS can share the
    catalog renderer.
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


def _selection_seed(request: ChannelMixPlanRequest) -> bytes:
    """Per-wallet, per-selection-inputs seed for weighted-random peer
    selection — keyed by this node's ``secret_key`` so every install fans
    out across providers, and stable across plan→execute (excludes the
    target amount) so the token re-derivation reproduces the same peers."""
    from app.services.channel_mix_planner import peer_selection_seed

    return peer_selection_seed(
        secret=settings.secret_key,
        network=settings.bitcoin_network,
        peer_mix_mode=request.peer_mix_mode,
        manual_picks=tuple(request.manual_picks),
        include_marginal_routing=request.include_marginal_routing,
    )


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
        target_capacity_sats=int(request.target_capacity_sats or 0),
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
        rng_seed=_selection_seed(request),
    )


async def _build_bootstrap_plan(request: ChannelMixPlanRequest) -> BootstrapPlan:
    """Run the bootstrap (capital-efficient inbound) planner.

    Resolves the live fee rates + eligible peer pool here (the pure
    :func:`derive_bootstrap_schedule` takes them as inputs), then
    simulates the open→drain→recycle loop for the chosen framing."""
    from app.services.boltz_service import (
        BOLTZ_MAX_AMOUNT_SATS,
        BOLTZ_MIN_AMOUNT_SATS,
    )
    from app.services.channel_mix_planner import (
        _resolve_fee_rates,
        derive_bootstrap_schedule,
        select_peers,
    )
    from app.services.mempool_fee_service import mempool_fee_service

    async def _oracle():
        return await mempool_fee_service.get_recommended_fees()

    medium, high, fee_warnings = await _resolve_fee_rates(_oracle)
    peers, axes = select_peers(
        network=settings.bitcoin_network,
        channel_count=64,  # full ordered eligible pool, not a cap
        mode=request.peer_mix_mode,
        manual_picks=tuple(request.manual_picks),
        include_marginal_routing=request.include_marginal_routing,
        rng_seed=_selection_seed(request),
    )

    deposit = None
    target = None
    if request.bootstrap_input_kind == "deposit":
        deposit = int(request.bootstrap_deposit_sats or 0)
    else:
        target = int(request.bootstrap_target_inbound_sats or 0)

    return derive_bootstrap_schedule(
        deposit_sats=deposit,
        target_inbound_sats=target,
        fee_rate_sat_vb_medium=medium,
        fee_rate_sat_vb_high=high,
        peers=peers,
        catalog_snapshot_date=SNAPSHOT_DATE,
        diversity_axes=axes,
        # Don't offer bootstrap when Boltz is unreachable (plan §7.1) —
        # the planner returns an empty schedule with an explanatory warning.
        boltz_available=await _resolve_boltz_available(),
        boltz_min=BOLTZ_MIN_AMOUNT_SATS,
        boltz_max=BOLTZ_MAX_AMOUNT_SATS,
        extra_warnings=list(fee_warnings),
    )


async def _active_run(db: AsyncSession) -> Optional[ChannelMixRun]:
    """Return any non-terminal channel-mix run (parallel or bootstrap),
    or None. Backs the one-active-run guard (plan §6a): two
    capital-consuming loops must never race the same UTXO set."""
    return (
        await db.execute(
            select(ChannelMixRun)
            .where(ChannelMixRun.state.in_(_NON_TERMINAL_RUN_STATES))
            .order_by(ChannelMixRun.started_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()


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
    if body.mode == "bootstrap":
        bootstrap = await _build_bootstrap_plan(body)
        return {
            "mode": "bootstrap",
            "plan": _plan_to_dict(bootstrap),
            "plan_token": sign_plan(bootstrap),
        }
    plan = await _build_plan(body)
    return {
        "mode": "parallel",
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
    is_bootstrap = body.mode == "bootstrap"

    if is_bootstrap:
        plan: Any = await _build_bootstrap_plan(plan_inputs)
        has_work = bool(plan.rounds)
    else:
        plan = await _build_plan(plan_inputs)
        has_work = bool(plan.per_channel)

    if not verify_plan_token(plan, body.plan_token):
        # Either the caller forged the token, the catalog refreshed, or
        # the fee oracle moved. Either way, the safe thing is to surface
        # a fresh plan and let the caller re-confirm.
        raise HTTPException(
            status_code=409,
            detail={
                "code": "plan_stale",
                "message": "The plan has changed since the token was issued — review and re-confirm.",
                "mode": body.mode,
                "plan": _plan_to_dict(plan),
                "plan_token": sign_plan(plan),
            },
        )
    if not has_work:
        raise HTTPException(
            status_code=400,
            detail={
                "code": "empty_plan",
                "message": (
                    "The planner produced no rounds for these inputs."
                    if is_bootstrap
                    else "The planner produced no channels for these inputs."
                ),
                "mode": body.mode,
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
        return {
            "mix_run_id": str(existing.id),
            "state": existing.state.value,
            "mode": existing.mode,
        }

    # Serialize the guard→insert→commit critical section across concurrent
    # executes (recovery plan §2). Acquired after the read-only token /
    # digest checks (those have their own UNIQUE backstop) and before the
    # guard, so two near-simultaneous distinct-plan executes can't both
    # pass the guard and create two active runs.
    await _acquire_execute_lock(db)

    # One-active-run guard (plan §6a): never start a second capital-
    # consuming loop while one is already in flight — two loops racing the
    # same UTXO set is the worst case for the concurrency failure modes.
    # Return the in-flight run so the UI resumes its progress view.
    active = await _active_run(db)
    if active is not None:
        return {
            "mix_run_id": str(active.id),
            "state": active.state.value,
            "mode": active.mode,
            "resumed": True,
        }

    if is_bootstrap:
        run = ChannelMixRun(
            api_key_id=admin_key.id,
            plan_token_digest=token_digest,
            state=ChannelMixRunState.QUEUED,
            mode="bootstrap",
            # For a bootstrap run these mirror the initial deposit; the
            # loop recomputes capacity from live balance each round.
            minimum_sats=plan.initial_deposit_sats,
            recommended_sats=plan.initial_deposit_sats,
            target_inbound_sats=plan.target_inbound_sats,
            channels=[],  # rounds appended as they run (not pre-materialized)
            warnings=list(plan.diagnostics.warnings),
            bootstrap_params={
                "peer_mix_mode": plan_inputs.peer_mix_mode,
                "manual_picks": list(plan_inputs.manual_picks),
                "include_marginal_routing": bool(
                    plan_inputs.include_marginal_routing
                ),
                "network": settings.bitcoin_network,
                "final_push_round": bool(plan_inputs.bootstrap_final_push_round),
                "deposit_sats": plan.initial_deposit_sats,
                "expected_total_inbound_sats": plan.expected_total_inbound_sats,
                "expected_rounds": plan.expected_rounds,
                "expected_total_fees_sats": plan.expected_total_fees_sats,
                "est_duration_minutes": plan.est_duration_minutes,
            },
        )
    else:
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
            return {
                "mix_run_id": str(existing.id),
                "state": existing.state.value,
                "mode": existing.mode,
            }
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
        "mode": run.mode,
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
        "mode": run.mode,
        "started_at": run.started_at.isoformat() if run.started_at else None,
        "updated_at": run.updated_at.isoformat() if run.updated_at else None,
        "completed_at": run.completed_at.isoformat() if run.completed_at else None,
        "minimum_sats": run.minimum_sats,
        "recommended_sats": run.recommended_sats,
        "target_inbound_sats": run.target_inbound_sats,
        "realized_inbound_sats": int(run.realized_inbound_sats or 0),
        "total_fees_sats": int(run.total_fees_sats or 0),
        "stop_requested": bool(run.stop_requested),
        "bootstrap_params": run.bootstrap_params,
        "channels": list(run.channels),
        "warnings": list(run.warnings),
        "error_message": run.error_message,
        "summary": _channels_summary(run),
    }


def _channels_summary(run: ChannelMixRun) -> dict[str, Any]:
    """Roll up the per-channel / per-round sub-states for polling."""
    channels = list(run.channels or [])
    if run.mode == "bootstrap":
        settled = sum(1 for c in channels if c.get("state") == "settled")
        failed = sum(
            1 for c in channels if c.get("state") in ("open_failed", "swap_failed")
        )
        in_flight = sum(
            1
            for c in channels
            if c.get("state") not in BOOTSTRAP_ROUND_TERMINAL_STATES
        )
        params = run.bootstrap_params or {}
        return {
            "mode": "bootstrap",
            "rounds_total": len(channels),
            "rounds_settled": settled,
            "rounds_failed": failed,
            "rounds_in_flight": in_flight,
            "expected_rounds": params.get("expected_rounds"),
            "realized_inbound_sats": int(run.realized_inbound_sats or 0),
            "expected_total_inbound_sats": params.get("expected_total_inbound_sats"),
            "target_inbound_sats": run.target_inbound_sats,
            "total_fees_sats": int(run.total_fees_sats or 0),
            "overall_state": run.state.value,
        }
    total = len(channels)
    active = sum(1 for c in channels if c.get("open_state") == "open_active")
    failed = sum(
        1 for c in channels
        if c.get("open_state") == "open_failed" or c.get("seed_state") == "seed_failed"
    )
    return {
        "mode": "parallel",
        "channels_total": total,
        "channels_active": active,
        "channels_failed": failed,
        "overall_state": run.state.value,
    }


@router.post("/runs/{mix_run_id}/stop")
async def post_channel_mix_run_stop(
    mix_run_id: UUID,
    body: ChannelMixRunStopRequest = ChannelMixRunStopRequest(),
    admin_key: APIKey = Depends(get_admin_key),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Stop a run — gracefully (default) or by force-cancelling now.

    * ``force=false`` (default): request a cooperative stop after the
      current round (the bootstrap "Stop after this round" control, plan
      §9 / §7.10). The executor lets the in-flight round settle (so a
      half-done swap isn't stranded), then finalizes instead of starting
      a new round. A no-op on an already-terminal run.
    * ``force=true``: mark the run terminal (``cancelled``) immediately,
      regardless of in-flight round/channel/swap state (recovery plan
      §1). The chain operations the run kicked off are independent and
      self-resolving (a broadcast open keeps confirming; an in-flight
      Boltz swap is driven to completion/refund by ``recover_boltz_swaps``),
      so cancelling strands nothing — it only stops the executor from
      starting *new* work and frees the one-active-run guard. The
      ``SELECT … FOR UPDATE`` serializes with any in-flight executor tick,
      so the cancel commits after the tick holding the row lock (the next
      tick early-returns on the terminal state). Idempotent on an
      already-terminal run.

      We also set ``stop_requested`` as belt-and-suspenders: the bootstrap
      executor commits mid-tick (open broadcast / swap create), which
      *releases* the row lock before its tick's final commit. Today every
      such path leaves the run non-dirty so the final commit can't clobber
      the cancel, but that's a fragile invariant — ``stop_requested``
      guarantees the run still finalizes cancelled at the next
      between-rounds check even if a future change reintroduced a clobber.
    """
    if body.force:
        run = (
            await db.execute(
                select(ChannelMixRun)
                .where(ChannelMixRun.id == mix_run_id)
                .with_for_update()
            )
        ).scalar_one_or_none()
        if run is None:
            raise HTTPException(status_code=404, detail="Channel-mix run not found")
        run.stop_requested = True
        finalize_run(run, ChannelMixRunState.CANCELLED)
        await db.commit()
        return {
            "mix_run_id": str(run.id),
            "state": run.state.value,
            "mode": run.mode,
            "stop_requested": bool(run.stop_requested),
        }

    run = (
        await db.execute(select(ChannelMixRun).where(ChannelMixRun.id == mix_run_id))
    ).scalar_one_or_none()
    if run is None:
        raise HTTPException(status_code=404, detail="Channel-mix run not found")
    if run.state not in TERMINAL_RUN_STATES and not run.stop_requested:
        run.stop_requested = True
        await db.commit()
    return {
        "mix_run_id": str(run.id),
        "state": run.state.value,
        "mode": run.mode,
        "stop_requested": bool(run.stop_requested),
    }


__all__ = ["router"]
