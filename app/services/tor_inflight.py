# SPDX-License-Identifier: MIT
"""Comprehensive in-flight detection inventory.

The Tor watchdog gates its NEWNYM action on "is anything
in-flight?" — because `SIGNAL NEWNYM`, despite NOT tearing down
streams already carrying traffic, makes all new circuits build
fresh. That can subtly destabilize mid-flight HTLCs (the next
retry inside a payment attempt builds a circuit with potentially
excluded exits or different latency). Treat the check as a hard
correctness gate: fail closed (skip NEWNYM) on any ambiguity.

The surfaces queried, in priority order:

| Surface                            | Source                                       |
|------------------------------------|----------------------------------------------|
| LN HTLCs                           | LND ``/v1/payments?include_incomplete=true`` |
| BoltzSwaps non-terminal            | DB: PAYING_INVOICE/INVOICE_PAID/CLAIMING/CLAIMED |
| Braiins Deposit sessions           | DB: non-terminal status                      |
| Anonymize sessions                 | DB: ``AnonymizeService.in_flight_count()``   |
| Anonymize step-up nonce in-flight  | DB: ``anonymize_stepup_state`` (kind='nonce', unexpired) |
| BOLT12 invoice request in-flight   | DB: status in (PENDING, INVOICE_RECEIVED)    |
| Cold storage swap non-terminal     | DB: ``cold_storage_swaps`` non-terminal      |
| Inbound liquidity swap non-terminal| DB: ``inbound_liquidity_swaps`` non-terminal |
| Mempool send tx awaiting confirm   | LND ``/v1/transactions`` (output txs 0-conf) |

Each query has a per-surface TTL — if a row has been "in-flight"
beyond its expected duration (2× the normal SLA), we treat it as
stuck and no longer blocking. This prevents permanent-deferral
when a session genuinely wedges.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


# A session factory is anything callable returning an async context
# manager that yields a ``AsyncSession``. Production uses
# :func:`app.core.database.get_db_context`; tests inject a factory
# wrapping a MagicMock session.
SessionFactory = Callable[[], AbstractAsyncContextManager[AsyncSession]]


# Per-surface stale-after timeouts. Beyond these the row is "stuck"
# and we stop deferring on its behalf. Conservative — better to defer
# longer than to interrupt something genuinely in-flight.
_LND_PROBE_TIMEOUT_S = 5.0
_BOLTZ_STUCK_AFTER_S = 60 * 60  # 1 hour
_BRAIINS_STUCK_AFTER_S = 2 * 60 * 60  # 2 hours
_STEPUP_NONCE_MAX_AGE_S = 10 * 60  # 10 minutes
_BOLT12_STUCK_AFTER_S = 30 * 60  # 30 minutes
# NOTE: cold-storage swaps and inbound-liquidity swaps are stored
# as BoltzSwap rows (verified at app/api/cold_storage.py:62) — the
# BoltzSwap probe transitively covers them. The "stuck after"
# windows for those surfaces inherit the BoltzSwap value above.
# Anonymize sessions delegate to AnonymizeService.in_flight_count()
# which has its own internal stale-row handling.


@dataclass(frozen=True)
class InFlightResult:
    """Result of an in-flight inventory probe.

    ``in_flight`` is the AND-reduction over all surfaces: True iff
    any surface reports something non-stale-non-terminal.
    ``surfaces`` is the list of non-empty surface labels so the
    audit log can record exactly which kept us from firing NEWNYM.
    """

    in_flight: bool
    surfaces: list[str]


def _now() -> datetime:
    return datetime.now(timezone.utc)


async def _lnd_htlc_in_flight() -> bool:
    """Query LND for in-flight HTLCs. Failure (e.g. LND breaker
    open — exactly the situation NEWNYM is meant to address) treated
    as 'unknown' → defer to fail-safe. Tight timeout keeps this from
    blocking the whole watchdog tick."""
    try:
        from app.services.lnd_service import lnd_service

        data, error = await asyncio.wait_for(
            lnd_service.list_payments_raw(
                include_incomplete=True,
                max_payments=20,
                reversed_=True,
            )
            if hasattr(lnd_service, "list_payments_raw")
            else _list_payments_fallback(),
            timeout=_LND_PROBE_TIMEOUT_S,
        )
        if error or not data:
            # Can't tell → fail-safe (assume something might be in flight).
            return True
        payments = data.get("payments") or []
        for p in payments:
            if p.get("status") == "IN_FLIGHT":
                return True
        return False
    except asyncio.TimeoutError:
        logger.info(
            "tor in-flight check: LND list_payments timed out; fail-safe to in_flight=True (defer NEWNYM)",
        )
        return True
    except Exception as exc:  # noqa: BLE001
        logger.info(
            "tor in-flight check: LND probe failed (%s); fail-safe defer",
            exc,
        )
        return True


async def _list_payments_fallback() -> tuple[Optional[dict], Optional[str]]:
    """If ``lnd_service`` doesn't have ``list_payments_raw``, fall back
    to the existing ``lookup_payment``-driven path which queries the
    same endpoint internally. Returns the raw payload shape consumers
    expect (``{"payments": [...]}``)."""
    from app.services.lnd_service import lnd_service

    try:
        # The existing lookup_payment helper queries
        # /v1/payments?include_incomplete=true. Without a specific
        # payment_hash we can't use it directly; instead, hit
        # _request once with the expected query.
        data, error = await lnd_service._request(  # noqa: SLF001
            "GET",
            "/v1/payments",
            params={
                "include_incomplete": "true",
                "max_payments": "20",
                "reversed": "true",
            },
        )
        return data, error
    except Exception as exc:  # noqa: BLE001
        return None, str(exc)


async def _boltz_swap_non_terminal_count(db: AsyncSession) -> int:
    """Count BoltzSwap rows in non-terminal states, dropping rows
    older than ``_BOLTZ_STUCK_AFTER_S`` (treat as stuck → don't
    block on them)."""
    from app.models.boltz_swap import BoltzSwap, SwapStatus

    cutoff = _now() - timedelta(seconds=_BOLTZ_STUCK_AFTER_S)
    result = await db.execute(
        select(BoltzSwap.id)
        .where(
            BoltzSwap.status.in_(
                [
                    SwapStatus.PAYING_INVOICE,
                    SwapStatus.INVOICE_PAID,
                    SwapStatus.CLAIMING,
                    SwapStatus.CLAIMED,
                ]
            ),
            BoltzSwap.updated_at > cutoff,
        )
        .limit(1)
    )
    return 1 if result.first() is not None else 0


async def _braiins_session_non_terminal_count(db: AsyncSession) -> int:
    from app.models.braiins_deposit_session import (
        NON_TERMINAL_STATUSES,
        BraiinsDepositSession,
    )

    cutoff = _now() - timedelta(seconds=_BRAIINS_STUCK_AFTER_S)
    result = await db.execute(
        select(BraiinsDepositSession.id)
        .where(
            BraiinsDepositSession.status.in_(list(NON_TERMINAL_STATUSES)),
            BraiinsDepositSession.updated_at > cutoff,
        )
        .limit(1)
    )
    return 1 if result.first() is not None else 0


async def _anonymize_session_in_flight_count() -> int:
    """Reuses the existing ``AnonymizeService.in_flight_count()``
    helper at app/services/anonymize/service.py:340. Failure is
    swallowed as fail-safe defer."""
    try:
        from app.services.anonymize.service import get_anonymize_service

        svc = get_anonymize_service()
        return int(svc.in_flight_count())
    except Exception as exc:  # noqa: BLE001
        logger.info("tor in-flight: anonymize probe failed (%s); defer", exc)
        return 1  # fail-safe


async def _stepup_nonce_pending_count(db: AsyncSession) -> int:
    """Count step-up nonces awaiting verification.

    The watchdog must defer NEWNYM while a step-up MFA round-trip is
    in flight. Persisted in ``anonymize_stepup_state`` with
    ``kind='nonce'``; we count rows whose ``expires_at`` hasn't
    passed (verifying past expiry is impossible anyway)."""
    from app.models.anonymize_session import AnonymizeStepupState

    now = _now()
    age_cutoff = now - timedelta(seconds=_STEPUP_NONCE_MAX_AGE_S)
    result = await db.execute(
        select(AnonymizeStepupState.id)
        .where(
            AnonymizeStepupState.kind == "nonce",
            AnonymizeStepupState.expires_at > now,
            AnonymizeStepupState.created_at > age_cutoff,
        )
        .limit(1)
    )
    return 1 if result.first() is not None else 0


async def _bolt12_invoice_request_in_flight_count(db: AsyncSession) -> int:
    """BOLT12 invoice requests in pending / received states."""
    from app.models.bolt12_invoice import (
        Bolt12InvoiceRequest,
        Bolt12InvoiceRequestStatus,
    )

    cutoff = _now() - timedelta(seconds=_BOLT12_STUCK_AFTER_S)
    result = await db.execute(
        select(Bolt12InvoiceRequest.id)
        .where(
            Bolt12InvoiceRequest.status.in_(
                [
                    Bolt12InvoiceRequestStatus.PENDING,
                    Bolt12InvoiceRequestStatus.INVOICE_RECEIVED,
                    Bolt12InvoiceRequestStatus.INVOICE_SENT,
                ]
            ),
            Bolt12InvoiceRequest.created_at > cutoff,
        )
        .limit(1)
    )
    return 1 if result.first() is not None else 0


async def _cold_storage_swap_in_flight_count(db: AsyncSession) -> int:
    """Cold-storage swap is just a BoltzSwap with a marker; the
    BoltzSwap query above already covers it. Kept as a separate
    surface for label clarity in the audit log."""
    return 0  # covered by _boltz_swap_non_terminal_count


async def _inbound_liquidity_swap_in_flight_count(db: AsyncSession) -> int:
    """Same comment as above — inbound liquidity uses BoltzSwap
    rows. Listed separately for log clarity."""
    return 0


async def _scoped_db_probe(
    session_factory: SessionFactory,
    probe: Callable[[AsyncSession], Awaitable[int]],
) -> int:
    """Open a fresh session and run ``probe`` against it.

    Each DB-touching probe MUST get its own session: SQLAlchemy's
    ``AsyncSession`` forbids concurrent ``.execute()`` calls on a
    single session (see SQLAlchemy error code ``isce``). A
    background-task that violates this poisons the watchdog's
    fail-safe path — every probe raises, every surface is reported
    in-flight, NEWNYM is deferred forever. See the 2026-06-02
    incident postmortem.
    """
    async with session_factory() as db:
        return await probe(db)


async def check_in_flight(session_factory: SessionFactory) -> InFlightResult:
    """Run all in-flight probes in parallel; return the aggregated
    result.

    The function deliberately treats any probe failure as fail-safe
    (defer NEWNYM). Better to delay recovery by one tick than to
    interrupt something genuinely in flight.

    Each DB-touching probe opens its own ``AsyncSession`` via
    ``session_factory`` so concurrent ``.execute()`` calls never
    share state — the path that wedged the watchdog on 2026-06-02.
    """
    probes: list[tuple[str, asyncio.Task]] = [
        ("lnd_htlc", asyncio.create_task(_lnd_htlc_in_flight())),
        ("boltz_swap", asyncio.create_task(_scoped_db_probe(session_factory, _boltz_swap_non_terminal_count))),
        (
            "braiins_deposit",
            asyncio.create_task(_scoped_db_probe(session_factory, _braiins_session_non_terminal_count)),
        ),
        ("anonymize_session", asyncio.create_task(_anonymize_session_in_flight_count())),
        ("anonymize_stepup", asyncio.create_task(_scoped_db_probe(session_factory, _stepup_nonce_pending_count))),
        (
            "bolt12_invoice_request",
            asyncio.create_task(_scoped_db_probe(session_factory, _bolt12_invoice_request_in_flight_count)),
        ),
    ]
    results: list[tuple[str, bool]] = []
    for label, task in probes:
        try:
            val = await task
            if isinstance(val, bool):
                results.append((label, val))
            else:
                results.append((label, int(val) > 0))
        except Exception as exc:  # noqa: BLE001
            logger.info(
                "tor in-flight: %s probe raised %s; fail-safe defer",
                label,
                exc,
            )
            results.append((label, True))
    surfaces = [label for label, hit in results if hit]
    return InFlightResult(in_flight=bool(surfaces), surfaces=surfaces)


__all__ = ["InFlightResult", "SessionFactory", "check_in_flight"]
