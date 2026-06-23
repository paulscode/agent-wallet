# SPDX-License-Identifier: MIT
"""Periodic scan for residual wallet-controlled L-BTC outputs.

When the LN->L-BTC leg of a Liquid hop succeeds but the L-BTC->LN
leg cannot be cooperatively or unilaterally driven to completion
(operator outage past timeout, or the operator refuses to settle),
the wallet ends up holding L-BTC at a per-session SLIP-77-derived
address. This task is the *detection* half of the residual-
recovery flow: it walks the candidate set of sessions, derives
the per-session Liquid output material, queries electrs-liquid for
unspent outputs at that address, locally unblinds them, and
upserts each L-BTC residual into ``liquid_residual_outputs``.

Sweeping the residual back to Lightning is a separate concern
handled by ``liquid_residual_recovery`` (one-shot L-BTC->LN
submarine swap per row).

Design choices kept intentionally simple for v1:

* Caller picks the candidate session set (e.g. all terminal
  sessions whose ``liquid_blinding_seed_enc`` is non-null). The
  task does not assume any particular SQL filter — it accepts the
  candidates and processes them.
* Upsert is idempotent on ``(txid, vout)`` thanks to the table's
  unique constraint: re-scans of the same UTXO update
  ``last_seen_at`` rather than inserting a duplicate.
* Outputs that fail to unblind under the per-session blinding key
  are silently skipped (they may belong to a different swap on a
  collision-resistant address; rate is effectively zero but
  defensive).
* Non-L-BTC outputs (e.g. a USDT or other Liquid asset that
  somehow landed at the address) are NOT inserted — they fall
  outside the recovery scope.
* The scan does not delete rows whose UTXOs are no longer
  on-chain (e.g. swept by a subsequent recovery). Spent rows are
  pinned by ``recovered_at`` instead, so the audit history stays
  intact.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Iterable, Optional
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.anonymize_session import (
    ANONYMIZE_TERMINAL_STATUSES,
    AnonymizeSession,
    LiquidResidualOutput,
)
from app.services.anonymize.liquid_backend import LiquidBackend
from app.services.anonymize.liquid_receive import (
    LiquidReceiveError,
    UnblindedUtxo,
    unblind_liquid_utxo,
)
from app.services.anonymize.liquid_seed import (
    LiquidSeedError,
    decrypt_session_blinding_seed_index,
    derive_session_liquid_output,
)
from app.services.anonymize.metadata import ANONYMIZE_LOGGER_NAME

if TYPE_CHECKING:
    from app.services.anonymize.liquid_address import LiquidNetwork

logger = logging.getLogger(ANONYMIZE_LOGGER_NAME)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class ResidualScanSummary:
    """Outcome of one scan pass.

    Returned to the caller (or surfaced in logs) so the
    background-task plumbing can size the next sleep interval +
    emit metrics.
    """

    sessions_scanned: int = 0
    sessions_skipped: int = 0
    utxos_observed: int = 0
    residuals_inserted: int = 0
    residuals_seen_again: int = 0
    backend_errors: tuple[str, ...] = field(default_factory=tuple)
    decode_errors: tuple[str, ...] = field(default_factory=tuple)


def _derivation_label(session_id: UUID, index: int) -> str:
    """Stable string used as the ``derivation_path`` column value.

    The Liquid spending key is HMAC-derived (per
    ``_derive_spending_privkey``) rather than BIP-32, so there is no
    literal m/.../* path. We persist the conceptual derivation so
    an operator can re-derive the exact key from the seed without
    having to dig through code.
    """
    return f"anonymize-liquid-spend|{session_id}|{index}"


async def _upsert_residual(
    db: AsyncSession,
    *,
    session: AnonymizeSession,
    derivation_index: int,
    ct_address: str,
    asset_id_hex: str,
    txid: str,
    vout: int,
    value_sat: int,
) -> bool:
    """Insert a residual row or refresh ``last_seen_at`` on an
    existing one. Returns ``True`` on insert, ``False`` on refresh.
    """
    existing = (
        await db.execute(
            select(LiquidResidualOutput)
            .where(LiquidResidualOutput.txid == txid)
            .where(LiquidResidualOutput.vout == vout)
        )
    ).scalar_one_or_none()
    now = _utc_now()
    if existing is not None:
        existing.last_seen_at = now
        return False
    db.add(
        LiquidResidualOutput(
            id=uuid4(),
            session_id=session.id,
            txid=txid,
            vout=int(vout),
            asset_id=asset_id_hex,
            value_sat=int(value_sat),
            address=ct_address,
            derivation_path=_derivation_label(session.id, derivation_index),
            discovered_at=now,
            last_seen_at=now,
        )
    )
    return True


async def scan_residual_liquid_balances(
    *,
    db: AsyncSession,
    backend: LiquidBackend,
    candidate_sessions: Iterable[AnonymizeSession],
    master_blinding_key: bytes,
    network: LiquidNetwork,  # imported under TYPE_CHECKING to avoid a runtime circular import
    lbtc_asset_id: bytes,
) -> ResidualScanSummary:
    """Walk ``candidate_sessions`` and record residual L-BTC at the
    per-session wallet-controlled address.

    The caller is responsible for narrowing the candidate set
    (typically: sessions whose ``liquid_blinding_seed_enc`` is set
    AND whose status is terminal so an in-flight lockup is not
    mistaken for a residual). Sessions missing the encrypted
    blinding-seed index are skipped with a count bumped on the
    summary.

    The backend MUST be the wallet's electrs-liquid client. The
    scan does not commit — the caller controls the transaction
    boundary so it can batch multiple scans or rollback on policy
    failure.
    """
    summary_kwargs: dict[str, int] = {
        "sessions_scanned": 0,
        "sessions_skipped": 0,
        "utxos_observed": 0,
        "residuals_inserted": 0,
        "residuals_seen_again": 0,
    }
    backend_errors: list[str] = []
    decode_errors: list[str] = []
    lbtc_asset_id_hex = lbtc_asset_id.hex()

    for session in candidate_sessions:
        if not session.liquid_blinding_seed_enc:
            summary_kwargs["sessions_skipped"] = int(summary_kwargs["sessions_skipped"]) + 1
            continue

        try:
            derivation_index = decrypt_session_blinding_seed_index(
                session.liquid_blinding_seed_enc,
            )
        except LiquidSeedError as exc:
            decode_errors.append(f"{session.id}:blinding_seed_decrypt:{exc}")
            summary_kwargs["sessions_skipped"] = int(summary_kwargs["sessions_skipped"]) + 1
            continue

        try:
            material = derive_session_liquid_output(
                master_blinding_key=master_blinding_key,
                session_id=session.id,
                derivation_index=derivation_index,
                network=network,
            )
        except LiquidSeedError as exc:
            decode_errors.append(f"{session.id}:derive:{exc}")
            summary_kwargs["sessions_skipped"] = int(summary_kwargs["sessions_skipped"]) + 1
            continue

        summary_kwargs["sessions_scanned"] = int(summary_kwargs["sessions_scanned"]) + 1

        utxos, err = await backend.get_address_utxos(
            script_pubkey=material.script_pubkey,
        )
        if err is not None:
            backend_errors.append(f"{session.id}:{err}")
            continue
        if not utxos:
            continue

        for utxo in utxos:
            summary_kwargs["utxos_observed"] = int(summary_kwargs["utxos_observed"]) + 1
            try:
                unblinded: UnblindedUtxo = unblind_liquid_utxo(
                    utxo=utxo,
                    blinding_privkey=material.blinding_privkey,
                )
            except LiquidReceiveError:
                # Not for us — silently skip.
                continue
            if unblinded.asset_id != lbtc_asset_id:
                # Non-L-BTC residual — out of scope for this recovery
                # path. We do NOT surface it as a residual; the
                # operator would have no sweep target anyway.
                continue
            if unblinded.value_sat <= 0:
                # CHECK constraint refuses this; skip defensively.
                continue
            try:
                inserted = await _upsert_residual(
                    db,
                    session=session,
                    derivation_index=derivation_index,
                    ct_address=material.ct_address,
                    asset_id_hex=lbtc_asset_id_hex,
                    txid=utxo.txid,
                    vout=utxo.vout,
                    value_sat=unblinded.value_sat,
                )
            except Exception as exc:  # noqa: BLE001
                # DB-level failure on a single row: log + continue
                # so a single bad row doesn't poison the whole scan.
                decode_errors.append(f"{session.id}:upsert:{exc}")
                continue
            if inserted:
                summary_kwargs["residuals_inserted"] = int(summary_kwargs["residuals_inserted"]) + 1
            else:
                summary_kwargs["residuals_seen_again"] = int(summary_kwargs["residuals_seen_again"]) + 1

    return ResidualScanSummary(
        sessions_scanned=int(summary_kwargs["sessions_scanned"]),
        sessions_skipped=int(summary_kwargs["sessions_skipped"]),
        utxos_observed=int(summary_kwargs["utxos_observed"]),
        residuals_inserted=int(summary_kwargs["residuals_inserted"]),
        residuals_seen_again=int(summary_kwargs["residuals_seen_again"]),
        backend_errors=tuple(backend_errors),
        decode_errors=tuple(decode_errors),
    )


async def select_residual_scan_candidates(
    db: AsyncSession,
    *,
    statuses: Optional[tuple[str, ...]] = None,
) -> list[AnonymizeSession]:
    """Default candidate-selection query.

    Returns sessions with a non-NULL ``liquid_blinding_seed_enc``
    whose status is terminal (the default). Restricting to terminal
    sessions ensures an in-flight lockup — a session still running its
    own hop / recovery loop against the same wallet-controlled output —
    is not mistaken for a residual and swept a second time. Callers may
    override the status filter for targeted scans (e.g. a manual
    "rescan one session" admin endpoint).
    """
    if statuses is None:
        statuses = tuple(sorted(ANONYMIZE_TERMINAL_STATUSES))

    result = await db.execute(
        select(AnonymizeSession)
        .where(AnonymizeSession.liquid_blinding_seed_enc.is_not(None))
        .where(AnonymizeSession.status.in_(statuses))
    )
    return list(result.scalars().all())


__all__ = [
    "ResidualScanSummary",
    "scan_residual_liquid_balances",
    "select_residual_scan_candidates",
]
