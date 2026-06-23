# SPDX-License-Identifier: MIT
"""One-shot L-BTC -> LN recovery of a residual wallet-controlled output.

This is the *recovery* half of the residual flow whose detection
side lives in :mod:`app.tasks.liquid_residual_scan`. It runs
**outside** the Anonymize session state machine: each call drives
exactly one submarine swap that sweeps a single
``LiquidResidualOutput`` row's UTXO back to the wallet's Lightning
channels.

Flow (per residual):

1. Load the residual row + its originating session.
2. Re-derive the per-session SLIP-77 spending + blinding material.
3. Fetch the UTXO from the Liquid backend, re-unblind it locally
   to recover the asset / value blinding factors that the scan
   task discarded.
4. Mint a fresh LN invoice for ``value_sat - operator_fee_buffer``.
5. Post a submarine swap request to the L-BTC -> LN operator.
6. Build + broadcast the Liquid spend that funds the operator's
   lockup address, reusing the existing
   :mod:`liquid_lock_subprocess` builder.
7. Stamp ``recovered_swap_id`` on the row. ``recovered_at`` is
   set only after :func:`finalize_residual_recovery` observes the
   LN invoice settlement.

A failure at any step leaves the row un-recovered; the dashboard
banner will re-surface it on the next render. Each retry is a
fresh swap (no swap-id reuse).

The dust threshold check is enforced at the boundary:
``value_sat < settings.liquid_residual_dust_threshold_sat`` is
refused with :class:`ResidualRecoveryNotEligibleError` regardless of
``dust_acknowledged_at`` — acknowledged-dust rows are
deliberately *non-recoverable*; un-acknowledging restores
recoverability iff the threshold check now passes (e.g. operator
lowered the threshold via config).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Optional, Protocol
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.anonymize_session import (
    ANONYMIZE_TERMINAL_STATUSES,
    AnonymizeSession,
    LiquidResidualOutput,
)
from app.services.anonymize.liquid_backend import LiquidBackend, LiquidUtxo
from app.services.anonymize.liquid_lock_subprocess import (
    LiquidLockIntegrationNotVerifiedError,
    LiquidLockRequest,
    LiquidLockResult,
    LiquidLockSubprocessError,
)
from app.services.anonymize.liquid_receive import (
    LiquidReceiveError,
    unblind_liquid_utxo,
)
from app.services.anonymize.liquid_seed import (
    LiquidSeedError,
    decrypt_session_blinding_seed_index,
    derive_session_liquid_output,
)
from app.services.anonymize.metadata import ANONYMIZE_LOGGER_NAME
from app.services.boltz_lockup_verify import verify_liquid_lockup_address

logger = logging.getLogger(ANONYMIZE_LOGGER_NAME)


# ── Errors ──────────────────────────────────────────────────────────


class ResidualRecoveryError(RuntimeError):
    """Base class for residual-recovery failures."""


class ResidualRecoveryNotFoundError(ResidualRecoveryError):
    """No residual row with the given id."""


class ResidualRecoveryNotEligibleError(ResidualRecoveryError):
    """Row is not eligible for swap-out.

    Covers: already-recovered rows (``recovered_at`` set),
    sub-dust-threshold rows, and rows whose originating session has
    been retention-purged (``session_id`` NULL — we cannot
    re-derive the spending key without the session id).
    """


# ── Protocols ───────────────────────────────────────────────────────


class _LndInvoiceCreator(Protocol):
    async def __call__(
        self,
        *,
        amount_sat: int,
        memo: str,
    ) -> tuple[Any, Optional[str]]: ...


class _LndInvoiceLookup(Protocol):
    async def __call__(
        self,
        payment_hash_hex: str,
    ) -> tuple[Any, Optional[str]]: ...


class _SubmarineSwapCreator(Protocol):
    """Subset of :class:`LiquidSwapClient` we need.

    Real callers pass a fully-configured
    ``LiquidSwapClient`` bound to the lbtc-to-ln operator URL
    chosen at startup via :func:`select_liquid_leg_urls`.
    """

    async def create_submarine_swap_from_lbtc(
        self,
        *,
        invoice: str,
        refund_public_key_hex: str,
    ) -> tuple[Any, Optional[str]]: ...


_LockSubprocessFn = Callable[[LiquidLockRequest], Awaitable[LiquidLockResult]]


# ── Dependency bundle ───────────────────────────────────────────────


@dataclass(frozen=True)
class ResidualRecoveryDeps:
    """Composable dependency bundle.

    Real callers build this once at process startup; tests inject
    fakes per-case.
    """

    backend: LiquidBackend
    submarine_client: _SubmarineSwapCreator
    lnd_create_invoice: _LndInvoiceCreator
    run_lock_subprocess: _LockSubprocessFn
    master_blinding_key: bytes
    lbtc_asset_id: bytes
    network: Any  # LiquidNetwork — kept loose to avoid circular import
    boltz_url: str
    # When ``None`` the backend's fee oracle is consulted. The
    # subprocess later clamps with the operator-configured floor.
    fee_rate_sat_per_vb: Optional[float] = None
    # Subtracted from the residual value before the LN invoice is
    # minted. Covers operator fee + on-chain fee allowance.
    operator_fee_buffer_sat: int = 1000
    # Whether to also call ``run_lock_subprocess`` (False useful for
    # dry-run / preview endpoints; real recovery sets True).
    broadcast: bool = True
    # Optional generator for the per-recovery refund keypair —
    # tests inject a deterministic generator.
    generate_swap_keypair: Optional[Callable[[], tuple[str, str]]] = None
    # Optional override for the LN-invoice payment-hash lookup
    # used by :func:`finalize_residual_recovery`. Kept on the deps
    # bundle so the API layer can wire a single object.
    lnd_lookup_invoice: Optional[_LndInvoiceLookup] = None


# ── Result ──────────────────────────────────────────────────────────


@dataclass(frozen=True)
class ResidualRecoveryResult:
    """Outcome of an :func:`initiate_residual_recovery` call.

    ``recovered_at_set`` is True only when the LN invoice was
    already observed settled inside this call. Otherwise the
    caller (or a periodic ``finalize_residual_recovery`` sweep)
    must follow up.
    """

    residual_id: UUID
    swap_id: str
    lockup_address: str
    lockup_txid: str
    invoice_payment_hash_hex: str
    expected_amount_sat: int
    recovered_at_set: bool


# ── Helpers ─────────────────────────────────────────────────────────


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


async def _load_residual(
    db: AsyncSession,
    residual_id: UUID,
) -> LiquidResidualOutput:
    # Hold the row under ``FOR UPDATE`` for the life of the caller's
    # transaction so concurrent swap-outs of the same residual
    # serialize: a second caller blocks here until the first commits,
    # then re-reads the stamped ``recovered_swap_id`` and is rejected
    # by ``_check_eligible``. This is the single-UTXO analogue of the
    # Braiins deposit service's ``_select_for_update`` guard. SQLite
    # (tests) cannot lock rows, so fall back to a plain read.
    locked_stmt = select(LiquidResidualOutput).where(LiquidResidualOutput.id == residual_id).with_for_update()
    try:
        row = (await db.execute(locked_stmt)).scalar_one_or_none()
    except Exception:  # noqa: BLE001 — dialect without row locking
        row = (
            await db.execute(select(LiquidResidualOutput).where(LiquidResidualOutput.id == residual_id))
        ).scalar_one_or_none()
    if row is None:
        raise ResidualRecoveryNotFoundError(f"no residual row {residual_id}")
    return row


async def _load_session_for(
    db: AsyncSession,
    session_id: Optional[UUID],
) -> AnonymizeSession:
    if session_id is None:
        raise ResidualRecoveryNotEligibleError(
            "residual row has no session_id (originating session was retention-purged); cannot re-derive spending key"
        )
    sess = (await db.execute(select(AnonymizeSession).where(AnonymizeSession.id == session_id))).scalar_one_or_none()
    if sess is None:
        raise ResidualRecoveryNotEligibleError(f"originating session {session_id} not found")
    # Recovery may only run once the originating session is quiesced.
    # A non-terminal session can still have its own hop / recovery loop
    # acting on the same SLIP-77-derived L-BTC output, and driving a
    # swap-out here would build a second spend of that UTXO from a
    # different subsystem (the per-row lock in ``_load_residual`` does
    # not cover that cross-path race). Fails closed.
    if sess.status not in ANONYMIZE_TERMINAL_STATUSES:
        raise ResidualRecoveryNotEligibleError(
            f"originating session {session_id} is still in flight "
            f"(status={sess.status!r}); residual recovery is only safe "
            f"once the session has reached a terminal state"
        )
    return sess


def _check_eligible(row: LiquidResidualOutput) -> None:
    if row.recovered_at is not None:
        raise ResidualRecoveryNotEligibleError(f"residual already recovered at {row.recovered_at.isoformat()}")
    # ``recovered_swap_id`` is stamped as soon as the recovery lock is
    # broadcast — before the LN settle that sets ``recovered_at``. A
    # retry/double-click in that window would mint a second swap and
    # broadcast a second lock spend of the same UTXO, so it must also
    # gate eligibility.
    if row.recovered_swap_id is not None:
        raise ResidualRecoveryNotEligibleError(
            f"residual recovery already in flight (swap {row.recovered_swap_id}); awaiting settlement"
        )
    threshold = int(settings.liquid_residual_dust_threshold_sat)
    if row.value_sat < threshold:
        raise ResidualRecoveryNotEligibleError(
            f"residual value {row.value_sat} sat is below the "
            f"dust threshold {threshold} sat; swap-out fees would "
            f"exceed the recovered amount"
        )


def _locate_utxo(
    utxos: list[LiquidUtxo],
    txid: str,
    vout: int,
) -> LiquidUtxo:
    for u in utxos:
        if u.txid == txid and int(u.vout) == int(vout):
            return u
    raise ResidualRecoveryError(
        f"backend does not list residual UTXO {txid}:{vout} as "
        f"unspent — it may have been swept by another flow; "
        f"re-run the scan task to refresh the row"
    )


def _default_keypair_generator() -> tuple[str, str]:
    # Local import to avoid pulling boltz_service eagerly at module
    # import time (which would tug in a number of optional deps).
    from app.services.boltz_service import _generate_keypair

    return _generate_keypair()


# ── Public API ──────────────────────────────────────────────────────


async def initiate_residual_recovery(
    *,
    db: AsyncSession,
    residual_id: UUID,
    deps: ResidualRecoveryDeps,
) -> ResidualRecoveryResult:
    """Drive a single L-BTC -> LN swap-out for the given residual.

    The caller controls the DB transaction boundary. On any error
    the row stays un-recovered (the function does not write
    ``recovered_swap_id`` until after the lock subprocess returns
    successfully). On success ``recovered_swap_id`` is set; the
    final ``recovered_at`` stamp is deferred to
    :func:`finalize_residual_recovery`.
    """

    row = await _load_residual(db, residual_id)
    _check_eligible(row)
    session = await _load_session_for(db, row.session_id)

    # ── Re-derive the per-session material ────────────────────────
    if not session.liquid_blinding_seed_enc:
        raise ResidualRecoveryNotEligibleError(
            "originating session has no liquid_blinding_seed_enc; cannot re-derive spending key"
        )
    try:
        derivation_index = decrypt_session_blinding_seed_index(
            session.liquid_blinding_seed_enc,
        )
        material = derive_session_liquid_output(
            master_blinding_key=deps.master_blinding_key,
            session_id=session.id,
            derivation_index=derivation_index,
            network=deps.network,
        )
    except LiquidSeedError as exc:
        raise ResidualRecoveryError(f"key re-derivation failed: {exc}") from exc

    # ── Fetch + re-unblind the UTXO ───────────────────────────────
    utxos, err = await deps.backend.get_address_utxos(
        script_pubkey=material.script_pubkey,
    )
    if err is not None:
        raise ResidualRecoveryError(f"backend get_address_utxos: {err}")
    utxo = _locate_utxo(list(utxos or ()), row.txid, row.vout)

    try:
        unblinded = unblind_liquid_utxo(
            utxo=utxo,
            blinding_privkey=material.blinding_privkey,
        )
    except LiquidReceiveError as exc:
        raise ResidualRecoveryError(f"could not unblind residual UTXO: {exc}") from exc

    if unblinded.asset_id != deps.lbtc_asset_id:
        raise ResidualRecoveryError("residual UTXO asset id no longer matches L-BTC — refusing")
    if int(unblinded.value_sat) != int(row.value_sat):
        raise ResidualRecoveryError(
            f"on-chain value {unblinded.value_sat} differs from recorded {row.value_sat}; re-run scan to resolve"
        )

    # ── Mint LN invoice ───────────────────────────────────────────
    invoice_amount_sat = int(row.value_sat) - int(deps.operator_fee_buffer_sat)
    if invoice_amount_sat <= 0:
        raise ResidualRecoveryNotEligibleError(
            f"residual value {row.value_sat} sat does not cover the "
            f"operator fee buffer {deps.operator_fee_buffer_sat} sat"
        )
    inv_result, inv_err = await deps.lnd_create_invoice(
        amount_sat=invoice_amount_sat,
        memo=f"anonymize-liquid-residual-{row.id}",
    )
    if inv_err is not None or inv_result is None:
        raise ResidualRecoveryError(f"lnd_create_invoice failed: {inv_err}")
    invoice = inv_result.get("bolt11") if isinstance(inv_result, dict) else getattr(inv_result, "payment_request", None)
    payment_hash = (
        inv_result.get("payment_hash") if isinstance(inv_result, dict) else getattr(inv_result, "r_hash", None)
    )
    if not invoice:
        raise ResidualRecoveryError("lnd_create_invoice returned no bolt11")
    payment_hash_hex = str(payment_hash or "")

    # ── Create submarine swap ─────────────────────────────────────
    kp_gen = deps.generate_swap_keypair or _default_keypair_generator
    refund_priv_hex, refund_pub_hex = kp_gen()
    swap, swap_err = await deps.submarine_client.create_submarine_swap_from_lbtc(
        invoice=invoice,
        refund_public_key_hex=refund_pub_hex,
    )
    if swap_err is not None or swap is None:
        raise ResidualRecoveryError(f"create_submarine_swap_from_lbtc: {swap_err or 'no swap'}")

    # Verify the operator-supplied lockup commits to the swap tree + OUR
    # refund key BEFORE funding it (same theft guard as the live L-BTC→LN
    # hop). Without this, a malicious operator could return an address it
    # solely controls, take the recovered L-BTC, and leave no refundable
    # script. Fails closed.
    ok, reason = verify_liquid_lockup_address(
        swap_tree=swap.swap_tree,
        lockup_address=str(swap.address),
        network=_network_to_subprocess_name(deps.network),
        swap_type="submarine",
        verify_leaf="refund",
        refund_public_key_hex=refund_pub_hex,
        claim_public_key_hex=swap.claim_public_key_hex,
        asset_id_hex=deps.lbtc_asset_id.hex(),
    )
    if not ok:
        raise ResidualRecoveryError(f"liquid residual lockup verification failed: {reason}")

    # The on-chain L-BTC amount the operator asks us to lock. It must
    # not exceed the residual UTXO's value (we cannot lock more than we
    # hold) and a non-positive amount is nonsensical. Because the minted
    # invoice is ``value_sat - operator_fee_buffer_sat``, bounding the
    # lockup to ``value_sat`` also caps the operator's implied fee to the
    # configured buffer — the operator's economic figure is not taken on
    # faith. Fails closed.
    expected_amount = int(swap.expected_amount_sat)
    lockup_address = str(swap.address)
    if expected_amount <= 0 or expected_amount > int(row.value_sat):
        raise ResidualRecoveryError(
            f"operator lockup amount {expected_amount} sat is out of range "
            f"for residual value {row.value_sat} sat — refusing"
        )

    # ── Reserve the recovery before acting ────────────────────────
    # Stamp and commit the swap id BEFORE broadcasting the lock spend, so a
    # crash between broadcast and stamp cannot leave the row eligible: a
    # retry re-reads the committed ``recovered_swap_id`` and ``_check_eligible``
    # rejects it, rather than minting a second swap and double-broadcasting the
    # same residual UTXO. A clean broadcast failure releases the reservation
    # (below) so the residual can be retried; only a hard crash leaves it
    # stamped, which blocks retries until an operator confirms the on-chain
    # state — the fund-safe default.
    row.recovered_swap_id = swap.id
    row.last_seen_at = _utc_now()
    await db.commit()

    # ── Build + broadcast the Liquid lock spend ───────────────────
    prevout_hex, prev_err = await deps.backend.get_transaction_hex(row.txid)
    if prev_err is not None or not prevout_hex:
        await _release_residual_reservation(db, residual_id)
        raise ResidualRecoveryError(f"backend get_transaction_hex: {prev_err or 'empty'}")

    fee_rate = deps.fee_rate_sat_per_vb
    if fee_rate is None:
        fee_oracle, fee_err = await deps.backend.estimate_fee_sat_per_vb(
            target_blocks=6,
        )
        if fee_err is None and fee_oracle is not None:
            fee_rate = float(fee_oracle)
        else:
            fee_rate = float(
                getattr(
                    settings,
                    "anonymize_liquid_fee_rate_floor_sat_per_vb",
                    0.1,
                )
            )

    lockup_txid = ""
    if deps.broadcast:
        request = LiquidLockRequest(
            utxo_txid=row.txid,
            utxo_vout=int(row.vout),
            utxo_value_sat=int(unblinded.value_sat),
            utxo_asset_id_hex=unblinded.asset_id.hex(),
            utxo_asset_blinding_factor_hex=unblinded.asset_blinding_factor.hex(),
            utxo_value_blinding_factor_hex=unblinded.value_blinding_factor.hex(),
            utxo_prevout_tx_hex=str(prevout_hex),
            utxo_script_pubkey_hex=material.script_pubkey.hex(),
            spending_private_key_hex=material.spending_privkey.hex(),
            destination_address=lockup_address,
            destination_amount_sat=expected_amount,
            fee_sat_per_vbyte=float(fee_rate),
            change_address=material.ct_address,
            network=_network_to_subprocess_name(deps.network),
            asset_id_hex=deps.lbtc_asset_id.hex(),
            boltz_url=deps.boltz_url,
        )
        try:
            lock_result = await deps.run_lock_subprocess(request)
        except LiquidLockIntegrationNotVerifiedError as exc:
            await _release_residual_reservation(db, residual_id)
            raise ResidualRecoveryError(str(exc)) from exc
        except LiquidLockSubprocessError as exc:
            await _release_residual_reservation(db, residual_id)
            raise ResidualRecoveryError(f"liquid lock subprocess failed: {exc}") from exc
        lockup_txid = lock_result.txid

    # The reservation was committed before the broadcast above; here we only
    # refresh the bookkeeping timestamp on the (already-reserved) row.
    row.last_seen_at = _utc_now()

    # Opportunistic settlement check: rare in practice (Boltz needs
    # at least one confirmation before paying the invoice) but
    # cheap to attempt — and useful in regtest.
    recovered_at_set = False
    if deps.lnd_lookup_invoice is not None and payment_hash_hex:
        settled = await _check_invoice_settled(
            deps.lnd_lookup_invoice,
            payment_hash_hex,
        )
        if settled:
            row.recovered_at = _utc_now()
            recovered_at_set = True

    return ResidualRecoveryResult(
        residual_id=row.id,
        swap_id=str(swap.id),
        lockup_address=lockup_address,
        lockup_txid=lockup_txid,
        invoice_payment_hash_hex=payment_hash_hex,
        expected_amount_sat=expected_amount,
        recovered_at_set=recovered_at_set,
    )


async def _release_residual_reservation(db: AsyncSession, residual_id: UUID) -> None:
    """Clear a pre-broadcast ``recovered_swap_id`` reservation after a clean
    broadcast failure so the residual can be retried. Best-effort: a failure
    to release leaves the row reserved, which is the fund-safe direction.
    """
    try:
        row = await _load_residual(db, residual_id)
        row.recovered_swap_id = None
        await db.commit()
    except Exception as exc:  # noqa: BLE001
        logger.warning("residual recovery: could not release reservation %s: %s", residual_id, exc)


async def finalize_residual_recovery(
    *,
    db: AsyncSession,
    residual_id: UUID,
    lnd_lookup_invoice: _LndInvoiceLookup,
    payment_hash_hex: str,
) -> bool:
    """Stamp ``recovered_at`` iff the LN invoice has settled.

    Returns ``True`` on stamp, ``False`` if the invoice is not yet
    settled. The caller controls the transaction boundary.

    ``payment_hash_hex`` is supplied by the caller (the API layer
    persists it alongside ``recovered_swap_id`` when initiating).
    Keeping it parameter-passed avoids adding a payment-hash column
    to ``liquid_residual_outputs`` for what is purely transient
    state.
    """
    row = await _load_residual(db, residual_id)
    if row.recovered_at is not None:
        return True
    if not row.recovered_swap_id:
        raise ResidualRecoveryNotEligibleError(
            "residual has no recovered_swap_id; call initiate_residual_recovery first"
        )
    if not payment_hash_hex:
        raise ResidualRecoveryError("missing payment_hash_hex")
    settled = await _check_invoice_settled(
        lnd_lookup_invoice,
        payment_hash_hex,
    )
    if not settled:
        return False
    row.recovered_at = _utc_now()
    row.last_seen_at = _utc_now()
    return True


async def _check_invoice_settled(
    lnd_lookup_invoice: _LndInvoiceLookup,
    payment_hash_hex: str,
) -> bool:
    try:
        info, err = await lnd_lookup_invoice(payment_hash_hex)
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "residual recovery: lookup_invoice raised: %s",
            exc,
        )
        return False
    if err is not None or info is None:
        return False
    settled = info.get("settled") if isinstance(info, dict) else getattr(info, "settled", False)
    return bool(settled)


def _network_to_subprocess_name(network: Any) -> str:
    """Translate the ``LiquidNetwork`` enum to the subprocess key.

    Kept local (mirroring ``liquid_hop_adapters._network_to_subprocess_name``)
    to avoid pulling that module's wider import surface.
    """
    name = getattr(network, "name", str(network)).upper()
    if name in {"MAINNET", "LIQUID", "PROD"}:
        return "mainnet"
    if name in {"TESTNET", "LIQUIDTESTNET"}:
        return "testnet"
    if name in {"REGTEST", "ELEMENTSREGTEST"}:
        return "regtest"
    return name.lower()


def build_default_residual_recovery_deps() -> Optional[ResidualRecoveryDeps]:
    """Wire the production dependency bundle for residual recovery.

    Returns ``None`` when the Liquid hop is disabled (mirroring
    :func:`hop_dispatcher.build_default_liquid_hop_deps`). The
    factory shares no state with the hop-dispatcher bundle —
    residual recovery is a one-shot utility outside the session
    state machine, so it gets its own ``LiquidSwapClient`` +
    backend instances. Callers cache the result if they invoke
    multiple recoveries in sequence.
    """
    from app.core.config import settings as _settings

    from .hop_dispatcher import is_liquid_hop_enabled
    from .liquid_backend import ElectrumLiquidBackend
    from .liquid_lock_subprocess import run_liquid_lock_subprocess
    from .liquid_seed import (
        load_liquid_master_blinding_key,
        resolve_liquid_btc_asset_id,
        resolve_liquid_network,
    )
    from .liquid_swap import LiquidSwapClient
    from .operators import select_liquid_leg_urls

    if not is_liquid_hop_enabled():
        return None

    master_key = load_liquid_master_blinding_key()
    if master_key is None:
        return None

    electrum_url = (_settings.anonymize_liquid_electrum_url or "").strip()
    if not electrum_url:
        return None

    try:
        legs = select_liquid_leg_urls()
    except RuntimeError:
        return None

    from app.services.chain.electrum import ElectrumClient

    backend = ElectrumLiquidBackend(ElectrumClient(electrum_url))
    submarine_client = LiquidSwapClient(base_url=legs.lbtc_to_ln_url)

    async def _lnd_create_invoice(*, amount_sat: int, memo: str) -> tuple[Any, Optional[str]]:
        from app.services.lnd_service import lnd_service

        try:
            result, err = await lnd_service.create_invoice(
                amount_sats=int(amount_sat),
                memo=str(memo),
            )
        except Exception as exc:  # noqa: BLE001
            return None, f"lnd_create_invoice failed: {exc}"
        if err is not None or result is None:
            return None, err or "lnd_create_invoice returned no invoice"
        return {
            "bolt11": result.get("payment_request"),
            "payment_hash": result.get("r_hash"),
        }, None

    async def _lnd_lookup_invoice(payment_hash_hex: str) -> tuple[Any, Optional[str]]:
        from app.services.lnd_service import lnd_service

        try:
            return await lnd_service.lookup_invoice(payment_hash_hex)
        except Exception as exc:  # noqa: BLE001
            return None, f"lookup_invoice failed: {exc}"

    return ResidualRecoveryDeps(
        backend=backend,
        submarine_client=submarine_client,
        lnd_create_invoice=_lnd_create_invoice,
        run_lock_subprocess=run_liquid_lock_subprocess,
        master_blinding_key=master_key,
        lbtc_asset_id=resolve_liquid_btc_asset_id(),
        network=resolve_liquid_network(),
        boltz_url=legs.lbtc_to_ln_url,
        lnd_lookup_invoice=_lnd_lookup_invoice,
    )


__all__ = [
    "ResidualRecoveryDeps",
    "ResidualRecoveryError",
    "ResidualRecoveryNotEligibleError",
    "ResidualRecoveryNotFoundError",
    "ResidualRecoveryResult",
    "build_default_residual_recovery_deps",
    "finalize_residual_recovery",
    "initiate_residual_recovery",
]
