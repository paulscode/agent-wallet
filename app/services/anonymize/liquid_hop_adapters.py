# SPDX-License-Identifier: MIT
"""Production adapters for the Liquid hop dependencies.

**Updated — chain-swap → reverse+submarine.** The
earlier ``liquid_chain_swap.LiquidChainSwapClient`` targeted
``/v2/swap/chain``, which is Boltz's on-chain ↔ on-chain product.
The wallet's Liquid hop actually needs LN ↔ on-chain (Liquid)
swaps, which map to:

* **LN → L-BTC**: a *reverse swap* with ``to: L-BTC``.
* **L-BTC → LN**: a *submarine swap* with ``from: L-BTC``.

The adapter factory composes the corrected swap client
(:class:`liquid_swap.LiquidSwapClient`) with the chain backend, the
CT receive path, the SLIP-77 derivation, and caller-supplied LN-side
callables.

**Runtime gate.** The Liquid hop's claim (cooperative MuSig2 +
Liquid tx assembly) requires a Node subprocess extension that's not
yet integration-validated against the live regtest harness. Until
that's verified, ``ANONYMIZE_LIQUID_INTEGRATION_VERIFIED=false``
gates the runtime path: the adapters refuse to invoke any code path
that would create a stuck session. Operators flip the gate to
``true`` after running the regtest integration test in their
environment.
"""

from __future__ import annotations

import logging
from typing import Any, Awaitable, Callable, Optional
from uuid import UUID

from app.core.config import settings
from app.services.boltz_lockup_verify import verify_liquid_lockup_address

from .hops.liquid import LiquidHopDeps
from .liquid_address import (
    LiquidAddressError,
    LiquidNetwork,
    encode_unconfidential_segwit,
    parse_liquid_address,
)
from .liquid_backend import LiquidBackend
from .liquid_claim_subprocess import (
    LiquidClaimRequest,
    LiquidClaimSubprocessError,
    run_liquid_claim_subprocess,
)
from .liquid_claim_subprocess import (
    LiquidIntegrationNotVerifiedError as _ClaimGateClosed,
)
from .liquid_credit_observer import observe_and_validate_credit
from .liquid_lock_subprocess import (
    LiquidLockIntegrationNotVerifiedError,
    LiquidLockRequest,
    LiquidLockSubprocessError,
    run_liquid_lock_subprocess,
)
from .liquid_receive import unblind_liquid_utxo
from .liquid_seed import (
    SessionLiquidOutput,
    derive_session_liquid_output,
)
from .liquid_swap import (
    LiquidSwapClient,
    generate_preimage_and_hash,
    generate_swap_keypair,
)
from .metadata import ANONYMIZE_LOGGER_NAME

logger = logging.getLogger(ANONYMIZE_LOGGER_NAME)


# ── Callable type aliases for the LN-side adapters the caller injects ─

LndSendPaymentFn = Callable[..., Awaitable[tuple[Any, Optional[str]]]]
"""``(payment_request, amount_sat) -> (result_dict, error)``."""

LndObserveSettledFn = Callable[..., Awaitable[tuple[bool, Optional[str]]]]
"""``(swap_id, session_id) -> (settled_bool, error)``."""

LndCreateInvoiceFn = Callable[..., Awaitable[tuple[Any, Optional[str]]]]
"""``(amount_sat, memo) -> ({"bolt11": ..., "payment_hash": ...}, error)``.

Used by the L-BTC→LN leg: the wallet must supply Boltz with an LN
invoice it wants paid. The submarine swap settles when Boltz routes
the payment to this invoice.
"""


def _network_to_subprocess_name(network: LiquidNetwork) -> str:
    """Map the wallet's Liquid network enum to the JS subprocess kwarg."""
    return {
        LiquidNetwork.MAINNET: "mainnet",
        LiquidNetwork.TESTNET: "testnet",
        LiquidNetwork.REGTEST: "regtest",
    }[network]


def _liquid_integration_verified() -> bool:
    """Read the runtime gate.

    Defaults to False so unverified deployments cannot start a real
    Liquid session.
    """
    return bool(getattr(settings, "anonymize_liquid_integration_verified", False))


class LiquidIntegrationNotVerifiedError(RuntimeError):
    """Raised by the adapters when the runtime gate is off.

    Surfaces a clear message so the operator can resolve by either
    completing the regtest integration test + flipping the gate, OR
    disabling the Liquid hop via ``ANONYMIZE_LIQUID_ENABLED=false``.
    """


async def _recover_liquid_claim_txid(backend, state) -> Optional[str]:  # type: ignore[no-untyped-def]
    """Best-effort recovery of a Liquid claim txid that was lost.

    ``run_liquid_claim_subprocess`` constructs *and broadcasts* the
    cooperative claim atomically, returning the txid parsed from
    stdout. If it broadcasts but then errors (non-zero exit, or the
    ``liquid_claim_broadcast_complete`` event is lost) the txid is
    dropped even though the L-BTC tx is on-chain at the wallet's
    per-session CT script.

    The CT script is single-use, so the lone UTXO sitting there *is*
    this swap's claim — recover its txid by scanning the dedicated
    anonymize Liquid backend. Returns ``None`` when the script isn't
    stashed yet, nothing is on-chain (genuine failure or not-yet-
    indexed), or the backend is transiently unavailable; callers then
    surface the original error and retry. Never raises.
    """
    script_hex = state.get("session_script_hex")
    if not script_hex:
        return None
    try:
        utxos, err = await backend.get_address_utxos(
            script_pubkey=bytes.fromhex(script_hex),
        )
        if err is not None or not utxos:
            return None
        # Single-use script ⇒ at most one UTXO; take the first.
        return str(utxos[0].txid) or None
    except Exception:  # noqa: BLE001
        return None


def build_liquid_hop_deps(
    *,
    backend: LiquidBackend,
    swap_client: LiquidSwapClient,
    lnd_send_payment: LndSendPaymentFn,
    lnd_observe_invoice_settled: LndObserveSettledFn,
    lnd_create_invoice: LndCreateInvoiceFn,
    master_blinding_key: bytes,
    expected_asset_id: bytes,
    network: LiquidNetwork,
    swap_state: dict[str, dict[str, Any]],
    submarine_swap_client: LiquidSwapClient | None = None,
    ln_to_lbtc_operator_id: str | None = None,
    lbtc_to_ln_operator_id: str | None = None,
) -> LiquidHopDeps:
    """Build production :class:`LiquidHopDeps` from injected dependencies.

    Each adapter satisfies the existing 5-callable ``LiquidHopDeps``
    contract; the implementation underneath is the corrected
    reverse+submarine flow.

    The reverse (LN→L-BTC) leg uses ``swap_client``. The submarine
    (L-BTC→LN) leg uses ``submarine_swap_client`` when provided; when
    omitted both legs share ``swap_client`` (single-operator
    deployment / legacy callers / tests). The production
    dispatcher selects per-leg operators from the signed registry —
    see :func:`operators.select_liquid_leg_urls`.

    Adapters that require the not-yet-integration-verified Node
    subprocess (cooperative claim + L-BTC tx assembly) raise
    :class:`LiquidIntegrationNotVerifiedError` when invoked while the
    runtime gate is off — the hop body's bounded-retry treats this
    as a hard error and routes the session to reconciliation
    instead of polling forever.
    """
    # Bind submarine_swap_client to swap_client when not provided so
    # the legacy single-client call sites keep working unchanged.
    submarine_client: LiquidSwapClient = submarine_swap_client if submarine_swap_client is not None else swap_client

    async def _create_ln_to_lbtc(
        *,
        amount_sat: int,
        session_id: UUID,
        blinding_seed_index: int,
    ) -> tuple[Optional[dict[str, Any]], Optional[str]]:
        """LN → L-BTC create adapter (reverse swap with ``to: L-BTC``).

        Generates preimage + claim keypair, calls Boltz, parses the
        returned Liquid lockup address to extract the scriptPubKey,
        derives the SLIP-77 per-script blinding privkey, stashes the
        per-swap state for the observer + claim step.

        ``blinding_seed_index`` is the wallet's per-session SLIP-77
        derivation index (decrypted from
        ``session.liquid_blinding_seed_enc`` by the hop body); the
        claim adapter uses it to re-derive the destination CT address.
        """
        if not _liquid_integration_verified():
            return None, (
                "ANONYMIZE_LIQUID_INTEGRATION_VERIFIED=false; refusing "
                "to create a Liquid swap until the operator confirms "
                "end-to-end integration in their environment"
            )

        preimage_hex, preimage_hash_hex = generate_preimage_and_hash()
        claim_priv_hex, claim_pub_hex = generate_swap_keypair()

        swap, err = await swap_client.create_reverse_swap_to_lbtc(
            invoice_amount_sat=int(amount_sat),
            preimage_hash_hex=preimage_hash_hex,
            claim_public_key_hex=claim_pub_hex,
        )
        if err is not None or swap is None:
            return None, err or "boltz returned no swap"

        # Verify the operator-supplied lockup commits to OUR claim key
        # BEFORE the wallet pays the LN invoice. The reverse leg pays
        # first and claims the L-BTC lockup afterwards; an operator that
        # returned a lockup whose claim leaf it controls would take the
        # LN funds and leave the wallet unable to claim. Reconstruct the
        # taproot output from the swap tree + keys and refuse on mismatch.
        ok, reason = verify_liquid_lockup_address(
            swap_tree=swap.swap_tree,
            lockup_address=swap.lockup_address,
            network=_network_to_subprocess_name(network),
            swap_type="reverse",
            verify_leaf="claim",
            claim_public_key_hex=claim_pub_hex,
            refund_public_key_hex=swap.refund_public_key_hex,
            asset_id_hex=expected_asset_id.hex(),
        )
        if not ok:
            logger.error(
                "anonymize liquid reverse swap %s: lockup verification FAILED (%s); refusing to pay",
                swap.id,
                reason,
            )
            return None, f"liquid reverse lockup verification failed: {reason}"

        try:
            info = parse_liquid_address(swap.lockup_address)
        except LiquidAddressError as exc:
            return None, f"boltz lockupAddress is not a Liquid address: {exc}"

        # SLIP-77 blinding privkey for the lockup's scriptPubKey.
        # Note: when Boltz reveals its own ``blinding_key_hex`` in the
        # response, the wallet uses THAT for unblinding (the Boltz-side
        # blinding key). The wallet's SLIP-77 derivation is reserved
        # for outputs the wallet itself blinds.
        blinding_priv = bytes.fromhex(swap.blinding_key_hex)
        if len(blinding_priv) != 32:
            return None, (f"boltz blindingKey is {len(blinding_priv)} bytes; expected 32")

        try:
            unconf = encode_unconfidential_segwit(
                info.script_pubkey,
                network=network,
            )
        except LiquidAddressError:
            unconf = swap.lockup_address

        swap_state[swap.id] = {
            "session_id": str(session_id),
            "leg": "ln_to_lbtc",
            "lockup_address": swap.lockup_address,
            "lockup_script_hex": info.script_pubkey.hex(),
            "expected_amount_sat": int(swap.onchain_amount_sat),
            "blinding_privkey_hex": swap.blinding_key_hex,
            "claim_private_key_hex": claim_priv_hex,
            "preimage_hex": preimage_hex,
            "preimage_hash_hex": preimage_hash_hex,
            "refund_public_key_hex": swap.refund_public_key_hex,
            "timeout_block_height": swap.timeout_block_height,
            "swap_tree_claim_leaf": swap.swap_tree.claim_leaf.output,
            "swap_tree_refund_leaf": swap.swap_tree.refund_leaf.output,
            "session_blinding_seed_index": int(blinding_seed_index),
        }
        return {
            "swap_id": swap.id,
            "invoice": swap.invoice,
            "lbtc_address": unconf,
        }, None

    async def _observe_credit(
        *,
        swap_id: Optional[str],
        session_id: UUID,
    ) -> tuple[Optional[str], Optional[str]]:
        """Poll the Liquid backend for the credit + unblind + validate.

        On a successful observation, the swap's per-state entry is
        enriched with the full lockup transaction hex (needed by the
        cooperative claim subprocess) so subsequent ticks don't need
        to re-fetch it.
        """
        if not swap_id:
            return None, "missing swap_id"
        state = swap_state.get(str(swap_id))
        if state is None:
            return None, f"no per-swap state for {swap_id!r}"
        lockup_script = bytes.fromhex(state["lockup_script_hex"])
        blinding_priv = bytes.fromhex(state["blinding_privkey_hex"])
        expected_amount = int(state["expected_amount_sat"])

        obs, err = await observe_and_validate_credit(
            backend=backend,
            lockup_script=lockup_script,
            blinding_privkey=blinding_priv,
            expected_asset_id=expected_asset_id,
            expected_amount_sat=expected_amount,
        )
        if err is not None:
            return None, err
        if obs is None:
            return None, None
        u = obs.unblinded.utxo

        # Fetch the full lockup transaction hex once and stash it for
        # the claim subprocess. The fetch is best-effort: a failure
        # here doesn't block the credit observation, the claim step
        # will retry the fetch and surface a clearer error.
        tx_hex, tx_err = await backend.get_transaction_hex(u.txid)
        if tx_err is None and tx_hex:
            state["lockup_tx_hex"] = tx_hex
            state["lockup_utxo_vout"] = int(u.vout)
            state["lockup_unblinded_value_sat"] = int(obs.unblinded.value_sat)
        return f"{u.txid}:{u.vout}", None

    def _resolve_session_output(
        session_id: UUID,
        *,
        blinding_seed_index: int,
    ) -> SessionLiquidOutput:
        """Re-derive the wallet's per-session L-BTC CT receive output."""
        return derive_session_liquid_output(
            master_blinding_key=master_blinding_key,
            session_id=session_id,
            derivation_index=int(blinding_seed_index),
            network=network,
        )

    async def _claim_lockup(
        *,
        swap_id: Optional[str],
        session_id: UUID,
    ) -> tuple[Optional[str], Optional[str]]:
        """Cooperative MuSig2 claim of Boltz's lockup → wallet CT addr.

        The destination address is derived from the session's
        ``liquid_blinding_seed_enc`` (assigned at session-create
        time). The subprocess writes the claim TX hex on fd 3 + emits
        a structured ``liquid_claim_broadcast_complete`` event on
        stdout carrying the broadcast txid.
        """
        if not _liquid_integration_verified():
            return None, (
                "ANONYMIZE_LIQUID_INTEGRATION_VERIFIED=false; refusing to invoke the cooperative claim subprocess"
            )
        if not swap_id:
            return None, "missing swap_id"
        state = swap_state.get(str(swap_id))
        if state is None:
            return None, f"no per-swap state for {swap_id!r}"
        lockup_tx_hex = state.get("lockup_tx_hex")
        if not lockup_tx_hex:
            return None, "lockup_tx_hex not stashed; observe step must run first"

        seed_index = state.get("session_blinding_seed_index")
        if not seed_index:
            return None, "session blinding seed index not stashed"
        try:
            output = _resolve_session_output(
                session_id,
                blinding_seed_index=int(seed_index),
            )
        except Exception as exc:  # noqa: BLE001
            return None, f"failed to derive session ct address: {exc}"
        # Persist the script + (Fernet-encrypted) spending privkey + the
        # cleartext blinding privkey so leg 2 can spend without re-
        # deriving from scratch. The wallet keeps the master blinding
        # key + derivation index, so re-derivation is always possible —
        # the cache here is just a perf shortcut.
        state["session_script_hex"] = output.script_pubkey.hex()
        state["session_blinding_privkey_hex"] = output.blinding_privkey.hex()
        state["session_spending_privkey_hex"] = output.spending_privkey.hex()
        state["session_ct_address"] = output.ct_address

        request = LiquidClaimRequest(
            boltz_url=swap_client._base_url,
            swap_id=str(swap_id),
            preimage_hex=str(state["preimage_hex"]),
            claim_private_key_hex=str(state["claim_private_key_hex"]),
            refund_public_key_hex=str(state["refund_public_key_hex"]),
            swap_tree={
                "claimLeaf": {
                    "version": 196,
                    "output": str(state["swap_tree_claim_leaf"]),
                },
                "refundLeaf": {
                    "version": 196,
                    "output": str(state["swap_tree_refund_leaf"]),
                },
            },
            lockup_tx_hex=str(lockup_tx_hex),
            destination_address=output.ct_address,
            blinding_key_hex=str(state["blinding_privkey_hex"]),
            network=_network_to_subprocess_name(network),
            asset_id_hex=expected_asset_id.hex(),
        )
        try:
            result = await run_liquid_claim_subprocess(request)
        except _ClaimGateClosed as exc:
            return None, str(exc)
        except LiquidClaimSubprocessError as exc:
            # The subprocess broadcasts the claim atomically; an error
            # here can still mean the L-BTC claim hit the chain
            # (broadcast-then-error). The per-session CT script is
            # single-use, so a UTXO there IS our claim — recover its
            # txid instead of wedging the session. If nothing is
            # on-chain (genuine failure / not-yet-indexed) surface the
            # original error so the step retries next tick.
            recovered = await _recover_liquid_claim_txid(backend, state)
            if recovered is not None:
                state["claim_txid"] = recovered
                logger.info(
                    "liquid claim %s: subprocess errored (%s) but the claim UTXO is on-chain; recovered claim_txid=%s",
                    swap_id,
                    exc,
                    recovered,
                )
                return recovered, None
            return None, f"liquid claim subprocess failed: {exc}"
        state["claim_tx_hex"] = result.claim_tx_hex
        state["claim_txid"] = result.txid
        return result.txid, None

    async def _observe_wallet_credit(
        *,
        swap_id: Optional[str],
        session_id: UUID,
    ) -> tuple[Optional[bool], Optional[str]]:
        """Wait for the wallet's claim TX to confirm.

        Returns ``(True, None)`` once the claim TX has at least one
        confirmation and the wallet sees a matching UTXO at its
        per-session script. On success the unblinded UTXO state is
        stashed so the leg-2 lock step has everything it needs.
        """
        if not swap_id:
            return False, "missing swap_id"
        state = swap_state.get(str(swap_id))
        if state is None:
            return False, f"no per-swap state for {swap_id!r}"
        # ``claim_txid`` may be absent here even though the claim landed
        # — e.g. an operator manual recovery set
        # ``pj["liquid_lbtc_claim_txid"]`` (which gates dispatch to this
        # step) without updating the encrypted swap_state blob this
        # cache hydrates from. The CT script is single-use, so we can
        # still identify the claim by the lone UTXO at that script and
        # backfill the txid (belt-and-braces). The script +
        # blinding key remain required — without them we can neither
        # scan nor unblind.
        claim_txid = state.get("claim_txid")

        script_hex = state.get("session_script_hex")
        blinding_priv_hex = state.get("session_blinding_privkey_hex")
        if not script_hex or not blinding_priv_hex:
            return False, "session script / blinding privkey not stashed"
        script = bytes.fromhex(script_hex)
        blinding_priv = bytes.fromhex(blinding_priv_hex)

        utxos, err = await backend.get_address_utxos(script_pubkey=script)
        if err is not None:
            return False, f"liquid backend error: {err}"
        if not utxos:
            return False, None

        for utxo in utxos:
            # When the txid is known, pin to it (strict). When it's
            # missing, the single-use script means this lone UTXO is the
            # claim — accept it and backfill the txid below.
            if claim_txid and utxo.txid != str(claim_txid):
                continue
            # Confirmation gate via block_height: electrs reports
            # ``block_height > 0`` for mined txs and ``None`` / ``0``
            # for mempool. Some operator builds of electrs-liquid
            # don't support the verbose ``blockchain.transaction.get``
            # call we'd otherwise use, so reading the height off the
            # UTXO entry itself is the portable path.
            if not utxo.block_height or int(utxo.block_height) <= 0:
                return False, None
            try:
                unblinded = unblind_liquid_utxo(
                    utxo=utxo,
                    blinding_privkey=blinding_priv,
                )
            except Exception as exc:  # noqa: BLE001
                return False, f"unblind failed: {exc}"
            if not claim_txid:
                state["claim_txid"] = utxo.txid
                logger.info(
                    "liquid observe: backfilled missing claim_txid=%s from single-use CT-script UTXO (swap=%s)",
                    utxo.txid,
                    swap_id,
                )
            state["wallet_utxo_txid"] = utxo.txid
            state["wallet_utxo_vout"] = int(utxo.vout)
            state["wallet_utxo_value_sat"] = int(unblinded.value_sat)
            state["wallet_utxo_asset_id_hex"] = unblinded.asset_id.hex()
            state["wallet_utxo_abf_hex"] = unblinded.asset_blinding_factor.hex()
            state["wallet_utxo_vbf_hex"] = unblinded.value_blinding_factor.hex()
            return True, None
        return False, None

    async def _create_lbtc_to_ln(
        *,
        lbtc_utxo: Optional[str],
        amount_sat: int,
        session_id: UUID,
    ) -> tuple[Optional[dict[str, Any]], Optional[str]]:
        """L-BTC → LN create adapter (submarine swap with ``from: L-BTC``).

        The wallet mints an LN invoice it controls, sends to Boltz,
        receives Boltz's Liquid lockup address. The actual L-BTC
        spend (wallet → lockup) is a separate hop step.

        The ``lbtc_utxo`` chain anchor is a sanity-check reference;
        it isn't sent on the wire.
        """
        if not _liquid_integration_verified():
            return None, (
                "ANONYMIZE_LIQUID_INTEGRATION_VERIFIED=false; refusing "
                "to create a Liquid submarine swap until the operator "
                "confirms end-to-end integration"
            )

        # Mint an LN invoice for the amount we want Boltz to pay us.
        inv_result, inv_err = await lnd_create_invoice(
            amount_sat=int(amount_sat),
            memo=f"anonymize-liquid-{session_id}",
        )
        if inv_err is not None or inv_result is None:
            return None, f"lnd_create_invoice failed: {inv_err}"
        invoice = (
            inv_result.get("bolt11") if isinstance(inv_result, dict) else getattr(inv_result, "payment_request", None)
        )
        payment_hash = (
            inv_result.get("payment_hash") if isinstance(inv_result, dict) else getattr(inv_result, "r_hash", None)
        )
        if not invoice:
            return None, "lnd_create_invoice returned no bolt11"

        refund_priv_hex, refund_pub_hex = generate_swap_keypair()
        swap, err = await submarine_client.create_submarine_swap_from_lbtc(
            invoice=invoice,
            refund_public_key_hex=refund_pub_hex,
        )
        if err is not None or swap is None:
            return None, err or "boltz returned no swap"

        # Verify the operator-supplied lockup commits to the swap tree +
        # OUR refund key BEFORE the wallet funds it. Without this an
        # operator could return an address it solely controls (no
        # refundable script for us), take the L-BTC funding, and leave
        # the wallet with no cooperative or unilateral refund path —
        # direct theft. Reconstruct the taproot output and refuse on
        # mismatch. (The Bitcoin submarine path does the same via
        # ``verify_submarine_lockup_address``.)
        ok, reason = verify_liquid_lockup_address(
            swap_tree=swap.swap_tree,
            lockup_address=swap.address,
            network=_network_to_subprocess_name(network),
            swap_type="submarine",
            verify_leaf="refund",
            refund_public_key_hex=refund_pub_hex,
            claim_public_key_hex=swap.claim_public_key_hex,
            asset_id_hex=expected_asset_id.hex(),
        )
        if not ok:
            logger.error(
                "anonymize liquid submarine swap %s: lockup verification FAILED (%s); refusing to fund",
                swap.id,
                reason,
            )
            return None, f"liquid submarine lockup verification failed: {reason}"

        swap_state[swap.id] = {
            "session_id": str(session_id),
            "leg": "lbtc_to_ln",
            "address": swap.address,  # where wallet locks L-BTC
            "expected_amount_sat": int(swap.expected_amount_sat),
            "claim_public_key_hex": swap.claim_public_key_hex,
            "blinding_privkey_hex": swap.blinding_key_hex,
            "refund_private_key_hex": refund_priv_hex,
            "invoice": invoice,
            "payment_hash_hex": payment_hash or "",
            "timeout_block_height": swap.timeout_block_height,
            "accept_zero_conf": swap.accept_zero_conf,
            "consumed_lbtc_utxo": lbtc_utxo or "",
            "swap_tree_claim_leaf": swap.swap_tree.claim_leaf.output,
            "swap_tree_refund_leaf": swap.swap_tree.refund_leaf.output,
        }
        return {"swap_id": swap.id}, None

    def _find_leg1_state(session_id: UUID) -> Optional[dict[str, Any]]:
        """Locate the leg-1 swap_state entry for ``session_id``.

        The swap_state map is keyed by Boltz swap id; the leg-2 entry
        only knows its own swap id, so we walk the values to find the
        sibling LN→L-BTC entry (tagged ``leg="ln_to_lbtc"``).
        """
        sid = str(session_id)
        for entry in swap_state.values():
            if entry.get("session_id") == sid and entry.get("leg") == "ln_to_lbtc":
                return entry
        return None

    async def _lock_for_submarine(
        *,
        swap_id: Optional[str],
        session_id: UUID,
    ) -> tuple[Optional[str], Optional[str]]:
        """Build + broadcast the wallet's L-BTC spend → Boltz's lockup.

        Composes the leg-1 wallet UTXO state + leg-2 swap address into
        a structured :class:`LiquidLockRequest` and hands it to the
        subprocess wrapper. The fee rate comes from the configured
        Liquid fee oracle (with the floor/ceiling clamps already
        applied).
        """
        if not _liquid_integration_verified():
            return None, ("ANONYMIZE_LIQUID_INTEGRATION_VERIFIED=false; refusing to invoke the lock subprocess")
        if not swap_id:
            return None, "missing swap_id"
        leg2 = swap_state.get(str(swap_id))
        if leg2 is None:
            return None, f"no leg-2 swap_state for {swap_id!r}"

        leg1 = _find_leg1_state(session_id)
        if leg1 is None:
            return None, "no leg-1 swap_state for this session"
        # ``wallet_utxo_vout`` is legitimately 0 for many claims (first
        # output), so use ``not in`` instead of truthiness checks for
        # numeric fields.
        for required in (
            "wallet_utxo_txid",
            "wallet_utxo_value_sat",
            "wallet_utxo_asset_id_hex",
            "wallet_utxo_abf_hex",
            "wallet_utxo_vbf_hex",
            "session_spending_privkey_hex",
            "session_script_hex",
            "session_ct_address",
        ):
            if not leg1.get(required):
                return None, f"leg-1 missing {required!r}"
        if "wallet_utxo_vout" not in leg1:
            return None, "leg-1 missing 'wallet_utxo_vout'"

        # Fetch the prevout tx hex so the JS subprocess can reconstruct
        # the input's commitments without an extra network round-trip
        # from inside the sandbox.
        prevout_hex, prevout_err = await backend.get_transaction_hex(
            str(leg1["wallet_utxo_txid"]),
        )
        if prevout_err is not None or not prevout_hex:
            return None, f"failed to fetch prevout tx hex: {prevout_err}"

        # Fee-rate: read the live oracle; fall back to the floor when
        # the oracle returns no value (the floor is itself bounded by
        # the operator-configured clamps).
        fee_rate_sat_vb, fee_err = await backend.estimate_fee_sat_per_vb(
            target_blocks=6,
        )
        if fee_err is not None or fee_rate_sat_vb is None:
            fee_rate_sat_vb = float(getattr(settings, "anonymize_liquid_fee_rate_floor_sat_per_vb", 0.1))

        request = LiquidLockRequest(
            utxo_txid=str(leg1["wallet_utxo_txid"]),
            utxo_vout=int(leg1["wallet_utxo_vout"]),
            utxo_value_sat=int(leg1["wallet_utxo_value_sat"]),
            utxo_asset_id_hex=str(leg1["wallet_utxo_asset_id_hex"]),
            utxo_asset_blinding_factor_hex=str(leg1["wallet_utxo_abf_hex"]),
            utxo_value_blinding_factor_hex=str(leg1["wallet_utxo_vbf_hex"]),
            utxo_prevout_tx_hex=str(prevout_hex),
            utxo_script_pubkey_hex=str(leg1["session_script_hex"]),
            spending_private_key_hex=str(leg1["session_spending_privkey_hex"]),
            destination_address=str(leg2["address"]),
            destination_amount_sat=int(leg2["expected_amount_sat"]),
            fee_sat_per_vbyte=float(fee_rate_sat_vb),
            change_address=str(leg1["session_ct_address"]),
            network=_network_to_subprocess_name(network),
            asset_id_hex=expected_asset_id.hex(),
            boltz_url=submarine_client._base_url,
        )
        try:
            result = await run_liquid_lock_subprocess(request)
        except LiquidLockIntegrationNotVerifiedError as exc:
            return None, str(exc)
        except LiquidLockSubprocessError as exc:
            return None, f"liquid lock subprocess failed: {exc}"
        leg2["lock_tx_hex"] = result.lock_tx_hex
        leg2["lock_txid"] = result.txid
        return result.txid, None

    return LiquidHopDeps(
        swap_state=swap_state,
        boltz_create_ln_to_lbtc_swap=_create_ln_to_lbtc,
        lnd_send_payment=lnd_send_payment,
        liquid_observe_credit=_observe_credit,
        liquid_claim_lockup=_claim_lockup,
        liquid_observe_wallet_credit=_observe_wallet_credit,
        boltz_create_lbtc_to_ln_swap=_create_lbtc_to_ln,
        liquid_lock_for_submarine=_lock_for_submarine,
        lnd_observe_invoice_settled=lnd_observe_invoice_settled,
        ln_to_lbtc_operator_id=ln_to_lbtc_operator_id,
        lbtc_to_ln_operator_id=lbtc_to_ln_operator_id,
    )


__all__ = [
    "LiquidIntegrationNotVerifiedError",
    "LndCreateInvoiceFn",
    "LndObserveSettledFn",
    "LndSendPaymentFn",
    "build_liquid_hop_deps",
]
