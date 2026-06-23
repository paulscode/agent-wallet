# SPDX-License-Identifier: MIT
"""Per-source-kind hop dispatcher.

Mirrors :mod:`observation_router` but for side-effecting hop steps.
The orchestrator calls a single ``hop_step_fn(db, session)`` per
tick; this module produces a callable bound to the production
adapters so the create endpoint + startup reconciliation can spawn
per-session tasks with one wire.

The Lightning self-source path wires:

* ``ext-lightning`` / ``lightning-self`` → reverse-swap hop body
  via :func:`hops.reverse.execute_reverse_hop_step`.

The submarine + priv_channel dispatchers extend this for the
on-chain self-source path.
"""

from __future__ import annotations

import logging
from typing import Any, Awaitable, Callable

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.anonymize_session import AnonymizeSession

from .hops.bolt12_pay import (
    Bolt12PayHopDeps,
    execute_bolt12_pay_hop_step,
)
from .hops.liquid import (
    LiquidHopDeps,
    execute_liquid_hop_step,
    is_liquid_hop_enabled,
)
from .hops.ln_self_pay import (
    LnSelfPayHopDeps,
    execute_ln_self_pay_hop_step,
)
from .hops.priv_channel import (
    PrivChannelHopDeps,
)
from .hops.reverse import ReverseHopDeps, execute_reverse_hop_step
from .hops.submarine import SubmarineHopDeps, execute_submarine_hop_step

HopStepFn = Callable[[AsyncSession, AnonymizeSession], Awaitable[Any]]


def build_default_reverse_hop_deps() -> ReverseHopDeps:
    """Bind the production adapters for the reverse-hop body.

    Each adapter wraps the corresponding wallet service call with
    the anonymize-stack hardening (pinned request shape, Tor
    isolation, dedicated chain client). The production wiring
    delegates to the existing wallet primitives; the pinned
    shape is enforced at the builder level so the wallet's call
    site is constrained by the anonymize-stack request body.
    """

    # The anonymize
    # stack issues Boltz egress through its own pinned-shape /
    # stream-isolated HTTP wrapper, NOT the wallet's general
    # ``boltz_service`` client. The wrapper enforces per-call SOCKS
    # auth (fresh Tor circuit), the pinned ClientHello + header set,
    # request-body padding, and the circuit-rebuild bandwidth budget.
    from .boltz_egress import AnonymizeBoltzClient
    from .operators import (
        resolve_operator_url_from_registry,
        resolve_reverse_leg_url,
    )

    def _reverse_base_url_for(session: AnonymizeSession) -> str:
        """Resolve the reverse-leg base URL per session.

        When the chain selector bound a ``reverse_operator_id`` to
        the session, look up the operator's URL from the signed
        registry — otherwise the swap egress would default to
        ``BOLTZ_REVERSE_ONION_URL`` / ``BOLTZ_ONION_URL``, which
        could be a different operator than the chain picked,
        defeating the distinct-operator splitting.

        Falls back to the env-pin resolver when no operator_id is
        bound (URL-pin bypass path / LN-only sessions /
        single-operator deployments).
        """
        op_id = getattr(session, "reverse_operator_id", None)
        if not op_id:
            pj = session.pipeline_json or {}
            if isinstance(pj, dict):
                op_id = pj.get("reverse_operator_id")
        url = resolve_operator_url_from_registry(op_id)
        if url:
            return url
        return resolve_reverse_leg_url()

    async def _create_reverse_swap(
        *,
        db: AsyncSession,
        request_body: dict[str, Any],
        session: AnonymizeSession,
    ) -> tuple[Any, Any]:
        from app.dashboard import DASHBOARD_KEY_ID

        # Construct a per-session client so the base URL
        # tracks the chain selector's bound operator.
        anonymize_boltz = AnonymizeBoltzClient(
            base_url=_reverse_base_url_for(session),
        )
        # Pass the bound reverse operator ID into the
        # anonymize client so it can verify the response signature
        # against the operator's pinned `public_key_hex`.
        op_id = getattr(session, "reverse_operator_id", None)
        if not op_id:
            pj = session.pipeline_json or {}
            op_id = pj.get("reverse_operator_id") if isinstance(pj, dict) else None
        return await anonymize_boltz.create_reverse_swap(
            db=db,
            api_key_id=DASHBOARD_KEY_ID,
            invoice_amount_sats=int(request_body["invoiceAmount"]),
            destination_address=request_body["claimAddress"],
            operator_id=op_id,
        )

    async def _get_swap_status(
        boltz_swap_id: str,
        *,
        operator_id: str | None = None,
    ) -> tuple[Any, Any, Any]:
        # Status polling must hit the SAME operator the swap
        # was created with. Resolve via the registry when an
        # operator_id is passed (or fall back to the leg-pinned
        # default for operator-agnostic deployments).
        registry_url = resolve_operator_url_from_registry(operator_id)
        base_url = registry_url if registry_url else resolve_reverse_leg_url()
        client = AnonymizeBoltzClient(base_url=base_url)
        return await client.get_swap_status(
            boltz_swap_id,
            operator_id=operator_id,
        )

    async def _send_payment(
        *,
        payment_request: str,
        max_parts: int,
    ) -> tuple[Any, Any]:
        from app.services.lnd_service import lnd_service

        # MPP K from the frozen pipeline. The wallet's
        # ``send_payment_v2`` honours ``max_parts`` per LND v0.18.
        result, error = await lnd_service.send_payment_v2(
            payment_request=payment_request,
            max_parts=max_parts,
            timeout_seconds=60,
        )
        return result, error

    async def _run_claim_subprocess(
        *,
        swap_id: str,
        lockup_tx: Any,
    ) -> tuple[Any, Any]:
        # The LN-source reverse leg delegates to
        # ``boltz_service.cooperative_claim`` which already spawns
        # ``boltz_claim.js`` with timeouts + SOCKS proxy + fd-3 hex
        # transport.
        # The wallet's cooperative_claim takes a swap row; the
        # adapter signature exposes the swap_id + lockup hex so the
        # reverse-leg implementation can mock-test the call.
        from sqlalchemy import select

        from app.core.database import get_session_maker
        from app.models.boltz_swap import BoltzSwap
        from app.services.boltz_service import boltz_service

        async with get_session_maker()() as db:
            swap = (await db.execute(select(BoltzSwap).where(BoltzSwap.boltz_swap_id == swap_id))).scalar_one_or_none()
            if swap is None:
                return None, f"swap row missing for id={swap_id}"
            lockup_hex = lockup_tx if isinstance(lockup_tx, str) else (lockup_tx or {}).get("hex", "")
            txid, error = await boltz_service.cooperative_claim(
                swap=swap,
                lockup_tx_hex=lockup_hex,
            )
        # cooperative_claim returns the txid; the fd-3
        # contract expects the hex itself. Production wiring reads
        # the hex from the subprocess's fd 3; the LN-source reverse
        # leg falls back to the swap row's claim_tx_hex column
        # populated by the wallet path.
        if error:
            return None, error
        return txid or "", None

    async def _chain_broadcast(tx_hex: str) -> tuple[Any, Any]:
        # Self-broadcast fallback through the
        # dedicated anonymize chain client. The general-wallet
        # ``mempool_fee_service`` shares one connection across
        # callers; routing the claim hex through it would let the
        # chain-backend operator correlate the broadcast with the
        # wallet's general activity.
        from .chain_egress import anonymize_broadcast_tx

        txid, error = await anonymize_broadcast_tx(tx_hex)
        if error is not None:
            return None, error
        return txid, None

    return ReverseHopDeps(
        boltz_create_reverse_swap=_create_reverse_swap,
        boltz_get_swap_status=_get_swap_status,
        lnd_send_payment=_send_payment,
        run_claim_subprocess=_run_claim_subprocess,
        chain_broadcast_tx=_chain_broadcast,
    )


def build_default_submarine_hop_deps() -> SubmarineHopDeps:
    """Bind the production adapters for the submarine hop body.

    Mirrors :func:`build_default_reverse_hop_deps`. Every external
    side-effect goes through the anonymize HTTP wrapper + the
    dedicated chain client; the funding-tx builder + refund
    subprocess hooks land alongside :mod:`coin_control` and the
    ``submarine_refund.js`` script.
    """
    from .boltz_egress import AnonymizeBoltzClient
    from .operators import (
        resolve_operator_url_from_registry,
        resolve_submarine_leg_url,
    )

    def _submarine_base_url_for(session: AnonymizeSession) -> str:
        """Resolve the submarine-leg base URL per session.
        See :func:`build_default_reverse_hop_deps._reverse_base_url_for`
        for the rationale — the chain selector's choice must drive
        URL routing or the distinct-operator splitting is
        decorative.
        """
        op_id = getattr(session, "submarine_operator_id", None)
        if not op_id:
            pj = session.pipeline_json or {}
            if isinstance(pj, dict):
                op_id = pj.get("submarine_operator_id")
        url = resolve_operator_url_from_registry(op_id)
        if url:
            return url
        return resolve_submarine_leg_url()

    async def _create_submarine_swap(
        *,
        db: AsyncSession,
        invoice: str,
        session: AnonymizeSession,
    ) -> tuple[Any, Any]:
        from app.dashboard import DASHBOARD_KEY_ID

        # Per-session client so the base URL tracks the
        # chain selector's bound submarine operator.
        anonymize_boltz = AnonymizeBoltzClient(
            base_url=_submarine_base_url_for(session),
        )
        # Bound submarine operator id from quote token.
        op_id = getattr(session, "submarine_operator_id", None)
        if not op_id:
            pj = session.pipeline_json or {}
            op_id = pj.get("submarine_operator_id") if isinstance(pj, dict) else None
        return await anonymize_boltz.create_submarine_swap(
            db=db,
            api_key_id=DASHBOARD_KEY_ID,
            invoice=invoice,
            anonymize_session_id=session.id,
            operator_id=op_id,
        )

    async def _get_swap_status(
        boltz_swap_id: str,
        *,
        operator_id: str | None = None,
    ) -> tuple[Any, Any, Any]:
        # Status polling must hit the SAME operator the swap
        # was created with.
        registry_url = resolve_operator_url_from_registry(operator_id)
        base_url = registry_url if registry_url else resolve_submarine_leg_url()
        client = AnonymizeBoltzClient(base_url=base_url)
        return await client.get_swap_status(
            boltz_swap_id,
            operator_id=operator_id,
        )

    async def _lnd_add_invoice(
        *,
        amount_sat: int,
        memo: str | None,
    ) -> tuple[Any, Any]:
        from app.services.lnd_service import lnd_service

        # The wallet's ``create_invoice`` returns a tuple of
        # ``(result, error)`` where ``result.payment_request`` is the
        # BOLT11 the submarine swap will pay out to.
        try:
            result, err = await lnd_service.create_invoice(
                amount_sats=int(amount_sat),
                memo=memo or "",
                expiry=3600,
            )
        except Exception as exc:  # noqa: BLE001
            return None, str(exc)
        if err is not None or result is None:
            return None, err or "create_invoice returned no result"
        return result, None

    async def _build_and_broadcast_funding_tx(
        *,
        lockup_address: str,
        amount_sat: int,
        session: AnonymizeSession,
    ) -> tuple[Any, Any]:
        # funding — send to the Boltz lockup address.
        #
        # Pin the spent UTXO to the closest exact-bin match
        # via :func:`select_exact_bin_funding` so the on-chain funding
        # tx is single-input + has no change output (the binning's
        # anonymity set is preserved). When no exact-bin UTXO exists,
        # the adapter falls back to LND's default coin selection
        # (which leaves change) — the over-pad consolidation
        # flow is the user-opt-in path the wizard surfaces.
        #
        # Jitter the feerate against the live economy
        # estimate so the on-chain fingerprint doesn't reveal a
        # rigid wallet-default sat/vB.
        from app.services.lnd_service import lnd_service

        from .chain_egress import get_anonymize_economy_feerate
        from .coin_control import (
            WalletUtxo,
            is_do_not_spend_label,
            is_utxo_refused_as_anonymize_source,
            select_exact_bin_funding,
        )
        from .txpolicy import feerate_jitter

        sat_per_vbyte: int | None = None
        economy, _fee_err = await get_anonymize_economy_feerate()
        if economy is not None and economy > 0:
            jittered = feerate_jitter(float(economy), minrelay_sat_per_vb=1.0)
            sat_per_vbyte = max(1, int(round(jittered)))

        # Fetch the wallet's UTXO catalog + pick the exact-
        # bin candidate. UTXOs labelled with the do-not-spend
        # prefixes are filtered out so the refund-lockdown
        # holds.
        outpoints: list | None = None
        try:
            utxos_raw, _ = await lnd_service.list_unspent(min_confs=1)
        except Exception:  # noqa: BLE001
            utxos_raw = None
        if utxos_raw:
            # Pull UTXO labels in one query so the do-not-spend filter
            # doesn't N+1 the DB.
            from sqlalchemy import select as _select

            from app.core.database import get_session_maker
            from app.models.utxo_label import UtxoLabel

            label_by_outpoint: dict[str, str] = {}
            try:
                async with get_session_maker()() as label_db:
                    rows = (
                        await label_db.execute(
                            _select(
                                UtxoLabel.txid,
                                UtxoLabel.vout,
                                UtxoLabel.label,
                            )
                        )
                    ).all()
                    for txid, vout, label in rows:
                        label_by_outpoint[f"{txid}:{int(vout)}"] = label or ""
            except Exception:  # noqa: BLE001
                label_by_outpoint = {}

            # Refuse pre-existing exact-bin UTXOs that
            # confirmed on/after the feature-enabled day.
            # ``feature_enabled_at_day`` comes from the singleton
            # settings_store; absence ⇒ predicate returns
            # ``(False, hint)`` and we admit the UTXO.
            from datetime import datetime as _dt
            from datetime import timedelta as _td
            from datetime import timezone as _tz

            from app.core.database import get_session_maker as _gsm

            from .settings_store import get_feature_enabled_at_day

            feature_day = None
            try:
                async with _gsm()() as _sd:
                    feature_day = await get_feature_enabled_at_day(_sd)
            except Exception:  # noqa: BLE001
                feature_day = None

            candidates: list[WalletUtxo] = []
            for u in utxos_raw:
                op = u.get("outpoint", {}) or {}
                tx = (op.get("txid_str") or "").lower()
                vi = int(op.get("output_index", 0))
                if not tx:
                    continue
                key = f"{tx}:{vi}"
                lbl = label_by_outpoint.get(key, "")
                if is_do_not_spend_label(lbl):
                    continue
                w = WalletUtxo(
                    outpoint=key,
                    value_sat=int(u.get("amount_sat", 0)),
                    confirmations=int(u.get("confirmations", 0)),
                    label=lbl,
                )
                # refusal — coarse ``confirmed_at`` derived
                # from ``confirmations × 10min``. Sufficient for the
                # day-granularity check.
                confirmed_at = _dt.now(_tz.utc) - _td(minutes=10 * int(w.confirmations))
                refused, _reason = is_utxo_refused_as_anonymize_source(
                    w,
                    confirmed_at=confirmed_at,
                    feature_enabled_at_day=feature_day,
                )
                if refused:
                    continue
                candidates.append(w)
            # Max fee estimate: 400 sat (conservative single-input
            # P2TR send tx). The tolerance covers the wiggle.
            sel = select_exact_bin_funding(
                candidates,
                bin_amount_sat=int(amount_sat),
                max_estimated_fee_sat=400,
            )
            if sel.chosen_outpoints:
                outpoints = []
                for s in sel.chosen_outpoints:
                    txid_part, vout_part = s.split(":", 1)
                    outpoints.append(
                        {
                            "txid_str": txid_part,
                            "output_index": int(vout_part),
                        }
                    )

        # When no exact-bin UTXO exists, we route through
        # the consolidation flow: a single tx that pays the Boltz
        # lockup AND emits a decoy output to a wallet-
        # controlled BIP-86 address. The overpad change LND
        # produces is later labelled `auto:anonymize-overpad`. When
        # an exact-bin UTXO is available (single-input + no-change
        # funding), we skip the decoy and use the direct path.
        needs_consolidation = outpoints is None
        if needs_consolidation:
            try:
                decoy_addr_result, _ = await lnd_service.new_address(
                    address_type="p2tr",
                )
            except Exception:  # noqa: BLE001
                decoy_addr_result = None
            decoy_address = (
                (decoy_addr_result or {}).get("address", "")
                if isinstance(decoy_addr_result, dict)
                else (getattr(decoy_addr_result, "address", "") or "")
            )
            if decoy_address:
                from .coin_control import build_decoy_consolidation_outputs
                from .decoy_seed import record_decoy_output

                plan = build_decoy_consolidation_outputs(
                    bin_amount_sat=int(amount_sat),
                    max_estimated_fee_sat=400,
                    decoy_address=decoy_address,
                    decoy_derivation_index=0,
                )
                outputs = [
                    {"address": str(lockup_address), "amount": int(amount_sat)},
                    {"address": decoy_address, "amount": int(plan.decoy_value_sat)},
                ]
                try:
                    result, err = await lnd_service.send_outputs(
                        outputs=outputs,
                        sat_per_vbyte=sat_per_vbyte,
                        label=(f"anonymize-submarine-consolidation-{getattr(session, 'id', '')}"),
                    )
                except Exception as exc:  # noqa: BLE001
                    return None, str(exc)
                if err is not None or result is None:
                    return None, err or "send_outputs returned no result"
                txid = result.get("txid", "")
                # Persist the decoy row + emit the audit event.
                try:
                    from app.core.database import get_session_maker as _gsm

                    async with _gsm()() as _dsess:
                        await record_decoy_output(
                            _dsess,
                            session_id=session.id,
                            derivation_index=int(plan.decoy_derivation_index),
                            address=str(plan.decoy_address),
                            value_sat=int(plan.decoy_value_sat),
                            outpoint=(f"{txid}:1" if txid else None),
                        )
                        await _dsess.commit()
                except Exception:  # noqa: BLE001
                    # Decoy-row write is best-effort; the funding tx
                    # has landed and the session can proceed.
                    pass
                return {
                    "tx_hex": "",
                    "txid": txid,
                    "sat_per_vbyte": sat_per_vbyte,
                    "decoy_address": decoy_address,
                    "decoy_value_sat": int(plan.decoy_value_sat),
                }, None

        try:
            coins_result, err = await lnd_service.send_coins(
                address=str(lockup_address),
                amount_sats=int(amount_sat),
                sat_per_vbyte=sat_per_vbyte,
                outpoints=outpoints,
                label=f"anonymize-submarine-{getattr(session, 'id', '')}",
            )
        except Exception as exc:  # noqa: BLE001
            return None, str(exc)
        if err is not None or coins_result is None:
            return None, err or "send_coins returned no result"
        return {
            "tx_hex": "",
            "txid": coins_result.get("txid", ""),
            "sat_per_vbyte": sat_per_vbyte,
            "pinned_outpoints": outpoints,
        }, None

    async def _run_refund_subprocess(
        *,
        swap_id: str,
        session: AnonymizeSession,
    ) -> tuple[Any, Any]:
        # refund — bridges into ``scripts/submarine_refund.js``
        # using the persisted refund private key. The subprocess
        # writes the refund tx hex on fd 3 (out-of-band
        # transport). Swap state (refund key, lockup hex, swap tree,
        # timeout) is piped on stdin as JSON; the script never sees
        # any of it via argv (visible in ``ps``) or env.
        import json
        from pathlib import Path

        from sqlalchemy import select

        from app.core.database import get_session_maker
        from app.core.encryption import decrypt_field
        from app.models.boltz_swap import BoltzSwap

        from .subprocess import (
            SubprocessTimeoutError,
            run_boltz_claim_js,
        )

        async with get_session_maker()() as db:
            swap = (await db.execute(select(BoltzSwap).where(BoltzSwap.boltz_swap_id == swap_id))).scalar_one_or_none()
        if swap is None:
            return None, f"submarine swap row missing for id={swap_id}"

        # A persisted submarine swap always carries the encrypted refund
        # (claim) private key; the create path writes it before the row
        # is committed. Guard so the refund payload never wraps None.
        assert swap.claim_private_key_hex is not None  # refund key persisted at swap creation

        # Derive a fresh wallet-controlled BIP-86 (p2tr) address for the
        # refund output. Previously this was left empty, so the refund
        # script aborted before broadcasting and the locked funds could
        # not be auto-refunded on a swap timeout.
        from app.services.lnd_service import lnd_service

        try:
            addr_result, addr_err = await lnd_service.new_address(address_type="p2tr")
        except Exception as exc:  # noqa: BLE001
            return None, f"submarine refund: could not derive change address: {exc}"
        refund_address = ""
        if isinstance(addr_result, dict):
            refund_address = str(addr_result.get("address") or "")
        elif addr_result is not None:
            refund_address = str(getattr(addr_result, "address", "") or "")
        if addr_err or not refund_address:
            return None, f"submarine refund: could not derive change address: {addr_err or 'no address'}"

        payload = {
            "swapId": swap.boltz_swap_id,
            "refundPrivateKey": decrypt_field(swap.claim_private_key_hex),
            "refundPublicKey": swap.claim_public_key_hex,
            "swapTree": swap.boltz_swap_tree_json,
            "timeoutBlockHeight": swap.timeout_block_height,
            "refundAddress": refund_address,
        }
        repo_root = Path(__file__).resolve().parents[3]
        try:
            # Use the temp-file out-of-band transport (same as the Liquid
            # scripts) so the refund-tx hex is captured reliably — the
            # legacy fd transport mismatched the wrapper's fd number.
            result = await run_boltz_claim_js(
                args=("scripts/submarine_refund.js",),
                cwd=repo_root,
                stdin_payload=json.dumps(payload).encode("utf-8"),
                use_tx_out_file=True,
            )
        except SubprocessTimeoutError as exc:
            return None, f"submarine refund subprocess timeout: {exc}"
        except RuntimeError as exc:
            return None, f"submarine refund subprocess failed: {exc}"
        hex_value = result.claim_tx_hex.value if result.claim_tx_hex is not None else None
        if not hex_value:
            return None, "submarine refund subprocess produced no fd-3 hex"
        if result.returncode != 0:
            return None, (f"submarine refund subprocess exit={result.returncode}")
        return hex_value, None

    async def _chain_broadcast(tx_hex: str) -> tuple[Any, Any]:
        from .chain_egress import anonymize_broadcast_tx

        txid, error = await anonymize_broadcast_tx(tx_hex)
        if error is not None:
            return None, error
        return txid, None

    async def _check_inbound_sufficient(receive_sats: int) -> str | None:
        # Local-only inbound capacity check (no third-party egress);
        # honours ``anonymize_inbound_preflight_enabled`` and is
        # best-effort (returns no refusal on any LND error). Reuses the
        # same helper the create-time gate uses so both points apply an
        # identical rule.
        from .inbound_preflight import inbound_preflight

        refusal, _warning = await inbound_preflight(receive_sats=receive_sats)
        return refusal

    return SubmarineHopDeps(
        boltz_create_submarine_swap=_create_submarine_swap,
        boltz_get_swap_status=_get_swap_status,
        lnd_add_invoice=_lnd_add_invoice,
        build_and_broadcast_funding_tx=_build_and_broadcast_funding_tx,
        run_refund_subprocess=_run_refund_subprocess,
        chain_broadcast_tx=_chain_broadcast,
        check_inbound_sufficient=_check_inbound_sufficient,
    )


def build_default_priv_channel_hop_deps() -> PrivChannelHopDeps:
    """Bind the production adapters for the priv_channel hop.

    Each adapter wraps an LND-RPC call. This ships the basic
    open/active/push/close-cooperative wires; the auto peer
    selection runs against a pre-fetched LND ``describe_graph``
    snapshot supplied by the caller.
    """
    from app.services.lnd_service import lnd_service

    async def _select_auto_peer(
        *,
        session: AnonymizeSession,
        **_kwargs: Any,
    ) -> tuple[Any, Any]:
        # Fetch LND's describe_graph snapshot, filter through
        # the auto-blocklist + cooldown set, weighted-
        # random pick over top-K. The blocklist + cooldown set come
        # from the wallet's recent-payments + sticky-peer history.
        from app.core.config import settings as _settings

        from .peer_selection import (
            candidates_from_lnd_graph,
            select_auto_peer,
        )

        # Snapshot the gossip graph (excluding unannounced/private
        # channels — anonymize-stack peers must be publicly-known).
        try:
            graph, gerr = await lnd_service.describe_graph(
                include_unannounced=False,
            )
        except Exception as exc:  # noqa: BLE001
            return None, f"describe_graph failed: {exc}"
        if gerr is not None or not isinstance(graph, dict):
            return None, gerr or "describe_graph returned no result"

        # Our own pubkey — exclude so we don't open to ourselves.
        try:
            our_info, _ = await lnd_service.get_info()
        except Exception:  # noqa: BLE001
            our_info = None
        our_info_dict: dict[str, Any] = dict(our_info) if our_info else {}
        our_pubkey: str | None = our_info_dict.get("identity_pubkey") or our_info_dict.get("pubkey") or None

        candidates = candidates_from_lnd_graph(
            nodes=list(graph.get("nodes", [])),
            channels=list(graph.get("edges", [])),
            our_node_pubkey=our_pubkey,
        )

        blocklist = frozenset(
            _settings.anonymize_peer_blocklist_list,
        )
        # cooldown set — sessions that recently used a peer
        # contribute to a "recent" set. The full cooldown ledger
        # lives alongside `auto_peer_chosen` event aggregation; for
        # now, derive from current channel peers so the next pick
        # doesn't duplicate one we already have a channel with.
        try:
            channels, _ = await lnd_service.get_channels()
        except Exception:  # noqa: BLE001
            channels = None
        recent_pubkeys = frozenset(
            (ch.get("remote_pubkey") or "") for ch in (channels or []) if (ch.get("remote_pubkey") or "")
        )

        chosen = select_auto_peer(
            candidates,
            blocklist=blocklist,
            recent_pubkeys=recent_pubkeys,
            min_outbound_capacity_sat=int(
                _settings.anonymize_min_sat or 0,
            ),
            top_k=int(
                _settings.anonymize_auto_peer_top_k or 24,
            ),
        )
        if chosen is None:
            return None, "no eligible auto-peer"

        # Record the audit event so the audit chain has the
        # chosen-peer evidence (the chosen pubkey is blinded by the
        # redactor before egress).
        # The caller commits the row.
        return chosen, None

    async def _open_private_channel(
        *,
        peer_pubkey: str,
        local_funding_amount_sat: int,
    ) -> tuple[Any, Any]:
        # Jitter the channel-open feerate so the funding
        # tx's fingerprint doesn't reveal a rigid sat/vB.
        from .chain_egress import get_anonymize_economy_feerate
        from .txpolicy import feerate_jitter

        sat_per_vbyte: int | None = None
        economy, _ = await get_anonymize_economy_feerate()
        if economy is not None and economy > 0:
            jittered = feerate_jitter(float(economy), minrelay_sat_per_vb=1.0)
            sat_per_vbyte = max(1, int(round(jittered)))

        try:
            result, err = await lnd_service.open_channel(
                node_pubkey_hex=str(peer_pubkey),
                local_funding_amount=int(local_funding_amount_sat),
                sat_per_vbyte=sat_per_vbyte,
                private=True,
            )
        except Exception as exc:  # noqa: BLE001
            return None, str(exc)
        if err is not None or not result:
            return None, err or "open_channel returned no result"
        # Encode the channel point as the orchestrator's canonical
        # ``txid:vout`` form.
        cp = f"{result.get('funding_txid')}:{int(result.get('output_index', 0))}"
        return cp, None

    async def _channel_is_active(*, channel_point: str) -> tuple[Any, Any]:
        try:
            channels, err = await lnd_service.get_channels()
        except Exception as exc:  # noqa: BLE001
            return None, str(exc)
        if err is not None or channels is None:
            return None, err or "get_channels returned no result"
        for ch in channels:
            cp = ch.get("channel_point") if isinstance(ch, dict) else None
            if cp and str(cp) == str(channel_point):
                return bool(ch.get("active", False)), None
        return False, None

    async def _send_payment_through_channel(
        *,
        channel_point: str,
        amount_sat: int,
        session: AnonymizeSession,
    ) -> tuple[Any, Any]:
        # The per-session loop synthesizes a route hint that
        # constrains the HTLC's first hop to ``channel_point``. The
        # actual route-hint construction lands alongside the
        # describe_graph fetcher; this stub fails closed so the
        # per-session loop's bounded-retry routes to reconciliation.
        return None, "priv_channel push route-hint wiring not yet completed"

    async def _close_channel_cooperative(*, channel_point: str) -> tuple[Any, Any]:
        # ``channel_point`` is ``txid:vout``; LND wants them split.
        try:
            txid, vout = str(channel_point).split(":", 1)
        except ValueError:
            return None, f"malformed channel_point: {channel_point!r}"
        try:
            result, err = await lnd_service.close_channel(
                funding_txid=txid,
                output_index=int(vout),
                force=False,  # — cooperative only.
            )
        except Exception as exc:  # noqa: BLE001
            return None, str(exc)
        if err is not None:
            return None, err
        return result, None

    return PrivChannelHopDeps(
        select_auto_peer=_select_auto_peer,
        lnd_open_private_channel=_open_private_channel,
        lnd_channel_is_active=_channel_is_active,
        lnd_send_payment_through_channel=_send_payment_through_channel,
        lnd_close_channel_cooperative=_close_channel_cooperative,
    )


def build_default_liquid_hop_deps() -> LiquidHopDeps | None:
    """Bind the production adapters for the Liquid round-trip hop.

    Returns ``None`` when the Liquid hop is disabled
    (``ANONYMIZE_LIQUID_ENABLED=false``, the default) — callers
    must skip the Liquid path in that case. Returns a fully-wired
    :class:`LiquidHopDeps` instance when enabled, composing against:

    * :class:`ElectrumLiquidBackend` over an
      :class:`ElectrumClient` configured for
      ``ANONYMIZE_LIQUID_ELECTRUM_URL``.
    * Two :class:`LiquidSwapClient` instances — one per leg.
      The LN→L-BTC client targets the reverse-analog operator (by
      default ``boltz-canonical``, since the L-BTC dwell output
      benefits from the largest mempool anonymity set). The L-BTC→LN
      client targets the submarine-analog operator (the
      most-recently-audited non-canonical Liquid-capable operator,
      with canonical as last-resort fallback). Both are resolved by
      :func:`operators.select_liquid_leg_urls`, which honours
      ``BOLTZ_CHAIN_LN_TO_LBTC_API_URL`` /
      ``BOLTZ_CHAIN_LBTC_TO_LN_API_URL`` as optional per-leg
      pin-overrides.
    * LND-side adapters wired against the wallet's ``lnd_service``.
    * SLIP-77 master blinding key derived from
      ``ANONYMIZE_LIQUID_SEED_FERNET``.

    The factory caches its result module-locally so the
    ``ElectrumClient`` connection + ``swap_state`` map are stable
    across dispatcher calls within a single process.
    """
    from app.core.config import settings as _settings

    if not is_liquid_hop_enabled():
        return None

    global _LIQUID_HOP_DEPS_CACHE
    cached = _LIQUID_HOP_DEPS_CACHE
    if cached is not None:
        return cached

    from app.services.chain.electrum import ElectrumClient

    from .liquid_backend import ElectrumLiquidBackend
    from .liquid_hop_adapters import build_liquid_hop_deps
    from .liquid_seed import (
        load_liquid_master_blinding_key,
        resolve_liquid_btc_asset_id,
        resolve_liquid_network,
    )
    from .liquid_swap import LiquidSwapClient

    electrum_url_raw = (_settings.anonymize_liquid_electrum_url or "").strip()
    if not electrum_url_raw:
        raise RuntimeError("ANONYMIZE_LIQUID_ELECTRUM_URL must be set when ANONYMIZE_LIQUID_ENABLED=true")
    master_key = load_liquid_master_blinding_key()
    if master_key is None:
        raise RuntimeError("ANONYMIZE_LIQUID_SEED_FERNET must be set when ANONYMIZE_LIQUID_ENABLED=true")
    asset_id = resolve_liquid_btc_asset_id()
    network = resolve_liquid_network()

    client = ElectrumClient(electrum_url_raw)
    backend = ElectrumLiquidBackend(client)

    # Per-leg operator selection — mirrors the LN↔on-chain leg-picking
    # policy in operator_selection._compute_chain: canonical Boltz on
    # the high-anonymity-set leg (LN→L-BTC, where the L-BTC dwell
    # output joins the largest mempool), alt operator (Middleway →
    # Eldamar fallback) on the submarine-analog leg (L-BTC→LN).
    # ``BOLTZ_CHAIN_LN_TO_LBTC_API_URL`` / ``BOLTZ_CHAIN_LBTC_TO_LN_API_URL``
    # remain as explicit pin-overrides; empty values fall through to
    # registry-driven selection.
    from .operators import select_liquid_leg_urls

    try:
        legs = select_liquid_leg_urls()
    except RuntimeError as exc:
        raise RuntimeError(
            f"Liquid hop enabled but no chain-swap operator URL is "
            f"available: {exc}. Populate the signed operator registry "
            f"or set BOLTZ_CHAIN_LN_TO_LBTC_API_URL + "
            f"BOLTZ_CHAIN_LBTC_TO_LN_API_URL."
        ) from exc

    # Audit-trail emission: forensic record of which operator IDs
    # this process bound for each Liquid leg on first dispatch.
    # Surfaced as a structured log event so SIEM forwarders and
    # operators tailing logs can correlate per-session swap activity
    # back to the operator-pair selection that produced it. Emitted
    # once per cache fill (i.e. once per process lifetime in steady
    # state); the cache reset hook re-emits it on the next call.
    from .metadata import ANONYMIZE_LOGGER_NAME as _ANL

    logging.getLogger(_ANL).info(
        "anonymize_liquid_operators_selected ln_to_lbtc=%s lbtc_to_ln=%s legs_distinct=%s",
        legs.ln_to_lbtc_operator_id or legs.ln_to_lbtc_url,
        legs.lbtc_to_ln_operator_id or legs.lbtc_to_ln_url,
        legs.legs_distinct,
    )

    if not legs.legs_distinct:
        # Diagnostic warning: both legs collapsed to the same operator
        # (single-operator-Liquid deployment). The hop still works but
        # the inter-leg unlinkability the registry split is designed
        # to provide is forfeit. Operators can either accept this
        # (smaller-deployment Liquid is opt-in) or add a second
        # Liquid-capable operator to the registry.
        from .metadata import ANONYMIZE_LOGGER_NAME as _ANL

        logging.getLogger(_ANL).warning(
            "liquid-hop: both chain-swap legs target the same operator "
            "(ln_to_lbtc=%s, lbtc_to_ln=%s); inter-leg unlinkability "
            "is reduced",
            legs.ln_to_lbtc_operator_id or legs.ln_to_lbtc_url,
            legs.lbtc_to_ln_operator_id or legs.lbtc_to_ln_url,
        )

    swap_client = LiquidSwapClient(base_url=legs.ln_to_lbtc_url)
    submarine_swap_client = LiquidSwapClient(base_url=legs.lbtc_to_ln_url) if legs.legs_distinct else swap_client

    # LN-side adapters — thin shims over the wallet's lnd_service so
    # the hop body doesn't drag in the full service module.
    async def _lnd_send_payment(
        *,
        payment_request: str,
        amount_sat: int,
    ) -> tuple[Any, str | None]:
        from app.services.lnd_service import lnd_service

        try:
            # The amount is encoded in the BOLT11 ``payment_request``;
            # ``send_payment_v2`` doesn't accept a separate amount
            # kwarg. (We keep ``amount_sat`` on the adapter signature
            # for parity with the Liquid swap-state book-keeping that
            # the caller threads through.) ``_=amount_sat`` is here
            # only to flag that we're intentionally discarding the
            # argument.
            _ = amount_sat
            result = await lnd_service.send_payment_v2(
                payment_request=payment_request,
            )
            return result, None
        except Exception as exc:  # noqa: BLE001
            return None, f"lnd_send_payment failed: {exc}"

    # Shared between the create + observe adapters so the observer
    # can pull the wallet-minted invoice's ``payment_hash`` keyed by
    # the Boltz swap id the hop body persists in ``pipeline_json``.
    swap_state: dict[str, dict[str, Any]] = {}

    async def _lnd_observe_invoice_settled(
        *,
        swap_id: str,
        session_id: Any,
    ) -> tuple[bool, str | None]:
        """Resolve the L-BTC→LN settlement by looking up our invoice.

        The L-BTC→LN create adapter stashes the wallet-minted
        invoice's ``payment_hash_hex`` in ``swap_state[swap_id]``.
        Boltz pays that invoice once it claims the wallet's L-BTC
        lockup; LND's ``lookup_invoice`` reflects the settlement.
        """
        from app.services.lnd_service import lnd_service

        _ = session_id
        if not swap_id:
            return False, "missing swap_id"
        state = swap_state.get(str(swap_id))
        if state is None:
            return False, f"no per-swap state for {swap_id!r}"
        payment_hash_hex = str(state.get("payment_hash_hex") or "")
        if not payment_hash_hex:
            return False, "no payment_hash recorded for swap"
        try:
            info, err = await lnd_service.lookup_invoice(payment_hash_hex)
        except Exception as exc:  # noqa: BLE001
            return False, f"lookup_invoice failed: {exc}"
        if err is not None or info is None:
            return False, err or "lookup_invoice returned no invoice"
        # LND's ``InvoiceInfo.settled`` is True only after the
        # routed payment has been claimed via the preimage reveal.
        settled = info.get("settled") if isinstance(info, dict) else getattr(info, "settled", False)
        return bool(settled), None

    async def _lnd_create_invoice(
        *,
        amount_sat: int,
        memo: str,
    ) -> tuple[Any, str | None]:
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
        # Translate LND's ``payment_request`` / ``r_hash`` to the
        # adapter contract's ``bolt11`` / ``payment_hash``.
        return {
            "bolt11": result.get("payment_request"),
            "payment_hash": result.get("r_hash"),
        }, None

    deps = build_liquid_hop_deps(
        backend=backend,
        swap_client=swap_client,
        submarine_swap_client=submarine_swap_client,
        lnd_send_payment=_lnd_send_payment,
        lnd_observe_invoice_settled=_lnd_observe_invoice_settled,
        lnd_create_invoice=_lnd_create_invoice,
        master_blinding_key=master_key,
        expected_asset_id=asset_id,
        network=network,
        swap_state=swap_state,
        ln_to_lbtc_operator_id=legs.ln_to_lbtc_operator_id,
        lbtc_to_ln_operator_id=legs.lbtc_to_ln_operator_id,
    )
    _LIQUID_HOP_DEPS_CACHE = deps
    return deps


def reset_default_liquid_hop_deps_cache() -> None:
    """Reset the module-local cache; intended for tests + supervisor restarts."""
    global _LIQUID_HOP_DEPS_CACHE
    _LIQUID_HOP_DEPS_CACHE = None


_LIQUID_HOP_DEPS_CACHE: "LiquidHopDeps | None" = None


def build_default_bolt12_pay_hop_deps() -> Bolt12PayHopDeps:
    """Bind the production adapter for the BOLT 12-exit hop body.

    The single adapter wraps the wallet's BOLT 12 outbound-payment
    machinery — the same flow the public ``/bolt12/pay`` endpoint
    drives. We invoke the inner :func:`app.api.bolt12._perform_pay_offer`
    helper directly, with a synthesised :class:`PayOfferRequest`,
    rather than hitting the FastAPI handler shell so the adapter can
    return a ``(result, error)`` tuple instead of raising
    :class:`HTTPException`.

    The adapter persists the standard BOLT 12 invoice + invreq rows
    (so the operator's dashboard reflects the BOLT 12 payment) AND
    surfaces the outcome to the anonymize hop body, which records
    the same outcome into ``pipeline_json["bolt12_pay_outcome"]``.

    Error handling: any exception from the inner helper (gateway
    unreachable, malformed reply, signature mismatch, settlement
    failure) is translated to an ``error`` string the hop body
    records as a session-level FAILED transition. The helper itself
    is responsible for keeping the per-invoice DB rows consistent
    (success → ``PAID`` / failure → ``FAILED`` with ``error_message``
    populated); the hop body's outcome record is a separate audit
    surface on the anonymize session row.
    """
    from app.api.bolt12 import PayOfferRequest, _perform_pay_offer
    from app.core.database import get_session_maker
    from app.models.api_key import APIKey

    async def _pay_bolt12_offer(
        *,
        offer: str,
        amount_msat: int,
        session: AnonymizeSession,
    ) -> tuple[Any, Any]:
        # Anonymize sessions don't have a user-facing API key — the
        # BOLT 12 row persistence uses the wallet's dashboard API key.
        from sqlalchemy import select

        from app.dashboard import DASHBOARD_KEY_ID

        async with get_session_maker()() as inner_db:
            key_row = (await inner_db.execute(select(APIKey).where(APIKey.id == DASHBOARD_KEY_ID))).scalar_one_or_none()
            if key_row is None:
                return None, "dashboard API key row missing"

            req = PayOfferRequest(
                offer=offer,
                amount_msat=int(amount_msat),
                quantity=None,
                payer_note=None,
            )
            try:
                result = await _perform_pay_offer(
                    req,
                    api_key=key_row,
                    db=inner_db,
                    ip=None,
                )
            except Exception as exc:  # noqa: BLE001 — translate to (result, error)
                return None, f"pay_offer failed: {exc}"

        # ``_perform_pay_offer`` returns the response dict. Translate
        # the public response shape into the hop body's expected shape.
        status_value = str(result.get("status") or "").upper()
        if status_value == "paid".upper():
            status = "paid"
        elif status_value == "failed".upper():
            status = "failed"
        else:
            status = "in_flight"
        return {
            "status": status,
            "payment_hash_hex": result.get("payment_hash_hex") or "",
            # ``_perform_pay_offer`` doesn't surface the preimage in
            # the public response shape (privacy: the preimage is
            # stored Fernet-wrapped on the invoice row). The
            # anonymize audit chain reads it from the invoice row
            # via the existing reconciliation sweep when needed.
            "preimage_hex": None,
            "error": None,
        }, None

    return Bolt12PayHopDeps(pay_bolt12_offer=_pay_bolt12_offer)


def build_default_ln_self_pay_hop_deps() -> LnSelfPayHopDeps:
    """Bind the production adapters for the LN self-pay source hop.

    The adapters wrap the wallet's ``LNDService`` (mint invoice, send
    the circular self-payment, look up settlement) plus a routing
    resolver that snapshots the wallet's channels and picks the
    self-pay posture (pinned vs MPP-split) from config.
    """
    from app.services.lnd_service import lnd_service

    async def _lnd_add_invoice(*, amount_sat: int, memo: str | None) -> tuple[Any, Any]:
        try:
            result, err = await lnd_service.create_invoice(
                amount_sats=int(amount_sat),
                memo=memo or "",
                expiry=3600,
            )
        except Exception as exc:  # noqa: BLE001
            return None, str(exc)
        if err is not None or result is None:
            return None, err or "create_invoice returned no result"
        return result, None

    async def _lnd_send_self_payment(
        *,
        payment_request: str,
        outgoing_chan_id: str | None = None,
        max_parts: int | None = None,
        ignored_pairs: list[tuple[str, str]] | None = None,
    ) -> tuple[Any, Any]:
        from app.core.config import settings as _settings

        fee_limit = int(_settings.anonymize_self_pay_fee_limit_sats)
        # Mutual exclusion: pin one channel OR MPP-split, never both in
        # a single call — LND drops the pin when max_parts > 1. The two
        # postures route through separate call sites.
        if outgoing_chan_id:
            return await lnd_service.send_payment_v2(
                payment_request=payment_request,
                outgoing_chan_id=outgoing_chan_id,
                allow_self_payment=True,
                fee_limit_sats=fee_limit,
                timeout_seconds=60,
            )
        return await lnd_service.send_payment_v2(
            payment_request=payment_request,
            max_parts=max_parts,
            ignored_pairs=ignored_pairs,
            allow_self_payment=True,
            fee_limit_sats=fee_limit,
            timeout_seconds=60,
        )

    async def _lnd_lookup_invoice(payment_hash_hex: str) -> tuple[Any, Any]:
        try:
            return await lnd_service.lookup_invoice(payment_hash_hex)
        except Exception as exc:  # noqa: BLE001
            return None, str(exc)

    async def _resolve_self_pay_route(*, session: AnonymizeSession, **_kwargs: Any) -> tuple[Any, Any]:
        from app.core.config import settings as _settings

        from .self_pay_routing import resolve_self_pay_route

        try:
            channels, cerr = await lnd_service.get_channels()
        except Exception as exc:  # noqa: BLE001
            return None, f"get_channels failed: {exc}"
        if cerr is not None or channels is None:
            return None, cerr or "get_channels returned no result"

        try:
            our_info, _ = await lnd_service.get_info()
        except Exception:  # noqa: BLE001
            our_info = None
        our_info_dict: dict[str, Any] = dict(our_info) if our_info else {}
        our_pubkey = our_info_dict.get("identity_pubkey") or our_info_dict.get("pubkey") or ""

        # The avoid set is the operator peer blocklist (e.g. exchange
        # hubs): excluded as pinned source channels and as first-hop
        # edges in split mode.
        avoid = set(_settings.anonymize_peer_blocklist_list)

        return resolve_self_pay_route(
            channels=[dict(ch) for ch in channels],
            our_pubkey=str(our_pubkey),
            avoid_pubkeys=avoid,
            bin_amount_sat=int(session.bin_amount_sat or 0),
            mode_policy=_settings.anonymize_self_pay_mode,
            split_min_channels=int(_settings.anonymize_self_pay_split_min_channels),
            mpp_max_parts=int(_settings.anonymize_reverse_mpp_chunks_range_max),
        )

    return LnSelfPayHopDeps(
        lnd_add_invoice=_lnd_add_invoice,
        lnd_send_self_payment=_lnd_send_self_payment,
        lnd_lookup_invoice=_lnd_lookup_invoice,
        resolve_self_pay_route=_resolve_self_pay_route,
    )


def default_hop_step_fn() -> HopStepFn:
    """Return a hop-step fn bound to the production adapters.

    The fn dispatches by status + source kind:
    * Status ``awaiting_liquid_dwell`` → Liquid hop body
      (unambiguous; this status only exists for the Liquid hop).
    * Status ``hopping`` + ``pipeline_json["uses_liquid"]`` set →
      Liquid hop body for the LN→L-BTC and L-BTC→LN legs.
    * LN-self source (``funding`` / ``ln_holding``) → self-pay hop
      body, which fires the circular self-payment.
    * On-chain source (``sourcing`` / ``funding`` / ``ln_holding``)
      → submarine hop body.
    * Everything else → reverse hop body.
    """
    reverse_deps = build_default_reverse_hop_deps()
    submarine_deps = build_default_submarine_hop_deps()
    bolt12_pay_deps = build_default_bolt12_pay_hop_deps()
    ln_self_pay_deps = build_default_ln_self_pay_hop_deps()
    # Liquid deps may be None when the hop is disabled (the default).
    liquid_deps = build_default_liquid_hop_deps()

    async def _fn(db: AsyncSession, session: AnonymizeSession) -> Any:
        source_kind = (session.source_kind or "").lower()
        is_onchain = source_kind in {"onchain-self", "ext-onchain"}
        is_ln_self = source_kind == "lightning-self"
        status = (session.status or "").lower()
        pj = session.pipeline_json or {}
        uses_liquid = bool(pj.get("uses_liquid", False))
        exit_kind = ((pj.get("exit") or {}).get("kind") or "reverse").lower()

        # Status awaiting_liquid_dwell is unambiguous — always Liquid.
        if status == "awaiting_liquid_dwell" and liquid_deps is not None:
            return await execute_liquid_hop_step(db, session, liquid_deps)
        # Mid-pipeline Liquid leg: hopping status + uses_liquid marker.
        if status == "hopping" and uses_liquid and liquid_deps is not None:
            return await execute_liquid_hop_step(db, session, liquid_deps)
        # BOLT 12 exit. Only fires once the session has
        # reached EXITING; pre-exit hops (sourcing / funding /
        # ln_holding / hopping) still route through the standard
        # hop bodies. Today bolt12_pay exits are LN-source only (the
        # quote builder + ``validate_pipeline`` enforce that), so
        # we never see them on an on-chain source row.
        if exit_kind == "bolt12_pay" and status == "exiting":
            return await execute_bolt12_pay_hop_step(
                db,
                session,
                bolt12_pay_deps,
            )
        # LN-self sources fire the circular self-payment during FUNDING
        # and settle into LN_HOLDING; the rest of the pipeline
        # (DELAYING / EXITING / CONFIRMING) routes through the reverse
        # hop body for the exit.
        if is_ln_self and status in {"funding", "ln_holding"}:
            return await execute_ln_self_pay_hop_step(db, session, ln_self_pay_deps)
        # On-chain sources route through submarine until LN_HOLDING
        # observes settlement; the rest of the pipeline (HOPPING /
        # EXITING / CONFIRMING) routes through the reverse hop body.
        if is_onchain and status in {"sourcing", "funding", "ln_holding"}:
            return await execute_submarine_hop_step(db, session, submarine_deps)
        return await execute_reverse_hop_step(db, session, reverse_deps)

    return _fn


__all__ = [
    "HopStepFn",
    "build_default_bolt12_pay_hop_deps",
    "build_default_ln_self_pay_hop_deps",
    "build_default_liquid_hop_deps",
    "build_default_priv_channel_hop_deps",
    "build_default_reverse_hop_deps",
    "build_default_submarine_hop_deps",
    "default_hop_step_fn",
    "reset_default_liquid_hop_deps_cache",
]
