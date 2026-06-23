# SPDX-License-Identifier: MIT
"""Public-facing projections of anonymize models.

The dashboard endpoints serialize ``AnonymizeSession`` / event rows
via these helpers, which strip every field that must never reach the
wire:

* destination_address_enc (encrypted destination)
* quote_hmac (the token's MAC; bound to internal key set)
* destination_address_blake2b_keyed (reuse-detection fingerprint)
* destination_reuse_key_generation, *_key columns
* last_error (PII surface)
* claim_tx_hex (chain anchor)
* hop_idempotency_key, hop_idempotency_nonce_enc

Two reasons to centralize the projection:

1. internal-ID egress enforcement — a list / detail endpoint
   that accidentally serialises ``session.id`` plus a Boltz internal
   id makes the row cross-referenceable from a screenshot. The
   projection enforces a stable allowlist of fields.
2. last-error redaction — the setter-side redactor already
   runs, but the projection drops the column entirely for the
   external surface.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from app.models.anonymize_session import (
    AnonymizeSession,
    AnonymizeSessionEvent,
)


def project_session_summary(session: AnonymizeSession) -> dict[str, Any]:
    """Safe wire shape for list-endpoint rows.

    Returns a flat dict suitable for JSON-encoding. Field order is
    stable (Python 3.7+ dict insertion order) so the response body
    matches the byte-pinned shape the SPA expects.

    Reconciliation-related fields are included on every row even when
    null so the SPA's row-rendering helpers can do a flat lookup
    instead of guarding every reference behind a key-existence check.
    """
    return {
        "id": str(session.id),
        "status": session.status,
        "source_kind": session.source_kind,
        "bin_amount_sat": int(session.bin_amount_sat or 0),
        "created_at": _iso(session.created_at),
        "completed_at": _iso(session.completed_at),
        "pipeline_schema_version": int(session.pipeline_schema_version or 0),
        # reconciliation triage fields. Always emitted for shape
        # stability; non-null only for sessions that have entered
        # AWAITING_RECONCILIATION at least once.
        "awaiting_reconciliation_reason": session.awaiting_reconciliation_reason,
        "pre_reconciliation_status": session.pre_reconciliation_status,
        "reconciliation_attempts": int(session.reconciliation_attempts or 0),
        "last_reconciliation_attempt_ts": _iso(session.last_reconciliation_attempt_ts),
        # Next-retry wall-clock for the SPA countdown.
        # Lazily computed via the probe module so this projection
        # module stays free of the probe's heavier imports.
        "next_retry_at_unix_s": _compute_next_retry_at_unix_s(session),
        # confirming-status display: "(X/Y)". Only meaningful for
        # status=CONFIRMING; emit on every row for shape stability so
        # the SPA can read it without conditionals.
        "confirmation_count": int(session.claim_tx_confirmations or 0),
        # inline detail panel. Already-redacted at the setter
        # but we surface only the redacted form here; the
        # raw column is never serialised.
        "last_error_redacted": session.last_error,
    }


def project_session_detail(
    session: AnonymizeSession,
    *,
    events: list[AnonymizeSessionEvent] | None = None,
    max_events: int = 200,
) -> dict[str, Any]:
    """Detail-endpoint shape: summary fields + event log + deposit info.

    Events are sorted oldest-first so the SPA can render the
    timeline naturally; bounded by ``max_events`` so a session with
    many retried hops can't blow the response size.

    For ``ext-lightning`` and ``ext-onchain`` sources, the
    ``deposit`` block surfaces the strings the wizard shows the
    depositor (BOLT 11 invoice, BOLT 12 offer, BIP-353 handle, or
    on-chain address). The block is sourced from
    ``pipeline_json["source"]`` and intentionally only includes
    public-safe deposit primitives — internal IDs, encrypted
    columns, and Boltz-side handles are NOT exposed.
    """
    out = project_session_summary(session)
    out["events"] = [project_session_event(e) for e in (events or [])[:max_events]]
    out["deposit"] = _project_deposit(session)
    return out


def _project_deposit(session: AnonymizeSession) -> dict[str, Any] | None:
    """Surface the deposit primitives for ``ext-*`` source kinds.

    Returns ``None`` for source kinds that don't have an inbound
    deposit step (the wallet's own LN / on-chain funds need no
    deposit prompt for the depositor). Otherwise returns a flat
    dict with whichever primitives the session-create endpoint
    populated.
    """
    pj = session.pipeline_json or {}
    if not isinstance(pj, dict):
        return None
    src_block = pj.get("source") or {}
    if not isinstance(src_block, dict):
        return None
    if session.source_kind not in {"ext-lightning", "ext-onchain"}:
        return None

    deposit: dict[str, Any] = {
        "method": src_block.get("deposit_method") or ("onchain" if session.source_kind == "ext-onchain" else "bolt11"),
    }
    # BOLT 11 deposit invoice — single-use blinded payment-request.
    if src_block.get("deposit_invoice"):
        deposit["bolt11_invoice"] = src_block["deposit_invoice"]
    # BOLT 12 deposit offer + optional BIP-353 handle.
    if src_block.get("deposit_bolt12_offer"):
        deposit["bolt12_offer"] = src_block["deposit_bolt12_offer"]
    if src_block.get("deposit_bip353_handle"):
        deposit["bip353_handle"] = src_block["deposit_bip353_handle"]
    if src_block.get("deposit_bip353_txt_record"):
        deposit["bip353_txt_record"] = src_block["deposit_bip353_txt_record"]
    # ext-onchain deposit address + amount lock.
    if src_block.get("deposit_address"):
        deposit["onchain_address"] = src_block["deposit_address"]
    if src_block.get("deposit_amount_sat") is not None:
        deposit["amount_sat"] = int(src_block["deposit_amount_sat"])
    if src_block.get("deposit_expiry_unix_s") is not None:
        deposit["expiry_unix_s"] = int(src_block["deposit_expiry_unix_s"])
    return deposit


def project_session_event(event: AnonymizeSessionEvent) -> dict[str, Any]:
    """Per-event wire shape.

    ``detail_json`` is included as-is — the orchestrator's event
    writer is the boundary that enforces the privacy-preserving
    subset. The projection refuses to leak
    ``hop_idempotency_key`` / ``hop_idempotency_nonce_enc``.
    """
    return {
        "ts": _iso(event.ts),
        "kind": event.kind,
        "detail": dict(event.detail_json or {}),
    }


def _iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def _compute_next_retry_at_unix_s(
    session: AnonymizeSession,
) -> float | None:
    """Lazy wrapper around the probe module's pure helper.

    Kept here (rather than imported at module load) so a circular
    import doesn't fire — the probe module imports the service
    helpers + state machine; importing it from this module at load
    time creates a cycle.
    """
    from .reconciliation_probe import compute_next_retry_at_unix_s

    return compute_next_retry_at_unix_s(session)


__all__ = [
    "project_session_summary",
    "project_session_detail",
    "project_session_event",
]
