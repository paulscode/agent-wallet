# SPDX-License-Identifier: MIT
"""UTXO management service.

Server-side logic for the dashboard UTXO surface:

* fetch the live UTXO set from LND and join it with stored labels;
* mutate label rows (set / clear);
* reconcile the label store against ``ListUnspent`` to mark spent
  outputs;
* assist with the consolidate flow (validation + post-broadcast
  inherit-on-spend label mapping).

The functions here all assume an authenticated caller (the dashboard
API layer is responsible for auth) and return plain Python data so
the FastAPI routes stay thin.
"""

from __future__ import annotations

import logging
import re
import unicodedata
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.utxo_label import (
    LABEL_MAX_LEN,
    AddressPurpose,
    UtxoLabel,
    UtxoLabelSource,
)
from app.services.lnd_service import lnd_service
from app.services.lnd_types import Outpoint, Utxo

logger = logging.getLogger(__name__)


# ─── Validation helpers ──────────────────────────────────────────────────

# 64 hex chars, lowercase. We re-emit canonicalised ids so downstream
# joins on the unique constraint never miss because of casing.
_TXID_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def normalise_label(label: str) -> str:
    """Trim, NFC-normalise, and validate a label.

    Raises ``ValueError`` for control bytes, anything > LABEL_MAX_LEN
    after NFC normalisation, or non-string input. Empty strings are
    allowed because a row may exist for a spent UTXO with no label
    text.
    """
    if label is None:
        return ""
    if not isinstance(label, str):
        raise ValueError("label must be a string")
    label = unicodedata.normalize("NFC", label).strip()
    if len(label) > LABEL_MAX_LEN:
        raise ValueError(f"label exceeds {LABEL_MAX_LEN} characters")
    for ch in label:
        cp = ord(ch)
        if cp < 0x20 and cp not in (0x09,):
            raise ValueError(f"label contains disallowed control byte (codepoint {cp:#04x})")
        if cp == 0x7F:
            raise ValueError("label contains DEL control byte (0x7f)")
    # Reject HTML-significant angle brackets as belt-and-suspenders against
    # a future renderer that interpolates labels into HTML/SVG (today they
    # render inert via Alpine x-text).
    if "<" in label or ">" in label:
        raise ValueError("label may not contain '<' or '>'")
    return label


def normalise_txid(txid: str) -> str:
    if not isinstance(txid, str) or not _TXID_RE.match(txid):
        raise ValueError("txid must be a 64-char hex string")
    return txid.lower()


# ─── Listing ─────────────────────────────────────────────────────────────


def _utxo_age_seconds(confirmations: int, *, secs_per_block: int = 600) -> int:
    """Approximate age in seconds based on confirmation count."""
    return max(0, int(confirmations) * secs_per_block)


def _utxo_key(txid: str, vout: int) -> str:
    return f"{txid}:{vout}"


async def list_utxos_with_labels(
    db: AsyncSession,
    *,
    min_confs: int = 0,
    include_spent: bool = False,
    search: str = "",
) -> dict[str, Any]:
    """Return live UTXOs joined with the stored label rows.

    Shape:

    .. code-block:: python

       {
           "utxos": [
               {
                   "txid": "...",
                   "vout": 0,
                   "amount_sat": 1000,
                   "address": "bc1q...",
                   "address_type": "WITNESS_PUBKEY_HASH",
                   "confirmations": 12,
                   "age_seconds": 7200,
                   "label": "Ocean payout",
                   "label_source": "auto:receive",
                   "key": "<txid>:<vout>",
               }, ...
           ],
           "total_sats": 1234567,
       }

    A trailing ``utxos_total`` (count) is omitted; the caller can take
    ``len(utxos)`` directly.
    """
    raw, error = await lnd_service.list_unspent(min_confs=min_confs)
    if error:
        return {"error": error}

    raw_utxos: list[Utxo] = raw or []

    # Bulk-fetch labels for this set in a single query.
    keys = [(u["outpoint"]["txid_str"], u["outpoint"]["output_index"]) for u in raw_utxos]
    label_map: dict[tuple[str, int], UtxoLabel] = {}
    if keys:
        # Compose a single OR expression so we don't issue N queries.
        # SQLAlchemy 2.x: ``tuple_(...)`` IN works on PG but not SQLite,
        # so we emit a flat OR which both engines optimise.
        clauses = [and_(UtxoLabel.txid == txid, UtxoLabel.vout == vout) for (txid, vout) in keys]
        stmt = select(UtxoLabel).where(or_(*clauses))
        result = await db.execute(stmt)
        for row in result.scalars():
            label_map[(row.txid, row.vout)] = row

    needle = (search or "").strip().lower()
    out: list[dict[str, Any]] = []
    total = 0
    for u in raw_utxos:
        op = u["outpoint"]
        txid, vout = op["txid_str"], op["output_index"]
        lbl = label_map.get((txid, vout))
        label = lbl.label if lbl and lbl.label else ""
        source = lbl.source.value if lbl else None
        amt = int(u["amount_sat"])
        addr = u.get("address", "")
        if needle:
            haystack = (label + " " + addr).lower()
            if needle not in haystack:
                continue
        total += amt
        out.append(
            {
                "txid": txid,
                "vout": vout,
                "key": _utxo_key(txid, vout),
                "amount_sat": amt,
                "address": addr,
                "address_type": u.get("address_type", "UNKNOWN"),
                "confirmations": int(u.get("confirmations", 0)),
                "age_seconds": _utxo_age_seconds(int(u.get("confirmations", 0))),
                "label": label,
                "label_source": source,
            }
        )

    out.sort(key=lambda r: r["amount_sat"], reverse=True)
    return {"utxos": out, "total_sats": total}


# ─── Label mutation ──────────────────────────────────────────────────────


async def set_label(
    db: AsyncSession,
    txid: str,
    vout: int,
    label: str,
    *,
    source: UtxoLabelSource = UtxoLabelSource.USER,
) -> UtxoLabel:
    """Insert or update the label row for an outpoint.

    A user-supplied empty string clears the row outright (we don't
    keep zero-value user rows for live UTXOs — they'd just clutter
    the recently-spent fold-down).
    """
    txid = normalise_txid(txid)
    label = normalise_label(label)

    stmt = select(UtxoLabel).where(UtxoLabel.txid == txid, UtxoLabel.vout == int(vout))
    existing = (await db.execute(stmt)).scalars().first()

    if not label and source == UtxoLabelSource.USER:
        if existing:
            await db.delete(existing)
            await db.flush()
        # Return a transient sentinel — callers only use it for the
        # response payload.
        return UtxoLabel(txid=txid, vout=int(vout), label="", source=source)

    if existing:
        existing.label = label
        existing.source = source
        existing.updated_at = datetime.now(timezone.utc)
        await db.flush()
        return existing

    row = UtxoLabel(txid=txid, vout=int(vout), label=label, source=source)
    db.add(row)
    await db.flush()
    return row


async def clear_label(db: AsyncSession, txid: str, vout: int) -> None:
    """Delete a user label row outright. No-op for non-user sources."""
    txid = normalise_txid(txid)
    stmt = select(UtxoLabel).where(UtxoLabel.txid == txid, UtxoLabel.vout == int(vout))
    existing = (await db.execute(stmt)).scalars().first()
    if existing and existing.source == UtxoLabelSource.USER:
        await db.delete(existing)
        await db.flush()


# ─── Address purposes (auto:receive seeding) ────────────────────────────


async def record_address_purpose(db: AsyncSession, address: str, purpose: str) -> None:
    """Persist the user's purpose for a freshly-generated receive address.

    Re-generating the same address with a new purpose overwrites the
    previous (and resets ``consumed_at``).
    """
    address = (address or "").strip()
    purpose = normalise_label(purpose)
    if not address or not purpose:
        return
    stmt = select(AddressPurpose).where(AddressPurpose.address == address)
    existing = (await db.execute(stmt)).scalars().first()
    if existing:
        existing.purpose = purpose
        existing.consumed_at = None
    else:
        db.add(AddressPurpose(address=address, purpose=purpose))
    await db.flush()

    # Best-effort: subscribe to scripthash notifications so
    # incoming funds trigger a reconcile in seconds rather than
    # waiting for the 5-min poll. No-op when Electrum is absent.
    try:
        from app.services.utxo_subscriptions import receive_address_subscriber

        await receive_address_subscriber.subscribe(address)
    except Exception as exc:  # noqa: BLE001
        logger.debug("receive-address subscribe failed for %s: %s", address, exc)


# ─── Reconcile (spent_at + auto:receive seeding) ────────────────────────


async def reconcile(db: AsyncSession) -> dict[str, int]:
    """Sync the label store with LND's current ``ListUnspent``.

    1. For every label row whose outpoint is no longer reported as
       unspent and has no ``spent_at`` yet, stamp it.
    2. For every unspent UTXO at an address with an unconsumed
       ``AddressPurpose`` row, create an ``auto:receive`` label
       (unless one already exists for that outpoint).
    3. Soft-purge spent rows that are older than 30 days **and** were
       not user-edited. User edits and inherited labels stick around
       for the audit trail per the implementation plan.

    Returns counters useful for the audit log / debug endpoints.
    """
    now = datetime.now(timezone.utc)
    raw, error = await lnd_service.list_unspent(min_confs=0)
    if error:
        return {"error": 1, "spent_marked": 0, "auto_labelled": 0, "purged": 0}

    raw_utxos: list[Utxo] = raw or []
    live_keys: set[tuple[str, int]] = {
        (u["outpoint"]["txid_str"], int(u["outpoint"]["output_index"])) for u in raw_utxos
    }

    # 1. Mark spent.
    spent_marked = 0
    stmt = select(UtxoLabel).where(UtxoLabel.spent_at.is_(None))
    for row in (await db.execute(stmt)).scalars():
        if (row.txid, int(row.vout)) not in live_keys:
            row.spent_at = now
            spent_marked += 1

    # 2. Auto-label receives.
    auto_labelled = 0
    if raw_utxos:
        addrs = list({u.get("address", "") for u in raw_utxos if u.get("address")})
        if addrs:
            purpose_stmt = select(AddressPurpose).where(
                AddressPurpose.address.in_(addrs),
                AddressPurpose.consumed_at.is_(None),
            )
            purpose_map = {ap.address: ap for ap in (await db.execute(purpose_stmt)).scalars()}
            if purpose_map:
                # Pre-fetch existing label rows for the candidate keys.
                candidates = [
                    (u["outpoint"]["txid_str"], int(u["outpoint"]["output_index"]))
                    for u in raw_utxos
                    if u.get("address") in purpose_map
                ]
                existing_keys: set[tuple[str, int]] = set()
                if candidates:
                    clauses = [and_(UtxoLabel.txid == t, UtxoLabel.vout == v) for (t, v) in candidates]
                    res = await db.execute(select(UtxoLabel).where(or_(*clauses)))
                    existing_keys = {(r.txid, int(r.vout)) for r in res.scalars()}
                for u in raw_utxos:
                    addr = u.get("address", "")
                    purpose = purpose_map.get(addr)
                    if not purpose:
                        continue
                    txid = u["outpoint"]["txid_str"]
                    vout = int(u["outpoint"]["output_index"])
                    if (txid, vout) in existing_keys:
                        continue
                    db.add(
                        UtxoLabel(
                            txid=txid,
                            vout=vout,
                            label=purpose.purpose,
                            source=UtxoLabelSource.AUTO_RECEIVE,
                        )
                    )
                    purpose.consumed_at = now
                    auto_labelled += 1

    # 3. Soft-purge stale spent rows.
    cutoff = now - timedelta(days=30)
    purge_stmt = select(UtxoLabel).where(
        UtxoLabel.spent_at.is_not(None),
        UtxoLabel.spent_at < cutoff,
        UtxoLabel.source != UtxoLabelSource.USER,
    )
    purged = 0
    for row in (await db.execute(purge_stmt)).scalars():
        await db.delete(row)
        purged += 1

    await db.flush()
    return {
        "error": 0,
        "spent_marked": spent_marked,
        "auto_labelled": auto_labelled,
        "purged": purged,
    }


# ─── Recently-spent fold-down ───────────────────────────────────────────


async def list_recently_spent(db: AsyncSession, *, days: int = 30) -> list[dict[str, Any]]:
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    stmt = (
        select(UtxoLabel)
        .where(
            UtxoLabel.spent_at.is_not(None),
            UtxoLabel.spent_at >= cutoff,
        )
        .order_by(UtxoLabel.spent_at.desc())
        .limit(200)
    )
    out: list[dict[str, Any]] = []
    for row in (await db.execute(stmt)).scalars():
        out.append(
            {
                "txid": row.txid,
                "vout": row.vout,
                "key": _utxo_key(row.txid, row.vout),
                "label": row.label,
                "label_source": row.source.value,
                "spent_at": row.spent_at.isoformat() if row.spent_at else None,
                "spent_txid": row.spent_txid,
            }
        )
    return out


# ─── Inherit-on-spend ───────────────────────────────────────────────────


async def inherit_on_spend(
    db: AsyncSession,
    *,
    spent_outpoints: list[Outpoint],
    new_txid: str,
    change_vout: Optional[int] = None,
    consolidate: bool = False,
) -> None:
    """Carry labels from spent inputs onto a successor UTXO.

    Called by the send-onchain and consolidate routes after we have
    the broadcast txid back from LND.

    Behaviour:

    * **Consolidate** (``consolidate=True``): the single new output
      (``change_vout``, defaults to ``0``) gets a synthetic label
      ``"Consolidated: <n> inputs"`` with source ``inherited``. Each
      input row is stamped with ``spent_at`` and ``spent_txid``.
    * **Regular send**: if exactly one of the spent inputs had a
      non-empty label, the change output (when ``change_vout`` is
      supplied) inherits that label verbatim. Multiple labels would
      collide so we don't pick a winner; the user can edit afterward.
    """
    if not new_txid or not spent_outpoints:
        return
    new_txid = normalise_txid(new_txid)

    # Stamp inputs and collect their labels.
    parent_labels: list[str] = []
    for op in spent_outpoints:
        txid = normalise_txid(op["txid_str"])
        vout = int(op["output_index"])
        stmt = select(UtxoLabel).where(UtxoLabel.txid == txid, UtxoLabel.vout == vout)
        row = (await db.execute(stmt)).scalars().first()
        if row is None:
            continue
        row.spent_at = datetime.now(timezone.utc)
        row.spent_txid = new_txid
        if row.label:
            parent_labels.append(row.label)

    target_vout = 0 if change_vout is None else int(change_vout)

    if consolidate:
        n = len(spent_outpoints)
        synthesised = f"Consolidated: {n} input{'s' if n != 1 else ''}"
        await set_label(
            db,
            new_txid,
            target_vout,
            synthesised,
            source=UtxoLabelSource.INHERITED,
        )
        return

    if change_vout is None:
        return  # caller has no change to inherit onto
    if len(parent_labels) == 1:
        await set_label(
            db,
            new_txid,
            target_vout,
            parent_labels[0],
            source=UtxoLabelSource.INHERITED,
        )
