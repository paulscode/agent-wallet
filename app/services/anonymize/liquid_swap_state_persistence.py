# SPDX-License-Identifier: MIT
"""Persist + restore the Liquid hop's per-swap state across restarts.

The Liquid hop dispatcher maintains an in-process ``swap_state``
dict keyed by Boltz swap id. The entries carry:

* Boltz-supplied data (re-fetchable via ``GET /v2/swap/{id}``).
* **Wallet-generated secrets** (preimage, claim private key) that
  are NOT re-derivable.
* Cached cleartext fields (the wallet's claimed UTXO + blinding
  factors) used by the leg-2 lock step.

A wallet restart between the leg-1 LN-payment broadcast and the
leg-1 claim broadcast would lose the wallet-generated secrets if
they live only in process memory — the L-BTC would sit at Boltz's
lockup forever (the refund path is gated by ``timeoutBlockHeight``
and not automated). This module persists the swap_state map for a
session into ``pipeline_json["liquid_swap_state_enc"]`` (Fernet-
wrapped) so a fresh process can hydrate the cache and resume.

The persistence scope is **per session**: each session's
swap_state entries (one for leg-1, one for leg-2) live inside that
session's pipeline_json. The dispatcher's process-wide swap_state
dict is reconstructed on demand from the session row whenever the
hop body ticks against an empty cache.
"""

from __future__ import annotations

import json
import logging
from typing import Any
from uuid import UUID

from app.core.encryption import decrypt_field, encrypt_field

from .metadata import ANONYMIZE_LOGGER_NAME

logger = logging.getLogger(ANONYMIZE_LOGGER_NAME)

_PIPELINE_JSON_KEY = "liquid_swap_state_enc"


def _entries_for_session(
    swap_state: dict[str, dict[str, Any]],
    session_id: UUID,
) -> dict[str, dict[str, Any]]:
    """Filter the process-wide swap_state map to one session.

    Each entry carries its session id (the create-adapter stashes
    ``"session_id": str(uuid)``); this helper picks the entries that
    belong to ``session_id``.
    """
    target = str(session_id)
    return {
        swap_id: dict(entry) for swap_id, entry in swap_state.items() if str(entry.get("session_id") or "") == target
    }


def persist_session_swap_state(
    session: Any,
    swap_state: dict[str, dict[str, Any]],
) -> None:
    """Encrypt + persist the session's swap_state entries on the row.

    Idempotent: writing the same state twice produces no observable
    change beyond the (different) Fernet ciphertext. The encryption
    layer ensures wallet-generated secrets (preimage / claim privkey)
    are never readable from a DB snapshot.

    Sets ``session.pipeline_json[_PIPELINE_JSON_KEY]`` to the urlsafe-
    base64 Fernet token (utf-8 string). The hop body's outer
    transaction is responsible for committing the row.
    """
    entries = _entries_for_session(swap_state, session.id)
    if not entries:
        # Nothing to persist; leave any prior blob in place rather
        # than overwriting it (defends against a transient cache miss
        # silently dropping the persisted state).
        return
    blob = json.dumps(entries, sort_keys=True, separators=(",", ":"))
    token = encrypt_field(blob)
    pj = dict(session.pipeline_json or {})
    pj[_PIPELINE_JSON_KEY] = token
    session.pipeline_json = pj


def restore_session_swap_state(
    session: Any,
    swap_state: dict[str, dict[str, Any]],
) -> bool:
    """Hydrate ``swap_state`` with the session's persisted entries.

    Returns ``True`` when at least one entry was restored, ``False``
    when there's nothing to restore (no persisted blob OR the cache
    already has the session's entries).

    Decryption failures are logged + treated as "no persisted state"
    — the hop body's bounded retry will route the session to
    reconciliation rather than blocking forever on a corrupted blob.
    """
    pj = session.pipeline_json or {}
    token = pj.get(_PIPELINE_JSON_KEY)
    if not token:
        return False
    # Fast-path: cache already has the session's entries.
    if _entries_for_session(swap_state, session.id):
        return False
    try:
        plaintext = decrypt_field(str(token))
        entries = json.loads(plaintext)
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "liquid_swap_state_enc decrypt/parse failed for session=%s: %s",
            session.id,
            exc,
        )
        return False
    if not isinstance(entries, dict):
        return False
    restored = 0
    for swap_id, entry in entries.items():
        if not isinstance(swap_id, str) or not isinstance(entry, dict):
            continue
        # Defensive: only restore if the cache doesn't already have a
        # newer in-process entry (don't overwrite live state).
        if swap_id in swap_state:
            continue
        swap_state[swap_id] = dict(entry)
        restored += 1
    return restored > 0


__all__ = [
    "persist_session_swap_state",
    "restore_session_swap_state",
]
