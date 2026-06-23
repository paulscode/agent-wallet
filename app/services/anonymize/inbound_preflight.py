# SPDX-License-Identifier: MIT
"""On-chain inbound pre-flight for anonymize session creation.

Mirrors the Braiins on-chain deposit inbound gate
(``braiins_deposit_service._inbound_preflight``). An on-chain-sourced
anonymize session's mandated first hop is a **submarine swap** (the
pipeline-normalization invariant in ``pipelines.py`` forces it), which
requires THIS node to **receive** the bin amount over Lightning from
the swap provider — i.e. Boltz must route a payment *inbound* to our
node. On a node with small/insufficient inbound channels that leg is
structurally un-completable: it locks funds on-chain first, then
refunds ~30 min later, burning miner fees and reconciliation budget for
nothing. Catch it at creation instead — before any funds move.

This is a purely **local** check: it reads our own node's channel
balances via ``lnd_service.inbound_capacity`` and never makes a
third-party request, so it does NOT touch the egress-isolation
invariant the anonymize Boltz/Liquid hops depend on
(``test_anonymize_boltz_egress``). The companion **Tier-2 routability
probe** from the Braiins feature is deliberately *omitted* here: it
fetches Boltz node pubkeys over the shared, non-isolated Boltz
transport, which would breach that invariant for a privacy session.

The caller maps a non-None ``refusal`` to the byte-pinned
``creation_unavailable`` (429) response so the reason never leaks into
the response shape; the terse reason string is for server-side logs
only. The ``warning`` is advisory (logged, never surfaced).
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Optional

from app.core.config import settings as _global_settings
from app.models.anonymize_session import AnonymizeSourceKind

if TYPE_CHECKING:
    from app.core.config import Settings
    from app.services.lnd_service import LNDService

logger = logging.getLogger(__name__)


# Source kinds whose mandated first hop is a submarine swap (on-chain →
# LN, Boltz pays our invoice = inbound). Matches the on-chain branch of
# the pipeline-normalization invariant in ``pipelines.py``.
_INBOUND_DEPENDENT_SOURCE_KINDS = frozenset(
    {
        AnonymizeSourceKind.ONCHAIN_SELF.value,
        AnonymizeSourceKind.EXT_ONCHAIN.value,
    }
)


def source_requires_inbound_preflight(source_kind: str) -> bool:
    """True for on-chain source kinds (submarine-funded → need inbound).

    LN sources (``lightning-self``/``ext-lightning``) don't submarine-
    swap at funding, so the inbound gate doesn't apply to them.
    """
    return source_kind in _INBOUND_DEPENDENT_SOURCE_KINDS


async def inbound_preflight(
    *,
    receive_sats: int,
    lnd: LNDService | None = None,
    settings_obj: Settings | None = None,
) -> tuple[Optional[str], Optional[str]]:
    """Check whether THIS node can plausibly RECEIVE ``receive_sats``
    over Lightning — the necessary condition for the submarine funding
    leg of an on-chain anonymize session (Boltz pays our invoice).

    Returns ``(refusal, warning)``:

    - ``refusal`` (str) → a terse server-side reason when total inbound
      can't cover the amount; the caller must refuse the session before
      any funds move (mapping it to the byte-pinned generic 429).
    - ``warning`` (str) → an advisory note when total inbound covers the
      amount but no single channel does (relies on the provider's MPP);
      non-blocking, logged only.

    Best-effort: returns ``(None, None)`` (allow) when disabled, on any
    LND error, or for a non-positive amount — a transient failure must
    never block a legitimate session.
    """
    cfg = settings_obj if settings_obj is not None else _global_settings
    if not getattr(cfg, "anonymize_inbound_preflight_enabled", True):
        return None, None
    if receive_sats <= 0:
        return None, None

    if lnd is None:
        from app.services.lnd_service import lnd_service

        lnd = lnd_service
    cap, cap_err = await lnd.inbound_capacity()
    if cap_err is not None or cap is None:
        logger.info("anonymize inbound pre-flight skipped (LND error): %s", cap_err)
        return None, None

    total_in = int(cap.get("total_receivable_sats", 0) or 0)
    largest_in = int(cap.get("largest_channel_receivable_sats", 0) or 0)
    # Small headroom over the bare amount — the provider pays the invoice
    # exactly, but channels need slack for the in-flight HTLC.
    margin = max(1000, receive_sats // 100)
    if total_in < receive_sats + margin:
        return (
            f"inbound_insufficient total={total_in} receive={receive_sats} margin={margin}",
            None,
        )
    if largest_in < receive_sats:
        return None, (f"single_channel_inbound={largest_in} < receive={receive_sats}; relies on MPP")
    return None, None


__all__ = ["inbound_preflight", "source_requires_inbound_preflight"]
