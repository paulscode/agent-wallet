# SPDX-License-Identifier: MIT
"""One-shot cooperative-refund recovery for stuck Braiins-Deposit
submarine sessions.

Usage (inside the API container):
    python scripts/recover_braiins_submarine.py <session-uuid>

Mints a fresh wallet P2TR address, asks Boltz to cooperatively
refund the locked HTLC, and projects the resulting refund txid
onto the session + ``BoltzSwap`` rows. Idempotent against an
already-REFUNDED swap.

Read-only against everything except the session/swap rows being
recovered. Errors are surfaced to stdout with non-zero exit.
"""

from __future__ import annotations

import asyncio
import sys
from uuid import UUID


async def _run(session_id: UUID) -> int:
    # Lazy import so ``python scripts/recover_braiins_submarine.py --help``
    # doesn't pay the full app-startup cost.
    from app.core.database import get_session_maker
    from app.services.braiins_deposit_service import braiins_deposit_service

    async with get_session_maker()() as db:
        refund_txid, err = await braiins_deposit_service.recover_submarine_refund(db, session_id)
    if refund_txid is None:
        print(f"FAILED: {err}", file=sys.stderr)
        return 1
    print(f"OK refund_txid={refund_txid}")
    return 0


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    try:
        session_id = UUID(argv[1])
    except ValueError as exc:
        print(f"invalid session-uuid: {exc}", file=sys.stderr)
        return 2
    return asyncio.run(_run(session_id))


if __name__ == "__main__":
    sys.exit(main(sys.argv))
