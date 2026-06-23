# SPDX-License-Identifier: MIT
"""One-shot diagnostic for a failed Braiins-Deposit submarine leg.

Usage (inside the api container, with venv active):

    python scripts/diagnose_braiins_submarine.py <braiins_session_id>

Resolves the linked submarine ``BoltzSwap`` row, prints what we
persisted on our side (status, error_message, status_history),
then re-queries Boltz's ``/swap/{id}`` endpoint and prints the full
JSON payload — which is where ``failureReason`` / ``failureDetails``
live for ``invoice.failedToPay`` swaps. We never persisted those
fields, so this is the only way to see them after the fact.

This script is read-only: it does not mutate session or swap state.
"""

from __future__ import annotations

import asyncio
import json
import sys
from uuid import UUID

from app.core.database import get_session_maker
from app.models.boltz_swap import BoltzSwap
from app.models.braiins_deposit_session import BraiinsDepositSession
from app.services.boltz_service import boltz_service


async def main(session_id_str: str) -> int:
    try:
        session_id = UUID(session_id_str)
    except ValueError:
        print(f"invalid session id: {session_id_str!r}", file=sys.stderr)
        return 2

    session_maker = get_session_maker()
    async with session_maker() as db:
        session = await db.get(BraiinsDepositSession, session_id)
        if session is None:
            print(f"no BraiinsDepositSession with id {session_id}", file=sys.stderr)
            return 3

        print("─── BraiinsDepositSession ───")
        print(f"  id:                       {session.id}")
        print(f"  status:                   {session.status}")
        print(f"  source_kind:              {session.source_kind}")
        print(f"  destination:              {session.destination_address}")
        print(f"  submarine_funding_txid:   {session.submarine_funding_txid}")
        print(f"  submarine_boltz_swap_id:  {session.submarine_boltz_swap_id}")
        print(f"  error_message:            {session.error_message}")

        if session.submarine_boltz_swap_id is None:
            print("\nno linked submarine swap row; nothing more to inspect.")
            return 0

        swap = await db.get(BoltzSwap, session.submarine_boltz_swap_id)
        if swap is None:
            print(
                f"\nlinked submarine BoltzSwap {session.submarine_boltz_swap_id} missing from DB",
                file=sys.stderr,
            )
            return 4

        print("\n─── Submarine BoltzSwap (DB) ───")
        print(f"  id:                       {swap.id}")
        print(f"  boltz_swap_id:            {swap.boltz_swap_id}")
        print(f"  status (internal):        {swap.status}")
        print(f"  boltz_status (last seen): {swap.boltz_status}")
        print(f"  invoice_amount_sats:      {swap.invoice_amount_sats}")
        print(f"  onchain_amount_sats:      {swap.onchain_amount_sats}")
        print(f"  error_message:            {swap.error_message}")
        print(f"  destination_address:      {swap.destination_address}")
        print(f"  timeout_block_height:     {getattr(swap, 'timeout_block_height', None)}")
        print("  status_history:")
        for entry in swap.status_history or []:
            print(f"    - {entry}")

        # Live re-query Boltz for the full payload.
        print("\n─── Boltz /swap/<id> (live) ───")
        status, data, err = await boltz_service.get_swap_status_from_boltz(swap.boltz_swap_id)
        if err:
            print(f"  ERROR querying Boltz: {err}")
            return 5
        print(f"  status: {status}")
        print("  full payload:")
        print(json.dumps(data, indent=2, default=str))

        # Highlight the failure-shape fields we'd want for diagnosis.
        if isinstance(data, dict):
            interesting = {
                k: data[k]
                for k in (
                    "failureReason",
                    "failureDetails",
                    "failure_reason",
                    "failure_details",
                    "error",
                    "reason",
                )
                if k in data
            }
            if interesting:
                print("\n  ── failure-shape fields ──")
                for k, v in interesting.items():
                    print(f"    {k}: {v}")
            else:
                print(
                    "\n  (no failureReason/failureDetails fields on the payload — "
                    "Boltz may have rotated them off; the swap entry might also "
                    "have been pruned)"
                )

    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(1)
    sys.exit(asyncio.run(main(sys.argv[1])))
