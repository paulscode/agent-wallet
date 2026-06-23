#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""End-to-end smoke for the J1 offer-less invreq responder.

Uses the regtest harness at ``/mnt/Black/regtest`` (cln1, cln2,
bolt12-gateway) and exercises the responder *without* booting the
full FastAPI wallet — we plug ``make_invreq_responder()`` directly
into a ``Bolt12Service`` instance pointed at the regtest gateway.

Pre-reqs:
  1. Regtest stack running: ``cd /mnt/Black/regtest && make up``.
  2. Channels open (cln2 → cln1 → lnd1) per the harness Makefile.
  3. ``BOLT12_ACCEPT_OFFERLESS_INVREQS=true`` in the environment
     this script inherits.
  4. A reachable Postgres (or sqlite) — the script uses
     ``settings.database_url`` and writes one Bolt12InvoiceRequest +
     one Bolt12Invoice row.

What it does:
  * Connects the gateway to cln1 + cln2 (idempotent ``ConnectPeer``).
  * Runs the wallet's BOLT 12 runtime + responder.
  * Calls ``lightning-cli -F createinvoicerequest`` on cln2 to mint
    a real, signed offer-less invreq targeting the gateway's node id
    and routes it via ``sendonionmessage`` to the gateway.
  * Waits for the responder to mint + reply with a BOLT 12 invoice.
  * Asserts a ``Bolt12Invoice`` row exists with the expected amount
    and ``offer_id IS NULL``.
  * Optionally: pays the inbound BOLT-11 minted by LND (the responder
    used ``add_blinded_invoice``) to confirm settlement.

Run with::

    BOLT12_ENABLED=true \\
    BOLT12_GATEWAY_GRPC=127.0.0.1:50061 \\
    BOLT12_ACCEPT_OFFERLESS_INVREQS=true \\
    DATABASE_URL=postgresql+asyncpg://… \\
    python scripts/regtest_offerless_invreq_smoke.py
"""

from __future__ import annotations

import asyncio
import json
import logging
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from sqlalchemy import select  # noqa: E402

from app.core.config import settings  # noqa: E402
from app.core.database import get_db_context  # noqa: E402
from app.models.bolt12_invoice import (  # noqa: E402
    Bolt12Direction,
    Bolt12Invoice,
    Bolt12InvoiceRequest,
    Bolt12InvoiceStatus,
)
from app.services.bolt12.runtime import (  # noqa: E402
    get_bolt12_service,
    start_bolt12_runtime,
    stop_bolt12_runtime,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("smoke")

# Regtest topology (matches /mnt/Black/regtest/docker-compose.yml).
CLN1_PUBKEY = "030f0e9898d7716db28145a76e03389fe882c3d6a7e94d50ce5d8baaf760f047ba"
CLN2_PUBKEY = "0355ed7d40f27591172a04710992ab332f76c094c91aa9b1750d5fc5c8075ed8ed"
CLN1_HOST = "cln1:9735"
CLN2_HOST = "cln2:9735"

AMOUNT_MSAT = 5_000_000  # 5000 sats — well within regtest channel capacity


def cln2(args: list[str]) -> dict:
    """Run a lightning-cli command on cln2 and return parsed JSON."""
    cmd = [
        "docker",
        "compose",
        "-f",
        "/mnt/Black/regtest/docker-compose.yml",
        "exec",
        "-T",
        "cln2",
        "lightning-cli",
        "--network=regtest",
    ] + args
    log.info("cln2 $ %s", " ".join(args))
    out = subprocess.check_output(cmd, text=True)
    return json.loads(out) if out.strip() else {}


async def main() -> int:
    if not settings.bolt12_enabled:
        log.error("BOLT12_ENABLED is false — set BOLT12_ENABLED=true and retry.")
        return 1
    if not settings.bolt12_accept_offerless_invreqs:
        log.error("BOLT12_ACCEPT_OFFERLESS_INVREQS is false — set it true and retry.")
        return 1

    log.info("Starting BOLT 12 runtime against %s", settings.bolt12_gateway_grpc)
    await start_bolt12_runtime()
    service = get_bolt12_service()
    gw = service._gateway  # noqa: SLF001 — smoke-only

    # Make sure the gateway can reach both CLN nodes for blinded
    # reply-path construction.
    log.info("Connecting gateway → cln1, cln2")
    await gw.connect_peer(node_id=bytes.fromhex(CLN1_PUBKEY), address=CLN1_HOST)
    await gw.connect_peer(node_id=bytes.fromhex(CLN2_PUBKEY), address=CLN2_HOST)

    ident = await gw.get_identity()
    gateway_node_id = ident.node_id.hex()
    log.info("Gateway node_id=%s peers=%d", gateway_node_id, ident.connected_peers)

    # cln2 needs a route towards the gateway's introduction-node
    # candidate (cln1 in our topology) to deliver the invreq onion.
    log.info("Asking cln2 to peer with cln1 directly so onion msgs route through it")
    try:
        cln2(["connect", f"{CLN1_PUBKEY}@cln1:9735"])
    except subprocess.CalledProcessError as exc:
        log.warning("cln2 connect → cln1 failed (may already be peered): %s", exc)

    # Build a real, signed offer-less invreq on cln2 targeting the
    # gateway. CLN's ``createinvoicerequest`` takes a JSON
    # invoice_request_offer with offer_amount_msat + offer_node_id
    # zero/missing → produces an offer-less invreq when no offer is
    # quoted. Some CLN versions expose this only via the
    # ``invoicerequest`` plugin command — adapt as needed.
    #
    # Easiest path: cln2 mints an invreq for an *empty* offer
    # constructed by the gateway's pubkey. That covers refund-style
    # invreqs and direct payments.
    log.info("Building offer-less invreq on cln2 amount=%d msat", AMOUNT_MSAT)
    try:
        # Some CLN builds expose `createinvoicerequest`. Others ship
        # only `fetchinvoice` (which requires an offer). The exact
        # command may need patching depending on your build.
        out = cln2(
            [
                "createinvoicerequest",
                "amount_msat=" + str(AMOUNT_MSAT),
                "description=smoke",
                f"recipient_node_id={gateway_node_id}",
            ]
        )
        invreq_blob = out.get("invreq") or out.get("bolt12")
    except subprocess.CalledProcessError:
        log.exception(
            "cln2 createinvoicerequest failed — your CLN may not support this command. "
            "Adapt to your build: any tool that produces a signed BOLT-12 invreq with "
            "no offer_issuer_id and routes it via sendonionmessage to the gateway works."
        )
        await stop_bolt12_runtime()
        return 2

    log.info("Got invreq from cln2 (%d chars). Sending via onion message…", len(invreq_blob))
    # cln2's `sendonionmessage` takes a hop list ending at the
    # gateway plus a TLV payload. The gateway-side responder picks
    # up TLV-64 (invreq) and replies along the embedded reply path.
    cln2(
        [
            "sendonionmessage",
            f'hops=[{{"id": "{gateway_node_id}", "tlvs": "{invreq_blob}"}}]',
        ]
    )

    # Wait for the responder to mint + the reply path to deliver.
    log.info("Waiting up to 30s for the inbound row to appear in DB…")
    for i in range(30):
        async with get_db_context() as db:
            row = (
                (
                    await db.execute(
                        select(Bolt12Invoice)
                        .where(
                            Bolt12Invoice.direction == Bolt12Direction.INBOUND,
                            Bolt12Invoice.amount_msat == AMOUNT_MSAT,
                            Bolt12Invoice.status == Bolt12InvoiceStatus.OPEN,
                        )
                        .order_by(Bolt12Invoice.id.desc())
                    )
                )
                .scalars()
                .first()
            )
        if row is not None:
            async with get_db_context() as db:
                ireq = (
                    await db.execute(
                        select(Bolt12InvoiceRequest).where(Bolt12InvoiceRequest.id == row.invoice_request_id)
                    )
                ).scalar_one()
            log.info(
                "✅ Persisted: invoice_id=%s payment_hash=%s offer_id=%s",
                row.id,
                row.payment_hash_hex,
                ireq.offer_id,
            )
            assert ireq.offer_id is None, "expected offer-less row"
            await stop_bolt12_runtime()
            return 0
        await asyncio.sleep(1)

    log.error("❌ Timed out waiting for inbound BOLT 12 invoice row.")
    await stop_bolt12_runtime()
    return 3


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
