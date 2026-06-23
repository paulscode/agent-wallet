# SPDX-License-Identifier: MIT
"""End-to-end integration test for the Liquid round-trip hop.

Drives the full Liquid leg-1 + leg-2 flow against the
BoltzExchange/regtest harness:

* Mint an LN invoice via the harness's ``lnd-2`` node.
* Create a Boltz reverse swap (LN → L-BTC).
* Pay the LN invoice from ``lnd-1`` so Boltz publishes the L-BTC
  lockup.
* Observe Boltz's lockup landing via the wallet's Liquid backend.
* Run :func:`run_liquid_claim_subprocess` to cooperatively claim
  the lockup to the wallet's per-session CT address.
* Wait for the claim TX to confirm.
* Create a Boltz submarine swap (L-BTC → LN).
* Run :func:`run_liquid_lock_subprocess` to spend the wallet's
  L-BTC to Boltz's submarine lockup address.
* Wait for Boltz to settle the wallet's LN invoice.

This test is **expensive** — it spawns multiple Node subprocesses,
hits a live LND + electrs-liquid + Boltz operator, and waits on real
block confirmations. It's gated behind:

* The ``regtest_harness`` pytest marker.
* A reachability probe for ``127.0.0.1:9001`` (the Boltz operator).
* The env var ``ANONYMIZE_INTEGRATION_E2E=1`` so the test isn't run
  by default — operators flip it on during the integration-verify
  step that precedes
  ``ANONYMIZE_LIQUID_INTEGRATION_VERIFIED=true``.

What this test does NOT do:

* Cover the dispatcher's session lifecycle (status transitions, DB
  persistence). That's tested separately in
  ``tests/unit/test_anonymize_liquid_hop.py``; the lifecycle is the
  same regardless of which adapter implementation is plugged in.
* Cover Tor routing. The harness is loopback; the wallet's SOCKS
  layer is replaced with a plain HTTP client for the duration of
  this test.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import socket
import subprocess
import time
from typing import AsyncIterator
from urllib.parse import urlparse

import httpx
import pytest

from app.services.anonymize import http as anon_http
from app.services.anonymize import liquid_swap as _liquid_swap
from app.services.anonymize.liquid_address import LiquidNetwork
from app.services.anonymize.liquid_ct import (
    derive_slip77_master_blinding_key,
)
from app.services.anonymize.liquid_hop_adapters import build_liquid_hop_deps
from app.services.anonymize.liquid_swap import LiquidSwapClient

_HARNESS_API_URL = "http://127.0.0.1:9001"
_SCRIPTS_CONTAINER = "boltz-scripts"


def _harness_reachable() -> bool:
    parsed = urlparse(_HARNESS_API_URL)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or 80
    try:
        with socket.create_connection((host, port), timeout=0.5):
            return True
    except OSError:
        return False


def _docker_available() -> bool:
    try:
        out = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", _SCRIPTS_CONTAINER],
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (subprocess.SubprocessError, FileNotFoundError):
        return False
    return out.stdout.strip() == "true"


pytestmark = [
    pytest.mark.regtest_harness,
    pytest.mark.skipif(
        os.environ.get("ANONYMIZE_INTEGRATION_E2E") != "1",
        reason=(
            "set ANONYMIZE_INTEGRATION_E2E=1 to run the E2E Liquid integration test (operator-side validation only)"
        ),
    ),
    pytest.mark.skipif(
        not _harness_reachable(),
        reason=f"Boltz harness not reachable on {_HARNESS_API_URL}",
    ),
    pytest.mark.skipif(
        not _docker_available(),
        reason=f"docker container {_SCRIPTS_CONTAINER!r} not running",
    ),
]


def _docker_exec(*cmd: str, timeout: float = 120.0) -> str:
    """Run a command inside the harness's scripts container.

    Default timeout is 120s — sufficient for a first-payment-after-
    cold-start LN payment through the harness's multi-hop graph.
    """
    res = subprocess.run(
        ["docker", "exec", _SCRIPTS_CONTAINER, *cmd],
        check=True,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return res.stdout


def _elements_cli(*args: str, timeout: float = 30.0) -> str:
    """Invoke ``elements-cli`` against the harness's elementsd container.

    Two wallets are auto-loaded by the harness: ``regtest`` and
    ``client``. Multi-wallet servers require ``-rpcwallet`` for wallet-
    scoped calls (``getnewaddress``, ``sendtoaddress``, etc.) — we
    always target ``regtest`` since the harness funds it.
    """
    return _docker_exec(
        "elements-cli",
        "-chain=liquidregtest",
        "-rpcconnect=elementsd",
        "-rpcport=18884",
        "-rpcuser=regtest",
        "-rpcpassword=regtest",
        "-rpcwallet=regtest",
        *args,
        timeout=timeout,
    )


def _lncli(node: int, *args: str) -> dict:
    """Invoke ``lncli`` against one of the harness's LND nodes."""
    raw = _docker_exec(
        "lncli",
        "--network=regtest",
        f"--lnddir=/root/.lnd-{int(node)}",
        f"--rpcserver=lnd-{int(node)}:10009",
        *args,
    )
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"raw": raw.strip()}


@pytest.fixture(autouse=True)
def _open_gate(monkeypatch: pytest.MonkeyPatch):
    """Open the runtime integration gate for the duration of the test."""
    from app.core.config import settings

    monkeypatch.setattr(
        settings,
        "anonymize_liquid_integration_verified",
        True,
        raising=False,
    )


@pytest.fixture(autouse=True)
def _bypass_socks(monkeypatch: pytest.MonkeyPatch):
    """Replace ``get_anonymize_client`` with a plain loopback client."""

    @contextlib.asynccontextmanager
    async def fake_client(
        *,
        call_site: str,
        socks_host: str,
        socks_port: int,
        timeout_s: float = 30.0,
    ) -> AsyncIterator[httpx.AsyncClient]:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(connect=2.0, read=30.0, write=5.0, pool=2.0),
            follow_redirects=False,
        ) as client:
            yield client

    monkeypatch.setattr(anon_http, "get_anonymize_client", fake_client)
    monkeypatch.setattr(_liquid_swap, "get_anonymize_client", fake_client)
    yield


@pytest.fixture
def _harness_asset_id() -> bytes:
    """Read the harness's L-BTC asset id from elementsd."""
    raw = _elements_cli("getsidechaininfo")
    obj = json.loads(raw)
    return bytes.fromhex(obj["pegged_asset"])


@pytest.mark.asyncio
async def test_full_liquid_round_trip_against_live_harness(
    _harness_asset_id: bytes,
) -> None:
    """End-to-end Liquid round-trip: LN → L-BTC → LN.

    Drives the adapter factory directly instead of routing through the
    full dispatcher; the dispatcher's status machine is exercised by
    the unit tests in ``test_anonymize_liquid_hop.py``.
    """
    # ── Build the production adapters wired to the live harness ──
    backend = await _build_live_backend()
    master = derive_slip77_master_blinding_key(b"\x42" * 64)
    swap_client = LiquidSwapClient(base_url=_HARNESS_API_URL)

    # The session-id is opaque to the test; we just need a stable UUID.
    from uuid import uuid4

    sid = uuid4()
    blinding_seed_index = 42

    payment_procs: list[subprocess.Popen] = []

    async def _lnd_send_payment(*, payment_request, amount_sat):
        # Reverse-swap HTLCs settle only AFTER the wallet claims the
        # L-BTC lockup (revealing the preimage). ``payinvoice``
        # therefore blocks until end-of-round-trip if awaited. Fire it
        # as a background process; the HTLC lives in LND's state
        # machine regardless of whether the CLI client is connected.
        # Redirect stdout/stderr to /dev/null — we don't read them and
        # leaving them as PIPE leaks file descriptors at GC time
        # (raised as ``ResourceWarning`` by pytest).
        proc = subprocess.Popen(
            [
                "docker",
                "exec",
                _SCRIPTS_CONTAINER,
                "lncli",
                "--network=regtest",
                "--lnddir=/root/.lnd-1",
                "--rpcserver=lnd-1:10009",
                "payinvoice",
                "--force",
                payment_request,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        payment_procs.append(proc)
        # Give LND a moment to route the HTLC; a fast-fail (e.g., no
        # route) would surface within ~2s. With stdout/stderr redirected
        # to DEVNULL we can't read the error message, but the non-zero
        # exit alone is enough to abort.
        await asyncio.sleep(2.0)
        if proc.poll() is not None and proc.returncode != 0:
            return None, (f"lnd-1 payinvoice fast-failed (exit={proc.returncode})")
        return {"status": "in_flight"}, None

    async def _lnd_observe_invoice_settled(*, swap_id, session_id):
        # The wallet-minted invoice lives on lnd-2 (the "wallet" node).
        # We poll its lookup; settlement comes after Boltz claims the
        # wallet's L-BTC lockup.
        raise NotImplementedError(
            "wired via dispatcher in production; this E2E test handles settlement observation inline"
        )

    async def _lnd_create_invoice(*, amount_sat, memo):
        res = await asyncio.to_thread(
            _lncli,
            2,
            "addinvoice",
            "--amt",
            str(int(amount_sat)),
            "--memo",
            str(memo),
        )
        return {
            "bolt11": res["payment_request"],
            "payment_hash": res["r_hash"],
        }, None

    swap_state: dict = {}
    deps = build_liquid_hop_deps(
        backend=backend,
        swap_client=swap_client,
        lnd_send_payment=_lnd_send_payment,
        lnd_observe_invoice_settled=_lnd_observe_invoice_settled,
        lnd_create_invoice=_lnd_create_invoice,
        master_blinding_key=master,
        expected_asset_id=_harness_asset_id,
        network=LiquidNetwork.REGTEST,
        swap_state=swap_state,
    )

    # ── Leg 1: LN → L-BTC ──
    create_out, err = await deps.boltz_create_ln_to_lbtc_swap(
        amount_sat=250_000,
        session_id=sid,
        blinding_seed_index=blinding_seed_index,
    )
    assert err is None, f"create_ln_to_lbtc failed: {err}"
    assert create_out and create_out["swap_id"]
    swap_id = create_out["swap_id"]
    invoice = create_out["invoice"]

    pay_res, pay_err = await _lnd_send_payment(
        payment_request=invoice,
        amount_sat=250_000,
    )
    assert pay_err is None, f"LN payment failed: {pay_err}"

    # Wait for the lockup to land. Boltz publishes the L-BTC lockup
    # ~immediately after the LN HTLC lands; allow a generous timeout.
    utxo_str = None
    for _ in range(60):
        utxo_str, obs_err = await deps.liquid_observe_credit(
            swap_id=swap_id,
            session_id=sid,
        )
        if utxo_str:
            break
        assert obs_err is None, f"observe_credit failed: {obs_err}"
        await asyncio.sleep(2.0)
    assert utxo_str, "Boltz lockup did not land within 120s"

    # Cooperative MuSig2 claim → wallet CT address.
    claim_txid, claim_err = await deps.liquid_claim_lockup(
        swap_id=swap_id,
        session_id=sid,
    )
    assert claim_err is None, f"claim failed: {claim_err}"
    assert claim_txid

    # Mine a few blocks + wait for confirmation.
    _elements_cli(
        "generatetoaddress",
        "2",
        _elements_cli("getnewaddress").strip(),
    )
    confirmed = False
    for _ in range(30):
        confirmed, conf_err = await deps.liquid_observe_wallet_credit(
            swap_id=swap_id,
            session_id=sid,
        )
        if confirmed:
            break
        assert conf_err is None, f"observe_wallet_credit failed: {conf_err}"
        await asyncio.sleep(2.0)
    assert confirmed, "wallet claim did not confirm within 60s"

    # ── Leg 2: L-BTC → LN ──
    lbtc_to_ln_out, lbtc_err = await deps.boltz_create_lbtc_to_ln_swap(
        lbtc_utxo=utxo_str,
        amount_sat=200_000,
        session_id=sid,
    )
    assert lbtc_err is None, f"create_lbtc_to_ln failed: {lbtc_err}"
    assert lbtc_to_ln_out and lbtc_to_ln_out["swap_id"]
    submarine_swap_id = lbtc_to_ln_out["swap_id"]

    lock_txid, lock_err = await deps.liquid_lock_for_submarine(
        swap_id=submarine_swap_id,
        session_id=sid,
    )
    assert lock_err is None, f"lock failed: {lock_err}"
    assert lock_txid

    # Mine + wait for the wallet's LN invoice to settle.
    _elements_cli(
        "generatetoaddress",
        "2",
        _elements_cli("getnewaddress").strip(),
    )

    # Inline LN settlement observer (independent of the dispatcher's
    # wiring). Looks up the wallet-minted invoice by payment hash on
    # lnd-2.
    leg2 = swap_state[submarine_swap_id]
    payment_hash = leg2["payment_hash_hex"]
    settled = False
    deadline = time.time() + 120.0
    while time.time() < deadline:
        inv = await asyncio.to_thread(
            _lncli,
            2,
            "lookupinvoice",
            payment_hash,
        )
        if inv.get("settled") is True or inv.get("state") == "SETTLED":
            settled = True
            break
        await asyncio.sleep(2.0)

    # Reap the background payinvoice subprocess(es) — they should
    # have settled now that the wallet completed the round-trip.
    # ``communicate`` drains + closes stdout/stderr pipes so the
    # subprocess.Popen finalizer doesn't raise ResourceWarning at GC.
    for proc in payment_procs:
        try:
            proc.communicate(timeout=5.0)
        except subprocess.TimeoutExpired:
            proc.terminate()
            try:
                proc.communicate(timeout=2.0)
            except subprocess.TimeoutExpired:
                proc.kill()
                try:
                    proc.communicate(timeout=2.0)
                except subprocess.TimeoutExpired:
                    pass

    assert settled, "LN invoice did not settle within 120s"


async def _build_live_backend():
    """Build a Liquid backend pointed at the harness's electrs-liquid.

    Returns an :class:`ElectrumLiquidBackend` over a started
    ``ElectrumClient`` — the client maintains its own asyncio loop and
    must be ``start()``'d before any RPC, otherwise calls fail with
    "electrum: not connected".
    """
    from app.services.anonymize.liquid_backend import ElectrumLiquidBackend
    from app.services.chain.electrum import ElectrumClient

    # The harness exposes electrs-liquid on 19002 (Electrum TCP).
    client = ElectrumClient("tcp://127.0.0.1:19002")
    await client.start()
    return ElectrumLiquidBackend(client)
