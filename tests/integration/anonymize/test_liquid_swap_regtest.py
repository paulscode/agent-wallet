# SPDX-License-Identifier: MIT
"""Live-regtest integration test for the Liquid swap HTTP client.

Drives :class:`LiquidSwapClient` against the BoltzExchange/regtest
harness (https://github.com/BoltzExchange/regtest) running locally.

Skipped when the harness is not reachable. Operators flip
``ANONYMIZE_LIQUID_INTEGRATION_VERIFIED=true`` only after this test
passes in their environment.

What this verifies:

* The body ``LiquidSwapClient.create_reverse_swap_to_lbtc()`` POSTs
  to ``/v2/swap/reverse`` is accepted by a live Boltz operator and
  the response parses into :class:`LiquidReverseSwap` with all
  required fields populated.
* The companion submarine create — once a throwaway invoice is
  minted — is accepted on ``/v2/swap/submarine`` and parses into
  :class:`LiquidSubmarineSwap`.

What this does **not** do (deferred to manual operator runs):

* Pay the LN invoice via LND.
* Wait for the L-BTC lockup to confirm.
* Run the cooperative MuSig2 claim subprocess.
* Broadcast the resulting Liquid claim transaction.

Each of those needs an LND/CLN wallet wired into the regtest LSP
graph; the value of CI here is the wire-shape lock against the
real backend.
"""

from __future__ import annotations

import contextlib
import hashlib
import secrets
import socket
from typing import AsyncIterator
from urllib.parse import urlparse

import httpx
import pytest
from coincurve import PrivateKey

from app.services.anonymize import http as anon_http
from app.services.anonymize.liquid_swap import (
    LiquidSwapClient,
    generate_preimage_and_hash,
    generate_swap_keypair,
)

_HARNESS_API_URL = "http://127.0.0.1:9001"


def _harness_reachable() -> bool:
    parsed = urlparse(_HARNESS_API_URL)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or 80
    try:
        with socket.create_connection((host, port), timeout=0.5):
            return True
    except OSError:
        return False


pytestmark = [
    pytest.mark.regtest_harness,
    pytest.mark.skipif(
        not _harness_reachable(),
        reason=(f"BoltzExchange/regtest harness not reachable on {_HARNESS_API_URL}; skip the integration check"),
    ),
]


@pytest.fixture(autouse=True)
def _bypass_socks(monkeypatch: pytest.MonkeyPatch):
    """Replace ``get_anonymize_client`` with a plain loopback client.

    The harness exposes the Boltz HTTP API directly on
    ``127.0.0.1:9001``; routing through Tor's ``liquid`` listener
    isn't required for a wire-shape check. The replacement preserves
    the async-context-manager protocol so :class:`LiquidSwapClient`
    sees the substitute as a drop-in.
    """

    @contextlib.asynccontextmanager
    async def fake_client(
        *,
        call_site: str,
        socks_host: str,
        socks_port: int,
        timeout_s: float = 30.0,
    ) -> AsyncIterator[httpx.AsyncClient]:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(connect=2.0, read=15.0, write=5.0, pool=2.0),
            follow_redirects=False,
        ) as client:
            yield client

    monkeypatch.setattr(anon_http, "get_anonymize_client", fake_client)
    # The swap-client module captured the symbol at import time.
    from app.services.anonymize import liquid_swap as _ls

    monkeypatch.setattr(_ls, "get_anonymize_client", fake_client)
    yield


def _make_client() -> LiquidSwapClient:
    return LiquidSwapClient(base_url=_HARNESS_API_URL)


@pytest.mark.asyncio
async def test_create_reverse_swap_to_lbtc_against_live_harness() -> None:
    """A real ``POST /v2/swap/reverse`` round-trip parses correctly."""
    client = _make_client()

    _, preimage_hash_hex = generate_preimage_and_hash()
    _, claim_pub_hex = generate_swap_keypair()

    swap, err = await client.create_reverse_swap_to_lbtc(
        invoice_amount_sat=250_000,
        preimage_hash_hex=preimage_hash_hex,
        claim_public_key_hex=claim_pub_hex,
    )
    assert err is None, f"reverse swap create failed: {err}"
    assert swap is not None

    assert swap.id
    assert swap.invoice.startswith("lnbcrt")
    # The regtest harness's Liquid HRP is ``el`` (confidential) /
    # ``ert`` (unconfidential).
    assert swap.lockup_address.startswith(("el1", "ert1", "lq1"))
    assert len(bytes.fromhex(swap.blinding_key_hex)) == 32
    assert len(bytes.fromhex(swap.refund_public_key_hex)) == 33
    assert swap.timeout_block_height > 0
    assert swap.onchain_amount_sat > 0
    assert swap.swap_tree.claim_leaf.output
    assert swap.swap_tree.refund_leaf.output


@pytest.mark.asyncio
async def test_create_submarine_swap_from_lbtc_against_live_harness() -> None:
    """A real ``POST /v2/swap/submarine`` round-trip parses correctly.

    Mints a throwaway invoice via the harness's helper endpoint so
    the operator has a well-formed BOLT11 to anchor the swap to.
    Skipped if the helper isn't exposed by this harness build.
    """
    timeout = httpx.Timeout(connect=2.0, read=15.0, write=5.0, pool=2.0)
    invoice: str | None = None
    async with httpx.AsyncClient(
        base_url=_HARNESS_API_URL,
        timeout=timeout,
    ) as raw:
        try:
            preimage = secrets.token_bytes(32)
            payment_hash = hashlib.sha256(preimage).hexdigest()
            resp = await raw.post(
                "/v2/lightning/BTC/bolt11",
                json={
                    "amount": 100_000,
                    "description": "anonymize-regtest-smoke",
                    "preimageHash": payment_hash,
                },
            )
            if resp.status_code in (404, 405):
                pytest.skip(
                    "harness does not expose /v2/lightning/BTC/bolt11; "
                    "submarine smoke needs an out-of-band invoice mint"
                )
            resp.raise_for_status()
            data = resp.json()
            invoice = data.get("invoice") or data.get("bolt11")
        except httpx.HTTPStatusError as exc:
            pytest.skip(f"harness invoice mint failed ({exc.response.status_code}); submarine smoke deferred")

    if not invoice:
        pytest.skip("harness returned no usable invoice for submarine smoke")

    client = _make_client()
    refund_priv = PrivateKey(secrets.token_bytes(32))
    refund_pub_hex = refund_priv.public_key.format(compressed=True).hex()

    swap, err = await client.create_submarine_swap_from_lbtc(
        invoice=invoice,
        refund_public_key_hex=refund_pub_hex,
    )
    assert err is None, f"submarine swap create failed: {err}"
    assert swap is not None
    assert swap.id
    assert swap.address.startswith(("el1", "ert1", "lq1"))
    assert len(bytes.fromhex(swap.blinding_key_hex)) == 32
    assert len(bytes.fromhex(swap.claim_public_key_hex)) == 33
    assert swap.timeout_block_height > 0
    assert swap.expected_amount_sat > 0
    assert swap.swap_tree.claim_leaf.output
    assert swap.swap_tree.refund_leaf.output
