# SPDX-License-Identifier: MIT
"""Submarine lockup-address verification.

Before funding a submarine swap the wallet reconstructs the expected
P2TR lockup address from the operator-supplied swap tree + our refund
key and refuses unless it matches the address the operator returned —
otherwise a malicious operator could substitute an address it controls
and steal the funding. Two layers of test:

* wiring — ``create_submarine_swap`` refuses to persist a swap when the
  verifier rejects, and persists when it accepts (verifier mocked);
* correctness — the real Node verifier accepts a genuine boltz-core swap
  and rejects a substituted address (skipped if ``node`` is unavailable).
"""

from __future__ import annotations

import json
import shutil
import subprocess
from contextlib import asynccontextmanager
from pathlib import Path
from uuid import uuid4

import httpx
import pytest

from app.services.anonymize import boltz_egress
from app.services.anonymize.boltz_egress import (
    AnonymizeBoltzClient,
    verify_submarine_lockup_address,
)

_SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"
_NODE = shutil.which("node")
_HAS_BOLTZ_CORE = (_SCRIPTS / "node_modules" / "boltz-core").is_dir()
_node_required = pytest.mark.skipif(
    not (_NODE and _HAS_BOLTZ_CORE),
    reason="requires node + scripts/node_modules/boltz-core",
)


def _mock_client(monkeypatch, response_json: dict):
    @asynccontextmanager
    async def _factory(*, call_site, socks_host, socks_port, timeout_s=30.0):
        def _handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=response_json)

        transport = httpx.MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            yield client

    monkeypatch.setattr(boltz_egress, "get_anonymize_client", _factory)
    monkeypatch.setattr(boltz_egress, "_generate_keypair", lambda: ("11" * 32, "02" + "22" * 32))


_SUBMARINE_RESPONSE = {
    "id": "sub-1",
    "address": "bc1 plockup-addr",
    "swapTree": {"claimLeaf": {"version": 196, "output": "ab"}, "refundLeaf": {"version": 196, "output": "cd"}},
    "expectedAmount": 100000,
    "claimPublicKey": "03" + "bb" * 32,
    "timeoutBlockHeight": 800000,
}


@pytest.mark.asyncio
async def test_create_submarine_refuses_when_verifier_rejects(db_session, monkeypatch):
    _mock_client(monkeypatch, _SUBMARINE_RESPONSE)
    monkeypatch.setattr(
        boltz_egress,
        "verify_submarine_lockup_address",
        lambda **_: (False, "address_mismatch"),
    )
    client = AnonymizeBoltzClient(base_url="https://boltz.invalid/api", socks_host="127.0.0.1", socks_port=9051)
    swap, err = await client.create_submarine_swap(
        db_session, api_key_id=uuid4(), invoice="lnbc1xxx"
    )
    assert swap is None
    assert err is not None and "verification failed" in err


@pytest.mark.asyncio
async def test_create_submarine_persists_when_verifier_accepts(db_session, monkeypatch):
    _mock_client(monkeypatch, _SUBMARINE_RESPONSE)
    monkeypatch.setattr(
        boltz_egress,
        "verify_submarine_lockup_address",
        lambda **_: (True, "ok"),
    )
    client = AnonymizeBoltzClient(base_url="https://boltz.invalid/api", socks_host="127.0.0.1", socks_port=9051)
    swap, err = await client.create_submarine_swap(
        db_session, api_key_id=uuid4(), invoice="lnbc1xxx"
    )
    assert err is None
    assert swap is not None and swap.boltz_swap_id == "sub-1"


@pytest.mark.asyncio
async def test_create_submarine_refuses_when_response_missing_tree(db_session, monkeypatch):
    resp = dict(_SUBMARINE_RESPONSE)
    resp.pop("swapTree")
    _mock_client(monkeypatch, resp)
    client = AnonymizeBoltzClient(base_url="https://boltz.invalid/api", socks_host="127.0.0.1", socks_port=9051)
    swap, err = await client.create_submarine_swap(
        db_session, api_key_id=uuid4(), invoice="lnbc1xxx"
    )
    assert swap is None
    assert err is not None and "missing address/swapTree" in err


def _build_genuine_swap() -> dict:
    """Use boltz-core to build a real swap tree + its lockup address."""
    js = """
    const ecc=require('tiny-secp256k1');const {ECPairFactory}=require('ecpair');
    const bj=require('bitcoinjs-lib');const {initEccLib,payments,networks}=bj;
    const b=require('boltz-core');const crypto=require('crypto');
    initEccLib(ecc);const ECPair=ECPairFactory(ecc);
    (async()=>{const z=require('@vulpemventures/secp256k1-zkp');const secp=await(z.default||z)();
    const claim=ECPair.makeRandom(),refund=ECPair.makeRandom();
    const tree=b.swapTree(false,crypto.randomBytes(32),claim.publicKey,refund.publicKey,800000);
    const m=new b.Musig(secp,claim,crypto.randomBytes(32),[claim.publicKey,refund.publicKey]);
    const addr=payments.p2tr({pubkey:b.TaprootUtils.tweakMusig(m,tree.tree),network:networks.bitcoin}).address;
    console.log(JSON.stringify({tree:b.SwapTreeSerializer.serializeSwapTree(tree),
      refund:refund.publicKey.toString('hex'),claim:claim.publicKey.toString('hex'),addr}));})();
    """
    out = subprocess.run(["node", "-e", js], cwd=str(_SCRIPTS), capture_output=True, text=True, timeout=30)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout.strip())


@_node_required
def test_verifier_accepts_genuine_and_rejects_substituted_address():
    d = _build_genuine_swap()
    ok, reason = verify_submarine_lockup_address(
        swap_tree_json=d["tree"],
        refund_public_key_hex=d["refund"],
        lockup_address=d["addr"],
        network="bitcoin",
    )
    assert ok is True, reason

    ok2, reason2 = verify_submarine_lockup_address(
        swap_tree_json=d["tree"],
        refund_public_key_hex=d["refund"],
        lockup_address="bc1qattackeraddressxxxxxxxxxxxxxxxxxxxxxxxx",
        network="bitcoin",
    )
    assert ok2 is False
    assert reason2 == "address_mismatch"


@_node_required
def test_verifier_rejects_tree_without_our_refund_key():
    d = _build_genuine_swap()
    # Verify against a DIFFERENT refund key than the tree commits to.
    other = _build_genuine_swap()
    ok, reason = verify_submarine_lockup_address(
        swap_tree_json=d["tree"],
        refund_public_key_hex=other["refund"],
        lockup_address=d["addr"],
        network="bitcoin",
    )
    assert ok is False
    assert reason == "refund_leaf_mismatch"
