# SPDX-License-Identifier: MIT
"""Liquid hop-deps factory.

Wires the real adapters end-to-end using:

* ``MockLiquidBackend`` for the chain backend
* ``httpx.MockTransport`` for the Boltz REST API (reverse + submarine
  endpoints, NOT the obsolete chain-swap endpoint)
* Caller-supplied async stubs for the LN-side (send_payment,
  observe_invoice_settled, create_invoice)

Covers the runtime-gate refusal path
(``ANONYMIZE_LIQUID_INTEGRATION_VERIFIED=false``) plus the happy
paths when the gate is open.
"""

from __future__ import annotations

import secrets
from contextlib import asynccontextmanager
from dataclasses import dataclass
from uuid import uuid4

import httpx
import pytest
import wallycore as _wally

from app.core.config import settings
from app.services.anonymize import liquid_swap
from app.services.anonymize.hops.liquid import LiquidHopDeps
from app.services.anonymize.liquid_address import (
    LiquidNetwork,
    encode_confidential_segwit,
)
from app.services.anonymize.liquid_backend import LiquidUtxo, MockLiquidBackend
from app.services.anonymize.liquid_ct import (
    LBTC_ASSET_ID_MAINNET,
    derive_script_blinding_privkey,
    derive_script_blinding_pubkey,
    derive_slip77_master_blinding_key,
)
from app.services.anonymize.liquid_hop_adapters import build_liquid_hop_deps
from app.services.anonymize.liquid_swap import LiquidSwapClient
from tests._bolt11_fixtures import BIND_INVOICE, BIND_PAYMENT_HASH

_ASSET = LBTC_ASSET_ID_MAINNET
_LOCKUP_SCRIPT = b"\x00\x14" + b"\x11" * 20


@pytest.fixture(autouse=True)
def _open_integration_gate(monkeypatch):
    """The runtime gate defaults to False; tests that exercise the
    real adapter paths need it open. Individual tests that exercise
    the closed path override this fixture's effect."""
    monkeypatch.setattr(
        settings,
        "anonymize_liquid_integration_verified",
        True,
    )
    # Reverse-swap creation now binds the returned invoice to our preimage
    # hash (security C1). _reverse_response() returns BIND_INVOICE, so make
    # the adapter's generated preimage hash match it.
    monkeypatch.setattr(
        "app.services.anonymize.liquid_hop_adapters.generate_preimage_and_hash",
        lambda: ("ab" * 32, BIND_PAYMENT_HASH),
    )
    # The Liquid lockup verifier reconstructs the taproot output from a
    # real swap tree via ``boltz-core``; these flow tests use synthetic
    # swap-tree fixtures, so the cryptographic verifier is stubbed to
    # accept. Its own correctness is covered by the round-trip test in
    # ``tests/unit/test_anonymize_liquid_lockup_verify.py``.
    monkeypatch.setattr(
        "app.services.anonymize.liquid_hop_adapters.verify_liquid_lockup_address",
        lambda **_kw: (True, "ok"),
    )


@dataclass
class _ClientCall:
    call_site: str
    requests: list[httpx.Request]


def _install_mock_swap_client(monkeypatch, handler) -> list[_ClientCall]:
    captured: list[_ClientCall] = []

    @asynccontextmanager
    async def _factory(*, call_site, socks_host, socks_port, timeout_s=30.0):
        call = _ClientCall(call_site=call_site, requests=[])
        captured.append(call)

        def _wrapped(request: httpx.Request) -> httpx.Response:
            call.requests.append(request)
            return handler(request)

        transport = httpx.MockTransport(_wrapped)
        async with httpx.AsyncClient(transport=transport) as client:
            yield client

    monkeypatch.setattr(liquid_swap, "get_anonymize_client", _factory)
    return captured


def _make_deps(
    monkeypatch,
    handler,
    *,
    lnd_send=None,
    lnd_observe=None,
    lnd_create_invoice=None,
):
    """Build a fully-wired deps + return the (deps, state, backend, master)."""
    _install_mock_swap_client(monkeypatch, handler)
    backend = MockLiquidBackend()
    swap_client = LiquidSwapClient(
        base_url="https://boltz.invalid",
        socks_port=9052,
    )

    async def _default_lnd_send(*, payment_request, amount_sat):
        return {"status": "succeeded"}, None

    async def _default_lnd_observe(*, swap_id, session_id):
        return True, None

    async def _default_lnd_create_invoice(*, amount_sat, memo):
        return {"bolt11": "lnbcrt1u1p...", "payment_hash": "ab" * 32}, None

    master = derive_slip77_master_blinding_key(b"\x42" * 64)
    state: dict = {}
    deps = build_liquid_hop_deps(
        backend=backend,
        swap_client=swap_client,
        lnd_send_payment=lnd_send or _default_lnd_send,
        lnd_observe_invoice_settled=lnd_observe or _default_lnd_observe,
        lnd_create_invoice=lnd_create_invoice or _default_lnd_create_invoice,
        master_blinding_key=master,
        expected_asset_id=_ASSET,
        network=LiquidNetwork.MAINNET,
        swap_state=state,
    )
    return deps, state, backend, master


def _build_blinded_utxo_for_script(
    *,
    blinding_privkey: bytes,
    script: bytes,
    amount_sat: int,
) -> LiquidUtxo:
    """Build a blinded UTXO observable under ``blinding_privkey``.

    Libwally's ``asset_*`` functions operate on **little-endian** asset
    hashes (the on-wire form). The wallet's ``LBTC_ASSET_ID_*``
    constants are in **big-endian / display** form, so the test must
    reverse before passing them to libwally and the unblind path
    (after my fix in ``liquid_receive``) reverses back to BE — which
    is what the test's assertions compare against.
    """
    from coincurve import PrivateKey

    recv_pub = PrivateKey(blinding_privkey).public_key.format(compressed=True)
    sender_priv = secrets.token_bytes(32)
    abf = secrets.token_bytes(32)
    vbf = secrets.token_bytes(32)
    asset_le = bytes(_ASSET)[::-1]
    gen = bytes(_wally.asset_generator_from_bytes(asset_le, abf))
    comm = bytes(_wally.asset_value_commitment(amount_sat, vbf, gen))
    proof = bytes(
        _wally.asset_rangeproof(
            amount_sat,
            recv_pub,
            sender_priv,
            asset_le,
            abf,
            vbf,
            comm,
            script,
            gen,
            1,
            0,
            36,
        )
    )
    nonce = bytes(_wally.ec_public_key_from_private_key(sender_priv))
    return LiquidUtxo(
        txid="cd" * 32,
        vout=0,
        script_pubkey=script,
        value_commitment=comm,
        asset_commitment=gen,
        nonce_commitment=nonce,
        rangeproof=proof,
        surjectionproof=b"",
        block_height=200,
    )


# Real response shapes captured from the regtest harness (see test_anonymize_liquid_swap.py).
def _reverse_response(lockup_addr: str, blinding_key_hex: str, onchain_amount: int) -> dict:
    return {
        "id": "reverse-id-1",
        "swapTree": {
            "claimLeaf": {"version": 196, "output": "8201" + "00" * 30},
            "refundLeaf": {"version": 196, "output": "20" + "00" * 31},
        },
        "blindingKey": blinding_key_hex,
        "lockupAddress": lockup_addr,
        "refundPublicKey": "02" + "aa" * 32,
        "timeoutBlockHeight": 1591,
        "invoice": BIND_INVOICE,
        "onchainAmount": onchain_amount,
    }


def _submarine_response() -> dict:
    return {
        "id": "submarine-id-1",
        "swapTree": {
            "claimLeaf": {"version": 196, "output": "a914" + "00" * 30},
            "refundLeaf": {"version": 196, "output": "20" + "00" * 31},
        },
        "blindingKey": "73" * 32,
        "address": (
            "el1pqd07rxdvtd9flna86004pwa9603l9v6wrpxlshdwslekdz6vprcj8fw4"
            "fxfm9k62pkgqyqmmkskz3sxaudlewceav8kcpzqct9lm9uya3za8ue9lp6nx"
        ),
        "claimPublicKey": "03" + "bb" * 32,
        "expectedAmount": 250_000,
        "timeoutBlockHeight": 10231,
        "acceptZeroConf": True,
        "bip21": "liquidnetwork:el1pqd07rxdvtd...",
    }


# ── Factory shape ──────────────────────────────────────────────────


def test_factory_returns_liquid_hop_deps_instance() -> None:
    backend = MockLiquidBackend()
    client = LiquidSwapClient(base_url="https://boltz.invalid", socks_port=9052)

    async def _stub(**kwargs):
        return None, None

    master = derive_slip77_master_blinding_key(b"\x42" * 64)
    deps = build_liquid_hop_deps(
        backend=backend,
        swap_client=client,
        lnd_send_payment=_stub,
        lnd_observe_invoice_settled=_stub,
        lnd_create_invoice=_stub,
        master_blinding_key=master,
        expected_asset_id=_ASSET,
        network=LiquidNetwork.MAINNET,
        swap_state={},
    )
    assert isinstance(deps, LiquidHopDeps)
    assert callable(deps.boltz_create_ln_to_lbtc_swap)
    assert callable(deps.lnd_send_payment)
    assert callable(deps.liquid_observe_credit)
    assert callable(deps.boltz_create_lbtc_to_ln_swap)
    assert callable(deps.lnd_observe_invoice_settled)


# ── Runtime gate ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_gate_closed_refuses_ln_to_lbtc_create(monkeypatch) -> None:
    """When ANONYMIZE_LIQUID_INTEGRATION_VERIFIED=false, the adapter
    must refuse rather than create a swap that can't be claimed."""
    monkeypatch.setattr(
        settings,
        "anonymize_liquid_integration_verified",
        False,
    )

    def _http(_request):
        return httpx.Response(200, json={})

    deps, _state, _backend, _master = _make_deps(monkeypatch, _http)
    out, err = await deps.boltz_create_ln_to_lbtc_swap(
        amount_sat=100_000,
        session_id=uuid4(),
        blinding_seed_index=42,
    )
    assert out is None
    assert "INTEGRATION_VERIFIED" in (err or "")


@pytest.mark.asyncio
async def test_gate_closed_refuses_lbtc_to_ln_create(monkeypatch) -> None:
    monkeypatch.setattr(
        settings,
        "anonymize_liquid_integration_verified",
        False,
    )

    def _http(_request):
        return httpx.Response(200, json={})

    deps, _state, _backend, _master = _make_deps(monkeypatch, _http)
    out, err = await deps.boltz_create_lbtc_to_ln_swap(
        lbtc_utxo="x:0",
        amount_sat=100_000,
        session_id=uuid4(),
    )
    assert out is None
    assert "INTEGRATION_VERIFIED" in (err or "")


# ── LN→L-BTC create adapter (reverse swap) ─────────────────────────


@pytest.mark.asyncio
async def test_ln_to_lbtc_create_persists_swap_state(monkeypatch) -> None:
    """The create adapter derives the SLIP-77 blinding privkey (from the
    Boltz-supplied blindingKey, NOT the wallet's master) and stashes
    everything the observer needs."""
    master = derive_slip77_master_blinding_key(b"\x42" * 64)
    blinding_pub = derive_script_blinding_pubkey(master, _LOCKUP_SCRIPT)
    lockup_addr = encode_confidential_segwit(
        _LOCKUP_SCRIPT,
        blinding_pub,
        network=LiquidNetwork.MAINNET,
    )
    # Use Boltz's blinding key (the response's blindingKey field). The
    # wallet uses THIS for unblinding, not its SLIP-77 derivation —
    # because Boltz controls the output construction here.
    boltz_blinding_priv = secrets.token_bytes(32)
    response = _reverse_response(
        lockup_addr=lockup_addr,
        blinding_key_hex=boltz_blinding_priv.hex(),
        onchain_amount=99_500,
    )

    def _handler(request):
        assert "/v2/swap/reverse" in str(request.url), str(request.url)
        return httpx.Response(200, json=response)

    deps, state, _backend, _master = _make_deps(monkeypatch, _handler)
    sid = uuid4()
    out, err = await deps.boltz_create_ln_to_lbtc_swap(
        amount_sat=100_000,
        session_id=sid,
        blinding_seed_index=42,
    )
    assert err is None
    assert out is not None
    assert out["swap_id"] == "reverse-id-1"
    assert out["invoice"] == BIND_INVOICE

    # State should be stashed under the swap_id
    stashed = state["reverse-id-1"]
    assert stashed["leg"] == "ln_to_lbtc"
    assert stashed["expected_amount_sat"] == 99_500
    assert bytes.fromhex(stashed["lockup_script_hex"]) == _LOCKUP_SCRIPT
    assert bytes.fromhex(stashed["blinding_privkey_hex"]) == boltz_blinding_priv
    assert stashed["timeout_block_height"] == 1591


@pytest.mark.asyncio
async def test_ln_to_lbtc_create_rejects_non_liquid_lockup_address(
    monkeypatch,
) -> None:
    """A response whose lockupAddress isn't a Liquid address must
    surface as an error — defends against a Boltz-side bug or wrong
    network."""
    response = _reverse_response(
        lockup_addr="bc1qzyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3aw53mz",
        blinding_key_hex="aa" * 32,
        onchain_amount=99_500,
    )

    def _handler(request):
        return httpx.Response(200, json=response)

    deps, _state, _backend, _master = _make_deps(monkeypatch, _handler)
    out, err = await deps.boltz_create_ln_to_lbtc_swap(
        amount_sat=100_000,
        session_id=uuid4(),
        blinding_seed_index=42,
    )
    assert out is None
    assert "not a Liquid address" in (err or "")


@pytest.mark.asyncio
async def test_ln_to_lbtc_create_rejects_wrong_blinding_key_length(
    monkeypatch,
) -> None:
    master = derive_slip77_master_blinding_key(b"\x42" * 64)
    blinding_pub = derive_script_blinding_pubkey(master, _LOCKUP_SCRIPT)
    lockup_addr = encode_confidential_segwit(
        _LOCKUP_SCRIPT,
        blinding_pub,
        network=LiquidNetwork.MAINNET,
    )
    response = _reverse_response(
        lockup_addr=lockup_addr,
        blinding_key_hex="aa" * 16,  # 16 bytes — too short
        onchain_amount=99_500,
    )

    def _handler(request):
        return httpx.Response(200, json=response)

    deps, _state, _backend, _master = _make_deps(monkeypatch, _handler)
    out, err = await deps.boltz_create_ln_to_lbtc_swap(
        amount_sat=100_000,
        session_id=uuid4(),
        blinding_seed_index=42,
    )
    assert out is None
    assert "blindingKey" in (err or "")


@pytest.mark.asyncio
async def test_ln_to_lbtc_create_propagates_http_error(monkeypatch) -> None:
    def _handler(request):
        return httpx.Response(500, text="boltz down")

    deps, _state, _backend, _master = _make_deps(monkeypatch, _handler)
    out, err = await deps.boltz_create_ln_to_lbtc_swap(
        amount_sat=100_000,
        session_id=uuid4(),
        blinding_seed_index=42,
    )
    assert out is None
    assert "500" in (err or "")


# ── Observe-credit adapter ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_observe_credit_returns_utxo_id_after_unblind(monkeypatch) -> None:
    """Create-swap stashes state → observe-credit polls backend →
    unblinds with Boltz's blinding key → validates → returns chain anchor."""
    master = derive_slip77_master_blinding_key(b"\x42" * 64)
    blinding_pub = derive_script_blinding_pubkey(master, _LOCKUP_SCRIPT)
    lockup_addr = encode_confidential_segwit(
        _LOCKUP_SCRIPT,
        blinding_pub,
        network=LiquidNetwork.MAINNET,
    )
    # The blinding privkey must match the one used in the UTXO's
    # rangeproof. For the receive path test, we use a fresh privkey
    # known to both sides.
    boltz_blinding_priv = derive_script_blinding_privkey(master, _LOCKUP_SCRIPT)
    response = _reverse_response(
        lockup_addr=lockup_addr,
        blinding_key_hex=boltz_blinding_priv.hex(),
        onchain_amount=100_000,
    )

    def _handler(request):
        return httpx.Response(200, json=response)

    deps, _state, backend, _master = _make_deps(monkeypatch, _handler)
    sid = uuid4()
    create_out, _ = await deps.boltz_create_ln_to_lbtc_swap(
        amount_sat=100_000,
        session_id=sid,
        blinding_seed_index=42,
    )
    swap_id = create_out["swap_id"]

    # Backend has no UTXO yet — observer returns (None, None)
    none_out, none_err = await deps.liquid_observe_credit(
        swap_id=swap_id,
        session_id=sid,
    )
    assert none_out is None
    assert none_err is None

    # Load a matching UTXO into the backend
    utxo = _build_blinded_utxo_for_script(
        blinding_privkey=boltz_blinding_priv,
        script=_LOCKUP_SCRIPT,
        amount_sat=100_000,
    )
    backend.add_utxo(_LOCKUP_SCRIPT, utxo)

    obs_out, obs_err = await deps.liquid_observe_credit(
        swap_id=swap_id,
        session_id=sid,
    )
    assert obs_err is None
    assert obs_out == f"{utxo.txid}:{utxo.vout}"


@pytest.mark.asyncio
async def test_observe_credit_fails_loud_on_underpayment(monkeypatch) -> None:
    master = derive_slip77_master_blinding_key(b"\x42" * 64)
    blinding_pub = derive_script_blinding_pubkey(master, _LOCKUP_SCRIPT)
    lockup_addr = encode_confidential_segwit(
        _LOCKUP_SCRIPT,
        blinding_pub,
        network=LiquidNetwork.MAINNET,
    )
    boltz_blinding_priv = derive_script_blinding_privkey(master, _LOCKUP_SCRIPT)
    response = _reverse_response(
        lockup_addr=lockup_addr,
        blinding_key_hex=boltz_blinding_priv.hex(),
        onchain_amount=100_000,
    )

    def _handler(request):
        return httpx.Response(200, json=response)

    deps, _state, backend, _master = _make_deps(monkeypatch, _handler)
    sid = uuid4()
    create_out, _ = await deps.boltz_create_ln_to_lbtc_swap(
        amount_sat=100_000,
        session_id=sid,
        blinding_seed_index=42,
    )
    # Boltz publishes a 50k credit (underpayment vs. expected 100k).
    utxo = _build_blinded_utxo_for_script(
        blinding_privkey=boltz_blinding_priv,
        script=_LOCKUP_SCRIPT,
        amount_sat=50_000,
    )
    backend.add_utxo(_LOCKUP_SCRIPT, utxo)

    obs_out, obs_err = await deps.liquid_observe_credit(
        swap_id=create_out["swap_id"],
        session_id=sid,
    )
    assert obs_out is None
    assert "below minimum" in (obs_err or "")


@pytest.mark.asyncio
async def test_observe_credit_rejects_missing_swap_state(monkeypatch) -> None:
    def _handler(request):
        return httpx.Response(200, json={})

    deps, _state, _backend, _master = _make_deps(monkeypatch, _handler)
    out, err = await deps.liquid_observe_credit(
        swap_id="never-created",
        session_id=uuid4(),
    )
    assert out is None
    assert "no per-swap state" in (err or "")


@pytest.mark.asyncio
async def test_observe_credit_rejects_missing_swap_id(monkeypatch) -> None:
    def _handler(request):
        return httpx.Response(200, json={})

    deps, _state, _backend, _master = _make_deps(monkeypatch, _handler)
    out, err = await deps.liquid_observe_credit(
        swap_id=None,
        session_id=uuid4(),
    )
    assert out is None
    assert "missing swap_id" in (err or "")


# ── L-BTC→LN create adapter (submarine swap) ───────────────────────


@pytest.mark.asyncio
async def test_lbtc_to_ln_create_persists_swap_state(monkeypatch) -> None:
    """The submarine create adapter mints an LN invoice via
    lnd_create_invoice, calls Boltz, and stashes the Boltz-supplied
    Liquid lockup address (where the wallet must send L-BTC)."""
    response = _submarine_response()

    def _handler(request):
        assert "/v2/swap/submarine" in str(request.url), str(request.url)
        return httpx.Response(200, json=response)

    deps, state, _backend, _master = _make_deps(monkeypatch, _handler)
    sid = uuid4()
    out, err = await deps.boltz_create_lbtc_to_ln_swap(
        lbtc_utxo="cd" * 32 + ":0",
        amount_sat=250_000,
        session_id=sid,
    )
    assert err is None
    assert out is not None
    assert out["swap_id"] == "submarine-id-1"
    stashed = state["submarine-id-1"]
    assert stashed["leg"] == "lbtc_to_ln"
    assert stashed["address"] == response["address"]
    assert stashed["expected_amount_sat"] == 250_000
    assert stashed["accept_zero_conf"] is True
    assert stashed["consumed_lbtc_utxo"] == "cd" * 32 + ":0"


@pytest.mark.asyncio
async def test_lbtc_to_ln_refuses_to_fund_on_failed_lockup_verification(monkeypatch) -> None:
    """If the Liquid lockup does not commit to our refund key, the
    submarine create adapter refuses — no funding of an operator-
    controlled address."""
    response = _submarine_response()

    def _handler(request):
        return httpx.Response(200, json=response)

    deps, state, _backend, _master = _make_deps(monkeypatch, _handler)
    # Override the autouse accept-stub with a rejection verdict.
    monkeypatch.setattr(
        "app.services.anonymize.liquid_hop_adapters.verify_liquid_lockup_address",
        lambda **_kw: (False, "refund_leaf_mismatch"),
    )
    out, err = await deps.boltz_create_lbtc_to_ln_swap(
        lbtc_utxo="cd" * 32 + ":0",
        amount_sat=250_000,
        session_id=uuid4(),
    )
    assert out is None
    assert "lockup verification failed" in (err or "")
    assert "submarine-id-1" not in state


@pytest.mark.asyncio
async def test_lbtc_to_ln_propagates_invoice_creation_failure(monkeypatch) -> None:
    async def _failing_create_invoice(*, amount_sat, memo):
        return None, "lnd_unavailable"

    def _handler(request):
        return httpx.Response(200, json=_submarine_response())

    deps, _state, _backend, _master = _make_deps(
        monkeypatch,
        _handler,
        lnd_create_invoice=_failing_create_invoice,
    )
    out, err = await deps.boltz_create_lbtc_to_ln_swap(
        lbtc_utxo="cd" * 32 + ":0",
        amount_sat=250_000,
        session_id=uuid4(),
    )
    assert out is None
    assert "lnd_create_invoice" in (err or "")


# ── LN-side adapter pass-through ───────────────────────────────────


@pytest.mark.asyncio
async def test_lnd_send_payment_is_pass_through(monkeypatch) -> None:
    captured: dict = {}

    async def _send(*, payment_request, amount_sat):
        captured["payment_request"] = payment_request
        captured["amount_sat"] = amount_sat
        return {"status": "succeeded"}, None

    def _http(_request):
        return httpx.Response(200, json={})

    deps, _state, _backend, _master = _make_deps(
        monkeypatch,
        _http,
        lnd_send=_send,
    )
    result, err = await deps.lnd_send_payment(
        payment_request="lnbc1pblob",
        amount_sat=100_000,
    )
    assert err is None
    assert result == {"status": "succeeded"}
    assert captured == {"payment_request": "lnbc1pblob", "amount_sat": 100_000}


@pytest.mark.asyncio
async def test_lnd_observe_invoice_settled_is_pass_through(monkeypatch) -> None:
    captured: dict = {}

    async def _observe(*, swap_id, session_id):
        captured["swap_id"] = swap_id
        captured["session_id"] = session_id
        return True, None

    def _http(_request):
        return httpx.Response(200, json={})

    deps, _state, _backend, _master = _make_deps(
        monkeypatch,
        _http,
        lnd_observe=_observe,
    )
    sid = uuid4()
    out, err = await deps.lnd_observe_invoice_settled(
        swap_id="x",
        session_id=sid,
    )
    assert err is None
    assert out is True
    assert captured == {"swap_id": "x", "session_id": sid}


# ── claim_txid recovery: claim backfill + observe resilience
#
# The
# claim subprocess broadcasts atomically, so a broadcast-then-error can
# leave the L-BTC claim on-chain with no recorded txid. The single-use
# per-session CT script lets us recover the txid from the chain.


def _simple_utxo(script: bytes, *, txid: str, block_height) -> LiquidUtxo:
    """Minimal UTXO for paths that never unblind (recovery scan + the
    mempool confirmation gate)."""
    return LiquidUtxo(
        txid=txid,
        vout=0,
        script_pubkey=script,
        value_commitment=b"",
        asset_commitment=b"",
        nonce_commitment=b"",
        rangeproof=b"",
        surjectionproof=b"",
        block_height=block_height,
    )


_CLAIM_STATE_BASE = {
    "lockup_tx_hex": "00" * 4,
    "blinding_privkey_hex": "44" * 32,  # Boltz lockup blinding key
    "session_blinding_seed_index": 42,
    "preimage_hex": "11" * 32,
    "claim_private_key_hex": "22" * 32,
    "refund_public_key_hex": "03" + "aa" * 32,
    "swap_tree_claim_leaf": "8201" + "00" * 30,
    "swap_tree_refund_leaf": "20" + "00" * 31,
}


@pytest.mark.asyncio
async def test_recover_liquid_claim_txid_finds_single_use_utxo() -> None:
    from app.services.anonymize.liquid_hop_adapters import (
        _recover_liquid_claim_txid,
    )

    backend = MockLiquidBackend()
    script = bytes.fromhex("5120" + "44" * 32)
    backend.add_utxo(script, _simple_utxo(script, txid="ab" * 32, block_height=5))
    got = await _recover_liquid_claim_txid(
        backend,
        {"session_script_hex": script.hex()},
    )
    assert got == "ab" * 32


@pytest.mark.asyncio
async def test_recover_liquid_claim_txid_none_when_absent() -> None:
    from app.services.anonymize.liquid_hop_adapters import (
        _recover_liquid_claim_txid,
    )

    backend = MockLiquidBackend()
    script = bytes.fromhex("5120" + "44" * 32)
    # Nothing on-chain (genuine failure / not yet indexed) → None.
    assert (
        await _recover_liquid_claim_txid(
            backend,
            {"session_script_hex": script.hex()},
        )
        is None
    )
    # No script stashed → None.
    assert await _recover_liquid_claim_txid(backend, {}) is None


@pytest.mark.asyncio
async def test_claim_lockup_recovers_txid_on_broadcast_then_error(
    monkeypatch,
) -> None:
    """Claim backfill: subprocess broadcasts then errors → adapter recovers the
    txid from the single-use CT-script UTXO instead of wedging."""
    monkeypatch.setattr(settings, "anonymize_liquid_integration_verified", True)

    def _http(_request):
        return httpx.Response(200, json={})

    deps, state, backend, _master = _make_deps(monkeypatch, _http)
    swap_id = "swap-claim-recover"
    state[swap_id] = dict(_CLAIM_STATE_BASE)

    from app.services.anonymize.liquid_claim_subprocess import (
        LiquidClaimSubprocessError,
    )

    async def _broadcast_then_die(request):
        # The adapter stashes session_script_hex BEFORE calling us, so
        # we can simulate "broadcast landed, then the script died".
        script = bytes.fromhex(state[swap_id]["session_script_hex"])
        backend.add_utxo(
            script,
            _simple_utxo(script, txid="cc" * 32, block_height=7),
        )
        raise LiquidClaimSubprocessError("broadcast ok, then crashed")

    monkeypatch.setattr(
        "app.services.anonymize.liquid_hop_adapters.run_liquid_claim_subprocess",
        _broadcast_then_die,
    )

    claim_txid, err = await deps.liquid_claim_lockup(
        swap_id=swap_id,
        session_id=uuid4(),
    )
    assert err is None
    assert claim_txid == "cc" * 32
    assert state[swap_id]["claim_txid"] == "cc" * 32


@pytest.mark.asyncio
async def test_claim_lockup_errors_when_nothing_broadcast(monkeypatch) -> None:
    """Claim backfill: genuine failure (nothing on-chain) surfaces the error so the
    step retries — no false recovery."""
    monkeypatch.setattr(settings, "anonymize_liquid_integration_verified", True)

    def _http(_request):
        return httpx.Response(200, json={})

    deps, state, backend, _master = _make_deps(monkeypatch, _http)
    swap_id = "swap-claim-fail"
    state[swap_id] = dict(_CLAIM_STATE_BASE)

    from app.services.anonymize.liquid_claim_subprocess import (
        LiquidClaimSubprocessError,
    )

    async def _just_fail(request):
        raise LiquidClaimSubprocessError("signing failed; nothing broadcast")

    monkeypatch.setattr(
        "app.services.anonymize.liquid_hop_adapters.run_liquid_claim_subprocess",
        _just_fail,
    )

    claim_txid, err = await deps.liquid_claim_lockup(
        swap_id=swap_id,
        session_id=uuid4(),
    )
    assert claim_txid is None
    assert "liquid claim subprocess failed" in (err or "")
    assert "claim_txid" not in state[swap_id]


@pytest.mark.asyncio
async def test_observe_wallet_credit_backfills_missing_claim_txid(
    monkeypatch,
) -> None:
    """Observe resilience: observe matches the single-use CT-script UTXO and backfills
    claim_txid when the cache lacks it (manual-recovery / hydration gap)."""

    def _http(_request):
        return httpx.Response(200, json={})

    deps, state, backend, _master = _make_deps(monkeypatch, _http)
    blinding_priv = secrets.token_bytes(32)
    script = bytes.fromhex("5120" + "33" * 32)
    swap_id = "swap-observe-backfill"
    state[swap_id] = {
        "session_script_hex": script.hex(),
        "session_blinding_privkey_hex": blinding_priv.hex(),
        # NOTE: no claim_txid
    }
    utxo = _build_blinded_utxo_for_script(
        blinding_privkey=blinding_priv,
        script=script,
        amount_sat=99_000,
    )
    backend.add_utxo(script, utxo)

    confirmed, err = await deps.liquid_observe_wallet_credit(
        swap_id=swap_id,
        session_id=uuid4(),
    )
    assert err is None
    assert confirmed is True
    assert state[swap_id]["claim_txid"] == utxo.txid
    assert state[swap_id]["wallet_utxo_txid"] == utxo.txid


@pytest.mark.asyncio
async def test_observe_wallet_credit_waits_when_mempool(monkeypatch) -> None:
    """Observe resilience: an unconfirmed (mempool) UTXO with no known claim_txid is not
    prematurely backfilled — observe waits for a confirmation."""

    def _http(_request):
        return httpx.Response(200, json={})

    deps, state, backend, _master = _make_deps(monkeypatch, _http)
    blinding_priv = secrets.token_bytes(32)
    script = bytes.fromhex("5120" + "35" * 32)
    swap_id = "swap-observe-mempool"
    state[swap_id] = {
        "session_script_hex": script.hex(),
        "session_blinding_privkey_hex": blinding_priv.hex(),
    }
    backend.add_utxo(
        script,
        _simple_utxo(script, txid="dd" * 32, block_height=None),
    )

    confirmed, err = await deps.liquid_observe_wallet_credit(
        swap_id=swap_id,
        session_id=uuid4(),
    )
    assert err is None
    assert confirmed is False
    assert "claim_txid" not in state[swap_id]


@pytest.mark.asyncio
async def test_observe_wallet_credit_strict_match_when_txid_known(
    monkeypatch,
) -> None:
    """Observe resilience: when claim_txid IS known the strict txid match is preserved —
    a non-matching UTXO at the script is ignored (existing behavior)."""

    def _http(_request):
        return httpx.Response(200, json={})

    deps, state, backend, _master = _make_deps(monkeypatch, _http)
    blinding_priv = secrets.token_bytes(32)
    script = bytes.fromhex("5120" + "36" * 32)
    swap_id = "swap-observe-strict"
    state[swap_id] = {
        "session_script_hex": script.hex(),
        "session_blinding_privkey_hex": blinding_priv.hex(),
        "claim_txid": "aa" * 32,  # known; differs from the UTXO below
    }
    # _build_blinded_utxo_for_script uses txid "cd"*32 ≠ "aa"*32.
    utxo = _build_blinded_utxo_for_script(
        blinding_privkey=blinding_priv,
        script=script,
        amount_sat=99_000,
    )
    backend.add_utxo(script, utxo)

    confirmed, err = await deps.liquid_observe_wallet_credit(
        swap_id=swap_id,
        session_id=uuid4(),
    )
    assert err is None
    assert confirmed is False  # non-matching UTXO ignored


@pytest.mark.asyncio
async def test_observe_wallet_credit_requires_script(monkeypatch) -> None:
    """Observe resilience: script/blinding remain required — without them observe can
    neither scan nor unblind."""

    def _http(_request):
        return httpx.Response(200, json={})

    deps, state, _backend, _master = _make_deps(monkeypatch, _http)
    swap_id = "swap-observe-noscript"
    state[swap_id] = {"session_blinding_privkey_hex": "11" * 32}  # no script

    confirmed, err = await deps.liquid_observe_wallet_credit(
        swap_id=swap_id,
        session_id=uuid4(),
    )
    assert confirmed is False
    assert "session script" in (err or "")
