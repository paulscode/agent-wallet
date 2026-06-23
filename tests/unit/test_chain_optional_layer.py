# SPDX-License-Identifier: MIT
"""Tests for the optional layer (electrs-driven enrichments).

Each feature is best-effort — must silently degrade when Electrum is
absent, and must NOT break existing flows. These tests exercise:

* ``optional_verify_tx`` / ``optional_confirmations`` / ``cached_tip_height``
  helpers on :class:`MempoolFeeService`.
* The ``_tx_pays_address`` helper used by the Boltz lockup verification.
* The dashboard ``/tx/{txid}/confirmations`` endpoint.
* The ``ReceiveAddressSubscriber`` lifecycle and best-effort idiom.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from app.services.boltz_service import _tx_pays_address
from app.services.chain.electrum import (
    _ELECTRUM_BREAKER,
    ElectrumChainBackend,
    ElectrumClient,
)
from app.services.mempool_fee_service import MempoolFeeService
from tests.unit._fake_electrum import FakeElectrumServer

# ─── Facade optional helpers ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_optional_verify_tx_returns_none_without_electrum(monkeypatch):
    monkeypatch.setattr("app.services.mempool_fee_service.settings.lnd_electrum_url", "")
    monkeypatch.setattr("app.services.mempool_fee_service.settings.chain_backend", "auto")
    svc = MempoolFeeService()
    try:
        assert svc.has_electrum is False
        assert await svc.optional_verify_tx("ab" * 32) is None
        assert await svc.optional_confirmations("ab" * 32) is None
        assert svc.cached_tip_height is None
    finally:
        await svc.close()


@pytest.mark.asyncio
async def test_optional_verify_tx_returns_none_when_breaker_open(monkeypatch):
    """When Electrum is configured but its breaker is open, helpers
    must NOT trigger an RPC and must return ``None``."""
    async with FakeElectrumServer() as server:
        _ELECTRUM_BREAKER.state = "open"
        _ELECTRUM_BREAKER.consecutive_failures = 99
        monkeypatch.setattr(
            "app.services.mempool_fee_service.settings.lnd_electrum_url",
            server.url,
        )
        monkeypatch.setattr("app.services.mempool_fee_service.settings.chain_backend", "auto")
        svc = MempoolFeeService()
        try:
            assert svc.has_electrum is True
            assert await svc.optional_verify_tx("ab" * 32) is None
        finally:
            _ELECTRUM_BREAKER.state = "closed"
            _ELECTRUM_BREAKER.consecutive_failures = 0
            await svc.close()


@pytest.mark.asyncio
async def test_optional_verify_tx_returns_data_when_healthy(monkeypatch):
    async with FakeElectrumServer() as server:
        _ELECTRUM_BREAKER.state = "closed"
        _ELECTRUM_BREAKER.consecutive_failures = 0
        monkeypatch.setattr(
            "app.services.mempool_fee_service.settings.lnd_electrum_url",
            server.url,
        )
        monkeypatch.setattr("app.services.mempool_fee_service.settings.chain_backend", "auto")
        server.set_response(
            "blockchain.transaction.get",
            {
                "txid": "ab" * 32,
                "confirmations": 1,
                "blockhash": "cc" * 32,
                "blocktime": 1_700_000_000,
                "vin": [],
                "vout": [{"value": 0.001, "scriptPubKey": {"address": "bc1qx"}}],
            },
        )
        svc = MempoolFeeService()
        client = ElectrumClient(server.url, connect_timeout_s=2.0, request_timeout_s=2.0)
        svc._electrum = ElectrumChainBackend(client=client, network="bitcoin")
        # Wait for handshake so the tip is populated before we assert.
        await client.start(wait_for_connect=True)
        try:
            data = await svc.optional_verify_tx("ab" * 32)
            assert data is not None
            assert data["txid"] == "ab" * 32
            # Cached tip from the fake's headers.subscribe (default 800_000).
            assert svc.cached_tip_height == 800_000
        finally:
            await svc.close()


@pytest.mark.asyncio
async def test_optional_confirmations_returns_none_on_error(monkeypatch):
    """If the underlying call returns an error tuple, helper returns ``None``."""
    monkeypatch.setattr("app.services.mempool_fee_service.settings.lnd_electrum_url", "")
    monkeypatch.setattr("app.services.mempool_fee_service.settings.chain_backend", "mempool")
    svc = MempoolFeeService()
    try:
        # Mock the underlying method to return an error.
        async def _err(_txid):
            return None, "boom"

        svc.get_transaction_confirmations = _err  # type: ignore[assignment]
        assert await svc.optional_confirmations("ab" * 32) is None
    finally:
        await svc.close()


# ─── _tx_pays_address helper ─────────────────────────────────────────


def test_tx_pays_address_match():
    tx = {
        "vout": [
            {"value": 0.0, "address": "bc1qother"},
            {"value": 0.001, "address": "bc1qexpected"},
        ]
    }
    assert _tx_pays_address(tx, "bc1qexpected") is True


def test_tx_pays_address_no_match():
    tx = {"vout": [{"address": "bc1qother"}]}
    assert _tx_pays_address(tx, "bc1qexpected") is False


def test_tx_pays_address_handles_empty_vout():
    assert _tx_pays_address({}, "bc1qx") is False
    assert _tx_pays_address({"vout": []}, "bc1qx") is False
    assert _tx_pays_address({"vout": [None, "x", {}]}, "bc1qx") is False


def test_tx_pays_address_empty_expected():
    assert _tx_pays_address({"vout": [{"address": "bc1qx"}]}, "") is False
    assert _tx_pays_address({"vout": [{"address": "bc1qx"}]}, "   ") is False


# ─── Receive-address subscriber ──────────────────────────────────────


@pytest.mark.asyncio
async def test_receive_subscriber_noop_without_electrum(monkeypatch):
    """``subscribe`` and ``start`` must be silent no-ops when Electrum
    is not configured. No DB hit, no exception."""
    monkeypatch.setattr("app.services.mempool_fee_service.settings.lnd_electrum_url", "")
    monkeypatch.setattr("app.services.mempool_fee_service.settings.chain_backend", "auto")
    # Replace the global facade with a fresh instance so has_electrum=False.
    fresh = MempoolFeeService()
    monkeypatch.setattr("app.services.mempool_fee_service.mempool_fee_service", fresh)
    try:
        from app.services.utxo_subscriptions import ReceiveAddressSubscriber

        sub = ReceiveAddressSubscriber()
        # No exception, no work.
        await sub.start()
        await sub.subscribe("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
        await sub.stop()
    finally:
        await fresh.close()


@pytest.mark.asyncio
async def test_receive_subscriber_handles_undecodable_address(monkeypatch):
    """An address the decoder rejects must not raise — log and move on."""
    async with FakeElectrumServer() as server:
        _ELECTRUM_BREAKER.state = "closed"
        _ELECTRUM_BREAKER.consecutive_failures = 0
        monkeypatch.setattr(
            "app.services.mempool_fee_service.settings.lnd_electrum_url",
            server.url,
        )
        monkeypatch.setattr("app.services.mempool_fee_service.settings.chain_backend", "auto")
        fresh = MempoolFeeService()
        client = ElectrumClient(server.url, connect_timeout_s=2.0, request_timeout_s=2.0)
        fresh._electrum = ElectrumChainBackend(client=client, network="bitcoin")
        await fresh.start()
        monkeypatch.setattr("app.services.mempool_fee_service.mempool_fee_service", fresh)
        try:
            from app.services.utxo_subscriptions import ReceiveAddressSubscriber

            sub = ReceiveAddressSubscriber()
            await sub.subscribe("not-a-valid-address-zzzzz")  # must not raise
            assert sub._sh_to_address == {}  # never recorded
        finally:
            await fresh.close()


@pytest.mark.asyncio
async def test_receive_subscriber_subscribes_valid_address(monkeypatch):
    async with FakeElectrumServer() as server:
        _ELECTRUM_BREAKER.state = "closed"
        _ELECTRUM_BREAKER.consecutive_failures = 0
        monkeypatch.setattr(
            "app.services.mempool_fee_service.settings.lnd_electrum_url",
            server.url,
        )
        monkeypatch.setattr("app.services.mempool_fee_service.settings.chain_backend", "auto")
        monkeypatch.setattr(
            "app.services.mempool_fee_service.settings.bitcoin_network",
            "bitcoin",
        )
        fresh = MempoolFeeService()
        client = ElectrumClient(server.url, connect_timeout_s=2.0, request_timeout_s=2.0)
        fresh._electrum = ElectrumChainBackend(client=client, network="bitcoin")
        await fresh.start()
        monkeypatch.setattr("app.services.mempool_fee_service.mempool_fee_service", fresh)
        # FakeElectrumServer auto-handles unknown methods; subscribe RPC
        # needs an explicit response.
        server.set_response("blockchain.scripthash.subscribe", None)
        try:
            from app.services.utxo_subscriptions import ReceiveAddressSubscriber

            sub = ReceiveAddressSubscriber()
            await sub.subscribe("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
            assert len(sub._sh_to_address) == 1
        finally:
            await fresh.close()


@pytest.mark.asyncio
async def test_receive_subscriber_notification_triggers_reconcile(monkeypatch):
    """A scripthash notification must enqueue a debounced reconcile."""
    from app.services.utxo_subscriptions import ReceiveAddressSubscriber

    sub = ReceiveAddressSubscriber()
    sub._sh_to_address = {"deadbeef": "bc1qx"}

    called = []

    async def fake_run() -> None:
        called.append(True)

    monkeypatch.setattr(sub, "_run_reconcile", fake_run)
    # Shorten debounce so the test doesn't spin.
    import asyncio

    orig_sleep = asyncio.sleep

    async def fast_sleep(_s):
        await orig_sleep(0)

    monkeypatch.setattr("app.services.utxo_subscriptions.asyncio.sleep", fast_sleep)

    await sub._on_notification("deadbeef", "newstatus")
    # Wait for the debounced task to finish.
    assert sub._reconcile_task is not None
    await sub._reconcile_task
    assert called == [True]


# ─── Dashboard /tx/{txid}/confirmations endpoint ─────────────────────


@pytest.mark.asyncio
async def test_dashboard_tx_confirmations_validates_txid_format():
    """The endpoint logic itself: bad txid → 400."""
    from app.dashboard.api import dashboard_tx_confirmations

    resp = await dashboard_tx_confirmations("not-hex")
    # Returns a JSONResponse with 400.
    assert getattr(resp, "status_code", None) == 400


@pytest.mark.asyncio
async def test_dashboard_tx_confirmations_unavailable_when_no_data(monkeypatch):
    """When the chain backend can't answer, the endpoint MUST return
    ``available: false`` rather than a 5xx."""
    from app.dashboard import api as dashboard_api

    fake_facade = MagicMock()
    fake_facade.optional_confirmations = AsyncMock(return_value=None)
    monkeypatch.setattr(dashboard_api, "mempool_fee_service", fake_facade)
    out = await dashboard_api.dashboard_tx_confirmations("ab" * 32)
    assert out == {"available": False, "txid": "ab" * 32}


@pytest.mark.asyncio
async def test_dashboard_tx_confirmations_returns_data_when_available(monkeypatch):
    from app.dashboard import api as dashboard_api

    fake_facade = MagicMock()
    fake_facade.optional_confirmations = AsyncMock(
        return_value={
            "confirmed": True,
            "confirmations": 3,
            "block_height": 800_001,
        }
    )
    monkeypatch.setattr(dashboard_api, "mempool_fee_service", fake_facade)
    out = await dashboard_api.dashboard_tx_confirmations("AB" * 32)
    assert out["available"] is True
    assert out["txid"] == "ab" * 32  # lowercased
    assert out["confirmed"] is True
    assert out["confirmations"] == 3
    assert out["block_height"] == 800_001


# ─── — swap-detail augmentation ──────────────────────────


@pytest.mark.asyncio
async def test_dashboard_swap_detail_augments_with_chain_fields(monkeypatch):
    """When the chain backend is available, swap-detail responses carry
    ``claim_confirmations``, ``current_block_height``, and
    ``blocks_until_timeout``."""
    from uuid import uuid4

    from app.dashboard import api as dashboard_api

    swap = MagicMock()
    swap.id = uuid4()
    swap.boltz_swap_id = "boltz-1"
    swap.status = MagicMock(value="claimed")
    swap.boltz_status = "transaction.confirmed"
    swap.invoice_amount_sats = 100_000
    swap.onchain_amount_sats = 99_500
    swap.destination_address = "bc1qx"
    swap.claim_txid = "cd" * 32
    swap.timeout_block_height = 800_144
    swap.error_message = None
    swap.status_history = []
    swap.created_at = None
    swap.completed_at = None

    monkeypatch.setattr(
        dashboard_api.boltz_service,
        "get_swap_by_id",
        AsyncMock(return_value=swap),
    )
    fake_facade = MagicMock()
    fake_facade.optional_confirmations = AsyncMock(return_value={"confirmations": 2, "block_height": 800_000})
    fake_facade.cached_tip_height = 800_001
    monkeypatch.setattr(dashboard_api, "mempool_fee_service", fake_facade)

    resp = await dashboard_api.cold_storage_swap_detail(swap.id, db=MagicMock())
    assert resp["claim_confirmations"] == 2
    assert resp["claim_block_height"] == 800_000
    assert resp["current_block_height"] == 800_001
    assert resp["blocks_until_timeout"] == 800_144 - 800_001


@pytest.mark.asyncio
async def test_dashboard_swap_detail_omits_chain_fields_when_unavailable(monkeypatch):
    """Without electrum, the optional fields are simply absent — base
    response shape is identical to today's."""
    from uuid import uuid4

    from app.dashboard import api as dashboard_api

    swap = MagicMock()
    swap.id = uuid4()
    swap.boltz_swap_id = "boltz-1"
    swap.status = MagicMock(value="claimed")
    swap.boltz_status = "transaction.confirmed"
    swap.invoice_amount_sats = 100_000
    swap.onchain_amount_sats = 99_500
    swap.destination_address = "bc1qx"
    swap.claim_txid = "cd" * 32
    swap.timeout_block_height = 800_144
    swap.error_message = None
    swap.status_history = []
    swap.created_at = None
    swap.completed_at = None

    monkeypatch.setattr(
        dashboard_api.boltz_service,
        "get_swap_by_id",
        AsyncMock(return_value=swap),
    )
    fake_facade = MagicMock()
    fake_facade.optional_confirmations = AsyncMock(return_value=None)
    fake_facade.cached_tip_height = None
    monkeypatch.setattr(dashboard_api, "mempool_fee_service", fake_facade)

    resp = await dashboard_api.cold_storage_swap_detail(swap.id, db=MagicMock())
    assert "claim_confirmations" not in resp
    assert "claim_block_height" not in resp
    assert "current_block_height" not in resp
    assert "blocks_until_timeout" not in resp
    # Base fields still present.
    assert resp["claim_txid"] == "cd" * 32
    assert resp["timeout_block_height"] == 800_144


# ─── — public API path (`app/api/cold_storage.py`) ───────


def _make_response_swap(**overrides):
    """Minimal duck-typed swap shaped for ``_swap_to_response``."""
    from uuid import uuid4

    swap = MagicMock()
    swap.id = uuid4()
    swap.boltz_swap_id = "boltz-1"
    swap.status = MagicMock(value="claimed")
    swap.boltz_status = "transaction.confirmed"
    swap.invoice_amount_sats = 100_000
    swap.onchain_amount_sats = 99_500
    swap.destination_address = "bc1qx"
    swap.fee_percentage = 0.5
    swap.miner_fee_sats = 200
    swap.boltz_invoice = "lnbc..."
    swap.claim_txid = "cd" * 32
    swap.timeout_block_height = 800_144
    swap.error_message = None
    swap.status_history = []
    swap.created_at = None
    swap.updated_at = None
    swap.completed_at = None
    for k, v in overrides.items():
        setattr(swap, k, v)
    return swap


@pytest.mark.asyncio
async def test_api_augment_with_chain_data_full(monkeypatch):
    """The public API helper enriches with all four fields when the
    facade is healthy and the swap has a claim_txid + timeout."""
    from app.api import cold_storage as api_cs

    fake_facade = MagicMock()
    fake_facade.optional_confirmations = AsyncMock(return_value={"confirmations": 5, "block_height": 800_010})
    fake_facade.cached_tip_height = 800_012
    monkeypatch.setattr("app.services.mempool_fee_service.mempool_fee_service", fake_facade)

    swap = _make_response_swap()
    base = api_cs._swap_to_response(swap)
    out = await api_cs._augment_with_chain_data(base, swap)
    assert out["claim_confirmations"] == 5
    assert out["claim_block_height"] == 800_010
    assert out["current_block_height"] == 800_012
    assert out["blocks_until_timeout"] == 800_144 - 800_012
    fake_facade.optional_confirmations.assert_awaited_once_with("cd" * 32)


@pytest.mark.asyncio
async def test_api_augment_skips_confirmations_without_claim_txid(monkeypatch):
    """When the swap has no claim_txid yet, the helper MUST NOT call
    the facade for confirmations."""
    from app.api import cold_storage as api_cs

    fake_facade = MagicMock()
    fake_facade.optional_confirmations = AsyncMock(return_value=None)
    fake_facade.cached_tip_height = 800_012
    monkeypatch.setattr("app.services.mempool_fee_service.mempool_fee_service", fake_facade)

    swap = _make_response_swap(claim_txid=None)
    base = api_cs._swap_to_response(swap)
    out = await api_cs._augment_with_chain_data(base, swap)
    assert "claim_confirmations" not in out
    fake_facade.optional_confirmations.assert_not_awaited()
    # Tip-aware fields still added (don't depend on claim_txid).
    assert out["current_block_height"] == 800_012
    assert out["blocks_until_timeout"] == 800_144 - 800_012


@pytest.mark.asyncio
async def test_api_augment_handles_missing_timeout(monkeypatch):
    """``blocks_until_timeout`` must be omitted when ``timeout_block_height``
    is None, even if the tip is known."""
    from app.api import cold_storage as api_cs

    fake_facade = MagicMock()
    fake_facade.optional_confirmations = AsyncMock(return_value=None)
    fake_facade.cached_tip_height = 800_012
    monkeypatch.setattr("app.services.mempool_fee_service.mempool_fee_service", fake_facade)

    swap = _make_response_swap(claim_txid=None, timeout_block_height=None)
    base = api_cs._swap_to_response(swap)
    out = await api_cs._augment_with_chain_data(base, swap)
    assert out["current_block_height"] == 800_012
    assert "blocks_until_timeout" not in out


# ─── — facade healthy-path optional_confirmations ────────────────


@pytest.mark.asyncio
async def test_optional_confirmations_returns_data_when_healthy(monkeypatch):
    monkeypatch.setattr("app.services.mempool_fee_service.settings.lnd_electrum_url", "")
    monkeypatch.setattr("app.services.mempool_fee_service.settings.chain_backend", "mempool")
    svc = MempoolFeeService()
    try:

        async def _ok(_txid):
            return (
                {"confirmed": True, "confirmations": 4, "block_height": 800_002},
                None,
            )

        svc.get_transaction_confirmations = _ok  # type: ignore[assignment]
        out = await svc.optional_confirmations("ab" * 32)
        assert out == {
            "confirmed": True,
            "confirmations": 4,
            "block_height": 800_002,
        }
    finally:
        await svc.close()


# ─── — subscriber: subscribe_scripthash failure swallowed ───────


@pytest.mark.asyncio
async def test_receive_subscriber_swallows_subscribe_rpc_failure(monkeypatch):
    """If the underlying ``client.subscribe_scripthash`` raises (cap
    reached, RPC error), the subscriber MUST log and continue."""
    async with FakeElectrumServer() as server:
        _ELECTRUM_BREAKER.state = "closed"
        _ELECTRUM_BREAKER.consecutive_failures = 0
        monkeypatch.setattr(
            "app.services.mempool_fee_service.settings.lnd_electrum_url",
            server.url,
        )
        monkeypatch.setattr("app.services.mempool_fee_service.settings.chain_backend", "auto")
        monkeypatch.setattr(
            "app.services.mempool_fee_service.settings.bitcoin_network",
            "bitcoin",
        )
        fresh = MempoolFeeService()
        client = ElectrumClient(server.url, connect_timeout_s=2.0, request_timeout_s=2.0)
        # Force subscribe_scripthash to raise.
        client.subscribe_scripthash = AsyncMock(  # type: ignore[method-assign]
            side_effect=RuntimeError("cap reached")
        )
        fresh._electrum = ElectrumChainBackend(client=client, network="bitcoin")
        monkeypatch.setattr("app.services.mempool_fee_service.mempool_fee_service", fresh)
        try:
            from app.services.utxo_subscriptions import ReceiveAddressSubscriber

            sub = ReceiveAddressSubscriber()
            # Must NOT raise.
            await sub.subscribe("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
            # The scripthash was registered locally even though the RPC
            # failed (so a future replay/retry has the address handy).
            assert len(sub._sh_to_address) == 1
        finally:
            await fresh.close()


# ─── — subscriber: start() loads addresses from DB ──────────────


@pytest.mark.asyncio
async def test_receive_subscriber_start_loads_db_addresses(monkeypatch, db_session):
    """``start()`` must enumerate ``AddressPurpose`` rows and call
    ``_subscribe`` for each."""
    from app.models.utxo_label import AddressPurpose
    from app.services import utxo_subscriptions as us_mod

    db_session.add(AddressPurpose(address="addr-1", purpose="rent"))
    db_session.add(AddressPurpose(address="addr-2", purpose="savings"))
    await db_session.commit()

    # has_electrum=True via a fake facade.
    fake_facade = MagicMock()
    fake_facade.has_electrum = True
    fake_facade._electrum = MagicMock()
    fake_facade._electrum.client = MagicMock()
    monkeypatch.setattr("app.services.mempool_fee_service.mempool_fee_service", fake_facade)

    # get_db_context must yield the test session.
    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def _ctx():
        yield db_session

    monkeypatch.setattr(us_mod, "get_db_context", _ctx)

    sub = us_mod.ReceiveAddressSubscriber()
    subscribed: list[str] = []

    async def fake_sub(self, address):  # noqa: ANN001
        subscribed.append(address)

    monkeypatch.setattr(us_mod.ReceiveAddressSubscriber, "_subscribe", fake_sub)

    await sub.start()
    assert sorted(subscribed) == ["addr-1", "addr-2"]
    assert sub._started is True
    # Idempotent — second call is a no-op.
    subscribed.clear()
    await sub.start()
    assert subscribed == []


# ─── — subscriber: _run_reconcile delegates to utxo_service ─────


@pytest.mark.asyncio
async def test_receive_subscriber_run_reconcile_calls_utxo_service(monkeypatch, db_session):
    from contextlib import asynccontextmanager

    from app.services import utxo_subscriptions as us_mod

    @asynccontextmanager
    async def _ctx():
        yield db_session

    monkeypatch.setattr(us_mod, "get_db_context", _ctx)
    fake_reconcile = AsyncMock(return_value={"auto_labelled": 2, "spent_marked": 1})
    monkeypatch.setattr("app.services.utxo_service.reconcile", fake_reconcile)

    sub = us_mod.ReceiveAddressSubscriber()
    await sub._run_reconcile()
    fake_reconcile.assert_awaited_once_with(db_session)


# ─── — subscriber: notification coalescing ──────────────────────


@pytest.mark.asyncio
async def test_receive_subscriber_coalesces_notifications(monkeypatch):
    """A burst of notifications must collapse into a single reconcile."""
    import asyncio as _asyncio

    from app.services import utxo_subscriptions as us_mod

    sub = us_mod.ReceiveAddressSubscriber()
    sub._sh_to_address = {"sh1": "addr-1", "sh2": "addr-2"}

    call_count = 0

    async def fake_run() -> None:
        nonlocal call_count
        call_count += 1

    monkeypatch.setattr(sub, "_run_reconcile", fake_run)

    orig_sleep = _asyncio.sleep

    async def fast_sleep(_s):
        await orig_sleep(0)

    monkeypatch.setattr(us_mod.asyncio, "sleep", fast_sleep)

    # Fire three notifications back-to-back.
    await sub._on_notification("sh1", "status-a")
    await sub._on_notification("sh2", "status-b")
    await sub._on_notification("sh1", "status-c")
    assert sub._reconcile_task is not None
    await sub._reconcile_task
    # All three coalesce into a single reconcile run.
    assert call_count == 1


# ─── — subscriber: stop() cancels pending reconcile ─────────────


@pytest.mark.asyncio
async def test_receive_subscriber_stop_cancels_pending(monkeypatch):
    import asyncio as _asyncio

    from app.services import utxo_subscriptions as us_mod

    sub = us_mod.ReceiveAddressSubscriber()
    sub._sh_to_address = {"sh1": "addr-1"}

    started = _asyncio.Event()
    finished = _asyncio.Event()

    async def slow_run() -> None:
        started.set()
        try:
            await _asyncio.sleep(60)
        finally:
            finished.set()

    monkeypatch.setattr(sub, "_run_reconcile", slow_run)
    # Force the debounce sleep to a no-op so we reach _run_reconcile fast.
    orig_sleep = _asyncio.sleep

    async def fast_sleep(_s):
        await orig_sleep(0)

    monkeypatch.setattr(us_mod.asyncio, "sleep", fast_sleep)

    await sub._on_notification("sh1", "x")
    # Wait until the slow run has actually started.
    await _asyncio.wait_for(started.wait(), timeout=2.0)
    await sub.stop()
    # Task is gone; state cleared.
    assert sub._reconcile_task is None
    assert sub._sh_to_address == {}
    assert sub._started is False
    # The cancelled coroutine completed its finally block.
    await _asyncio.wait_for(finished.wait(), timeout=2.0)


# ─── — issuance hook: record_address_purpose subscribes ─────────


@pytest.mark.asyncio
async def test_record_address_purpose_calls_subscriber(monkeypatch, db_session):
    """A freshly-issued receive address must trigger
    ``receive_address_subscriber.subscribe(address)``."""
    from app.services import utxo_service

    seen: list[str] = []

    class _FakeSub:
        async def subscribe(self, address):
            seen.append(address)

    monkeypatch.setattr(
        "app.services.utxo_subscriptions.receive_address_subscriber",
        _FakeSub(),
    )

    await utxo_service.record_address_purpose(db_session, address="bc1qexampleaddress", purpose="rent")
    await db_session.commit()
    assert seen == ["bc1qexampleaddress"]


@pytest.mark.asyncio
async def test_record_address_purpose_swallows_subscriber_errors(monkeypatch, db_session):
    """If the subscriber raises, the persistence path must still
    succeed — the subscription is best-effort, not a precondition."""
    from sqlalchemy import select

    from app.models.utxo_label import AddressPurpose
    from app.services import utxo_service

    class _AngrySub:
        async def subscribe(self, address):
            raise RuntimeError("nope")

    monkeypatch.setattr(
        "app.services.utxo_subscriptions.receive_address_subscriber",
        _AngrySub(),
    )

    # Must not raise.
    await utxo_service.record_address_purpose(db_session, address="bc1qotheraddress", purpose="rent")
    await db_session.commit()
    row = (
        (await db_session.execute(select(AddressPurpose).where(AddressPurpose.address == "bc1qotheraddress")))
        .scalars()
        .first()
    )
    assert row is not None
    assert row.purpose == "rent"


# ─── — Boltz advance_swap integration hook ──────────────────────


@pytest.mark.asyncio
async def test_advance_swap_lockup_verification_logs_on_mismatch(monkeypatch, db_session, caplog):
    """When the verified lockup does not pay the expected address,
    ``advance_swap`` MUST log a warning and still proceed to claim."""
    import logging
    from unittest.mock import patch
    from uuid import uuid4

    from app.models.boltz_swap import BoltzSwap, SwapStatus
    from app.services.boltz_service import BoltzSwapService

    svc = BoltzSwapService()
    swap = BoltzSwap(
        id=uuid4(),
        api_key_id=uuid4(),
        boltz_swap_id="test-lockup-mismatch",
        status=SwapStatus.INVOICE_PAID,
        boltz_status="swap.created",
        invoice_amount_sats=100_000,
        destination_address="bcrt1qdest",
        status_history=[],
        preimage_hex="encrypted_preimage",
        claim_private_key_hex="encrypted_key",
        boltz_refund_public_key_hex="02" + "ff" * 32,
        boltz_swap_tree_json={"claimLeaf": {}},
        boltz_lockup_address="bc1qexpected",
    )
    db_session.add(swap)
    await db_session.commit()

    lockup_id = "ee" * 32
    boltz_data = {"transaction": {"id": lockup_id}}
    # Lockup TX pays a DIFFERENT address.
    fake_facade = MagicMock()
    fake_facade.optional_verify_tx = AsyncMock(return_value={"vout": [{"address": "bc1qWRONG"}]})
    monkeypatch.setattr("app.services.mempool_fee_service.mempool_fee_service", fake_facade)

    caplog.set_level(logging.WARNING, logger="app.services.boltz_service")

    with (
        patch.object(
            svc,
            "get_swap_status_from_boltz",
            new_callable=AsyncMock,
            return_value=("transaction.mempool", boltz_data, None),
        ),
        patch.object(
            svc,
            "get_lockup_transaction",
            new_callable=AsyncMock,
            return_value=(None, "boltz error"),  # short-circuit before claim
        ),
    ):
        result_swap, _err = await svc.advance_swap(db_session, swap)

    fake_facade.optional_verify_tx.assert_awaited_once_with(lockup_id)
    # Mismatch was logged.
    assert any("does NOT pay expected address" in rec.message for rec in caplog.records)
    # Status still advanced to CLAIMING (verification is non-blocking).
    assert result_swap.status == SwapStatus.CLAIMING


@pytest.mark.asyncio
async def test_advance_swap_lockup_verification_skipped_without_id(monkeypatch, db_session):
    """No ``transaction.id`` in boltz_data → the helper is never invoked."""
    from unittest.mock import patch
    from uuid import uuid4

    from app.models.boltz_swap import BoltzSwap, SwapStatus
    from app.services.boltz_service import BoltzSwapService

    svc = BoltzSwapService()
    swap = BoltzSwap(
        id=uuid4(),
        api_key_id=uuid4(),
        boltz_swap_id="test-no-lockup-id",
        status=SwapStatus.INVOICE_PAID,
        boltz_status="swap.created",
        invoice_amount_sats=100_000,
        destination_address="bcrt1qdest",
        status_history=[],
        preimage_hex="encrypted_preimage",
        claim_private_key_hex="encrypted_key",
        boltz_refund_public_key_hex="02" + "ff" * 32,
        boltz_swap_tree_json={"claimLeaf": {}},
        boltz_lockup_address="bc1qexpected",
    )
    db_session.add(swap)
    await db_session.commit()

    fake_facade = MagicMock()
    fake_facade.optional_verify_tx = AsyncMock()
    monkeypatch.setattr("app.services.mempool_fee_service.mempool_fee_service", fake_facade)

    with (
        patch.object(
            svc,
            "get_swap_status_from_boltz",
            new_callable=AsyncMock,
            return_value=("transaction.mempool", {}, None),  # no transaction block
        ),
        patch.object(
            svc,
            "get_lockup_transaction",
            new_callable=AsyncMock,
            return_value=(None, "stop"),
        ),
    ):
        await svc.advance_swap(db_session, swap)

    fake_facade.optional_verify_tx.assert_not_awaited()


@pytest.mark.asyncio
async def test_advance_swap_lockup_verification_swallows_facade_error(monkeypatch, db_session):
    """If ``optional_verify_tx`` raises, the claim path MUST still run."""
    from unittest.mock import patch
    from uuid import uuid4

    from app.models.boltz_swap import BoltzSwap, SwapStatus
    from app.services.boltz_service import BoltzSwapService

    svc = BoltzSwapService()
    swap = BoltzSwap(
        id=uuid4(),
        api_key_id=uuid4(),
        boltz_swap_id="test-facade-error",
        status=SwapStatus.INVOICE_PAID,
        boltz_status="swap.created",
        invoice_amount_sats=100_000,
        destination_address="bcrt1qdest",
        status_history=[],
        preimage_hex="encrypted_preimage",
        claim_private_key_hex="encrypted_key",
        boltz_refund_public_key_hex="02" + "ff" * 32,
        boltz_swap_tree_json={"claimLeaf": {}},
        boltz_lockup_address="bc1qexpected",
    )
    db_session.add(swap)
    await db_session.commit()

    fake_facade = MagicMock()
    fake_facade.optional_verify_tx = AsyncMock(side_effect=RuntimeError("boom"))
    monkeypatch.setattr("app.services.mempool_fee_service.mempool_fee_service", fake_facade)

    with (
        patch.object(
            svc,
            "get_swap_status_from_boltz",
            new_callable=AsyncMock,
            return_value=(
                "transaction.mempool",
                {"transaction": {"id": "aa" * 32}},
                None,
            ),
        ),
        patch.object(
            svc,
            "get_lockup_transaction",
            new_callable=AsyncMock,
            return_value=(None, "stop"),
        ),
    ):
        result_swap, _err = await svc.advance_swap(db_session, swap)

    assert result_swap.status == SwapStatus.CLAIMING
