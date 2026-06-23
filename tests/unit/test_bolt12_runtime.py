# SPDX-License-Identifier: MIT
"""Tests for the BOLT 12 runtime singleton + /status endpoint."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from app.services.bolt12 import runtime as rt


@pytest.fixture(autouse=True)
def _reset_runtime():
    rt._reset_for_tests()
    # The production guard refuses to dial without a token unless
    # DEBUG is true; default the fixture to debug=True so existing
    # tests (which never set the token) keep exercising the dial path.
    # Tests that specifically want to assert the production guard
    # override DEBUG inside their own `with patch.object(...)` block.
    with patch.object(rt.settings, "debug", True, create=True):
        yield
    rt._reset_for_tests()


@pytest.mark.asyncio
async def test_start_is_noop_when_disabled() -> None:
    with (
        patch.object(rt.settings, "bolt12_enabled", False, create=True),
        patch.object(rt.settings, "bolt12_gateway_grpc", "", create=True),
    ):
        await rt.start_bolt12_runtime()
        state = rt.get_bolt12_runtime_state()
        assert state.enabled is False
        assert state.running is False
        assert state.last_error is None


@pytest.mark.asyncio
async def test_start_is_noop_when_target_empty_even_if_enabled() -> None:
    with (
        patch.object(rt.settings, "bolt12_enabled", True, create=True),
        patch.object(rt.settings, "bolt12_gateway_grpc", "", create=True),
    ):
        await rt.start_bolt12_runtime()
        assert rt.get_bolt12_runtime_state().enabled is False


@pytest.mark.asyncio
async def test_start_records_last_error_on_gateway_failure() -> None:
    with (
        patch.object(rt.settings, "bolt12_enabled", True, create=True),
        patch.object(rt.settings, "bolt12_gateway_grpc", "bolt12-gateway:50061", create=True),
        patch.object(rt.Bolt12Service, "start", new=AsyncMock(side_effect=RuntimeError("boom"))),
    ):
        await rt.start_bolt12_runtime()
        state = rt.get_bolt12_runtime_state()
        assert state.enabled is True
        assert state.running is False
        assert state.last_error is not None
        assert "boom" in state.last_error


@pytest.mark.asyncio
async def test_start_then_stop_happy_path() -> None:
    fake_ident = type(
        "Ident",
        (),
        {"network": "regtest", "node_id": b"\x02" * 33, "connected_peers": 0},
    )()
    with (
        patch.object(rt.settings, "bolt12_enabled", True, create=True),
        patch.object(rt.settings, "bolt12_gateway_grpc", "bolt12-gateway:50061", create=True),
        patch.object(rt.settings, "bitcoin_network", "regtest", create=True),
        patch.object(rt.Bolt12Service, "start", new=AsyncMock(return_value=None)),
        patch.object(rt.Bolt12Service, "stop", new=AsyncMock(return_value=None)),
        patch.object(rt.Bolt12GatewayClient, "get_identity", new=AsyncMock(return_value=fake_ident)),
        patch.object(rt.Bolt12GatewayClient, "close", new=AsyncMock(return_value=None)),
    ):
        await rt.start_bolt12_runtime()
        state = rt.get_bolt12_runtime_state()
        assert state.running is True
        assert state.last_error is None

        # idempotent
        await rt.start_bolt12_runtime()
        assert rt.get_bolt12_runtime_state().running is True

        await rt.stop_bolt12_runtime()
        assert rt.get_bolt12_runtime_state().running is False

        # idempotent stop
        await rt.stop_bolt12_runtime()


@pytest.mark.asyncio
async def test_start_spawns_node_address_pusher_and_stop_cancels_it() -> None:
    """Lifespan contract: ``start_bolt12_runtime`` MUST spawn the
    node-address-pusher task when the refresh interval is non-zero,
    and ``stop_bolt12_runtime`` MUST cancel it cleanly. Pin so a
    future refactor that drops the wiring from the lifespan can't
    silently regress the ConnectionNeeded cache push side."""
    fake_ident = type(
        "Ident",
        (),
        {"network": "regtest", "node_id": b"\x02" * 33, "connected_peers": 0},
    )()
    with (
        patch.object(rt.settings, "bolt12_enabled", True, create=True),
        patch.object(rt.settings, "bolt12_gateway_grpc", "bolt12-gateway:50061", create=True),
        patch.object(rt.settings, "bitcoin_network", "regtest", create=True),
        patch.object(
            rt.settings,
            "bolt12_gateway_node_address_refresh_interval_s",
            3600,
            create=True,
        ),
        patch.object(rt.Bolt12Service, "start", new=AsyncMock(return_value=None)),
        patch.object(rt.Bolt12Service, "stop", new=AsyncMock(return_value=None)),
        patch.object(rt.Bolt12GatewayClient, "get_identity", new=AsyncMock(return_value=fake_ident)),
        patch.object(rt.Bolt12GatewayClient, "close", new=AsyncMock(return_value=None)),
    ):
        await rt.start_bolt12_runtime()
        task = rt._runtime.node_address_pusher_task
        assert task is not None, "pusher task must be created"
        assert not task.done(), "pusher task must be running"

        await rt.stop_bolt12_runtime()
        # Task is either done OR has been awaited; either way the
        # runtime forgets its handle so a future start spawns fresh.
        assert rt._runtime.node_address_pusher_task is None


@pytest.mark.asyncio
async def test_start_skips_node_address_pusher_when_interval_zero() -> None:
    """``BOLT12_GATEWAY_NODE_ADDRESS_REFRESH_INTERVAL_S=0`` is the
    documented "disable the push side" knob. The runtime must
    honour it by NOT spawning the task at all."""
    fake_ident = type(
        "Ident",
        (),
        {"network": "regtest", "node_id": b"\x02" * 33, "connected_peers": 0},
    )()
    with (
        patch.object(rt.settings, "bolt12_enabled", True, create=True),
        patch.object(rt.settings, "bolt12_gateway_grpc", "bolt12-gateway:50061", create=True),
        patch.object(rt.settings, "bitcoin_network", "regtest", create=True),
        patch.object(
            rt.settings,
            "bolt12_gateway_node_address_refresh_interval_s",
            0,
            create=True,
        ),
        patch.object(rt.Bolt12Service, "start", new=AsyncMock(return_value=None)),
        patch.object(rt.Bolt12Service, "stop", new=AsyncMock(return_value=None)),
        patch.object(rt.Bolt12GatewayClient, "get_identity", new=AsyncMock(return_value=fake_ident)),
        patch.object(rt.Bolt12GatewayClient, "close", new=AsyncMock(return_value=None)),
    ):
        await rt.start_bolt12_runtime()
        assert rt._runtime.node_address_pusher_task is None
        await rt.stop_bolt12_runtime()


@pytest.mark.asyncio
async def test_start_refuses_on_gateway_network_mismatch() -> None:
    """Wallet on regtest + gateway reporting mainnet must abort start."""
    fake_ident = type(
        "Ident",
        (),
        {"network": "mainnet", "node_id": b"\x02" * 33, "connected_peers": 0},
    )()
    with (
        patch.object(rt.settings, "bolt12_enabled", True, create=True),
        patch.object(rt.settings, "bolt12_gateway_grpc", "bolt12-gateway:50061", create=True),
        patch.object(rt.settings, "bitcoin_network", "regtest", create=True),
        patch.object(rt.Bolt12Service, "start", new=AsyncMock(return_value=None)),
        patch.object(rt.Bolt12Service, "stop", new=AsyncMock(return_value=None)),
        patch.object(rt.Bolt12GatewayClient, "get_identity", new=AsyncMock(return_value=fake_ident)),
        patch.object(rt.Bolt12GatewayClient, "close", new=AsyncMock(return_value=None)),
    ):
        await rt.start_bolt12_runtime()
        state = rt.get_bolt12_runtime_state()
        assert state.running is False
        assert state.last_error is not None
        assert "network mismatch" in state.last_error.lower()


@pytest.mark.asyncio
async def test_start_refuses_when_gateway_omits_network_field() -> None:
    """Pre-network-field gateway build must be rejected at startup."""
    fake_ident = type(
        "Ident",
        (),
        {"network": "", "node_id": b"\x02" * 33, "connected_peers": 0},
    )()
    with (
        patch.object(rt.settings, "bolt12_enabled", True, create=True),
        patch.object(rt.settings, "bolt12_gateway_grpc", "bolt12-gateway:50061", create=True),
        patch.object(rt.settings, "bitcoin_network", "regtest", create=True),
        patch.object(rt.Bolt12Service, "start", new=AsyncMock(return_value=None)),
        patch.object(rt.Bolt12Service, "stop", new=AsyncMock(return_value=None)),
        patch.object(rt.Bolt12GatewayClient, "get_identity", new=AsyncMock(return_value=fake_ident)),
        patch.object(rt.Bolt12GatewayClient, "close", new=AsyncMock(return_value=None)),
    ):
        await rt.start_bolt12_runtime()
        state = rt.get_bolt12_runtime_state()
        assert state.running is False
        assert state.last_error is not None
        assert "network" in state.last_error.lower()


@pytest.mark.asyncio
async def test_get_bolt12_service_503_when_disabled() -> None:
    with patch.object(rt.settings, "bolt12_enabled", False, create=True):
        with pytest.raises(rt.HTTPException) as ei:
            rt.get_bolt12_service()
        assert ei.value.status_code == 503
        assert "disabled" in ei.value.detail.lower()


@pytest.mark.asyncio
async def test_get_bolt12_service_503_when_not_running() -> None:
    with (
        patch.object(rt.settings, "bolt12_enabled", True, create=True),
        patch.object(rt.settings, "bolt12_gateway_grpc", "x:1", create=True),
    ):
        with pytest.raises(rt.HTTPException) as ei:
            rt.get_bolt12_service()
        assert ei.value.status_code == 503
        assert "not running" in ei.value.detail.lower()


@pytest.mark.asyncio
async def test_get_bolt12_service_returns_running_service() -> None:
    sentinel = object()
    rt._inject_for_tests(sentinel)  # type: ignore[arg-type]
    with (
        patch.object(rt.settings, "bolt12_enabled", True, create=True),
        patch.object(rt.settings, "bolt12_gateway_grpc", "x:1", create=True),
    ):
        assert rt.get_bolt12_service() is sentinel


@pytest.mark.asyncio
async def test_supervisor_reconnects_after_initial_failure() -> None:
    """Initial connect fails; supervisor's next iteration succeeds."""
    import asyncio

    fake_ident = type(
        "Ident",
        (),
        {"network": "regtest", "node_id": b"\x02" * 33, "connected_peers": 0},
    )()

    # First call to Bolt12Service.start raises, subsequent calls succeed.
    start_mock = AsyncMock(side_effect=[RuntimeError("boom"), None])

    with (
        patch.object(rt.settings, "bolt12_enabled", True, create=True),
        patch.object(rt.settings, "bolt12_gateway_grpc", "bolt12-gateway:50061", create=True),
        patch.object(rt.settings, "bitcoin_network", "regtest", create=True),
        patch.object(rt.Bolt12Service, "start", new=start_mock),
        patch.object(rt.Bolt12Service, "stop", new=AsyncMock(return_value=None)),
        patch.object(rt.Bolt12GatewayClient, "get_identity", new=AsyncMock(return_value=fake_ident)),
        patch.object(rt.Bolt12GatewayClient, "close", new=AsyncMock(return_value=None)),
        patch.object(rt, "RECONNECT_BACKOFF_MIN_S", 0.01),
        patch.object(rt, "RECONNECT_BACKOFF_MAX_S", 0.05),
    ):
        await rt.start_bolt12_runtime()
        # Initial start failed.
        assert rt.get_bolt12_runtime_state().running is False
        assert rt.get_bolt12_runtime_state().permanently_disabled is False
        # Wait for the supervisor to retry.
        for _ in range(50):
            await asyncio.sleep(0.05)
            if rt.get_bolt12_runtime_state().running:
                break
        assert rt.get_bolt12_runtime_state().running is True
        assert rt.get_bolt12_runtime_state().reconnect_count >= 1
        await rt.stop_bolt12_runtime()


@pytest.mark.asyncio
async def test_supervisor_does_not_retry_when_permanently_disabled() -> None:
    """Network mismatch sets permanently_disabled; no reconnect attempts."""
    import asyncio

    fake_ident = type(
        "Ident",
        (),
        {"network": "mainnet", "node_id": b"\x02" * 33, "connected_peers": 0},
    )()
    start_mock = AsyncMock(return_value=None)

    with (
        patch.object(rt.settings, "bolt12_enabled", True, create=True),
        patch.object(rt.settings, "bolt12_gateway_grpc", "bolt12-gateway:50061", create=True),
        patch.object(rt.settings, "bitcoin_network", "regtest", create=True),
        patch.object(rt.Bolt12Service, "start", new=start_mock),
        patch.object(rt.Bolt12Service, "stop", new=AsyncMock(return_value=None)),
        patch.object(rt.Bolt12GatewayClient, "get_identity", new=AsyncMock(return_value=fake_ident)),
        patch.object(rt.Bolt12GatewayClient, "close", new=AsyncMock(return_value=None)),
        patch.object(rt, "RECONNECT_BACKOFF_MIN_S", 0.01),
        patch.object(rt, "RECONNECT_BACKOFF_MAX_S", 0.05),
    ):
        await rt.start_bolt12_runtime()
        state = rt.get_bolt12_runtime_state()
        assert state.running is False
        assert state.permanently_disabled is True

        # Give the supervisor a chance to (incorrectly) retry.
        await asyncio.sleep(0.1)
        # Bolt12Service.start should have been called exactly once
        # (the initial connect that hit the network mismatch).
        assert start_mock.await_count == 1
        await rt.stop_bolt12_runtime()


# ──: refuse to dial an unauthenticated gateway in production ─


@pytest.mark.asyncio
async def test_start_refuses_when_token_missing_in_production() -> None:
    """If BOLT12 is
    enabled and DEBUG is false (production posture), the runtime
    must refuse to dial a gateway when BOLT12_GATEWAY_TOKEN is
    unset. Failing here surfaces the misconfiguration in api logs
    rather than as a cryptic transport error after a successful
    dial against an unauthenticated peer."""
    with (
        patch.object(rt.settings, "bolt12_enabled", True, create=True),
        patch.object(rt.settings, "bolt12_gateway_grpc", "127.0.0.1:50061", create=True),
        patch.object(rt.settings, "bolt12_gateway_token", "", create=True),
        patch.object(rt.settings, "debug", False, create=True),
    ):
        await rt.start_bolt12_runtime()
        state = rt.get_bolt12_runtime_state()
        assert state.running is False
        assert state.permanently_disabled is True
        assert state.last_error is not None
        assert "BOLT12_GATEWAY_TOKEN" in state.last_error


@pytest.mark.asyncio
async def test_start_allows_empty_token_when_debug_true() -> None:
    """In debug/regtest the gateway may be reachable on a private
    docker network without a token, so the runtime should *attempt*
    the dial (and surface a transport-level error if the gateway
    really is unreachable) rather than refuse outright."""
    with (
        patch.object(rt.settings, "bolt12_enabled", True, create=True),
        patch.object(rt.settings, "bolt12_gateway_grpc", "127.0.0.1:1", create=True),
        patch.object(rt.settings, "bolt12_gateway_token", "", create=True),
        patch.object(rt.settings, "debug", True, create=True),
    ):
        await rt.start_bolt12_runtime()
        state = rt.get_bolt12_runtime_state()
        # The dial WILL fail (port 1 is unbound) but the failure must
        # be a transport error, not the production guard.
        assert state.permanently_disabled is False
        if state.last_error is not None:
            assert "BOLT12_GATEWAY_TOKEN" not in state.last_error
