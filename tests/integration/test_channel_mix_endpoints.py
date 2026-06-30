# SPDX-License-Identifier: MIT
"""Integration tests for the channel-mix planner endpoints.

Covers both the API-key surface (``/v1/wallet/channel-mix/...``) and the
session-authed dashboard wrappers (``/dashboard/api/channel-mix/...``).
Focus is on edge cases the unit-test suite can't reach end-to-end:

* mempool oracle unavailable → planner still produces a plan, warns,
  and the token still validates,
* fee-spike scenario (high feerate >> medium) → cushion grows
  accordingly,
* plan-stale (token tampered) → 409 with a fresh plan body,
* execute happy path → ``ChannelMixRun`` row created and the executor
  task enqueued,
* run-wide partial-failure rollup from the persisted per-channel state.
"""

from __future__ import annotations

import importlib
import time
from typing import AsyncGenerator
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker

from app.core.config import settings
from app.core.database import get_db
from app.dashboard.auth import COOKIE_NAME


# ─── Fixtures ────────────────────────────────────────────────────────


def _make_session_cookie() -> str:
    from app.dashboard.auth import _sign

    expires = int(time.time()) + 86400
    import secrets as _secrets

    payload = f"sess-cmix-{_secrets.token_urlsafe(8)}:{expires}"
    return f"{payload}.{_sign(payload)}"


@pytest_asyncio.fixture
async def dashboard_client(db_engine) -> AsyncGenerator[AsyncClient, None]:
    """Test client with the dashboard router mounted."""
    from fastapi import FastAPI

    from app.dashboard.api import router as dashboard_api

    app = FastAPI()
    app.include_router(dashboard_api)

    session_factory = async_sessionmaker(db_engine, expire_on_commit=False)

    async def override_get_db():
        async with session_factory() as session:
            yield session

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport,
        base_url="http://test",
        follow_redirects=False,
        headers={"X-Requested-With": "XMLHttpRequest"},
    ) as ac:
        cookie = _make_session_cookie()
        ac.cookies.set(COOKIE_NAME, cookie)
        yield ac

    app.dependency_overrides.clear()


@pytest.fixture(autouse=True)
def _force_mainnet_catalog(monkeypatch):
    """Catalog is mainnet-only; pin the network for every test in this
    module so the planner has peers to select from."""
    monkeypatch.setattr(settings, "bitcoin_network", "bitcoin")
    monkeypatch.setattr(settings, "small_channel_peer_catalog_enabled", True)


@pytest.fixture(autouse=True)
def _reset_catalog_module():
    from app.services import small_channel_peers as scp_module

    importlib.reload(scp_module)
    yield


@pytest.fixture(autouse=True)
def _bypass_csrf():
    """The channel-mix mutating endpoints sit behind ``_require_auth_csrf``.
    Generating a real CSRF token in tests would require Redis; patching
    ``check_csrf_token`` to return "ok" mirrors the bypass used by the
    other dashboard integration test files."""
    with patch(
        "app.dashboard.api.check_csrf_token",
        new_callable=AsyncMock,
        return_value="ok",
    ):
        yield


def _stub_fee_oracle(*, medium: int, high: int):
    """Build an async stub that pretends to be ``mempool_fee_service``."""

    async def _stub():
        return {"hourFee": medium, "halfHourFee": medium, "fastestFee": high}, None

    return _stub


def _stub_unavailable_oracle():
    async def _stub():
        return None, "mempool unreachable"

    return _stub


# ─── Plan endpoint ────────────────────────────────────────────────────


class TestPlanEndpoint:
    @pytest.mark.asyncio
    async def test_returns_plan_and_token(self, dashboard_client, monkeypatch):
        with patch(
            "app.dashboard.api.mempool_fee_service.get_recommended_fees",
            side_effect=_stub_fee_oracle(medium=10, high=15),
        ):
            resp = await dashboard_client.post(
                "/dashboard/api/channel-mix/plan",
                json={
                    "target_capacity_sats": 800_000,
                    "outbound_option": "balanced",
                    "peer_mix_mode": "recommended_diverse",
                },
            )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert "plan" in body and "plan_token" in body
        plan = body["plan"]
        # Recommended is always at least minimum (buffer is never negative).
        assert plan["recommended_sats"] >= plan["minimum_sats"]
        assert plan["per_channel"], "planner should have selected at least one peer"
        # Breakdown components sum to recommended.
        b = plan["breakdown"]
        derived_min = b["channel_capacity_sats"] + b["open_fees_sats"]
        derived_rec = (
            derived_min
            + b["close_reserve_sats"]
            + b["fee_spike_cushion_sats"]
            + b["future_channel_slot_sats"]
        )
        assert derived_min == plan["minimum_sats"]
        assert derived_rec == plan["recommended_sats"]

    @pytest.mark.asyncio
    async def test_warns_when_mempool_oracle_unavailable(self, dashboard_client):
        with patch(
            "app.dashboard.api.mempool_fee_service.get_recommended_fees",
            side_effect=_stub_unavailable_oracle(),
        ):
            resp = await dashboard_client.post(
                "/dashboard/api/channel-mix/plan",
                json={"target_capacity_sats": 800_000},
            )
        assert resp.status_code == 200, resp.text
        plan = resp.json()["plan"]
        warnings = plan["diagnostics"]["warnings"]
        # The planner must surface a warning so the wizard can show "we
        # couldn't read mempool fees" instead of silently overcharging
        # the user.
        assert any("mempool" in w.lower() or "fee" in w.lower() for w in warnings)

    @pytest.mark.asyncio
    async def test_fee_spike_grows_cushion(self, dashboard_client):
        """When high-priority feerate is well above medium, the fee-spike
        cushion's "delta-to-high" arm should dominate the floor."""
        with patch(
            "app.dashboard.api.mempool_fee_service.get_recommended_fees",
            side_effect=_stub_fee_oracle(medium=20, high=200),
        ):
            resp = await dashboard_client.post(
                "/dashboard/api/channel-mix/plan",
                json={"target_capacity_sats": 800_000},
            )
        plan = resp.json()["plan"]
        # cushion >= delta between high and medium open-fees.
        # 1 channel * 250 vbytes * (200 - 20) sat/vB = 45 000
        assert plan["breakdown"]["fee_spike_cushion_sats"] >= 45_000

    @pytest.mark.asyncio
    async def test_room_for_one_more_adds_future_slot(self, dashboard_client):
        from app.services.channel_mix_planner import FUTURE_CHANNEL_SLOT_SATS

        with patch(
            "app.dashboard.api.mempool_fee_service.get_recommended_fees",
            side_effect=_stub_fee_oracle(medium=10, high=15),
        ):
            resp = await dashboard_client.post(
                "/dashboard/api/channel-mix/plan",
                json={
                    "target_capacity_sats": 800_000,
                    "leave_room_for_one_more": True,
                },
            )
        plan = resp.json()["plan"]
        assert plan["breakdown"]["future_channel_slot_sats"] == FUTURE_CHANNEL_SLOT_SATS

    @pytest.mark.asyncio
    async def test_unauthenticated_request_rejected(self, dashboard_client):
        dashboard_client.cookies.delete(COOKIE_NAME)
        resp = await dashboard_client.post(
            "/dashboard/api/channel-mix/plan",
            json={"target_capacity_sats": 800_000},
        )
        assert resp.status_code in (401, 403)


# ─── Execute endpoint ────────────────────────────────────────────────


class TestExecuteEndpoint:
    @pytest.mark.asyncio
    async def test_rejects_tampered_token_with_plan_stale(self, dashboard_client):
        """Replaying the same inputs with a bogus plan_token must
        produce 409 plan_stale + a fresh plan body."""
        with patch(
            "app.dashboard.api.mempool_fee_service.get_recommended_fees",
            side_effect=_stub_fee_oracle(medium=10, high=15),
        ):
            resp = await dashboard_client.post(
                "/dashboard/api/channel-mix/execute",
                json={
                    "target_capacity_sats": 800_000,
                    "outbound_option": "balanced",
                    "peer_mix_mode": "recommended_diverse",
                    "plan_token": "not-a-real-token-but-fits-length",
                },
            )
        assert resp.status_code == 409, resp.text
        body = resp.json()
        assert body["detail"]["code"] == "plan_stale"
        # A fresh plan + token come back so the dashboard can rebuild
        # the preview without a second round-trip.
        assert body["detail"]["plan"]["per_channel"]
        assert body["detail"]["plan_token"]

    @pytest.mark.asyncio
    async def test_happy_path_persists_run_and_enqueues_task(self, dashboard_client):
        """Plan → execute with the same inputs persists a
        ``ChannelMixRun`` and schedules the executor task."""
        with patch(
            "app.dashboard.api.mempool_fee_service.get_recommended_fees",
            side_effect=_stub_fee_oracle(medium=10, high=15),
        ), patch(
            "app.tasks.channel_mix_tasks.process_channel_mix_run.delay"
        ) as mock_delay:
            plan_resp = await dashboard_client.post(
                "/dashboard/api/channel-mix/plan",
                json={
                    "target_capacity_sats": 800_000,
                    "outbound_option": "balanced",
                },
            )
            assert plan_resp.status_code == 200, plan_resp.text
            plan_body = plan_resp.json()

            exec_resp = await dashboard_client.post(
                "/dashboard/api/channel-mix/execute",
                json={
                    "target_capacity_sats": 800_000,
                    "outbound_option": "balanced",
                    "plan_token": plan_body["plan_token"],
                },
            )
        assert exec_resp.status_code == 201, exec_resp.text
        exec_body = exec_resp.json()
        assert exec_body["state"] == "queued"
        assert exec_body["mix_run_id"]
        mock_delay.assert_called_once_with(exec_body["mix_run_id"])

    @pytest.mark.asyncio
    async def test_repeat_execute_with_same_token_is_idempotent(
        self, dashboard_client,
    ):
        """A retried execute call carrying the same plan_token must
        resolve to the same ``ChannelMixRun`` row — not a duplicate that
        would open every channel twice."""
        with patch(
            "app.dashboard.api.mempool_fee_service.get_recommended_fees",
            side_effect=_stub_fee_oracle(medium=10, high=15),
        ), patch(
            "app.tasks.channel_mix_tasks.process_channel_mix_run.delay"
        ) as mock_delay:
            plan_resp = await dashboard_client.post(
                "/dashboard/api/channel-mix/plan",
                json={
                    "target_capacity_sats": 800_000,
                    "outbound_option": "balanced",
                },
            )
            plan_body = plan_resp.json()
            execute_body = {
                "target_capacity_sats": 800_000,
                "outbound_option": "balanced",
                "plan_token": plan_body["plan_token"],
            }
            first = await dashboard_client.post(
                "/dashboard/api/channel-mix/execute", json=execute_body,
            )
            second = await dashboard_client.post(
                "/dashboard/api/channel-mix/execute", json=execute_body,
            )
        # First call creates the run → 201; replay matches an existing
        # row, so the response is a retrieval → 200.
        assert first.status_code == 201
        assert second.status_code == 200
        assert first.json()["mix_run_id"] == second.json()["mix_run_id"]
        # Only the first call should have enqueued the executor task.
        mock_delay.assert_called_once_with(first.json()["mix_run_id"])

    @pytest.mark.asyncio
    async def test_empty_plan_rejected_with_400(self, dashboard_client, monkeypatch):
        """When the catalog is empty (e.g. non-mainnet network), the
        planner produces zero per-channel slots; execute must reject
        with 400 ``empty_plan`` instead of persisting an empty run."""
        from app.core.config import settings

        # Switch the network to non-mainnet so the catalog returns
        # nothing — the planner's primary "no catalog peers fit" path.
        monkeypatch.setattr(settings, "bitcoin_network", "regtest")
        with patch(
            "app.dashboard.api.mempool_fee_service.get_recommended_fees",
            side_effect=_stub_fee_oracle(medium=10, high=15),
        ), patch(
            "app.tasks.channel_mix_tasks.process_channel_mix_run.delay"
        ) as mock_delay:
            plan_resp = await dashboard_client.post(
                "/dashboard/api/channel-mix/plan",
                json={"target_capacity_sats": 800_000},
            )
            assert plan_resp.status_code == 200, plan_resp.text
            plan_body = plan_resp.json()
            assert plan_body["plan"]["per_channel"] == []

            exec_resp = await dashboard_client.post(
                "/dashboard/api/channel-mix/execute",
                json={
                    "target_capacity_sats": 800_000,
                    "plan_token": plan_body["plan_token"],
                },
            )
        assert exec_resp.status_code == 400, exec_resp.text
        assert exec_resp.json()["detail"]["code"] == "empty_plan"
        # No run row should have been persisted; no executor task
        # enqueued.
        mock_delay.assert_not_called()


# ─── Bootstrap (capital-efficient inbound) endpoints ────────────────


class TestBootstrapEndpoints:
    """End-to-end coverage of the bootstrap strategy through the real
    HTTP layer: request-model acceptance, ``BootstrapPlan`` JSON
    serialization (nested peer), plan-token round-trip, run creation
    with bootstrap fields, the one-active-run guard, stop, status
    rollup, and the Boltz-unavailable gate."""

    @staticmethod
    def _oracle():
        return patch(
            "app.services.mempool_fee_service.mempool_fee_service.get_recommended_fees",
            side_effect=_stub_fee_oracle(medium=10, high=15),
        )

    @staticmethod
    def _boltz(available: bool):
        return patch(
            "app.api.channel_mix._resolve_boltz_available",
            new_callable=AsyncMock,
            return_value=available,
        )

    @pytest.mark.asyncio
    async def test_bootstrap_plan_returns_schedule(self, dashboard_client):
        with self._oracle(), self._boltz(True):
            resp = await dashboard_client.post(
                "/dashboard/api/channel-mix/plan",
                json={
                    "mode": "bootstrap",
                    "bootstrap_input_kind": "target",
                    "bootstrap_target_inbound_sats": 1_500_000,
                },
            )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["mode"] == "bootstrap"
        plan = body["plan"]
        assert plan["rounds"], "expected a non-empty bootstrap schedule"
        assert plan["expected_total_inbound_sats"] >= 1_500_000
        # The recycling win: the deposit needed is below the target.
        assert plan["initial_deposit_sats"] < 1_500_000
        # Nested SmallChannelPeer survives the asdict → JSON projection.
        assert plan["rounds"][0]["peer"]["alias"]
        assert body["plan_token"]

    @pytest.mark.asyncio
    async def test_bootstrap_execute_then_stop_and_status(
        self, dashboard_client, db_engine
    ):
        import uuid as _uuid

        from sqlalchemy import select

        from app.models.channel_mix_run import ChannelMixRun

        inputs = {
            "mode": "bootstrap",
            "bootstrap_input_kind": "target",
            "bootstrap_target_inbound_sats": 1_500_000,
        }
        with self._oracle(), self._boltz(True), patch(
            "app.tasks.channel_mix_tasks.process_channel_mix_run.delay"
        ) as mock_delay:
            plan_resp = await dashboard_client.post(
                "/dashboard/api/channel-mix/plan", json=inputs
            )
            plan_body = plan_resp.json()
            exec_resp = await dashboard_client.post(
                "/dashboard/api/channel-mix/execute",
                json={**inputs, "plan_token": plan_body["plan_token"]},
            )
        assert exec_resp.status_code == 201, exec_resp.text
        eb = exec_resp.json()
        assert eb["mode"] == "bootstrap"
        assert eb["state"] == "queued"
        mock_delay.assert_called_once_with(eb["mix_run_id"])

        # The persisted row is a bootstrap run with no pre-materialized
        # channels and the runtime params the executor needs.
        session_factory = async_sessionmaker(db_engine, expire_on_commit=False)
        async with session_factory() as s:
            run = (
                await s.execute(
                    select(ChannelMixRun).where(
                        ChannelMixRun.id == _uuid.UUID(eb["mix_run_id"])
                    )
                )
            ).scalar_one()
            assert run.mode == "bootstrap"
            assert run.target_inbound_sats == 1_500_000
            assert run.channels == []
            assert run.bootstrap_params and run.bootstrap_params["network"]

        # Stop control flips stop_requested.
        stop_resp = await dashboard_client.post(
            f"/dashboard/api/channel-mix/runs/{eb['mix_run_id']}/stop"
        )
        assert stop_resp.status_code == 200, stop_resp.text
        assert stop_resp.json()["stop_requested"] is True

        # Status exposes the bootstrap rollup shape.
        status_resp = await dashboard_client.get(
            f"/dashboard/api/channel-mix/runs/{eb['mix_run_id']}"
        )
        sb = status_resp.json()
        assert sb["mode"] == "bootstrap"
        assert sb["summary"]["mode"] == "bootstrap"
        assert sb["stop_requested"] is True
        assert sb["target_inbound_sats"] == 1_500_000

    @pytest.mark.asyncio
    async def test_one_active_run_guard_returns_existing(self, dashboard_client):
        """A second run can't start while one is non-terminal — the
        execute call returns the in-flight run (plan §6a)."""
        with self._oracle(), self._boltz(True), patch(
            "app.tasks.channel_mix_tasks.process_channel_mix_run.delay"
        ):
            plan_a = (
                await dashboard_client.post(
                    "/dashboard/api/channel-mix/plan",
                    json={"mode": "bootstrap", "bootstrap_target_inbound_sats": 1_500_000},
                )
            ).json()
            first = await dashboard_client.post(
                "/dashboard/api/channel-mix/execute",
                json={
                    "mode": "bootstrap",
                    "bootstrap_target_inbound_sats": 1_500_000,
                    "plan_token": plan_a["plan_token"],
                },
            )
            # A different plan (parallel this time) while one is active.
            plan_b = (
                await dashboard_client.post(
                    "/dashboard/api/channel-mix/plan",
                    json={"target_capacity_sats": 800_000},
                )
            ).json()
            second = await dashboard_client.post(
                "/dashboard/api/channel-mix/execute",
                json={"target_capacity_sats": 800_000, "plan_token": plan_b["plan_token"]},
            )
        assert first.status_code == 201
        assert second.status_code == 200, second.text
        sb = second.json()
        assert sb.get("resumed") is True
        assert sb["mix_run_id"] == first.json()["mix_run_id"]

    @pytest.mark.asyncio
    async def test_bootstrap_execute_same_token_is_idempotent(self, dashboard_client):
        """A retried bootstrap execute with the same plan_token resolves to
        the same run (digest idempotency), not a duplicate loop."""
        inputs = {"mode": "bootstrap", "bootstrap_target_inbound_sats": 1_500_000}
        with self._oracle(), self._boltz(True), patch(
            "app.tasks.channel_mix_tasks.process_channel_mix_run.delay"
        ) as mock_delay:
            plan_body = (
                await dashboard_client.post(
                    "/dashboard/api/channel-mix/plan", json=inputs
                )
            ).json()
            body = {**inputs, "plan_token": plan_body["plan_token"]}
            first = await dashboard_client.post(
                "/dashboard/api/channel-mix/execute", json=body
            )
            second = await dashboard_client.post(
                "/dashboard/api/channel-mix/execute", json=body
            )
        assert first.status_code == 201
        assert second.status_code == 200
        assert first.json()["mix_run_id"] == second.json()["mix_run_id"]
        mock_delay.assert_called_once_with(first.json()["mix_run_id"])

    @pytest.mark.asyncio
    async def test_bootstrap_not_offered_when_boltz_unavailable(self, dashboard_client):
        with self._oracle(), self._boltz(False):
            resp = await dashboard_client.post(
                "/dashboard/api/channel-mix/plan",
                json={"mode": "bootstrap", "bootstrap_target_inbound_sats": 1_500_000},
            )
        assert resp.status_code == 200, resp.text
        plan = resp.json()["plan"]
        assert plan["rounds"] == []
        assert any("Boltz" in w for w in plan["diagnostics"]["warnings"])


# ─── Onboarding funding recommender endpoint ────────────────────────


class TestOnboardingRecommend:
    """End-to-end coverage of POST /onboarding/recommend: each use case maps
    to the right strategy/numbers via the real planners."""

    @staticmethod
    def _oracle():
        return patch(
            "app.services.mempool_fee_service.mempool_fee_service.get_recommended_fees",
            side_effect=_stub_fee_oracle(medium=10, high=15),
        )

    @staticmethod
    def _boltz(available: bool):
        return patch(
            "app.api.channel_mix._resolve_boltz_available",
            new_callable=AsyncMock,
            return_value=available,
        )

    async def _post(self, client, body):
        return await client.post("/dashboard/api/onboarding/recommend", json=body)

    @pytest.mark.asyncio
    async def test_spend_recommends_pure_outbound_parallel(self, dashboard_client):
        with self._oracle(), self._boltz(True):
            resp = await self._post(
                dashboard_client, {"use_case": "spend", "scale_sats": 500_000}
            )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        p = body["primary"]
        assert p["strategy"] == "parallel"
        assert p["outbound_option"] == "custom"   # pure outbound (0% inbound)
        assert p["deposit_sats"] >= 500_000
        assert body["alternative"] is None

    @pytest.mark.asyncio
    async def test_both_recommends_balanced_parallel(self, dashboard_client):
        with self._oracle(), self._boltz(True):
            resp = await self._post(
                dashboard_client, {"use_case": "both", "scale_sats": 800_000}
            )
        p = resp.json()["primary"]
        assert p["strategy"] == "parallel"
        assert p["outbound_option"] == "balanced"

    @pytest.mark.asyncio
    async def test_explore_uses_small_starter(self, dashboard_client):
        from app.services.onboarding_recommender import EXPLORE_STARTER_SATS

        with self._oracle(), self._boltz(True):
            resp = await self._post(dashboard_client, {"use_case": "explore"})
        p = resp.json()["primary"]
        assert p["strategy"] == "parallel"
        assert p["target_capacity_sats"] == EXPLORE_STARTER_SATS

    @pytest.mark.asyncio
    async def test_receive_large_defaults_to_efficient_with_fast_alternative(
        self, dashboard_client
    ):
        with self._oracle(), self._boltz(True):
            resp = await self._post(
                dashboard_client, {"use_case": "receive", "scale_sats": 2_000_000}
            )
        body = resp.json()
        assert body["primary"]["strategy"] == "bootstrap"
        assert body["primary"]["deposit_sats"] < 2_000_000  # the recycling win
        assert body["primary"]["estimate"]["rounds"] >= 1
        assert body["alternative"]["strategy"] == "parallel"

    @pytest.mark.asyncio
    async def test_receive_falls_back_to_fast_when_boltz_down(self, dashboard_client):
        with self._oracle(), self._boltz(False):
            resp = await self._post(
                dashboard_client, {"use_case": "receive", "scale_sats": 2_000_000}
            )
        body = resp.json()
        assert body["primary"]["strategy"] == "parallel"   # direct/fast
        assert body["alternative"] is None
        assert any("Boltz" in w for w in body["warnings"])

    @pytest.mark.asyncio
    async def test_below_floor_scale_is_raised_with_a_note(self, dashboard_client):
        with self._oracle(), self._boltz(True):
            resp = await self._post(
                dashboard_client, {"use_case": "spend", "scale_sats": 5_000}
            )
        body = resp.json()
        assert body["primary"]["strategy"] == "parallel"
        assert any("minimum" in w.lower() for w in body["warnings"])


# ─── Pydantic Literal-type validation on the dashboard wrapper ──────


class TestDashboardInputValidation:
    """The dashboard wrapper pins ``outbound_option`` and
    ``peer_mix_mode`` to the planner's Literal types so a garbage value
    surfaces as a 422 at the API boundary, never silently collapsing
    onto the planner's default branch."""

    @pytest.mark.asyncio
    async def test_garbage_outbound_option_rejected_with_422(self, dashboard_client):
        with patch(
            "app.dashboard.api.mempool_fee_service.get_recommended_fees",
            side_effect=_stub_fee_oracle(medium=10, high=15),
        ):
            resp = await dashboard_client.post(
                "/dashboard/api/channel-mix/plan",
                json={
                    "target_capacity_sats": 800_000,
                    "outbound_option": "not-a-real-option",
                },
            )
        assert resp.status_code == 422, resp.text
        # FastAPI's validation error mentions the offending field name.
        body = resp.json()
        offending_fields = {
            "/".join(str(p) for p in err.get("loc", []))
            for err in body.get("detail", [])
            if isinstance(err, dict)
        }
        assert any("outbound_option" in f for f in offending_fields), body

    @pytest.mark.asyncio
    async def test_garbage_peer_mix_mode_rejected_with_422(self, dashboard_client):
        with patch(
            "app.dashboard.api.mempool_fee_service.get_recommended_fees",
            side_effect=_stub_fee_oracle(medium=10, high=15),
        ):
            resp = await dashboard_client.post(
                "/dashboard/api/channel-mix/plan",
                json={
                    "target_capacity_sats": 800_000,
                    "peer_mix_mode": "made-up-mode",
                },
            )
        assert resp.status_code == 422, resp.text
        body = resp.json()
        offending_fields = {
            "/".join(str(p) for p in err.get("loc", []))
            for err in body.get("detail", [])
            if isinstance(err, dict)
        }
        assert any("peer_mix_mode" in f for f in offending_fields), body


# ─── Run-status endpoint + rollup ───────────────────────────────────


class TestRunStatusEndpoint:
    @pytest.mark.asyncio
    async def test_returns_404_for_unknown_run(self, dashboard_client):
        # An arbitrary UUID — never persisted, so the endpoint must 404.
        resp = await dashboard_client.get(
            "/dashboard/api/channel-mix/runs/00000000-0000-0000-0000-000000000000"
        )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_partial_failure_state_surfaces_through_status(
        self, dashboard_client, db_engine,
    ):
        """A run with one open_active + one open_failed channel rolls up
        to ``partial_failure``; the GET endpoint must reflect that."""
        from app.models.channel_mix_run import (
            ChannelMixRun,
            ChannelMixRunState,
            make_channel_entry,
        )
        from app.dashboard import DASHBOARD_KEY_ID

        session_factory = async_sessionmaker(db_engine, expire_on_commit=False)
        async with session_factory() as session:
            entries = [
                make_channel_entry(
                    peer_alias="alpha",
                    peer_pubkey="00" * 33,
                    peer_host="alpha:9735",
                    capacity_sats=400_000,
                    push_sat=0,
                    expected_inbound_seed_sats=0,
                    inbound_seed_strategy="push_only",
                ),
                make_channel_entry(
                    peer_alias="beta",
                    peer_pubkey="11" * 33,
                    peer_host="beta:9735",
                    capacity_sats=400_000,
                    push_sat=0,
                    expected_inbound_seed_sats=0,
                    inbound_seed_strategy="push_only",
                ),
            ]
            entries[0]["open_state"] = "open_active"
            entries[0]["seed_state"] = "skipped"
            entries[1]["open_state"] = "open_failed"
            entries[1]["open_error"] = "peer rejected open"
            entries[1]["seed_state"] = "skipped"
            run = ChannelMixRun(
                api_key_id=DASHBOARD_KEY_ID,
                plan_token_digest="abcd" * 16,  # 64-char placeholder
                state=ChannelMixRunState.PARTIAL_FAILURE,
                minimum_sats=800_000,
                recommended_sats=850_000,
                channels=entries,
                warnings=[],
            )
            session.add(run)
            await session.commit()
            await session.refresh(run)
            run_id = str(run.id)

        resp = await dashboard_client.get(
            f"/dashboard/api/channel-mix/runs/{run_id}"
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["state"] == "partial_failure"
        assert body["summary"]["channels_total"] == 2
        assert body["summary"]["channels_active"] == 1
        assert body["summary"]["channels_failed"] == 1
        # The per-channel error message reaches the dashboard so the
        # operator can see why a slot failed.
        failed = [c for c in body["channels"] if c["open_state"] == "open_failed"]
        assert failed and failed[0]["open_error"] == "peer rejected open"
