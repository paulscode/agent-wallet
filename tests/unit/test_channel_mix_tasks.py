# SPDX-License-Identifier: MIT
"""Unit tests for the channel-mix Celery executor.

Drives one run forward against stubbed ``lnd_service`` / ``boltz_service``
shims so the per-channel state machine can be exercised without a real
node or swap provider. The focus is on the transitions the unit-test
planner suite can't reach end-to-end:

* a failed open promotes the seed slot to ``skipped`` so the run-wide
  rollup terminates (regression test for the bug where seed_state stayed
  at ``queued`` forever),
* the run-wide rollup correctly distinguishes COMPLETE from
  PARTIAL_FAILURE.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker

from app.models.channel_mix_run import (
    ChannelMixRun,
    ChannelMixRunState,
    make_channel_entry,
)


class _FakeLnd:
    """Drives ``_open_one_channel`` deterministically per-pubkey.

    The behaviour map is keyed on the peer pubkey so different channels
    in the same run can succeed and fail independently — exactly the
    setup needed for the partial-failure rollup test.
    """

    def __init__(self, behaviour: dict[str, str]):
        # behaviour[pubkey] in {"open_ok", "connect_fail", "open_fail"}
        self.behaviour = behaviour
        self.active_pubkeys: list[str] = []

    async def connect_peer(self, pubkey: str, host: str):
        outcome = self.behaviour.get(pubkey, "open_ok")
        if outcome == "connect_fail":
            return False, "peer unreachable"
        return True, None

    async def open_channel(
        self,
        node_pubkey_hex: str,
        local_funding_amount: int,
        sat_per_vbyte: int | None = None,
        push_sat: int = 0,
        private: bool = False,
    ):
        outcome = self.behaviour.get(node_pubkey_hex, "open_ok")
        if outcome == "open_fail":
            return None, "funding broadcast rejected"
        # Successful open — return the real LND-service result shape.
        self.active_pubkeys.append(node_pubkey_hex)
        return ({"funding_txid": "ab" * 32, "output_index": 0}, None)

    async def get_channels(self):
        return (
            [
                {
                    "remote_pubkey": pk,
                    "channel_point": "ab" * 32 + ":0",
                    "active": True,
                }
                for pk in self.active_pubkeys
            ],
            None,
        )

    async def get_pending_channels_detail(self):
        # Opens in these tests promote straight to active, so nothing is
        # pending — but the auto-resolution backstop (recovery plan §3)
        # may probe, so answer cleanly.
        return [], None

    async def new_address(self, address_type: str = "p2wkh"):
        return {"address": "bc1qstub"}, None


@pytest_asyncio.fixture
async def session_factory(db_engine):
    return async_sessionmaker(db_engine, expire_on_commit=False)


def _digest(seed: str) -> str:
    """64-char hex stand-in for the plan-token digest these tests don't
    care about. Each call returns a fresh value so independent tests
    can persist multiple runs without violating the UNIQUE constraint."""
    import hashlib
    import uuid as _uuid

    return hashlib.sha256(f"{seed}-{_uuid.uuid4()}".encode()).hexdigest()


def _two_channel_run() -> ChannelMixRun:
    entries = [
        make_channel_entry(
            peer_alias="alpha",
            peer_pubkey="aa" * 33,
            peer_host="alpha:9735",
            capacity_sats=400_000,
            push_sat=0,
            expected_inbound_seed_sats=100_000,
            inbound_seed_strategy="boltz_reverse",
        ),
        make_channel_entry(
            peer_alias="beta",
            peer_pubkey="bb" * 33,
            peer_host="beta:9735",
            capacity_sats=400_000,
            push_sat=0,
            expected_inbound_seed_sats=100_000,
            inbound_seed_strategy="boltz_reverse",
        ),
    ]
    return ChannelMixRun(
        api_key_id=UUID("00000000-0000-0000-0000-da5b0a4d0000"),
        plan_token_digest=_digest("two-channel-run"),
        state=ChannelMixRunState.QUEUED,
        minimum_sats=800_000,
        recommended_sats=900_000,
        channels=entries,
        warnings=[],
    )


class TestExecutorRollup:
    @pytest.mark.asyncio
    async def test_failed_open_promotes_seed_to_skipped(
        self, monkeypatch, session_factory,
    ):
        """When an open fails, the executor must mark the seed slot
        ``skipped`` so the run can reach a terminal state."""
        from app.tasks import channel_mix_tasks as cmix

        async with session_factory() as session:
            run = _two_channel_run()
            # Force both opens to fail so we can verify the seed
            # promotion without dependent state.
            session.add(run)
            await session.commit()
            await session.refresh(run)
            run_id = run.id

        fake_lnd = _FakeLnd({"aa" * 33: "open_fail", "bb" * 33: "open_fail"})
        monkeypatch.setattr(
            "app.services.lnd_service.lnd_service", fake_lnd, raising=False,
        )

        # Patch ``get_db_context`` so the executor uses our session
        # factory.
        from contextlib import asynccontextmanager

        @asynccontextmanager
        async def fake_ctx():
            async with session_factory() as s:
                yield s

        monkeypatch.setattr(
            "app.tasks.channel_mix_tasks.get_db_context", fake_ctx, raising=False,
        )

        await cmix._run_one_mix(run_id)

        async with session_factory() as session:
            row = (
                await session.execute(
                    select(ChannelMixRun).where(ChannelMixRun.id == run_id)
                )
            ).scalar_one()
        # Both opens failed → run rolls up to partial_failure (zero
        # active + at least one failed).
        assert row.state == ChannelMixRunState.PARTIAL_FAILURE
        for ch in row.channels:
            assert ch["open_state"] == "open_failed"
            # The bug being guarded against: seed_state would stay at
            # "queued" so the run could never terminate.
            assert ch["seed_state"] == "skipped"

    @pytest.mark.asyncio
    async def test_mixed_open_results_yield_partial_failure(
        self, monkeypatch, session_factory,
    ):
        """One open succeeds, one fails → partial_failure with the
        successful channel reaching open_active + seeded."""
        from app.tasks import channel_mix_tasks as cmix

        # Override the Boltz reverse-swap path so seeded channels
        # advance without a real swap provider.
        class _FakeBoltz:
            async def create_reverse_swap(self, db, **kwargs):
                class _Swap:
                    id = UUID("11111111-1111-1111-1111-111111111111")

                return _Swap(), None

        monkeypatch.setattr(
            "app.services.boltz_service.boltz_service",
            _FakeBoltz(),
            raising=False,
        )

        async with session_factory() as session:
            run = _two_channel_run()
            session.add(run)
            await session.commit()
            await session.refresh(run)
            run_id = run.id

        fake_lnd = _FakeLnd({"aa" * 33: "open_ok", "bb" * 33: "open_fail"})
        monkeypatch.setattr(
            "app.services.lnd_service.lnd_service", fake_lnd, raising=False,
        )

        from contextlib import asynccontextmanager

        @asynccontextmanager
        async def fake_ctx():
            async with session_factory() as s:
                yield s

        monkeypatch.setattr(
            "app.tasks.channel_mix_tasks.get_db_context", fake_ctx, raising=False,
        )

        await cmix._run_one_mix(run_id)

        async with session_factory() as session:
            row = (
                await session.execute(
                    select(ChannelMixRun).where(ChannelMixRun.id == run_id)
                )
            ).scalar_one()
        assert row.state == ChannelMixRunState.PARTIAL_FAILURE
        # First channel: open succeeded, became active, then seeded.
        assert row.channels[0]["open_state"] == "open_active"
        assert row.channels[0]["seed_state"] == "seeded"
        # Second channel: open failed, seed promoted to skipped.
        assert row.channels[1]["open_state"] == "open_failed"
        assert row.channels[1]["seed_state"] == "skipped"


def _one_channel_run() -> ChannelMixRun:
    import hashlib
    import uuid as _uuid

    entry = make_channel_entry(
        peer_alias="alpha",
        peer_pubkey="aa" * 33,
        peer_host="alpha:9735",
        capacity_sats=400_000,
        push_sat=0,
        expected_inbound_seed_sats=0,
        inbound_seed_strategy="push_only",
    )
    return ChannelMixRun(
        api_key_id=UUID("00000000-0000-0000-0000-da5b0a4d0000"),
        plan_token_digest=hashlib.sha256(_uuid.uuid4().bytes).hexdigest(),
        state=ChannelMixRunState.QUEUED,
        minimum_sats=400_000,
        recommended_sats=400_000,
        channels=[entry],
        warnings=[],
    )


class _StuckParallelLnd:
    """Open succeeds but the channel never promotes to active; the pending
    view can be steered to report it force-closing (confirmed-dead) or
    clean (still pending)."""

    def __init__(self, *, dead: bool):
        self.dead = dead
        self.active_pubkeys: list[str] = []

    async def connect_peer(self, pubkey, host):
        return True, None

    async def open_channel(self, node_pubkey_hex, local_funding_amount,
                           sat_per_vbyte=None, push_sat=0, private=False):
        self.active_pubkeys.append(node_pubkey_hex)
        return ({"funding_txid": "ab" * 32, "output_index": 0}, None)

    async def get_channels(self):
        # Never report the channel active → it stays open_pending.
        return [], None

    async def get_pending_channels_detail(self):
        if self.dead:
            return ([{"type": "force_closing",
                      "channel_point": "ab" * 32 + ":0",
                      "remote_node_pub": "aa" * 33}], None)
        return ([{"type": "pending_open",
                  "channel_point": "ab" * 32 + ":0",
                  "remote_node_pub": "aa" * 33}], None)

    async def new_address(self, address_type: str = "p2wkh"):
        return {"address": "bc1qstub"}, None


class TestParallelAutoResolution:
    """A parallel channel wedged in open_pending is auto-failed when
    confirmed-dead or past the per-wait hard backstop (recovery plan §3)."""

    @pytest.mark.asyncio
    async def test_confirmed_dead_parallel_channel_fails(
        self, monkeypatch, session_factory
    ):
        from contextlib import asynccontextmanager

        from app.tasks import channel_mix_tasks as cmix

        async with session_factory() as s:
            run = _one_channel_run()
            s.add(run)
            await s.commit()
            await s.refresh(run)
            run_id = run.id

        monkeypatch.setattr(
            "app.services.lnd_service.lnd_service",
            _StuckParallelLnd(dead=True), raising=False,
        )

        @asynccontextmanager
        async def fake_ctx():
            async with session_factory() as s:
                yield s

        monkeypatch.setattr(
            "app.tasks.channel_mix_tasks.get_db_context", fake_ctx, raising=False,
        )

        # Tick 1 opens the channel (→ open_pending). The confirmed-dead
        # probe runs BEFORE the open step, so a just-opened channel is
        # deliberately NOT checked on the same tick (LND may not have
        # registered the funding tx yet). Tick 2 detects it force-closing.
        await cmix._run_one_mix(run_id)
        async with session_factory() as s:
            row = (
                await s.execute(select(ChannelMixRun).where(ChannelMixRun.id == run_id))
            ).scalar_one()
        assert row.channels[0]["open_state"] == "open_pending"

        await cmix._run_one_mix(run_id)
        async with session_factory() as s:
            row = (
                await s.execute(select(ChannelMixRun).where(ChannelMixRun.id == run_id))
            ).scalar_one()
        assert row.channels[0]["open_state"] == "open_failed"
        assert row.state == ChannelMixRunState.PARTIAL_FAILURE
        assert row.completed_at is not None

    @pytest.mark.asyncio
    async def test_slow_parallel_channel_not_failed(
        self, monkeypatch, session_factory
    ):
        from contextlib import asynccontextmanager

        from app.tasks import channel_mix_tasks as cmix

        async with session_factory() as s:
            run = _one_channel_run()
            s.add(run)
            await s.commit()
            await s.refresh(run)
            run_id = run.id

        monkeypatch.setattr(
            "app.services.lnd_service.lnd_service",
            _StuckParallelLnd(dead=False), raising=False,
        )

        @asynccontextmanager
        async def fake_ctx():
            async with session_factory() as s:
                yield s

        monkeypatch.setattr(
            "app.tasks.channel_mix_tasks.get_db_context", fake_ctx, raising=False,
        )

        await cmix._run_one_mix(run_id)

        async with session_factory() as s:
            row = (
                await s.execute(select(ChannelMixRun).where(ChannelMixRun.id == run_id))
            ).scalar_one()
        # Still pending (alive-but-slow), fresh wait → not failed.
        assert row.channels[0]["open_state"] == "open_pending"
        assert row.state == ChannelMixRunState.IN_PROGRESS

    @pytest.mark.asyncio
    async def test_hard_timeout_fails_parallel_channel(
        self, monkeypatch, session_factory
    ):
        """A parallel open_pending wait older than the per-wait backstop is
        failed even when the channel isn't confirmed-dead."""
        from contextlib import asynccontextmanager
        from datetime import datetime, timedelta, timezone

        from app.services.channel_mix_planner import (
            CHANNEL_MIX_WAIT_HARD_TIMEOUT_MINUTES,
        )
        from app.tasks import channel_mix_tasks as cmix

        async with session_factory() as s:
            run = _one_channel_run()
            # Pre-stamp the channel as already open_pending with an ancient
            # wait, so the backstop fires this tick.
            entry = run.channels[0]
            entry["open_state"] = "open_pending"
            entry["open_txid"] = "ab" * 32
            entry["open_output_index"] = 0
            entry["open_pending_since"] = (
                datetime.now(timezone.utc)
                - timedelta(minutes=CHANNEL_MIX_WAIT_HARD_TIMEOUT_MINUTES + 60)
            ).isoformat()
            run.channels[0] = entry
            s.add(run)
            await s.commit()
            await s.refresh(run)
            run_id = run.id

        # Channel is alive-but-slow (pending_open) → only the timeout fails it.
        monkeypatch.setattr(
            "app.services.lnd_service.lnd_service",
            _StuckParallelLnd(dead=False), raising=False,
        )

        @asynccontextmanager
        async def fake_ctx():
            async with session_factory() as s:
                yield s

        monkeypatch.setattr(
            "app.tasks.channel_mix_tasks.get_db_context", fake_ctx, raising=False,
        )

        await cmix._run_one_mix(run_id)

        async with session_factory() as s:
            row = (
                await s.execute(select(ChannelMixRun).where(ChannelMixRun.id == run_id))
            ).scalar_one()
        assert row.channels[0]["open_state"] == "open_failed"
        assert row.state == ChannelMixRunState.PARTIAL_FAILURE


class TestExecutorAuditLog:
    """The executor writes one ``channel_mix_open`` row to the audit log
    per channel open attempt — both success and failure paths — so the
    audit chain has visibility into executor-driven channel opens
    matching the coverage that hand-driven ``/channel/open`` calls
    already enjoy."""

    @pytest.mark.asyncio
    async def test_audit_rows_emitted_for_open_and_failure(
        self, monkeypatch, session_factory,
    ):
        from contextlib import asynccontextmanager

        from app.models.audit_log import AuditLog
        from app.tasks import channel_mix_tasks as cmix

        class _FakeBoltz:
            async def create_reverse_swap(self, db, **kwargs):
                class _Swap:
                    id = UUID("22222222-2222-2222-2222-222222222222")

                return _Swap(), None

        monkeypatch.setattr(
            "app.services.boltz_service.boltz_service",
            _FakeBoltz(),
            raising=False,
        )

        async with session_factory() as session:
            run = _two_channel_run()
            session.add(run)
            await session.commit()
            await session.refresh(run)
            run_id = run.id

        # One channel opens successfully, the other fails — exercises
        # both the success and the failure audit paths.
        fake_lnd = _FakeLnd({"aa" * 33: "open_ok", "bb" * 33: "open_fail"})
        monkeypatch.setattr(
            "app.services.lnd_service.lnd_service", fake_lnd, raising=False,
        )

        @asynccontextmanager
        async def fake_ctx():
            async with session_factory() as s:
                yield s

        monkeypatch.setattr(
            "app.tasks.channel_mix_tasks.get_db_context", fake_ctx, raising=False,
        )

        await cmix._run_one_mix(run_id)

        async with session_factory() as session:
            audit_rows = list(
                (
                    await session.execute(
                        select(AuditLog).where(AuditLog.action == "channel_mix_open")
                    )
                )
                .scalars()
                .all()
            )

        # Exactly two audit rows — one per channel-open attempt.
        assert len(audit_rows) == 2
        by_pubkey = {
            row.details.get("peer_pubkey"): row for row in audit_rows
        }
        # Success row — capacity reported, no error.
        ok_row = by_pubkey["aa" * 33]
        assert ok_row.success is True
        assert ok_row.error_message is None
        assert ok_row.amount_sats == 400_000
        assert ok_row.details["mix_run_id"] == str(run_id)
        # Failure row — error string captured, success=False.
        fail_row = by_pubkey["bb" * 33]
        assert fail_row.success is False
        assert "open failed" in (fail_row.error_message or "").lower()
        assert fail_row.amount_sats == 400_000
        assert fail_row.details["mix_run_id"] == str(run_id)


class TestRecoverChannelMixRuns:
    """The periodic ``recover_channel_mix_runs`` Celery-beat task picks
    up any run left in a non-terminal state after a worker crash and
    re-enqueues the executor. Terminal-state runs are skipped — they
    don't need driving forward."""

    @pytest.mark.asyncio
    async def test_re_enqueues_only_non_terminal_runs(
        self, monkeypatch, session_factory,
    ):
        from contextlib import asynccontextmanager
        from unittest.mock import patch

        from app.tasks import channel_mix_tasks as cmix

        # Persist one of each state. Only QUEUED + IN_PROGRESS should
        # be re-queued; COMPLETE, PARTIAL_FAILURE, and CANCELLED stay
        # put.
        queued = _two_channel_run()
        queued.state = ChannelMixRunState.QUEUED

        in_progress = _two_channel_run()
        in_progress.plan_token_digest = _digest("recover-in-progress")
        in_progress.state = ChannelMixRunState.IN_PROGRESS

        complete = _two_channel_run()
        complete.plan_token_digest = _digest("recover-complete")
        complete.state = ChannelMixRunState.COMPLETE

        partial = _two_channel_run()
        partial.plan_token_digest = _digest("recover-partial")
        partial.state = ChannelMixRunState.PARTIAL_FAILURE

        cancelled = _two_channel_run()
        cancelled.plan_token_digest = _digest("recover-cancelled")
        cancelled.state = ChannelMixRunState.CANCELLED

        async with session_factory() as session:
            session.add_all([queued, in_progress, complete, partial, cancelled])
            await session.commit()
            await session.refresh(queued)
            await session.refresh(in_progress)
            queued_id = str(queued.id)
            in_progress_id = str(in_progress.id)

        @asynccontextmanager
        async def fake_ctx():
            async with session_factory() as s:
                yield s

        monkeypatch.setattr(
            "app.tasks.channel_mix_tasks.get_db_context", fake_ctx, raising=False,
        )

        with patch(
            "app.tasks.channel_mix_tasks.process_channel_mix_run.delay"
        ) as mock_delay:
            result = await cmix._run_recover_mix_runs()

        assert result == {"recovered": 2}
        # Exactly the two non-terminal runs were re-queued.
        delayed_ids = {call.args[0] for call in mock_delay.call_args_list}
        assert delayed_ids == {queued_id, in_progress_id}

    @pytest.mark.asyncio
    async def test_no_runs_returns_zero_recovered(
        self, monkeypatch, session_factory,
    ):
        """Empty table → no enqueue work → the task returns cleanly."""
        from contextlib import asynccontextmanager
        from unittest.mock import patch

        from app.tasks import channel_mix_tasks as cmix

        @asynccontextmanager
        async def fake_ctx():
            async with session_factory() as s:
                yield s

        monkeypatch.setattr(
            "app.tasks.channel_mix_tasks.get_db_context", fake_ctx, raising=False,
        )

        with patch(
            "app.tasks.channel_mix_tasks.process_channel_mix_run.delay"
        ) as mock_delay:
            result = await cmix._run_recover_mix_runs()

        assert result == {"recovered": 0}
        mock_delay.assert_not_called()
