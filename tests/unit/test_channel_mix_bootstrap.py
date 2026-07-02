# SPDX-License-Identifier: MIT
"""Unit tests for the capital-efficient inbound *bootstrap* feature.

Two layers:

* The pure economic model — :func:`_simulate_bootstrap` and
  :func:`derive_bootstrap_schedule` — pinned hard: tapering capacities,
  per-round erosion, the floor stop, the Boltz-min stop, fee-spike
  sensitivity, and the target↔deposit framings.
* The sequential settle-aware executor — one round driven through
  open → active → drain → settle against stubbed ``lnd_service`` /
  ``boltz_service``, plus the insufficient-funds and stop-after-round
  finalizations.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker

from app.models.channel_mix_run import (
    ChannelMixRun,
    ChannelMixRunState,
    make_bootstrap_round_entry,
)
from app.services.channel_mix_planner import (
    BOOTSTRAP_DEFAULT_BOLTZ_MAX_SATS,
    BOOTSTRAP_DEFAULT_BOLTZ_MIN_SATS,
    PER_CHANNEL_FLOOR_SATS,
    bootstrap_drain_for_capacity,
    derive_bootstrap_schedule,
    select_peers,
    _simulate_bootstrap,
)


# ─── Pure economic model ──────────────────────────────────────────


def _sim(deposit, *, medium=10.0, high=20.0, max_rounds=40, target=None,
         boltz_min=BOOTSTRAP_DEFAULT_BOLTZ_MIN_SATS,
         boltz_max=BOOTSTRAP_DEFAULT_BOLTZ_MAX_SATS):
    return _simulate_bootstrap(
        deposit,
        sat_per_vb_medium=medium,
        sat_per_vb_high=high,
        boltz_min=boltz_min,
        boltz_max=boltz_max,
        max_rounds=max_rounds,
        target_inbound_sats=target,
    )


class TestBootstrapSimulation:
    def test_recycling_builds_more_inbound_than_deposit(self):
        """The whole point: a small deposit recycles into multiples of
        itself in inbound."""
        rounds, inbound, fees, residual = _sim(500_000)
        assert len(rounds) > 1
        # 500k deposit should build well over the deposit in inbound.
        assert inbound > 2_000_000
        assert fees > 0
        assert residual > 0

    def test_capacities_taper(self):
        """Each round opens a smaller channel than the last (erosion)."""
        rounds, *_ = _sim(500_000)
        caps = [c for (c, _d, _o, _s) in rounds]
        assert caps == sorted(caps, reverse=True)
        assert all(a > b for a, b in zip(caps, caps[1:]))

    def test_stops_at_floor(self):
        """The loop stops when the next channel would fall below the
        per-channel floor — never opens a sub-floor channel."""
        rounds, *_ = _sim(500_000)
        caps = [c for (c, _d, _o, _s) in rounds]
        assert all(c >= PER_CHANNEL_FLOOR_SATS for c in caps)

    def test_deposit_below_floor_yields_no_rounds(self):
        rounds, inbound, fees, residual = _sim(PER_CHANNEL_FLOOR_SATS // 2)
        assert rounds == []
        assert inbound == 0

    def test_boltz_min_stops_before_undrainable_round(self):
        """Every round's drain is at least the Boltz minimum — the loop
        never opens a channel it can't drain by swap."""
        rounds, *_ = _sim(400_000)
        drains = [d for (_c, d, _o, _s) in rounds]
        assert all(d >= BOOTSTRAP_DEFAULT_BOLTZ_MIN_SATS for d in drains)

    def test_fee_spike_reduces_inbound(self):
        """Higher feerates erode capital faster → less total inbound."""
        _r1, inbound_low, _f1, _x1 = _sim(500_000, medium=5.0, high=8.0)
        _r2, inbound_high, _f2, _x2 = _sim(500_000, medium=80.0, high=120.0)
        assert inbound_high < inbound_low

    def test_max_rounds_cap(self):
        rounds, *_ = _sim(5_000_000, max_rounds=3)
        assert len(rounds) == 3

    def test_target_early_break(self):
        """With a target, the loop stops as soon as it's reached."""
        rounds, inbound, _f, _x = _sim(500_000, target=1_000_000)
        assert inbound >= 1_000_000
        # Should not have run all the way to the floor.
        rounds_full, inbound_full, _f2, _x2 = _sim(500_000)
        assert len(rounds) < len(rounds_full)

    def test_drain_clamped_to_boltz_max(self):
        # A capacity whose drainable exceeds the Boltz max clamps down.
        drain = bootstrap_drain_for_capacity(
            50_000_000, boltz_max=BOOTSTRAP_DEFAULT_BOLTZ_MAX_SATS
        )
        assert drain == BOOTSTRAP_DEFAULT_BOLTZ_MAX_SATS


class TestDeriveBootstrapSchedule:
    def _peers(self):
        peers, _axes = select_peers(
            network="bitcoin", channel_count=64, mode="recommended_diverse"
        )
        return peers

    def test_no_peers_yields_warning_and_no_rounds(self):
        plan = derive_bootstrap_schedule(
            deposit_sats=500_000,
            fee_rate_sat_vb_medium=10.0,
            fee_rate_sat_vb_high=20.0,
            peers=[],
            catalog_snapshot_date="2026-01-01",
        )
        assert plan.rounds == ()
        assert plan.expected_rounds == 0
        assert any("No catalog peers" in w for w in plan.diagnostics.warnings)

    def test_boltz_unavailable_yields_no_rounds(self):
        """Bootstrap isn't offered when Boltz is unreachable at plan time
        (plan §7.1) — even with a full catalog."""
        plan = derive_bootstrap_schedule(
            deposit_sats=500_000,
            fee_rate_sat_vb_medium=10.0,
            fee_rate_sat_vb_high=20.0,
            peers=self._peers(),
            catalog_snapshot_date="2026-01-01",
            boltz_available=False,
        )
        assert plan.rounds == ()
        assert plan.expected_rounds == 0
        assert any("Boltz is unreachable" in w for w in plan.diagnostics.warnings)

    def test_deposit_framing(self):
        peers = self._peers()
        assert peers, "expected a non-empty mainnet catalog"
        plan = derive_bootstrap_schedule(
            deposit_sats=500_000,
            fee_rate_sat_vb_medium=10.0,
            fee_rate_sat_vb_high=20.0,
            peers=peers,
            catalog_snapshot_date="2026-01-01",
        )
        assert plan.initial_deposit_sats == 500_000
        assert plan.expected_rounds == len(plan.rounds) > 0
        assert plan.expected_total_inbound_sats > 500_000
        # Every round carries an assigned peer + a positive drain.
        assert all(r.peer is not None for r in plan.rounds)
        assert all(r.drain_target_sats >= BOOTSTRAP_DEFAULT_BOLTZ_MIN_SATS for r in plan.rounds)
        # Duration estimate is rounds × 4 confs × 10 min.
        assert plan.est_duration_minutes == len(plan.rounds) * 4 * 10

    def test_target_framing_finds_a_deposit_reaching_target(self):
        peers = self._peers()
        plan = derive_bootstrap_schedule(
            target_inbound_sats=1_500_000,
            fee_rate_sat_vb_medium=10.0,
            fee_rate_sat_vb_high=20.0,
            peers=peers,
            catalog_snapshot_date="2026-01-01",
        )
        assert plan.target_inbound_sats == 1_500_000
        assert plan.expected_total_inbound_sats >= 1_500_000
        # The recycling win: the deposit needed is far below the target.
        assert plan.initial_deposit_sats < 1_500_000

    def test_small_target_is_reached_not_under_recommended(self):
        """Regression: for small receive targets the required deposit is
        *larger* than the target (one channel's drainable < its capacity).
        The solver must reach the target — not under-recommend a deposit that
        builds less, with a false 'short of target' warning."""
        peers = self._peers()
        for target in (150_000, 155_000, 160_000, 200_000):
            plan = derive_bootstrap_schedule(
                target_inbound_sats=target,
                fee_rate_sat_vb_medium=10.0,
                fee_rate_sat_vb_high=20.0,
                peers=peers,
                catalog_snapshot_date="2026-01-01",
            )
            assert plan.expected_total_inbound_sats >= target, (target, plan)
            assert not any(
                "short of" in w for w in plan.diagnostics.warnings
            ), (target, plan.diagnostics.warnings)
        # The smallest target needs a deposit above it (no recycling room).
        small = derive_bootstrap_schedule(
            target_inbound_sats=150_000, fee_rate_sat_vb_medium=10.0,
            fee_rate_sat_vb_high=20.0, peers=peers, catalog_snapshot_date="x",
        )
        assert small.initial_deposit_sats > 150_000

    def test_peers_assigned_round_robin(self):
        peers = self._peers()
        plan = derive_bootstrap_schedule(
            deposit_sats=500_000,
            fee_rate_sat_vb_medium=10.0,
            fee_rate_sat_vb_high=20.0,
            peers=peers,
            catalog_snapshot_date="2026-01-01",
        )
        if len(plan.rounds) >= 2 and len(peers) >= 2:
            # Round-robin: the first two rounds use distinct peers.
            assert plan.rounds[0].peer.node_id_hex != plan.rounds[1].peer.node_id_hex


# ─── Executor (sequential settle-aware) ───────────────────────────


class _BootLnd:
    """Stub LND for the bootstrap round driver."""

    def __init__(self, *, confirmed=600_000, active=True, open_ok=True,
                 local_balance=400_000, reserved_anchor=0, open_error_msg=None):
        self.confirmed = confirmed
        self.active = active
        self.open_ok = open_ok
        self.local_balance = local_balance
        self.reserved_anchor = reserved_anchor
        # When set, open_channel returns this error (used to simulate LND's
        # "reserved wallet balance invalidated" rejection). Overrides open_ok.
        self.open_error_msg = open_error_msg
        self.opened: list[str] = []
        self.open_attempts: list[int] = []
        self.connected: set[str] = set()

    async def get_wallet_balance(self):
        return (
            {
                "confirmed_balance": self.confirmed,
                "total_balance": self.confirmed,
                "reserved_balance_anchor_chan": self.reserved_anchor,
            },
            None,
        )

    async def connect_peer(self, pubkey, host):
        self.connected.add(pubkey)
        return {}, None

    async def list_peer_pubkeys(self):
        # connect_peer records the peer; the round driver waits on this to
        # confirm the connection landed before opening.
        return set(self.connected), None

    async def open_channel(self, node_pubkey_hex, local_funding_amount,
                           sat_per_vbyte=None, push_sat=0, private=False):
        self.open_attempts.append(int(local_funding_amount))
        if self.open_error_msg is not None:
            return None, self.open_error_msg
        if not self.open_ok:
            return None, "funding broadcast rejected"
        self.opened.append(node_pubkey_hex)
        return {"funding_txid": "cd" * 32, "output_index": 0}, None

    async def channel_is_active(self, channel_point):
        return self.active, {"active": self.active}, None

    async def get_channels(self):
        return (
            [
                {
                    "remote_pubkey": pk,
                    # Default open returns funding_txid "cd"*32 / vout 0, so
                    # the channel point the confirmed-dead check (recovery
                    # plan §3.1) builds matches this.
                    "channel_point": "cd" * 32 + ":0",
                    "active": self.active,
                    "chan_id": "12345",
                    "local_balance": self.local_balance,
                    "local_chan_reserve_sat": 4_000,
                    "commit_fee": 1_000,
                    "unsettled_balance": 0,
                }
                for pk in self.opened
            ],
            None,
        )

    async def get_pending_channels_detail(self):
        # While the channel hasn't gone active it's still confirming →
        # report it as pending_open so the confirmed-dead backstop treats
        # it as alive-but-slow rather than abandoned (recovery plan §3.1).
        if self.active:
            return [], None
        return (
            [
                {
                    "type": "pending_open",
                    "channel_point": "cd" * 32 + ":0",
                    "remote_node_pub": "aa" * 33,
                }
            ],
            None,
        )

    async def new_address(self, address_type: str = "p2wkh"):
        return {"address": "bc1qbootstub"}, None


@pytest_asyncio.fixture
async def session_factory(db_engine):
    return async_sessionmaker(db_engine, expire_on_commit=False)


def _digest(seed: str) -> str:
    import hashlib
    return hashlib.sha256(f"{seed}-{uuid4()}".encode()).hexdigest()


def _bootstrap_run(*, channels=None, target=None, stop=False,
                   realized=0) -> ChannelMixRun:
    return ChannelMixRun(
        api_key_id=UUID("00000000-0000-0000-0000-da5b0a4d0000"),
        plan_token_digest=_digest("bootstrap-run"),
        state=ChannelMixRunState.QUEUED,
        mode="bootstrap",
        minimum_sats=500_000,
        recommended_sats=500_000,
        target_inbound_sats=target,
        realized_inbound_sats=realized,
        stop_requested=stop,
        channels=channels or [],
        warnings=[],
        bootstrap_params={
            "peer_mix_mode": "recommended_diverse",
            "manual_picks": [],
            "include_marginal_routing": False,
            "network": "bitcoin",
        },
    )


def _patch_ctx_and_lnd(monkeypatch, session_factory, lnd):
    @asynccontextmanager
    async def fake_ctx():
        async with session_factory() as s:
            yield s

    monkeypatch.setattr(
        "app.tasks.channel_mix_tasks.get_db_context", fake_ctx, raising=False
    )
    monkeypatch.setattr(
        "app.services.lnd_service.lnd_service", lnd, raising=False
    )

    async def _fake_feerate():
        return 10.0

    monkeypatch.setattr(
        "app.tasks.channel_mix_tasks._bootstrap_feerate_sat_vb",
        _fake_feerate,
        raising=False,
    )


def _make_boltz_swap(
    swap_id, *, status, claim_txid=None, lockup_txid=None, onchain=None, invoice=300_000
):
    """Persist-ready BoltzSwap row in a given terminal/in-flight status."""
    from app.models.boltz_swap import BoltzSwap

    return BoltzSwap(
        id=swap_id,
        boltz_swap_id=f"b-{str(swap_id)[:8]}",
        api_key_id=UUID("00000000-0000-0000-0000-da5b0a4d0000"),
        invoice_amount_sats=invoice,
        destination_address="bc1qclaim",
        status=status,
        claim_txid=claim_txid,
        lockup_txid=lockup_txid,
        onchain_amount_sats=onchain,
    )


class _CapturingBoltz:
    """Records create_reverse_swap calls; optionally fails."""

    def __init__(self, *, error=None):
        self.error = error
        self.calls = 0
        self.last = {}

    async def create_reverse_swap(
        self, db, *, api_key_id, invoice_amount_sats, destination_address,
        outgoing_chan_id=None,
    ):
        self.calls += 1
        self.last = {
            "amount": invoice_amount_sats,
            "outgoing_chan_id": outgoing_chan_id,
        }
        if self.error:
            return None, self.error

        class _Swap:
            id = UUID("11111111-1111-1111-1111-111111111111")

        return _Swap(), None


class _NoCreateBoltz:
    """Asserts create_reverse_swap is never called (idempotency guard)."""

    async def create_reverse_swap(self, *a, **k):
        raise AssertionError("create_reverse_swap must not be called")


def _seed_round(state, **over):
    entry = make_bootstrap_round_entry(
        round_index=over.pop("round_index", 0),
        peer_alias="alpha",
        peer_pubkey="aa" * 33,
        peer_host="alpha:9735",
        capacity_sats=over.pop("capacity_sats", 400_000),
        drain_target_sats=over.pop("drain_target_sats", 300_000),
        spendable_before_sats=500_000,
        state=state,
    )
    entry.update(over)
    return entry


class TestBootstrapExecutor:
    @pytest.mark.asyncio
    async def test_first_tick_opens_a_round(self, monkeypatch, session_factory):
        from app.tasks import channel_mix_tasks as cmix

        async with session_factory() as s:
            run = _bootstrap_run(target=1_000_000)
            s.add(run)
            await s.commit()
            await s.refresh(run)
            run_id = run.id

        # Channel not active yet → the open lands in open_pending.
        lnd = _BootLnd(confirmed=600_000, active=False)
        _patch_ctx_and_lnd(monkeypatch, session_factory, lnd)

        await cmix._run_one_mix(run_id)

        async with session_factory() as s:
            row = (
                await s.execute(select(ChannelMixRun).where(ChannelMixRun.id == run_id))
            ).scalar_one()
        assert row.state == ChannelMixRunState.IN_PROGRESS
        assert len(row.channels) == 1
        assert row.channels[0]["state"] == "open_pending"
        assert row.channels[0]["open_txid"]
        assert lnd.opened, "expected a channel-open call"

    @pytest.mark.asyncio
    async def test_reserves_for_existing_anchor_channels(
        self, monkeypatch, session_factory
    ):
        """A round opened while earlier anchor channels are still open must
        leave room for LND's growing anchor reserve (10k per channel) — the
        capacity is smaller by exactly one reserve unit vs. the first channel,
        so LND doesn't reject with "reserved wallet balance invalidated"."""
        from app.tasks import channel_mix_tasks as cmix

        caps = {}
        for reserved in (0, cmix.BOOTSTRAP_ANCHOR_RESERVE_PER_CHAN):
            async with session_factory() as s:
                run = _bootstrap_run(target=100_000_000)
                s.add(run)
                await s.commit()
                await s.refresh(run)
                run_id = run.id
            lnd = _BootLnd(confirmed=300_000, active=False, reserved_anchor=reserved)
            _patch_ctx_and_lnd(monkeypatch, session_factory, lnd)
            await cmix._run_one_mix(run_id)
            async with session_factory() as s:
                row = (
                    await s.execute(select(ChannelMixRun).where(ChannelMixRun.id == run_id))
                ).scalar_one()
            caps[reserved] = row.channels[0]["capacity_sats"]

        # One existing anchor channel → 10k less capacity than none.
        assert caps[0] - caps[cmix.BOOTSTRAP_ANCHOR_RESERVE_PER_CHAN] == (
            cmix.BOOTSTRAP_ANCHOR_RESERVE_PER_CHAN
        )

    @pytest.mark.asyncio
    async def test_reserve_error_shrinks_capacity_same_peer(
        self, monkeypatch, session_factory
    ):
        """An in-flight round whose open hits LND's anchor-reserve check must
        shrink its capacity and retry the SAME peer (the error is wallet-level,
        not peer-specific — cycling peers would be futile)."""
        from app.tasks import channel_mix_tasks as cmix

        entry = make_bootstrap_round_entry(
            round_index=0,
            peer_alias="p0",
            peer_pubkey="00" * 33,
            peer_host="p0:9735",
            capacity_sats=400_000,
            drain_target_sats=300_000,
            spendable_before_sats=500_000,
            state="opening",
        )
        lnd = _BootLnd(
            open_error_msg=(
                'LND error (500): {"code":2, "message":"reserved wallet balance '
                'invalidated: transaction would leave insufficient funds..."}'
            )
        )
        _patch_ctx_and_lnd(monkeypatch, session_factory, lnd)
        async with session_factory() as s:
            run = _bootstrap_run(channels=[entry])
            run.state = ChannelMixRunState.IN_PROGRESS
            s.add(run)
            await s.commit()
            await s.refresh(run)
            original = run.channels[0]["peer_pubkey"]

            await cmix._advance_bootstrap_round(s, run, 0)

            assert run.channels[0]["peer_pubkey"] == original  # same peer
            assert run.channels[0]["state"] == "opening"
            assert run.channels[0]["capacity_sats"] == (
                400_000 - cmix.BOOTSTRAP_ANCHOR_RESERVE_PER_CHAN
            )
            assert run.channels[0]["reserve_shrink_attempts"] == 1
            assert lnd.opened == []  # never broadcast a funding tx

    @pytest.mark.asyncio
    async def test_large_balance_caps_round_capacity(
        self, monkeypatch, session_factory
    ):
        """A balance far larger than one channel's worth opens a capped
        channel (drainable ≤ Boltz max), not a giant one — the excess
        stays on-chain to fund later rounds (plan §2)."""
        from app.services.channel_mix_planner import (
            BOOTSTRAP_DEFAULT_BOLTZ_MAX_SATS,
            bootstrap_capacity_cap,
        )
        from app.tasks import channel_mix_tasks as cmix

        async with session_factory() as s:
            run = _bootstrap_run(target=100_000_000)
            s.add(run)
            await s.commit()
            await s.refresh(run)
            run_id = run.id

        lnd = _BootLnd(confirmed=100_000_000, active=False)
        _patch_ctx_and_lnd(monkeypatch, session_factory, lnd)

        await cmix._run_one_mix(run_id)

        async with session_factory() as s:
            row = (
                await s.execute(select(ChannelMixRun).where(ChannelMixRun.id == run_id))
            ).scalar_one()
        cap = row.channels[0]["capacity_sats"]
        assert cap == bootstrap_capacity_cap(BOOTSTRAP_DEFAULT_BOLTZ_MAX_SATS)
        assert cap < 100_000_000  # not the whole balance

    @pytest.mark.asyncio
    async def test_insufficient_balance_stops_immediately(
        self, monkeypatch, session_factory
    ):
        from app.tasks import channel_mix_tasks as cmix

        async with session_factory() as s:
            run = _bootstrap_run()
            s.add(run)
            await s.commit()
            await s.refresh(run)
            run_id = run.id

        lnd = _BootLnd(confirmed=10_000)  # well below the floor + fee
        _patch_ctx_and_lnd(monkeypatch, session_factory, lnd)

        await cmix._run_one_mix(run_id)

        async with session_factory() as s:
            row = (
                await s.execute(select(ChannelMixRun).where(ChannelMixRun.id == run_id))
            ).scalar_one()
        assert row.state == ChannelMixRunState.STOPPED_INSUFFICIENT
        assert row.channels == []

    @pytest.mark.asyncio
    async def test_unreachable_peer_escalates_not_wedges(
        self, monkeypatch, session_factory
    ):
        """A peer whose connect keeps failing must escalate to the next
        eligible peer rather than wedge the round forever (plan §7.5)."""
        from app.tasks import channel_mix_tasks as cmix

        class _NoConnectLnd(_BootLnd):
            async def connect_peer(self, pubkey, host):
                return None, "peer unreachable"

        lnd = _NoConnectLnd()
        _patch_ctx_and_lnd(monkeypatch, session_factory, lnd)

        entry = make_bootstrap_round_entry(
            round_index=0,
            peer_alias="p0",
            peer_pubkey="00" * 33,
            peer_host="p0:9735",
            capacity_sats=400_000,
            drain_target_sats=300_000,
            spendable_before_sats=500_000,
            state="opening",
        )
        async with session_factory() as s:
            run = _bootstrap_run(channels=[entry])
            run.state = ChannelMixRunState.IN_PROGRESS
            s.add(run)
            await s.commit()
            await s.refresh(run)

            original = run.channels[0]["peer_pubkey"]
            for _ in range(cmix.BOOTSTRAP_MAX_CONNECT_ATTEMPTS):
                await cmix._advance_bootstrap_round(s, run, 0)

            # Escalated to a different (real catalog) peer; still trying.
            assert run.channels[0]["peer_pubkey"] != original
            assert run.channels[0]["state"] == "opening"

    @pytest.mark.asyncio
    async def test_open_peer_not_online_retries_same_peer(
        self, monkeypatch, session_factory
    ):
        """"peer not online" from open (right after a successful connect) is a
        transient LND race — retry the SAME peer a bounded number of ticks
        before escalating, rather than burning through the peer catalog."""
        from app.tasks import channel_mix_tasks as cmix

        class _NotOnlineThenOkLnd(_BootLnd):
            def __init__(self, *, fail_first: int, **kw):
                super().__init__(**kw)
                self._fail_first = fail_first
                self.open_calls = 0

            async def open_channel(self, node_pubkey_hex, local_funding_amount,
                                   sat_per_vbyte=None, push_sat=0, private=False):
                self.open_calls += 1
                if self.open_calls <= self._fail_first:
                    return None, "LND error (500): peer 00 is not online"
                self.opened.append(node_pubkey_hex)
                return {"funding_txid": "cd" * 32, "output_index": 0}, None

        # Fails "not online" once, then succeeds — should stay on the same peer.
        lnd = _NotOnlineThenOkLnd(fail_first=1)
        _patch_ctx_and_lnd(monkeypatch, session_factory, lnd)

        entry = make_bootstrap_round_entry(
            round_index=0,
            peer_alias="p0",
            peer_pubkey="00" * 33,
            peer_host="p0:9735",
            capacity_sats=400_000,
            drain_target_sats=300_000,
            spendable_before_sats=500_000,
            state="opening",
        )
        async with session_factory() as s:
            run = _bootstrap_run(channels=[entry])
            run.state = ChannelMixRunState.IN_PROGRESS
            s.add(run)
            await s.commit()
            await s.refresh(run)
            original = run.channels[0]["peer_pubkey"]

            # Tick 1: open rejected "not online" → transient retry, same peer.
            await cmix._advance_bootstrap_round(s, run, 0)
            assert run.channels[0]["peer_pubkey"] == original
            assert run.channels[0]["state"] == "opening"
            assert run.channels[0]["connect_attempts"] == 1

            # Tick 2: open succeeds → advances to open_pending, same peer.
            await cmix._advance_bootstrap_round(s, run, 0)
            assert run.channels[0]["peer_pubkey"] == original
            assert run.channels[0]["state"] == "open_pending"

    @pytest.mark.asyncio
    async def test_peer_never_comes_online_escalates(
        self, monkeypatch, session_factory
    ):
        """connect_peer succeeds but the peer never shows in ListPeers (the
        connection never lands): the in-tick wait must escalate to the next
        peer after the bounded retries rather than open into a dead peer."""
        from app.tasks import channel_mix_tasks as cmix

        # Probe once per tick, no sleeps, so the test is fast.
        monkeypatch.setattr(cmix, "BOOTSTRAP_PEER_CONNECT_WAIT_POLLS", 1)

        class _ConnectButNeverOnlineLnd(_BootLnd):
            async def connect_peer(self, pubkey, host):
                # Reports success but never records the peer as connected,
                # so list_peer_pubkeys keeps returning an empty set.
                return {}, None

        lnd = _ConnectButNeverOnlineLnd()
        _patch_ctx_and_lnd(monkeypatch, session_factory, lnd)

        entry = make_bootstrap_round_entry(
            round_index=0,
            peer_alias="p0",
            peer_pubkey="00" * 33,
            peer_host="p0:9735",
            capacity_sats=400_000,
            drain_target_sats=300_000,
            spendable_before_sats=500_000,
            state="opening",
        )
        async with session_factory() as s:
            run = _bootstrap_run(channels=[entry])
            run.state = ChannelMixRunState.IN_PROGRESS
            s.add(run)
            await s.commit()
            await s.refresh(run)
            original = run.channels[0]["peer_pubkey"]

            for _ in range(cmix.BOOTSTRAP_MAX_CONNECT_ATTEMPTS):
                await cmix._advance_bootstrap_round(s, run, 0)

            # Never opened (opened list empty) and escalated to another peer.
            assert lnd.opened == []
            assert run.channels[0]["peer_pubkey"] != original
            assert run.channels[0]["state"] == "opening"

    @pytest.mark.asyncio
    async def test_open_active_creates_and_pins_swap(
        self, monkeypatch, session_factory
    ):
        from app.tasks import channel_mix_tasks as cmix

        # A round already active, awaiting its drain.
        entry = make_bootstrap_round_entry(
            round_index=0,
            peer_alias="alpha",
            peer_pubkey="aa" * 33,
            peer_host="alpha:9735",
            capacity_sats=400_000,
            drain_target_sats=300_000,
            spendable_before_sats=500_000,
            state="open_active",
        )
        entry["open_txid"] = "cd" * 32
        entry["open_output_index"] = 0

        async with session_factory() as s:
            run = _bootstrap_run(channels=[entry], target=1_000_000)
            run.state = ChannelMixRunState.IN_PROGRESS
            s.add(run)
            await s.commit()
            await s.refresh(run)
            run_id = run.id

        lnd = _BootLnd(active=True, local_balance=400_000)
        # The round was pre-seeded as active; make get_channels surface it.
        lnd.opened.append("aa" * 33)
        _patch_ctx_and_lnd(monkeypatch, session_factory, lnd)

        captured = {}

        class _FakeBoltz:
            async def create_reverse_swap(self, db, *, api_key_id,
                                          invoice_amount_sats,
                                          destination_address,
                                          outgoing_chan_id=None):
                captured["outgoing_chan_id"] = outgoing_chan_id
                captured["amount"] = invoice_amount_sats

                class _Swap:
                    id = UUID("11111111-1111-1111-1111-111111111111")

                return _Swap(), None

        monkeypatch.setattr(
            "app.services.boltz_service.boltz_service", _FakeBoltz(), raising=False
        )

        await cmix._run_one_mix(run_id)

        async with session_factory() as s:
            row = (
                await s.execute(select(ChannelMixRun).where(ChannelMixRun.id == run_id))
            ).scalar_one()
        rnd = row.channels[0]
        assert rnd["state"] == "swap_pending"
        assert rnd["swap_id"] == "11111111-1111-1111-1111-111111111111"
        # The drain must be pinned to the freshly-opened channel.
        assert captured["outgoing_chan_id"] == "12345"
        # And sized within the Boltz bounds.
        assert BOOTSTRAP_DEFAULT_BOLTZ_MIN_SATS <= captured["amount"] <= BOOTSTRAP_DEFAULT_BOLTZ_MAX_SATS

    @pytest.mark.asyncio
    async def test_swap_settle_credits_inbound(self, monkeypatch, session_factory):
        from app.models.boltz_swap import BoltzSwap, SwapStatus
        from app.tasks import channel_mix_tasks as cmix

        swap_id = uuid4()
        entry = make_bootstrap_round_entry(
            round_index=0,
            peer_alias="alpha",
            peer_pubkey="aa" * 33,
            peer_host="alpha:9735",
            capacity_sats=400_000,
            drain_target_sats=300_000,
            spendable_before_sats=500_000,
            state="swap_pending",
        )
        entry["open_txid"] = "cd" * 32
        entry["open_output_index"] = 0
        entry["swap_id"] = str(swap_id)
        entry["expected_inbound_sats"] = 300_000
        entry["open_fee_sats"] = 2_500

        async with session_factory() as s:
            swap = BoltzSwap(
                id=swap_id,
                boltz_swap_id="boltz-xyz",
                api_key_id=UUID("00000000-0000-0000-0000-da5b0a4d0000"),
                invoice_amount_sats=300_000,
                destination_address="bc1qclaim",
                status=SwapStatus.COMPLETED,
                claim_txid="ef" * 32,
                onchain_amount_sats=297_000,
            )
            s.add(swap)
            run = _bootstrap_run(channels=[entry], target=10_000_000)
            run.state = ChannelMixRunState.IN_PROGRESS
            s.add(run)
            await s.commit()
            await s.refresh(run)
            run_id = run.id

        # After settle, the loop tries the next round; keep balance low so
        # it parks in AWAITING_FUNDS rather than opening another channel.
        lnd = _BootLnd(confirmed=5_000)
        _patch_ctx_and_lnd(monkeypatch, session_factory, lnd)

        await cmix._run_one_mix(run_id)

        async with session_factory() as s:
            row = (
                await s.execute(select(ChannelMixRun).where(ChannelMixRun.id == run_id))
            ).scalar_one()
        rnd = row.channels[0]
        assert rnd["state"] == "settled"
        assert rnd["recycled_sats"] == 297_000
        assert rnd["swap_claim_txid"] == "ef" * 32

    @pytest.mark.asyncio
    async def test_swap_completed_without_claim_txid_still_settles(
        self, monkeypatch, session_factory
    ):
        """A drain swap can reach COMPLETED with no persisted claim_txid (the
        claim-broadcast-but-not-committed race). The recycle still succeeded, so
        the round must settle and credit inbound rather than wedge the run —
        the txid is only a mempool-link convenience, not a settle gate."""
        from app.models.boltz_swap import BoltzSwap, SwapStatus
        from app.tasks import channel_mix_tasks as cmix

        swap_id = uuid4()
        entry = make_bootstrap_round_entry(
            round_index=0,
            peer_alias="alpha",
            peer_pubkey="aa" * 33,
            peer_host="alpha:9735",
            capacity_sats=400_000,
            drain_target_sats=300_000,
            spendable_before_sats=500_000,
            state="swap_pending",
        )
        entry["open_txid"] = "cd" * 32
        entry["open_output_index"] = 0
        entry["swap_id"] = str(swap_id)
        entry["expected_inbound_sats"] = 300_000
        entry["open_fee_sats"] = 2_500

        async with session_factory() as s:
            s.add(BoltzSwap(
                id=swap_id,
                boltz_swap_id="boltz-nocl",
                api_key_id=UUID("00000000-0000-0000-0000-da5b0a4d0000"),
                invoice_amount_sats=300_000,
                destination_address="bc1qclaim",
                status=SwapStatus.COMPLETED,
                claim_txid=None,  # never persisted
                onchain_amount_sats=297_000,
            ))
            run = _bootstrap_run(channels=[entry], target=10_000_000)
            run.state = ChannelMixRunState.IN_PROGRESS
            s.add(run)
            await s.commit()
            await s.refresh(run)
            run_id = run.id

        lnd = _BootLnd(confirmed=5_000)
        _patch_ctx_and_lnd(monkeypatch, session_factory, lnd)

        await cmix._run_one_mix(run_id)

        async with session_factory() as s:
            row = (
                await s.execute(select(ChannelMixRun).where(ChannelMixRun.id == run_id))
            ).scalar_one()
        rnd = row.channels[0]
        assert rnd["state"] == "settled", "COMPLETED swap must settle even without claim_txid"
        assert rnd["recycled_sats"] == 297_000
        assert int(row.realized_inbound_sats or 0) == 300_000
        # Inbound credited = the drain amount; fees = open + (drain - recycled).
        assert row.realized_inbound_sats == 300_000
        assert row.total_fees_sats == 2_500 + (300_000 - 297_000)
        # Balance too low to continue → AWAITING_FUNDS (non-terminal).
        assert row.state == ChannelMixRunState.AWAITING_FUNDS

    @pytest.mark.asyncio
    async def test_stop_requested_finalizes_cancelled(
        self, monkeypatch, session_factory
    ):
        from app.tasks import channel_mix_tasks as cmix

        settled = make_bootstrap_round_entry(
            round_index=0,
            peer_alias="alpha",
            peer_pubkey="aa" * 33,
            peer_host="alpha:9735",
            capacity_sats=400_000,
            drain_target_sats=300_000,
            spendable_before_sats=500_000,
            state="settled",
        )
        async with session_factory() as s:
            run = _bootstrap_run(channels=[settled], stop=True, realized=300_000)
            run.state = ChannelMixRunState.IN_PROGRESS
            s.add(run)
            await s.commit()
            await s.refresh(run)
            run_id = run.id

        lnd = _BootLnd(confirmed=600_000)  # plenty — but stop wins
        _patch_ctx_and_lnd(monkeypatch, session_factory, lnd)

        await cmix._run_one_mix(run_id)

        async with session_factory() as s:
            row = (
                await s.execute(select(ChannelMixRun).where(ChannelMixRun.id == run_id))
            ).scalar_one()
        assert row.state == ChannelMixRunState.CANCELLED
        # No new round started despite ample balance.
        assert len(row.channels) == 1


# ─── Executor: resume / idempotency (§7.9, §8) ────────────────────


class TestBootstrapResume:
    @pytest.mark.asyncio
    async def test_opening_with_txid_does_not_rebroadcast(
        self, monkeypatch, session_factory
    ):
        """A round resumed in 'opening' with an open_txid already set must
        transition to open_pending WITHOUT broadcasting a second funding
        tx (open-idempotency guard, plan §7.9/§8)."""
        from app.tasks import channel_mix_tasks as cmix

        entry = _seed_round("opening", open_txid="cd" * 32, open_output_index=0)
        lnd = _BootLnd()
        _patch_ctx_and_lnd(monkeypatch, session_factory, lnd)
        async with session_factory() as s:
            run = _bootstrap_run(channels=[entry])
            run.state = ChannelMixRunState.IN_PROGRESS
            s.add(run)
            await s.commit()
            await s.refresh(run)
            await cmix._advance_bootstrap_round(s, run, 0)
            assert run.channels[0]["state"] == "open_pending"
        assert lnd.opened == [], "must not open a second channel on resume"

    @pytest.mark.asyncio
    async def test_swap_pending_resume_does_not_recreate_swap(
        self, monkeypatch, session_factory
    ):
        """A round resumed in 'swap_pending' with a swap_id re-reads the
        existing swap and never creates a second one (swap-idempotency,
        plan §8)."""
        from app.models.boltz_swap import SwapStatus
        from app.tasks import channel_mix_tasks as cmix

        swap_id = uuid4()
        entry = _seed_round("swap_pending", swap_id=str(swap_id),
                            expected_inbound_sats=300_000)
        lnd = _BootLnd()
        _patch_ctx_and_lnd(monkeypatch, session_factory, lnd)
        monkeypatch.setattr(
            "app.services.boltz_service.boltz_service", _NoCreateBoltz(), raising=False
        )
        async with session_factory() as s:
            s.add(_make_boltz_swap(swap_id, status=SwapStatus.PAYING_INVOICE))
            run = _bootstrap_run(channels=[entry])
            run.state = ChannelMixRunState.IN_PROGRESS
            s.add(run)
            await s.commit()
            await s.refresh(run)
            # Must not raise (the _NoCreateBoltz guard) and must stay pending.
            await cmix._advance_bootstrap_round(s, run, 0)
            assert run.channels[0]["state"] == "swap_pending"


# ─── Executor: drain failure paths (§7.1) ─────────────────────────


class TestBootstrapDrainFailures:
    @pytest.mark.asyncio
    async def test_swap_create_error_retries_then_fails(
        self, monkeypatch, session_factory
    ):
        """Repeated swap-create failures exhaust the retry budget → the
        round is swap_failed and the run rolls up to PARTIAL_FAILURE
        (channel kept; plan §7.1)."""
        from app.tasks import channel_mix_tasks as cmix

        entry = _seed_round("open_active", open_txid="cd" * 32, open_output_index=0)
        lnd = _BootLnd(active=True)
        lnd.opened.append("aa" * 33)
        _patch_ctx_and_lnd(monkeypatch, session_factory, lnd)
        monkeypatch.setattr(
            "app.services.boltz_service.boltz_service",
            _CapturingBoltz(error="boltz down"),
            raising=False,
        )
        async with session_factory() as s:
            run = _bootstrap_run(channels=[entry], target=10_000_000)
            run.state = ChannelMixRunState.IN_PROGRESS
            s.add(run)
            await s.commit()
            await s.refresh(run)
            run_id = run.id

        for _ in range(cmix.BOOTSTRAP_MAX_SWAP_ATTEMPTS):
            await cmix._run_one_mix(run_id)

        async with session_factory() as s:
            row = (
                await s.execute(select(ChannelMixRun).where(ChannelMixRun.id == run_id))
            ).scalar_one()
        assert row.channels[0]["state"] == "swap_failed"
        assert row.state == ChannelMixRunState.PARTIAL_FAILURE

    @pytest.mark.asyncio
    async def test_swap_pending_stamps_lockup_and_claim_txids(
        self, monkeypatch, session_factory
    ):
        """While the drain swap is still confirming (not COMPLETED), the round
        entry surfaces the swap's lockup + claim txids so the progress card can
        link them in the mempool explorer during their confirmation wait."""
        from app.models.boltz_swap import SwapStatus
        from app.tasks import channel_mix_tasks as cmix

        swap_id = uuid4()
        entry = _seed_round(
            "swap_pending", swap_id=str(swap_id), expected_inbound_sats=300_000
        )
        lnd = _BootLnd()
        _patch_ctx_and_lnd(monkeypatch, session_factory, lnd)
        async with session_factory() as s:
            # In-flight (claiming), claim broadcast but not yet confirmed.
            s.add(_make_boltz_swap(
                swap_id, status=SwapStatus.CLAIMING,
                lockup_txid="aa" * 32, claim_txid="bb" * 32,
            ))
            run = _bootstrap_run(channels=[entry])
            run.state = ChannelMixRunState.IN_PROGRESS
            s.add(run)
            await s.commit()
            await s.refresh(run)
            run_id = run.id

        await cmix._run_one_mix(run_id)

        async with session_factory() as s:
            row = (
                await s.execute(select(ChannelMixRun).where(ChannelMixRun.id == run_id))
            ).scalar_one()
        rnd = row.channels[0]
        # Still confirming, and both on-chain txids are now surfaced for linking.
        assert rnd["state"] == "swap_pending"
        assert rnd["swap_lockup_txid"] == "aa" * 32
        assert rnd["swap_claim_txid"] == "bb" * 32

    @pytest.mark.asyncio
    async def test_swap_status_failed_exhausts_to_swap_failed(
        self, monkeypatch, session_factory
    ):
        """A drain whose LN payment can't route (swap goes FAILED) retries
        a bounded number of times, then the round is swap_failed (§7.1)."""
        from app.models.boltz_swap import SwapStatus
        from app.tasks import channel_mix_tasks as cmix

        swap_id = uuid4()
        entry = _seed_round(
            "swap_pending",
            swap_id=str(swap_id),
            expected_inbound_sats=300_000,
            swap_attempts=cmix.BOOTSTRAP_MAX_SWAP_ATTEMPTS - 1,
        )
        lnd = _BootLnd()
        _patch_ctx_and_lnd(monkeypatch, session_factory, lnd)
        async with session_factory() as s:
            s.add(_make_boltz_swap(swap_id, status=SwapStatus.FAILED))
            run = _bootstrap_run(channels=[entry])
            run.state = ChannelMixRunState.IN_PROGRESS
            s.add(run)
            await s.commit()
            await s.refresh(run)
            run_id = run.id

        await cmix._run_one_mix(run_id)

        async with session_factory() as s:
            row = (
                await s.execute(select(ChannelMixRun).where(ChannelMixRun.id == run_id))
            ).scalar_one()
        assert row.channels[0]["state"] == "swap_failed"
        assert row.state == ChannelMixRunState.PARTIAL_FAILURE

    @pytest.mark.asyncio
    async def test_swap_in_flight_stays_pending(self, monkeypatch, session_factory):
        """A swap still paying/claiming keeps the round in swap_pending
        (the recycle gate; plan §4)."""
        from app.models.boltz_swap import SwapStatus
        from app.tasks import channel_mix_tasks as cmix

        swap_id = uuid4()
        entry = _seed_round("swap_pending", swap_id=str(swap_id),
                            expected_inbound_sats=300_000)
        lnd = _BootLnd()
        _patch_ctx_and_lnd(monkeypatch, session_factory, lnd)
        async with session_factory() as s:
            s.add(_make_boltz_swap(swap_id, status=SwapStatus.CLAIMING))
            run = _bootstrap_run(channels=[entry], target=10_000_000)
            run.state = ChannelMixRunState.IN_PROGRESS
            s.add(run)
            await s.commit()
            await s.refresh(run)
            run_id = run.id

        await cmix._run_one_mix(run_id)

        async with session_factory() as s:
            row = (
                await s.execute(select(ChannelMixRun).where(ChannelMixRun.id == run_id))
            ).scalar_one()
        assert row.channels[0]["state"] == "swap_pending"
        assert row.state == ChannelMixRunState.IN_PROGRESS

    @pytest.mark.asyncio
    async def test_long_swap_wait_flags_stuck_note(
        self, monkeypatch, session_factory
    ):
        """A confirmation that takes too long surfaces a non-fatal stuck
        note (plan §7.2) without failing the round."""
        from datetime import datetime, timedelta, timezone

        from app.models.boltz_swap import SwapStatus
        from app.tasks import channel_mix_tasks as cmix

        swap_id = uuid4()
        old = (datetime.now(timezone.utc) - timedelta(hours=5)).isoformat()
        entry = _seed_round("swap_pending", swap_id=str(swap_id),
                            expected_inbound_sats=300_000, waiting_since=old)
        lnd = _BootLnd()
        _patch_ctx_and_lnd(monkeypatch, session_factory, lnd)
        async with session_factory() as s:
            s.add(_make_boltz_swap(swap_id, status=SwapStatus.CLAIMING))
            run = _bootstrap_run(channels=[entry])
            run.state = ChannelMixRunState.IN_PROGRESS
            s.add(run)
            await s.commit()
            await s.refresh(run)
            await cmix._advance_bootstrap_round(s, run, 0)
            assert run.channels[0]["state"] == "swap_pending"  # not failed
            assert run.error_message and "longer than expected" in run.error_message


# ─── Executor: drain sizing + stops/timeouts (§4, §6, §11.4) ──────


class TestBootstrapSizingAndStops:
    @pytest.mark.asyncio
    async def test_drain_sized_from_live_channel(self, monkeypatch, session_factory):
        """The drain is the live channel's drainable netted of the routing
        budget: (local − reserve − commit − unsettled) / (1 + 3%)."""
        from app.tasks import channel_mix_tasks as cmix

        entry = _seed_round("open_active", open_txid="cd" * 32, open_output_index=0)
        lnd = _BootLnd(active=True, local_balance=400_000)  # reserve 4k, commit 1k
        lnd.opened.append("aa" * 33)
        _patch_ctx_and_lnd(monkeypatch, session_factory, lnd)
        boltz = _CapturingBoltz()
        monkeypatch.setattr(
            "app.services.boltz_service.boltz_service", boltz, raising=False
        )
        async with session_factory() as s:
            run = _bootstrap_run(channels=[entry], target=10_000_000)
            run.state = ChannelMixRunState.IN_PROGRESS
            s.add(run)
            await s.commit()
            await s.refresh(run)
            await cmix._advance_bootstrap_round(s, run, 0)
        # drainable = 400000 - 4000 - 1000 - 0 = 395000; /1.03 → 383495
        assert boltz.last["amount"] == int(395_000 / 1.03)

    @pytest.mark.asyncio
    async def test_awaiting_funds_times_out_to_stopped(
        self, monkeypatch, session_factory
    ):
        """After a settled round, a balance that stays below the next open
        past the tolerance window finalizes STOPPED_INSUFFICIENT (§6)."""
        from app.tasks import channel_mix_tasks as cmix

        settled = _seed_round("settled")
        lnd = _BootLnd(confirmed=5_000)  # below floor
        _patch_ctx_and_lnd(monkeypatch, session_factory, lnd)
        async with session_factory() as s:
            run = _bootstrap_run(channels=[settled], realized=300_000)
            run.state = ChannelMixRunState.AWAITING_FUNDS
            run.bootstrap_params = {
                **run.bootstrap_params,
                "awaiting_since": "2020-01-01T00:00:00+00:00",
            }
            s.add(run)
            await s.commit()
            await s.refresh(run)
            run_id = run.id

        await cmix._run_one_mix(run_id)

        async with session_factory() as s:
            row = (
                await s.execute(select(ChannelMixRun).where(ChannelMixRun.id == run_id))
            ).scalar_one()
        assert row.state == ChannelMixRunState.STOPPED_INSUFFICIENT

    @pytest.mark.asyncio
    async def test_max_duration_finalizes_complete(
        self, monkeypatch, session_factory
    ):
        """A run that exceeds the wall-clock cap finalizes COMPLETE with a
        note, even with ample balance (plan §11.4)."""
        from datetime import datetime, timezone

        from app.tasks import channel_mix_tasks as cmix

        lnd = _BootLnd(confirmed=600_000)
        _patch_ctx_and_lnd(monkeypatch, session_factory, lnd)
        async with session_factory() as s:
            run = _bootstrap_run(target=10_000_000)
            run.state = ChannelMixRunState.IN_PROGRESS
            run.started_at = datetime(2020, 1, 1, tzinfo=timezone.utc)
            s.add(run)
            await s.commit()
            await s.refresh(run)
            run_id = run.id

        await cmix._run_one_mix(run_id)

        async with session_factory() as s:
            row = (
                await s.execute(select(ChannelMixRun).where(ChannelMixRun.id == run_id))
            ).scalar_one()
        assert row.state == ChannelMixRunState.COMPLETE
        assert row.channels == []  # never opened a round
        assert any("maximum run duration" in w for w in row.warnings)

    @pytest.mark.asyncio
    async def test_stop_lets_inflight_round_continue(
        self, monkeypatch, session_factory
    ):
        """Stop-after-this-round must NOT abandon an in-flight round — it
        keeps advancing until the round settles, then cancels (§7.10)."""
        from app.tasks import channel_mix_tasks as cmix

        # Round mid-open; channel not active yet.
        entry = _seed_round("open_pending", open_txid="cd" * 32, open_output_index=0)
        lnd = _BootLnd(active=False)
        _patch_ctx_and_lnd(monkeypatch, session_factory, lnd)
        async with session_factory() as s:
            run = _bootstrap_run(channels=[entry], stop=True)
            run.state = ChannelMixRunState.IN_PROGRESS
            s.add(run)
            await s.commit()
            await s.refresh(run)
            run_id = run.id

        await cmix._run_one_mix(run_id)

        async with session_factory() as s:
            row = (
                await s.execute(select(ChannelMixRun).where(ChannelMixRun.id == run_id))
            ).scalar_one()
        # Still in progress on the in-flight round — not cancelled yet.
        assert row.state == ChannelMixRunState.IN_PROGRESS
        assert row.channels[0]["state"] == "open_pending"


# ─── Executor: Boltz-min stop (defensive; §7.8) ─


class TestBootstrapBoltzMinStop:
    @pytest.mark.asyncio
    async def test_undrainable_capacity_completes(
        self, monkeypatch, session_factory
    ):
        """When the next round's drain would fall below the Boltz minimum,
        the loop stops COMPLETE with a note and leaves the residual on-chain
        (spendable) rather than opening a channel it can't recycle (§7.8)."""
        from app.tasks import channel_mix_tasks as cmix

        # Force the "drain below min" branch by raising the Boltz minimum
        # above what a floor-sized channel can drain.
        monkeypatch.setattr(
            "app.services.channel_mix_planner.BOOTSTRAP_DEFAULT_BOLTZ_MIN_SATS",
            100_000_000,
            raising=False,
        )
        lnd = _BootLnd(confirmed=300_000)
        _patch_ctx_and_lnd(monkeypatch, session_factory, lnd)
        async with session_factory() as s:
            run = _bootstrap_run()
            s.add(run)
            await s.commit()
            await s.refresh(run)
            run_id = run.id

        await cmix._run_one_mix(run_id)

        async with session_factory() as s:
            row = (
                await s.execute(select(ChannelMixRun).where(ChannelMixRun.id == run_id))
            ).scalar_one()
        assert row.state == ChannelMixRunState.COMPLETE
        assert row.channels == []
        assert any("practical limit" in w for w in row.warnings)


# ─── Recover beat (§8) ────────────────────────────────────────────


class TestBootstrapRecover:
    @pytest.mark.asyncio
    async def test_recover_reenqueues_awaiting_funds_run(
        self, monkeypatch, session_factory
    ):
        """The recovery scan must re-enqueue AWAITING_FUNDS runs (so a
        bootstrap loop waiting on a recycling claim self-heals)."""
        from unittest.mock import MagicMock

        from app.tasks import channel_mix_tasks as cmix

        @asynccontextmanager
        async def fake_ctx():
            async with session_factory() as s:
                yield s

        monkeypatch.setattr(cmix, "get_db_context", fake_ctx, raising=False)
        mock_delay = MagicMock()
        monkeypatch.setattr(
            cmix.process_channel_mix_run, "delay", mock_delay, raising=False
        )
        async with session_factory() as s:
            run = _bootstrap_run(channels=[_seed_round("settled")])
            run.state = ChannelMixRunState.AWAITING_FUNDS
            s.add(run)
            await s.commit()
            await s.refresh(run)
            run_id = str(run.id)

        await cmix._run_recover_mix_runs()
        mock_delay.assert_any_call(run_id)


# ─── Schedule warnings + peer assignment + model helper ───────────


class TestBootstrapScheduleEdges:
    def _peers(self):
        peers, _axes = select_peers(
            network="bitcoin", channel_count=64, mode="recommended_diverse"
        )
        return peers

    def test_min_stop_branch_exercised_with_high_boltz_min(self):
        """With a Boltz minimum above the floor-sized drain, the loop stops
        before opening an undrainable round (exercises the §7.8 branch in
        the pure model)."""
        rounds, inbound, _f, _r = _sim(500_000, boltz_min=10_000_000)
        # Every emitted round still drains >= the (high) minimum.
        assert all(d >= 10_000_000 for (_c, d, _o, _s) in rounds)

    def test_deposit_below_floor_warns(self):
        plan = derive_bootstrap_schedule(
            deposit_sats=10_000,  # below one-channel floor
            fee_rate_sat_vb_medium=10.0,
            fee_rate_sat_vb_high=20.0,
            peers=self._peers(),
            catalog_snapshot_date="2026-01-01",
        )
        assert plan.rounds == ()
        assert any("below the one-channel floor" in w for w in plan.diagnostics.warnings)

    def test_long_run_warns_about_hours_and_fees(self):
        plan = derive_bootstrap_schedule(
            deposit_sats=2_000_000,
            fee_rate_sat_vb_medium=10.0,
            fee_rate_sat_vb_high=20.0,
            peers=self._peers(),
            catalog_snapshot_date="2026-01-01",
        )
        # A multi-hour schedule must warn (rounds × 40 min ≥ 120 min).
        if plan.est_duration_minutes >= 120:
            assert any("hour" in w for w in plan.diagnostics.warnings)

    def test_assign_peers_over_cap_flagged(self):
        from app.services.channel_mix_planner import _assign_bootstrap_peers

        peers = self._peers()[:2]  # only two eligible
        assigned, over = _assign_bootstrap_peers(7, peers, max_per_peer=3)
        assert len(assigned) == 7
        # 7 rounds over 2 peers → ceil(7/2)=4 > 3 → over-cap flagged.
        assert over is True
        # Round-robin spread.
        assert assigned[0].node_id_hex != assigned[1].node_id_hex


class TestBootstrapModelHelper:
    def test_make_bootstrap_round_entry_shape(self):
        entry = make_bootstrap_round_entry(
            round_index=2,
            peer_alias="x",
            peer_pubkey="ab" * 33,
            peer_host="x:9735",
            capacity_sats=400_000,
            drain_target_sats=300_000,
            spendable_before_sats=500_000,
        )
        assert entry["round_index"] == 2
        assert entry["state"] == "opening"
        assert entry["capacity_sats"] == 400_000
        for k in (
            "open_txid", "open_output_index", "swap_id", "swap_claim_txid",
            "recycled_sats", "open_error", "swap_error",
        ):
            assert entry[k] is None
        assert entry["expected_inbound_sats"] == 0


# ─── Auto-resolution backstops (recovery plan §3) ──────────────────


class _DeadChannelLnd(_BootLnd):
    """LND stub whose channel point is reported force-closing — the
    confirmed-dead signal (recovery plan §3.1)."""

    async def channel_is_active(self, channel_point):
        return False, None, None

    async def get_pending_channels_detail(self):
        return (
            [
                {
                    "type": "force_closing",
                    "channel_point": "cd" * 32 + ":0",
                    "remote_node_pub": "aa" * 33,
                }
            ],
            None,
        )

    async def get_channels(self):
        return [], None


class _AliveChannelLnd(_BootLnd):
    """Channel exists and is active — never confirmed-dead, so only the
    hard wall-clock backstop can fail a wait against it."""

    def __init__(self, **kw):
        super().__init__(active=True, **kw)

    async def channel_is_active(self, channel_point):
        return False, {"active": False}, None  # not active yet (still waiting)

    async def get_pending_channels_detail(self):
        return [], None

    async def get_channels(self):
        return (
            [{"remote_pubkey": "aa" * 33, "channel_point": "cd" * 32 + ":0",
              "active": True, "chan_id": "1", "local_balance": 400_000,
              "local_chan_reserve_sat": 4_000, "commit_fee": 1_000,
              "unsettled_balance": 0}],
            None,
        )


class TestBootstrapAutoResolution:
    @pytest.mark.asyncio
    async def test_confirmed_dead_channel_fails_round(
        self, monkeypatch, session_factory
    ):
        """An open_pending round whose channel LND reports force-closing is
        auto-failed → run PARTIAL_FAILURE (also closes §7.11)."""
        from app.tasks import channel_mix_tasks as cmix

        entry = _seed_round("open_pending", open_txid="cd" * 32, open_output_index=0)
        lnd = _DeadChannelLnd(active=False)
        _patch_ctx_and_lnd(monkeypatch, session_factory, lnd)
        async with session_factory() as s:
            run = _bootstrap_run(channels=[entry], target=10_000_000)
            run.state = ChannelMixRunState.IN_PROGRESS
            s.add(run)
            await s.commit()
            await s.refresh(run)
            run_id = run.id

        await cmix._run_one_mix(run_id)

        async with session_factory() as s:
            row = (
                await s.execute(select(ChannelMixRun).where(ChannelMixRun.id == run_id))
            ).scalar_one()
        assert row.channels[0]["state"] == "open_failed"
        assert row.state == ChannelMixRunState.PARTIAL_FAILURE
        assert row.completed_at is not None
        assert "force-closed or abandoned" in (row.channels[0].get("open_error") or "")

    @pytest.mark.asyncio
    async def test_slow_pending_channel_is_not_failed(
        self, monkeypatch, session_factory
    ):
        """A merely-slow channel (still pending_open, within the backstop)
        is left waiting — no false fail."""
        from app.tasks import channel_mix_tasks as cmix

        entry = _seed_round("open_pending", open_txid="cd" * 32, open_output_index=0)
        lnd = _BootLnd(active=False)  # pending_open via stub, fresh wait
        _patch_ctx_and_lnd(monkeypatch, session_factory, lnd)
        async with session_factory() as s:
            run = _bootstrap_run(channels=[entry], target=10_000_000)
            run.state = ChannelMixRunState.IN_PROGRESS
            s.add(run)
            await s.commit()
            await s.refresh(run)
            run_id = run.id

        await cmix._run_one_mix(run_id)

        async with session_factory() as s:
            row = (
                await s.execute(select(ChannelMixRun).where(ChannelMixRun.id == run_id))
            ).scalar_one()
        assert row.channels[0]["state"] == "open_pending"  # still waiting
        assert row.state == ChannelMixRunState.IN_PROGRESS

    @pytest.mark.asyncio
    async def test_hard_timeout_fails_a_stuck_wait(
        self, monkeypatch, session_factory
    ):
        """A single wait older than the per-wait hard backstop is failed
        even when the channel itself isn't confirmed-dead (§3.2)."""
        from datetime import datetime, timedelta, timezone

        from app.services.channel_mix_planner import (
            CHANNEL_MIX_WAIT_HARD_TIMEOUT_MINUTES,
        )
        from app.tasks import channel_mix_tasks as cmix

        old = (
            datetime.now(timezone.utc)
            - timedelta(minutes=CHANNEL_MIX_WAIT_HARD_TIMEOUT_MINUTES + 60)
        ).isoformat()
        entry = _seed_round(
            "open_pending", open_txid="cd" * 32, open_output_index=0,
            waiting_since=old,
        )
        lnd = _AliveChannelLnd()  # channel alive → only the timeout can fail it
        _patch_ctx_and_lnd(monkeypatch, session_factory, lnd)
        async with session_factory() as s:
            run = _bootstrap_run(channels=[entry], target=10_000_000)
            run.state = ChannelMixRunState.IN_PROGRESS
            s.add(run)
            await s.commit()
            await s.refresh(run)
            run_id = run.id

        await cmix._run_one_mix(run_id)

        async with session_factory() as s:
            row = (
                await s.execute(select(ChannelMixRun).where(ChannelMixRun.id == run_id))
            ).scalar_one()
        assert row.channels[0]["state"] == "open_failed"
        assert row.state == ChannelMixRunState.PARTIAL_FAILURE

    @pytest.mark.asyncio
    async def test_per_wait_not_per_run_timeout(
        self, monkeypatch, session_factory
    ):
        """A healthy long-running bootstrap whose *total* age exceeds the
        cap but whose *current* wait is fresh is NOT failed — proving the
        per-wait (not per-run) semantics."""
        from datetime import datetime, timedelta, timezone

        from app.services.channel_mix_planner import (
            CHANNEL_MIX_WAIT_HARD_TIMEOUT_MINUTES,
        )
        from app.tasks import channel_mix_tasks as cmix

        settled = _seed_round("settled", round_index=0)
        # In-flight round: a fresh wait (just started), but the run as a
        # whole is very old.
        fresh = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
        inflight = _seed_round(
            "open_pending", round_index=1, open_txid="cd" * 32,
            open_output_index=0, waiting_since=fresh,
        )
        lnd = _BootLnd(active=False)  # pending_open, alive-but-slow
        _patch_ctx_and_lnd(monkeypatch, session_factory, lnd)
        async with session_factory() as s:
            run = _bootstrap_run(channels=[settled, inflight], target=10_000_000)
            run.state = ChannelMixRunState.IN_PROGRESS
            run.started_at = datetime(2020, 1, 1, tzinfo=timezone.utc)  # ancient
            s.add(run)
            await s.commit()
            await s.refresh(run)
            run_id = run.id

        await cmix._run_one_mix(run_id)

        async with session_factory() as s:
            row = (
                await s.execute(select(ChannelMixRun).where(ChannelMixRun.id == run_id))
            ).scalar_one()
        assert row.channels[1]["state"] == "open_pending"  # current wait fresh
        assert row.state == ChannelMixRunState.IN_PROGRESS
