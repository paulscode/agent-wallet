# SPDX-License-Identifier: MIT
"""Tests for ``app.services.bolt12.sticky_peer_reconciler``.

Covers the three failure modes the reconciler exists to handle:

1. Startup reconciliation builds the desired set from active
   default-receive offers + the well-known-payers registry.
2. Periodic ticks re-push the set (idempotent) and dial peers the
   gateway reports as missing.
3. Coordination invariants — pushes are no-ops when the gateway
   runtime is down; errors don't break the loop.

The Rust on-disconnect handler is tested in ``cargo test``; this
file pins the Python-side contract.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from app.core.config import settings
from app.models.bolt12_offer import (
    Bolt12Offer,
    Bolt12OfferSource,
    Bolt12OfferStatus,
)
from app.services.bolt12 import sticky_peer_reconciler as reconciler
from app.services.bolt12.well_known_payers import WELL_KNOWN_PAYERS


@pytest.fixture(autouse=True)
async def _cleanup_reconciler_task():
    """Defensive cleanup. The reconciler task is a module global; a
    test that errors before stopping the task would leak it into the
    next test. This autouse fixture cancels any leftover task post-
    test so each test starts from a clean state."""
    yield
    if reconciler._reconciler_task is not None:
        await reconciler.stop_reconciler()


def _patch_db_context(db):
    """Return a patch object that makes ``get_db_context()`` yield
    the test fixture's session instead of opening a new engine.

    The reconciler imports ``get_db_context`` at module load time, so
    the patch must target the reconciler's own namespace, not
    ``app.core.database``."""

    @asynccontextmanager
    async def _ctx():
        yield db

    return patch(
        "app.services.bolt12.sticky_peer_reconciler.get_db_context",
        _ctx,
    )


# ── helpers ───────────────────────────────────────────────────────


@pytest.fixture
def force_mainnet(monkeypatch):
    """Force settings.bitcoin_network to ``bitcoin`` so the OCEAN
    mainnet-only entry matches in the reconciler.

    Also stubs ``BOOTSTRAP_OM_PEERS`` to an empty tuple so each
    well-known-payer test asserts on payer entries only. Bootstrap
    peers are covered separately in ``TestBootstrapPeers``."""
    monkeypatch.setattr(settings, "bitcoin_network", "bitcoin")
    monkeypatch.setattr(
        settings,
        "bolt12_auto_peer_well_known_payers",
        True,
    )
    monkeypatch.setattr(reconciler, "BOOTSTRAP_OM_PEERS", ())


@pytest.fixture
def stub_runtime(monkeypatch):
    """Replace the reconciler's runtime client + return a stub."""
    from app.services.bolt12 import runtime as bolt12_runtime

    stub_client = MagicMock()
    stub_client.set_sticky_peers = AsyncMock(
        return_value=MagicMock(sticky_count=0),
    )
    stub_client.connect_peer = AsyncMock(
        return_value=MagicMock(already_connected=False),
    )
    # Default get_identity: no peers connected.
    ident = MagicMock()
    ident.peers = ()
    stub_client.get_identity = AsyncMock(return_value=ident)

    # Stash the previous value so we restore it cleanly.
    original = bolt12_runtime._runtime.client
    bolt12_runtime._runtime.client = stub_client

    yield stub_client

    bolt12_runtime._runtime.client = original


async def _add_default_receive(db, *, api_key_id, description: str) -> Bolt12Offer:
    offer = Bolt12Offer(
        api_key_id=api_key_id,
        bolt12="lno1test" + uuid4().hex,
        description=description,
        amount_msat=None,
        currency=None,
        issuer=None,
        issuer_id_hex="02" + "ab" * 32,
        quantity_max=None,
        source=Bolt12OfferSource.ISSUED,
        is_default_receive=True,
        status=Bolt12OfferStatus.ACTIVE,
    )
    db.add(offer)
    await db.commit()
    await db.refresh(offer)
    return offer


# ── _compute_desired_peers ────────────────────────────────────────


class TestComputeDesiredPeers:
    @pytest.mark.asyncio
    async def test_returns_empty_when_no_offers(self, force_mainnet, db_session):
        # No offers at all → empty desired set.
        with _patch_db_context(db_session):
            peers = await reconciler._compute_desired_peers()
        assert peers == ()

    @pytest.mark.asyncio
    async def test_returns_empty_when_auto_peer_disabled(
        self,
        monkeypatch,
        db_session,
    ):
        # Kill switch must zero the desired set even when an OCEAN
        # offer exists. Operators rely on this to fully opt out.
        monkeypatch.setattr(settings, "bitcoin_network", "bitcoin")
        monkeypatch.setattr(
            settings,
            "bolt12_auto_peer_well_known_payers",
            False,
        )

        # Seed an API key + OCEAN offer.
        from app.core.security import generate_api_key, hash_api_key
        from app.models.api_key import APIKey

        raw = generate_api_key()
        api_key = APIKey(
            id=uuid4(),
            name="t",
            key_hash=hash_api_key(raw),
            is_admin=True,
        )
        db_session.add(api_key)
        await db_session.commit()
        await _add_default_receive(
            db_session,
            api_key_id=api_key.id,
            description="OCEAN Payouts for bc1qabc",
        )

        with _patch_db_context(db_session):
            peers = await reconciler._compute_desired_peers()
        assert peers == ()

    @pytest.mark.asyncio
    async def test_matches_ocean_offer(self, force_mainnet, db_session):
        from app.core.security import generate_api_key, hash_api_key
        from app.models.api_key import APIKey

        raw = generate_api_key()
        api_key = APIKey(
            id=uuid4(),
            name="t",
            key_hash=hash_api_key(raw),
            is_admin=True,
        )
        db_session.add(api_key)
        await db_session.commit()
        await _add_default_receive(
            db_session,
            api_key_id=api_key.id,
            description="OCEAN Payouts for bc1qabc",
        )

        with _patch_db_context(db_session):
            peers = await reconciler._compute_desired_peers()
        assert len(peers) == 1
        ocean = next(p for p in WELL_KNOWN_PAYERS if p.label == "OCEAN")
        assert peers[0].label == "OCEAN"
        assert peers[0].node_id == bytes.fromhex(ocean.node_id_hex)
        assert peers[0].address == ocean.address

    @pytest.mark.asyncio
    async def test_deduplicates_same_payer_across_keys(
        self,
        force_mainnet,
        db_session,
    ):
        # Two API keys each with an OCEAN default-receive offer
        # must produce ONE sticky entry (de-dup on node_id) so we
        # don't dial the same peer twice.
        from app.core.security import generate_api_key, hash_api_key
        from app.models.api_key import APIKey

        for i in range(2):
            raw = generate_api_key()
            api_key = APIKey(
                id=uuid4(),
                name=f"t-{i}",
                key_hash=hash_api_key(raw),
                is_admin=True,
            )
            db_session.add(api_key)
            await db_session.commit()
            await _add_default_receive(
                db_session,
                api_key_id=api_key.id,
                description=f"OCEAN Payouts for bc1q{i}",
            )

        with _patch_db_context(db_session):
            peers = await reconciler._compute_desired_peers()
        assert len(peers) == 1, "OCEAN appears once across N matching offers"

    @pytest.mark.asyncio
    async def test_skips_non_matching_descriptions(
        self,
        force_mainnet,
        db_session,
    ):
        from app.core.security import generate_api_key, hash_api_key
        from app.models.api_key import APIKey

        raw = generate_api_key()
        api_key = APIKey(
            id=uuid4(),
            name="t",
            key_hash=hash_api_key(raw),
            is_admin=True,
        )
        db_session.add(api_key)
        await db_session.commit()
        await _add_default_receive(
            db_session,
            api_key_id=api_key.id,
            description="Just a generic offer description",
        )

        with _patch_db_context(db_session):
            peers = await reconciler._compute_desired_peers()
        assert peers == ()

    @pytest.mark.asyncio
    async def test_skips_mainnet_only_on_regtest(self, monkeypatch, db_session):
        monkeypatch.setattr(settings, "bitcoin_network", "regtest")
        monkeypatch.setattr(
            settings,
            "bolt12_auto_peer_well_known_payers",
            True,
        )

        from app.core.security import generate_api_key, hash_api_key
        from app.models.api_key import APIKey

        raw = generate_api_key()
        api_key = APIKey(
            id=uuid4(),
            name="t",
            key_hash=hash_api_key(raw),
            is_admin=True,
        )
        db_session.add(api_key)
        await db_session.commit()
        await _add_default_receive(
            db_session,
            api_key_id=api_key.id,
            description="OCEAN Payouts for bcrt1qabc",
        )

        with _patch_db_context(db_session):
            peers = await reconciler._compute_desired_peers()
        assert peers == (), "regtest wallet must not include the mainnet-only OCEAN entry in its desired sticky set"

    @pytest.mark.asyncio
    async def test_skips_inactive_offers(self, force_mainnet, db_session):
        from app.core.security import generate_api_key, hash_api_key
        from app.models.api_key import APIKey

        raw = generate_api_key()
        api_key = APIKey(
            id=uuid4(),
            name="t",
            key_hash=hash_api_key(raw),
            is_admin=True,
        )
        db_session.add(api_key)
        await db_session.commit()
        offer = await _add_default_receive(
            db_session,
            api_key_id=api_key.id,
            description="OCEAN Payouts for bc1qabc",
        )
        offer.status = Bolt12OfferStatus.DISABLED
        await db_session.commit()

        with _patch_db_context(db_session):
            peers = await reconciler._compute_desired_peers()
        assert peers == (), "Disabled default-receive offers must not contribute to the sticky set"


# ── bootstrap OM peers (always-on third-party intros) ─────────────


class TestBootstrapPeers:
    """The bootstrap registry guarantees the gateway has at least
    one viable ``offer_paths`` introduction node even before the
    operator configures their first well-known payer. These tests
    pin that the reconciler always emits those entries on mainnet."""

    @pytest.mark.asyncio
    async def test_bootstrap_peers_present_with_no_offers(
        self,
        monkeypatch,
        db_session,
    ):
        # No offers at all but BOOTSTRAP_OM_PEERS is non-empty —
        # those entries MUST appear in the desired set so the
        # gateway connects to them at startup.
        monkeypatch.setattr(settings, "bitcoin_network", "bitcoin")
        monkeypatch.setattr(
            settings,
            "bolt12_auto_peer_well_known_payers",
            True,
        )
        # Real registry (not the empty stub force_mainnet uses).
        from app.services.bolt12.well_known_payers import (
            BOOTSTRAP_OM_PEERS as REAL_BOOTSTRAP,
        )

        with _patch_db_context(db_session):
            peers = await reconciler._compute_desired_peers()
        expected_ids = {bytes.fromhex(b.node_id_hex) for b in REAL_BOOTSTRAP if b.mainnet_only}
        emitted_ids = {p.node_id for p in peers}
        assert expected_ids.issubset(emitted_ids), (
            f"bootstrap peers missing from desired set: "
            f"expected={[i.hex() for i in expected_ids]} "
            f"emitted={[i.hex() for i in emitted_ids]}"
        )

    @pytest.mark.asyncio
    async def test_bootstrap_peers_skipped_on_regtest(
        self,
        monkeypatch,
        db_session,
    ):
        # Bootstrap entries are mainnet-only — a regtest wallet
        # must not include them (their pubkeys aren't valid on
        # other chains).
        monkeypatch.setattr(settings, "bitcoin_network", "regtest")
        monkeypatch.setattr(
            settings,
            "bolt12_auto_peer_well_known_payers",
            True,
        )
        with _patch_db_context(db_session):
            peers = await reconciler._compute_desired_peers()
        assert peers == ()

    @pytest.mark.asyncio
    async def test_bootstrap_peers_skipped_when_auto_peer_disabled(
        self,
        monkeypatch,
        db_session,
    ):
        # The kill switch zeroes the desired set including
        # bootstrap entries, so operators can fully opt out.
        monkeypatch.setattr(settings, "bitcoin_network", "bitcoin")
        monkeypatch.setattr(
            settings,
            "bolt12_auto_peer_well_known_payers",
            False,
        )
        with _patch_db_context(db_session):
            peers = await reconciler._compute_desired_peers()
        assert peers == ()

    @pytest.mark.asyncio
    async def test_bootstrap_plus_payer_combined(
        self,
        monkeypatch,
        db_session,
    ):
        # Mainnet + active OCEAN offer + non-empty bootstrap registry
        # should yield bootstrap entries AND OCEAN.
        monkeypatch.setattr(settings, "bitcoin_network", "bitcoin")
        monkeypatch.setattr(
            settings,
            "bolt12_auto_peer_well_known_payers",
            True,
        )

        from app.core.security import generate_api_key, hash_api_key
        from app.models.api_key import APIKey
        from app.services.bolt12.well_known_payers import (
            BOOTSTRAP_OM_PEERS as REAL_BOOTSTRAP,
        )

        raw = generate_api_key()
        api_key = APIKey(
            id=uuid4(),
            name="t",
            key_hash=hash_api_key(raw),
            is_admin=True,
        )
        db_session.add(api_key)
        await db_session.commit()
        await _add_default_receive(
            db_session,
            api_key_id=api_key.id,
            description="OCEAN Payouts for bc1qabc",
        )

        with _patch_db_context(db_session):
            peers = await reconciler._compute_desired_peers()
        emitted_ids = {p.node_id for p in peers}
        ocean = next(p for p in WELL_KNOWN_PAYERS if p.label == "OCEAN")
        assert bytes.fromhex(ocean.node_id_hex) in emitted_ids, "OCEAN entry missing from combined desired set"
        for b in REAL_BOOTSTRAP:
            if b.mainnet_only:
                assert bytes.fromhex(b.node_id_hex) in emitted_ids, (
                    f"bootstrap peer {b.label} missing from combined desired set"
                )


# ── _push_sticky_set ──────────────────────────────────────────────


class TestPushStickySet:
    @pytest.mark.asyncio
    async def test_pushes_to_gateway(self, stub_runtime):
        from app.services.bolt12.sticky_peer_reconciler import DesiredPeer

        ok = await reconciler._push_sticky_set(
            (
                DesiredPeer(
                    label="OCEAN",
                    node_id=b"\x02" + b"\xaa" * 32,
                    address="1.1.1.1:9735",
                ),
            ),
        )
        assert ok is True
        stub_runtime.set_sticky_peers.assert_awaited_once()
        call_args = stub_runtime.set_sticky_peers.await_args
        peers = call_args.args[0]
        assert len(peers) == 1
        assert peers[0].address == "1.1.1.1:9735"

    @pytest.mark.asyncio
    async def test_noop_when_runtime_client_is_none(self, monkeypatch):
        from app.services.bolt12 import runtime as bolt12_runtime
        from app.services.bolt12.sticky_peer_reconciler import DesiredPeer

        original = bolt12_runtime._runtime.client
        bolt12_runtime._runtime.client = None
        try:
            ok = await reconciler._push_sticky_set(
                (
                    DesiredPeer(
                        label="OCEAN",
                        node_id=b"\x02" + b"\xbb" * 32,
                        address="x:1",
                    ),
                ),
            )
        finally:
            bolt12_runtime._runtime.client = original
        assert ok is False, "no gateway client = no push; the next tick retries when the runtime supervisor reconnects"

    @pytest.mark.asyncio
    async def test_swallows_set_sticky_failures(self, stub_runtime):
        from app.services.bolt12.sticky_peer_reconciler import DesiredPeer

        stub_runtime.set_sticky_peers.side_effect = RuntimeError("gateway said nope")
        ok = await reconciler._push_sticky_set(
            (
                DesiredPeer(
                    label="OCEAN",
                    node_id=b"\x02" + b"\xcc" * 32,
                    address="y:1",
                ),
            ),
        )
        assert ok is False, "RPC error must be swallowed and logged"


# ── _dial_if_missing ──────────────────────────────────────────────


class TestDialIfMissing:
    @pytest.mark.asyncio
    async def test_dials_only_missing_peers(self, stub_runtime):
        # Gateway reports peer A connected; B and C are missing.
        from app.services.bolt12.sticky_peer_reconciler import DesiredPeer

        connected_a = MagicMock()
        connected_a.node_id = b"\x02" + b"\x01" * 32
        ident = MagicMock()
        ident.peers = (connected_a,)
        stub_runtime.get_identity.return_value = ident

        desired = (
            DesiredPeer(
                label="A",
                node_id=b"\x02" + b"\x01" * 32,
                address="a:1",
            ),
            DesiredPeer(
                label="B",
                node_id=b"\x02" + b"\x02" * 32,
                address="b:1",
            ),
            DesiredPeer(
                label="C",
                node_id=b"\x02" + b"\x03" * 32,
                address="c:1",
            ),
        )
        await reconciler._dial_if_missing(desired)
        # A was already connected — no dial. B + C should have been
        # dialed.
        assert stub_runtime.connect_peer.await_count == 2
        dialed_node_ids = {call.kwargs["node_id"] for call in stub_runtime.connect_peer.await_args_list}
        assert dialed_node_ids == {
            b"\x02" + b"\x02" * 32,
            b"\x02" + b"\x03" * 32,
        }

    @pytest.mark.asyncio
    async def test_dial_timeout_does_not_abort_loop(
        self,
        stub_runtime,
        monkeypatch,
    ):
        # A timeout on one peer must not prevent dialing the next.
        from app.services.bolt12.sticky_peer_reconciler import DesiredPeer

        # No peers connected — both will be dialed.
        ident = MagicMock()
        ident.peers = ()
        stub_runtime.get_identity.return_value = ident

        # First dial hangs forever; second succeeds. Cap the per-peer
        # timeout to 0.1 s so the test stays fast.
        monkeypatch.setattr(
            reconciler,
            "PER_PEER_DIAL_TIMEOUT_S",
            0.1,
        )

        hanging_event = asyncio.Event()  # never set

        async def _connect(*, node_id, address):
            if node_id == b"\x02" + b"\x01" * 32:
                await hanging_event.wait()
            return MagicMock(already_connected=False)

        stub_runtime.connect_peer.side_effect = _connect

        desired = (
            DesiredPeer(
                label="hang",
                node_id=b"\x02" + b"\x01" * 32,
                address="h:1",
            ),
            DesiredPeer(
                label="ok",
                node_id=b"\x02" + b"\x02" * 32,
                address="o:1",
            ),
        )
        await reconciler._dial_if_missing(desired)
        # Both attempts happened — the second was reached despite
        # the first hanging past its per-peer timeout.
        assert stub_runtime.connect_peer.await_count == 2


# ── refresh_sticky_set (out-of-band trigger) ──────────────────────


class TestStickyPushLock:
    """The module-level ``_sticky_push_lock`` serialises the
    read-then-push critical section across the periodic reconciler
    tick and out-of-band ``refresh_sticky_set`` callers.

    Without the lock, the following race is observable:
      1. Periodic reconciler reads DB (sees empty state)
      2. Admin commits an OCEAN offer
      3. Admin's refresh reads DB (sees OCEAN), pushes [OCEAN]
      4. Periodic reconciler push lands with stale [], overwriting
         the refresh's correct push.

    The lock guarantees the LAST pusher always reads the most
    recent committed DB state, closing the window.
    """

    @pytest.mark.asyncio
    async def test_refresh_blocks_until_reconciler_push_completes(
        self,
        stub_runtime,
        monkeypatch,
    ):
        # Verify: while ``run_reconciler_loop``'s push is in flight,
        # ``refresh_sticky_set`` waits for the lock — it does NOT
        # start its own read until the reconciler has released the
        # lock. This is what closes the stale-push race.
        monkeypatch.setattr(settings, "bolt12_enabled", True)
        monkeypatch.setattr(
            settings,
            "bolt12_gateway_grpc",
            "localhost:9999",
        )

        # Track the order of read+push operations.
        events: list[str] = []

        # Reconciler's read: returns empty (simulates pre-commit
        # state). Blocks long enough for the refresh to attempt the
        # lock.
        reconciler_read_started = asyncio.Event()
        reconciler_can_finish_push = asyncio.Event()
        refresh_read_started = asyncio.Event()

        async def _reconciler_compute():
            events.append("reconciler_compute_start")
            reconciler_read_started.set()
            # Hold so the refresh has time to try the lock.
            await asyncio.sleep(0)
            events.append("reconciler_compute_done")
            return ()

        async def _refresh_compute():
            events.append("refresh_compute_start")
            refresh_read_started.set()
            await asyncio.sleep(0)
            events.append("refresh_compute_done")
            return ()

        # We can't easily swap _compute_desired_peers per-caller, so
        # instead we instrument _push_sticky_set to count events and
        # hold up the reconciler push until told to release.
        push_call_count = {"n": 0}

        async def _slow_reconciler_push(desired):
            push_call_count["n"] += 1
            events.append(f"push_start_{push_call_count['n']}")
            if push_call_count["n"] == 1:
                # First push (reconciler's): wait for refresh to
                # have tried the lock before we finish.
                await reconciler_can_finish_push.wait()
            events.append(f"push_done_{push_call_count['n']}")
            return True

        monkeypatch.setattr(
            reconciler,
            "_compute_desired_peers",
            _reconciler_compute,
        )
        monkeypatch.setattr(
            reconciler,
            "_push_sticky_set",
            _slow_reconciler_push,
        )

        # Start the reconciler tick. It acquires the lock, reads,
        # then starts its (slow) push.
        recon_task = asyncio.create_task(
            reconciler.run_reconciler_loop(interval_s=30.0),
        )
        try:
            # Wait for the reconciler to be mid-push.
            await asyncio.wait_for(reconciler_read_started.wait(), 1.0)
            # Give the loop a beat to land in the push.
            await asyncio.sleep(0.05)
            assert events[-1] == "push_start_1", f"reconciler should be mid-push; events={events}"

            # Now invoke refresh_sticky_set with a different compute
            # fn so we can distinguish its events.
            monkeypatch.setattr(
                reconciler,
                "_compute_desired_peers",
                _refresh_compute,
            )
            refresh_task = asyncio.create_task(
                reconciler.refresh_sticky_set(),
            )

            # Give refresh a chance to try the lock and BLOCK.
            await asyncio.sleep(0.05)
            assert not refresh_read_started.is_set(), (
                "refresh_sticky_set MUST NOT have started its read "
                "while the reconciler still holds the lock — that's "
                "the race we set out to close"
            )

            # Release the reconciler's push.
            reconciler_can_finish_push.set()
            await refresh_task

            # Refresh must have started its read AFTER the
            # reconciler's push completed.
            push_done_idx = events.index("push_done_1")
            refresh_read_idx = events.index("refresh_compute_start")
            assert refresh_read_idx > push_done_idx, (
                "refresh's read must happen after the reconciler "
                "released the lock — otherwise the race we're "
                "guarding against could still trigger"
            )
        finally:
            recon_task.cancel()
            try:
                await recon_task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass


class TestRefreshStickySet:
    @pytest.mark.asyncio
    async def test_refresh_pushes_current_desired_set(
        self,
        force_mainnet,
        stub_runtime,
        db_session,
        monkeypatch,
    ):
        # Bolt12 must be considered "enabled" for the refresh helper
        # to act — the BOLT12-disabled guard inside ``refresh_sticky_set``
        # mirrors the start-reconciler guard.
        monkeypatch.setattr(settings, "bolt12_enabled", True)
        monkeypatch.setattr(
            settings,
            "bolt12_gateway_grpc",
            "localhost:9999",
        )

        from app.core.security import generate_api_key, hash_api_key
        from app.models.api_key import APIKey

        raw = generate_api_key()
        api_key = APIKey(
            id=uuid4(),
            name="t",
            key_hash=hash_api_key(raw),
            is_admin=True,
        )
        db_session.add(api_key)
        await db_session.commit()
        await _add_default_receive(
            db_session,
            api_key_id=api_key.id,
            description="OCEAN Payouts for bc1qabc",
        )

        with _patch_db_context(db_session):
            await reconciler.refresh_sticky_set()

        # Refresh always pushes — even if the set is empty, the
        # gateway needs the empty replacement to drop stale
        # entries.
        stub_runtime.set_sticky_peers.assert_awaited_once()
        pushed = stub_runtime.set_sticky_peers.await_args.args[0]
        assert len(pushed) == 1
        ocean = next(p for p in WELL_KNOWN_PAYERS if p.label == "OCEAN")
        assert pushed[0].node_id == bytes.fromhex(ocean.node_id_hex)

    @pytest.mark.asyncio
    async def test_refresh_is_noop_when_bolt12_disabled(
        self,
        stub_runtime,
        monkeypatch,
    ):
        monkeypatch.setattr(settings, "bolt12_enabled", False)
        monkeypatch.setattr(settings, "bolt12_gateway_grpc", "")
        await reconciler.refresh_sticky_set()
        stub_runtime.set_sticky_peers.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_refresh_swallows_compute_failures(
        self,
        stub_runtime,
        monkeypatch,
    ):
        # An exception during desired-set computation must not
        # propagate to the offer-mint caller — the user's configure
        # request must succeed even if the reconciler is sick.
        monkeypatch.setattr(settings, "bolt12_enabled", True)
        monkeypatch.setattr(
            settings,
            "bolt12_gateway_grpc",
            "localhost:9999",
        )

        async def _explode():
            raise RuntimeError("simulated DB blow-up")

        monkeypatch.setattr(
            reconciler,
            "_compute_desired_peers",
            _explode,
        )
        # Must not raise.
        await reconciler.refresh_sticky_set()


# ── lifecycle ─────────────────────────────────────────────────────


class TestReconcilerLifecycle:
    @pytest.mark.asyncio
    async def test_start_and_stop_are_idempotent(
        self,
        force_mainnet,
        stub_runtime,
        db_session,
        monkeypatch,
    ):
        # The reconciler's start guard skips when BOLT 12 is
        # disabled; force a non-empty target so the test exercises
        # the actual spawn path.
        monkeypatch.setattr(settings, "bolt12_enabled", True)
        monkeypatch.setattr(
            settings,
            "bolt12_gateway_grpc",
            "localhost:9999",
        )
        # First start: spawns the task. The startup pass runs
        # _compute_desired_peers which talks to the DB, so we wrap
        # the whole lifecycle in the db-context patch.
        with _patch_db_context(db_session):
            await reconciler.start_reconciler()
            try:
                task1 = reconciler._reconciler_task
                assert task1 is not None and not task1.done()
                # Second start: no-op (task already running).
                await reconciler.start_reconciler()
                assert reconciler._reconciler_task is task1
            finally:
                await reconciler.stop_reconciler()
        # Double-stop is safe.
        await reconciler.stop_reconciler()
        assert reconciler._reconciler_task is None

    @pytest.mark.asyncio
    async def test_start_skipped_when_bolt12_disabled(
        self,
        monkeypatch,
    ):
        # The reconciler must not spawn its task when BOLT 12 is
        # disabled or has no gateway target — otherwise the task
        # would idle forever, pushing empty sticky sets every 30 s
        # against a None client. Verify the guard.
        monkeypatch.setattr(settings, "bolt12_enabled", False)
        monkeypatch.setattr(settings, "bolt12_gateway_grpc", "")
        # Ensure no leftover task from prior tests.
        reconciler._reconciler_task = None
        await reconciler.start_reconciler()
        assert reconciler._reconciler_task is None, (
            "reconciler must not spawn a task when BOLT 12 is disabled — the loop would just no-op forever"
        )

    @pytest.mark.asyncio
    async def test_start_skipped_when_no_gateway_target(
        self,
        monkeypatch,
    ):
        # ``bolt12_enabled=True`` + empty target is the "I'd like
        # BOLT 12 but haven't configured the gateway yet" state.
        # The reconciler still skips — there's nothing to push to.
        monkeypatch.setattr(settings, "bolt12_enabled", True)
        monkeypatch.setattr(settings, "bolt12_gateway_grpc", "")
        reconciler._reconciler_task = None
        await reconciler.start_reconciler()
        assert reconciler._reconciler_task is None

    @pytest.mark.asyncio
    async def test_loop_survives_tick_exception(
        self,
        force_mainnet,
        stub_runtime,
        monkeypatch,
    ):
        # Wire a poisoned _compute_desired_peers that errors on the
        # first call but succeeds on the second. The reconciler must
        # log and continue past the first failure so a transient DB
        # blip doesn't kill the long-running loop.
        call_count = {"n": 0}

        async def _flaky():
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise RuntimeError("transient db error")
            return ()

        monkeypatch.setattr(
            reconciler,
            "_compute_desired_peers",
            _flaky,
        )
        # Use a tight interval so the test doesn't sleep forever.
        task = asyncio.create_task(
            reconciler.run_reconciler_loop(interval_s=0.05),
        )
        try:
            # Give the loop time to make at least two iterations.
            await asyncio.sleep(0.2)
            assert call_count["n"] >= 2, "loop must keep ticking after a thrown exception"
        finally:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
