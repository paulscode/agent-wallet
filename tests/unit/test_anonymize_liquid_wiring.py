# SPDX-License-Identifier: MIT
"""Liquid integration wiring — confirms the Liquid feature surface
actually reaches the production runtime, not just the unit tests.

Covers:

* ``hop_dispatcher.default_hop_step_fn`` dispatches to the Liquid hop
  body for ``awaiting_liquid_dwell`` AND for ``hopping`` sessions
  whose ``pipeline_json["uses_liquid"]`` flag is set.
* ``hop_dispatcher.build_default_liquid_hop_deps`` returns ``None``
  when the Liquid hop is disabled and a wired ``LiquidHopDeps``
  when it's enabled.
* ``startup.run_anonymize_startup_gates`` calls the Liquid startup
  asserts so a misconfigured deploy fails at boot, not at quote.
* ``liquid_seed.load_liquid_master_blinding_key`` returns ``None``
  when the bundle is unset and the SLIP-77 master key when set.
"""

from __future__ import annotations

from unittest.mock import patch
from uuid import uuid4

import pytest
from cryptography.fernet import Fernet

from app.core.config import settings
from app.models.anonymize_session import AnonymizeSession, AnonymizeStatus
from app.services.anonymize.hop_dispatcher import (
    build_default_liquid_hop_deps,
    default_hop_step_fn,
    reset_default_liquid_hop_deps_cache,
)
from app.services.anonymize.hops.liquid import LiquidHopDeps
from app.services.anonymize.liquid_seed import (
    LiquidSeedError,
    load_liquid_master_blinding_key,
)


@pytest.fixture(autouse=True)
def _reset_hop_deps_cache():
    """The dispatcher caches deps module-locally; reset between tests."""
    reset_default_liquid_hop_deps_cache()
    yield
    reset_default_liquid_hop_deps_cache()


# ── load_liquid_master_blinding_key ────────────────────────────────


def test_load_master_blinding_key_returns_none_when_unset(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_liquid_seed_fernet", "")
    assert load_liquid_master_blinding_key() is None


def test_load_master_blinding_key_returns_64_bytes_when_set(monkeypatch) -> None:
    key = Fernet.generate_key().decode("ascii")
    monkeypatch.setattr(settings, "anonymize_liquid_seed_fernet", key)
    out = load_liquid_master_blinding_key()
    assert isinstance(out, bytes)
    assert len(out) == 64


def test_load_master_blinding_key_is_deterministic(monkeypatch) -> None:
    """Same Fernet bundle config → same master key. The hop has to be
    deterministic across process restarts."""
    key = Fernet.generate_key().decode("ascii")
    monkeypatch.setattr(settings, "anonymize_liquid_seed_fernet", key)
    a = load_liquid_master_blinding_key()
    b = load_liquid_master_blinding_key()
    assert a == b


def test_load_master_blinding_key_uses_first_key_only(monkeypatch) -> None:
    """Multi-key bundles: only the first key derives the master so a
    rotation that adds a new key doesn't change the derivation."""
    k1 = Fernet.generate_key().decode("ascii")
    k2 = Fernet.generate_key().decode("ascii")
    monkeypatch.setattr(settings, "anonymize_liquid_seed_fernet", k1)
    only_first = load_liquid_master_blinding_key()
    monkeypatch.setattr(
        settings,
        "anonymize_liquid_seed_fernet",
        f"{k1},{k2}",
    )
    with_second = load_liquid_master_blinding_key()
    assert only_first == with_second


def test_load_master_blinding_key_rejects_malformed_first_key(monkeypatch) -> None:
    monkeypatch.setattr(
        settings,
        "anonymize_liquid_seed_fernet",
        "not-base64!!!",
    )
    with pytest.raises(LiquidSeedError):
        load_liquid_master_blinding_key()


# ── build_default_liquid_hop_deps ──────────────────────────────────


def test_build_default_returns_none_when_liquid_disabled(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_liquid_enabled", False)
    assert build_default_liquid_hop_deps() is None


def test_build_default_raises_when_enabled_without_electrum_url(
    monkeypatch,
) -> None:
    monkeypatch.setattr(settings, "anonymize_liquid_enabled", True)
    monkeypatch.setattr(settings, "anonymize_liquid_electrum_url", "")
    with pytest.raises(RuntimeError) as exc:
        build_default_liquid_hop_deps()
    assert "ANONYMIZE_LIQUID_ELECTRUM_URL" in str(exc.value)


def test_build_default_raises_when_enabled_without_seed(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_liquid_enabled", True)
    monkeypatch.setattr(
        settings,
        "anonymize_liquid_electrum_url",
        "tcp://electrs:50001",
    )
    monkeypatch.setattr(settings, "anonymize_liquid_seed_fernet", "")
    with pytest.raises(RuntimeError) as exc:
        build_default_liquid_hop_deps()
    assert "ANONYMIZE_LIQUID_SEED_FERNET" in str(exc.value)


def test_build_default_raises_when_boltz_chain_urls_unset(monkeypatch) -> None:
    """When both env-pin URLs are empty AND the signed registry is
    unavailable, the dispatcher must refuse — it has no operator URL
    to target. With the registry available, the dispatcher falls back
    to registry-driven selection (covered by a separate test)."""
    monkeypatch.setattr(settings, "anonymize_liquid_enabled", True)
    monkeypatch.setattr(
        settings,
        "anonymize_liquid_electrum_url",
        "tcp://electrs:50001",
    )
    monkeypatch.setattr(
        settings,
        "anonymize_liquid_seed_fernet",
        Fernet.generate_key().decode("ascii"),
    )
    # Bitcoin mainnet → L-BTC asset id is built-in so the resolution
    # passes and the next check (Boltz URLs) fires.
    monkeypatch.setattr(settings, "bitcoin_network", "bitcoin")
    monkeypatch.setattr(settings, "boltz_chain_ln_to_lbtc_api_url", "")
    monkeypatch.setattr(settings, "boltz_chain_lbtc_to_ln_api_url", "")
    # Point the registry loader at a path that does not exist so
    # the env-empty branch in select_liquid_leg_urls() fails with
    # "no URL available".
    monkeypatch.setattr(
        settings,
        "anonymize_boltz_operator_registry_path",
        "/nonexistent/operators.json",
    )
    with pytest.raises(RuntimeError) as exc:
        build_default_liquid_hop_deps()
    assert "no chain-swap operator URL" in str(exc.value) or "BOLTZ_CHAIN" in str(exc.value)


def test_build_default_succeeds_when_fully_configured(monkeypatch) -> None:
    """Happy path: every required knob set → a real LiquidHopDeps."""
    monkeypatch.setattr(settings, "anonymize_liquid_enabled", True)
    monkeypatch.setattr(
        settings,
        "anonymize_liquid_electrum_url",
        "tcp://electrs:50001",
    )
    monkeypatch.setattr(
        settings,
        "anonymize_liquid_seed_fernet",
        Fernet.generate_key().decode("ascii"),
    )
    monkeypatch.setattr(
        settings,
        "boltz_chain_ln_to_lbtc_api_url",
        "https://boltz-a.invalid",
    )
    monkeypatch.setattr(
        settings,
        "boltz_chain_lbtc_to_ln_api_url",
        "https://boltz-b.invalid",
    )
    monkeypatch.setattr(settings, "bitcoin_network", "bitcoin")
    deps = build_default_liquid_hop_deps()
    assert deps is not None
    assert isinstance(deps, LiquidHopDeps)


def test_build_default_caches_deps_across_calls(monkeypatch) -> None:
    """The dispatcher calls the factory once per process; subsequent
    calls must return the cached instance so the ElectrumClient +
    swap_state map aren't duplicated."""
    monkeypatch.setattr(settings, "anonymize_liquid_enabled", True)
    monkeypatch.setattr(
        settings,
        "anonymize_liquid_electrum_url",
        "tcp://electrs:50001",
    )
    monkeypatch.setattr(
        settings,
        "anonymize_liquid_seed_fernet",
        Fernet.generate_key().decode("ascii"),
    )
    monkeypatch.setattr(
        settings,
        "boltz_chain_ln_to_lbtc_api_url",
        "https://boltz-a.invalid",
    )
    monkeypatch.setattr(
        settings,
        "boltz_chain_lbtc_to_ln_api_url",
        "https://boltz-b.invalid",
    )
    monkeypatch.setattr(settings, "bitcoin_network", "bitcoin")
    a = build_default_liquid_hop_deps()
    b = build_default_liquid_hop_deps()
    assert a is b


# ── default_hop_step_fn dispatch ───────────────────────────────────


def _session(*, status: str, pj: dict | None = None) -> AnonymizeSession:
    return AnonymizeSession(
        id=uuid4(),
        status=status,
        source_kind="lightning-self",
        requested_amount_sat=250_000,
        bin_amount_sat=250_000,
        pipeline_json=pj or {},
        quote_hmac=b"x" * 32,
        destination_address_enc=b"ct",
        destination_script_type="p2tr",
        pipeline_schema_version=10,
        destination_address_blake2b_keyed=b"\xab" * 32,
        destination_reuse_key_generation=0,
    )


def _enable_liquid(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_liquid_enabled", True)
    monkeypatch.setattr(
        settings,
        "anonymize_liquid_electrum_url",
        "tcp://electrs:50001",
    )
    monkeypatch.setattr(
        settings,
        "anonymize_liquid_seed_fernet",
        Fernet.generate_key().decode("ascii"),
    )
    monkeypatch.setattr(
        settings,
        "boltz_chain_ln_to_lbtc_api_url",
        "https://boltz-a.invalid",
    )
    monkeypatch.setattr(
        settings,
        "boltz_chain_lbtc_to_ln_api_url",
        "https://boltz-b.invalid",
    )
    monkeypatch.setattr(settings, "bitcoin_network", "bitcoin")


@pytest.mark.asyncio
async def test_dispatch_routes_awaiting_liquid_dwell_to_liquid(
    db_session,
    monkeypatch,
) -> None:
    _enable_liquid(monkeypatch)
    captured: list[str] = []

    async def _fake_liquid(db, session, deps):
        captured.append("liquid")
        return "liquid-noop"

    async def _fake_reverse(db, session, deps):
        captured.append("reverse")
        return "reverse-noop"

    with (
        patch(
            "app.services.anonymize.hop_dispatcher.execute_liquid_hop_step",
            _fake_liquid,
        ),
        patch(
            "app.services.anonymize.hop_dispatcher.execute_reverse_hop_step",
            _fake_reverse,
        ),
    ):
        fn = default_hop_step_fn()
        sess = _session(status=AnonymizeStatus.AWAITING_LIQUID_DWELL.value)
        await fn(db_session, sess)
    assert captured == ["liquid"]


@pytest.mark.asyncio
async def test_dispatch_routes_hopping_with_uses_liquid_marker_to_liquid(
    db_session,
    monkeypatch,
) -> None:
    _enable_liquid(monkeypatch)
    captured: list[str] = []

    async def _fake_liquid(db, session, deps):
        captured.append("liquid")

    async def _fake_reverse(db, session, deps):
        captured.append("reverse")

    with (
        patch(
            "app.services.anonymize.hop_dispatcher.execute_liquid_hop_step",
            _fake_liquid,
        ),
        patch(
            "app.services.anonymize.hop_dispatcher.execute_reverse_hop_step",
            _fake_reverse,
        ),
    ):
        fn = default_hop_step_fn()
        sess = _session(
            status=AnonymizeStatus.HOPPING.value,
            pj={"uses_liquid": True},
        )
        await fn(db_session, sess)
    assert captured == ["liquid"]


@pytest.mark.asyncio
async def test_dispatch_routes_hopping_without_marker_to_reverse(
    db_session,
    monkeypatch,
) -> None:
    """A regular LN-source hopping session — no Liquid marker — must
    still route to the reverse hop body, even when Liquid is enabled
    globally. Otherwise non-Liquid sessions would silently mis-route."""
    _enable_liquid(monkeypatch)
    captured: list[str] = []

    async def _fake_liquid(db, session, deps):
        captured.append("liquid")

    async def _fake_reverse(db, session, deps):
        captured.append("reverse")

    with (
        patch(
            "app.services.anonymize.hop_dispatcher.execute_liquid_hop_step",
            _fake_liquid,
        ),
        patch(
            "app.services.anonymize.hop_dispatcher.execute_reverse_hop_step",
            _fake_reverse,
        ),
    ):
        fn = default_hop_step_fn()
        sess = _session(status=AnonymizeStatus.HOPPING.value, pj={})
        await fn(db_session, sess)
    assert captured == ["reverse"]


@pytest.mark.asyncio
async def test_dispatch_routes_to_reverse_when_liquid_disabled(
    db_session,
    monkeypatch,
) -> None:
    """Even with the awaiting_liquid_dwell status, if Liquid is
    disabled globally the dispatcher must NOT call the Liquid body
    (it would NotImplementedError or produce a no-op). Fall through
    to the reverse hop, which will route the session to
    reconciliation if the status doesn't fit."""
    monkeypatch.setattr(settings, "anonymize_liquid_enabled", False)
    captured: list[str] = []

    async def _fake_liquid(db, session, deps):
        captured.append("liquid")

    async def _fake_reverse(db, session, deps):
        captured.append("reverse")

    with (
        patch(
            "app.services.anonymize.hop_dispatcher.execute_liquid_hop_step",
            _fake_liquid,
        ),
        patch(
            "app.services.anonymize.hop_dispatcher.execute_reverse_hop_step",
            _fake_reverse,
        ),
    ):
        fn = default_hop_step_fn()
        sess = _session(status=AnonymizeStatus.AWAITING_LIQUID_DWELL.value)
        await fn(db_session, sess)
    assert captured == ["reverse"]


# ── Startup gates ──────────────────────────────────────────────────


def test_startup_gates_call_liquid_asserts(monkeypatch) -> None:
    """When Liquid is enabled, a missing seed must fail at boot —
    via assert_liquid_seed_configured being called from
    run_anonymize_startup_gates."""
    monkeypatch.setattr(settings, "anonymize_liquid_enabled", True)
    monkeypatch.setattr(settings, "anonymize_liquid_seed_fernet", "")
    # Stub out the non-Liquid gates so we exercise only the Liquid one.
    with (
        patch(
            "app.services.anonymize.startup.assert_onion_only_egress",
            lambda: None,
        ),
        patch(
            "app.services.anonymize.startup.assert_signed_operator_registry_loadable",
            lambda: (True, 0),
        ),
    ):
        from app.services.anonymize.startup import run_anonymize_startup_gates

        with pytest.raises(LiquidSeedError):
            run_anonymize_startup_gates()


def test_startup_gates_noop_when_liquid_disabled(monkeypatch) -> None:
    """When Liquid is disabled, the Liquid gates pass silently even
    with no seed / no asset-id config."""
    monkeypatch.setattr(settings, "anonymize_liquid_enabled", False)
    monkeypatch.setattr(settings, "anonymize_liquid_seed_fernet", "")
    monkeypatch.setattr(settings, "anonymize_liquid_btc_asset_id", "")
    monkeypatch.setattr(settings, "bitcoin_network", "regtest")
    with (
        patch(
            "app.services.anonymize.startup.assert_onion_only_egress",
            lambda: None,
        ),
        patch(
            "app.services.anonymize.startup.assert_signed_operator_registry_loadable",
            lambda: (True, 0),
        ),
        patch(
            "app.services.anonymize.startup.assert_anonymize_tor_distinct_from_lnd",
            lambda: True,
        ),
        patch(
            "app.services.anonymize.startup.assert_node_binary_present",
            lambda: True,
        ),
        patch(
            "app.services.anonymize.startup.assert_subprocess_lockfile_present",
            lambda: True,
        ),
    ):
        from app.services.anonymize.startup import run_anonymize_startup_gates

        # Must NOT raise.
        out = run_anonymize_startup_gates()
        assert isinstance(out, dict)
