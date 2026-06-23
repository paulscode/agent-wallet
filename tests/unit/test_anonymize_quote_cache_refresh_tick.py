# SPDX-License-Identifier: MIT
"""Quote-cache refresh tick wiring.

The refresh tick must:
* iterate operator entries (round-robin) — degenerating to the
  ``"default"`` operator id when no registry file is configured;
* issue the egress through the dedicated ``quote_cache_refresh``
  SOCKS listener (asserted indirectly by mocking
  :func:`fetch_reverse_pair_info_for_cache`);
* HMAC-sign the cached entry under
  ``ANONYMIZE_QUOTE_CACHE_SIGNING_KEY_FERNET`` so the read path can
  reject a tampered cache line.
"""

from __future__ import annotations

import pytest
from cryptography.fernet import Fernet

from app.core.config import settings
from app.services.anonymize import boltz_egress as boltz_egress_mod
from app.services.anonymize import service as anon_service
from app.services.anonymize.quote_cache import (
    CacheKey,
    get_quote_cache,
    reset_quote_cache,
    verify_cache_entry,
)


@pytest.fixture
def cache_signing_key(monkeypatch):
    monkeypatch.setattr(
        settings,
        "anonymize_quote_cache_signing_key_fernet",
        Fernet.generate_key().decode("ascii"),
    )


@pytest.fixture
def empty_registry(monkeypatch, tmp_path):
    """Force the operator registry to be empty so the refresh falls
    back to the single ``default`` operator id."""
    monkeypatch.setattr(
        settings,
        "anonymize_boltz_operator_registry_path",
        str(tmp_path / "nonexistent.json"),
    )


@pytest.fixture(autouse=True)
def reset_cache_between_tests():
    reset_quote_cache()
    yield
    reset_quote_cache()


@pytest.fixture
def skip_first_egress_jitter(monkeypatch):
    """Pre-mark the cache as already-jittered so ``_quote_cache_refresh_run``
    skips the first-egress sleep. Without this, every test that calls
    ``_quote_cache_refresh_run`` blocks 30–60 s on the production jitter
    sampler. The dedicated jitter test below opts OUT of this fixture
    by sampling sleep itself."""
    cache = get_quote_cache()
    cache._qc_first_egress_jitter_applied = True


@pytest.mark.asyncio
async def test_first_egress_jitter_sleeps_only_on_first_invocation(
    monkeypatch,
    cache_signing_key,
    empty_registry,
) -> None:
    """The first refresh sleeps a jitter window;
    subsequent invocations skip the sleep."""
    monkeypatch.setattr(
        settings,
        "anonymize_first_egress_bootstrap_jitter_s",
        5,
    )

    async def _payload(operator_id, **_):
        return {"fee": 1}, None

    monkeypatch.setattr(
        boltz_egress_mod,
        "fetch_reverse_pair_info_for_cache",
        _payload,
    )

    sleeps: list[float] = []

    async def _fake_sleep(duration):
        sleeps.append(duration)

    import asyncio as _asyncio

    monkeypatch.setattr(_asyncio, "sleep", _fake_sleep)

    await anon_service._quote_cache_refresh_run()
    await anon_service._quote_cache_refresh_run()
    # The first call slept once; the second skipped (no extra sleep).
    assert len(sleeps) == 1
    assert sleeps[0] >= 0.0


@pytest.mark.asyncio
async def test_refresh_tick_populates_signed_cache_entry(
    monkeypatch,
    cache_signing_key,
    empty_registry,
    skip_first_egress_jitter,
) -> None:
    captured: list[str] = []

    async def _stub(operator_id, **_):
        captured.append(operator_id)
        return {"fee_floor_sat_per_vb": 1.0, "min": 50_000}, None

    monkeypatch.setattr(
        boltz_egress_mod,
        "fetch_reverse_pair_info_for_cache",
        _stub,
    )

    await anon_service._quote_cache_refresh_run()

    # Default operator id used when registry is empty.
    assert captured == ["default"]

    cache = get_quote_cache()
    key = CacheKey(operator_id="default", pair="BTC/BTC", asset="BTC")
    entry = cache.get(key)
    assert entry is not None
    assert entry.payload["fee_floor_sat_per_vb"] == 1.0
    # Entry is HMAC-signed and verifies under the configured key.
    assert entry.operator_signature is not None
    assert verify_cache_entry(entry) is True


@pytest.mark.asyncio
async def test_refresh_tick_preserves_cache_on_egress_failure(
    monkeypatch,
    cache_signing_key,
    empty_registry,
    skip_first_egress_jitter,
) -> None:
    """A transient Boltz outage must not drop the cache to empty."""
    # Pre-populate the cache with a valid entry.
    cache = get_quote_cache()
    from app.services.anonymize.quote_cache import (
        CacheEntry,
        sign_cache_entry,
    )

    key = CacheKey(operator_id="default", pair="BTC/BTC", asset="BTC")
    sig = sign_cache_entry(
        key=key,
        payload={"fee": "old"},
        fetched_at_unix_s=500.0,
        signing_key_generation=0,
    )
    cache.put(
        CacheEntry(
            key=key,
            payload={"fee": "old"},
            fetched_at_unix_s=500.0,
            operator_signature=sig,
            signing_key_generation=0,
        )
    )

    async def _stub_fail(operator_id, **_):
        return None, "boltz transient outage"

    monkeypatch.setattr(
        boltz_egress_mod,
        "fetch_reverse_pair_info_for_cache",
        _stub_fail,
    )

    await anon_service._quote_cache_refresh_run()

    # Old entry is still present.
    entry = cache.get(key)
    assert entry is not None
    assert entry.payload == {"fee": "old"}


@pytest.mark.asyncio
async def test_refresh_tick_round_robins_across_registry(
    monkeypatch,
    cache_signing_key,
    tmp_path,
    skip_first_egress_jitter,
) -> None:
    """When a multi-operator registry is configured the refresh tick
    advances the cursor one operator per tick."""
    registry_path = tmp_path / "operators.json"
    registry_path.write_text(
        '[{"operator_id": "alpha", "onion": "abc.onion", '
        '"public_key_hex": "11"},'
        '{"operator_id": "beta", "onion": "def.onion", '
        '"public_key_hex": "22"}]'
    )
    monkeypatch.setattr(
        settings,
        "anonymize_boltz_operator_registry_path",
        str(registry_path),
    )

    captured: list[str] = []

    async def _stub(operator_id, **_):
        captured.append(operator_id)
        return {"fee": 1}, None

    monkeypatch.setattr(
        boltz_egress_mod,
        "fetch_reverse_pair_info_for_cache",
        _stub,
    )

    # Three ticks cycle alpha → beta → alpha.
    await anon_service._quote_cache_refresh_run()
    await anon_service._quote_cache_refresh_run()
    await anon_service._quote_cache_refresh_run()
    assert captured == ["alpha", "beta", "alpha"]
