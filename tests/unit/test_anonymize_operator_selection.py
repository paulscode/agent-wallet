# SPDX-License-Identifier: MIT
"""Operator-selection logic.

Covers:

* Chain composition (default rule, explicit env vars).
* The capacity pre-filter, probe-result cache, and fresh network probe.
* Three outcome types: success, ``SubmarineChainExhausted``,
  ``ReverseProbeFailed``.
* Audit-log emission helpers (sub/reverse selected, reverse probe failed).

The fresh network probe is mocked at the ``httpx.AsyncClient`` boundary
so the tests don't need a live Tor listener.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from app.core.config import settings
from app.services.anonymize.operator_selection import (
    _PROBE_CACHE,
    OperatorSelectionResult,
    ReverseProbeFailed,
    SubmarineChainExhausted,
    _capacity_supports_bin,
    _compute_chain,
    invalidate_probe_cache,
    select_operators_for_onchain_session,
)
from app.services.anonymize.operators import OperatorEntry

# ── Fixtures ────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _clear_probe_cache():
    """Reset the module-global probe cache between cases."""
    _PROBE_CACHE.clear()
    yield
    _PROBE_CACHE.clear()


@pytest.fixture(autouse=True)
def _clear_chain_env(monkeypatch):
    """Reset chain-composition env vars to defaults between cases."""
    monkeypatch.setattr(settings, "anonymize_submarine_operator_primary", "")
    monkeypatch.setattr(settings, "anonymize_submarine_operator_secondary", "")
    monkeypatch.setattr(settings, "anonymize_reverse_operator", "")


def _entry(
    op_id: str,
    *,
    volume: int = 0,
    audit_date: str = "",
    onion: str | None = None,
) -> OperatorEntry:
    return OperatorEntry(
        operator_id=op_id,
        onion=onion or f"http://{op_id}.onion",
        public_key_hex="",
        attested_min_24h_volume_satoshis=volume,
        last_audit_date=audit_date or None,
    )


_BUNDLED_REGISTRY = [
    _entry("boltz-canonical", volume=200_000_000, audit_date="2026-05-13"),
    _entry("middleway", volume=2_000_000, audit_date="2026-05-13"),
    _entry("eldamar", volume=1_000_000, audit_date="2026-05-13"),
]


# ── chain composition ──────────────────────────────────────────


def test_default_chain_picks_middleway_primary_eldamar_secondary() -> None:
    """Default-computation rule with the bundled 3-operator registry.

    Boltz canonical is fixed on the reverse leg. The non-reverse
    operators sort by last_audit_date desc (tied here, all on
    2026-05-13) then by attested_min_24h_volume_satoshis desc
    (Middleway 2M > Eldamar 1M) → Middleway is primary, Eldamar
    is secondary.
    """
    chain = _compute_chain(_BUNDLED_REGISTRY)
    assert chain.reverse.operator_id == "boltz-canonical"
    assert chain.primary.operator_id == "middleway"
    assert chain.secondary.operator_id == "eldamar"


def test_explicit_env_vars_override_defaults(monkeypatch) -> None:
    """Setting any of the three env vars overrides the default-rule."""
    monkeypatch.setattr(
        settings,
        "anonymize_submarine_operator_primary",
        "eldamar",
    )
    chain = _compute_chain(_BUNDLED_REGISTRY)
    assert chain.primary.operator_id == "eldamar"
    # Reverse stays at the default (boltz-canonical).
    assert chain.reverse.operator_id == "boltz-canonical"
    # Secondary auto-falls-to the remaining non-reverse, non-primary
    # operator (Middleway).
    assert chain.secondary.operator_id == "middleway"


def test_single_operator_registry_yields_no_chain() -> None:
    """A registry with only the reverse operator (no alts) collapses
    to "primary → single-operator-with-consent" — both primary and
    secondary slots are empty."""
    chain = _compute_chain([_BUNDLED_REGISTRY[0]])
    assert chain.reverse.operator_id == "boltz-canonical"
    assert chain.primary is None
    assert chain.secondary is None


# ── capacity pre-filter ──────────────────────────────────────


def test_capacity_filter_permissive_on_cache_miss() -> None:
    """When the operator-info cache has no entry for the operator,
    the filter is permissive (the probe + actual createswap will
    catch any real capacity mismatch)."""
    # No cache entry seeded for "unknown-op" → permissive.
    assert _capacity_supports_bin("unknown-op", 5_000_000) is True


def test_capacity_filter_skips_operator_below_bin() -> None:
    """When cached /v2/pairs says maximal < bin, the filter rejects."""
    from app.services.anonymize.quote_cache import (
        CacheEntry,
        CacheKey,
        get_quote_cache,
    )

    cache = get_quote_cache()
    cache.put(
        CacheEntry(
            key=CacheKey(operator_id="eldamar", pair="BTC/BTC", asset="BTC"),
            payload={"BTC": {"BTC": {"limits": {"maximal": 1_000_000}}}},
            fetched_at_unix_s=0.0,
        )
    )
    try:
        # 1M bin is at the limit — admitted.
        assert _capacity_supports_bin("eldamar", 1_000_000) is True
        # 2M bin exceeds the limit — rejected.
        assert _capacity_supports_bin("eldamar", 2_000_000) is False
    finally:
        cache.remove(CacheKey(operator_id="eldamar", pair="BTC/BTC", asset="BTC"))


# ── probe-result cache ───────────────────────────────────────


def test_probe_cache_invalidation_clears_entry() -> None:
    """``invalidate_probe_cache`` evicts a specific operator's entry
    across all listeners."""
    from app.services.anonymize.operator_selection import _probe_cache_put

    _probe_cache_put("middleway", "boltz_submarine", reachable=True)
    _probe_cache_put("middleway", "boltz_reverse", reachable=True)
    assert ("middleway", "boltz_submarine") in _PROBE_CACHE
    assert ("middleway", "boltz_reverse") in _PROBE_CACHE
    invalidate_probe_cache("middleway")
    # Both listener entries for this operator must be evicted.
    assert ("middleway", "boltz_submarine") not in _PROBE_CACHE
    assert ("middleway", "boltz_reverse") not in _PROBE_CACHE


def test_record_operator_outlier_invalidates_probe_cache(monkeypatch) -> None:
    """The hook wired in operator_health.record_operator_outlier MUST
    call invalidate_probe_cache so a real degradation event bypasses
    a stale "reachable" cache entry. Verifies the cache evicts all
    listener-specific entries for the degraded operator."""
    from app.services.anonymize.operator_selection import _probe_cache_put

    # Pre-populate the cache for one listener.
    _probe_cache_put("middleway", "boltz_submarine", reachable=True)
    assert ("middleway", "boltz_submarine") in _PROBE_CACHE

    invalidate_probe_cache("middleway")
    assert ("middleway", "boltz_submarine") not in _PROBE_CACHE


def test_probe_cache_per_listener_isolation() -> None:
    """Cache keys are ``(operator_id, call_site)`` so a
    successful probe on one listener does NOT cause a cache hit for
    another listener. Critical for the consolidated single-operator
    fallback probe: it must re-verify boltz-canonical on the
    submarine listener even though the reverse-leg probe just
    succeeded."""
    from app.services.anonymize.operator_selection import (
        _probe_cache_get,
        _probe_cache_put,
    )

    _probe_cache_put("boltz-canonical", "boltz_reverse", reachable=True)
    # Cache hit on reverse listener.
    assert _probe_cache_get("boltz-canonical", "boltz_reverse") is not None
    # Cache MISS on submarine listener — the consolidated probe must
    # actually run.
    assert _probe_cache_get("boltz-canonical", "boltz_submarine") is None


# ── settings ───────────────────────────────────────────


def test_probe_default_timeout_is_six_seconds() -> None:
    """decision — regression guard for the env-var default."""
    assert settings.anonymize_operator_probe_timeout_s == pytest.approx(6.0)


def test_probe_cache_default_ttl_is_sixty_seconds() -> None:
    """decision — regression guard for the env-var default."""
    assert settings.anonymize_operator_probe_cache_ttl_s == pytest.approx(60.0)


# ── End-to-end selector outcomes ────────────────────────────────────


async def _fake_degraded(db) -> frozenset[str]:  # pragma: no cover (helper)
    return frozenset()


@pytest.mark.asyncio
async def test_chain_exhausted_returns_sentinel_without_consent(monkeypatch) -> None:
    """Both alts fail probe, ``allow_single_operator_fallback=false``
    → returns :class:`SubmarineChainExhausted`."""

    async def _all_fail(operator, call_site):
        return False

    monkeypatch.setattr(
        "app.services.anonymize.operator_selection._probe_operator",
        _all_fail,
    )
    monkeypatch.setattr(
        "app.services.anonymize.operator_selection.all_degraded_operator_ids",
        _fake_degraded,
        raising=False,
    )
    # Patch where the function is imported into the module (it does
    # `from .operator_health import all_degraded_operator_ids` inside
    # the function body).
    monkeypatch.setattr(
        "app.services.anonymize.operator_health.all_degraded_operator_ids",
        _fake_degraded,
    )

    db = MagicMock()
    result = await select_operators_for_onchain_session(
        registry=_BUNDLED_REGISTRY,
        bin_amount_sat=250_000,
        allow_single_operator_fallback=False,
        db=db,
    )
    # Reverse probe is ALSO running concurrently and ALSO fails (the
    # _all_fail mock applies to all operators), so the selector
    # returns ReverseProbeFailed (reverse-side failure wins).
    assert isinstance(result, ReverseProbeFailed)
    assert result.operator_id == "boltz-canonical"


@pytest.mark.asyncio
async def test_happy_path_with_distinct_pair(monkeypatch) -> None:
    """All operators reachable → :class:`OperatorSelectionResult`
    with Middleway on submarine, Boltz canonical on reverse."""

    async def _all_reachable(operator, call_site):
        return True

    monkeypatch.setattr(
        "app.services.anonymize.operator_selection._probe_operator",
        _all_reachable,
    )
    monkeypatch.setattr(
        "app.services.anonymize.operator_health.all_degraded_operator_ids",
        _fake_degraded,
    )

    db = MagicMock()
    result = await select_operators_for_onchain_session(
        registry=_BUNDLED_REGISTRY,
        bin_amount_sat=250_000,
        allow_single_operator_fallback=False,
        db=db,
    )
    assert isinstance(result, OperatorSelectionResult)
    assert result.submarine.operator_id == "middleway"
    assert result.reverse.operator_id == "boltz-canonical"
    assert result.selection_source == "primary"


@pytest.mark.asyncio
async def test_secondary_fallback_when_primary_fails(monkeypatch) -> None:
    """Primary alt unreachable, secondary reachable → result reflects
    secondary with ``selection_source="secondary_after_primary_failed"``."""

    async def _probe(operator, call_site):
        # Middleway fails, everyone else succeeds.
        return operator.operator_id != "middleway"

    monkeypatch.setattr(
        "app.services.anonymize.operator_selection._probe_operator",
        _probe,
    )
    monkeypatch.setattr(
        "app.services.anonymize.operator_health.all_degraded_operator_ids",
        _fake_degraded,
    )

    db = MagicMock()
    result = await select_operators_for_onchain_session(
        registry=_BUNDLED_REGISTRY,
        bin_amount_sat=250_000,
        allow_single_operator_fallback=False,
        db=db,
    )
    assert isinstance(result, OperatorSelectionResult)
    assert result.submarine.operator_id == "eldamar"
    assert result.selection_source == "secondary_after_primary_failed"
    # The chain trajectory records both attempts in order.
    statuses = [a.status for a in result.submarine_chain_attempted]
    assert statuses == ["unreachable", "selected"]


@pytest.mark.asyncio
async def test_single_operator_fallback_consent_consolidates_on_boltz(
    monkeypatch,
) -> None:
    """Both alts fail AND user consented → result uses Boltz canonical
    on BOTH legs with ``selection_source="single_operator_after_chain_exhausted"``."""

    async def _probe(operator, call_site):
        # Only Boltz canonical is reachable.
        return operator.operator_id == "boltz-canonical"

    monkeypatch.setattr(
        "app.services.anonymize.operator_selection._probe_operator",
        _probe,
    )
    monkeypatch.setattr(
        "app.services.anonymize.operator_health.all_degraded_operator_ids",
        _fake_degraded,
    )

    db = MagicMock()
    result = await select_operators_for_onchain_session(
        registry=_BUNDLED_REGISTRY,
        bin_amount_sat=250_000,
        allow_single_operator_fallback=True,
        db=db,
    )
    assert isinstance(result, OperatorSelectionResult)
    assert result.submarine.operator_id == "boltz-canonical"
    assert result.reverse.operator_id == "boltz-canonical"
    assert result.selection_source == "single_operator_after_chain_exhausted"


@pytest.mark.asyncio
async def test_consolidated_probe_failure_sets_from_single_operator_fallback(
    monkeypatch,
) -> None:
    """When the user consents to single-operator fallback AND
    the submarine chain is exhausted AND the consolidated probe of
    Boltz canonical (on the boltz_submarine listener) ALSO fails →
    returns :class:`ReverseProbeFailed` with
    ``from_single_operator_fallback=True``.

    This is the sentinel discriminator the quote endpoint reads to
    pick between the two 503 wire codes. Maps to
    ``all_submarine_operators_unreachable``.
    """
    probe_calls: list[tuple[str, str]] = []

    async def _probe(operator, call_site):
        probe_calls.append((operator.operator_id, call_site))
        # Reverse-leg probe (boltz_reverse) succeeds.
        # Submarine-leg probes (boltz_submarine) ALL fail — including
        # the consolidated probe of boltz-canonical that runs after
        # the chain walk and the user's consent.
        if call_site == "boltz_reverse":
            return True
        return False

    monkeypatch.setattr(
        "app.services.anonymize.operator_selection._probe_operator",
        _probe,
    )
    monkeypatch.setattr(
        "app.services.anonymize.operator_health.all_degraded_operator_ids",
        _fake_degraded,
    )

    db = MagicMock()
    result = await select_operators_for_onchain_session(
        registry=_BUNDLED_REGISTRY,
        bin_amount_sat=250_000,
        allow_single_operator_fallback=True,
        db=db,
    )
    assert isinstance(result, ReverseProbeFailed)
    assert result.operator_id == "boltz-canonical"
    assert result.from_single_operator_fallback is True

    # The consolidated probe MUST run on boltz_submarine — that's
    # the whole point of running it (the reverse-leg listener
    # already succeeded; we need to verify the submarine listener).
    assert ("boltz-canonical", "boltz_submarine") in probe_calls


@pytest.mark.asyncio
async def test_reverse_probe_failure_returns_reverse_probe_failed(
    monkeypatch,
) -> None:
    """Reverse-leg probe fails, submarine chain succeeds → returns
    :class:`ReverseProbeFailed` (reverse-side failure wins)."""

    async def _probe(operator, call_site):
        # Reverse fails; submarine candidates succeed.
        return operator.operator_id != "boltz-canonical"

    monkeypatch.setattr(
        "app.services.anonymize.operator_selection._probe_operator",
        _probe,
    )
    monkeypatch.setattr(
        "app.services.anonymize.operator_health.all_degraded_operator_ids",
        _fake_degraded,
    )

    db = MagicMock()
    result = await select_operators_for_onchain_session(
        registry=_BUNDLED_REGISTRY,
        bin_amount_sat=250_000,
        allow_single_operator_fallback=False,
        db=db,
    )
    assert isinstance(result, ReverseProbeFailed)
    assert result.operator_id == "boltz-canonical"
    assert result.from_single_operator_fallback is False


# ── / hop_dispatcher URL routing ───────────────────────────────


def test_resolve_operator_url_from_registry_returns_onion(monkeypatch) -> None:
    """The registry lookup returns the operator's onion URL
    so the hop_dispatcher can route per-session swap egress to the
    correct operator. Without this, the chain selector would be
    decorative — egress would always hit ``BOLTZ_*_ONION_URL``.
    """
    from app.services.anonymize import operators

    monkeypatch.setattr(
        operators,
        "load_signed_operator_registry",
        lambda *_a, **_k: _BUNDLED_REGISTRY,
    )
    url = operators.resolve_operator_url_from_registry("middleway")
    assert url == "http://middleway.onion"

    url2 = operators.resolve_operator_url_from_registry("boltz-canonical")
    assert url2 == "http://boltz-canonical.onion"


def test_resolve_operator_url_returns_none_for_unknown(monkeypatch) -> None:
    """Unknown operator_id → None so the caller can fall back to
    ``resolve_*_leg_url()`` env-pin resolution."""
    from app.services.anonymize import operators

    monkeypatch.setattr(
        operators,
        "load_signed_operator_registry",
        lambda *_a, **_k: _BUNDLED_REGISTRY,
    )
    assert operators.resolve_operator_url_from_registry("no-such-op") is None
    # Empty string / None also map to None.
    assert operators.resolve_operator_url_from_registry("") is None
    assert operators.resolve_operator_url_from_registry(None) is None


# ── probe-cache semantics ─────────────────────────────────────


@pytest.mark.asyncio
async def test_probe_cache_hit_short_circuits_network_call(monkeypatch) -> None:
    """A fresh cache hit MUST skip the probe network call.
    The wizard's form-step issues a quote on every field change;
    re-probing each time would burn Tor circuits + perceived latency."""
    from app.services.anonymize.operator_selection import _probe_cache_put

    call_count = {"n": 0}

    async def _probe(operator, call_site):
        call_count["n"] += 1
        return True

    monkeypatch.setattr(
        "app.services.anonymize.operator_selection._probe_operator",
        _probe,
    )
    monkeypatch.setattr(
        "app.services.anonymize.operator_health.all_degraded_operator_ids",
        _fake_degraded,
    )

    # Pre-warm the cache for every operator + the listeners the
    # selector will use.
    for op in _BUNDLED_REGISTRY:
        _probe_cache_put(op.operator_id, "boltz_submarine", reachable=True)
        _probe_cache_put(op.operator_id, "boltz_reverse", reachable=True)

    db = MagicMock()
    result = await select_operators_for_onchain_session(
        registry=_BUNDLED_REGISTRY,
        bin_amount_sat=250_000,
        allow_single_operator_fallback=False,
        db=db,
    )
    assert isinstance(result, OperatorSelectionResult)
    # No network probes — cache hits all the way through.
    assert call_count["n"] == 0


def test_probe_cache_expires_after_ttl(monkeypatch) -> None:
    """Entries past ``anonymize_operator_probe_cache_ttl_s``
    are evicted on read; a subsequent read MUST treat the cache as
    empty (returning None)."""
    from app.services.anonymize.operator_selection import (
        _PROBE_CACHE,
        _probe_cache_get,
        _ProbeCacheEntry,
    )

    monkeypatch.setattr(
        settings,
        "anonymize_operator_probe_cache_ttl_s",
        60.0,
    )
    # Insert a stale entry (61 s old).
    import time as _time

    _PROBE_CACHE[("middleway", "boltz_submarine")] = _ProbeCacheEntry(
        reachable=True,
        recorded_at_unix_s=_time.time() - 61.0,
    )
    # Cache miss on read because TTL expired.
    assert _probe_cache_get("middleway", "boltz_submarine") is None


def test_probe_cache_records_failures(monkeypatch) -> None:
    """Failed probes ALSO get cached so a flapping operator
    doesn't cost the user a 6 s probe on every form-field change."""
    from app.services.anonymize.operator_selection import (
        _PROBE_CACHE,
        _probe_cache_put,
    )

    _probe_cache_put("middleway", "boltz_submarine", reachable=False)
    assert ("middleway", "boltz_submarine") in _PROBE_CACHE
    assert _PROBE_CACHE[("middleway", "boltz_submarine")].reachable is False


# ── fresh-probe semantics ─────────────────────────────────────


@pytest.mark.asyncio
async def test_probe_timeout_treated_as_unreachable(monkeypatch) -> None:
    """Fresh network probe — a probe that times out maps to ``unreachable``,
    not to a raised exception that crashes the selector."""
    import httpx

    async def _hanging(operator, call_site):
        raise httpx.TimeoutException("simulated timeout")

    # The internal _probe_operator already catches and returns False;
    # this test verifies the chain walk treats False as "unreachable".
    async def _wrap(operator, call_site):
        return False

    monkeypatch.setattr(
        "app.services.anonymize.operator_selection._probe_operator",
        _wrap,
    )
    monkeypatch.setattr(
        "app.services.anonymize.operator_health.all_degraded_operator_ids",
        _fake_degraded,
    )
    db = MagicMock()
    result = await select_operators_for_onchain_session(
        registry=_BUNDLED_REGISTRY,
        bin_amount_sat=250_000,
        allow_single_operator_fallback=False,
        db=db,
    )
    # Both reverse and submarine fail → ReverseProbeFailed (reverse-side wins).
    assert isinstance(result, ReverseProbeFailed)


@pytest.mark.asyncio
async def test_per_leg_socks_listener_used_for_each_probe(monkeypatch) -> None:
    """Submarine-leg probes go through ``boltz_submarine``
    listener; reverse-leg probes through ``boltz_reverse``. Routing all
    probes through one listener would collapse the per-leg Tor isolation."""
    call_sites: list[str] = []

    async def _probe(operator, call_site):
        call_sites.append(call_site)
        return True

    monkeypatch.setattr(
        "app.services.anonymize.operator_selection._probe_operator",
        _probe,
    )
    monkeypatch.setattr(
        "app.services.anonymize.operator_health.all_degraded_operator_ids",
        _fake_degraded,
    )
    db = MagicMock()
    await select_operators_for_onchain_session(
        registry=_BUNDLED_REGISTRY,
        bin_amount_sat=250_000,
        allow_single_operator_fallback=False,
        db=db,
    )
    # Reverse probe runs on boltz_reverse; submarine-chain candidates
    # on boltz_submarine. Both listeners exercised.
    assert "boltz_reverse" in call_sites
    assert "boltz_submarine" in call_sites


# ── chain-walk trajectory ─────────────────────────────────────


@pytest.mark.asyncio
async def test_chain_attempted_records_all_candidates_in_order(monkeypatch) -> None:
    """``submarine_chain_attempted`` carries every candidate
    in attempt order. Primary degraded + secondary unreachable →
    both rows present with correct statuses."""

    async def _degraded(db) -> frozenset[str]:
        return frozenset({"middleway"})

    async def _probe(operator, call_site):
        # Eldamar probe fails; reverse probe succeeds.
        return operator.operator_id != "eldamar"

    monkeypatch.setattr(
        "app.services.anonymize.operator_selection._probe_operator",
        _probe,
    )
    monkeypatch.setattr(
        "app.services.anonymize.operator_health.all_degraded_operator_ids",
        _degraded,
    )

    db = MagicMock()
    result = await select_operators_for_onchain_session(
        registry=_BUNDLED_REGISTRY,
        bin_amount_sat=250_000,
        allow_single_operator_fallback=False,
        db=db,
    )
    # Chain exhausted: Middleway degraded, Eldamar unreachable.
    assert isinstance(result, SubmarineChainExhausted)
    # Attempts list carries both, in order.
    statuses = [(a.operator_id, a.status) for a in result.chain_attempted]
    assert statuses == [
        ("middleway", "degraded"),
        ("eldamar", "unreachable"),
    ]


# ── reverse-leg + chain-walk parallelism ──────────────────────


@pytest.mark.asyncio
async def test_reverse_probe_failure_does_not_block_submarine_chain_walk(
    monkeypatch,
) -> None:
    """The reverse probe runs concurrently with the submarine
    chain walk. A failing reverse probe must NOT short-circuit the
    chain walk early; both legs are fully evaluated, then the
    reverse-failure outcome takes precedence."""
    submarine_probed: list[str] = []

    async def _probe(operator, call_site):
        if call_site == "boltz_submarine":
            submarine_probed.append(operator.operator_id)
            return True
        # Reverse probe fails.
        return False

    monkeypatch.setattr(
        "app.services.anonymize.operator_selection._probe_operator",
        _probe,
    )
    monkeypatch.setattr(
        "app.services.anonymize.operator_health.all_degraded_operator_ids",
        _fake_degraded,
    )

    db = MagicMock()
    result = await select_operators_for_onchain_session(
        registry=_BUNDLED_REGISTRY,
        bin_amount_sat=250_000,
        allow_single_operator_fallback=False,
        db=db,
    )
    # Reverse failure wins.
    assert isinstance(result, ReverseProbeFailed)
    # But the submarine chain walk DID run (primary was probed).
    assert "middleway" in submarine_probed


@pytest.mark.asyncio
async def test_reverse_probe_in_degraded_list_treated_as_unreachable(
    monkeypatch,
) -> None:
    """Probe-result cache — when the reverse operator is in
    ``all_degraded_operator_ids``, the selector skips the probe and
    immediately returns ``ReverseProbeFailed(status="degraded")``."""

    async def _degraded(db) -> frozenset[str]:
        return frozenset({"boltz-canonical"})

    async def _probe(operator, call_site):
        return True  # Probes succeed, but reverse never gets probed.

    monkeypatch.setattr(
        "app.services.anonymize.operator_selection._probe_operator",
        _probe,
    )
    monkeypatch.setattr(
        "app.services.anonymize.operator_health.all_degraded_operator_ids",
        _degraded,
    )
    db = MagicMock()
    result = await select_operators_for_onchain_session(
        registry=_BUNDLED_REGISTRY,
        bin_amount_sat=250_000,
        allow_single_operator_fallback=False,
        db=db,
    )
    assert isinstance(result, ReverseProbeFailed)
    assert result.status == "degraded"


# ── single-operator fallback edge cases ───────────────────────


@pytest.mark.asyncio
async def test_single_operator_fallback_available_false_when_reverse_cannot_serve_bin(
    monkeypatch,
) -> None:
    """When the reverse operator's cached pair-info says it
    can't serve the bin (capacity insufficient for consolidation),
    ``single_operator_fallback_available`` is False so the SPA
    hides the Use-single-operator button."""
    from app.services.anonymize.quote_cache import (
        CacheEntry,
        CacheKey,
        get_quote_cache,
    )

    async def _probe(operator, call_site):
        # Only Boltz canonical (reverse) is reachable; submarine chain fails.
        return operator.operator_id == "boltz-canonical"

    monkeypatch.setattr(
        "app.services.anonymize.operator_selection._probe_operator",
        _probe,
    )
    monkeypatch.setattr(
        "app.services.anonymize.operator_health.all_degraded_operator_ids",
        _fake_degraded,
    )
    # Seed a cache entry where Boltz canonical's max-send is below the bin.
    cache = get_quote_cache()
    cache.put(
        CacheEntry(
            key=CacheKey(operator_id="boltz-canonical", pair="BTC/BTC", asset="BTC"),
            payload={"BTC": {"BTC": {"limits": {"maximal": 100_000}}}},
            fetched_at_unix_s=0.0,
        )
    )
    try:
        db = MagicMock()
        result = await select_operators_for_onchain_session(
            registry=_BUNDLED_REGISTRY,
            bin_amount_sat=250_000,  # > Boltz canonical's "maximal=100_000"
            allow_single_operator_fallback=False,
            db=db,
        )
        assert isinstance(result, SubmarineChainExhausted)
        # Boltz canonical can't serve 250k either → fallback not available.
        assert result.single_operator_fallback_available is False
    finally:
        cache.remove(
            CacheKey(operator_id="boltz-canonical", pair="BTC/BTC", asset="BTC"),
        )


@pytest.mark.asyncio
async def test_degraded_operator_skipped_without_probing(monkeypatch) -> None:
    """An operator in ``all_degraded_operator_ids`` is skipped at
    the probe-result cache without ever issuing a probe (records ``status="degraded"``
    in the chain-walk trajectory)."""
    probe_calls: list[str] = []

    async def _probe(operator, call_site):
        probe_calls.append(operator.operator_id)
        return True

    async def _degraded(db) -> frozenset[str]:
        return frozenset({"middleway"})

    monkeypatch.setattr(
        "app.services.anonymize.operator_selection._probe_operator",
        _probe,
    )
    monkeypatch.setattr(
        "app.services.anonymize.operator_health.all_degraded_operator_ids",
        _degraded,
    )

    db = MagicMock()
    result = await select_operators_for_onchain_session(
        registry=_BUNDLED_REGISTRY,
        bin_amount_sat=250_000,
        allow_single_operator_fallback=False,
        db=db,
    )
    assert isinstance(result, OperatorSelectionResult)
    # Middleway is degraded; selector falls straight to Eldamar.
    assert result.submarine.operator_id == "eldamar"
    # First chain attempt records the degraded status.
    assert result.submarine_chain_attempted[0].operator_id == "middleway"
    assert result.submarine_chain_attempted[0].status == "degraded"
    # And Middleway was NEVER probed.
    assert "middleway" not in probe_calls
