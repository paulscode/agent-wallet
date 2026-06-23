# SPDX-License-Identifier: MIT
"""Clock-skew probe via HTTP ``Date`` headers.

The recurring probe queries each configured trusted source through
the anonymize wrapper, parses the server's ``Date`` header, and
records the median delta as the measured skew. The result feeds:

* the create-endpoint clock-skew gate (refuse session creation
  when the measurement is missing or out of band);
* the self-broadcast tick's skew-window check.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime

import httpx
import pytest

from app.core.config import settings
from app.services.anonymize import clock as clock_mod
from app.services.anonymize import service as anon_service


def _http_date(dt: datetime) -> str:
    return format_datetime(dt.astimezone(timezone.utc), usegmt=True)


def _install_mock_anonymize_client(
    monkeypatch,
    responses_for_url: dict[str, httpx.Response],
) -> list[httpx.Request]:
    requests: list[httpx.Request] = []

    @asynccontextmanager
    async def _factory(*, call_site, socks_host, socks_port, timeout_s=30.0):
        def _handler(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            url = str(request.url)
            # Fuzzy match on URL prefix so callers can configure
            # path-bearing sources without extra mapping work.
            for prefix, resp in responses_for_url.items():
                if url.startswith(prefix):
                    return resp
            return httpx.Response(404)

        transport = httpx.MockTransport(_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            yield client

    monkeypatch.setattr(clock_mod, "get_anonymize_client", _factory)
    return requests


@pytest.fixture
def listeners_configured(monkeypatch):
    monkeypatch.setattr(
        settings,
        "anonymize_tor_socks_ports",
        "boltz_submarine=9050,boltz_reverse=9051,liquid=9052,"
        "chain_backend=9053,bip353_dns=9054,quote_cache_refresh=9055,"
        "chain_backend_general=9056,chain_backend_anonymize=9057",
    )


@pytest.fixture(autouse=True)
def _fast_probe(monkeypatch):
    """Collapse the per-tick sample window to zero so probe-loop tests
    don't wait the 20-second production schedule. Production knobs
    (N=12, window=20s, min=6, trim=0.15) are exercised by the
    ``aggregate_samples`` unit tests below — the probe-loop tests
    here only need to verify the *plumbing* (URL routing, ``Date``
    parsing, error handling), so collapsing N to a small number with
    no inter-sample sleep keeps them fast.
    """
    monkeypatch.setattr(settings, "anonymize_clock_skew_sample_window_s", 0.0)
    monkeypatch.setattr(settings, "anonymize_clock_skew_samples_per_tick", 3)
    monkeypatch.setattr(settings, "anonymize_clock_skew_min_samples_for_decision", 1)
    monkeypatch.setattr(settings, "anonymize_clock_skew_trim_fraction", 0.0)


# ── probe_clock_skew_via_http ────────────────────────────────────────


@pytest.mark.asyncio
async def test_probe_returns_empty_when_no_sources_configured(
    monkeypatch,
    listeners_configured,
) -> None:
    monkeypatch.setattr(settings, "anonymize_clock_skew_probe_sources", "")
    # Disable the clock-skew-sources registry fallback so this test
    # exercises the "no sources anywhere" path; the fallback path has
    # its own test below.
    monkeypatch.setattr(
        clock_mod,
        "_clock_skew_sources_fallback_urls",
        lambda: (),
    )
    state = await clock_mod.probe_clock_skew_via_http()
    assert state.skew_ms is None
    assert state.sources_consulted == ()


@pytest.mark.asyncio
async def test_probe_falls_back_to_clock_skew_sources_when_setting_blank(
    monkeypatch,
    listeners_configured,
) -> None:
    """When ``anonymize_clock_skew_probe_sources`` is blank the probe
    pulls URLs from the signed clock-skew-sources registry so a fresh
    deployment can boot without manual config. Callers who pass an
    explicit ``sources`` tuple opt out of the fallback."""
    monkeypatch.setattr(settings, "anonymize_clock_skew_probe_sources", "")
    monkeypatch.setattr(
        clock_mod,
        "_clock_skew_sources_fallback_urls",
        lambda: ("https://src-a.onion/", "https://src-b.onion/"),
    )

    local_now = datetime(2026, 5, 10, tzinfo=timezone.utc)
    responses = {
        "https://src-a.onion/": httpx.Response(
            200,
            headers={"Date": _http_date(local_now)},
        ),
        "https://src-b.onion/": httpx.Response(
            200,
            headers={"Date": _http_date(local_now)},
        ),
    }
    _install_mock_anonymize_client(monkeypatch, responses)

    state = await clock_mod.probe_clock_skew_via_http(
        now_fn=lambda: local_now.timestamp(),
    )
    assert state.skew_ms is not None
    assert set(state.sources_consulted) == {
        "https://src-a.onion/",
        "https://src-b.onion/",
    }


@pytest.mark.asyncio
async def test_probe_does_not_fallback_when_explicit_sources_empty(
    monkeypatch,
    listeners_configured,
) -> None:
    """Passing an explicit empty ``sources`` tuple is a deliberate
    "no probe" signal from the caller — the clock-skew-sources
    registry fallback must not silently substitute URLs in that case."""
    monkeypatch.setattr(
        clock_mod,
        "_clock_skew_sources_fallback_urls",
        lambda: ("https://src-a.onion/",),
    )
    state = await clock_mod.probe_clock_skew_via_http(sources=())
    assert state.skew_ms is None
    assert state.sources_consulted == ()


@pytest.mark.asyncio
async def test_probe_records_median_skew_across_sources(
    monkeypatch,
    listeners_configured,
) -> None:
    """Two sources, one +500 ms, one −500 ms → median is one of them.

    We freeze the local clock by stubbing ``now_fn``; the test only
    needs to assert the helper computed something inside the expected
    band, not exact equality (the half-RTT compensation introduces
    a tiny smear).
    """
    monkeypatch.setattr(
        settings,
        "anonymize_clock_skew_probe_sources",
        "https://a.example/,https://b.example/",
    )

    local_now = datetime(2026, 5, 10, tzinfo=timezone.utc)

    def _now() -> float:
        return local_now.timestamp()

    responses = {
        "https://a.example/": httpx.Response(
            200,
            headers={"Date": _http_date(local_now + timedelta(milliseconds=500))},
        ),
        "https://b.example/": httpx.Response(
            200,
            headers={"Date": _http_date(local_now - timedelta(milliseconds=500))},
        ),
    }
    _install_mock_anonymize_client(monkeypatch, responses)

    state = await clock_mod.probe_clock_skew_via_http(now_fn=_now)
    assert state.skew_ms is not None
    # HTTP Date is second-resolution — the +500ms / -500ms truncate
    # to 0 / 0 on the wire (the headers round to whole seconds).
    # The median over [0, 0] is 0; assert the band.
    assert abs(state.skew_ms) <= 1000
    assert len(state.sources_consulted) == 2


@pytest.mark.asyncio
async def test_probe_skips_sources_without_date_header(
    monkeypatch,
    listeners_configured,
) -> None:
    monkeypatch.setattr(
        settings,
        "anonymize_clock_skew_probe_sources",
        "https://has-date/,https://no-date/",
    )

    local_now = datetime(2026, 5, 10, tzinfo=timezone.utc)
    responses = {
        "https://has-date/": httpx.Response(
            200,
            headers={"Date": _http_date(local_now)},
        ),
        "https://no-date/": httpx.Response(200, text="ok"),
    }
    _install_mock_anonymize_client(monkeypatch, responses)

    state = await clock_mod.probe_clock_skew_via_http(
        now_fn=lambda: local_now.timestamp(),
    )
    assert state.skew_ms is not None
    assert state.sources_consulted == ("https://has-date/",)


@pytest.mark.asyncio
async def test_probe_returns_empty_when_all_sources_fail(
    monkeypatch,
    listeners_configured,
) -> None:
    monkeypatch.setattr(
        settings,
        "anonymize_clock_skew_probe_sources",
        "https://bad-1/,https://bad-2/",
    )

    @asynccontextmanager
    async def _failing(*, call_site, socks_host, socks_port, timeout_s=30.0):
        raise RuntimeError("simulated transport failure")
        yield  # pragma: no cover

    monkeypatch.setattr(clock_mod, "get_anonymize_client", _failing)

    state = await clock_mod.probe_clock_skew_via_http()
    assert state.skew_ms is None


# ── _clock_skew_probe_run tick ─────────────────────────────────────


@pytest.mark.asyncio
async def test_tick_persists_measurement_when_probe_succeeds(
    monkeypatch,
    db_engine,
) -> None:
    from sqlalchemy.ext.asyncio import async_sessionmaker

    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    monkeypatch.setattr("app.core.database.get_session_maker", lambda: factory)

    async def _stub_probe(**_):
        return clock_mod.ClockSkewState(
            skew_ms=42,
            measured_at_unix_s=1_000.0,
            sources_consulted=("https://a/",),
        )

    monkeypatch.setattr(clock_mod, "probe_clock_skew_via_http", _stub_probe)

    await anon_service._clock_skew_probe_run()

    async with factory() as db:
        loaded = await clock_mod.load_clock_skew_state(db)
    assert loaded.skew_ms == 42


@pytest.mark.asyncio
async def test_tick_does_not_persist_when_probe_empty(
    monkeypatch,
    db_engine,
) -> None:
    from sqlalchemy.ext.asyncio import async_sessionmaker

    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    monkeypatch.setattr("app.core.database.get_session_maker", lambda: factory)

    # Pre-populate runtime_state with a valid measurement; the empty
    # probe result MUST NOT overwrite it (a transient outage shouldn't
    # drop the cache to "no measurement").
    async with factory() as db:
        await clock_mod.store_clock_skew_state(
            db,
            clock_mod.ClockSkewState(skew_ms=5, measured_at_unix_s=500.0),
        )
        await db.commit()

    async def _stub_empty(**_):
        return clock_mod.ClockSkewState.empty()

    monkeypatch.setattr(clock_mod, "probe_clock_skew_via_http", _stub_empty)

    await anon_service._clock_skew_probe_run()

    async with factory() as db:
        loaded = await clock_mod.load_clock_skew_state(db)
    assert loaded.skew_ms == 5  # not overwritten


@pytest.mark.asyncio
async def test_tick_updates_health_card_through_stashed_app(
    monkeypatch,
    db_engine,
) -> None:
    """The probe pushes its threshold check onto
    ``app.state.anonymize_health`` when the service is bootstrapped
    with a real FastAPI app reference."""
    from types import SimpleNamespace

    from sqlalchemy.ext.asyncio import async_sessionmaker

    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    monkeypatch.setattr("app.core.database.get_session_maker", lambda: factory)

    fake_app = SimpleNamespace(
        state=SimpleNamespace(
            anonymize_health={"clock_skew_within_threshold": True},
        ),
    )

    from app.services.anonymize.service import (
        get_anonymize_service,
        reset_anonymize_service,
    )

    reset_anonymize_service()
    svc = get_anonymize_service()
    svc._fastapi_app = fake_app  # type: ignore[attr-defined]

    async def _stub_over(**_):
        return clock_mod.ClockSkewState(
            skew_ms=10_000,
            measured_at_unix_s=1.0,
            sources_consulted=("https://a/",),
        )

    monkeypatch.setattr(clock_mod, "probe_clock_skew_via_http", _stub_over)

    await anon_service._clock_skew_probe_run()

    assert fake_app.state.anonymize_health["clock_skew_within_threshold"] is False

    reset_anonymize_service()


# ── aggregate_samples (pure math) ─────────────────────────────────────


import random


def _synthesize_samples(
    *,
    true_skew_ms: int,
    n: int,
    rng: random.Random,
    rtt_jitter_ms: int = 0,
) -> list[int]:
    """Build N samples mimicking the probe's raw delta_ms values.

    The probe computes ``delta_ms = (floor(server_unix_s) − local_midpoint_unix_s) * 1000``.
    With a true skew of ``true_skew_ms``, each sample's local clock at
    the sampling phase is uniformly distributed over a 1-second
    interval relative to the server's last second-tick. So the raw
    delta is ``true_skew − phase * 1000``, where ``phase ∈ [0, 1)``
    is the sub-second component of the local time at sample.
    Optional ``rtt_jitter_ms`` adds Gaussian noise to model Tor RTT.
    """
    out: list[int] = []
    for _ in range(n):
        phase_ms = rng.random() * 1000.0
        noise_ms = rng.gauss(0, rtt_jitter_ms) if rtt_jitter_ms else 0.0
        delta_ms = int(round(true_skew_ms - phase_ms + noise_ms))
        out.append(delta_ms)
    return out


def test_aggregate_returns_none_below_min_samples() -> None:
    assert (
        clock_mod.aggregate_samples(
            [42, 7, -5],
            trim_fraction=0.15,
            min_samples=6,
        )
        is None
    )


def test_aggregate_returns_none_on_empty_input() -> None:
    assert (
        clock_mod.aggregate_samples(
            [],
            trim_fraction=0.15,
            min_samples=1,
        )
        is None
    )


def test_aggregate_recovers_zero_skew_from_truncated_samples() -> None:
    """True skew 0 plus truncation noise should recover within 100 ms.

    With N=20 samples and no extra RTT noise the analytical standard
    error is ~65 ms; a 100 ms band gives roughly 1.5 standard
    deviations of headroom and stays deterministic under the seeded
    RNG. This is a tolerance over deterministic input, NOT an
    empirical-mean assertion.
    """
    rng = random.Random(0xCAFE)
    samples = _synthesize_samples(true_skew_ms=0, n=20, rng=rng)
    recovered = clock_mod.aggregate_samples(
        samples,
        trim_fraction=0.15,
        min_samples=6,
    )
    assert recovered is not None
    assert abs(recovered) <= 100, f"recovered={recovered}"


@pytest.mark.parametrize("true_skew_ms", [-1500, -200, 200, 1500])
def test_aggregate_recovers_known_skew_values(true_skew_ms: int) -> None:
    rng = random.Random(0xBEEF ^ true_skew_ms)
    samples = _synthesize_samples(true_skew_ms=true_skew_ms, n=20, rng=rng)
    recovered = clock_mod.aggregate_samples(
        samples,
        trim_fraction=0.15,
        min_samples=6,
    )
    assert recovered is not None
    # Standard error at N=20 is ~65 ms (uniform-truncation noise
    # alone); 250 ms is ~3 standard errors times the sqrt(pi/2)
    # median-vs-mean efficiency factor, large enough to absorb the
    # worst seeded draw deterministically. This bound is over fixed
    # seeded inputs — NOT an empirical-mean assertion.
    assert abs(recovered - true_skew_ms) <= 250, f"true={true_skew_ms} recovered={recovered}"


def test_aggregate_drops_outliers_via_trimmed_median() -> None:
    """10 well-behaved samples + 2 wild outliers → trim drops the
    outliers; recovered skew matches the clean-only result.

    Untrimmed median would still survive 2 outliers in a 12-sample
    set, but trimmed-median is what production uses; this test pins
    that behavior so a future change to ``trim_fraction=0`` doesn't
    silently regress under noisy-network conditions.
    """
    rng = random.Random(0xDEADBEEF)
    clean = _synthesize_samples(true_skew_ms=0, n=10, rng=rng)
    # Two extreme outliers — a stalled Tor circuit returning a delta
    # off by many seconds (raw delta around −3000 to −5000 ms).
    poisoned = clean + [-9_999, +9_999]
    recovered = clock_mod.aggregate_samples(
        poisoned,
        trim_fraction=0.15,
        min_samples=6,
    )
    assert recovered is not None
    assert abs(recovered) <= 150


def test_aggregate_bias_correction_is_500ms() -> None:
    """A single sample with raw delta D recovers as D + 500 ms.

    This pins the truncation-bias-correction constant; if someone
    later changes it (e.g. introduces a different rounding mode in
    the probe), the test will fail visibly.
    """
    # Single-sample edge case — disable trim and lower min so the
    # bias-correction is the only math left.
    assert (
        clock_mod.aggregate_samples(
            [-500],
            trim_fraction=0.0,
            min_samples=1,
        )
        == 0
    )
    assert (
        clock_mod.aggregate_samples(
            [0],
            trim_fraction=0.0,
            min_samples=1,
        )
        == 500
    )
    assert (
        clock_mod.aggregate_samples(
            [-1500],
            trim_fraction=0.0,
            min_samples=1,
        )
        == -1000
    )


@pytest.mark.parametrize("seed", [0, 1, 42, 0xCAFE, 0xBEEF, 0xDEAD])
def test_aggregate_convergence_band_across_seeds(seed: int) -> None:
    """Property-style sweep: across multiple seeds, N=20 samples of
    a known true skew always recover within the analytical standard-
    error bound (about 200 ms at N=20). Acts as a regression guard
    against any future change that quietly biases the estimator.
    Deterministic per-seed inputs — NOT an empirical-mean assertion."""
    rng = random.Random(seed)
    true = rng.randint(-2000, 2000)
    samples = _synthesize_samples(true_skew_ms=true, n=20, rng=rng)
    recovered = clock_mod.aggregate_samples(
        samples,
        trim_fraction=0.15,
        min_samples=6,
    )
    assert recovered is not None
    # 3-standard-error band: SE(N=20) is ~65 ms, 3 SE is ~200 ms.
    # Use 250 to absorb the median-vs-mean efficiency loss (median
    # is sqrt(pi/2) ~ 1.25 times wider than mean for Gaussian-like
    # distributions; truncation noise is uniform, so the actual loss
    # is smaller, but we add slack).
    assert abs(recovered - true) <= 250, f"seed={seed} true={true} recovered={recovered}"
