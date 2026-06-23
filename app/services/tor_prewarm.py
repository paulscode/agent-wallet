# SPDX-License-Identifier: MIT
"""HS descriptor pre-warming for known onions.

First request to a ``.onion`` blocks ~5-15 s while Tor fetches the
hidden-service descriptor from the HSDir ring. Operators don't
notice this on a long-lived process, but they do notice on every
container restart — the first Boltz quote / LND call / anonymize
operator probe waits.

This module issues lightweight HEAD requests against the onion
endpoints we know we'll talk to (LND REST, Boltz operators, the
configured signed-operator registry) at FastAPI lifespan startup.
The Tor client caches the resulting descriptors so the first real
call doesn't pay the round-trip.

Budget: 10 s total. We dispatch every probe concurrently, then
wait on the gather with a hard timeout. Partial pre-warm is fine
— anything we miss gets fetched lazily on first real use.
"""

from __future__ import annotations

import asyncio
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


_PREWARM_BUDGET_S = 10.0
_PREWARM_PER_REQUEST_TIMEOUT_S = 8.0


def _collect_known_onions() -> list[str]:
    """Gather every ``.onion`` URL the wallet expects to call.

    Sources:
      * LND REST URL (if .onion).
      * Boltz onion URLs (shared + per-leg overrides).
      * Each entry in the signed operator registry.

    De-duplicated by (host, port) so we don't pre-warm the same
    descriptor twice when two services share an onion.
    """
    from app.core.config import settings

    candidates: list[str] = [
        settings.lnd_rest_url,
        settings.boltz_onion_url,
        settings.boltz_submarine_onion_url,
        settings.boltz_reverse_onion_url,
    ]
    # Operators registry — multi-operator wallets have multiple entries.
    try:
        from app.services.anonymize.operators import load_operator_registry

        for entry in load_operator_registry():
            if entry.onion:
                candidates.append(entry.onion)
    except Exception as exc:  # noqa: BLE001
        # The registry is optional; failures don't block pre-warm.
        logger.info("tor prewarm: skipping operator registry: %s", exc)

    seen: set[tuple[str, int]] = set()
    onions: list[str] = []
    for raw in candidates:
        if not raw or ".onion" not in raw:
            continue
        try:
            parsed = urlparse(raw)
        except Exception:  # noqa: BLE001
            continue
        host = (parsed.hostname or "").lower()
        if not host.endswith(".onion"):
            continue
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        key = (host, port)
        if key in seen:
            continue
        seen.add(key)
        onions.append(raw)
    return onions


def _proxy_for_url(url: str) -> str:
    """Pick the right SOCKS proxy for ``url``.

    Single mode: every URL goes through ``lnd_tor_proxy`` (the
    unified ``tor-proxy``).

    Split mode: the LND REST endpoint goes through ``tor-lnd``;
    every other onion (Boltz, operator registry, etc.) goes
    through ``tor-anonymize``. The pool choice matters because
    each Tor process has its own descriptor cache — prewarming
    through tor-lnd doesn't help tor-anonymize's first call to
    the same onion."""
    from app.core.config import settings

    base_proxy = settings.lnd_tor_proxy or "socks5h://tor-proxy:9050"
    if not getattr(settings, "tor_split_mode", False):
        return base_proxy
    # Split mode. ``lnd_tor_proxy`` already routes LND traffic
    # through ``tor-lnd``; we use it only for the LND REST onion.
    if url and url == getattr(settings, "lnd_rest_url", ""):
        return base_proxy
    socks_host = settings.anonymize_tor_socks_host or "tor-anonymize"
    # Default anonymize SOCKS port is 9050 inside the
    # tor-anonymize container — same scheme + port as the unified
    # ``tor-proxy``.
    return f"socks5h://{socks_host}:9050"


async def _prewarm_one(url: str) -> tuple[str, bool, str | None]:
    """HEAD ``url`` via the right Tor SOCKS5 proxy. Returns
    ``(url, ok, error_or_none)``. Failure is non-fatal — pre-warm
    is best-effort."""
    import httpx

    proxy = _proxy_for_url(url)
    probe_url = _probe_url_for(url)
    try:
        async with httpx.AsyncClient(
            proxy=proxy,
            timeout=_PREWARM_PER_REQUEST_TIMEOUT_S,
            verify=False,  # Boltz onion endpoints serve self-signed certs.
            follow_redirects=False,
        ) as client:
            # HEAD avoids body transfer. Onion endpoints often 405
            # on HEAD; that's fine — the descriptor fetch still ran.
            await client.head(probe_url)
        return (url, True, None)
    except Exception as exc:  # noqa: BLE001
        return (url, False, str(exc)[:200])


def _probe_url_for(url: str) -> str:
    """Pick a path on ``url`` that returns 200 rather than 404 so the
    pre-warm log line isn't misleading. The descriptor fetch happens
    on the round-trip regardless of the path, so this is purely
    cosmetic.

    Boltz and the operator registry both expose ``/version`` under
    their API base (``/api/v2`` and ``/v2`` respectively). Anything
    else (e.g. the LND REST root) is left untouched.
    """
    try:
        parsed = urlparse(url)
    except Exception:  # noqa: BLE001
        return url
    path = (parsed.path or "").rstrip("/")
    if path.endswith("/api/v2") or path.endswith("/v2"):
        return url.rstrip("/") + "/version"
    return url


async def prewarm_known_onions() -> dict[str, bool]:
    """Pre-warm HS descriptors for every known onion endpoint.

    Returns a dict mapping each attempted URL to ``True``/``False``
    (whether the round-trip — and thus the descriptor fetch —
    completed within budget).

    Bounded by :data:`_PREWARM_BUDGET_S`. Any URL that didn't
    complete is reported as ``False`` so the operator can see what
    didn't pre-warm in the audit log.

    No-op when no Tor proxy is configured — without a SOCKS5 proxy
    we'd attempt clearnet HEAD requests which can't fetch HS
    descriptors anyway. This also keeps test/CI environments quiet
    when ``LND_TOR_PROXY`` defaults to empty.
    """
    from app.core.config import settings

    if not getattr(settings, "lnd_tor_proxy", None):
        return {}
    onions = _collect_known_onions()
    if not onions:
        return {}

    logger.info(
        "tor prewarm: warming %d HS descriptor(s) within %.0fs budget",
        len(onions),
        _PREWARM_BUDGET_S,
    )
    tasks = [asyncio.create_task(_prewarm_one(u)) for u in onions]
    try:
        # asyncio.wait_for cancels outstanding tasks on timeout —
        # explicit gather + wait_for is the cleanest way to apply a
        # whole-batch deadline without losing partial results.
        done, pending = await asyncio.wait(
            tasks,
            timeout=_PREWARM_BUDGET_S,
        )
        for p in pending:
            p.cancel()
    except Exception as exc:  # noqa: BLE001
        logger.info("tor prewarm: gather failed: %s", exc)
        return {u: False for u in onions}

    results: dict[str, bool] = {}
    for t in tasks:
        if not t.done():
            continue
        try:
            url, ok, _err = t.result()
        except Exception:  # noqa: BLE001
            continue
        results[url] = ok
    # Anything that didn't finish counts as a miss.
    for u in onions:
        results.setdefault(u, False)
    ok_count = sum(1 for v in results.values() if v)
    logger.info(
        "tor prewarm: %d/%d HS descriptors prewarmed",
        ok_count,
        len(onions),
    )
    return results


__all__ = ["prewarm_known_onions"]
