# SPDX-License-Identifier: MIT
"""
FastAPI application entry point.

- Mounts all routers
- Configures CORS
- Startup / shutdown hooks
- Health / readiness endpoints (unauthenticated)
"""

import asyncio
import logging
import logging.config
import re
import secrets
import sys
import uuid
from collections.abc import AsyncGenerator, MutableMapping
from contextlib import asynccontextmanager
from typing import Any, Optional

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from starlette.responses import Response

from app.core.config import settings
from app.core.database import engine_registry, get_session_maker
from app.core.limiter import limiter

logger = logging.getLogger(__name__)


def _configure_logging() -> None:
    """Configure logging based on LOG_FORMAT setting."""
    level = getattr(logging, settings.log_level.upper(), logging.INFO)

    if settings.log_format == "json":
        try:
            from pythonjsonlogger.json import JsonFormatter  # type: ignore[import-not-found]

            handler = logging.StreamHandler(sys.stdout)
            handler.setFormatter(
                JsonFormatter(
                    fmt="%(asctime)s %(levelname)s %(name)s %(message)s",
                    rename_fields={"asctime": "timestamp", "levelname": "level"},
                )
            )
            logging.root.handlers = [handler]
            logging.root.setLevel(level)
        except ImportError:
            logging.basicConfig(level=level, format="%(levelname)-5.5s [%(name)s] %(message)s")
            logging.warning("python-json-logger not installed; falling back to text logging")
    else:
        logging.basicConfig(level=level, format="%(levelname)-5.5s [%(name)s] %(message)s")


_configure_logging()


def _validate_mempool_url() -> None:
    """Refuse to start if ``LND_MEMPOOL_URL`` resolves to an internal IP.

    ``MempoolFeeService`` builds an HTTP client whose ``base_url`` is
    taken straight from ``LND_MEMPOOL_URL``. Without this guard, an
    operator who points the variable at ``http://169.254.169.254`` or
    ``http://10.0.0.x`` (or a hostname that resolves there) turns the
    server into an SSRF reflector against the cloud metadata service
    or local intranet. Operators running a legitimate self-hosted
    mempool instance on a private subnet must opt in by setting
    ``MEMPOOL_ALLOW_INTERNAL=true``. Onion / .local hostnames are
    permitted because they are routed via the configured Tor proxy
    rather than the host's network stack.
    """
    from urllib.parse import urlparse

    from app.core.net_guard import host_resolves_to_blocked

    raw = settings.lnd_mempool_url or ""
    if not raw:
        return
    if settings.mempool_allow_internal:
        logger.warning(
            "MEMPOOL_ALLOW_INTERNAL=true — SSRF guard on LND_MEMPOOL_URL "
            "is bypassed. Only enable this for genuinely self-hosted "
            "internal mempool instances."
        )
        return

    try:
        parsed = urlparse(raw)
    except Exception as e:
        raise RuntimeError(f"LND_MEMPOOL_URL is not a parsable URL: {e}") from e

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        raise RuntimeError("LND_MEMPOOL_URL must include a hostname")
    if hostname.endswith(".onion") or hostname.endswith(".local"):
        return

    # One policy governs both the startup guard and the request-time
    # egress guard: ``host_resolves_to_blocked`` rejects the classic
    # private/loopback/link-local ranges AND non-globally-routable space
    # (CGNAT, benchmarking, documentation) and decodes IPv6-embedded IPv4
    # (6to4 / mapped / Teredo) so an address tunnelling the cloud metadata
    # IP cannot slip through. An unresolvable host is treated as blocked.
    if host_resolves_to_blocked(hostname):
        raise RuntimeError(
            f"LND_MEMPOOL_URL ({raw}) is unresolvable or resolves to a "
            "non-routable address. Set MEMPOOL_ALLOW_INTERNAL=true only if "
            "this is a deliberate self-hosted internal endpoint."
        )


async def _run_tor_proxy_reach_check() -> None:
    """One-shot SOCKS5 reachability check for the
    configured ``LND_TOR_PROXY``. Logs an operator-visible error
    when the proxy is unreachable so misconfigured operator-
    supplied Tor setups don't fail silently on every onion call.

    Non-fatal: the api still starts because clearnet endpoints
    keep working. The error in docker logs is the signal.
    """
    try:
        from app.services.tor_proxy_reach_check import (
            check_tor_proxy_reachable,
        )

        await check_tor_proxy_reachable()
    except Exception as exc:  # noqa: BLE001
        logger.info("tor proxy reach check: top-level error: %s", exc)


async def _run_tor_dns_leak_check() -> None:
    """DNS-leak / Tor-routing verification at startup. A
    confirmed leak (``IsTor=false`` from check.torproject.org) is
    a loud ERROR in docker logs but does NOT refuse to start —
    operator decides whether to fix or proceed."""
    try:
        from app.services.tor_dns_leak_check import check_for_dns_leak

        await check_for_dns_leak()
    except Exception as exc:  # noqa: BLE001
        logger.info("tor dns leak check: top-level error: %s", exc)


async def _run_tor_prewarm() -> None:
    """Fire-and-forget HS descriptor pre-warm at lifespan
    startup. Bounded by the module's internal 10 s budget; partial
    results are fine (and expected on first boot before Tor has
    bootstrapped). Any exception is swallowed so a slow/missing
    SOCKS proxy can't crash the api process."""
    try:
        from app.services.tor_prewarm import prewarm_known_onions

        await prewarm_known_onions()
    except Exception as exc:  # noqa: BLE001
        logger.info("tor prewarm: top-level error: %s", exc)


async def _run_tor_diversity_smoke() -> None:
    """Startup exit-relay diversity smoke test.

    Fires once per process. Skipped if Tor isn't ready (no failure).
    Soft-fails when probes time out (audit log only). Hard-fails
    (raises) only on observed circuit collision — that's a real
    isolation regression and refusing to serve traffic is correct.

    The hard-fail propagates out of lifespan startup, which is what
    we want: FastAPI won't accept traffic until lifespan completes
    successfully."""
    from app.services.tor_diversity_smoke import (
        DiversitySmokeFailureError,
        run_diversity_smoke,
    )

    try:
        result = await run_diversity_smoke()
    except DiversitySmokeFailureError:
        # Re-raise: this should abort startup.
        raise
    except Exception as exc:  # noqa: BLE001
        logger.warning("tor diversity smoke: skipped due to error: %s", exc)
        return
    if result.skipped:
        logger.info(
            "tor diversity smoke: skipped (%s)",
            result.error or "unknown",
        )
        return
    if result.ok:
        logger.info(
            "tor diversity smoke: ok — %d listeners probed, %d distinct circuits.",
            result.listeners_probed,
            result.distinct_circuits,
        )
    else:
        logger.warning(
            "tor diversity smoke: soft-fail — %d/%d listeners probed ok, %d distinct circuits, error=%s",
            result.listeners_ok,
            result.listeners_probed,
            result.distinct_circuits,
            result.error,
        )


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:  # type: ignore[override]
    """Startup / shutdown lifecycle."""
    # ── Validate SECRET_KEY ──
    _insecure_defaults = {"change-me-to-a-random-64-char-string", ""}
    if settings.secret_key in _insecure_defaults or len(settings.secret_key) < 32:
        raise RuntimeError(
            "SECRET_KEY is missing or insecure (must be >= 32 chars). "
            "Generate one with: python -c 'import secrets; print(secrets.token_hex(32))'"
        )
    if not settings.enable_hsts:
        logger.warning(
            "HSTS is disabled (ENABLE_HSTS=false). Session cookies will NOT have the "
            "Secure flag — they will be sent over plain HTTP. Set ENABLE_HSTS=true "
            "in production to enforce HTTPS and mark all cookies as Secure."
        )
    if settings.rate_limit_fail_policy == "open":
        logger.warning(
            "RATE_LIMIT_FAIL_POLICY is 'open' — payment rate limits will be bypassed "
            "when Redis is unavailable. Set to 'closed' for stricter safety."
        )
    if not settings.mempool_tls_verify and not settings.mempool_ca_cert:
        from urllib.parse import urlparse as _urlparse

        _mempool_host = (_urlparse(settings.lnd_mempool_url).hostname or "").lower()
        if not _mempool_host.endswith(".onion"):
            logger.warning(
                "MEMPOOL_TLS_VERIFY=false with no MEMPOOL_CA_CERT — connection to %s "
                "is vulnerable to on-path TLS tampering of fee / chain-tip / tx "
                "status data. Pin the self-signed cert via MEMPOOL_CA_CERT, or use "
                "mempool.space over HTTPS.",
                settings.lnd_mempool_url,
            )
    if settings.enable_dashboard and settings.dashboard_token and len(settings.dashboard_token) < 16:
        logger.warning("DASHBOARD_TOKEN is shorter than 16 characters. Use a strong token for production deployments.")
    if settings.lnd_max_payment_sats == -1:
        logger.warning(
            "LND_MAX_PAYMENT_SATS is -1 — per-payment safety limit is DISABLED. "
            "Any single API call can spend unlimited sats."
        )
    # Warn when connecting to a remote database without SSL
    _db_url_lower = settings.database_url.lower()
    _is_local_db = any(h in _db_url_lower for h in ("localhost", "127.0.0.1", "::1"))
    if not _is_local_db and not settings.database_require_ssl:
        logger.warning(
            "DATABASE_URL points to a remote host but DATABASE_REQUIRE_SSL is false. "
            "Set DATABASE_REQUIRE_SSL=true to encrypt database connections."
        )
    # Warn when connecting to a remote Redis without TLS
    _redis_lower = settings.redis_url.lower()
    _is_local_redis = any(h in _redis_lower for h in ("localhost", "127.0.0.1", "::1"))
    if not _is_local_redis and not _redis_lower.startswith("rediss://"):
        logger.warning(
            "REDIS_URL points to a remote host but does not use rediss:// (TLS). "
            "Set REDIS_URL=rediss://... to encrypt Redis connections."
        )
    # Warn when LND TLS verification is disabled without a pinned cert on
    # a clearnet/LAN link. In that posture the admin macaroon rides an
    # unauthenticated channel and is exposed to an on-path attacker;
    # pinning LND_TLS_CERT (with LND_TLS_VERIFY=true) is the safe path.
    # Onion hosts are exempt — the onion address authenticates the peer.
    if not settings.lnd_tls_verify and not settings.lnd_tls_cert:
        from urllib.parse import urlparse as _urlparse

        _lnd_host = (_urlparse(settings.lnd_rest_url).hostname or "").lower()
        if not _lnd_host.endswith(".onion"):
            logger.warning(
                "LND_TLS_VERIFY is false and no LND_TLS_CERT is pinned for a non-onion "
                "LND host. The admin macaroon is exposed to on-path interception. "
                "Set LND_TLS_VERIFY=true and pin LND_TLS_CERT."
            )

    # Same posture for the Electrum backend: an ``ssl://`` link with
    # verification off and no pinned cert leaves chain-tip / tx-status /
    # fee data — which feeds automated send decisions — tamperable by an
    # on-path attacker. Pin LND_ELECTRUM_CA_CERT instead. Onion hosts
    # authenticate the peer and are exempt; ``tcp://`` carries no TLS to
    # weaken and is out of scope for this warning.
    if settings.lnd_electrum_url and not settings.lnd_electrum_tls_verify and not settings.lnd_electrum_ca_cert:
        from urllib.parse import urlparse as _urlparse

        _electrum_parsed = _urlparse(settings.lnd_electrum_url)
        _electrum_host = (_electrum_parsed.hostname or "").lower()
        if _electrum_parsed.scheme == "ssl" and not _electrum_host.endswith(".onion"):
            logger.warning(
                "LND_ELECTRUM_TLS_VERIFY is false and no LND_ELECTRUM_CA_CERT is pinned "
                "for a non-onion ssl:// Electrum host. Chain-tip / tx-status / fee data "
                "is exposed to on-path tampering. Set LND_ELECTRUM_TLS_VERIFY=true and "
                "pin LND_ELECTRUM_CA_CERT."
            )

    # The audit-chain front-truncation defense relies on the off-box
    # receiver verifying the HMAC signature on each anchor delivery.
    # That signature is keyed on ALERT_WEBHOOK_SHARED_SECRET; without it
    # anchors (and all alerts) ship unauthenticated, so a tamperer who
    # can reach the receiver can forge count/deleted/head_hash and the
    # front-truncation reconciliation no longer holds.
    if settings.alert_webhook_url and not settings.alert_webhook_shared_secret:
        logger.warning(
            "ALERT_WEBHOOK_URL is set but ALERT_WEBHOOK_SHARED_SECRET is not — webhook "
            "alerts and audit-chain anchors are sent UNSIGNED. Front-truncation "
            "detection is not effective until you set ALERT_WEBHOOK_SHARED_SECRET and "
            "verify X-Agent-Wallet-Signature on the receiver."
        )

    # SSRF guard for LND_MEMPOOL_URL — refuse to start if the
    # configured mempool endpoint resolves to a non-routable address
    # (RFC1918, loopback, link-local, etc.). Operators running a
    # genuinely self-hosted internal mempool instance must opt in
    # explicitly via MEMPOOL_ALLOW_INTERNAL=true.
    _validate_mempool_url()

    # Raise a security alert when the shared rate limiter fell back to
    # per-process in-memory storage. Without shared storage the IP-level
    # limits (including login brute-force protection) are enforced
    # per-worker, so the effective ceiling scales with the worker count.
    from app.core import limiter as _limiter_mod

    if _limiter_mod.storage_degraded_reason:
        from app.services.alert_service import send_alert

        await send_alert(
            "rate_limit_degraded",
            f"Shared rate-limit storage degraded: {_limiter_mod.storage_degraded_reason}. "
            "IP-level limits are enforced per-worker until this is resolved.",
            details={"reason": _limiter_mod.storage_degraded_reason},
        )

    # Anonymize service startup gates.
    # These run before the dashboard accepts session-creation requests.
    # When ``anonymize_enabled=False`` the gates are skipped and the
    # dashboard endpoints return 404 — that's the operator's explicit
    # "feature off" signal.
    if settings.anonymize_enabled:
        from app.services.anonymize.startup import (
            AnonymizeStartupError,
            run_anonymize_startup_gates,
        )
        from app.services.anonymize.task_supervisor import (
            install_last_error_redaction_listener,
        )

        # Wire the last_error redactor before
        # any session row can be written.
        install_last_error_redaction_listener()

        try:
            anonymize_status = run_anonymize_startup_gates()
        except AnonymizeStartupError as exc:
            # Hard fail: the message names the offending endpoint and
            # points at the config-knob escape hatch. The operator can
            # either fix the URL or set
            # ``ANONYMIZE_ENFORCE_ONION_ONLY_EGRESS=false`` to opt into
            # the documented privacy-tier downgrade.
            raise RuntimeError(str(exc)) from exc
        # Surface the boolean health summary on the FastAPI app state
        # so the ``/dashboard/api/anonymize/health`` endpoint can read
        # it without re-running the gates on every request.
        app.state.anonymize_health = dict(anonymize_status)

        # Stand up the orchestrator: registers the audit-emit,
        # GC sweep, and decoy-catchup recurring tasks
        # and starts the supervisor. Shutdown stops it cleanly below.
        from app.services.anonymize.service import (
            bootstrap_anonymize_orchestrator,
        )

        await bootstrap_anonymize_orchestrator(app=app)

    # Warn when the dashboard is exposed beyond loopback but no
    # ``TRUSTED_PROXIES`` are configured. Without trusted proxies the
    # dashboard's session-IP binding silently degrades to whatever the
    # last-hop reverse proxy reports as ``client.host`` (which is the
    # proxy itself, identical for every user) — defeating the
    # protection without any indication in the logs.
    if (
        settings.enable_dashboard
        and settings.api_host not in ("127.0.0.1", "localhost", "::1")
        and not settings.trusted_proxies_list
    ):
        logger.warning(
            "ENABLE_DASHBOARD is true and API_HOST=%s is non-loopback, "
            "but TRUSTED_PROXIES is empty. Dashboard session IP-binding "
            "will be applied against the reverse proxy's address (the "
            "same for every client) and provides no real protection. "
            "Set TRUSTED_PROXIES to your reverse proxy's CIDR (e.g. "
            "'172.16.0.0/12') so X-Forwarded-For is honoured.",
            settings.api_host,
        )
    # The audit chain detects in-place tampering, and the signed
    # high-water row detects removal of the newest rows locally. Neither
    # survives an attacker who can drop the whole database (including the
    # high-water row): only an off-box anchor stream does. Warn when no
    # authenticated external anchor is configured so an operator who
    # needs that guarantee knows it is absent.
    if not settings.alert_webhook_shared_secret:
        logger.warning(
            "No ALERT_WEBHOOK_SHARED_SECRET is configured. The audit chain "
            "detects tampering and the signed high-water detects local "
            "truncation, but without an authenticated off-box anchor a full "
            "database wipe leaves no external evidence. Configure "
            "ALERT_WEBHOOK_URL + ALERT_WEBHOOK_SHARED_SECRET to anchor the "
            "chain off-box."
        )
    logger.info(
        "Agent Wallet starting — network=%s, tor=%s",
        settings.bitcoin_network,
        settings.boltz_use_tor,
    )

    # Chain backend startup — bring up the Electrum client when
    # configured. In ``electrum`` mode this fails loud if the
    # connection can't come up; in ``auto`` mode failures are logged
    # and the supervisor retries in the background while the wallet
    # falls back to the Mempool HTTP backend.
    try:
        from app.services.mempool_fee_service import mempool_fee_service

        if mempool_fee_service.has_electrum:
            logger.info(
                "chain backend: electrum primary (%s), fallback=%s",
                settings.lnd_electrum_url,
                "mempool-http" if mempool_fee_service.has_fallback else "none",
            )
            await mempool_fee_service.start()

            # Best-effort: load receive-address subscriptions
            # so incoming deposits trigger a reconcile via push
            # rather than waiting for the 5-min poll. Failure here
            # is non-fatal in any chain_backend mode.
            try:
                from app.services.utxo_subscriptions import (
                    receive_address_subscriber,
                )

                await receive_address_subscriber.start()
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "receive-address subscriptions failed to initialise: %s",
                    exc,
                )
        else:
            logger.info("chain backend: mempool HTTP only (electrum disabled)")
    except Exception as e:
        if settings.chain_backend == "electrum":
            logger.error("Chain backend startup failed in strict electrum mode: %s", e)
            raise
        logger.warning("Chain backend startup warning: %s", e)

    # DB pool startup probe.
    #
    # Refuse to come up if the database is unreachable. Without DB
    # the wallet has no audit trail, no API key validation, and no
    # swap recovery. Better to fail readiness than to start in a
    # silently-broken state.
    #
    # Skipped for SQLite (test/dev only — in-process, never
    # "unreachable", and the production engine factory uses
    # Postgres-specific kwargs that aren't accepted by SQLite).
    if not settings.database_url.startswith("sqlite"):
        try:
            import asyncio as _asyncio

            from sqlalchemy import text as _sql_text

            from app.core.database import get_engine as _get_engine

            async def _db_probe() -> None:
                eng = _get_engine()
                async with eng.connect() as conn:
                    await conn.execute(_sql_text("SELECT 1"))

            await _asyncio.wait_for(_db_probe(), timeout=10.0)
            logger.info("Database connectivity probe passed.")
        except Exception as e:  # noqa: BLE001
            logger.error(
                "Database connectivity probe failed at startup: %s. "
                "Refusing to come up — fix DATABASE_URL or the DB host "
                "and restart.",
                e,
            )
            raise RuntimeError(f"Database unreachable at startup: {e}") from e

    # Recover any pending Boltz swaps from previous run.
    #
    # We run the recovery *synchronously* in lifespan with a
    # bounded budget so we don't depend on Celery being up: a
    # transient broker outage would otherwise leave mid-flight
    # swaps stranded in PENDING forever. If Celery *is* up, it
    # also runs the same task on a periodic schedule so anything
    # that timed out at startup gets picked up later.
    try:
        import asyncio as _asyncio

        from app.tasks.boltz_tasks import _run_recover_swaps

        try:
            await _asyncio.wait_for(_run_recover_swaps(), timeout=60.0)
            logger.info("Boltz swap recovery completed at startup.")
        except _asyncio.TimeoutError:
            logger.warning(
                "Boltz swap recovery exceeded 60s startup budget — "
                "remaining swaps will be picked up by the periodic "
                "recovery task."
            )
    except Exception as e:
        logger.warning("Synchronous swap recovery failed: %s", e)

    # Best-effort: also schedule on Celery so the periodic task
    # picks up anything we couldn't finish synchronously.
    try:
        from app.tasks.boltz_tasks import recover_boltz_swaps

        recover_boltz_swaps.delay()
        logger.info("Scheduled Boltz swap recovery task.")
    except Exception as e:
        logger.warning("Could not schedule swap recovery (Celery may not be running): %s", e)

    # Braiins Deposit recovery — drive any non-terminal session
    # forward one step. Bounded budget; periodic Celery task picks
    # up anything we couldn't finish. Only runs when the feature is
    # enabled.
    if settings.braiins_deposit_enabled:
        try:
            import asyncio as _asyncio

            from app.tasks.braiins_deposit_tasks import (
                _run_recover_braiins_deposits,
            )

            try:
                await _asyncio.wait_for(_run_recover_braiins_deposits(), timeout=30.0)
                logger.info("Braiins Deposit recovery completed at startup.")
            except _asyncio.TimeoutError:
                logger.warning(
                    "Braiins Deposit recovery exceeded 30s startup budget — "
                    "remaining sessions will be picked up by the periodic task."
                )
        except Exception as e:  # noqa: BLE001
            logger.warning("Synchronous Braiins Deposit recovery failed: %s", e)

    # BOLT 12 runtime — best-effort start (no-op if disabled).
    from app.services.bolt12.runtime import (
        start_bolt12_runtime,
        stop_bolt12_runtime,
    )

    await start_bolt12_runtime()

    # Sticky-peer reconciler — keeps the gateway connected to
    # well-known payers (OCEAN, etc.) across gateway restarts and
    # network blips. Best-effort: never break startup if the
    # reconciler can't compute its desired set. Coordinates with the
    # Rust-side on-disconnect handler via the shared per-pubkey
    # mutex inside the gateway's ConnectPeer codepath, so a Python
    # dial + Rust redial can't race a duplicate connection.
    try:
        from app.services.bolt12.sticky_peer_reconciler import (
            start_reconciler as start_bolt12_sticky_reconciler,
        )

        await start_bolt12_sticky_reconciler()
    except Exception:  # noqa: BLE001
        logger.exception("BOLT 12 sticky-peer reconciler start failed")

    # Fail any BOLT 12 invreq rows stranded as PENDING from a
    # prior crash. Best-effort — never break startup if the table
    # is empty / migration hasn't run yet.
    try:
        from app.core.database import get_db_context
        from app.services.bolt12.reconcile import reconcile_stranded_invreqs

        async with get_db_context() as _db:
            result = await reconcile_stranded_invreqs(_db, request_timeout_seconds=60.0)
        if result.get("timed_out"):
            logger.info(
                "BOLT 12 startup reconcile: timed out %d stranded invreqs.",
                result["timed_out"],
            )
    except Exception as e:  # noqa: BLE001
        logger.warning("BOLT 12 invreq reconciliation failed: %s", e)

    # Liquid fee-oracle refresh task. Polls the
    # backend on the configured cadence so quote-time reads are
    # cache-only with no per-quote egress. Only fires when the Liquid
    # hop is enabled; otherwise the cache stays empty and quotes that
    # try to use it surface ``no_cache`` (the safe-side ceiling).
    _liquid_fee_oracle_task: asyncio.Task[None] | None = None
    try:
        from app.services.anonymize.hops.liquid import is_liquid_hop_enabled
    except Exception:  # noqa: BLE001
        is_liquid_hop_enabled = lambda: False  # type: ignore[assignment]  # noqa: E731  # one-line import-fallback shim
    if is_liquid_hop_enabled():
        try:
            from app.services.anonymize.hop_dispatcher import (
                build_default_liquid_hop_deps,
            )
            from app.services.anonymize.liquid_fee_oracle import (
                get_liquid_fee_oracle,
            )

            # Pull the same deps the dispatcher caches so the oracle
            # and the hop body share one ElectrumClient connection.
            _liquid_deps = build_default_liquid_hop_deps()
            if _liquid_deps is not None:
                # The deps' backend is the same instance the dispatcher
                # uses; pluck it out via a fresh build_default call.
                # The cache is the dict-shaped LiquidHopDeps; the
                # backend isn't directly exposed there, so we rebuild
                # an ElectrumLiquidBackend dedicated to the oracle.
                # Construction is cheap (no socket open until first
                # call), so the duplicate is fine.
                from app.services.anonymize.liquid_backend import (
                    ElectrumLiquidBackend,
                )
                from app.services.chain.electrum import ElectrumClient

                _oracle_client = ElectrumClient(settings.anonymize_liquid_electrum_url)
                _oracle_backend = ElectrumLiquidBackend(_oracle_client)
                _oracle = get_liquid_fee_oracle(_oracle_backend)

                _oracle_interval = max(30, int(settings.anonymize_liquid_fee_rate_cache_ttl_s))

                async def _liquid_fee_oracle_refresh_loop() -> None:
                    while True:
                        try:
                            await _oracle.refresh()
                        except Exception as exc:  # noqa: BLE001
                            logger.warning(
                                "liquid fee-oracle refresh failed: %s",
                                exc,
                            )
                        try:
                            await asyncio.sleep(_oracle_interval)
                        except asyncio.CancelledError:
                            return

                _liquid_fee_oracle_task = asyncio.create_task(
                    _liquid_fee_oracle_refresh_loop(),
                    name="liquid-fee-oracle-refresh",
                )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "liquid fee-oracle task not started: %s",
                exc,
            )

    # Periodic HTTP-client recycle. Cycles upstream clients on
    # a fixed interval so leaked sockets / stale TLS sessions /
    # connection-pool wedges get forcibly cleaned. Circuit breakers
    # cover the brief reconnect blip.
    _recycle_task: asyncio.Task[None] | None = None
    try:
        _recycle_interval = float(settings.http_client_recycle_seconds)
    except Exception:  # noqa: BLE001
        _recycle_interval = 0.0
    if _recycle_interval > 0:

        async def _http_client_recycle_loop() -> None:
            from app.services.boltz_service import boltz_service
            from app.services.lnd_service import lnd_service
            from app.services.mempool_fee_service import mempool_fee_service

            while True:
                try:
                    await asyncio.sleep(_recycle_interval)
                except asyncio.CancelledError:
                    return
                _recyclable: tuple[tuple[str, Any], ...] = (
                    ("lnd", lnd_service),
                    ("boltz", boltz_service),
                    ("mempool", mempool_fee_service),
                )
                for name, svc in _recyclable:
                    try:
                        await svc.close()
                    except Exception as exc:  # noqa: BLE001
                        logger.warning("client recycle: close %s client failed: %s", name, exc)

        _recycle_task = asyncio.create_task(_http_client_recycle_loop(), name="http-client-recycle")

    # Start the Tor recovery watchdog. It polls the
    # Tor breaker, gates NEWNYM on the in-flight inventory
    # , and escalates through tiers when circuits
    # stay wedged. Supervised: if the loop crashes, the supervisor
    # restarts it up to 3 times in 5 minutes before staying stopped.
    #
    # Split mode runs TWO watchdog + event-stream tasks
    # (one per Tor pool); single mode runs one. The task list is
    # built dynamically so shutdown can cancel whatever we spawned.
    from app.services.tor_event_stream import start_event_stream as _start_tor_events
    from app.services.tor_watchdog import start_watchdog as _start_tor_watchdog

    _split = bool(getattr(settings, "tor_split_mode", False))
    _tor_pool_labels: list[str] = ["lnd", "anonymize"] if _split else ["unified"]

    _tor_watchdog_stop_event: asyncio.Event = asyncio.Event()
    _tor_watchdog_tasks: list[asyncio.Task[None]] = [
        asyncio.create_task(
            _start_tor_watchdog(_tor_watchdog_stop_event, pool=p),
            name=f"tor-watchdog-{p}",
        )
        for p in _tor_pool_labels
    ]

    # Live SETEVENTS subscription per pool.
    _tor_event_stop_event: asyncio.Event = asyncio.Event()
    _tor_event_tasks: list[asyncio.Task[None]] = [
        asyncio.create_task(
            _start_tor_events(_tor_event_stop_event, pool=p),
            name=f"tor-event-stream-{p}",
        )
        for p in _tor_pool_labels
    ]

    # LND-onion keepalive. Cheap GET /v1/getinfo on a 60 s cadence
    # so at least one warm Tor circuit to LND's hidden service
    # stays available for latency-sensitive callers (BOLT-12
    # responder racing Ocean's ~60-90 s deadline). Honors the
    # ``lnd_keepalive_interval_s`` knob (0 disables).
    from app.services.lnd_keepalive import run_lnd_keepalive as _run_lnd_keepalive

    _lnd_keepalive_stop_event: asyncio.Event = asyncio.Event()
    _lnd_keepalive_task: Optional[asyncio.Task[None]] = asyncio.create_task(
        _run_lnd_keepalive(_lnd_keepalive_stop_event),
        name="lnd-keepalive",
    )

    # LND Tor supervisor — staggered HSFETCH → NEWNYM → SIGHUP →
    # healthcheck ladder when the LND .onion goes stale (driver:
    # 2026-06-01 incident). Reads _LND_BREAKER
    # state, gates on corroborating signals (other-onion probe +
    # HSFETCH), and bounds itself with a rolling 24 h cycle cap.
    # Default-on (settings.lnd_tor_recovery_enabled = True). The
    # supervisor itself decides whether to act each tick; this
    # lifespan just owns its task lifecycle.
    from app.services.lnd_tor_supervisor import (
        run_lnd_tor_supervisor as _run_lnd_tor_supervisor,
    )

    _lnd_tor_supervisor_stop_event: asyncio.Event = asyncio.Event()
    _lnd_tor_supervisor_task: Optional[asyncio.Task[None]] = asyncio.create_task(
        _run_lnd_tor_supervisor(_lnd_tor_supervisor_stop_event),
        name="lnd-tor-supervisor",
    )

    # 2026-06-12 (T4): periodic HSFETCH probe of our LND onion so
    # operators can see HS-descriptor freshness on /livez.
    from app.services.lnd_hs_descriptor_age import (
        run_hs_descriptor_age_probe as _run_hs_age_probe,
    )

    _hs_age_stop_event: asyncio.Event = asyncio.Event()
    _hs_age_task: Optional[asyncio.Task[None]] = asyncio.create_task(
        _run_hs_age_probe(_hs_age_stop_event),
        name="lnd-hs-descriptor-age",
    )

    # 2026-06-12 (T6): per-channel uptime tracker. 30 s polling
    # cadence — tighter than keepalive's 60 s so chronic flappers
    # surface without manual investigation.
    from app.services.lnd_channel_uptime import (
        run_channel_uptime_tracker as _run_channel_uptime,
    )

    _channel_uptime_stop_event: asyncio.Event = asyncio.Event()
    _channel_uptime_task: Optional[asyncio.Task[None]] = asyncio.create_task(
        _run_channel_uptime(_channel_uptime_stop_event),
        name="lnd-channel-uptime-tracker",
    )

    # 2026-06-12 (S3): channel-flap detector. Catches sub-minute
    # active→inactive transitions that the 60 s keepalive misses;
    # feeds the same NEWNYM-burst trigger.
    from app.services.lnd_channel_flap_detector import (
        run_channel_flap_detector as _run_channel_flap,
    )

    _channel_flap_stop_event: asyncio.Event = asyncio.Event()
    _channel_flap_task: Optional[asyncio.Task[None]] = asyncio.create_task(
        _run_channel_flap(_channel_flap_stop_event),
        name="lnd-channel-flap-detector",
    )

    # 2026-06-12 (S1): inbound-symptom HS supervisor. SIGHUP Tor
    # when subscribers can't keep a stream alive long enough —
    # the strongest wallet-side action for "peers can't reach
    # our HS" symptoms.
    from app.services.bolt12.inbound_supervisor import (
        run_inbound_supervisor as _run_inbound_supervisor,
    )

    _inbound_supervisor_stop_event: asyncio.Event = asyncio.Event()
    _inbound_supervisor_task: Optional[asyncio.Task[None]] = asyncio.create_task(
        _run_inbound_supervisor(_inbound_supervisor_stop_event),
        name="bolt12-inbound-supervisor",
    )

    # Only spawn these tasks when a Tor
    # proxy is actually configured. Without one we'd just be
    # attempting clearnet HEAD requests / SOCKS5 round-trips that
    # can't complete, leaving sockets dangling at shutdown.
    _tor_prewarm_task: Optional[asyncio.Task[None]] = None
    _tor_smoke_task: Optional[asyncio.Task[None]] = None
    _tor_proxy_reach_task: Optional[asyncio.Task[None]] = None
    _tor_dns_leak_task: Optional[asyncio.Task[None]] = None
    _lnd_tor_proxy = getattr(settings, "lnd_tor_proxy", "")
    if isinstance(_lnd_tor_proxy, str) and _lnd_tor_proxy:
        # One-shot SOCKS5 round-trip so a misconfigured
        # operator-supplied Tor surfaces in docker logs on first
        # boot rather than 30 minutes later in an onion call.
        _tor_proxy_reach_task = asyncio.create_task(
            _run_tor_proxy_reach_check(),
            name="tor-proxy-reach-check",
        )
        # DNS-leak / Tor-routing verification. Confirms
        # the proxy is actually routing traffic through Tor and
        # not silently falling back to direct connect.
        _tor_dns_leak_task = asyncio.create_task(
            _run_tor_dns_leak_check(),
            name="tor-dns-leak-check",
        )
        # Pre-warm HS descriptors for known onions (LND, Boltz,
        # operator registry). Fire-and-forget; the 10 s internal budget
        # bounds wall-clock cost and partial results are fine — anything
        # we don't pre-warm gets fetched lazily on first real use.
        _tor_prewarm_task = asyncio.create_task(
            _run_tor_prewarm(),
            name="tor-prewarm",
        )

        # Startup exit-relay diversity smoke test. Skips itself
        # when Tor isn't ready (cold boot). Hard-fails (raises) only on
        # observed circuit collision; that aborts startup intentionally,
        # because broken listener isolation is a security regression.
        # Fire-and-forget here; the hard-fail path is opt-in via
        # ``tor_diversity_smoke_blocking`` for tightly-managed deploys.
        if not getattr(settings, "tor_diversity_smoke_blocking", False):
            _tor_smoke_task = asyncio.create_task(
                _run_tor_diversity_smoke(),
                name="tor-diversity-smoke",
            )
        else:
            # Blocking variant — wait for the smoke test to finish so a
            # hard-fail aborts lifespan before traffic is accepted.
            await _run_tor_diversity_smoke()

    yield

    # Graceful shutdown drain.
    # Flip the flag so new HTTP requests get 503 immediately, then
    # wait up to ``shutdown_drain_seconds`` for in-flight handlers
    # to finish before we tear down service clients underneath them.
    from app.core.concurrency import begin_shutdown, in_flight_count, wait_for_drain

    begin_shutdown()

    # Cancel the client-recycle loop before draining so it cannot tear
    # down clients underneath in-flight requests.
    if _recycle_task is not None:
        _recycle_task.cancel()
        try:
            await _recycle_task
        except (asyncio.CancelledError, Exception):
            pass

    # Cancel the Liquid fee-oracle refresh loop.
    if _liquid_fee_oracle_task is not None:
        _liquid_fee_oracle_task.cancel()
        try:
            await _liquid_fee_oracle_task
        except (asyncio.CancelledError, Exception):
            pass

    # Graceful Tor watchdog shutdown. Set the stop
    # event, give the loops one tick to notice, then cancel as a
    # backstop in case any is mid-sleep. — same pattern but
    # over the per-pool task list.
    try:
        _tor_watchdog_stop_event.set()
    except Exception:  # noqa: BLE001
        pass
    for _task in _tor_watchdog_tasks:
        try:
            await asyncio.wait_for(_task, timeout=5.0)
        except (asyncio.TimeoutError, asyncio.CancelledError, Exception):
            _task.cancel()
            try:
                await _task
            except (asyncio.CancelledError, Exception):
                pass

    # Same shutdown pattern for the event-stream tasks.
    try:
        _tor_event_stop_event.set()
    except Exception:  # noqa: BLE001
        pass
    for _task in _tor_event_tasks:
        try:
            await asyncio.wait_for(_task, timeout=5.0)
        except (asyncio.TimeoutError, asyncio.CancelledError, Exception):
            _task.cancel()
            try:
                await _task
            except (asyncio.CancelledError, Exception):
                pass

    # Stop the LND keepalive loop.
    try:
        _lnd_keepalive_stop_event.set()
    except Exception:  # noqa: BLE001
        pass
    if _lnd_keepalive_task is not None and not _lnd_keepalive_task.done():
        try:
            await asyncio.wait_for(_lnd_keepalive_task, timeout=5.0)
        except (asyncio.TimeoutError, asyncio.CancelledError, Exception):
            _lnd_keepalive_task.cancel()
            try:
                await _lnd_keepalive_task
            except (asyncio.CancelledError, Exception):
                pass

    # Stop the LND Tor supervisor loop. The supervisor's tick may
    # be in the middle of an HSFETCH / NEWNYM / SIGHUP step; give
    # it ~5 s to wrap up cleanly before cancelling.
    try:
        _lnd_tor_supervisor_stop_event.set()
    except Exception:  # noqa: BLE001
        pass
    if _lnd_tor_supervisor_task is not None and not _lnd_tor_supervisor_task.done():
        try:
            await asyncio.wait_for(_lnd_tor_supervisor_task, timeout=5.0)
        except (asyncio.TimeoutError, asyncio.CancelledError, Exception):
            _lnd_tor_supervisor_task.cancel()
            try:
                await _lnd_tor_supervisor_task
            except (asyncio.CancelledError, Exception):
                pass

    # 2026-06-12: stop the new background tasks (T4/T6/S3/S1).
    for stop_ev, task in (
        (_hs_age_stop_event, _hs_age_task),
        (_channel_uptime_stop_event, _channel_uptime_task),
        (_channel_flap_stop_event, _channel_flap_task),
        (_inbound_supervisor_stop_event, _inbound_supervisor_task),
    ):
        try:
            stop_ev.set()
        except Exception:  # noqa: BLE001
            pass
        if task is not None and not task.done():
            try:
                await asyncio.wait_for(task, timeout=3.0)
            except (asyncio.TimeoutError, asyncio.CancelledError, Exception):
                task.cancel()
                try:
                    await task
                except (asyncio.CancelledError, Exception):
                    pass

    # Cancel any still-running pre-warm task. It's bounded
    # internally to 10 s; this is just belt-and-braces for the rare
    # case where shutdown lands during the prewarm window.
    if _tor_prewarm_task is not None and not _tor_prewarm_task.done():
        _tor_prewarm_task.cancel()
        try:
            await _tor_prewarm_task
        except (asyncio.CancelledError, Exception):
            pass

    # Cancel the diversity smoke task if it's still running.
    if _tor_smoke_task is not None and not _tor_smoke_task.done():
        _tor_smoke_task.cancel()
        try:
            await _tor_smoke_task
        except (asyncio.CancelledError, Exception):
            pass

    # Same shutdown pattern for the proxy-reach probe.
    if _tor_proxy_reach_task is not None and not _tor_proxy_reach_task.done():
        _tor_proxy_reach_task.cancel()
        try:
            await _tor_proxy_reach_task
        except (asyncio.CancelledError, Exception):
            pass

    # Same shutdown pattern for the DNS-leak probe.
    if _tor_dns_leak_task is not None and not _tor_dns_leak_task.done():
        _tor_dns_leak_task.cancel()
        try:
            await _tor_dns_leak_task
        except (asyncio.CancelledError, Exception):
            pass

    drained = await wait_for_drain(settings.shutdown_drain_seconds)
    if drained:
        logger.info("Shutdown drain complete — no in-flight requests.")
    else:
        logger.warning(
            "Shutdown drain timed out after %.1fs with %d in-flight requests; proceeding with teardown.",
            settings.shutdown_drain_seconds,
            in_flight_count(),
        )

    # Shutdown — close service HTTP clients
    from app.core.rate_limit import close_redis
    from app.services.boltz_service import boltz_service
    from app.services.lnd_service import lnd_service
    from app.services.mempool_fee_service import mempool_fee_service

    # Stop the anonymize orchestrator before tearing down LND / Boltz
    # so per-session tasks see a clean cancel rather than a torn-down
    # downstream client.
    if settings.anonymize_enabled:
        try:
            from app.services.anonymize.service import get_anonymize_service

            await get_anonymize_service().stop()
        except Exception:  # noqa: BLE001
            logger.warning("anonymize orchestrator shutdown raised", exc_info=True)

    # Stop the sticky-peer reconciler BEFORE stop_bolt12_runtime —
    # otherwise its final tick could land on a half-torn-down client.
    try:
        from app.services.bolt12.sticky_peer_reconciler import (
            stop_reconciler as stop_bolt12_sticky_reconciler,
        )

        await stop_bolt12_sticky_reconciler()
    except Exception:  # noqa: BLE001
        logger.warning(
            "BOLT 12 sticky-peer reconciler shutdown raised",
            exc_info=True,
        )

    await stop_bolt12_runtime()
    await lnd_service.close()
    await boltz_service.close()
    try:
        from app.services.utxo_subscriptions import receive_address_subscriber

        await receive_address_subscriber.stop()
    except Exception:  # noqa: BLE001
        pass
    await mempool_fee_service.close()
    await close_redis()

    # Shutdown — dispose all async engines
    for eng in engine_registry.values():
        await eng.dispose()  # type: ignore[attr-defined]
    engine_registry.clear()
    logger.info("Agent Wallet shut down.")


app = FastAPI(
    title="Agent Wallet",
    description="A Bitcoin and Lightning wallet service providing AI agents an interface for transacting in Bitcoin.",
    version="0.1.0",
    lifespan=lifespan,
    docs_url="/docs" if settings.enable_docs else None,
    redoc_url="/redoc" if settings.enable_docs else None,
    openapi_url="/openapi.json" if settings.enable_docs else None,
)

app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    return JSONResponse(
        status_code=429,
        content={"detail": "Rate limit exceeded. Try again later."},
        headers={"Retry-After": "60"},
    )


# ─── CORS ───────────────────────────────────────────────────────────────────
# Always add CORS middleware. When no origins are configured, allow_origins=[]
# explicitly blocks all cross-origin requests (prevents simple-request bypass).
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list if settings.cors_origins_list else [],
    allow_credentials=True if settings.cors_origins_list else False,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)


# ─── Trusted Proxy Headers ───────────────────────────────────────────────────
if settings.trusted_proxies_list:
    from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

    app.add_middleware(
        ProxyHeadersMiddleware,  # type: ignore[arg-type]
        trusted_hosts=settings.trusted_proxies_list,
    )


# ─── Anonymize timing floor ─────────────────────────────
# Registered last so it becomes the outermost middleware — every
# anonymize-prefixed POST response (success or auth/CSRF/422 fast-fail)
# is held until the configured floor elapses. Disabled when the
# anonymize feature itself is off.
if settings.anonymize_enabled:
    from app.services.anonymize.middleware import AnonymizeTimingMiddleware

    app.add_middleware(AnonymizeTimingMiddleware)


# ─── Request Body Size Limit ─────────────────────────────────────────────────
MAX_BODY_SIZE = 1_048_576  # 1 MB


# ─── concurrency cap, drain, in-flight gauge ──────────────────
from app.core.concurrency import (
    TrackInFlight,
    configure_concurrent_cap,
    is_shutting_down,
    release_for_key,
    try_acquire_for_key,
)

configure_concurrent_cap(settings.max_concurrent_requests_per_key)

# Paths that bypass the drain + per-key cap. Health/readiness must
# stay reachable during shutdown so the load balancer can detect
# the drain transition.
_DRAIN_BYPASS_PREFIXES = (
    "/health",
    "/ready",
    "/v1/admin/services",
    "/v1/admin/tasks/status",
    "/metrics",
)


def _api_key_id_from_headers(request: Request) -> str | None:
    """Best-effort stable id for the per-key concurrency cap.

    Hashes the bearer token (the same SHA-256 truncation used by
    :func:`app.core.security.hash_api_key`) so we do not have to
    hit the DB just to get the cap. Returns ``None`` for unauthed
    requests; those bypass the per-key cap (rate-limit middleware
    rejects them by other means).
    """
    auth = request.headers.get("authorization") or ""
    if not auth.lower().startswith("bearer "):
        return None
    token = auth[7:].strip()
    if not token:
        return None
    # Cheap, stable, non-reversible — enough to key a semaphore.
    import hashlib

    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:32]


@app.middleware("http")
async def concurrency_and_drain(request: Request, call_next: Any) -> Response:
    path = request.url.path

    # Bypass for ops endpoints — these must stay reachable.
    if any(path.startswith(p) for p in _DRAIN_BYPASS_PREFIXES):
        async with TrackInFlight():
            response: Response = await call_next(request)
            return response

    # Refuse new requests once shutdown begins.
    if is_shutting_down():
        return JSONResponse(
            status_code=503,
            content={"detail": "Server is draining; retry the request later."},
            headers={"Retry-After": "30"},
        )

    # Per-API-key concurrency cap.
    key_id = _api_key_id_from_headers(request)
    acquired = False
    if key_id is not None:
        acquired = try_acquire_for_key(key_id)
        if not acquired:
            return JSONResponse(
                status_code=429,
                content={
                    "detail": (
                        "Too many concurrent requests for this API key "
                        f"(cap={settings.max_concurrent_requests_per_key}). "
                        "Slow down or stagger calls."
                    )
                },
            )

    try:
        async with TrackInFlight():
            response = await call_next(request)
            return response
    finally:
        if acquired and key_id is not None:
            release_for_key(key_id)


@app.middleware("http")
async def limit_body_size(request: Request, call_next: Any) -> Response:
    # Fast path: trust an honest Content-Length and reject before reading.
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > MAX_BODY_SIZE:
                return JSONResponse(status_code=413, content={"detail": "Request body too large"})
        except ValueError:
            return JSONResponse(status_code=400, content={"detail": "Invalid Content-Length header"})

    # Defence-in-depth: also enforce the cap on streamed bodies that omit
    # Content-Length (Transfer-Encoding: chunked, HTTP/2). Drain the
    # body up-front so we can refuse oversized requests *before*
    # invoking the handler — running the handler with a truncated body
    # let it observe partial state (database writes from the part we
    # accepted, response objects already constructed) which then got
    # silently discarded when the wrapper rewrote the response to 413.
    original_receive = request._receive  # type: ignore[attr-defined]
    buffered_messages: list[MutableMapping[str, Any]] = []
    received = 0
    while True:
        message = await original_receive()
        if message.get("type") != "http.request":
            buffered_messages.append(message)
            break
        chunk = message.get("body", b"") or b""
        received += len(chunk)
        if received > MAX_BODY_SIZE:
            return JSONResponse(status_code=413, content={"detail": "Request body too large"})
        buffered_messages.append(message)
        if not message.get("more_body", False):
            break

    replay_iter = iter(buffered_messages)

    async def replay_receive() -> Any:
        try:
            return next(replay_iter)
        except StopIteration:
            return await original_receive()

    request._receive = replay_receive  # type: ignore[attr-defined]
    response: Response = await call_next(request)
    return response


# ─── Request Correlation ID ───────────────────────────────────────────────────
_REQUEST_ID_RE = re.compile(r"^[a-zA-Z0-9\-_]{1,128}$")


@app.middleware("http")
async def request_id_middleware(request: Request, call_next: Any) -> Response:
    raw = request.headers.get("X-Request-ID", "")
    request_id = raw if _REQUEST_ID_RE.match(raw) else uuid.uuid4().hex
    request.state.request_id = request_id
    response: Response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    return response


# ─── CSP Nonce ────────────────────────────────────────────────────────────────
@app.middleware("http")
async def csp_nonce_middleware(request: Request, call_next: Any) -> Response:
    """Generate a per-request cryptographic nonce for Content-Security-Policy."""
    request.state.csp_nonce = secrets.token_urlsafe(16)
    response: Response = await call_next(request)
    return response


# ─── Security Headers ───────────────────────────────────────────────────────
@app.middleware("http")
async def security_headers(request: Request, call_next: Any) -> Response:
    response: Response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
    if settings.enable_hsts:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    if request.url.path.startswith("/dashboard"):
        nonce = getattr(request.state, "csp_nonce", "")
        # Using @alpinejs/csp build which evaluates expressions without
        # Function() / eval(), so 'unsafe-eval' is not needed.
        # The dashboard
        # vendor assets are served from ``/dashboard/static/vendor/``
        # rather than ``cdn.jsdelivr.net``, so the CSP no longer needs
        # to allow-list any third-party host. SRI on each <script>
        # remains as defence-in-depth.
        # ``style-src`` allows ``'unsafe-inline'`` because Alpine's
        # runtime applies inline ``style`` attributes (e.g. via
        # x-show, x-transition) that have no nonce. Per CSP spec,
        # mixing a nonce with ``'unsafe-inline'`` causes the browser
        # to ignore ``'unsafe-inline'``, so the nonce is omitted
        # here. The risk is limited: dashboard markup is templated
        # server-side from trusted sources, and ``script-src``
        # remains nonce-locked which prevents arbitrary JS injection
        # (the typical vector for stylesheet-based exfiltration).
        csp = (
            "default-src 'self'; "
            f"script-src 'self' 'nonce-{nonce}'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "form-action 'self'; "
            "frame-ancestors 'none'"
        )
        if settings.enable_hsts:
            csp += "; upgrade-insecure-requests"
        response.headers["Content-Security-Policy"] = csp
    elif settings.enable_docs and request.url.path in (
        "/docs",
        "/redoc",
        "/openapi.json",
    ):
        # Swagger UI and ReDoc load JS/CSS from a CDN and execute
        # inline scripts to bootstrap. Our default ``default-src
        # 'none'`` policy blocks all of that, leaving operators
        # staring at a blank page when they enable ``ENABLE_DOCS``.
        # Emit a docs-only relaxed CSP that still blocks framing,
        # form posts, and base-uri hijacking. Operators who do not
        # need /docs should keep ``ENABLE_DOCS=false`` (the default).
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "img-src 'self' data: https://fastapi.tiangolo.com; "
            "font-src 'self' data:; "
            "connect-src 'self'; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "form-action 'none'; "
            "frame-ancestors 'none'"
        )
    else:
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
        )
    # Deliver a freshly-rotated CSRF token (stashed on request.state by the
    # auth dependency) on the *final* response. FastAPI does not merge
    # dependency-set headers onto a directly-returned Response, so an
    # endpoint that returns its own JSONResponse (every error path) would
    # otherwise drop ``X-CSRF-Token-Next`` — the server rotates the token
    # but the client never learns it and the next write fails CSRF (403).
    csrf_next = getattr(request.state, "csrf_next", None)
    if isinstance(csrf_next, str) and csrf_next:
        response.headers["X-CSRF-Token-Next"] = csrf_next
    return response


# ─── Routers ──────────────────────────────────────────────────────────
from app.api.admin import router as admin_router
from app.api.bolt12 import router as bolt12_router
from app.api.channel_mix import router as channel_mix_router
from app.api.channels import router as channels_router
from app.api.cold_storage import router as cold_storage_router
from app.api.livez import router as livez_router
from app.api.mempool import router as mempool_router
from app.api.payments import router as payments_router
from app.api.peer_catalog import router as peer_catalog_router
from app.api.tor_metrics import router as tor_metrics_router
from app.api.wallet import router as wallet_router

app.include_router(livez_router)
app.include_router(wallet_router)
app.include_router(payments_router)
app.include_router(channels_router)
app.include_router(cold_storage_router)
app.include_router(mempool_router)
app.include_router(admin_router)
app.include_router(bolt12_router)
app.include_router(peer_catalog_router)
app.include_router(channel_mix_router)
app.include_router(tor_metrics_router)

# ─── Sign / Verify Message ──────────────────────────────────────────
# Verify endpoints always available; sign endpoints gated on
# ENABLE_SIGN_ADDRESS_API / ENABLE_SIGN_NODE_API. Disabled sign
# endpoints are not mounted (404 to probes).
from app.api.sign import (
    sign_address_router,
    sign_node_router,
)
from app.api.sign import (
    verify_router as sign_verify_router,
)

app.include_router(sign_verify_router)
if settings.enable_sign_address_api:
    app.include_router(sign_address_router)
    logger.info("Sign-address API enabled (POST /v1/wallet/sign/address).")
if settings.enable_sign_node_api:
    app.include_router(sign_node_router)
    logger.info("Sign-node API enabled (POST /v1/wallet/sign/node).")

# ─── Dashboard UI ──────────────────────────────────────────────────
if settings.enable_dashboard:
    from pathlib import Path as _Path

    from fastapi.staticfiles import StaticFiles

    from app.dashboard.api import router as dashboard_api
    from app.dashboard.auth import ensure_token_ready
    from app.dashboard.routes import router as dashboard_routes

    app.include_router(dashboard_routes)
    app.include_router(dashboard_api)
    app.mount(
        "/dashboard/static",
        StaticFiles(directory=str(_Path(__file__).parent / "dashboard" / "static")),
        name="dashboard-static",
    )
    ensure_token_ready()

    @app.get("/", include_in_schema=False)
    async def _root_to_dashboard() -> RedirectResponse:
        """Send the site root to the dashboard, which is served under /dashboard/."""
        return RedirectResponse(url="/dashboard/")

    logger.info("Dashboard enabled at /dashboard/")


# ─── Unauthenticated health / readiness probes ───────────────────────
@app.get("/health", tags=["system"])
async def health() -> dict[str, str]:
    """Liveness probe — confirms the process is running (no auth required)."""
    return {"status": "ok"}


@app.get("/ready", tags=["system"], response_model=None)
async def readiness() -> dict[str, Any] | JSONResponse:
    """Readiness probe — checks DB + critical upstream services.

    Returns 503 when the load balancer should *not* route traffic
    here:

    * The database is unreachable (always P0 — without DB the
      wallet cannot serve requests).
    * The LND breaker is open (P0 — payments would all fail).

    Soft dependencies (Boltz, mempool, BOLT 12 gateway) are reported
    in the response payload for visibility but do not flip the
    HTTP status. Per-component results are read from in-process
    health snapshots; the endpoint never blocks on upstream calls.
    """
    from app.services.health import get_health

    db_status = "connected"
    db_ok = True
    try:
        session_maker = get_session_maker()
        async with session_maker() as session:
            from sqlalchemy import text

            await session.execute(text("SELECT 1"))
    except Exception as e:
        logger.warning("Readiness check: DB failed: %s", e)
        db_status = "connection_failed"
        db_ok = False

    lnd_health = get_health("lnd")
    lnd_breaker_state = lnd_health.breaker.state if lnd_health and lnd_health.breaker else "unknown"
    lnd_ok = lnd_health is None or lnd_health.breaker is None or lnd_health.breaker.state != "open"

    services_summary: dict[str, Any] = {}
    for name in ("lnd", "boltz", "mempool", "bolt12_gateway"):
        h = get_health(name)
        if h is None:
            continue
        services_summary[name] = {
            "healthy": h.healthy,
            "enabled": h.enabled,
        }

    payload: dict[str, Any] = {
        "status": "ok" if (db_ok and lnd_ok) else "unavailable",
        "database": db_status,
        "lnd_breaker": lnd_breaker_state,
        "services": services_summary,
    }

    if not (db_ok and lnd_ok):
        return JSONResponse(status_code=503, content=payload)
    return payload


# ─── top-level Prometheus-format metrics endpoint ───────────────
@app.get("/metrics", tags=["system"], response_class=PlainTextResponse)
async def metrics(request: Request) -> str:
    """Prometheus text-format metrics for the wallet process.

    Surfaces in-flight request counters and a handful of
    DB-derived gauges so operators can wire up alerting on
    pending-work backlogs.

    The process gauges (in-flight, shutting-down) are unauthenticated so
    a liveness scraper works without credentials. The DB-derived
    business gauges (pending swaps / invoice requests) reveal wallet
    activity, so they are only emitted to a caller presenting a valid
    admin API key.
    """
    from app.core.concurrency import in_flight_count, is_shutting_down

    lines: list[str] = []

    lines.append("# HELP agent_wallet_in_flight_requests Current in-flight HTTP requests.")
    lines.append("# TYPE agent_wallet_in_flight_requests gauge")
    lines.append(f"agent_wallet_in_flight_requests {in_flight_count()}")

    lines.append("# HELP agent_wallet_shutting_down Whether the process is draining (1) or accepting traffic (0).")
    lines.append("# TYPE agent_wallet_shutting_down gauge")
    lines.append(f"agent_wallet_shutting_down {1 if is_shutting_down() else 0}")

    # DB-derived gauges. Best-effort — never fail the metrics scrape.
    # Gated behind an admin key so anonymous callers can't read wallet
    # business state (pending swap / invoice-request counts).
    try:
        from sqlalchemy import func, select

        from app.core.database import get_session_maker
        from app.core.security import request_has_admin_key

        session_maker = get_session_maker()
        async with session_maker() as session:
            if not await request_has_admin_key(request, session):
                return "\n".join(lines) + "\n"
            try:
                from app.models.boltz_swap import BoltzSwap, SwapStatus

                pending_swaps = (
                    await session.execute(
                        select(func.count(BoltzSwap.id)).where(
                            BoltzSwap.status.in_(
                                [
                                    SwapStatus.CREATED,
                                    SwapStatus.PAYING_INVOICE,
                                    SwapStatus.INVOICE_PAID,
                                    SwapStatus.CLAIMING,
                                ]
                            )
                        )
                    )
                ).scalar() or 0
                lines.append("# HELP agent_wallet_pending_swaps Boltz swaps awaiting completion.")
                lines.append("# TYPE agent_wallet_pending_swaps gauge")
                lines.append(f"agent_wallet_pending_swaps {int(pending_swaps)}")
            except Exception:  # noqa: BLE001
                pass

            try:
                from app.models.bolt12_invoice import (
                    Bolt12InvoiceRequest,
                    Bolt12InvoiceRequestStatus,
                )

                pending_invreqs = (
                    await session.execute(
                        select(func.count(Bolt12InvoiceRequest.id)).where(
                            Bolt12InvoiceRequest.status == Bolt12InvoiceRequestStatus.PENDING
                        )
                    )
                ).scalar() or 0
                lines.append(
                    "# HELP agent_wallet_pending_bolt12_invreqs BOLT 12 invoice requests awaiting fulfillment."
                )
                lines.append("# TYPE agent_wallet_pending_bolt12_invreqs gauge")
                lines.append(f"agent_wallet_pending_bolt12_invreqs {int(pending_invreqs)}")
            except Exception:  # noqa: BLE001
                pass
    except Exception:  # noqa: BLE001
        pass

    return "\n".join(lines) + "\n"


def run() -> None:
    """Console entry point (``agent-wallet``): launch the API with uvicorn.

    Reads the bind host/port from settings (``API_HOST`` / ``API_PORT``).
    For production deployments, run uvicorn/gunicorn directly so you can
    tune workers, timeouts, and TLS termination.
    """
    import uvicorn

    from app.core.config import settings

    uvicorn.run("app.main:app", host=settings.api_host, port=settings.api_port, reload=False)
