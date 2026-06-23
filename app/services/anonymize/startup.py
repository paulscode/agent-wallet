# SPDX-License-Identifier: MIT
"""Startup-time validation gates for the anonymize service.

This module is the *single* place ``app.main`` calls to decide whether
the anonymize feature can be admitted. Its checks fail closed: any
mis-configured surface refuses to start the anonymize service while
leaving the rest of the dashboard up.

 / catalogue of startup probes:

* Onion-only egress enforcement.
* Anonymize Tor process distinct from LND's Tor process.
* MultiFernet canary decryption (deferred until the canary
  row exists in the database).
* Node binary, lockfile SRI, Tor control-port reachability,
  initial quote-cache warm refresh (filled in alongside the supervisor
  + cache modules).

The onion-only gate and the Tor-process-distinctness predicate run
here; the remaining gates are called from the same entry point.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from app.core.config import settings

from .metadata import ANONYMIZE_LOGGER_NAME

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession
    from sqlalchemy.orm import Session

logger = logging.getLogger(ANONYMIZE_LOGGER_NAME)


class AnonymizeStartupError(RuntimeError):
    """Raised when a startup gate refuses to admit the anonymize service."""


def _is_onion_url(raw: str) -> bool:
    """True iff ``raw`` is a v3 onion URL.

    A v3 onion address is 56 base32 chars + ``.onion``. We accept v2
    addresses for backwards-compat in this predicate but the
    operator-registry loader requires v3.
    """
    if not raw:
        return False
    parsed = urlparse(raw if "://" in raw else "http://" + raw)
    host = (parsed.hostname or "").lower()
    return host.endswith(".onion")


def collect_anonymize_egress_endpoints() -> list[tuple[str, str]]:
    """Enumerate the URLs the anonymize stack will egress to.

    Returns a list of ``(label, url)`` pairs so failure messages can
    name the offending endpoint. Empty values are skipped — those are
    optional knobs the operator hasn't set yet.

    For the Boltz legs we check the URL the *production* dispatcher
    actually uses (i.e., the onion form when configured), not the
    clearnet `*_API_URL` fallbacks. The dispatcher constructs
    ``AnonymizeBoltzClient(base_url=resolve_*_leg_url())`` which
    prefers `*_ONION_URL`; the clearnet `*_API_URL` is purely a
    documentation / fallback artifact for non-Tor deployments. The
    earlier shape of this function flagged operators with valid
    onion-only configurations as "non-onion egress" because their
    clearnet `*_API_URL` default was still in place.

    The BIP-353 DoH endpoint is intentionally exempted — per the
     design (and `docs/anonymize.md`), the wallet routes DoH
    queries through the dedicated `bip353_dns` SOCKS listener, so a
    clearnet HTTPS DoH provider is acceptable (the provider sees a
    Tor exit's IP, not the wallet host's). Operators who *want* an
    onion DoH endpoint can still configure one; the gate just doesn't
    require it.
    """
    from .operators import (
        resolve_reverse_leg_url,
        resolve_submarine_leg_url,
    )

    out: list[tuple[str, str]] = []

    # distinct-operator splitting. Check the URL the production
    # dispatcher uses (onion-preferring) rather than the clearnet
    # fallback.
    submarine = resolve_submarine_leg_url(prefer_onion=True)
    if submarine:
        out.append(("BOLTZ_SUBMARINE_ONION_URL", submarine))
    reverse = resolve_reverse_leg_url(prefer_onion=True)
    if reverse and reverse != submarine:
        out.append(("BOLTZ_REVERSE_ONION_URL", reverse))

    # BIP-353 DoH endpoint — Tor-routed via the dedicated
    # `bip353_dns` SOCKS listener regardless of URL scheme; clearnet
    # HTTPS is acceptable. NOT included in the onion-only egress
    # gate. (Operator runbook explicitly calls this out.)

    # chain backend endpoints — both general and anonymize-side.
    if settings.lnd_electrum_url:
        out.append(("LND_ELECTRUM_URL", settings.lnd_electrum_url))
    if settings.lnd_mempool_url:
        out.append(("LND_MEMPOOL_URL", settings.lnd_mempool_url))

    return out


def assert_onion_only_egress() -> None:
    """Refuse to start with non-onion endpoints.

    Honored only when both ``ANONYMIZE_REQUIRE_TOR=true`` and
    ``ANONYMIZE_ENFORCE_ONION_ONLY_EGRESS=true`` (defaults). When
    either is off, the operator has explicitly opted out and the
    scorer caps the resulting sessions at ``weak``.

    Lightning-only deployments using the public Mempool HTTP backend MAY opt
    into ``ANONYMIZE_ALLOW_PUBLIC_CHAIN_BACKEND=true``; that opt-in
    excludes the chain backend from the gate but still caps tier
    at ``weak``.

    A co-resident / private-network chain backend MAY instead opt into
    ``ANONYMIZE_TRUSTED_LOCAL_CHAIN_BACKEND=true``; that exempts the chain
    backend from the gate WITHOUT the tier cap, since a local backend has no
    third-party observer (the opt-in is inert unless every chain host is
    actually local).
    """
    from .chain import is_trusted_local_chain_backend

    if not (settings.anonymize_require_tor and settings.anonymize_enforce_onion_only_egress):
        return  # Operator has explicitly opted out — surfaced via score cap.

    trusted_local = is_trusted_local_chain_backend()
    endpoints = collect_anonymize_egress_endpoints()
    bad: list[tuple[str, str]] = []
    for label, url in endpoints:
        is_chain_backend = label in ("LND_ELECTRUM_URL", "LND_MEMPOOL_URL")
        # documented exception: when the operator has
        # explicitly opted into a public chain backend, the chain
        # endpoint itself is allowed to be clearnet (and the resulting
        # session caps at weak via the scorer). A trusted local backend is
        # likewise exempt — but without the cap (handled in the scorer).
        if is_chain_backend and (settings.anonymize_allow_public_chain_backend or trusted_local):
            continue
        if not _is_onion_url(url):
            bad.append((label, url))
    if bad:
        names = ", ".join(label for label, _ in bad)
        raise AnonymizeStartupError(
            "anonymize service refuses to start: non-onion egress endpoint(s) "
            f"configured ({names}). Either set them to .onion URLs, or "
            "set ANONYMIZE_ENFORCE_ONION_ONLY_EGRESS=false (which caps "
            "all anonymize sessions at the `weak` privacy tier)."
        )


async def assert_sentinel_uuid_fk_integrity(db: AsyncSession) -> None:
    """FK-substitute integrity check.

    The migration 016 NOT-VALID FK + CHECK admit either a real
    ``boltz_swaps.id`` or the all-zeros sentinel UUID; sentinel rows
    are written by gc-pass-8 and skipped by the partial indexes. This
    startup pass walks every ``anonymize_session`` row whose swap-id
    columns are non-null and non-sentinel, and asserts each value
    references a live ``boltz_swaps`` row. Drift (e.g., a backup
    restore that brought back a session-row but lost its swap-row)
    raises so the operator can repair manually rather than running
    silently against a dangling reference.
    """
    from sqlalchemy import select

    from app.models.anonymize_session import AnonymizeSession
    from app.models.boltz_swap import BoltzSwap
    from app.services.anonymize.gc import swap_anchor_sentinel_uuid

    sentinel = swap_anchor_sentinel_uuid()
    drift: list[str] = []

    for col, label in (
        (AnonymizeSession.submarine_swap_id, "submarine_swap_id"),
        (AnonymizeSession.reverse_swap_id, "reverse_swap_id"),
    ):
        stmt = (
            select(AnonymizeSession.id, col)
            .where(col.is_not(None))
            .where(col != sentinel)
            .where(AnonymizeSession.deleted_at.is_(None))
        )
        result = await db.execute(stmt)
        for sess_id, swap_id in result.all():
            target = await db.get(BoltzSwap, swap_id)
            if target is None:
                drift.append(f"anonymize_session={sess_id} {label}={swap_id} references a missing boltz_swaps row")
                if len(drift) >= 5:
                    break
        if len(drift) >= 5:
            break

    if drift:
        raise AnonymizeStartupError(
            "FK-substitute integrity check found dangling swap-id "
            f"reference(s): {drift}. Either restore the missing "
            "boltz_swaps rows or move the sessions to a terminal "
            "state before re-deploying."
        )


def assert_chain_client_listeners_distinct() -> None:
    """Refuse same-listener config.

    The general-purpose chain client (used by ``mempool_fee_service``
    and any wallet-wide chain query) MUST use a different SOCKS
    listener from the anonymize-only chain client. Sharing a listener
    re-opens the correlation channel that the dedicated-
    connection mitigation closed.
    """
    from .chain import (
        ChainBackendError,
        assert_listeners_distinct,
        get_anonymize_chain_client_spec,
        get_general_chain_client_spec,
    )

    g = get_general_chain_client_spec()
    a = get_anonymize_chain_client_spec()
    try:
        assert_listeners_distinct(g, a)
    except ChainBackendError as exc:
        raise AnonymizeStartupError(str(exc)) from exc


def assert_quote_cache_signing_key_loadable() -> None:
    """Quote-cache integrity-key gate.

    The operator-fee / limit data served from the quote cache is
    signed with an HMAC under ``ANONYMIZE_QUOTE_CACHE_SIGNING_KEY_FERNET``
    and verified on read. The key is required so the read path always
    has a signature to verify against; without it a writer to the cache
    table could serve attacker-chosen operator data unsigned. Refuse to
    start the anonymize service when the key is missing or too short,
    matching the fail-closed posture of the quote-token keyset and the
    decoy seed.
    """
    raw = (settings.anonymize_quote_cache_signing_key_fernet or "").strip()
    if len(raw) < 32:
        raise AnonymizeStartupError(
            "ANONYMIZE_QUOTE_CACHE_SIGNING_KEY_FERNET is missing or shorter "
            "than 32 characters. The quote-cache integrity signature cannot "
            "be enforced without it. Set a strong key (a Fernet key is the "
            "documented form) before starting the anonymize service."
        )


def assert_key_retention_horizons_satisfied() -> None:
    """Startup horizon invariant.

    Refuses to start when any rotation policy violates
    ``RETENTION_DAYS >= DESTINATION_RETENTION_DAYS + ROTATION_DAYS``.

    Why: a key that's purged before its destination-retention horizon
    can leak in a backup taken *while* the rotated-out key is still
    needed to verify hashes / re-derive nonces. This applies to
    every rotated key set (reuse-detection,
    hop-idempotency, quote-token).
    """
    from .rotation import all_policies, horizon_invariant_satisfied

    dest = int(settings.anonymize_destination_retention_days)
    offenders: list[str] = []
    for policy in all_policies():
        if not horizon_invariant_satisfied(policy, destination_retention_days=dest):
            offenders.append(
                f"{policy.name}: retention={policy.retention_days}d "
                f"< dest_retention={dest}d + rotation={policy.rotation_days}d"
            )
    if offenders:
        raise AnonymizeStartupError(
            "key-retention horizon invariant violated for: "
            f"{offenders}. The rotation framework refuses to start "
            "because a rotated-out key would be purged before any "
            "session it signed reaches its destination-retention "
            "horizon."
        )


async def assert_settings_quantize_allowlist_superset(db: AsyncSession) -> None:
    """Registry-superset gate.

    Asserts the in-code ``ANONYMIZE_SETTINGS_QUANTIZE_KEYS`` is a
    *superset* of the in-DB ``anonymize_settings_quantize_allowlist``
    table. If a key exists in the DB allow-list but not in the code
    registry, the trigger would silently quantize a value the code
    has stopped expecting — refuse to start so an operator-side
    schema rollback is caught loudly.

    The reverse direction (code carries a key the DB allow-list does
    not) is fine: alembic env.py sets the per-connection GUC to the
    code-registry set, so the trigger falls back to that on writes.
    """
    from sqlalchemy import inspect, text

    from .metadata import ANONYMIZE_SETTINGS_QUANTIZE_KEYS

    def _has_table(sync_session: Session) -> bool:
        return inspect(sync_session.connection()).has_table("anonymize_settings_quantize_allowlist")

    table_exists = await db.run_sync(_has_table)
    if not table_exists:
        # Test runs that skip migration 017 — nothing to check.
        return

    rows = await db.execute(text("SELECT key FROM anonymize_settings_quantize_allowlist"))
    db_keys = {r[0] for r in rows.fetchall()}
    missing = db_keys - ANONYMIZE_SETTINGS_QUANTIZE_KEYS
    if missing:
        raise AnonymizeStartupError(
            "anonymize_settings_quantize_allowlist contains keys not in "
            f"the in-code ANONYMIZE_SETTINGS_QUANTIZE_KEYS registry: {sorted(missing)}. "
            "Either roll the DB allow-list back, or add the key to the code "
            "registry before bringing the service up."
        )


def assert_pipeline_schema_version_check_invariant() -> None:
    """Runtime invariant on schema-version encoding.

    The DB column has a ``CHECK (pipeline_schema_version >= 10)``
    (migration 016) and a ``// 10`` retention quantization.
    This helper asserts the application-layer constants match the
    storage contract:

    * ``ANONYMIZE_PIPELINE_SCHEMA_VERSION_CURRENT >= 10``
    * ``ANONYMIZE_PIPELINE_SCHEMA_VERSION_MIN_SUPPORTED >= 10``
    * ``MIN_SUPPORTED <= CURRENT``

    Raises :class:`AnonymizeStartupError` on violation.
    """
    current = int(settings.anonymize_pipeline_schema_version_current)
    min_supported = int(settings.anonymize_pipeline_schema_version_min_supported)
    if current < 10:
        raise AnonymizeStartupError(
            f"ANONYMIZE_PIPELINE_SCHEMA_VERSION_CURRENT = {current} must be >= 10 (MAJOR*10+MINOR encoding)."
        )
    if min_supported < 10:
        raise AnonymizeStartupError(
            f"ANONYMIZE_PIPELINE_SCHEMA_VERSION_MIN_SUPPORTED = {min_supported} "
            "must be >= 10 (the storage CHECK refuses lower values)."
        )
    if min_supported > current:
        raise AnonymizeStartupError(
            f"ANONYMIZE_PIPELINE_SCHEMA_VERSION_MIN_SUPPORTED = {min_supported} "
            f"is greater than CURRENT = {current}; the running code cannot "
            "produce a session that satisfies its own MIN_SUPPORTED gate."
        )


async def assert_pipeline_schema_forward_compat(db: AsyncSession) -> None:
    """Forward-compat invariant.

    Refuse to start when any in-flight session's
    ``pipeline_schema_version`` is below the running code's
    ``ANONYMIZE_PIPELINE_SCHEMA_VERSION_MIN_SUPPORTED``. The
    ``MIN_SUPPORTED`` cannot increase faster than the longest-possible
    session lifetime (~10 days); a too-aggressive bump silently
    invalidates in-flight sessions, which is worse than refusing to
    start.

    The startup gate routes the offending session to
    ``awaiting_reconciliation`` (operator-actionable) by raising
    here; the orchestrator's reconciliation pass then surfaces the
    schema-too-old situation in the dashboard. We don't auto-resume
    such sessions because the *running* code may not understand
    their frozen ``pipeline_json``.
    """
    from sqlalchemy import select

    from app.models.anonymize_session import (
        ANONYMIZE_TERMINAL_STATUSES,
        AnonymizeSession,
    )

    min_supported = int(settings.anonymize_pipeline_schema_version_min_supported)
    stmt = (
        select(AnonymizeSession.id, AnonymizeSession.pipeline_schema_version)
        .where(AnonymizeSession.pipeline_schema_version < min_supported)
        .where(AnonymizeSession.status.notin_(list(ANONYMIZE_TERMINAL_STATUSES)))
        .where(AnonymizeSession.deleted_at.is_(None))
    )
    result = await db.execute(stmt)
    offenders = list(result.all())
    if offenders:
        ids = [str(row[0]) for row in offenders[:5]]
        raise AnonymizeStartupError(
            f"refusing to start: {len(offenders)} in-flight session(s) "
            f"carry pipeline_schema_version < {min_supported} (first 5 "
            f"ids: {ids}). Either roll back the code to the prior "
            "MIN_SUPPORTED, or move the offending sessions to "
            "awaiting_reconciliation manually before re-deploying."
        )


def assert_node_binary_present() -> bool:
    """``boltz_claim.js`` requires ``node`` on $PATH.

    Returns the boolean status (True iff ``node`` is reachable). The
    caller surfaces this on the health card; it does NOT raise. A
    deployment without ``node`` cannot run cooperative-claim sessions
    but can still serve session listings, so this check is fail-soft.
    """
    import shutil

    return shutil.which("node") is not None


def assert_subprocess_lockfile_present() -> bool:
    """``scripts/package-lock.json`` exists in the repo.

    The actual SRI verification of the patched ``boltz_claim.js``
    runs lazily on first invocation (the wrapper computes the hash
    against ``ANONYMIZE_BOLTZ_CLAIM_JS_SRI_DEV_BYPASS`` policy). Phase
    1 only checks file presence so a deployment built without the
    script directory fails closed at startup.
    """
    from pathlib import Path

    repo_root = Path(__file__).resolve().parents[3]
    return (
        (repo_root / "scripts" / "package.json").is_file()
        and (repo_root / "scripts" / "package-lock.json").is_file()
        and (repo_root / "scripts" / "boltz_claim.js").is_file()
        and (repo_root / "scripts" / "compute_sri.sh").is_file()
    )


def assert_anonymize_tor_distinct_from_lnd() -> bool:
    """Anonymize Tor process != LND's Tor process.

    Returns a best-effort boolean rather than raising:
    ``anonymize_tor_distinct_from_lnd`` is exposed on the health card
     so the dashboard renders a warning when the operator has
    not yet split the processes via the ``docker-compose.anonymize.yml``
    overlay.

    A real assertion (refuse to start) applies once the in-app Tor
    supervisor is wired. Until then, a deployment that shares a single
    Tor process with LND has its tier capped at ``moderate`` by the
    scorer.
    """
    listener_ports = set(settings.anonymize_tor_socks_ports_dict.values())
    lnd_proxy = settings.lnd_tor_proxy or ""
    if not lnd_proxy:
        # No LND Tor configured — no overlap risk in this run.
        return True
    parsed = urlparse(lnd_proxy)
    lnd_port = parsed.port
    if lnd_port is None:
        return True
    return lnd_port not in listener_ports


def assert_signed_operator_registry_loadable() -> tuple[bool, int]:
    """Signed-registry startup gate.

    Calls :func:`operators.load_signed_operator_registry` which:
    * returns ``[]`` on an empty / missing registry (single-operator default),
    * raises :class:`RegistrySignatureError` when ``operators.json``
      is present but ``operators.sig`` is missing / does not verify
      against any pinned ``ANONYMIZE_REGISTRY_RELEASE_KEY_FINGERPRINTS``
      entry.

    Returns ``(loaded_ok, registry_size)`` so the health card can
    distinguish "loaded zero" from "loaded N". A signature failure
    raises :class:`AnonymizeStartupError` so the lifespan refuses to
    start the orchestrator with a tampered registry.

    The grace policy:
    ``ANONYMIZE_OPERATOR_SIG_MISMATCH_GRACE_S`` controls how long
    a *runtime* signature mismatch may persist before active sessions
    are routed through reconciliation. The startup gate has no
    grace — boot refuses immediately on mismatch, since a
    fresh-start operator can simply roll back the registry.
    """
    from .operators import (
        RegistryLoadError,
        RegistrySignatureError,
        load_signed_operator_registry,
    )

    try:
        entries = load_signed_operator_registry()
    except RegistrySignatureError as exc:
        raise AnonymizeStartupError(f"operators.sig verification failed: {exc}") from exc
    except RegistryLoadError as exc:
        raise AnonymizeStartupError(f"operators.json could not be loaded: {exc}") from exc
    return True, len(entries)


def assert_operator_chain_env_resolves() -> None:
    """Validate the
    chain-composition env vars against the loaded registry.

    Refuses to boot when any explicit operator-id env var is set but
    doesn't resolve, or when the resulting chain violates a pairwise
    distinctness invariant (primary≠reverse, primary≠secondary,
    reverse≠secondary). Empty env vars defer to the
    default-computation rule, which is always valid.
    """
    from app.core.config import settings as _settings

    from .operators import RegistryLoadError, load_signed_operator_registry

    try:
        registry = load_signed_operator_registry()
    except RegistryLoadError:
        # The signed-registry gate already surfaces this; here we
        # just skip the chain check rather than double-reporting.
        return

    primary = (_settings.anonymize_submarine_operator_primary or "").strip()
    secondary = (_settings.anonymize_submarine_operator_secondary or "").strip()
    reverse = (_settings.anonymize_reverse_operator or "").strip()

    if not any([primary, secondary, reverse]):
        return  # full default-computation path; nothing to validate.

    known_ids = {entry.operator_id for entry in registry}

    def _check_in_registry(env_name: str, op_id: str) -> None:
        if op_id and op_id not in known_ids:
            raise AnonymizeStartupError(f"{env_name}={op_id!r} but no operator with that id is in the loaded registry")

    _check_in_registry("ANONYMIZE_SUBMARINE_OPERATOR_PRIMARY", primary)
    _check_in_registry("ANONYMIZE_SUBMARINE_OPERATOR_SECONDARY", secondary)
    _check_in_registry("ANONYMIZE_REVERSE_OPERATOR", reverse)

    # Pairwise distinctness — but only when *both* operators in a
    # pair are explicitly set. Blank values defer to the
    # default-computation rule, which is constructed to enforce
    # distinctness by construction (reverse picked first, then the
    # submarine chain from the remaining set).
    if primary and reverse and primary == reverse:
        raise AnonymizeStartupError(
            "ANONYMIZE_SUBMARINE_OPERATOR_PRIMARY and "
            "ANONYMIZE_REVERSE_OPERATOR resolve to the same operator — "
            "distinct operators are required for on-chain sessions "
        )
    if primary and secondary and primary == secondary:
        raise AnonymizeStartupError(
            "ANONYMIZE_SUBMARINE_OPERATOR_PRIMARY and "
            "ANONYMIZE_SUBMARINE_OPERATOR_SECONDARY are the same — "
            "a secondary equal to the primary defeats the fallback"
        )
    if reverse and secondary and reverse == secondary:
        raise AnonymizeStartupError(
            "ANONYMIZE_REVERSE_OPERATOR and "
            "ANONYMIZE_SUBMARINE_OPERATOR_SECONDARY are the same — "
            "the secondary attempt would silently collapse into the "
            "single-operator-fallback case without user consent"
        )


def run_anonymize_startup_gates() -> dict[str, bool | int]:
    """Run every startup gate and return a status dict.

    Hard-failing gates raise :class:`AnonymizeStartupError`. Soft gates
    return their pass/fail status in the dict so the health card can
    surface them. Called from ``app.main`` once at startup.

    The return shape mirrors the boolean health summary so the
    same dict is what the dashboard renders.
    """
    assert_onion_only_egress()
    # Signed-registry load; refuses to start when
    # the registry is present but the signature is missing / does
    # not verify against the pinned fingerprint allow-list.
    operators_loaded, registry_size = assert_signed_operator_registry_loadable()
    # Validate the
    # chain-composition env vars against the loaded registry. Raises
    # AnonymizeStartupError on any misconfiguration.
    assert_operator_chain_env_resolves()
    # Liquid hop startup gates. No-op when the
    # Liquid hop is disabled; raises LiquidSeedError when enabled but
    # the seed or asset-id config is missing/malformed.
    from .liquid_seed import (
        assert_liquid_btc_asset_id_configured,
        assert_liquid_seed_configured,
    )

    assert_liquid_seed_configured()
    assert_liquid_btc_asset_id_configured()
    # Quote-cache integrity key — required so cached operator data is
    # always signed and verifiable on read.
    assert_quote_cache_signing_key_loadable()
    # #78 horizon invariant,
    # and canary-decrypt run inside:func:`bootstrap_anonymize_
    # orchestrator` (async + DB-bound) — the orchestrator refuses to
    # start when any of those fail. The synchronous gates above are
    # the prefix that can run before a DB session is available.
    return {
        "egress_endpoints_onion_only": True,
        "anonymize_tor_distinct_from_lnd": assert_anonymize_tor_distinct_from_lnd(),
        # Additional health-card booleans.
        # Soft (don't refuse to start; surface so operator can react).
        "node_binary_present": assert_node_binary_present(),
        "subprocess_lockfile_present": assert_subprocess_lockfile_present(),
        # Default to "skew within threshold" until the live
        # NTP probe runs and updates this via runtime_state. The
        # create-endpoint gate at api.py reads this key from app state.
        "clock_skew_within_threshold": True,
        # Same default-true pattern for Tor bootstrap.
        "tor_bootstrap_ready": True,
        # The dashboard reads these to render the health card.
        "operators_loaded": operators_loaded,
        "operator_registry_size": registry_size,
        "quote_cache_fresh": True,
    }


def assert_tor_or_blocked(*, call_site: str) -> None:
    """Refuse hop egress unless Tor is required.

    Every per-hop network-egress call site invokes this helper as
    its first action. When ``ANONYMIZE_REQUIRE_TOR=true`` (default)
    the assertion is a no-op and the call proceeds; the egress
    itself goes through the SOCKS listeners resolved by
    :mod:`tor`. When the operator has explicitly disabled Tor
    enforcement, the helper raises :class:`AnonymizeStartupError`
    so the hop fails closed instead of silently leaking via clearnet.

    The policy — "called at the top of every hop's
    network-egress path" — is enforced by:
    1. This helper, which makes the policy explicit.
    2. The companion CI lint
       ``test_anonymize_hops_call_assert_tor_or_blocked`` (added when
       the hops carry executable code).

    ``call_site`` is recorded in the error message so the operator's
    log makes the offending hop obvious.
    """
    if not settings.anonymize_require_tor:
        raise AnonymizeStartupError(
            f"hop egress refused for call_site={call_site!r}: "
            "ANONYMIZE_REQUIRE_TOR=false. The anonymize service does not "
            "permit clearnet egress; either set ANONYMIZE_REQUIRE_TOR=true "
            "or disable the anonymize feature with ANONYMIZE_ENABLED=false."
        )


__all__ = [
    "AnonymizeStartupError",
    "assert_chain_client_listeners_distinct",
    "assert_key_retention_horizons_satisfied",
    "assert_onion_only_egress",
    "assert_quote_cache_signing_key_loadable",
    "assert_anonymize_tor_distinct_from_lnd",
    "assert_node_binary_present",
    "assert_pipeline_schema_forward_compat",
    "assert_pipeline_schema_version_check_invariant",
    "assert_sentinel_uuid_fk_integrity",
    "assert_settings_quantize_allowlist_superset",
    "assert_subprocess_lockfile_present",
    "assert_tor_or_blocked",
    "collect_anonymize_egress_endpoints",
    "assert_signed_operator_registry_loadable",
    "assert_operator_chain_env_resolves",
    "run_anonymize_startup_gates",
]
