# SPDX-License-Identifier: MIT
"""items 14, 34 — startup gates.

Item 34 (onion-only egress): refuse to start with any non-onion
external endpoint when the defaults ``anonymize_require_tor=true`` +
``anonymize_enforce_onion_only_egress=true`` are in effect.

Item 14 (Tor isolation, partial): when LND's Tor SOCKS port matches
any anonymize listener port, the predicate returns False so the
health card renders the warning.
"""

from __future__ import annotations

import pytest

from app.core.config import settings
from app.services.anonymize.startup import (
    AnonymizeStartupError,
    assert_anonymize_tor_distinct_from_lnd,
    assert_onion_only_egress,
    assert_quote_cache_signing_key_loadable,
    collect_anonymize_egress_endpoints,
    run_anonymize_startup_gates,
)


def test_quote_cache_signing_key_gate_refuses_when_missing(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_quote_cache_signing_key_fernet", "")
    with pytest.raises(AnonymizeStartupError) as exc:
        assert_quote_cache_signing_key_loadable()
    assert "QUOTE_CACHE_SIGNING_KEY" in str(exc.value)


def test_quote_cache_signing_key_gate_refuses_short_key(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_quote_cache_signing_key_fernet", "tooshort")
    with pytest.raises(AnonymizeStartupError):
        assert_quote_cache_signing_key_loadable()


def test_quote_cache_signing_key_gate_accepts_configured_key(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_quote_cache_signing_key_fernet", "a" * 44)
    assert_quote_cache_signing_key_loadable()  # must not raise

_ONION_OPERATOR_A = "http://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad.onion/api/v2"
_ONION_OPERATOR_B = "http://bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbad.onion/api/v2"
_ONION_DOH = "https://ccccccccccccccccccccccccccccccccccccccccccccccccccccccad.onion/dns-query"
_ONION_ELECTRUM = "tcp://ddddddddddddddddddddddddddddddddddddddddddddddddddddddad.onion:50001"


def test_collect_egress_endpoints_uses_onion_urls(monkeypatch) -> None:
    """The gate checks the URL the production dispatcher
    actually uses (onion-preferring via ``resolve_*_leg_url``), not
    the legacy clearnet ``*_API_URL`` fallbacks. A regression that
    reverted to reading clearnet settings would falsely refuse to
    start an onion-only deployment."""
    monkeypatch.setattr(settings, "boltz_submarine_onion_url", _ONION_OPERATOR_A)
    monkeypatch.setattr(settings, "boltz_reverse_onion_url", _ONION_OPERATOR_B)
    monkeypatch.setattr(settings, "boltz_onion_url", _ONION_OPERATOR_B)
    monkeypatch.setattr(settings, "lnd_electrum_url", _ONION_ELECTRUM)
    monkeypatch.setattr(settings, "lnd_mempool_url", "")
    out = dict(collect_anonymize_egress_endpoints())
    assert out["BOLTZ_SUBMARINE_ONION_URL"] == _ONION_OPERATOR_A
    assert out["BOLTZ_REVERSE_ONION_URL"] == _ONION_OPERATOR_B
    assert out["LND_ELECTRUM_URL"] == _ONION_ELECTRUM
    # BIP-353 DoH is Tor-routed via the dedicated
    # ``bip353_dns`` SOCKS listener regardless of URL scheme, so it
    # is intentionally exempt from the onion-only egress gate.
    # Operators who *want* an onion DoH can still configure one but
    # the gate doesn't require it.
    assert "ANONYMIZE_BIP353_DOH_ENDPOINT" not in out


def test_collect_egress_endpoints_falls_back_to_shared_onion(monkeypatch) -> None:
    """When the leg-specific onions are unset, the resolver falls
    back to the shared ``BOLTZ_ONION_URL`` — the gate should see
    that single URL (no spurious duplicate entry)."""
    monkeypatch.setattr(settings, "boltz_submarine_onion_url", "")
    monkeypatch.setattr(settings, "boltz_reverse_onion_url", "")
    monkeypatch.setattr(settings, "boltz_onion_url", _ONION_OPERATOR_B)
    monkeypatch.setattr(settings, "lnd_electrum_url", "")
    monkeypatch.setattr(settings, "lnd_mempool_url", "")
    out = dict(collect_anonymize_egress_endpoints())
    # Single-operator deployment — submarine + reverse resolve to the
    # same URL; the gate dedupes them so only one entry appears.
    assert out["BOLTZ_SUBMARINE_ONION_URL"] == _ONION_OPERATOR_B
    assert "BOLTZ_REVERSE_ONION_URL" not in out


def test_onion_only_egress_passes_with_all_onion_endpoints(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_require_tor", True)
    monkeypatch.setattr(settings, "anonymize_enforce_onion_only_egress", True)
    monkeypatch.setattr(settings, "boltz_submarine_api_url", _ONION_OPERATOR_A)
    monkeypatch.setattr(settings, "boltz_reverse_api_url", _ONION_OPERATOR_B)
    monkeypatch.setattr(settings, "boltz_api_url", _ONION_OPERATOR_B)
    monkeypatch.setattr(settings, "anonymize_bip353_doh_endpoint", _ONION_DOH)
    monkeypatch.setattr(settings, "lnd_electrum_url", _ONION_ELECTRUM)
    monkeypatch.setattr(settings, "lnd_mempool_url", "")
    # Should not raise.
    assert_onion_only_egress()


def test_onion_only_egress_rejects_clearnet_boltz(monkeypatch) -> None:
    """When the operator puts a clearnet URL in ``BOLTZ_ONION_URL``
    (a misconfiguration — the field is named ``onion`` for a
    reason), the gate MUST refuse to start. Same rejection applies
    to the leg-specific ``BOLTZ_REVERSE_ONION_URL`` when set."""
    monkeypatch.setattr(settings, "anonymize_require_tor", True)
    monkeypatch.setattr(settings, "anonymize_enforce_onion_only_egress", True)
    monkeypatch.setattr(settings, "boltz_submarine_onion_url", "")
    monkeypatch.setattr(settings, "boltz_reverse_onion_url", "")
    # Production dispatcher reads ``boltz_onion_url`` via the resolver.
    monkeypatch.setattr(settings, "boltz_onion_url", "https://api.boltz.exchange/v2")
    monkeypatch.setattr(settings, "lnd_electrum_url", "")
    monkeypatch.setattr(settings, "lnd_mempool_url", "")
    with pytest.raises(AnonymizeStartupError, match="non-onion egress"):
        assert_onion_only_egress()


def test_onion_only_egress_skipped_when_opted_out(monkeypatch) -> None:
    """Operator opt-out: gate does NOT raise; tier cap fires elsewhere."""
    monkeypatch.setattr(settings, "anonymize_require_tor", True)
    monkeypatch.setattr(settings, "anonymize_enforce_onion_only_egress", False)
    monkeypatch.setattr(settings, "boltz_api_url", "https://api.boltz.exchange/v2")
    monkeypatch.setattr(settings, "lnd_electrum_url", "")
    monkeypatch.setattr(settings, "lnd_mempool_url", "")
    assert_onion_only_egress()


def test_onion_only_egress_allows_clearnet_chain_backend_when_opted_in(monkeypatch) -> None:
    """Explicit opt-in for public chain backend; tier caps at weak."""
    monkeypatch.setattr(settings, "anonymize_require_tor", True)
    monkeypatch.setattr(settings, "anonymize_enforce_onion_only_egress", True)
    monkeypatch.setattr(settings, "anonymize_allow_public_chain_backend", True)
    monkeypatch.setattr(settings, "boltz_reverse_api_url", _ONION_OPERATOR_B)
    monkeypatch.setattr(settings, "boltz_api_url", _ONION_OPERATOR_B)
    monkeypatch.setattr(settings, "anonymize_bip353_doh_endpoint", _ONION_DOH)
    monkeypatch.setattr(settings, "lnd_electrum_url", "")
    monkeypatch.setattr(settings, "lnd_mempool_url", "https://mempool.space")
    assert_onion_only_egress()


def test_onion_only_egress_allows_trusted_local_chain_backend(monkeypatch) -> None:
    """A co-resident chain backend with the trusted-local opt-in is exempt from
    the gate (it boots) — without the public opt-in and without a tier cap."""
    monkeypatch.setattr(settings, "anonymize_require_tor", True)
    monkeypatch.setattr(settings, "anonymize_enforce_onion_only_egress", True)
    monkeypatch.setattr(settings, "anonymize_allow_public_chain_backend", False)
    monkeypatch.setattr(settings, "anonymize_trusted_local_chain_backend", True)
    monkeypatch.setattr(settings, "boltz_reverse_api_url", _ONION_OPERATOR_B)
    monkeypatch.setattr(settings, "boltz_api_url", _ONION_OPERATOR_B)
    monkeypatch.setattr(settings, "anonymize_bip353_doh_endpoint", _ONION_DOH)
    monkeypatch.setattr(settings, "lnd_electrum_url", "tcp://electrs.embassy:50001")
    monkeypatch.setattr(settings, "lnd_mempool_url", "http://mempool-rdts.embassy:8999")
    assert_onion_only_egress()


def test_onion_only_egress_trusted_local_inert_on_public_backend(monkeypatch) -> None:
    """The trusted-local opt-in must NOT relax a genuinely public backend: the
    gate still refuses to start (fail-closed)."""
    monkeypatch.setattr(settings, "anonymize_require_tor", True)
    monkeypatch.setattr(settings, "anonymize_enforce_onion_only_egress", True)
    monkeypatch.setattr(settings, "anonymize_allow_public_chain_backend", False)
    monkeypatch.setattr(settings, "anonymize_trusted_local_chain_backend", True)
    monkeypatch.setattr(settings, "boltz_reverse_api_url", _ONION_OPERATOR_B)
    monkeypatch.setattr(settings, "boltz_api_url", _ONION_OPERATOR_B)
    monkeypatch.setattr(settings, "anonymize_bip353_doh_endpoint", _ONION_DOH)
    monkeypatch.setattr(settings, "lnd_electrum_url", "")
    monkeypatch.setattr(settings, "lnd_mempool_url", "https://mempool.space")
    with pytest.raises(AnonymizeStartupError, match="non-onion egress"):
        assert_onion_only_egress()


def test_anonymize_tor_distinct_returns_true_when_no_lnd_proxy(monkeypatch) -> None:
    monkeypatch.setattr(settings, "lnd_tor_proxy", "")
    assert assert_anonymize_tor_distinct_from_lnd() is True


def test_anonymize_tor_distinct_returns_false_on_listener_collision(monkeypatch) -> None:
    """When LND_TOR_PROXY shares a port with an anonymize listener, the
    predicate returns False so the health card surfaces the warning."""
    # Default listener config includes 9050 (boltz_submarine).
    monkeypatch.setattr(settings, "lnd_tor_proxy", "socks5://127.0.0.1:9050")
    assert assert_anonymize_tor_distinct_from_lnd() is False


def test_run_anonymize_startup_gates_returns_status(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_require_tor", True)
    monkeypatch.setattr(settings, "anonymize_enforce_onion_only_egress", True)
    monkeypatch.setattr(settings, "boltz_submarine_api_url", "")
    monkeypatch.setattr(settings, "boltz_reverse_api_url", _ONION_OPERATOR_B)
    monkeypatch.setattr(settings, "boltz_api_url", _ONION_OPERATOR_B)
    monkeypatch.setattr(settings, "anonymize_bip353_doh_endpoint", _ONION_DOH)
    monkeypatch.setattr(settings, "lnd_electrum_url", "")
    monkeypatch.setattr(settings, "lnd_mempool_url", "")
    monkeypatch.setattr(settings, "lnd_tor_proxy", "")
    status = run_anonymize_startup_gates()
    assert status["egress_endpoints_onion_only"] is True
    assert status["anonymize_tor_distinct_from_lnd"] is True


# ── chain-composition env-var validation ────────────────


def _registry_loader(operator_ids: list[str]):
    """Return a stand-in for ``load_signed_operator_registry`` that
    yields a registry containing exactly ``operator_ids``."""
    from app.services.anonymize.operators import OperatorEntry

    def _load(*_args, **_kwargs):
        return [
            OperatorEntry(
                operator_id=op_id,
                onion=f"http://{op_id}.onion",
                public_key_hex="",
            )
            for op_id in operator_ids
        ]

    return _load


def test_chain_gate_accepts_blank_env_vars(monkeypatch) -> None:
    """default-rule path: blank operator-id env vars defer to
    the default-computation logic, which is always valid."""
    from app.services.anonymize import operators
    from app.services.anonymize.startup import (
        assert_operator_chain_env_resolves,
    )

    monkeypatch.setattr(
        operators,
        "load_signed_operator_registry",
        _registry_loader(["boltz-canonical", "middleway", "eldamar"]),
    )
    monkeypatch.setattr(settings, "anonymize_submarine_operator_primary", "")
    monkeypatch.setattr(settings, "anonymize_submarine_operator_secondary", "")
    monkeypatch.setattr(settings, "anonymize_reverse_operator", "")
    assert_operator_chain_env_resolves()  # must not raise.


def test_chain_gate_refuses_primary_id_not_in_registry(monkeypatch) -> None:
    from app.services.anonymize import operators
    from app.services.anonymize.startup import (
        AnonymizeStartupError,
        assert_operator_chain_env_resolves,
    )

    monkeypatch.setattr(
        operators,
        "load_signed_operator_registry",
        _registry_loader(["boltz-canonical", "middleway", "eldamar"]),
    )
    monkeypatch.setattr(settings, "anonymize_submarine_operator_primary", "no-such-op")
    with pytest.raises(AnonymizeStartupError, match="PRIMARY"):
        assert_operator_chain_env_resolves()


def test_chain_gate_refuses_secondary_id_not_in_registry(monkeypatch) -> None:
    from app.services.anonymize import operators
    from app.services.anonymize.startup import (
        AnonymizeStartupError,
        assert_operator_chain_env_resolves,
    )

    monkeypatch.setattr(
        operators,
        "load_signed_operator_registry",
        _registry_loader(["boltz-canonical", "middleway", "eldamar"]),
    )
    monkeypatch.setattr(
        settings,
        "anonymize_submarine_operator_secondary",
        "no-such-op",
    )
    with pytest.raises(AnonymizeStartupError, match="SECONDARY"):
        assert_operator_chain_env_resolves()


def test_chain_gate_refuses_reverse_id_not_in_registry(monkeypatch) -> None:
    from app.services.anonymize import operators
    from app.services.anonymize.startup import (
        AnonymizeStartupError,
        assert_operator_chain_env_resolves,
    )

    monkeypatch.setattr(
        operators,
        "load_signed_operator_registry",
        _registry_loader(["boltz-canonical", "middleway", "eldamar"]),
    )
    monkeypatch.setattr(settings, "anonymize_reverse_operator", "no-such-op")
    with pytest.raises(AnonymizeStartupError, match="REVERSE_OPERATOR"):
        assert_operator_chain_env_resolves()


def test_chain_gate_refuses_primary_equals_reverse(monkeypatch) -> None:
    from app.services.anonymize import operators
    from app.services.anonymize.startup import (
        AnonymizeStartupError,
        assert_operator_chain_env_resolves,
    )

    monkeypatch.setattr(
        operators,
        "load_signed_operator_registry",
        _registry_loader(["boltz-canonical", "middleway", "eldamar"]),
    )
    monkeypatch.setattr(settings, "anonymize_submarine_operator_primary", "middleway")
    monkeypatch.setattr(settings, "anonymize_reverse_operator", "middleway")
    with pytest.raises(AnonymizeStartupError, match="same operator"):
        assert_operator_chain_env_resolves()


def test_chain_gate_refuses_primary_equals_secondary(monkeypatch) -> None:
    from app.services.anonymize import operators
    from app.services.anonymize.startup import (
        AnonymizeStartupError,
        assert_operator_chain_env_resolves,
    )

    monkeypatch.setattr(
        operators,
        "load_signed_operator_registry",
        _registry_loader(["boltz-canonical", "middleway", "eldamar"]),
    )
    monkeypatch.setattr(settings, "anonymize_submarine_operator_primary", "middleway")
    monkeypatch.setattr(
        settings,
        "anonymize_submarine_operator_secondary",
        "middleway",
    )
    with pytest.raises(AnonymizeStartupError, match="defeats the fallback"):
        assert_operator_chain_env_resolves()


def test_chain_gate_refuses_reverse_equals_secondary(monkeypatch) -> None:
    from app.services.anonymize import operators
    from app.services.anonymize.startup import (
        AnonymizeStartupError,
        assert_operator_chain_env_resolves,
    )

    monkeypatch.setattr(
        operators,
        "load_signed_operator_registry",
        _registry_loader(["boltz-canonical", "middleway", "eldamar"]),
    )
    monkeypatch.setattr(settings, "anonymize_reverse_operator", "middleway")
    monkeypatch.setattr(
        settings,
        "anonymize_submarine_operator_secondary",
        "middleway",
    )
    with pytest.raises(AnonymizeStartupError, match="collapse"):
        assert_operator_chain_env_resolves()


def test_chain_gate_accepts_blank_env_vars_with_single_operator_registry(
    monkeypatch,
) -> None:
    """Blank env vars + single-operator registry → the gate
    accepts. The default-rule path handles the degenerate registry by
    leaving primary/secondary unset and reverse on the only entry
    (effectively reverting to single-operator-deployment behavior)."""
    from app.services.anonymize import operators
    from app.services.anonymize.startup import (
        assert_operator_chain_env_resolves,
    )

    monkeypatch.setattr(
        operators,
        "load_signed_operator_registry",
        _registry_loader(["boltz-canonical"]),
    )
    monkeypatch.setattr(settings, "anonymize_submarine_operator_primary", "")
    monkeypatch.setattr(settings, "anonymize_submarine_operator_secondary", "")
    monkeypatch.setattr(settings, "anonymize_reverse_operator", "")
    assert_operator_chain_env_resolves()  # must not raise.


# ── Quantize-keys allow-list superset ───────────────────────────


@pytest.mark.asyncio
async def test_quantize_allowlist_passes_when_table_absent(db_session) -> None:
    """Without migration 017, the assertion is a no-op."""
    from app.services.anonymize.startup import (
        assert_settings_quantize_allowlist_superset,
    )

    await assert_settings_quantize_allowlist_superset(db_session)


@pytest.mark.asyncio
async def test_quantize_allowlist_passes_when_db_subset_of_registry(db_session) -> None:
    """When the DB allow-list is a subset of the in-code registry, pass."""
    from sqlalchemy import text

    from app.services.anonymize.startup import (
        assert_settings_quantize_allowlist_superset,
    )

    # Create the lightweight allow-list table.
    await db_session.execute(text("CREATE TABLE anonymize_settings_quantize_allowlist (key TEXT PRIMARY KEY)"))
    await db_session.execute(
        text("INSERT INTO anonymize_settings_quantize_allowlist (key) VALUES ('feature_enabled_at_day')")
    )
    await db_session.commit()
    # No raise.
    await assert_settings_quantize_allowlist_superset(db_session)


@pytest.mark.asyncio
async def test_quantize_allowlist_raises_when_db_carries_unknown_key(
    db_session,
) -> None:
    """A DB-side key not in the code registry refuses startup."""
    from sqlalchemy import text

    from app.services.anonymize.startup import (
        AnonymizeStartupError,
        assert_settings_quantize_allowlist_superset,
    )

    await db_session.execute(text("CREATE TABLE anonymize_settings_quantize_allowlist (key TEXT PRIMARY KEY)"))
    await db_session.execute(
        text("INSERT INTO anonymize_settings_quantize_allowlist (key) VALUES ('rogue_key_NOT_in_registry')")
    )
    await db_session.commit()
    with pytest.raises(AnonymizeStartupError, match="rogue_key_NOT_in_registry"):
        await assert_settings_quantize_allowlist_superset(db_session)
