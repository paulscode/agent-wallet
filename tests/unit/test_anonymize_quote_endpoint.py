# SPDX-License-Identifier: MIT
"""POST /anonymize/quote endpoint."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock

import pytest
from cryptography.fernet import Fernet

from app.core.config import settings
from app.dashboard.api import dash_anonymize_quote

_REGTEST_P2TR = "bcrt1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqc8gma6"


@pytest.fixture
def _quote_keyset(monkeypatch):
    monkeypatch.setattr(
        settings,
        "anonymize_quote_token_hmac_key_fernet",
        Fernet.generate_key().decode("ascii"),
    )


def _mock_request(*, body: dict | None, cookie: str | None = "abc123") -> MagicMock:
    """Build a mock Starlette request shaped for the endpoint."""
    raw = json.dumps(body).encode("utf-8") if body is not None else b""

    req = MagicMock()
    req.body = AsyncMock(return_value=raw)
    req.cookies = {"dashboard_session": cookie} if cookie else {}
    req.app.state.anonymize_health = {
        "egress_endpoints_onion_only": True,
        "operator_registry_size": 1,
    }
    return req


@pytest.mark.asyncio
async def test_quote_returns_404_when_disabled() -> None:
    settings.anonymize_enabled = False
    try:
        resp = await dash_anonymize_quote(_mock_request(body={}))
        assert resp.status_code == 404
    finally:
        settings.anonymize_enabled = True


@pytest.mark.asyncio
async def test_quote_returns_503_when_keyset_missing(monkeypatch) -> None:
    settings.anonymize_enabled = True
    monkeypatch.setattr(settings, "anonymize_quote_token_hmac_key_fernet", "")
    resp = await dash_anonymize_quote(
        _mock_request(
            body={
                "source_kind": "ext-lightning",
                "destination_address": _REGTEST_P2TR,
                "requested_amount_sat": 250_000,
            }
        )
    )
    assert resp.status_code == 503


@pytest.mark.asyncio
async def test_quote_happy_path_signs_token(_quote_keyset) -> None:
    settings.anonymize_enabled = True
    out = await dash_anonymize_quote(
        _mock_request(
            body={
                "source_kind": "ext-lightning",
                "destination_address": _REGTEST_P2TR,
                "requested_amount_sat": 250_000,
            }
        )
    )
    assert isinstance(out, dict)
    assert "quote_token" in out
    assert out["quote_token"].count(".") == 2  # gen.b64.mac
    assert out["bin_amount_sat"] == 250_000
    assert out["advisory_tier"] in {"weak", "moderate", "strong"}


@pytest.mark.asyncio
async def test_quote_admits_onchain_source_via_chain_selector(
    _quote_keyset,
    monkeypatch,
) -> None:
    """On-chain
    sources go through the async chain selector. Under the new
    contract the endpoint is responsible for running it before
    calling the synchronous quote builder. This test stands in for
    a working selector by patching it to return a happy-path
    distinct-pair result, so the test covers the endpoint wiring
    without depending on a live Tor listener.

    A separate integration suite covers the failure paths
    (``SubmarineChainExhausted`` → 409, ``ReverseProbeFailed`` →
    503) end-to-end.
    """
    settings.anonymize_enabled = True

    from app.services.anonymize.operator_selection import (
        ChainAttempt,
        OperatorSelectionResult,
    )
    from app.services.anonymize.operators import OperatorEntry

    happy_selection = OperatorSelectionResult(
        submarine=OperatorEntry(
            operator_id="middleway",
            onion="http://sub.onion",
            public_key_hex="",
            attested_min_24h_volume_satoshis=2_000_000,
        ),
        reverse=OperatorEntry(
            operator_id="boltz-canonical",
            onion="http://rev.onion",
            public_key_hex="",
            attested_min_24h_volume_satoshis=200_000_000,
        ),
        submarine_chain_attempted=(ChainAttempt(operator_id="middleway", status="selected"),),
        submarine_primary="middleway",
        selection_source="primary",
    )

    async def _fake_selector(**kwargs):
        return happy_selection

    monkeypatch.setattr(
        "app.services.anonymize.operator_selection.select_operators_for_onchain_session",
        _fake_selector,
    )

    out = await dash_anonymize_quote(
        _mock_request(
            body={
                "source_kind": "onchain-self",
                "destination_address": _REGTEST_P2TR,
                "requested_amount_sat": 250_000,
            }
        )
    )
    assert isinstance(out, dict), f"expected dict, got {out}"
    assert "quote_token" in out
    assert out["submarine_operator_id"] == "middleway"
    assert out["reverse_operator_id"] == "boltz-canonical"
    assert out["submarine_chain"]["selection_source"] == "primary"


# ── quote-endpoint error responses ────────────────────


@pytest.mark.asyncio
async def test_quote_url_pin_bypass_skips_chain_selector(
    _quote_keyset,
    monkeypatch,
) -> None:
    """URL-pin bypass — when ``BOLTZ_SUBMARINE_ONION_URL`` or
    ``BOLTZ_REVERSE_ONION_URL`` is set, the endpoint MUST skip the
    chain selector entirely. The session uses the pinned URL directly
    and the chain logic is suppressed.

    Verifies the bypass path doesn't crash and the response shape
    omits the chain-trajectory fields (since no chain ran).
    """
    settings.anonymize_enabled = True
    monkeypatch.setattr(
        settings,
        "boltz_submarine_onion_url",
        "http://pinned-sub.onion/v2",
    )
    monkeypatch.setattr(
        settings,
        "boltz_reverse_onion_url",
        "http://pinned-rev.onion/v2",
    )

    # Patch the selector to raise if called — the URL-pin bypass
    # must skip it entirely.
    async def _selector_must_not_run(**_kwargs):
        raise AssertionError("selector was called despite URL pins being set; the bypass is broken")

    monkeypatch.setattr(
        "app.services.anonymize.operator_selection.select_operators_for_onchain_session",
        _selector_must_not_run,
    )

    out = await dash_anonymize_quote(
        _mock_request(
            body={
                "source_kind": "onchain-self",
                "destination_address": _REGTEST_P2TR,
                "requested_amount_sat": 250_000,
            }
        )
    )
    assert isinstance(out, dict)
    assert "quote_token" in out
    # No chain ran → no submarine_chain field in response.
    assert "submarine_chain" not in out


@pytest.mark.asyncio
async def test_quote_submarine_chain_exhausted_returns_409(
    _quote_keyset,
    monkeypatch,
) -> None:
    """Both submarine alts unreachable + no consent → HTTP 409
    with ``submarine_chain_exhausted`` body. ``attempted[]`` carries
    per-candidate status; ``single_operator_fallback_available`` is
    true when Boltz canonical can serve as the consolidated target."""
    settings.anonymize_enabled = True
    from app.services.anonymize.operator_selection import (
        ChainAttempt,
        SubmarineChainExhausted,
    )

    sentinel = SubmarineChainExhausted(
        chain_attempted=(
            ChainAttempt(operator_id="middleway", status="unreachable"),
            ChainAttempt(operator_id="eldamar", status="unreachable"),
        ),
        single_operator_fallback_available=True,
    )

    async def _fake_selector(**kwargs):
        return sentinel

    monkeypatch.setattr(
        "app.services.anonymize.operator_selection.select_operators_for_onchain_session",
        _fake_selector,
    )

    resp = await dash_anonymize_quote(
        _mock_request(
            body={
                "source_kind": "onchain-self",
                "destination_address": _REGTEST_P2TR,
                "requested_amount_sat": 250_000,
            }
        )
    )
    assert resp.status_code == 409
    import json as _json

    body = _json.loads(resp.body)
    assert body["code"] == "submarine_chain_exhausted"
    assert body["single_operator_fallback_available"] is True
    assert body["attempted"] == [
        {"operator_id": "middleway", "status": "unreachable"},
        {"operator_id": "eldamar", "status": "unreachable"},
    ]


@pytest.mark.asyncio
async def test_quote_reverse_probe_failed_returns_503(
    _quote_keyset,
    monkeypatch,
) -> None:
    """Reverse-leg probe failed independently of submarine
    chain → HTTP 503 ``reverse_probe_failed`` with the reverse
    operator_id."""
    settings.anonymize_enabled = True
    from app.services.anonymize.operator_selection import ReverseProbeFailed

    async def _fake_selector(**kwargs):
        return ReverseProbeFailed(
            operator_id="boltz-canonical",
            status="unreachable",
            from_single_operator_fallback=False,
        )

    monkeypatch.setattr(
        "app.services.anonymize.operator_selection.select_operators_for_onchain_session",
        _fake_selector,
    )

    resp = await dash_anonymize_quote(
        _mock_request(
            body={
                "source_kind": "onchain-self",
                "destination_address": _REGTEST_P2TR,
                "requested_amount_sat": 250_000,
            }
        )
    )
    assert resp.status_code == 503
    import json as _json

    body = _json.loads(resp.body)
    assert body["code"] == "reverse_probe_failed"
    assert body["operator_id"] == "boltz-canonical"


@pytest.mark.asyncio
async def test_quote_all_submarine_operators_unreachable_returns_503(
    _quote_keyset,
    monkeypatch,
) -> None:
    """User consented to single-operator fallback AND the
    consolidated probe of Boltz canonical (on the submarine listener)
    ALSO failed → HTTP 503 ``all_submarine_operators_unreachable``.

    The wire-mapping discriminator is the sentinel's
    ``from_single_operator_fallback`` field (NOT the request's
    consent flag) — regression guard for the
    prophylactic-consent-flag bug noted in plan.
    """
    settings.anonymize_enabled = True
    from app.services.anonymize.operator_selection import ReverseProbeFailed

    async def _fake_selector(**kwargs):
        return ReverseProbeFailed(
            operator_id="boltz-canonical",
            status="unreachable",
            from_single_operator_fallback=True,
        )

    monkeypatch.setattr(
        "app.services.anonymize.operator_selection.select_operators_for_onchain_session",
        _fake_selector,
    )

    resp = await dash_anonymize_quote(
        _mock_request(
            body={
                "source_kind": "onchain-self",
                "destination_address": _REGTEST_P2TR,
                "requested_amount_sat": 250_000,
                "allow_single_operator_fallback": True,
            }
        )
    )
    assert resp.status_code == 503
    import json as _json

    body = _json.loads(resp.body)
    assert body["code"] == "all_submarine_operators_unreachable"


@pytest.mark.asyncio
async def test_quote_response_carries_attempted_array_on_success(
    _quote_keyset,
    monkeypatch,
) -> None:
    """Success responses include the full chain-walk
    trajectory under ``submarine_chain.attempted``."""
    settings.anonymize_enabled = True
    from app.services.anonymize.operator_selection import (
        ChainAttempt,
        OperatorSelectionResult,
    )
    from app.services.anonymize.operators import OperatorEntry

    selection = OperatorSelectionResult(
        submarine=OperatorEntry(
            operator_id="eldamar",
            onion="http://sub.onion",
            public_key_hex="",
        ),
        reverse=OperatorEntry(
            operator_id="boltz-canonical",
            onion="http://rev.onion",
            public_key_hex="",
        ),
        submarine_chain_attempted=(
            ChainAttempt(operator_id="middleway", status="unreachable"),
            ChainAttempt(operator_id="eldamar", status="selected"),
        ),
        submarine_primary="middleway",
        selection_source="secondary_after_primary_failed",
    )

    async def _fake_selector(**kwargs):
        return selection

    monkeypatch.setattr(
        "app.services.anonymize.operator_selection.select_operators_for_onchain_session",
        _fake_selector,
    )

    out = await dash_anonymize_quote(
        _mock_request(
            body={
                "source_kind": "onchain-self",
                "destination_address": _REGTEST_P2TR,
                "requested_amount_sat": 250_000,
            }
        )
    )
    assert isinstance(out, dict)
    chain = out["submarine_chain"]
    assert chain["primary_attempted"] == "middleway"
    assert chain["primary_status"] == "unreachable"
    assert chain["selected"] == "eldamar"
    assert chain["selection_source"] == "secondary_after_primary_failed"
    assert chain["attempted"] == [
        {"operator_id": "middleway", "status": "unreachable"},
        {"operator_id": "eldamar", "status": "selected"},
    ]
    # And the inline advisory note appears in advisory_tier_notes.
    notes_blob = " ".join(out["advisory_tier_notes"]).lower()
    assert "primary submarine operator unreachable" in notes_blob


@pytest.mark.asyncio
async def test_quote_with_primary_unreachable_returns_secondary_with_advisory(
    _quote_keyset,
    monkeypatch,
) -> None:
    """When the primary alt fails but the secondary succeeds,
    the response carries the secondary in ``submarine_operator_id``,
    ``selection_source="secondary_after_primary_failed"``, and the
    inline advisory note in ``advisory_tier_notes``."""
    settings.anonymize_enabled = True

    from app.services.anonymize.operator_selection import (
        ChainAttempt,
        OperatorSelectionResult,
    )
    from app.services.anonymize.operators import OperatorEntry

    selection = OperatorSelectionResult(
        submarine=OperatorEntry(
            operator_id="eldamar",
            onion="http://eldamar.onion",
            public_key_hex="",
        ),
        reverse=OperatorEntry(
            operator_id="boltz-canonical",
            onion="http://boltz.onion",
            public_key_hex="",
        ),
        submarine_chain_attempted=(
            ChainAttempt(operator_id="middleway", status="unreachable"),
            ChainAttempt(operator_id="eldamar", status="selected"),
        ),
        submarine_primary="middleway",
        selection_source="secondary_after_primary_failed",
    )

    async def _fake_selector(**kwargs):
        return selection

    monkeypatch.setattr(
        "app.services.anonymize.operator_selection.select_operators_for_onchain_session",
        _fake_selector,
    )

    out = await dash_anonymize_quote(
        _mock_request(
            body={
                "source_kind": "onchain-self",
                "destination_address": _REGTEST_P2TR,
                "requested_amount_sat": 250_000,
            }
        )
    )
    assert isinstance(out, dict)
    assert out["submarine_operator_id"] == "eldamar"
    assert out["submarine_chain"]["selection_source"] == ("secondary_after_primary_failed")
    assert any("primary submarine operator unreachable" in n.lower() for n in out["advisory_tier_notes"])


@pytest.mark.asyncio
async def test_quote_with_consent_returns_single_operator_with_moderate_cap(
    _quote_keyset,
    monkeypatch,
) -> None:
    """Consent re-quote that succeeds: selection_source =
    ``single_operator_after_chain_exhausted``, tier capped at moderate,
    submarine == reverse == boltz-canonical."""
    settings.anonymize_enabled = True

    from app.services.anonymize.operator_selection import (
        ChainAttempt,
        OperatorSelectionResult,
    )
    from app.services.anonymize.operators import OperatorEntry

    boltz = OperatorEntry(
        operator_id="boltz-canonical",
        onion="http://boltz.onion",
        public_key_hex="",
        attested_min_24h_volume_satoshis=200_000_000,
    )

    selection = OperatorSelectionResult(
        submarine=boltz,
        reverse=boltz,
        submarine_chain_attempted=(
            ChainAttempt(operator_id="middleway", status="unreachable"),
            ChainAttempt(operator_id="eldamar", status="unreachable"),
        ),
        submarine_primary="middleway",
        selection_source="single_operator_after_chain_exhausted",
    )

    async def _fake_selector(**kwargs):
        return selection

    monkeypatch.setattr(
        "app.services.anonymize.operator_selection.select_operators_for_onchain_session",
        _fake_selector,
    )

    out = await dash_anonymize_quote(
        _mock_request(
            body={
                "source_kind": "onchain-self",
                "destination_address": _REGTEST_P2TR,
                "requested_amount_sat": 250_000,
                "allow_single_operator_fallback": True,
            }
        )
    )
    assert isinstance(out, dict)
    assert out["submarine_operator_id"] == "boltz-canonical"
    assert out["reverse_operator_id"] == "boltz-canonical"
    assert out["submarine_chain"]["selection_source"] == ("single_operator_after_chain_exhausted")
    # Tier capped at moderate (distinct_operators=False).
    assert out["advisory_tier"] in {"weak", "moderate"}
    notes_blob = " ".join(out["advisory_tier_notes"]).lower()
    assert "submarine alt operators exhausted" in notes_blob


@pytest.mark.asyncio
async def test_quote_attempted_array_carries_skipped_amount_unsupported(
    _quote_keyset,
    monkeypatch,
) -> None:
    """When an operator is skipped at the capacity pre-filter,
    its ``attempted[]`` entry carries
    ``status="skipped_amount_unsupported"`` so the SPA can render a
    clearer message than ``unreachable``."""
    settings.anonymize_enabled = True

    from app.services.anonymize.operator_selection import (
        ChainAttempt,
        OperatorSelectionResult,
    )
    from app.services.anonymize.operators import OperatorEntry

    selection = OperatorSelectionResult(
        submarine=OperatorEntry(
            operator_id="middleway",
            onion="http://middleway.onion",
            public_key_hex="",
        ),
        reverse=OperatorEntry(
            operator_id="boltz-canonical",
            onion="http://boltz.onion",
            public_key_hex="",
        ),
        submarine_chain_attempted=(
            ChainAttempt(operator_id="middleway", status="selected"),
            ChainAttempt(operator_id="eldamar", status="skipped_amount_unsupported"),
        ),
        submarine_primary="middleway",
        selection_source="primary",
    )

    async def _fake_selector(**kwargs):
        return selection

    monkeypatch.setattr(
        "app.services.anonymize.operator_selection.select_operators_for_onchain_session",
        _fake_selector,
    )

    out = await dash_anonymize_quote(
        _mock_request(
            body={
                "source_kind": "onchain-self",
                "destination_address": _REGTEST_P2TR,
                "requested_amount_sat": 250_000,
            }
        )
    )
    attempted = out["submarine_chain"]["attempted"]
    assert {"operator_id": "eldamar", "status": "skipped_amount_unsupported"} in attempted


@pytest.mark.asyncio
async def test_quote_rejects_malformed_destination(_quote_keyset) -> None:
    settings.anonymize_enabled = True
    resp = await dash_anonymize_quote(
        _mock_request(
            body={
                "source_kind": "ext-lightning",
                "destination_address": "not-a-bitcoin-address",
                "requested_amount_sat": 250_000,
            }
        )
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_quote_rejects_amount_outside_range(
    _quote_keyset,
    monkeypatch,
) -> None:
    settings.anonymize_enabled = True
    monkeypatch.setattr(settings, "anonymize_min_sat", 50_000)
    resp = await dash_anonymize_quote(
        _mock_request(
            body={
                "source_kind": "ext-lightning",
                "destination_address": _REGTEST_P2TR,
                "requested_amount_sat": 1_000,
            }
        )
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_quote_rejects_invalid_json_body(_quote_keyset) -> None:
    settings.anonymize_enabled = True
    req = _mock_request(body=None)
    req.body = AsyncMock(return_value=b"not-json{")
    resp = await dash_anonymize_quote(req)
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_quote_different_cookies_produce_different_tokens(
    _quote_keyset,
) -> None:
    """#7 — cookie subject is bound into the token."""
    settings.anonymize_enabled = True
    body = {
        "source_kind": "ext-lightning",
        "destination_address": _REGTEST_P2TR,
        "requested_amount_sat": 250_000,
    }
    out_a = await dash_anonymize_quote(_mock_request(body=body, cookie="alice"))
    out_b = await dash_anonymize_quote(_mock_request(body=body, cookie="bob"))
    assert out_a["quote_token"] != out_b["quote_token"]


@pytest.mark.asyncio
async def test_quote_response_shape_is_stable(_quote_keyset) -> None:
    """The SPA pins the response keys; this test catches reorder
    regressions. Operator assignment added
    optional ``reverse_operator_id`` / ``submarine_operator_id`` /
    ``submarine_chain`` fields that appear when the selector picked
    an operator; the fixed keys remain a SUBSET of the response so
    forward-compatible additions don't break the SPA."""
    settings.anonymize_enabled = True
    out = await dash_anonymize_quote(
        _mock_request(
            body={
                "source_kind": "ext-lightning",
                "destination_address": _REGTEST_P2TR,
                "requested_amount_sat": 250_000,
            }
        )
    )
    fixed_keys = {
        "quote_token",
        "bin_amount_sat",
        "advisory_tier",
        "advisory_tier_notes",
        "min_executed_chunks_for_target_tier",
        "issued_at_unix_s",
        "ttl_s",
        "uses_liquid",
    }
    assert fixed_keys.issubset(set(out.keys()))
    # The only optional fields that should appear on an LN-only quote
    # is ``reverse_operator_id``. ``submarine_*`` keys must NOT
    # appear (LN-only has no submarine leg).
    assert "submarine_operator_id" not in out
    assert "submarine_chain" not in out


# ── BIP-353 destination handling ───────────────────────────────────


@pytest.mark.asyncio
async def test_quote_resolves_bip353_handle_to_onchain_fallback(
    _quote_keyset,
    monkeypatch,
) -> None:
    """A ``user@host`` destination is resolved at quote-time. The
    response surfaces the resolved on-chain address in a ``bip353``
    block so the SPA can render the resolution to the user."""
    from app.services.anonymize import dns as bip353_mod

    async def _fake_resolve(handle, **_kwargs):
        return bip353_mod.Bip353Result(
            user_at_domain=handle,
            dns_name="alice.user._bitcoin-payment.example.com",
            bolt12_offer="lno1deadbeef",
            bolt11_invoice=None,
            onchain_address=_REGTEST_P2TR,
            raw_txt=f"bitcoin:{_REGTEST_P2TR}?lno=lno1deadbeef",
        )

    monkeypatch.setattr(bip353_mod, "resolve_bip353", _fake_resolve)
    await bip353_mod.reset_cache_for_tests()

    settings.anonymize_enabled = True
    out = await dash_anonymize_quote(
        _mock_request(
            body={
                "source_kind": "ext-lightning",
                "destination_address": "alice@example.com",
                "requested_amount_sat": 250_000,
            }
        )
    )
    assert "quote_token" in out
    assert out["bip353"]["handle"] == "alice@example.com"
    assert out["bip353"]["resolved_address"] == _REGTEST_P2TR


@pytest.mark.asyncio
async def test_quote_accepts_bip353_lightning_only_as_bolt12_exit(
    _quote_keyset,
    monkeypatch,
) -> None:
    """BIP-353 destinations that publish only ``lno=`` (no on-chain
    fallback) resolve to a BOLT 12-exit pipeline. The response carries
    the resolved offer in the ``bip353`` block so the SPA can render
    ``alice@example.com → lno1…`` as the confirmation."""
    from app.services.anonymize import dns as bip353_mod

    async def _fake_resolve(handle, **_kwargs):
        return bip353_mod.Bip353Result(
            user_at_domain=handle,
            dns_name="alice.user._bitcoin-payment.example.com",
            bolt12_offer="lno1only",
            bolt11_invoice=None,
            onchain_address=None,
            raw_txt="bitcoin:?lno=lno1only",
        )

    monkeypatch.setattr(bip353_mod, "resolve_bip353", _fake_resolve)
    await bip353_mod.reset_cache_for_tests()

    settings.anonymize_enabled = True
    out = await dash_anonymize_quote(
        _mock_request(
            body={
                "source_kind": "ext-lightning",
                "destination_address": "alice@example.com",
                "requested_amount_sat": 250_000,
            }
        )
    )
    assert "quote_token" in out
    assert out["bip353"]["handle"] == "alice@example.com"
    assert out["bip353"]["exit_kind"] == "bolt12_pay"
    assert out["bip353"]["bolt12_offer"] == "lno1only"
    # No on-chain address resolved for a BOLT 12-only handle.
    assert out["bip353"]["resolved_address"] == ""


@pytest.mark.asyncio
async def test_quote_rejects_bip353_bolt11_only(
    _quote_keyset,
    monkeypatch,
) -> None:
    """BIP-353 destinations that publish ONLY a BOLT 11 invoice (no
    on-chain fallback, no BOLT 12 offer) are still refused — a BOLT 11
    invoice's sub-hour expiry cannot survive a meaningful mixing dwell.
    Surfaces the standard ``destination_rejected`` shape."""
    from app.services.anonymize import dns as bip353_mod

    async def _fake_resolve(handle, **_kwargs):
        return bip353_mod.Bip353Result(
            user_at_domain=handle,
            dns_name="alice.user._bitcoin-payment.example.com",
            bolt12_offer=None,
            bolt11_invoice="lnbc100u",
            onchain_address=None,
            raw_txt="bitcoin:?lightning=lnbc100u",
        )

    monkeypatch.setattr(bip353_mod, "resolve_bip353", _fake_resolve)
    await bip353_mod.reset_cache_for_tests()

    settings.anonymize_enabled = True
    resp = await dash_anonymize_quote(
        _mock_request(
            body={
                "source_kind": "ext-lightning",
                "destination_address": "alice@example.com",
                "requested_amount_sat": 250_000,
            }
        )
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_quote_does_not_add_bip353_block_for_raw_address(
    _quote_keyset,
) -> None:
    """A raw on-chain address must NOT carry a ``bip353`` block in
    the response — the field's presence is the signal that
    resolution happened."""
    settings.anonymize_enabled = True
    out = await dash_anonymize_quote(
        _mock_request(
            body={
                "source_kind": "ext-lightning",
                "destination_address": _REGTEST_P2TR,
                "requested_amount_sat": 250_000,
            }
        )
    )
    assert "bip353" not in out


# ── deposit_method ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_quote_binds_deposit_method_into_token(_quote_keyset) -> None:
    """A per-quote ``deposit_method=bolt12`` is bound into the signed
    pipeline_json so a tampered create-body cannot switch the
    deposit type after the quote was signed."""
    import base64

    settings.anonymize_enabled = True
    out = await dash_anonymize_quote(
        _mock_request(
            body={
                "source_kind": "ext-lightning",
                "destination_address": _REGTEST_P2TR,
                "requested_amount_sat": 250_000,
                "deposit_method": "bolt12",
            }
        )
    )
    assert "quote_token" in out

    # Decode the canonical body the token signs and assert the
    # deposit_method is bound into the source block.
    parts = out["quote_token"].split(".")
    assert len(parts) == 3
    canonical_b64 = parts[1] + "=" * (-len(parts[1]) % 4)
    payload = json.loads(base64.urlsafe_b64decode(canonical_b64))
    pipeline = json.loads(payload["canonical_pipeline_json"])
    assert pipeline["source"]["deposit_method"] == "bolt12"


@pytest.mark.asyncio
async def test_quote_falls_back_to_settings_deposit_method(
    _quote_keyset,
    monkeypatch,
) -> None:
    """When no per-quote ``deposit_method`` is supplied, the builder
    reads the operator-wide setting."""
    import base64

    monkeypatch.setattr(
        settings,
        "anonymize_ext_lightning_deposit_method",
        "bolt12",
    )
    settings.anonymize_enabled = True
    out = await dash_anonymize_quote(
        _mock_request(
            body={
                "source_kind": "ext-lightning",
                "destination_address": _REGTEST_P2TR,
                "requested_amount_sat": 250_000,
            }
        )
    )
    parts = out["quote_token"].split(".")
    canonical_b64 = parts[1] + "=" * (-len(parts[1]) % 4)
    payload = json.loads(base64.urlsafe_b64decode(canonical_b64))
    pipeline = json.loads(payload["canonical_pipeline_json"])
    assert pipeline["source"]["deposit_method"] == "bolt12"


@pytest.mark.asyncio
async def test_quote_rejects_invalid_deposit_method(_quote_keyset) -> None:
    """An unknown ``deposit_method`` is refused with the standard
    ``destination_rejected`` shape (the builder raises QuoteBuildError)."""
    settings.anonymize_enabled = True
    resp = await dash_anonymize_quote(
        _mock_request(
            body={
                "source_kind": "ext-lightning",
                "destination_address": _REGTEST_P2TR,
                "requested_amount_sat": 250_000,
                "deposit_method": "trampoline-bouncing",
            }
        )
    )
    assert resp.status_code == 422
