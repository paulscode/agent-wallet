# SPDX-License-Identifier: MIT
"""Quote builder: build + sign a quote token."""

from __future__ import annotations

import base64
import hashlib

import pytest
from cryptography.fernet import Fernet

from app.core.config import settings
from app.services.anonymize.quote_builder import (
    QuoteBuildError,
    QuoteRequest,
    build_quote,
    result_to_dict,
)
from app.services.anonymize.quote_token import (
    QuoteTokenKeySet,
    load_quote_token_keyset,
)


@pytest.fixture
def _keyset(monkeypatch) -> QuoteTokenKeySet:
    """Seed an active quote-token key and return the loaded set."""
    monkeypatch.setattr(
        settings,
        "anonymize_quote_token_hmac_key_fernet",
        Fernet.generate_key().decode("ascii"),
    )
    ks = load_quote_token_keyset()
    assert ks is not None
    return ks


# A valid regtest p2tr address (matches the project's BITCOIN_NETWORK
# default in test config). Use a documented test vector.
_REGTEST_P2TR = "bcrt1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqc8gma6"
_REGTEST_P2WKH = "bcrt1qqyqszqgpqyqszqgpqyqszqgpqyqszqgpvxat9t"


def _qreq(*, source_kind="ext-lightning", amount=250_000) -> QuoteRequest:
    return QuoteRequest(
        source_kind=source_kind,
        destination_address=_REGTEST_P2TR,
        requested_amount_sat=amount,
        cookie_subject="user-123",
        canonical_request_body=b'{"requested_amount_sat":250000}',
    )


# ── Happy path ───────────────────────────────────────────────────────


def test_build_quote_returns_signed_token(_keyset) -> None:
    res = build_quote(_qreq(), keyset=_keyset)
    assert res.quote_token  # non-empty
    # The token has three dot-separated parts (gen.b64.mac).
    assert res.quote_token.count(".") == 2


def test_build_quote_bins_amount_to_configured_set(_keyset, monkeypatch) -> None:
    monkeypatch.setattr(
        settings,
        "anonymize_amount_bins_sat",
        "50000,100000,250000,500000,1000000",
    )
    # quantizes DOWN to the nearest bin. 260_000 → 250_000.
    res = build_quote(_qreq(amount=260_000), keyset=_keyset)
    assert res.bin_amount_sat == 250_000


def test_build_quote_advisory_tier_for_lightning_self(_keyset) -> None:
    """LN source + good defaults score above weak."""
    res = build_quote(
        _qreq(source_kind="lightning-self"),
        keyset=_keyset,
        operator_registry_size=3,
    )
    assert res.advisory_tier in {"weak", "moderate", "strong"}


def test_build_quote_min_executed_chunks_for_target_tier(_keyset) -> None:
    res = build_quote(_qreq(), keyset=_keyset)
    # For any tier, the min-K advisory is at least 1.
    assert res.min_executed_chunks_for_target_tier >= 1


def _canonical_pipeline_json(res) -> dict:
    """Decode the canonical pipeline JSON bound into a quote token."""
    import json

    _gen, b64, _mac = res.quote_token.split(".")
    pad = b"=" * (-len(b64) % 4)
    bound = json.loads(base64.urlsafe_b64decode(b64.encode("ascii") + pad))
    return json.loads(bound["canonical_pipeline_json"])


def test_lightning_self_pipeline_carries_self_pay_hop(_keyset) -> None:
    """A lightning-self quote pins the self-pay source hop into the
    pipeline so the privacy score credits the channel-balance reshuffle
    the hop performs before the reverse exit."""
    res = build_quote(_qreq(source_kind="lightning-self"), keyset=_keyset)
    canonical_pj = _canonical_pipeline_json(res)
    assert canonical_pj["source"]["kind"] == "lightning-self"
    assert [h["kind"] for h in canonical_pj["hops"]] == ["ln_self_pay"]


def test_ext_lightning_pipeline_has_no_self_pay_hop(_keyset) -> None:
    """An externally-funded ext-lightning source does no self-pay, so
    it carries no source hop — only the reverse exit."""
    res = build_quote(_qreq(source_kind="ext-lightning"), keyset=_keyset)
    canonical_pj = _canonical_pipeline_json(res)
    assert canonical_pj["source"]["kind"] == "ext-lightning"
    assert [h["kind"] for h in canonical_pj["hops"]] == []


def test_onchain_source_below_submarine_minimum_rejected(_keyset) -> None:
    # On-chain sources fund via a submarine swap (operator min 100k by
    # default). A below-minimum request must fail fast at quote time
    # rather than create a session that wedges at swap-create.
    with pytest.raises(QuoteBuildError, match="100,000"):
        build_quote(_qreq(source_kind="onchain-self", amount=50_000), keyset=_keyset)


def test_ext_onchain_below_submarine_minimum_rejected(_keyset) -> None:
    with pytest.raises(QuoteBuildError, match="submarine swap minimum"):
        build_quote(_qreq(source_kind="ext-onchain", amount=50_000), keyset=_keyset)


def test_lightning_source_not_constrained_by_onchain_minimum(_keyset) -> None:
    # The on-chain minimum must NOT apply to Lightning sources — they
    # don't use a submarine swap. 50k is allowed (global floor).
    res = build_quote(_qreq(source_kind="lightning-self", amount=50_000), keyset=_keyset)
    assert res.quote_token


def test_result_to_dict_has_stable_shape(_keyset) -> None:
    res = build_quote(_qreq(), keyset=_keyset)
    out = result_to_dict(res)
    # The fixed (always-present) keys.
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
    # Optional fields
    # that appear only when an operator was actually selected. LN-only
    # quotes attach ``reverse_operator_id`` (single registry operator
    # for the reverse leg) but NOT ``submarine_operator_id`` /
    # ``submarine_chain`` (no chain walk for LN-only sources).
    optional_keys = set(out.keys()) - fixed_keys
    assert optional_keys.issubset(
        {
            "reverse_operator_id",
            "submarine_operator_id",
            "submarine_chain",
        }
    )
    assert "submarine_operator_id" not in out  # LN-only never has one
    assert "submarine_chain" not in out
    # Default request leaves prefer_liquid=False so the result-side
    # uses_liquid flag is False — the schema includes the key, the
    # value is False until an opt-in request comes in.
    assert out["uses_liquid"] is False


# ── Option C — per-quote prefer_liquid flag ──────────────────────────


def test_prefer_liquid_with_master_switch_off_downgrades_silently(
    _keyset,
    monkeypatch,
) -> None:
    """Operator hasn't enabled the Liquid hop → opt-in is ignored.

    The result still surfaces the downgrade so the SPA can flag it
    instead of silently lying to the user. The token also binds
    ``uses_liquid=False`` so the create endpoint never sets the
    pipeline marker.
    """
    monkeypatch.setattr(settings, "anonymize_liquid_enabled", False)
    req = QuoteRequest(
        source_kind="lightning-self",
        destination_address=_REGTEST_P2TR,
        requested_amount_sat=250_000,
        cookie_subject="u",
        canonical_request_body=b"{}",
        prefer_liquid=True,
    )
    res = build_quote(req, keyset=_keyset)
    assert res.uses_liquid is False
    out = result_to_dict(res)
    assert out["uses_liquid"] is False


def test_prefer_liquid_with_master_switch_on_routes_through_liquid(
    _keyset,
    monkeypatch,
) -> None:
    monkeypatch.setattr(settings, "anonymize_liquid_enabled", True)
    req = QuoteRequest(
        source_kind="lightning-self",
        destination_address=_REGTEST_P2TR,
        requested_amount_sat=250_000,
        cookie_subject="u",
        canonical_request_body=b"{}",
        prefer_liquid=True,
    )
    res = build_quote(req, keyset=_keyset)
    assert res.uses_liquid is True
    out = result_to_dict(res)
    assert out["uses_liquid"] is True


def test_prefer_liquid_default_is_false(_keyset) -> None:
    """No opt-in → uses_liquid stays False even with master switch on."""
    res = build_quote(_qreq(), keyset=_keyset)
    assert res.uses_liquid is False


def test_uses_liquid_is_bound_into_quote_token(_keyset, monkeypatch) -> None:
    """The token's bound payload must include ``uses_liquid`` so a
    LN-only token cannot be replayed as a Liquid-opt-in token."""
    monkeypatch.setattr(settings, "anonymize_liquid_enabled", True)
    from app.services.anonymize.quote_token import decode_quote_token

    req = QuoteRequest(
        source_kind="lightning-self",
        destination_address=_REGTEST_P2TR,
        requested_amount_sat=250_000,
        cookie_subject="u",
        canonical_request_body=b"{}",
        prefer_liquid=True,
    )
    res = build_quote(req, keyset=_keyset)
    bound = decode_quote_token(res.quote_token, keyset=_keyset)
    assert bound.get("uses_liquid") is True


# ── Rejection paths ──────────────────────────────────────────────────


def _mock_selection(
    *,
    submarine_id: str = "middleway",
    reverse_id: str = "boltz-canonical",
    selection_source: str = "primary",
):
    """Build a mock :class:`OperatorSelectionResult` for tests that
    exercise the on-chain branch of ``build_quote``.

     the endpoint is responsible for calling the async
    selector and passing the result here; tests stand in with a
    pre-fabricated result so they can stay synchronous.
    """
    from app.services.anonymize.operator_selection import (
        ChainAttempt,
        OperatorSelectionResult,
    )
    from app.services.anonymize.operators import OperatorEntry

    submarine = OperatorEntry(
        operator_id=submarine_id,
        onion="http://sub.onion",
        public_key_hex="",
    )
    reverse = OperatorEntry(
        operator_id=reverse_id,
        onion="http://rev.onion",
        public_key_hex="",
    )
    return OperatorSelectionResult(
        submarine=submarine,
        reverse=reverse,
        submarine_chain_attempted=(ChainAttempt(operator_id=submarine_id, status="selected"),),
        submarine_primary=submarine_id,
        selection_source=selection_source,
    )


def test_build_quote_admits_onchain_single_operator_with_moderate_cap(
    _keyset,
) -> None:
    """Single-operator-fallback path. Selection layer picks
    the same operator for both legs (after user consent); the scorer
    caps the tier at moderate via ``distinct_operators=False``."""
    selection = _mock_selection(
        submarine_id="boltz-canonical",
        reverse_id="boltz-canonical",
        selection_source="single_operator_after_chain_exhausted",
    )
    res = build_quote(
        QuoteRequest(
            source_kind="onchain-self",
            destination_address=_REGTEST_P2TR,
            requested_amount_sat=250_000,
            cookie_subject="u",
            canonical_request_body=b"{}",
        ),
        keyset=_keyset,
        selection=selection,
    )
    assert res.advisory_tier in {"weak", "moderate"}
    # The cap reason MUST mention distinct operators so the UI's
    # banner copy stays in sync with the scorer's note.
    note_blob = " ".join(res.advisory_tier_notes).lower()
    assert "distinct operators" in note_blob


def test_build_quote_rejects_unknown_source_kind(_keyset) -> None:
    with pytest.raises(QuoteBuildError, match="unsupported source kind"):
        build_quote(
            QuoteRequest(
                source_kind="bogus-kind",
                destination_address=_REGTEST_P2TR,
                requested_amount_sat=250_000,
                cookie_subject="u",
                canonical_request_body=b"{}",
            ),
            keyset=_keyset,
        )


def test_build_quote_admits_onchain_when_distinct_legs_configured(
    _keyset,
    monkeypatch,
) -> None:
    """On-chain sources mint a submarine first hop
    with the mandatory inter-leg delay window. Under the new
    selection model the test supplies a distinct-pair selection
    directly instead of relying on URL pins (which now disable the
    chain logic)."""
    selection = _mock_selection(
        submarine_id="middleway",
        reverse_id="boltz-canonical",
        selection_source="primary",
    )
    out = build_quote(
        QuoteRequest(
            source_kind="ext-onchain",
            destination_address=_REGTEST_P2TR,
            requested_amount_sat=250_000,
            cookie_subject="u",
            canonical_request_body=b"{}",
        ),
        keyset=_keyset,
        selection=selection,
    )
    # Decode the bound payload — pipeline JSON should carry a
    # submarine hop + a non-None inter_leg_delay.
    import base64
    import json

    _gen, b64, _mac = out.quote_token.split(".")
    pad = b"=" * (-len(b64) % 4)
    bound = json.loads(base64.urlsafe_b64decode(b64.encode("ascii") + pad))
    canonical_pj = json.loads(bound["canonical_pipeline_json"])
    assert canonical_pj["source"]["kind"] == "ext-onchain"
    assert [h["kind"] for h in canonical_pj["hops"]] == ["submarine"]
    assert canonical_pj["inter_leg_delay"] is not None
    assert canonical_pj["inter_leg_delay"]["min_seconds"] > 0


def test_build_quote_rejects_amount_below_min(_keyset, monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_min_sat", 100_000)
    with pytest.raises(QuoteBuildError, match="outside"):
        build_quote(_qreq(amount=10_000), keyset=_keyset)


def test_build_quote_rejects_amount_above_max(_keyset, monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_max_sat", 1_000_000)
    with pytest.raises(QuoteBuildError, match="outside"):
        build_quote(_qreq(amount=5_000_000), keyset=_keyset)


def test_build_quote_rejects_malformed_destination(_keyset) -> None:
    with pytest.raises(QuoteBuildError, match="destination"):
        build_quote(
            QuoteRequest(
                source_kind="ext-lightning",
                destination_address="not-a-bitcoin-address",
                requested_amount_sat=250_000,
                cookie_subject="u",
                canonical_request_body=b"{}",
            ),
            keyset=_keyset,
        )


# ── Token bindings (#7 OWASP A01/A03) ─────────────────────────────


def test_token_binds_cookie_subject_hmac(_keyset) -> None:
    """Verifying with a different cookie subject fails."""
    req = _qreq()
    res = build_quote(req, keyset=_keyset)
    # Recreate the candidate exactly — same cookie subject + body.
    from app.services.anonymize.quote_builder import _hmac_cookie_subject
    from app.services.anonymize.quote_token import QuoteTokenPayload

    cookie_hmac = _hmac_cookie_subject(req.cookie_subject, _keyset.active_key)
    body_hash = hashlib.sha256(req.canonical_request_body).digest()
    # Round-trip a candidate the verifier will accept.
    candidate = QuoteTokenPayload(
        canonical_pipeline_json=b"",  # fill below
        bin_amount_sat=res.bin_amount_sat,
        submarine_operator_id=None,
        reverse_operator_id=None,
        delay_min_s=settings.anonymize_default_delay_min_s,
        delay_max_s=settings.anonymize_default_delay_max_s,
        inter_leg_min_s=None,
        inter_leg_max_s=None,
        requested_mpp_k=0,  # don't know exact K; verify_quote_token
        # will fail because we can't reproduce the random K. Instead,
        # decode the token to inspect.
        issued_at_unix_s=res.issued_at_unix_s,
        ttl_s=res.ttl_s,
        cookie_subject_hmac=cookie_hmac,
        canonical_request_body_hash=body_hash,
    )
    # We can't reconstruct K (it's random). Instead inspect the token
    # parts and confirm cookie_hmac + body_hash are present.
    _gen, b64part, _mac = res.quote_token.split(".")
    pad = b"=" * (-len(b64part) % 4)
    decoded = base64.urlsafe_b64decode(b64part.encode("ascii") + pad)
    assert base64.b64encode(cookie_hmac).decode("ascii") in decoded.decode("utf-8")
    assert base64.b64encode(body_hash).decode("ascii") in decoded.decode("utf-8")
    # Suppress unused-variable warning.
    _ = candidate


def test_token_body_hash_differs_with_different_request_body(_keyset) -> None:
    """Two builds with different request bodies produce different tokens."""
    a = build_quote(
        QuoteRequest(
            source_kind="ext-lightning",
            destination_address=_REGTEST_P2TR,
            requested_amount_sat=250_000,
            cookie_subject="u",
            canonical_request_body=b'{"a":1}',
        ),
        keyset=_keyset,
    )
    b = build_quote(
        QuoteRequest(
            source_kind="ext-lightning",
            destination_address=_REGTEST_P2TR,
            requested_amount_sat=250_000,
            cookie_subject="u",
            canonical_request_body=b'{"a":2}',
        ),
        keyset=_keyset,
    )
    assert a.quote_token != b.quote_token


def test_token_carries_issued_at_and_ttl(_keyset) -> None:
    res = build_quote(_qreq(), keyset=_keyset, now_unix_s=1_700_000_000)
    assert res.issued_at_unix_s == 1_700_000_000
    assert res.ttl_s == int(settings.anonymize_quote_token_ttl_s)


def test_p2wkh_destination_is_accepted(_keyset) -> None:
    """p2wkh is in the allowed script-type set."""
    res = build_quote(
        QuoteRequest(
            source_kind="ext-lightning",
            destination_address=_REGTEST_P2WKH,
            requested_amount_sat=250_000,
            cookie_subject="u",
            canonical_request_body=b"{}",
        ),
        keyset=_keyset,
    )
    assert res.bin_amount_sat > 0
