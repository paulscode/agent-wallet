# SPDX-License-Identifier: MIT
"""AnonymityScorer tests.

The scorer is a deterministic heuristic. The hard-cap logic is the
load-bearing part; many.x mitigations trade off a small amount of
usability for a hard cap that no amount of mixing can bypass.
"""

from __future__ import annotations

from app.services.anonymize.pipelines import (
    DelayPolicy,
    Exit,
    Hop,
    InterLegDelay,
    Pipeline,
    Source,
)
from app.services.anonymize.policy import (
    PipelineEnv,
    min_tier,
    quantize_to_bin,
    score,
)


def _strong_env(**overrides) -> PipelineEnv:
    """Build the env that would otherwise produce ``strong``.

    Volume cap is
    reverse-leg-only; submarine volume is informational. Legacy
    ``operator_min_attested_volume_satoshis`` kwarg is accepted as
    a shim that maps to ``reverse_attested_volume_satoshis`` for
    test brevity.
    """
    # Legacy kwarg shim — old tests pass ``operator_min_attested_volume_satoshis``;
    # map it onto the new reverse-leg field.
    if "operator_min_attested_volume_satoshis" in overrides:
        overrides.setdefault(
            "reverse_attested_volume_satoshis",
            overrides.pop("operator_min_attested_volume_satoshis"),
        )
    base = dict(
        has_onchain_source=False,
        distinct_operators=True,
        amount_is_binned=True,
        exit_diversity="asn",
        tor_process_shared_with_lnd=False,
        public_chain_backend_enabled=False,
        exact_audit_logs_enabled=False,
        destination_script_type="p2tr",
        plain_bolt11_ext_deposit=False,
        operator_registry_size=3,
        has_funding_change=False,
        egress_endpoints_onion_only=True,
        in_flight_concurrent_sessions=1,
        used_preconsolidation=False,
        audit_bucket_suppression_disabled=False,
        reverse_attested_volume_satoshis=10_000_000_000,
        submarine_attested_volume_satoshis=0,
        operator_min_volume_multiple=100,
        chain_anchor_redaction_disabled=False,
        registry_signature_verification_failed_at_load=False,
    )
    base.update(overrides)
    return PipelineEnv(**base)


def _ln_pipeline(*, with_priv_channel: bool = False, with_liquid: bool = False) -> Pipeline:
    hops: list[Hop] = [Hop(kind="ln_self_pay")]
    if with_priv_channel:
        hops.append(Hop(kind="priv_channel"))
    if with_liquid:
        hops.append(Hop(kind="liquid"))
    return Pipeline(
        schema_version=10,
        source=Source(kind="ext-lightning"),
        hops=tuple(hops),
        exit=Exit(kind="reverse", destination_address="bc1p…"),
        bin_amount_sat=250_000,
        delay_policy=DelayPolicy(min_seconds=3600),
        inter_leg_delay=InterLegDelay(),
    )


def test_min_tier_helper() -> None:
    assert min_tier("weak", "strong") == "weak"
    assert min_tier("strong", "moderate") == "moderate"
    assert min_tier("strong", "strong") == "strong"


def test_quantize_to_bin_rounds_down() -> None:
    bins = [50_000, 100_000, 250_000, 500_000]
    assert quantize_to_bin(74_000, bins) == 50_000
    assert quantize_to_bin(250_000, bins) == 250_000
    assert quantize_to_bin(490_000, bins) == 250_000
    assert quantize_to_bin(40_000, bins) == 0  # below smallest


def test_strong_pipeline_with_strong_env_scores_strong() -> None:
    p = _ln_pipeline(with_priv_channel=True, with_liquid=True)
    r = score(p, _strong_env())
    assert r.tier == "strong"
    assert r.cap == "strong"
    assert r.points >= 6


def test_unbinned_amount_caps_at_weak() -> None:
    """Amount-correlation across legs dominates without binning."""
    p = _ln_pipeline(with_priv_channel=True, with_liquid=True)
    r = score(p, _strong_env(amount_is_binned=False))
    assert r.tier == "weak"
    assert r.cap == "weak"
    assert any("binned" in n.lower() for n in r.notes)


def test_shared_tor_process_caps_at_moderate() -> None:
    """HSDir leak risk."""
    p = _ln_pipeline(with_priv_channel=True, with_liquid=True)
    r = score(p, _strong_env(tor_process_shared_with_lnd=True))
    assert r.cap == "moderate"
    assert r.tier == "moderate"


def test_public_chain_backend_caps_at_weak() -> None:
    p = _ln_pipeline(with_priv_channel=True, with_liquid=True)
    r = score(p, _strong_env(public_chain_backend_enabled=True))
    assert r.cap == "weak"
    assert r.tier == "weak"


def test_exact_audit_logs_caps_at_weak() -> None:
    p = _ln_pipeline(with_priv_channel=True, with_liquid=True)
    r = score(p, _strong_env(exact_audit_logs_enabled=True))
    assert r.cap == "weak"


def test_uncommon_destination_script_caps_at_moderate() -> None:
    p = _ln_pipeline(with_priv_channel=True, with_liquid=True)
    r = score(p, _strong_env(destination_script_type="p2sh-p2wpkh"))
    assert r.cap == "moderate"


def test_concurrent_in_flight_caps_at_moderate() -> None:
    p = _ln_pipeline(with_priv_channel=True, with_liquid=True)
    r = score(p, _strong_env(in_flight_concurrent_sessions=2))
    assert r.cap == "moderate"


def test_chain_anchor_redaction_disabled_caps_at_weak() -> None:
    """CRITICAL: output_txid retention nullifies destination redaction."""
    p = _ln_pipeline(with_priv_channel=True, with_liquid=True)
    r = score(p, _strong_env(chain_anchor_redaction_disabled=True))
    assert r.cap == "weak"


def test_low_volume_operator_caps_at_moderate() -> None:
    """Operator-volume dilution floor.

    A non-zero but below-threshold attestation produces the
    "actually-low-volume" copy that tells the user the operator
    published a number and it's smaller than this bin needs.
    """
    p = _ln_pipeline(with_priv_channel=True, with_liquid=True)
    # Multiple = 100; bin_amount = 250_000; threshold = 25_000_000.
    # Set attested below.
    r = score(p, _strong_env(operator_min_attested_volume_satoshis=10_000_000))
    assert r.cap == "moderate"
    # Exactly one note must mention the dilution floor; it MUST be the
    # "below the dilution floor" variant, NOT the v1-default "unknown
    # volume" variant.
    dilution_notes = [n for n in r.notes if "dilution" in n.lower()]
    assert len(dilution_notes) == 1
    assert "below" in dilution_notes[0].lower()


# ── volume-cap scoring (reverse-leg-only model) ────────


def test_low_reverse_volume_caps_tier_to_moderate() -> None:
    """Reverse below threshold caps the tier; submarine note
    does NOT fire when submarine volume is well above threshold."""
    p = _ln_pipeline(with_priv_channel=True, with_liquid=True)
    # bin=250_000 * multiplier=100 = threshold=25M. Reverse below,
    # submarine well above.
    r = score(
        p,
        _strong_env(
            has_onchain_source=True,
            reverse_attested_volume_satoshis=10_000_000,
            submarine_attested_volume_satoshis=10_000_000_000,
        ),
    )
    assert r.cap == "moderate"
    joined = " ".join(r.notes).lower()
    assert "reverse-leg operator" in joined
    assert "submarine-leg operator processes" not in joined


def test_low_submarine_volume_does_not_cap_tier() -> None:
    """Submarine below threshold fires soft note WITHOUT
    capping the tier (reverse-leg drives the cap)."""
    p = _ln_pipeline(with_priv_channel=True, with_liquid=True)
    r = score(
        p,
        _strong_env(
            has_onchain_source=True,
            reverse_attested_volume_satoshis=10_000_000_000,
            submarine_attested_volume_satoshis=2_000_000,
        ),
    )
    # No cap from volume — pipeline still reaches strong.
    assert r.cap == "strong"
    joined = " ".join(r.notes).lower()
    assert "submarine-leg operator processes" in joined


def test_low_both_volumes_caps_and_fires_both_notes() -> None:
    """Both below threshold: tier capped (reverse),
    both notes present in order (reverse first, submarine second)."""
    p = _ln_pipeline(with_priv_channel=True, with_liquid=True)
    r = score(
        p,
        _strong_env(
            has_onchain_source=True,
            reverse_attested_volume_satoshis=10_000_000,
            submarine_attested_volume_satoshis=2_000_000,
        ),
    )
    assert r.cap == "moderate"
    notes_joined = " ".join(r.notes).lower()
    assert "reverse-leg operator" in notes_joined
    assert "submarine-leg operator processes" in notes_joined
    # Order check: reverse-leg note appears before submarine-leg note.
    reverse_idx = next(i for i, n in enumerate(r.notes) if "reverse-leg operator" in n.lower())
    submarine_idx = next(i for i, n in enumerate(r.notes) if "submarine-leg operator processes" in n.lower())
    assert reverse_idx < submarine_idx


def test_submarine_note_suppressed_for_lnonly_session() -> None:
    """LN-only sessions have no submarine leg; the soft
    note must NOT fire even if submarine volume happens to be 0."""
    p = _ln_pipeline(with_priv_channel=True, with_liquid=True)
    r = score(
        p,
        _strong_env(
            has_onchain_source=False,
            reverse_attested_volume_satoshis=10_000_000_000,
            submarine_attested_volume_satoshis=0,
        ),
    )
    joined = " ".join(r.notes).lower()
    assert "submarine-leg operator processes" not in joined


def test_submarine_note_suppressed_for_zero_submarine_volume() -> None:
    """The soft note's ``> 0`` guard suppresses it for the
    single-operator-fallback path where the consolidated target's
    submarine attested volume is recorded as 0."""
    p = _ln_pipeline(with_priv_channel=True, with_liquid=True)
    r = score(
        p,
        _strong_env(
            has_onchain_source=True,
            reverse_attested_volume_satoshis=10_000_000_000,
            submarine_attested_volume_satoshis=0,
        ),
    )
    joined = " ".join(r.notes).lower()
    assert "submarine-leg operator processes" not in joined


def test_estimated_sessions_floor_at_one() -> None:
    """When submarine volume is below the bin amount, the
    estimated sessions calculation floors at 1 (not 0)."""
    p = _ln_pipeline(with_priv_channel=True, with_liquid=True)
    # bin=250_000, submarine_volume=100_000 → 100_000 // 250_000 = 0.
    # The note must report "1 session(s)", not "0".
    r = score(
        p,
        _strong_env(
            has_onchain_source=True,
            reverse_attested_volume_satoshis=10_000_000_000,
            submarine_attested_volume_satoshis=100_000,
        ),
    )
    submarine_note = next(
        (n for n in r.notes if "submarine-leg operator processes" in n.lower()),
        "",
    )
    assert "about 1 session" in submarine_note


def test_reverse_zero_volume_copy_says_does_not_currently_publish() -> None:
    """Zero reverse volume uses the "does not currently publish"
    copy, not the "below dilution floor" copy."""
    p = _ln_pipeline(with_priv_channel=True, with_liquid=True)
    r = score(p, _strong_env(reverse_attested_volume_satoshis=0))
    assert r.cap == "moderate"
    joined = " ".join(r.notes).lower()
    assert "does not currently publish" in joined
    assert "below the dilution floor" not in joined


def test_unknown_volume_caps_at_moderate_with_explanatory_copy() -> None:
    """When the
    reverse-leg operator has not published a 24-hour swap volume
    attestation (volume = 0), the scorer caps the tier
    conservatively. The user-facing note must distinguish "we
    haven't received a number" from "operator told us a low number"
    — otherwise non-technical users would read the cap as a
    statement about the operator rather than a statement about
    missing data.
    """
    p = _ln_pipeline(with_priv_channel=True, with_liquid=True)
    r = score(p, _strong_env(operator_min_attested_volume_satoshis=0))
    assert r.cap == "moderate"
    # The note must NOT use the "below the dilution floor" wording.
    joined = " ".join(r.notes).lower()
    assert "below the dilution floor" not in joined
    # And it MUST explain that the cap is precautionary, not
    # because a low number was observed.
    assert any("does not currently publish" in n.lower() for n in r.notes)
