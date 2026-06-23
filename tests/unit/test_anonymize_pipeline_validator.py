# SPDX-License-Identifier: MIT
"""Pipeline-validator tests normalization invariant.

Scope: validate that the pipeline taxonomy honors the
"on-chain source must traverse a submarine hop as the first hop, and
there is at most one submarine hop" rule. The rule is enforced both
at session-creation and re-asserted at hop-execution boundaries.
"""

from __future__ import annotations

import pytest

from app.services.anonymize.pipelines import (
    DelayPolicy,
    Exit,
    Hop,
    InterLegDelay,
    Pipeline,
    PipelineValidationError,
    Source,
    validate_pipeline,
)


def _make_pipeline(
    *,
    source_kind: str,
    hops: tuple[Hop, ...],
    bin_amount_sat: int = 250_000,
) -> Pipeline:
    return Pipeline(
        schema_version=10,
        source=Source(kind=source_kind),
        hops=hops,
        exit=Exit(kind="reverse", destination_address="bc1q…"),
        bin_amount_sat=bin_amount_sat,
        delay_policy=DelayPolicy(),
        inter_leg_delay=InterLegDelay(),
    )


def test_ln_source_with_no_hops_is_valid() -> None:
    """ext-lightning + reverse-only is the simplest valid Lightning self-source pipeline."""
    p = _make_pipeline(source_kind="ext-lightning", hops=())
    validate_pipeline(p, max_hops=6)


def test_ln_source_with_ln_self_pay_is_valid() -> None:
    p = _make_pipeline(
        source_kind="lightning-self",
        hops=(Hop(kind="ln_self_pay"),),
    )
    validate_pipeline(p, max_hops=6)


def test_ln_source_rejects_submarine_hop() -> None:
    """LN sources must never include a submarine hop."""
    p = _make_pipeline(
        source_kind="ext-lightning",
        hops=(Hop(kind="submarine"), Hop(kind="ln_self_pay")),
    )
    with pytest.raises(PipelineValidationError, match="must not include a submarine hop"):
        validate_pipeline(p, max_hops=6)


def test_onchain_source_requires_submarine_first_hop() -> None:
    """Onchain-self / ext-onchain must have submarine as the first hop."""
    p = _make_pipeline(
        source_kind="onchain-self",
        hops=(Hop(kind="ln_self_pay"),),
    )
    with pytest.raises(PipelineValidationError, match="requires a `submarine` first hop"):
        validate_pipeline(p, max_hops=6)


def test_onchain_source_with_proper_submarine_first_hop_is_valid() -> None:
    p = _make_pipeline(
        source_kind="ext-onchain",
        hops=(Hop(kind="submarine"), Hop(kind="ln_self_pay")),
    )
    validate_pipeline(p, max_hops=6)


def test_pipeline_rejects_more_than_one_submarine_hop() -> None:
    p = _make_pipeline(
        source_kind="onchain-self",
        hops=(Hop(kind="submarine"), Hop(kind="submarine")),
    )
    with pytest.raises(PipelineValidationError, match="more than one submarine"):
        validate_pipeline(p, max_hops=6)


def test_pipeline_rejects_unknown_source_kind() -> None:
    p = _make_pipeline(source_kind="bogus", hops=())
    with pytest.raises(PipelineValidationError, match="unknown source"):
        validate_pipeline(p, max_hops=6)


def test_submarine_pipeline_rejects_missing_inter_leg_delay() -> None:
    """A submarine pipeline without an inter_leg_delay
    window violates the mandatory-delay invariant."""
    p = Pipeline(
        schema_version=10,
        source=Source(kind="onchain-self"),
        hops=(Hop(kind="submarine"),),
        exit=Exit(kind="reverse", destination_address="bc1q…"),
        bin_amount_sat=250_000,
        delay_policy=DelayPolicy(),
        inter_leg_delay=None,
    )
    with pytest.raises(PipelineValidationError, match="inter_leg_delay window"):
        validate_pipeline(p, max_hops=6)


def test_submarine_pipeline_rejects_zero_inter_leg_min() -> None:
    """Min_seconds must be positive."""
    p = Pipeline(
        schema_version=10,
        source=Source(kind="onchain-self"),
        hops=(Hop(kind="submarine"),),
        exit=Exit(kind="reverse", destination_address="bc1q…"),
        bin_amount_sat=250_000,
        delay_policy=DelayPolicy(),
        inter_leg_delay=InterLegDelay(min_seconds=0, max_seconds=3600),
    )
    with pytest.raises(PipelineValidationError, match="min_seconds must be positive"):
        validate_pipeline(p, max_hops=6)


def test_submarine_pipeline_rejects_inverted_inter_leg_bounds() -> None:
    p = Pipeline(
        schema_version=10,
        source=Source(kind="onchain-self"),
        hops=(Hop(kind="submarine"),),
        exit=Exit(kind="reverse", destination_address="bc1q…"),
        bin_amount_sat=250_000,
        delay_policy=DelayPolicy(),
        inter_leg_delay=InterLegDelay(min_seconds=7200, max_seconds=3600),
    )
    with pytest.raises(PipelineValidationError, match="max_seconds must be >= min_seconds"):
        validate_pipeline(p, max_hops=6)


def test_ln_only_pipeline_does_not_require_inter_leg_delay() -> None:
    """LN-only pipelines (no submarine) don't need the inter-leg
    field — there's no on-chain leg to correlate against."""
    p = Pipeline(
        schema_version=10,
        source=Source(kind="ext-lightning"),
        hops=(),
        exit=Exit(kind="reverse", destination_address="bc1q…"),
        bin_amount_sat=250_000,
        delay_policy=DelayPolicy(),
        inter_leg_delay=None,
    )
    validate_pipeline(p, max_hops=6)


def test_pipeline_max_hops_bound() -> None:
    """Pipeline-shape resource bound."""
    too_many = tuple(Hop(kind="ln_self_pay") for _ in range(7))
    p = _make_pipeline(source_kind="lightning-self", hops=too_many)
    with pytest.raises(PipelineValidationError, match="max_hops"):
        validate_pipeline(p, max_hops=6)


# ── BOLT 12-exit pipelines ──────────────────────────────────


def _make_bolt12_pipeline(
    *,
    source_kind: str = "ext-lightning",
    hops: tuple[Hop, ...] = (),
    offer: str = "lno1deadbeef",
    bip353_handle: str | None = "alice@example.com",
) -> Pipeline:
    return Pipeline(
        schema_version=10,
        source=Source(kind=source_kind),
        hops=hops,
        exit=Exit(
            kind="bolt12_pay",
            destination_address="",
            bolt12_offer=offer,
            bip353_handle=bip353_handle,
        ),
        bin_amount_sat=250_000,
        delay_policy=DelayPolicy(),
        inter_leg_delay=None,
    )


def test_bolt12_pay_exit_with_ln_source_is_valid() -> None:
    """The supported shape: LN source + bolt12_pay exit + non-empty offer."""
    p = _make_bolt12_pipeline()
    validate_pipeline(p, max_hops=6)


def test_bolt12_pay_exit_with_onchain_source_rejected() -> None:
    """An on-chain source with bolt12_pay exit is refused — the
    submarine + bolt12_pay composition isn't wired yet."""
    p = _make_bolt12_pipeline(
        source_kind="onchain-self",
        hops=(Hop(kind="submarine"),),
    )
    with pytest.raises(PipelineValidationError, match="LN source"):
        validate_pipeline(p, max_hops=6)


def test_bolt12_pay_exit_without_offer_rejected() -> None:
    """An exit with kind=bolt12_pay but no offer is refused
    (validation runs at quote-build + session-create boundaries)."""
    p = _make_bolt12_pipeline(offer="")
    with pytest.raises(PipelineValidationError, match="bolt12_offer"):
        validate_pipeline(p, max_hops=6)


def test_bolt12_pay_exit_invalid_kind_rejected() -> None:
    """A malformed ``exit.kind`` is refused."""
    p = Pipeline(
        schema_version=10,
        source=Source(kind="ext-lightning"),
        hops=(),
        exit=Exit(kind="other_kind", destination_address="bc1q…"),  # type: ignore[arg-type]
        bin_amount_sat=250_000,
        delay_policy=DelayPolicy(),
        inter_leg_delay=None,
    )
    with pytest.raises(PipelineValidationError, match="exit kind"):
        validate_pipeline(p, max_hops=6)


# ── ext-lightning deposit-method ──────────────────


def _make_ext_lightning_pipeline(
    *,
    deposit_invoice: str | None = None,
    deposit_bolt12_offer: str | None = None,
    deposit_bip353_handle: str | None = None,
) -> Pipeline:
    return Pipeline(
        schema_version=10,
        source=Source(
            kind="ext-lightning",
            deposit_invoice=deposit_invoice,
            deposit_bolt12_offer=deposit_bolt12_offer,
            deposit_bip353_handle=deposit_bip353_handle,
        ),
        hops=(),
        exit=Exit(kind="reverse", destination_address="bc1q…"),
        bin_amount_sat=250_000,
        delay_policy=DelayPolicy(),
        inter_leg_delay=None,
    )


def test_ext_lightning_bolt11_only_is_valid() -> None:
    p = _make_ext_lightning_pipeline(deposit_invoice="lnbc100u")
    validate_pipeline(p, max_hops=6)


def test_ext_lightning_bolt12_only_is_valid() -> None:
    p = _make_ext_lightning_pipeline(deposit_bolt12_offer="lno1deadbeef")
    validate_pipeline(p, max_hops=6)


def test_ext_lightning_bolt11_and_bolt12_together_rejected() -> None:
    """Mutually-exclusive: the depositor can pay one or the other,
    not both — accepting both would let an attacker race payments."""
    p = _make_ext_lightning_pipeline(
        deposit_invoice="lnbc100u",
        deposit_bolt12_offer="lno1deadbeef",
    )
    with pytest.raises(PipelineValidationError, match="mutually exclusive"):
        validate_pipeline(p, max_hops=6)


def test_ext_lightning_bip353_handle_requires_bolt12_offer() -> None:
    """A BIP-353 handle is only meaningful when paired with a BOLT 12
    offer — the handle's DNS TXT record is what publishes the offer."""
    p = _make_ext_lightning_pipeline(
        deposit_invoice="lnbc100u",
        deposit_bip353_handle="session-abc@wallet.example.com",
    )
    with pytest.raises(PipelineValidationError, match="deposit_bip353_handle"):
        validate_pipeline(p, max_hops=6)


def test_ext_lightning_bip353_handle_with_bolt12_offer_is_valid() -> None:
    p = _make_ext_lightning_pipeline(
        deposit_bolt12_offer="lno1deadbeef",
        deposit_bip353_handle="session-abc@wallet.example.com",
    )
    validate_pipeline(p, max_hops=6)
