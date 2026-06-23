# SPDX-License-Identifier: MIT
"""/ items 26 + 53 — frozen pipeline persistence + size cap.

Round-trip a Pipeline through ``pipeline_to_json`` /
``pipeline_from_json``, verify schema-version forward-compat
gating, and assert the byte-size limit applies.
"""

from __future__ import annotations

import pytest

from app.services.anonymize.pipelines import (
    DelayPolicy,
    Exit,
    Hop,
    InterLegDelay,
    Pipeline,
    PipelineSchemaTooOldError,
    PipelineValidationError,
    Source,
    pipeline_from_json,
    pipeline_to_json,
    validate_pipeline,
)


def _sample_pipeline(*, schema_version: int = 10) -> Pipeline:
    return Pipeline(
        schema_version=schema_version,
        source=Source(kind="ext-lightning"),
        hops=(Hop(kind="ln_self_pay", params={"channel_id": 7}),),
        exit=Exit(
            kind="reverse",
            destination_address="bcrt1qexample",
            cooperative_only=True,
        ),
        bin_amount_sat=250_000,
        delay_policy=DelayPolicy(min_seconds=3600, max_seconds=21600),
        inter_leg_delay=InterLegDelay(min_seconds=21600, max_seconds=172800),
    )


def test_pipeline_roundtrips_through_canonical_json() -> None:
    p = _sample_pipeline()
    encoded = pipeline_to_json(p)
    assert isinstance(encoded, bytes)
    # Canonical (sorted-keys, no whitespace) — sanity check.
    assert b" " not in encoded.split(b'"', 1)[0]  # no leading whitespace
    decoded = pipeline_from_json(encoded, min_supported_schema_version=10)
    assert decoded == p


def test_pipeline_from_json_accepts_dict_payload() -> None:
    p = _sample_pipeline()
    encoded = pipeline_to_json(p)
    import json

    obj = json.loads(encoded)
    assert pipeline_from_json(obj, min_supported_schema_version=10) == p


def test_pipeline_schema_too_old_raises() -> None:
    """Too-old schema routes to awaiting_reconciliation."""
    p = _sample_pipeline(schema_version=9)
    encoded = pipeline_to_json(p)
    with pytest.raises(PipelineSchemaTooOldError):
        pipeline_from_json(encoded, min_supported_schema_version=10)


def test_validate_pipeline_enforces_byte_cap() -> None:
    """Pipeline_json bytes ≤ ANONYMIZE_MAX_PIPELINE_JSON_BYTES."""
    # Build a tiny pipeline; set the cap below the encoded size.
    p = _sample_pipeline()
    encoded_size = len(pipeline_to_json(p))
    with pytest.raises(PipelineValidationError, match="pipeline_json size"):
        validate_pipeline(p, max_hops=6, max_pipeline_json_bytes=encoded_size - 1)


def test_validate_pipeline_passes_under_byte_cap() -> None:
    p = _sample_pipeline()
    encoded_size = len(pipeline_to_json(p))
    validate_pipeline(p, max_hops=6, max_pipeline_json_bytes=encoded_size + 100)


def test_validate_pipeline_max_hops_still_enforced_with_byte_cap() -> None:
    too_many = tuple(Hop(kind="ln_self_pay") for _ in range(7))
    p = Pipeline(
        schema_version=10,
        source=Source(kind="lightning-self"),
        hops=too_many,
        exit=Exit(kind="reverse", destination_address="bc1q…"),
        bin_amount_sat=100_000,
        delay_policy=DelayPolicy(),
    )
    with pytest.raises(PipelineValidationError, match="max_hops"):
        validate_pipeline(p, max_hops=6, max_pipeline_json_bytes=100_000)


def test_bolt12_pay_exit_roundtrips_through_canonical_json() -> None:
    """The BOLT 12-exit fields (offer + handle) survive the
    canonical-JSON round-trip so a session created under bolt12_pay
    can re-hydrate cleanly after a worker restart."""
    p = Pipeline(
        schema_version=10,
        source=Source(kind="ext-lightning"),
        hops=(),
        exit=Exit(
            kind="bolt12_pay",
            destination_address="",
            cooperative_only=True,
            bolt12_offer="lno1deadbeef",
            bip353_handle="alice@example.com",
        ),
        bin_amount_sat=250_000,
        delay_policy=DelayPolicy(),
        inter_leg_delay=None,
    )
    encoded = pipeline_to_json(p)
    decoded = pipeline_from_json(encoded, min_supported_schema_version=10)
    assert decoded == p
    assert decoded.exit.kind == "bolt12_pay"
    assert decoded.exit.bolt12_offer == "lno1deadbeef"
    assert decoded.exit.bip353_handle == "alice@example.com"


def test_legacy_pipeline_without_bolt12_fields_still_decodes() -> None:
    """An older row that predates the BOLT 12 fields must still
    decode — ``pipeline_from_json`` defaults the new fields to None."""
    import json

    legacy = {
        "schema_version": 10,
        "source": {
            "kind": "ext-lightning",
            "selected_outpoints": [],
            "deposit_invoice": None,
            "deposit_address": None,
        },
        "hops": [],
        "exit": {
            "kind": "reverse",
            "destination_address": "bcrt1qlegacy",
            "cooperative_only": True,
        },
        "bin_amount_sat": 250_000,
        "delay_policy": {
            "kind": "uniform",
            "min_seconds": 3600,
            "max_seconds": 21600,
            "scheduled_start": None,
            "scheduled_end": None,
            "utc_window_start_hour": None,
            "utc_window_end_hour": None,
        },
        "inter_leg_delay": None,
    }
    decoded = pipeline_from_json(
        json.dumps(legacy).encode(),
        min_supported_schema_version=10,
    )
    assert decoded.exit.kind == "reverse"
    assert decoded.exit.bolt12_offer is None
    assert decoded.exit.bip353_handle is None
