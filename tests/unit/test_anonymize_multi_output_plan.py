# SPDX-License-Identifier: MIT
"""Multi-output session plan validation + persistence.

Covers:

* :func:`validate_multi_output_plan` — refusal of empty / over-cap /
  duplicate-address / non-binned / non-positive plans.
* :func:`sample_schedule_offsets_s` — band, sortedness, inverted-
  config degenerate path.
* :func:`persist_outputs` — writes one row per output, monotonic
  ``output_index``, ``UNIQUE(session_id, output_index)`` enforcement.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from sqlalchemy import select

from app.core.config import settings
from app.models.anonymize_session import (
    AnonymizeSession,
    AnonymizeSessionOutput,
    AnonymizeStatus,
)
from app.services.anonymize.multi_output_plan import (
    MultiOutputPlan,
    MultiOutputPlanError,
    MultiOutputQuoteRequest,
    OutputSpec,
    build_multi_output_plan_from_request,
    persist_outputs,
    sample_schedule_offsets_s,
    validate_multi_output_plan,
)


def _spec(*, addr: str = "addr-A", amount: int = 100_000) -> OutputSpec:
    return OutputSpec(
        destination_address=addr,
        destination_script_type="p2tr",
        bin_amount_sat=amount,
    )


def _plan(specs: list[OutputSpec]) -> MultiOutputPlan:
    return MultiOutputPlan(session_id=uuid4(), outputs=specs)


# ── validate_multi_output_plan ──────────────────────────────────────


def test_validate_refuses_empty_plan() -> None:
    with pytest.raises(MultiOutputPlanError):
        validate_multi_output_plan(_plan([]))


def test_validate_refuses_over_cap(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_multi_output_max_count", 2)
    specs = [
        _spec(addr="a", amount=100_000),
        _spec(addr="b", amount=100_000),
        _spec(addr="c", amount=100_000),
    ]
    with pytest.raises(MultiOutputPlanError) as exc:
        validate_multi_output_plan(_plan(specs))
    assert "MULTI_OUTPUT_MAX_COUNT" in str(exc.value)


def test_validate_refuses_total_over_aggregate_cap(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_multi_output_max_total_sat", 250_000)
    specs = [
        _spec(addr="a", amount=100_000),
        _spec(addr="b", amount=100_000),
        _spec(addr="c", amount=100_000),
    ]
    with pytest.raises(MultiOutputPlanError) as exc:
        validate_multi_output_plan(_plan(specs))
    assert "MULTI_OUTPUT_MAX_TOTAL_SAT" in str(exc.value)


def test_validate_admits_total_at_aggregate_cap(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_multi_output_max_total_sat", 300_000)
    specs = [
        _spec(addr="a", amount=100_000),
        _spec(addr="b", amount=100_000),
        _spec(addr="c", amount=100_000),
    ]
    # Sum equals the ceiling exactly — admitted.
    validate_multi_output_plan(_plan(specs))


def test_validate_refuses_duplicate_addresses() -> None:
    specs = [
        _spec(addr="same", amount=100_000),
        _spec(addr="same", amount=100_000),
    ]
    with pytest.raises(MultiOutputPlanError) as exc:
        validate_multi_output_plan(_plan(specs))
    assert "duplicate" in str(exc.value).lower()


def test_validate_refuses_non_binned_amounts(monkeypatch) -> None:
    monkeypatch.setattr(
        settings,
        "anonymize_amount_bins_sat",
        "100000,250000",
    )
    specs = [_spec(addr="a", amount=187_654)]  # not in {100k, 250k}
    with pytest.raises(MultiOutputPlanError) as exc:
        validate_multi_output_plan(_plan(specs))
    assert "AMOUNT_BINS_SAT" in str(exc.value)


def test_validate_refuses_non_positive_amount() -> None:
    specs = [_spec(addr="a", amount=0)]
    with pytest.raises(MultiOutputPlanError):
        validate_multi_output_plan(_plan(specs))


def test_validate_refuses_empty_address() -> None:
    specs = [_spec(addr="", amount=100_000)]
    with pytest.raises(MultiOutputPlanError) as exc:
        validate_multi_output_plan(_plan(specs))
    assert "destination_address" in str(exc.value)


def test_validate_refuses_empty_script_type() -> None:
    spec = OutputSpec(
        destination_address="addr-a",
        destination_script_type="",
        bin_amount_sat=100_000,
    )
    with pytest.raises(MultiOutputPlanError) as exc:
        validate_multi_output_plan(_plan([spec]))
    assert "destination_script_type" in str(exc.value)


def test_validate_admits_valid_plan(monkeypatch) -> None:
    monkeypatch.setattr(
        settings,
        "anonymize_amount_bins_sat",
        "50000,100000,250000,500000,1000000",
    )
    monkeypatch.setattr(settings, "anonymize_multi_output_max_count", 5)
    specs = [
        _spec(addr="a", amount=100_000),
        _spec(addr="b", amount=250_000),
        _spec(addr="c", amount=500_000),
    ]
    validate_multi_output_plan(_plan(specs))


# ── sample_schedule_offsets_s ───────────────────────────────────────


def test_sample_offsets_empty_n_returns_empty() -> None:
    assert sample_schedule_offsets_s(0) == []


def test_sample_offsets_within_band(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_multi_output_schedule_min_s", 3600)
    monkeypatch.setattr(settings, "anonymize_multi_output_schedule_max_s", 7200)
    out = sample_schedule_offsets_s(5, now_unix_s=0.0)
    assert len(out) == 5
    for v in out:
        assert 3600 <= v <= 7200


def test_sample_offsets_returned_sorted_ascending(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_multi_output_schedule_min_s", 1000)
    monkeypatch.setattr(settings, "anonymize_multi_output_schedule_max_s", 9000)
    out = sample_schedule_offsets_s(10, now_unix_s=0.0)
    assert out == sorted(out)


def test_sample_offsets_inverted_config_degenerates_to_min(monkeypatch) -> None:
    """Misconfigured max < min — the helper degenerates rather than
    raising so an operator who fat-fingers a knob can still ship."""
    monkeypatch.setattr(settings, "anonymize_multi_output_schedule_min_s", 3600)
    monkeypatch.setattr(settings, "anonymize_multi_output_schedule_max_s", 60)
    out = sample_schedule_offsets_s(3, now_unix_s=0.0)
    assert out == [3600.0, 3600.0, 3600.0]


# ── persist_outputs ─────────────────────────────────────────────────


def _session() -> AnonymizeSession:
    return AnonymizeSession(
        id=uuid4(),
        status=AnonymizeStatus.CREATED.value,
        source_kind="onchain-self",
        requested_amount_sat=850_000,
        bin_amount_sat=100_000,  # mirror of output_index=0
        pipeline_json={},
        quote_hmac=b"x" * 32,
        destination_address_enc=b"ct-singular",
        destination_script_type="p2tr",
        pipeline_schema_version=10,
        destination_address_blake2b_keyed=b"\xab" * 32,
        destination_reuse_key_generation=0,
    )


@pytest.mark.asyncio
async def test_persist_writes_one_row_per_output(
    db_session,
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        settings,
        "anonymize_amount_bins_sat",
        "100000,250000,500000",
    )
    sess = _session()
    db_session.add(sess)
    await db_session.flush()
    specs = [
        _spec(addr="addr-a", amount=100_000),
        _spec(addr="addr-b", amount=250_000),
        _spec(addr="addr-c", amount=500_000),
    ]
    plan = MultiOutputPlan(session_id=sess.id, outputs=specs)
    await persist_outputs(
        db_session,
        plan=plan,
        encrypt_address=lambda s: ("enc:" + s).encode("utf-8"),
        blake2b_keyed=lambda s: ("hash:" + s).encode("utf-8") + b"\x00" * 28,
        reuse_key_generation=0,
        schedule_offsets_unix_s=[1.0, 2.0, 3.0],
    )
    await db_session.commit()
    rows = (
        (
            await db_session.execute(
                select(AnonymizeSessionOutput)
                .where(AnonymizeSessionOutput.session_id == sess.id)
                .order_by(AnonymizeSessionOutput.output_index)
            )
        )
        .scalars()
        .all()
    )
    assert [r.output_index for r in rows] == [0, 1, 2]
    assert [r.bin_amount_sat for r in rows] == [100_000, 250_000, 500_000]
    assert [r.scheduled_at_unix_s for r in rows] == [1.0, 2.0, 3.0]
    assert rows[0].destination_address_enc == b"enc:addr-a"
    assert rows[0].destination_address_blake2b_keyed.startswith(b"hash:addr-a")


@pytest.mark.asyncio
async def test_persist_refuses_mismatched_schedule_length(
    db_session,
) -> None:
    sess = _session()
    db_session.add(sess)
    await db_session.flush()
    specs = [_spec(addr="a", amount=100_000), _spec(addr="b", amount=100_000)]
    plan = MultiOutputPlan(session_id=sess.id, outputs=specs)
    with pytest.raises(MultiOutputPlanError):
        await persist_outputs(
            db_session,
            plan=plan,
            encrypt_address=lambda s: b"x",
            blake2b_keyed=lambda s: b"\x00" * 32,
            reuse_key_generation=0,
            schedule_offsets_unix_s=[1.0],  # length mismatch
        )


@pytest.mark.asyncio
async def test_persist_allows_null_schedule(db_session) -> None:
    """When schedule offsets are unknown at plan time, the column
    stays NULL — the orchestrator fills it later when the egress
    pipeline takes ownership."""
    sess = _session()
    db_session.add(sess)
    await db_session.flush()
    specs = [_spec(addr="a", amount=100_000)]
    plan = MultiOutputPlan(session_id=sess.id, outputs=specs)
    await persist_outputs(
        db_session,
        plan=plan,
        encrypt_address=lambda s: b"x",
        blake2b_keyed=lambda s: b"\x00" * 32,
        reuse_key_generation=0,
        schedule_offsets_unix_s=None,
    )
    await db_session.commit()
    row = (
        await db_session.execute(select(AnonymizeSessionOutput).where(AnonymizeSessionOutput.session_id == sess.id))
    ).scalar_one()
    assert row.scheduled_at_unix_s is None


# ── build_multi_output_plan_from_request ────────────────────────────


_REGTEST_P2TR = "bcrt1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqc8gma6"
_REGTEST_P2WPKH = "bcrt1qqyqszqgpqyqszqgpqyqszqgpqyqszqgpvxat9t"
_REGTEST_P2WSH = "bcrt1qqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqezzy8c"


def _multi_req(
    *,
    destinations: list[tuple[str, int]],
    source_kind: str = "lightning-self",
) -> MultiOutputQuoteRequest:
    return MultiOutputQuoteRequest(
        source_kind=source_kind,
        destinations=destinations,
        cookie_subject="cookie-abc",
        canonical_request_body=b"{}",
    )


def test_build_plan_admits_two_distinct_destinations(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_min_sat", 50_000)
    monkeypatch.setattr(settings, "anonymize_max_sat", 10_000_000)
    monkeypatch.setattr(
        settings,
        "anonymize_amount_bins_sat",
        "50000,100000,250000,500000,1000000",
    )
    req = _multi_req(
        destinations=[
            (_REGTEST_P2TR, 100_000),
            (_REGTEST_P2WPKH, 250_000),
        ]
    )
    sid = uuid4()
    plan = build_multi_output_plan_from_request(req, session_id=sid)
    assert plan.session_id == sid
    assert len(plan.outputs) == 2
    assert plan.outputs[0].destination_address == _REGTEST_P2TR
    assert plan.outputs[0].destination_script_type == "p2tr"
    assert plan.outputs[0].bin_amount_sat == 100_000
    assert plan.outputs[1].destination_address == _REGTEST_P2WPKH
    assert plan.outputs[1].destination_script_type == "p2wpkh"
    assert plan.outputs[1].bin_amount_sat == 250_000


def test_build_plan_refuses_empty_destinations() -> None:
    req = _multi_req(destinations=[])
    with pytest.raises(MultiOutputPlanError):
        build_multi_output_plan_from_request(req, session_id=uuid4())


def test_build_plan_refuses_unsupported_source_kind() -> None:
    req = _multi_req(
        source_kind="kafkaesque",
        destinations=[(_REGTEST_P2TR, 100_000)],
    )
    with pytest.raises(MultiOutputPlanError) as exc:
        build_multi_output_plan_from_request(req, session_id=uuid4())
    assert "source kind" in str(exc.value)


def test_build_plan_refuses_amount_outside_range(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_min_sat", 50_000)
    monkeypatch.setattr(settings, "anonymize_max_sat", 10_000_000)
    req = _multi_req(destinations=[(_REGTEST_P2TR, 1)])
    with pytest.raises(MultiOutputPlanError) as exc:
        build_multi_output_plan_from_request(req, session_id=uuid4())
    assert "outside" in str(exc.value)


def test_build_plan_refuses_malformed_destination(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_min_sat", 50_000)
    monkeypatch.setattr(settings, "anonymize_max_sat", 10_000_000)
    req = _multi_req(destinations=[("not-a-real-address", 100_000)])
    with pytest.raises(MultiOutputPlanError) as exc:
        build_multi_output_plan_from_request(req, session_id=uuid4())
    assert "destination rejected" in str(exc.value)


def test_build_plan_quantizes_requested_amount_to_bin(monkeypatch) -> None:
    """A requested amount slightly below a bin gets quantized up."""
    monkeypatch.setattr(settings, "anonymize_min_sat", 50_000)
    monkeypatch.setattr(settings, "anonymize_max_sat", 10_000_000)
    monkeypatch.setattr(
        settings,
        "anonymize_amount_bins_sat",
        "50000,100000,250000,500000",
    )
    req = _multi_req(destinations=[(_REGTEST_P2TR, 99_999)])
    plan = build_multi_output_plan_from_request(req, session_id=uuid4())
    # Quantizer picks the smallest bin >= requested (or the closest bin).
    assert plan.outputs[0].bin_amount_sat in {50_000, 100_000}


def test_build_plan_refuses_duplicate_destinations(monkeypatch) -> None:
    """Two outputs to the same address — caught by the validator."""
    monkeypatch.setattr(settings, "anonymize_min_sat", 50_000)
    monkeypatch.setattr(settings, "anonymize_max_sat", 10_000_000)
    monkeypatch.setattr(
        settings,
        "anonymize_amount_bins_sat",
        "100000,250000",
    )
    req = _multi_req(
        destinations=[
            (_REGTEST_P2TR, 100_000),
            (_REGTEST_P2TR, 250_000),
        ]
    )
    with pytest.raises(MultiOutputPlanError) as exc:
        build_multi_output_plan_from_request(req, session_id=uuid4())
    assert "duplicate" in str(exc.value).lower()


def test_build_plan_refuses_over_cap(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_min_sat", 50_000)
    monkeypatch.setattr(settings, "anonymize_max_sat", 10_000_000)
    monkeypatch.setattr(
        settings,
        "anonymize_amount_bins_sat",
        "100000,250000,500000",
    )
    monkeypatch.setattr(settings, "anonymize_multi_output_max_count", 1)
    req = _multi_req(
        destinations=[
            (_REGTEST_P2TR, 100_000),
            (_REGTEST_P2WPKH, 250_000),
        ]
    )
    with pytest.raises(MultiOutputPlanError) as exc:
        build_multi_output_plan_from_request(req, session_id=uuid4())
    assert "MULTI_OUTPUT_MAX_COUNT" in str(exc.value)


@pytest.mark.asyncio
async def test_unique_index_blocks_duplicate_output_index(
    db_session,
) -> None:
    """The DB-level ``UNIQUE(session_id, output_index)`` defends against
    a mid-pipeline retry inserting a duplicate row."""
    sess = _session()
    db_session.add(sess)
    await db_session.flush()
    specs = [_spec(addr="a", amount=100_000)]
    plan = MultiOutputPlan(session_id=sess.id, outputs=specs)
    await persist_outputs(
        db_session,
        plan=plan,
        encrypt_address=lambda s: b"x",
        blake2b_keyed=lambda s: b"\x00" * 32,
        reuse_key_generation=0,
        schedule_offsets_unix_s=None,
    )
    await db_session.commit()
    # Manually attempt a second row at output_index=0.
    db_session.add(
        AnonymizeSessionOutput(
            session_id=sess.id,
            output_index=0,
            destination_address_enc=b"x",
            destination_script_type="p2tr",
            bin_amount_sat=100_000,
            destination_address_blake2b_keyed=b"\x00" * 32,
            destination_reuse_key_generation=0,
        )
    )
    with pytest.raises(Exception):
        await db_session.commit()
