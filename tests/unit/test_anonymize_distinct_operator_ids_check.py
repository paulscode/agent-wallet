# SPDX-License-Identifier: MIT
"""/ Cluster K — distinct-operator-IDs DB CHECK.

The ``ck_anonymize_session_distinct_operator_ids`` constraint
refuses rows that pair the submarine + reverse legs with the same
operator id. NULL on either side passes (single-operator path).
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from sqlalchemy.exc import IntegrityError

from app.models.anonymize_session import AnonymizeSession, AnonymizeStatus


def _base_kwargs() -> dict:
    return {
        "id": uuid4(),
        "status": AnonymizeStatus.CREATED.value,
        "source_kind": "ext-onchain",
        "requested_amount_sat": 250_000,
        "bin_amount_sat": 250_000,
        "pipeline_json": {},
        "quote_hmac": b"x" * 32,
        "destination_address_enc": b"ct",
        "destination_script_type": "p2tr",
        "pipeline_schema_version": 10,
        "destination_address_blake2b_keyed": b"\xab" * 32,
        "destination_reuse_key_generation": 0,
    }


@pytest.mark.asyncio
async def test_check_admits_when_both_operator_ids_null(db_session) -> None:
    row = AnonymizeSession(
        **_base_kwargs(),
        submarine_operator_id=None,
        reverse_operator_id=None,
    )
    db_session.add(row)
    await db_session.commit()


@pytest.mark.asyncio
async def test_check_admits_when_only_reverse_set(db_session) -> None:
    row = AnonymizeSession(
        **_base_kwargs(),
        submarine_operator_id=None,
        reverse_operator_id="op-solo",
    )
    db_session.add(row)
    await db_session.commit()


@pytest.mark.asyncio
async def test_check_admits_distinct_operator_ids(db_session) -> None:
    row = AnonymizeSession(
        **_base_kwargs(),
        submarine_operator_id="op-alpha",
        reverse_operator_id="op-beta",
    )
    db_session.add(row)
    await db_session.commit()


@pytest.mark.asyncio
async def test_check_rejects_identical_operator_ids(db_session) -> None:
    row = AnonymizeSession(
        **_base_kwargs(),
        submarine_operator_id="op-shared",
        reverse_operator_id="op-shared",
    )
    db_session.add(row)
    with pytest.raises(IntegrityError):
        await db_session.commit()
