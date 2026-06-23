# SPDX-License-Identifier: MIT
"""Task isolation wrapper + redactor.

The wrapper catches BaseException (except CancelledError) and returns
a TaskFailure carrying the redacted message. CancelledError must
re-raise so cooperative shutdown still works.
"""

from __future__ import annotations

import asyncio
from uuid import uuid4

import pytest

from app.services.anonymize.task_supervisor import (
    TaskFailure,
    redact_for_last_error,
    run_session_task_isolated,
)


def test_redactor_strips_bech32_addresses() -> None:
    text = "failed to encode bcrt1qexampleexampleexampleexampleexampleexampl"
    out = redact_for_last_error(text)
    assert "bcrt1q" not in out
    assert "<redacted>" in out


def test_redactor_strips_64_hex_runs() -> None:
    text = "txid=" + "ab" * 32 + " not found"
    out = redact_for_last_error(text)
    assert "ab" * 32 not in out
    assert "<redacted>" in out
    assert "not found" in out


def test_redactor_strips_secp256k1_pubkey() -> None:
    text = "peer 02" + "11" * 32 + " disconnected"
    out = redact_for_last_error(text)
    assert "02" + "11" * 32 not in out


def test_redactor_strips_v3_onion() -> None:
    # v3 onion = 56 base32 chars + ".onion".
    onion = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuv2d.onion"
    assert len(onion.split(".")[0]) == 56
    text = f"could not reach {onion}:80"
    out = redact_for_last_error(text)
    assert ".onion" not in out
    assert "<redacted>" in out


def test_redactor_handles_empty_string() -> None:
    assert redact_for_last_error("") == ""


def test_redactor_strips_legacy_p2pkh_address() -> None:
    """Genesis Satoshi address; canonical mainnet legacy P2PKH."""
    text = "destination=1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa was rejected"
    out = redact_for_last_error(text)
    assert "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" not in out


# ── isolation wrapper ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_isolated_task_returns_value_on_success() -> None:
    sid = uuid4()

    async def good() -> int:
        return 42

    out = await run_session_task_isolated(sid, good)
    assert out == 42


@pytest.mark.asyncio
async def test_isolated_task_returns_failure_on_exception() -> None:
    sid = uuid4()

    async def bad() -> None:
        raise RuntimeError("destination=bcrt1qexampleexampleexampleexampleexampleexample failed")

    out = await run_session_task_isolated(sid, bad)
    assert isinstance(out, TaskFailure)
    assert out.exception_class == "RuntimeError"
    assert out.session_id == sid
    # The persisted message must NOT contain the bech32 address.
    assert "bcrt1q" not in out.redacted_message
    assert "<redacted>" in out.redacted_message


@pytest.mark.asyncio
async def test_isolated_task_propagates_cancellation() -> None:
    """CancelledError must escape so cooperative shutdown works."""
    sid = uuid4()

    async def cancelled() -> None:
        raise asyncio.CancelledError

    with pytest.raises(asyncio.CancelledError):
        await run_session_task_isolated(sid, cancelled)


@pytest.mark.asyncio
async def test_isolated_task_handles_base_exception() -> None:
    """BaseException subclasses (other than CancelledError) are caught."""
    sid = uuid4()

    async def boom() -> None:
        raise SystemExit("we should not exit the orchestrator over one session")

    out = await run_session_task_isolated(sid, boom)
    assert isinstance(out, TaskFailure)
    assert out.exception_class == "SystemExit"
