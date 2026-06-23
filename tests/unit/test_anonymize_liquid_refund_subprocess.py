# SPDX-License-Identifier: MIT
"""Tests for ``app.services.anonymize.liquid_refund_subprocess``.

Parallel to ``test_anonymize_liquid_claim_subprocess.py`` — the
wrapper is unit-tested in isolation by monkeypatching the underlying
``run_boltz_claim_js`` so no Node binary is spawned. Assertions
cover payload shape, the integration gate, mode dispatch, and error
modes.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from app.services.anonymize import liquid_refund_subprocess as mod
from app.services.anonymize import subprocess as anonsub


def _payload_request(**overrides: Any) -> mod.LiquidRefundRequest:
    base = dict(
        boltz_url="http://boltz.regtest",
        swap_id="swap-deadbeef",
        refund_private_key_hex="bb" * 32,
        swap_tree={
            "claimLeaf": {"version": 192, "output": "51" + "11" * 32},
            "refundLeaf": {"version": 192, "output": "51" + "22" * 32},
        },
        lockup_tx_hex="ff" * 50,
        refund_address="lq1qq..." + ("z" * 8),
        blinding_key_hex="dd" * 32,
        timeout_block_height=1234,
        network="regtest",
        claim_public_key_hex="02" + "cc" * 32,
    )
    base.update(overrides)
    return mod.LiquidRefundRequest(**base)


def _fake_subprocess_result(
    *,
    returncode: int = 0,
    stdout_redacted: bytes = (
        b'{"event":"liquid_submarine_refund_broadcast","mode":"cooperative","txid":"abc123","swapId":"x"}\n'
    ),
    stderr_redacted: bytes = b"",
    refund_tx_hex: str | None = "ffaa" * 32,
) -> anonsub.SubprocessResult:
    sentinel = anonsub._PROCESS_SENTINEL  # noqa: SLF001
    claim = anonsub.ClaimTxHex(value=refund_tx_hex, __sentinel__=sentinel)
    return anonsub.SubprocessResult(
        returncode=returncode,
        stdout_redacted=stdout_redacted,
        stderr_redacted=stderr_redacted,
        claim_tx_hex=claim,
    )


def _open_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        mod.settings,
        "anonymize_liquid_integration_verified",
        True,
        raising=False,
    )


# ── Gate behaviour ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_refuses_when_integration_gate_is_off(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        mod.settings,
        "anonymize_liquid_integration_verified",
        False,
        raising=False,
    )
    with pytest.raises(mod.LiquidIntegrationNotVerifiedError):
        await mod.run_liquid_refund_subprocess(_payload_request())


@pytest.mark.asyncio
async def test_proceeds_when_integration_gate_is_on(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _open_gate(monkeypatch)
    seen: dict[str, Any] = {}

    async def fake_run(*, args, cwd, timeout_s=None, stdin_payload=None, use_tx_out_file=False):
        seen["args"] = args
        seen["cwd"] = str(cwd)
        return _fake_subprocess_result()

    monkeypatch.setattr(mod, "run_boltz_claim_js", fake_run)
    result = await mod.run_liquid_refund_subprocess(_payload_request())
    assert result.txid == "abc123"
    assert result.mode == "cooperative"
    assert result.refund_tx_hex.startswith("ffaa")
    assert seen["args"] == ("scripts/submarine_refund_liquid.js",)
    assert (mod._repo_root() / "scripts" / "submarine_refund_liquid.js").exists()


# ── Payload shape ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_payload_uses_camelcase_wire_names(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Required snake_case Python fields translate to camelCase JS."""
    _open_gate(monkeypatch)
    captured: dict[str, Any] = {}

    async def fake_run(*, args, cwd, timeout_s=None, stdin_payload=None, use_tx_out_file=False):
        captured["stdin_payload"] = stdin_payload
        return _fake_subprocess_result()

    monkeypatch.setattr(mod, "run_boltz_claim_js", fake_run)
    req = _payload_request(
        asset_id_hex="ab" * 32,
        socks_proxy="socks5://127.0.0.1:9052",
        current_block_height=900,
        fee_rate_sat_per_vb=5,
    )
    await mod.run_liquid_refund_subprocess(req)
    body = json.loads(captured["stdin_payload"].decode("utf-8"))
    expected_required = {
        "boltzUrl",
        "swapId",
        "refundPrivateKey",
        "swapTree",
        "lockupTxHex",
        "refundAddress",
        "blindingKey",
        "timeoutBlockHeight",
        "network",
    }
    assert expected_required <= set(body.keys())
    assert body["claimPublicKey"] == "02" + "cc" * 32
    assert body["assetId"] == "ab" * 32
    assert body["socksProxy"] == "socks5://127.0.0.1:9052"
    assert body["currentBlockHeight"] == 900
    assert body["feeRate"] == 5


@pytest.mark.asyncio
async def test_payload_omits_optional_fields_when_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _open_gate(monkeypatch)
    captured: dict[str, Any] = {}

    async def fake_run(*, args, cwd, timeout_s=None, stdin_payload=None, use_tx_out_file=False):
        captured["stdin_payload"] = stdin_payload
        return _fake_subprocess_result()

    monkeypatch.setattr(mod, "run_boltz_claim_js", fake_run)
    await mod.run_liquid_refund_subprocess(
        _payload_request(claim_public_key_hex=None),
    )
    body = json.loads(captured["stdin_payload"].decode("utf-8"))
    assert "claimPublicKey" not in body
    assert "assetId" not in body
    assert "currentBlockHeight" not in body
    assert "feeRate" not in body
    assert "socksProxy" not in body
    assert "mode" not in body


# ── Mode dispatch ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_default_mode_omits_mode_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cooperative is default — payload must NOT carry a ``mode`` key
    so the JS-side destructure default applies."""
    _open_gate(monkeypatch)
    captured: dict[str, Any] = {}

    async def fake_run(*, args, cwd, timeout_s=None, stdin_payload=None, use_tx_out_file=False):
        captured["stdin_payload"] = stdin_payload
        return _fake_subprocess_result()

    monkeypatch.setattr(mod, "run_boltz_claim_js", fake_run)
    await mod.run_liquid_refund_subprocess(_payload_request())
    body = json.loads(captured["stdin_payload"].decode("utf-8"))
    assert "mode" not in body


@pytest.mark.asyncio
async def test_unilateral_mode_serializes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _open_gate(monkeypatch)
    captured: dict[str, Any] = {}

    async def fake_run(*, args, cwd, timeout_s=None, stdin_payload=None, use_tx_out_file=False):
        captured["stdin_payload"] = stdin_payload
        return _fake_subprocess_result(
            stdout_redacted=(
                b'{"event":"liquid_submarine_refund_broadcast","mode":"unilateral","txid":"uni_xyz","swapId":"x"}\n'
            ),
        )

    monkeypatch.setattr(mod, "run_boltz_claim_js", fake_run)
    res = await mod.run_liquid_refund_subprocess(
        _payload_request(mode="unilateral"),
    )
    body = json.loads(captured["stdin_payload"].decode("utf-8"))
    assert body["mode"] == "unilateral"
    assert res.mode == "unilateral"
    assert res.txid == "uni_xyz"


@pytest.mark.asyncio
async def test_unknown_mode_rejected_before_spawn(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unsupported modes are rejected at the Python boundary so the
    JS subprocess isn't even spawned with garbage."""
    _open_gate(monkeypatch)

    called = {"n": 0}

    async def fake_run(**_kwargs):
        called["n"] += 1
        return _fake_subprocess_result()

    monkeypatch.setattr(mod, "run_boltz_claim_js", fake_run)
    with pytest.raises(mod.LiquidRefundSubprocessError, match="unsupported"):
        await mod.run_liquid_refund_subprocess(
            _payload_request(mode="bogus"),
        )
    assert called["n"] == 0


# ── Error modes ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_nonzero_exit_raises_with_stderr_redacted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _open_gate(monkeypatch)

    async def fake_run(**_kwargs):
        return _fake_subprocess_result(
            returncode=4,
            stderr_redacted=b"<redacted-hex> broke",
        )

    monkeypatch.setattr(mod, "run_boltz_claim_js", fake_run)
    with pytest.raises(mod.LiquidRefundSubprocessError) as exc_info:
        await mod.run_liquid_refund_subprocess(_payload_request())
    assert "exit=4" in str(exc_info.value)


@pytest.mark.asyncio
async def test_missing_fd3_hex_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    _open_gate(monkeypatch)

    async def fake_run(**_kwargs):
        return _fake_subprocess_result(refund_tx_hex=None)

    monkeypatch.setattr(mod, "run_boltz_claim_js", fake_run)
    with pytest.raises(mod.LiquidRefundSubprocessError, match="no fd-3 hex"):
        await mod.run_liquid_refund_subprocess(_payload_request())


@pytest.mark.asyncio
async def test_stdout_missing_event_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    _open_gate(monkeypatch)

    async def fake_run(**_kwargs):
        return _fake_subprocess_result(stdout_redacted=b"")

    monkeypatch.setattr(mod, "run_boltz_claim_js", fake_run)
    with pytest.raises(mod.LiquidRefundSubprocessError, match="broadcast event"):
        await mod.run_liquid_refund_subprocess(_payload_request())


@pytest.mark.asyncio
async def test_subprocess_timeout_maps_to_refund_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _open_gate(monkeypatch)

    async def fake_run(**_kwargs):
        raise anonsub.SubprocessTimeoutError("test timeout")

    monkeypatch.setattr(mod, "run_boltz_claim_js", fake_run)
    with pytest.raises(mod.LiquidRefundSubprocessError, match="timeout"):
        await mod.run_liquid_refund_subprocess(_payload_request())
