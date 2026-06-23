# SPDX-License-Identifier: MIT
"""Tests for ``app.services.anonymize.liquid_lock_subprocess``.

Mirrors the test pattern in
``test_anonymize_liquid_claim_subprocess.py``: monkeypatches
``run_boltz_claim_js`` so no Node process is spawned and no live
Boltz operator is contacted. Asserts the payload shape (the JS-side
wire contract), the integration gate, and each error mode.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from app.services.anonymize import liquid_lock_subprocess as mod
from app.services.anonymize import subprocess as anonsub


def _payload_request(**overrides: Any) -> mod.LiquidLockRequest:
    base = dict(
        utxo_txid="ab" * 32,
        utxo_vout=0,
        utxo_value_sat=250_000,
        utxo_asset_id_hex="cc" * 32,
        utxo_asset_blinding_factor_hex="11" * 32,
        utxo_value_blinding_factor_hex="22" * 32,
        utxo_prevout_tx_hex="ff" * 50,
        utxo_script_pubkey_hex="0014" + "33" * 20,
        spending_private_key_hex="44" * 32,
        destination_address="lq1qq..." + "x" * 30,
        destination_amount_sat=200_000,
        fee_sat_per_vbyte=0.1,
        change_address="el1qq..." + "y" * 30,
        network="regtest",
        asset_id_hex="cc" * 32,
        boltz_url="http://boltz.regtest",
    )
    base.update(overrides)
    return mod.LiquidLockRequest(**base)


def _fake_subprocess_result(
    *,
    returncode: int = 0,
    stdout_redacted: bytes = (b'{"event":"liquid_lock_broadcast_complete","txid":"deadbeef"}\n'),
    stderr_redacted: bytes = b"",
    lock_tx_hex: str | None = "ffaa" * 32,
) -> anonsub.SubprocessResult:
    """Build a ``SubprocessResult`` mirroring a successful run."""
    sentinel = anonsub._PROCESS_SENTINEL  # noqa: SLF001
    claim = anonsub.ClaimTxHex(value=lock_tx_hex, __sentinel__=sentinel)
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
    with pytest.raises(mod.LiquidLockIntegrationNotVerifiedError):
        await mod.run_liquid_lock_subprocess(_payload_request())


@pytest.mark.asyncio
async def test_proceeds_when_integration_gate_is_on(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _open_gate(monkeypatch)
    seen: dict[str, Any] = {}

    async def fake_run(*, args, cwd, timeout_s=None, stdin_payload=None, use_tx_out_file=False):
        seen["args"] = args
        seen["stdin_payload"] = stdin_payload
        return _fake_subprocess_result()

    monkeypatch.setattr(mod, "run_boltz_claim_js", fake_run)
    result = await mod.run_liquid_lock_subprocess(_payload_request())
    assert result.txid == "deadbeef"
    assert result.lock_tx_hex.startswith("ffaa")
    assert seen["args"] == ("scripts/boltz_lock_liquid.js",)
    assert (mod._repo_root() / "scripts" / "boltz_lock_liquid.js").exists()


# ── Payload shape ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_payload_uses_camelcase_wire_names(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _open_gate(monkeypatch)
    captured: dict[str, Any] = {}

    async def fake_run(*, args, cwd, timeout_s=None, stdin_payload=None, use_tx_out_file=False):
        captured["stdin_payload"] = stdin_payload
        return _fake_subprocess_result()

    monkeypatch.setattr(mod, "run_boltz_claim_js", fake_run)
    req = _payload_request(socks_proxy="socks5://127.0.0.1:9052")
    await mod.run_liquid_lock_subprocess(req)
    body = json.loads(captured["stdin_payload"].decode("utf-8"))
    expected_required = {
        "utxoTxid",
        "utxoVout",
        "utxoValueSat",
        "utxoAssetIdHex",
        "utxoAssetBlindingFactorHex",
        "utxoValueBlindingFactorHex",
        "utxoPrevoutTxHex",
        "utxoScriptPubKeyHex",
        "spendingPrivateKey",
        "destinationAddress",
        "destinationAmountSat",
        "feeSatPerVbyte",
        "network",
        "assetId",
        "boltzUrl",
    }
    assert expected_required <= set(body.keys())
    assert body["changeAddress"].startswith("el1qq")
    assert body["socksProxy"] == "socks5://127.0.0.1:9052"


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
    req = _payload_request(change_address=None)
    await mod.run_liquid_lock_subprocess(req)
    body = json.loads(captured["stdin_payload"].decode("utf-8"))
    assert "changeAddress" not in body
    assert "socksProxy" not in body


# ── Error modes ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_nonzero_exit_raises_with_stderr_redacted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _open_gate(monkeypatch)

    async def fake_run(*, args, cwd, timeout_s=None, stdin_payload=None, use_tx_out_file=False):
        return _fake_subprocess_result(
            returncode=9,
            stderr_redacted=b"<redacted-hex> broke",
        )

    monkeypatch.setattr(mod, "run_boltz_claim_js", fake_run)
    with pytest.raises(mod.LiquidLockSubprocessError, match="exit=9"):
        await mod.run_liquid_lock_subprocess(_payload_request())


@pytest.mark.asyncio
async def test_missing_fd3_hex_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    _open_gate(monkeypatch)

    async def fake_run(*, args, cwd, timeout_s=None, stdin_payload=None, use_tx_out_file=False):
        return _fake_subprocess_result(lock_tx_hex=None)

    monkeypatch.setattr(mod, "run_boltz_claim_js", fake_run)
    with pytest.raises(mod.LiquidLockSubprocessError, match="no fd-3 hex"):
        await mod.run_liquid_lock_subprocess(_payload_request())


@pytest.mark.asyncio
async def test_stdout_missing_event_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    _open_gate(monkeypatch)

    async def fake_run(*, args, cwd, timeout_s=None, stdin_payload=None, use_tx_out_file=False):
        return _fake_subprocess_result(stdout_redacted=b"")

    monkeypatch.setattr(mod, "run_boltz_claim_js", fake_run)
    with pytest.raises(mod.LiquidLockSubprocessError, match="broadcast txid event"):
        await mod.run_liquid_lock_subprocess(_payload_request())


@pytest.mark.asyncio
async def test_subprocess_timeout_maps_to_lock_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _open_gate(monkeypatch)

    async def fake_run(*, args, cwd, timeout_s=None, stdin_payload=None, use_tx_out_file=False):
        raise anonsub.SubprocessTimeoutError("test timeout")

    monkeypatch.setattr(mod, "run_boltz_claim_js", fake_run)
    with pytest.raises(mod.LiquidLockSubprocessError, match="timeout"):
        await mod.run_liquid_lock_subprocess(_payload_request())


# ── Parse path (unit) ──────────────────────────────────────────────


def test_parse_stdout_txid_accepts_well_formed_event() -> None:
    line = b'{"event":"liquid_lock_broadcast_complete","txid":"deadbeef"}\n'
    assert mod._parse_stdout_txid(line) == "deadbeef"


def test_parse_stdout_txid_rejects_wrong_event() -> None:
    line = b'{"event":"liquid_claim_broadcast_complete","txid":"x"}'
    assert mod._parse_stdout_txid(line) is None


def test_parse_stdout_txid_handles_empty() -> None:
    assert mod._parse_stdout_txid(b"") is None
    assert mod._parse_stdout_txid(b"   \n") is None
