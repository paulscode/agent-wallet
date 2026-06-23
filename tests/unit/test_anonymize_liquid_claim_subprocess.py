# SPDX-License-Identifier: MIT
"""Tests for ``app.services.anonymize.liquid_claim_subprocess``.

The wrapper is unit-tested in isolation by monkeypatching the
underlying ``run_boltz_claim_js`` so no real Node binary is spawned
and no live Boltz operator is contacted. Assertions cover the JSON
payload shape (the JS-side wire contract), the integration gate,
and each error mode.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from app.services.anonymize import liquid_claim_subprocess as mod
from app.services.anonymize import subprocess as anonsub


def _payload_request(**overrides: Any) -> mod.LiquidClaimRequest:
    base = dict(
        boltz_url="http://boltz.regtest",
        swap_id="swap-deadbeef",
        preimage_hex="aa" * 32,
        claim_private_key_hex="bb" * 32,
        refund_public_key_hex="02" + "cc" * 32,
        swap_tree={
            "claimLeaf": {"version": 192, "output": "51" + "11" * 32},
            "refundLeaf": {"version": 192, "output": "51" + "22" * 32},
        },
        lockup_tx_hex="ff" * 50,
        destination_address="lq1qq..." + ("z" * 8),
        blinding_key_hex="dd" * 32,
        network="regtest",
    )
    base.update(overrides)
    return mod.LiquidClaimRequest(**base)


def _fake_subprocess_result(
    *,
    returncode: int = 0,
    stdout_redacted: bytes = b'{"event":"liquid_claim_broadcast_complete","txid":"abc123"}\n',
    stderr_redacted: bytes = b"",
    claim_tx_hex: str | None = "ffaa" * 32,
) -> anonsub.SubprocessResult:
    """Build a ``SubprocessResult`` mirroring a successful run.

    The ``ClaimTxHex`` carries the per-process sentinel so the
    wrapper's value extraction succeeds. None of the side-effect
    paths in subprocess.py are touched.
    """
    sentinel = anonsub._PROCESS_SENTINEL  # noqa: SLF001
    claim = anonsub.ClaimTxHex(value=claim_tx_hex, __sentinel__=sentinel)
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
    """Default settings have the gate off; the wrapper must refuse."""
    monkeypatch.setattr(
        mod.settings,
        "anonymize_liquid_integration_verified",
        False,
        raising=False,
    )
    with pytest.raises(mod.LiquidIntegrationNotVerifiedError):
        await mod.run_liquid_claim_subprocess(_payload_request())


@pytest.mark.asyncio
async def test_proceeds_when_integration_gate_is_on(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _open_gate(monkeypatch)
    seen: dict[str, Any] = {}

    async def fake_run(*, args, cwd, timeout_s=None, stdin_payload=None, use_tx_out_file=False):
        seen["args"] = args
        seen["cwd"] = str(cwd)
        seen["timeout_s"] = timeout_s
        seen["stdin_payload"] = stdin_payload
        return _fake_subprocess_result()

    monkeypatch.setattr(mod, "run_boltz_claim_js", fake_run)
    result = await mod.run_liquid_claim_subprocess(_payload_request())
    assert result.txid == "abc123"
    assert result.claim_tx_hex.startswith("ffaa")
    # Script path is documented + stable: keep the assertion strict.
    assert seen["args"] == ("scripts/boltz_claim_liquid.js",)
    # cwd is the repo root; sufficient to check the package.json sits there.
    assert (mod._repo_root() / "scripts" / "boltz_claim_liquid.js").exists()


# ── Payload shape ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_payload_uses_camelcase_wire_names(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The JS subprocess receives camelCase keys; the Python dataclass
    is snake_case. The translation layer must match the documented JS
    contract."""
    _open_gate(monkeypatch)
    captured: dict[str, Any] = {}

    async def fake_run(*, args, cwd, timeout_s=None, stdin_payload=None, use_tx_out_file=False):
        captured["stdin_payload"] = stdin_payload
        return _fake_subprocess_result()

    monkeypatch.setattr(mod, "run_boltz_claim_js", fake_run)
    req = _payload_request(asset_id_hex="ab" * 32, socks_proxy="socks5://127.0.0.1:9052")
    await mod.run_liquid_claim_subprocess(req)
    body = json.loads(captured["stdin_payload"].decode("utf-8"))
    # Required keys (every field of LiquidClaimRequest maps to one).
    expected_required = {
        "boltzUrl",
        "swapId",
        "preimage",
        "claimPrivateKey",
        "refundPublicKey",
        "swapTree",
        "lockupTxHex",
        "destinationAddress",
        "blindingKey",
        "network",
    }
    assert expected_required <= set(body.keys())
    # Optional keys present iff supplied.
    assert body["assetId"] == "ab" * 32
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
    await mod.run_liquid_claim_subprocess(_payload_request())
    body = json.loads(captured["stdin_payload"].decode("utf-8"))
    assert "assetId" not in body
    assert "socksProxy" not in body


# ── Error modes ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_nonzero_exit_raises_with_stderr_redacted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _open_gate(monkeypatch)

    async def fake_run(*, args, cwd, timeout_s=None, stdin_payload=None, use_tx_out_file=False):
        return _fake_subprocess_result(
            returncode=7,
            stderr_redacted=b"<redacted-hex> broke",
        )

    monkeypatch.setattr(mod, "run_boltz_claim_js", fake_run)
    with pytest.raises(mod.LiquidClaimSubprocessError) as exc_info:
        await mod.run_liquid_claim_subprocess(_payload_request())
    assert "exit=7" in str(exc_info.value)


@pytest.mark.asyncio
async def test_missing_fd3_hex_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    _open_gate(monkeypatch)

    async def fake_run(*, args, cwd, timeout_s=None, stdin_payload=None, use_tx_out_file=False):
        return _fake_subprocess_result(claim_tx_hex=None)

    monkeypatch.setattr(mod, "run_boltz_claim_js", fake_run)
    with pytest.raises(mod.LiquidClaimSubprocessError, match="no fd-3 hex"):
        await mod.run_liquid_claim_subprocess(_payload_request())


@pytest.mark.asyncio
async def test_stdout_missing_event_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    _open_gate(monkeypatch)

    async def fake_run(*, args, cwd, timeout_s=None, stdin_payload=None, use_tx_out_file=False):
        # Successful exit + fd-3 hex but stdout is missing the event.
        return _fake_subprocess_result(stdout_redacted=b"")

    monkeypatch.setattr(mod, "run_boltz_claim_js", fake_run)
    with pytest.raises(mod.LiquidClaimSubprocessError, match="broadcast txid event"):
        await mod.run_liquid_claim_subprocess(_payload_request())


@pytest.mark.asyncio
async def test_subprocess_timeout_maps_to_claim_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _open_gate(monkeypatch)

    async def fake_run(*, args, cwd, timeout_s=None, stdin_payload=None, use_tx_out_file=False):
        raise anonsub.SubprocessTimeoutError("test timeout")

    monkeypatch.setattr(mod, "run_boltz_claim_js", fake_run)
    with pytest.raises(mod.LiquidClaimSubprocessError, match="timeout"):
        await mod.run_liquid_claim_subprocess(_payload_request())


@pytest.mark.asyncio
async def test_subprocess_oversize_maps_to_claim_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _open_gate(monkeypatch)

    async def fake_run(*, args, cwd, timeout_s=None, stdin_payload=None, use_tx_out_file=False):
        raise anonsub.SubprocessOutputTooLargeError("cap=1024")

    monkeypatch.setattr(mod, "run_boltz_claim_js", fake_run)
    with pytest.raises(mod.LiquidClaimSubprocessError, match="too much output"):
        await mod.run_liquid_claim_subprocess(_payload_request())


# ── Parse path (unit) ──────────────────────────────────────────────


def test_parse_stdout_txid_accepts_well_formed_event() -> None:
    line = b'{"event":"liquid_claim_broadcast_complete","txid":"ab12"}\n'
    assert mod._parse_stdout_txid(line) == "ab12"


def test_parse_stdout_txid_rejects_wrong_event() -> None:
    line = b'{"event":"other","txid":"ab12"}'
    assert mod._parse_stdout_txid(line) is None


def test_parse_stdout_txid_handles_empty() -> None:
    assert mod._parse_stdout_txid(b"") is None
    assert mod._parse_stdout_txid(b"   \n") is None


# ── Mode dispatch (cooperative / unilateral) ───────────────────────


@pytest.mark.asyncio
async def test_default_mode_omits_mode_key_from_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The default cooperative mode must NOT serialize a ``mode`` key
    so the wire shape stays byte-identical for existing call sites
    (the JS script's destructure defaults to ``cooperative`` when the
    key is absent)."""
    _open_gate(monkeypatch)
    captured: dict[str, Any] = {}

    async def fake_run(*, args, cwd, timeout_s=None, stdin_payload=None, use_tx_out_file=False):
        captured["stdin_payload"] = stdin_payload
        return _fake_subprocess_result()

    monkeypatch.setattr(mod, "run_boltz_claim_js", fake_run)
    await mod.run_liquid_claim_subprocess(_payload_request())
    body = json.loads(captured["stdin_payload"].decode("utf-8"))
    assert "mode" not in body


@pytest.mark.asyncio
async def test_unilateral_mode_serializes_into_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When the caller selects unilateral, the wrapper emits the
    matching ``mode: "unilateral"`` field so the JS script takes
    the script-path branch."""
    _open_gate(monkeypatch)
    captured: dict[str, Any] = {}

    async def fake_run(*, args, cwd, timeout_s=None, stdin_payload=None, use_tx_out_file=False):
        captured["stdin_payload"] = stdin_payload
        return _fake_subprocess_result()

    monkeypatch.setattr(mod, "run_boltz_claim_js", fake_run)
    await mod.run_liquid_claim_subprocess(_payload_request(mode="unilateral"))
    body = json.loads(captured["stdin_payload"].decode("utf-8"))
    assert body["mode"] == "unilateral"
