# SPDX-License-Identifier: MIT
"""Boltz_claim.js out-of-band hex transport.

Python-side static verification that the JS script:

* Writes the claim-tx hex to fd 3, not stdout.
* Stdout carries only structured event lines.
* Locks child_process so a grandchild spawn cannot escape the sandbox.

Plus a Python-side check that the only construction site for
``ClaimTxHex`` (via ``read_fd_3``) is matched by a runtime sentinel
guard, so a future regression that builds a ``ClaimTxHex`` directly
fails the gate.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.services.anonymize.subprocess import (
    ClaimTxHex,
    assert_is_claim_tx_hex_from_fd3,
)

REPO = Path(__file__).resolve().parents[2]
JS_SCRIPT = REPO / "scripts" / "boltz_claim.js"
SUBMARINE_REFUND_JS = REPO / "scripts" / "submarine_refund.js"


def test_js_script_writes_hex_to_fd_3() -> None:
    """The cooperative claim-tx hex goes to fd 3, not stdout."""
    text = JS_SCRIPT.read_text(encoding="utf-8")
    # The script uses fs.writeSync(3, finalTxHex) — exact substring.
    assert "fs.writeSync(3, finalTxHex)" in text


def test_js_script_does_not_log_hex_to_stdout() -> None:
    """The stdout event carries no hex for the anonymize path.

    The anonymize wrapper reads the claim-tx hex out-of-band on fd 3 and
    never sets ``emitTxHexStdout``, so for that path the hex never crosses
    stdout. Any stdout ``txHex`` emit must be gated behind the
    ``emitTxHexStdout`` flag so it cannot leak into the anonymize logs.
    """
    import re

    text = JS_SCRIPT.read_text(encoding="utf-8")
    assert "claim_broadcast_complete" in text
    assert "emitTxHexStdout" in text, "stdout hex emit must be controlled by an explicit flag"
    for match in re.finditer(r"txHex:\s*finalTxHex", text):
        preceding = text[max(0, match.start() - 40) : match.start()]
        assert "emitTxHexStdout" in preceding, "txHex on stdout must be gated by emitTxHexStdout"


def test_js_script_locks_child_process_against_grandchild_spawn() -> None:
    """child_process methods are monkey-patched to refuse spawn/fork."""
    text = JS_SCRIPT.read_text(encoding="utf-8")
    assert "lockChildProcess" in text
    assert "forbidden_grandchild_spawn" in text
    # Every spawn-shaped method is wrapped.
    for method in ("spawn", "spawnSync", "exec", "execSync", "execFile", "execFileSync", "fork"):
        assert f"cp.{method} = refuse(" in text, f"cp.{method} not locked"


def test_submarine_refund_script_writes_fd_3() -> None:
    """The submarine-refund JS follows the same fd-3 out-of-band
    transport — refund tx hex on fd 3, structured events on stdout."""
    text = SUBMARINE_REFUND_JS.read_text(encoding="utf-8")
    assert "fs.writeSync(3," in text
    # The broadcast-attempt audit marker (the script emits
    # ``submarine_refund_broadcast`` at every actual broadcast site).
    assert "submarine_refund_broadcast" in text


def test_submarine_refund_script_locks_grandchild_spawn() -> None:
    """The lockChildProcess guard is replicated on submarine_refund.js."""
    text = SUBMARINE_REFUND_JS.read_text(encoding="utf-8")
    assert "lockChildProcess" in text
    assert "forbidden_grandchild_spawn" in text
    for method in ("spawn", "spawnSync", "exec", "execSync", "execFile", "execFileSync", "fork"):
        assert f"cp.{method} = refuse(" in text, f"cp.{method} not locked"


def test_submarine_refund_script_reads_input_from_stdin() -> None:
    """The script reads its swap state via stdin JSON, not argv (so
    ``ps`` cannot leak the refund private key)."""
    text = SUBMARINE_REFUND_JS.read_text(encoding="utf-8")
    assert "process.stdin" in text


def test_submarine_refund_script_refuses_pre_timeout_broadcast() -> None:
    """A refund tx pre-``timeoutBlockHeight`` would be rejected on
    chain; the script emits a structured event so the parent can
    park + retry."""
    text = SUBMARINE_REFUND_JS.read_text(encoding="utf-8")
    assert "refund_not_yet_eligible" in text


def test_claim_tx_hex_constructed_directly_is_rejected() -> None:
    """A ``ClaimTxHex`` built outside ``read_fd_3`` fails the runtime guard."""
    direct = ClaimTxHex(value="deadbeef")
    with pytest.raises(TypeError, match="read_fd_3"):
        assert_is_claim_tx_hex_from_fd3(direct)


def test_claim_tx_hex_with_empty_sentinel_is_rejected() -> None:
    direct = ClaimTxHex(value="deadbeef", __sentinel__=b"")
    with pytest.raises(TypeError, match="read_fd_3"):
        assert_is_claim_tx_hex_from_fd3(direct)


def test_claim_tx_hex_with_wrong_sentinel_is_rejected() -> None:
    direct = ClaimTxHex(value="deadbeef", __sentinel__=b"\x00" * 16)
    with pytest.raises(TypeError, match="read_fd_3"):
        assert_is_claim_tx_hex_from_fd3(direct)
