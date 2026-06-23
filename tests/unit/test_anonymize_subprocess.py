# SPDX-License-Identifier: MIT
"""Subprocess wrapper for boltz_claim.js.

Pure-helper-level tests:
* ``redact_hex_runs`` collapses long hex runs (defends against
  claim-tx-hex-in-logs leak).
* ``read_fd_3`` produces a ``ClaimTxHex`` carrying the per-process
  sentinel; ``assert_is_claim_tx_hex_from_fd3`` rejects forgeries.
* The actual subprocess spawn requires ``node`` on PATH; a
  best-effort smoke test runs only when ``node`` is available so
  CI doesn't fail on minimal images.
"""

from __future__ import annotations

import os
import shutil

import pytest

from app.services.anonymize import subprocess as anonsub


def test_redact_hex_runs_collapses_long_hex() -> None:
    payload = b"prefix " + (b"deadbeef" * 13) + b" suffix"  # 104-byte hex run
    out = anonsub.redact_hex_runs(payload)
    assert b"<redacted-hex>" in out
    assert b"deadbeef" not in out
    assert b"prefix " in out
    assert b"suffix" in out


def test_redact_hex_runs_leaves_short_hex_alone() -> None:
    payload = b"short hex deadbeef in the middle"
    out = anonsub.redact_hex_runs(payload)
    assert b"deadbeef" in out
    assert b"<redacted-hex>" not in out


def test_redact_hex_runs_handles_mixed_case() -> None:
    payload = b"DEADBEEF" * 13
    out = anonsub.redact_hex_runs(payload)
    assert out == b"<redacted-hex>"


def test_redact_hex_runs_redacts_only_hex_alphabet() -> None:
    """A long string of non-hex letters must NOT be redacted."""
    payload = b"x" * 200  # not hex (x is not in 0-9a-f)
    out = anonsub.redact_hex_runs(payload)
    assert out == payload


def test_read_fd_3_round_trips_hex(tmp_path) -> None:
    """``read_fd_3`` decodes a hex payload and produces a sentinel-bearing ClaimTxHex."""
    r, w = os.pipe()
    payload = b"deadbeef" * 4
    os.write(w, payload)
    os.close(w)
    out = anonsub.read_fd_3(r, max_bytes=1024)
    assert out.value == payload.decode("ascii")
    # The sentinel-checking helper must accept this instance.
    anonsub.assert_is_claim_tx_hex_from_fd3(out)


def test_read_fd_3_returns_none_on_empty_payload() -> None:
    r, w = os.pipe()
    os.close(w)  # immediately EOF
    out = anonsub.read_fd_3(r, max_bytes=1024)
    assert out.value is None


def test_read_fd_3_rejects_non_ascii_payload() -> None:
    r, w = os.pipe()
    os.write(w, b"\x80\x81\x82")
    os.close(w)
    with pytest.raises(ValueError, match="not ASCII"):
        anonsub.read_fd_3(r, max_bytes=1024)


def test_read_fd_3_rejects_non_hex_payload() -> None:
    r, w = os.pipe()
    os.write(w, b"this is ascii but not hex")
    os.close(w)
    with pytest.raises(ValueError, match="not a hex string"):
        anonsub.read_fd_3(r, max_bytes=1024)


def test_read_fd_3_enforces_max_bytes() -> None:
    r, w = os.pipe()
    os.write(w, b"a" * 5000)
    os.close(w)
    with pytest.raises(anonsub.SubprocessOutputTooLargeError):
        anonsub.read_fd_3(r, max_bytes=100)


def test_assert_is_claim_tx_hex_from_fd3_rejects_forgery() -> None:
    """A ``ClaimTxHex`` instance built without the sentinel must be rejected."""
    forged = anonsub.ClaimTxHex(value="deadbeef")  # no sentinel
    with pytest.raises(TypeError, match="forbidden"):
        anonsub.assert_is_claim_tx_hex_from_fd3(forged)


@pytest.mark.asyncio
async def test_run_boltz_claim_js_kills_timeout(tmp_path) -> None:
    """``run_boltz_claim_js`` raises ``SubprocessTimeoutError`` past the budget."""
    if shutil.which("node") is None:
        pytest.skip("node binary not installed; subprocess smoke test skipped")
    # Write a tiny JS that just sleeps. We bypass the wrapper's args
    # and pass a -e expression; the wrapper invokes "node" with our
    # args, so passing ["-e", "..."] runs an inline script.
    with pytest.raises(anonsub.SubprocessTimeoutError):
        await anonsub.run_boltz_claim_js(
            args=["-e", "setTimeout(() => {}, 60000);"],
            cwd=tmp_path,
            timeout_s=0.5,
        )


@pytest.mark.asyncio
async def test_run_boltz_claim_js_redacts_hex_in_stderr(tmp_path) -> None:
    """A subprocess that writes hex to stderr has its capture redacted."""
    if shutil.which("node") is None:
        pytest.skip("node binary not installed; subprocess smoke test skipped")
    js = 'process.stderr.write("' + ("deadbeef" * 13) + '\\n");process.exit(0);'
    result = await anonsub.run_boltz_claim_js(args=["-e", js], cwd=tmp_path, timeout_s=10)
    assert b"<redacted-hex>" in result.stderr_redacted
    assert b"deadbeef" not in result.stderr_redacted


@pytest.mark.asyncio
async def test_run_boltz_claim_js_pipes_stdin_payload(tmp_path) -> None:
    """When ``stdin_payload`` is supplied the child receives it on
    stdin — used by submarine_refund.js to ingest the swap state
    without leaking it via argv (visible in ``ps``)."""
    if shutil.which("node") is None:
        pytest.skip("node binary not installed; subprocess smoke test skipped")
    # Read all of stdin and echo its length on stderr (which the
    # wrapper captures through the redactor). A pure stdin echo is
    # enough to prove the pipe is wired.
    js = (
        "let data='';"
        "process.stdin.on('data',c=>data+=c);"
        "process.stdin.on('end',()=>{"
        "  process.stderr.write('len=' + data.length);"
        "  process.exit(0);"
        "});"
    )
    payload = b'{"swap_id": "test"}'
    result = await anonsub.run_boltz_claim_js(
        args=["-e", js],
        cwd=tmp_path,
        timeout_s=10,
        stdin_payload=payload,
    )
    assert result.returncode == 0
    assert f"len={len(payload)}".encode("ascii") in result.stderr_redacted


@pytest.mark.asyncio
async def test_run_boltz_claim_js_default_stdin_is_devnull(tmp_path) -> None:
    """Without ``stdin_payload`` the legacy boltz_claim path sees an
    empty stdin (DEVNULL)."""
    if shutil.which("node") is None:
        pytest.skip("node binary not installed; subprocess smoke test skipped")
    js = (
        "let data='';"
        "process.stdin.on('data',c=>data+=c);"
        "process.stdin.on('end',()=>{"
        "  const len=data.length;"
        "  process.stderr.write('len=' + len);"
        "  process.exit(0);"
        "});"
    )
    result = await anonsub.run_boltz_claim_js(
        args=["-e", js],
        cwd=tmp_path,
        timeout_s=10,
    )
    assert result.returncode == 0
    assert b"len=0" in result.stderr_redacted


# ── Streaming hex redactor with whitespace tolerance + allowlist ──


def test_redactor_replaces_long_hex_run(monkeypatch) -> None:
    from app.core.config import settings
    from app.services.anonymize.subprocess import redact_hex_runs

    monkeypatch.setattr(settings, "anonymize_redactor_hex_threshold", 10)
    monkeypatch.setattr(
        settings,
        "anonymize_redactor_hex_whitespace_tolerance_bytes",
        0,
    )
    out = redact_hex_runs(b"prefix " + (b"a" * 100) + b" suffix")
    assert b"<redacted-hex>" in out
    assert b"a" * 100 not in out


def test_redactor_passes_short_hex_through(monkeypatch) -> None:
    from app.core.config import settings
    from app.services.anonymize.subprocess import redact_hex_runs

    monkeypatch.setattr(settings, "anonymize_redactor_hex_threshold", 10)
    monkeypatch.setattr(
        settings,
        "anonymize_redactor_hex_whitespace_tolerance_bytes",
        0,
    )
    short = b"deadbeef"  # 8 chars < threshold
    assert redact_hex_runs(short) == short


def test_redactor_whitespace_tolerance_unifies_split_run(monkeypatch) -> None:
    """A hex run split by whitespace gets redacted as one."""
    from app.core.config import settings
    from app.services.anonymize.subprocess import redact_hex_runs

    monkeypatch.setattr(settings, "anonymize_redactor_hex_threshold", 10)
    monkeypatch.setattr(
        settings,
        "anonymize_redactor_hex_whitespace_tolerance_bytes",
        4,
    )
    # 40 hex chars split across spaces — total run inclusive of whitespace.
    body = b"aaaaaaaaaa   bbbbbbbbbb\n\nccccccccccdddddddddd"
    out = redact_hex_runs(body)
    assert b"<redacted-hex>" in out
    # The hex bytes are gone.
    assert b"aaaaaaaaaa" not in out


def test_redactor_allowlist_passes_known_hex_through(monkeypatch) -> None:
    """An xpub / canary digest stored in the allow-list is not redacted."""
    from app.core.config import settings
    from app.services.anonymize.subprocess import (
        redact_hex_runs,
        set_redactor_allowlist,
    )

    monkeypatch.setattr(settings, "anonymize_redactor_hex_threshold", 10)
    monkeypatch.setattr(
        settings,
        "anonymize_redactor_hex_whitespace_tolerance_bytes",
        0,
    )
    safe = b"deadbeefcafe1234567890"  # 22 chars
    try:
        set_redactor_allowlist([safe])
        out = redact_hex_runs(b"start " + safe + b" end")
        assert safe in out
        assert b"<redacted-hex>" not in out
    finally:
        set_redactor_allowlist([])


def test_redactor_allowlist_does_not_protect_unrelated_hex(monkeypatch) -> None:
    from app.core.config import settings
    from app.services.anonymize.subprocess import (
        redact_hex_runs,
        set_redactor_allowlist,
    )

    monkeypatch.setattr(settings, "anonymize_redactor_hex_threshold", 10)
    monkeypatch.setattr(
        settings,
        "anonymize_redactor_hex_whitespace_tolerance_bytes",
        0,
    )
    try:
        set_redactor_allowlist([b"deadbeefcafe1234567890"])
        out = redact_hex_runs(b"unrelated " + (b"f" * 50))
        assert b"<redacted-hex>" in out
    finally:
        set_redactor_allowlist([])


def test_redactor_clear_allowlist(monkeypatch) -> None:
    """An empty allow-list clears the previous configuration."""
    from app.core.config import settings
    from app.services.anonymize.subprocess import (
        redact_hex_runs,
        set_redactor_allowlist,
    )

    monkeypatch.setattr(settings, "anonymize_redactor_hex_threshold", 10)
    monkeypatch.setattr(
        settings,
        "anonymize_redactor_hex_whitespace_tolerance_bytes",
        0,
    )
    payload = b"abc" * 10  # 30 chars, above the 10-char threshold
    set_redactor_allowlist([payload])
    set_redactor_allowlist([])  # clear
    # Now this hex string would be redacted again.
    out = redact_hex_runs(payload)
    assert b"<redacted-hex>" in out
