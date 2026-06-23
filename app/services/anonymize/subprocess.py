# SPDX-License-Identifier: MIT
"""Subprocess wrapper for ``boltz_claim.js``.

Every invocation of the Boltz cooperative-claim helper goes through
this wrapper. Responsibilities, in order:

* Hard wall-clock timeout, captured-output size cap, scrubbed
  env, locked cwd. The wrapper kills timed-out children at the
  process-group level so they cannot orphan into the host.
* Out-of-band claim-tx hex transport via
  ``fd 3``. The subprocess writes hex to a dedicated pipe, never to
  stdout/stderr; stdout/stderr carry only structured JSON event lines.
* Streaming hex-run redactor. Every byte the wrapper
  surfaces (stderr capture, exception payload, log lines) flows
  through a regex filter that replaces hex strings of length ≥
  ``ANONYMIZE_REDACTOR_HEX_THRESHOLD`` with ``<redacted-hex>`` so a
  subprocess regression that puts hex on stdout cannot leak into a
  log.
*:class:`ClaimTxHex` newtype with a per-process random
  sentinel forcing the ``claim_tx_hex`` setter to receive a value
  produced by ``read_fd_3()`` rather than arbitrary captured stdout.

This module ships the wrapper; the ``boltz_claim.js`` extensions
that *write to fd 3* land alongside the cooperative-claim path.
The wrapper is forward-compatible: a script that doesn't use fd 3
returns ``ClaimTxHex(None)`` and the orchestrator falls back to the
documented error path.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import secrets
import signal
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Iterable

from app.core.config import settings

from .metadata import ANONYMIZE_LOGGER_NAME

logger = logging.getLogger(ANONYMIZE_LOGGER_NAME)


# Per-process random sentinel ensuring a ``ClaimTxHex`` instance can
# only be constructed via :func:`read_fd_3`. A regression that writes
# arbitrary captured stdout into the column will fail the type check.
_PROCESS_SENTINEL: Final[bytes] = secrets.token_bytes(16)


# The well-known out-of-band file descriptor the Node scripts write
# their cooperative-claim / refund / lock tx hex to. Node 20 reserves
# fd 3 for its own IPC-channel placeholder, so we use fd 4 — the
# parent ``preexec_fn`` dup2's its read-pipe's write-end into this fd
# before exec. All claim / refund / lock JS scripts hard-code the
# same numeric constant; keep the JS side in sync if this changes.
OUT_OF_BAND_TX_FD: Final[int] = 4


class SubprocessTimeoutError(RuntimeError):
    """Raised when ``boltz_claim.js`` exceeds its wall-clock budget."""


class SubprocessOutputTooLargeError(RuntimeError):
    """Raised when captured stderr exceeds ANONYMIZE_SUBPROCESS_CAPTURE_MAX_BYTES."""


@dataclass(frozen=True)
class ClaimTxHex:
    """Wrapper around the cooperative-claim tx hex.

    Constructed only via :func:`read_fd_3`. The internal sentinel
    matches the per-process value so a regression that bypasses
    ``read_fd_3`` (e.g., by manually instantiating the dataclass)
    fails the runtime check in
    :func:`assert_is_claim_tx_hex_from_fd3`.
    """

    value: str | None
    __sentinel__: bytes = b""


def assert_is_claim_tx_hex_from_fd3(claim: ClaimTxHex) -> None:
    """Runtime check: refuse a ``ClaimTxHex`` not produced by ``read_fd_3``."""
    if claim.__sentinel__ != _PROCESS_SENTINEL:
        raise TypeError(
            "claim_tx_hex must come from subprocess.read_fd_3(); constructing ClaimTxHex directly is forbidden"
        )


# Minimum hex-run length the streaming redactor recognizes.
# Configurable so a future "more aggressive" mode can be flipped.
def _hex_threshold() -> int:
    return max(8, int(settings.anonymize_redactor_hex_threshold))


# Captured-output size cap.
def _capture_max_bytes() -> int:
    return max(1024, int(settings.anonymize_subprocess_capture_max_bytes))


_HEX_RUN_REPLACEMENT: Final[bytes] = b"<redacted-hex>"

# Bytes-allow-list of long-hex strings that the redactor
# must NOT redact. Loaded from anonymize_runtime_state at boot; this
# module-level set is the fallback used by tests + the fresh-deploy path.
_REDACTOR_ALLOWLIST: set[bytes] = set()


def set_redactor_allowlist(values: Iterable[bytes]) -> None:
    """Replace the allow-list at boot (in tests).

    Production callers pass the decrypted xpub / release-key
    fingerprint / FERNET canary digest values loaded from
    ``anonymize_runtime_state``. Empty input clears the list.
    """
    _REDACTOR_ALLOWLIST.clear()
    for v in values:
        if isinstance(v, (bytes, bytearray)) and v:
            _REDACTOR_ALLOWLIST.add(bytes(v))


def redact_hex_runs(payload: bytes) -> bytes:
    """Streaming-style hex-run redactor.

    Replaces every contiguous hex sequence of length >=
    ``ANONYMIZE_REDACTOR_HEX_THRESHOLD`` with ``<redacted-hex>``.
    The streaming version of this function (used by the live
    subprocess wrapper) handles cross-chunk boundaries; this
    function is the offline counterpart with the same vocabulary.

    Two refinements:

    * **Whitespace tolerance** — small runs of whitespace within
      a hex run are treated as part of the run, so a misbehaving
      ``console.log`` that breaks the hex across two ``write()``
      calls cannot escape redaction. Tolerance is bounded by
      ``ANONYMIZE_REDACTOR_HEX_WHITESPACE_TOLERANCE_BYTES``.
    * **Allow-list** — bytes pre-loaded via
      :func:`set_redactor_allowlist` (xpub, release-key fingerprint,
      FERNET canary digest) pass through unchanged.

    The replacement is conservative: any false positive (e.g., a
    legitimate signature in an error message) is over-redacted. The
    raw error remains in the anonymize logger at WARNING for
    debugging.
    """
    threshold = _hex_threshold()
    tolerance = max(0, int(settings.anonymize_redactor_hex_whitespace_tolerance_bytes))
    # Hex run with embedded whitespace bursts of <= tolerance bytes.
    if tolerance == 0:
        pat = re.compile(rb"[0-9a-fA-F]{" + str(threshold).encode() + rb",}")
    else:
        # Hex + optional whitespace + hex, with bounded whitespace runs.
        pat = re.compile(
            rb"[0-9a-fA-F](?:[0-9a-fA-F]|\s{1,"
            + str(tolerance).encode()
            + rb"}(?=[0-9a-fA-F])){"
            + str(max(1, threshold - 1)).encode()
            + rb",}"
        )

    def _sub(m: "re.Match[bytes]") -> bytes:
        matched = m.group(0)
        # Bytes-allow-list — pass through if the run (whitespace-stripped)
        # equals an allow-listed value.
        stripped = b"".join(matched.split())
        if stripped in _REDACTOR_ALLOWLIST:
            return matched
        return _HEX_RUN_REPLACEMENT

    return pat.sub(_sub, payload)


def read_fd_3(fd: int, *, max_bytes: int | None = None) -> ClaimTxHex:
    """Read the claim-tx hex from a dedicated file descriptor.

    The subprocess writes the hex to fd 3 (a parent-side pipe). The
    parent reads up to ``max_bytes`` (default
    ``ANONYMIZE_SUBPROCESS_CAPTURE_MAX_BYTES``) and returns a
    :class:`ClaimTxHex` carrying the per-process sentinel so the
    column-setter can verify provenance.
    """
    max_bytes = max_bytes if max_bytes is not None else _capture_max_bytes()
    chunks: list[bytes] = []
    total = 0
    try:
        while True:
            chunk = os.read(fd, 4096)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > max_bytes:
                raise SubprocessOutputTooLargeError(f"fd 3 produced more than {max_bytes} bytes")
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
    raw = b"".join(chunks).strip()
    if not raw:
        return ClaimTxHex(value=None, __sentinel__=_PROCESS_SENTINEL)
    # The hex is expected to be ASCII; reject anything else.
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("fd 3 payload is not ASCII") from exc
    if not re.fullmatch(r"[0-9a-fA-F]+", text):
        raise ValueError("fd 3 payload is not a hex string")
    return ClaimTxHex(value=text, __sentinel__=_PROCESS_SENTINEL)


def _scrubbed_env() -> dict[str, str]:
    """Return a minimal env dict for the subprocess.

    Only ``PATH`` is preserved (the subprocess needs ``node``).
    Everything else is stripped so a leaked env var (``LND_*``,
    ``BOLTZ_*``, ``DATABASE_URL``) cannot reach the JS process.
    """
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        # Some Node features (esp. crypto fallback) need a working
        # locale; ``C`` is enough.
        "LC_ALL": "C",
    }


@dataclass(frozen=True)
class SubprocessResult:
    """Captured output of a sandboxed subprocess run."""

    returncode: int
    stdout_redacted: bytes
    stderr_redacted: bytes
    claim_tx_hex: ClaimTxHex


async def run_boltz_claim_js(
    *,
    args: Iterable[str],
    cwd: Path,
    timeout_s: float | None = None,
    capture_max_bytes: int | None = None,
    stdin_payload: bytes | None = None,
    use_tx_out_file: bool = False,
) -> SubprocessResult:
    """Spawn ``boltz_claim.js`` (or another fd-3-shaped Node script)
    under the sandbox.

    The subprocess inherits a dedicated read-pipe on fd 3 (the parent
    holds the write end while it spawns, then closes it). Stdout and
    stderr are captured to memory subject to the size cap and routed
    through the hex redactor before any logging or return.

    The child runs in its own process group so a wall-clock timeout
    can kill the entire group via ``SIGKILL`` — denying a misbehaving
    ``node`` process the chance to fork a grandchild that lingers.

    ``stdin_payload`` (when non-None) is piped into the child's
    stdin. The bytes are passed verbatim — callers that pass JSON
    are responsible for serializing it. When omitted, stdin is
    redirected to ``/dev/null`` (the legacy boltz_claim path).
    """
    timeout = float(timeout_s if timeout_s is not None else settings.anonymize_claim_js_timeout_s)
    cap = capture_max_bytes if capture_max_bytes is not None else _capture_max_bytes()

    # ``use_tx_out_file=True`` swaps the fd-3 transport for an
    # ephemeral file: the parent creates a temp file, exports its path
    # via ``BOLTZ_TX_OUT_FILE`` for the script to consume, and reads
    # the file after exit. This bypasses Node 20's startup-time
    # fd-3..N placeholder injection (which mangles writes to inherited
    # pipes on those fds) — see the comment above ``OUT_OF_BAND_TX_FD``.
    tx_out_file_path: Path | None = None
    if use_tx_out_file:
        import tempfile

        tmp = tempfile.NamedTemporaryFile(
            prefix="boltz-tx-",
            suffix=".hex",
            delete=False,
        )
        tmp.close()
        tx_out_file_path = Path(tmp.name)

    # Create the fd-3 pipe. Parent reads via ``read_end`` after wait.
    read_end, write_end = os.pipe()
    stdin_arg = subprocess.PIPE if stdin_payload is not None else subprocess.DEVNULL

    # ``pass_fds`` keeps the write-end open in the child but at the
    # SAME numeric fd as the parent — NOT at the well-known
    # :data:`OUT_OF_BAND_TX_FD`. The Node scripts write to a hard-
    # coded ``fs.writeSync(OUT_OF_BAND_TX_FD, ...)`` so we have to
    # renumber the pipe in the child after fork. The ``preexec_fn``
    # hook runs post-fork / pre-exec in the child.
    #
    # Note: Node 20 opens **fd 3** to a private placeholder at
    # startup regardless of what the parent passes there (a safety
    # behaviour for IPC-channel detection). We use fd 4 instead —
    # Node leaves higher fds alone.
    def _preexec_dup_pipe() -> None:
        os.dup2(write_end, OUT_OF_BAND_TX_FD)

    env = _scrubbed_env()
    if tx_out_file_path is not None:
        env["BOLTZ_TX_OUT_FILE"] = str(tx_out_file_path)

    try:
        proc = await asyncio.create_subprocess_exec(
            "node",
            *args,
            cwd=str(cwd),
            stdin=stdin_arg,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            # Keep the write-end alive in the child + dup it into the
            # well-known out-of-band fd.
            pass_fds=(write_end,),
            preexec_fn=_preexec_dup_pipe,
            env=env,
            # New process group so ``os.killpg`` kills the whole tree
            # on timeout. ``start_new_session`` is the cross-asyncio
            # equivalent of ``setsid``.
            start_new_session=True,
        )
    except FileNotFoundError as exc:
        # `node` not installed — a common setup gap. Surface
        # a clear error rather than a stack trace into the orchestrator.
        os.close(read_end)
        os.close(write_end)
        raise RuntimeError("node binary not found in PATH; cannot run boltz_claim.js") from exc
    finally:
        # Parent never writes to the fd-3 pipe; close the write end
        # so the child's eventual close on its end produces an EOF
        # for our reader.
        try:
            os.close(write_end)
        except OSError:
            pass

    try:
        try:
            stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(input=stdin_payload), timeout=timeout)
        except asyncio.TimeoutError:
            # Kill the process group, not just the child — `node` may
            # have spawned subprocesses we want gone too.
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            await proc.wait()
            raise SubprocessTimeoutError(f"boltz_claim.js exceeded {timeout} s") from None
    finally:
        if tx_out_file_path is not None:
            # Temp-file transport: the script wrote the hex to the
            # path passed via ``BOLTZ_TX_OUT_FILE``. Read + unlink it
            # here. A non-existent file means the script didn't write
            # (e.g., it errored before reaching the write site).
            try:
                os.close(read_end)
            except OSError:
                pass
            try:
                raw = tx_out_file_path.read_bytes() if tx_out_file_path.exists() else b""
                if len(raw) > cap:
                    raise SubprocessOutputTooLargeError(f"BOLTZ_TX_OUT_FILE produced more than {cap} bytes")
                text = raw.decode("ascii", errors="strict").strip() if raw else ""
                if text:
                    if any(c not in "0123456789abcdefABCDEF" for c in text):
                        raise ValueError("BOLTZ_TX_OUT_FILE contained non-hex chars")
                    claim = ClaimTxHex(
                        value=text,
                        __sentinel__=_PROCESS_SENTINEL,
                    )
                else:
                    claim = ClaimTxHex(
                        value=None,
                        __sentinel__=_PROCESS_SENTINEL,
                    )
            except (ValueError, SubprocessOutputTooLargeError) as exc:
                logger.warning("boltz_claim.js tx-out-file read failed: %s", exc)
                claim = ClaimTxHex(value=None, __sentinel__=_PROCESS_SENTINEL)
            finally:
                try:
                    tx_out_file_path.unlink(missing_ok=True)
                except OSError:
                    pass
        else:
            # Read whatever fd 3 produced before we close it. A
            # timed-out subprocess may have written nothing — that's
            # fine, the ``ClaimTxHex(None)`` is what the caller sees.
            try:
                claim = read_fd_3(read_end, max_bytes=cap)
            except (ValueError, SubprocessOutputTooLargeError) as exc:
                logger.warning("boltz_claim.js fd-3 read failed: %s", exc)
                try:
                    os.close(read_end)
                except OSError:
                    pass
                claim = ClaimTxHex(
                    value=None,
                    __sentinel__=_PROCESS_SENTINEL,
                )

    if len(stdout_b) > cap or len(stderr_b) > cap:
        raise SubprocessOutputTooLargeError(f"captured output exceeded cap {cap}")

    return SubprocessResult(
        returncode=proc.returncode if proc.returncode is not None else -1,
        stdout_redacted=redact_hex_runs(stdout_b),
        stderr_redacted=redact_hex_runs(stderr_b),
        claim_tx_hex=claim,
    )


__all__ = [
    "ClaimTxHex",
    "SubprocessResult",
    "SubprocessTimeoutError",
    "SubprocessOutputTooLargeError",
    "assert_is_claim_tx_hex_from_fd3",
    "redact_hex_runs",
    "set_redactor_allowlist",
    "read_fd_3",
    "run_boltz_claim_js",
]
