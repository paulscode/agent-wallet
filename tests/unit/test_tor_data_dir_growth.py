# SPDX-License-Identifier: MIT
"""Tor DataDirectory growth detection tests.

Covers both the volume-size probe (``_data_dir_used_mb``) and the
threshold check (``_maybe_warn_data_dir_growth``).

The probe must fail closed when:
  - The path isn't configured.
  - The path doesn't exist (dev/test environments, or the operator
    is running their own Tor outside the compose stack).
  - The path exists but isn't a dedicated mountpoint — statvfs would
    return the host filesystem's stats, which is wildly misleading.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from app.services.tor_watchdog import (
    _data_dir_used_mb,
    _maybe_warn_data_dir_growth,
)

# ── _data_dir_used_mb fail-closed paths ────────────────────────────


@pytest.mark.asyncio
async def test_returns_none_when_path_not_configured() -> None:
    """Empty ``tor_data_dir_mount_path`` → None (no probe attempted)."""
    with patch("app.core.config.settings.tor_data_dir_mount_path", ""):
        result = await _data_dir_used_mb()
    assert result is None


@pytest.mark.asyncio
async def test_returns_none_when_path_missing(tmp_path) -> None:
    """If the configured path doesn't exist on disk, return None
    rather than raising or claiming 0 MB used."""
    missing = tmp_path / "definitely-not-a-mount"
    with patch(
        "app.core.config.settings.tor_data_dir_mount_path",
        str(missing),
    ):
        result = await _data_dir_used_mb()
    assert result is None


@pytest.mark.asyncio
async def test_returns_none_when_path_is_not_a_mountpoint(tmp_path) -> None:
    """A plain directory (not a mount) must return None — statvfs
    would report the parent filesystem, which is meaningless for
    detecting Tor's DataDirectory growth specifically.
    """
    plain_dir = tmp_path / "tor-data"
    plain_dir.mkdir()
    with patch(
        "app.core.config.settings.tor_data_dir_mount_path",
        str(plain_dir),
    ):
        result = await _data_dir_used_mb()
    assert result is None


@pytest.mark.asyncio
async def test_returns_int_mb_when_real_mountpoint(tmp_path, monkeypatch) -> None:
    """When the path is a real mountpoint AND we walk its contents,
    the returned MB count reflects what's actually IN the
    directory, NOT the underlying filesystem's used bytes.

    Pinned to catch a regression toward the old ``statvfs``-based
    implementation: a Docker named volume sitting on the host
    filesystem reports ``statvfs`` numbers that include EVERY file
    on the host, producing the 2.5 TB false-positive observed in
    the field. The directory-walk implementation reads only what's
    actually under ``/var/lib/tor``.
    """
    # Build a fake DataDirectory with known content size: 3 files
    # totaling 5 MB (1 MB + 2 MB + 2 MB). Walk should sum to ~5 MB.
    vol = tmp_path / "tor-data"
    vol.mkdir()
    (vol / "cached-microdescs").write_bytes(b"\x00" * (1 * 1024 * 1024))
    (vol / "consensus").write_bytes(b"\x00" * (2 * 1024 * 1024))
    sub = vol / "keys"
    sub.mkdir()
    (sub / "secret_id_key").write_bytes(b"\x00" * (2 * 1024 * 1024))

    monkeypatch.setattr(
        "app.core.config.settings.tor_data_dir_mount_path",
        str(vol),
    )
    with patch("os.path.ismount", return_value=True):
        result = await _data_dir_used_mb()

    # Allow ±1 MB tolerance (rounding from bytes → MB).
    assert result is not None
    assert 4 <= result <= 6, (
        f"directory walk should report ~5 MB based on file content; "
        f"got {result}. Regression: this used to be statvfs-based "
        f"and reported the whole host filesystem's used bytes."
    )


@pytest.mark.asyncio
async def test_does_not_report_host_filesystem_used_bytes() -> None:
    """regression — the field-observed 2.5 TB false positive
    came from ``os.statvfs()`` returning the underlying host
    filesystem stats for a Docker volume mount. The new walk-based
    implementation must NOT touch ``os.statvfs`` at all."""
    import app.services.tor_watchdog as mod

    statvfs_called = {"n": 0}
    real_statvfs = __import__("os").statvfs

    def _spy(*args, **kwargs):
        statvfs_called["n"] += 1
        return real_statvfs(*args, **kwargs)

    with patch("os.statvfs", side_effect=_spy):
        # Call against a non-mountpoint path so the function early-
        # returns; we just want to assert statvfs was NOT consulted.
        with patch(
            "app.core.config.settings.tor_data_dir_mount_path",
            "/nonexistent",
        ):
            await mod._data_dir_used_mb()
    assert statvfs_called["n"] == 0, (
        "os.statvfs should not be called by the growth check; "
        "Docker-volume statvfs returns host-filesystem stats which "
        "produced a 2.5 TB false positive in the field."
    )


# ── _maybe_warn_data_dir_growth threshold logic ────────────────────


@pytest.mark.asyncio
async def test_warn_skipped_when_used_mb_none() -> None:
    """The probe returning None must not emit a spurious warning —
    None means "couldn't measure", not "0 MB used"."""
    fake_emit = AsyncMock()
    with patch("app.services.tor_watchdog._emit_audit", fake_emit):
        await _maybe_warn_data_dir_growth(None)
    fake_emit.assert_not_called()


@pytest.mark.asyncio
async def test_warn_skipped_when_below_threshold() -> None:
    fake_emit = AsyncMock()
    with (
        patch(
            "app.core.config.settings.tor_data_dir_warn_mb",
            100,
        ),
        patch(
            "app.services.tor_watchdog._emit_audit",
            fake_emit,
        ),
    ):
        await _maybe_warn_data_dir_growth(50)
    fake_emit.assert_not_called()


@pytest.mark.asyncio
async def test_warn_fires_when_threshold_crossed() -> None:
    """At or above threshold we emit an audit-log entry naming the
    threshold and the measured size — the operator-facing signal that
    Tor's DataDirectory is growing unexpectedly."""
    fake_emit = AsyncMock()
    with (
        patch(
            "app.core.config.settings.tor_data_dir_warn_mb",
            100,
        ),
        patch(
            "app.services.tor_watchdog._emit_audit",
            fake_emit,
        ),
    ):
        await _maybe_warn_data_dir_growth(150)
    fake_emit.assert_awaited_once()
    args, kwargs = fake_emit.await_args
    action = args[0]
    details = kwargs.get("details") or (args[1] if len(args) > 1 else None)
    assert action == "tor_data_dir_growth_warning"
    assert details["used_mb"] == 150
    assert details["threshold_mb"] == 100


@pytest.mark.asyncio
async def test_warn_is_idempotent_each_tick() -> None:
    """The watchdog tick fires every ~30s but the threshold-warn
    must NOT suppress itself indefinitely — operator visibility
    requires re-emission on each tick while still above threshold.

    NOTE: there is no in-process suppression today; this test pins
    that decision so a future "deduplicate audit emits" refactor
    has to revisit the operator-visibility requirement.
    """
    fake_emit = AsyncMock()
    with (
        patch(
            "app.core.config.settings.tor_data_dir_warn_mb",
            100,
        ),
        patch(
            "app.services.tor_watchdog._emit_audit",
            fake_emit,
        ),
    ):
        await _maybe_warn_data_dir_growth(150)
        await _maybe_warn_data_dir_growth(151)
        await _maybe_warn_data_dir_growth(152)
    assert fake_emit.await_count == 3
