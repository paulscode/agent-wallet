# SPDX-License-Identifier: MIT
"""Signed clock-skew probe-source registry.

The recurring clock-skew probe HEADs each URL in this list over Tor and
compares the server ``Date`` header to the local clock. Mirrors the
operators-registry design ([operators.py]) but with a simpler schema —
clock-skew sources don't carry signing keys, attested volume, or any of
the swap-operator-specific metadata.

The registry is signed by the same maintainer who signs ``operators.json``;
the wallet verifies the detached signature at load time against the
bundled ``maintainer.asc`` and the fingerprint(s) pinned in
``ANONYMIZE_REGISTRY_RELEASE_KEY_FINGERPRINTS`` (reused — same
maintainer, no point requiring two parallel allow-lists).

The list ships **independent** of the swap operators by default so a
single compromised swap operator cannot simultaneously poison the
clock-skew measurement and a swap leg.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from app.core.config import settings

from .operators import verify_detached_signature


@dataclass(frozen=True)
class ClockSkewSource:
    """One row of ``clock_skew_sources.json``."""

    source_id: str
    url: str
    label: str | None = None
    last_audit_date: str | None = None


class ClockSkewSourcesLoadError(RuntimeError):
    """Raised when ``clock_skew_sources.json`` cannot be parsed."""


class ClockSkewSourcesSignatureError(RuntimeError):
    """Raised when the detached signature does not verify."""


def _canonicalize_for_signing(text: str) -> bytes:
    """Canonical bytes signed by the maintainer.

    Matches the formula used for ``operators.json``:
    ``text.rstrip('\\n ').encode('utf-8')``. Keep this in sync if the
    operators-side canonicalization changes.
    """
    return text.rstrip("\n ").encode("utf-8")


def load_clock_skew_sources(
    path: str | Path | None = None,
    *,
    text: str | None = None,
) -> list[ClockSkewSource]:
    """Parse the clock-skew sources file without signature verification.

    When ``text`` is supplied the parser uses those exact bytes instead
    of re-reading ``path``; the signed loader passes the bytes it just
    verified so verified and parsed content cannot differ (closes a
    verify-then-reread TOCTOU).

    Returns ``[]`` for a missing or empty file so the probe's caller
    can treat "no curated list" as "no fallback" cleanly. Raises
    :class:`ClockSkewSourcesLoadError` on malformed content.
    """
    if path is None:
        path = settings.anonymize_clock_skew_sources_path
    p = Path(path)
    if text is None:
        if not p.is_file():
            return []
        try:
            text = p.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise ClockSkewSourcesLoadError(f"could not read {p}: {exc}") from exc
    else:
        text = text.strip()
    if not text:
        return []
    try:
        raw = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ClockSkewSourcesLoadError(f"{p} is not valid JSON: {exc}") from exc

    if not isinstance(raw, list):
        raise ClockSkewSourcesLoadError(f"{p} must be a JSON array of source entries")

    out: list[ClockSkewSource] = []
    seen_ids: set[str] = set()
    seen_urls: set[str] = set()
    for i, item in enumerate(raw):
        if not isinstance(item, dict):
            raise ClockSkewSourcesLoadError(f"{p}[{i}]: entry is not an object")
        try:
            entry = ClockSkewSource(
                source_id=str(item["source_id"]),
                url=str(item["url"]),
                label=item.get("label"),
                last_audit_date=item.get("last_audit_date"),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ClockSkewSourcesLoadError(f"{p}[{i}]: malformed entry ({exc})") from exc
        if not entry.source_id:
            raise ClockSkewSourcesLoadError(f"{p}[{i}]: source_id is empty")
        if not entry.url or "://" not in entry.url:
            raise ClockSkewSourcesLoadError(f"{p}[{i}]: url must be an absolute URL")
        if entry.source_id in seen_ids:
            raise ClockSkewSourcesLoadError(f"{p}: duplicate source_id {entry.source_id!r}")
        if entry.url in seen_urls:
            raise ClockSkewSourcesLoadError(f"{p}: duplicate url {entry.url!r}")
        seen_ids.add(entry.source_id)
        seen_urls.add(entry.url)
        out.append(entry)
    return out


def load_signed_clock_skew_sources(
    *,
    sources_path: str | None = None,
    signature_path: str | None = None,
    fingerprints: list[str] | None = None,
) -> list[ClockSkewSource]:
    """Load + signature-verify ``clock_skew_sources.json``.

    Mirrors :func:`operators.load_signed_operator_registry`:

    * Missing or empty file → returns ``[]`` (no signature required).
      The probe falls through to ``ClockSkewState.empty`` which is
      the existing fail-closed default.
    * File non-empty + signature missing/invalid →
      :class:`ClockSkewSourcesSignatureError`.

    The maintainer fingerprint(s) come from
    ``ANONYMIZE_REGISTRY_RELEASE_KEY_FINGERPRINTS`` (the same allow-list
    used by the operators registry — both artifacts are signed by the
    same maintainer in the canonical deployment).
    """
    if sources_path is None:
        sources_path = settings.anonymize_clock_skew_sources_path
    if signature_path is None:
        signature_path = settings.anonymize_clock_skew_sources_sig_path
    if fingerprints is None:
        fingerprints = settings.anonymize_registry_release_key_fingerprints_list

    src_p = Path(sources_path)
    sig_p = Path(signature_path)
    # Accept either ``.sig`` (raw ed25519) or ``.sig.asc`` (armored
    # OpenPGP) — matches the operators-side dual-format support so a
    # maintainer can use one key flow for both artifacts.
    sig_asc_p = sig_p.with_suffix(sig_p.suffix + ".asc")
    if sig_asc_p.is_file():
        sig_p = sig_asc_p

    if not src_p.is_file():
        return []
    # Read the file ONCE and use those exact bytes for both signature
    # verification and parsing — never re-read (TOCTOU). (security M1)
    raw_text = src_p.read_text(encoding="utf-8")
    if not raw_text.strip():
        return []

    canonical = _canonicalize_for_signing(raw_text)

    if not sig_p.is_file():
        raise ClockSkewSourcesSignatureError(
            f"clock_skew_sources.json present but signature file is "
            f"missing (checked {sig_asc_p} and {sig_p}) — refusing to "
            "load the registry without a detached signature."
        )
    sig_bytes = sig_p.read_bytes()

    if not fingerprints:
        raise ClockSkewSourcesSignatureError(
            "clock_skew_sources.json + signature are present but "
            "ANONYMIZE_REGISTRY_RELEASE_KEY_FINGERPRINTS is unset — "
            "the loader cannot decide which release key to trust."
        )

    if not any(
        verify_detached_signature(
            canonical_bytes=canonical,
            signature_bytes=sig_bytes,
            fingerprint=fp,
        )
        for fp in fingerprints
    ):
        raise ClockSkewSourcesSignatureError(
            "clock-skew sources signature does not verify against any "
            f"pinned release key ({len(fingerprints)} fingerprint(s) tried)."
        )

    return load_clock_skew_sources(src_p, text=raw_text)


__all__ = [
    "ClockSkewSource",
    "ClockSkewSourcesLoadError",
    "ClockSkewSourcesSignatureError",
    "load_clock_skew_sources",
    "load_signed_clock_skew_sources",
]
