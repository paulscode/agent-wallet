# SPDX-License-Identifier: MIT
"""Regression tests for dashboard external asset references.

Locks in the requirement that every cross-origin <script> and external
``<link rel="stylesheet">`` in the dashboard templates be pinned to a
specific version, carries a Subresource Integrity (SRI) ``integrity``
digest, and declares ``crossorigin="anonymous"``. A drift in any of
these would either break SRI enforcement or open a supply-chain hole
if the CDN is compromised.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

TEMPLATES_DIR = Path(__file__).resolve().parents[2] / "app" / "dashboard" / "templates"

# Cross-origin <script src="..."> tag matcher. Captures the full tag.
_EXTERNAL_SCRIPT_RE = re.compile(
    r"<script\b[^>]*\bsrc\s*=\s*\"(?P<url>https?://[^\"]+)\"[^>]*>",
    re.IGNORECASE,
)
# Cross-origin <link rel="stylesheet" href="..."> matcher. Order of
# attributes is not assumed.
_EXTERNAL_LINK_RE = re.compile(
    r"<link\b(?=[^>]*\brel\s*=\s*\"stylesheet\")[^>]*\bhref\s*=\s*\"(?P<url>https?://[^\"]+)\"[^>]*>",
    re.IGNORECASE,
)
_VERSION_PIN_RE = re.compile(r"@\d+\.\d+\.\d+(?:[-+][\w.]+)?(?:/|$)")


def _iter_template_files() -> list[Path]:
    return sorted(TEMPLATES_DIR.rglob("*.html"))


def _external_script_tags() -> list[tuple[Path, str, str]]:
    out: list[tuple[Path, str, str]] = []
    for path in _iter_template_files():
        text = path.read_text(encoding="utf-8")
        for m in _EXTERNAL_SCRIPT_RE.finditer(text):
            out.append((path, m.group(0), m.group("url")))
    return out


def _external_stylesheet_tags() -> list[tuple[Path, str, str]]:
    out: list[tuple[Path, str, str]] = []
    for path in _iter_template_files():
        text = path.read_text(encoding="utf-8")
        for m in _EXTERNAL_LINK_RE.finditer(text):
            out.append((path, m.group(0), m.group("url")))
    return out


def test_dashboard_has_external_scripts():
    # The dashboard vendor assets
    # are now served locally from ``app/dashboard/static/vendor/``
    # rather than from ``cdn.jsdelivr.net``. The original intent of
    # this guard — "make sure SRI-pinning tests don't go vacuous if
    # someone removes every script" — is now covered by the
    # ``test_vendored_assets_*`` tests below, so this assertion is a
    # no-op when no external scripts are present.
    tags = _external_script_tags()
    if tags:
        # If external scripts are reintroduced in the future, the
        # SRI/pinning assertions below must still trip on them.
        return


@pytest.mark.parametrize(
    "path,tag,url",
    _external_script_tags(),
    ids=lambda v: v.name if isinstance(v, Path) else str(v)[:60],
)
def test_external_scripts_have_sri_and_pinned_version(path: Path, tag: str, url: str):
    assert 'integrity="sha' in tag, f"<script src={url!r}> in {path.name} is missing an SRI integrity attribute"
    assert 'crossorigin="anonymous"' in tag, f'<script src={url!r}> in {path.name} is missing crossorigin="anonymous"'
    assert _VERSION_PIN_RE.search(url), (
        f"<script src={url!r}> in {path.name} is not pinned to an explicit "
        f"semver — SRI provides no protection without a stable URL"
    )


def test_external_stylesheets_have_sri_and_pinned_version():
    """Any cross-origin stylesheet must carry SRI + crossorigin + a pinned version.

    Currently the dashboard ships no external stylesheets, so this test
    is vacuously true. It exists so that adding a CDN stylesheet in the
    future without SRI/version-pin trips a regression rather than
    silently widening the supply-chain attack surface.
    """
    for path, tag, url in _external_stylesheet_tags():
        assert 'integrity="sha' in tag, f"<link href={url!r}> in {path.name} is missing an SRI integrity attribute"
        assert 'crossorigin="anonymous"' in tag, (
            f'<link href={url!r}> in {path.name} is missing crossorigin="anonymous"'
        )
        assert _VERSION_PIN_RE.search(url), (
            f"<link href={url!r}> in {path.name} is not pinned to an explicit "
            f"semver — SRI provides no protection without a stable URL"
        )


# ── (): vendored CDN assets ──
#
# The dashboard now serves Alpine/Lucide/qrcode from
# ``app/dashboard/static/vendor/`` instead of ``cdn.jsdelivr.net``.
# These tests lock in the requirement so a regression that re-introduces
# a CDN <script> tag, or drops an SRI digest, fails CI immediately.
import base64 as _base64
import hashlib as _hashlib

_REPO_ROOT = Path(__file__).resolve().parents[2]
_VENDOR_DIR = _REPO_ROOT / "app" / "dashboard" / "static" / "vendor"
_BASE_TEMPLATE = TEMPLATES_DIR / "base.html"
_MAIN_PY = _REPO_ROOT / "app" / "main.py"

# Vendored files we expect to exist + their pinned SRI digests as written
# into the template. If you upgrade a vendor file, update the digest here
# and in ``base.html`` together (run ``scripts/compute_sri.sh``).
_VENDORED_ASSETS = {
    "alpinejs-csp-3.15.11.min.js": "sha384-TIk3zaxqa4vMqf5I0fQA5imzQDYj1TODC6n9XoykD/M+27VHsOJcDkic2bhwMHGN",
    "lucide-0.469.0.min.js": "sha384-hJnF5AwidE18GSWTAGHv3ByzzvfNZ1Tcx5y1UUV3WkauuMCEzBJBMSwSt/PUPXnM",
    "qrcode-1.4.4.min.js": "sha384-0RsG1yo/crf/1Qc14sho26SXXOTngNCjgJw7fuvXBt9W/OChF/Ijx+aUuBDqQwEk",
}


def test_no_external_cdn_in_rendered_base_template():
    """``base.html`` must not reference ``cdn.jsdelivr.net``."""
    text = _BASE_TEMPLATE.read_text(encoding="utf-8")
    assert "cdn.jsdelivr.net" not in text, (
        "base.html still references cdn.jsdelivr.net — requires "
        "the dashboard vendor assets to be served from "
        "/dashboard/static/vendor/ instead"
    )


def test_csp_header_omits_cdn_jsdelivr_net_for_dashboard():
    """The dashboard CSP string in app/main.py must not allow-list
    ``cdn.jsdelivr.net``. The ``/docs`` CSP is a separate
    block governed by ``ENABLE_DOCS`` and is intentionally excluded
    from this check.

    Asserts on the rendered CSP string literal — Python comments in
    the same block are ignored on purpose so that rationale text
    mentioning the old CDN host doesn't trip the regression."""
    text = _MAIN_PY.read_text(encoding="utf-8")

    # Slice from the dashboard guard to the next ``elif``/``else``.
    start = text.index('if request.url.path.startswith("/dashboard")')
    end = text.index("\n    elif", start)
    dashboard_block = text[start:end]

    # Strip ``#``-prefixed comment lines so the rationale text doesn't
    # match. Then assert the CSP source has no jsdelivr reference.
    non_comment = "\n".join(line for line in dashboard_block.splitlines() if not line.lstrip().startswith("#"))
    assert "cdn.jsdelivr.net" not in non_comment, (
        "Dashboard CSP still allow-lists cdn.jsdelivr.net — "
        "requires the vendor host to be removed from script-src/style-src"
    )


def test_vendored_assets_exist():
    """Each entry in ``_VENDORED_ASSETS`` is a real file."""
    for filename in _VENDORED_ASSETS:
        path = _VENDOR_DIR / filename
        assert path.is_file(), f"missing vendored asset: {path}"
        assert path.stat().st_size > 0, f"vendored asset is empty: {path}"


def test_vendored_assets_have_pinned_sri_hashes_matching_template():
    """The SHA-384 of each vendored file matches the ``integrity``
    digest written into ``base.html``. If they drift, the browser
    rejects the script — fail loudly in CI instead."""
    template_text = _BASE_TEMPLATE.read_text(encoding="utf-8")
    for filename, expected_sri in _VENDORED_ASSETS.items():
        data = (_VENDOR_DIR / filename).read_bytes()
        digest = _base64.b64encode(_hashlib.sha384(data).digest()).decode("ascii")
        actual_sri = f"sha384-{digest}"
        assert actual_sri == expected_sri, (
            f"{filename} on disk hashes to {actual_sri} but the template "
            f"pins {expected_sri} — re-run scripts/compute_sri.sh and "
            f"update base.html"
        )
        assert expected_sri in template_text, f"base.html does not contain the pinned SRI for {filename}"
        assert f"/dashboard/static/vendor/{filename}" in template_text, (
            f"base.html does not reference /dashboard/static/vendor/{filename}"
        )
