# SPDX-License-Identifier: MIT
"""Help-page anchor convention tests.

Locks the contract between the SPA's per-reason ``Get help`` button
and the dashboard-served help page. The SPA computes the anchor as
``trouble-<reason-with-underscores-replaced-by-hyphens>``; the help
page MUST surface a matching ``id="..."`` for every reason the
classifier knows about so the click resolves to a real anchor.

Cross-refs:
* ``app/dashboard/static/dashboard.js`` :func:`_anonymizeOpenHelp`
* ``docs/anonymize_troubleshooting.md`` per-reason runbook
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_HELP_HTML = Path(__file__).resolve().parents[2] / "app" / "dashboard" / "static" / "help" / "anonymize.html"
_ANONYMIZE_MD = Path(__file__).resolve().parents[2] / "docs" / "anonymize_troubleshooting.md"

# Reasons enumerated in the SPA's ``_anonymizeReasonLabel`` map.
# Mirrors the per-reason dispatch in ``dashboard.js``; keep in sync.
_KNOWN_REASONS = (
    "mpp_k_floor_exhausted",
    "circuit_rebuild_throttled",
    "bounded_retry_exhausted",
    "wall_clock_budget_exceeded",
    "external_state_unknown",
    "economy_feerate_unavailable",
    "stuck_htlc_alarm",
    "claim_feerate_outlier",
    "operator_signature_mismatch",
    "claim_tx_validation_failed",
    "clock_skew_exceeds_deadline_margin",
    "pipeline_schema_below_min_supported",
    "inbound_insufficient_at_lockup",
)


def _reason_to_slug(reason: str) -> str:
    """Mirror of the SPA's ``slug = reason.replace(/_/g, '-')`` rule."""
    return reason.replace("_", "-")


def _expected_anchor(reason: str) -> str:
    """The full anchor id the help page must surface."""
    return f"trouble-{_reason_to_slug(reason)}"


# ── Help page existence + anchor coverage ────────────────────────────


def test_help_page_exists() -> None:
    """The static help page MUST exist at the dashboard-served path."""
    assert _HELP_HTML.exists(), f"Expected help page at {_HELP_HTML} (referenced by dashboard.js _anonymizeOpenHelp)"


def test_help_page_has_generic_fallback_anchor() -> None:
    """Unknown reasons / missing slug route to ``#troubleshooting``."""
    html = _HELP_HTML.read_text(encoding="utf-8")
    assert 'id="troubleshooting"' in html


@pytest.mark.parametrize("reason", _KNOWN_REASONS)
def test_help_page_has_anchor_for_every_known_reason(reason: str) -> None:
    """Every reason in the SPA's label map must have a matching
    anchor in the help page. Missing ones would surface as "scrolled
    to top" instead of the expected section, which is bad UX."""
    html = _HELP_HTML.read_text(encoding="utf-8")
    anchor = _expected_anchor(reason)
    assert f'id="{anchor}"' in html, (
        f"Help page is missing anchor {anchor!r} for reason "
        f"{reason!r}. The SPA's Get-help button will resolve to a "
        f"non-existent anchor."
    )


@pytest.mark.parametrize("reason", _KNOWN_REASONS)
def test_help_page_also_includes_unknown_anchor(reason: str) -> None:
    """A dedicated ``trouble-unknown`` anchor exists so the SPA can
    point unrecognised reasons at a helpful page rather than the
    bare ``#troubleshooting`` TOC."""
    # Reuses the same parametrize fixture to be explicit; the
    # actual assertion is constant.
    html = _HELP_HTML.read_text(encoding="utf-8")
    assert 'id="trouble-unknown"' in html


# ── docs/anonymize.md cross-anchor parity ────────────────────────────


def test_docs_md_has_troubleshooting_section() -> None:
    """The canonical docs/anonymize_troubleshooting.md authors the per-reason
    runbook; the help page mirrors it. Both must surface the same
    anchor set so a docs reader and a dashboard user follow the
    same convention."""
    text = _ANONYMIZE_MD.read_text(encoding="utf-8")
    assert 'id="troubleshooting"' in text


@pytest.mark.parametrize("reason", _KNOWN_REASONS)
def test_docs_md_has_per_reason_anchor(reason: str) -> None:
    """Each reason needs a matching anchor in docs/anonymize.md."""
    text = _ANONYMIZE_MD.read_text(encoding="utf-8")
    anchor = _expected_anchor(reason)
    pattern = re.compile(rf'id="{re.escape(anchor)}"')
    assert pattern.search(text), (
        f"docs/anonymize.md is missing anchor {anchor!r} for reason "
        f"{reason!r}. The troubleshooting section in this "
        f"doc should mirror the dashboard's help page."
    )


def test_anchor_naming_convention_matches_spa() -> None:
    """Lock the slug rule. The SPA does:

        slug = reason.replace(/_/g, '-')
        href = '#trouble-' + slug

    A subtle change to the rule (e.g. switching to lowercased camelCase)
    would silently break every help link without breaking any tests
    that don't pin the rule itself."""
    assert _reason_to_slug("mpp_k_floor_exhausted") == "mpp-k-floor-exhausted"
    assert _reason_to_slug("operator_signature_mismatch") == ("operator-signature-mismatch")
    assert _expected_anchor("foo_bar") == "trouble-foo-bar"


def test_known_reasons_constant_matches_python_classifier() -> None:
    """Cross-file consistency lock.

    The Python classifier in ``reconciliation_classify.py`` enumerates
    the reasons in three internal frozensets. The test-side constant
    ``_KNOWN_REASONS`` is the source of truth for help-page coverage,
    docs anchors, and the SPA's ``_anonymizeReasonIsKnown`` set.
    They must stay in sync: if a new reason is added to the classifier
    without updating this constant, the help page and SPA won't ship
    coverage for it.
    """
    from app.services.anonymize import reconciliation_classify as _rc

    classifier_union = _rc._TRANSIENT_REASONS | _rc._SEMI_REASONS | _rc._TERMINAL_REASONS
    test_side = frozenset(_KNOWN_REASONS)
    missing_from_tests = classifier_union - test_side
    extra_in_tests = test_side - classifier_union
    assert not missing_from_tests, (
        f"reconciliation_classify has reasons that this test's "
        f"_KNOWN_REASONS constant is missing: {sorted(missing_from_tests)}. "
        f"Add them to _KNOWN_REASONS, ``app/dashboard/static/help/anonymize.html``, "
        f"``docs/anonymize.md`` troubleshooting section, and the SPA's "
        f"``_anonymizeReasonIsKnown`` set."
    )
    assert not extra_in_tests, (
        f"This test's _KNOWN_REASONS lists reasons not in the classifier: "
        f"{sorted(extra_in_tests)}. Either add them to the classifier "
        f"or remove from the test constant."
    )


def test_cancellable_reasons_subset_of_classifier_set() -> None:
    """The cancellable set must be a subset of the classifier's
    known reasons — a reason can't be cancellable without first being
    classified."""
    from app.services.anonymize import reconciliation_classify as _rc

    classifier_union = _rc._TRANSIENT_REASONS | _rc._SEMI_REASONS | _rc._TERMINAL_REASONS
    cancellable = _rc._CANCELLABLE_REASONS
    leaked = cancellable - classifier_union
    assert not leaked, (
        f"Reasons in _CANCELLABLE_REASONS not in the classifier: "
        f"{sorted(leaked)}. Every cancellable reason must be classified "
        f"so its recovery class is well-defined."
    )
