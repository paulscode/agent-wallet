# SPDX-License-Identifier: MIT
"""Shape + privacy guards for the Anonymize "phase & health" progress
timeline in the dashboard.

Posture: render only a
friendly per-event label + a COARSE relative timestamp, plus the current
status phase and curated health fields. NEVER render raw event detail,
txids, addresses, operator IDs, or the withdrawal side; never leak a raw
status enum or event kind. Live-refresh while active; static once
terminal; retention-aware.

These are static-shape tests (the dashboard JS has no JS test runner),
matching the repo's existing dashboard-test convention.
"""

from __future__ import annotations

import re
from pathlib import Path

from app.models.anonymize_session import AnonymizeStatus

_REPO = Path(__file__).resolve().parents[2]
_DASHBOARD_HTML = _REPO / "app" / "dashboard" / "templates" / "dashboard.html"
_DASHBOARD_JS = _REPO / "app" / "dashboard" / "static" / "dashboard.js"


def _html() -> str:
    return _DASHBOARD_HTML.read_text(encoding="utf-8")


def _js() -> str:
    return _DASHBOARD_JS.read_text(encoding="utf-8")


def _anonymize_tab_block() -> str:
    text = _html()
    start = text.find("<!-- ANONYMIZE TAB")
    assert start != -1, "ANONYMIZE TAB block not found"
    end = text.find("<!-- ACTIVITY TAB -->", start)
    assert end != -1, "ACTIVITY TAB anchor missing"
    return text[start:end]


def _js_func(name: str) -> str:
    """Return the body of a method ``name(...) { ... }`` from dashboard.js,
    matched to the dedent-closing ``\\n        },`` (8-space indent)."""
    js = _js()
    m = re.search(
        rf"{re.escape(name)}\([^)]*\)\s*\{{(?P<body>.+?)\n        \}},",
        js,
        re.DOTALL,
    )
    assert m, f"method {name} not found in dashboard.js"
    return m.group("body")


# ── Current-phase label coverage (no raw enum) ───────────────────────


def test_status_label_covers_all_statuses() -> None:
    """``anonymizeStatusLabel`` is the friendly current-phase label; every
    AnonymizeStatus must be handled so the raw enum never reaches the UI.
    (awaiting_reconciliation is handled via its own branch, not the map.)"""
    body = _js_func("anonymizeStatusLabel")
    missing = [m.value for m in AnonymizeStatus if (f"{m.value}:" not in body) and (f"'{m.value}'" not in body)]
    assert not missing, (
        f"anonymizeStatusLabel missing explicit handling for: {missing} — "
        f"every status must map to friendly text (no raw enum in the UI)"
    )


# ── Event-label whitelist: unknown/noisy kinds are filtered ──────────


def test_event_label_filters_unknown_kinds() -> None:
    """``_anonymizeEventLabel`` must map via a whitelist and return '' for
    anything not in it — so a raw/new/internal kind is filtered from the
    timeline rather than shown verbatim."""
    body = _js_func("_anonymizeEventLabel")
    assert "labels[kind] || ''" in body, (
        "_anonymizeEventLabel must default unknown kinds to '' (whitelist-only; never return the raw kind)"
    )
    # The real, user-meaningful persisted event kinds get friendly labels.
    for kind in (
        "hop_attempt_started",
        "hop_attempt_completed",
        "auto_peer_chosen",
        "reconciliation_attempt_started",
        "reconciliation_attempt_completed",
        "reconciliation_escalated",
        "anonymize_refund_locked",
    ):
        assert f"{kind}:" in body, f"meaningful event kind {kind!r} must be labelled"
    # Noisy internal / retention / audit kinds must NOT be mapped to a
    # label (they fall through to '' and are filtered). Checked as object
    # keys (``kind:``) so the explanatory comment naming them doesn't
    # count as a mapping.
    for noisy in (
        "reconciliation_wall_clock_flipped",
        "reconciliation_pre_status_heuristic_applied",
        "mpp_k_floor_exhausted",
        "redacted_history",
    ):
        assert f"{noisy}:" not in body, f"internal kind {noisy!r} must not be mapped to a timeline label"


def test_progress_entries_filter_empty_labels_and_read_no_detail() -> None:
    """The timeline builder must drop filtered (empty-label) entries and
    read ONLY ``kind`` + ``ts`` from each event — never ``detail`` — so no
    linkable data can leak regardless of detail_json contents."""
    body = _js_func("anonymizeProgressEntries")
    assert "if (!label) continue" in body, "must filter empty-label entries"
    assert "ev.kind" in body and "ev.ts" in body, "must read kind + ts"
    assert "ev.detail" not in body and ".detail" not in body, "timeline must NEVER read raw event detail (privacy)"
    # Coarse timestamps via the existing relative-time helper.
    assert "anonymizeRelativeTime(ev.ts)" in body, "must use coarse relative time"


# ── Retention awareness ──────────────────────────────────────────────


def test_expired_note_gated_on_terminal_and_empty() -> None:
    body = _js_func("anonymizeProgressExpiredNote")
    assert "_anonymizeIsTerminalStatus" in body, "retention note must only show for terminal sessions"
    assert "retention" in body.lower(), "note must mention retention"
    # Not-loaded sessions return '' (no premature note).
    assert "if (!Array.isArray(events)) return ''" in body


# ── Live while active, static when terminal ──────────────────────────


def test_open_detail_refreshes_only_while_non_terminal() -> None:
    """The sessions poll must live-refresh an OPEN detail's timeline only
    while its session is non-terminal; a terminal detail stays static."""
    js = _js()
    # The poll tick refreshes the open detail through the detail fetch,
    # gated on a non-terminal status check.
    poll = re.search(
        r"anonymizeStartSessionsPolling\(\)\s*\{(?P<body>.+?)\n        \}",
        js,
        re.DOTALL,
    )
    assert poll, "anonymizeStartSessionsPolling not found"
    pbody = poll.group("body")
    assert "anonymizeSessionDetailOpen" in pbody
    assert "!this._anonymizeIsTerminalStatus(open.status)" in pbody, "must skip refresh for terminal sessions"
    assert "_anonymizeFetchSessionRecovery(openSid)" in pbody


def test_detail_fetch_captures_events() -> None:
    """The detail fetch (which feeds the recovery banner) must also
    capture the privacy-projected event list for the timeline."""
    body = _js_func("_anonymizeFetchSessionRecovery")
    assert "anonymizeSessionEvents" in body
    assert "data.events" in body


# ── Template wiring + no detail/identifier leakage in the markup ─────


def test_detail_panel_renders_progress_timeline() -> None:
    block = _anonymize_tab_block()
    assert "anonymizeProgressEntries(s)" in block, "inline detail panel must render the progress timeline"
    assert "anonymizeProgressExpiredNote(s)" in block, "inline detail panel must render the retention note"
    # The timeline markup renders only the friendly label + coarse time.
    assert "e.label" in block and "e.when" in block
    # And must not reach into raw event detail / identifiers from markup.
    for forbidden in ("e.detail", "e.txid", "e.address", ".detail_json"):
        assert forbidden not in block, f"progress markup must not reference {forbidden!r}"
