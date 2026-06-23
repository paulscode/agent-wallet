# SPDX-License-Identifier: MIT
"""Template-shape + browser-artifact regression guards for the
Braiins Deposit dedicated tab.

The Braiins Deposit launcher moved from a Total Balance corner button
to its own tab placed after Anonymize. These tests pin:

* The tab block exists in the dashboard template and is iterated via
  ``visibleTabs`` (so ``BRAIINS_DEPOSIT_ENABLED=false`` hides it).
* The corner-launcher block was removed.
* The ``visibleTabs`` getter gates on ``braiinsDepositEnabled``.
* The list-row template references the status / caption / time-ago
  helpers and uses the existing ``mempoolTxUrl`` for txid links.
* The pulse-dot is gated on the new ``braiinsDepositListHasActiveSession``
  getter (not the wizard-scoped ``braiinsDepositHasActiveSession``).
* The list-tab poller uses a timer name distinct from the wizard
  poller and has the three guards (active-session, active-tab,
  visibility).
* The bootstrap-config block + ``init()`` reader plumb the
  ``braiins_deposit_enabled`` flag through.
* The wizard create / cancel / retry / refund / regenerate-invoice
  success paths refresh the list.
"""

from __future__ import annotations

import re
from pathlib import Path

from app.models.braiins_deposit_session import BraiinsDepositStatus

_REPO = Path(__file__).resolve().parents[2]
_DASHBOARD_HTML = _REPO / "app" / "dashboard" / "templates" / "dashboard.html"
_DASHBOARD_JS = _REPO / "app" / "dashboard" / "static" / "dashboard.js"
_DASHBOARD_ROUTES = _REPO / "app" / "dashboard" / "routes.py"
_DASHBOARD_API = _REPO / "app" / "dashboard" / "api.py"


def _api() -> str:
    return _DASHBOARD_API.read_text(encoding="utf-8")


def _html() -> str:
    return _DASHBOARD_HTML.read_text(encoding="utf-8")


def _js() -> str:
    return _DASHBOARD_JS.read_text(encoding="utf-8")


def _routes() -> str:
    return _DASHBOARD_ROUTES.read_text(encoding="utf-8")


def _braiins_tab_block() -> str:
    """Return the HTML between the BRAIINS DEPOSIT TAB marker and the
    next tab (ACTIVITY)."""
    text = _html()
    start_marker = "<!-- BRAIINS DEPOSIT TAB"
    end_marker = "<!-- ACTIVITY TAB -->"
    start = text.find(start_marker)
    assert start != -1, "BRAIINS DEPOSIT TAB block not found in dashboard.html"
    end = text.find(end_marker, start)
    assert end != -1, "ACTIVITY TAB anchor missing after BRAIINS DEPOSIT TAB"
    return text[start:end]


# ── Template-shape regression guards ─────────────────────────────


def test_braiins_deposit_tab_block_exists() -> None:
    html = _html()
    assert "activeTab === 'braiins-deposit'" in html, (
        "BRAIINS DEPOSIT tab content block must exist in the dashboard template"
    )


def test_onchain_inbound_caveat_lives_in_glossary_not_a_banner() -> None:
    """Tier 1b — the inbound-routing caveat must stay discoverable via the
    on-chain glossary tooltips (the (i) buttons), NOT an always-on banner
    that crowds the form. Both on-chain source kinds carry it."""
    js = _js()
    # The caveat is part of the on-chain + external-onchain glossary bodies.
    assert js.count("auto-refunds and you pay the on-chain fees") >= 2, (
        "inbound-routing caveat must be present in both the 'on-chain' and 'external-onchain' glossary entries"
    )
    assert "needs your node to RECEIVE" in js, "glossary caveat must explain the deposit depends on inbound LN routing"
    # Regression guard: the always-on amber banner + steering button were
    # removed deliberately; don't let them creep back.
    html = _html()
    assert "Use a Lightning deposit instead" not in html, (
        "the always-on Lightning-steering banner button should not return"
    )


def test_channel_open_strategy_wired_in_dashboard() -> None:
    """Channel-open funding strategy: state, plumbing, labels, glossary,
    and the Advanced toggle are all present in the dashboard SPA."""
    js = _js()
    html = _html()
    # State + operator flag.
    assert "braiinsDepositFundingStrategy:" in js
    assert "braiinsDepositChannelOpenEnabled:" in js
    # funding_strategy threaded into the quote + create requests.
    assert js.count("funding_strategy: this.braiinsDepositFundingStrategy") >= 2, (
        "funding_strategy must be sent on the quote and create requests"
    )
    # OPENING_CHANNEL handled in the status helpers (label + step).
    assert "opening_channel" in js, "OPENING_CHANNEL must be labeled in the SPA"
    # Glossary entries + both surfaced via (i) tooltips (not orphaned).
    assert "'open-a-channel'" in js and "'channel-reserve'" in js
    assert "braiinsDepositToggleInfoTip('open-a-channel')" in html
    assert "braiinsDepositToggleInfoTip('channel-reserve')" in html
    # Reserve disclosed in the review (D3) — never folded into "fees".
    # These quote fields are read through null-safe getters in dashboard.js
    # (the @alpinejs/csp evaluator throws on dotted access of a null quote,
    # even guarded, during a quote refresh), so the field names live in the
    # JS now; the template renders them via the braiinsDepositChannel* getters.
    assert "channel_reserve_sats" in js
    # Channel-minimum over-commit surfaced: the channel size + the
    # bumped-to-minimum notice (what becomes Lightning balance).
    assert "channel_capacity_sats" in js
    assert "channel_bumped_to_min" in js
    assert "channel_excess_to_ln_sats" in js
    assert "minimum size" in html  # the bumped-to-min explanation copy
    # Bin affordability uses the per-bin quote's exact required-on-chain
    # (so a bumped channel deposit's 150k requirement greys unaffordable
    # bins correctly, not the rough swap estimate).
    assert "q.required_onchain_balance_sats" in js
    # The Advanced disclosure toggle + getter.
    assert "braiinsDepositChannelOptionAvailable" in js
    assert "braiinsDepositSelectFundingStrategy" in js
    assert "Open a channel instead of a swap" in html
    # Operator flag consumed from the presets payload.
    assert "presets.channel_open_enabled" in js
    # Include-extras toggle is NOT hidden for the channel strategy — the
    # final send is identical across sources, so the choice applies
    # consistently (regression guard against re-hiding it).
    assert 'x-show="!braiinsDepositIsChannelStrategy"' not in html


def test_recoverable_failure_framed_as_interrupted() -> None:
    """A FAILED session that still holds its fresh UTXO is recoverable
    (funds safe, Retry send finishes it) — the UI frames it as
    "interrupted", not a scary failure."""
    js = _js()
    html = _html()
    # The recoverable-failure helper + its use in badge/label/caption.
    assert "braiinsDepositIsRecoverableFailure" in js
    assert "INTERRUPTED" in js
    # Badge + chip are session-aware (so they can detect the fresh UTXO).
    assert "braiinsDepositStatusBadgeClass(s)" in html
    assert "braiinsDepositStatusLabel(s)" in html
    # Failure view reframes + affirms funds are safe.
    assert "Deposit interrupted" in html
    assert "funds are safe in your wallet" in js or "funds are safe" in html


def test_ext_oc_mempool_detection_banner() -> None:
    """When an ext-onchain deposit is seen in the mempool, the await
    screen swaps "Waiting for your deposit…" for "Deposit detected —
    waiting for confirmations (X/Y)" + a mempool link."""
    js = _js()
    html = _html()
    # Detection getters present + use the live confirmation count.
    assert "braiinsDepositExtDepositDetected" in js
    assert "confirmations_live" in js, (
        "detection must prefer the live confirmation count enriched by the detail endpoint"
    )
    assert "ext_oc_confirmations_required" in js
    # Banner + mempool link in the template.
    assert "Deposit detected" in html
    assert "braiinsDepositExtDepositDetected" in html
    assert "mempoolTxUrl(braiinsDepositExtDetectedTxid)" in html, (
        "detected banner must link the deposit tx to the mempool app"
    )


def test_cancelled_framed_neutrally_not_as_error() -> None:
    """A user-initiated Cancel is NOT a failure — the failed-step view
    must frame it neutrally ("Deposit cancelled", neutral icon), never as
    "Something went wrong" with an error reason. Driven by
    ``braiinsDepositIsCancelled``."""
    js = _js()
    html = _html()
    assert "braiinsDepositIsCancelled" in js, "cancelled-framing helper missing"
    assert "Deposit cancelled" in html, "cancelled view needs a neutral header"
    # The error ('Something went wrong') + Reason branches must EXCLUDE
    # cancelled, so a clean cancel never reads as an error.
    assert (
        "!braiinsDepositIsCancelled(braiinsDepositSession) "
        "&& !braiinsDepositIsRecoverableFailure(braiinsDepositSession)"
    ) in html, "the error branch must exclude cancelled"


def test_braiins_progress_poller_has_inflight_guard_and_timeout() -> None:
    """The 5s progress poller must not overlap slow detail requests (the
    detail endpoint drives a state tick + live confirmation lookups over
    Tor). Overlapping ticks pile up, congest Tor, and hang the rest of
    the dashboard — so it needs an in-flight guard + a bounded timeout."""
    js = _js()
    assert "_braiinsDepositPollInFlight" in js, "poller needs an in-flight guard"
    # The detail poll must carry a wall-clock timeout so a stuck request
    # aborts instead of wedging the poller.
    import re

    # Find the poll function and assert a timeoutMs is passed on its GET.
    m = re.search(r"_pollBraiinsDepositOnce\s*\(\)\s*\{.*?\n        \}", js, re.DOTALL)
    assert m, "_pollBraiinsDepositOnce not found"
    body = m.group(0)
    assert "_braiinsDepositPollInFlight = true" in body
    assert "timeoutMs" in body, "detail poll must pass a timeoutMs"


def test_channel_funding_tx_has_mempool_links() -> None:
    """The channel funding tx is viewable in the configured mempool app
    from both the list row and the progress view (same pattern as the
    submarine/send txids)."""
    html = _html()
    # Progress view: a "Channel funding transaction" block with a mempool link.
    assert "Channel funding transaction" in html
    assert "mempoolTxUrl(braiinsDepositSession.channel_open_txid)" in html
    # List row: a compact "channel tx" mempool link.
    assert "mempoolTxUrl(s.channel_open_txid)" in html
    # Live confirmation count ("N / M confirmations") in the progress view,
    # enriched by the session-detail endpoint.
    assert "channel_open_confirmations" in html
    assert "channel_activation_confs" in html
    api = _api()
    assert "channel_open_confirmations" in api
    assert "channel_activation_confs" in api


def test_channel_open_enabled_emitted_in_presets() -> None:
    api = _api()
    assert "channel_open_enabled" in api, "presets endpoint must emit channel_open_enabled for the wizard"


def test_connect_peer_preflight_wired() -> None:
    """D2/C — connect-peer preflight: endpoint + JS check + Start gate."""
    api = _api()
    js = _js()
    html = _html()
    assert "/braiins-deposit/channel-peer-check" in api, "preflight endpoint missing"
    assert "braiins_deposit_channel_peer_check" in api
    assert "_braiinsCheckChannelPeer" in js
    assert "braiinsDepositChannelPeerReachable" in js
    # Start is gated on reachability.
    assert "braiinsDepositChannelPeerReachable === false" in js
    # Soft warning surfaced.
    assert "Can't reach the channel peer" in html


def test_d1a_contextual_recommendation_wired() -> None:
    """D1(a) — surface channel-open when a swap is refused for inbound."""
    api = _api()
    js = _js()
    html = _html()
    assert "channel_open_suggested" in api, "endpoint must flag channel_open_suggested"
    assert "braiinsDepositChannelSuggested" in js
    assert "braiinsDepositAcceptChannelSuggestion" in js
    assert "Open a channel instead" in html


def test_d1c_post_refund_retry_wired() -> None:
    """D1(c) — retry a refunded on-chain swap via channel-open."""
    js = _js()
    html = _html()
    assert "braiinsDepositCanRetryViaChannel" in js
    assert "braiinsDepositRetryViaChannel" in js
    assert "Retry via channel" in html


def test_braiins_deposit_tab_in_tabs_array() -> None:
    js = _js()
    # The tab entry must exist…
    assert re.search(
        r"\{\s*id:\s*'braiins-deposit'\s*,"
        r"\s*label:\s*'Braiins Deposit'\s*,"
        r"\s*icon:\s*'pickaxe'\s*\}",
        js,
    ), "Braiins Deposit entry missing from the JS `tabs` array"
    # …and it must come after anonymize and before activity.
    anonymize_pos = js.find("id: 'anonymize'")
    braiins_pos = js.find("id: 'braiins-deposit'")
    activity_pos = js.find("id: 'activity'")
    assert 0 < anonymize_pos < braiins_pos < activity_pos, (
        "Braiins Deposit tab must be ordered between Anonymize and Activity"
    )


def test_total_balance_card_no_longer_carries_launcher() -> None:
    """The corner launcher block was removed. Regression guard against
    a future revert that re-introduces it."""
    html = _html()
    # The absolute-positioned launcher had a unique combination of
    # classes; assert none of these remain in the Total Balance card
    # region.
    forbidden = [
        "absolute bottom-3 left-3",
        'title="Send a round-amount deposit to Braiins Hashpower"',
    ]
    for needle in forbidden:
        assert needle not in html, f"corner-launcher artifact still present in template: {needle!r}"


def test_visible_tabs_getter_gates_braiins_deposit_on_enabled_flag() -> None:
    js = _js()
    # Find the getter body.
    m = re.search(
        r"get\s+visibleTabs\s*\(\)\s*\{(?P<body>.+?)\}\s*,",
        js,
        re.DOTALL,
    )
    assert m, "visibleTabs getter not found"
    body = m.group("body")
    assert "braiins-deposit" in body, "visibleTabs must reference the braiins-deposit tab id"
    assert "braiinsDepositEnabled" in body, "visibleTabs must gate braiins-deposit on braiinsDepositEnabled"


def test_tab_nav_iterates_visible_tabs_not_tabs() -> None:
    html = _html()
    assert 'x-for="t in visibleTabs"' in html, 'tab nav loop must use `x-for="t in visibleTabs"` so the gate works'
    # The legacy `x-for="t in tabs"` template loop is gone.
    assert 'x-for="t in tabs"' not in html, 'legacy `x-for="t in tabs"` template loop must be replaced'


def test_braiins_deposit_list_row_references_status_helpers() -> None:
    block = _braiins_tab_block()
    helpers = (
        "braiinsDepositStatusBadgeClass",
        "braiinsDepositStatusLabel",
        "braiinsDepositStatusCaption",
        # Dust prevention — row amount label is now produced by
        # ``braiinsDepositRowAmountLabel`` which formats the bin AND
        # the "absorbed" delta when actual_sent_sats != bin.
        "braiinsDepositRowAmountLabel",
        "braiinsDepositFormatDestination",
        "braiinsDepositRowTimeLabel",
    )
    for helper in helpers:
        assert helper in block, f"Braiins deposit row template missing reference to {helper}()"


def test_braiins_deposit_row_mempool_link_uses_existing_helper() -> None:
    """: per-row 'View on mempool' links use the existing
    ``mempoolTxUrl(txid)`` helper, not a hardcoded host."""
    block = _braiins_tab_block()
    assert "mempoolTxUrl(s.send_txid)" in block, "send_txid mempool link must use mempoolTxUrl() helper"
    # And no hardcoded mempool host in this block:
    assert "mempool.space" not in block, "Braiins deposit tab must not hardcode mempool.space — use mempoolTxUrl()"


def test_pulse_dot_gated_on_list_has_active_session() -> None:
    """The pulse-dot is gated on the new list-derived getter, not on
    the wizard-scoped flat property."""
    html = _html()
    # The nav-bar pulse-dot for the tab uses the new getter.
    needle = "t.id === 'braiins-deposit' && braiinsDepositListHasActiveSession"
    assert needle in html, "tab-nav pulse-dot must be gated on braiinsDepositListHasActiveSession"


# ── Bootstrap-config wiring ─────────────────────────────────────


def test_dashboard_page_context_includes_braiins_deposit_enabled() -> None:
    routes = _routes()
    # The TemplateResponse context dict carries the flag.
    assert "braiins_deposit_enabled" in routes, "routes.py must expose braiins_deposit_enabled to the template context"
    assert "settings.braiins_deposit_enabled" in routes


def test_bootstrap_config_emits_braiins_deposit_enabled() -> None:
    html = _html()
    assert "braiins_deposit_enabled" in html, "dashboard.html bootstrap-config block must emit braiins_deposit_enabled"
    # It must live in the dashboard-config <script> JSON block.
    cfg_block = re.search(
        r'<script id="dashboard-config"[^>]*>(.+?)</script>',
        html,
        re.DOTALL,
    )
    assert cfg_block, "dashboard-config <script> block not found"
    assert "braiins_deposit_enabled" in cfg_block.group(1)


def test_dashboard_js_reads_braiins_deposit_enabled_from_boot_config() -> None:
    js = _js()
    assert "cfg.braiins_deposit_enabled" in js, "init() boot-config reader must consume cfg.braiins_deposit_enabled"
    assert "this.braiinsDepositEnabled = cfg.braiins_deposit_enabled" in js, (
        "boot-config reader must assign cfg.braiins_deposit_enabled to the SPA flag"
    )


# ── SPA browser-artifact tests ──────────────────────────────────


def test_list_poller_pauses_on_three_guards() -> None:
    """``_braiinsDepositScheduleListPoll`` must observe all three
    guards: list has active session, tab is active, doc is visible."""
    js = _js()
    m = re.search(
        r"_braiinsDepositScheduleListPoll\s*\(\)\s*\{(?P<body>.+?)\n\s{8}\},",
        js,
        re.DOTALL,
    )
    assert m, "_braiinsDepositScheduleListPoll method body not found"
    body = m.group("body")
    assert "braiinsDepositListHasActiveSession" in body, "scheduler must short-circuit when no row is non-terminal"
    assert "this.activeTab !== 'braiins-deposit'" in body, "scheduler must short-circuit when the tab isn't active"
    assert "visibilityState" in body, "scheduler must short-circuit when the browser tab isn't visible"


def test_list_poller_timer_distinct_from_wizard_poller() -> None:
    """Regression guard: the list poller must NOT collide with the
    wizard (detail) poller. The list poll is a self-rescheduling
    ``setTimeout`` (``_braiinsDepositListPollTimer``); the wizard detail
    poll was migrated onto the guarded ``_poll`` utility under the
    ``braiinsDetail`` key. They remain distinct mechanisms with
    distinct identifiers."""
    js = _js()
    assert "_braiinsDepositListPollTimer" in js, "list poller timer name missing from SPA"
    # The wizard's detail poll must still exist — now via _poll().
    assert "_poll('braiinsDetail'" in js, "wizard detail poller went missing — wizard polling would break"


def test_wizard_create_handler_refreshes_list() -> None:
    """After a successful ``POST /braiins-deposit/sessions`` the create
    handler must refresh the deposits list."""
    js = _js()
    m = re.search(
        r"async\s+braiinsDepositStart\s*\(\)\s*\{(?P<body>.+?)\n\s{8}\},",
        js,
        re.DOTALL,
    )
    assert m, "braiinsDepositStart method body not found"
    body = m.group("body")
    assert "this.braiinsDepositFetchSessions()" in body, (
        "create handler must call braiinsDepositFetchSessions() after success"
    )


def test_wizard_cancel_handler_refreshes_list() -> None:
    js = _js()
    m = re.search(
        r"async\s+braiinsDepositCancel\s*\(\)\s*\{(?P<body>.+?)\n\s{8}\},",
        js,
        re.DOTALL,
    )
    assert m
    assert "braiinsDepositFetchSessions" in m.group("body")


def test_wizard_retry_handler_refreshes_list() -> None:
    js = _js()
    m = re.search(
        r"async\s+braiinsDepositRetrySend\s*\(\)\s*\{(?P<body>.+?)\n\s{8}\},",
        js,
        re.DOTALL,
    )
    assert m
    assert "braiinsDepositFetchSessions" in m.group("body")


def test_wizard_regenerate_invoice_handler_refreshes_list() -> None:
    js = _js()
    m = re.search(
        r"async\s+braiinsDepositRegenerateInvoice\s*\(\)\s*\{(?P<body>.+?)\n\s{8}\},",
        js,
        re.DOTALL,
    )
    assert m
    assert "braiinsDepositFetchSessions" in m.group("body")


def test_wizard_submit_refund_handler_refreshes_list() -> None:
    js = _js()
    m = re.search(
        r"async\s+braiinsDepositSubmitRefund\s*\(\)\s*\{(?P<body>.+?)\n\s{8}\},",
        js,
        re.DOTALL,
    )
    assert m
    assert "braiinsDepositFetchSessions" in m.group("body")


def test_restore_braiins_deposit_populates_sessions_list() -> None:
    """Page-load restore must seed ``braiinsDepositSessions`` so the
    pulse-dot lights immediately without waiting for the user to
    click the tab."""
    js = _js()
    m = re.search(
        r"async\s+_restoreBraiinsDeposit\s*\(\)\s*\{(?P<body>.+?)\n\s{8}\},",
        js,
        re.DOTALL,
    )
    assert m, "_restoreBraiinsDeposit method body not found"
    body = m.group("body")
    assert "this.braiinsDepositSessions" in body, "_restoreBraiinsDeposit must write to braiinsDepositSessions on load"


def test_restore_braiins_deposit_uses_shared_resume_helper() -> None:
    """_restoreBraiinsDeposit and the list-row Resume button
    must funnel through ``_resumeBraiinsDepositSession`` so the
    wizard-resume logic has a single source of truth."""
    js = _js()
    m = re.search(
        r"async\s+_restoreBraiinsDeposit\s*\(\)\s*\{(?P<body>.+?)\n\s{8}\},",
        js,
        re.DOTALL,
    )
    assert m
    assert "_resumeBraiinsDepositSession" in m.group("body"), (
        "_restoreBraiinsDeposit must delegate to _resumeBraiinsDepositSession"
    )


def test_resume_helper_supports_open_modal_option() -> None:
    """The shared resume helper must accept an ``openModal`` flag so
    page-load (no modal pop) and Resume-button (modal pop) paths can
    share the same implementation."""
    js = _js()
    m = re.search(
        r"_resumeBraiinsDepositSession\s*\(session(?:,\s*opts)?\)\s*\{"
        r"(?P<body>.+?)\n\s{8}\},",
        js,
        re.DOTALL,
    )
    assert m, "_resumeBraiinsDepositSession method body not found"
    body = m.group("body")
    # Either the signature explicitly takes opts/openModal, or the
    # body reads opts.openModal — either form is acceptable.
    assert "openModal" in body, "_resumeBraiinsDepositSession must honour an openModal option"


def test_wizard_terminal_transitions_refresh_list() -> None:
    """When the wizard's per-tick poller transitions to a
    terminal status (completed / failed / cancelled / refunded), the
    deposits-list tab must mirror that change so the row's status
    badge updates without waiting for the next list poll."""
    js = _js()
    m = re.search(
        r"async\s+_pollBraiinsDepositOnce\s*\([^)]*\)\s*\{(?P<body>.+?)\n\s{8}\},",
        js,
        re.DOTALL,
    )
    assert m, "_pollBraiinsDepositOnce method body not found"
    body = m.group("body")
    # The wizard poller has exactly two terminal branches — `completed`
    # and `failed|cancelled|refunded`. Both should call the list
    # refresher exactly once apiece so the list mirrors the wizard.
    # We pin "at least two" to allow for safe additional future calls.
    refresh_count = body.count("this.braiinsDepositFetchSessions()")
    assert refresh_count >= 2, (
        "wizard poller must refresh the deposits list on both terminal "
        f"branches (completed + failed/cancelled/refunded); found {refresh_count}"
    )
    # And both terminal-status conditionals must still be present.
    assert "data.status === 'completed'" in body
    assert "data.status === 'failed'" in body
    assert "'cancelled'" in body or "data.status === 'cancelled'" in body
    assert "'refunded'" in body or "data.status === 'refunded'" in body


def test_periodic_list_poll_refreshes_silently() -> None:
    """The 10 s deposits-list poll must refresh *silently* — no toggling
    of ``braiinsDepositSessionsLoading`` — so a background refresh doesn't
    flash the "Loading…" line and shift the list layout each tick
    (the reported periodic flicker)."""
    js = _js()
    poll = re.search(
        r"_braiinsDepositScheduleListPoll\s*\(\)\s*\{(?P<body>.+?)\n\s{8}\},",
        js,
        re.DOTALL,
    )
    assert poll, "_braiinsDepositScheduleListPoll not found"
    poll_body = poll.group("body")
    assert re.search(
        r"braiinsDepositFetchSessions\(\s*\{\s*silent:\s*true\s*\}\s*\)",
        poll_body,
    ), "periodic poll must call braiinsDepositFetchSessions({ silent: true })"

    fetch = re.search(
        r"async\s+braiinsDepositFetchSessions\s*\([^)]*\)\s*\{(?P<body>.+?)\n\s{8}\},",
        js,
        re.DOTALL,
    )
    assert fetch, "braiinsDepositFetchSessions not found"
    fbody = fetch.group("body")
    # Loading flag must be gated on !silent so polls don't flicker it.
    assert "if (!silent)" in fbody, "braiinsDepositFetchSessions must gate the loading flag on !silent"
    assert "braiinsDepositSessionsLoading = true" in fbody, "foreground fetches should still show the loading state"


# ── Status / caption helper coverage ────────────────────────────


def test_status_badge_class_covers_all_enum_values() -> None:
    """Every value in the server's ``BraiinsDepositStatus`` enum must
    map to a Tailwind class in the SPA's badge helper. Catches drift
    when a new status is added to the model without a UI counterpart."""
    js = _js()
    m = re.search(
        r"braiinsDepositStatusBadgeClass\s*\(\s*\w+\s*\)\s*\{(?P<body>.+?)\n\s{8}\},",
        js,
        re.DOTALL,
    )
    assert m, "braiinsDepositStatusBadgeClass method body not found"
    body = m.group("body")
    # The body has a default branch for unknown statuses, but every
    # enum value should appear explicitly so the maintainer is forced
    # to pick a colour rather than silently falling back to slate.
    missing = [member.value for member in BraiinsDepositStatus if f"case '{member.value}':" not in body]
    assert not missing, f"braiinsDepositStatusBadgeClass missing explicit branches for: {missing}"


def test_status_caption_handles_refunded_branch() -> None:
    """REFUNDED is a terminal-but-distinct state — its caption must
    not be the same as FAILED."""
    js = _js()
    m = re.search(
        r"braiinsDepositStatusCaption\s*\(\s*session\s*\)\s*\{(?P<body>.+?)\n\s{8}\},",
        js,
        re.DOTALL,
    )
    assert m, "braiinsDepositStatusCaption method body not found"
    body = m.group("body")
    assert "case 'refunded'" in body, "REFUNDED status must have its own caption branch"
    assert "case 'failed'" in body, "FAILED status must have its own caption branch"


def test_status_caption_covers_all_enum_values() -> None:
    """Parallel to ``test_status_badge_class_covers_all_enum_values``
    — every status the server can emit must have an explicit caption
    branch. A missing branch would render the raw enum value (like
    "submarine_swapping") to the user, which is unhelpful."""
    js = _js()
    m = re.search(
        r"braiinsDepositStatusCaption\s*\(\s*session\s*\)\s*\{(?P<body>.+?)\n\s{8}\},",
        js,
        re.DOTALL,
    )
    assert m
    body = m.group("body")
    missing = [member.value for member in BraiinsDepositStatus if f"case '{member.value}':" not in body]
    assert not missing, (
        f"braiinsDepositStatusCaption missing explicit branches for: "
        f"{missing} — every BraiinsDepositStatus value should have a "
        f"human-readable caption so the user never sees the raw enum"
    )


def test_status_label_covers_all_enum_values() -> None:
    """The progress-log line uses ``_braiinsDepositStatusLabel`` to turn
    each ``status_history`` entry into human text. Every status the
    server can record must have an explicit case — a missing one falls
    through to the raw-enum default and leaks e.g. 'awaiting_ln_funds'
    into the log (now visible in the success/failed panels too)."""
    js = _js()
    m = re.search(
        r"_braiinsDepositStatusLabel\s*\(\s*status\s*,\s*detail\s*\)\s*\{"
        r"(?P<body>.+?)\n\s{8}\},",
        js,
        re.DOTALL,
    )
    assert m, "_braiinsDepositStatusLabel not found"
    body = m.group("body")
    missing = [member.value for member in BraiinsDepositStatus if f"case '{member.value}':" not in body]
    assert not missing, (
        f"_braiinsDepositStatusLabel missing explicit branches for: "
        f"{missing} — every status that can appear in status_history must "
        f"map to human text so the progress log never shows the raw enum"
    )


def test_progress_log_autoscrolls_to_newest_entry() -> None:
    """The live progress log auto-scrolls to the newest entry when a new
    transition is appended — gated on a length increase so a steady-state
    5 s poll doesn't yank a user who scrolled up back to the bottom."""
    assert 'x-ref="braiinsProgressLog"' in _html(), "live progress-log container must expose an x-ref for autoscroll"
    js = _js()
    assert "$refs.braiinsProgressLog" in js and "scrollTop" in js, (
        "poller must scroll the progress-log ref to its newest entry"
    )
    assert "_braiinsDepositLogLen" in js, (
        "autoscroll must be gated on a new entry being appended (tracked via _braiinsDepositLogLen)"
    )


def test_broadcast_caption_surfaces_error_message_when_stuck() -> None:
    """The server's ``_maybe_flag_stuck`` writes a warning
    to ``error_message`` on BROADCAST rows whose send tx hasn't
    confirmed within ``BRAIINS_DEPOSIT_BROADCAST_STUCK_BLOCKS``. The
    list-row caption must surface that warning so the user notices."""
    js = _js()
    m = re.search(
        r"braiinsDepositStatusCaption\s*\(\s*session\s*\)\s*\{(?P<body>.+?)\n\s{8}\},",
        js,
        re.DOTALL,
    )
    assert m
    body = m.group("body")
    # Locate the broadcast branch and verify it consults error_message.
    bcast = re.search(
        r"case 'broadcast':\s*(?P<branch>.+?)case ",
        body,
        re.DOTALL,
    )
    assert bcast, "broadcast caption branch not found"
    assert "error_message" in bcast.group("branch"), (
        "broadcast caption must surface session.error_message (the stuck-warning written by _maybe_flag_stuck)"
    )


def test_primary_action_covers_failed_with_fresh_utxo() -> None:
    """A FAILED session with a ``fresh_utxo_txid`` is
    retry-eligible regardless of source kind (the wizard's existing
    ``braiinsDepositCanRetrySend`` getter gates on the same condition).
    The row must surface a primary action so the user can recover."""
    js = _js()
    m = re.search(
        r"braiinsDepositHasPrimaryAction\s*\(\s*session\s*\)\s*\{(?P<body>.+?)\n\s{8}\},",
        js,
        re.DOTALL,
    )
    assert m
    body = m.group("body")
    assert "fresh_utxo_txid" in body, (
        "braiinsDepositHasPrimaryAction must check fresh_utxo_txid so "
        "FAILED-after-FUNDED self-source sessions surface a retry action"
    )


def test_primary_action_label_distinguishes_retry_vs_refund() -> None:
    """When a FAILED row offers a primary action, the label must
    distinguish "Retry send" (fresh UTXO still recoverable via the
    /retry-send endpoint) from "Submit refund" (ext_onchain refund-
    prompt panel needed)."""
    js = _js()
    m = re.search(
        r"braiinsDepositPrimaryActionLabel\s*\(\s*session\s*\)\s*\{(?P<body>.+?)\n\s{8}\},",
        js,
        re.DOTALL,
    )
    assert m
    body = m.group("body")
    assert "'Retry send'" in body, (
        "Primary action label must include 'Retry send' for the FAILED-with-fresh-utxo retry branch"
    )
    assert "'Submit refund'" in body, (
        "Primary action label must include 'Submit refund' for the ext_onchain refund-prompt branch"
    )
    assert "'Resume'" not in body, (
        "the generic 'Resume' label was removed — awaiting-funds rows no "
        "longer carry a redundant button that just re-opens the dialog "
        "(the row click already does that)"
    )


def test_awaiting_funds_rows_have_no_redundant_resume_button() -> None:
    """``awaiting_ln_funds`` / ``awaiting_onchain_funds`` rows must NOT
    surface a primary-action button: it only re-opened the dialog, which
    clicking the row already does. Only states whose button does
    something a row click doesn't (e.g. the fee-reduction override) keep
    a button."""
    js = _js()
    m = re.search(
        r"braiinsDepositHasPrimaryAction\s*\(\s*session\s*\)\s*\{(?P<body>.+?)\n\s{8}\},",
        js,
        re.DOTALL,
    )
    assert m
    body = m.group("body")
    assert "case 'awaiting_onchain_funds':" not in body, (
        "awaiting_onchain_funds must not return a primary action (redundant)"
    )
    assert "case 'awaiting_ln_funds':" not in body, "awaiting_ln_funds must not return a primary action (redundant)"
    # The fee-reduction override (a genuinely distinct action) stays.
    assert "case 'awaiting_fee_reduction':" in body


def test_swap_terminal_statuses_matches_server_terminal_set() -> None:
    """The client-side ``SWAP_TERMINAL_STATUSES`` set drives the
    pulse-dot, the poller, and the resume routing. Pin it against
    the server's ``TERMINAL_STATUSES`` frozenset so future status
    additions can't silently desync."""
    from app.models.braiins_deposit_session import TERMINAL_STATUSES

    js = _js()
    m = re.search(
        r"SWAP_TERMINAL_STATUSES\s*=\s*new Set\(\[(?P<body>[^\]]+)\]\)",
        js,
    )
    assert m, "SWAP_TERMINAL_STATUSES declaration not found"
    listed = {s.strip().strip("'\"") for s in m.group("body").split(",") if s.strip()}
    server_set = {s.value for s in TERMINAL_STATUSES}
    assert listed == server_set, (
        f"SWAP_TERMINAL_STATUSES has drifted from server's TERMINAL_STATUSES: client={listed} server={server_set}"
    )


# ── Tab header card ──────────────────────────────────────────────


def test_header_card_renders_new_deposit_button_calling_open_wizard() -> None:
    """The header card carries a '+ New deposit' button
    that invokes the existing wizard via ``openBraiinsDeposit()`` —
    the wizard itself is unchanged, only its entry point moved."""
    block = _braiins_tab_block()
    # The button must invoke openBraiinsDeposit (existing method —
    # the corner launcher previously called the same method).
    assert "openBraiinsDeposit()" in block, "header card '+ New deposit' button must call openBraiinsDeposit()"
    # Visible label.
    assert "New deposit" in block, "header card must render the 'New deposit' button label"


def test_header_card_body_describes_the_feature() -> None:
    """The header card's body copy explains what Braiins
    Deposit does so a first-time visitor doesn't have to dig for the
    feature's purpose. The exact wording is a regression guard
    against accidental copy churn."""
    # Normalize whitespace so a line break inside "Braiins Hashpower"
    # (from prose word-wrap in the template) doesn't trip the search.
    normalized = re.sub(r"\s+", " ", _braiins_tab_block())
    # Key phrases that should survive any copy polish.
    assert "Braiins Hashpower" in normalized, (
        "header card body must mention 'Braiins Hashpower' so the user knows which pool this is for"
    )
    assert "Boltz" in normalized, (
        "header card body must mention 'Boltz' so the UTXO-provenance rationale is discoverable from the SPA itself"
    )
    assert "manual review" in normalized, (
        "header card body must mention 'manual review' so the user understands what problem the feature solves"
    )


def test_header_action_switches_to_resume_when_deposit_in_flight() -> None:
    """The server enforces one in-flight deposit per key, so the header
    action is honest about it: when a deposit is active it offers
    "View in progress" (resume the live dialog) instead of silently
    reopening under a "New deposit" label. Both buttons are gated on
    ``braiinsDepositListHasActiveSession`` so exactly one shows."""
    block = _braiins_tab_block()
    # Active → "View in progress" calling braiinsDepositResumeActive().
    resume_match = re.search(
        r'<template x-if="braiinsDepositListHasActiveSession">'
        r".*?braiinsDepositResumeActive\(\).*?View in progress.*?</template>",
        block,
        re.DOTALL,
    )
    assert resume_match, (
        "header must offer a 'View in progress' action gated on "
        "braiinsDepositListHasActiveSession that calls "
        "braiinsDepositResumeActive()"
    )
    # Idle → "New deposit" calling openBraiinsDeposit().
    new_match = re.search(
        r'<template x-if="!braiinsDepositListHasActiveSession">'
        r".*?openBraiinsDeposit\(\).*?New deposit.*?</template>",
        block,
        re.DOTALL,
    )
    assert new_match, (
        "header must offer a 'New deposit' action gated on "
        "!braiinsDepositListHasActiveSession that calls openBraiinsDeposit()"
    )


# ── Deposits list — surrounding panel ────────────────────────────


def test_list_panel_has_refresh_button_calling_fetch() -> None:
    """The deposits list panel has a manual Refresh
    button that always works, independent of the auto-poll cadence."""
    block = _braiins_tab_block()
    # The Refresh button must invoke braiinsDepositFetchSessions.
    refresh_match = re.search(
        r'<button[^>]*?x-on:click="braiinsDepositFetchSessions\(\)"[^>]*?>'
        r".*?Refresh.*?</button>",
        block,
        re.DOTALL,
    )
    assert refresh_match, "deposits list panel must carry a Refresh button calling braiinsDepositFetchSessions()"


def test_list_panel_renders_empty_state_copy() -> None:
    """Empty-state copy must guide the first-time user to
    the '+ New deposit' button."""
    block = _braiins_tab_block()
    # Gated on the right tri-state condition.
    empty_match = re.search(
        r"braiinsDepositSessions\.length === 0\s*"
        r"&&\s*!braiinsDepositSessionsLoading\s*"
        r"&&\s*!braiinsDepositSessionsError",
        block,
    )
    assert empty_match, "empty-state must be gated on three conditions: list empty, not loading, no error"
    # And the user-facing copy must point at the '+ New deposit' button.
    assert "No deposits yet" in block, "empty-state must surface 'No deposits yet' guidance copy"


def test_list_panel_renders_loading_state() -> None:
    """Loading state shows a 'Loading…' line while the
    fetch is in flight."""
    block = _braiins_tab_block()
    assert 'x-show="braiinsDepositSessionsLoading"' in block, (
        "loading state must be gated on braiinsDepositSessionsLoading"
    )
    assert ("Loading…" in block) or ("Loading&hellip;" in block), "loading state must render the 'Loading…' message"


def test_list_panel_renders_error_state() -> None:
    """Fetch error renders the message in red and keeps
    the refresh button clickable."""
    block = _braiins_tab_block()
    error_match = re.search(
        r'x-show="braiinsDepositSessionsError"[^>]*?x-text="braiinsDepositSessionsError"',
        block,
    )
    assert error_match, "error state must be gated on + rendered from braiinsDepositSessionsError"
    # And the styling tone must be red.
    assert "text-red-" in block, "error state must use red text styling"


# ── Details disclosure ───────────────────────────────────────────


def test_details_disclosure_button_toggles_per_row() -> None:
    """Each row has a Details button that toggles
    an inline disclosure scoped to the row's session id."""
    block = _braiins_tab_block()
    # Button must invoke the toggle helper with the row's session id.
    assert "braiinsDepositToggleRowDetails(s.id)" in block, (
        "Details disclosure toggle must scope to the row's session id"
    )
    # And the disclosure body must be gated on the same per-row flag.
    assert 'x-show="braiinsDepositRowDetailsOpen[s.id]"' in block, (
        "Details disclosure body must be gated on braiinsDepositRowDetailsOpen[s.id]"
    )


def test_details_disclosure_renders_pipeline_fields() -> None:
    """The Details disclosure surfaces the
    pipeline txids + error_message that the user might need to
    diagnose a failure (submarine, fresh UTXO, send, refund, error)."""
    block = _braiins_tab_block()
    # The disclosure body must reference each pipeline field. Each
    # field is gated by an x-if so it only renders when present.
    for needle in (
        "submarine_funding_txid",
        "fresh_utxo_txid",
        "send_txid",
        "send_confirmations",
        "refund_txid",
        "error_message",
    ):
        assert needle in block, f"Details disclosure must surface {needle!r}"


def test_details_chevron_uses_static_icons_for_lucide_compat() -> None:
    """Lucide replaces ``<i>`` with ``<svg>`` once, so a dynamic
    ``:data-lucide`` binding would strand the icon in its initial
    direction. Two static icons gated by ``x-show`` is the right
    pattern."""
    block = _braiins_tab_block()
    # Both chevron icons must be present, each gated by an x-show on
    # the disclosure state.
    chevron_down = re.search(
        r'<i\s+data-lucide="chevron-down"[^>]*?x-show="!braiinsDepositRowDetailsOpen\[s\.id\]"',
        block,
    )
    chevron_up = re.search(
        r'<i\s+data-lucide="chevron-up"[^>]*?x-show="braiinsDepositRowDetailsOpen\[s\.id\]"',
        block,
    )
    assert chevron_down, (
        "Details disclosure must render a static chevron-down icon gated "
        "on closed state (lucide replaces <i> with <svg> on first sweep, "
        "so dynamic :data-lucide would strand the icon direction)"
    )
    assert chevron_up, "Details disclosure must render a static chevron-up icon gated on open state"


# ── Auto-refresh cadence ─────────────────────────────────────────


def test_list_poller_uses_10_second_cadence() -> None:
    """Poll every 10 seconds while at least one row is
    non-terminal. Pin the literal so a future tuning ('1 hour, why
    not?') has to deliberately update both code AND test."""
    js = _js()
    m = re.search(
        r"_braiinsDepositScheduleListPoll\s*\(\)\s*\{(?P<body>.+?)\n\s{8}\},",
        js,
        re.DOTALL,
    )
    assert m, "_braiinsDepositScheduleListPoll method body not found"
    body = m.group("body")
    setTimeout_match = re.search(
        r"setTimeout\([^,]+,\s*([\d_]+)\s*\)",
        body,
    )
    assert setTimeout_match, "setTimeout call not found in list poller"
    interval_literal = setTimeout_match.group(1).replace("_", "")
    interval_ms = int(interval_literal)
    assert interval_ms == 10000, f"poll cadence must be 10000 ms (10 s); got {interval_ms}"


def test_list_poller_uses_setTimeout_not_setInterval() -> None:
    """The poller re-arms itself via ``setTimeout`` after
    each fetch resolves, not a ``setInterval`` that fires regardless
    of overlapping requests. This is a subtle but important
    distinction — setInterval would queue up parallel requests when
    the network is slow."""
    js = _js()
    m = re.search(
        r"_braiinsDepositScheduleListPoll\s*\(\)\s*\{(?P<body>.+?)\n\s{8}\},",
        js,
        re.DOTALL,
    )
    assert m
    body = m.group("body")
    assert "setTimeout(" in body, (
        "list poller must use setTimeout so the next fetch is scheduled after the current one resolves"
    )
    assert "setInterval(" not in body, (
        "list poller must NOT use setInterval (would queue overlapping fetches under slow network)"
    )


# ── Active-session getter logic ──────────────────────────────────


def test_list_has_active_session_getter_excludes_terminal_statuses() -> None:
    """The indicator getter must return true iff any row
    is in a non-terminal status, i.e. iff at least one row's status
    is NOT in ``SWAP_TERMINAL_STATUSES``."""
    js = _js()
    m = re.search(
        r"get braiinsDepositListHasActiveSession\(\)\s*\{(?P<body>.+?)\n\s{8}\},",
        js,
        re.DOTALL,
    )
    assert m, "braiinsDepositListHasActiveSession getter not found"
    body = m.group("body")
    assert "braiinsDepositSessions.some" in body, "getter must iterate the sessions list"
    assert "SWAP_TERMINAL_STATUSES.has" in body, "getter must check terminal-status membership"
    assert "!" in body, "getter must negate the terminal-status check (active = not terminal)"


# ── Helper: braiinsDepositRowTimeLabel branches ───────────────────────


def test_row_time_label_distinguishes_terminal_from_in_flight() -> None:
    """Terminal rows use ``completed_at`` (with ``updated_at``
    and ``created_at`` fallbacks); non-terminal rows always show
    'submitted Nm ago' from ``created_at``."""
    js = _js()
    m = re.search(
        r"braiinsDepositRowTimeLabel\s*\(\s*session\s*\)\s*\{(?P<body>.+?)\n\s{8}\},",
        js,
        re.DOTALL,
    )
    assert m, "braiinsDepositRowTimeLabel method body not found"
    body = m.group("body")
    # Must consult terminal status to decide which timestamp to use.
    assert "SWAP_TERMINAL_STATUSES" in body, "row time label must branch on terminal vs non-terminal status"
    # The terminal branch must prefer completed_at with fallbacks.
    assert "completed_at" in body, "terminal-branch row time label must consult completed_at"
    assert "updated_at" in body, (
        "row time label must fall back to updated_at for terminal rows "
        "where completed_at is null (REFUNDED / FAILED / CANCELLED)"
    )
    assert "created_at" in body, "row time label must consult created_at for non-terminal rows"


# ── Empty state distinguished from filtered/no-results ───────────


def test_empty_state_only_shows_when_list_is_truly_empty() -> None:
    """There's no client-side filtering — the empty state
    shows iff the server returned zero rows, not iff a filter
    elided them. Pin the three-condition gate so a future "show
    only active" toggle doesn't quietly swallow the empty copy."""
    block = _braiins_tab_block()
    # The empty-state copy must be inside a template gated on
    # length === 0 AND !loading AND !error.
    empty_template_match = re.search(
        r'<template[^>]*?x-if="braiinsDepositSessions\.length === 0[^"]*?">'
        r".*?No deposits yet.*?</template>",
        block,
        re.DOTALL,
    )
    assert empty_template_match, (
        "empty-state copy must live inside an x-if gated on the list actually being empty (not just loading or error)"
    )


# ── Resume helper modal behavior ─────────────────────────────────


def test_resume_helper_opens_modal_only_when_requested() -> None:
    """The shared helper opens the wizard modal when
    invoked by the list-row Resume button (``openModal: true``) but
    NOT when invoked by ``_restoreBraiinsDeposit`` on page load —
    auto-popping the modal on every page reload would be jarring."""
    js = _js()
    m = re.search(
        r"_resumeBraiinsDepositSession\s*\(session(?:,\s*opts)?\)\s*\{"
        r"(?P<body>.+?)\n\s{8}\},",
        js,
        re.DOTALL,
    )
    assert m
    body = m.group("body")
    # The modal-open assignment must be conditionally guarded.
    open_block = re.search(
        r"if\s*\(\s*openModal\s*\)\s*\{[^}]*?braiinsDepositOpen\s*=\s*true",
        body,
        re.DOTALL,
    )
    assert open_block, (
        "_resumeBraiinsDepositSession must only set braiinsDepositOpen when the caller passed openModal=true"
    )
    # And the wizard poller must always start (so wizard-state hydrates
    # whether or not the modal is open).
    assert "_startBraiinsDepositPoller" in body, (
        "_resumeBraiinsDepositSession must start the wizard poller "
        "regardless of openModal so the session state stays fresh"
    )


def test_invoke_primary_action_opens_modal() -> None:
    """Clicking a row's primary-action button must
    surface the wizard modal so the user sees the input UI
    (refund-address panel, await-funds panel, etc.)."""
    js = _js()
    m = re.search(
        r"braiinsDepositInvokePrimaryAction\s*\(session\)\s*\{(?P<body>.+?)\n\s{8}\},",
        js,
        re.DOTALL,
    )
    assert m, "braiinsDepositInvokePrimaryAction method body not found"
    body = m.group("body")
    assert "_resumeBraiinsDepositSession" in body, "primary-action button must delegate to the shared resume helper"
    # And it must request a modal pop (openModal: true).
    assert "openModal: true" in body, (
        "primary-action button must request openModal: true so the wizard surfaces the input UI"
    )


# ── List state initialization ────────────────────────────────────


def test_failure_explanation_distinguishes_transient_from_terminal() -> None:
    """The wizard's failure view used to say "Your Lightning balance
    was not debited" for ANY failure with no ``fresh_utxo_txid`` —
    including transient ``Connection failed`` errors where the HTLC
    is in fact in-flight at Boltz (LN balance IS reduced). This was
    the user-facing half of the 2026-05-21 incident.

    The fix adds a third branch that inspects ``error_message`` for
    the transient prefixes that ``send_payment_sync`` surfaces when
    the HTTP stream to LND drops. Pin the branch so a future copy
    polish doesn't silently revert it.
    """
    js = _js()
    m = re.search(
        r"get\s+braiinsDepositFailureExplanation\(\)\s*\{(?P<body>.+?)\n\s{8}\},",
        js,
        re.DOTALL,
    )
    assert m, "braiinsDepositFailureExplanation getter not found"
    body = m.group("body")
    # The existing two branches must still be present (sats-safe +
    # not-debited paths).
    assert "fresh_utxo_txid" in body, "getter must still gate the 'sats are safe' branch on fresh_utxo_txid"
    assert "not debited" in body, (
        "getter must still surface the 'Lightning balance was not debited' message for definitive payment failures"
    )
    # The new branch must inspect error_message for at least one of
    # the transient prefixes the LND client surfaces.
    assert "error_message" in body, (
        "getter must consult error_message to distinguish transient (in-flight HTLC) from definitive failures"
    )
    transient_markers = (
        "connection failed",
        "request failed",
        "did not reach a terminal state",
        "lnd error",
    )
    found = [m for m in transient_markers if m in body.lower()]
    assert found, (
        "getter must check error_message for at least one transient "
        "prefix (Connection failed / Request failed / "
        "did not reach a terminal state / LND error 5xx); none of "
        f"{transient_markers!r} were found"
    )
    # And it must produce different copy in the transient branch.
    assert "in-flight" in body.lower() or "still in flight" in body.lower(), (
        "transient branch must mention the in-flight HTLC so the user "
        "doesn't think their balance was untouched (it wasn't)"
    )


def test_wizard_template_uses_no_alpinejs_csp_forbidden_globals() -> None:
    """The dashboard runs the @alpinejs/csp build which does NOT
    expose JS globals (``Math``, ``JSON``, ``Date``, etc.) inside
    expressions. Any ``x-text="Math.max(...)"`` etc. in the wizard
    template crashes at evaluation time with ``Undefined variable:
    Math`` and the affected UI never renders.

    The fix is to move the computation into a getter on the Alpine
    state object (see ``braiinsDepositExpectedChangeSats`` /
    ``braiinsDepositExtRemainingSats``).

    This test scans the dashboard template for any forbidden global
    inside an Alpine directive attribute and fails fast if one is
    introduced.
    """
    html = (Path(__file__).resolve().parents[2] / "app" / "dashboard" / "templates" / "dashboard.html").read_text(
        encoding="utf-8"
    )
    # Find every Alpine directive (x-..., :..., @...) and check that
    # its attribute value has no forbidden globals. Use word-boundary
    # anchors so legitimate helper names (``formatDate``, ``parseAmount``,
    # etc.) don't false-match on the global they merely resemble.
    directive_re = re.compile(
        r'(?:x-[a-z:.-]+|@\w+|:\w+(?:\.\w+)*)="([^"]*)"',
    )
    forbidden_globals = (
        re.compile(r"\bMath\."),
        re.compile(r"\bJSON\."),
        re.compile(r"\bDate\."),
        re.compile(r"\bnew Date\b"),
        re.compile(r"\bObject\."),
        re.compile(r"\bArray\."),
        re.compile(r"\bparseInt\b"),
        re.compile(r"\bparseFloat\b"),
        re.compile(r"\bNumber\("),
        re.compile(r"\bString\("),
        re.compile(r"\bBoolean\("),
        re.compile(r"\bwindow\."),
        re.compile(r"\bdocument\."),
        re.compile(r"\blocalStorage\b"),
        re.compile(r"\bsessionStorage\b"),
        re.compile(r"\bconsole\."),
        re.compile(r"\bsetTimeout\b"),
        re.compile(r"\bsetInterval\b"),
        re.compile(r"\bfetch\("),
        re.compile(r"\bPromise\."),
        re.compile(r"\bencodeURIComponent\b"),
        re.compile(r"\bdecodeURIComponent\b"),
    )
    offenders: list[tuple[str, str]] = []
    for m in directive_re.finditer(html):
        expr = m.group(1)
        for needle in forbidden_globals:
            if needle.search(expr):
                offenders.append((needle.pattern, expr))
    assert not offenders, (
        "Alpine directive attributes must not reference JS globals "
        "(@alpinejs/csp doesn't expose them) — move the computation "
        "into an Alpine getter. Offenders:\n"
        + "\n".join(f"  {needle!r} in {expr[:120]}" for needle, expr in offenders[:10])
    )


def test_wizard_template_uses_no_alpinejs_csp_unsupported_syntax() -> None:
    """The @alpinejs/csp expression evaluator supports a restricted
    subset of JS. Several modern syntactic forms aren't compiled in
    and silently fail at render time:

      * optional chaining ``a?.b``
      * nullish coalescing ``a ?? b``
      * template literals (backticks)
      * arrow functions ``=>``
      * spread/rest operator ``...``

    The codebase works around each via explicit alternatives (safe-
    shape defaults, ternaries, string concatenation, named methods).
    This test catches any reintroduction in Alpine directive
    attributes.
    """
    html = (Path(__file__).resolve().parents[2] / "app" / "dashboard" / "templates" / "dashboard.html").read_text(
        encoding="utf-8"
    )
    directive_re = re.compile(
        r'(?:x-[a-z:.-]+|@\w+|:\w+(?:\.\w+)*)="([^"]*)"',
    )
    unsupported = (
        (re.compile(r"\?\."), "optional chaining (?.)"),
        (re.compile(r"\?\?"), "nullish coalescing (??)"),
        (re.compile(r"`"), "template literal (backticks)"),
        (re.compile(r"=>"), "arrow function (=>)"),
        # Match `...` only when followed by an identifier or `{`/`[`
        # so legitimate ellipses in user-facing copy ('Syncing...',
        # 'Loading...') don't false-trip.
        (re.compile(r"\.\.\.\s*[A-Za-z_$\[\{]"), "spread/rest operator (...)"),
    )
    offenders: list[tuple[str, str]] = []
    for m in directive_re.finditer(html):
        expr = m.group(1)
        for needle, label in unsupported:
            if needle.search(expr):
                offenders.append((label, expr))
    assert not offenders, (
        "Alpine directive attributes must not use JS syntax that "
        "@alpinejs/csp doesn't compile in. Offenders:\n"
        + "\n".join(f"  {label}: {expr[:120]}" for label, expr in offenders[:10])
    )


def test_open_wizard_is_synchronous() -> None:
    """UX: ``openBraiinsDeposit`` must NOT be ``async`` — awaiting
    the LND-backed /braiins-deposit/presets fetch before showing the
    modal gave a 3-4 s "is this button broken?" delay. The modal must
    open synchronously, with the presets refresh deferred to the
    background via ``_refreshBraiinsDepositPresets``."""
    js = _js()
    m = re.search(
        r"^\s{8}(async\s+)?openBraiinsDeposit\(\)\s*\{",
        js,
        re.MULTILINE,
    )
    assert m, "openBraiinsDeposit() declaration not found"
    assert m.group(1) is None, (
        "openBraiinsDeposit() must NOT be async — the modal needs to "
        "open synchronously so the click feels instant. The LND-backed "
        "presets fetch is deferred to _refreshBraiinsDepositPresets()."
    )


def test_open_wizard_seeds_balances_from_cached_summary() -> None:
    """UX: with the LND fetch deferred to the background, the modal
    must seed its balance state from the dashboard's already-cached
    ``localBalance``/``confirmedBalance`` so the chip-affordability
    check is sensible on first render."""
    js = _js()
    m = re.search(
        r"^\s{8}openBraiinsDeposit\(\)\s*\{(?P<body>.+?)^\s{8}\},",
        js,
        re.DOTALL | re.MULTILINE,
    )
    assert m
    body = m.group("body")
    assert "this.localBalance" in body, (
        "openBraiinsDeposit() must seed braiinsDepositLnBalance from "
        "this.localBalance (the dashboard's cached LN balance) so the "
        "form renders correctly before the background fetch resolves"
    )
    assert "this.confirmedBalance" in body, (
        "openBraiinsDeposit() must seed braiinsDepositOnchainBalance "
        "from this.confirmedBalance (the dashboard's cached on-chain "
        "balance) for the same reason"
    )


def test_open_wizard_fires_background_presets_refresh() -> None:
    """UX: both branches of ``openBraiinsDeposit`` (resume in-flight
    session AND clean form reset) must fire the background presets
    fetch — otherwise the form's chip-affordability check ages
    indefinitely off the cached values."""
    js = _js()
    m = re.search(
        r"^\s{8}openBraiinsDeposit\(\)\s*\{(?P<body>.+?)^\s{8}\},",
        js,
        re.DOTALL | re.MULTILINE,
    )
    assert m
    body = m.group("body")
    # Two call sites: one in the in-flight resume branch, one in the
    # clean-form branch.
    refresh_calls = body.count("_refreshBraiinsDepositPresets(")
    assert refresh_calls >= 2, (
        "openBraiinsDeposit() must fire _refreshBraiinsDepositPresets() "
        "from BOTH branches (in-flight resume AND clean form reset); "
        f"found {refresh_calls}"
    )


def test_refresh_presets_helper_exists_and_is_async() -> None:
    """UX: the background refresh must be async so the modal opens
    in the same tick the click handler returns."""
    js = _js()
    m = re.search(
        r"^\s{8}async _refreshBraiinsDepositPresets\(\)\s*\{(?P<body>.+?)^\s{8}\},",
        js,
        re.DOTALL | re.MULTILINE,
    )
    assert m, (
        "_refreshBraiinsDepositPresets() must exist and be declared ``async`` (it does the LND-backed presets fetch)"
    )
    body = m.group("body")
    # Must hit the presets endpoint.
    assert "/braiins-deposit/presets" in body, "_refreshBraiinsDepositPresets() must fetch /braiins-deposit/presets"
    # And must consume the documented payload fields.
    for field in (
        "preset_amounts",
        "lightning_local_balance_sats",
        "onchain_confirmed_balance_sats",
        "ext_enabled",
        "ext_ln_invoice_ttl_s",
    ):
        assert field in body, f"_refreshBraiinsDepositPresets() must consume {field!r} from the /presets payload"


def test_list_state_fields_initialized() -> None:
    """The new list-tab state fields must be declared on
    the Alpine.data object with sensible defaults. Catches typos /
    re-typings in future refactors."""
    js = _js()
    # Extract the Alpine.data block. We look for a slice of the
    # declarations rather than the whole object.
    expected = (
        ("braiinsDepositSessions: []", "list defaults to empty array"),
        ("braiinsDepositSessionsLoading: false", "loading flag defaults to false"),
        ("braiinsDepositSessionsError: ''", "error message defaults to empty string"),
        ("_braiinsDepositListPollTimer: null", "list poller timer handle defaults to null"),
        ("braiinsDepositRowDetailsOpen: {}", "per-row disclosure state defaults to empty object"),
    )
    for needle, why in expected:
        assert needle in js, f"missing list-tab state initializer: {needle!r} ({why})"


# ── Reopen any deposit (active or terminal) + read-only history ──────


def _wizard_block(start_marker: str, end_marker: str) -> str:
    text = _html()
    start = text.find(start_marker)
    assert start != -1, f"{start_marker!r} not found in dashboard.html"
    end = text.find(end_marker, start)
    assert end != -1, f"{end_marker!r} not found after {start_marker!r}"
    return text[start:end]


def test_list_row_is_clickable_to_reopen_dialog() -> None:
    """Every deposit row (active OR terminal) must reopen the dialog so
    a non-technical user has one consistent way back into any deposit.
    The row is a keyboard-accessible button bound to
    braiinsDepositViewSession(s)."""
    block = _braiins_tab_block()
    li_match = re.search(r"<li\b[^>]*>", block)
    assert li_match, "deposits list <li> not found"
    li = li_match.group(0)
    assert "braiinsDepositViewSession(s)" in li, "list row must call braiinsDepositViewSession(s) to reopen the dialog"
    assert 'role="button"' in li and "tabindex=" in li, "list row must be keyboard-accessible (role=button + tabindex)"
    assert "keydown.enter" in li, "list row must reopen on Enter key"


def test_inner_row_controls_stop_propagation() -> None:
    """Inner controls (primary action, txid links, Details toggle,
    details disclosure) must stop click propagation so they don't also
    trigger the row-level reopen."""
    block = _braiins_tab_block()
    # Primary action + Details toggle use .stop on their click bindings.
    assert 'x-on:click.stop="braiinsDepositInvokePrimaryAction(s)"' in block, (
        "primary action button must use x-on:click.stop"
    )
    assert 'x-on:click.stop="braiinsDepositToggleRowDetails(s.id)"' in block, "Details toggle must use x-on:click.stop"
    # The three external tx links carry a bare x-on:click.stop guard.
    assert block.count("x-on:click.stop") >= 5, (
        "row action button, details toggle, details container, and the three tx links must all stop propagation"
    )


def test_success_panel_renders_progress_log() -> None:
    """Reopening a COMPLETED deposit must show its full timestamped
    history, so the success panel includes the progress-log block.
    Scoped to the braiins wizard via its step anchor (the bare
    "SUCCESS" comment is shared with other wizards)."""
    success = _wizard_block(
        "braiinsDepositStep === 'success'",
        "braiinsDepositStep === 'failed'",
    )
    assert "braiinsDepositProgressLog" in success, "success panel must render the braiinsDepositProgressLog block"


def test_failed_panel_renders_progress_log() -> None:
    """Reopening a FAILED/CANCELLED/REFUNDED deposit must show its full
    timestamped history, so the failed panel includes the log block."""
    failed = _wizard_block(
        "braiinsDepositStep === 'failed'",
        "<!-- ═══ API KEYS MODAL ═══ -->",
    )
    assert "braiinsDepositProgressLog" in failed, "failed panel must render the braiinsDepositProgressLog block"


def test_view_session_and_resume_active_helpers_exist() -> None:
    """The reopen plumbing must be present: a per-row view helper and a
    header resume-active helper."""
    js = _js()
    assert "braiinsDepositViewSession(session)" in js, "braiinsDepositViewSession(session) helper must exist"
    assert "braiinsDepositResumeActive()" in js, "braiinsDepositResumeActive() helper must exist"


def test_resume_helper_skips_poller_for_terminal_sessions() -> None:
    """A reopened terminal deposit is read-only history — the 5 s poller
    must NOT run for it (it would needlessly re-hit the detail endpoint).
    The resume helper branches on SWAP_TERMINAL_STATUSES around the
    poller start."""
    js = _js()
    helper = re.search(
        r"_resumeBraiinsDepositSession\(session, opts\) \{.*?\n        \},",
        js,
        re.DOTALL,
    )
    assert helper, "_resumeBraiinsDepositSession not found"
    body = helper.group(0)
    assert "_stopBraiinsDepositPoller()" in body, "resume helper must stop the poller for terminal sessions"
    assert "SWAP_TERMINAL_STATUSES.has(session.status" in body, (
        "resume helper must branch poller start on terminal status"
    )
    assert "_startBraiinsDepositPoller()" in body, "resume helper must still start the poller for live sessions"
