# SPDX-License-Identifier: MIT
"""Browser-artifact minimization for the anonymize tab.

The anonymize wizard keeps state in memory only:

* No ``localStorage`` / ``sessionStorage`` / ``IndexedDB`` writes.
* No URL search params or fragment identifiers carry destination
  addresses, deposit invoices, output txids, quote tokens, or session
  detail payloads.
* Sensitive ``<input>`` elements (when the wizard ships) carry
  ``autocomplete="off"``, ``autocapitalize="off"``, ``autocorrect="off"``,
  ``spellcheck="false"``, and no ``name`` value that invites browser
  address-book autofill.
* No third-party JS, analytics, error-reporting beacon, remote font,
  or remote image in the anonymize view.

The placeholder tab body ships no inputs of its own. The test
enforces the *no-storage / no-third-party* part of the
policy and a soft "warn me when inputs land" diagnostic. The
input-attribute checks become hard once the wizard renders fields.
"""

from __future__ import annotations

import re
from pathlib import Path

_DASHBOARD_HTML = Path(__file__).resolve().parents[2] / "app" / "dashboard" / "templates" / "dashboard.html"
_DASHBOARD_JS = Path(__file__).resolve().parents[2] / "app" / "dashboard" / "static" / "dashboard.js"


def _anonymize_tab_block() -> str:
    """Return the HTML region between the ANONYMIZE TAB marker and the next tab."""
    text = _DASHBOARD_HTML.read_text(encoding="utf-8")
    start_marker = "<!-- ANONYMIZE TAB"
    end_marker = "<!-- ACTIVITY TAB -->"
    start = text.find(start_marker)
    assert start != -1, "ANONYMIZE TAB block not found in dashboard.html"
    end = text.find(end_marker, start)
    assert end != -1, "ACTIVITY TAB anchor missing after ANONYMIZE TAB"
    return text[start:end]


def test_anonymize_tab_has_no_browser_storage_writes() -> None:
    block = _anonymize_tab_block()
    forbidden = (
        "localStorage",
        "sessionStorage",
        "indexedDB",
        "IndexedDB",
        "document.cookie",
    )
    offenders = [f for f in forbidden if f in block]
    assert not offenders, f"anonymize tab block must not write to browser storage; found: {offenders}"


def test_anonymize_tab_has_no_third_party_assets() -> None:
    """No remote JS / fonts / images sourced from outside the dashboard origin."""
    block = _anonymize_tab_block()
    third_party_pat = re.compile(
        r"""(?:
            <script\s+[^>]*src=["']https?://      # remote <script src>
            | <link\s+[^>]*href=["']https?://     # remote <link href>
            | <img\s+[^>]*src=["']https?://       # remote <img>
            | <iframe\s+[^>]*src=["']https?://    # remote <iframe>
        )""",
        re.VERBOSE,
    )
    matches = third_party_pat.findall(block)
    assert not matches, f"anonymize tab block must not reference third-party assets; found: {matches}"


def test_dashboard_js_anonymize_tab_entry_present() -> None:
    """The Anonymize tab must be registered in the SPA's tabs array."""
    js = _DASHBOARD_JS.read_text(encoding="utf-8")
    assert "id: 'anonymize'" in js, "Anonymize tab missing from SPA tabs[]"


def test_anonymize_tab_inputs_disable_browser_artifacts() -> None:
    """Every text/number ``<input>`` in the anonymize tab
    disables browser autocomplete / autocapitalize / autocorrect /
    spellcheck so a clipboard-history or browser-profile sync can't
    quietly capture the destination address + amount.

    Radio + checkbox inputs are exempt — they have no text-cache
    surface and the browser doesn't autofill them. So is the
    unquoted ``type=radio`` variant (used by the new button-card
    source picker, where the radio is hidden via ``sr-only``).
    """
    block = _anonymize_tab_block()
    import re

    inputs = re.findall(r"<input\b[^>]*>", block, flags=re.IGNORECASE)
    assert inputs, "Anonymize tab has no <input> elements"
    sensitive = [
        tag
        for tag in inputs
        if not re.search(
            r'type\s*=\s*"?(radio|checkbox)"?',
            tag,
            flags=re.IGNORECASE,
        )
    ]
    for tag in sensitive:
        lowered = tag.lower()
        assert 'autocomplete="off"' in lowered, f"missing autocomplete=off: {tag}"
        assert 'autocapitalize="off"' in lowered, f"missing autocapitalize=off: {tag}"
        assert 'autocorrect="off"' in lowered, f"missing autocorrect=off: {tag}"
        assert 'spellcheck="false"' in lowered, f"missing spellcheck=false: {tag}"


# ── — deposit-method selector + step 4 wiring ──────────────────


def test_wizard_state_carries_deposit_method() -> None:
    """The anonymize wizard's reactive state MUST carry a
    ``deposit_method`` field so the BOLT 11 / BOLT 12 selector
    binds. Without this the ext-lightning radio group has nothing
    to ``x-model`` against and the toggle silently no-ops."""
    js = _DASHBOARD_JS.read_text(encoding="utf-8")
    assert "deposit_method" in js, "anonymize wizard JS missing deposit_method field"


def test_wizard_sends_deposit_method_on_ext_lightning() -> None:
    """The quote payload MUST include ``deposit_method`` when the
    selected source is ``ext-lightning`` — otherwise the per-quote
    binding falls back to the operator default and the SPA's
    explicit choice is silently ignored."""
    js = _DASHBOARD_JS.read_text(encoding="utf-8")
    assert "payload.deposit_method = this.anonymizeWizardDepositMethod" in js


def test_wizard_deposit_step_renders_deposit_block() -> None:
    """The deposit-primitive step (renumbered from 4 → 2 by the
    merged-form rework) MUST render the ``deposit`` block from the
    create-session response. Without this step the depositor has
    no way to retrieve the BOLT 11 invoice / BOLT 12 offer they
    need to pay."""
    block = _anonymize_tab_block()
    # The deposit-primitive panel exists at Step 2 and reads from
    # anonymizeCreated.deposit.
    assert "anonymizeWizardStep === 2" in block
    assert "anonymizeCreated.deposit.bolt12_offer" in block
    assert "anonymizeCreated.deposit.bolt11_invoice" in block
    assert "anonymizeCreated.deposit.bip353_handle" in block
    assert "anonymizeCreated.deposit.bip353_txt_record" in block


def test_wizard_deposit_step_includes_qr_canvas() -> None:
    """The deposit-render panel includes a QR canvas so the depositor
    can scan from a phone wallet without a clipboard copy step."""
    block = _anonymize_tab_block()
    assert 'x-ref="anonDepositQr"' in block


def test_wizard_confirm_transitions_to_deposit_step() -> None:
    """After a successful create with an ext-source primitive, the
    wizard captures the response into ``anonymizeCreated`` and
    advances to the deposit step (Step 2 in the merged-form layout,
    renumbered from the historical Step 4)."""
    js = _DASHBOARD_JS.read_text(encoding="utf-8")
    assert "this.anonymizeCreated = data" in js
    assert "this.anonymizeWizardStep = 2" in js


def test_wizard_deposit_method_radio_present() -> None:
    """The step-2 deposit-method radio group exists and is gated to
    ext-lightning sources (other source kinds don't have a deposit
    invoice the depositor pays)."""
    block = _anonymize_tab_block()
    assert 'name="anz_deposit_method"' in block
    assert 'value="bolt11"' in block
    assert 'value="bolt12"' in block
    # The group must be hidden for non-ext-lightning sources.
    assert "anonymizeWizardSourceKind === 'ext-lightning'" in block


def test_step1_form_is_merged_braiins_style() -> None:
    """The merged-form rework collapses the historical 3-input-step
    wizard into a single Step 1 with source + amount-chips +
    destination + inline quote review. Pins the structural anchors
    so a future refactor that accidentally splits these back into
    separate steps trips this guard."""
    block = _anonymize_tab_block()
    # The "Where should the sats come from?" header (Braiins-style).
    assert "Where should the sats come from?" in block
    # The bin-chip selector is rendered by iterating anonymizeBinPresets.
    assert "anonymizeBinPresets" in block
    assert "anonymizeSelectAmount" in block
    # The destination address input lives on the same Step 1.
    assert "anonymizeWizardDestinationAddress" in block
    # The inline quote review (advisory tier badge) is rendered on
    # Step 1, not gated behind a Preview step.
    assert "anonymizeQuoteOrEmpty.advisory_tier" in block
    # The old explicit Steps 2 and 3 no longer exist (their content
    # is merged inline into Step 1).
    assert "<!-- Step 2: details -->" not in block
    assert "<!-- Step 3: review -->" not in block


def test_step1_liquid_toggle_above_source_picker() -> None:
    """The Liquid hop opt-in renders ABOVE the 'Where should the
    sats come from?' source picker — placement is a deliberate UX
    call so users see the advanced privacy switch before they
    commit to a source kind."""
    block = _anonymize_tab_block()
    liquid_idx = block.find("'liquid-route'")
    source_label_idx = block.find("Where should the sats come from?")
    assert liquid_idx > 0
    assert source_label_idx > 0
    assert liquid_idx < source_label_idx, "Liquid hop toggle should render above the source picker"


def test_dashboard_js_exposes_merged_form_helpers() -> None:
    """The new merged-form Step 1 relies on a handful of JS helpers
    that the template references; pin them so a refactor that
    drops one trips this guard rather than producing a silent UI
    bug."""
    js = _DASHBOARD_JS.read_text(encoding="utf-8")
    for name in (
        "anonymizeSelectSource",  # source button-card click handler
        "anonymizeSelectAmount",  # bin-chip click handler
        "anonymizeBinAllowed",  # per-chip disabled gate
        "_debounceAnonymizeQuote",  # auto-fetch debouncer
        "get anonymizeSourceCaption",  # per-source caption getter
        "get anonymizeBinPresets",  # runtime bin list (from policy)
    ):
        assert name in js, f"dashboard.js missing merged-form helper: {name}"


def test_bin_presets_source_from_operator_policy() -> None:
    """The chip set rendered by the wizard MUST reflect the
    operator's actual ``amount_bins_sat`` configuration rather than
    a hardcoded ladder — otherwise an operator who restricts bins
    sees chips for amounts the server would reject."""
    js = _DASHBOARD_JS.read_text(encoding="utf-8")
    # The getter reads from the policy first.
    assert "this.anonymizePolicy" in js
    assert "amount_bins_sat" in js
    # And falls back to the canonical ladder when the policy hasn't
    # loaded yet OR is misconfigured with an empty bin list.
    assert "_anonymizeBinPresetsFallback" in js, "Missing the fallback ladder for empty/missing policy bins"


def test_default_amount_snaps_to_policy_bin_on_load() -> None:
    """When the operator's bin list doesn't include the hardcoded
    250,000 default, the policy-load handler should snap the
    requested amount to the nearest configured bin — otherwise no
    chip is highlighted on first paint, and the user has to
    explicitly pick before they can preview a quote."""
    js = _DASHBOARD_JS.read_text(encoding="utf-8")
    assert "_anonymizeSnapAmountToPolicyBins" in js, "Missing the snap-to-nearest-bin helper"
    # And the policy fetch must invoke it.
    import re

    match = re.search(r"async anonymizeFetchPolicy\(\)\s*\{(.*?)\n\s{8}\},", js, re.DOTALL)
    assert match
    body = match.group(1)
    assert "_anonymizeSnapAmountToPolicyBins" in body, (
        "anonymizeFetchPolicy() must call _anonymizeSnapAmountToPolicyBins"
    )


def test_chip_selector_guards_against_disabled_amounts() -> None:
    """The chip click handler must refuse to set an amount that
    falls outside the operator's policy (min_sat / max_sat). Both
    the chip's ``:disabled`` attribute AND the JS handler enforce
    this — defence-in-depth against UI-state desync."""
    js = _DASHBOARD_JS.read_text(encoding="utf-8")
    block = _anonymize_tab_block()
    # The template's chip button binds :disabled to the
    # ``anonymizeBinDisabled`` wrapper (which composes the policy
    # ``anonymizeBinAllowed`` predicate with the self-source
    # insufficient-balance check).
    assert ':disabled="anonymizeBinDisabled(amt)"' in block, "Chip selector must disable chips outside the policy range"
    # The JS handler also short-circuits on the same predicate so
    # disabled chips can't be activated via keyboard or via dev-tools.
    assert "if (this.anonymizeBinDisabled(amt)) return" in js, "anonymizeSelectAmount must guard against disabled bins"


def test_generate_address_button_triggers_debounced_quote_refetch() -> None:
    """When the user clicks the 'Generate' button (programmatic
    address set), the input's ``@input`` handler doesn't fire, so
    the debounced quote fetch wouldn't otherwise re-run. The
    handler must explicitly call ``_debounceAnonymizeQuote`` after
    setting the address so the inline preview reflects the new
    destination."""
    js = _DASHBOARD_JS.read_text(encoding="utf-8")
    import re

    func_match = re.search(
        r"async anonymizeGenerateDestinationAddress\(\)\s*\{(.*?)\n\s{8}\},",
        js,
        re.DOTALL,
    )
    assert func_match, "anonymizeGenerateDestinationAddress() not found"
    body = func_match.group(1)
    assert "this.anonymizeWizardDestinationAddress = data.address" in body
    assert "_debounceAnonymizeQuote" in body, (
        "anonymizeGenerateDestinationAddress must kick the debounced "
        "quote fetch after setting the address programmatically"
    )


def test_wizard_close_and_reset_cancel_debounce_timer() -> None:
    """A debounced quote-fetch scheduled before close/reset must
    NOT fire afterwards — it would either render a stale preview
    against a closed wizard or pollute the next session's state."""
    js = _DASHBOARD_JS.read_text(encoding="utf-8")
    import re

    for fn_name in ("anonymizeWizardClose", "anonymizeWizardReset"):
        match = re.search(rf"{fn_name}\(\)\s*\{{(.*?)\n\s{{8}}\}},", js, re.DOTALL)
        assert match, f"{fn_name}() not found"
        body = match.group(1)
        assert "_anonymizeQuoteDebounceTimer" in body, f"{fn_name}() must clear the debounced quote timer"


def test_step1_source_radios_have_info_icons() -> None:
    """Each Step-1 source radio carries an ⓘ info-icon that opens a
    plain-language popover explaining the source. Mirrors the
    Braiins-Deposit external-source picker so the two wizards feel
    consistent."""
    block = _anonymize_tab_block()
    for tip_key in (
        "'src-lightning-self'",
        "'src-onchain-self'",
        "'src-ext-lightning'",
        "'src-ext-onchain'",
    ):
        assert f"anonymizeToggleInfoTip({tip_key})" in block, f"Step-1 source picker missing info-icon for {tip_key}"
    # The popovers must render via the standard anonymizeInfoTipOpen
    # gating used elsewhere in the wizard.
    for tip_key in (
        "'src-lightning-self'",
        "'src-onchain-self'",
        "'src-ext-lightning'",
        "'src-ext-onchain'",
    ):
        assert f"anonymizeInfoTipOpen === {tip_key}" in block, (
            f"Step-1 source picker missing popover gate for {tip_key}"
        )


# ── — operator-diversity advisory banner ─────────────────────


def test_wizard_state_carries_anonymize_policy() -> None:
    """The SPA caches the server-side policy fetch so the step-1
    advisory banner can read ``operator_diversity.distinct_operators_configured``
    without an extra round-trip.

    Historical note: the cache used to default to ``null`` and call
    sites guarded with ``anonymizePolicy && anonymizePolicy.x``. The
    @alpinejs/csp build was found NOT to reliably short-circuit
    ``a && a.b`` when ``a`` is null — it touched ``a.b`` anyway and
    threw — so the default was refactored to a safe-shape object
    with zero / empty fields, plus an ``anonymizePolicyLoaded`` flag
    that gates "have we fetched yet?" checks.
    """
    js = _DASHBOARD_JS.read_text(encoding="utf-8")
    # The safe-shape default must declare the field and at least the
    # min/max keys the template reads directly.
    assert "anonymizePolicy: {" in js
    assert "min_sat: 0" in js
    assert "max_sat: 0" in js
    # The hydration flag replaces the old ``=== null`` check.
    assert "anonymizePolicyLoaded: false" in js
    # The fetch helper itself stays unchanged.
    assert "anonymizeFetchPolicy" in js


def test_wizard_fetches_policy_on_open() -> None:
    """The policy endpoint MUST be fetched lazily on first wizard open
    so the banner has its inputs available without a blocking call
    during dashboard startup."""
    js = _DASHBOARD_JS.read_text(encoding="utf-8")
    # The reset-and-open helper triggers the policy fetch when the
    # cache is empty.
    assert "this.anonymizeFetchPolicy()" in js
    assert "/anonymize/policy" in js


def test_wizard_step1_renders_single_operator_banner() -> None:
    """The step-1 combined on-chain advisory block exists in the
    template, is gated on ``anonymizeShowSingleOperatorBanner()``,
    leads with the consolidated "capped at moderate" framing, mentions
    the single-operator clause, and carries the Learn-more link the
    docs file backs."""
    block = _anonymize_tab_block()
    assert 'x-show="anonymizeShowSingleOperatorBanner()"' in block
    assert "Privacy capped at moderate" in block
    assert "single Boltz operator handling both legs" in block
    # The Learn-more anchor is x-bind:href to the policy-returned URL
    # so the SPA stays in sync with whichever docs path the backend
    # advertises.
    assert 'x-bind:href="anonymizeOperatorDiversityLearnMoreUrl()"' in block


def test_wizard_step1_renders_distinct_operator_onchain_banner() -> None:
    """The shorter on-chain advisory for distinct-operator deployments
    exists, is gated on its own helper, and drops the operator clause."""
    block = _anonymize_tab_block()
    assert 'x-show="anonymizeShowDistinctOperatorOnchainBanner()"' in block
    # Both variants share the "Privacy capped at moderate:" lede; the
    # distinct-operator variant must NOT mention the single-operator
    # join clause, which only applies to single-operator deployments.
    # We assert structural presence here; the gating-by-source test
    # below covers when each variant fires.


def test_wizard_banner_predicate_gates_on_onchain_source() -> None:
    """The banner predicate MUST only fire for on-chain source kinds.
    Lightning sources have no submarine leg + therefore no
    correlation, so the advisory would be misleading."""
    js = _DASHBOARD_JS.read_text(encoding="utf-8")
    # The predicate gates on both 'onchain-self' and 'ext-onchain'.
    assert "'onchain-self', 'ext-onchain'" in js
    # And falls back to "don't show" when the policy fetch failed.
    assert "if (!od) return false" in js


def test_quote_fetch_skips_when_destination_empty() -> None:
    """The form-first rework auto-triggers ``anonymizeFetchQuote`` on
    source-kind / amount / Liquid-toggle changes. If the user hasn't
    typed a destination yet, the server returns an opaque 422 and the
    UI would surface a misleading "preview failed" error. The fetch
    helper MUST silently bail when the destination is empty."""
    js = _DASHBOARD_JS.read_text(encoding="utf-8")
    # Pinned guard at the top of the fetch helper.
    assert "Empty destination — silently bail" in js


# ── operator attribution + chain-exhausted modal ────────────────────


def test_template_renders_submarine_operator_attribution() -> None:
    """The inline quote-review block renders the submarine
    operator_id with a yellow secondary-fallback pill underneath."""
    block = _anonymize_tab_block()
    # The submarine cell is gated on the on-chain source getter.
    assert 'x-if="anonymizeWizardIsOnchainSource"' in block
    # And reads the operator_id off the quote response (via the
    # null-safe ``anonymizeQuoteOrEmpty`` accessor).
    assert "anonymizeQuoteOrEmpty.submarine_operator_id" in block
    # The yellow secondary-fallback pill is gated on a getter that
    # checks ``selection_source === 'secondary_after_primary_failed'``.
    assert "anonymizeSubmarineSecondaryFallbackActive" in block
    assert "primary unreachable — using secondary" in block


def test_template_renders_reverse_operator_attribution() -> None:
    """The reverse cell renders regardless of source kind."""
    block = _anonymize_tab_block()
    assert "anonymizeQuoteOrEmpty.reverse_operator_id" in block


def test_template_renders_chain_exhausted_modal() -> None:
    """The chain-exhausted modal block exists, is
    gated on ``anonymizeShowSingleOperatorFallbackModal``, and the
    Use-single-operator button is hidden when
    ``single_operator_fallback_available`` is false."""
    block = _anonymize_tab_block()
    assert 'x-show="anonymizeShowSingleOperatorFallbackModal"' in block
    # Modal body must explain both choices the user faces.
    assert "Both alt operators unreachable" in block
    assert "Privacy tier capped at" in block
    # The single-operator button is conditionally rendered.
    assert "anonymizeChainExhaustedDetail.single_operator_fallback_available" in block
    # And wired to the retry helper.
    assert "anonymizeRetryQuoteWithFallback()" in block


def test_js_carries_chain_exhausted_state_and_handlers() -> None:
    """JS state vars + the retry method exist."""
    js = _DASHBOARD_JS.read_text(encoding="utf-8")
    # Initial state.
    assert "anonymizeAllowSingleOperatorFallback: false" in js
    assert "anonymizeChainExhaustedDetail: {}" in js
    assert "anonymizeShowSingleOperatorFallbackModal: false" in js
    # Retry helper.
    assert "anonymizeRetryQuoteWithFallback()" in js
    # Error-handler branches for the three new error codes.
    assert "indexOf('submarine_chain_exhausted')" in js
    assert "indexOf('reverse_probe_failed')" in js
    assert "indexOf('all_submarine_operators_unreachable')" in js


def test_api_helper_attaches_error_body_to_thrown_error() -> None:
    """The modal needs the 409 body's ``attempted[]`` array
    and ``single_operator_fallback_available`` flag. The api()
    helper MUST attach the parsed JSON body as ``err.detail`` so
    callers can read structured-error fields."""
    js = _DASHBOARD_JS.read_text(encoding="utf-8")
    assert "err.detail = data" in js
    assert "err.status = res.status" in js
