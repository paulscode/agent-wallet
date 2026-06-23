# SPDX-License-Identifier: MIT
"""Cross-file consistency tests for the Braiins-Deposit info-icon glossary.

The wizard template references glossary terms by id (e.g.
``braiinsDepositToggleInfoTip('confirmation')``). The corresponding
title + body strings live in the ``BRAIINS_DEPOSIT_GLOSSARY`` dict
inside ``app/dashboard/static/dashboard.js``. A drift between the two
would render an empty popover at runtime — invisible to unit tests
without a browser harness.

These tests scan both files textually and pin the invariant that every
``braiinsDepositToggleInfoTip('<id>')`` in the template has a matching
key in the JS dictionary.
"""

from __future__ import annotations

import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
_TEMPLATE = _ROOT / "app" / "dashboard" / "templates" / "dashboard.html"
_DASH_JS = _ROOT / "app" / "dashboard" / "static" / "dashboard.js"


def _template_terms() -> set[str]:
    src = _TEMPLATE.read_text(encoding="utf-8")
    # Match ``braiinsDepositToggleInfoTip('foo')`` calls.
    return set(re.findall(r"braiinsDepositToggleInfoTip\(\s*'([^']+)'\s*\)", src))


def _js_glossary_keys() -> set[str]:
    """Extract the keys inside ``const BRAIINS_DEPOSIT_GLOSSARY = { ... }``
    in the dashboard JS. We do a small regex parse rather than evaluate
    JS — the dict's keys are simple single-quoted strings followed by
    a colon.
    """
    src = _DASH_JS.read_text(encoding="utf-8")
    start_match = re.search(r"const BRAIINS_DEPOSIT_GLOSSARY\s*=\s*\{", src)
    assert start_match, "BRAIINS_DEPOSIT_GLOSSARY not found in dashboard.js"
    # Walk braces to find the matching closing brace.
    i = start_match.end() - 1  # at the opening '{'
    depth = 0
    end = None
    while i < len(src):
        c = src[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                end = i + 1
                break
        i += 1
    assert end is not None, "couldn't find end of BRAIINS_DEPOSIT_GLOSSARY"
    body = src[start_match.start() : end]
    # Match top-level keys of the form ``'foo':`` (with possible
    # leading whitespace at line start).
    keys = set()
    for m in re.finditer(r"^\s*'([a-z][a-z0-9-]*)'\s*:\s*\{", body, re.MULTILINE):
        keys.add(m.group(1))
    return keys


class TestGlossaryDriftGuard:
    def test_every_template_term_has_a_glossary_entry(self):
        template_terms = _template_terms()
        glossary_keys = _js_glossary_keys()
        assert template_terms, "template should reference at least one glossary term"
        missing = template_terms - glossary_keys
        assert not missing, (
            f"Template references glossary term(s) with no JS entry: {sorted(missing)}. "
            f"Add them to BRAIINS_DEPOSIT_GLOSSARY in dashboard.js."
        )

    def test_glossary_has_all_plan_terms(self):
        """enumerates 11 plain-language terms. The JS dictionary
        should hold at minimum those keys so future template additions
        of any plan term ⓘ icon find a populated popover."""
        glossary_keys = _js_glossary_keys()
        # The canonical term inventory maps to these dict keys.
        plan_terms = {
            "sats",
            "lightning",
            "on-chain",
            "btc-tx-prepared",
            "boltz",
            "confirmation",
            "txid",
            "mempool",
            "fee-priority",
            "fresh-tx",
            "manual-review",
        }
        missing = plan_terms - glossary_keys
        assert not missing, f"plan terms missing from BRAIINS_DEPOSIT_GLOSSARY: {sorted(missing)}"

    def test_auto_select_source_is_wired_into_open(self):
        """The wizard "pre-fills based on which balance the
        user has". The auto-select helper must actually be called
        from ``openBraiinsDeposit`` (it would be dead code otherwise).

        Note: ``openBraiinsDeposit`` is intentionally NOT ``async`` —
        the modal opens synchronously so the click feels instant, with
        the LND-backed presets fetch deferred to the background via
        ``_refreshBraiinsDepositPresets``.
        """
        src = _DASH_JS.read_text(encoding="utf-8")
        # Find the openBraiinsDeposit function body.
        open_match = re.search(
            r"^\s{8}openBraiinsDeposit\(\)\s*\{(.*?)^\s{8}\},",
            src,
            re.DOTALL | re.MULTILINE,
        )
        assert open_match, "openBraiinsDeposit() not found in dashboard.js"
        body = open_match.group(1)
        assert "_braiinsDepositAutoSelectSource" in body, (
            "openBraiinsDeposit() must call _braiinsDepositAutoSelectSource "
            "so the source toggle pre-fills based on available balances "
            "."
        )

    def test_make_another_refreshes_balances(self):
        """``braiinsDepositMakeAnother`` must re-fetch
        presets so the post-deposit balances drive the next quote.
        Without this, the wizard's chip-affordability check uses
        the stale pre-deposit balance.
        """
        src = _DASH_JS.read_text(encoding="utf-8")
        make_match = re.search(
            r"braiinsDepositMakeAnother\(\)\s*\{(.*?)^\s*\},",
            src,
            re.DOTALL | re.MULTILINE,
        )
        assert make_match, "braiinsDepositMakeAnother() not found in dashboard.js"
        body = make_match.group(1)
        assert "openBraiinsDeposit" in body, (
            "braiinsDepositMakeAnother() must await openBraiinsDeposit() "
            "so balances + auto-selected source reflect the post-deposit "
            "state."
        )

    def test_restore_braiins_deposit_restores_source_kind(self):
        """``_restoreBraiinsDeposit`` must propagate the
        active session's ``source_kind`` into the wizard's toggle
        state, otherwise a page reload mid-flow shows the wrong
        source selected.

        The wizard-resume logic was factored into the shared
        ``_resumeBraiinsDepositSession`` helper per the dedicated-tab
        plan; this test now checks the helper body instead of
        the (now-thin) ``_restoreBraiinsDeposit`` wrapper.
        """
        src = _DASH_JS.read_text(encoding="utf-8")
        # The restore wrapper must still delegate to the shared helper.
        restore_match = re.search(
            r"async _restoreBraiinsDeposit\(\)\s*\{(.*?)^\s*\},",
            src,
            re.DOTALL | re.MULTILINE,
        )
        assert restore_match, "_restoreBraiinsDeposit() not found in dashboard.js"
        assert "_resumeBraiinsDepositSession" in restore_match.group(1), (
            "_restoreBraiinsDeposit() must delegate to _resumeBraiinsDepositSession "
            "so the source-kind / wizard-state logic has a single source of truth."
        )
        # The shared helper carries the source-kind restoration.
        helper_match = re.search(
            r"_resumeBraiinsDepositSession\(session(?:,\s*opts)?\)\s*\{(.*?)^\s*\},",
            src,
            re.DOTALL | re.MULTILINE,
        )
        assert helper_match, "_resumeBraiinsDepositSession() not found in dashboard.js"
        body = helper_match.group(1)
        assert "braiinsDepositSourceKind" in body, (
            "_resumeBraiinsDepositSession() must set braiinsDepositSourceKind from the resumed session row."
        )
        assert "'onchain'" in body or '"onchain"' in body, (
            "_resumeBraiinsDepositSession() should accept 'onchain' as a valid source_kind value."
        )

    def test_glossary_keys_have_nonempty_titles_and_bodies(self):
        src = _DASH_JS.read_text(encoding="utf-8")
        # Match each ``'key': { title: '...', body: '...' }`` entry.
        # Tolerate single or double quotes on title/body, plus
        # backslash-escaped characters inside.
        entry_re = re.compile(
            r"'([a-z][a-z0-9-]*)'\s*:\s*\{\s*"
            r"title:\s*['\"]((?:[^'\"\\]|\\.)*)['\"]\s*,\s*"
            r"body:\s*['\"]((?:[^'\"\\]|\\.)+)['\"]\s*,?\s*\}",
            re.DOTALL,
        )
        entries = entry_re.findall(src)
        assert entries, "expected to parse at least one glossary entry"
        for key, title, body in entries:
            assert title.strip(), f"glossary key {key!r} has an empty title"
            assert body.strip(), f"glossary key {key!r} has an empty body"
            # Sanity check: the body should be a real sentence,
            # not a placeholder.
            assert len(body) >= 30, f"glossary key {key!r} body looks suspiciously short: {body!r}"


class TestExtSourceCrossFileConsistency:
    """Ext-source wiring guards — assert the ext-source surfaces are
    present in both the template and dashboard.js."""

    def test_template_renders_four_source_options(self):
        src = _TEMPLATE.read_text(encoding="utf-8")
        # All four source kinds must be wired into the source picker.
        for kind in ("'lightning'", "'onchain'", "'ext_lightning'", "'ext_onchain'"):
            assert f"braiinsDepositSelectSource({kind})" in src, f"Template missing source picker for {kind}"

    def test_source_picker_uses_label_radio_pattern(self):
        """The source picker uses label+radio (matching
        the Anonymize wizard) so the nested info-icon <button> stays
        HTML-valid. We check for the ``name="braiins_deposit_source"``
        radio group as the discriminating signature."""
        src = _TEMPLATE.read_text(encoding="utf-8")
        assert 'name="braiins_deposit_source"' in src, (
            "Source picker should use <input type=radio name=braiins_deposit_source>"
        )

    def test_each_source_radio_has_info_icon(self):
        """Per-radio info-icons that open glossary
        popovers. All four source kinds must have a toggle entry."""
        src = _TEMPLATE.read_text(encoding="utf-8")
        for tip_key in (
            "'lightning'",
            "'on-chain'",
            "'external-lightning'",
            "'external-onchain'",
        ):
            assert f"braiinsDepositToggleInfoTip({tip_key})" in src, (
                f"Source picker missing info-icon for glossary key {tip_key}"
            )

    def test_ext_oc_await_screen_has_confirmation_infoicon(self):
        """Plan.b — the ext-OC await_funds status banner cites
        "1 confirmation" with an ⓘ that opens the existing
        ``confirmation`` glossary popover."""
        src = _TEMPLATE.read_text(encoding="utf-8")
        # Find the await_funds ext-OC section and confirm the toggle
        # call uses the 'confirmation' glossary key.
        assert "braiinsDepositToggleInfoTip('confirmation')" in src, (
            "ext-OC await screen missing info-icon on 'confirmation'"
        )

    def test_ext_ln_expired_invoice_panel_present(self):
        """Plan.a — when the LN invoice countdown hits 0,
        the QR + invoice card are replaced with a 'This invoice
        expired' panel and the "Generate new invoice" button is
        prominently rendered."""
        src = _TEMPLATE.read_text(encoding="utf-8")
        assert "braiinsDepositExtInvoiceExpired" in src, (
            "Template missing the expired-invoice UI gate (braiinsDepositExtInvoiceExpired)"
        )
        assert "This invoice expired" in src, "Template missing the 'This invoice expired' message"

    def test_ext_ln_payment_received_two_stage_flip_present(self):
        """Plan.a — when funds arrive, the wizard shows
        "✓ Payment received!" inside the await screen for ~2.5s
        before transitioning to the progress view."""
        src = _TEMPLATE.read_text(encoding="utf-8")
        js = _DASH_JS.read_text(encoding="utf-8")
        assert "braiinsDepositExtPaymentReceived" in src, "Template missing the 'Payment received!' transient banner"
        assert "braiinsDepositExtPaymentReceived = true" in js, (
            "dashboard.js missing the two-stage transition flag flip"
        )
        # The flag must clear via setTimeout to actually transition
        # the step.
        assert "setTimeout" in js, (
            "dashboard.js must use a setTimeout to transition after the 'Payment received!' banner"
        )

    def test_braiins_deposit_session_default_is_safe_shape_not_null(self):
        """The @alpinejs/csp build does NOT short-circuit ``a && a.b``
        in attribute expressions. Initialising ``braiinsDepositSession``
        to ``null`` causes "Cannot read property of null or undefined"
        crashes on every ``braiinsDepositSession && braiinsDepositSession.x``
        template expression. This pin guards against a future refactor
        accidentally reverting to ``null`` (matching the same pattern
        ``bolt12Receive`` already uses)."""
        src = _DASH_JS.read_text(encoding="utf-8")
        # The factory function must exist.
        assert "function _emptyBraiinsDepositSession" in src, (
            "dashboard.js missing _emptyBraiinsDepositSession() factory"
        )
        # The Alpine-state initialisation must call the factory, NOT
        # set null.
        assert "braiinsDepositSession: _emptyBraiinsDepositSession()" in src, (
            "braiinsDepositSession state must be initialised via the safe-shape factory, not null"
        )
        assert "braiinsDepositSession: null" not in src, (
            "braiinsDepositSession must not be initialised to null — Alpine CSP cannot short-circuit && property access"
        )
        # Reset paths in openBraiinsDeposit + braiinsDepositMakeAnother
        # must also use the factory, not null.
        assert "this.braiinsDepositSession = null" not in src, (
            "Reset paths must re-initialise via _emptyBraiinsDepositSession(), not null"
        )

    def test_quote_response_carries_ext_ln_invoice_ttl(self):
        """Plan.c — the quote endpoint response includes
        ``ext_ln_invoice_ttl_s`` so the wizard can render the
        countdown ceiling without a separate presets round-trip."""
        # The API layer attaches the field after the service-side
        # quote returns. We grep on the literal so a refactor that
        # moves the attachment elsewhere still surfaces.
        api_path = _ROOT / "app" / "dashboard" / "api.py"
        api = api_path.read_text(encoding="utf-8")
        # Find the quote endpoint and verify the TTL is attached.
        quote_idx = api.find("/braiins-deposit/quote")
        assert quote_idx >= 0
        # Search within ~2000 chars after the route declaration.
        block = api[quote_idx : quote_idx + 2500]
        assert "ext_ln_invoice_ttl_s" in block, "Quote endpoint must surface ext_ln_invoice_ttl_s in its response."

    def test_template_renders_two_section_headers(self):
        src = _TEMPLATE.read_text(encoding="utf-8")
        # The 4-option picker is grouped under two visible section
        # headers — mirroring the Anonymize wizard's source step.
        # Search inside the Braiins-Deposit modal so a stray header
        # elsewhere doesn't accidentally satisfy the check.
        modal_start = src.find("braiinsDepositOpen")
        assert modal_start >= 0
        modal_end = src.find("END BRAIINS DEPOSIT MODAL", modal_start)
        if modal_end < 0:
            # No end-marker comment — use a generous slice.
            modal_end = modal_start + 60_000
        block = src[modal_start:modal_end]
        assert "Agent Wallet" in block, "missing 'Agent Wallet' section header"
        assert "External Source" in block, "missing 'External Source' section header"

    def test_template_has_await_funds_step(self):
        src = _TEMPLATE.read_text(encoding="utf-8")
        assert "braiinsDepositStep === 'await_funds'" in src, "Template missing the ext-source await_funds step"

    def test_template_has_refund_panel(self):
        src = _TEMPLATE.read_text(encoding="utf-8")
        assert "braiinsDepositNeedsRefund" in src, "Template missing the ext-OC refund-prompt panel"
        assert "braiinsDepositSubmitRefund" in src, "Template's refund panel must wire braiinsDepositSubmitRefund()"
        assert "braiinsDepositExtRefundAddress" in src, (
            "Template's refund panel must x-model braiinsDepositExtRefundAddress"
        )

    def test_dashboard_js_exposes_ext_source_methods(self):
        src = _DASH_JS.read_text(encoding="utf-8")
        for name in (
            "braiinsDepositRegenerateInvoice",
            "braiinsDepositSubmitRefund",
            "braiinsDepositCopyInvoice",
            "braiinsDepositCopyAddress",
            "_refreshBraiinsDepositExtAwaitView",
            "_scheduleBraiinsDepositCountdown",
            "_stopBraiinsDepositCountdown",
            "_renderBraiinsDepositQr",
        ):
            assert name in src, f"dashboard.js missing ext-source method/helper: {name}"

    def test_dashboard_js_exposes_ext_source_getters(self):
        src = _DASH_JS.read_text(encoding="utf-8")
        for getter in (
            "get braiinsDepositStartButtonLabel",
            "get braiinsDepositDebitLabel",
            "get braiinsDepositDebitAmount",
            "get braiinsDepositSourceCaption",
            "get braiinsDepositNeedsRefund",
            "get braiinsDepositCanRegenerateInvoice",
            "get braiinsDepositExtCountdownText",
        ):
            assert getter in src, f"dashboard.js missing ext-source getter: {getter}"

    def test_open_braiins_deposit_loads_ext_enabled_flag(self):
        """The ``ext_enabled`` kill switch from the server's
        /presets payload must hydrate the SPA's ext-flow toggle.

        The presets fetch was moved out of ``openBraiinsDeposit`` into
        ``_refreshBraiinsDepositPresets`` (which runs in the background
        so the modal opens instantly). Verify the background helper
        still consumes ``ext_enabled``.
        """
        src = _DASH_JS.read_text(encoding="utf-8")
        refresh_match = re.search(
            r"_refreshBraiinsDepositPresets\(\)\s*\{(.*?)^\s{8}\},",
            src,
            re.DOTALL | re.MULTILINE,
        )
        assert refresh_match, "_refreshBraiinsDepositPresets() not found in dashboard.js"
        body = refresh_match.group(1)
        assert "ext_enabled" in body, (
            "_refreshBraiinsDepositPresets() should read presets.ext_enabled "
            "so the External Source radios reflect the operator's kill switch"
        )
        # And openBraiinsDeposit itself must wire the background fetch
        # in (otherwise ext_enabled never gets refreshed on wizard open).
        open_match = re.search(
            r"^\s{8}openBraiinsDeposit\(\)\s*\{(.*?)^\s{8}\},",
            src,
            re.DOTALL | re.MULTILINE,
        )
        assert open_match, "openBraiinsDeposit() not found"
        assert "_refreshBraiinsDepositPresets" in open_match.group(1), (
            "openBraiinsDeposit() must fire _refreshBraiinsDepositPresets() "
            "so the wizard's ext kill switch picks up server updates"
        )

    def test_restore_accepts_ext_source_kinds(self):
        """Ext-source kinds (``ext_lightning`` / ``ext_onchain``)
        must be valid resume targets. The wizard-resume logic was
        factored into the shared ``_resumeBraiinsDepositSession``
        helper per the dedicated-tab plan; this test checks the
        helper body instead of the (now-thin) ``_restoreBraiinsDeposit``
        wrapper."""
        src = _DASH_JS.read_text(encoding="utf-8")
        helper_match = re.search(
            r"_resumeBraiinsDepositSession\(session(?:,\s*opts)?\)\s*\{(.*?)^\s*\},",
            src,
            re.DOTALL | re.MULTILINE,
        )
        assert helper_match, "_resumeBraiinsDepositSession() not found"
        body = helper_match.group(1)
        assert "ext_lightning" in body and "ext_onchain" in body, (
            "_resumeBraiinsDepositSession() must accept ext_lightning / ext_onchain as valid source_kind values"
        )

    def test_step_states_include_await_funds(self):
        src = _DASH_JS.read_text(encoding="utf-8")
        assert "'await_funds'" in src, (
            "dashboard.js step-state machine must include the await_funds branch for ext sources"
        )

    def test_qr_payloads_use_uri_schemes(self):
        src = _DASH_JS.read_text(encoding="utf-8")
        # BIP-21 + lightning: prefixes — wallets pre-fill amount from
        # these scheme-prefixed payloads.
        assert "'bitcoin:'" in src, "QR payload for ext-OC must use the bitcoin: URI scheme"
        assert "'lightning:'" in src, "QR payload for ext-LN must use the lightning: URI scheme"

    def test_glossary_has_ext_source_keys(self):
        """Three glossary keys for the ext flows."""
        src = _DASH_JS.read_text(encoding="utf-8")
        for key in ("external-lightning", "external-onchain", "lightning-invoice"):
            assert f"'{key}':" in src, f"BRAIINS_DEPOSIT_GLOSSARY missing ext-source key {key!r}"

    def test_progress_dots_getter_present(self):
        """The progress dot row varies by source_kind.
        The ``braiinsDepositProgressDots`` getter encapsulates that
        list so the template doesn't replicate the branching."""
        src = _DASH_JS.read_text(encoding="utf-8")
        assert "get braiinsDepositProgressDots" in src, "dashboard.js missing braiinsDepositProgressDots getter"

    def test_progress_dots_includes_ext_labels(self):
        """The ext-source variants must add a leading 'Payment
        received' / 'Deposit confirmed' dot."""
        src = _DASH_JS.read_text(encoding="utf-8")
        # Both labels are inside the getter body, so a substring
        # search is sufficient.
        assert "'Payment received'" in src, "dashboard.js missing ext-LN 'Payment received' dot label"
        assert "'Deposit confirmed'" in src, "dashboard.js missing ext-OC 'Deposit confirmed' dot label"

    def test_template_renders_progress_dots_via_getter(self):
        """The template iterates the getter rather
        than replicating the source_kind branching."""
        src = _TEMPLATE.read_text(encoding="utf-8")
        assert "braiinsDepositProgressDots" in src, (
            "Template should render progress dots via the braiinsDepositProgressDots getter"
        )

    def test_submarine_funding_txid_shown_for_ext_onchain(self):
        """Ext-OC sessions also go through SUBMARINE_SWAPPING, so the
        submarine-funding txid display must include ext_onchain in
        its source-kind gate."""
        src = _TEMPLATE.read_text(encoding="utf-8")
        # Search for a single line that gates submarine_funding_txid
        # display on both source kinds.
        assert "source_kind === 'ext_onchain'" in src, "Template's submarine-funding panel must accept ext_onchain"
