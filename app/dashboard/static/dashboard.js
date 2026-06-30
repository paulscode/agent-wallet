// SPDX-License-Identifier: MIT
/**
 * Dashboard Alpine.js component (CSP-compatible).
 *
 * Registered via Alpine.data() so the @alpinejs/csp build can evaluate
 * template expressions without 'unsafe-eval'.  All state, methods, and
 * helpers that were previously in an inline <script> block live here.
 */

// Onboarding wizard peer picker — sourced from the small-channel peer
// catalog served at ``/dashboard/api/peer-catalog/small-channel``.
// The catalog ships in-repo (``app/services/small_channel_peers.json``)
// and is read once per dashboard session, cached in component state.
// Retry budget for the lazy fetch is bounded by ``CATALOG_FETCH_RETRY_BACKOFFS_MS``
// (below) — total wall-clock attempt window of ~10 s. On final
// failure or when the operator has disabled the catalog
// (``SMALL_CHANNEL_PEER_CATALOG_ENABLED=false``), the picker collapses
// to the "A different node" mode only and surfaces a retry affordance.
const CATALOG_FETCH_RETRY_BACKOFFS_MS = [500, 2000, 5000];

// Onchain confirmed-balance threshold at which the onboarding wizard
// offers the multi-channel planner alongside the single-channel
// picker. Below this, the planner's output is approximately one
// channel anyway — we save the user a decision by keeping the
// existing single-channel flow.
const CHANNEL_PLANNER_AUTOOFFER_FLOOR_SATS = 400000;

// How often the dashboard polls the channel-mix run status while the
// executor is driving the per-channel state machine. Tracks the
// cadence the Boltz / Braiins polling already use so the dashboard
// doesn't accumulate background timers at different rates.
const CHANNEL_MIX_RUN_POLL_MS = 5000;

// Onboarding default-amount safety buffer (sats). We pre-fill the
// channel amount as ``onchain - buffer`` so the wallet keeps a small
// reserve for on-chain fees (e.g. cooperative close fees, future
// rebalances). Larger of 10k sats or 2 % of available balance.
const ONBOARDING_SAFETY_BUFFER_SATS = 10000;
const ONBOARDING_SAFETY_BUFFER_PCT = 0.02;

// Inbound-liquidity wizard (Add Receive Capacity). Mirrors the
// Boltz reverse-swap thresholds enforced server-side in
// ``app/services/boltz_service.py``. The wizard hides the routing
// fee limit and amount-bounds chrome behind these constants so the
// dialog only surfaces one decision (amount).
const BOLTZ_MIN_AMOUNT_SATS = 25_000;
const BOLTZ_MAX_AMOUNT_SATS = 25_000_000;
// Lightning-leg routing-fee budget reserved on top of the invoice amount.
// Mirrors ``routing_fee_buffer_pct`` in ``cold_storage_initiate``
// (app/dashboard/api.py); keep in sync. The wizard caps Max-button amounts
// by this so the post-confirm "channel only has X sats free" rejection
// can't fire on a value the UI just suggested.
const BOLTZ_ROUTING_FEE_BUFFER_PCT = 0.03;
// ``floor(x / (1 + BOLTZ_ROUTING_FEE_BUFFER_PCT))`` — the largest amount A
// whose ``A * (1 + buffer)`` fits inside ``x``. Inlined so callers can read
// the math.
const _withBoltzBuffer = (x) =>
    Math.max(0, Math.floor(x / (1 + BOLTZ_ROUTING_FEE_BUFFER_PCT)));
const INBOUND_SAFETY_MARGIN_SATS = 5_000;   // headroom above the requested invoice amount
const INBOUND_LOCAL_RESERVE_SATS = 10_000;  // keep some sats in the channel for routing fees
// Pad (on top of the live commit_fee) reserved on a rebalance source
// channel for the anchor outputs + the commit-fee growth from adding the
// rebalance HTLC, so LND doesn't reject the send with "insufficient
// local balance" at execution time.
const REBALANCE_HEADROOM_PAD_SATS = 1_000;
// Mapping from the underlying Boltz status to the wizard's three
// user-visible progress stages. ``_swapUserStepIndex`` reads from
// this so both Cold Storage and the inbound flow share the table.
const SWAP_USER_STEP_INDEX = {
    created: 0,
    paying_invoice: 1,
    invoice_paid: 1,
    claiming: 2,
    claimed: 2,
    completed: 3,
};
const SWAP_TERMINAL_STATUSES = new Set([
    'completed', 'failed', 'cancelled', 'refunded',
]);
// The swap-id pins
// below are persisted to ``sessionStorage`` rather than
// ``localStorage`` so they do not survive a tab close or browser
// restart. The legacy ``_LOCALSTORAGE_`` suffix is retained for git
// blame continuity; treat as "swap-state storage key".
const INBOUND_LOCALSTORAGE_KEY = 'inboundActiveSwapId';
const COLD_LOCALSTORAGE_KEY = 'coldActiveSwapId';
// Per-channel "Open Inbound" swap pin. Stores a small JSON blob
// (``{swapId, chanId}``) rather than a bare id so a resume can tell
// which channel an in-flight swap belongs to and surface it.
const CHANNEL_INBOUND_LOCALSTORAGE_KEY = 'chInboundActiveSwap';

// Default wall-clock timeout (ms) applied to idempotent READS (GET/…)
// in ``api()`` when the caller didn't pass an explicit ``timeoutMs``.
// Bounds the ~37 otherwise-unbounded GETs so no read can hang the SPA
// when LND/Tor is slow. Well above a normal response, below "wedged".
// Mutations get NO default (see ``_apiSend``). A caller can opt a
// specific read OUT with ``{ timeoutMs: 0 }``.
const DEFAULT_READ_TIMEOUT_MS = 15000;

// ``/channels`` is the heaviest dashboard read: over an onion LND it fans
// out to several Tor round trips (channel list + last-used enrichment),
// and the server-side httpx client itself allows up to 30 s for onion
// endpoints. The default 15 s read budget sat *below* that backend
// envelope, so a slow-but-succeeding call was aborted by the browser and
// surfaced as a spurious "couldn't load channels". Give channel reads a
// budget that matches the backend rather than racing it.
const CHANNELS_READ_TIMEOUT_MS = 30000;

/** Plain-language glossary surfaced by the Braiins Deposit wizard.
 *  Kept here so docs and in-UI tooltips share a source of truth.
 *  Used by ``braiinsDepositGlossaryTitle`` / ``braiinsDepositGlossaryBody``
 *  to render the currently-open popover. */
const BRAIINS_DEPOSIT_GLOSSARY = {
    'sats': {
        title: 'sats',
        body: 'Sats (short for "satoshis") are the smallest unit of bitcoin. 100,000,000 sats = 1 BTC. 100,000 sats ≈ a small everyday amount.',
    },
    'lightning': {
        title: 'Lightning balance',
        body: 'The portion of your bitcoin held in Lightning payment channels. Lightning lets you send and receive instantly with very low fees, but its balance has to be opened in a "channel" first.',
    },
    'on-chain': {
        title: 'Bitcoin chain / on-chain',
        body: 'The main Bitcoin ledger — slower than Lightning (~10 minutes per confirmation) and has a per-transaction fee, but anyone can see and verify the transaction with a block explorer. Note: an on-chain deposit needs your node to RECEIVE this amount over Lightning from the swap provider; if it can\'t be reached, the deposit auto-refunds and you pay the on-chain fees. A Lightning deposit avoids this step.',
    },
    'open-a-channel': {
        title: 'Open a channel (instead of a swap)',
        body: 'For on-chain deposits, instead of a submarine swap this opens a new Lightning channel to a recommended routing peer with your funds, then converts that to a fresh Bitcoin transaction for Braiins. It works even when a swap can\'t be routed to your node — slower (~30-60 min for the channel to confirm), and ~1% stays in the new channel as receive capacity you keep.',
    },
    'channel-reserve': {
        title: 'Channel reserve',
        body: 'Every Lightning channel keeps ~1% of its size unspendable on each side (a Lightning safety rule). On a channel-open deposit that ~1% stays in the new channel rather than reaching Braiins — but it becomes receive (inbound) capacity you keep, and is recoverable later by closing the channel.',
    },
    'routing-headroom': {
        title: 'Lightning routing headroom',
        body: 'A safety reserve for the Lightning leg — capped at 3% — not a fee you pay. The actual routing fee is usually a small fraction of this (often well under 0.5%). It is reserved so the payment has enough fee budget to find a route and won\'t fail; whatever isn\'t used stays in your wallet\'s Lightning balance. It is not paid to the wallet operator or to Braiins.',
    },
    'inbound-bootstrap': {
        title: 'Build inbound efficiently',
        body: 'Inbound (receive) capacity normally costs as much to set up as the amount you want to receive. This option recycles the same funds instead: it opens one channel, swaps that channel\'s balance back to your on-chain wallet (which leaves the channel able to receive), then reuses the returned funds to open the next channel — and repeats. You can build several times your starting amount in inbound, but each round waits for on-chain confirmations, so it takes hours and costs a little in fees each round. It runs in the background; you can keep using the wallet.',
    },
    'btc-tx-prepared': {
        title: 'Bitcoin transaction prepared',
        body: 'Boltz Exchange has produced a Bitcoin transaction that pays the sats you converted into your wallet. The transaction has been broadcast to the network and is waiting to be confirmed by miners.',
    },
    'boltz': {
        title: 'Boltz Exchange',
        body: 'Boltz is the service we use to convert sats between Lightning and the Bitcoin chain. Your wallet already uses it for the "Cold Storage" and "Add Receive Capacity" features. No account or login — every transaction is independent.',
    },
    'confirmation': {
        title: 'Confirmation',
        body: 'A confirmation is a Bitcoin block added on top of the block that includes your transaction. More confirmations = harder for anyone to reverse the transaction. Most services credit your deposit after 1–3 confirmations (~10–30 minutes).',
    },
    'txid': {
        title: 'Transaction ID',
        body: 'A 64-character unique fingerprint for a Bitcoin transaction. Paste it into any block explorer (such as mempool.space) to see its current status and details.',
    },
    'mempool': {
        title: 'Mempool',
        body: 'After a Bitcoin transaction is broadcast it waits in the network\'s "mempool" (memory pool) for a few minutes to ~an hour until a miner includes it in a block. Your transaction has been broadcast and is queued.',
    },
    'fee-priority': {
        title: 'Fee priority',
        body: 'Higher priority pays more sats per byte to miners, so your transaction confirms faster. Medium typically confirms within 30–60 minutes; Low can take several hours during busy periods.',
    },
    'fresh-tx': {
        title: 'Fresh transaction',
        body: 'The Boltz claim produces a brand-new Bitcoin transaction in your wallet whose parents trace only to Boltz. Braiins\' anti-fraud algorithm accepts that kind of clean parent without manual review.',
    },
    'manual-review': {
        title: 'Manual review',
        body: 'Some services (including Braiins Hashpower) automatically flag deposits whose recent transaction history looks unusual for a human to check before crediting. Reviews almost always pass but they introduce a delay of hours to a day. The Braiins-Deposit flow produces a transaction shape the algorithm clears automatically.',
    },
    // External-source glossary entries.
    'external-lightning': {
        title: 'External Lightning',
        body: 'Lightning funds held in a wallet other than this one — your phone wallet, a desktop wallet, or a custodial service that supports Lightning withdrawals. You pay an invoice we generate; we handle everything else.',
    },
    'external-onchain': {
        title: 'External on-chain',
        body: 'Bitcoin held in a wallet other than this one — a hardware wallet, an exchange withdrawal, or any other on-chain Bitcoin wallet. You send to an address we generate; we handle everything else. Note: this still needs your node to RECEIVE the amount over Lightning from the swap provider; if it can\'t be reached, the deposit auto-refunds and you pay the on-chain fees. An external Lightning deposit avoids this step.',
    },
    'lightning-invoice': {
        title: 'Lightning invoice',
        body: 'A one-time payment request your wallet shows so another wallet can pay you over Lightning. Starts with "lnbc…". Most modern Lightning wallets can scan the QR code or paste the text.',
    },
    'include-extras': {
        title: 'Include extras in the deposit',
        body: 'When on (recommended), the wallet sends the entire fresh UTXO to Braiins minus the network fee — Braiins receives slightly more than the bin amount and your wallet keeps no change. When off, the wallet sends exactly the bin amount and returns the remainder as a change UTXO; at high fees that small change can cost more to spend than it is worth (dust).',
    },
};

/** Shared helper: map a Boltz swap status string to the 0-3 index
 *  the wizard's progress view (and the Cold Storage dialog) use to
 *  drive their "step 1 / 2 / 3" UI. Unknown statuses default to 0
 *  so a swap that lands in an unexpected state still renders. */
function _swapUserStepIndex(status) {
    if (!status) return 0;
    const idx = SWAP_USER_STEP_INDEX[status];
    return typeof idx === 'number' ? idx : 0;
}

/** Safe-shape placeholder for ``braiinsDepositSession`` BEFORE the
 *  first API populate. The Alpine @alpinejs/csp build does NOT
 *  reliably short-circuit ``a && a.b`` in attribute expressions —
 *  templates like ``braiinsDepositSession && braiinsDepositSession.x``
 *  still evaluate ``.x`` when ``braiinsDepositSession`` is ``null``
 *  and throw "Cannot read property of null or undefined". Same root
 *  cause as ``bolt12Receive``'s safe-shape pattern (see comment
 *  above ``bolt12Receive`` in the Alpine state). Returning a fresh
 *  object on each call avoids accidental cross-session reference
 *  sharing when sessions are reset (close → reopen, make-another).
 *
 *  An "empty" session is distinguished from a "real" session by
 *  ``id === ''`` — JS guards that previously read ``!session``
 *  should read ``!session.id`` after this change. */
function _emptyBraiinsDepositSession() {
    return {
        id: '',
        status: '',
        source_kind: '',
        deposit_amount_sats: 0,
        destination_address: '',
        fresh_address: null,
        fresh_utxo_txid: null,
        fresh_utxo_vout: null,
        fresh_utxo_amount_sats: null,
        fresh_utxo_confirmations: null,
        send_txid: null,
        send_confirmations: null,
        send_confirmations_live: null,
        broadcast_block_height: null,
        submarine_lockup_address: null,
        submarine_lockup_amount_sats: null,
        submarine_funding_txid: null,
        submarine_funding_confirmations: null,
        funding_strategy: 'swap',
        channel_open_txid: null,
        channel_capacity_sats: null,
        channel_peer_pubkey: null,
        channel_open_confirmations: null,
        channel_activation_confs: null,
        ext_intake_address: null,
        ext_intake_amount_sats: null,
        ext_intake_received_sats: 0,
        ext_intake_txids: [],
        ext_funds_received_at: null,
        ext_ln_invoice: null,
        ext_ln_invoice_expires_at: null,
        ext_ln_boltz_status: null,
        refund_address: null,
        refund_txid: null,
        error_message: null,
        status_history: [],
        created_at: null,
        updated_at: null,
        completed_at: null,
    };
}

document.addEventListener('alpine:init', () => {
    Alpine.data('dashboard', () => ({
        // ── State ──
        loading: true,
        error: null,
        summary: null,
        info: null,
        fees: null,
        feesError: null,
        // Per-section load errors. Set when a
        // section's fetch fails (initial load OR a poll refresh) so the
        // UI can show "Couldn't load — Retry" instead of a stale/empty
        // section with no explanation. Cleared on the next success.
        channelsError: null,
        paymentsError: null,
        transactionsError: null,
        channels: null,
        pendingChannels: null,
        payments: null,
        invoices: null,
        transactions: null,
        activity: null,
        activityOffset: 0,
        toast: '',
        showBtc: false,
        nodeInfoOpen: false,
        activeTab: 'channels',
        // On-chain inner tab strip + UTXO management state. All kept
        // as flat top-level scalars because the @alpinejs/csp build
        // does not support nested-path reactivity inside ``:disabled``
        // / ``x-show`` expressions.
        onchainSubTab: 'transactions',
        utxos: [],
        utxosTotalSats: 0,
        utxosLoading: false,
        utxoSearch: '',
        utxoEditingKey: '',
        utxoEditingDraft: '',
        recentlySpent: [],
        recentlySpentOpen: false,
        // Coin-control accordion shared by Send On-chain + Cold Storage.
        sendCoinControlOpen: false,
        sendCoinControlMode: 'auto',  // 'auto' | 'manual'
        sendCoinControlSelected: [],   // array of "txid:vout" keys
        sendCoinControlSelectedTotal: 0,
        // Consolidate dialog state.
        consolidateOpen: false,
        consolidateOutpoints: [],   // array of "txid:vout" keys
        consolidateSelectedTotal: 0,
        consolidateDestType: 'p2wkh',
        consolidateSatPerVbyte: null,
        consolidateLoading: false,
        consolidateError: '',
        // BOLT 12
        // Two derived lists, one per sub-tab. ``bolt12IssuedOffers``
        // backs the Issue tab's "My offers" history;
        // ``bolt12Payees`` backs the Pay tab's address book.
        bolt12IssuedOffers: null,
        // ``bolt12Payees`` defaults to ``[]`` (not ``null``) because the
        // @alpinejs/csp expression evaluator does not short-circuit
        // ``a && a.b`` reliably — it still touches ``a.b`` when ``a`` is
        // null and throws. An empty array satisfies all guard reads
        // (``!arr || arr.length === 0`` → empty-state; ``arr && arr.length > 0``
        // → table hidden) until the API populates it.
        bolt12Payees: [],
        bolt12Error: '',
        bolt12PayDecoded: null,
        bolt12PayDecodeTimer: null,
        bolt12PayDecoding: false,
        bolt12SaveLoading: false,
        // BOLT 12 issue form
        bolt12IssueForm: {
            currency: '',
            issuer: '',
            quantity_max: '',
            absolute_expiry: '',
        },
        // Description and amount live outside the form because the
        // @alpinejs/csp evaluator chokes on nested-path reactivity
        // in some bindings — e.g. `:disabled="!form.description"`
        // would not re-evaluate when the user typed into x-model.
        // Top-level scalars dodge the issue entirely.
        bolt12IssueDescription: '',
        bolt12IssueAmount: '',
        bolt12IssueResult: null,
        bolt12IssueError: '',
        bolt12IssueLoading: false,
        bolt12IssueAdvancedOpen: false,
        bolt12IssueAmountUnit: 'sats',
        // BOLT 12 default-receive panel ("give this to Ocean") — the
        // top-of-Issue-tab section. Backed by /dashboard/api/bolt12/receive.
        // ``bolt12Receive`` defaults to a safe-shape object (not ``null``)
        // for the same reason as ``bolt12Payees`` above: Alpine's CSP
        // evaluator cannot short-circuit chained ``&&`` property access
        // and would throw on templates like ``bolt12Receive.warnings.length``
        // before the API responds. The empty ``warnings`` array makes the
        // warnings ``x-if`` cleanly evaluate to false, while ``runtime``,
        // ``offer`` and ``inbound_liquidity`` stay undefined so their
        // truthy-guarded branches stay collapsed until populated.
        bolt12Receive: { warnings: [], runtime: null, offer: null, inbound_liquidity: null },
        bolt12ReceiveLoading: false,
        bolt12ReceiveError: '',
        // Powers the "Connect to a public node" CTA the receive panel
        // renders alongside the ``no_publicly_routable_om_peer``
        // warning. ``Loading`` disables the button + swaps its label
        // to "Connecting…"; ``Error`` shows a red inline message below
        // the button when the dial round fails (network down, every
        // well-known payer unreachable, etc.). Both reset to a clean
        // state whenever the receive panel is refetched.
        bolt12AutoPeerLoading: false,
        bolt12AutoPeerError: '',
        // Whether the legacy "Issue another offer" form is expanded.
        // Default closed so the canonical receive UX dominates.
        bolt12IssueAnotherOpen: false,
        // Configure-receive modal state. The modal lets the user
        // mint a new default receive offer whose description matches
        // a specific payer's requirements (e.g. Ocean mining pool's
        // mandated "OCEAN Payouts for bc1...address" format).
        showBolt12ConfigureReceive: false,
        bolt12ReceivePreset: 'ocean',  // 'ocean' | 'custom'
        bolt12ReceiveOceanAddress: '',
        bolt12ReceiveCustomDescription: '',
        bolt12ReceiveConfigureLoading: false,
        bolt12ReceiveConfigureError: '',
        // Currently-selected offer in the "My offers" list. Drives
        // which offer is rendered in the upper detail panel of the
        // Issue tab. Defaults to the default-receive offer when set,
        // otherwise the first active issued offer.
        bolt12SelectedOfferId: null,
        // Cache: offer-id → {address, owned} for OCEAN-prefixed offers
        // whose payout address we've checked against the wallet's
        // on-chain pool. Populated lazily when an OCEAN offer is
        // rendered; gates the "Sign payout message" shortcut on the
        // Offer Details card.
        bolt12OceanOwnership: {},
        // Click-to-expand modal for a BOLT 12 offer QR. Offers with
        // blinded paths push the QR to version 40, so the inline
        // thumbnail can be hard to scan from across a room — the
        // modal renders the same payload at full-viewport size.
        showOfferQrModal: false,
        offerQrModalText: '',
        offerQrModalLabel: '',

        // Streamlined sign-message dialog for an OCEAN payout address
        // we already know belongs to this wallet. Drops the
        // address/identity inputs from the full Sign/Verify dialog so
        // the user only has to enter the message + click Sign.
        showOceanSignDialog: false,
        oceanSignAddress: '',
        oceanSignMessage: '',
        oceanSignLoading: false,
        oceanSignError: '',
        oceanSignSignature: '',
        oceanSignFormat: '',
        oceanSignCopied: false,
        // True when the dialog was opened from an OCEAN offer whose
        // ownership couldn't be auto-verified (LND build lacks the
        // probe RPCs). The dialog shows a small disclaimer so the
        // user knows the sign attempt may fail if the address isn't
        // actually theirs.
        oceanSignUnverified: false,
        // BOLT 12 pay form
        bolt12PayForm: {
            offer: '',
            amount_msat: '',
            quantity: '',
            payer_note: '',
        },
        bolt12PayResult: null,
        bolt12PayError: '',
        bolt12PayLoading: false,
        bolt12SubTab: 'issue',  // 'issue' | 'pay'
        tabs: [
            { id: 'channels', label: 'Channels', icon: 'git-branch' },
            { id: 'payments', label: 'Payments', icon: 'arrow-up-right' },
            { id: 'invoices', label: 'Invoices', icon: 'arrow-down-left' },
            { id: 'bolt12', label: 'Offers', icon: 'tag' },
            { id: 'onchain', label: 'On-chain', icon: 'link' },
            // Anonymize: privacy-preserving UTXO + Lightning mixing wizard.
            { id: 'anonymize', label: 'Anonymize', icon: 'shield-check' },
            { id: 'braiins-deposit', label: 'Braiins Deposit', icon: 'pickaxe' },
            { id: 'activity', label: 'Activity', icon: 'history' },
        ],

        // ── Anonymize wizard ──
        // Merged-form wizard: a single Step 1 form (source + amount
        // + destination + inline quote) followed by Step 2 (deposit
        // primitive, ext sources only). Quote auto-fetches via
        // ``_debounceAnonymizeQuote`` when the form fields change;
        // POST /anonymize/sessions fires from ``anonymizeConfirm``.
        // Self sources skip Step 2 and close the wizard on confirm.
        anonymizeWizardOpen: false,
        // Form-step rework: 1 = single merged form (source + amount +
        // destination + inline quote), 2 = deposit-primitive screen
        // for ext sources (self sources close on confirm instead).
        anonymizeWizardStep: 1,
        // Wizard inputs live as flat top-level scalars (rather than a
        // nested object) because the @alpinejs/csp build refuses
        // property-assignment expressions on nested paths — the same
        // reason ``bolt12IssueDescription`` etc. above are hoisted out
        // of ``bolt12IssueForm``.
        anonymizeWizardSourceKind: 'lightning-self',
        anonymizeWizardDestinationAddress: '',
        anonymizeWizardRequestedAmountSat: 250000,
        // Fallback bin-amount ladder used when the operator's policy
        // hasn't loaded yet OR is misconfigured with an empty
        // ``amount_bins_sat``. The runtime chip list is exposed via
        // the ``anonymizeBinPresets`` getter, which prefers the
        // operator's actual configuration when available.
        _anonymizeBinPresetsFallback: [
            10000, 25000, 50000, 100000, 250000, 500000, 1000000, 2500000, 5000000,
        ],
        // Debounce timer for the inline-quote auto-fetch. Mirrors
        // Braiins-Deposit's quote-debouncer pattern.
        _anonymizeQuoteDebounceTimer: null,
        // Option C — per-quote opt-in for the Liquid hop.
        // The server downgrades silently when its master switch
        // is off; the response surface ``uses_liquid`` reflects
        // the post-downgrade decision so we can show a notice.
        anonymizeWizardPreferLiquid: false,
        // Ext-lightning deposit primitive.
        // ``bolt11`` keeps the legacy single-use blinded invoice
        // flow; ``bolt12`` mints a per-session BOLT 12 offer (and
        // optionally a BIP-353 handle when the operator has
        // ``ANONYMIZE_BIP353_DEPOSIT_DOMAIN`` configured).
        anonymizeWizardDepositMethod: 'bolt11',
        anonymizeQuote: null,
        anonymizeQuoteError: '',
        anonymizeQuoteLoading: false,
        // One-shot consent flag set by the modal's Use single
        // operator button. Reset to false on every successful
        // quote-fetch and on wizard close so it never carries
        // implicitly across sessions.
        anonymizeAllowSingleOperatorFallback: false,
        // Populated from the 409 chain-exhausted response
        // body so the modal can iterate attempted[] and read
        // single_operator_fallback_available. Reset to {} on wizard
        // close and on successful quote-fetch.
        anonymizeChainExhaustedDetail: {},
        // Gates the modal. Reset to false on wizard
        // close, on successful quote-fetch, and on Cancel / Use
        // single operator clicks in the modal.
        anonymizeShowSingleOperatorFallbackModal: false,
        anonymizeCreateError: '',
        anonymizeCreateLoading: false,
        // Captures the session-create response so step 4
        // can render the deposit primitive (BOLT 11 invoice / BOLT 12
        // offer / BIP-353 handle) the depositor pays. Without this,
        // the wizard closed immediately on confirm and the depositor
        // had no way to retrieve the primitive after creation.
        //
        // Defaults to a safe-shape object (NOT ``null``) for the same
        // reason ``bolt12Receive`` above does: the @alpinejs/csp
        // expression evaluator does not short-circuit ``a && a.b``
        // reliably — it still touches ``a.b`` when ``a`` is null and
        // throws. The empty ``id`` is what the outer step-4
        // ``x-if`` reads to decide whether anything has been
        // created yet; populated by ``anonymizeConfirm`` on success.
        anonymizeCreated: {
            id: '',
            deposit: {
                method: '',
                bolt11_invoice: null,
                bolt12_offer: null,
                bip353_handle: null,
                bip353_txt_record: null,
                onchain_address: null,
                amount_sat: 0,
            },
        },
        anonymizeDepositCopied: '',  // 'bolt11'|'bolt12'|'bip353'|'txt'|'onchain'|'onchain_amount'|''
        anonymizeSessions: [],
        anonymizeSessionsError: '',
        anonymizeSessionsLoading: false,
        // Flips true on the first successful sessions fetch. The tab
        // watcher uses this to refetch SILENTLY on re-activation —
        // otherwise the populated session list briefly flashes back
        // to "Loading…" every time the user navigates away and
        // returns. The very first activation (no data yet) still
        // shows the spinner so the user has feedback.
        anonymizeSessionsHydrated: false,
        // App-wide non-blocking confirm modal. Replaces
        // ``window.confirm`` so the click handler doesn't
        // synchronously block the event loop (which Chrome flagged
        // with a "[Violation] 'click' handler took N ms" log).
        // Backed by flat scalars + a Promise-based ``askConfirm``
        // helper so calling code stays as terse as the old
        // ``if (!window.confirm(msg)) return`` idiom.
        confirmOpen: false,
        confirmBody: '',
        confirmOkLabel: 'Confirm',
        confirmCancelLabel: 'Cancel',
        confirmDangerous: false,
        _confirmResolve: null,
        // Id of the session whose inline detail panel is open
        // (empty string = all collapsed). Single-open semantics keep
        // the row list compact; the user can click another row to
        // switch focus without manual collapse. Top-level scalar so
        // @alpinejs/csp can assign from x-on:click.
        anonymizeSessionDetailOpen: '',
        // Per-session recovery hints keyed by session id, populated
        // on toggle-open via a one-shot GET of the session-detail
        // endpoint. The detail endpoint aggregates per-leg BoltzSwap
        // classifier output and any session-level rules (e.g.
        // awaiting_liquid_dwell stuck). When unset the banner stays
        // hidden — the list endpoint does not enrich rows to keep
        // the polling cost low.
        anonymizeSessionRecovery: {},
        // Per-session progress timeline keyed by session id, captured
        // from the same detail-endpoint fetch that feeds the recovery
        // banner. Holds the privacy-projected event list ({ts, kind})
        // — we render coarse time + a friendly kind label only, never
        // the raw event detail. Undefined until the detail is opened.
        anonymizeSessionEvents: {},
        // Countdown / "Retrying when network recovers"
        // switchover threshold in seconds. Default mirrors
        // ``ANONYMIZE_RECONCILIATION_COUNTDOWN_THRESHOLD_S`` (600 s).
        // Overridden when ``/anonymize/policy`` is fetched on
        // wizard open.
        anonymizeReconciliationCountdownThresholdS: 600,
        // Confirming-status target ("X / Y"). Default 2 mirrors
        // ``ANONYMIZE_CLAIM_MIN_CONFIRMATIONS``. Overridden via
        // ``anonymizeApplyClockPolicy`` when /anonymize/policy fires.
        anonymizeClaimMinConfirmations: 2,
        // Residual L-BTC outputs awaiting operator action. Hydrated
        // alongside ``anonymizeFetchSessions``. Banner-only state —
        // an empty ``rows`` array suppresses the banner entirely so
        // the Anonymize tab stays uncluttered when there is nothing
        // to recover. ``_busyIds`` flags rows currently driving a
        // POST so the dashboard can disable the per-row buttons.
        anonymizeLiquidResiduals: {
            rows: [],
            total_value_sat: 0,
            recoverable_count: 0,
            recoverable_value_sat: 0,
            dust_threshold_sat: 0,
        },
        anonymizeLiquidResidualsError: '',
        anonymizeLiquidResidualsLoading: false,
        _anonymizeLiquidResidualsBusyIds: {},
        // Unix-seconds snapshot the row-countdown helper
        // reads. Updated by a 1-Hz timer (`anonymizeStartSessionsPolling`)
        // so the countdown caption decrements smoothly between the
        // 8-second sessions-list polls.
        anonymizeRowTickSnapshot: Math.floor(Date.now() / 1000),
        // Server-side anonymize policy (fetched once on tab
        // open). The SPA reads ``operator_diversity.distinct_operators_configured``
        // to decide whether to surface the single-operator advisory
        // banner when the user picks an on-chain source kind.
        // Safe-shape default (NOT ``null``) so template expressions
        // like ``anonymizePolicy.min_sat`` evaluate cleanly before
        // the API fetch lands. The @alpinejs/csp build does not
        // reliably short-circuit ``a && a.b`` when ``a`` is null —
        // it still touches ``a.b`` and throws — see the comment on
        // ``bolt12Payees`` above for the same pattern. The fields
        // are zero / empty until /anonymize/policy populates them;
        // ``anonymizePolicyLoaded`` is the canonical "have we
        // fetched yet?" gate that replaces the old ``=== null``
        // check.
        anonymizePolicy: {
            min_sat: 0,
            max_sat: 0,
            bitcoin_network: '',
            amount_bins_sat: [],
            operator_diversity: {},
            disclosures: {},
            clock_skew: null,
            tor_bootstrap_ready: false,
            reconciliation_countdown_threshold_s: 600,
            claim_min_confirmations: 2,
            // Default false so the Liquid hop UI stays hidden until
            // /anonymize/policy returns and the operator has opted in.
            liquid_available: false,
        },
        anonymizePolicyLoaded: false,
        anonymizePolicyLoading: false,
        // Info-icon tooltips in the anonymize wizard. Holds the
        // currently-open term id (empty string = none). Top-level
        // scalar so the @alpinejs/csp build can assign to it from
        // ``x-on:click`` and ``x-on:click.outside`` without a nested-
        // path expression.
        anonymizeInfoTipOpen: '',
        // "Generate" button next to the wizard's destination
        // address input mints a fresh native-segwit address from this
        // wallet's on-chain pool, useful for self-mixing flows (e.g.
        // anonymizing UTXOs before sending to a mining-pool payout).
        anonymizeGenerateAddressLoading: false,
        anonymizeGenerateAddressError: '',
        // Clock-skew probe status, mirrored from
        // /anonymize/policy. The wizard polls this during 'warming_up'
        // to render the calibrating banner + countdown, and disables
        // Confirm while non-'healthy'.
        anonymizeClockStatus: 'unknown',
        anonymizeClockSkewMs: null,
        anonymizeClockThresholdMs: null,
        anonymizeClockSamplesCollected: 0,
        anonymizeClockSamplesTarget: 0,
        anonymizeClockWarmupCompletesAt: null,
        anonymizeTorBootstrapReady: true,
        // Live countdown ticker; recomputed every second from
        // ``anonymizeClockWarmupCompletesAt`` so the banner shows
        // a wall-clock-friendly "ready in 12s" instead of stale data.
        anonymizeClockSecondsRemaining: 0,
        _anonymizeClockCountdownTimer: null,

        // Dialogs
        showFundWallet: false,
        showSendPayment: false,
        showReceiveInvoice: false,
        showColdStorage: false,
        showOpenChannel: false,
        showSendOnchain: false,

        // ── Tor Health panel ──
        showTorHealth: false,
        torHealthLoading: false,
        torHealthError: '',
        torHealthData: null,
        torHealthDetailsOpen: false,    // panel: reveal the technical breakdown
        // Cached snapshot of just the breaker state for the header
        // indicator dot, refreshed by a background poll so it's a live
        // at-a-glance signal without opening the panel.
        torHealthIndicatorState: null,  // 'closed' | 'half_open' | 'open' | null
        // SIGHUP reload state
        torHealthReloading: false,
        torHealthReloadStatus: '',

        // ── Settings menu / API keys / Audit log ──
        showSettingsMenu: false,
        showApiKeys: false,
        apiKeys: [],
        apiKeysLoading: false,
        apiKeysError: '',
        apiKeysFilter: 'all',
        apiKeysSearch: '',
        apiKeyDraftOpen: false,
        // ``scope`` carries the radio-button value verbatim — one of
        // 'monitor' / 'spend' / 'admin' — and ships to the server as-is.
        apiKeyDraft: { name: '', scope: 'monitor', expires_in_days: 365 },
        apiKeyDraftError: '',
        apiKeyDraftSubmitting: false,
        apiKeyJustCreated: null,    // { id, name, key, scope, is_admin, expires_at }
        apiKeyRotateContext: null,  // { oldId, oldName } when in a rotate flow
        // Clipboard auto-clear: when the operator copies a freshly
        // minted key plaintext we schedule a clipboard wipe 60s
        // later. The countdown is surfaced in the UI;
        // the timer/interval ids are tracked so we can cancel on
        // modal close or a second copy.
        apiKeyClipboardCountdown: 0,
        _apiKeyClipboardTimer: null,
        _apiKeyClipboardInterval: null,
        _apiKeyClipboardText: '',
        apiKeyEditId: null,
        apiKeyEditName: '',
        apiKeyConfirm: null,        // { kind, key, title, message, ... }
        apiKeyConfirmAcknowledged: false,

        showAuditLog: false,
        auditEntries: [],
        auditNextCursor: null,
        auditActions: [],
        auditFilter: { action: '', api_key_name: '', range: '24h' },
        auditExpanded: {},
        auditLoading: false,
        auditError: '',
        auditVerifyResult: null,
        auditReanchoring: false,

        // Tip the developer (Lightning Address; injected from server
        // config — ``dashboard_tip_lightning_address``). Opens a small
        // amount-picker, then funnels into the existing LNURL send
        // flow so all the usual fee/limit/audit machinery applies.
        // Empty string hides the tip option entirely.
        showTipDialog: false,
        tipAddress: '',
        tipPresets: [1000, 5000, 21000, 100000],
        tipAmountStr: '5000',
        tipComment: '',

        // Rebalance (circular self-payment)
        showRebalance: false,
        rebalance: {
            source: null,            // ChannelInfo of source (set by openRebalance)
            dest: null,              // ChannelInfo of dest, or null while picking
            amountSats: 10000,
            feeLimitSats: 50,
            // Fee-limit input mode: 'sats' lets the user set a flat
            // sat cap, 'percent' expresses it as a percentage of the
            // amount (auto-recomputed as amountSats changes). The
            // backend always receives the resolved sats value.
            feeLimitMode: 'percent',
            feeLimitPercent: 0.5,
            // Reactive shadow of ``rebalanceEffectiveFeeLimitSats()``
            // for templates: Alpine's CSP build occasionally fails to
            // pick up dependencies that live inside chained method
            // calls (``this.foo()`` → ``this.bar()`` → property read),
            // so we maintain this with a ``$watch`` on the inputs and
            // bind ``x-text`` to a plain property instead. Updated by
            // ``_recomputeFeeLimitApproxSats()``.
            feeLimitApproxSats: 0,
            timeoutSeconds: 60,
            search: '',              // dest picker filter
            sortBy: 'best',          // 'best' | 'alias' | 'capacity' | 'ratio'
            showAllDests: false,     // include dests with low inbound
            quote: null,             // last successful /quote response
            quoteError: '',
            quoting: false,
            running: false,
            result: null,            // success summary
            error: '',
            steps: [],               // streaming status messages
            recent: [],              // last 5 successful rebalances
            _quoteTimer: null,
        },

        // Reactive mirrors for the rebalance visualisation. The CSP
        // expression evaluator does not reliably register property
        // reads that happen inside chained method calls, so any
        // template binding that depends on ``rebalance.amountSats``
        // (the SVG slice rects, arrow path, "Remaining after",
        // "After", validity outline, button enable, etc.) reads from
        // these flat scalars instead. ``_recomputeRebalanceVis()``
        // refreshes them whenever amount / source / dest change.
        rebalSrcLocalW: 0,
        rebalSrcSliceX: 0,
        rebalSrcSliceW: 0,
        rebalDstLocalW: 0,
        rebalDstSliceX: 0,
        rebalDstSliceW: 0,
        rebalArrowPath: '',
        rebalArrowOk: true,
        rebalSrcRemainingLocal: 0,
        rebalDstNewLocal: 0,
        rebalMaxSendableSrc: 0,

        // Flat top-level mirror of ``rebalance.amountSats``. The CSP
        // build's ``$watch`` on nested paths is unreliable after the
        // first mutation, and ``x-model`` writes through nested paths
        // can fail to propagate reactively. The amount input binds
        // ``x-model.number`` to this scalar; an ``init()`` watcher
        // mirrors changes back into ``rebalance.amountSats`` (which
        // remains the source of truth for the backend payload) and
        // triggers the visualisation recompute.
        rebalanceAmountSats: 10000,

        // Flat mirror of ``rebalance.feeLimitPercent`` for the same
        // reason — ``x-model`` writes to a nested path are rejected
        // by the CSP expression evaluator ("Property assignments are
        // prohibited in the CSP build").
        rebalanceFeeLimitPercent: 0.5,
        // Flat mirror of ``rebalance.feeLimitSats`` for the same
        // reason. The percent and sats inputs both write to flat
        // scalars, and a watcher mirrors them into the nested
        // ``rebalance.*`` object that the backend payload uses.
        rebalanceFeeLimitSats: 50,

        // Fund wallet
        fundAddrType: 'p2wkh',
        fundAddress: '',
        fundLoading: false,
        fundError: '',
        fundCopied: false,
        fundPurpose: '',

        // Send payment
        payInvoice: '',
        decodedInvoice: null,
        payLoading: false,
        payResult: null,
        payError: '',

        // Send payment — unified advanced controls (mirrors the
        // ``rebalance`` namespace). Visible after a recipient is
        // resolved (LNURL) or an invoice is decoded (BOLT 11).
        // Default fee mode is 'sats' for Pay (vs 'percent' for
        // Rebalance) — for external payments a flat sat cap is
        // safer than a percentage of arbitrary amounts.
        pay: {
            feeLimitMode: 'sats',
            feeLimitPercent: 0.5,
            feeLimitSats: 100,
            // Reactive shadow of ``payEffectiveFeeLimitSats()`` for
            // the "≈ N sats max" hint. The CSP expression evaluator
            // can miss reactive reads through chained method calls,
            // so we maintain this with a $watch on the inputs and
            // bind ``x-text`` to a plain property instead.
            feeLimitApproxSats: 100,
            timeoutSeconds: 60,
            // Source-channel pin (advanced accordion).
            sourceOpen: false,
            sourceSearch: '',
            sourceSortBy: 'local_desc',
            sourceShowAll: false,
            source: null,
            // Route quote (Estimate fee).
            quote: null,
            quoting: false,
            quoteError: '',
        },

        // Flat top-level mirrors for x-model writes that the CSP
        // build cannot perform on nested paths. ``init()`` watches
        // each one and mirrors the value back into ``pay.*``.
        payFeeLimitPercent: 0.5,
        payFeeLimitSats: 100,
        payTimeoutSeconds: 60,

        // LNURL / Lightning Address flow. ``lnurlState`` drives the
        // recipient-card UI between paste and the existing BOLT11
        // review screen:
        //   idle       — no LNURL flow active
        //   resolving  — POST /lnurl/resolve in flight
        //   resolved   — recipient card visible, awaiting amount/comment
        //   requesting — POST /lnurl/invoice in flight
        //   ready      — invoice received; we hand off to existing /decode flow
        lnurlState: 'idle',
        lnurlError: '',
        lnurlParams: null,
        lnurlAmountSats: 0,
        lnurlAmountStr: '',
        lnurlComment: '',
        // Sanitised success_action stashed at /lnurl/invoice time, shown
        // alongside the pay-success panel. Cleared on dialog reset.
        lnurlSuccessAction: null,

        // Receive invoice
        recvAmountStr: '',
        recvMemo: '',
        recvExpiry: 3600,
        recvLoading: false,
        createdInvoice: null,
        recvError: '',
        recvCopied: false,
        // Settlement watcher state. ``recvPaid`` flips when the polled
        // invoice transitions to SETTLED so the dialog can swap the QR
        // for the celebration view. ``recvPaidDisplaySats`` runs a
        // short count-up animation from 0 to ``recvPaidAmountSats``.
        recvPaid: false,
        recvPaidAmountSats: 0,
        recvPaidDisplaySats: 0,
        recvSparkSeq: [0, 1, 2, 3, 4, 5, 6, 7],
        _recvCountUpRaf: null,

        // Cold storage
        coldTab: 'onchain',
        coldStep: 'form',
        coldAddress: '',
        coldAmount: null,
        coldFeePriority: 'medium',
        coldEstimate: null,
        coldBoltzAddress: '',
        coldBoltzAmount: null,
        // When ``/cold-storage/fees`` is served from the stale slot
        // (Boltz API unreachable), we surface a yellow banner on
        // the form and disable Review Swap until the operator
        // ticks "Proceed anyway". The flag resets on every fresh
        // open of the cold-storage modal and on ``coldBoltzNewSwap``.
        coldBoltzAcceptStale: false,
        // ``boltzFees`` and ``swapHistory`` default to safe shapes (not
        // ``null``) because the @alpinejs/csp expression evaluator does
        // not reliably short-circuit chained ``&&`` property access —
        // templates like ``boltzFees && coldBoltzAmount < boltzFees.min``
        // throw on the dotted access before the API responds. ``Infinity``
        // bounds keep the min/max guards inert (no value can be below
        // the min or above the max) until the real fee data lands.
        boltzFees: { min: Infinity, max: -Infinity },
        // Tracks whether ``fetchBoltzFees`` has completed at least
        // once (success or failure). Drives the inbound-liquidity
        // wizard's three-state form: never-fetched (loading),
        // fetched-and-reachable (form usable), fetched-and-failed
        // (red unreachable banner). Without this, the wizard
        // briefly flashes the unreachable banner during the
        // initial Tor-routed fetch.
        _boltzFeesFetched: false,
        coldLoading: false,
        coldResultData: null,
        coldResult: '',
        coldError: '',
        // Lightning swap state
        swapHistory: [],
        activeSwapId: null,
        activeSwapStatus: null,
        activeSwapError: null,
        activeSwapStep: 0,
        // Claim txid for the in-flight swap. Tracked from the
        // moment the swap detail response carries one (status
        // ``claimed`` onward) so the progress view can surface a
        // mempool-explorer + clipboard affordance while the claim
        // tx is waiting for confirmation. Cleared on dialog close
        // and on starting a fresh swap.
        activeSwapClaimTxid: '',
        activeSwapClaimConfirmations: null,
        // Boltz's lockup tx — they broadcast it on-chain after we pay
        // the Lightning side; populated as soon as Boltz reports
        // ``transaction.mempool``. Surfaced as a Mempool link during
        // the wait window BEFORE we broadcast our own claim, so the
        // user can watch the lockup confirm instead of staring at a
        // blank "Confirming the on-chain transaction" progress step.
        // Once ``activeSwapClaimTxid`` lands, the lockup link hides
        // and the claim link replaces it (it's the more
        // user-relevant artifact — the tx that lands in their wallet).
        activeSwapLockupTxid: '',
        activeSwapLockupConfirmations: null,
        // Recovery hint surfaced by the cold-storage swap detail
        // endpoint. Shape: ``{ state, severity, headline, detail,
        // actions: [...], metadata: {...} }``. ``null`` when the
        // server omits it (legacy detail responses) or before the
        // first poll lands. Drives the recovery banner above the
        // progress steps.
        activeSwapRecovery: null,
        activeSwapRecoveryBusy: false,
        activeSwapRecoveryError: '',
        swapIsFailed: false,
        swapSteps: [
            { key: 'created', label: 'Created', desc: 'Swap initiated with Boltz' },
            { key: 'paying', label: 'Paying Invoice', desc: 'Lightning payment in progress' },
            { key: 'claiming', label: 'Claiming', desc: 'Broadcasting on-chain claim' },
            { key: 'completed', label: 'Complete', desc: 'Funds sent to cold storage' },
        ],

        // ── Add Receive Capacity (inbound liquidity wizard) ──
        // Mirrors the Cold-Storage swap surface but presents the
        // reverse-swap as "moving sats on-chain to make room to
        // receive". State is intentionally separate from
        // ``activeSwapId`` so a user running Cold Storage and the
        // inbound flow concurrently does not get state collisions.
        showInboundCapacity: false,
        inboundStep: 'form',                  // 'form' | 'progress' | 'success' | 'failed'
        inboundAmountSats: null,
        inboundAmountTouched: false,
        inboundFeeBreakdownOpen: false,
        inboundLoading: false,
        inboundError: '',
        inboundActiveSwapId: null,
        inboundSwapStatus: null,
        inboundClaimTxid: '',
        inboundClaimConfirmations: null,
        inboundSwapError: '',
        inboundDestinationAddress: '',
        // Pre-fill seed: when the dialog is opened from the
        // "short" warning banner, this carries the recv-amount the
        // user was trying to invoice so the default suggested
        // amount can cover it plus a small margin.
        inboundSeedRecvAmount: 0,

        // ── Close Channels (multi-select) ───────────────────────────
        showCloseChannels: false,
        closeStep: 'select',          // 'select' | 'review' | 'progress'
        closeSearch: '',
        closeSortBy: 'local_desc',    // 'local_desc' | 'capacity' | 'alias'
        closeShowInactive: true,
        closeSelected: [],            // array of chan_id
        closeResults: [],             // [{chan_id, alias, force, ok, error}]
        closeRunning: false,
        // chan_ids dimmed on the main tab until the next poll relocates
        // them into the closing section.
        closeChanIds: [],

        // ── Open Inbound (per-channel) ──────────────────────────────
        // Opens receive capacity on ONE chosen channel by draining its
        // local balance: either to the user's own on-chain wallet (a
        // Boltz reverse swap pinned to the channel) or by paying an
        // external Lightning destination through it. Kept on its own
        // flat scalars (the CSP build can't short-circuit dotted access
        // on a possibly-null object) and its own swap-id pin so a
        // per-channel swap never collides with the global Cold Storage
        // or Add-Receive-Capacity flows.
        showChannelInbound: false,
        ciChannel: null,            // the channel this dialog targets
        ciTab: 'onchain',           // 'onchain' | 'lightning'
        ciMaxFreeable: 0,           // rebalanceMaxSendable(channel)
        // on-chain (Boltz) sub-state — mirrors the inbound wizard
        ciStep: 'form',             // 'form' | 'progress' | 'success' | 'failed'
        ciAddress: '',
        ciAmountSats: null,
        ciAmountTouched: false,
        // Backend-suggested retry amount surfaced by the
        // ``insufficient_balance`` rejection payload — non-zero only
        // when the user can recover with one click. Cleared on next
        // submit attempt.
        ciSuggestedRetryAmount: 0,
        ciFeeBreakdownOpen: false,
        ciGenerating: false,
        ciLoading: false,
        ciError: '',
        ciActiveSwapId: null,
        ciSwapStatus: null,
        ciClaimTxid: '',
        ciClaimConfirmations: null,
        // Boltz's lockup tx — they broadcast this on-chain after we
        // pay the LN side; populated as soon as Boltz reports
        // ``transaction.mempool``. Surface it as a Mempool link so the
        // user can watch confirmations during the wait window before
        // we can broadcast our own claim tx (which sets ``ciClaimTxid``).
        ciLockupTxid: '',
        ciLockupConfirmations: null,
        ciSwapError: '',
        ciSwapRecovery: null,      // backend recovery hint for a stuck swap
        ciRecoveryBusy: false,
        ciRecoveryError: '',
        ciAdvancedOpen: false,     // Lightning tab: fee-limit disclosure
        // Four-stage progress tracker (mirrors the Cold Storage swap
        // tracker, keyed off the shared 0-3 ``_swapUserStepIndex``) with
        // plain-language labels for the non-technical audience.
        ciSwapSteps: [
            { key: 'created', label: 'Getting started', desc: 'Setting up the transfer' },
            { key: 'paying', label: 'Sending over Lightning', desc: 'Paying over the Lightning Network' },
            { key: 'claiming', label: 'Receiving to your wallet', desc: 'Confirming the on-chain transaction' },
            { key: 'completed', label: 'Done', desc: 'Sats are in your wallet' },
        ],

        // Best-effort live confirmation tracking.
        // Maps txid → { confirmations, confirmed, block_height,
        // available }; populated by ``txConfPoll`` and consumed
        // by send-onchain / consolidate result views. Silently
        // empty when the chain backend can't answer.
        txConfs: {},

        // Open channel
        chanPubkey: '',
        chanHost: '',
        chanAmount: null,
        chanFeeRate: null,
        chanFeePriority: 'medium',
        chanPrivate: false,
        chanLoading: false,
        chanResult: null,
        chanError: '',

        // ── Braiins Deposit (round-amount Hashpower deposit) ──
        // Single wizard with five possible steps driven by
        // ``braiinsDepositStep``:
        //   form -> [await_funds] -> progress -> success | failed
        // ``await_funds`` is inserted for external sources
        // (ext_lightning / ext_onchain) and skipped for self sources.
        braiinsDepositOpen: false,
        braiinsDepositStep: 'form',  // 'form' | 'await_funds' | 'progress' | 'success' | 'failed'
        braiinsDepositEnabled: true,
        // Set from the runtime-config island (backend ANONYMIZE_ENABLED). Default
        // false so the experimental Anonymize tab stays hidden unless the backend
        // confirms the feature is on; also gates its session/residual polling.
        anonymizeEnabled: false,
        braiinsDepositPresets: [
            50000, 100000, 250000, 500000,
            1000000, 2000000, 3000000, 4000000, 5000000,
        ],
        braiinsDepositAmountSats: null,
        braiinsDepositAddress: '',
        braiinsDepositAddressError: '',
        braiinsDepositLnBalance: 0,
        // On-chain self-source balance + source toggle. The wizard
        // auto-selects the default source based on which balance
        // can afford the deposit.
        braiinsDepositOnchainBalance: 0,
        // Four source kinds. Self ("lightning" / "onchain")
        // gate on the wallet's own balance; external
        // ("ext_lightning" / "ext_onchain") accept funds from any
        // other wallet via an invoice / address.
        braiinsDepositSourceKind: 'lightning',
        // Channel-open alternative for on-chain sources. ``'swap'``
        // (default) = submarine swap; ``'channel'`` = open a channel to
        // the configured routing peer instead (swap-bypass). Surfaced behind an "Advanced"
        // toggle on on-chain sources; reset to 'swap' whenever the source
        // changes. ``braiinsDepositChannelOpenEnabled`` gates whether the
        // toggle is shown at all (operator flag, set from presets).
        braiinsDepositFundingStrategy: 'swap',
        braiinsDepositChannelOpenEnabled: false,
        // Connect-peer preflight (D2/C): null = unknown/not-checked,
        // true = peer reachable, false = unreachable/ineligible.
        braiinsDepositChannelPeerReachable: null,
        braiinsDepositChannelPeerReason: '',
        braiinsDepositChannelPeerChecking: false,
        // D1(a): set when a refused swap deposit could work via channel-open.
        braiinsDepositChannelSuggested: false,
        // Operator kill switch for ext sources. Defaults to
        // true; set from the presets endpoint on open.
        braiinsDepositExtEnabled: true,
        braiinsDepositExtLnInvoiceTtlS: 3600,
        // User-chosen send mode. ``true`` (default) = dust-safe
        // no-change send (the wallet absorbs extras into the
        // deposit output). ``false`` = exact-amount send with a
        // change UTXO returned to the wallet — surfaced to the
        // user via an info bubble warning about dust risk at
        // high fees.
        braiinsDepositIncludeExtras: true,
        braiinsDepositQuote: null,
        braiinsDepositQuoteLoading: false,
        // Per-preset quote cache for the adaptive bin floor.
        // Populated when the wizard opens; each entry is a full
        // quote object so the SPA can read ``arrival_feasible`` per
        // bin without re-fetching as the user clicks around.
        braiinsDepositQuotesByBin: {},
        braiinsDepositQuotesByBinLoading: false,
        braiinsDepositFeeDetailsOpen: false,
        braiinsDepositLoading: false,
        braiinsDepositError: '',
        // Defaults to a safe-shape object (NOT ``null``) so Alpine's
        // @alpinejs/csp evaluator can't blow up on
        // ``braiinsDepositSession.x`` reads in template expressions
        // before the API populates a real session. See
        // ``_emptyBraiinsDepositSession`` near the top of this file.
        braiinsDepositSession: _emptyBraiinsDepositSession(),
        braiinsDepositSessionId: null,
        braiinsDepositHasActiveSession: false,
        braiinsDepositInfoTipOpen: '',
        braiinsDepositAllTxsOpen: false,
        braiinsDepositWhatHappensNextOpen: false,
        // Ext-LN invoice expiry countdown ticker (seconds).
        // Recomputed from session.ext_ln_invoice_expires_at on every
        // 1-Hz tick while in the await_funds step.
        braiinsDepositExtCountdownSeconds: 0,
        _braiinsDepositExtCountdownTimer: null,
        // Plan.a — two-stage transition. When the poller
        // detects funds-arrived, we flip this flag to true for ~2.5s
        // (showing a "Payment received!" banner inside the await
        // screen) before the step actually transitions to 'progress'.
        // This gives the user a beat to register what happened so the
        // screen doesn't whip past them.
        braiinsDepositExtPaymentReceived: false,
        _braiinsDepositExtPaymentReceivedTimer: null,
        // Ext-OC refund panel state. Bound to the input on
        // the failure screen.
        braiinsDepositExtRefundAddress: '',
        braiinsDepositExtRefundError: '',
        _braiinsDepositPollInFlight: false,
        _braiinsDepositQuoteTimer: null,

        // ── Braiins Deposit — dedicated tab state ──
        // Distinct from the wizard-scoped fields above. The tab renders
        // a list of recent deposits and polls /braiins-deposit/sessions
        // every 10s while at least one row is non-terminal.
        braiinsDepositSessions: [],
        braiinsDepositSessionsLoading: false,
        braiinsDepositSessionsError: '',
        _braiinsDepositListPollTimer: null,
        // Per-row disclosure state — maps session id -> bool. Used by
        // the Details ▾ disclosure inside each row.
        braiinsDepositRowDetailsOpen: {},

        // ── Onboarding wizard ──
        // Replaces the tabs view for users whose wallet is in an
        // "empty / not yet usable" state. State is derived from
        // ``summary`` + ``transactions`` + ``pendingChannels`` via
        // the ``onboardingStep`` getter; these flat fields only hold
        // user-controlled inputs (peer choice, amount, custom URI)
        // and a transient "I just submitted, suppress flicker" flag.
        onboardingSkipped: false,
        // Which mode the wizard's picker is in. ``recommended_default``
        // auto-picks the cheapest ⭐ catalog peer that accepts the
        // current amount; ``pick_from_list`` lets the user choose any
        // catalog entry; ``custom`` accepts a pubkey or pubkey@host:port
        // pasted into a textarea.
        onboardingPeerChoiceMode: 'recommended_default',
        // Selected pubkey in ``pick_from_list`` mode; empty until the
        // user clicks a row in the catalog table.
        onboardingPickedPubkey: '',
        // Sort key for the catalog table in ``pick_from_list`` mode.
        // One of ``'fee'`` (ascending median ppm, base as tiebreaker),
        // ``'channels'`` (descending count), or ``'capacity'``
        // (descending BTC).
        onboardingPickFromListSort: 'fee',
        onboardingCustomUri: '',
        onboardingAmountSats: null,
        onboardingAmountTouched: false,             // user typed a value → stop auto-defaulting
        onboardingLoading: false,
        onboardingError: '',
        // Small-channel peer catalog, fetched on dashboard mount so
        // the channel-card enrichment (catalog badges + per-card info
        // tooltip) renders without waiting for the onboarding wizard.
        // ``null`` until the first fetch completes; the load state
        // below disambiguates "not started" from "loading" from
        // "loaded" from "failed."
        smallChannelPeerCatalog: null,
        smallChannelPeerCatalogLoadState: 'idle',
        // Channel card whose info tooltip is currently open — chan_id
        // for active channels, channel_point for pending opens, or ``''``
        // when no card is open. At most one tooltip is open at a time
        // so the dashboard doesn't accumulate floating popups.
        openChannelInfoTooltip: '',

        // ── Channel-mix planner ──
        // Tracks the multi-channel planner flow. Drives both the
        // onboarding wizard's "Plan multiple channels" branch and the
        // standalone planner the Channels tab exposes.
        //
        // ``channelPlanMode`` enumerates the wizard step within the
        // planner: 'wizard_choice' (the user is being asked whether
        // they want one channel or many), 'plan_form' (the planner's
        // inputs are open), 'plan_preview' (the planner has produced a
        // plan), 'executing' (the executor is running), 'done' (the
        // run reached a terminal state).
        channelPlanMode: 'wizard_choice',
        // Form inputs. Defaults are filled in when the planner opens.
        channelPlanForm: {
            target_capacity_sats: 0,
            outbound_option: 'balanced',
            custom_inbound_pct: null,
            peer_mix_mode: 'recommended_diverse',
            manual_picks: [],
            leave_room_for_one_more: false,
            include_marginal_routing: false,
            // Bootstrap (capital-efficient inbound) inputs.
            mode: 'parallel',
            bootstrap_input_kind: 'target',
            bootstrap_target_inbound_sats: null,
            bootstrap_deposit_sats: null,
            bootstrap_final_push_round: false,
        },
        // The {plan, plan_token} returned by ``/wallet/channel-mix/plan``.
        channelPlanResult: null,
        // Toggles between "send the recommended amount" (default) and
        // "send the bare minimum" (user opts in via the link).
        channelPlanShowMinimum: false,
        // Whether the "Why the buffer?" disclosure is expanded.
        channelPlanWhyOpen: false,
        // ``true`` while a /plan or /execute call is in flight, so the
        // submit button can render its loading state.
        channelPlanLoading: false,
        // Last user-visible error from /plan or /execute.
        channelPlanError: '',
        // Channel-mix run we're currently polling.
        channelMixRunId: '',
        // Latest polled status of that run.
        channelMixRun: null,
        _channelMixPollTimer: null,
        // True for a brief window after a channel first goes active
        // so the wizard's celebration view can play before the regular
        // dashboard takes over.
        onboardingCelebrating: false,
        _onboardingCelebrationTimer: null,

        // Sign / Verify Message
        showSignDialog: false,
        signTab: 'sign',                  // 'sign' | 'verify'
        signIdentity: 'address',          // 'address' | 'node'
        signStep: 'form',                 // 'form' | 'review' | 'result'
        signAddress: '',
        signMessage: '',
        signResult: null,                 // { address, address_type, signature, format } or { signature, node_pubkey }
        signLoading: false,
        signError: '',
        signExportFormat: 'signature',   // 'signature' | 'json' | 'sparrow' | 'ascii'
        signCopiedFlag: false,
        signConfig: null,                 // { max_chars, autocomplete }
        signAddressOptions: [],           // [{address, last_used?}]
        signAddressFilterOpen: false,
        verifyIdentity: 'address',
        verifyAddress: '',
        verifyMessage: '',
        verifySignature: '',
        verifyPaste: '',
        verifyResult: null,
        verifyLoading: false,
        verifyError: '',

        // Refresh timers
        _timers: [],

        // Block clock — flashes the height in the header when a new
        // block lands. ``_lastSeenBlockHeight`` lets us detect changes
        // independently of any specific render path; ``blockClockBump``
        // is a CSS-driven animation key flipped briefly on each new
        // block so the digits do a tasteful flip-in.
        _lastSeenBlockHeight: 0,
        blockClockBump: false,
        _blockClockBumpTimer: null,

        // Flat mirrors of nested ``info.*`` props. The @alpinejs/csp
        // expression parser does NOT short-circuit ``a && a.b``: it
        // still drills into ``a.b`` even when ``a`` is null, throwing
        // "Cannot read property of null or undefined". Mirror to
        // top-level scalars and gate templates on these instead.
        infoAlias: '',
        infoSynced: false,
        infoBlockHeight: 0,

        // ══════════════════════════════════════════════════════════════
        //  CSP-safe helper getters
        //  (replace optional-chaining / globals in template expressions)
        // ══════════════════════════════════════════════════════════════

        /** On-chain confirmed balance (sats). */
        get confirmedBalance() {
            return this.summary?.onchain?.confirmed_balance || 0;
        },
        /** On-chain unconfirmed balance (sats). */
        get unconfirmedBalance() {
            return this.summary?.onchain?.unconfirmed_balance || 0;
        },
        /** On-chain total = confirmed + unconfirmed. Used for the headline
         *  on the On-chain card so a wallet whose only UTXO is mid-spend
         *  (confirmed 0, change pending) shows its real total rather than
         *  "0 sats". Spendability checks still use ``confirmedBalance``. */
        get onchainTotalBalance() {
            return (this.confirmedBalance || 0) + (this.unconfirmedBalance || 0);
        },
        /** Lightning local (outbound) balance (sats). */
        get localBalance() {
            return this.summary?.lightning?.local_balance_sat || 0;
        },
        /** Lightning remote (inbound) balance (sats). */
        get remoteBalance() {
            return this.summary?.lightning?.remote_balance_sat || 0;
        },
        /** Block height formatted with locale separators. */
        get blockHeightDisplay() {
            return this.info?.block_height?.toLocaleString() || '';
        },
        /** Whether the cold-storage result was successful. */
        get coldResultSuccess() {
            return this.coldResultData && this.coldResultData.success;
        },
        /** Whether the cold-storage result was a failure. */
        get coldResultFailed() {
            return this.coldResultData && !this.coldResultData.success;
        },
        /** The fee estimate / result objects, or an empty object when
         *  none is loaded. Both start null and reset to null on each
         *  re-estimate / reset, so the panel's field bindings read
         *  through these — the CSP build evaluates dotted access even
         *  behind ``&&``, and a re-estimate can null the object while the
         *  panel is still tearing down. */
        get coldEstimateOrEmpty() {
            return this.coldEstimate || {};
        },
        get coldResultDataOrEmpty() {
            return this.coldResultData || {};
        },
        /**
         * Whether to show the swap-recovery banner. Computed in JS (which
         * short-circuits) because the Alpine CSP expression evaluator does
         * not short-circuit `&&` through dotted property access, so an
         * inline `activeSwapRecovery && activeSwapRecovery.severity` throws
         * when activeSwapRecovery is null.
         */
        get showSwapRecoveryBanner() {
            const r = this.activeSwapRecovery;
            return !!(r && (r.severity === 'warning' || r.severity === 'critical'));
        },
        /** Cold Storage progress view: show the Boltz lockup-tx
         *  Mempool link IFF we know the lockup txid AND our own claim
         *  hasn't broadcast yet. Once ``activeSwapClaimTxid`` lands,
         *  the claim panel takes over (it's the more user-relevant
         *  link — the tx that actually arrives in their wallet). Mirrors
         *  ``ciShouldShowLockupTxid`` for the per-channel Open Inbound
         *  flow. */
        get shouldShowActiveSwapLockupTxid() {
            return !!this.activeSwapLockupTxid && !this.activeSwapClaimTxid;
        },
        /** Whether the active swap-recovery banner has actions to render. */
        get swapRecoveryHasActions() {
            const r = this.activeSwapRecovery;
            return !!(r && r.actions && r.actions.length > 0);
        },

        // ── CSP-safe Math wrappers ──
        mathMin(a, b) { return Math.min(a, b); },
        mathMax(a, b) { return Math.max(a, b); },
        mathCeil(a)   { return Math.ceil(a); },

        /** Format a date string to "Mon DD" short form. */
        formatDateStr(dateStr) {
            if (!dateStr) return '';
            return new Date(dateStr).toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
        },

        // ── Multi-statement click handlers ──
        /** Cold-storage on-chain: go back from failure result. */
        coldOnchainTryAgain() {
            this.coldStep = 'form';
            this.coldResultData = null;
        },
        /** Cold-storage lightning: reset form for a new swap. */
        coldBoltzNewSwap() {
            this.coldStep = 'form';
            this.coldResultData = null;
            this.activeSwapId = null;
            this.activeSwapClaimTxid = '';
            this.activeSwapClaimConfirmations = null;
            this.activeSwapLockupTxid = '';
            this.activeSwapLockupConfirmations = null;
            this.coldBoltzAmount = null;
            this.coldBoltzAddress = '';
            this.coldBoltzAcceptStale = false;
        },
        /** Set Boltz amount to maximum sendable. Falls back to the
         *  hard-coded Boltz cap when the fees fetch hasn't returned
         *  a usable max yet — without this, clicking Send Max during
         *  the initial loading window would set the amount to
         *  ``-Infinity`` (the sentinel default for ``boltzFees.max``)
         *  and the input would display garbage. */
        setMaxBoltzAmount() {
            const max = this.boltzFeesUsable ? this.boltzFees.max : 25000000;
            const raw = Math.min(
                this.summary?.lightning?.local_balance_sat || 0,
                max,
            );
            // Reserve the routing-fee buffer the backend requires —
            // otherwise Max fills a value that fails the post-confirm
            // insufficient-balance check.
            this.coldBoltzAmount = _withBoltzBuffer(raw);
        },
        /** True only when ``fetchBoltzFees`` has completed *and*
         *  the resulting payload carries finite ``min`` / ``max``
         *  values. ``boltzFees`` defaults to the sentinel
         *  ``{ min: Infinity, max: -Infinity }`` until the first
         *  fetch resolves; expressions reading ``boltzFees.min``
         *  before then would yield "Minimum: ∞" warnings.
         *  Centralised here so both the Cold-Storage form and any
         *  future surface gate on a single signal. */
        get boltzFeesUsable() {
            if (!this._boltzFeesFetched) return false;
            const fees = this.boltzFees || {};
            return typeof fees.min === 'number' && isFinite(fees.min)
                && typeof fees.max === 'number' && isFinite(fees.max);
        },

        /** Cold-Storage Lightning tab: amount is below the Boltz
         *  minimum *and* we have a real minimum to compare against.
         *  Without the ``boltzFeesUsable`` gate, the warning flashes
         *  "Minimum: ∞ sats" during the initial Tor-routed fetch. */
        coldBoltzAmountBelowMin() {
            return this.boltzFeesUsable
                && this.coldBoltzAmount > 0
                && this.coldBoltzAmount < this.boltzFees.min;
        },

        /** Symmetric — would flash "Maximum: -∞ sats" without the
         *  gate. */
        coldBoltzAmountAboveMax() {
            return this.boltzFeesUsable
                && this.coldBoltzAmount > 0
                && this.coldBoltzAmount > this.boltzFees.max;
        },

        /** Boltz service fee in sats. */
        boltzFeeAmount() {
            return Math.ceil(this.coldBoltzAmount * this.boltzFees.fees_percentage / 100);
        },
        /** Total Boltz miner fees (lockup + claim). */
        boltzMinerTotal() {
            return this.boltzFees.fees_miner_lockup + this.boltzFees.fees_miner_claim;
        },
        /** Estimated sats received on-chain after Boltz fees. */
        boltzReceiveAmount() {
            return Math.max(0, this.coldBoltzAmount - this.boltzFeeAmount() - this.boltzMinerTotal());
        },
        /** Whether the entered Boltz amount is within the allowed range. */
        isBoltzAmountInRange() {
            return this.coldBoltzAmount > 0
                && this.boltzFees
                && this.coldBoltzAmount >= (this.boltzFees.min || 0)
                && this.coldBoltzAmount <= (this.boltzFees.max || 25000000);
        },
        /** Boltz fee range placeholder text. Falls back to the
         *  hard-coded range while ``boltzFees`` is still at the
         *  sentinel default \u2014 otherwise the placeholder reads
         *  "\u221e \u2013 -\u221e" during the initial fetch window. */
        boltzPlaceholder() {
            if (!this.boltzFeesUsable) return '25,000 \u2013 25,000,000';
            return this.formatSats(this.boltzFees.min) + ' \u2013 ' + this.formatSats(this.boltzFees.max);
        },
        /** Whether the Review Swap button should be disabled. */
        get boltzReviewDisabled() {
            var b = this.boltzFees;
            return !this.coldBoltzAddress
                || this.coldBoltzAddress.length < 26
                || !this.coldBoltzAmount
                || (b && (this.coldBoltzAmount < b.min || this.coldBoltzAmount > b.max))
                || this.coldBoltzAmount > this.localBalance
                || (b && b.stale && !this.coldBoltzAcceptStale);
        },
        /** Dismiss the toast notification after a delay. */
        initToastDismiss() {
            setTimeout(() => { this.toast = ''; }, 3000);
        },

        // ── CSP-safe template helpers ──

        /** Format ISO date string with time for activity log. */
        formatDateFull(dateStr) {
            if (!dateStr) return '\u2014';
            return new Date(dateStr).toLocaleString(undefined, {month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'});
        },

        /** Absolute value of a parsed transaction amount. */
        txAbsAmount(amount) {
            return Math.abs(parseInt(amount || 0));
        },

        /** Whether a transaction amount is non-negative. */
        txIsPositive(amount) {
            return parseInt(amount) >= 0;
        },

        /** Channel display name: peer alias (preferred), legacy alias,
         *  or truncated pubkey as a last resort. LND populates
         *  ``peer_alias`` from the gossip graph; ``remote_alias`` is
         *  kept for backward compatibility with older payloads. */
        channelAlias(ch) {
            if (!ch) return '';
            const alias = (ch.peer_alias || ch.remote_alias || '').trim();
            if (alias) return alias;
            return ch.remote_pubkey ? ch.remote_pubkey.slice(0, 16) + '…' : '';
        },

        /** Three-state channel-status classifier used by the dot icon
         *  next to each channel row. Returns:
         *
         *    'active'       — fully routable (green dot)
         *    'waiting'      — funded + peer connected, but peer hasn't
         *                     finalised ``channel_ready`` yet, usually
         *                     because their LND requires more
         *                     confirmations than ours did. Resolves on
         *                     its own once the peer catches up. (yellow)
         *    'offline'      — peer not currently connected; channel
         *                     can't carry HTLCs until the peer
         *                     reconnects. (grey)
         *
         *  When the backend couldn't determine ``peer_connected`` (LND
         *  ``/peers`` call failed), the field is missing — fall back to
         *  the historical binary green/grey behaviour by treating
         *  ``ch.active=false`` as 'offline' so we don't surface a
         *  yellow dot we can't actually justify.
         */
        channelStatus(ch) {
            if (!ch) return 'offline';
            if (ch.active) return 'active';
            if (ch.peer_connected === true) return 'waiting';
            return 'offline';
        },
        /** CSS class for the dot. */
        channelStatusDotClass(ch) {
            switch (this.channelStatus(ch)) {
                case 'active':  return 'bg-neon-green';
                case 'waiting': return 'bg-neon-yellow';
                default:        return 'bg-gray-600';
            }
        },
        /** Tooltip text — what the dot's colour means in plain English. */
        channelStatusTooltip(ch) {
            switch (this.channelStatus(ch)) {
                case 'active':
                    return 'Active — ready to send and receive payments.';
                case 'waiting':
                    return 'Funded and peer is connected, but they ' +
                           "haven't finalised the channel yet (usually " +
                           'because their node requires more confirmations ' +
                           'than ours did). This typically clears in a few ' +
                           'blocks.';
                default:
                    return 'Peer is offline. The channel will become ' +
                           'usable again as soon as the peer reconnects.';
            }
        },

        /** Per-channel in-flight flag for the "Reconnect peer" button,
         *  keyed by chan_id. Drives the spinner + disabled state. */
        channelReconnectBusy: {},
        /** Per-channel result toast (success or error) for the
         *  "Reconnect peer" action. Keyed by chan_id. ``null`` clears it.
         *  Shape: ``{ ok: bool, message: string }``. */
        channelReconnectResult: {},

        /** Run the disconnect/reconnect pair on this channel's peer.
         *  Idempotent on the LND side (a healthy active channel just
         *  blips briefly and reactivates); the operator decides when to
         *  fire it based on the yellow dot + tooltip. */
        async reconnectChannelPeer(ch) {
            if (!ch || !ch.chan_id) return;
            const id = ch.chan_id;
            if (this.channelReconnectBusy[id]) return;
            this.channelReconnectBusy = { ...this.channelReconnectBusy, [id]: true };
            this.channelReconnectResult = { ...this.channelReconnectResult, [id]: null };
            try {
                const data = await this.api(
                    'POST',
                    '/channels/' + encodeURIComponent(id) + '/reconnect-peer',
                );
                this.channelReconnectResult = {
                    ...this.channelReconnectResult,
                    [id]: {
                        ok: true,
                        message: 'Reconnected. The channel will refresh in a moment.',
                    },
                };
                // Refresh the channel list a beat later so the dot has
                // a chance to flip green if this worked.
                setTimeout(() => this.fetchChannels(), 2000);
            } catch (e) {
                this.channelReconnectResult = {
                    ...this.channelReconnectResult,
                    [id]: {
                        ok: false,
                        message: (e && e.message) || 'Reconnect failed. Try again in a few minutes.',
                    },
                };
            }
            this.channelReconnectBusy = { ...this.channelReconnectBusy, [id]: false };
            this.$nextTick(() => this.initIcons());
        },

        /** Unique key for a pending channel. */
        pendingChannelKey(pc) {
            return pc.channel_point || JSON.stringify(pc);
        },

        /** Truncated pubkey for pending channel display. */
        pendingPubkey(pc) {
            return pc.remote_node_pub ? pc.remote_node_pub.slice(0, 16) + '…' : '';
        },

        /** Funding txid extracted from a pending channel's
         *  ``channel_point`` ("txid:vout"). Returns "" if absent so
         *  the copy / mempool affordances can hide cleanly. */
        pendingTxid(pc) {
            const cp = (pc && pc.channel_point) || '';
            const colon = cp.indexOf(':');
            return colon > 0 ? cp.slice(0, colon) : cp;
        },

        /** Number of confirmations the funding transaction has, or
         *  ``0`` while it's still in the mempool. lnd returns
         *  ``confirmation_height`` = the block the funding tx was
         *  mined in (0 = unconfirmed); we subtract from the chain
         *  tip exposed by ``getinfo`` to get the count. */
        pendingConfirmations(pc) {
            const conf = (pc && pc.confirmation_height) || 0;
            const tip = (this.info && this.info.block_height) || 0;
            if (!conf || !tip || tip < conf) return 0;
            return tip - conf + 1;
        },

        /** Default lnd ``minconf`` for an inbound channel to graduate
         *  out of pending. lnd's default is 3; wumbo or remotely
         *  configured peers can demand more, but 3 is the right
         *  hint to show in the UI for the common case. */
        pendingConfTarget() {
            return 3;
        },

        /** Short human label for the confirmation state of a pending
         *  open channel. */
        pendingConfLabel(pc) {
            const n = this.pendingConfirmations(pc);
            if (n <= 0) return 'In mempool — awaiting first confirmation';
            const target = this.pendingConfTarget();
            return n + ' / ~' + target + ' confirmation' + (target === 1 ? '' : 's');
        },

        // ── Pending/closing channel presentation ───────────────────
        /** Friendly status label for a pending channel of any kind. */
        pendingStatusLabel(pc) {
            switch (pc && pc.type) {
                case 'pending_open': return 'Opening';
                case 'waiting_close': return 'Closing — broadcasting';
                case 'pending_close': return 'Closing';
                case 'force_closing': return 'Force-closing';
                default: return 'Pending';
            }
        },
        /** Status-dot colour by pending type. */
        pendingDotClass(pc) {
            switch (pc && pc.type) {
                case 'force_closing': return 'bg-amber-400 animate-pulse-neon';
                case 'pending_close': return 'bg-neon-cyan animate-pulse-neon';
                default: return 'bg-neon-yellow animate-pulse-neon';
            }
        },
        /** The relevant txid to surface. For a *closing* channel that's
         *  the closing tx only — never fall back to the funding (open)
         *  tx, which would mislead (e.g. while ``waiting_close`` has no
         *  closing_txid yet, show nothing). For a pending-open channel
         *  it's the funding tx. */
        pendingDisplayTxid(pc) {
            if (!pc) return '';
            if (pc.type === 'pending_open') return this.pendingTxid(pc);
            return pc.closing_txid || '';
        },
        /** Context-aware label for that txid. */
        pendingTxLabel(pc) {
            return (pc && pc.type === 'pending_open') ? 'Funding tx:' : 'Closing tx:';
        },
        /** Plain-language ETA for force-close fund maturity. */
        closingMaturityLabel(pc) {
            const blocks = (pc && pc.blocks_til_maturity) || 0;
            if (blocks <= 0) return 'Funds maturing — releasing shortly';
            const mins = blocks * 10;
            let when;
            if (mins < 60) when = '~' + mins + ' min';
            else if (mins < 1440) when = '~' + Math.round(mins / 60) + 'h';
            else when = '~' + Math.round(mins / 1440) + ' day' + (Math.round(mins / 1440) === 1 ? '' : 's');
            return 'Funds release in ~' + blocks + ' block' + (blocks === 1 ? '' : 's') + ' (' + when + ')';
        },

        /** Aggregate force-close limbo balance for the On-chain card. */
        get limboBalance() {
            return (this.summary && this.summary.pending_channels
                    && this.summary.pending_channels.total_limbo_balance) || 0;
        },

        /** Whether a still-listed active channel has just had a close
         *  requested (dim+disable its card until the poll relocates it). */
        isChannelClosing(ch) {
            if (!ch) return false;
            return this.closeChanIds.indexOf(ch.chan_id) !== -1;
        },

        /** Activity log items array (CSP-safe). */
        get activityList() {
            return (this.activity && this.activity.items) || [];
        },

        /** Whether activity items exist. */
        get hasActivity() {
            return this.activity && this.activity.items && this.activity.items.length > 0;
        },

        /** Whether activity pagination is needed. */
        get activityHasPages() {
            return this.activity && this.activity.total > 50;
        },

        /** Activity "Showing X of Y" label. */
        activityShowingLabel() {
            var count = this.activityList.length;
            return 'Showing ' + count + ' of ' + (this.activity ? this.activity.total : 0);
        },

        /** Navigate to previous activity page. */
        activityPrev() {
            this.activityOffset = Math.max(0, this.activityOffset - 50);
            this.fetchActivity();
        },

        /** Navigate to next activity page. */
        activityNext() {
            this.activityOffset += 50;
            this.fetchActivity();
        },

        /** Whether prev page button is disabled. */
        get activityPrevDisabled() {
            return this.activityOffset === 0;
        },

        /** Whether next page button is disabled. */
        get activityNextDisabled() {
            return !this.activity || this.activityOffset + 50 >= this.activity.total;
        },

        /** Set cold on-chain amount to max sendable. */
        setMaxColdAmount() {
            if (this.sendCoinControlMode === 'manual' && this.sendCoinControlSelected.length > 0) {
                this.coldAmount = Math.max(0, this.sendCoinControlSelectedTotal - (this.coldEstimate ? this.coldEstimate.fee_sat : 500));
                return;
            }
            this.coldAmount = Math.max(0, this.confirmedBalance - (this.coldEstimate ? this.coldEstimate.fee_sat : 500));
        },

        /** Whether on-chain cold-storage review button should be disabled. */
        get coldReviewDisabled() {
            if (!this.isValidBtcAddress(this.coldAddress) || !this.coldAmount || this.coldAmount < 546) return true;
            if (this.sendCoinControlMode === 'manual') {
                if (this.sendCoinControlSelected.length === 0) return true;
                if (this.coldAmount > this.sendCoinControlSelectedTotal) return true;
                return false;
            }
            return this.coldAmount > this.confirmedBalance;
        },

        /** Button text for lightning swap result. */
        get coldResultBtnText() {
            return this.coldResultData && this.coldResultData.success ? 'New Swap' : 'Try Again';
        },

        /** Go back from decoded invoice review to input. */
        backFromInvoiceReview() {
            this.decodedInvoice = null;
            this.payError = '';
        },

        /** Reset fund address to generate a new one. */
        resetFundAddress() {
            this.fundAddress = '';
            this.fundCopied = false;
            this.fundError = '';
        },

        /** Switch cold storage dialog to on-chain tab. */
        switchColdOnchain() {
            this.coldTab = 'onchain';
            this.coldStep = 'form';
            this.coldResult = '';
            this.coldError = '';
        },

        /** Switch cold storage dialog to lightning tab. */
        switchColdLightning() {
            this.coldTab = 'lightning';
            this.coldStep = 'form';
            this.coldResult = '';
            this.coldError = '';
        },

        // Convenience entry points exposed on the On-chain tab so users
        // can reach send/receive functionality from the place they
        // intuitively look for it. Both reuse the existing dialogs
        // verbatim — no duplicated state or UI — they just open the
        // right modal in the right initial state. Defined as methods
        // (rather than inline expressions) because the @alpinejs/csp
        // evaluator does not support multi-statement bodies.
        openOnchainSend() {
            this.coldTab = 'onchain';
            this.coldStep = 'form';
            this.coldResult = '';
            this.coldError = '';
            this.coldResultData = null;
            this.coldEstimate = null;
            this.showSendOnchain = true;
        },
        /** Close the Send On-chain dialog and reset its state. Mirrors
         *  closeColdStorage() but without lightning-swap teardown. */
        closeSendOnchain() {
            this.showSendOnchain = false;
            this.coldStep = 'form';
            this.coldResult = '';
            this.coldError = '';
            this.coldEstimate = null;
            this.coldResultData = null;
        },
        /** Reset the Send On-chain dialog after a failed send. */
        sendOnchainTryAgain() {
            this.coldStep = 'form';
            this.coldResultData = null;
        },
        openOnchainReceive() {
            // Always present a clean slate: a previous successful or
            // failed generate would otherwise leave `fundAddress`
            // populated (hiding the address-type picker behind
            // `x-show="!fundAddress"`) or `fundLoading` stuck true.
            this.fundAddress = '';
            this.fundError = '';
            this.fundLoading = false;
            this.fundCopied = false;
            this.fundAddrType = 'p2wkh';
            this.showFundWallet = true;
        },

        // ── Init ──
        async init() {
            this._loadRuntimeConfig();
            // Onboarding skip flag — hydrate before fetchAll() so a
            // returning skipped user never sees the wizard flash.
            try {
                this.onboardingSkipped = localStorage.getItem('onboardingSkipped') === '1';
            } catch (_e) {
                this.onboardingSkipped = false;
            }
            await this.fetchAll();
            this.initIcons();

            // Onboarding wizard reactivity. ``$watch`` on the getter
            // fires whenever the derived step changes (welcome →
            // awaiting_deposit → ready_to_connect → connecting → null).
            // Pre-fill the suggested amount on first land in
            // ``ready_to_connect`` and start/stop the 4 s poller.
            // On the connecting → null edge we play a brief
            // celebration view before handing off to the
            // regular dashboard.
            this.$watch('onboardingStep', (newStep, oldStep) => {
                if (newStep && !this._isPolling('onboarding')) {
                    this._startOnboardingPoller();
                } else if (!newStep) {
                    this._stopOnboardingPoller();
                }
                if (newStep === 'ready_to_connect') {
                    this._maybePrefillOnboardingAmount();
                    // Fetch the small-channel catalog so the picker can
                    // render the recommended-default + pick-from-catalog
                    // modes. Fire-and-forget; the load-state field
                    // drives the template gating.
                    this._ensureSmallChannelPeerCatalog();
                }
                // The wallet just became usable — only celebrate when
                // we came from ``connecting`` (a channel-open the user
                // actually drove through the wizard) AND the user did
                // not explicitly skip. Otherwise quietly hand off.
                if (oldStep === 'connecting' && !newStep && !this.onboardingSkipped) {
                    this._triggerOnboardingCelebration();
                } else if (!oldStep && newStep) {
                    // Wizard just mounted (e.g. user hit "Resume guided
                    // setup" from the header menu). The freshly-rendered
                    // ``<i data-lucide>`` placeholders need replacement;
                    // the initial fetchAll() initIcons() call missed them
                    // because the wizard wasn't in the DOM yet.
                    this.$nextTick(() => this.initIcons());
                } else if (oldStep && !newStep) {
                    this.$nextTick(() => this.initIcons());
                }
            });
            // Kick the poller for the initial state.
            if (this.onboardingStep) this._startOnboardingPoller();
            if (this.onboardingStep === 'ready_to_connect') {
                this._maybePrefillOnboardingAmount();
                this._ensureSmallChannelPeerCatalog();
            }

            // Resume an in-progress inbound-liquidity swap from a
            // previous session if the user refreshed mid-flow. Fires
            // and forgets — the page is already interactive by the
            // time the network round-trip resolves.
            this._restoreInboundSwap();
            // Same recovery for an in-progress Cold-Storage swap
            // (previously these swaps had no UI recovery — the
            // dialog would reopen on the empty form even though the
            // backend Celery task was still working).
            this._restoreColdSwap();
            // And for a per-channel "Open Inbound" swap.
            this._restoreChannelInbound();
            // Braiins Deposit session resume — server enforces a
            // single in-flight session per dashboard, so we just
            // ask the server for it rather than pinning to
            // localStorage.
            this._restoreBraiinsDeposit();
            // Listen for browser tab visibility changes so the
            // Braiins-Deposit list poller pauses while the user is on
            // another browser tab and resumes when they come back.
            if (typeof document !== 'undefined') {
                document.addEventListener('visibilitychange', () => {
                    if (document.visibilityState === 'visible'
                            && this.activeTab === 'braiins-deposit') {
                        this.braiinsDepositFetchSessions();
                    } else if (this._braiinsDepositListPollTimer) {
                        clearTimeout(this._braiinsDepositListPollTimer);
                        this._braiinsDepositListPollTimer = null;
                    }
                });
            }
            // Keep the suggested amount fresh until the user types.
            this.$watch('summary', () => {
                if (this.onboardingStep === 'ready_to_connect') {
                    this._maybePrefillOnboardingAmount();
                }
            });

            // Auto-refresh intervals (guarded pollers)
            this._poll('summary', () => this.fetchSummary(),
                { intervalMs: 30000, immediate: false });
            // Channel + info refresh adapts to context: a tighter
            // 15 s cadence when there's at least one pending-open
            // channel (so confirmation progress feels responsive
            // around block-storms), otherwise 60 s. The interval is
            // recreated whenever pendingChannels changes shape.
            this._refreshChannelsTimer();
            this.$watch('pendingChannels', () => this._refreshChannelsTimer());
            this._poll('activity',
                () => Promise.all([this.fetchPayments(), this.fetchInvoices()]),
                { intervalMs: 30000, immediate: false });
            // Keep the Settings → Tor Health dot live so it's a real
            // at-a-glance signal without opening the panel. Cheap: the
            // probe is a local Tor control-port query.
            this._poll('torHealthIndicator', () => this._torHealthIndicatorTick(),
                { intervalMs: 60000, immediate: true });

            // Rebalance fee preview: keep ``feeLimitApproxSats`` in
            // sync with the percent + amount inputs so the "≈ N sats"
            // hint never goes stale. We watch each input explicitly
            // because the CSP expression evaluator can miss
            // transitive reactive reads through chained method calls.
            this.$watch('rebalance.feeLimitPercent', () => this._recomputeFeeLimitApproxSats());
            this.$watch('rebalanceAmountSats', () => this._recomputeFeeLimitApproxSats());
            this.$watch('rebalance.feeLimitMode', () => this._recomputeFeeLimitApproxSats());
            this.$watch('rebalance.feeLimitSats', () => this._recomputeFeeLimitApproxSats());

            // Mirror the flat fee-limit scalars (the ones the CSP-
            // safe x-models actually write to) back into the nested
            // ``rebalance.*`` payload, then re-quote.
            this.$watch('rebalanceFeeLimitPercent', (v) => {
                const n = Number(v);
                this.rebalance.feeLimitPercent = Number.isFinite(n) && n >= 0 ? n : 0;
                this.scheduleRebalanceQuote();
            });
            this.$watch('rebalanceFeeLimitSats', (v) => {
                const n = parseInt(v, 10);
                this.rebalance.feeLimitSats = Number.isFinite(n) && n >= 0 ? n : 0;
                this.scheduleRebalanceQuote();
            });

            // Rebalance visualisation: recompute the flat scalars
            // (slice positions, arrow path, "remaining after", etc.)
            // whenever the inputs that drive them change. The amount
            // is watched via the flat ``rebalanceAmountSats`` mirror
            // because the CSP build's nested-path ``$watch`` is
            // unreliable after the first mutation.
            this.$watch('rebalanceAmountSats', (v) => {
                const n = parseInt(v, 10);
                this.rebalance.amountSats = Number.isFinite(n) && n > 0 ? n : 0;
                this._recomputeRebalanceVis();
                this.scheduleRebalanceQuote();
            });
            this.$watch('rebalance.source', () => this._recomputeRebalanceVis());
            this.$watch('rebalance.dest', () => this._recomputeRebalanceVis());
            this._recomputeRebalanceVis();

            // Send-payment advanced controls: keep the flat mirrors,
            // the nested ``pay.*`` object, and the reactive
            // ``feeLimitApproxSats`` shadow in sync. Same pattern as
            // the rebalance watchers above; the CSP build cannot
            // x-model into nested paths.
            this.$watch('payFeeLimitPercent', (v) => {
                const n = Number(v);
                this.pay.feeLimitPercent = Number.isFinite(n) && n >= 0 ? n : 0;
                this._recomputePayFeeLimitApproxSats();
                this.pay.quote = null;
            });
            this.$watch('payFeeLimitSats', (v) => {
                const n = parseInt(v, 10);
                this.pay.feeLimitSats = Number.isFinite(n) && n >= 0 ? n : 0;
                this._recomputePayFeeLimitApproxSats();
                this.pay.quote = null;
            });
            this.$watch('payTimeoutSeconds', (v) => {
                const n = parseInt(v, 10);
                if (Number.isFinite(n) && n >= 5 && n <= 300) {
                    this.pay.timeoutSeconds = n;
                }
            });
            this.$watch('lnurlAmountStr', () => {
                this._recomputePayFeeLimitApproxSats();
                this.pay.quote = null;
            });
            this.$watch('decodedInvoice', () => {
                this._recomputePayFeeLimitApproxSats();
                this.pay.quote = null;
            });
            this.$watch('pay.source', () => {
                this.pay.quote = null;
                this.pay.quoteError = '';
            });

            // Block clock: bump the digits whenever block_height
            // increases. Only fires after the first non-zero value so
            // we don't animate the initial render.
            //
            // Watches ``info`` rather than ``info.block_height`` because
            // the CSP-build's path watcher throws ``Cannot read property
            // of null or undefined`` when the parent is null — and ``info``
            // is null until /info resolves (fetchAll fires it in parallel
            // and no longer blocks on it).
            this.$watch('info', (newInfo) => {
                const newVal = newInfo && newInfo.block_height;
                if (!newVal) return;
                if (this._lastSeenBlockHeight && newVal > this._lastSeenBlockHeight) {
                    this.blockClockBump = true;
                    if (this._blockClockBumpTimer) clearTimeout(this._blockClockBumpTimer);
                    this._blockClockBumpTimer = setTimeout(() => { this.blockClockBump = false; }, 900);
                    // Refresh the UTXO list when a new block lands so
                    // the Confirmations column updates without a
                    // manual page reload. Only fetch when the user is
                    // actually looking at the UTXOs subtab to avoid
                    // unnecessary LND calls.
                    if (this.onchainSubTab === 'utxos') {
                        this.loadUtxos();
                    }
                    // Same idea for the Transactions subtab — keep
                    // the num_confirmations column live.
                    if (this.onchainSubTab === 'transactions') {
                        this.fetchTransactions();
                    }
                }
                this._lastSeenBlockHeight = newVal;
            });

            // Mirror nested ``info.*`` reads onto flat top-level
            // scalars so CSP-build templates can avoid chained
            // property access on a possibly-null object.
            this.$watch('info', (val) => {
                this.infoAlias = (val && val.alias) || '';
                this.infoSynced = !!(val && val.synced_to_chain);
                this.infoBlockHeight = (val && val.block_height) || 0;
            });

            // Cold Storage: auto-fetch Boltz fees + swap history when dialog opens
            this.$watch('showColdStorage', (val) => {
                if (val) {
                    // If there's already an active swap (e.g. the user
                    // closed the dialog mid-flow and re-opened it),
                    // route straight to the progress view and make
                    // sure the poller is running — don't drop the
                    // user back into the empty form.
                    if (this.activeSwapId
                            && this.activeSwapStatus
                            && !SWAP_TERMINAL_STATUSES.has(this.activeSwapStatus)) {
                        this.coldTab = 'lightning';
                        this.coldStep = 'progress';
                        if (!this._isPolling('coldSwap')) this.startSwapPoll();
                    }
                    this.fetchBoltzFees();
                    this.fetchSwapHistory();
                    this.$nextTick(() => this.initIcons());
                }
            });
            // Cold Storage: auto-estimate on-chain fee when inputs change
            this.$watch('coldAddress', () => this.debounceColdEstimate());
            this.$watch('coldAmount', () => this.debounceColdEstimate());
            // Re-render icons whenever cold step changes
            this.$watch('coldStep', () => this.$nextTick(() => this.initIcons()));
            // Re-render icons when dialogs open
            this.$watch('showFundWallet', () => this.$nextTick(() => this.initIcons()));
            this.$watch('showSendOnchain', () => this.$nextTick(() => this.initIcons()));
            this.$watch('showRebalance', () => this.$nextTick(() => this.initIcons()));
            this.$watch('showSendPayment', () => this.$nextTick(() => this.initIcons()));
            this.$watch('showReceiveInvoice', () => this.$nextTick(() => this.initIcons()));
            this.$watch('showChannelInbound', () => this.$nextTick(() => this.initIcons()));
            // Re-render icons for the per-channel "Open Inbound" dialog's
            // dynamically-inserted blocks (step transitions, the recovery
            // banner, and the claim-txid affordance that appears mid-poll).
            this.$watch('ciStep', () => this.$nextTick(() => this.initIcons()));
            this.$watch('ciSwapStatus', () => this.$nextTick(() => this.initIcons()));
            this.$watch('ciClaimTxid', () => this.$nextTick(() => this.initIcons()));
            this.$watch('ciSwapRecovery', () => this.$nextTick(() => this.initIcons()));
            // BOLT 12: lazy-load offers the first time the tab is opened.
            // We deliberately do NOT call fetchBolt12Receive() here — that
            // endpoint auto-mints a default offer on first hit, which would
            // skip the empty-state "Create your first offer" CTA. The list
            // load decides whether to fetch the receive panel.
            this.$watch('activeTab', (val) => {
                if (val === 'bolt12' && this.bolt12IssuedOffers === null) {
                    this.fetchBolt12IssuedOffersInitial();
                    this.fetchBolt12Payees();
                }
                if (val === 'anonymize') {
                    // Refresh on tab activation so the user sees the
                    // current state when returning to the tab, then
                    // start polling while any session is non-terminal.
                    // Silent mode after the first hydration so the
                    // session list doesn't flash "Loading…" each time
                    // the user re-enters the tab.
                    this.anonymizeFetchSessions(
                        {silent: this.anonymizeSessionsHydrated},
                    );
                    this.anonymizeStartSessionsPolling();
                    // Fetch the policy so the row template's
                    // confirming-status target ("X/Y") and the
                    // countdown threshold are populated even
                    // when the user hasn't opened the wizard. Both
                    // values have safe hardcoded defaults so a fetch
                    // failure leaves the SPA functional.
                    if (!this.anonymizePolicyLoaded) {
                        this.anonymizeFetchPolicy();
                    }
                } else {
                    this.anonymizeStopSessionsPolling();
                }
                if (val === 'braiins-deposit') {
                    this.braiinsDepositFetchSessions();
                } else if (this._braiinsDepositListPollTimer) {
                    clearTimeout(this._braiinsDepositListPollTimer);
                    this._braiinsDepositListPollTimer = null;
                }
                this.$nextTick(() => this.initIcons());
            });
        },

        initIcons() {
            // Funnel through the page-level pointer-safe renderer (see
            // dashboard.html), which never swaps icon nodes while a pointer is
            // pressed (so the `<i>`→`<svg>` swap can't cancel an in-flight click
            // on a button's icon). $nextTick so Alpine has flushed the new
            // icons into the DOM before we render them.
            this.$nextTick(() => { if (window.renderIcons) window.renderIcons(); });
        },

        // ── API helpers ──
        _getCsrfToken() {
            // ():
            // CSRF lives in a meta tag, not a JS-readable cookie. We
            // read from there on every request so the latest rotated
            // value (written back by ``_storeCsrfNext`` after the
            // server sends ``X-CSRF-Token-Next``) is always used.
            const meta = document.querySelector('meta[name="csrf-token"]');
            return (meta && meta.getAttribute('content')) || '';
        },

        _storeCsrfNext(headers) {
            // The server rotates the CSRF token on every successful
            // state-changing request and surfaces the new value via
            // ``X-CSRF-Token-Next``. Persist it for subsequent
            // calls; on read-only requests the header is absent and
            // we leave the existing token alone.
            if (!headers || typeof headers.get !== 'function') return;
            const next = headers.get('X-CSRF-Token-Next');
            if (!next) return;
            let meta = document.querySelector('meta[name="csrf-token"]');
            if (!meta) {
                meta = document.createElement('meta');
                meta.setAttribute('name', 'csrf-token');
                document.head.appendChild(meta);
            }
            meta.setAttribute('content', next);
        },

        // Serialise state-changing requests through a single shared
        // promise chain. The dashboard rotates the CSRF token on
        // every successful POST/PUT/PATCH/DELETE and surfaces the
        // new value via ``X-CSRF-Token-Next``. If two such requests
        // were in flight at the same time, both would read the same
        // pre-rotation token from the meta tag — but the server only
        // accepts each token once, so the second one lands as 403
        // ("CSRF token missing or invalid"). The race shows up
        // anywhere a debounce, poller, or background prefetcher can
        // overlap a user-triggered action (the original report:
        // switching the Braiins deposit source to On-chain kicks
        // off a per-bin quote batch, then picking an amount fires a
        // single quote against the same now-stale token).
        //
        // GET requests don't rotate the token and so don't need to
        // join the queue. Errors on the stored chain are swallowed
        // so one failure doesn't poison subsequent calls; each
        // awaiter still observes its own rejection.
        _csrfMutationChain: null,
        _isMutatingMethod(method) {
            const m = String(method || '').toUpperCase();
            return m === 'POST' || m === 'PUT' || m === 'PATCH' || m === 'DELETE';
        },

        // ── Guarded network poller ─────────────────────────────────────
        // Registry of active network pollers, keyed by a stable string.
        // Every network poller goes through ``_poll`` so the in-flight
        // guard (skip a tick while the previous run is still running),
        // the cadence, and the teardown live in ONE place instead of
        // being re-derived per feature. ``fn`` is an async fetch function
        // (it uses ``api()`` so it inherits the default read timeout).
        // Feature-specific STOP conditions stay INSIDE ``fn`` (which
        // calls ``this._stopPoll(key)`` when done) — ``_poll`` only owns
        // interval + guard + lifecycle. Call ``_poll`` only from JS method
        // bodies, never a template directive (the @alpinejs/csp build
        // rejects inline arrow/function args in directives).
        _pollState: null,
        _poll(key, fn, opts) {
            const o = opts || {};
            const intervalMs = Number(o.intervalMs) || 5000;
            const immediate = o.immediate !== false;   // default: fire now
            if (!this._pollState) this._pollState = {};
            this._stopPoll(key);                        // idempotent (re)start
            const state = { inFlight: false, timer: null };
            const tick = async () => {
                if (state.inFlight) return;             // skip — no pile-up
                state.inFlight = true;
                try {
                    await fn();
                } catch (_e) {
                    // Pollers fail quietly and keep cadence; a timed-out
                    // or errored tick is swallowed and retried next
                    // interval. The guard clears in ``finally``.
                } finally {
                    state.inFlight = false;
                }
            };
            state.timer = setInterval(tick, intervalMs);
            this._pollState[key] = state;
            // Register into the SPA's existing teardown array so a single
            // cleanup path stops every poller.
            if (this._timers) this._timers.push(state.timer);
            if (immediate) tick();
            return state.timer;
        },
        _stopPoll(key) {
            const st = this._pollState && this._pollState[key];
            if (!st) return;
            if (st.timer) {
                clearInterval(st.timer);
                if (this._timers) {
                    const idx = this._timers.indexOf(st.timer);
                    if (idx >= 0) this._timers.splice(idx, 1);
                }
            }
            delete this._pollState[key];
        },
        _isPolling(key) {
            return !!(this._pollState && this._pollState[key]);
        },

        async api(method, path, body, opts) {
            if (this._isMutatingMethod(method)) {
                const prev = this._csrfMutationChain || Promise.resolve();
                const run = () => this._apiSend(method, path, body, opts);
                const next = prev.then(run, run);
                this._csrfMutationChain = next.catch(() => {});
                return next;
            }
            return this._apiSend(method, path, body, opts);
        },

        async _apiSend(method, path, body, opts) {
            const reqOpts = { method, headers: { 'X-Requested-With': 'XMLHttpRequest' } };
            const csrf = this._getCsrfToken();
            if (csrf) reqOpts.headers['X-CSRF-Token'] = csrf;
            if (body) {
                reqOpts.headers['Content-Type'] = 'application/json';
                reqOpts.body = JSON.stringify(body);
            }
            // Wall-clock timeout (ms). Idempotent READS get a DEFAULT
            // timeout (``DEFAULT_READ_TIMEOUT_MS``) so no GET can hang the
            // SPA when LND/Tor is slow. MUTATIONS get NO default — aborting
            // a write the server may have already applied (open a channel,
            // pay an invoice) would make the UI show failure for a
            // succeeded write; mutations that should be bounded opt in
            // explicitly. A per-call override always wins, and an explicit
            // ``timeoutMs: 0`` opts a read OUT — distinguished from "not
            // specified" by KEY PRESENCE (not truthiness), so 0 means
            // "no timeout" while an omitted key takes the read default.
            // When the timeout fires fetch() rejects with TimeoutError /
            // AbortError, surfaced as a friendly message below.
            const hasTimeoutOverride =
                opts && Object.prototype.hasOwnProperty.call(opts, 'timeoutMs');
            let timeoutMs;
            if (hasTimeoutOverride) {
                timeoutMs = opts.timeoutMs;
            } else if (!this._isMutatingMethod(method)) {
                timeoutMs = DEFAULT_READ_TIMEOUT_MS;
            }
            if (typeof timeoutMs === 'number' && timeoutMs > 0) {
                try {
                    reqOpts.signal = AbortSignal.timeout(timeoutMs);
                } catch (_e) {
                    // AbortSignal.timeout (2022+) not available in this
                    // browser — fall back to a manual AbortController.
                    const ctrl = new AbortController();
                    setTimeout(() => ctrl.abort(), timeoutMs);
                    reqOpts.signal = ctrl.signal;
                }
            }
            let res;
            try {
                res = await fetch('/dashboard/api' + path, reqOpts);
            } catch (e) {
                // Translate AbortError → friendly message so callers
                // (and the user) see "request timed out" instead of
                // "Failed to fetch" or "The operation was aborted".
                if (e && (e.name === 'AbortError' || e.name === 'TimeoutError')) {
                    const err = new Error(
                        'Request timed out — the node may be unreachable. '
                        + 'Check that LND and Tor are connected, then retry.'
                    );
                    err.status = 0;
                    err.timedOut = true;
                    throw err;
                }
                throw e;
            }
            if (res.status === 401) {
                // Surface a "Session expired" hint on the login page
                // so the user understands why they were bounced out
                // mid-flow (vs being silently dropped on a bare
                // login form).
                window.location.href = '/dashboard/login?error=expired';
                return null;
            }
            // Pick up the rotated CSRF token, if any, before
            // we hand control back to the caller. Done regardless
            // of res.ok so a 4xx state-changing response (e.g.
            // 422 validation error) still leaves the SPA holding
            // a current token instead of a stale one.
            this._storeCsrfNext(res.headers);
            const data = await res.json();
            if (!res.ok) {
                const err = new Error(this._formatApiError(data));
                // Attach the full JSON body so callers can read
                // structured-error fields (e.g. the 409
                // submarine_chain_exhausted body's ``attempted`` array
                // and ``single_operator_fallback_available`` flag).
                err.detail = data;
                err.status = res.status;
                throw err;
            }
            return data;
        },

        /** Coerce a FastAPI / generic JSON error body into a single
         *  human-readable string. FastAPI surfaces 422 validation
         *  failures as ``{detail: [{loc, msg, type, ...}, ...]}``;
         *  passing that array through ``new Error()`` would render
         *  it as ``[object Object]`` in the UI.
         *
         *  Some endpoints (notably the anonymize byte-pinned 422 / 429
         *  responses) use a ``{code: "...", ...}`` shape instead of
         *  ``detail``. Fall through to that so the caller's
         *  ``msg.includes(...)`` checks still match. */
        _formatApiError(data) {
            if (!data) return 'Request failed';
            const d = data.detail;
            if (typeof d === 'string') return d;
            if (typeof data.code === 'string') return data.code;
            if (Array.isArray(d) && d.length > 0) {
                return d.map((it) => {
                    if (it && typeof it === 'object') {
                        const field = Array.isArray(it.loc) ? it.loc.filter((x) => x !== 'body').join('.') : '';
                        const msg = it.msg || it.message || JSON.stringify(it);
                        return field ? field + ': ' + msg : msg;
                    }
                    return String(it);
                }).join('; ');
            }
            if (d && typeof d === 'object') {
                return d.msg || d.message || JSON.stringify(d);
            }
            return data.message || 'Request failed';
        },

        // ── Anonymize wizard methods ──

        // Safe-shape default for ``anonymizeCreated``. Same structure
        // as the initial state field so the @alpinejs/csp evaluator's
        // ``a && a.b`` non-short-circuit behaviour can't trip on a
        // null ``deposit`` after a reset.
        _anonymizeCreatedEmpty() {
            return {
                id: '',
                deposit: {
                    method: '',
                    bolt11_invoice: null,
                    bolt12_offer: null,
                    bip353_handle: null,
                    bip353_txt_record: null,
                    onchain_address: null,
                    amount_sat: 0,
                },
            };
        },

        anonymizeWizardReset() {
            this.anonymizeWizardStep = 1;
            this.anonymizeCreated = this._anonymizeCreatedEmpty();
            this.anonymizeDepositCopied = '';
            this.anonymizeWizardSourceKind = 'lightning-self';
            this.anonymizeWizardDestinationAddress = '';
            this.anonymizeWizardRequestedAmountSat = 250000;
            this.anonymizeWizardPreferLiquid = false;
            this.anonymizeWizardDepositMethod = 'bolt11';
            this.anonymizeQuote = null;
            this.anonymizeQuoteError = '';
            this.anonymizeCreateError = '';
            // Reset chain-walk state so a prior
            // session's chain-exhaustion modal / consent flag can't
            // carry forward implicitly.
            this.anonymizeAllowSingleOperatorFallback = false;
            this.anonymizeChainExhaustedDetail = {};
            this.anonymizeShowSingleOperatorFallbackModal = false;
            // Cancel any in-flight debounced quote-fetch so a stale
            // timer scheduled before the reset can't fire against
            // the fresh state.
            if (this._anonymizeQuoteDebounceTimer) {
                clearTimeout(this._anonymizeQuoteDebounceTimer);
                this._anonymizeQuoteDebounceTimer = null;
            }
        },

        anonymizeWizardOpenAndReset() {
            this.anonymizeWizardReset();
            this.anonymizeWizardOpen = true;
            // Always refetch on wizard open so the clock-skew status
            // is current — operator_diversity is cacheable but the
            // probe status changes minute-to-minute.
            this.anonymizeFetchPolicy();
        },

        async anonymizeFetchPolicy() {
            this.anonymizePolicyLoading = true;
            try {
                const policy = await this.api(
                    'GET', '/anonymize/policy',
                );
                this.anonymizePolicy = policy;
                this.anonymizePolicyLoaded = true;
                // If the operator hasn't enabled the Liquid hop,
                // clear any stale prefer_liquid the wizard may have
                // retained — the checkbox is now hidden and a true
                // value would silently ride along on every quote.
                if (!policy || !policy.liquid_available) {
                    this.anonymizeWizardPreferLiquid = false;
                }
                this.anonymizeApplyClockPolicy(policy);
                // Snap the default requested amount to the nearest
                // policy-configured bin if the hardcoded default
                // (250,000) isn't in the operator's bin list. Without
                // this, no chip would be highlighted on first paint
                // for non-standard bin deployments. We only snap when
                // the user hasn't touched the form yet — once they
                // pick a chip, their choice is sticky.
                this._anonymizeSnapAmountToPolicyBins(policy);
                // Kick off polling whenever the probe is mid-tick OR
                // we don't yet have a decisive status. Polling self-
                // terminates once both conditions clear.
                const stillRefreshing =
                    this.anonymizeClockWarmupCompletesAt != null;
                const decisive =
                    this.anonymizeClockStatus === 'healthy' ||
                    this.anonymizeClockStatus === 'unhealthy';
                if (stillRefreshing || !decisive) {
                    this.anonymizeStartClockPolling();
                }
            } catch (_e) {
                // Non-fatal: the wizard still works, the banner just
                // won't render (treated as "no advisory available").
                // Leave ``anonymizePolicy`` as its safe-shape default
                // so template expressions don't throw — only clear
                // the ``Loaded`` flag so the next tab activation can
                // retry.
                this.anonymizePolicyLoaded = false;
            } finally {
                this.anonymizePolicyLoading = false;
            }
        },

        anonymizeShowSingleOperatorBanner() {
            // Combined on-chain advisory shown when
            // the user selected an on-chain source AND the deployment
            // routes both swap legs through a single Boltz operator.
            // Covers both the funding-UTXO identity-linkability concern
            // and the single-operator correlation concern in one place.
            // Lightning sources don't trigger this banner because they
            // have no on-chain entry to leak.
            const onchain = ['onchain-self', 'ext-onchain'].includes(
                this.anonymizeWizardSourceKind,
            );
            if (!onchain) return false;
            const od = (this.anonymizePolicy || {}).operator_diversity;
            if (!od) return false;
            return od.distinct_operators_configured === false;
        },

        anonymizeShowDistinctOperatorOnchainBanner() {
            // Shorter advisory shown when the user selected
            // an on-chain source AND the deployment routes the two
            // swap legs through distinct Boltz operators. The
            // operator-correlation clause drops out; only the
            // funding-UTXO identity-linkability concern remains.
            const onchain = ['onchain-self', 'ext-onchain'].includes(
                this.anonymizeWizardSourceKind,
            );
            if (!onchain) return false;
            const od = (this.anonymizePolicy || {}).operator_diversity;
            if (!od) return false;
            return od.distinct_operators_configured === true;
        },

        anonymizeOperatorDiversityLearnMoreUrl() {
            const od = (this.anonymizePolicy || {}).operator_diversity || {};
            return od.learn_more_url || '';
        },

        anonymizeWizardClose() {
            this.anonymizeWizardOpen = false;
            this.anonymizeInfoTipOpen = '';
            this.anonymizeStopClockPolling();
            // Cancel any pending debounced quote-fetch so it doesn't
            // fire against a now-closed wizard.
            if (this._anonymizeQuoteDebounceTimer) {
                clearTimeout(this._anonymizeQuoteDebounceTimer);
                this._anonymizeQuoteDebounceTimer = null;
            }
        },

        async anonymizeGenerateDestinationAddress() {
            // Mint a fresh native-segwit (bc1q...) address from this
            // wallet's on-chain pool and drop it into the destination
            // input. LND returns the next unused derivation each call,
            // so the address is guaranteed fresh — both for the
            // destination-reuse hard-block and for general
            // privacy. The address is labeled "anonymize destination"
            // in the wallet's UTXO purpose store so it's traceable in
            // the on-chain UTXO list later.
            this.anonymizeGenerateAddressError = '';
            this.anonymizeGenerateAddressLoading = true;
            try {
                const data = await this.api('POST', '/address', {
                    address_type: 'p2wkh',
                    purpose: 'anonymize destination',
                });
                if (data && data.address) {
                    this.anonymizeWizardDestinationAddress = data.address;
                    // Programmatic set doesn't fire the input's @input
                    // handler, so kick the debounced quote re-fetch
                    // manually — otherwise the inline preview stays
                    // stale until the user touches another field.
                    this._debounceAnonymizeQuote();
                }
            } catch (e) {
                this.anonymizeGenerateAddressError =
                    (e && e.message) || 'Could not generate address';
            } finally {
                this.anonymizeGenerateAddressLoading = false;
            }
        },

        // ── Clock-skew status polling ──
        //
        // The wizard fetches /anonymize/policy on open (already wired
        // via ``anonymizeFetchPolicy``) and reads the ``clock_skew``
        // block. If the probe is mid-tick, this kicks off a 2.5 s
        // polling loop until the status becomes decisive (healthy or
        // unhealthy). The countdown timer ticks every 1 s for a smooth
        // user-facing "ready in Xs" display.

        anonymizeApplyClockPolicy(policy) {
            const cs = (policy || {}).clock_skew || {};
            this.anonymizeClockStatus = cs.status || 'unknown';
            this.anonymizeClockSkewMs = cs.measured_skew_ms;
            this.anonymizeClockThresholdMs = cs.threshold_ms;
            this.anonymizeClockSamplesCollected = cs.samples_collected || 0;
            this.anonymizeClockSamplesTarget = cs.samples_target || 0;
            this.anonymizeClockWarmupCompletesAt =
                cs.warmup_completes_at_unix_s || null;
            this.anonymizeTorBootstrapReady =
                (policy || {}).tor_bootstrap_ready !== false;
            // Countdown vs static switchover threshold.
            const t = Number((policy || {}).reconciliation_countdown_threshold_s);
            if (!Number.isNaN(t) && t > 0) {
                this.anonymizeReconciliationCountdownThresholdS = t;
            }
            // Confirming-status target.
            const minConfs = Number((policy || {}).claim_min_confirmations);
            if (!Number.isNaN(minConfs) && minConfs > 0) {
                this.anonymizeClaimMinConfirmations = minConfs;
            }
            this.anonymizeRecomputeClockCountdown();
        },

        anonymizeRecomputeClockCountdown() {
            const at = this.anonymizeClockWarmupCompletesAt;
            if (at == null) {
                this.anonymizeClockSecondsRemaining = 0;
                return;
            }
            const nowS = Date.now() / 1000;
            this.anonymizeClockSecondsRemaining =
                Math.max(0, Math.ceil(at - nowS));
        },

        anonymizeStartClockPolling() {
            if (this._isPolling('anonymizeClock')) return;
            // Guarded network poll — GET /anonymize/policy at 2.5 s;
            // ``anonymizeRefreshClockStatus`` stops it once the clock
            // status is decisive.
            this._poll('anonymizeClock',
                () => this.anonymizeRefreshClockStatus(),
                { intervalMs: 2500, immediate: false });
            // Separate 1-Hz countdown so the banner's "ready in Xs"
            // stays smooth between policy fetches (local, no network).
            if (this._anonymizeClockCountdownTimer) {
                clearInterval(this._anonymizeClockCountdownTimer);
            }
            this._anonymizeClockCountdownTimer = setInterval(() => {
                this.anonymizeRecomputeClockCountdown();
            }, 1000);
        },

        anonymizeStopClockPolling() {
            this._stopPoll('anonymizeClock');
            if (this._anonymizeClockCountdownTimer) {
                clearInterval(this._anonymizeClockCountdownTimer);
                this._anonymizeClockCountdownTimer = null;
            }
        },

        async anonymizeRefreshClockStatus() {
            try {
                const policy = await this.api('GET', '/anonymize/policy');
                this.anonymizePolicy = policy;
                this.anonymizePolicyLoaded = true;
                if (!policy || !policy.liquid_available) {
                    this.anonymizeWizardPreferLiquid = false;
                }
                this.anonymizeApplyClockPolicy(policy);
                // Stop polling once the probe is no longer mid-tick
                // (warmup_completes_at_unix_s cleared) AND status is
                // decisive. Subsequent background refreshes are
                // surfaced by the next ``anonymizeFetchPolicy`` on
                // wizard re-open.
                const stillRefreshing =
                    this.anonymizeClockWarmupCompletesAt != null;
                const decisive =
                    this.anonymizeClockStatus === 'healthy' ||
                    this.anonymizeClockStatus === 'unhealthy';
                if (!stillRefreshing && decisive) {
                    this.anonymizeStopClockPolling();
                }
            } catch (_e) {
                // Leave fields stale; the next tick retries. Don't
                // alarm the user with a transient policy-fetch error.
            }
        },

        // Info-icon tooltip controls. ``id`` is the term identifier
        // (e.g. 'bin-amount'). Toggle re-clicks close the open tip;
        // clicking a different term's icon switches the open tip.
        anonymizeToggleInfoTip(id) {
            this.anonymizeInfoTipOpen =
                this.anonymizeInfoTipOpen === id ? '' : id;
        },

        anonymizeCloseInfoTip() {
            this.anonymizeInfoTipOpen = '';
        },

        // Wizard step navigation. The form-step rework collapsed
        // the old 3-step input flow into a single Step 1, so Next /
        // Back are no longer used by the template — kept here as
        // safe no-ops so any older callers don't throw.
        anonymizeWizardNext() { /* no-op (single-step form) */ },
        anonymizeWizardBack() { /* no-op (single-step form) */ },

        // ── Step-2 input validation ──
        //
        // The server intentionally returns an opaque
        // ``destination_rejected`` (byte-pinned 422) so an
        // attacker can't enumerate which validator tripped. That's
        // good for an attacker — and bad for an end user staring at a
        // generic error. These two helpers re-implement the most
        // common rejection paths *client-side* so the user sees an
        // inline, human-readable explanation BEFORE clicking Preview,
        // and a more useful fallback message when the server still
        // 422s for something we couldn't catch locally (typically a
        // bech32 checksum miss).
        //
        // They are intentionally permissive — bech32 checksum
        // validation requires a real library and would inflate the
        // bundle, so we leave that to the server and just give a
        // generic explanation when nothing local matches.
        _anonymizeFormatSats(n) {
            const v = Number(n) || 0;
            return v.toLocaleString();
        },

        anonymizeValidateAmount() {
            const policy = this.anonymizePolicy || {};
            const minSat = Number(policy.min_sat) || 0;
            const maxSat = Number(policy.max_sat) || 0;
            const v = Number(this.anonymizeWizardRequestedAmountSat);
            if (!v || Number.isNaN(v) || v <= 0) {
                return 'Enter an amount in sats.';
            }
            if (minSat > 0 && v < minSat) {
                return 'Amount is too small. Minimum is '
                    + this._anonymizeFormatSats(minSat) + ' sats.';
            }
            if (maxSat > 0 && v > maxSat) {
                return 'Amount is too large. Maximum is '
                    + this._anonymizeFormatSats(maxSat) + ' sats.';
            }
            return '';
        },

        anonymizeValidateDestination() {
            const raw = String(this.anonymizeWizardDestinationAddress || '');
            const v = raw.trim();
            if (!v) return '';  // empty is gated by the disabled state
            // Whitespace inside the field (a paste artefact) is the
            // single most common typo we can warn on cleanly.
            if (v.length !== raw.length || /\s/.test(v)) {
                return 'Address contains spaces — re-paste it cleanly.';
            }
            // BIP-353 handle (user@domain): the server resolves it
            // via DNS-over-HTTPS-over-Tor before validating, so we
            // can't shape-check it here. Empty validation is the
            // right call.
            if (v.indexOf('@') !== -1 && v.indexOf(':') === -1) return '';
            // BOLT 12 offer (lno1...) is also resolved server-side.
            if (/^lno1[0-9a-z]+$/i.test(v)) return '';
            // URI wrappers and Lightning-style schemes — the server
            // rejects every variant under the same opaque code, so
            // we surface them with specific copy.
            const lc = v.toLowerCase();
            const wrappers = ['bitcoin:', 'lightning:', 'lnurl', 'liquidnetwork:'];
            for (let i = 0; i < wrappers.length; i++) {
                if (lc.indexOf(wrappers[i]) !== -1) {
                    return 'Use a raw address (no "bitcoin:" URI, '
                        + 'LNURL, or Lightning wrapper).';
                }
            }
            // Network-prefix sanity check. ``anonymizePolicy`` exposes
            // ``bitcoin_network`` so the SPA can tell mainnet from
            // testnet/regtest without baking the network into the
            // build.
            const network = String(
                (this.anonymizePolicy || {}).bitcoin_network || '',
            );
            // Legacy P2PKH is rejected by anonymize on every network
            // (privacy reason — script-type cap).
            if (network === 'bitcoin' && /^1[a-km-zA-HJ-NP-Z1-9]/.test(v)) {
                return 'Legacy addresses (starting with 1…) aren’t '
                    + 'supported. Use a Taproot (bc1p…) or native '
                    + 'SegWit (bc1q…) address.';
            }
            if ((network === 'testnet' || network === 'signet' || network === 'regtest')
                && /^[mn][a-km-zA-HJ-NP-Z1-9]/.test(v)
            ) {
                return 'Legacy addresses (starting with m… or n…) '
                    + 'aren’t supported. Use a Taproot or native '
                    + 'SegWit address.';
            }
            // Mainnet wallet but the address looks like testnet/regtest.
            if (network === 'bitcoin'
                && (lc.indexOf('tb1') === 0 || lc.indexOf('bcrt1') === 0)
            ) {
                return 'This wallet is on mainnet. The address looks '
                    + 'like a testnet/regtest address — use a bc1… '
                    + 'address instead.';
            }
            // Testnet/signet wallet but the address looks like mainnet.
            if ((network === 'testnet' || network === 'signet')
                && lc.indexOf('bc1') === 0
                && lc.indexOf('bcrt1') !== 0
            ) {
                return 'This wallet is on testnet. The address looks '
                    + 'like a mainnet address — use a tb1… address '
                    + 'instead.';
            }
            // Regtest wallet but the address is mainnet- or testnet-shaped.
            if (network === 'regtest'
                && (
                    (lc.indexOf('bc1') === 0 && lc.indexOf('bcrt1') !== 0)
                    || lc.indexOf('tb1') === 0
                )
            ) {
                return 'This wallet is on regtest. Use a bcrt1… '
                    + 'address.';
            }
            return '';
        },

        // Translate the byte-pinned ``destination_rejected`` body into
        // a user-readable explanation. The server intentionally
        // doesn't say which validator tripped, so we list
        // the common causes and remind the user of the constraint
        // they can re-check locally.
        _anonymizeQuoteFallbackMessage() {
            return 'We couldn’t preview this session. Common causes: '
                + 'the address has a typo (the wallet checks the '
                + 'address’s checksum), it’s on the wrong network, '
                + 'or it’s a legacy address (starting with 1…, m…, '
                + 'n…, or 3…). Double-check the destination and try '
                + 'again.';
        },

        async anonymizeFetchQuote() {
            this.anonymizeQuoteError = '';
            this.anonymizeQuote = null;
            // Empty destination — silently bail. The form-first
            // rework auto-triggers this fetch on source-kind / amount
            // changes, but the user may not have filled in a
            // destination yet. Showing the server's opaque 422 as a
            // "preview failed" error here would be misleading.
            const destRaw = String(
                this.anonymizeWizardDestinationAddress || '',
            ).trim();
            if (!destRaw) {
                return;
            }
            // Run client-side validators first so the user gets a
            // friendly message instead of an opaque server 422.
            const amountErr = this.anonymizeValidateAmount();
            if (amountErr) {
                this.anonymizeQuoteError = amountErr;
                return;
            }
            const destErr = this.anonymizeValidateDestination();
            if (destErr) {
                this.anonymizeQuoteError = destErr;
                return;
            }
            this.anonymizeQuoteLoading = true;
            const payload = {
                source_kind: this.anonymizeWizardSourceKind,
                destination_address: this.anonymizeWizardDestinationAddress,
                requested_amount_sat: Number(
                    this.anonymizeWizardRequestedAmountSat,
                ),
                prefer_liquid: Boolean(this.anonymizeWizardPreferLiquid),
            };
            // The deposit-method binding is only meaningful
            // for ``ext-lightning``. Sending it on other source kinds
            // would still be ignored server-side, but omitting it
            // keeps the canonical request body minimal.
            if (this.anonymizeWizardSourceKind === 'ext-lightning') {
                payload.deposit_method = this.anonymizeWizardDepositMethod;
            }
            // Explicit single-operator-fallback consent. Set by the SPA only
            // after the user clicked Use single operator in the
            // modal; reset to false on every fresh quote-fetch so a
            // prior consent doesn't carry forward implicitly.
            if (this.anonymizeAllowSingleOperatorFallback) {
                payload.allow_single_operator_fallback = true;
            }
            try {
                const data = await this.api(
                    'POST', '/anonymize/quote', payload,
                );
                this.anonymizeQuote = data;
                // Successful quote — reset chain-exhausted modal state
                // and the one-shot consent flag.
                this.anonymizeChainExhaustedDetail = {};
                this.anonymizeShowSingleOperatorFallbackModal = false;
                this.anonymizeAllowSingleOperatorFallback = false;
                // Quote renders INLINE on Step 1 in the merged form
                // — no step transition.
            } catch (e) {
                const msg = (e && e.message) || '';
                // 409 chain-exhausted: surface the modal so
                // the user can opt into single-operator fallback or
                // try again later.
                if (msg.indexOf('submarine_chain_exhausted') !== -1) {
                    this.anonymizeChainExhaustedDetail = (
                        e && e.detail
                    ) || {};
                    this.anonymizeShowSingleOperatorFallbackModal = true;
                    return;
                }
                // 503 reverse-leg failed: no fallback in v1.
                if (msg.indexOf('reverse_probe_failed') !== -1) {
                    this.anonymizeQuoteError =
                        'The reverse-leg operator is currently '
                        + 'unreachable. This is usually a Tor-side '
                        + 'transient — try again in a few minutes.';
                    return;
                }
                // 503 all operators unreachable (consent path).
                if (msg.indexOf('all_submarine_operators_unreachable') !== -1) {
                    this.anonymizeQuoteError =
                        'All configured operators are currently '
                        + 'unreachable. Try again later.';
                    return;
                }
                // Map the byte-pinned ``destination_rejected`` code to
                // a friendlier fallback when our local validators
                // didn't catch it.
                if (msg.indexOf('destination_rejected') !== -1) {
                    this.anonymizeQuoteError =
                        this._anonymizeQuoteFallbackMessage();
                } else {
                    this.anonymizeQuoteError = msg || 'Preview failed';
                }
            } finally {
                this.anonymizeQuoteLoading = false;
            }
        },

        /** Re-submit the quote with explicit consent
         *  to fall back to single-operator (Boltz on both legs,
         *  capped at moderate tier). Called from the modal's
         *  **Use single operator** button. */
        anonymizeRetryQuoteWithFallback() {
            this.anonymizeAllowSingleOperatorFallback = true;
            this.anonymizeShowSingleOperatorFallbackModal = false;
            this._debounceAnonymizeQuote();
        },

        /** Debounce wrapper: schedule an ``anonymizeFetchQuote`` ~250ms
         *  after the last form-field change so we don't fire a quote
         *  request on every keystroke / radio change. Mirrors Braiins-
         *  Deposit's ``_debounceBraiinsDepositQuote`` pattern. */
        _debounceAnonymizeQuote() {
            if (this._anonymizeQuoteDebounceTimer) {
                clearTimeout(this._anonymizeQuoteDebounceTimer);
            }
            this._anonymizeQuoteDebounceTimer = setTimeout(() => {
                this._anonymizeQuoteDebounceTimer = null;
                this.anonymizeFetchQuote();
            }, 250);
        },

        /** Source-kind picker — invoked from the button-card radios.
         *  Persists the choice and re-fetches the quote so the
         *  inline preview reflects the new selection (different
         *  source kinds get different advisory tiers + residual
         *  notes). */
        anonymizeSelectSource(kind) {
            const valid = ['lightning-self', 'onchain-self', 'ext-lightning', 'ext-onchain'];
            if (valid.indexOf(kind) < 0) return;
            if (this.anonymizeWizardSourceKind === kind) return;
            this.anonymizeWizardSourceKind = kind;
            this.anonymizeQuote = null;
            // Switching to a self source can make the currently
            // requested bin unaffordable. Snap to the largest
            // still-allowed-AND-affordable bin so the wizard doesn't
            // leave the user staring at a disabled selection.
            if (this.anonymizeBinDisabled(this.anonymizeWizardRequestedAmountSat)) {
                const bins = this.anonymizeBinPresets || [];
                let best = null;
                for (const amt of bins) {
                    if (this.anonymizeBinDisabled(amt)) continue;
                    if (best === null || amt > best) best = amt;
                }
                if (best !== null) {
                    this.anonymizeWizardRequestedAmountSat = best;
                }
            }
            this._debounceAnonymizeQuote();
        },

        /** Bin-chip selector. Sets the requested amount and triggers
         *  a debounced re-quote. */
        anonymizeSelectAmount(amt) {
            if (this.anonymizeBinDisabled(amt)) return;
            if (this.anonymizeWizardRequestedAmountSat === amt) return;
            this.anonymizeWizardRequestedAmountSat = amt;
            this.anonymizeQuote = null;
            this._debounceAnonymizeQuote();
        },

        /** Returns true when the given bin amount is within the
         *  operator-configured ``min_sat``/``max_sat`` policy. Out-
         *  of-range chips render disabled. */
        anonymizeBinAllowed(amt) {
            const p = this.anonymizePolicy || {};
            if (typeof p.min_sat === 'number' && amt < p.min_sat) return false;
            if (typeof p.max_sat === 'number' && amt > p.max_sat) return false;
            return true;
        },

        /** Returns true when the wallet has enough balance on the
         *  selected source to cover this bin amount plus rough fee
         *  headroom. External sources are always considered
         *  affordable (we don't know the user's external balance).
         *  Final gating happens server-side on session create. */
        anonymizeBinAffordable(amt) {
            const kind = this.anonymizeWizardSourceKind;
            if (kind === 'ext-lightning' || kind === 'ext-onchain') {
                return true;
            }
            if (kind === 'onchain-self') {
                // On-chain self: leading submarine swap eats ~0.5%
                // + ~1000 sats lockup miner fee + on-chain funding
                // fee, then the LN→on-chain leg eats ~3.5% boltz pct
                // + routing headroom.
                const required = Math.ceil(amt * 1.045) + 5000;
                return (this.confirmedBalance || 0) >= required;
            }
            // lightning-self: just the LN→on-chain leg headroom.
            const required = Math.ceil(amt * 1.035) + 4000;
            return (this.localBalance || 0) >= required;
        },

        /** Combined gating predicate used by the chip ``:disabled``
         *  binding. Disabled when either policy-out-of-range or
         *  insufficient-balance fires. */
        anonymizeBinDisabled(amt) {
            return !this.anonymizeBinAllowed(amt)
                || !this.anonymizeBinAffordable(amt);
        },

        /** Plain-language reason a chip is disabled, surfaced via
         *  the button ``:title`` so the user gets an explanation on
         *  hover / long-press. Empty string when the chip is
         *  enabled. */
        anonymizeBinDisabledReason(amt) {
            const p = this.anonymizePolicy || {};
            if (typeof p.min_sat === 'number' && amt < p.min_sat) {
                return 'Below the swap minimum of '
                    + this.formatSats(p.min_sat) + ' sats.';
            }
            if (typeof p.max_sat === 'number' && amt > p.max_sat) {
                return 'Above the swap maximum of '
                    + this.formatSats(p.max_sat) + ' sats.';
            }
            if (!this.anonymizeBinAffordable(amt)) {
                const kind = this.anonymizeWizardSourceKind;
                if (kind === 'onchain-self') {
                    return 'Insufficient on-chain balance for this bin '
                        + '(need ~' + this.formatSats(Math.ceil(amt * 1.045) + 5000)
                        + ' sats including fees; you have '
                        + this.formatSats(this.confirmedBalance || 0) + ').';
                }
                if (kind === 'lightning-self') {
                    return 'Insufficient Lightning outbound balance for '
                        + 'this bin (need ~'
                        + this.formatSats(Math.ceil(amt * 1.035) + 4000)
                        + ' sats including fees; you have '
                        + this.formatSats(this.localBalance || 0) + ').';
                }
            }
            return '';
        },

        /** Pick the policy-configured bin closest to the currently
         *  requested amount when the current value isn't already in
         *  the bin list. Called from ``anonymizeFetchPolicy`` so the
         *  default (250,000) snaps to a real bin on non-standard
         *  deployments. No-op when the policy bin list is empty
         *  (the getter falls back to the hardcoded ladder, which
         *  always includes 250,000). */
        _anonymizeSnapAmountToPolicyBins(policy) {
            const bins = (policy || {}).amount_bins_sat;
            if (!Array.isArray(bins) || bins.length === 0) return;
            const target = Number(this.anonymizeWizardRequestedAmountSat) || 0;
            if (bins.indexOf(target) >= 0) return;
            let best = bins[0];
            let bestDiff = Math.abs(best - target);
            for (let i = 1; i < bins.length; i++) {
                const d = Math.abs(bins[i] - target);
                if (d < bestDiff) {
                    best = bins[i];
                    bestDiff = d;
                }
            }
            this.anonymizeWizardRequestedAmountSat = best;
            // If a quote was already fetched / is in flight against
            // the pre-snap amount, drop it and re-fetch so the
            // inline review matches the chip we just highlighted.
            if (this.anonymizeQuote || this.anonymizeQuoteLoading) {
                this.anonymizeQuote = null;
                this._debounceAnonymizeQuote();
            }
        },

        /** Runtime bin-amount chip set. Prefers the operator's
         *  configured ``amount_bins_sat`` (via the policy fetch) so
         *  the chips reflect what the server actually accepts; falls
         *  back to a canonical ladder when the policy hasn't loaded
         *  yet OR is misconfigured (empty bins list).
         *
         *  The server quantizes the requested amount on POST in any
         *  case — this getter just keeps the chips honest. */
        get anonymizeBinPresets() {
            const fromPolicy = (this.anonymizePolicy || {}).amount_bins_sat;
            if (Array.isArray(fromPolicy) && fromPolicy.length > 0) {
                return fromPolicy;
            }
            return this._anonymizeBinPresetsFallback;
        },

        /** Per-source plain-language caption rendered under the
         *  source-picker grid. Mirrors Braiins-Deposit's
         *  ``braiinsDepositSourceCaption`` getter. */
        get anonymizeSourceCaption() {
            switch (this.anonymizeWizardSourceKind) {
                case 'lightning-self':
                    return 'Fastest path. Uses this wallet\'s Lightning channel balance directly.';
                case 'onchain-self':
                    return 'Uses this wallet\'s on-chain UTXOs. Adds an extra ~10-minute submarine swap up front; caps the privacy tier at moderate.';
                case 'ext-lightning':
                    return 'Pay a one-time Lightning invoice from any other wallet — your phone, desktop, or a custodial service that supports Lightning withdrawals.';
                case 'ext-onchain':
                    return 'Send sats on-chain to a fresh address from any other wallet. Slowest path; caps the privacy tier at moderate.';
                default: return '';
            }
        },

        /** True when the wizard's source kind is on-chain
         *  (the operator-attribution block's submarine cell renders
         *  only in this case). */
        get anonymizeWizardIsOnchainSource() {
            return this.anonymizeWizardSourceKind === 'onchain-self'
                || this.anonymizeWizardSourceKind === 'ext-onchain';
        },

        /** The quote object, or an empty object when no quote is loaded.
         *  The quote-review fields read through this so a template
         *  binding never reaches a property of ``null`` — the CSP build
         *  evaluates dotted access even behind ``&&``, and the quote can
         *  flip to ``null`` (re-quote) while the review block is still
         *  tearing down. */
        get anonymizeQuoteOrEmpty() {
            return this.anonymizeQuote || {};
        },

        /** True when the quote landed on the secondary
         *  submarine operator because the primary was unreachable.
         *  Drives the yellow "primary unreachable — using secondary"
         *  pill next to the submarine-leg label. */
        get anonymizeSubmarineSecondaryFallbackActive() {
            const q = this.anonymizeQuote || {};
            const chain = q.submarine_chain || {};
            return chain.selection_source === 'secondary_after_primary_failed';
        },

        async anonymizeConfirm() {
            if (!this.anonymizeQuote || !this.anonymizeQuote.quote_token) {
                this.anonymizeCreateError = 'No quote loaded';
                return;
            }
            this.anonymizeCreateError = '';
            this.anonymizeCreateLoading = true;
            try {
                const data = await this.api('POST', '/anonymize/sessions', {
                    quote_token: this.anonymizeQuote.quote_token,
                });
                // Capture the session-detail shape (which
                // carries the ``deposit`` block) and transition to
                // step 4 so the depositor can copy / scan the BOLT 11
                // invoice or BOLT 12 offer. Sessions that don't have
                // a meaningful deposit primitive (lightning-self,
                // onchain-self with no immediate prompt) skip step 4
                // and close the wizard directly.
                //
                // The server returns ``deposit: null`` for self-pay
                // sources. The Alpine CSP evaluator does not short-
                // circuit ``a && a.b`` reliably, so we coerce ``null``
                // into the safe-shape empty deposit to keep every
                // template expression null-safe.
                if (!data.deposit) {
                    data.deposit = this._anonymizeCreatedEmpty().deposit;
                }
                this.anonymizeCreated = data;
                await this.anonymizeFetchSessions();
                // A new session is in flight — make sure the auto-poll
                // is running so its status updates appear without the
                // user having to click Refresh.
                this.anonymizeStartSessionsPolling();
                if (this._anonymizeHasDepositPrimitive(data)) {
                    // Ext sources transition to the deposit-primitive
                    // step (renumbered from 4 → 2 by the merged-form
                    // rework). Self sources have no primitive to show
                    // and close the wizard directly.
                    this.anonymizeWizardStep = 2;
                    // Render the QR on next tick once the
                    // canvas ref is bound, and hydrate Lucide icons
                    // (the amount copy button) on the now-rendered view.
                    this.$nextTick(() => {
                        this._anonymizeRenderDepositQr();
                        this.initIcons();
                    });
                } else {
                    this.anonymizeWizardClose();
                }
            } catch (e) {
                // Friendly copy for the transient states the
                // create endpoint returns as 503. The raw detail codes
                // (``anonymize_clock_warming_up`` /
                // ``anonymize_clock_skew_unhealthy``) are jargon for
                // most users; the banners above already explain the
                // root cause, so here we just nudge them to wait or
                // sync their clock.
                const msg = (e && e.message) || 'Create failed';
                if (msg.includes('anonymize_clock_warming_up')) {
                    this.anonymizeCreateError =
                        'Time-sync check still in progress. Try again in a few seconds.';
                    // Restart polling so the user sees the banner and
                    // the button re-enables automatically when ready.
                    this.anonymizeFetchPolicy();
                } else if (msg.includes('anonymize_clock_skew_unhealthy')) {
                    this.anonymizeCreateError =
                        "Your local clock is out of sync. Enable NTP on your system and try again.";
                } else if (msg.includes('creation_unavailable')) {
                    // This 429 is byte-pinned across several refusal
                    // causes (so they can't be told apart on the wire),
                    // so the message lists them; the server log names the
                    // exact one. Causes: (a) concurrency cap
                    // (ANONYMIZE_TIER_CONCURRENCY_CAP), (b) per-hour
                    // creation rate (ANONYMIZE_CREATE_WINDOW_MAX_PER_HOUR),
                    // or (c) — for on-chain sources — not enough INBOUND
                    // Lightning liquidity to receive the swap amount.
                    this.anonymizeCreateError =
                        "Session creation was refused. Likely one of: too many sessions " +
                        "recently or in-flight (rate/concurrency caps), or — for an on-chain " +
                        "source — your node lacks the inbound Lightning liquidity to receive " +
                        "the amount (on-chain anonymize swaps you funds out on-chain and back " +
                        "in over Lightning, so you need inbound ≥ the amount). The server log " +
                        "names the exact cause. For rate caps when testing, raise " +
                        "ANONYMIZE_TIER_CONCURRENCY_CAP / ANONYMIZE_CREATE_WINDOW_MAX_PER_HOUR in .env.";
                } else {
                    this.anonymizeCreateError = msg;
                }
            } finally {
                this.anonymizeCreateLoading = false;
            }
        },

        // ── Step 4 helpers (deposit primitive rendering) ──

        _anonymizeHasDepositPrimitive(data) {
            if (!data || !data.deposit) return false;
            const d = data.deposit;
            return Boolean(
                d.bolt11_invoice || d.bolt12_offer || d.onchain_address,
            );
        },

        anonymizeDepositPrimary() {
            // Pick the primary QR/copy target. BOLT 12 takes
            // precedence over BOLT 11 (the session can carry only
            // one of the two; both is rejected by the validator),
            // and on-chain falls through last for ext-onchain
            // sessions whose deposit address lives in the same block.
            const d = (this.anonymizeCreated || {}).deposit || {};
            if (d.bolt12_offer) {
                return { kind: 'bolt12', value: d.bolt12_offer };
            }
            if (d.bolt11_invoice) {
                return { kind: 'bolt11', value: d.bolt11_invoice };
            }
            if (d.onchain_address) {
                return { kind: 'onchain', value: d.onchain_address };
            }
            return { kind: '', value: '' };
        },

        _anonymizeRenderDepositQr() {
            const primary = this.anonymizeDepositPrimary();
            if (!primary.value) return;
            const canvas = this.$refs.anonDepositQr;
            if (!canvas) return;
            // BOLT 12 / BOLT 11 / on-chain addresses are all
            // alphanumeric uppercase-friendly — uppercase the
            // string so the encoder uses the smaller alphanumeric
            // QR alphabet (QR v40-L max ≈4296 chars vs. ≈2953 for
            // mixed-case bytes). bech32 strings round-trip case-
            // insensitively so this is safe.
            const value = primary.kind === 'onchain'
                ? primary.value
                : primary.value.toUpperCase();
            this.renderQr(canvas, value);
        },

        async anonymizeCopyDeposit(kind) {
            const d = (this.anonymizeCreated || {}).deposit || {};
            let value = '';
            if (kind === 'bolt12') value = d.bolt12_offer || '';
            else if (kind === 'bolt11') value = d.bolt11_invoice || '';
            else if (kind === 'bip353') value = d.bip353_handle || '';
            else if (kind === 'txt') value = d.bip353_txt_record || '';
            else if (kind === 'onchain') value = d.onchain_address || '';
            // RAW integer sats (no separators) so it pastes cleanly into
            // another wallet's amount field.
            else if (kind === 'onchain_amount') value = d.amount_sat ? String(d.amount_sat) : '';
            if (!value) return;
            try {
                this._copyToClipboard(value);
                this.anonymizeDepositCopied = kind;
                window.setTimeout(() => {
                    if (this.anonymizeDepositCopied === kind) {
                        this.anonymizeDepositCopied = '';
                    }
                }, 1500);
            } catch (_e) {
                // Clipboard API can fail under non-HTTPS / non-focus;
                // the visible primitive is still selectable so the
                // user can copy manually.
            }
        },

        anonymizeDepositDone() {
            this.anonymizeWizardClose();
        },

        // Single-call entry point for the Anonymize tab's ``x-init``.
        // The Alpine CSP build can't parse multi-statement
        // expressions (``a(); b()``), so we wrap the two cold-start
        // fetches in a method that takes no arguments.
        anonymizeInitTab() {
            this.anonymizeFetchSessions();
            this.anonymizeFetchLiquidResiduals();
        },

        async anonymizeFetchSessions(opts) {
            // Anonymize off: skip the poll entirely (no endpoint to hit; the tab
            // is hidden too). Avoids the harmless-but-noisy 404 on /sessions.
            if (!this.anonymizeEnabled) return;
            // ``silent`` skips the Loading… indicator + the transient
            // error wipe so background polls don't flash a layout
            // shift every 8s. Foreground fetches (initial load, manual
            // Refresh, post-action refetch) still surface progress.
            const silent = !!(opts && opts.silent);
            if (!silent) {
                this.anonymizeSessionsError = '';
                this.anonymizeSessionsLoading = true;
            }
            try {
                const data = await this.api('GET', '/anonymize/sessions');
                const next = (data && data.sessions) || [];
                // Diff statuses BEFORE swapping the array so
                // the toast helper sees the transition.
                this._anonymizeNoticeStatusChanges(next);
                this.anonymizeSessions = next;
                // Mark hydrated so subsequent tab re-activations can
                // refetch silently (no "Loading…" flash over already-
                // populated rows).
                this.anonymizeSessionsHydrated = true;
                if (silent) {
                    // A successful silent poll clears any stale error
                    // banner without ever toggling the Loading… flag.
                    this.anonymizeSessionsError = '';
                }
            } catch (e) {
                this.anonymizeSessionsError = (e && e.message) || 'Load failed';
            } finally {
                if (!silent) {
                    this.anonymizeSessionsLoading = false;
                }
            }
            // Auto-stop polling once every session has reached a
            // terminal status — no point hammering the API when there's
            // nothing left to advance. The next manual Refresh or tab
            // re-activation will pick up newly-created sessions.
            if (!this._anonymizeHasNonTerminalSession()) {
                this.anonymizeStopSessionsPolling();
            }
            // Refresh the residual L-BTC banner in lockstep so a
            // session that completes mid-poll can surface its
            // dust output without waiting for a separate fetch.
            this.anonymizeFetchLiquidResiduals({silent: true});
        },

        // ── Residual L-BTC recovery banner ──────────────────────
        // Fetches the list of pending residual outputs (dust + above-
        // threshold) the operator can act on. Tolerates 404 (anonymize
        // or Liquid hop disabled) by quietly clearing local state so
        // the banner stays hidden. ``silent`` mirrors the sessions
        // fetcher — suppresses the Loading flag for background polls.
        async anonymizeFetchLiquidResiduals(opts) {
            if (!this.anonymizeEnabled) return;
            const silent = !!(opts && opts.silent);
            if (!silent) {
                this.anonymizeLiquidResidualsError = '';
                this.anonymizeLiquidResidualsLoading = true;
            }
            try {
                const data = await this.api('GET', '/anonymize/liquid-residuals');
                this.anonymizeLiquidResiduals = {
                    rows: (data && data.rows) || [],
                    total_value_sat: (data && data.total_value_sat) || 0,
                    recoverable_count: (data && data.recoverable_count) || 0,
                    recoverable_value_sat: (data && data.recoverable_value_sat) || 0,
                    dust_threshold_sat: (data && data.dust_threshold_sat) || 0,
                };
                if (silent) this.anonymizeLiquidResidualsError = '';
            } catch (e) {
                // 404 = anonymize or Liquid hop disabled. Treat as
                // "nothing to show" rather than surfacing an error.
                const status = e && e.status;
                if (status === 404) {
                    this.anonymizeLiquidResiduals = {
                        rows: [], total_value_sat: 0,
                        recoverable_count: 0, recoverable_value_sat: 0,
                        dust_threshold_sat: 0,
                    };
                    this.anonymizeLiquidResidualsError = '';
                } else {
                    this.anonymizeLiquidResidualsError =
                        (e && e.message) || 'Load failed';
                }
            } finally {
                if (!silent) this.anonymizeLiquidResidualsLoading = false;
            }
        },

        anonymizeResidualRowBusy(residualId) {
            return !!(
                this._anonymizeLiquidResidualsBusyIds
                && this._anonymizeLiquidResidualsBusyIds[residualId]
            );
        },

        async _anonymizeResidualPost(residualId, suffix, confirmMsg) {
            if (this.anonymizeResidualRowBusy(residualId)) return;
            if (confirmMsg) {
                const ok = await this.askConfirm({body: confirmMsg});
                if (!ok) return;
            }
            // Vue-style reactive assignment so Alpine picks up the
            // change. We use a fresh object rather than mutating in
            // place to keep the reactive dependency tracking working
            // for the Alpine x-bind:disabled expressions.
            this._anonymizeLiquidResidualsBusyIds = Object.assign(
                {}, this._anonymizeLiquidResidualsBusyIds || {},
                {[residualId]: true},
            );
            this.anonymizeLiquidResidualsError = '';
            try {
                await this.api(
                    'POST',
                    '/anonymize/liquid-residuals/' + encodeURIComponent(residualId)
                        + '/' + suffix,
                );
                await this.anonymizeFetchLiquidResiduals({silent: true});
            } catch (e) {
                this.anonymizeLiquidResidualsError =
                    (e && e.message) || 'Action failed';
            } finally {
                const next = Object.assign(
                    {}, this._anonymizeLiquidResidualsBusyIds || {},
                );
                delete next[residualId];
                this._anonymizeLiquidResidualsBusyIds = next;
            }
        },

        anonymizeResidualSwapOut(residualId) {
            return this._anonymizeResidualPost(
                residualId,
                'swap-out',
                'Initiate a submarine swap to recover this L-BTC residual to Lightning?',
            );
        },

        anonymizeResidualAcknowledgeDust(residualId) {
            return this._anonymizeResidualPost(
                residualId,
                'acknowledge-dust',
                'Mark this residual as economically-unrecoverable dust and hide it from the banner?',
            );
        },

        anonymizeResidualUnacknowledgeDust(residualId) {
            return this._anonymizeResidualPost(residualId, 'unacknowledge-dust');
        },

        // Terminal statuses mirror ``ANONYMIZE_TERMINAL_STATUSES`` in
        // app/models/anonymize_session.py. Keep in sync if statuses
        // are added/removed.
        _anonymizeHasNonTerminalSession() {
            const terminal = {
                completed: true,
                completed_with_reorg_uncertainty: true,
                cancelled: true,
                failed: true,
            };
            const sessions = this.anonymizeSessions || [];
            for (let i = 0; i < sessions.length; i++) {
                if (!terminal[sessions[i].status]) return true;
            }
            return false;
        },

        anonymizeStartSessionsPolling() {
            if (!this._isPolling('anonymizeSessions')) {
                // 8 s cadence — sessions advance over minutes (hops,
                // confirmations) so sub-10s polling is plenty without
                // overloading the dashboard endpoint. Guarded:
                // the in-flight guard + default read timeout keep a slow
                // /anonymize/sessions tick from piling up.
                this._poll('anonymizeSessions', async () => {
                    if (this.activeTab !== 'anonymize') {
                        this.anonymizeStopSessionsPolling();
                        return;
                    }
                    if (!this._anonymizeHasNonTerminalSession()) {
                        // Idle: no work to poll for. ``anonymizeFetchSessions``
                        // will be triggered again on next tab activation.
                        this.anonymizeStopSessionsPolling();
                        return;
                    }
                    await this.anonymizeFetchSessions({silent: true});
                    // Live-refresh an OPEN detail panel's progress
                    // timeline while its session is still active. A
                    // terminal session's detail is left static (no
                    // re-fetch) — its history won't change.
                    const openSid = this.anonymizeSessionDetailOpen;
                    if (openSid) {
                        const open = (this.anonymizeSessions || []).find(
                            x => x && String(x.id) === String(openSid),
                        );
                        if (open && !this._anonymizeIsTerminalStatus(open.status)) {
                            await this._anonymizeFetchSessionRecovery(openSid);
                        }
                    }
                }, { intervalMs: 8000, immediate: false });
            }
            // Separate 1-Hz countdown so the "Next try in Xs"
            // caption decrements smoothly between the 8-second
            // sessions-list polls. Independent timer so we can keep
            // ticking the countdown even when polling backs off.
            if (!this._anonymizeRowTickTimer) {
                this._anonymizeRowTickTimer = setInterval(() => {
                    this.anonymizeRowTickSnapshot = Math.floor(Date.now() / 1000);
                }, 1000);
            }
        },

        anonymizeStopSessionsPolling() {
            this._stopPoll('anonymizeSessions');
            if (this._anonymizeRowTickTimer) {
                clearInterval(this._anonymizeRowTickTimer);
                this._anonymizeRowTickTimer = null;
            }
        },

        // ── — row rendering helpers ──
        //
        // Plain-English labels for the sessions list. Kept as plain
        // method lookups so the @alpinejs/csp build can call them
        // from x-text expressions (no inline JS literals or arrows
        // in the template).
        //
        // Mirrors the status-to-label mapping used by the
        // reconciliation/recovery flow and the
        // ANONYMIZE_TERMINAL_STATUSES enum in
        // app/models/anonymize_session.py. Keep in sync.

        anonymizeStatusLabel(s) {
            const status = (s && s.status) || '';
            if (status === 'awaiting_reconciliation') {
                return this._anonymizeReasonLabel(
                    (s && s.awaiting_reconciliation_reason) || '',
                ).label;
            }
            const labels = {
                created: 'Starting…',
                sourcing: 'Waiting for funding',
                funding: 'Received funding',
                ln_holding: 'Holding Lightning payment',
                delaying: 'Privacy delay',
                hopping: 'Mixing',
                awaiting_liquid_dwell: 'Privacy delay (Liquid)',
                exiting: 'Sending to your address',
                confirming: this._anonymizeConfirmingLabel(s),
                completed: 'Done',
                completed_with_reorg_uncertainty: 'Done — verify on-chain',
                awaiting_channel_close: 'Closing temporary channel',
                refunding: 'Refunding to your wallet',
                cancelled: 'Cancelled',
                failed: 'Failed',
            };
            return labels[status] || status || 'Unknown';
        },

        _anonymizeConfirmingLabel(s) {
            // "Confirming on-chain (X/Y)" where X is the
            // running confirmation count and Y is the target read
            // from /anonymize/policy. Default Y=2 mirrors
            // ANONYMIZE_CLAIM_MIN_CONFIRMATIONS.
            const got = (s && Number(s.confirmation_count)) || 0;
            const target = this.anonymizeClaimMinConfirmations || 2;
            return 'Confirming on-chain (' + got + '/' + target + ')';
        },

        anonymizeStatusDescription(s) {
            const status = (s && s.status) || '';
            if (status === 'awaiting_reconciliation') {
                return this._anonymizeReasonLabel(
                    (s && s.awaiting_reconciliation_reason) || '',
                ).description;
            }
            const desc = {
                created: 'Setting up your session.',
                sourcing: 'Send your deposit to continue.',
                funding: 'Locking your deposit into the mix.',
                ln_holding: 'Payment received. Privacy delay starts soon.',
                delaying: 'Waiting before next step (improves privacy).',
                hopping: 'Routing your funds through privacy hops.',
                awaiting_liquid_dwell: 'Holding on Liquid for privacy.',
                exiting: 'Final payment going out.',
                confirming: 'Waiting for blockchain confirmations.',
                completed: 'Funds delivered to your address.',
                completed_with_reorg_uncertainty:
                    'Delivered but a recent reorg means you should double-check.',
                awaiting_channel_close:
                    'Wrapping up — channel cooperatively closing.',
                refunding: 'Sending funds back to you on-chain.',
                cancelled: 'You cancelled this session.',
                failed: 'This session didn’t complete.',
            };
            return desc[status] || '';
        },

        // True while a wallet-on-chain-sourced session is in FUNDING —
        // the submarine hop has broadcast the wallet's on-chain funding
        // and is waiting for it to confirm/settle before the mix can
        // start. Gated to FUNDING specifically: CREATED/SOURCING are
        // pre-broadcast (the swap is still being issued), so claiming a
        // transaction is "confirming" there would be inaccurate. Drives
        // a privacy-preserving caption. The funding txid is deliberately
        // NOT surfaced anywhere in the anonymize UI (see
        // ``anonymizeOnchainTip*`` and the projection allowlist) —
        // showing it would let the session be linked to an on-chain
        // transaction, the exact correlation the mix breaks.
        anonymizeAwaitingOnchainFunding(s) {
            return !!s && s.source_kind === 'onchain-self' && s.status === 'funding';
        },
        // Per-session key for the "why no txid?" info popover. Built in
        // JS (not the template) so the CSP expression evaluator never
        // sees string concatenation.
        anonymizeOnchainTipKey(s) {
            return 'onchain-funding-' + ((s && s.id) || '');
        },
        anonymizeToggleOnchainTip(s) {
            this.anonymizeToggleInfoTip(this.anonymizeOnchainTipKey(s));
        },
        anonymizeOnchainTipOpen(s) {
            return this.anonymizeInfoTipOpen === this.anonymizeOnchainTipKey(s);
        },

        // Color tone for the status badge. Mirrors column 3.
        anonymizeStatusTone(s) {
            const status = (s && s.status) || '';
            if (status === 'completed' ||
                status === 'completed_with_reorg_uncertainty') return 'green';
            if (status === 'awaiting_reconciliation' ||
                status === 'refunding') return 'yellow';
            if (status === 'cancelled' || status === 'failed') return 'gray';
            return 'blue';  // active in-flight statuses
        },

        // Tailwind class string keyed off the tone. Computed via a
        // helper rather than inline template literals because the
        // @alpinejs/csp parser doesn't allow them.
        anonymizeStatusBadgeClass(s) {
            const tone = this.anonymizeStatusTone(s);
            const base =
                'text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded';
            const tones = {
                green: ' bg-green-900/40 text-green-200',
                yellow: ' bg-yellow-900/40 text-yellow-200',
                gray: ' bg-navy-700 text-gray-300',
                blue: ' bg-blue-900/40 text-blue-200',
            };
            return base + (tones[tone] || tones.gray);
        },

        // Per-reason plain-English mapping for
        // ``awaiting_reconciliation``. Returns {label, description}.
        _anonymizeReasonLabel(reason) {
            const map = {
                mpp_k_floor_exhausted: {
                    label: 'Lightning routing failed',
                    description:
                        'Couldn’t find a Lightning route. No funds were moved.',
                },
                circuit_rebuild_throttled: {
                    label: 'Network throttled — retrying',
                    description:
                        'Too many Tor connections recently. Will retry shortly.',
                },
                bounded_retry_exhausted: {
                    label: 'Hit a snag',
                    description:
                        'The session ran into repeated errors. No funds at risk.',
                },
                wall_clock_budget_exceeded: {
                    label: 'Session went stale',
                    description: 'Idle too long — refreshing status.',
                },
                external_state_unknown: {
                    label: 'Can’t reach operator',
                    description:
                        'Couldn’t reach the swap operator. Will retry.',
                },
                economy_feerate_unavailable: {
                    label: 'Can’t read on-chain fees',
                    description: 'Chain fee oracle unavailable. Will retry.',
                },
                stuck_htlc_alarm: {
                    label: 'Lightning payment stuck',
                    description:
                        'Your payment is in flight but slow. Waiting for it to settle or fail.',
                },
                claim_feerate_outlier: {
                    label: 'Operator changed fees',
                    description:
                        'The swap operator’s claim fee fell outside the safe range. Funds can be refunded.',
                },
                operator_signature_mismatch: {
                    label: 'Operator security check failed',
                    description:
                        'An operator’s signature didn’t match what we expected. Recommend refund.',
                },
                claim_tx_validation_failed: {
                    label: 'Couldn’t sign claim',
                    description:
                        'We couldn’t safely sign the claim transaction. Funds can be refunded.',
                },
                clock_skew_exceeds_deadline_margin: {
                    label: 'Clock too far off',
                    description:
                        'System clock skewed beyond safe range. Will resume once it catches up.',
                },
                pipeline_schema_below_min_supported: {
                    label: 'Session schema too old',
                    description:
                        'This session was created under an older wallet version that’s no longer supported.',
                },
                inbound_insufficient_at_lockup: {
                    label: 'Can’t receive over Lightning',
                    description:
                        'Your node can’t currently receive this amount over Lightning, so the swap can’t complete. No funds were moved — cancel and try again once you have more inbound capacity.',
                },
            };
            if (!reason) {
                return {
                    label: 'Needs your attention',
                    description: 'Click Details for more.',
                };
            }
            return map[reason] || {
                label: 'Needs your attention',
                description: 'Click Details for more. (Reason: ' + reason + ')',
            };
        },

        // Friendly source-kind labels.
        anonymizeSourceKindLabel(kind) {
            const map = {
                'lightning-self': 'Lightning (self-paid)',
                'ext-lightning': 'Lightning (external)',
                'onchain-self': 'On-chain (self-paid)',
                'ext-onchain': 'On-chain (external)',
            };
            return map[kind || ''] || (kind || '');
        },

        // Render bin_amount_sat as "₿ 250,000 sat".
        anonymizeFormatAmount(sat) {
            const n = Number(sat) || 0;
            return '₿ ' + n.toLocaleString() + ' sat';
        },

        // Toggle the inline detail panel for one row. Single-
        // open semantics: clicking the same row twice collapses;
        // clicking a different row switches. On open, fire a one-
        // shot detail fetch so the recovery banner can render with
        // the latest per-leg classifier output.
        anonymizeToggleDetail(sessionId) {
            const sid = String(sessionId || '');
            if (this.anonymizeSessionDetailOpen === sid) {
                this.anonymizeSessionDetailOpen = '';
                return;
            }
            this.anonymizeSessionDetailOpen = sid;
            this._anonymizeFetchSessionRecovery(sid);
        },

        /** One-shot fetch of the anonymize session-detail endpoint
         *  to refresh ``anonymizeSessionRecovery[sid]``. Best-
         *  effort — failures leave the previous hint untouched so
         *  a transient network blip doesn't clear a stale banner.
         */
        async _anonymizeFetchSessionRecovery(sid) {
            if (!sid) return;
            try {
                const data = await this.api(
                    'GET', '/anonymize/sessions/' + encodeURIComponent(sid),
                );
                if (data && data.recovery) {
                    this.anonymizeSessionRecovery = {
                        ...this.anonymizeSessionRecovery,
                        [sid]: data.recovery,
                    };
                } else if (data) {
                    const next = { ...this.anonymizeSessionRecovery };
                    delete next[sid];
                    this.anonymizeSessionRecovery = next;
                }
                // Capture the privacy-projected event list for the
                // progress timeline. Always set (even to []) once the
                // detail has been fetched so the panel can distinguish
                // "no activity / retention-expired" from "not loaded".
                if (data) {
                    this.anonymizeSessionEvents = {
                        ...this.anonymizeSessionEvents,
                        [sid]: Array.isArray(data.events) ? data.events : [],
                    };
                }
            } catch (_e) {
                /* swallow — keep previous banner */
            }
        },

        /** Convenience accessor used by the inline detail panel. */
        anonymizeRecoveryFor(s) {
            if (!s) return null;
            return this.anonymizeSessionRecovery[String(s.id)] || null;
        },

        /** True when the per-session banner should render — only
         *  warning/critical severity surfaces a banner; ok/info
         *  hints stay silent. */
        anonymizeRecoveryVisible(s) {
            const r = this.anonymizeRecoveryFor(s);
            return !!(r && (r.severity === 'warning' || r.severity === 'critical'));
        },

        /** Banner colour helper — returns the Tailwind class string
         *  for the wrapper based on severity. */
        anonymizeRecoveryBannerClass(s) {
            const r = this.anonymizeRecoveryFor(s);
            if (r && r.severity === 'critical') {
                return 'bg-neon-pink/10 border border-neon-pink/30';
            }
            return 'bg-neon-yellow/10 border border-neon-yellow/30';
        },

        /** Icon colour helper for the inline severity icon. */
        anonymizeRecoveryIconClass(s) {
            const r = this.anonymizeRecoveryFor(s);
            return r && r.severity === 'critical' ? 'text-neon-pink' : 'text-neon-yellow';
        },

        /** Returns the lucide icon name for the severity. */
        anonymizeRecoveryIconName(s) {
            const r = this.anonymizeRecoveryFor(s);
            return r && r.severity === 'critical' ? 'alert-octagon' : 'alert-triangle';
        },

        anonymizeDetailExpanded(s) {
            return (s && this.anonymizeSessionDetailOpen === String(s.id)) || false;
        },

        // ── Progress timeline (phase & health) ───────────────────
        // Privacy posture: we render only a friendly label derived from
        // the event ``kind`` + a COARSE timestamp. The raw event
        // ``detail`` is never read here, so nothing linkable (txids,
        // addresses, operators, the withdrawal side) can leak — even if
        // a future writer puts richer data in detail_json. Unknown /
        // noisy internal kinds map to '' and are filtered out, so the
        // raw enum never reaches the UI either.

        _anonymizeIsTerminalStatus(status) {
            const terminal = {
                completed: true,
                completed_with_reorg_uncertainty: true,
                cancelled: true,
                failed: true,
            };
            return !!terminal[status];
        },

        /** Friendly label for a session-event ``kind``. Returns '' for
         *  internal/noisy/unknown kinds so they're filtered from the
         *  timeline (never shown raw). */
        _anonymizeEventLabel(kind) {
            // Whitelist of the user-meaningful kinds actually persisted as
            // AnonymizeSessionEvent rows. Everything else (internal
            // heuristics like reconciliation_wall_clock_flipped /
            // mpp_k_floor_exhausted, retention markers like
            // redacted_history, admin spend-override audits, and any
            // future/unknown kind) maps to '' and is filtered out — so a
            // raw kind never reaches the UI.
            const labels = {
                hop_attempt_started: 'Mixing hop started',
                hop_attempt_completed: 'Mixing hop completed',
                auto_peer_chosen: 'Selected a mixing peer',
                reconciliation_attempt_started: 'Recovery attempt started',
                reconciliation_attempt_completed: 'Recovery attempt finished',
                reconciliation_escalated: 'Escalated for manual review',
                anonymize_refund_locked: 'Refund secured',
            };
            return labels[kind] || '';
        },

        /** Build the rendered timeline for a session's open detail:
         *  ``[{label, when}]``, oldest-first, with noisy kinds dropped
         *  and coarse relative timestamps. Reads only ``kind`` + ``ts``. */
        anonymizeProgressEntries(s) {
            const sid = s && String(s.id);
            if (!sid) return [];
            const events = this.anonymizeSessionEvents[sid];
            if (!Array.isArray(events)) return [];
            const out = [];
            for (let i = 0; i < events.length; i++) {
                const ev = events[i] || {};
                const label = this._anonymizeEventLabel(ev.kind);
                if (!label) continue;  // filter internal/unknown kinds
                out.push({
                    label: label,
                    when: this.anonymizeRelativeTime(ev.ts),
                });
            }
            return out;
        },

        /** Retention note: shown only for a terminal session whose
         *  detail has been loaded but has no surviving timeline entries
         *  (events deleted / kind-collapsed by the retention pass).
         *  Returns '' otherwise — including for fresh sessions that
         *  simply haven't emitted activity yet. */
        anonymizeProgressExpiredNote(s) {
            const sid = s && String(s.id);
            if (!sid) return '';
            const events = this.anonymizeSessionEvents[sid];
            if (!Array.isArray(events)) return '';  // not loaded yet
            if (this.anonymizeProgressEntries(s).length > 0) return '';
            if (this._anonymizeIsTerminalStatus(s && s.status)) {
                return 'Older activity has expired (privacy retention).';
            }
            return '';
        },

        // Countdown caption for AR rows. Returns
        // the user-facing string to show beneath the status
        // description. Empty when no countdown should be shown
        // (Class C reasons, no last_attempt, etc.).
        //
        // Behavior:
        //   - next_retry within threshold (≤ 10 min default) →
        //     "Next try in 3m 12s" (decrements every second).
        //   - next_retry beyond threshold → "Retrying when network
        //     recovers" (no countdown — too anxiety-inducing for
        //     long backoffs).
        //   - next_retry is null/in the past → "" (no caption).
        anonymizeNextRetryCaption(s) {
            if (!s) return '';
            const next = Number(s.next_retry_at_unix_s);
            if (!next || Number.isNaN(next)) return '';
            const nowS = this.anonymizeRowTickSnapshot || (Date.now() / 1000);
            const remaining = next - nowS;
            if (remaining <= 0) return '';
            const threshold = this.anonymizeReconciliationCountdownThresholdS || 600;
            if (remaining > threshold) {
                return 'Retrying when network recovers';
            }
            const total = Math.ceil(remaining);
            const m = Math.floor(total / 60);
            const sec = total % 60;
            if (m > 0) {
                return 'Next try in ' + m + 'm ' + sec + 's';
            }
            return 'Next try in ' + sec + 's';
        },

        // Format "last_reconciliation_attempt_ts" (ISO string) as a
        // friendly relative time: "2 minutes ago", "5 hours ago", or
        // "just now". Returns '' when null/absent. Used by the
        // inline detail panel.
        anonymizeRelativeTime(iso) {
            if (!iso) return '';
            const then = Date.parse(iso);
            if (Number.isNaN(then)) return '';
            const deltaS = Math.max(0, (Date.now() - then) / 1000);
            if (deltaS < 30) return 'just now';
            if (deltaS < 90) return 'about a minute ago';
            const m = Math.round(deltaS / 60);
            if (m < 60) return m + ' minutes ago';
            const h = Math.round(m / 60);
            if (h < 24) return h + ' hours ago';
            const d = Math.round(h / 24);
            return d + ' days ago';
        },

        // ── — per-row action decision ──
        //
        // Mirrors ``reconciliation_classify._CANCELLABLE_REASONS``
        // on the server. Keep in sync if reasons are added/removed.
        _anonymizeReasonIsCancellable(reason) {
            const set = {
                mpp_k_floor_exhausted: true,
                circuit_rebuild_throttled: true,
                bounded_retry_exhausted: true,
                wall_clock_budget_exceeded: true,
                inbound_insufficient_at_lockup: true,
            };
            return !!(reason && set[reason]);
        },

        // True iff the reason is in the classifier's known set
        // (mirrors the 12 reasons in ``reconciliation_classify.py``).
        // Used by ``anonymizePrimaryAction`` to route unrecognised
        // reasons to "View details" instead of the default
        // "Try again" branch.
        _anonymizeReasonIsKnown(reason) {
            if (!reason) return false;
            const known = {
                mpp_k_floor_exhausted: true,
                circuit_rebuild_throttled: true,
                bounded_retry_exhausted: true,
                wall_clock_budget_exceeded: true,
                external_state_unknown: true,
                economy_feerate_unavailable: true,
                stuck_htlc_alarm: true,
                claim_feerate_outlier: true,
                operator_signature_mismatch: true,
                claim_tx_validation_failed: true,
                clock_skew_exceeds_deadline_margin: true,
                pipeline_schema_below_min_supported: true,
                inbound_insufficient_at_lockup: true,
            };
            return !!known[reason];
        },

        // Reassurance copy for the inline detail panel.
        // The cancellable reasons are exactly the no-funds-moved
        // set, so we reuse the same predicate. Plain
        // method wrapper kept so the x-show expression in the
        // template reads as documentation.
        anonymizeReasonNoFundsAtRisk(s) {
            const reason = (s && s.awaiting_reconciliation_reason) || '';
            return this._anonymizeReasonIsCancellable(reason);
        },

        // Reassurance copy for the no-funds-at-risk case. Worded by
        // source kind: for a Lightning source an intermediate mixing hop
        // can leave the funds on-chain in the user's own wallet, so a
        // flat "no funds moved" reads as inaccurate — the truthful point
        // is that nothing left their control and nothing reached the
        // destination, even if the funds changed form.
        anonymizeNoFundsMessage(s) {
            const sk = (s && s.source_kind) || '';
            if (sk === 'lightning-self' || sk === 'ext-lightning') {
                return 'Your funds are safe in your wallet — nothing reached your '
                    + 'destination. Mixing may have moved them from your Lightning '
                    + 'balance to on-chain, but they never left your control.';
            }
            return 'No funds have left your wallet — nothing reached your '
                + 'destination and your funds are safe.';
        },

        // Returns the primary action for a row, or null if the row
        // shouldn't render one (e.g. in-progress statuses past the
        // point-of-no-return). Shape: ``{label, kind}``.
        anonymizePrimaryAction(s) {
            if (!s) return null;
            const status = s.status || '';
            if (status === 'awaiting_reconciliation') {
                const reason = s.awaiting_reconciliation_reason || '';
                // Reasons where Class A auto-retry will handle it
                // without operator action: no primary button so the
                // user sees "system's working on it" via the auto-
                // retry caption.
                const passive = {
                    circuit_rebuild_throttled: true,
                    wall_clock_budget_exceeded: true,
                    external_state_unknown: true,
                    economy_feerate_unavailable: true,
                    stuck_htlc_alarm: true,
                    clock_skew_exceeds_deadline_margin: true,
                };
                if (passive[reason]) return null;
                // Reasons where funds are recoverable → Refund primary.
                const refundable = {
                    claim_feerate_outlier: true,
                    operator_signature_mismatch: true,
                    claim_tx_validation_failed: true,
                };
                if (refundable[reason]) {
                    return {label: 'Refund', kind: 'reconcile_refund'};
                }
                // Schema-too-old: no recovery, just "Mark done".
                if (reason === 'pipeline_schema_below_min_supported') {
                    return {label: 'Mark done', kind: 'reconcile_fail'};
                }
                // Inbound-insufficient-at-lockup: the on-chain funding
                // step has no legal AR→FUNDING resume edge, so "Try
                // again" can never succeed (the auto-probe escalates the
                // row to Failed). No funds moved → Cancel is the honest,
                // working primary action; the user starts a fresh
                // session once they have inbound.
                if (reason === 'inbound_insufficient_at_lockup') {
                    return {label: 'Cancel', kind: 'reconcile_cancel'};
                }
                // Unknown / unclassified reason: route to Details so
                // the operator can read the raw code before acting.
                // Unknown-reason row.
                if (!this._anonymizeReasonIsKnown(reason)) {
                    return {label: 'View details', kind: 'details'};
                }
                // Default for cancellable Class A/B no-funds-moved
                // reasons: Try again.
                return {label: 'Try again', kind: 'reconcile_retry'};
            }
            // Refund inline on LN_HOLDING and DELAYING. The
            // existing /refund endpoint already accepts these.
            if (status === 'ln_holding' || status === 'delaying') {
                return {label: 'Refund', kind: 'refund_in_flow'};
            }
            return null;
        },

        // Returns the secondary action (low-prominence text-link).
        anonymizeSecondaryAction(s) {
            if (!s) return null;
            const status = s.status || '';
            if (status !== 'awaiting_reconciliation') return null;
            const reason = s.awaiting_reconciliation_reason || '';
            // Reasons where funds-at-risk → secondary is "Get help"
            // so the user has a path to the runbook for operator-
            // judgement scenarios.
            const fundsAtRisk = {
                claim_feerate_outlier: true,
                operator_signature_mismatch: true,
                claim_tx_validation_failed: true,
                stuck_htlc_alarm: true,
                external_state_unknown: true,
            };
            if (fundsAtRisk[reason]) {
                return {label: 'Get help', kind: 'help'};
            }
            // inbound_insufficient_at_lockup uses Cancel as its PRIMARY
            // action (it can't be retried), so its secondary is Get help
            // — the runbook explains adding inbound / using an LN source
            // — rather than a duplicate Cancel button.
            if (reason === 'inbound_insufficient_at_lockup') {
                return {label: 'Get help', kind: 'help'};
            }
            // Cancellable Class A/B → secondary is Cancel.
            if (this._anonymizeReasonIsCancellable(reason)) {
                return {label: 'Cancel', kind: 'reconcile_cancel'};
            }
            // Unknown / unclassified reason → secondary is "Get help"
            // so the operator can read the runbook for triage even
            // when the primary action is just "View details". Per
            // plan unknown-reason row.
            if (!this._anonymizeReasonIsKnown(reason)) {
                return {label: 'Get help', kind: 'help'};
            }
            return null;
        },

        // Flat-getter wrappers for the action descriptors. The
        // @alpinejs/csp build's expression parser is strict about
        // property access on function-call results, so we expose
        // .label and .kind via dedicated method calls rather than
        // relying on ``anonymizePrimaryAction(s).label`` chains in
        // the template.
        anonymizePrimaryActionLabel(s) {
            const a = this.anonymizePrimaryAction(s);
            return a ? a.label : '';
        },
        anonymizePrimaryActionKind(s) {
            const a = this.anonymizePrimaryAction(s);
            return a ? a.kind : '';
        },
        anonymizeHasPrimaryAction(s) {
            return !!this.anonymizePrimaryAction(s);
        },
        anonymizeSecondaryActionLabel(s) {
            const a = this.anonymizeSecondaryAction(s);
            return a ? a.label : '';
        },
        anonymizeSecondaryActionKind(s) {
            const a = this.anonymizeSecondaryAction(s);
            return a ? a.kind : '';
        },
        anonymizeHasSecondaryAction(s) {
            return !!this.anonymizeSecondaryAction(s);
        },

        // Dispatch table for primary / secondary action clicks.
        // Called from x-on:click with the row's session id + a kind
        // string the helpers above produced.
        async anonymizeInvokeAction(sessionId, kind) {
            if (!sessionId || !kind) return;
            if (kind === 'details') {
                this.anonymizeToggleDetail(sessionId);
                return;
            }
            if (kind === 'help') {
                // Find the row to read its reason.
                const sess = (this.anonymizeSessions || []).find(
                    (x) => String(x.id) === String(sessionId),
                );
                const reason = sess && sess.awaiting_reconciliation_reason
                    ? sess.awaiting_reconciliation_reason : '';
                this._anonymizeOpenHelp(reason);
                return;
            }
            if (kind === 'reconcile_retry') {
                await this._anonymizeReconciliationRetry(sessionId);
                return;
            }
            if (kind === 'reconcile_cancel') {
                await this._anonymizeReconciliationCancel(sessionId);
                return;
            }
            if (kind === 'reconcile_fail') {
                await this._anonymizeReconciliationFail(sessionId);
                return;
            }
            if (kind === 'reconcile_refund') {
                await this._anonymizeReconciliationRefund(sessionId);
                return;
            }
            if (kind === 'refund_in_flow') {
                await this._anonymizeRefundInFlow(sessionId);
                return;
            }
            if (kind === 'liquid_cooperative_refund') {
                await this._anonymizeLiquidRefund(sessionId, 'cooperative');
                return;
            }
            if (kind === 'liquid_unilateral_refund') {
                await this._anonymizeLiquidRefund(sessionId, 'unilateral');
                return;
            }
            if (kind === 'liquid_reverse_unilateral_claim') {
                await this._anonymizeLiquidReverseClaim(sessionId);
                return;
            }
        },

        /** True when the session's recovery hint lists ``actionId`` —
         *  drives the Liquid-refund buttons in the recovery banner. The
         *  recovery hint is only present once the detail panel has
         *  fetched it (see ``_anonymizeFetchSessionRecovery``). */
        anonymizeRecoveryHasAction(s, actionId) {
            const r = this.anonymizeRecoveryFor(s);
            return !!(r && Array.isArray(r.actions) && r.actions.includes(actionId));
        },

        /** Refund the wallet's locked L-BTC submarine lockup (Liquid
         *  round-trip leg 2). ``cooperative`` co-signs with Boltz (works
         *  anytime); ``unilateral`` is the post-timeout script-path
         *  fallback. The endpoints enforce their own preconditions and
         *  return a clean error if not applicable. */
        async _anonymizeLiquidRefund(sessionId, mode) {
            const isUnilateral = mode === 'unilateral';
            if (!await this.askConfirm({
                body: isUnilateral
                    ? 'Broadcast a unilateral (post-timeout) refund of your locked '
                        + 'Liquid funds back to your wallet? Use this only if the '
                        + 'cooperative refund has failed.'
                    : 'Refund your locked Liquid funds back to your wallet? This '
                        + 'co-signs a refund transaction with the swap provider.',
                ok: 'Refund',
                cancel: 'Not now',
            })) return;
            const path = isUnilateral ? 'unilateral-refund' : 'cooperative-refund';
            try {
                await this.api(
                    'POST',
                    '/anonymize/sessions/' + sessionId
                        + '/liquid-recovery/submarine/' + path,
                );
                this._anonymizeShowToast('Liquid refund started');
            } catch (e) {
                this._anonymizeShowToast(
                    (e && e.message) || 'Liquid refund failed',
                );
            }
            await this.anonymizeFetchSessions();
            // Refresh the open detail panel's recovery banner so the
            // buttons reflect the new state.
            if (this.anonymizeSessionDetailOpen) {
                await this._anonymizeFetchSessionRecovery(this.anonymizeSessionDetailOpen);
            }
        },

        /** Broadcast the post-timeout unilateral claim of the wallet's
         *  L-BTC from the leg-1 reverse swap. Used when the cooperative
         *  claim is stuck after the preimage was revealed (so the LN
         *  funds are committed and the L-BTC must be landed). The session
         *  resumes on its own once the claim confirms. */
        async _anonymizeLiquidReverseClaim(sessionId) {
            if (!await this.askConfirm({
                body: 'Broadcast a direct claim of your Liquid funds back to your '
                    + 'wallet? Use this when the normal claim is stuck — it works '
                    + 'even if the swap provider is offline. The session continues '
                    + 'once the claim confirms.',
                ok: 'Claim',
                cancel: 'Not now',
            })) return;
            try {
                await this.api(
                    'POST',
                    '/anonymize/sessions/' + sessionId
                        + '/liquid-recovery/reverse/unilateral-claim',
                );
                this._anonymizeShowToast('Liquid claim broadcast');
            } catch (e) {
                this._anonymizeShowToast(
                    (e && e.message) || 'Liquid claim failed',
                );
            }
            await this.anonymizeFetchSessions();
            if (this.anonymizeSessionDetailOpen) {
                await this._anonymizeFetchSessionRecovery(this.anonymizeSessionDetailOpen);
            }
        },

        async _anonymizeReconciliationRetry(sessionId) {
            // Try again is idempotent + reversible → no confirm dialog.
            try {
                await this.api(
                    'POST',
                    '/anonymize/sessions/' + sessionId
                        + '/reconciliation/retry',
                );
                this._anonymizeShowToast('Session retrying…');
            } catch (e) {
                this._anonymizeShowToast(
                    (e && e.message) || 'Retry failed',
                );
            }
            await this.anonymizeFetchSessions();
            this.anonymizeStartSessionsPolling();
        },

        async _anonymizeReconciliationCancel(sessionId) {
            if (!await this.askConfirm({
                body: 'Cancel this session? Your funds remain in your wallet and '
                    + 'nothing reached your destination. The session will be '
                    + 'marked cancelled.',
                ok: 'Cancel session',
                cancel: 'Keep session',
                dangerous: true,
            })) return;
            try {
                await this.api(
                    'POST',
                    '/anonymize/sessions/' + sessionId
                        + '/reconciliation/cancel',
                );
                this._anonymizeShowToast('Session cancelled');
            } catch (e) {
                this._anonymizeShowToast(
                    (e && e.message) || 'Cancel failed',
                );
            }
            await this.anonymizeFetchSessions();
        },

        async _anonymizeReconciliationFail(sessionId) {
            // row 6 — Mark Done is currently only surfaced for
            // ``pipeline_schema_below_min_supported`` (see
            // ``anonymizePrimaryAction``). Copy is specific to that
            // reason; if a future reason routes through reconcile_fail
            // this dialog should be generalised.
            if (!await this.askConfirm({
                body: 'Close this session? This session was created under an '
                    + 'older wallet version that’s no longer supported. '
                    + 'No funds were moved.',
                ok: 'Close session',
                cancel: 'Keep open',
            })) return;
            try {
                await this.api(
                    'POST',
                    '/anonymize/sessions/' + sessionId
                        + '/reconciliation/fail',
                );
                this._anonymizeShowToast('Session closed');
            } catch (e) {
                this._anonymizeShowToast(
                    (e && e.message) || 'Close failed',
                );
            }
            await this.anonymizeFetchSessions();
        },

        async _anonymizeReconciliationRefund(sessionId) {
            if (!await this.askConfirm({
                body: 'Refund this session? Funds in flight will be sent back '
                    + 'to your wallet. This requires a fresh confirmation '
                    + 'step.',
                ok: 'Refund',
                cancel: 'Not now',
            })) return;
            // Fetch a step-up nonce bound to the
            // ``anonymize_reconciliation_refund`` scope, then submit
            // the refund with the nonce.
            let nonce;
            try {
                const issued = await this.api(
                    'POST', '/anonymize/stepup/issue',
                    // session_id binds the nonce to this session so it
                    // can't be replayed against another (security H3).
                    {scope: 'anonymize_reconciliation_refund', session_id: sessionId},
                );
                nonce = issued && issued.nonce ? issued.nonce : '';
                if (!nonce) {
                    this._anonymizeShowToast(
                        'Couldn’t obtain re-auth nonce',
                    );
                    return;
                }
            } catch (e) {
                this._anonymizeShowToast(
                    (e && e.message) || 'Re-auth failed',
                );
                return;
            }
            try {
                await this.api(
                    'POST',
                    '/anonymize/sessions/' + sessionId
                        + '/reconciliation/refund',
                    {stepup_nonce: nonce},
                );
                this._anonymizeShowToast('Refund started');
            } catch (e) {
                this._anonymizeShowToast(
                    (e && e.message) || 'Refund failed',
                );
            }
            await this.anonymizeFetchSessions();
        },

        async _anonymizeRefundInFlow(sessionId) {
            if (!await this.askConfirm({
                body: 'Refund this session? Funds in flight will be sent back '
                    + 'to your wallet. Any Lightning fees already paid are '
                    + 'not recoverable.',
                ok: 'Refund',
                cancel: 'Not now',
            })) return;
            try {
                await this.api(
                    'POST',
                    '/anonymize/sessions/' + sessionId + '/refund',
                );
                this._anonymizeShowToast('Refund started');
            } catch (e) {
                this._anonymizeShowToast(
                    (e && e.message) || 'Refund failed',
                );
            }
            await this.anonymizeFetchSessions();
        },

        // Open the troubleshooting anchor for a reason.
        // Known reasons (in ``_anonymizeReasonIsKnown``) get a
        // direct anchor ``#trouble-<slug>``; unrecognised reasons
        // route to the dedicated ``#trouble-unknown`` anchor so the
        // browser doesn't land on the bare TOC. Empty reason →
        // generic ``#troubleshooting``.
        _anonymizeOpenHelp(reason) {
            let href;
            if (!reason) {
                href = '/dashboard/static/help/anonymize.html#troubleshooting';
            } else if (this._anonymizeReasonIsKnown(reason)) {
                const slug = reason.replace(/_/g, '-');
                href = '/dashboard/static/help/anonymize.html#trouble-' + slug;
            } else {
                href = '/dashboard/static/help/anonymize.html#trouble-unknown';
            }
            // open in a new tab so the user keeps their dashboard state.
            window.open(href, '_blank', 'noopener');
        },

        _anonymizeShowToast(message) {
            if (!message) return;
            this.toast = String(message);
            setTimeout(() => {
                // Only clear if no newer toast has taken over.
                if (this.toast === message) this.toast = '';
            }, 3500);
        },

        // Promise-based confirm modal. Returns ``true`` if the user
        // clicks the OK button, ``false`` on dismiss (Cancel button,
        // backdrop click, or Escape). Callers use the same shape as
        // the old ``window.confirm`` flow:
        //
        //   if (!await this.askConfirm({body: 'Are you sure?'})) return;
        //
        // Options: ``body`` (required), ``ok``, ``cancel``, ``dangerous``.
        // ``dangerous: true`` swaps the OK button to the neon-pink
        // destructive style.
        askConfirm(opts) {
            const o = opts || {};
            // If a previous prompt is still hanging (shouldn't happen
            // — modal is single-instance — but defensive), resolve
            // it as dismissed so the old promise doesn't dangle.
            if (this._confirmResolve) {
                const stale = this._confirmResolve;
                this._confirmResolve = null;
                try { stale(false); } catch (_e) {}
            }
            this.confirmBody = String(o.body || '');
            this.confirmOkLabel = String(o.ok || 'Confirm');
            this.confirmCancelLabel = String(o.cancel || 'Cancel');
            this.confirmDangerous = !!o.dangerous;
            const self = this;
            return new Promise((resolve) => {
                self._confirmResolve = resolve;
                self.confirmOpen = true;
            });
        },

        confirmAccept() {
            const r = this._confirmResolve;
            this._confirmResolve = null;
            this.confirmOpen = false;
            if (r) r(true);
        },

        confirmDismiss() {
            const r = this._confirmResolve;
            this._confirmResolve = null;
            this.confirmOpen = false;
            if (r) r(false);
        },

        // Surface meaningful status transitions as toasts.
        // Called from anonymizeFetchSessions on every poll tick. Stores
        // a snapshot of statuses keyed by session id so subsequent
        // ticks can diff.
        _anonymizePrevStatuses: {},
        _anonymizeNoticeStatusChanges(nextSessions) {
            const prev = this._anonymizePrevStatuses || {};
            const next = {};
            for (let i = 0; i < (nextSessions || []).length; i++) {
                const row = nextSessions[i];
                if (!row || !row.id) continue;
                next[row.id] = row.status;
                const before = prev[row.id];
                if (!before || before === row.status) continue;
                this._anonymizeToastForTransition(before, row.status, row);
            }
            this._anonymizePrevStatuses = next;
        },

        _anonymizeToastForTransition(fromStatus, toStatus, row) {
            // From AWAITING_RECONCILIATION → any live status: resumed.
            if (fromStatus === 'awaiting_reconciliation') {
                if (toStatus === 'exiting'
                    || toStatus === 'confirming'
                    || toStatus === 'hopping'
                    || toStatus === 'delaying'
                    || toStatus === 'ln_holding'
                ) {
                    this._anonymizeShowToast('Session resumed');
                    return;
                }
            }
            // Completion (success).
            if (toStatus === 'completed'
                || toStatus === 'completed_with_reorg_uncertainty'
            ) {
                this._anonymizeShowToast('Session done — funds delivered');
                return;
            }
            // Failure.
            if (toStatus === 'failed') {
                this._anonymizeShowToast(
                    'Session failed — open Details',
                );
                return;
            }
            // Refund start.
            if (toStatus === 'refunding') {
                this._anonymizeShowToast('Refund in progress');
                return;
            }
            // Active forward transitions stay silent (too noisy).
        },

        async anonymizeCancelSession(sessionId) {
            // row 1 — pre-flow Cancel confirmation.
            if (!await this.askConfirm({
                body: 'Cancel this session? No funds will be moved. You can '
                    + 'start a new session anytime.',
                ok: 'Cancel session',
                cancel: 'Keep session',
                dangerous: true,
            })) return;
            try {
                await this.api(
                    'POST', '/anonymize/sessions/' + sessionId + '/cancel',
                );
                await this.anonymizeFetchSessions();
            } catch (_e) {
                await this.anonymizeFetchSessions();
            }
        },

        // Logout helper. Lives on the component (rather than as an
        // inline arrow in the template) because the @alpinejs/csp
        // expression evaluator does not support arrow functions or
        // method-chained ``.finally()`` callbacks — it throws
        // ``CSP Parser Error: Unexpected token: PUNCTUATION ")"``.
        async logout() {
            try {
                await this.api('POST', '/logout');
            } catch (_e) {
                // Ignore network/server errors — we still want to land
                // on the login page so the user has a clear next step.
            }
            window.location.href = '/dashboard/login';
        },

        // ── Data fetching ──
        async fetchAll() {
            this.loading = true;
            this.error = null;

            // Seed empty arrays for the list-shaped fields BEFORE we
            // await anything. The dashboard's inner template renders as
            // soon as ``summary`` is back, but ``@alpinejs/csp``'s
            // expression parser doesn't fully short-circuit ``||`` / ``&&``
            // — so expressions like ``!channels || channels.length === 0``
            // throw when ``channels`` is still ``null``. Empty arrays
            // satisfy the parser and naturally render the "no data" UI
            // until the real values arrive.
            this.channels = [];
            this.pendingChannels = [];
            this.payments = [];
            this.invoices = [];
            this.transactions = [];

            // Kick off every request in parallel, but bind state per-request
            // as each one resolves. Only ``/summary`` gates the loading
            // spinner — a slow endpoint (e.g. ``/fees`` while the chain
            // backend is retrying upstream) must not hold the whole
            // dashboard hostage.
            //
            // ``/summary`` carries a client-side 10 s wall-clock timeout
            // so an unreachable LND (e.g. Tor circuit wedged trying to
            // route to LND's onion) can't hang the dashboard for the
            // full server-side retry envelope. After 10 s the request
            // aborts and the user lands on the error state with a
            // Retry button rather than an indefinite spinner.
            const summaryP   = this.api('GET', '/summary', null, { timeoutMs: 10000 });
            const infoP      = this.api('GET', '/info');
            const feesP      = this.api('GET', '/fees');
            const channelsP  = this.api('GET', '/channels', null, { timeoutMs: CHANNELS_READ_TIMEOUT_MS });
            const pendingP   = this.api('GET', '/channels/pending', null, { timeoutMs: CHANNELS_READ_TIMEOUT_MS });
            const paymentsP  = this.api('GET', '/payments');
            const invoicesP  = this.api('GET', '/invoices');
            const txP        = this.api('GET', '/transactions');
            // Fire-and-forget catalog fetch so the channel-card
            // enrichment (badges + per-card info tooltip) renders as
            // soon as ``/channels`` lands. The catalog's load-state
            // field gates the bindings; an in-flight or failed fetch
            // surfaces nothing on the cards (silent miss).
            this._ensureSmallChannelPeerCatalog();

            try {
                this.summary = await summaryP;
            } catch (e) {
                this.error = e.message || 'Failed to load wallet data';
            }
            this.loading = false;
            this.initIcons();
            // Fetch activity in background (independent of the parallel set)
            this.fetchActivity();

            // Stragglers fill in as they arrive. Each one re-runs icon
            // hydration on its own next tick so newly-rendered Lucide
            // ``<i>`` elements get replaced once their data is in view.
            const stragglers = [
                infoP.then(v => { this.info = v; }, () => {}),
                feesP.then(
                    v => { this.fees = v; this.feesError = v ? null : 'No data'; },
                    e => { this.feesError = e?.message || 'Failed'; },
                ),
                channelsP.then(
                    v => { this.channels = v; this.channelsError = null; },
                    e => { this.channelsError = (e && e.message) || 'Couldn’t load channels'; },
                ),
                pendingP.then(v => { this.pendingChannels = v; }, () => {}),
                paymentsP.then(
                    v => { this.payments = v; this.paymentsError = null; },
                    e => { this.paymentsError = (e && e.message) || 'Couldn’t load payments'; },
                ),
                invoicesP.then(v => { this.invoices = v; }, () => {}),
                txP.then(
                    v => { this.transactions = v; this.transactionsError = null; },
                    e => { this.transactionsError = (e && e.message) || 'Couldn’t load transactions'; },
                ),
            ];
            Promise.allSettled(stragglers).then(() => this.initIcons());
        },

        async fetchSummary() { try { this.summary = await this.api('GET', '/summary'); } catch(e) {} },
        async fetchInfo() { try { this.info = await this.api('GET', '/info'); } catch(e) {} },
        async fetchTransactions() { try { this.transactions = await this.api('GET', '/transactions'); this.transactionsError = null; } catch(e) { this.transactionsError = (e && e.message) || 'Couldn’t load transactions'; } },
        async fetchChannels() { try { this.channels = await this.api('GET', '/channels', null, { timeoutMs: CHANNELS_READ_TIMEOUT_MS }); this.pendingChannels = await this.api('GET', '/channels/pending', null, { timeoutMs: CHANNELS_READ_TIMEOUT_MS }); this.channelsError = null; this._pruneCloseChanIds(); } catch(e) { this.channelsError = (e && e.message) || 'Couldn’t load channels'; } },

        /** Drop "just-closed" dim markers once the channel has left the
         *  active list (relocated to the closing section), so the set
         *  doesn't grow across a long-lived session. */
        _pruneCloseChanIds() {
            if (!this.closeChanIds.length) return;
            const live = this.channels || [];
            this.closeChanIds = this.closeChanIds.filter(id => live.some(c => c.chan_id === id));
        },

        /** Recreate the channels/info/fees auto-refresh timer at the
         *  cadence appropriate for the current pending-channel state.
         *  15 s while a channel is awaiting confirmations (so the
         *  on-screen counter keeps up with back-to-back blocks), 60 s
         *  otherwise. Idempotent — safe to call from $watch. */
        _channelsTimerInterval: null,
        _refreshChannelsTimer() {
            // Tighten the cadence while any channel is mid-open or mid-close
            // so confirmation/maturity progress updates promptly.
            const inFlight = (this.pendingChannels || []).some((pc) => pc && (
                pc.type === 'pending_open'
                || pc.type === 'waiting_close'
                || pc.type === 'pending_close'
                || pc.type === 'force_closing'
            ));
            const desired = inFlight ? 15000 : 60000;
            // No-op when the cadence is unchanged and the poller is live.
            if (this._channelsTimerInterval === desired && this._isPolling('channels')) return;
            this._channelsTimerInterval = desired;
            // ``_poll`` stops + restarts the 'channels' key at the new
            // cadence; the in-flight guard prevents overlap at the
            // tighter 15 s pending-open cadence.
            this._poll('channels', () => Promise.all([
                this.fetchChannels(), this.fetchInfo(), this.fetchFees(),
            ]), { intervalMs: desired, immediate: false });
        },
        async fetchFees() { try { this.fees = await this.api('GET', '/fees'); this.feesError = null; } catch(e) { this.feesError = e.message || 'Failed'; } },
        async fetchPayments() { try { this.payments = await this.api('GET', '/payments'); this.paymentsError = null; } catch(e) { this.paymentsError = (e && e.message) || 'Couldn’t load payments'; } },
        async fetchInvoices() { try { this.invoices = await this.api('GET', '/invoices'); } catch(e) {} },
        async fetchActivity() { try { this.activity = await this.api('GET', '/activity?limit=50&offset=' + this.activityOffset); } catch(e) {} },

        // ── BOLT 12 ──
        async fetchBolt12IssuedOffers() {
            try {
                this.bolt12IssuedOffers = await this.api(
                    'GET', '/bolt12/offers?source=issued'
                );
                // Auto-select the most useful offer for the upper
                // detail panel. Priority: current selection (if it
                // still exists), default-receive offer, first active
                // offer, first offer.
                this._reconcileBolt12Selection();
            } catch (e) {
                this.bolt12Error = e.message || 'Failed to load offers';
            }
            this.$nextTick(() => this.initIcons());
        },
        // Initial load: list issued offers WITHOUT triggering the
        // auto-mint on /bolt12/receive. If the user already has at
        // least one issued offer, fetch the receive panel for the
        // gateway/inbound-liquidity context. Otherwise show the
        // empty-state CTA.
        async fetchBolt12IssuedOffersInitial() {
            await this.fetchBolt12IssuedOffers();
            if ((this.bolt12IssuedOffers || []).length > 0) {
                this.fetchBolt12Receive();
            }
        },
        // Returns true when the user has not yet configured their
        // first BOLT 12 receive offer. The backend auto-mints a
        // placeholder default-receive offer the first time the
        // /bolt12/receive endpoint is hit, with the canonical
        // description below. We treat the user as "unconfigured"
        // until they explicitly mint an offer with a real
        // description (Ocean address or custom string).
        bolt12IsUnconfigured() {
            const list = this.bolt12IssuedOffers || [];
            if (list.length === 0) return true;
            const PLACEHOLDER = 'Receive offer (configure for your payer)';
            return list.every(o => (o.description || '') === PLACEHOLDER);
        },
        _reconcileBolt12Selection() {
            const list = this.bolt12IssuedOffers || [];
            if (list.length === 0) {
                this.bolt12SelectedOfferId = null;
                return;
            }
            const cur = this.bolt12SelectedOfferId;
            if (cur && list.some(o => o.id === cur)) return;
            const def = list.find(o => o.is_default_receive && o.status === 'active');
            const active = list.find(o => o.status === 'active');
            this.bolt12SelectedOfferId = (def || active || list[0]).id;
        },
        bolt12SelectedOffer() {
            const list = this.bolt12IssuedOffers || [];
            if (this.bolt12SelectedOfferId) {
                const hit = list.find(o => o.id === this.bolt12SelectedOfferId);
                if (hit) return hit;
            }
            // Fallback to the default-receive payload while the
            // issued list is still loading.
            return (this.bolt12Receive && this.bolt12Receive.offer) || null;
        },
        selectBolt12Offer(id) {
            this.bolt12SelectedOfferId = id;
            this.$nextTick(() => this.initIcons());
        },

        // ── OCEAN payout-address ownership detection ──
        //
        // OCEAN's documented description format is
        // ``"OCEAN Payouts for <btc-address>"``. When the address is
        // one we own on-chain (i.e. it's a payout destination we
        // generated from this wallet), we expose a streamlined
        // "Sign payout message" button on the Offer Details card so
        // the user can sign an OCEAN auth-challenge without typing
        // the address by hand.

        bolt12ExtractOceanAddress(description) {
            // Parser mirrors ``well_known_payers.match_for_description``
            // on the server. Case-insensitive on the prefix to be
            // lenient with copy/paste mistakes; the address itself is
            // case-sensitive on the wire.
            const desc = String(description || '');
            const m = desc.match(/^OCEAN Payouts for (\S+)/i);
            return m ? m[1] : '';
        },

        async _bolt12CheckOceanOwnership(offerId, address) {
            // Idempotent — calls into the server's
            // ``/sign/owns-address`` and caches by offer id. The
            // cache value the template inspects:
            //   { address, status: 'pending'|'owned'|'not-owned'|'unverified' }
            //
            // ``unverified`` is the LND-build-doesn't-have-the-RPC
            // case (both probes 404). The dashboard shows the button
            // anyway in that case — the sign attempt will surface a
            // clear error if the address really isn't ours.
            if (!offerId || !address) return;
            const cur = this.bolt12OceanOwnership[offerId];
            if (cur && cur.address === address) return;
            this.bolt12OceanOwnership[offerId] = {
                address, status: 'pending',
            };
            try {
                const res = await this.api(
                    'GET',
                    '/sign/owns-address?address=' + encodeURIComponent(address),
                );
                let status = 'not-owned';
                if (res && res.owned === true) {
                    status = 'owned';
                } else if (res && res.owned === null) {
                    // Server couldn't verify (no ownership-probe RPCs
                    // available on this LND build). Optimistic show.
                    status = 'unverified';
                }
                this.bolt12OceanOwnership[offerId] = { address, status };
            } catch (_e) {
                // Actual error from the server (502 etc.) — hide the
                // shortcut so a real LND outage doesn't trip a
                // misleading button.
                this.bolt12OceanOwnership[offerId] = {
                    address, status: 'not-owned',
                };
            }
        },

        bolt12CanSignPayoutMessage(offer) {
            // True iff this offer is the OCEAN-prefixed shape AND
            // either:
            //   * we confirmed the address is owned by the wallet, OR
            //   * the LND build couldn't be probed for ownership but
            //     we want the feature to remain accessible.
            //
            // ``pending`` returns false so the button stays hidden
            // until we have an answer (avoids show/hide flicker).
            if (!offer || !offer.id) return false;
            const addr = this.bolt12ExtractOceanAddress(offer.description);
            if (!addr) return false;
            // Kick the lookup if we haven't yet. ``x-effect`` calls
            // this on every reactive read, so the cache check inside
            // ``_bolt12CheckOceanOwnership`` is what keeps it from
            // dispatching infinite requests.
            this._bolt12CheckOceanOwnership(offer.id, addr);
            const entry = this.bolt12OceanOwnership[offer.id];
            if (!entry || entry.address !== addr) return false;
            return entry.status === 'owned' || entry.status === 'unverified';
        },

        bolt12OceanOwnershipUnverified(offer) {
            // True only when the dashboard is showing the button
            // optimistically. Used by the streamlined dialog to
            // surface a "couldn't auto-verify" hint so the user has
            // calibrated expectations.
            if (!offer || !offer.id) return false;
            const addr = this.bolt12ExtractOceanAddress(offer.description);
            if (!addr) return false;
            const entry = this.bolt12OceanOwnership[offer.id];
            return !!(entry && entry.address === addr
                      && entry.status === 'unverified');
        },

        // ── Streamlined OCEAN sign dialog ──
        //
        // Pre-fills the address (which we already verified is owned)
        // and skips the identity selector + verify tab so the user
        // only has to type the message OCEAN gave them and copy the
        // signature back.

        openOfferQrModal(text, label) {
            if (!text) return;
            this.offerQrModalText = String(text);
            this.offerQrModalLabel = String(label || '');
            this.showOfferQrModal = true;
            this.$nextTick(() => this.initIcons());
        },

        closeOfferQrModal() {
            this.showOfferQrModal = false;
        },

        openOceanSignDialog(address, unverified) {
            if (!address) return;
            this.oceanSignAddress = address;
            this.oceanSignMessage = '';
            this.oceanSignLoading = false;
            this.oceanSignError = '';
            this.oceanSignSignature = '';
            this.oceanSignFormat = '';
            this.oceanSignCopied = false;
            this.oceanSignUnverified = !!unverified;
            this.showOceanSignDialog = true;
            this.$nextTick(() => this.initIcons());
        },

        closeOceanSignDialog() {
            this.showOceanSignDialog = false;
        },

        oceanSignFormReady() {
            const msg = String(this.oceanSignMessage || '');
            if (msg.length === 0) return false;
            // Same control-byte guard as the full Sign dialog so a
            // bad paste fails the client check before hitting the
            // server.
            for (let i = 0; i < msg.length; i++) {
                const cp = msg.charCodeAt(i);
                if ((cp < 0x20 && cp !== 0x09 && cp !== 0x0A && cp !== 0x0D)
                    || cp === 0x7F) {
                    return false;
                }
            }
            return true;
        },

        async submitOceanSign() {
            if (!this.oceanSignFormReady()) return;
            if (this.oceanSignLoading) return;
            this.oceanSignLoading = true;
            this.oceanSignError = '';
            this.oceanSignSignature = '';
            this.oceanSignFormat = '';
            this.oceanSignCopied = false;
            try {
                // Reuses the same backend the full Sign dialog uses —
                // the only difference is what we render on success.
                const r = await this.api('POST', '/sign/address', {
                    address: this.oceanSignAddress,
                    message: this.oceanSignMessage,
                });
                this.oceanSignSignature = (r && r.signature) || '';
                this.oceanSignFormat = (r && r.format) || '';
            } catch (e) {
                this.oceanSignError = (e && e.message) || 'Signing failed';
            } finally {
                this.oceanSignLoading = false;
                this.$nextTick(() => this.initIcons());
            }
        },

        async copyOceanSignature() {
            if (!this.oceanSignSignature) return;
            await this.copyText(this.oceanSignSignature);
            this.oceanSignCopied = true;
            setTimeout(() => { this.oceanSignCopied = false; }, 2000);
        },
        // Returns a grammatically-correct inbound-capacity warning
        // string when capacity is below the operator-configured
        // threshold (``warn_threshold_sat`` from /bolt12/receive,
        // controlled by BOLT12_RECEIVE_INBOUND_WARN_SATS), or empty
        // string to hide the message. A threshold of 0 disables the
        // warning entirely.
        bolt12InboundCapacityMessage() {
            const il = this.bolt12Receive && this.bolt12Receive.inbound_liquidity;
            if (!il) return '';
            const sats = Number(il.remote_balance_sat || 0);
            const threshold = Number(il.warn_threshold_sat || 0);
            if (threshold <= 0) return '';
            if (sats >= threshold) return '';
            if (sats <= 0) {
                return 'There is no inbound capacity. Payouts will fail '
                    + 'until you have an inbound channel.';
            }
            return 'Inbound capacity is only ' + sats.toLocaleString()
                + ' sats. Payouts larger than this will fail.';
        },
        // Opens the new-offer dialog with the Ocean preset selected
        // by default. Used by the empty-state CTA and the "New offer"
        // button on the Issue tab. Distinct from
        // openBolt12ConfigureReceive() which pre-fills from whatever
        // is already configured.
        openBolt12NewOffer() {
            this.bolt12ReceiveConfigureError = '';
            this.bolt12ReceivePreset = 'ocean';
            this.bolt12ReceiveOceanAddress = '';
            this.bolt12ReceiveCustomDescription = '';
            this.showBolt12ConfigureReceive = true;
            this.$nextTick(() => this.initIcons());
        },
        // CSP-safe preset switcher. Inline multi-statement @click
        // expressions like "preset = 'ocean'; err = ''" don't
        // execute reliably under @alpinejs/csp; this method keeps
        // the buttons reactive.
        setBolt12ReceivePreset(preset) {
            this.bolt12ReceivePreset = preset;
            this.bolt12ReceiveConfigureError = '';
            this.$nextTick(() => this.initIcons());
        },

        // Open the configure-receive modal. Pre-fills the custom
        // description box with whatever's already on the offer so
        // the user can edit incrementally.
        openBolt12ConfigureReceive() {
            this.bolt12ReceiveConfigureError = '';
            this.bolt12ReceivePreset = 'ocean';
            this.bolt12ReceiveOceanAddress = '';
            const cur = this.bolt12Receive && this.bolt12Receive.offer
                ? (this.bolt12Receive.offer.description || '')
                : '';
            // If the current description already looks like an Ocean
            // template, pre-select Ocean and pull out the address.
            const m = cur.match(/^OCEAN Payouts for (\S+)/i);
            if (m) {
                this.bolt12ReceivePreset = 'ocean';
                this.bolt12ReceiveOceanAddress = m[1];
                this.bolt12ReceiveCustomDescription = '';
            } else {
                this.bolt12ReceivePreset = cur ? 'custom' : 'ocean';
                this.bolt12ReceiveCustomDescription = cur;
            }
            this.showBolt12ConfigureReceive = true;
            this.$nextTick(() => this.initIcons());
        },
        // Computed description preview for the modal. Kept as a
        // method (not a getter) so Alpine's CSP evaluator doesn't
        // have to re-track dependencies on every render.
        bolt12ReceiveComputedDescription() {
            if (this.bolt12ReceivePreset === 'ocean') {
                const addr = (this.bolt12ReceiveOceanAddress || '').trim();
                if (!addr) return '';
                return 'OCEAN Payouts for ' + addr;
            }
            return (this.bolt12ReceiveCustomDescription || '').trim();
        },
        // Light validation. We don't enforce checksum/network here —
        // Ocean does its own check. We just guard against obviously
        // wrong inputs (empty, too short, contains whitespace).
        bolt12ReceiveValidationError() {
            const desc = this.bolt12ReceiveComputedDescription();
            if (!desc) return 'Description is required';
            if (desc.length > 640) return 'Description must be 640 characters or fewer';
            if (this.bolt12ReceivePreset === 'ocean') {
                const addr = (this.bolt12ReceiveOceanAddress || '').trim();
                // Bitcoin addresses are 26-90 chars on mainnet/segwit/taproot.
                if (addr.length < 14) return 'Bitcoin address looks too short';
                if (/\s/.test(addr)) return 'Bitcoin address must not contain spaces';
            }
            return '';
        },
        async submitBolt12ConfigureReceive() {
            const err = this.bolt12ReceiveValidationError();
            if (err) {
                this.bolt12ReceiveConfigureError = err;
                return;
            }
            this.bolt12ReceiveConfigureError = '';
            this.bolt12ReceiveConfigureLoading = true;
            try {
                this.bolt12Receive = await this.api(
                    'POST',
                    '/bolt12/receive/configure',
                    { description: this.bolt12ReceiveComputedDescription() },
                );
                this.showBolt12ConfigureReceive = false;
                this.toast = 'Receive offer updated';
                setTimeout(() => { this.toast = ''; }, 2000);
                // Refresh the issued-offers list so the demoted
                // previous default appears in the history without
                // its default badge, and so the new offer drives the
                // upper detail panel.
                if (this.bolt12Receive && this.bolt12Receive.offer && this.bolt12Receive.offer.id) {
                    this.bolt12SelectedOfferId = this.bolt12Receive.offer.id;
                }
                await this.fetchBolt12IssuedOffers();
            } catch (e) {
                this.bolt12ReceiveConfigureError = e.message || 'Update failed';
            }
            this.bolt12ReceiveConfigureLoading = false;
            this.$nextTick(() => this.initIcons());
        },
        // Loads (and on first call, mints) the default receive offer
        // along with inbound-liquidity + gateway-runtime context.
        // The whole Issue tab's top section renders from this one
        // payload.
        // Single-expression wrapper for the Refresh button (the CSP
        // build can't parse two calls separated by ';').
        bolt12RefreshReceive() {
            this.fetchBolt12Receive();
            this.fetchBolt12IssuedOffers();
        },
        async fetchBolt12Receive() {
            this.bolt12ReceiveLoading = true;
            this.bolt12ReceiveError = '';
            // A fresh panel fetch supersedes any inline auto-peer error
            // banner — clear it so a stale message from a previous
            // failed attempt doesn't linger past the refresh.
            this.bolt12AutoPeerError = '';
            try {
                this.bolt12Receive = await this.api('GET', '/bolt12/receive');
            } catch (e) {
                this.bolt12ReceiveError = e.message || 'Failed to load receive offer';
            }
            this.bolt12ReceiveLoading = false;
            this.$nextTick(() => this.initIcons());
        },

        // "Connect to a public node" — iterates the server-side
        // well-known-payers registry and stops at the first
        // successful dial. Powers the inline CTA the receive panel
        // shows alongside the ``no_publicly_routable_om_peer``
        // warning when none of the gateway's onion-message-capable
        // peers have a clearnet address.
        //
        // Three observable outcomes:
        //   1. Dial succeeds → toast "Connected to <peer>", refetch
        //      the receive panel so the warning disappears.
        //   2. Dial succeeds but the new peer doesn't end up in the
        //      candidate set (e.g. doesn't negotiate onion-messages)
        //      → toast still says we connected, but a follow-up
        //      refetch keeps the warning. The user sees the warning
        //      persist with an inline note explaining why.
        //   3. Every dial fails → red inline error under the button.
        async bolt12AutoPeerForReceive() {
            if (this.bolt12AutoPeerLoading) return;
            this.bolt12AutoPeerLoading = true;
            this.bolt12AutoPeerError = '';
            let result = null;
            try {
                result = await this.api(
                    'POST', '/bolt12/receive/auto-peer',
                );
            } catch (e) {
                this.bolt12AutoPeerError = (e && e.message)
                    || 'Couldn’t reach the wallet — try again in a moment.';
                this.bolt12AutoPeerLoading = false;
                return;
            }
            if (!result || !result.connected) {
                // No payer in the registry connected. Surface a
                // friendly, non-jargon message — the registry itself
                // is an implementation detail.
                this.bolt12AutoPeerError = 'Couldn’t reach any of the '
                    + 'suggested public nodes. Check the wallet’s '
                    + 'internet connection and try again.';
                this.bolt12AutoPeerLoading = false;
                return;
            }
            const peer = result.peer || {};
            const label = peer.label || 'public node';
            const verb = peer.already_connected ? 'Already connected to' : 'Connected to';
            this.toast = verb + ' ' + label;
            setTimeout(() => {
                if (this.toast === verb + ' ' + label) this.toast = '';
            }, 3500);
            // Refetch the panel so the warning clears (or, if the new
            // peer didn't actually solve the problem, stays visible
            // with a clear explanation).
            await this.fetchBolt12Receive();
            // If the warning is still present after a successful dial,
            // the gateway connected but the peer didn't satisfy the
            // introduction-node filter (e.g. doesn't negotiate
            // onion-messages in init). Tell the user plainly.
            const stillBad = ((this.bolt12Receive && this.bolt12Receive.warnings) || [])
                .some((w) => w && w.code === 'no_publicly_routable_om_peer');
            if (stillBad) {
                this.bolt12AutoPeerError = 'Connected to ' + label
                    + ', but it doesn’t support BOLT 12 routing. The '
                    + 'wallet operator may need to peer with a different '
                    + 'public node.';
            }
            this.bolt12AutoPeerLoading = false;
        },
        // Promote an existing issued offer to be the default. Then
        // refresh both the receive panel and the issued-offers list.
        async setBolt12DefaultReceive(offerId) {
            if (!offerId) return;
            if (!await this.askConfirm({
                body: 'Make this your default receive offer? Existing payers '
                    + 'using your previous default offer will keep working — '
                    + 'you only need to update payers when you want them to '
                    + 'use the new offer.',
                ok: 'Make default',
            })) return;
            try {
                await this.api('POST', '/bolt12/offers/' + encodeURIComponent(offerId) + '/set-default');
                this.toast = 'Default receive offer updated';
                setTimeout(() => { this.toast = ''; }, 2000);
                await this.fetchBolt12Receive();
                await this.fetchBolt12IssuedOffers();
            } catch (e) {
                this.bolt12Error = e.message || 'Action failed';
            }
        },
        async fetchBolt12Payees() {
            try {
                this.bolt12Payees = await this.api(
                    'GET', '/bolt12/offers?source=imported,paid'
                );
            } catch (e) {
                this.bolt12Error = e.message || 'Failed to load payees';
            }
            this.$nextTick(() => this.initIcons());
        },
        // Inline decode preview for the Pay form. Debounced — we
        // don't want to hammer the codec on every keystroke. Result
        // is shown directly under the textarea so the user can
        // sanity-check the offer before clicking Pay or Save.
        scheduleBolt12PayDecode() {
            if (this.bolt12PayDecodeTimer) clearTimeout(this.bolt12PayDecodeTimer);
            this.bolt12PayDecoded = null;
            this.bolt12PayError = '';
            const offer = (this.bolt12PayForm.offer || '').trim();
            if (!offer) return;
            this.bolt12PayDecodeTimer = setTimeout(async () => {
                this.bolt12PayDecoding = true;
                try {
                    this.bolt12PayDecoded = await this.api(
                        'POST', '/bolt12/decode', { offer }
                    );
                } catch (e) {
                    this.bolt12PayError = e.message || 'Decode failed';
                }
                this.bolt12PayDecoding = false;
            }, 350);
        },
        async saveBolt12Payee() {
            const offer = (this.bolt12PayForm.offer || '').trim();
            if (!offer) {
                this.bolt12PayError = 'Paste an offer string first';
                return;
            }
            this.bolt12SaveLoading = true;
            this.bolt12PayError = '';
            try {
                await this.api('POST', '/bolt12/offers', { offer });
                this.toast = 'Payee saved';
                setTimeout(() => { this.toast = ''; }, 2000);
                await this.fetchBolt12Payees();
            } catch (e) {
                this.bolt12PayError = e.message || 'Save failed';
            }
            this.bolt12SaveLoading = false;
        },
        prefillBolt12Pay(offerString) {
            this.bolt12SubTab = 'pay';
            this.bolt12PayForm.offer = offerString || '';
            this.bolt12PayResult = null;
            this.bolt12PayError = '';
            this.scheduleBolt12PayDecode();
        },
        async removeBolt12Offer(id, kind) {
            // ``kind`` controls the confirm copy + which list to
            // refresh. The backend already branches on the row's
            // source; this is purely UX.
            if (!id) return;
            const issued = kind === 'issued';
            if (!await this.askConfirm({
                body: issued
                    ? 'Disable this offer? The orchestrator will stop accepting new invoice requests against it.'
                    : 'Remove this payee from your address book?',
                ok: issued ? 'Disable offer' : 'Remove payee',
                dangerous: true,
            })) return;
            try {
                await this.api('DELETE', '/bolt12/offers/' + encodeURIComponent(id));
                if (kind === 'issued') await this.fetchBolt12IssuedOffers();
                else await this.fetchBolt12Payees();
            } catch (e) {
                this.bolt12Error = e.message || 'Action failed';
            }
        },
        bolt12AmountSats(msat) {
            if (msat === null || msat === undefined) return '\u2014';
            return Math.floor(Number(msat) / 1000).toLocaleString();
        },
        bolt12RelativeTime(iso) {
            if (!iso) return 'never';
            const t = new Date(iso).getTime();
            if (!Number.isFinite(t)) return 'never';
            const diff = Date.now() - t;
            const sec = Math.floor(diff / 1000);
            if (sec < 60) return 'just now';
            const min = Math.floor(sec / 60);
            if (min < 60) return min + 'm ago';
            const hr = Math.floor(min / 60);
            if (hr < 24) return hr + 'h ago';
            const day = Math.floor(hr / 24);
            if (day < 30) return day + 'd ago';
            return new Date(iso).toLocaleDateString();
        },

        // ── BOLT 12 issue ──
        _formatSatsDisplay(sats) {
            // Up to 3 decimals, no trailing zeros. Empty string for non-finite.
            if (!Number.isFinite(sats)) return '';
            const rounded = Math.round(sats * 1000) / 1000;
            // toFixed(3) then strip trailing zeros and a dangling '.'
            return rounded.toFixed(3).replace(/\.?0+$/, '');
        },
        _convertBolt12IssueAmount(toUnit, fromUnit) {
            // Re-express the *displayed* amount when the user toggles
            // the unit radio. Internal source-of-truth is whatever's
            // in the input field at the moment of the switch.
            if (toUnit === fromUnit) return;
            const raw = this.bolt12IssueAmount;
            if (raw === '' || raw === null || raw === undefined) return;
            const n = Number(raw);
            if (!Number.isFinite(n)) return;
            if (toUnit === 'msats') {
                // sats → msats: multiply by 1000, integer.
                this.bolt12IssueAmount = String(Math.round(n * 1000));
            } else {
                // msats → sats: divide by 1000, up to 3 decimals (no trailing zeros).
                this.bolt12IssueAmount = this._formatSatsDisplay(n / 1000);
            }
        },
        useBolt12IssueSats() {
            this._convertBolt12IssueAmount('sats', this.bolt12IssueAmountUnit);
            this.bolt12IssueAmountUnit = 'sats';
        },
        useBolt12IssueMsats() {
            this._convertBolt12IssueAmount('msats', this.bolt12IssueAmountUnit);
            this.bolt12IssueAmountUnit = 'msats';
        },
        bolt12IssueAmountStep() {
            return this.bolt12IssueAmountUnit === 'sats' ? '0.001' : '1';
        },
        _coerceIssuePayload() {
            // Strip empty strings + coerce numeric fields. Backend
            // pydantic models reject empty strings on optional ints,
            // so we drop them rather than send "".
            const f = this.bolt12IssueForm;
            const out = { description: (this.bolt12IssueDescription || '').trim() };
            // Amount: convert from current display unit to msats.
            const amtRaw = this.bolt12IssueAmount;
            if (amtRaw !== '' && amtRaw !== null && amtRaw !== undefined) {
                const n = Number(amtRaw);
                if (Number.isFinite(n)) {
                    const msat = this.bolt12IssueAmountUnit === 'sats'
                        ? Math.round(n * 1000)
                        : Math.trunc(n);
                    if (msat > 0) out.amount_msat = msat;
                }
            }
            const num = (k) => {
                const v = f[k];
                if (v === '' || v === null || v === undefined) return;
                const n = Number(v);
                if (Number.isFinite(n)) out[k] = Math.trunc(n);
            };
            num('quantity_max');
            num('absolute_expiry');
            const str = (k) => {
                const v = (f[k] || '').trim();
                if (v) out[k] = v;
            };
            str('currency');
            str('issuer');
            return out;
        },
        async issueBolt12Offer() {
            this.bolt12IssueError = '';
            this.bolt12IssueResult = null;
            const payload = this._coerceIssuePayload();
            if (!payload.description) {
                this.bolt12IssueError = 'Description is required';
                return;
            }
            this.bolt12IssueLoading = true;
            try {
                this.bolt12IssueResult = await this.api(
                    'POST', '/bolt12/offers/issue', payload
                );
                this.toast = 'Offer issued';
                setTimeout(() => { this.toast = ''; }, 2000);
                // Refresh the issued-offers history so the new row appears.
                await this.fetchBolt12IssuedOffers();
            } catch (e) {
                this.bolt12IssueError = e.message || 'Issue failed';
            }
            this.bolt12IssueLoading = false;
        },
        resetBolt12IssueForm() {
            this.bolt12IssueForm = {
                currency: '', issuer: '',
                quantity_max: '', absolute_expiry: '',
            };
            this.bolt12IssueDescription = '';
            this.bolt12IssueAmount = '';
            this.bolt12IssueResult = null;
            this.bolt12IssueError = '';
            this.bolt12IssueAmountUnit = 'sats';
        },

        // ── BOLT 12 pay ──
        _coercePayPayload() {
            const f = this.bolt12PayForm;
            const out = { offer: (f.offer || '').trim() };
            const num = (k) => {
                const v = f[k];
                if (v === '' || v === null || v === undefined) return;
                const n = Number(v);
                if (Number.isFinite(n)) out[k] = Math.trunc(n);
            };
            num('amount_msat');
            num('quantity');
            const note = (f.payer_note || '').trim();
            if (note) out.payer_note = note;
            return out;
        },
        async payBolt12Offer() {
            this.bolt12PayError = '';
            this.bolt12PayResult = null;
            const payload = this._coercePayPayload();
            if (!payload.offer) {
                this.bolt12PayError = 'Paste an offer string first';
                return;
            }
            this.bolt12PayLoading = true;
            try {
                this.bolt12PayResult = await this.api(
                    'POST', '/bolt12/pay', payload
                );
                this.toast = 'Invoice received — copy it to a BOLT 12 wallet to pay';
                setTimeout(() => { this.toast = ''; }, 4000);
                // Pay flow upserts the offer into the payees list —
                // refresh so it appears (or its last-paid bumps).
                await this.fetchBolt12Payees();
            } catch (e) {
                this.bolt12PayError = e.message || 'Pay failed';
            }
            this.bolt12PayLoading = false;
        },
        resetBolt12PayForm() {
            this.bolt12PayForm = {
                offer: '', amount_msat: '', quantity: '', payer_note: '',
            };
            this.bolt12PayResult = null;
            this.bolt12PayError = '';
            this.bolt12PayDecoded = null;
        },

        // ── Formatters ──
        formatSats(sats) { return Number(sats || 0).toLocaleString(); },
        formatBtc(sats) { return (Number(sats || 0) / 100_000_000).toFixed(8); },
        formatDate(ts) {
            if (!ts) return '\u2014';
            return new Date(ts * 1000).toLocaleDateString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
        },
        // Compact "5m / 3h / 12d ago" style label for unix-second
        // timestamps. Used by per-channel "Last used" tags.
        formatRelativeTime(ts) {
            if (!ts) return '\u2014';
            const diff = Math.max(0, Math.floor(Date.now() / 1000) - Number(ts));
            if (diff < 60) return 'just now';
            if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
            if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
            if (diff < 30 * 86400) return Math.floor(diff / 86400) + 'd ago';
            if (diff < 365 * 86400) return Math.floor(diff / (30 * 86400)) + 'mo ago';
            return Math.floor(diff / (365 * 86400)) + 'y ago';
        },
        totalBalance() {
            const onchain = (this.summary?.onchain?.confirmed_balance || 0) + (this.summary?.onchain?.unconfirmed_balance || 0);
            const lightning = this.summary?.lightning?.local_balance_sat || 0;
            return onchain + lightning;
        },
        mempoolTxUrl(txid) {
            const base = (this.mempoolBaseUrl || 'https://mempool.space').replace(/\/+$/, '');
            return base + '/tx/' + txid;
        },

        // ── Clipboard ──
        // Copy text to the clipboard with a fallback for non-secure contexts.
        // ``navigator.clipboard`` only exists in a secure context (HTTPS or
        // localhost); when the dashboard is served over plain HTTP on the LAN
        // (e.g. Umbrel at http://<device>.local) it is undefined, so we fall
        // back to a hidden-textarea + ``document.execCommand('copy')``. Returns
        // true on (attempted) success, false if copying isn't possible.
        _copyToClipboard(text) {
            const value = String(text == null ? '' : text);
            try {
                if (navigator.clipboard && navigator.clipboard.writeText) {
                    // Async; fall back if the browser rejects (permissions, etc.).
                    navigator.clipboard.writeText(value).catch(() => this._execCopyFallback(value));
                    return true;
                }
            } catch (_e) {
                // Fall through to the execCommand path.
            }
            return this._execCopyFallback(value);
        },
        _execCopyFallback(value) {
            try {
                const ta = document.createElement('textarea');
                ta.value = value;
                ta.setAttribute('readonly', '');
                ta.style.position = 'fixed';
                ta.style.top = '-9999px';
                ta.style.left = '-9999px';
                document.body.appendChild(ta);
                ta.select();
                ta.setSelectionRange(0, value.length);
                const ok = document.execCommand('copy');
                document.body.removeChild(ta);
                return ok;
            } catch (_e) {
                return false;
            }
        },
        copyText(text) {
            this._copyToClipboard(text);
            this.toast = 'Copied!';
            setTimeout(() => this.toast = '', 2000);
            this.initIcons();
        },

        // ── Runtime config (injected by template as a JSON island) ──
        // Read once at init() so we don't re-parse on every link
        // render. Falls back gracefully if the script tag is missing
        // (e.g. when the JS is loaded outside the dashboard template
        // during tests).
        mempoolBaseUrl: 'https://mempool.space',

        _loadRuntimeConfig() {
            try {
                const el = document.getElementById('dashboard-config');
                if (!el) return;
                const cfg = JSON.parse(el.textContent || '{}');
                if (cfg && typeof cfg.mempool_public_url === 'string' && cfg.mempool_public_url) {
                    this.mempoolBaseUrl = cfg.mempool_public_url;
                }
                if (cfg && typeof cfg.braiins_deposit_enabled === 'boolean') {
                    this.braiinsDepositEnabled = cfg.braiins_deposit_enabled;
                }
                if (cfg && typeof cfg.anonymize_enabled === 'boolean') {
                    this.anonymizeEnabled = cfg.anonymize_enabled;
                }
                if (cfg && typeof cfg.tip_lightning_address === 'string') {
                    this.tipAddress = cfg.tip_lightning_address;
                }
            } catch (_e) {
                // Bad JSON — keep the default. Don't block boot.
            }
        },

        // ── BOLT 12 helpers ──
        // Translate a raw Bolt12InvoiceStatus enum value into prose
        // the user can act on. ``open`` from a pay-flow row means
        // "we got an invoice but did not actually send the HTLC" —
        // the wallet does not send the HTLC for BOLT 12 pay-flows, so
        // the user completes the payment elsewhere.
        bolt12FriendlyStatus(status) {
            switch (status) {
                case 'open': return 'Invoice received (not yet paid)';
                case 'paid': return 'Paid';
                case 'expired': return 'Expired';
                case 'failed': return 'Failed';
                default: return status || '—';
            }
        },
        copyBolt12Invoice(text) {
            this.copyText(text);
        },

        // ── Fund Wallet ──
        async generateAddress() {
            this.fundLoading = true;
            this.fundError = '';
            this.fundAddress = '';
            this.fundCopied = false;
            try {
                const data = await this.api('POST', '/address', { address_type: this.fundAddrType, purpose: this.fundPurpose || '' });
                this.fundAddress = data.address;
                this.$nextTick(() => {
                    this.renderQr(this.$refs.fundQr, 'bitcoin:' + this.fundAddress);
                    this.initIcons();
                });
            } catch (e) {
                this.fundError = e.message;
            }
            this.fundLoading = false;
        },
        fundCopyAddress() {
            if (!this.fundAddress) return;
            this._copyToClipboard(this.fundAddress);
            this.fundCopied = true;
            setTimeout(() => this.fundCopied = false, 2500);
            this.initIcons();
        },

        // ── Send Payment ──
        get payInputType() {
            const t = this.payInvoice.trim();
            if (!t) return '';
            if (/^ln(bc|tb|tbs|bcrt)[a-z0-9]+$/i.test(t)) return 'bolt11';
            if (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(t)) return 'lnaddr';
            if (/^lnurl[a-z0-9]+$/i.test(t)) return 'lnurl';
            return 'unknown';
        },
        get payInvoiceExpired() {
            if (!this.decodedInvoice) return false;
            return (this.decodedInvoice.timestamp + this.decodedInvoice.expiry) * 1000 < Date.now();
        },
        get payExpiresAt() {
            if (!this.decodedInvoice) return '\u2014';
            const d = new Date((this.decodedInvoice.timestamp + this.decodedInvoice.expiry) * 1000);
            return d.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
        },
        async pasteInvoice() {
            try {
                const text = await navigator.clipboard.readText();
                if (text) {
                    this.payInvoice = text.trim().replace(/^lightning:/i, '');
                    this.decodedInvoice = null;
                    this.payResult = null;
                    this.payError = '';
                    this._resetLnurlState();
                }
            } catch (e) {}
        },
        async decodeInvoice() {
            this.payLoading = true;
            this.payError = '';
            try {
                this.decodedInvoice = await this.api('POST', '/decode', { payment_request: this.payInvoice.trim() });
                this.$nextTick(() => this.initIcons());
            } catch (e) {
                this.payError = e.message || 'Failed to decode invoice. Check the format and try again.';
            }
            this.payLoading = false;
        },
        async sendPayment() {
            this.payLoading = true;
            this.payError = '';
            try {
                const body = {
                    payment_request: this.payInvoice.trim(),
                    fee_limit_sats: this.payEffectiveFeeLimitSats(),
                    timeout_seconds: this.payTimeoutSeconds || 60,
                };
                if (this.pay.source && this.pay.source.chan_id) {
                    body.outgoing_chan_id = String(this.pay.source.chan_id);
                }
                const data = await this.api('POST', '/pay', body);
                this.payResult = {
                    success: true,
                    hash: data.payment_hash,
                    fees: data.payment_route?.total_fees,
                    hops: data.payment_route?.hops,
                };
                this.fetchSummary();
                this.fetchPayments();
                this.$nextTick(() => this.initIcons());
            } catch (e) {
                this.payResult = {
                    success: false,
                    error: e.message || 'Payment failed',
                };
                this.$nextTick(() => this.initIcons());
            }
            this.payLoading = false;
        },
        resetSendPayment() {
            this.payInvoice = '';
            this.decodedInvoice = null;
            this.payResult = null;
            this.payError = '';
            this.payResetAdvanced();
            this._resetLnurlState();
            this.$nextTick(() => this.initIcons());
        },
        _resetLnurlState() {
            this.lnurlState = 'idle';
            this.lnurlError = '';
            this.lnurlParams = null;
            this.lnurlAmountSats = 0;
            this.lnurlAmountStr = '';
            this.lnurlComment = '';
            this.lnurlSuccessAction = null;
        },
        // ── LNURL / Lightning Address ──
        // Step 1: resolve the recipient → recipient card.
        async resolveLnurl() {
            const t = this.payInvoice.trim();
            if (!t) return;
            this.lnurlError = '';
            this.lnurlState = 'resolving';
            try {
                const data = await this.api('POST', '/lnurl/resolve', { text: t });
                this.lnurlParams = data;
                // Default amount: min sendable (rounded up). Many recipients
                // set min=1 sat so this lets the user immediately Continue.
                const minSats = Number(data.min_sendable_sats || 1);
                const maxSats = Number(data.max_sendable_sats || minSats);
                let defaultAmount = minSats;
                if (minSats === maxSats) {
                    // Fixed-amount recipient (e.g. paywall): pin the field.
                    defaultAmount = minSats;
                }
                this.lnurlAmountSats = defaultAmount;
                this.lnurlAmountStr = String(defaultAmount);
                this.lnurlComment = '';
                this.lnurlState = 'resolved';
                this.$nextTick(() => this.initIcons());
            } catch (e) {
                this.lnurlState = 'error';
                this.lnurlError = e.message || 'Failed to resolve recipient';
                this.$nextTick(() => this.initIcons());
            }
        },
        // Step 2: ask the recipient for a BOLT11 at the chosen amount.
        // On success we plug the BOLT11 into the existing /decode →
        // review flow so the user gets the same confirmation screen
        // as a pasted invoice (description, expiry, fee limit).
        async requestLnurlInvoice() {
            if (!this.lnurlParams) return;
            const amount = parseInt(this.lnurlAmountStr, 10);
            if (!Number.isFinite(amount) || amount <= 0) {
                this.lnurlError = 'Enter a valid amount in sats';
                return;
            }
            const minSats = Number(this.lnurlParams.min_sendable_sats || 0);
            const maxSats = Number(this.lnurlParams.max_sendable_sats || 0);
            if (amount < minSats || amount > maxSats) {
                this.lnurlError = 'Amount must be between ' + minSats + ' and ' + maxSats + ' sats';
                return;
            }
            this.lnurlError = '';
            this.lnurlState = 'requesting';
            try {
                const data = await this.api('POST', '/lnurl/invoice', {
                    handle: this.lnurlParams.handle,
                    amount_sats: amount,
                    comment: this.lnurlComment || '',
                });
                // Stash the success_action for display after pay.
                this.lnurlSuccessAction = data.success_action || null;
                // Replace the paste field with the BOLT11 so the
                // existing review/sendPayment path takes over.
                this.payInvoice = data.payment_request;
                this.lnurlState = 'ready';
                await this.decodeInvoice();
            } catch (e) {
                this.lnurlState = 'resolved';
                this.lnurlError = e.message || 'Failed to request invoice';
                this.$nextTick(() => this.initIcons());
            }
        },
        // Cancel the recipient card and return to the paste field.
        backFromLnurl() {
            this._resetLnurlState();
            this.payInvoice = '';
            this.$nextTick(() => this.initIcons());
        },
        get lnurlAmountFixed() {
            if (!this.lnurlParams) return false;
            return Number(this.lnurlParams.min_sendable_sats) === Number(this.lnurlParams.max_sendable_sats);
        },
        get lnurlCommentMax() {
            if (!this.lnurlParams) return 0;
            const allowed = Number(this.lnurlParams.comment_allowed || 0);
            return allowed > 280 ? 280 : allowed;
        },
        closeSendPayment() {
            this.showSendPayment = false;
            this.resetSendPayment();
        },

        // ── Tip the developer ────────────────────────────────────
        // Subtle "buy me a coffee" flow. Opens a small amount picker
        // pre-loaded with the developer's Lightning Address; the
        // chosen amount is then handed off to the standard LNURL
        // pipeline (resolveLnurl → recipient card → pay) so audit
        // logging, fee limits and the dashboard payment cap all
        // apply identically to a tip. No special-case backend
        // route — the address is just a normal LUD-16 recipient.
        openTipDialog() {
            this.tipAmountStr = '5000';
            this.tipComment = '';
            this.showTipDialog = true;
            this.$nextTick(() => this.initIcons());
        },
        closeTipDialog() {
            this.showTipDialog = false;
        },
        tipSelectPreset(sats) {
            this.tipAmountStr = String(sats);
        },
        // CSP-build expression helpers — Alpine's CSP parser doesn't
        // expose globals like ``parseInt`` to inline expressions.
        tipAmountValue() {
            const n = parseInt(this.tipAmountStr, 10);
            return Number.isFinite(n) ? n : 0;
        },
        tipPresetActive(p) {
            return this.tipAmountValue() === p;
        },
        tipCanContinue() {
            return this.tipAmountValue() > 0;
        },
        async continueToTipPayment() {
            const amt = parseInt(this.tipAmountStr, 10);
            if (!Number.isFinite(amt) || amt <= 0) return;
            const comment = this.tipComment || '';
            const address = this.tipAddress;
            this.showTipDialog = false;
            // Wire into the existing send-payment flow exactly as if
            // the operator had pasted the address by hand.
            this.resetSendPayment();
            this.payInvoice = address;
            this.showSendPayment = true;
            await this.$nextTick();
            await this.resolveLnurl();
            // The tip dialog already collected the amount + comment, so
            // prefill them and skip the redundant LNURL recipient-card
            // review — go straight to the final confirmation (fee tweak +
            // send). ``requestLnurlInvoice`` re-validates the amount
            // against the recipient's min/max; if it's out of range it
            // leaves us on the recipient card with an error so the user
            // can adjust. For a fixed-amount recipient we keep the card
            // (the chosen tip amount can't apply), which is vanishingly
            // rare for a Lightning Address.
            if (this.lnurlState === 'resolved') {
                if (this.lnurlCommentMax > 0 && comment) {
                    this.lnurlComment = comment.slice(0, this.lnurlCommentMax);
                }
                if (!this.lnurlAmountFixed) {
                    this.lnurlAmountStr = String(amt);
                    await this.requestLnurlInvoice();
                }
            }
            this.$nextTick(() => this.initIcons());
        },

        // ── Send Payment — advanced controls ─────────────────────
        // Mirrors the rebalance dialog: fee-limit %/sats toggle with
        // live ≈sats hint, optional source-channel pin via an
        // accordion, and an explicit Estimate-fee probe. Shared by
        // both the BOLT 11 and LNURL flows because the LNURL invoice
        // ultimately becomes a BOLT 11 payment.

        // Single source of truth for "what amount are we about to
        // send right now?". For BOLT 11, the decoded invoice's
        // num_satoshis. For LNURL, the user's typed amount before
        // the invoice has arrived.
        payAmountSats() {
            if (this.decodedInvoice && Number(this.decodedInvoice.num_satoshis) > 0) {
                return Number(this.decodedInvoice.num_satoshis);
            }
            const lnurlAmt = parseInt(this.lnurlAmountStr, 10);
            if (Number.isFinite(lnurlAmt) && lnurlAmt > 0) return lnurlAmt;
            return 0;
        },

        // Resolve fee limit to flat sats. Floored at 1 sat so a
        // tiny percentage on a small amount doesn't hand LND a
        // 0-sat cap (which it interprets as "no fee allowed").
        payEffectiveFeeLimitSats() {
            const p = this.pay;
            if (p.feeLimitMode === 'percent') {
                const amt = this.payAmountSats();
                const pct = Number(p.feeLimitPercent);
                if (!Number.isFinite(pct) || pct < 0) return 0;
                if (amt <= 0) return Math.max(0, parseInt(p.feeLimitSats, 10) || 0);
                return Math.max(1, Math.ceil(amt * pct / 100));
            }
            const sats = parseInt(p.feeLimitSats, 10);
            return Number.isFinite(sats) && sats >= 0 ? sats : 0;
        },

        _recomputePayFeeLimitApproxSats() {
            this.pay.feeLimitApproxSats = this.payEffectiveFeeLimitSats();
        },

        // Toggle %/sats fee mode while preserving the rendered
        // value across the switch (matches rebalanceSetFeeMode).
        paySetFeeMode(mode) {
            const p = this.pay;
            if (mode === p.feeLimitMode) return;
            const amt = this.payAmountSats();
            if (mode === 'percent' && amt > 0) {
                const sats = parseInt(p.feeLimitSats, 10) || 0;
                p.feeLimitPercent = Math.round((sats / amt) * 100 * 100) / 100;
                this.payFeeLimitPercent = p.feeLimitPercent;
            } else if (mode === 'sats') {
                p.feeLimitSats = this.payEffectiveFeeLimitSats();
                this.payFeeLimitSats = p.feeLimitSats;
            }
            p.feeLimitMode = mode;
            this._recomputePayFeeLimitApproxSats();
            this.pay.quote = null;          // any fee change invalidates the route quote
            this.pay.quoteError = '';
        },

        // Eligible source channels for an outbound payment: active,
        // online, with non-zero local headroom. Filtered by search
        // string and (optionally) by the current amount.
        paySourceCandidates() {
            const all = (this.channels || []).filter(c => c.active);
            const amt = this.payAmountSats();
            const search = (this.pay.sourceSearch || '').trim().toLowerCase();
            const filtered = all.filter(c => {
                const sendable = this.rebalanceMaxSendable(c);
                if (!this.pay.sourceShowAll && amt > 0 && sendable < amt) return false;
                if (!this.pay.sourceShowAll && sendable < 1000) return false;
                if (!search) return true;
                const alias = (c.peer_alias || '').toLowerCase();
                const pk = (c.remote_pubkey || '').toLowerCase();
                return alias.includes(search) || pk.startsWith(search);
            });
            const sortBy = this.pay.sourceSortBy;
            return filtered.slice().sort((a, b) => {
                if (sortBy === 'alias') {
                    return (a.peer_alias || '').localeCompare(b.peer_alias || '');
                }
                if (sortBy === 'local_asc') {
                    return this.rebalanceMaxSendable(a) - this.rebalanceMaxSendable(b);
                }
                // 'local_desc' — most local liquidity first.
                return this.rebalanceMaxSendable(b) - this.rebalanceMaxSendable(a);
            });
        },

        paySelectSource(ch) {
            this.pay.source = ch;
            this.pay.sourceOpen = false;
            this.pay.quote = null;
            this.pay.quoteError = '';
        },

        payClearSource() {
            this.pay.source = null;
            this.pay.quote = null;
            this.pay.quoteError = '';
        },

        // Max button on the LNURL amount input. Clamps to recipient
        // max-sendable and (when a source is pinned) the source's
        // outbound headroom.
        lnurlSetMax() {
            if (!this.lnurlParams) return;
            let max = Number(this.lnurlParams.max_sendable_sats) || 0;
            if (this.pay.source) {
                max = Math.min(max, this.rebalanceMaxSendable(this.pay.source));
            }
            if (max > 0) this.lnurlAmountStr = String(max);
        },

        // Probe a route via /pay/quote. Read-only; does not commit
        // a payment. Mirrors rebalance's explicit Probe behaviour.
        async payEstimateRoute() {
            if (!this.payInvoice || !this.payInvoice.trim()) return;
            this.pay.quoting = true;
            this.pay.quote = null;
            this.pay.quoteError = '';
            try {
                const body = {
                    payment_request: this.payInvoice.trim(),
                    fee_limit_sats: Math.max(this.payEffectiveFeeLimitSats(), 1),
                };
                if (this.pay.source && this.pay.source.chan_id) {
                    body.outgoing_chan_id = String(this.pay.source.chan_id);
                }
                const data = await this.api('POST', '/pay/quote', body);
                if (data.ok) {
                    this.pay.quote = data;
                } else if (data.no_route) {
                    this.pay.quoteError = data.detail || 'No route found';
                } else {
                    this.pay.quoteError = 'Could not estimate route';
                }
            } catch (e) {
                this.pay.quoteError = e.message || 'Could not estimate route';
            }
            this.pay.quoting = false;
            this.$nextTick(() => this.initIcons());
        },

        // Inline-handler shims. The Alpine CSP-build parser rejects
        // both multi-statement `;` expressions and property
        // assignments, so any non-trivial @click / @input must call
        // a method instead.
        clearPayInvoiceState() {
            this.decodedInvoice = null;
            this.payError = '';
            this.lnurlError = '';
        },
        togglePaySourceAccordion() {
            this.pay.sourceOpen = !this.pay.sourceOpen;
        },
        // Truthy helper for the route-quote display. Avoids
        // ``pay.quote && pay.quote.route`` template expressions which
        // the CSP parser sometimes mis-evaluates when ``pay.quote``
        // transitions from object → null mid-render.
        payQuoteRoute() {
            const q = this.pay && this.pay.quote;
            return q && q.route ? q.route : null;
        },

        // Reset the advanced section back to defaults. Called when
        // the dialog closes or the user clicks "New payment".
        payResetAdvanced() {
            this.pay.feeLimitMode = 'sats';
            this.pay.feeLimitPercent = 0.5;
            this.pay.feeLimitSats = 100;
            this.pay.feeLimitApproxSats = 100;
            this.pay.timeoutSeconds = 60;
            this.pay.sourceOpen = false;
            this.pay.sourceSearch = '';
            this.pay.sourceSortBy = 'local_desc';
            this.pay.sourceShowAll = false;
            this.pay.source = null;
            this.pay.quote = null;
            this.pay.quoting = false;
            this.pay.quoteError = '';
            this.payFeeLimitPercent = 0.5;
            this.payFeeLimitSats = 100;
            this.payTimeoutSeconds = 60;
        },

        // ── Receive Invoice ──
        async createInvoice() {
            this.recvLoading = true;
            this.recvError = '';
            this._stopRecvPolling();
            this.recvPaid = false;
            this.recvPaidAmountSats = 0;
            this.recvPaidDisplaySats = 0;
            try {
                const amount = this.recvAmountStr ? parseInt(this.recvAmountStr, 10) : 0;
                this.createdInvoice = await this.api('POST', '/invoice', {
                    amount_sats: amount,
                    memo: this.recvMemo,
                    expiry: this.recvExpiry,
                });
                this.$nextTick(() => {
                    this.renderQr(this.$refs.recvQr, this.createdInvoice.payment_request.toUpperCase());
                    this.initIcons();
                });
                this._startRecvPolling();
            } catch (e) {
                this.recvError = e.message;
            }
            this.recvLoading = false;
        },

        // Polls the new ``/invoice/{r_hash}`` lookup at ~1.5 s while the
        // Receive dialog is open. We stop on the first SETTLED state
        // (success path), CANCELED (invoice expired or operator
        // cancelled), or any transport error — the latter to avoid
        // hammering LND when something upstream is broken. Polling is
        // also cleared by ``resetReceiveInvoice`` / ``closeReceiveInvoice``.
        _startRecvPolling() {
            if (!this.createdInvoice || !this.createdInvoice.r_hash) return;
            const rHash = this.createdInvoice.r_hash;
            this._stopRecvPolling();
            this._poll('recvInvoice', async () => {
                // If the user closed the dialog or generated a fresh
                // invoice underneath us, bail. Each createInvoice call
                // resets ``createdInvoice.r_hash``, so a tick scheduled
                // for the previous invoice would otherwise race.
                if (!this.createdInvoice || this.createdInvoice.r_hash !== rHash || !this.showReceiveInvoice) {
                    this._stopRecvPolling();
                    return;
                }
                try {
                    const inv = await this.api('GET', '/invoice/' + encodeURIComponent(rHash));
                    if (!inv) return;
                    if (inv.state === 'SETTLED' || inv.settled) {
                        this._stopRecvPolling();
                        this._onInvoiceSettled(inv);
                    } else if (inv.state === 'CANCELED') {
                        this._stopRecvPolling();
                    }
                } catch (e) {
                    // Transport error — stop polling; the user can hit
                    // "New Invoice" to retry.
                    this._stopRecvPolling();
                }
            }, { intervalMs: 1500, immediate: false });
        },

        _stopRecvPolling() {
            this._stopPoll('recvInvoice');
            if (this._recvCountUpRaf) {
                cancelAnimationFrame(this._recvCountUpRaf);
                this._recvCountUpRaf = null;
            }
        },

        _onInvoiceSettled(inv) {
            const paid = Math.max(0, parseInt(inv.amt_paid_sat, 10) || 0);
            this.recvPaidAmountSats = paid;
            this.recvPaid = true;
            // Refresh the wallet summary so the new balance is reflected
            // without waiting for the next 30 s tick.
            this.fetchSummary();
            this.fetchInvoices();
            // Re-hydrate Lucide icons in the newly-rendered success view
            // and then run the sats count-up.
            this.$nextTick(() => {
                this.initIcons();
                this._animateSatsCountUp(paid, 900);
            });
        },

        // requestAnimationFrame-based count from 0 → ``target`` over
        // ``durationMs`` with an ease-out cubic so the last few sats
        // tick in slowly. Skipped for zero-amount (open-amount) invoices
        // where there's nothing to count.
        _animateSatsCountUp(target, durationMs) {
            if (target <= 0) { this.recvPaidDisplaySats = 0; return; }
            const start = performance.now();
            const step = (now) => {
                const t = Math.min(1, (now - start) / durationMs);
                const eased = 1 - Math.pow(1 - t, 3);
                this.recvPaidDisplaySats = Math.round(target * eased);
                if (t < 1) {
                    this._recvCountUpRaf = requestAnimationFrame(step);
                } else {
                    this.recvPaidDisplaySats = target;
                    this._recvCountUpRaf = null;
                }
            };
            this._recvCountUpRaf = requestAnimationFrame(step);
        },

        // Spark fan-out — each spark is rotated to its own angle on
        // the parent wrapper, then a CSS keyframe slides it outward.
        // Inline ``transform: rotate(...)`` driven by Alpine because
        // generating eight bespoke keyframes per angle would be noisy
        // and locks the count at build time.
        recvSparkStyle(i) {
            return { transform: 'rotate(' + (i * 45) + 'deg)', transformOrigin: 'center center' };
        },

        recvCopyInvoice() {
            if (!this.createdInvoice) return;
            this._copyToClipboard(this.createdInvoice.payment_request);
            this.recvCopied = true;
            setTimeout(() => this.recvCopied = false, 2500);
            this.initIcons();
        },
        resetReceiveInvoice() {
            this._stopRecvPolling();
            this.createdInvoice = null;
            this.recvCopied = false;
            this.recvAmountStr = '';
            this.recvMemo = '';
            this.recvError = '';
            this.recvPaid = false;
            this.recvPaidAmountSats = 0;
            this.recvPaidDisplaySats = 0;
            this.$nextTick(() => this.initIcons());
        },
        closeReceiveInvoice() {
            this.showReceiveInvoice = false;
            this.resetReceiveInvoice();
        },

        // ── Cold Storage ──
        isValidBtcAddress(addr) {
            if (!addr) return false;
            const t = addr.trim();
            if (/^bc1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{25,87}$/i.test(t)) return true;
            if (/^1[1-9A-HJ-NP-Za-km-z]{25,34}$/.test(t)) return true;
            if (/^3[1-9A-HJ-NP-Za-km-z]{25,34}$/.test(t)) return true;
            return false;
        },
        getAddressType(addr) {
            if (!addr) return '';
            const t = addr.trim();
            if (/^bc1p/i.test(t)) return 'Taproot (P2TR)';
            if (/^bc1q/i.test(t)) return 'Native SegWit (P2WPKH)';
            if (/^3/.test(t)) return 'SegWit (P2SH)';
            if (/^1/.test(t)) return 'Legacy (P2PKH)';
            return 'Unknown';
        },
        _coldEstimateTimeout: null,
        debounceColdEstimate() {
            clearTimeout(this._coldEstimateTimeout);
            this._coldEstimateTimeout = setTimeout(() => this.autoEstimateColdFee(), 500);
        },
        // Fee-priority picker handler. A single method so the @click is
        // one expression — the @alpinejs/csp build's parser rejects
        // multi-statement directives ("a = b; c()"). Shared by the
        // Send-On-Chain and Cold-Storage fee-priority buttons.
        coldSelectFeePriority(v) {
            this.coldFeePriority = v;
            this.debounceColdEstimate();
        },
        async autoEstimateColdFee() {
            if (!this.isValidBtcAddress(this.coldAddress) || !this.coldAmount || this.coldAmount < 546) return;
            const targetConf = this.coldFeePriority === 'high' ? 1 : this.coldFeePriority === 'medium' ? 3 : 6;
            try {
                const body = {
                    address: this.coldAddress,
                    amount_sats: this.coldAmount,
                    target_conf: targetConf,
                };
                const ops = this._currentSendOutpoints();
                if (ops) body.outpoints = ops;
                this.coldEstimate = await this.api('POST', '/estimate-fee', body);
            } catch (e) {
                this.coldEstimate = null;
            }
        },
        async sendColdOnchain() {
            this.coldLoading = true;
            this.coldError = '';
            try {
                const feeRate = this.fees ? this.fees[this.coldFeePriority === 'high' ? 'fastestFee' : (this.coldFeePriority === 'medium' ? 'halfHourFee' : 'hourFee')] : undefined;
                // Audit label differentiates the entry point so operators
                // can tell at a glance whether a withdrawal originated
                // from the Cold Storage flow or the generic Send dialog.
                const label = this.showSendOnchain ? 'On-chain send (dashboard)' : 'Cold storage withdrawal';
                const body = {
                    address: this.coldAddress,
                    amount_sats: this.coldAmount,
                    sat_per_vbyte: feeRate || undefined,
                    label,
                };
                const ops = this._currentSendOutpoints();
                if (ops) body.outpoints = ops;
                const data = await this.api('POST', '/send-onchain', body);
                this.coldResultData = { success: true, txid: data.txid };
                this.coldStep = 'result';
                this.fetchSummary();
                // Refresh the transactions + UTXO lists immediately so the
                // newly-broadcast tx appears in the On-chain tab the
                // moment the user closes this dialog. Without these the
                // user sees a stale list until the next 30 s periodic
                // ``fetchSummary`` tick and wonders if their send
                // actually went through.
                this.fetchTransactions();
                this.loadUtxos();
                // Track confirmations live when chain backend is up.
                this.startTxConfPoll(data.txid);
            } catch (e) {
                this.coldResultData = { success: false, error: e.message || 'Transaction failed' };
                this.coldStep = 'result';
            }
            this.coldLoading = false;
        },
        async fetchBoltzFees() {
            try {
                this.boltzFees = await this.api('GET', '/cold-storage/fees');
            } catch (e) {}
            // Drives the inbound wizard's three-state form. Set
            // *after* the try/catch so the inbound dialog can
            // distinguish "still loading" (flag false) from
            // "fetch failed" (flag true, fees still at sentinel).
            this._boltzFeesFetched = true;
        },
        async fetchSwapHistory() {
            try {
                this.swapHistory = await this.api('GET', '/cold-storage/swaps?limit=10');
            } catch (e) {}
        },
        async initiateBoltzSwap() {
            this.coldLoading = true;
            try {
                const data = await this.api('POST', '/cold-storage/initiate', {
                    amount_sats: this.coldBoltzAmount,
                    destination_address: this.coldBoltzAddress,
                    purpose: 'cold_storage',
                });
                this.activeSwapId = data.id;
                this.activeSwapStatus = data.status;
                // Pin the swap-id to localStorage so a refresh
                // mid-swap (or a browser crash) resumes the
                // progress view rather than losing the in-flight
                // UI. ``_restoreColdSwap()`` reads this on init;
                // ``pollSwapStatus`` / cancel / completion paths
                // clear it on terminal status.
                try {
                    if (this.activeSwapId) {
                        sessionStorage.setItem(COLD_LOCALSTORAGE_KEY, this.activeSwapId);
                    }
                } catch (_e) { /* private mode — non-fatal */ }
                this.coldStep = 'progress';
                this.startSwapPoll();
            } catch (e) {
                this.coldResultData = { success: false, error: e.message };
                this.coldStep = 'result';
            }
            this.coldLoading = false;
        },
        startSwapPoll() {
            this.stopSwapPoll();
            this._poll('coldSwap', () => this.pollSwapStatus(),
                { intervalMs: 5000, immediate: false });
        },
        stopSwapPoll() {
            this._stopPoll('coldSwap');
        },

        // Generic confirmation poller used by send-onchain
        // and consolidate result views. No-op when the chain backend
        // can't answer (``available: false``).
        startTxConfPoll(txid) {
            if (!txid || this._isPolling('txconf:' + txid)) return;
            this._poll('txconf:' + txid, async () => {
                try {
                    const data = await this.api('GET', '/tx/' + txid + '/confirmations');
                    this.txConfs = { ...this.txConfs, [txid]: data };
                    if (data && data.confirmed && data.confirmations >= 6) {
                        this.stopTxConfPoll(txid);
                    }
                } catch (_) { /* keep silent — best-effort */ }
            }, { intervalMs: 15000, immediate: true });
        },
        stopTxConfPoll(txid) {
            this._stopPoll('txconf:' + txid);
        },
        async pollSwapStatus() {
            if (!this.activeSwapId) return;
            let data;
            try {
                data = await this.api('GET', '/cold-storage/swaps/' + this.activeSwapId);
            } catch (e) {
                // 404 — the swap was purged or never existed on
                // this backend. Stop polling and route to a clean
                // failure view so the user isn't stuck on a
                // spinner forever. The previous behaviour swallowed
                // ALL errors silently (the bare ``catch (e) {}``
                // would loop every 5 s indefinitely on a dead swap).
                const msg = (e && e.message) || '';
                if (msg.includes('404') || msg.toLowerCase().includes('not found')) {
                    this.stopSwapPoll();
                    try { sessionStorage.removeItem(COLD_LOCALSTORAGE_KEY); } catch (_e) {}
                    this.coldResultData = {
                        success: false,
                        error: 'We lost track of this swap. Please check the swap history.',
                    };
                    this.coldStep = 'result';
                    return;
                }
                // Transient errors (network blip, 5xx, Tor wobble)
                // are tolerated — the next tick will retry. We
                // surface them via ``coldError`` so the user has a
                // hint that something is off rather than wondering
                // why the dots stopped advancing.
                this.coldError = msg || 'Network error — retrying…';
                return;
            }
            // A successful fetch clears any transient-error message
            // from a prior tick.
            this.coldError = '';
            this.activeSwapStatus = data.status;
            this.activeSwapError = data.error_message;
            // Capture the claim txid as soon as it appears on
            // the swap detail. ``claim_txid`` lands the moment
            // the wallet broadcasts the claim — i.e. status
            // ``claimed`` — which is precisely the on-chain
            // confirmation wait we want to surface to the user
            // (with copy + mempool affordance per the
            // cross-cutting tx-affordance policy).
            if (data.claim_txid) {
                this.activeSwapClaimTxid = data.claim_txid;
            }
            if (typeof data.claim_confirmations === 'number') {
                this.activeSwapClaimConfirmations = data.claim_confirmations;
            }
            // Same pattern for the Boltz lockup tx — surfaced as a
            // Mempool link during the wait window before our own claim
            // tx broadcasts. See ``shouldShowActiveSwapLockupTxid`` and
            // the dedicated template panel.
            if (data.lockup_txid) {
                this.activeSwapLockupTxid = data.lockup_txid;
            }
            if (typeof data.lockup_confirmations === 'number') {
                this.activeSwapLockupConfirmations = data.lockup_confirmations;
            }
            this.activeSwapRecovery = (data && data.recovery) ? data.recovery : null;
            // Shared 0-3 status mapping (see ``_swapUserStepIndex``
            // at module top) — keeps Cold Storage + inbound
            // wizard in sync if a new Boltz status is added.
            this.activeSwapStep = _swapUserStepIndex(data.status);
            this.swapIsFailed = ['failed', 'cancelled', 'refunded'].includes(data.status);
            if (data.status === 'completed') {
                this.stopSwapPoll();
                try { sessionStorage.removeItem(COLD_LOCALSTORAGE_KEY); } catch (_e) {}
                this.coldResultData = { success: true, claimTxid: data.claim_txid };
                this.coldStep = 'result';
                this.fetchSummary();
            } else if (this.swapIsFailed) {
                this.stopSwapPoll();
                try { sessionStorage.removeItem(COLD_LOCALSTORAGE_KEY); } catch (_e) {}
                this.coldResultData = { success: false, error: data.error_message || 'Swap ' + data.status };
                this.coldStep = 'result';
            }
        },
        async cancelBoltzSwap() {
            if (!this.activeSwapId) return;
            this.coldLoading = true;
            try {
                await this.api('POST', '/cold-storage/swaps/' + this.activeSwapId + '/cancel');
                this.stopSwapPoll();
                try { sessionStorage.removeItem(COLD_LOCALSTORAGE_KEY); } catch (_e) {}
                this.coldStep = 'form';
                this.activeSwapId = null;
            } catch (e) {
                // Cancel failed — most commonly because the swap
                // raced past ``created`` between the click and the
                // backend reaching the cancel handler. Surface the
                // message; the progress view's ``coldError``
                // template now renders it (see dashboard.html).
                this.coldError = e.message;
            }
            this.coldLoading = false;
        },

        /** Operator-driven recovery action for a stuck swap.
         *
         *  ``action`` is one of the identifiers the classifier
         *  emits on ``recovery.actions``: ``cooperative_claim`` or
         *  ``unilateral_claim``. The first retries the Musig2
         *  cooperative claim; the second falls back to the
         *  script-path unilateral claim (only valid post-timeout).
         *
         *  On success the next ``pollSwapStatus`` tick will refresh
         *  the recovery hint. On failure the error is surfaced
         *  inline via ``activeSwapRecoveryError``; the banner stays
         *  visible so the operator can decide whether to retry or
         *  escalate.
         */
        async invokeSwapRecoveryAction(action) {
            if (!this.activeSwapId) return;
            if (this.activeSwapRecoveryBusy) return;
            const path = action === 'unilateral_claim'
                ? '/cold-storage/swaps/' + this.activeSwapId + '/unilateral-claim'
                : '/cold-storage/swaps/' + this.activeSwapId + '/cooperative-claim';
            this.activeSwapRecoveryBusy = true;
            this.activeSwapRecoveryError = '';
            try {
                await this.api('POST', path);
                await this.pollSwapStatus();
            } catch (e) {
                this.activeSwapRecoveryError = (e && e.message) || 'Recovery action failed.';
            }
            this.activeSwapRecoveryBusy = false;
        },

        /** Resume an in-progress Cold-Storage swap after a page
         *  refresh. Reads the pinned swap-id from localStorage and,
         *  if the swap is still non-terminal, opens the dialog
         *  straight into the progress view. Mirrors
         *  ``_restoreInboundSwap`` for the inbound flow. */
        async _restoreColdSwap() {
            let swapId;
            try {
                swapId = sessionStorage.getItem(COLD_LOCALSTORAGE_KEY) || '';
            } catch (_e) {
                swapId = '';
            }
            if (!swapId) return;
            let data;
            try {
                data = await this.api('GET', '/cold-storage/swaps/' + encodeURIComponent(swapId));
            } catch (_e) {
                // Network blip or backend reset — clear the pin so
                // we don't keep retrying every page load.
                try { sessionStorage.removeItem(COLD_LOCALSTORAGE_KEY); } catch (_e2) {}
                return;
            }
            if (!data || !data.status) return;
            if (SWAP_TERMINAL_STATUSES.has(data.status)) {
                // Swap already wrapped up; drop the pin and let
                // the regular swap-history list surface it on
                // the next dialog open.
                try { sessionStorage.removeItem(COLD_LOCALSTORAGE_KEY); } catch (_e) {}
                return;
            }
            // Resume the progress view.
            this.activeSwapId = swapId;
            this.activeSwapStatus = data.status;
            this.activeSwapStep = _swapUserStepIndex(data.status);
            this.activeSwapClaimTxid = data.claim_txid || '';
            this.activeSwapClaimConfirmations =
                (typeof data.claim_confirmations === 'number') ? data.claim_confirmations : null;
            this.activeSwapLockupTxid = data.lockup_txid || '';
            this.activeSwapLockupConfirmations =
                (typeof data.lockup_confirmations === 'number') ? data.lockup_confirmations : null;
            this.coldTab = 'lightning';
            this.coldStep = 'progress';
            this.showColdStorage = true;
            this.startSwapPoll();
            this.$nextTick(() => this.initIcons());
        },
        closeColdStorage() {
            this.showColdStorage = false;
            this.coldStep = 'form';
            this.coldResult = '';
            this.coldError = '';
            this.coldEstimate = null;
            this.coldResultData = null;
            this.activeSwapClaimTxid = '';
            this.activeSwapClaimConfirmations = null;
            this.stopSwapPoll();
        },

        // ── Open Channel ──
        setChanFee(priority) {
            this.chanFeePriority = priority;
            if (this.fees) {
                const map = { low: this.fees.hourFee, medium: this.fees.halfHourFee, high: this.fees.fastestFee };
                this.chanFeeRate = map[priority] || null;
            }
        },

        /** Parse the Pubkey-or-URI input. A node URI has the form
         *  ``<66-hex pubkey>@<host:port>``; a bare pubkey is just
         *  the 66-hex string. Returns ``{pubkey, host}`` with
         *  whitespace stripped, or ``null`` if neither shape
         *  matches. Used both to drive the conditional host field
         *  in the UI and to split the value before submit. */
        _parsePubkeyOrUri(raw) {
            const v = (raw || '').trim();
            if (!v) return null;
            const at = v.indexOf('@');
            if (at > 0) {
                const pubkey = v.slice(0, at).trim();
                const host = v.slice(at + 1).trim();
                if (/^[0-9a-fA-F]{66}$/.test(pubkey) && host) {
                    return { pubkey: pubkey.toLowerCase(), host };
                }
                return null;
            }
            if (/^[0-9a-fA-F]{66}$/.test(v)) {
                return { pubkey: v.toLowerCase(), host: '' };
            }
            return null;
        },

        /** Whether the Pubkey field currently contains a full
         *  ``pubkey@host`` URI. Drives ``x-show`` on the Host input. */
        get chanIsUri() {
            const parsed = this._parsePubkeyOrUri(this.chanPubkey);
            return !!(parsed && parsed.host);
        },

        async openChannel() {
            const parsed = this._parsePubkeyOrUri(this.chanPubkey);
            if (!parsed) {
                this.chanError = 'Enter a valid 66-character node pubkey, or a full "pubkey@host:port" URI.';
                return;
            }
            // If the input was a URI, the host comes from it and the
            // separate Host field (which is hidden in that case) is
            // ignored. Otherwise we fall back to the Host input.
            const host = parsed.host || (this.chanHost || '').trim();
            if (!await this.askConfirm({
                body: 'Open channel with ' + this.formatSats(this.chanAmount) + ' sats?',
                ok: 'Open channel',
            })) return;
            this.chanLoading = true;
            this.chanError = '';
            this.chanResult = null;
            try {
                this.chanResult = await this._doOpenChannel({
                    pubkey: parsed.pubkey,
                    host: host,
                    amountSats: this.chanAmount,
                    satPerVbyte: this.chanFeeRate || undefined,
                    isPrivate: this.chanPrivate,
                });
            } catch (e) {
                this.chanError = e.message || 'Open channel failed';
            }
            this.chanLoading = false;
        },

        /** Shared channel-open primitive used by both the regular Open
         *  Channel dialog and the onboarding wizard. Refreshes channels
         *  + summary on success so the caller's view updates without
         *  waiting for the next refresh tick. Errors propagate. */
        async _doOpenChannel({ pubkey, host, amountSats, satPerVbyte, isPrivate }) {
            const result = await this.api('POST', '/channel/open', {
                pubkey: pubkey,
                host: host,
                local_funding_amount: amountSats,
                sat_per_vbyte: satPerVbyte || undefined,
                private: !!isPrivate,
            });
            this.fetchChannels();
            this.fetchSummary();
            return result;
        },
        closeOpenChannel() {
            this.showOpenChannel = false;
            this.chanResult = null;
            this.chanError = '';
        },

        // ──────────────────────────────────────────────────────────────
        //  Onboarding wizard
        //  Replaces the dashboard tabs while the wallet is empty. State
        //  is derived from the same payloads that drive the rest of the
        //  dashboard; no separate persistence.
        // ──────────────────────────────────────────────────────────────

        /** Wizard state machine. A null return means "render the
         *  normal dashboard". */
        get onboardingStep() {
            if (this.onboardingSkipped) return null;
            if (!this.summary) return null;
            const t = this.summary.totals || {};
            if ((t.num_active_channels || 0) >= 1) return null;
            if ((t.num_pending_channels || 0) >= 1) return 'connecting';
            if ((t.onchain_sats || 0) > 0) return 'ready_to_connect';
            if ((t.unconfirmed_sats || 0) > 0) return 'awaiting_deposit';
            // Defensive: a user with lightning balance but no channels
            // is in a stuck state we can't help with from here. Fall
            // through to the regular dashboard so they can see what's
            // going on rather than be trapped on the welcome screen.
            if ((t.lightning_local_sats || 0) > 0) return null;
            return 'welcome';
        },

        /** Incoming-deposit txs (mempool, amount > 0), newest first. */
        get onboardingDepositTxs() {
            return (this.transactions || [])
                .filter((t) => (t.num_confirmations || 0) === 0 && (t.amount || 0) > 0)
                .sort((a, b) => (b.time_stamp || 0) - (a.time_stamp || 0));
        },

        /** Total unconfirmed incoming sats — used for the "Incoming"
         *  amount on the awaiting_deposit step. Reads from
         *  ``totals.unconfirmed_sats`` (authoritative) rather than
         *  summing /transactions, which can miss txs in the brief
         *  window before LND has indexed a fresh receive. */
        get onboardingIncomingSats() {
            return (this.summary && this.summary.totals && this.summary.totals.unconfirmed_sats) || 0;
        },

        /** Confirmed on-chain sats (totals.onchain_sats). Wrapped as
         *  a getter so the CSP-safe template never has to chain
         *  ``summary.totals.x``, matching the rest of the dashboard. */
        get onboardingOnchainSats() {
            return (this.summary && this.summary.totals && this.summary.totals.onchain_sats) || 0;
        },

        /** True once at least one active channel exists. Drives the
         *  visibility of the "Resume guided setup" menu entry. */
        get onboardingHasActiveChannel() {
            return ((this.summary && this.summary.totals && this.summary.totals.num_active_channels) || 0) >= 1;
        },

        /** First pending-open channel, or null. ``/channels/pending``
         *  returns a flat array of detail entries shaped like
         *  ``{type, remote_node_pub, channel_point, capacity, ...}``
         *  — NOT a grouped object — so we filter on ``type`` rather
         *  than indexing into a ``.pending_open`` key. */
        get onboardingPendingChannel() {
            const list = this.pendingChannels || [];
            for (let i = 0; i < list.length; i++) {
                if (list[i] && list[i].type === 'pending_open') return list[i];
            }
            return null;
        },

        /** Funding txid (hex, no :vout) of the pending channel. */
        get onboardingFundingTxid() {
            const ch = this.onboardingPendingChannel;
            if (!ch) return '';
            return this._extractTxidFromChannelPoint(ch.channel_point || '');
        },

        /** Confirmations seen so far for the pending channel's
         *  funding tx, capped at the 3-conf milestone we display. */
        get onboardingConfirmations() {
            const txid = this.onboardingFundingTxid;
            if (!txid) return 0;
            const tx = (this.transactions || []).find((t) => t.tx_hash === txid);
            if (!tx) return 0;
            return Math.min(3, Math.max(0, tx.num_confirmations || 0));
        },

        /** Width of the connecting-step progress bar, as a CSS
         *  ``width: NN%`` string. Pre-computed here because the
         *  CSP-safe Alpine expression parser can't call ``Math.round``
         *  directly inside an ``:style`` binding. */
        get onboardingProgressStyle() {
            const pct = Math.round((this.onboardingConfirmations / 3) * 100);
            return 'width: ' + Math.max(0, Math.min(100, pct)) + '%';
        },

        /** Capacity (sats) of the pending channel — used in the
         *  "Channel with X — capacity Y" line. */
        get onboardingPendingCapacity() {
            const ch = this.onboardingPendingChannel;
            if (!ch) return 0;
            return Math.max(0, parseInt(ch.capacity, 10) || 0);
        },

        /** Friendly label for the pending-channel counterparty.
         *  Pending-open detail entries don't include ``peer_alias``
         *  (that field only exists on active channels via
         *  ``peer_alias_lookup=true``), so the fallback chain is:
         *  catalog match → truncated pubkey → generic. */
        get onboardingPendingPeerLabel() {
            const ch = this.onboardingPendingChannel;
            if (!ch) return '';
            const pk = (ch.remote_node_pub || '').toLowerCase();
            const catalogEntry = this._lookupCatalogPeer(pk);
            if (catalogEntry) return catalogEntry.alias;
            if (pk) return pk.slice(0, 10) + '…' + pk.slice(-4);
            return 'your chosen node';
        },

        /** The cheapest ⭐-tagged catalog peer whose ``min_channel_size_sats``
         *  fits the currently-entered amount. ``null`` when:
         *    * the catalog hasn't loaded yet, or
         *    * the catalog is empty (non-mainnet / kill-switch off / fetch failed), or
         *    * no recommended peer accepts an amount this small.
         *  Used by the ready_to_connect step to show "Will use:" alongside
         *  the recommended radio. */
        get onboardingRecommendedPeer() {
            return this._recommendedPeerForAmount(this.onboardingAmountSats);
        },

        /** Catalog peers whose ``min_channel_size_sats`` fits the
         *  currently-entered amount. Sorted by the active table sort
         *  key (``fee`` / ``channels`` / ``capacity``).
         *  Drives the "Pick from list" table. */
        get onboardingFilteredPeers() {
            const peers = this._peersAcceptingAmount(this.onboardingAmountSats);
            const sort = this.onboardingPickFromListSort;
            // Make a shallow copy so the sort doesn't mutate the cached catalog.
            const copy = peers.slice();
            if (sort === 'channels') {
                copy.sort((a, b) => (b.channels_count || 0) - (a.channels_count || 0));
            } else if (sort === 'capacity') {
                copy.sort((a, b) => (b.capacity_btc || 0) - (a.capacity_btc || 0));
            } else {
                // ``fee``: ascending ppm, base as tiebreaker. Matches the
                // server-side ``cheapest_n`` helper's order.
                copy.sort((a, b) => {
                    const ppmA = a.typical?.fee_rate_milli_msat || 0;
                    const ppmB = b.typical?.fee_rate_milli_msat || 0;
                    if (ppmA !== ppmB) return ppmA - ppmB;
                    return (a.typical?.fee_base_msat || 0) - (b.typical?.fee_base_msat || 0);
                });
            }
            return copy;
        },

        /** Short text summary of the catalog filter result. Used as the
         *  "N / M peers fit your amount" caption above the table. */
        get onboardingPeerStats() {
            const total = this.smallChannelPeerCatalog?.peers?.length || 0;
            if (total === 0) return '';
            const fitting = this.onboardingFilteredPeers.length;
            if (fitting === total) return total + ' peers verified';
            return fitting + ' of ' + total + ' peers fit your amount';
        },

        /** True when the operator has the catalog enabled, the current
         *  network is mainnet, and the catalog has loaded successfully
         *  with at least one entry. False otherwise. Drives the
         *  visibility of the recommended-default + pick-from-catalog
         *  modes (the custom mode is always available). */
        get onboardingCatalogAvailable() {
            if (this.smallChannelPeerCatalogLoadState !== 'loaded') return false;
            const cat = this.smallChannelPeerCatalog;
            if (!cat || !cat.enabled) return false;
            const peers = cat.peers || [];
            return peers.length > 0;
        },

        /** True when the wizard should expose ONLY the custom mode —
         *  catalog endpoint failed, kill-switch is off, or current
         *  network is non-mainnet. The picker collapses to a single
         *  radio in that case (the user sees no choice to make). */
        get onboardingCustomModeOnly() {
            return !this.onboardingCatalogAvailable
                && this.smallChannelPeerCatalogLoadState !== 'loading';
        },

        /** Short explanation for why the picker collapsed to custom-only.
         *  Returns '' when not in custom-only mode (or when the failure
         *  has its own retry footer). The fetch-failed state is handled
         *  separately by the retry footer; non-mainnet and kill-switch
         *  cases get the lines below. */
        get onboardingCustomOnlyExplanation() {
            if (!this.onboardingCustomModeOnly) return '';
            if (this.smallChannelPeerCatalogLoadState === 'failed') return '';
            const cat = this.smallChannelPeerCatalog;
            // Catalog endpoint returned ``enabled: false`` — operator
            // opted out. Nothing the user can do about it.
            if (cat && cat.enabled === false) {
                return 'The peer catalog is turned off on this wallet. Paste a pubkey to continue.';
            }
            // Catalog enabled but network isn't mainnet. The bundled
            // peers are all mainnet identities.
            if (cat && cat.network && cat.network !== 'bitcoin') {
                return 'The peer catalog is mainnet-only. Paste a pubkey for your current network.';
            }
            // Loaded but empty — shouldn't happen with the bundled
            // catalog but log-friendly fallback copy keeps the dialog
            // helpful if it ever does.
            return 'No catalog peers are available right now. Paste a pubkey to continue.';
        },

        /** Snapshot date the catalog returned, formatted for display.
         *  Empty string when no catalog is loaded. */
        get onboardingCatalogSnapshotDate() {
            return this.smallChannelPeerCatalog?.snapshot_date || '';
        },

        /** True when the amount + chosen peer form a valid open request
         *  (so we can enable the submit button). */
        get onboardingCanOpen() {
            const sats = Number(this.onboardingAmountSats) || 0;
            if (sats <= 0) return false;
            if ((this.summary?.totals?.onchain_sats || 0) < sats) return false;
            const mode = this.onboardingPeerChoiceMode;
            if (mode === 'recommended_default') {
                return !!this.onboardingRecommendedPeer;
            }
            if (mode === 'pick_from_list') {
                if (!this.onboardingPickedPubkey) return false;
                const picked = this._lookupCatalogPeer(this.onboardingPickedPubkey);
                if (!picked) return false;
                return (picked.min_channel_size_sats || 0) <= sats;
            }
            // ``custom`` — accept either bare pubkey or pubkey@host:port.
            return !!this._parsePubkeyOrUri(this.onboardingCustomUri);
        },

        /** Helper text below the recommended radio explaining why an
         *  amount is too small. Null when there's nothing to say. */
        get onboardingAmountTooSmallReason() {
            const sats = Number(this.onboardingAmountSats) || 0;
            if (sats <= 0) return null;
            if (this.onboardingPeerChoiceMode !== 'recommended_default') return null;
            if (this.onboardingRecommendedPeer) return null;
            const cat = this.smallChannelPeerCatalog;
            const peers = cat?.peers || [];
            if (peers.length === 0) return null;
            // The smallest min_channel_size_sats across the catalog —
            // the floor the user needs to clear before any catalog peer
            // becomes a viable recommended pick.
            const floor = peers.reduce(
                (acc, p) => Math.min(acc, p.min_channel_size_sats || Infinity),
                Infinity,
            );
            if (!isFinite(floor)) return null;
            return 'The smallest verified peer needs ' +
                this.formatSats(floor) + ' sats. Increase the amount or pick "A different node".';
        },

        /** Maximum capacity the user can add right now given their
         *  local balance and the safety reserve. Used to power the
         * "You can add up to N sats" note shown when
         *  the user landed here from the soft-warning banner with a
         *  recv-amount their channel can't cover. */
        get inboundMaxAddableCapacity() {
            const local = this.inboundLocalBalanceSats;
            if (local <= 0) return 0;
            const ceiling = Math.max(0, local - INBOUND_LOCAL_RESERVE_SATS);
            return Math.min(ceiling, BOLTZ_MAX_AMOUNT_SATS);
        },

        /** True when the user came from the short-warning banner with
         *  a recv-amount that exceeds what their local balance can
         *  practically cover. Drives the cap-explanation note in
         *  the form view. */
        get inboundCappedBySeed() {
            const seed = this.inboundSeedRecvAmount || 0;
            if (seed <= 0) return false;
            const needed = Math.max(0, seed - this.inboundCapacitySats) + INBOUND_SAFETY_MARGIN_SATS;
            return this.inboundMaxAddableCapacity < needed;
        },

        /** Suggested default amount when first entering
         *  ready_to_connect. Keeps a safety reserve so on-chain fees
         *  don't fail later. */
        get onboardingSuggestedAmount() {
            const onchain = (this.summary && this.summary.totals && this.summary.totals.onchain_sats) || 0;
            if (onchain <= 0) return 0;
            const buffer = Math.max(
                ONBOARDING_SAFETY_BUFFER_SATS,
                Math.floor(onchain * ONBOARDING_SAFETY_BUFFER_PCT),
            );
            return Math.max(0, onchain - buffer);
        },

        _extractTxidFromChannelPoint(cp) {
            if (!cp || typeof cp !== 'string') return '';
            const colon = cp.indexOf(':');
            return colon > 0 ? cp.slice(0, colon) : cp;
        },

        // ── Channel-card catalog enrichment ────────────────────────
        //
        // Each channel card consults the small-channel peer catalog
        // (lazily fetched on dashboard mount) so the user sees the
        // catalog's perspective on their peers: a ⭐ badge for vetted
        // recommended-default peers, a ⚠️ badge for peers the catalog
        // flagged with a routing caveat, and a per-card info tooltip
        // showing the peer's summary + fee tier + outbound-enabled
        // ratio + snapshot date. The catalog itself is mainnet-only;
        // unmatched peers render with no badge or info icon (silent
        // miss, no judgement implied).

        /** Catalog entry for a channel's remote peer, or ``null`` when
         *  there's no match. Accepts both active channels (``remote_pubkey``)
         *  and pending channels (``remote_node_pub``). */
        channelPeerCatalogInfo(ch) {
            if (!ch) return null;
            const pk = ch.remote_pubkey || ch.remote_node_pub || '';
            if (!pk) return null;
            return this._lookupCatalogPeer(pk);
        },

        /** Catalog-derived badge kind for a channel — ``'star'`` (⭐),
         *  ``'warning'`` (⚠️), or ``''`` for no badge. ``'warning'``
         *  takes precedence over ``'star'`` when both apply (the
         *  routing concern is the more important signal). */
        channelPeerBadge(ch) {
            const info = this.channelPeerCatalogInfo(ch);
            if (!info) return '';
            if (this._peerHasMarginalRouting(info)) return 'warning';
            if ((info.tags || []).indexOf('recommended_default') !== -1) return 'star';
            return '';
        },

        /** Days since the catalog last verified this peer. Returns
         *  ``null`` when the catalog has no entry for the channel's
         *  peer (silent miss) or when the date doesn't parse. */
        channelPeerVerifiedDaysAgo(ch) {
            const info = this.channelPeerCatalogInfo(ch);
            if (!info || !info.verified_at) return null;
            const parsed = Date.parse(info.verified_at + 'T00:00:00Z');
            if (isNaN(parsed)) return null;
            const days = Math.floor((Date.now() - parsed) / (24 * 60 * 60 * 1000));
            return days >= 0 ? days : null;
        },

        /** Human-readable label for a fee tier — capitalised for display
         *  in the tooltip. */
        channelPeerFeeTierLabel(info) {
            if (!info || !info.fee_tier) return '';
            const labels = {
                very_low: 'Very low fees',
                low: 'Low fees',
                moderate: 'Moderate fees',
                high: 'High fees',
                hybrid: 'Hybrid (base + ppm)',
                flat_fee: 'Flat-fee model',
            };
            return labels[info.fee_tier] || info.fee_tier;
        },

        /** Human-readable label for a connectivity tier. */
        channelPeerConnectivityLabel(info) {
            if (!info || !info.connectivity_tier) return '';
            const labels = {
                limited: 'Limited connectivity',
                adequate: 'Adequately connected',
                well: 'Well connected',
                highly: 'Highly connected',
            };
            return labels[info.connectivity_tier] || info.connectivity_tier;
        },

        /** Outbound-enabled ratio formatted as a percentage string, or
         *  empty when the catalog didn't sample one for this peer. */
        channelPeerOutboundPct(info) {
            if (!info || info.outbound_enabled_ratio == null) return '';
            return Math.round(info.outbound_enabled_ratio * 100) + '%';
        },

        /** Click handler for the channel card's info icon — toggles the
         *  per-channel tooltip. The ``openChannelInfoTooltip`` field
         *  carries the chan_id (or pending channel_point) of whichever
         *  card is currently open, or ``''`` when none is. Clicking the
         *  same icon a second time closes the tooltip. */
        toggleChannelInfo(ch) {
            const key = this._channelInfoKey(ch);
            if (!key) return;
            if (this.openChannelInfoTooltip === key) {
                this.openChannelInfoTooltip = '';
            } else {
                this.openChannelInfoTooltip = key;
            }
        },

        /** Close handler bound to ``@click.outside`` and
         *  ``@keydown.escape.window`` on the tooltip surface. */
        closeChannelInfo() {
            this.openChannelInfoTooltip = '';
        },

        /** Outside-click handler bound to each channel card's tooltip
         *  wrapper. Closes the open tooltip only when the outside click
         *  happens against the card whose tooltip is currently open;
         *  clicks against another card's wrapper would otherwise leave
         *  the open tooltip stuck. Extracted because Alpine's CSP
         *  expression parser can't compile an ``if (cond) call()``
         *  statement form inline in a directive. */
        closeChannelInfoIfOwned(ch) {
            const key = this._channelInfoKey(ch);
            if (key && this.openChannelInfoTooltip === key) {
                this.closeChannelInfo();
            }
        },

        /** Stable per-card key the tooltip uses to identify "is this my
         *  channel's tooltip?" — chan_id for active channels, the
         *  ``channel_point`` outpoint for pending opens. */
        _channelInfoKey(ch) {
            if (!ch) return '';
            return String(ch.chan_id || ch.channel_point || '');
        },

        /** Count of active + pending channels whose remote peer is in
         *  the catalog. Drives the "X of your Y channels…" summary
         *  line at the top of the Channels tab. */
        get catalogMatchedChannelCount() {
            const all = (this.channels || []).concat(this.pendingChannels || []);
            let n = 0;
            for (const ch of all) {
                if (this.channelPeerCatalogInfo(ch)) n += 1;
            }
            return n;
        },

        /** Total active + pending channels, used as the denominator in
         *  the summary line. */
        get totalChannelCount() {
            return (this.channels || []).length + (this.pendingChannels || []).length;
        },

        /** True when the Channels-tab summary line should render —
         *  there's at least one catalog-matched channel AND the user
         *  has at least one channel total. Hides on a no-match wallet
         *  so we don't draw attention to the gap. */
        get shouldShowCatalogMatchedSummary() {
            return this.catalogMatchedChannelCount > 0 && this.totalChannelCount > 0;
        },

        // ── End channel-card catalog enrichment ───────────────────

        /** Catalog peers whose ``min_channel_size_sats`` is at or below
         *  ``sats``. Returns an empty array when the catalog hasn't
         *  loaded yet or no peer accepts an amount this small. */
        _peersAcceptingAmount(sats) {
            const n = Number(sats) || 0;
            if (n <= 0) return [];
            const cat = this.smallChannelPeerCatalog;
            if (!cat || !cat.enabled) return [];
            const peers = cat.peers || [];
            const out = [];
            for (const peer of peers) {
                if ((peer.min_channel_size_sats || 0) <= n) out.push(peer);
            }
            return out;
        },

        /** Look up a catalog peer by pubkey (case-insensitive).
         *  Returns the catalog entry or null when not in the catalog. */
        _lookupCatalogPeer(pubkey) {
            if (!pubkey) return null;
            const needle = String(pubkey).toLowerCase();
            const cat = this.smallChannelPeerCatalog;
            if (!cat) return null;
            const peers = cat.peers || [];
            for (const peer of peers) {
                if ((peer.node_id_hex || '').toLowerCase() === needle) return peer;
            }
            return null;
        },

        /** True when ``peer`` carries a ``marginal_routing`` caveat —
         *  the catalog's signal that the peer's outbound-enabled ratio
         *  is meaningfully below the healthy threshold. The recommended
         *  picker skips these so a fresh wallet doesn't auto-route into
         *  a peer whose own gossip says they refuse to forward. They
         *  remain visible (and selectable) in the Pick-from-list table,
         *  rendered with a ⚠️ badge. */
        _peerHasMarginalRouting(peer) {
            const caveats = peer.caveats || [];
            for (const c of caveats) {
                if (c && c.kind === 'marginal_routing') return true;
            }
            return false;
        },

        /** Pick the cheapest ⭐ catalog peer whose
         *  ``min_channel_size_sats`` fits ``sats``. Falls back to the
         *  cheapest non-⭐ peer that accepts the amount when no
         *  recommended peer fits. ``marginal_routing`` peers are
         *  excluded from auto-picking. Returns null when nothing
         *  accepts. */
        _recommendedPeerForAmount(sats) {
            const candidates = this._peersAcceptingAmount(sats).filter(
                (p) => !this._peerHasMarginalRouting(p),
            );
            if (candidates.length === 0) return null;
            const ranked = candidates.slice().sort((a, b) => {
                const aStar = (a.tags || []).indexOf('recommended_default') !== -1 ? 0 : 1;
                const bStar = (b.tags || []).indexOf('recommended_default') !== -1 ? 0 : 1;
                if (aStar !== bStar) return aStar - bStar;
                const ppmA = a.typical?.fee_rate_milli_msat || 0;
                const ppmB = b.typical?.fee_rate_milli_msat || 0;
                if (ppmA !== ppmB) return ppmA - ppmB;
                return (a.typical?.fee_base_msat || 0) - (b.typical?.fee_base_msat || 0);
            });
            return ranked[0];
        },

        // ── Channel-mix planner helpers ────────────────────────────

        /** True whenever the channel-mix planner is open — drives the
         *  top-level mount gates for the wizard wrapper (so the
         *  planner panels can render even after the onboarding flow
         *  has completed) and for the main dashboard (so the planner
         *  visually occupies the page like a modal step). */
        get channelPlannerActive() {
            return this.channelPlanMode !== 'wizard_choice';
        },

        /** True when the onboarding wizard should offer the
         *  "Plan multiple channels" branch alongside the single-
         *  channel picker. The threshold is the operator-tunable
         *  ``CHANNEL_PLANNER_AUTOOFFER_FLOOR_SATS``; below it the
         *  single-channel flow is the right answer anyway. */
        get onboardingPlannerOffered() {
            const onchain = this.onboardingOnchainSats || 0;
            return onchain > CHANNEL_PLANNER_AUTOOFFER_FLOOR_SATS;
        },

        /** The number the wizard pre-selects for the planner's target
         *  capacity. Same suggestion logic as the single-channel
         *  picker — onchain balance minus a safety reserve. */
        get channelPlanSuggestedTarget() {
            return this.onboardingSuggestedAmount || 0;
        },

        /** Drive the planner's submit-disabled state. */
        get channelPlanCanSubmit() {
            const f = this.channelPlanForm || {};
            if (this.channelPlanLoading) return false;
            if (f.mode === 'bootstrap') {
                const amount = f.bootstrap_input_kind === 'deposit'
                    ? Number(f.bootstrap_deposit_sats || 0)
                    : Number(f.bootstrap_target_inbound_sats || 0);
                return amount > 0;
            }
            return Number(f.target_capacity_sats || 0) > 0;
        },

        /** True when the active plan/preview is the bootstrap strategy. */
        get channelPlanIsBootstrap() {
            const m = (this.channelPlanResult && this.channelPlanResult.mode)
                || (this.channelPlanForm && this.channelPlanForm.mode);
            return m === 'bootstrap';
        },

        /** The BootstrapPlan body (same accessor as channelPlanPlan, but
         *  named for the bootstrap-specific template bindings). */
        get channelBootstrapPlan() {
            return this.channelPlanPlan || {};
        },

        /** Human "~N hours" / "~N min" label for the bootstrap estimate. */
        get channelBootstrapDurationLabel() {
            const mins = (this.channelBootstrapPlan.est_duration_minutes) || 0;
            if (mins >= 120) return Math.round(mins / 60) + ' hours';
            if (mins >= 60) return '1 hour';
            return Math.max(1, Math.round(mins)) + ' min';
        },

        /** True when the planner's plan-preview view should expose the
         *  "Why the buffer?" disclosure. Disabled when minimum-mode is
         *  active (the buffer breakdown isn't being applied). */
        get channelPlanShowBuffer() {
            const plan = this.channelPlanPlan;
            if (!plan) return false;
            const b = plan.breakdown || {};
            return (b.close_reserve_sats || 0) > 0
                || (b.fee_spike_cushion_sats || 0) > 0;
        },

        /** Headline funding number — recommended by default,
         *  minimum when the user opted in. */
        get channelPlanHeadlineSats() {
            const plan = this.channelPlanPlan;
            if (!plan) return 0;
            return this.channelPlanShowMinimum
                ? (plan.minimum_sats || 0)
                : (plan.recommended_sats || 0);
        },

        /** True only when a plan body is available — the planner
         *  preview surface gates on this getter rather than dotted
         *  ``channelPlanResult && channelPlanResult.plan`` in the
         *  template, since the Alpine CSP build does not short-circuit
         *  the dotted access on a null left-hand side. */
        get channelPlanHasResult() {
            return !!(this.channelPlanResult && this.channelPlanResult.plan);
        },

        /** The Plan body; null until ``submitChannelPlan`` succeeds. */
        get channelPlanPlan() {
            if (!this.channelPlanResult) return null;
            return this.channelPlanResult.plan || null;
        },

        /** Per-channel openings — always returns an array so template
         *  iteration is safe before the plan resolves. */
        get channelPlanPerChannel() {
            const plan = this.channelPlanPlan;
            if (!plan) return [];
            return Array.isArray(plan.per_channel) ? plan.per_channel : [];
        },

        /** Buffer breakdown — flat object even when no plan yet. */
        get channelPlanBreakdown() {
            const plan = this.channelPlanPlan;
            return (plan && plan.breakdown) || {};
        },

        /** Planner warnings; always an array for template iteration. */
        get channelPlanWarnings() {
            const plan = this.channelPlanPlan;
            if (!plan) return [];
            const d = plan.diagnostics || {};
            return Array.isArray(d.warnings) ? d.warnings : [];
        },

        /** Minimum funding sats, defaulted to 0 so the template's
         *  ``formatSats`` call never sees undefined. */
        get channelPlanMinimumSats() {
            const plan = this.channelPlanPlan;
            return (plan && plan.minimum_sats) || 0;
        },

        /** Recommended funding sats, defaulted to 0. */
        get channelPlanRecommendedSats() {
            const plan = this.channelPlanPlan;
            return (plan && plan.recommended_sats) || 0;
        },

        /** Future-channel-slot sats (the "leave room for one more"
         *  contribution); 0 when the buffer wasn't requested. */
        get channelPlanFutureChannelSlotSats() {
            return this.channelPlanBreakdown.future_channel_slot_sats || 0;
        },

        /** Per-channel (or per-round) state entries for the executing
         *  screen; always an array. */
        get channelMixRunChannels() {
            if (!this.channelMixRun) return [];
            return Array.isArray(this.channelMixRun.channels)
                ? this.channelMixRun.channels
                : [];
        },

        /** True when the run being polled is a bootstrap run. */
        get channelMixRunIsBootstrap() {
            return !!(this.channelMixRun && this.channelMixRun.mode === 'bootstrap');
        },

        get channelMixRunRealizedInbound() {
            return (this.channelMixRun && this.channelMixRun.realized_inbound_sats) || 0;
        },

        get channelMixRunTotalFees() {
            return (this.channelMixRun && this.channelMixRun.total_fees_sats) || 0;
        },

        get channelMixRunStopRequested() {
            return !!(this.channelMixRun && this.channelMixRun.stop_requested);
        },

        get channelMixRunWarnings() {
            if (!this.channelMixRun) return [];
            return Array.isArray(this.channelMixRun.warnings)
                ? this.channelMixRun.warnings
                : [];
        },

        /** "settled / expected" rounds label for the bootstrap progress. */
        get channelMixRunRoundsLabel() {
            const s = (this.channelMixRun && this.channelMixRun.summary) || {};
            const done = s.rounds_settled || 0;
            const expected = s.expected_rounds;
            return expected ? (done + ' / ~' + expected) : String(done);
        },

        /** A short status line for the bootstrap run's overall state. */
        get channelMixRunStateLabel() {
            const st = this.channelMixRun && this.channelMixRun.state;
            if (st === 'awaiting_funds') return 'Waiting for funds to recycle…';
            if (st === 'stopped_insufficient') return 'Stopped — not enough capital to continue.';
            if (st === 'partial_failure') return 'Stopped early — some rounds didn’t complete.';
            if (st === 'cancelled') return 'Stopped at your request.';
            if (st === 'complete') return 'Finished.';
            return '';
        },

        /** Non-fatal "taking longer than expected" note from the executor
         *  (e.g. a confirmation that's slow); empty string when none. */
        get channelMixRunNote() {
            return (this.channelMixRun && this.channelMixRun.error_message) || '';
        },

        /** Friendly label for one bootstrap round's sub-state. */
        channelMixRoundStateLabel(state) {
            const map = {
                opening: 'opening channel',
                open_pending: 'confirming…',
                open_active: 'channel active',
                swapping: 'draining…',
                swap_pending: 'recycling (confirming)…',
                settled: 'done',
                open_failed: 'open failed',
                swap_failed: 'drain failed',
            };
            return map[state] || String(state || '').replace(/_/g, ' ');
        },

        /** Reset the planner state — used both when the user dismisses
         *  the wizard and when the form needs to re-open with fresh
         *  inputs. */
        _resetChannelPlanState() {
            this.channelPlanMode = 'wizard_choice';
            this.channelPlanResult = null;
            this.channelPlanShowMinimum = false;
            this.channelPlanWhyOpen = false;
            this.channelPlanLoading = false;
            this.channelPlanError = '';
            this.channelMixRunId = '';
            this.channelMixRun = null;
            this._stopChannelMixPolling();
            this.channelPlanForm = {
                target_capacity_sats: this.channelPlanSuggestedTarget,
                outbound_option: 'balanced',
                custom_inbound_pct: null,
                peer_mix_mode: 'recommended_diverse',
                manual_picks: [],
                leave_room_for_one_more: false,
                include_marginal_routing: false,
                mode: 'parallel',
                bootstrap_input_kind: 'target',
                bootstrap_target_inbound_sats: null,
                bootstrap_deposit_sats: null,
                bootstrap_final_push_round: false,
            };
        },

        /** Open the planner — moves the wizard into ``plan_form``. */
        openChannelPlanner() {
            this._resetChannelPlanState();
            this.channelPlanMode = 'plan_form';
        },

        /** Open the planner pre-set to the capital-efficient bootstrap
         *  strategy — the onboarding "build inbound from a smaller
         *  deposit" path (plan §9). Defaults to the target-inbound
         *  framing so the new user states what they want to receive. */
        openInboundBootstrap() {
            this._resetChannelPlanState();
            this.channelPlanForm.mode = 'bootstrap';
            this.channelPlanForm.bootstrap_input_kind = 'target';
            this.channelPlanMode = 'plan_form';
        },

        /** Return to the wizard choice (or close the planner from the
         *  Channels tab). */
        closeChannelPlanner() {
            this._resetChannelPlanState();
            this.channelPlanMode = 'wizard_choice';
        },

        /** Submit the planner's form to ``/wallet/channel-mix/plan``. */
        async submitChannelPlan() {
            this.channelPlanError = '';
            if (!this.channelPlanCanSubmit) return;
            this.channelPlanLoading = true;
            try {
                const result = await this.api(
                    'POST',
                    '/channel-mix/plan',
                    this.channelPlanForm,
                );
                this.channelPlanResult = result;
                this.channelPlanMode = 'plan_preview';
            } catch (e) {
                this.channelPlanError = (e && e.message) || 'Couldn’t build the plan.';
            } finally {
                this.channelPlanLoading = false;
            }
        },

        /** Execute the previously-built plan and start polling the
         *  resulting mix run. */
        async executeChannelPlan() {
            if (!this.channelPlanResult || !this.channelPlanResult.plan_token) return;
            this.channelPlanError = '';
            this.channelPlanLoading = true;
            try {
                const body = Object.assign({}, this.channelPlanForm, {
                    plan_token: this.channelPlanResult.plan_token,
                });
                const result = await this.api(
                    'POST',
                    '/channel-mix/execute',
                    body,
                );
                this.channelMixRunId = result.mix_run_id;
                this.channelMixRun = null;
                this.channelPlanMode = 'executing';
                this._startChannelMixPolling();
            } catch (e) {
                // ``409 plan_stale`` ships a fresh plan; re-render the
                // preview with it so the user can re-confirm.
                if (e && e.status === 409 && e.detail && e.detail.plan && e.detail.plan_token) {
                    this.channelPlanResult = {
                        mode: e.detail.mode || this.channelPlanForm.mode,
                        plan: e.detail.plan,
                        plan_token: e.detail.plan_token,
                    };
                    this.channelPlanMode = 'plan_preview';
                    this.channelPlanError = e.detail.message || 'The plan has changed — please review and re-confirm.';
                } else {
                    this.channelPlanError = (e && e.message) || 'Couldn’t start the plan.';
                }
            } finally {
                this.channelPlanLoading = false;
            }
        },

        /** Begin the per-channel polling loop. The dashboard refreshes
         *  every ``CHANNEL_MIX_RUN_POLL_MS`` ms while the run is in a
         *  non-terminal state. */
        _startChannelMixPolling() {
            this._stopChannelMixPolling();
            const poll = async () => {
                if (!this.channelMixRunId) return;
                try {
                    const body = await this.api(
                        'GET',
                        '/channel-mix/runs/' + this.channelMixRunId,
                    );
                    this.channelMixRun = body;
                    const state = body && body.state;
                    // ``awaiting_funds`` is a transient bootstrap state —
                    // keep polling. The rest are terminal.
                    const terminal = (
                        state === 'complete'
                        || state === 'partial_failure'
                        || state === 'cancelled'
                        || state === 'stopped_insufficient'
                    );
                    if (terminal) {
                        this.channelPlanMode = 'done';
                        this._stopChannelMixPolling();
                        // Refresh the rest of the dashboard so the new
                        // channels appear in the channels tab.
                        this.fetchChannels();
                        this.fetchSummary();
                    }
                } catch (e) {
                    // Transient — keep polling.
                }
            };
            poll();
            this._channelMixPollTimer = setInterval(poll, CHANNEL_MIX_RUN_POLL_MS);
        },

        _stopChannelMixPolling() {
            if (this._channelMixPollTimer) {
                clearInterval(this._channelMixPollTimer);
                this._channelMixPollTimer = null;
            }
        },

        /** Request a cooperative stop of the running bootstrap loop after
         *  its current round (the "Stop after this round" control). */
        async stopChannelMixRun() {
            if (!this.channelMixRunId || this.channelMixRunStopRequested) return;
            try {
                const body = await this.api(
                    'POST',
                    '/channel-mix/runs/' + this.channelMixRunId + '/stop',
                );
                if (body && this.channelMixRun) {
                    this.channelMixRun.stop_requested = !!body.stop_requested;
                }
            } catch (e) {
                // Best-effort — the next poll reflects the real state.
            }
        },

        // ── End channel-mix planner helpers ───────────────────────

        /** Lazily fetch the small-channel peer catalog from the
         *  session-authed dashboard endpoint. Idempotent: a successful
         *  load is cached for the dashboard session; a failed load can
         *  be retried via the user-facing retry button (call with
         *  ``{ force: true }``). The retry-with-backoff budget is
         *  defined by ``CATALOG_FETCH_RETRY_BACKOFFS_MS``. */
        async _ensureSmallChannelPeerCatalog(opts) {
            const force = !!(opts && opts.force);
            if (!force && this.smallChannelPeerCatalogLoadState === 'loaded') return;
            if (!force && this.smallChannelPeerCatalogLoadState === 'loading') return;
            this.smallChannelPeerCatalogLoadState = 'loading';
            const backoffs = [0].concat(CATALOG_FETCH_RETRY_BACKOFFS_MS);
            for (let attempt = 0; attempt < backoffs.length; attempt++) {
                if (backoffs[attempt] > 0) {
                    await new Promise((r) => setTimeout(r, backoffs[attempt]));
                }
                try {
                    const body = await this.api('GET', '/peer-catalog/small-channel');
                    if (body && typeof body === 'object') {
                        this.smallChannelPeerCatalog = body;
                        this.smallChannelPeerCatalogLoadState = 'loaded';
                        return;
                    }
                } catch (e) {
                    // Fall through to the next backoff; the final
                    // attempt's failure flips the load state.
                }
            }
            this.smallChannelPeerCatalogLoadState = 'failed';
            this.smallChannelPeerCatalog = null;
        },

        /** Retry-the-fetch handler bound to the "Couldn't load peer
         *  catalog" footer's retry link. */
        async onboardingRetryCatalog() {
            await this._ensureSmallChannelPeerCatalog({ force: true });
        },

        /** Click handler for the catalog table — pick a peer by pubkey
         *  and switch to ``pick_from_list`` mode if not already in it. */
        onboardingPickCatalogPeer(pubkey) {
            this.onboardingPickedPubkey = pubkey || '';
            this.onboardingPeerChoiceMode = 'pick_from_list';
        },

        /** Pre-fill the channel-amount input the first time the user
         *  lands on ``ready_to_connect``. Re-runs whenever the
         *  on-chain balance grows (e.g. a second deposit confirmed)
         *  but stops once the user has typed anything. */
        _maybePrefillOnboardingAmount() {
            if (this.onboardingAmountTouched) return;
            const suggested = this.onboardingSuggestedAmount;
            if (suggested > 0) this.onboardingAmountSats = suggested;
        },

        /** Called by the amount input's ``@input`` to flag user edits.
         *  After this fires we stop overwriting the value when the
         *  on-chain balance changes. */
        onboardingMarkAmountTouched() {
            this.onboardingAmountTouched = true;
        },

        /** Open the Fund Wallet dialog from the wizard. Thin proxy so
         *  the template doesn't reach across to a method named after
         *  a different surface. */
        onboardingOpenDeposit() {
            this.openOnchainReceive();
        },

        /** Submit the wizard's open-channel form. Builds the peer
         *  arguments from the user's choice of catalog recommendation,
         *  catalog table selection, or custom URI, and delegates to
         *  ``_doOpenChannel``. */
        async onboardingOpenChannel() {
            this.onboardingError = '';
            const sats = Number(this.onboardingAmountSats) || 0;
            if (sats <= 0) {
                this.onboardingError = 'Enter a channel amount.';
                return;
            }
            let pubkey;
            let host;
            const mode = this.onboardingPeerChoiceMode;
            if (mode === 'recommended_default') {
                const peer = this.onboardingRecommendedPeer;
                if (!peer) {
                    this.onboardingError = this.onboardingAmountTooSmallReason
                        || 'No verified peer accepts this amount. Try increasing it or pick "A different node".';
                    return;
                }
                pubkey = peer.node_id_hex;
                host = peer.address;
            } else if (mode === 'pick_from_list') {
                if (!this.onboardingPickedPubkey) {
                    this.onboardingError = 'Pick a peer from the catalog first.';
                    return;
                }
                const peer = this._lookupCatalogPeer(this.onboardingPickedPubkey);
                if (!peer) {
                    this.onboardingError = 'The chosen peer is no longer in the catalog. Pick another or use "A different node".';
                    return;
                }
                if ((peer.min_channel_size_sats || 0) > sats) {
                    this.onboardingError = peer.alias + ' needs at least '
                        + this.formatSats(peer.min_channel_size_sats) + ' sats.';
                    return;
                }
                pubkey = peer.node_id_hex;
                host = peer.address;
            } else {
                const parsed = this._parsePubkeyOrUri(this.onboardingCustomUri);
                if (!parsed) {
                    this.onboardingError = 'Enter a valid 66-character node pubkey, or a full "pubkey@host:port" URI.';
                    return;
                }
                pubkey = parsed.pubkey;
                host = parsed.host;
                if (!host) {
                    this.onboardingError = 'A connection address (host:port) is required for the first connection.';
                    return;
                }
            }
            // Use the medium fee rate so the user doesn't have to
            // pick. Power users can fall back to the regular Open
            // Channel dialog under the menu.
            const fees = this.fees || {};
            const feeRate = fees.halfHourFee || fees.hourFee || undefined;
            this.onboardingLoading = true;
            try {
                await this._doOpenChannel({
                    pubkey: pubkey,
                    host: host,
                    amountSats: sats,
                    satPerVbyte: feeRate,
                    isPrivate: false,
                });
                // ``_doOpenChannel`` fires fetchChannels + fetchSummary
                // but does not await them. The wizard auto-transitions
                // to ``connecting`` as soon as ``summary.totals.
                // num_pending_channels`` becomes >= 1, so we MUST
                // populate ``this.pendingChannels`` *before* assigning
                // the new summary — otherwise the connecting view
                // renders with empty "Channel with X" / "Funding
                // transaction" sections for a few hundred ms until
                // the parallel fetchChannels resolves.
                //
                // Await channels first, then summary, so the step
                // transition sees both fields populated.
                await this.fetchChannels();
                await this.fetchSummary();
                this.fetchTransactions();
            } catch (e) {
                this.onboardingError = e.message || 'Could not open the channel. Please try again.';
            }
            this.onboardingLoading = false;
        },

        onboardingSkip() {
            try { localStorage.setItem('onboardingSkipped', '1'); } catch (_e) {}
            this.onboardingSkipped = true;
            this._stopOnboardingPoller();
        },

        onboardingResume() {
            try { localStorage.removeItem('onboardingSkipped'); } catch (_e) {}
            this.onboardingSkipped = false;
            // The watcher will start the poller again on next tick.
        },
        // Single-expression wrapper for the menu item (the CSP build
        // can't parse "onboardingResume(); showSettingsMenu = false").
        onboardingResumeFromMenu() {
            this.onboardingResume();
            this.showSettingsMenu = false;
        },

        /** 4 s tick that refreshes the three payloads the wizard
         *  reads from. Runs ONLY while ``onboardingStep`` is non-null.
         *  Sharpens perceived latency at each state-machine boundary
         *  (deposit broadcast → confirmed → channel-active). */
        _startOnboardingPoller() {
            this._poll('onboarding', () => {
                if (!this.onboardingStep) {
                    this._stopOnboardingPoller();
                    return Promise.resolve();
                }
                // Only re-poll pending channels when we're already
                // expecting one (connecting state). Otherwise this
                // payload doesn't move. Return the combined promise so
                // the in-flight guard holds until all calls settle.
                const calls = [this.fetchSummary(), this.fetchTransactions()];
                if (this.onboardingStep === 'connecting') {
                    calls.push(this.fetchChannels());
                }
                return Promise.all(calls);
            }, { intervalMs: 4000, immediate: false });
        },

        _stopOnboardingPoller() {
            this._stopPoll('onboarding');
        },

        /** Show the "You're connected!" celebration view for ~2.4 s
         *  after the user's first channel goes active. Keeps the
         *  wizard mounted across the boundary so the rings + check
         *  animation has time to play before the regular dashboard
         *  takes over. Re-uses the ``recv-paid-*`` keyframes from
         *  the Receive-Lightning dialog. */
        _triggerOnboardingCelebration() {
            this.onboardingCelebrating = true;
            if (this._onboardingCelebrationTimer) {
                clearTimeout(this._onboardingCelebrationTimer);
            }
            this.$nextTick(() => this.initIcons());
            this._onboardingCelebrationTimer = setTimeout(() => {
                this.onboardingCelebrating = false;
                this._onboardingCelebrationTimer = null;
                this.$nextTick(() => this.initIcons());
            }, 2400);
        },

        // ──────────────────────────────────────────────────────────────
        //  Add Receive Capacity — inbound liquidity wizard
        //
        //  Reverse-swaps a slice of the user's outbound balance into
        //  on-chain sats in their *own* wallet. The on-chain sats
        //  themselves stay theirs; the operation's effect is that
        //  the channel's local/remote shifts toward remote, which is
        //  what "inbound liquidity" means in user-facing terms.
        // ──────────────────────────────────────────────────────────────

        /** Aggregate inbound liquidity across all active channels. */
        get inboundCapacitySats() {
            return (this.summary && this.summary.totals
                    && this.summary.totals.lightning_remote_sats) || 0;
        },

        /** Local outbound balance. Read straight off the existing
         *  ``localBalance`` getter for consistency. */
        get inboundLocalBalanceSats() {
            return this.localBalance || 0;
        },

        /** Drives the banner in the Receive-Lightning dialog.
         *  Returns ``'block'`` (hard block, zero inbound),
         *  ``'short'`` (have some but less than the user is asking
         *  for), or ``null`` (no banner). The "no active channels"
         *  case returns null because the onboarding wizard handles
         *  it. */
        get inboundBannerKind() {
            if (!this.summary) return null;
            const totals = this.summary.totals || {};
            if ((totals.num_active_channels || 0) < 1) return null;
            const have = this.inboundCapacitySats;
            if (have === 0) return 'block';
            const requested = parseInt(this.recvAmountStr, 10) || 0;
            if (requested > 0 && requested > have) return 'short';
            return null;
        },

        /** True when the user has a channel but its local balance is
         *  below the Boltz minimum — neither "Add capacity" nor any
         *  other automatic path can help them here. Drives the
         *  non-actionable variant of the banner copy. */
        get inboundChannelTooSmall() {
            if (!this.summary) return false;
            const totals = this.summary.totals || {};
            if ((totals.num_active_channels || 0) < 1) return false;
            return (this.inboundLocalBalanceSats > 0
                    && this.inboundLocalBalanceSats < BOLTZ_MIN_AMOUNT_SATS);
        },

        /** Default amount for the form. Context-aware:
         *
         *   - If we landed here from the "short" banner, the seed
         *     recv-amount is set, so pick ``recv - inbound + margin``.
         *   - Otherwise default to ``local / 2``.
         *
         *  Clamped to ``[BOLTZ_MIN, BOLTZ_MAX]`` and to
         *  ``local - reserve`` so we never suggest draining the
         *  whole channel. */
        get inboundSuggestedAmount() {
            const local = this.inboundLocalBalanceSats;
            if (local <= 0) return 0;
            const seedRecv = this.inboundSeedRecvAmount || 0;
            let target;
            if (seedRecv > 0) {
                const have = this.inboundCapacitySats;
                target = Math.max(0, seedRecv - have) + INBOUND_SAFETY_MARGIN_SATS;
            } else {
                target = Math.floor(local / 2);
            }
            const ceiling = Math.max(0, local - INBOUND_LOCAL_RESERVE_SATS);
            target = Math.min(target, ceiling, BOLTZ_MAX_AMOUNT_SATS);
            target = Math.max(target, BOLTZ_MIN_AMOUNT_SATS);
            // If the ceiling itself is below the Boltz floor (tiny
            // channel), prefer 0 over a bogus "25,000" suggestion.
            if (ceiling < BOLTZ_MIN_AMOUNT_SATS) return 0;
            return target;
        },

        /** True while ``fetchBoltzFees`` hasn't completed at least
         *  once. Used to suppress the "unreachable" banner on the
         *  first dialog open before the Tor-routed fetch has had
         *  time to resolve. */
        get inboundFeesLoading() {
            return !this._boltzFeesFetched;
        },

        /** True when we have a usable Boltz fees payload from a
         *  completed fetch. Becomes definitively false only after
         *  the fetch has attempted at least once *and* the
         *  response didn't carry ``fees_percentage`` (i.e. a real
         *  failure, not the in-flight sentinel). The form gates
         *  submit on this and uses the loading vs unreachable
         *  distinction to pick the right UI. */
        get inboundBoltzReachable() {
            if (!this._boltzFeesFetched) return false;
            const fees = this.boltzFees || {};
            // ``fees_percentage`` is always non-null on a successful
            // ``/cold-storage/fees`` response (see cold_storage.py).
            // Its absence after a completed fetch is the cleanest
            // signal of an unreachable Boltz.
            return typeof fees.fees_percentage === 'number';
        },

        /** Boltz percentage fee in sats for the current amount. */
        get inboundBoltzPercentageFeeSats() {
            const amount = Number(this.inboundAmountSats) || 0;
            const fees = this.boltzFees || {};
            const pct = fees.fees_percentage || 0;
            return Math.ceil(amount * pct / 100);
        },

        /** Total miner fees Boltz charges (lockup + claim). */
        get inboundBoltzMinerFeeSats() {
            const fees = this.boltzFees || {};
            return (fees.fees_miner_lockup || 0) + (fees.fees_miner_claim || 0);
        },

        /** Combined fee the user pays — the headline number on the
         * form view (combined + expandable details). */
        get inboundTotalFeeSats() {
            return this.inboundBoltzPercentageFeeSats + this.inboundBoltzMinerFeeSats;
        },

        /** Sats the user will receive on-chain after fees. */
        get inboundReceiveOnchainSats() {
            const amount = Number(this.inboundAmountSats) || 0;
            return Math.max(0, amount - this.inboundTotalFeeSats);
        },

        /** Submit-button gate. */
        get inboundCanSubmit() {
            if (this.inboundLoading) return false;
            if (!this.inboundBoltzReachable) return false;
            const amount = Number(this.inboundAmountSats) || 0;
            if (amount < BOLTZ_MIN_AMOUNT_SATS) return false;
            if (amount > BOLTZ_MAX_AMOUNT_SATS) return false;
            if (amount > this.inboundLocalBalanceSats) return false;
            return true;
        },

        /** Validation message for the amount input — surfaced inline
         *  next to the input when non-empty. Distinct from
         *  ``inboundError`` (which carries server errors after
         *  submit). */
        get inboundAmountError() {
            const amount = Number(this.inboundAmountSats) || 0;
            if (amount <= 0) return '';
            if (amount < BOLTZ_MIN_AMOUNT_SATS) {
                return 'Minimum is ' + this.formatSats(BOLTZ_MIN_AMOUNT_SATS) + ' sats.';
            }
            if (amount > BOLTZ_MAX_AMOUNT_SATS) {
                return 'Maximum is ' + this.formatSats(BOLTZ_MAX_AMOUNT_SATS) + ' sats.';
            }
            if (amount > this.inboundLocalBalanceSats) {
                return 'You only have ' + this.formatSats(this.inboundLocalBalanceSats) +
                       ' sats available on your channel.';
            }
            return '';
        },

        /** Mapped 0-3 progress index for the view. */
        get inboundProgressStepIndex() {
            return _swapUserStepIndex(this.inboundSwapStatus);
        },

        /** Cancel button is visible only in ``created``. */
        get inboundIsCancellable() {
            return this.inboundSwapStatus === 'created';
        },

        /** The claim-tx affordance appears in the progress view once
         *  the wallet has broadcast the claim — i.e. status is
         *  ``claimed`` or ``completed`` AND the swap detail has
         *  surfaced ``claim_txid``. */
        get inboundShouldShowClaimTxid() {
            if (!this.inboundClaimTxid) return false;
            return (this.inboundSwapStatus === 'claimed'
                    || this.inboundSwapStatus === 'completed');
        },

        /** Banner CTA / message shaping for the Receive-Lightning
         *  dialog. Each branch returns a small struct the template
         *  reads via ``x-text`` / ``:disabled``. Returns null when
         *  no banner is needed. */
        get inboundBannerPayload() {
            const kind = this.inboundBannerKind;
            if (!kind) return null;
            if (this.inboundChannelTooSmall) {
                return {
                    tone: 'warning',
                    text: 'Your channel is too small to add receive capacity automatically. Try opening a larger channel.',
                    cta: null,
                };
            }
            if (kind === 'block') {
                return {
                    tone: 'block',
                    text: "You can't receive Lightning payments yet.",
                    cta: 'Add receive capacity',
                };
            }
            // 'short' — soft warning.
            return {
                tone: 'short',
                text: 'You can only receive up to ' + this.formatSats(this.inboundCapacitySats) + ' sats right now.',
                cta: 'Add more capacity',
            };
        },

        // ── Methods ────────────────────────────────────────────────

        /** Open the dialog. ``seedRecvAmount`` is the amount the user
         *  was trying to invoice when they clicked through the "short"
         *  banner; pass 0 (or omit) from the generic entry point so
         *  the default falls back to ``local / 2``.
         *
         * "Multiple concurrent swaps": if an inbound
         *  swap is already in flight (an active swap id is pinned),
         *  the dialog opens straight to the progress view so the
         *  user picks up where they left off rather than starting a
         *  duplicate. */
        openInboundCapacity(seedRecvAmount) {
            if (this.inboundActiveSwapId
                    && this.inboundSwapStatus
                    && !SWAP_TERMINAL_STATUSES.has(this.inboundSwapStatus)) {
                // A swap is in flight. Route to the progress view
                // and make sure the poller is running (in case the
                // dialog was closed earlier and the poller stopped).
                this.inboundStep = 'progress';
                this.showInboundCapacity = true;
                if (!this._isPolling('inboundSwap')) {
                    this._startInboundPoller();
                }
                this.$nextTick(() => this.initIcons());
                return;
            }
            this.inboundSeedRecvAmount = parseInt(seedRecvAmount, 10) || 0;
            this.inboundStep = 'form';
            this.inboundAmountSats = null;
            this.inboundAmountTouched = false;
            this.inboundFeeBreakdownOpen = false;
            this.inboundLoading = false;
            this.inboundError = '';
            this.inboundClaimTxid = '';
            this.inboundClaimConfirmations = null;
            this.inboundSwapError = '';
            this.inboundDestinationAddress = '';
            // Make sure we have current Boltz fees — same pattern as
            // the Cold Storage dialog. ``fetchBoltzFees`` is idempotent
            // and caches the result.
            this.fetchBoltzFees();
            this.showInboundCapacity = true;
            this._maybePrefillInboundAmount();
            this.$nextTick(() => this.initIcons());
        },

        closeInboundCapacity() {
            this.showInboundCapacity = false;
            this._stopInboundPoller();
            // Intentionally do NOT clear the localStorage swap-id pin
            // here — the swap may still be in flight in the background;
            // clearing only happens on terminal status. The user's
            // next page load will resume the progress view if the
            // swap is still active.
        },

        _maybePrefillInboundAmount() {
            if (this.inboundAmountTouched) return;
            const suggested = this.inboundSuggestedAmount;
            if (suggested > 0) this.inboundAmountSats = suggested;
        },

        inboundMarkAmountTouched() {
            this.inboundAmountTouched = true;
        },

        inboundToggleFeeBreakdown() {
            this.inboundFeeBreakdownOpen = !this.inboundFeeBreakdownOpen;
        },

        /** Submit the form: mint a fresh on-chain address, POST the
         *  reverse swap, capture the swap_id, pin to localStorage,
         *  transition to the progress view, and start polling. */
        async submitInboundCapacity() {
            if (!this.inboundCanSubmit) return;
            this.inboundLoading = true;
            this.inboundError = '';
            let address;
            try {
                const addrData = await this.api('POST', '/address', {
                    address_type: 'p2wkh',
                    purpose: 'inbound_liquidity',
                });
                address = (addrData || {}).address || '';
                if (!address) {
                    throw new Error('Could not generate a receiving address.');
                }
            } catch (e) {
                this.inboundError = e.message || 'Could not generate a receiving address.';
                this.inboundLoading = false;
                return;
            }
            this.inboundDestinationAddress = address;
            try {
                const data = await this.api('POST', '/cold-storage/initiate', {
                    amount_sats: this.inboundAmountSats,
                    destination_address: address,
                    purpose: 'inbound_liquidity',
                });
                this.inboundActiveSwapId = (data || {}).id || null;
                this.inboundSwapStatus = (data || {}).status || 'created';
                if (this.inboundActiveSwapId) {
                    try {
                        sessionStorage.setItem(INBOUND_LOCALSTORAGE_KEY, this.inboundActiveSwapId);
                    } catch (_e) { /* private mode — non-fatal */ }
                    this.inboundStep = 'progress';
                    this._startInboundPoller();
                }
            } catch (e) {
                this.inboundError = e.message || 'Could not add receive capacity. Please try again.';
            }
            this.inboundLoading = false;
            this.$nextTick(() => this.initIcons());
        },

        /** Restore an in-progress swap on page load. Read the pinned
         *  swap-id from localStorage; if still non-terminal, hop
         *  straight to the progress view. */
        async _restoreInboundSwap() {
            let swapId;
            try {
                swapId = sessionStorage.getItem(INBOUND_LOCALSTORAGE_KEY) || '';
            } catch (_e) {
                swapId = '';
            }
            if (!swapId) return;
            let data;
            try {
                data = await this.api('GET', '/cold-storage/swaps/' + encodeURIComponent(swapId));
            } catch (_e) {
                // Network blip or swap was purged server-side. Drop the
                // pin so we don't keep retrying on every page load.
                try { sessionStorage.removeItem(INBOUND_LOCALSTORAGE_KEY); } catch (_e2) {}
                return;
            }
            if (!data || !data.status) return;
            if (SWAP_TERMINAL_STATUSES.has(data.status)) {
                // Already done — clear the pin and let the regular
                // summary refresh surface the new inbound capacity.
                try { sessionStorage.removeItem(INBOUND_LOCALSTORAGE_KEY); } catch (_e) {}
                return;
            }
            // Resume the progress view.
            this.inboundActiveSwapId = swapId;
            this.inboundSwapStatus = data.status;
            this.inboundClaimTxid = data.claim_txid || '';
            this.inboundClaimConfirmations = (typeof data.claim_confirmations === 'number')
                ? data.claim_confirmations : null;
            this.inboundAmountSats = data.invoice_amount_sats || null;
            this.inboundDestinationAddress = data.destination_address || '';
            this.inboundStep = 'progress';
            this.showInboundCapacity = true;
            this._startInboundPoller();
            this.$nextTick(() => this.initIcons());
        },

        /** 5 s tick that polls ``/cold-storage/swaps/{id}``. Same
         *  cadence as Cold Storage. Tears down on terminal status,
         *  user-close, or transport error. */
        _startInboundPoller() {
            this._stopInboundPoller();
            if (!this.inboundActiveSwapId) return;
            const swapId = this.inboundActiveSwapId;
            // Guarded — fire once immediately so the progress
            // view is fresh, then settle into the 5 s cadence with an
            // in-flight guard so a slow tick can't pile up.
            this._poll('inboundSwap', async () => {
                if (this.inboundActiveSwapId !== swapId) {
                    this._stopInboundPoller();
                    return;
                }
                let data;
                try {
                    data = await this.api('GET', '/cold-storage/swaps/' + encodeURIComponent(swapId));
                } catch (_e) {
                    // Don't tear down on transient failures — Boltz
                    // is Tor-routed; one missed tick is fine.
                    return;
                }
                if (!data || !data.status) return;
                this.inboundSwapStatus = data.status;
                this.inboundClaimTxid = data.claim_txid || '';
                this.inboundClaimConfirmations = (typeof data.claim_confirmations === 'number')
                    ? data.claim_confirmations : null;
                if (data.status === 'completed') {
                    this._onInboundSwapComplete();
                } else if (SWAP_TERMINAL_STATUSES.has(data.status)) {
                    this._onInboundSwapFailed(data.error_message || data.status);
                }
            }, { intervalMs: 5000, immediate: true });
        },

        _stopInboundPoller() {
            this._stopPoll('inboundSwap');
        },

        // Single-expression wrapper for the "Try again" button (the CSP
        // build can't parse a 4-assignment ';'-separated directive).
        inboundResetToForm() {
            this.inboundStep = 'form';
            this.inboundSwapError = '';
            this.inboundError = '';
            this.inboundActiveSwapId = null;
        },

        _onInboundSwapComplete() {
            this._stopInboundPoller();
            this.inboundStep = 'success';
            try { sessionStorage.removeItem(INBOUND_LOCALSTORAGE_KEY); } catch (_e) {}
            // Refresh summary so the banner / capacity readout
            // updates without waiting for the 30 s tick.
            this.fetchSummary();
            this.fetchTransactions();
            this.fetchChannels();
            this.$nextTick(() => this.initIcons());
        },

        _onInboundSwapFailed(reason) {
            this._stopInboundPoller();
            this.inboundSwapError = reason || 'The swap did not complete.';
            // Clear ``inboundError`` (the form/cancel-attempt error)
            // when crossing the step boundary — otherwise a failed
            // cancel that races with a terminal status could leave
            // a stale form-level message visible on next return to
            // the form via "Try again".
            this.inboundError = '';
            this.inboundStep = 'failed';
            try { sessionStorage.removeItem(INBOUND_LOCALSTORAGE_KEY); } catch (_e) {}
            // Refresh summary so any partial state (e.g. refunded
            // on-chain) is reflected without delay.
            this.fetchSummary();
            this.$nextTick(() => this.initIcons());
        },

        async cancelInboundSwap() {
            if (!this.inboundActiveSwapId) return;
            if (!this.inboundIsCancellable) return;
            try {
                await this.api('POST', '/cold-storage/swaps/' + encodeURIComponent(this.inboundActiveSwapId) + '/cancel');
            } catch (e) {
                this.inboundError = e.message || 'Could not cancel.';
                return;
            }
            // Drop the localStorage pin immediately on a
            // successful 200 rather than waiting for the next poller
            // tick. Without this, a refresh in the 0-5 s window
            // between cancel-200 and the poller seeing ``cancelled``
            // would have ``_restoreInboundSwap`` re-fetch a swap the
            // user has already explicitly dismissed.
            try { sessionStorage.removeItem(INBOUND_LOCALSTORAGE_KEY); } catch (_e) {}
            // Poll the cancelled status one more time so the view
            // routes to ``failed`` without waiting 5 s for the next
            // interval tick.
            if (this._isPolling('inboundSwap')) {
                // Restarting the guarded poller fires an immediate read
                // (immediate: true) on the next _startInboundPoller.
                this._startInboundPoller();
            }
        },

        /** Close inbound dialog and open Receive-Lightning, pre-
         *  filled if the user was originally trying to invoice an
         *  amount that triggered the soft warning. */
        inboundCreateInvoiceNow() {
            const seed = this.inboundSeedRecvAmount || 0;
            this.closeInboundCapacity();
            if (seed > 0) {
                this.recvAmountStr = String(seed);
            }
            this.showReceiveInvoice = true;
            this.$nextTick(() => this.initIcons());
        },

        /** Entry from the Receive-Lightning banner. Passes the
         *  currently-typed recv amount as the seed so the form's
         *  default suggestion covers it. */
        inboundOpenFromBanner() {
            const amount = parseInt(this.recvAmountStr, 10) || 0;
            this.showReceiveInvoice = false;
            this.openInboundCapacity(amount);
        },

        // ──────────────────────────────────────────────────────────────
        //  Open Inbound — per-channel receive capacity
        //
        //  Two ways to drain a chosen channel's local balance (which is
        //  what raises its inbound/remote balance):
        //    • on-chain  — a Boltz reverse swap, pinned to the channel,
        //                  landing sats in the user's own wallet.
        //    • lightning — pay an external invoice/LNURL/address out
        //                  through the channel (reuses the Send flow with
        //                  its source pinned to this channel).
        //  The on-chain tab mirrors the Add-Receive-Capacity wizard's
        //  proven swap lifecycle on its own ``ci*`` state + swap-id pin.
        // ──────────────────────────────────────────────────────────────

        /** Channel alias for the dialog header / progress copy. */
        get ciChannelAlias() {
            return this.ciChannel ? this.channelAlias(this.ciChannel) : '';
        },

        /** Percentage fee in sats for the typed amount. */
        get ciBoltzPercentageFeeSats() {
            const amount = Number(this.ciAmountSats) || 0;
            const fees = this.boltzFees || {};
            const pct = fees.fees_percentage || 0;
            return Math.ceil(amount * pct / 100);
        },
        get ciBoltzMinerFeeSats() {
            const fees = this.boltzFees || {};
            return (fees.fees_miner_lockup || 0) + (fees.fees_miner_claim || 0);
        },
        get ciTotalFeeSats() {
            return this.ciBoltzPercentageFeeSats + this.ciBoltzMinerFeeSats;
        },
        get ciReceiveOnchainSats() {
            const amount = Number(this.ciAmountSats) || 0;
            return Math.max(0, amount - this.ciTotalFeeSats);
        },
        /** Upper bound the user may move out of this channel: the
         *  channel's own spendable, capped by the live Boltz maximum,
         *  then reduced by the Lightning routing-fee buffer the backend
         *  reserves at confirm time. Without the buffer step, Max would
         *  fill a value that always trips the post-confirm "this channel
         *  only has X sats free" rejection. */
        get ciAmountCeiling() {
            const freeable = this.ciMaxFreeable || 0;
            // ``boltzFees.max`` is the sentinel ``-Infinity`` until the
            // fees fetch lands (and ``-Infinity`` is still ``typeof
            // 'number'``), so guard on finiteness and fall back to the
            // constant — otherwise the Max button would fill -Infinity.
            const fees = this.boltzFees || {};
            const boltzMax = (Number.isFinite(fees.max) && fees.max > 0) ? fees.max : BOLTZ_MAX_AMOUNT_SATS;
            const raw = Math.min(freeable, boltzMax);
            return _withBoltzBuffer(raw);
        },
        get ciBoltzReachable() {
            if (!this._boltzFeesFetched) return false;
            return typeof (this.boltzFees || {}).fees_percentage === 'number';
        },
        get ciFeesLoading() {
            return !this._boltzFeesFetched;
        },
        get ciAmountError() {
            const amount = Number(this.ciAmountSats) || 0;
            if (amount <= 0) return '';
            if (amount < BOLTZ_MIN_AMOUNT_SATS) {
                return 'Minimum is ' + this.formatSats(BOLTZ_MIN_AMOUNT_SATS) + ' sats.';
            }
            const ceiling = this.ciAmountCeiling;
            if (amount > ceiling) {
                return 'This channel can free up at most ' + this.formatSats(ceiling) + ' sats right now.';
            }
            return '';
        },
        get ciCanSubmit() {
            if (this.ciLoading || this.ciGenerating) return false;
            if (!this.ciBoltzReachable) return false;
            if (!this.ciAddress) return false;
            const amount = Number(this.ciAmountSats) || 0;
            if (amount < BOLTZ_MIN_AMOUNT_SATS) return false;
            if (amount > this.ciAmountCeiling) return false;
            return true;
        },
        get ciProgressStepIndex() {
            return _swapUserStepIndex(this.ciSwapStatus);
        },
        get ciIsCancellable() {
            return this.ciSwapStatus === 'created';
        },
        get ciShouldShowClaimTxid() {
            if (!this.ciClaimTxid) return false;
            return (this.ciSwapStatus === 'claimed' || this.ciSwapStatus === 'completed');
        },
        /** Show the Boltz lockup-tx Mempool link IFF:
         *
         *    1. we know the lockup txid (Boltz has reported it), and
         *    2. our claim hasn't yet broadcast — once ``claim_txid`` is
         *       set, the claim tx is the more user-relevant link (it's
         *       the one that lands in the user's wallet); we hide the
         *       lockup link so the progress panel doesn't show two
         *       parallel mempool entries that confuse the user.
         *
         *  Result: during the "we paid LN, waiting for Boltz's lockup to
         *  confirm before we can claim" window the user sees a working
         *  Mempool link instead of a blank wait. */
        get ciShouldShowLockupTxid() {
            return !!this.ciLockupTxid && !this.ciClaimTxid;
        },
        /** Recovery banner gates — computed in JS because the CSP
         *  evaluator can't short-circuit dotted access on a null. */
        get ciShowRecoveryBanner() {
            const r = this.ciSwapRecovery;
            return !!(r && (r.severity === 'warning' || r.severity === 'critical'));
        },
        get ciRecoveryHasActions() {
            const r = this.ciSwapRecovery;
            return !!(r && r.actions && r.actions.length > 0);
        },
        /** Plain-language label for a recovery action (non-technical
         *  audience): "Retry claim" / "Recover on-chain". */
        ciRecoveryActionLabel(action) {
            if (action === 'cooperative_claim') return 'Retry claim';
            if (action === 'unilateral_claim') return 'Recover on-chain';
            return action;
        },

        /** Suggested default amount: half of what's freeable, clamped
         *  to ``[BOLTZ_MIN, ceiling]``. Returns 0 when the channel
         *  can't free at least the Boltz minimum. */
        get ciSuggestedAmount() {
            const ceiling = this.ciAmountCeiling;
            if (ceiling < BOLTZ_MIN_AMOUNT_SATS) return 0;
            let target = Math.floor((this.ciMaxFreeable || 0) / 2);
            target = Math.min(target, ceiling);
            target = Math.max(target, BOLTZ_MIN_AMOUNT_SATS);
            return target;
        },

        /** Open the per-channel dialog. If a per-channel swap is already
         *  in flight, route straight to its progress view (one swap at a
         *  time) regardless of which channel was clicked, so the user
         *  resumes rather than starting a duplicate. */
        openChannelInbound(ch) {
            if (this.ciActiveSwapId
                    && this.ciSwapStatus
                    && !SWAP_TERMINAL_STATUSES.has(this.ciSwapStatus)) {
                const sameChannel = !!(this.ciChannel && ch && this.ciChannel.chan_id === ch.chan_id);
                this.ciTab = 'onchain';
                this.showChannelInbound = true;
                if (sameChannel) {
                    // Resume this channel's own in-flight swap.
                    this.ciStep = 'progress';
                    if (!this._isPolling('ciSwap')) this._startCiPoller();
                } else {
                    // One swap at a time: a transfer is already running on a
                    // *different* channel. Don't hijack the dialog — show a
                    // notice (naming the busy channel) and offer to view it.
                    this.ciStep = 'busy';
                }
                this.$nextTick(() => this.initIcons());
                return;
            }
            this.ciChannel = ch;
            this.ciMaxFreeable = this.rebalanceMaxSendable(ch);
            this.ciTab = 'onchain';
            this.ciStep = 'form';
            this.ciAddress = '';
            this.ciAmountSats = null;
            this.ciAmountTouched = false;
            this.ciSuggestedRetryAmount = 0;
            this.ciFeeBreakdownOpen = false;
            this.ciAdvancedOpen = false;
            this.ciGenerating = false;
            this.ciLoading = false;
            this.ciError = '';
            this.ciClaimTxid = '';
            this.ciClaimConfirmations = null;
            this.ciLockupTxid = '';
            this.ciLockupConfirmations = null;
            this.ciSwapError = '';
            // Clear any prior (terminal) swap identity so a fresh start
            // can't be confused with a stale completed/failed swap.
            this.ciActiveSwapId = null;
            this.ciSwapStatus = null;
            this.ciSwapRecovery = null;
            this.ciRecoveryBusy = false;
            this.ciRecoveryError = '';
            // Re-check liveness at click time: the card only shows the
            // button for active channels, but a channel can drop between
            // render and click. Surface a notice rather than letting the
            // submit fail opaquely at the backend.
            if (ch && !ch.active) {
                this.ciError = 'This channel is offline right now, so it can’t send. Try again once it reconnects.';
            }
            // Lightning tab reuses the Send-Payment machinery; pin its
            // source channel so the payment leaves through this channel.
            this.resetSendPayment();
            this.pay.source = ch;
            this.fetchBoltzFees();
            this.showChannelInbound = true;
            this._ciMaybePrefillAmount();
            this.$nextTick(() => this.initIcons());
        },

        closeChannelInbound() {
            this.showChannelInbound = false;
            this._stopCiPoller();
            // Unpin the Send source so a later *global* Send isn't
            // unexpectedly constrained to this channel.
            this.pay.source = null;
            // Intentionally keep the swap-id pin: a swap may still be in
            // flight; it's cleared only on terminal status.
        },

        ciSelectTab(tab) {
            this.ciTab = tab;
            this.$nextTick(() => this.initIcons());
        },

        /** From the "busy on another channel" notice: jump to the
         *  in-flight swap's progress view. */
        ciViewRunningSwap() {
            this.ciStep = 'progress';
            if (!this._isPolling('ciSwap')) this._startCiPoller();
            this.$nextTick(() => this.initIcons());
        },

        _ciMaybePrefillAmount() {
            if (this.ciAmountTouched) return;
            const suggested = this.ciSuggestedAmount;
            if (suggested > 0) this.ciAmountSats = suggested;
        },
        ciMarkAmountTouched() {
            this.ciAmountTouched = true;
        },
        ciToggleFeeBreakdown() {
            this.ciFeeBreakdownOpen = !this.ciFeeBreakdownOpen;
        },
        ciSetMaxAmount() {
            this.ciAmountTouched = true;
            this.ciAmountSats = this.ciAmountCeiling;
        },

        /** Mint a fresh native-SegWit address in the user's own wallet
         *  for the swap's on-chain leg. */
        async ciGenerateAddress() {
            this.ciGenerating = true;
            this.ciError = '';
            try {
                const data = await this.api('POST', '/address', {
                    address_type: 'p2wkh',
                    purpose: 'inbound_liquidity',
                });
                this.ciAddress = (data || {}).address || '';
                if (!this.ciAddress) throw new Error('Could not generate an address.');
            } catch (e) {
                this.ciError = e.message || 'Could not generate an address.';
            }
            this.ciGenerating = false;
            this.$nextTick(() => this.initIcons());
        },

        /** Start the channel-pinned reverse swap. */
        async ciStartSwap() {
            if (!this.ciCanSubmit) return;
            if (!this.ciChannel || !this.ciChannel.chan_id) return;
            this.ciLoading = true;
            this.ciError = '';
            this.ciSuggestedRetryAmount = 0;
            try {
                const data = await this.api('POST', '/cold-storage/initiate', {
                    amount_sats: this.ciAmountSats,
                    destination_address: this.ciAddress,
                    purpose: 'inbound_liquidity',
                    outgoing_chan_id: String(this.ciChannel.chan_id),
                });
                this.ciActiveSwapId = (data || {}).id || null;
                this.ciSwapStatus = (data || {}).status || 'created';
                if (this.ciActiveSwapId) {
                    this._ciPersistPin();
                    this.ciStep = 'progress';
                    this._startCiPoller();
                }
            } catch (e) {
                this.ciError = e.message || 'Could not start the transfer. Please try again.';
                // Backend ships ``suggested_amount_sats`` on the
                // insufficient-balance rejection so the UI can offer a
                // one-click retry. Only surface it when it's actually
                // submittable (≥ Boltz minimum) — otherwise the button
                // would lead to a "below the minimum" rejection.
                const detail = e && e.detail;
                const suggested = detail && Number(detail.suggested_amount_sats);
                if (Number.isFinite(suggested)
                    && suggested >= BOLTZ_MIN_AMOUNT_SATS
                    && suggested < (this.ciAmountSats || 0)) {
                    this.ciSuggestedRetryAmount = Math.floor(suggested);
                }
            }
            this.ciLoading = false;
            this.$nextTick(() => this.initIcons());
        },

        /** One-click "Try with X sats instead" handler — fills the
         *  amount with the backend's suggestion, clears the error +
         *  suggestion, leaves the user on the confirm step ready to
         *  click "Open inbound room" again. */
        ciAcceptSuggestedRetry() {
            if (!this.ciSuggestedRetryAmount) return;
            this.ciAmountSats = this.ciSuggestedRetryAmount;
            this.ciAmountTouched = true;
            this.ciSuggestedRetryAmount = 0;
            this.ciError = '';
            this.$nextTick(() => this.initIcons());
        },

        _ciPersistPin() {
            try {
                sessionStorage.setItem(CHANNEL_INBOUND_LOCALSTORAGE_KEY, JSON.stringify({
                    swapId: this.ciActiveSwapId,
                    chanId: (this.ciChannel && this.ciChannel.chan_id) || '',
                }));
            } catch (_e) { /* private mode — non-fatal */ }
        },
        _ciClearPin() {
            try { sessionStorage.removeItem(CHANNEL_INBOUND_LOCALSTORAGE_KEY); } catch (_e) {}
        },

        _startCiPoller() {
            this._stopCiPoller();
            if (!this.ciActiveSwapId) return;
            const swapId = this.ciActiveSwapId;
            this._poll('ciSwap', async () => {
                if (this.ciActiveSwapId !== swapId) {
                    this._stopCiPoller();
                    return;
                }
                let data;
                try {
                    data = await this.api('GET', '/cold-storage/swaps/' + encodeURIComponent(swapId));
                } catch (_e) {
                    // Boltz is Tor-routed; tolerate a missed tick.
                    return;
                }
                if (!data || !data.status) return;
                this.ciSwapStatus = data.status;
                this.ciClaimTxid = data.claim_txid || '';
                this.ciClaimConfirmations = (typeof data.claim_confirmations === 'number')
                    ? data.claim_confirmations : null;
                this.ciLockupTxid = data.lockup_txid || '';
                this.ciLockupConfirmations = (typeof data.lockup_confirmations === 'number')
                    ? data.lockup_confirmations : null;
                // Backend recovery classifier hint — drives the
                // one-tap "Retry claim" / "Recover on-chain" banner
                // for a stuck swap.
                this.ciSwapRecovery = (data && data.recovery) ? data.recovery : null;
                if (data.status === 'completed') {
                    this._onCiSwapComplete();
                } else if (SWAP_TERMINAL_STATUSES.has(data.status)) {
                    this._onCiSwapFailed(data.error_message || data.status);
                }
            }, { intervalMs: 5000, immediate: true });
        },
        _stopCiPoller() {
            this._stopPoll('ciSwap');
        },

        _onCiSwapComplete() {
            this._stopCiPoller();
            this.ciStep = 'success';
            this._ciClearPin();
            this.fetchSummary();
            this.fetchChannels();
            this.fetchTransactions();
            this.$nextTick(() => this.initIcons());
        },
        _onCiSwapFailed(reason) {
            this._stopCiPoller();
            this.ciSwapError = reason || 'The transfer did not complete.';
            this.ciError = '';
            this.ciStep = 'failed';
            this._ciClearPin();
            this.fetchSummary();
            this.fetchChannels();
            this.$nextTick(() => this.initIcons());
        },

        ciResetToForm() {
            // Refresh the channel snapshot + spendable cap before showing
            // the form again. This matters when "Try again" is reached
            // after a swap that was *restored* from a page refresh (where
            // only a chan_id stub exists, so ciMaxFreeable would be 0),
            // and it keeps the cap current if balances shifted.
            if (this.ciChannel) {
                const fresh = (this.channels || []).find(c => c.chan_id === this.ciChannel.chan_id);
                if (fresh) this.ciChannel = fresh;
                this.ciMaxFreeable = this.rebalanceMaxSendable(this.ciChannel);
            }
            this.ciStep = 'form';
            this.ciSwapError = '';
            this.ciError = '';
            this.ciActiveSwapId = null;
            this.ciSwapStatus = null;
            this.ciSwapRecovery = null;
            this.ciRecoveryError = '';
        },

        async ciCancelSwap() {
            if (!this.ciActiveSwapId || !this.ciIsCancellable) return;
            try {
                await this.api('POST', '/cold-storage/swaps/' + encodeURIComponent(this.ciActiveSwapId) + '/cancel');
            } catch (e) {
                this.ciError = e.message || 'Could not cancel.';
                return;
            }
            this._ciClearPin();
            if (this._isPolling('ciSwap')) this._startCiPoller();
        },

        /** Operator-driven recovery for a stuck swap. ``action`` is one
         *  of the classifier's ``recovery.actions`` ids: ``cooperative_claim``
         *  (retry the claim) or ``unilateral_claim`` (script-path claim,
         *  valid post-timeout). Refreshes the poller on success. */
        async invokeCiRecoveryAction(action) {
            if (!this.ciActiveSwapId || this.ciRecoveryBusy) return;
            const path = action === 'unilateral_claim'
                ? '/cold-storage/swaps/' + encodeURIComponent(this.ciActiveSwapId) + '/unilateral-claim'
                : '/cold-storage/swaps/' + encodeURIComponent(this.ciActiveSwapId) + '/cooperative-claim';
            this.ciRecoveryBusy = true;
            this.ciRecoveryError = '';
            try {
                await this.api('POST', path);
                if (this._isPolling('ciSwap')) this._startCiPoller();
            } catch (e) {
                this.ciRecoveryError = (e && e.message) || 'Recovery action failed.';
            }
            this.ciRecoveryBusy = false;
        },

        /** Lightning tab: decode a BOLT11 or resolve an LNURL/address,
         *  branching on the detected input type. Kept in JS so the
         *  CSP template doesn't need a method-calling ternary. */
        ciContinueLightning() {
            if (this.payInputType === 'bolt11') {
                this.decodeInvoice();
            } else {
                this.resolveLnurl();
            }
        },

        /** Lightning tab: clear the send state for another payment while
         *  keeping the source pinned to this channel (``resetSendPayment``
         *  clears the pin, so we re-apply it). */
        ciResetPayment() {
            this.resetSendPayment();
            this.pay.source = this.ciChannel;
            this.$nextTick(() => this.initIcons());
        },

        /** Lightning tab: pay the external destination out through this
         *  channel, then refresh channels so the card updates. The
         *  source pin was set in ``openChannelInbound``. */
        async ciSendPayment() {
            await this.sendPayment();
            if (this.payResult && this.payResult.success) {
                this.fetchChannels();
            }
        },

        /** Resume an in-flight per-channel swap after a page refresh. */
        async _restoreChannelInbound() {
            let raw;
            try {
                raw = sessionStorage.getItem(CHANNEL_INBOUND_LOCALSTORAGE_KEY) || '';
            } catch (_e) {
                return;
            }
            if (!raw) return;
            let pin;
            try {
                pin = JSON.parse(raw);
            } catch (_e) {
                this._ciClearPin();
                return;
            }
            const swapId = pin && pin.swapId;
            if (!swapId) { this._ciClearPin(); return; }
            let data;
            try {
                data = await this.api('GET', '/cold-storage/swaps/' + encodeURIComponent(swapId));
            } catch (_e) {
                this._ciClearPin();
                return;
            }
            if (!data || !data.status) return;
            if (SWAP_TERMINAL_STATUSES.has(data.status)) {
                this._ciClearPin();
                return;
            }
            // Resume the progress view. Rebuild a minimal channel stub
            // from the pinned chanId + the live channel list (if loaded)
            // so the header can still name the channel.
            const stub = (this.channels || []).find(c => c.chan_id === (pin.chanId || '')) || { chan_id: pin.chanId || '' };
            this.ciChannel = stub;
            this.ciActiveSwapId = swapId;
            this.ciSwapStatus = data.status;
            this.ciClaimTxid = data.claim_txid || '';
            this.ciClaimConfirmations = (typeof data.claim_confirmations === 'number')
                ? data.claim_confirmations : null;
            this.ciSwapRecovery = (data && data.recovery) ? data.recovery : null;
            this.ciAmountSats = data.invoice_amount_sats || null;
            this.ciAddress = data.destination_address || '';
            this.ciTab = 'onchain';
            this.ciStep = 'progress';
            this.showChannelInbound = true;
            this._startCiPoller();
            this.$nextTick(() => this.initIcons());
        },

        // ──────────────────────────────────────────────────────────────
        //  Close Channels — multi-select
        //
        //  Cooperative close for online peers (fast, cheap); force close
        //  for offline peers (broadcasts our commitment; funds are
        //  time-locked until the channel's CSV matures). Force is
        //  auto-detected from each channel's active flag.
        // ──────────────────────────────────────────────────────────────
        openCloseChannels() {
            this.closeStep = 'select';
            this.closeSearch = '';
            this.closeSortBy = 'local_desc';
            this.closeShowInactive = true;
            this.closeSelected = [];
            this.closeResults = [];
            this.closeRunning = false;
            this.showCloseChannels = true;
            this.$nextTick(() => this.initIcons());
        },
        closeCloseChannels() {
            this.showCloseChannels = false;
        },

        /** Channels eligible to close, filtered + sorted for the picker. */
        closeCandidates() {
            const search = (this.closeSearch || '').trim().toLowerCase();
            const all = (this.channels || []).filter(c => {
                // Hide a channel whose close was already requested this
                // session (it's mid-relocation to the closing section).
                if (this.isChannelClosing(c)) return false;
                if (!this.closeShowInactive && !c.active) return false;
                if (!search) return true;
                const alias = (c.peer_alias || '').toLowerCase();
                const pk = (c.remote_pubkey || '').toLowerCase();
                return alias.includes(search) || pk.startsWith(search);
            });
            const sortBy = this.closeSortBy;
            return all.slice().sort((a, b) => {
                if (sortBy === 'alias') return this.channelAlias(a).localeCompare(this.channelAlias(b));
                if (sortBy === 'capacity') return (b.capacity || 0) - (a.capacity || 0);
                // 'local_desc' — most local balance to free up first.
                return (b.local_balance || 0) - (a.local_balance || 0);
            });
        },
        closeIsSelected(ch) {
            return ch && this.closeSelected.indexOf(ch.chan_id) !== -1;
        },
        closeToggle(ch) {
            if (!ch || !ch.chan_id) return;
            const i = this.closeSelected.indexOf(ch.chan_id);
            if (i === -1) this.closeSelected.push(ch.chan_id);
            else this.closeSelected.splice(i, 1);
        },
        /** The selected channel objects (not just ids). */
        closeSelectedChannels() {
            const sel = this.closeSelected;
            return (this.channels || []).filter(c => sel.indexOf(c.chan_id) !== -1);
        },
        /** Force is required when the peer is offline (inactive channel). */
        closeWillForce(ch) {
            return !(ch && ch.active);
        },
        /** Total local balance that will return on-chain. */
        closeSelectedTotalSats() {
            return this.closeSelectedChannels().reduce((sum, c) => sum + (c.local_balance || 0), 0);
        },
        /** Selected channels split into cooperative vs force groups. */
        closeCoopGroup() {
            return this.closeSelectedChannels().filter(c => !this.closeWillForce(c));
        },
        closeForceGroup() {
            return this.closeSelectedChannels().filter(c => this.closeWillForce(c));
        },
        closeReview() {
            if (this.closeSelected.length === 0) return;
            this.closeStep = 'review';
            this.$nextTick(() => this.initIcons());
        },
        closeBack() {
            this.closeStep = 'select';
            this.$nextTick(() => this.initIcons());
        },

        /** Final confirm + per-channel close. Iterates the selection,
         *  calling the close endpoint once per channel, and records a
         *  per-channel result. Successes are dimmed on the main tab. */
        async confirmAndClose() {
            const targets = this.closeSelectedChannels();
            if (targets.length === 0) return;
            const n = targets.length;
            if (!await this.askConfirm({
                body: 'Close ' + n + ' channel' + (n === 1 ? '' : 's') + '? Their balances return to your on-chain wallet. This can\'t be undone.',
                ok: 'Close ' + n + ' channel' + (n === 1 ? '' : 's'),
                cancel: 'Keep open',
                dangerous: true,
            })) return;
            this.closeStep = 'progress';
            this.closeRunning = true;
            this.closeResults = [];
            for (const ch of targets) {
                const force = this.closeWillForce(ch);
                const entry = { chan_id: ch.chan_id, alias: this.channelAlias(ch), force, ok: false, error: '' };
                try {
                    await this.api('POST', '/channel/close', {
                        channel_point: ch.channel_point,
                        force,
                    });
                    entry.ok = true;
                    if (this.closeChanIds.indexOf(ch.chan_id) === -1) this.closeChanIds.push(ch.chan_id);
                } catch (e) {
                    entry.error = (e && e.message) || 'Close failed.';
                }
                this.closeResults.push(entry);
                this.$nextTick(() => this.initIcons());
            }
            this.closeRunning = false;
            this.fetchChannels();
            this.fetchSummary();
            this.$nextTick(() => this.initIcons());
        },

        /** Whether a failed close may be retried as a force close. Only
         *  offered when the channel's peer is now offline — force is the
         *  wrong tool while the peer is online (e.g. a coop close that
         *  failed on in-flight HTLCs should be waited out, not forced). */
        closeRetryIsForceable(result) {
            if (!result || result.ok) return false;
            const ch = (this.channels || []).find(c => c.chan_id === result.chan_id);
            return !!(ch && !ch.active);
        },

        /** Retry a failed cooperative close as a force close (the fix when
         *  the peer turned out to be offline). Guarded to offline channels
         *  so an online peer is never force-closed from a retry. */
        async closeForceRetry(result) {
            if (!this.closeRetryIsForceable(result)) return;
            const ch = (this.channels || []).find(c => c.chan_id === result.chan_id);
            if (!ch) { result.error = 'Channel no longer listed.'; return; }
            result.error = '';
            result.force = true;
            try {
                await this.api('POST', '/channel/close', { channel_point: ch.channel_point, force: true });
                result.ok = true;
                if (this.closeChanIds.indexOf(ch.chan_id) === -1) this.closeChanIds.push(ch.chan_id);
                this.fetchChannels();
                this.fetchSummary();
            } catch (e) {
                result.error = (e && e.message) || 'Force close failed.';
            }
            this.$nextTick(() => this.initIcons());
        },

        // ── Braiins Deposit (round-amount Hashpower deposit) ──

        /** Open the wizard. If a session is already in flight, jump
         *  straight to the progress view.
         *
         *  Synchronous click handler so the modal opens instantly.
         *  The /braiins-deposit/presets fetch (which hits LND for
         *  channel + wallet balances and can take 3-4 s over Tor) is
         *  moved to ``_refreshBraiinsDepositPresets`` and runs in the
         *  background. The form renders immediately using the
         *  dashboard's already-cached summary balances; the
         *  background fetch refines them when it lands. */
        openBraiinsDeposit() {
            // Seed the wizard's balance state from the dashboard's
            // already-cached summary so the form has sensible numbers
            // BEFORE the background presets fetch resolves. ``summary``
            // is refreshed periodically by the dashboard, so these are
            // usually only seconds stale.
            if (typeof this.localBalance === 'number') {
                this.braiinsDepositLnBalance = this.localBalance;
            }
            if (typeof this.confirmedBalance === 'number') {
                this.braiinsDepositOnchainBalance = this.confirmedBalance;
            }
            // Pre-fill source based on available balances —
            // prefer Lightning when sufficient, fall back to on-chain.
            // We only auto-select when there's no active in-flight
            // session (otherwise the session's stored source_kind is
            // restored further below).
            // ``braiinsDepositSession`` is always a safe-shape object,
            // so "no real session" is detected by the empty id, not
            // by falsiness. Terminal-status sessions also count as
            // "no active session" for auto-select purposes.
            if (!this.braiinsDepositSession.id
                    || SWAP_TERMINAL_STATUSES.has(this.braiinsDepositSession.status || '')) {
                this._braiinsDepositAutoSelectSource();
            }
            // If we already have a tracked session, reopen on its
            // progress view rather than restarting from form.
            //
            // External sources route to the ``await_funds`` step
            // while the session is waiting for the user to pay /
            // deposit. Once the session moves past AWAITING_*_FUNDS,
            // the standard ``progress`` view takes over.
            if (this.braiinsDepositSession
                    && this.braiinsDepositSession.status
                    && !SWAP_TERMINAL_STATUSES.has(this.braiinsDepositSession.status)) {
                const st = this.braiinsDepositSession.status;
                if (st === 'awaiting_ln_funds' || st === 'awaiting_onchain_funds') {
                    this.braiinsDepositStep = 'await_funds';
                } else {
                    this.braiinsDepositStep = 'progress';
                }
                this.braiinsDepositOpen = true;
                this._startBraiinsDepositPoller();
                this.$nextTick(() => this.initIcons());
                // Refresh presets in the background so any stale
                // values get refined (notably the ext kill switch).
                this._refreshBraiinsDepositPresets();
                return;
            }
            // Otherwise reset to a clean form. Clear any prior
            // session so the form doesn't carry forward stale txids
            // / amounts from the previous (terminal) session.
            this.braiinsDepositStep = 'form';
            this.braiinsDepositAmountSats = null;
            this.braiinsDepositAddress = '';
            this.braiinsDepositAddressError = '';
            this.braiinsDepositQuote = null;
            this.braiinsDepositError = '';
            this.braiinsDepositLoading = false;
            // Reset the per-session ``include_extras`` choice to
            // the default (true = dust-safe / recommended) so a
            // fresh form doesn't inherit the previous session's
            // opt-out. Each deposit is an independent decision.
            this.braiinsDepositIncludeExtras = true;
            this.braiinsDepositInfoTipOpen = '';
            this.braiinsDepositSession = _emptyBraiinsDepositSession();
            this.braiinsDepositSessionId = null;
            this.braiinsDepositHasActiveSession = false;
            this.braiinsDepositAllTxsOpen = false;
            this.braiinsDepositWhatHappensNextOpen = false;
            this.braiinsDepositOpen = true;
            this.$nextTick(() => this.initIcons());
            // Background refresh of presets + balances; modal already
            // visible at this point. When the fetch lands, the chip
            // affordability + balance displays sharpen up.
            this._refreshBraiinsDepositPresets();
            // Start the periodic per-bin quote refresh so
            // the bin floor stays accurate across fee swings while
            // the wizard is open.
            this._startBraiinsDepositQuotesByBinPoller();
        },

        /** Background refresh of the /braiins-deposit/presets payload
         *  (preset amounts, LN/on-chain balances, ext kill switch +
         *  invoice TTL ceiling). The wizard modal is already open by
         *  the time this fires; updates land in-place as the form
         *  reacts to fresh values. */
        async _refreshBraiinsDepositPresets() {
            let presets;
            try {
                presets = await this.api('GET', '/braiins-deposit/presets');
            } catch (_e) { return; /* non-fatal */ }
            if (!presets) return;
            if (Array.isArray(presets.preset_amounts)) {
                this.braiinsDepositPresets = presets.preset_amounts;
            }
            if (typeof presets.lightning_local_balance_sats === 'number') {
                this.braiinsDepositLnBalance = presets.lightning_local_balance_sats;
            }
            if (typeof presets.onchain_confirmed_balance_sats === 'number') {
                this.braiinsDepositOnchainBalance = presets.onchain_confirmed_balance_sats;
            }
            if (typeof presets.ext_enabled === 'boolean') {
                this.braiinsDepositExtEnabled = presets.ext_enabled;
            }
            if (typeof presets.channel_open_enabled === 'boolean') {
                this.braiinsDepositChannelOpenEnabled = presets.channel_open_enabled;
            }
            if (typeof presets.ext_ln_invoice_ttl_s === 'number') {
                this.braiinsDepositExtLnInvoiceTtlS = presets.ext_ln_invoice_ttl_s;
            }
            // Layer 3 adaptive bin floor. Fetch a quote for
            // every preset so the wizard can grey out infeasible
            // bins at current fees. Fire-and-forget; partial cache
            // population is acceptable (the unfetched bins just
            // don't get the adaptive disable until the quote lands).
            this._refreshBraiinsDepositQuotesByBin();
        },

        async _refreshBraiinsDepositQuotesByBin() {
            // Coalesce rapid invocations (source-kind clicks,
            // include-extras toggles, wizard re-opens) so we don't
            // fire N quotes per preset for every click. The user
            // can easily hit the 60/minute IP rate limit otherwise:
            // 10 presets × 6 source clicks = 60 in seconds.
            //
            // Pattern:
            //   - A short debounce window (220 ms) merges bursts of
            //     calls into one batch.
            //   - An epoch counter lets an in-flight batch detect
            //     that a newer batch has been queued and abort
            //     after its current request (no point finishing a
            //     stale source-kind's quotes).
            //   - The poller (60 s interval) flows through the same
            //     path; its tick is effectively immediate because
            //     no other call is pending when it fires.
            if (this._braiinsDepositQuotesByBinDebounce) {
                clearTimeout(this._braiinsDepositQuotesByBinDebounce);
            }
            this._braiinsDepositQuotesByBinDebounce = setTimeout(
                () => { this._runBraiinsDepositQuotesByBin(); }, 220
            );
        },

        async _runBraiinsDepositQuotesByBin() {
            // Fetch quotes for the current preset list and source
            // kind. Cache results keyed by bin amount.
            //
            // The CSRF-rotation serialisation that used to live here
            // now happens globally in ``api()`` for every state-
            // changing request. The local re-entry guard remains: a
            // 60 s poller drives this method; if a tick overruns its
            // interval, the next tick must not start a second
            // concurrent batch (would double the per-bin work and
            // overwrite ``braiinsDepositQuotesByBin`` mid-fill).
            if (this._braiinsDepositQuotesByBinInFlight) return;
            const presets = this.braiinsDepositPresets || [];
            if (!presets.length) return;
            this._braiinsDepositQuotesByBinInFlight = true;
            this.braiinsDepositQuotesByBinLoading = true;
            // Bump epoch so any *future* debounced call can abort
            // this batch by mismatching the epoch we capture below.
            this._braiinsDepositQuotesByBinEpoch =
                (this._braiinsDepositQuotesByBinEpoch || 0) + 1;
            const epoch = this._braiinsDepositQuotesByBinEpoch;
            const sourceKind = this.braiinsDepositSourceKind || 'lightning';
            const includeExtras = this.braiinsDepositIncludeExtras !== false;
            try {
                // One HTTP request for the whole preset cache. The
                // server returns { quotes: { "<amount>": <quote|null> } }.
                // This keeps us well under the 60/minute global IP
                // rate limit even when other dashboard pollers are
                // active (balances, sessions, channels, …).
                let resp;
                try {
                    resp = await this.api(
                        'POST', '/braiins-deposit/quotes-batch',
                        {
                            amount_sats_list: presets.slice(),
                            source_kind: sourceKind,
                            include_extras: includeExtras,
                            funding_strategy: this.braiinsDepositFundingStrategy,
                        },
                    );
                } catch (_e) {
                    // Whole-batch failure (e.g. 429, network blip).
                    // Leave the existing cache in place rather than
                    // clobbering it with an empty object — the next
                    // poller tick will retry.
                    return;
                }
                // Drop the result if a newer batch was queued mid-flight
                // (user toggled source/extras) or the wizard was closed.
                if (epoch !== this._braiinsDepositQuotesByBinEpoch) return;
                if (!this.braiinsDepositOpen) return;
                const out = {};
                const quotes = (resp && resp.quotes) || {};
                for (const amt of presets) {
                    const q = quotes[String(amt)];
                    if (q) out[amt] = q;
                }
                this.braiinsDepositQuotesByBin = out;
            } finally {
                this.braiinsDepositQuotesByBinLoading = false;
                this._braiinsDepositQuotesByBinInFlight = false;
            }
        },

        /** Reset to a clean Step-1 form view from the Done view —
         * the wizard's "Make another" affordance. Clears
         *  the previous session AND re-runs ``openBraiinsDeposit``
         *  so balances + auto-selected source reflect the post-
         *  deposit state (the user just spent some sats; the chip
         *  affordability calculus has likely changed). */
        async braiinsDepositMakeAnother() {
            this.braiinsDepositAmountSats = null;
            this.braiinsDepositAddress = '';
            this.braiinsDepositAddressError = '';
            this.braiinsDepositQuote = null;
            this.braiinsDepositError = '';
            // Same rationale as the form-reset branch in
            // ``openBraiinsDeposit``: the include-extras choice is
            // per-session, so a fresh deposit starts at the
            // recommended default.
            this.braiinsDepositIncludeExtras = true;
            this.braiinsDepositInfoTipOpen = '';
            this.braiinsDepositSession = _emptyBraiinsDepositSession();
            this.braiinsDepositSessionId = null;
            this.braiinsDepositHasActiveSession = false;
            this.braiinsDepositAllTxsOpen = false;
            this.braiinsDepositWhatHappensNextOpen = false;
            // Clear any lingering ext-flow state too so the
            // next session lands cleanly.
            this.braiinsDepositExtRefundAddress = '';
            this.braiinsDepositExtRefundError = '';
            this._stopBraiinsDepositCountdown();
            this._stopBraiinsDepositExtPaymentReceived();
            // ``openBraiinsDeposit`` re-fetches presets (which
            // include live balances) and runs the source auto-select
            // when no active session is tracked. We've already
            // cleared ``braiinsDepositSession`` above, so it'll take
            // the form-reset branch.
            await this.openBraiinsDeposit();
        },

        closeBraiinsDeposit() {
            this.braiinsDepositOpen = false;
            this._stopBraiinsDepositPoller();
            this._stopBraiinsDepositCountdown();
            this._stopBraiinsDepositExtPaymentReceived();
            this._stopBraiinsDepositQuotesByBinPoller();
        },

        // Periodic refresh while the wizard is open so the
        // per-bin viability cache catches fee drift. Cadence is
        // 60 s: long enough to keep load light (one quote per bin
        // per minute), short enough that a user who dwells on the
        // wizard for several minutes sees fresh viability state.
        _startBraiinsDepositQuotesByBinPoller() {
            // Guarded. ``_refreshBraiinsDepositQuotesByBin`` keeps
            // its own in-flight flag too (it's also called directly), so
            // the double guard is harmless.
            this._poll('braiinsQuotes', () => {
                if (this.braiinsDepositOpen) {
                    return this._refreshBraiinsDepositQuotesByBin();
                }
                return Promise.resolve();
            }, { intervalMs: 60 * 1000, immediate: false });
        },
        _stopBraiinsDepositQuotesByBinPoller() {
            this._stopPoll('braiinsQuotes');
        },

        /** Clear the two-stage "Payment received!" transition timer
         *  + flag. Called from any code path that leaves the
         *  await_funds step (close, make-another, terminal status). */
        _stopBraiinsDepositExtPaymentReceived() {
            if (this._braiinsDepositExtPaymentReceivedTimer) {
                clearTimeout(this._braiinsDepositExtPaymentReceivedTimer);
                this._braiinsDepositExtPaymentReceivedTimer = null;
            }
            this.braiinsDepositExtPaymentReceived = false;
        },

        braiinsDepositCanAfford(amt) {
            // Affordability check uses the rough invoice headroom
            // for the currently-selected source. Final gating happens
            // server-side on session create.
            //
            // External sources don't gate on the wallet's
            // own balance — we don't know the user's external balance.
            // Every preset is enabled for ext sources.
            if (this.braiinsDepositSourceKind === 'ext_lightning'
                    || this.braiinsDepositSourceKind === 'ext_onchain') {
                return true;
            }
            if (this.braiinsDepositSourceKind === 'onchain') {
                // Prefer the exact required-on-chain figure from the
                // per-bin quote when available — it reflects the selected
                // funding strategy, including a channel-open deposit that
                // was BUMPED up to the channel minimum (which needs far
                // more on-chain than the bin, e.g. 150,000 for a 50,000
                // deposit). Falling back to the rough swap-headroom
                // estimate only before the per-bin cache has loaded.
                const q = this.braiinsDepositQuotesByBin
                    && this.braiinsDepositQuotesByBin[amt];
                if (q && typeof q.required_onchain_balance_sats === 'number'
                        && q.required_onchain_balance_sats > 0) {
                    return this.braiinsDepositOnchainBalance
                        >= q.required_onchain_balance_sats;
                }
                // On-chain source: ~3.5% LN headroom + ~0.5% submarine
                // pct + ~1000 sats lockup miner fee + funding-tx fee.
                const required = Math.ceil(amt * 1.045) + 5000;
                return this.braiinsDepositOnchainBalance >= required;
            }
            const required = Math.ceil(amt * 1.035) + 4000;
            return this.braiinsDepositLnBalance >= required;
        },

        // Layer 3 — adaptive bin floor at current fees.
        braiinsDepositBinViableAtCurrentFees(amt) {
            // If the per-bin quote cache hasn't loaded yet, treat
            // every bin as viable (don't disable buttons prematurely).
            // Once the cache populates, the ``arrival_feasible``
            // flag from each preset's quote gates the button.
            const q = this.braiinsDepositQuotesByBin
                && this.braiinsDepositQuotesByBin[amt];
            if (!q) return true;
            return q.arrival_feasible !== false;
        },
        braiinsDepositBinRecommended(amt) {
            // Tag the smallest currently-VIABLE-AND-AFFORDABLE bin
            // as "rec" so the user has a fee-aware default. Returns
            // false when no per-bin data exists yet.
            const presets = this.braiinsDepositPresets || [];
            for (const candidate of presets) {
                if (!this.braiinsDepositCanAfford(candidate)) continue;
                if (!this.braiinsDepositBinViableAtCurrentFees(candidate)) continue;
                return candidate === amt;
            }
            return false;
        },
        braiinsDepositBinTitle(amt) {
            if (!this.braiinsDepositCanAfford(amt)) {
                return 'Insufficient balance for this bin amount.';
            }
            if (!this.braiinsDepositBinViableAtCurrentFees(amt)) {
                return 'Network fees too high right now for this bin. '
                    + 'Pick a larger amount or wait for fees to drop.';
            }
            return '';
        },
        get braiinsDepositBinFloorActive() {
            // True when at least one preset is disabled due to fees
            // (used to gate the info line below the grid).
            const presets = this.braiinsDepositPresets || [];
            if (!Object.keys(this.braiinsDepositQuotesByBin || {}).length) {
                return false;
            }
            for (const amt of presets) {
                if (!this.braiinsDepositBinViableAtCurrentFees(amt)) {
                    return true;
                }
            }
            return false;
        },
        get braiinsDepositCurrentFeeRateVb() {
            // Surface the live fee rate from the active quote (the
            // adaptive-floor info line displays this).
            const q = this.braiinsDepositQuote
                || (this.braiinsDepositQuotesByBin
                    && Object.values(this.braiinsDepositQuotesByBin)[0]);
            return (q && q.arrival_current_fee_rate_vb) || 0;
        },

        // Arrival display + range disclosure.
        get braiinsDepositArrivalInfeasible() {
            // Dedicated getter (rather than a template-side `quote &&
            // quote.arrival_feasible === false` expression) because the
            // Alpine CSP build's evaluator doesn't short-circuit
            // through dotted property access on null.
            const q = this.braiinsDepositQuote;
            return !!q && q.arrival_feasible === false;
        },
        get braiinsDepositArrivalHasRange() {
            const q = this.braiinsDepositQuote;
            if (!q) return false;
            const lo = Number(q.arrival_min_sats || 0);
            const hi = Number(q.arrival_max_sats || 0);
            // Range is "real" when min > 0 (feasible) and min < max.
            return lo > 0 && lo < hi;
        },
        get braiinsDepositArrivalDisplay() {
            const q = this.braiinsDepositQuote;
            if (!q) return '';
            // Infeasible: show the bin amount with a strikethrough-style
            // gray fallback so the user still sees what they asked for.
            if (q.arrival_feasible === false) {
                return this.formatSats(this.braiinsDepositAmountSats || 0) + ' sats';
            }
            const lo = Number(q.arrival_min_sats || 0);
            const hi = Number(q.arrival_max_sats || 0);
            if (lo > 0 && lo < hi) {
                return this.formatSats(lo) + ' – ' + this.formatSats(hi) + ' sats';
            }
            // Min == max (or unset): single value.
            const v = lo > 0 ? lo : (this.braiinsDepositAmountSats || 0);
            return this.formatSats(v) + ' sats';
        },

        /** Pick the default source based on available balances.
         *  For self sources, prefer Lightning when sufficient, fall
         *  back to on-chain. When neither
         *  self-source can afford the smallest preset, auto-select
         *  ext-LN (most users have an external Lightning wallet) —
         *  never auto-select ext-OC since its ~30-min confirmation
         *  wait is too friction-heavy to be a silent default.
         */
        _braiinsDepositAutoSelectSource(referenceAmount) {
            const amt = Number(referenceAmount)
                || (this.braiinsDepositPresets && this.braiinsDepositPresets[0])
                || 50000;
            const lnReq = Math.ceil(amt * 1.035) + 4000;
            const ocReq = Math.ceil(amt * 1.045) + 5000;
            if (this.braiinsDepositLnBalance >= lnReq) {
                this.braiinsDepositSourceKind = 'lightning';
            } else if (this.braiinsDepositOnchainBalance >= ocReq) {
                this.braiinsDepositSourceKind = 'onchain';
            } else if (this.braiinsDepositExtEnabled) {
                this.braiinsDepositSourceKind = 'ext_lightning';
            } else {
                this.braiinsDepositSourceKind = 'lightning';
            }
        },

        /** User clicks the source toggle. Persist the choice and
         *  re-fetch the quote against the new source. */
        braiinsDepositSelectSource(kind) {
            const valid = ['lightning', 'onchain', 'ext_lightning', 'ext_onchain'];
            if (valid.indexOf(kind) < 0) return;
            if (this.braiinsDepositSourceKind === kind) return;
            this.braiinsDepositSourceKind = kind;
            // Channel-open only applies to on-chain sources; reset to the
            // default swap strategy whenever the source changes so we never
            // carry a stale 'channel' choice onto a Lightning source.
            this.braiinsDepositFundingStrategy = 'swap';
            this.braiinsDepositChannelPeerReachable = null;
            this.braiinsDepositChannelPeerReason = '';
            this.braiinsDepositQuote = null;
            // Refresh the per-bin quote cache because the
            // submarine-leg surcharge for ``onchain``/``ext_onchain``
            // changes the expected_fresh_utxo, which can flip
            // feasibility for borderline bins.
            this.braiinsDepositQuotesByBin = {};
            this._refreshBraiinsDepositQuotesByBin();
            if (this.braiinsDepositAmountSats) {
                this._debounceBraiinsDepositQuote();
            }
        },

        /** Whether the "open a channel instead" advanced toggle should be
         *  offered: an on-chain source + the operator flag on. (The
         *  server still validates eligibility per amount.) */
        get braiinsDepositChannelOptionAvailable() {
            if (!this.braiinsDepositChannelOpenEnabled) return false;
            return this.braiinsDepositSourceKind === 'onchain'
                || this.braiinsDepositSourceKind === 'ext_onchain';
        },

        get braiinsDepositIsChannelStrategy() {
            return this.braiinsDepositFundingStrategy === 'channel';
        },

        /** Toggle between the swap and channel funding strategies and
         *  re-quote (the capacity / required-on-chain math differs).
         *  Switching to 'channel' kicks off the connect-peer preflight. */
        braiinsDepositSelectFundingStrategy(strategy) {
            if (strategy !== 'swap' && strategy !== 'channel') return;
            if (!this.braiinsDepositChannelOptionAvailable && strategy === 'channel') {
                return;
            }
            if (this.braiinsDepositFundingStrategy === strategy) return;
            this.braiinsDepositFundingStrategy = strategy;
            this.braiinsDepositChannelPeerReachable = null;
            this.braiinsDepositChannelPeerReason = '';
            this.braiinsDepositQuote = null;
            this.braiinsDepositQuotesByBin = {};
            this._refreshBraiinsDepositQuotesByBin();
            if (this.braiinsDepositAmountSats) {
                this._debounceBraiinsDepositQuote();
            }
            if (strategy === 'channel') {
                this._braiinsCheckChannelPeer();
            }
        },

        /** Connect-peer preflight: ask the server whether the channel peer
         *  for the current amount is reachable right now. Advisory — sets
         *  ``braiinsDepositChannelPeerReachable`` which gates Start and
         *  surfaces a soft warning. */
        async _braiinsCheckChannelPeer() {
            const amt = this.braiinsDepositAmountSats;
            if (!amt || !this.braiinsDepositIsChannelStrategy) return;
            this.braiinsDepositChannelPeerChecking = true;
            try {
                const data = await this.api(
                    'POST', '/braiins-deposit/channel-peer-check',
                    { amount_sats: amt },
                );
                // Ignore a stale response if the user flipped back to swap.
                if (!this.braiinsDepositIsChannelStrategy) return;
                this.braiinsDepositChannelPeerReachable = !!(data && data.reachable);
                this.braiinsDepositChannelPeerReason = (data && data.reason) || '';
            } catch (_e) {
                // Network/we-couldn't-check → leave as unknown (null) so we
                // don't hard-block on a transient check failure.
                this.braiinsDepositChannelPeerReachable = null;
            } finally {
                this.braiinsDepositChannelPeerChecking = false;
            }
        },

        braiinsDepositSelectAmount(amt) {
            if (!this.braiinsDepositCanAfford(amt)) return;
            this.braiinsDepositAmountSats = amt;
            this.braiinsDepositError = '';
            // Drop the previous quote immediately so the fee preview
            // and the "What happens next" block don't show numbers
            // computed against the old amount until the debounced
            // re-quote arrives.
            this.braiinsDepositQuote = null;
            this._debounceBraiinsDepositQuote();
            // The channel peer is amount-dependent (capacity → peer); re-run
            // the preflight when the amount changes under the channel strategy.
            if (this.braiinsDepositIsChannelStrategy) {
                this.braiinsDepositChannelPeerReachable = null;
                this._braiinsCheckChannelPeer();
            }
        },

        _debounceBraiinsDepositQuote() {
            if (this._braiinsDepositQuoteTimer) {
                clearTimeout(this._braiinsDepositQuoteTimer);
            }
            this._braiinsDepositQuoteTimer = setTimeout(
                () => this._fetchBraiinsDepositQuote(), 250
            );
        },

        async _fetchBraiinsDepositQuote() {
            if (!this.braiinsDepositAmountSats) return;
            // Capture the request context so we can discard a stale
            // response if the user changed source_kind / amount /
            // include_extras while the request was in flight. Without
            // this guard, a Lightning-shaped quote that lands after
            // the user has switched to On-chain will overwrite the
            // just-cleared quote with a payload that lacks the
            // ``submarine_*`` fields the on-chain template branch
            // dereferences, producing Alpine expression errors.
            const reqSourceKind = this.braiinsDepositSourceKind;
            const reqAmountSats = this.braiinsDepositAmountSats;
            const reqIncludeExtras = this.braiinsDepositIncludeExtras !== false;
            this.braiinsDepositQuoteLoading = true;
            try {
                const data = await this.api('POST', '/braiins-deposit/quote', {
                    amount_sats: reqAmountSats,
                    source_kind: reqSourceKind,
                    include_extras: reqIncludeExtras,
                    funding_strategy: this.braiinsDepositFundingStrategy,
                });
                if (this.braiinsDepositSourceKind !== reqSourceKind
                        || this.braiinsDepositAmountSats !== reqAmountSats
                        || (this.braiinsDepositIncludeExtras !== false) !== reqIncludeExtras) {
                    // User mutated the inputs while this request was
                    // in flight; a newer fetch is already scheduled.
                    // Drop this response on the floor.
                    return;
                }
                this.braiinsDepositQuote = data;
            } catch (e) {
                if (this.braiinsDepositSourceKind !== reqSourceKind
                        || this.braiinsDepositAmountSats !== reqAmountSats
                        || (this.braiinsDepositIncludeExtras !== false) !== reqIncludeExtras) {
                    return;
                }
                this.braiinsDepositQuote = null;
                this.braiinsDepositError = e.message || 'Could not fetch fee estimate.';
            } finally {
                if (this.braiinsDepositSourceKind === reqSourceKind
                        && this.braiinsDepositAmountSats === reqAmountSats
                        && (this.braiinsDepositIncludeExtras !== false) === reqIncludeExtras) {
                    this.braiinsDepositQuoteLoading = false;
                }
            }
        },

        /** User toggles the include-extras checkbox. Invalidate the
         *  current quote + the per-bin cache and re-fetch both
         *  against the new mode. Matches the source-kind switch
         *  flow so the wizard always shows numbers consistent with
         *  the broadcast mode the user just chose. */
        braiinsDepositSetIncludeExtras(value) {
            const next = !!value;
            if (this.braiinsDepositIncludeExtras === next) return;
            this.braiinsDepositIncludeExtras = next;
            this.braiinsDepositQuote = null;
            this.braiinsDepositQuotesByBin = {};
            this._refreshBraiinsDepositQuotesByBin();
            if (this.braiinsDepositAmountSats) {
                this._debounceBraiinsDepositQuote();
            }
        },

        get braiinsDepositCanStart() {
            if (!this.braiinsDepositAmountSats) return false;
            if (!this.braiinsDepositAddress || !this.braiinsDepositAddress.trim()) return false;
            if (this.braiinsDepositAddressError) return false;
            if (!this.braiinsDepositQuote) return false;
            // Dust-prevention infeasibility gate. When the
            // current fee rate would broadcast a tx that arrives
            // below the bin amount, refuse to start. The user
            // either picks a larger bin or waits for fees to drop.
            if (this.braiinsDepositQuote.arrival_feasible === false) {
                return false;
            }
            // Channel-open preflight gate: if the user picked the channel
            // strategy and the peer isn't reachable (or the amount isn't
            // channel-eligible), block Start with a soft reason.
            if (this.braiinsDepositIsChannelStrategy) {
                if (this.braiinsDepositQuote.channel_eligible === false) return false;
                if (this.braiinsDepositChannelPeerReachable === false) return false;
            }
            // Ext sources skip the Agent-Wallet balance gate
            // — the user funds the deposit from another wallet.
            if (this.braiinsDepositSourceKind === 'ext_lightning'
                    || this.braiinsDepositSourceKind === 'ext_onchain') {
                return true;
            }
            if (this.braiinsDepositSourceKind === 'onchain') {
                if (this.braiinsDepositOnchainBalance
                        < this.braiinsDepositQuote.required_onchain_balance_sats) {
                    return false;
                }
            } else if (this.braiinsDepositLnBalance
                    < this.braiinsDepositQuote.required_lightning_balance_sats) {
                return false;
            }
            return true;
        },

        get braiinsDepositStartHint() {
            if (!this.braiinsDepositAmountSats) return 'Choose an amount.';
            if (!this.braiinsDepositAddress.trim()) return 'Paste your Braiins deposit address.';
            if (this.braiinsDepositAddressError) return this.braiinsDepositAddressError;
            if (!this.braiinsDepositQuote) return 'Fetching fee estimate…';
            // Dust-prevention infeasibility hint.
            if (this.braiinsDepositQuote.arrival_feasible === false) {
                return 'Network fees too high for this bin amount right now. '
                    + 'Pick a larger amount or wait for fees to drop.';
            }
            // Ext sources never gate on the wallet's own
            // balance — there's nothing to hint about.
            if (this.braiinsDepositSourceKind === 'ext_lightning'
                    || this.braiinsDepositSourceKind === 'ext_onchain') {
                return '';
            }
            if (this.braiinsDepositSourceKind === 'onchain') {
                if (this.braiinsDepositOnchainBalance
                        < this.braiinsDepositQuote.required_onchain_balance_sats) {
                    return 'You need more on-chain balance for this amount.';
                }
            } else if (this.braiinsDepositLnBalance
                    < this.braiinsDepositQuote.required_lightning_balance_sats) {
                return 'You need more Lightning balance for this amount.';
            }
            return '';
        },

        // Label for the Start button — flips between self ("Start
        // deposit") and external ("Generate invoice → / Generate
        // address →") so the user knows whether clicking will debit
        // their wallet or just mint a receive primitive.
        get braiinsDepositStartButtonLabel() {
            if (this.braiinsDepositSourceKind === 'ext_lightning') {
                return 'Generate invoice →';
            }
            if (this.braiinsDepositSourceKind === 'ext_onchain') {
                return 'Generate address →';
            }
            return 'Start deposit';
        },

        // Step-2 panel "balance / payment" line. Adapts
        // per-source-kind: self sources show the wallet debit, ext
        // sources show the user's intake amount.
        get braiinsDepositDebitLabel() {
            switch (this.braiinsDepositSourceKind) {
                case 'onchain': return 'On-chain balance debited';
                case 'ext_lightning': return "You'll pay via Lightning";
                case 'ext_onchain': return "You'll send on-chain";
                default: return 'Lightning balance debited';
            }
        },

        get braiinsDepositDebitAmount() {
            if (!this.braiinsDepositQuote) return 0;
            const q = this.braiinsDepositQuote;
            switch (this.braiinsDepositSourceKind) {
                case 'onchain': return q.required_onchain_balance_sats || 0;
                case 'ext_lightning': return q.required_external_deposit_sats || 0;
                case 'ext_onchain': return q.required_external_deposit_sats || 0;
                default: return q.required_lightning_balance_sats || 0;
            }
        },

        // ── Null-safe quote-field accessors for the deposit dialog ──
        // The Alpine @alpinejs/csp evaluator does NOT short-circuit through
        // dotted property access: an inline `braiinsDepositQuote && braiinsDepositQuote.foo`
        // still throws "Cannot read property of null or undefined" while the
        // quote is null (initial open, and the brief null window while a quote
        // refresh clears braiinsDepositQuote before refilling it). Every quote
        // field the template renders therefore goes through one of these getters, where the guard
        // runs as ordinary JS. (Same constraint that gave us braiinsDepositArrivalInfeasible.)
        get braiinsDepositRequiredExternalSats() {
            const q = this.braiinsDepositQuote;
            return q ? (q.required_external_deposit_sats || 0) : 0;
        },
        get braiinsDepositSubmarineLockupSats() {
            const q = this.braiinsDepositQuote;
            return q ? (q.submarine_lockup_amount_sats || 0) : 0;
        },
        get braiinsDepositInvoiceAmountSats() {
            const q = this.braiinsDepositQuote;
            return q ? (q.invoice_amount_sats || 0) : 0;
        },
        get braiinsDepositTotalFeeSats() {
            const q = this.braiinsDepositQuote;
            return q ? (q.total_fee_sats || 0) : 0;
        },
        get braiinsDepositSubmarineServiceFeeSats() {
            const q = this.braiinsDepositQuote;
            return q ? ((q.submarine_percentage_fee_sats || 0) + (q.submarine_miner_fee_sats || 0)) : 0;
        },
        get braiinsDepositSubmarineFundingFeeSats() {
            const q = this.braiinsDepositQuote;
            return q ? (q.submarine_funding_fee_sats || 0) : 0;
        },
        get braiinsDepositBoltzServiceFeeSats() {
            const q = this.braiinsDepositQuote;
            return q ? ((q.boltz_percentage_fee_sats || 0) + (q.boltz_miner_fee_sats || 0)) : 0;
        },
        get braiinsDepositRoutingFeeSats() {
            const q = this.braiinsDepositQuote;
            return q ? (q.estimated_routing_fee_sats || 0) : 0;
        },
        get braiinsDepositSendFeeSats() {
            const q = this.braiinsDepositQuote;
            return q ? (q.estimated_send_fee_sats || 0) : 0;
        },
        get braiinsDepositChannelCapacitySats() {
            const q = this.braiinsDepositQuote;
            return q ? (q.channel_capacity_sats || 0) : 0;
        },
        get braiinsDepositChannelExcessToLnSats() {
            const q = this.braiinsDepositQuote;
            return q ? (q.channel_excess_to_ln_sats || 0) : 0;
        },
        get braiinsDepositChannelExcessPlusReserveSats() {
            const q = this.braiinsDepositQuote;
            return q ? ((q.channel_excess_to_ln_sats || 0) + (q.channel_reserve_sats || 0)) : 0;
        },
        get braiinsDepositChannelBumpedToMin() {
            const q = this.braiinsDepositQuote;
            return !!(q && q.channel_bumped_to_min);
        },
        // Gate for the channel-open disclosure block. Folds the old inline
        // `braiinsDepositIsChannelStrategy && braiinsDepositQuote && braiinsDepositQuote.channel_eligible`.
        get braiinsDepositShowChannelDisclosure() {
            const q = this.braiinsDepositQuote;
            return this.braiinsDepositIsChannelStrategy && !!q && !!q.channel_eligible;
        },

        // Plain-language one-line caption under the source picker.
        get braiinsDepositSourceCaption() {
            switch (this.braiinsDepositSourceKind) {
                case 'onchain':
                    return '';
                case 'ext_lightning':
                    return 'Pay a Lightning invoice from any other wallet — your phone, desktop, or a custodial service that supports Lightning withdrawals.';
                case 'ext_onchain':
                    return 'Send sats on-chain to a fresh address from any other wallet — a hardware wallet, exchange withdrawal, etc. About 20-30 min to confirm.';
                default: return '';
            }
        },

        // Wizard lead-in blurb. Lives in JS rather than an inline
        // ``x-text`` expression because the strings contain
        // apostrophes ("we'll") that would terminate single-quoted
        // JS literals — Alpine's @alpinejs/csp parser can't escape
        // them inside attribute values.
        get braiinsDepositLeadDescription() {
            if (this.braiinsDepositSourceKind === 'ext_lightning') {
                return "We'll show you a Lightning invoice to pay from your other "
                    + "wallet. Once you pay, we'll build a fresh Bitcoin transaction "
                    + "and send the deposit to Braiins (~10 minutes after your "
                    + "payment). You can close this window — we'll keep working.";
            }
            if (this.braiinsDepositSourceKind === 'ext_onchain') {
                return "We'll show you a Bitcoin address to send sats to from your "
                    + "other wallet. Once your deposit confirms, we'll build a fresh "
                    + "Bitcoin transaction and send it to Braiins. About 30 minutes "
                    + "end-to-end. You can close this window — we'll keep working.";
            }
            if (this.braiinsDepositSourceKind === 'onchain') {
                return "We'll move your on-chain sats to Lightning, then back to a fresh "
                    + "Bitcoin transaction, then send the round amount to Braiins. "
                    + "About 20 minutes end-to-end. You can close this window — we'll "
                    + "keep working in the background.";
            }
            return "We'll convert your Lightning balance into a fresh Bitcoin transaction "
                + "(~10 minutes), then send the round amount to Braiins. You can close "
                + "this window — we'll keep working in the background.";
        },

        /** Progress-step index for the dot row.
         *
         *  Lightning-source (3-dot): 0=building / 1=sending / 2=confirming
         *  On-chain-source (4-dot): 0=converting-to-LN / 1=building /
         *    2=sending / 3=confirming
         *
         *  Returns 0..N-1 where N depends on source.
         */
        /** Ordered list of progress-row dots for the current session.
         *  Each entry: ``{label, index}`` where ``index`` is the
         *  position in the row (0-based). The active step is
         *  ``braiinsDepositProgressStep``; dots whose index is ≤ that
         *  value are rendered as past-or-current.
         *
         * Dot-row variants:
         *      self-LN: Build BTC tx → Send → Confirming                       (3 dots)
         *      self-OC: Convert to LN → Build BTC tx → Send → Confirming        (4 dots)
         *      ext-LN:  Payment received → Build BTC tx → Send → Confirming     (4 dots)
         *      ext-OC:  Deposit confirmed → Convert to LN → Build BTC tx →
         *               Send → Confirming                                       (5 dots)
         */
        get braiinsDepositProgressDots() {
            const s = this.braiinsDepositSession;
            const sk = s && s.source_kind;
            const dots = [];
            if (sk === 'ext_lightning') {
                dots.push({ label: 'Payment received' });
            } else if (sk === 'ext_onchain') {
                dots.push({ label: 'Deposit confirmed' });
            }
            if (sk === 'onchain' || sk === 'ext_onchain') {
                dots.push({ label: 'Converting on-chain to Lightning' });
            }
            dots.push({ label: 'Building your Bitcoin transaction' });
            dots.push({ label: 'Sending to Braiins' });
            dots.push({ label: 'Confirming on the Bitcoin chain' });
            // Backfill 0-based indices so the template can compare
            // against ``braiinsDepositProgressStep`` without re-doing
            // the math inline.
            for (let i = 0; i < dots.length; i++) dots[i].index = i;
            return dots;
        },

        get braiinsDepositProgressStep() {
            const s = this.braiinsDepositSession;
            if (!s) return 0;
            // Ext-LN gets a 4-dot row whose first dot
            // ("Payment received") is already complete when the user
            // lands on the progress view. Ext-OC gets a 5-dot row
            // ("Deposit confirmed" + the 4 self-OC dots). The shared
            // index space is "everything past the leading-done dot",
            // so we shift +1 for ext sources.
            const isOnchainFlow = s.source_kind === 'onchain'
                                  || s.source_kind === 'ext_onchain';
            const isExt = s.source_kind === 'ext_lightning'
                          || s.source_kind === 'ext_onchain';
            if (isOnchainFlow) {
                // Self-OC + ext-OC share the same downstream pipeline.
                // For ext-OC we add a leading "Deposit confirmed" dot
                // that's always at-or-past, so the active index is
                // bumped by 1.
                const shift = isExt ? 1 : 0;
                if (['created', 'submarine_swapping', 'opening_channel'].includes(s.status)) return 0 + shift;
                if (s.status === 'swapping') return 1 + shift;
                // AWAITING_FEE_REDUCTION sits between FUNDED
                // and SENDING/BROADCAST. Treat it as the FUNDED dot:
                // the on-chain claim has landed; we're waiting for
                // the broadcast.
                if (['funded', 'sending', 'awaiting_fee_reduction'].includes(s.status)) return 2 + shift;
                if (s.status === 'broadcast' || s.status === 'completed') return 3 + shift;
                return 0 + shift;
            }
            // Lightning-source flow (self-LN or ext-LN). Ext-LN adds
            // a leading "Payment received" dot, shifting the active
            // index by 1.
            const shift = isExt ? 1 : 0;
            if (['created', 'awaiting_ln_funds', 'swapping'].includes(s.status)) return 0 + shift;
            if (['funded', 'sending', 'awaiting_fee_reduction'].includes(s.status)) return 1 + shift;
            if (s.status === 'broadcast' || s.status === 'completed') return 2 + shift;
            return 0 + shift;
        },

        get braiinsDepositCanRetrySend() {
            const s = this.braiinsDepositSession;
            return !!(s && s.status === 'failed' && s.fresh_utxo_txid);
        },

        get braiinsDepositFailureExplanation() {
            const s = this.braiinsDepositSession;
            if (!s) return 'We weren\'t able to complete this deposit.';
            if (s.fresh_utxo_txid) {
                return ('Your sats are safe — they\'re in your wallet as a Bitcoin '
                        + 'transaction. You can retry the send or send manually.');
            }
            // Connection-failed / Request-failed / 5xx-LND errors mean
            // the HTTP stream to LND dropped during the pay-invoice
            // call — LND does NOT cancel an in-flight HTLC when its
            // caller disconnects, so the LN balance may actually be
            // debited (held by Boltz). The 2026-05-21 incident hit
            // this branch with 101,920 sats stuck in a HOLD HTLC for
            // hours while the wizard said "not debited". Don't
            // mislead the user — surface the in-flight possibility.
            const err = (s.error_message || '').toLowerCase();
            const looksTransient = err.indexOf('connection failed') >= 0
                || err.indexOf('request failed') >= 0
                || err.indexOf('did not reach a terminal state') >= 0
                || err.indexOf('lnd error (5') >= 0;
            if (looksTransient) {
                return ('The connection to your node dropped during the '
                        + 'payment — the HTLC may still be in-flight at '
                        + 'Boltz. The wallet will retry recovery in the '
                        + 'background. If your local balance stays '
                        + 'reduced, check `lncli trackpayment` and '
                        + 'wait for the HOLD invoice to either settle '
                        + '(deposit completes) or expire (balance '
                        + 'restored).');
            }
            return ('Your Lightning balance was not debited.');
        },

        /** Change returned to the wallet after the on-chain deposit
         *  and send-fee land. Only meaningful in exact-amount mode
         *  (``include_extras=false``); dust-safe mode returns zero
         *  because the no-change tx leaves no wallet-side change.
         *  Prefers the server's ``expected_change_sats`` projection
         *  (which uses a more accurate vbytes count) and falls
         *  back to a local computation for resiliency. ``Math.max``
         *  is not exposed in @alpinejs/csp expressions so the
         *  computation lives here. */
        get braiinsDepositExpectedChangeSats() {
            const q = this.braiinsDepositQuote;
            if (!q) return 0;
            if (this.braiinsDepositIncludeExtras !== false) return 0;
            if (typeof q.expected_change_sats === 'number') {
                return q.expected_change_sats > 0 ? q.expected_change_sats : 0;
            }
            const fresh = Number(q.expected_fresh_utxo_sats) || 0;
            const sent = Number(this.braiinsDepositAmountSats) || 0;
            const fee = Number(q.estimated_send_fee_sats) || 0;
            const change = fresh - sent - fee;
            return change > 0 ? change : 0;
        },

        /** Sats the wallet absorbs into the deposit output when
         *  the user picked dust-safe mode. Equals the projected
         *  arrival minus the bin amount, clamped to zero. Used
         *  in the "What happens next" copy so the user sees a
         *  concrete number instead of just "extras". */
        get braiinsDepositAbsorbedExtrasSats() {
            const q = this.braiinsDepositQuote;
            if (!q) return 0;
            if (this.braiinsDepositIncludeExtras === false) return 0;
            const bin = Number(this.braiinsDepositAmountSats) || 0;
            const lo = Number(q.arrival_min_sats) || 0;
            const hi = Number(q.arrival_max_sats) || 0;
            // Show the smaller (high-fee) projection so the
            // user sees the conservative number.
            const v = lo > 0 ? lo : hi;
            const extras = v - bin;
            return extras > 0 ? extras : 0;
        },

        /** Whether the projected change UTXO would cost more to
         *  SPEND LATER (at a padded fee rate) than it's worth.
         *  Even when the change is non-zero now, the user has to
         *  spend it sometime, and a typical fee spike between now
         *  and then can flip it into uneconomical dust. Advisory
         *  only — the server still marks the quote feasible so the
         *  user can proceed if they accept the risk. Only
         *  meaningful when the user opted OUT of include-extras
         *  mode (otherwise no change UTXO exists). */
        get braiinsDepositChangeDustRisk() {
            if (this.braiinsDepositIncludeExtras !== false) return false;
            const q = this.braiinsDepositQuote;
            if (!q) return false;
            return q.expected_change_dust_risk === true;
        },

        /** The dust-spend threshold (sats) the server modeled for
         *  the dust-risk warning. Surfaced to the UI so the
         *  warning copy can quote a concrete number. */
        get braiinsDepositChangeDustThresholdSats() {
            const q = this.braiinsDepositQuote;
            if (!q) return 0;
            const v = Number(q.expected_change_dust_threshold_sats) || 0;
            return v > 0 ? v : 0;
        },

        /** Remaining sats the user still needs to send to the ext
         *  intake address to complete a partially-funded deposit.
         *  Same ``Math.max`` rationale as above. */
        get braiinsDepositExtRemainingSats() {
            const s = this.braiinsDepositSession;
            if (!s) return 0;
            const need = Number(s.ext_intake_amount_sats) || 0;
            const have = Number(s.ext_intake_received_sats) || 0;
            const remaining = need - have;
            return remaining > 0 ? remaining : 0;
        },

        // ── ext-OC mempool-detection state ──────────────────────────
        // Deposit txs seen at the intake address (incl. 0-conf), each
        // enriched by the detail endpoint with ``confirmations_live``.
        get braiinsDepositExtDetectedTxs() {
            const s = this.braiinsDepositSession;
            if (!s || s.source_kind !== 'ext_onchain') return [];
            return Array.isArray(s.ext_intake_txids) ? s.ext_intake_txids : [];
        },
        // Confirmations for one intake-tx record: prefer the live count
        // (enriched by the detail endpoint) over the persisted snapshot.
        _braiinsDepositTxConfs(t) {
            if (!t) return 0;
            if (typeof t.confirmations_live === 'number') return t.confirmations_live;
            if (typeof t.confirmations === 'number') return t.confirmations;
            return 0;
        },
        get braiinsDepositExtConfsRequired() {
            const s = this.braiinsDepositSession;
            const n = s && Number(s.ext_oc_confirmations_required);
            return (n && n > 0) ? n : 1;
        },
        // Detected deposits still BELOW the confirmation threshold — the
        // ones the wizard is actively waiting on. A confirmed-but-short
        // deposit is NOT here (the partial-deposit banner covers that).
        get braiinsDepositExtPendingTxs() {
            const req = this.braiinsDepositExtConfsRequired;
            return this.braiinsDepositExtDetectedTxs.filter(
                (t) => this._braiinsDepositTxConfs(t) < req,
            );
        },
        // True once a sub-threshold deposit is seen (mempool / confirming)
        // while still awaiting on-chain funds — drives the "detected,
        // waiting for confirmations" banner.
        get braiinsDepositExtDepositDetected() {
            const s = this.braiinsDepositSession;
            return !!(s
                && s.status === 'awaiting_onchain_funds'
                && this.braiinsDepositExtPendingTxs.length > 0);
        },
        // Lowest confirmation count across the pending deposits (the one
        // gating the advance).
        get braiinsDepositExtDetectedConfs() {
            const txs = this.braiinsDepositExtPendingTxs;
            if (!txs.length) return 0;
            let lowest = Infinity;
            for (const t of txs) {
                const c = this._braiinsDepositTxConfs(t);
                if (c < lowest) lowest = c;
            }
            return (lowest === Infinity) ? 0 : Math.max(0, lowest);
        },
        // The pending deposit txid to link to mempool.
        get braiinsDepositExtDetectedTxid() {
            const txs = this.braiinsDepositExtPendingTxs;
            return (txs[0] && txs[0].txid) || '';
        },

        // ── Submit ──────────────────────────────────────────────────

        async braiinsDepositStart() {
            if (!this.braiinsDepositCanStart) return;
            this.braiinsDepositLoading = true;
            this.braiinsDepositError = '';
            this.braiinsDepositChannelSuggested = false;
            const body = {
                amount_sats: this.braiinsDepositAmountSats,
                destination_address: this.braiinsDepositAddress.trim(),
                source_kind: this.braiinsDepositSourceKind,
                include_extras: this.braiinsDepositIncludeExtras !== false,
                funding_strategy: this.braiinsDepositFundingStrategy,
            };
            // Echo the quote's total fee so the server can
            // detect drift between Step 2 and Start.
            if (this.braiinsDepositQuote
                    && typeof this.braiinsDepositQuote.total_fee_sats === 'number') {
                body.expected_total_fee_sats = this.braiinsDepositQuote.total_fee_sats;
            }
            try {
                const data = await this.api('POST', '/braiins-deposit/sessions', body);
                this.braiinsDepositSession = data;
                this.braiinsDepositSessionId = (data || {}).id || null;
                this.braiinsDepositHasActiveSession = true;
                // Ext sources land on the await_funds step
                // (the wizard shows the invoice / address to pay).
                // Self sources go straight to progress.
                if (data
                        && (data.status === 'awaiting_ln_funds'
                            || data.status === 'awaiting_onchain_funds')) {
                    this.braiinsDepositStep = 'await_funds';
                } else {
                    this.braiinsDepositStep = 'progress';
                }
                this._startBraiinsDepositPoller();
                // Reflect the new session in the dedicated tab's list
                // so the pulse-dot lights immediately.
                this.braiinsDepositFetchSessions();
            } catch (e) {
                const msg = (e && e.message) || '';
                if (/already in progress/i.test(msg) || /in_flight/i.test(msg)) {
                    // Another session is already in flight — fetch
                    // and resume on the progress view instead of
                    // failing.
                    await this._restoreBraiinsDeposit();
                    if (this.braiinsDepositSessionId) {
                        this.braiinsDepositStep = 'progress';
                    } else {
                        this.braiinsDepositError = msg || 'A deposit is already in progress.';
                    }
                } else if (/quote_stale/i.test(msg)) {
                    // Fees changed between Step 2 and Start.
                    // Re-quote silently and surface a banner so the
                    // user confirms the new numbers before retrying.
                    await this._fetchBraiinsDepositQuote();
                    this.braiinsDepositError =
                        'Fees changed since you opened this — please review and start again.';
                } else {
                    this.braiinsDepositError = msg || 'Could not start the deposit.';
                    // D1(a) contextual recommendation: the server flagged
                    // that this on-chain swap can't be routed to our node
                    // but a channel-open would work. Offer it inline.
                    const detail = e && e.detail;
                    this.braiinsDepositChannelSuggested = !!(
                        detail && detail.channel_open_suggested
                        && this.braiinsDepositChannelOptionAvailable
                    );
                }
            }
            this.braiinsDepositLoading = false;
            this.$nextTick(() => this.initIcons());
        },

        /** D1(a): accept the inline "open a channel instead" recommendation
         *  after a swap deposit was refused for lack of inbound routing. */
        braiinsDepositAcceptChannelSuggestion() {
            this.braiinsDepositChannelSuggested = false;
            this.braiinsDepositError = '';
            this.braiinsDepositSelectFundingStrategy('channel');
        },

        async braiinsDepositCancel() {
            if (!this.braiinsDepositSessionId) return;
            try {
                await this.api('POST',
                    '/braiins-deposit/sessions/'
                    + encodeURIComponent(this.braiinsDepositSessionId)
                    + '/cancel');
            } catch (e) {
                this.braiinsDepositError = (e && e.message) || 'Could not cancel.';
                return;
            }
            // Force-poll once.
            await this._pollBraiinsDepositOnce();
            this.braiinsDepositFetchSessions();
        },

        async braiinsDepositRetrySend() {
            if (!this.braiinsDepositSessionId) return;
            try {
                const data = await this.api('POST',
                    '/braiins-deposit/sessions/'
                    + encodeURIComponent(this.braiinsDepositSessionId)
                    + '/retry-send');
                this.braiinsDepositSession = data;
                if (data && !SWAP_TERMINAL_STATUSES.has(data.status)) {
                    this.braiinsDepositStep = 'progress';
                    this._startBraiinsDepositPoller();
                }
                this.braiinsDepositFetchSessions();
            } catch (e) {
                this.braiinsDepositError = (e && e.message) || 'Retry failed.';
            }
        },

        // ── External-source wizard helpers ─────────────────────────

        /** Re-mint the Boltz reverse-swap invoice (ext-LN, when the
         *  previous invoice has expired or is close to expiring). */
        async braiinsDepositRegenerateInvoice() {
            if (!this.braiinsDepositSessionId) return;
            this.braiinsDepositLoading = true;
            this.braiinsDepositError = '';
            try {
                const data = await this.api('POST',
                    '/braiins-deposit/sessions/'
                    + encodeURIComponent(this.braiinsDepositSessionId)
                    + '/regenerate-invoice');
                this.braiinsDepositSession = data;
                // Reset the countdown ticker against the new expiry.
                this._refreshBraiinsDepositExtAwaitView(data);
                this.braiinsDepositFetchSessions();
            } catch (e) {
                this.braiinsDepositError =
                    (e && e.message) || 'Could not generate a new invoice.';
            }
            this.braiinsDepositLoading = false;
        },

        /** Submit a user-provided refund address for an ext-OC session
         *  that failed after receiving funds. */
        async braiinsDepositSubmitRefund() {
            const addr = (this.braiinsDepositExtRefundAddress || '').trim();
            if (!addr) {
                this.braiinsDepositExtRefundError =
                    'Paste an address from your other wallet.';
                return;
            }
            this.braiinsDepositExtRefundError = '';
            this.braiinsDepositLoading = true;
            try {
                const data = await this.api('POST',
                    '/braiins-deposit/sessions/'
                    + encodeURIComponent(this.braiinsDepositSessionId)
                    + '/submit-refund', { refund_address: addr });
                this.braiinsDepositSession = data;
                // Clear the input on success.
                this.braiinsDepositExtRefundAddress = '';
                this.braiinsDepositFetchSessions();
            } catch (e) {
                this.braiinsDepositExtRefundError =
                    (e && e.message) || 'Refund could not be sent.';
            }
            this.braiinsDepositLoading = false;
            this.$nextTick(() => this.initIcons());
        },

        /** Returns true when the failure screen should render the
         *  refund-prompt panel (ext-OC failed post-funds, no refund
         *  yet sent).
         *
         *  Gate: ``fresh_utxo_txid`` must be null. Once the Boltz
         *  reverse-swap claim has landed, the user's original deposit
         *  outpoints are gone (consumed by the submarine leg); a
         *  refund-send pinned to those outpoints would fail. After
         *  that point recovery is via "Retry send" (which spends the
         *  fresh claim UTXO into the Braiins address as planned). */
        get braiinsDepositNeedsRefund() {
            const s = this.braiinsDepositSession;
            if (!s) return false;
            if (s.source_kind !== 'ext_onchain') return false;
            if (s.status !== 'failed') return false;
            if ((s.ext_intake_received_sats || 0) <= 0) return false;
            if (s.refund_txid) return false;
            if (s.fresh_utxo_txid) return false;
            return true;
        },

        /** The Generate-new-invoice button stays disabled until either
         *  the countdown is below 5 minutes or the invoice has fully
         * expired. */
        get braiinsDepositCanRegenerateInvoice() {
            const s = this.braiinsDepositSession;
            if (!s || s.source_kind !== 'ext_lightning') return false;
            if (s.status !== 'awaiting_ln_funds') return false;
            // Treat unknown / zero countdown as "fully expired" so the
            // user can always recover from a stuck state.
            return this.braiinsDepositExtCountdownSeconds <= 300;
        },

        /** Cap that drives the countdown's color flip (true → red). */
        get braiinsDepositExtCountdownCritical() {
            return this.braiinsDepositExtCountdownSeconds > 0
                && this.braiinsDepositExtCountdownSeconds <= 300;
        },

        /** True once the ext-LN invoice countdown has hit zero AND
         *  the Boltz swap is still unpaid (no claim_txid). The
         *  await_funds screen swaps the QR + invoice card for a
         *  "This invoice expired" message at this point (plan
         *.a) so the user doesn't accidentally pay a dead
         *  invoice. ``braiinsDepositCanRegenerateInvoice`` becomes
         *  true here so the user can mint a fresh one. */
        get braiinsDepositExtInvoiceExpired() {
            const s = this.braiinsDepositSession;
            if (!s || s.source_kind !== 'ext_lightning') return false;
            if (s.status !== 'awaiting_ln_funds') return false;
            return this.braiinsDepositExtCountdownSeconds <= 0
                && this._braiinsDepositExtCountdownTimer !== null;
        },

        /** ``mm:ss`` countdown rendering. Returns "Expired" once at 0
         *  and "—" when no expiry is known (e.g. ext-OC sessions). */
        get braiinsDepositExtCountdownText() {
            const s = this.braiinsDepositSession;
            if (!s || s.source_kind !== 'ext_lightning') return '—';
            const total = this.braiinsDepositExtCountdownSeconds;
            if (total <= 0) return 'Expired';
            const mm = Math.floor(total / 60);
            const ss = total % 60;
            return mm + ':' + (ss < 10 ? '0' + ss : ss);
        },

        /** Update the await_funds view (countdown + QR rendering)
         *  every time the poller refreshes the session. */
        _refreshBraiinsDepositExtAwaitView(session) {
            if (!session) return;
            // Reset the countdown ticker against the latest expiry
            // timestamp. The ticker is a 1-Hz interval that recomputes
            // the seconds-remaining from the wall clock.
            if (session.source_kind === 'ext_lightning'
                    && session.ext_ln_invoice_expires_at) {
                this._scheduleBraiinsDepositCountdown(session.ext_ln_invoice_expires_at);
            } else {
                this._stopBraiinsDepositCountdown();
            }
            // Re-render the QR code lazily — only when the underlying
            // primitive changed. The renderer is best-effort: if the
            // QR library isn't available, the user still has the
            // click-to-copy text fallback.
            this.$nextTick(() => {
                this._renderBraiinsDepositQr(session);
                // Hydrate Lucide icons on this screen (e.g. the amount
                // copy button) — covers the poll-driven entry into
                // await_funds where no other initIcons fires.
                this.initIcons();
            });
        },

        _scheduleBraiinsDepositCountdown(expiresAtIso) {
            this._stopBraiinsDepositCountdown();
            const recompute = () => {
                const expiry = Date.parse(expiresAtIso);
                if (!isFinite(expiry)) {
                    this.braiinsDepositExtCountdownSeconds = 0;
                    return;
                }
                const now = Date.now();
                const remaining = Math.max(0, Math.floor((expiry - now) / 1000));
                this.braiinsDepositExtCountdownSeconds = remaining;
            };
            recompute();
            this._braiinsDepositExtCountdownTimer = setInterval(recompute, 1000);
        },

        _stopBraiinsDepositCountdown() {
            if (this._braiinsDepositExtCountdownTimer) {
                clearInterval(this._braiinsDepositExtCountdownTimer);
                this._braiinsDepositExtCountdownTimer = null;
            }
        },

        /** Render the QR for the await_funds primitive. Uses the
         *  same approach the Anonymize wizard uses (a canvas with an
         *  x-ref). Payload is a BIP-21 / lightning: URI for best
         *  external-wallet compatibility. */
        _renderBraiinsDepositQr(session) {
            if (!session) return;
            let canvas = null;
            let payload = '';
            if (session.source_kind === 'ext_lightning') {
                canvas = this.$refs && this.$refs.braiinsDepositExtLnQr;
                if (session.ext_ln_invoice) {
                    payload = 'lightning:' + session.ext_ln_invoice;
                }
            } else if (session.source_kind === 'ext_onchain') {
                canvas = this.$refs && this.$refs.braiinsDepositExtOcQr;
                if (session.ext_intake_address) {
                    const amount_btc = (
                        (session.ext_intake_amount_sats || 0) / 100_000_000
                    ).toFixed(8);
                    // BIP-21 URI with amount pre-filled.
                    payload = 'bitcoin:' + session.ext_intake_address
                        + '?amount=' + amount_btc
                        + '&label=Braiins%20Deposit';
                }
            }
            if (!canvas || !payload) return;
            // Re-use the dashboard-wide ``renderQr`` helper so we get
            // the same EC-level fallback the BOLT 12 offer flow uses.
            try { this.renderQr(canvas, payload); } catch (_e) { /* swallow */ }
        },

        /** Click-to-copy handlers for the await_funds primitives.
         *  Confirmation is the global "Copied!" toast raised by
         *  ``copyText`` — the cards show a copy icon + tooltip rather
         *  than an inline label. */
        async braiinsDepositCopyInvoice() {
            const s = this.braiinsDepositSession;
            if (!s || !s.ext_ln_invoice) return;
            await this.copyText(s.ext_ln_invoice);
        },

        async braiinsDepositCopyAddress() {
            const s = this.braiinsDepositSession;
            if (!s || !s.ext_intake_address) return;
            await this.copyText(s.ext_intake_address);
        },

        async braiinsDepositCopyAmount() {
            // Copy the RAW integer sats (no thousands separators) so it
            // pastes cleanly into another wallet's amount field.
            const s = this.braiinsDepositSession;
            const sats = s && s.ext_intake_amount_sats;
            if (!sats) return;
            await this.copyText(String(sats));
        },

        braiinsDepositToggleInfoTip(id) {
            this.braiinsDepositInfoTipOpen =
                this.braiinsDepositInfoTipOpen === id ? '' : id;
        },

        /** Glossary title/body lookups. CSP-safe (no expression
         *  computation in templates beyond a getter call). */
        braiinsDepositGlossaryTitle(id) {
            const entry = BRAIINS_DEPOSIT_GLOSSARY[id];
            return entry ? entry.title : '';
        },
        braiinsDepositGlossaryBody(id) {
            const entry = BRAIINS_DEPOSIT_GLOSSARY[id];
            return entry ? entry.body : '';
        },

        /** Render the server-side status_history into the
         *  timestamped progress log shown in the wizard's Step-3
         *  view. Each entry has shape ``{status, timestamp, detail?}``;
         *  we map status to plain-language text. */
        get braiinsDepositProgressLog() {
            const s = this.braiinsDepositSession;
            if (!s || !Array.isArray(s.status_history)) return [];
            return s.status_history.map((entry) => {
                const ts = entry && entry.timestamp
                    ? this._braiinsDepositFormatTime(entry.timestamp)
                    : '';
                const txt = this._braiinsDepositStatusLabel(entry && entry.status, entry && entry.detail);
                return { ts, text: txt, status: entry && entry.status };
            });
        },

        _braiinsDepositFormatTime(iso) {
            try {
                const d = new Date(iso);
                if (Number.isNaN(d.getTime())) return '';
                const hh = String(d.getHours()).padStart(2, '0');
                const mm = String(d.getMinutes()).padStart(2, '0');
                const ss = String(d.getSeconds()).padStart(2, '0');
                return hh + ':' + mm + ':' + ss;
            } catch (_e) { return ''; }
        },

        _braiinsDepositStatusLabel(status, detail) {
            switch (status) {
                case 'created':            return 'Started';
                case 'awaiting_ln_funds':  return 'Waiting for your Lightning payment';
                case 'awaiting_onchain_funds':
                    return 'Waiting for your on-chain deposit';
                case 'submarine_swapping': return 'Converting on-chain to Lightning';
                case 'opening_channel':    return 'Opening a Lightning channel';
                case 'swapping':           return 'Converting Lightning balance to a Bitcoin transaction';
                case 'funded':             return 'Received the Bitcoin transaction in your wallet';
                case 'sending':            return 'Sending to Braiins';
                case 'awaiting_fee_reduction':
                    // Wizard's per-step label for parked sessions —
                    // matches the dashboard-tab caption so a user
                    // sees the same context wherever they look.
                    return 'Waiting for network fees to drop';
                case 'broadcast':          return 'Sent to Braiins (waiting for confirmation)';
                case 'completed':          return 'Confirmed';
                case 'refunded':           return 'Refunded';
                case 'cancelled':          return 'Cancelled';
                case 'failed':             return 'Failed' + (detail ? (': ' + String(detail)) : '');
                default:                   return status || '';
            }
        },

        // Send-Onchain discovery hint.
        get sendOnchainShowBraiinsDepositHint() {
            if (!this.braiinsDepositEnabled) return false;
            // Respect the persistent dismissal.
            try {
                if (localStorage.getItem('braiinsDepositHintDismissed') === '1') {
                    return false;
                }
            } catch (_e) { /* private mode — non-fatal */ }
            const amt = Number(this.coldAmount) || 0;
            if (!amt) return false;
            // Exact match against a preset, not a tolerance band.
            if (!this.braiinsDepositPresets.includes(amt)) return false;
            // Need enough LN balance.
            const ln = this.braiinsDepositLnBalance
                || (this.summary && this.summary.lightning
                    && this.summary.lightning.local_balance_sat) || 0;
            const required = Math.ceil(amt * 1.035) + 4000;
            return ln >= required;
        },

        dismissBraiinsDepositHint() {
            try { localStorage.setItem('braiinsDepositHintDismissed', '1'); } catch (_e) {}
        },

        /** Click "Use Braiins Deposit →" — close the Send-Onchain
         *  dialog and open the Braiins-Deposit wizard pre-filled with
         *  the address + amount the user already typed. */
        openBraiinsDepositFromSendOnchain() {
            const seedAddr = (this.coldAddress || '').trim();
            const seedAmt = Number(this.coldAmount) || 0;
            this.closeSendOnchain();
            this.openBraiinsDeposit();
            // Apply after openBraiinsDeposit resets state.
            this.$nextTick(() => {
                if (this.braiinsDepositPresets.includes(seedAmt)) {
                    this.braiinsDepositSelectAmount(seedAmt);
                }
                if (seedAddr) {
                    this.braiinsDepositAddress = seedAddr;
                    this.braiinsDepositValidateAddress();
                }
                this.initIcons();
            });
        },

        /** Light client-side validation. Catches obvious typos and
         *  rejects legacy P2PKH (which Braiins also accepts but is
         *  more likely to be flagged). Server does the authoritative
         *  network-aware check. */
        braiinsDepositValidateAddress() {
            const v = (this.braiinsDepositAddress || '').trim();
            if (!v) { this.braiinsDepositAddressError = ''; return; }
            if (/^1[1-9A-HJ-NP-Za-km-z]{25,34}$/.test(v)) {
                this.braiinsDepositAddressError = (
                    'Braiins uses modern addresses (bc1… or 3…). '
                    + 'Please double-check the address you copied.'
                );
                return;
            }
            if (!this.isValidBtcAddress(v)) {
                this.braiinsDepositAddressError = 'This doesn\'t look like a Bitcoin address.';
                return;
            }
            this.braiinsDepositAddressError = '';
        },

        // ── Polling ─────────────────────────────────────────────────

        _startBraiinsDepositPoller() {
            this._stopBraiinsDepositPoller();
            if (!this.braiinsDepositSessionId) return;
            // Reset the log-length tracker so the first poll tick scrolls
            // the progress log to its newest entry on (re)open, rather
            // than inheriting a prior session's count.
            this._braiinsDepositLogLen = 0;
            const sid = this.braiinsDepositSessionId;
            // Guarded. ``_pollBraiinsDepositOnce`` carries the
            // detail-endpoint's 20 s timeout + its own in-flight flag
            // (it's also called directly), so the double guard is benign.
            // Fire once immediately so the progress view is fresh.
            this._poll('braiinsDetail', async () => {
                if (this.braiinsDepositSessionId !== sid) {
                    this._stopBraiinsDepositPoller();
                    return;
                }
                await this._pollBraiinsDepositOnce();
            }, { intervalMs: 5000, immediate: true });
        },

        _stopBraiinsDepositPoller() {
            this._stopPoll('braiinsDetail');
        },

        async _pollBraiinsDepositOnce() {
            if (!this.braiinsDepositSessionId) return;
            // In-flight guard: the detail endpoint can be slow (it drives
            // a state-machine tick + live confirmation lookups over Tor —
            // e.g. get_channels + mempool while a channel opens). The 5 s
            // interval must NOT fire overlapping requests, or slow ticks
            // pile up, congest the single Tor SOCKS, and starve the rest
            // of the dashboard (including a page refresh's /summary). Skip
            // a tick whenever the previous request is still running.
            if (this._braiinsDepositPollInFlight) return;
            this._braiinsDepositPollInFlight = true;
            let data;
            try {
                data = await this.api('GET',
                    '/braiins-deposit/sessions/'
                    + encodeURIComponent(this.braiinsDepositSessionId),
                    null, { timeoutMs: 20000 });
            } catch (_e) {
                // Transient (incl. our own 20 s abort) — keep retrying on
                // the cadence; the guard cleared in finally.
                return;
            } finally {
                this._braiinsDepositPollInFlight = false;
            }
            if (!data || !data.status) return;
            this.braiinsDepositSession = data;
            this.braiinsDepositHasActiveSession = !SWAP_TERMINAL_STATUSES.has(data.status);
            // Auto-scroll the live progress log to the newest entry, but
            // ONLY when a new transition was appended — so a 5 s poll
            // tick doesn't yank the view back down while the user has
            // scrolled up to read earlier entries.
            const _logLen = Array.isArray(data.status_history)
                ? data.status_history.length : 0;
            if (this.braiinsDepositStep === 'progress'
                    && _logLen > (this._braiinsDepositLogLen || 0)) {
                this.$nextTick(() => {
                    const el = this.$refs.braiinsProgressLog;
                    if (el) el.scrollTop = el.scrollHeight;
                });
            }
            this._braiinsDepositLogLen = _logLen;
            // Step transitions for the ext flows.
            //
            //  * In await_funds, render the receive primitive (QR /
            //    countdown) every tick.
            //  * Once the status leaves awaiting_*_funds (because the
            //    user paid / deposited), flip the step to ``progress``
            //    so the standard progress view takes over.
            if (data.status === 'awaiting_ln_funds'
                    || data.status === 'awaiting_onchain_funds') {
                if (this.braiinsDepositStep !== 'await_funds') {
                    this.braiinsDepositStep = 'await_funds';
                }
                this._refreshBraiinsDepositExtAwaitView(data);
            } else if (this.braiinsDepositStep === 'await_funds'
                       && !SWAP_TERMINAL_STATUSES.has(data.status)) {
                // Plan.a — two-stage transition. Flip the
                // status text first ("✓ Payment received!"), give the
                // user ~2.5s to read it, THEN transition the step.
                // The flag is idempotent: a second poll tick while
                // we're already in the receive-banner window leaves
                // the timer untouched.
                if (!this.braiinsDepositExtPaymentReceived) {
                    this._stopBraiinsDepositCountdown();
                    this.braiinsDepositExtPaymentReceived = true;
                    this._braiinsDepositExtPaymentReceivedTimer = setTimeout(() => {
                        this.braiinsDepositStep = 'progress';
                        this.braiinsDepositExtPaymentReceived = false;
                        this._braiinsDepositExtPaymentReceivedTimer = null;
                        this.$nextTick(() => this.initIcons());
                    }, 2500);
                    this.$nextTick(() => this.initIcons());
                }
            }
            // Route to success / failed view on terminal status.
            if (data.status === 'completed') {
                // keeps the poller alive past `completed` until
                // 6 conf so a reorg is detectable; gate the list-tab
                // mirror on the FIRST transition tick so we don't
                // re-fetch the list on every subsequent confirmation
                // bump.
                const transitioning = this.braiinsDepositStep !== 'success';
                this.braiinsDepositStep = 'success';
                this.fetchSummary();
                this.fetchTransactions();
                const liveConfs = (typeof data.send_confirmations_live === 'number'
                                   ? data.send_confirmations_live
                                   : (data.send_confirmations || 0));
                if (liveConfs >= 6) {
                    this._stopBraiinsDepositPoller();
                }
                // Mirror the wizard's terminal transition into the
                // deposits-list tab.
                if (transitioning) {
                    this.braiinsDepositFetchSessions();
                }
                this.$nextTick(() => this.initIcons());
            } else if (data.status === 'failed' || data.status === 'cancelled'
                       || data.status === 'refunded') {
                const transitioning = this.braiinsDepositStep !== 'failed';
                this._stopBraiinsDepositPoller();
                this._stopBraiinsDepositCountdown();
                this._stopBraiinsDepositExtPaymentReceived();
                this.braiinsDepositStep = 'failed';
                this.fetchSummary();
                if (transitioning) {
                    this.braiinsDepositFetchSessions();
                }
                this.$nextTick(() => this.initIcons());
            }
        },

        /** Restore an in-progress session on page load. Pulls the
         *  most-recent non-terminal session from the server (the
         *  one-in-flight invariant means there's at most one) and
         *  hydrates wizard state so a subsequent open lands on the
         *  right step. Also seeds the deposits-list tab so the
         *  active-session pulse-dot lights up immediately without
         *  waiting for the user to click the tab. */
        async _restoreBraiinsDeposit() {
            // _loadRuntimeConfig runs earlier in init() so this flag
            // already reflects the server's BRAIINS_DEPOSIT_ENABLED.
            // Skip the wasted 404 round-trip when the feature is off.
            if (!this.braiinsDepositEnabled) return;
            let sessions;
            try {
                sessions = await this.api('GET', '/braiins-deposit/sessions');
            } catch (_e) { return; }
            if (!Array.isArray(sessions)) return;
            // Seed the deposits-list tab so the pulse-dot reflects
            // reality on page load.
            this.braiinsDepositSessions = sessions;
            if (sessions.length === 0) return;
            const active = sessions.find(
                s => s && s.status && !SWAP_TERMINAL_STATUSES.has(s.status)
            );
            if (!active) return;
            // Hydrate wizard state without auto-popping the modal —
            // shared helper, single source of truth for resume logic.
            this._resumeBraiinsDepositSession(active, { openModal: false });
        },

        // ── Braiins Deposit — dedicated tab ──
        // The tab renders a list of recent deposits (mirror of the
        // Anonymize sessions list). Distinct from the wizard's
        // single-session view above — the tab and the wizard share
        // ``openBraiinsDeposit()`` and the resume plumbing but are
        // otherwise independent.

        /** True iff any row in the list is in a non-terminal status. */
        get braiinsDepositListHasActiveSession() {
            return this.braiinsDepositSessions.some(
                s => s && s.status && !SWAP_TERMINAL_STATUSES.has(s.status),
            );
        },

        /** Filter the ``tabs`` array on feature flags. Currently
         *  Braiins Deposit is the only feature-gated tab in the SPA. */
        get visibleTabs() {
            return this.tabs.filter(t => {
                if (t.id === 'braiins-deposit') {
                    return this.braiinsDepositEnabled;
                }
                if (t.id === 'anonymize') {
                    return this.anonymizeEnabled;
                }
                return true;
            });
        },

        /** Fetch the deposits list. Pure read — no side effects on the
         *  wizard's own session state. */
        async braiinsDepositFetchSessions(opts) {
            if (!this.braiinsDepositEnabled) return;
            // ``silent`` (used by the periodic poll) skips toggling the
            // loading flag so a background refresh every 10 s doesn't
            // flash the "Loading…" line and shift the list layout. The
            // row data still updates in place (x-for keyed on s.id).
            const silent = !!(opts && opts.silent);
            if (!silent) {
                this.braiinsDepositSessionsLoading = true;
                this.braiinsDepositSessionsError = '';
            }
            try {
                const data = await this.api(
                    'GET', '/braiins-deposit/sessions',
                );
                this.braiinsDepositSessions = Array.isArray(data) ? data : [];
                // Clear any stale error once a fetch succeeds.
                this.braiinsDepositSessionsError = '';
                this._braiinsDepositScheduleListPoll();
            } catch (e) {
                // On a silent poll failure keep the last-good list and
                // stay quiet — surfacing a transient error here would
                // itself flicker. Foreground fetches still report.
                if (!silent) {
                    this.braiinsDepositSessionsError =
                        (e && e.message) || 'Failed to load deposits';
                }
            } finally {
                if (!silent) {
                    this.braiinsDepositSessionsLoading = false;
                }
            }
        },

        /** Schedule the next poll tick. Three guards: at least one
         *  non-terminal row, the tab is active, the browser tab is
         *  visible. Cleared on any of: tab switch, completion, hide. */
        _braiinsDepositScheduleListPoll() {
            if (this._braiinsDepositListPollTimer) {
                clearTimeout(this._braiinsDepositListPollTimer);
                this._braiinsDepositListPollTimer = null;
            }
            if (!this.braiinsDepositListHasActiveSession) return;
            if (this.activeTab !== 'braiins-deposit') return;
            if (typeof document !== 'undefined'
                    && document.visibilityState !== 'visible') return;
            this._braiinsDepositListPollTimer = setTimeout(() => {
                // Silent: background refresh must not flash the loading
                // line or shift the list layout (the periodic flicker).
                this.braiinsDepositFetchSessions({ silent: true });
            }, 10000);
        },

        /** Maps lowercase enum -> Tailwind color classes. */
        /** A FAILED session that still holds its fresh UTXO is RECOVERABLE
         *  — the swap completed and the clean UTXO is in the wallet; only
         *  the final send was interrupted (e.g. an app restart). The send
         *  never broadcast, so funds are safe and "Retry send" finishes it.
         *  We frame these as "interrupted", not a scary "failed". */
        braiinsDepositIsRecoverableFailure(session) {
            return !!(session
                && session.status === 'failed'
                && session.fresh_utxo_txid);
        },

        // A user-initiated cancel is NOT a failure — frame it neutrally
        // (no scary "something went wrong" / alert icon).
        braiinsDepositIsCancelled(session) {
            return !!(session && session.status === 'cancelled');
        },

        braiinsDepositStatusBadgeClass(sessionOrStatus) {
            const session = (sessionOrStatus && typeof sessionOrStatus === 'object')
                ? sessionOrStatus : null;
            const status = session ? session.status : sessionOrStatus;
            // Recoverable failure → amber (warning), not red (error).
            if (session && this.braiinsDepositIsRecoverableFailure(session)) {
                return 'bg-amber-500/15 border-amber-500/40 text-amber-300';
            }
            switch (status) {
                case 'completed':
                    return 'bg-emerald-500/15 border-emerald-500/40 text-emerald-300';
                case 'refunded':
                    return 'bg-amber-500/15 border-amber-500/40 text-amber-300';
                case 'failed':
                    return 'bg-red-500/15 border-red-500/40 text-red-300';
                case 'cancelled':
                    return 'bg-gray-500/15 border-gray-500/40 text-gray-400';
                case 'broadcast':
                    return 'bg-sky-500/15 border-sky-500/40 text-sky-300';
                case 'awaiting_fee_reduction':
                    // Layer 4 — fees-too-high parking state. Amber
                    // so it stands out from the (slate) in-progress
                    // states; we want the operator to notice this
                    // and decide whether to wait or override.
                    return 'bg-amber-500/15 border-amber-500/40 text-amber-300';
                case 'created':
                case 'awaiting_ln_funds':
                case 'awaiting_onchain_funds':
                case 'submarine_swapping':
                case 'opening_channel':
                case 'swapping':
                case 'funded':
                case 'sending':
                    return 'bg-slate-500/15 border-slate-500/40 text-slate-300';
                default:
                    return 'bg-slate-500/15 border-slate-500/40 text-slate-300';
            }
        },

        /** Short uppercase label for the status chip. */
        braiinsDepositStatusLabel(sessionOrStatus) {
            const session = (sessionOrStatus && typeof sessionOrStatus === 'object')
                ? sessionOrStatus : null;
            const status = session ? session.status : sessionOrStatus;
            if (session && this.braiinsDepositIsRecoverableFailure(session)) {
                return 'INTERRUPTED';
            }
            if (!status) return '';
            return String(status).toUpperCase().replace(/_/g, ' ');
        },

        /** One-line caption summarising "where the session is right now". */
        braiinsDepositStatusCaption(session) {
            if (!session || !session.status) return '';
            const s = session.status;
            const conf = Number(session.send_confirmations || 0);
            switch (s) {
                case 'created':
                    return 'preparing…';
                case 'awaiting_ln_funds':
                    return 'awaiting Lightning payment';
                case 'awaiting_onchain_funds':
                    return 'awaiting on-chain deposit';
                case 'submarine_swapping':
                    return 'on-chain → Lightning swap in progress';
                case 'opening_channel':
                    if (session.error_message) return session.error_message;
                    return 'opening a Lightning channel (waiting for confirmations)';
                case 'swapping':
                    return 'Lightning → on-chain swap in progress';
                case 'funded':
                    return 'swap claim landed; preparing send';
                case 'sending':
                    return 'broadcasting on-chain send';
                case 'awaiting_fee_reduction':
                    // Layer 4 — surface the threshold the operator
                    // is waiting for. The auto-checker resumes when
                    // current high-priority fees drop to ≤ N sat/vB
                    // where N is computed from the UTXO headroom over
                    // the bin amount.
                    {
                        const t = Number(session.resume_threshold_sat_per_vbyte || 0);
                        if (t > 0) {
                            return 'waiting for fees ≤ ' + t
                                + ' sat/vB to resume (current rate too high)';
                        }
                        if (session.send_infeasible_reason === 'would_underpay_bin') {
                            return 'network fees too high — would underpay bin; waiting for fees to drop';
                        }
                        return 'network fees too high to send — waiting for fees to drop';
                    }
                case 'broadcast':
                    // The server's _maybe_flag_stuck sets error_message on
                    // a BROADCAST row whose send tx hasn't confirmed within
                    // BRAIINS_DEPOSIT_BROADCAST_STUCK_BLOCKS. Surface that
                    // warning here so the user notices stuck sessions
                    // without having to open the wizard.
                    if (session.error_message) return session.error_message;
                    if (conf === 0) return 'awaiting 1st confirmation';
                    return 'awaiting confirmation (' + conf + ')';
                case 'completed':
                    return 'completed';
                case 'refunded':
                    return 'Boltz could not settle — funds restored';
                case 'failed':
                    if (this.braiinsDepositIsRecoverableFailure(session)) {
                        return 'interrupted — your funds are safe in your wallet; '
                            + 'use Retry send to finish';
                    }
                    return session.error_message
                        ? 'failed: ' + session.error_message
                        : 'failed';
                case 'cancelled':
                    return 'cancelled before payment';
                default:
                    return s;
            }
        },

        /** "1,000,000 sat" */
        braiinsDepositFormatAmount(sats) {
            return this.formatSats(sats) + ' sat';
        },

        // Render the row amount such that the bin is the
        // primary number and the actual-sent delta is shown as a
        // small hint when present. Older rows without
        // actual_sent_sats render unchanged.
        //
        // Two delta shapes:
        //   * Positive (`+847 absorbed`): low-fee broadcast routed
        //     the safety buffer into the deposit. Net win for the
        //     user — they got more hashpower credit.
        // * Negative (`-12,180 short`): operator override (
        //     "Broadcast anyway") fired; the destination received
        //     less than the bin amount. Labelled "short" so the
        //     user sees this is a debit, not an absorption.
        braiinsDepositRowAmountLabel(session) {
            if (!session) return '';
            const bin = Number(session.deposit_amount_sats || 0);
            const actual = session.actual_sent_sats == null
                ? null : Number(session.actual_sent_sats);
            if (actual == null || actual === bin) {
                return this.formatSats(bin) + ' sat';
            }
            const delta = actual - bin;
            if (delta > 0) {
                return this.formatSats(bin) + ' sat (+'
                    + this.formatSats(delta) + ' absorbed)';
            }
            // delta < 0 — operator-override case.
            return this.formatSats(bin) + ' sat ('
                + this.formatSats(delta) + ' short)';
        },
        braiinsDepositRowAmountHasDelta(session) {
            if (!session) return false;
            const bin = Number(session.deposit_amount_sats || 0);
            const actual = session.actual_sent_sats == null
                ? null : Number(session.actual_sent_sats);
            return actual != null && actual !== bin;
        },

        /** Truncate a bech32 / base58 address for display. */
        braiinsDepositFormatDestination(addr) {
            if (!addr) return '';
            return addr.length > 12
                ? addr.slice(0, 6) + '…' + addr.slice(-4)
                : addr;
        },

        /** Truncate a 64-char hex txid. */
        braiinsDepositFormatTxid(txid) {
            if (!txid) return '';
            return txid.length > 16
                ? txid.slice(0, 8) + '…' + txid.slice(-4)
                : txid;
        },

        /** "submitted 2m ago" / "completed 1h ago" — picks the most
         *  meaningful timestamp depending on terminal/non-terminal. */
        braiinsDepositRowTimeLabel(session) {
            if (!session) return '';
            const isTerminal = session.status
                && SWAP_TERMINAL_STATUSES.has(session.status);
            let isoTs = null;
            let prefix = 'submitted';
            if (isTerminal) {
                isoTs = session.completed_at
                    || session.updated_at
                    || session.created_at;
                if (session.status === 'completed') prefix = 'completed';
                else if (session.status === 'refunded') prefix = 'refunded';
                else if (session.status === 'cancelled') prefix = 'cancelled';
                else if (session.status === 'failed') prefix = 'failed';
            } else {
                isoTs = session.created_at;
                prefix = 'submitted';
            }
            if (!isoTs) return '';
            return prefix + ' ' + this._braiinsDepositRelativeTime(isoTs);
        },

        /** Format an ISO 8601 timestamp as "Nm ago" / "Xh ago". */
        _braiinsDepositRelativeTime(iso) {
            const t = Date.parse(iso);
            if (!Number.isFinite(t)) return '';
            const delta = Math.max(0, Math.floor((Date.now() - t) / 1000));
            if (delta < 60) return delta + 's ago';
            if (delta < 3600) return Math.floor(delta / 60) + 'm ago';
            if (delta < 86400) return Math.floor(delta / 3600) + 'h ago';
            return Math.floor(delta / 86400) + 'd ago';
        },

        /** True when the row needs user input via a primary action. */
        braiinsDepositHasPrimaryAction(session) {
            if (!session || !session.status) return false;
            switch (session.status) {
                // NB: ``awaiting_ln_funds`` / ``awaiting_onchain_funds``
                // used to show a "Resume" button, but it merely re-opened
                // the dialog — identical to clicking the row — so it was
                // removed as redundant. The row click + status caption
                // already cover those states. Only states whose button
                // does something a row click DOESN'T keep a button.
                case 'awaiting_fee_reduction':
                    // One-tap override that broadcasts the under-bin send
                    // (with a confirm) WITHOUT opening the dialog — a
                    // genuinely distinct action, so it stays a row button.
                    return true;
                case 'failed':
                    // Two FAILED branches surface a primary action:
                    //   1. ext_onchain FAILED with a deposit already
                    //      received exposes the refund-prompt panel.
                    //   2. Any source FAILED after FUNDED (i.e. with a
                    //      fresh_utxo_txid recorded) is retry-eligible
                    //      via /retry-send — the wizard's failure view
                    //      surfaces a "Retry send" button gated on the
                    //      same condition.
                    if (session.fresh_utxo_txid) return true;
                    return session.source_kind === 'ext_onchain'
                        && Number(session.ext_intake_received_sats || 0) > 0
                        && !session.refund_txid;
                default:
                    return false;
            }
        },

        /** Label for the primary action button. */
        braiinsDepositPrimaryActionLabel(session) {
            if (!session) return '';
            if (session.status === 'awaiting_fee_reduction') {
                return 'Broadcast anyway';
            }
            if (session.status === 'failed') {
                // Retry-after-FUNDED branch beats refund-prompt branch
                // — if both are eligible we prefer retry (the fresh
                // UTXO is more recoverable than a refund send).
                if (session.fresh_utxo_txid) return 'Retry send';
                return 'Submit refund';
            }
            // No generic "Resume" — the awaiting states no longer carry
            // a redundant row button (the row itself opens the dialog).
            return '';
        },

        /** D1(c): a refunded on-chain SWAP deposit can be retried via the
         *  channel-open strategy (which doesn't need inbound routing).
         *  Offered only when the operator has channel-open enabled. */
        braiinsDepositCanRetryViaChannel(session) {
            if (!session) return false;
            if (!this.braiinsDepositChannelOpenEnabled) return false;
            if (session.status !== 'refunded') return false;
            if (session.funding_strategy === 'channel') return false;
            return session.source_kind === 'onchain'
                || session.source_kind === 'ext_onchain';
        },

        /** Seed the wizard form from a refunded session and switch to the
         *  channel strategy, then open the form so the user confirms +
         *  starts a NEW session (the refunded one is terminal; no funds
         *  are auto-moved). */
        braiinsDepositRetryViaChannel(session) {
            if (!this.braiinsDepositCanRetryViaChannel(session)) return;
            this.braiinsDepositSourceKind =
                session.source_kind === 'ext_onchain' ? 'ext_onchain' : 'onchain';
            this.braiinsDepositAmountSats = Number(session.deposit_amount_sats) || null;
            this.braiinsDepositAddress = session.destination_address || '';
            this.braiinsDepositFundingStrategy = 'channel';
            this.braiinsDepositChannelPeerReachable = null;
            this.braiinsDepositChannelPeerReason = '';
            this.braiinsDepositChannelSuggested = false;
            this.braiinsDepositError = '';
            // Safe-shape factory, never null (Alpine CSP can't short-circuit
            // ``a && a.b`` — see _emptyBraiinsDepositSession).
            this.braiinsDepositSession = _emptyBraiinsDepositSession();
            this.braiinsDepositSessionId = null;
            this.braiinsDepositHasActiveSession = false;
            this.braiinsDepositQuote = null;
            this.braiinsDepositStep = 'form';
            this.braiinsDepositOpen = true;
            this._debounceBraiinsDepositQuote();
            this._braiinsCheckChannelPeer();
            this.$nextTick(() => this.initIcons());
        },

        // Wizard-side override for a parked session. Same
        // contract as the list-row "Broadcast anyway" button; this
        // handler is bound to the in-wizard amber banner so the
        // user has the override available from whichever surface
        // they're looking at.
        async braiinsDepositWizardOverride() {
            const s = this.braiinsDepositSession;
            if (!s || !s.id) return;
            if (!window.confirm(
                'Broadcast now even though network fees are high?\n\n'
                + 'You\'ll receive slightly less hashpower credit '
                + 'at Braiins than the bin amount you originally '
                + 'chose. Waiting for fees to drop is free; this '
                + 'override is one-way.'
            )) return;
            try {
                await this.api(
                    'POST',
                    '/braiins-deposit/sessions/' + s.id
                    + '/retry-send?accept_underpay=true',
                );
            } catch (e) {
                window.alert(
                    'Override failed: ' + ((e && e.message) || 'unknown error')
                );
            }
            // Trigger the next poll tick so the session state
            // updates immediately rather than waiting up to 5s.
            this._pollBraiinsDepositOnce();
        },

        /** Invoke the primary action. Most paths reopen the wizard;
         *  the dust-prevention parked state hits /retry-send with the
         *  accept_underpay override (the user explicitly chose this
         *  by clicking the "Broadcast anyway" button). */
        async braiinsDepositInvokePrimaryAction(session) {
            if (!session || !session.id) return;
            if (session.status === 'awaiting_fee_reduction') {
                // Confirm before overriding the dust-prevention
                // floor. The user signs off on receiving less than the
                // bin amount at Braiins (the fee absorbs the difference).
                if (!window.confirm(
                    'Broadcast now even though network fees are high?\n\n'
                    + 'You\'ll receive slightly less hashpower credit '
                    + 'at Braiins than the bin amount you originally '
                    + 'chose. Waiting for fees to drop is free; this '
                    + 'override is one-way.'
                )) return;
                try {
                    await this.api(
                        'POST',
                        '/braiins-deposit/sessions/' + session.id
                        + '/retry-send?accept_underpay=true',
                    );
                } catch (e) {
                    // Surface failure inline; the row will refresh
                    // on the next poll.
                    window.alert(
                        'Override failed: ' + ((e && e.message) || 'unknown error')
                    );
                }
                this.braiinsDepositFetchSessions();
                return;
            }
            this._resumeBraiinsDepositSession(session, { openModal: true });
        },

        /** Open the wizard scoped to an existing session. Shared between
         *  the list-row Resume button (``openModal: true``) and the
         *  ``_restoreBraiinsDeposit`` page-load path (``openModal: false``,
         *  hydrates wizard state without auto-popping the modal). */
        _resumeBraiinsDepositSession(session, opts) {
            if (!session) return;
            const openModal = !!(opts && opts.openModal);
            this.braiinsDepositSession = session;
            this.braiinsDepositSessionId = session.id;
            this.braiinsDepositHasActiveSession =
                !SWAP_TERMINAL_STATUSES.has(session.status || '');
            this.braiinsDepositAmountSats = session.deposit_amount_sats;
            this.braiinsDepositAddress = session.destination_address || '';
            const validSources = [
                'lightning', 'onchain', 'ext_lightning', 'ext_onchain',
            ];
            if (validSources.indexOf(session.source_kind) >= 0) {
                this.braiinsDepositSourceKind = session.source_kind;
            }
            // Hop straight to the right step for ext sources awaiting
            // funds; everything else gets the progress panel.
            if (session.status === 'awaiting_ln_funds'
                    || session.status === 'awaiting_onchain_funds') {
                this.braiinsDepositStep = 'await_funds';
            } else if (SWAP_TERMINAL_STATUSES.has(session.status || '')) {
                this.braiinsDepositStep = session.status === 'completed'
                    ? 'success' : 'failed';
            } else {
                this.braiinsDepositStep = 'progress';
            }
            if (openModal) {
                this.braiinsDepositOpen = true;
            }
            // Only poll live sessions. A reopened terminal deposit is a
            // read-only history — polling it would needlessly re-hit the
            // detail endpoint (and its advance() tick) on a 5 s cadence
            // for a session that will never change.
            if (SWAP_TERMINAL_STATUSES.has(session.status || '')) {
                this._stopBraiinsDepositPoller();
            } else {
                this._startBraiinsDepositPoller();
            }
        },

        /** Open the dialog for ANY deposit row — active or terminal — so
         *  the user can review its full progress log. The row click in
         *  the deposits list binds here; the shared resume helper routes
         *  to the right step and only starts the live poller for
         *  non-terminal sessions. */
        braiinsDepositViewSession(session) {
            if (!session || !session.id) return;
            this._resumeBraiinsDepositSession(session, { openModal: true });
            this.$nextTick(() => this.initIcons());
        },

        /** Reopen the single in-flight deposit's live dialog. Bound to
         *  the header's "View in progress" button. The server enforces
         *  one in-flight deposit per key, so there is at most one. */
        braiinsDepositResumeActive() {
            const active = this.braiinsDepositSessions.find(
                s => s && s.status && !SWAP_TERMINAL_STATUSES.has(s.status),
            );
            if (active) {
                this.braiinsDepositViewSession(active);
            } else {
                // Race: the list changed between render and click — fall
                // back to the normal open path (fresh form).
                this.openBraiinsDeposit();
            }
        },

        /** Toggle inline Details disclosure for a row. */
        braiinsDepositToggleRowDetails(sessionId) {
            this.braiinsDepositRowDetailsOpen[sessionId] =
                !this.braiinsDepositRowDetailsOpen[sessionId];
        },

        // ── Rebalance (circular self-payment) ──
        // The flow is intentionally framed from the source channel:
        // "send sats out of THIS channel, receive them back on a
        // different channel of the same node." The destination
        // picker, max-amount math, animated SVG arrow, and history
        // panel all hang off this single ``rebalance`` namespace.

        openRebalance(ch) {
            // Reset everything so a stale dest / quote from a prior
            // session doesn't bleed across channel cards.
            this.rebalance.source = ch;
            this.rebalance.dest = null;
            // Sensible default amount: 25% of the source's local
            // balance, capped at 100k sats and floored at 1k. The
            // user will tweak — this is just so the input isn't 0.
            const local = ch.local_balance || 0;
            this.rebalance.amountSats = Math.max(1000, Math.min(100000, Math.floor(local * 0.25)));
            this.rebalanceAmountSats = this.rebalance.amountSats;
            this.rebalance.feeLimitSats = Math.max(10, Math.ceil(this.rebalance.amountSats * 0.005));
            this.rebalance.feeLimitMode = 'percent';
            this.rebalance.feeLimitPercent = 0.5;
            this.rebalanceFeeLimitPercent = this.rebalance.feeLimitPercent;
            this.rebalanceFeeLimitSats = this.rebalance.feeLimitSats;
            this.rebalance.timeoutSeconds = 60;            this.rebalance.search = '';
            this.rebalance.sortBy = 'best';
            this.rebalance.showAllDests = false;
            this.rebalance.quote = null;
            this.rebalance.quoteError = '';
            this.rebalance.quoting = false;
            this.rebalance.running = false;
            this.rebalance.result = null;
            this.rebalance.error = '';
            this.rebalance.steps = [];
            if (this.rebalance._quoteTimer) {
                clearTimeout(this.rebalance._quoteTimer);
                this.rebalance._quoteTimer = null;
            }
            // Seed the approx-sats hint so it's correct on first paint.
            this._recomputeFeeLimitApproxSats();
            this.showRebalance = true;
            this.fetchRebalanceRecent();
        },

        closeRebalance() {
            this.showRebalance = false;
            this.rebalance.source = null;
            this.rebalance.dest = null;
            this.rebalance.quote = null;
            this.rebalance.result = null;
            this.rebalance.error = '';
            this.rebalance.steps = [];
            if (this.rebalance._quoteTimer) {
                clearTimeout(this.rebalance._quoteTimer);
                this.rebalance._quoteTimer = null;
            }
        },

        // Local outbound headroom on a channel (matches backend math).
        rebalanceMaxSendable(ch) {
            if (!ch) return 0;
            const cap = ch.capacity || 0;
            const local = ch.local_balance || 0;
            const reserve = ch.local_chan_reserve_sat || 0;
            const unsettled = ch.unsettled_balance || 0;
            // Beyond the channel reserve, the initiator must keep the
            // commitment fee (which grows as the rebalance HTLC is added)
            // and the anchor outputs funded, or LND rejects the send with
            // "insufficient local balance". Reserve the live commit_fee
            // (when we're the initiator) plus a fixed anchor/growth pad,
            // keeping the old 1% floor for large channels.
            const commitFee = ch.initiator ? (ch.commit_fee || 0) : 0;
            const headroom = Math.max(Math.floor(cap / 100), commitFee + REBALANCE_HEADROOM_PAD_SATS);
            return Math.max(local - reserve - unsettled - headroom, 0);
        },

        // Local inbound headroom on a channel (matches backend math).
        rebalanceMaxReceivable(ch) {
            if (!ch) return 0;
            const cap = ch.capacity || 0;
            const remote = ch.remote_balance || 0;
            const reserve = ch.remote_chan_reserve_sat || 0;
            const unsettled = ch.unsettled_balance || 0;
            const safety = Math.floor(cap / 100);
            return Math.max(remote - reserve - unsettled - safety, 0);
        },

        // The real upper bound the user can rebalance, given the
        // currently chosen source + dest pair.
        rebalanceMaxAmount() {
            // The source channel forwards amount + routing fee, so reserve
            // the fee budget from the sendable side. The destination
            // receives exactly the amount (the final hop charges no fee),
            // so its inbound headroom caps the amount directly.
            const a = this._rebalanceReserveFee(this.rebalanceMaxSendable(this.rebalance.source));
            const b = this.rebalanceMaxReceivable(this.rebalance.dest);
            if (!this.rebalance.dest) return a;
            return Math.max(Math.min(a, b), 0);
        },
        /** Reduce a sendable amount so amount + routing fee fits within it,
         *  using the current fee-limit mode (percent or flat sats). */
        _rebalanceReserveFee(sendable) {
            const r = this.rebalance;
            if (r.feeLimitMode === 'percent') {
                const pct = Number(r.feeLimitPercent);
                if (!Number.isFinite(pct) || pct <= 0) return sendable;
                // amount + amount*pct/100 <= sendable → amount <= sendable/(1+pct/100)
                return Math.floor(sendable / (1 + pct / 100));
            }
            const sats = parseInt(r.feeLimitSats, 10);
            const fee = (Number.isFinite(sats) && sats > 0) ? sats : 0;
            return Math.max(sendable - fee, 0);
        },

        // Fill the amount input with the computed Max.
        rebalanceSetMax() {
            const max = this.rebalanceMaxAmount();
            if (max > 0) {
                this.rebalanceAmountSats = max;
                this.rebalance.amountSats = max;
                this._recomputeRebalanceVis();
                this.scheduleRebalanceQuote();
            }
        },

        // Filter + sort the destination candidate list.
        rebalanceCandidates() {
            const src = this.rebalance.source;
            if (!src) return [];
            const all = (this.channels || []).filter(c => c.active && c.chan_id !== src.chan_id);
            const search = (this.rebalance.search || '').trim().toLowerCase();
            const filtered = all.filter(c => {
                const headroom = this.rebalanceMaxReceivable(c);
                if (!this.rebalance.showAllDests && headroom < 1000) return false;
                if (!search) return true;
                const alias = (c.peer_alias || '').toLowerCase();
                const pk = (c.remote_pubkey || '').toLowerCase();
                return alias.includes(search) || pk.startsWith(search);
            });
            const sortBy = this.rebalance.sortBy;
            return filtered.slice().sort((a, b) => {
                if (sortBy === 'alias') {
                    return (a.peer_alias || '').localeCompare(b.peer_alias || '');
                }
                if (sortBy === 'capacity') {
                    return (b.capacity || 0) - (a.capacity || 0);
                }
                if (sortBy === 'ratio') {
                    const ra = (a.remote_balance || 0) / Math.max(a.capacity || 1, 1);
                    const rb = (b.remote_balance || 0) / Math.max(b.capacity || 1, 1);
                    return rb - ra;
                }
                // 'best' = most receive-friendly (highest remote ratio,
                // then highest absolute receivable).
                const ra = (a.remote_balance || 0) / Math.max(a.capacity || 1, 1);
                const rb = (b.remote_balance || 0) / Math.max(b.capacity || 1, 1);
                if (rb !== ra) return rb - ra;
                return this.rebalanceMaxReceivable(b) - this.rebalanceMaxReceivable(a);
            });
        },

        rebalancePickDest(ch) {
            this.rebalance.dest = ch;
            this.rebalance.quote = null;
            this.rebalance.quoteError = '';
            this.scheduleRebalanceQuote();
        },

        rebalanceClearDest() {
            this.rebalance.dest = null;
            this.rebalance.quote = null;
            this.rebalance.quoteError = '';
        },

        // Resolve the user's fee limit to a flat sats value. In
        // 'percent' mode it floats with the amount, so a user can
        // pick "0.5%" once and have it stay correct as they tweak
        // the amount slider. Floored at 1 sat so a tiny rebalance
        // doesn't accidentally send 0-sat fee_limit to LND.
        rebalanceEffectiveFeeLimitSats() {
            const r = this.rebalance;
            if (r.feeLimitMode === 'percent') {
                const amt = this._rebalAmtSats();
                const pct = Number(r.feeLimitPercent);
                if (!Number.isFinite(pct) || pct < 0) return 0;
                return Math.max(1, Math.ceil(amt * pct / 100));
            }
            const sats = parseInt(r.feeLimitSats, 10);
            return Number.isFinite(sats) && sats >= 0 ? sats : 0;
        },

        // Push the resolved fee-limit value into a reactive property
        // so templates can render it without depending on chained
        // method-call reactivity. Called by $watch on the relevant
        // inputs (see init()).
        _recomputeFeeLimitApproxSats() {
            this.rebalance.feeLimitApproxSats = this.rebalanceEffectiveFeeLimitSats();
        },

        // Refresh the flat scalars that the SVG + summary lines bind
        // to. Centralised so we only do the math once per change.
        _recomputeRebalanceVis() {
            const r = this.rebalance;
            this.rebalSrcLocalW = this.rebalanceSrcLocalW();
            this.rebalSrcSliceX = this.rebalanceSrcSliceX();
            this.rebalSrcSliceW = this.rebalanceSrcSliceW();
            this.rebalDstLocalW = this.rebalanceDstLocalW();
            this.rebalDstSliceX = this.rebalanceDstSliceX();
            this.rebalDstSliceW = this.rebalanceDstSliceW();
            this.rebalArrowPath = this.rebalanceArrowPath();
            this.rebalArrowOk = this.rebalanceArrowOk();
            this.rebalSrcRemainingLocal = this.rebalanceSrcRemainingLocal();
            this.rebalDstNewLocal = this.rebalanceDstNewLocal();
            this.rebalMaxSendableSrc = r.source ? this.rebalanceMaxSendable(r.source) : 0;
        },

        // Toggle between flat-sats and percent fee modes. When
        // switching to percent, derive a percent that matches the
        // current sats so the displayed value doesn't jump; vice
        // versa for switching back.
        rebalanceSetFeeMode(mode) {
            const r = this.rebalance;
            if (mode === r.feeLimitMode) return;
            const amt = this._rebalAmtSats();
            if (mode === 'percent' && amt > 0) {
                const sats = parseInt(r.feeLimitSats, 10) || 0;
                // Round to 2 dp so the input shows a tidy number.
                r.feeLimitPercent = Math.round((sats / amt) * 100 * 100) / 100;
                this.rebalanceFeeLimitPercent = r.feeLimitPercent;
            } else if (mode === 'sats') {
                r.feeLimitSats = this.rebalanceEffectiveFeeLimitSats();
                this.rebalanceFeeLimitSats = r.feeLimitSats;
            }
            r.feeLimitMode = mode;
            this.scheduleRebalanceQuote();
        },

        // Debounced quote refresh — fires whenever the user changes
        // amount/fee/dest. 350 ms feels live without spamming LND.
        scheduleRebalanceQuote() {
            if (this.rebalance._quoteTimer) clearTimeout(this.rebalance._quoteTimer);
            this.rebalance.quoteError = '';
            const amt = parseInt(this.rebalance.amountSats, 10);
            if (!this.rebalance.source || !this.rebalance.dest || !amt || amt <= 0) {
                this.rebalance.quote = null;
                return;
            }
            // Skip the round-trip when the amount is already known to
            // exceed source max-sendable or dest max-receivable: the
            // server would reject with 400 and the UI already shows
            // the red invalid-state outline via ``rebalArrowOk``.
            if (!this.rebalArrowOk) {
                this.rebalance.quote = null;
                return;
            }
            this.rebalance._quoteTimer = setTimeout(() => this.fetchRebalanceQuote(), 350);
        },

        async fetchRebalanceQuote() {
            const r = this.rebalance;
            if (!r.source || !r.dest) return;
            r.quoting = true;
            r.quoteError = '';
            try {
                const data = await this.api('POST', '/rebalance/quote', {
                    source_chan_id: r.source.chan_id,
                    dest_chan_id: r.dest.chan_id,
                    amount_sats: parseInt(r.amountSats, 10),
                    fee_limit_sats: this.rebalanceEffectiveFeeLimitSats(),
                });
                // The server returns 200 + ``no_route: true`` when LND's
                // pathfinder reports no path satisfies the constraints.
                // That's a routing outcome, not a fault — show it as a
                // friendly inline hint instead of a route summary.
                if (data && data.no_route) {
                    r.quote = null;
                    r.quoteError = data.detail || 'No route found.';
                } else {
                    r.quote = data;
                }
            } catch (e) {
                r.quote = null;
                r.quoteError = e.message || 'No route';
            }
            r.quoting = false;
        },

        async executeRebalance() {
            const r = this.rebalance;
            if (!r.source || !r.dest) return;
            const amt = parseInt(r.amountSats, 10);
            const fee = this.rebalanceEffectiveFeeLimitSats();
            const timeout = parseInt(r.timeoutSeconds, 10);
            if (!amt || amt <= 0) { r.error = 'Amount required'; return; }
            r.running = true;
            r.error = '';
            r.result = null;
            r.steps = [
                { label: 'Mint invoice on local node', state: 'active' },
                { label: 'Probe route', state: 'pending' },
                { label: 'Send circular payment', state: 'pending' },
                { label: 'Settle', state: 'pending' },
            ];
            // The backend mints + probes + sends in one shot, so the
            // step list animates optimistically: by the time the
            // single HTTP call returns, all four are either ✓ or one
            // is ✗. This still gives the user a sense of progress.
            try {
                const data = await this.api('POST', '/rebalance', {
                    source_chan_id: r.source.chan_id,
                    dest_chan_id: r.dest.chan_id,
                    amount_sats: amt,
                    fee_limit_sats: fee,
                    timeout_seconds: timeout,
                });
                r.steps = r.steps.map(s => ({ ...s, state: 'done' }));
                r.result = data;
                this.toast = 'Rebalanced ' + this.formatSats(data.result?.amount_sats || amt)
                    + ' sats (' + this.formatSats(data.result?.fee_sats || 0) + ' sats fee)';
                setTimeout(() => { this.toast = ''; }, 4000);
                // Refresh channel balances so the source/dest cards
                // show the new state next time the user opens them.
                this.fetchChannels();
                this.fetchSummary();
                this.fetchRebalanceRecent();
                // Auto-close after a short delay so the user can see
                // the success state, but not so long it feels stuck.
                setTimeout(() => {
                    if (this.rebalance.result && !this.rebalance.error) {
                        this.closeRebalance();
                    }
                }, 2500);
            } catch (e) {
                r.error = e.message || 'Rebalance failed';
                // Mark the in-flight step as failed; everything
                // earlier was either done or skipped.
                let failed = false;
                r.steps = r.steps.map(s => {
                    if (failed) return { ...s, state: 'pending' };
                    if (s.state === 'active' || s.state === 'pending') {
                        failed = true;
                        return { ...s, state: 'fail' };
                    }
                    return s;
                });
            }
            r.running = false;
        },

        async fetchRebalanceRecent() {
            try {
                const data = await this.api('GET', '/rebalance/recent?limit=5');
                this.rebalance.recent = data.rebalances || [];
            } catch (_e) {
                this.rebalance.recent = [];
            }
        },

        // ── Rebalance bar/SVG geometry helpers ──
        // The @alpinejs/csp build does NOT expose ``Math`` or
        // ``parseInt`` to inline expressions, so any arithmetic that
        // needs them has to live in component methods. These helpers
        // are what the source/dest/candidate capacity bars and the SVG
        // visualisation read for their widths and offsets.

        // ``X || 0`` style coalesce that also works for the string
        // numerics LND REST sometimes hands back.
        _rebalNum(v) {
            const n = Number(v);
            return Number.isFinite(n) ? n : 0;
        },
        _rebalAmtSats() {
            const n = parseInt(this.rebalanceAmountSats, 10);
            return Number.isFinite(n) && n > 0 ? n : 0;
        },

        // Inline ``style=""`` strings for the HTML capacity bars (the
        // 6px stacked yellow/cyan ribbons in the source card and the
        // destination candidate list).
        rebalanceLocalStyle(ch) {
            if (!ch) return 'width: 0%';
            const cap = this._rebalNum(ch.capacity);
            if (cap <= 0) return 'width: 0%';
            const pct = (this._rebalNum(ch.local_balance) / cap) * 100;
            return 'width: ' + Math.max(0, Math.min(100, pct)) + '%';
        },
        rebalanceRemoteStyle(ch) {
            if (!ch) return 'width: 0%';
            const cap = this._rebalNum(ch.capacity);
            if (cap <= 0) return 'width: 0%';
            const pct = (this._rebalNum(ch.remote_balance) / cap) * 100;
            return 'width: ' + Math.max(0, Math.min(100, pct)) + '%';
        },

        // ── SVG geometry (viewport width = 400) ──
        // The two bars are drawn full-width so we can map balances
        // linearly. The "slice" is the moving chunk that highlights
        // the proposed rebalance amount on each bar.
        _REBAL_W: 400,
        _rebalChanW(ch, sats) {
            if (!ch) return 0;
            const cap = this._rebalNum(ch.capacity);
            if (cap <= 0) return 0;
            return Math.max(0, Math.min(this._REBAL_W, (sats / cap) * this._REBAL_W));
        },
        // Source bar — yellow "current local" rect.
        rebalanceSrcLocalW() {
            const r = this.rebalance;
            if (!r.source) return 0;
            return this._rebalChanW(r.source, this._rebalNum(r.source.local_balance));
        },
        // Source bar — highlighted slice that's about to leave (drawn
        // from ``srcSliceStart`` with width ``srcSliceW``).
        rebalanceSrcSliceX() {
            const r = this.rebalance;
            if (!r.source) return 0;
            const local = this._rebalNum(r.source.local_balance);
            const amt = Math.min(this._rebalAmtSats(), local);
            return this._rebalChanW(r.source, local - amt);
        },
        rebalanceSrcSliceW() {
            const r = this.rebalance;
            if (!r.source) return 0;
            const local = this._rebalNum(r.source.local_balance);
            const amt = Math.min(this._rebalAmtSats(), local);
            return this._rebalChanW(r.source, amt);
        },
        // Dest bar — yellow "current local" rect.
        rebalanceDstLocalW() {
            const r = this.rebalance;
            if (!r.dest) return 0;
            return this._rebalChanW(r.dest, this._rebalNum(r.dest.local_balance));
        },
        // Dest bar — highlighted slice that's about to arrive
        // (extends to the right of dest local).
        rebalanceDstSliceX() {
            return this.rebalanceDstLocalW();
        },
        rebalanceDstSliceW() {
            const r = this.rebalance;
            if (!r.dest) return 0;
            const remote = this._rebalNum(r.dest.remote_balance);
            const amt = Math.min(this._rebalAmtSats(), remote);
            return this._rebalChanW(r.dest, amt);
        },

        // Local balance left on the source after the rebalance lands
        // (in sats, not bar-pixels). Used in the under-bar summary
        // line so the user can see exactly how much liquidity stays
        // on the source side. Floored at 0 for sanity if the user
        // typed an amount > local_balance.
        rebalanceSrcRemainingLocal() {
            const r = this.rebalance;
            if (!r.source) return 0;
            const local = this._rebalNum(r.source.local_balance);
            const amt = Math.min(this._rebalAmtSats(), local);
            return Math.max(0, local - amt);
        },
        // Local balance on the destination *after* the rebalance —
        // dst.local_balance + amount (clamped to capacity). Mirrors
        // the visual "after" state shown on the dest bar.
        rebalanceDstNewLocal() {
            const r = this.rebalance;
            if (!r.dest) return 0;
            const local = this._rebalNum(r.dest.local_balance);
            const cap = this._rebalNum(r.dest.capacity);
            const amt = this._rebalAmtSats();
            return Math.min(cap || (local + amt), local + amt);
        },

        // Build the SVG path for the curved arrow connecting the
        // *right edge* of the source's outgoing slice to the *right
        // edge* of the destination's incoming slice. The path runs
        // horizontally from each slice all the way past the right
        // edge of the channel bars (by ``lead`` px) before the curve
        // joins the two endpoints, so the loop sits cleanly to the
        // right of the bars regardless of how full either channel
        // is. The SVG sets ``overflow:visible`` so the loop can
        // extend past the viewBox. Returns "" when nothing to draw.
        rebalanceArrowPath() {
            const r = this.rebalance;
            if (!r.source || !r.dest) return '';
            const srcMidY = 28;       // mid-height of source bar
            const dstMidY = 112;      // mid-height of dest bar
            const x1 = this.rebalanceSrcLocalW();
            const x2 = this.rebalanceDstLocalW() + this.rebalanceDstSliceW();
            // Lead = horizontal distance the path extends past the
            // bar's right edge before/after the curve. 60px reads
            // clearly as a "swoop" without dominating the panel.
            const lead = 60;
            const loopX = this._REBAL_W + lead;
            // Control points sit ``lead`` further right than the
            // loop endpoints, which keeps the tangent horizontal at
            // the join with the straight segments.
            const cx = loopX + lead;
            return 'M ' + x1 + ' ' + srcMidY
                 + ' L ' + loopX + ' ' + srcMidY
                 + ' C ' + cx + ' ' + srcMidY + ', '
                       + cx + ' ' + dstMidY + ', '
                       + loopX + ' ' + dstMidY
                 + ' L ' + x2 + ' ' + dstMidY;
        },

        rebalanceArrowOk() {
            const r = this.rebalance;
            if (!r.source || !r.dest) return true;
            const amt = this._rebalAmtSats();
            return amt > 0
                && amt <= this.rebalanceMaxSendable(r.source)
                && amt <= this.rebalanceMaxReceivable(r.dest);
        },

        // ── QR Code rendering ──
        renderQr(canvas, text) {
            if (!canvas || !text) return;
            // BOLT 12 offers can be long (≥1k chars when offer_paths
            // is included). Try progressively lower error-correction
            // levels until the data fits or we run out of options.
            // qrcode@1.5 supports L/M/Q/H; L gives the largest
            // capacity (≈2953 alphanumeric chars at version 40).
            const levels = ['M', 'L'];
            const ctx = canvas.getContext('2d');
            for (const ecc of levels) {
                try {
                    QRCode.toCanvas(canvas, text, {
                        width: 200,
                        margin: 2,
                        errorCorrectionLevel: ecc,
                        color: { dark: '#000000', light: '#ffffff' },
                    });
                    canvas.dataset.qrTooLong = '0';
                    return;
                } catch (e) {
                    // qrcode.js throws when the data overflows v40.
                    // Try the next, lower level.
                    continue;
                }
            }
            // Still didn't fit → blank the canvas and flag for the
            // template to show a "share as text" fallback.
            if (ctx) {
                ctx.clearRect(0, 0, canvas.width, canvas.height);
            }
            canvas.dataset.qrTooLong = '1';
            console.warn('QR render: payload too long for a single frame (' + text.length + ' chars)');
        },

        // Render a QR into ``container`` as inline SVG. Used for the
        // BOLT 12 offer flows where the payload is dense (≥1k chars)
        // and a rasterized canvas at modest CSS size leaves each
        // module only ~1 pixel wide — under most phone scanners'
        // resolution floor. SVG stays crisp at any size, so a
        // small thumbnail remains scannable when the user zooms
        // their phone camera in.
        renderQrSvg(container, text) {
            if (!container || !text) return;
            const levels = ['M', 'L'];
            for (const ecc of levels) {
                let svgString = null;
                try {
                    QRCode.toString(text, {
                        type: 'svg',
                        margin: 2,
                        errorCorrectionLevel: ecc,
                        color: { dark: '#000000', light: '#ffffff' },
                    }, (err, str) => {
                        if (!err) svgString = str;
                    });
                } catch (_e) {
                    // qrcode throws when the payload overflows v40 at
                    // the requested EC level — drop one level and retry.
                    continue;
                }
                if (svgString) {
                    container.innerHTML = svgString;
                    const svg = container.querySelector('svg');
                    if (svg) {
                        // Let CSS drive size; preserveAspectRatio so the
                        // QR scales cleanly inside whatever box the
                        // template gives us.
                        svg.removeAttribute('width');
                        svg.removeAttribute('height');
                        svg.setAttribute('style', 'width:100%;height:100%;display:block;');
                    }
                    container.dataset.qrTooLong = '0';
                    return;
                }
            }
            container.innerHTML = '';
            container.dataset.qrTooLong = '1';
            console.warn('QR render: payload too long for a single frame (' + text.length + ' chars)');
        },

        // ══════════════════════════════════════════════════════════════
        //  Sign / Verify Message
        // ══════════════════════════════════════════════════════════════
        async openSignDialog() {
            this.showSignDialog = true;
            this.signTab = 'sign';
            this.signIdentity = 'address';
            this.signStep = 'form';
            this.signAddress = '';
            this.signMessage = '';
            this.signResult = null;
            this.signError = '';
            this.signExportFormat = 'signature';
            this.verifyIdentity = 'address';
            this.verifyAddress = '';
            this.verifyMessage = '';
            this.verifySignature = '';
            this.verifyPaste = '';
            this.verifyResult = null;
            this.verifyError = '';
            // Lazy load config + address suggestions
            if (!this.signConfig) {
                try { this.signConfig = await this.api('GET', '/sign/config'); } catch(e) {}
            }
            await this.loadSignAddresses();
            this.initIcons();
        },
        closeSignDialog() {
            this.showSignDialog = false;
        },
        async loadSignAddresses() {
            const mode = this.signConfig?.autocomplete || 'txn_history';
            if (mode === 'off') { this.signAddressOptions = []; return; }
            try {
                const res = await this.api('GET', '/sign/addresses');
                this.signAddressOptions = res?.addresses || [];
            } catch (e) {
                this.signAddressOptions = [];
            }
        },
        signMessageMaxChars() {
            return this.signConfig?.max_chars || 4096;
        },
        signFormReady() {
            const msgOk = this.signMessage && this.signMessage.length > 0
                && this.signMessage.length <= this.signMessageMaxChars()
                && !this.signMessageHasControlBytes();
            if (!msgOk) return false;
            if (this.signIdentity === 'node') return true;
            return this.signAddress && this.signAddress.length >= 14;
        },
        addressTypeLabel(addr) {
            if (!addr) return '';
            const a = addr.toLowerCase();
            if (a.startsWith('bc1p') || a.startsWith('tb1p')) return 'Taproot (P2TR)';
            if (a.startsWith('bc1') || a.startsWith('tb1')) return 'SegWit (P2WPKH)';
            if (a.startsWith('3') || a.startsWith('2')) return 'P2SH (legacy / wrapped)';
            if (a.startsWith('1') || a.startsWith('m') || a.startsWith('n')) return 'Legacy (P2PKH)';
            return 'Unknown';
        },
        signFormatHint() {
            if (this.signIdentity === 'node') return 'zbase32 (LND node identity)';
            const t = this.addressTypeLabel(this.signAddress);
            if (t.startsWith('Taproot') || t.startsWith('SegWit')) return 'BIP-322 simple';
            return 'BIP-137 (legacy)';
        },
        signMessageHasControlBytes() {
            if (!this.signMessage) return false;
            for (let i = 0; i < this.signMessage.length; i++) {
                const cp = this.signMessage.charCodeAt(i);
                if ((cp < 0x20 && cp !== 0x09 && cp !== 0x0A && cp !== 0x0D) || cp === 0x7F) {
                    return true;
                }
            }
            return false;
        },
        gotoSignReview() {
            if (!this.signFormReady()) return;
            this.signError = '';
            this.signStep = 'review';
            this.initIcons();
        },
        async submitSign() {
            this.signLoading = true;
            this.signError = '';
            try {
                if (this.signIdentity === 'address') {
                    this.signResult = await this.api('POST', '/sign/address', {
                        address: this.signAddress,
                        message: this.signMessage,
                    });
                } else {
                    this.signResult = await this.api('POST', '/sign/node', {
                        message: this.signMessage,
                    });
                }
                this.signStep = 'result';
                this.signExportFormat = 'signature';
            } catch (e) {
                this.signError = e.message || 'Signing failed';
            }
            this.signLoading = false;
            this.initIcons();
        },
        signedExport() {
            if (!this.signResult) return '';
            const r = this.signResult;
            const fmt = this.signExportFormat;
            if (this.signIdentity === 'node') {
                if (fmt === 'json') {
                    return JSON.stringify({
                        identity: 'node',
                        node_pubkey: r.node_pubkey,
                        message: this.signMessage,
                        signature: r.signature,
                        format: 'zbase32',
                    }, null, 2);
                }
                return r.signature;
            }
            // address identity
            if (fmt === 'signature') {
                return r.signature;
            }
            if (fmt === 'json') {
                return JSON.stringify({
                    identity: 'address',
                    address: r.address,
                    address_type: r.address_type,
                    message: this.signMessage,
                    signature: r.signature,
                    format: r.format,
                }, null, 2);
            }
            if (fmt === 'sparrow') {
                return r.address + '\n' + this.signMessage + '\n' + r.signature;
            }
            // ascii armor
            return [
                '-----BEGIN BITCOIN SIGNED MESSAGE-----',
                this.signMessage,
                '-----BEGIN BITCOIN SIGNATURE-----',
                r.address,
                r.signature,
                '-----END BITCOIN SIGNATURE-----',
            ].join('\n');
        },
        copySignedExport() {
            const txt = this.signedExport();
            if (!txt) return;
            this._copyToClipboard(txt);
            this.signCopiedFlag = true;
            this.toast = 'Signature copied';
            setTimeout(() => { this.signCopiedFlag = false; this.toast = ''; }, 1800);
        },
        downloadSignedExport() {
            const txt = this.signedExport();
            if (!txt) return;
            const ext = this.signExportFormat === 'json' ? 'json'
                : this.signExportFormat === 'ascii' ? 'asc'
                : 'txt';
            const blob = new Blob([txt], { type: 'text/plain' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'signed-message.' + ext;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        },
        signNewMessage() {
            this.signStep = 'form';
            this.signMessage = '';
            this.signResult = null;
            this.signError = '';
        },
        async parsePastedSignedMessage() {
            const blob = (this.verifyPaste || '').trim();
            if (!blob) return;
            try {
                const parsed = await this.api('POST', '/sign/parse', { blob });
                this.verifyIdentity = parsed.identity || 'address';
                this.verifyAddress = parsed.address || '';
                this.verifyMessage = parsed.message || '';
                this.verifySignature = parsed.signature || '';
                this.verifyPaste = '';
                this.verifyError = '';
            } catch (e) {
                this.verifyError = e.message || 'Could not parse signed message';
            }
        },
        verifyFormReady() {
            const msgOk = this.verifyMessage && this.verifyMessage.length > 0
                && this.verifyMessage.length <= this.signMessageMaxChars();
            const sigOk = this.verifySignature && this.verifySignature.length > 0;
            if (!msgOk || !sigOk) return false;
            if (this.verifyIdentity === 'node') return true;
            return this.verifyAddress && this.verifyAddress.length >= 14;
        },
        async submitVerify() {
            this.verifyLoading = true;
            this.verifyError = '';
            this.verifyResult = null;
            try {
                if (this.verifyIdentity === 'address') {
                    this.verifyResult = await this.api('POST', '/verify/address', {
                        address: this.verifyAddress,
                        message: this.verifyMessage,
                        signature: this.verifySignature,
                    });
                } else {
                    this.verifyResult = await this.api('POST', '/verify/node', {
                        message: this.verifyMessage,
                        signature: this.verifySignature,
                    });
                }
            } catch (e) {
                this.verifyError = e.message || 'Verification failed';
            }
            this.verifyLoading = false;
            this.initIcons();
        },

        // ── UTXO management ─────────────────────────────────────────
        // Backed by /dashboard/api/utxos. Methods are intentionally
        // CSP-safe — no nested-path reactivity in templates relies
        // on these (templates always read top-level scalars).
        utxoKey(u) { return (u.txid || '') + ':' + (u.vout || 0); },

        get filteredUtxos() {
            const q = (this.utxoSearch || '').trim().toLowerCase();
            if (!q) return this.utxos;
            return this.utxos.filter(function (u) {
                return ((u.label || '') + ' ' + (u.address || '')).toLowerCase().indexOf(q) >= 0;
            });
        },

        async loadUtxos() {
            this.utxosLoading = true;
            try {
                const data = await this.api('GET', '/utxos');
                this.utxos = (data && data.utxos) || [];
                this.utxosTotalSats = (data && data.total_sats) || 0;
                // Drop any stale coin-control selections that no longer
                // map to a live UTXO (e.g. the user spent that UTXO in
                // another flow while the dialog was open).
                const liveKeys = new Set(this.utxos.map((u) => u.key));
                this.sendCoinControlSelected = this.sendCoinControlSelected.filter((k) => liveKeys.has(k));
                this.consolidateOutpoints = this.consolidateOutpoints.filter((k) => liveKeys.has(k));
                this._recomputeCoinControlTotals();
            } catch (e) {
                this.utxos = [];
                this.utxosTotalSats = 0;
                this.toast = e.message || 'Failed to load UTXOs';
            }
            this.utxosLoading = false;
            this.initIcons();
        },

        // ── CSP-safe click handlers ────────────────────────────────
        // The @alpinejs/csp expression parser does not accept
        // multi-statement bodies (``a; b()``) or ``if`` keywords. Wrap
        // template-side compound logic into a single method call.
        showUtxosTab() {
            this.onchainSubTab = 'utxos';
            this.loadUtxos();
        },
        toggleRecentlySpent() {
            this.recentlySpentOpen = !this.recentlySpentOpen;
            if (this.recentlySpentOpen) this.loadRecentlySpent();
        },
        toggleSendCoinControl() {
            this.sendCoinControlOpen = !this.sendCoinControlOpen;
            if (this.sendCoinControlOpen && this.utxos.length === 0) this.loadUtxos();
        },

        async loadRecentlySpent() {
            try {
                const data = await this.api('GET', '/utxos/recently-spent');
                this.recentlySpent = (data && data.recently_spent) || [];
            } catch (e) {
                this.recentlySpent = [];
            }
        },

        startUtxoLabelEdit(u) {
            this.utxoEditingKey = u.key;
            this.utxoEditingDraft = u.label || '';
        },

        // ``@alpinejs/csp``'s expression parser does not accept arrow
        // functions, so inline ``x-init="$nextTick(() => $el.focus())"``
        // throws ``Unexpected token: PUNCTUATION )``. Templates pass
        // ``$el`` to this helper instead; the ``$nextTick`` callback
        // lives in regular JS where arrow functions are fine.
        focusOnInit(el) {
            this.$nextTick(() => { if (el) el.focus(); });
        },

        cancelUtxoLabel() {
            this.utxoEditingKey = '';
            this.utxoEditingDraft = '';
        },

        async commitUtxoLabel(u) {
            const draft = (this.utxoEditingDraft || '').trim();
            try {
                await this.api('PATCH', '/utxos/' + encodeURIComponent(u.txid) + '/' + u.vout + '/label', { label: draft });
                u.label = draft;
                u.label_source = draft ? 'user' : null;
            } catch (e) {
                this.toast = e.message || 'Failed to save label';
            }
            this.cancelUtxoLabel();
        },

        // Coin-control selection helpers (Send dialog)
        toggleCoinControlSelection(u) {
            const idx = this.sendCoinControlSelected.indexOf(u.key);
            if (idx >= 0) this.sendCoinControlSelected.splice(idx, 1);
            else this.sendCoinControlSelected.push(u.key);
            this._recomputeCoinControlTotals();
            // Re-trigger the fee estimate since input set changed.
            this.debounceColdEstimate();
        },

        _recomputeCoinControlTotals() {
            const selSet = new Set(this.sendCoinControlSelected);
            let sendTotal = 0;
            const conSet = new Set(this.consolidateOutpoints);
            let conTotal = 0;
            for (const u of this.utxos) {
                if (selSet.has(u.key)) sendTotal += u.amount_sat;
                if (conSet.has(u.key)) conTotal += u.amount_sat;
            }
            this.sendCoinControlSelectedTotal = sendTotal;
            this.consolidateSelectedTotal = conTotal;
        },

        /** Map the current coin-control selection to the API outpoints
         *  payload, or null if auto-mode / no selection. */
        _currentSendOutpoints() {
            if (this.sendCoinControlMode !== 'manual') return null;
            if (!this.sendCoinControlSelected.length) return null;
            const out = [];
            const selSet = new Set(this.sendCoinControlSelected);
            for (const u of this.utxos) {
                if (selSet.has(u.key)) {
                    out.push({ txid_str: u.txid, output_index: u.vout });
                }
            }
            return out.length ? out : null;
        },

        // ── Consolidate dialog ──────────────────────────────────────
        openConsolidateDialog() {
            this.consolidateOpen = true;
            this.consolidateOutpoints = [];
            this.consolidateSelectedTotal = 0;
            this.consolidateError = '';
            this.consolidateLoading = false;
            // Reuse the same UTXO list as the on-chain tab.
            this.loadUtxos();
            this.initIcons();
        },

        closeConsolidate() {
            this.consolidateOpen = false;
            this.consolidateError = '';
        },

        toggleConsolidateSelection(u) {
            const idx = this.consolidateOutpoints.indexOf(u.key);
            if (idx >= 0) this.consolidateOutpoints.splice(idx, 1);
            else this.consolidateOutpoints.push(u.key);
            this._recomputeCoinControlTotals();
        },

        consolidateSelectAll() {
            this.consolidateOutpoints = this.utxos.map((u) => u.key);
            this._recomputeCoinControlTotals();
        },

        async submitConsolidate() {
            if (!this.consolidateOutpoints.length) return;
            this.consolidateLoading = true;
            this.consolidateError = '';
            try {
                const selSet = new Set(this.consolidateOutpoints);
                const ops = this.utxos
                    .filter((u) => selSet.has(u.key))
                    .map((u) => ({ txid_str: u.txid, output_index: u.vout }));
                const body = {
                    outpoints: ops,
                    dest_address_type: this.consolidateDestType,
                    sat_per_vbyte: this.consolidateSatPerVbyte || undefined,
                };
                const data = await this.api('POST', '/consolidate', body);
                this.toast = 'Consolidate broadcast: ' + (data.txid || '').substring(0, 12) + '…';
                this.closeConsolidate();
                this.fetchSummary();
                this.loadUtxos();
                // Refresh the transactions list so the consolidation tx
                // appears immediately rather than after the next periodic
                // ``fetchSummary`` tick — same UX rationale as the
                // Send On-chain dialog.
                this.fetchTransactions();
                // Track confirmations live when chain backend is up.
                if (data.txid) this.startTxConfPoll(data.txid);
            } catch (e) {
                this.consolidateError = e.message || 'Consolidate failed';
            }
            this.consolidateLoading = false;
        },

        // ════════════════════════════════════════════════════════════
        // API Key management + Audit log
        // ════════════════════════════════════════════════════════════

        // ── Helpers ──
        formatExpires(iso) {
            if (!iso) return 'never';
            const when = new Date(iso);
            if (isNaN(when.getTime())) return iso;
            const days = Math.round((when.getTime() - Date.now()) / 86400000);
            const date = when.toLocaleDateString(undefined, {
                year: 'numeric', month: 'short', day: 'numeric',
            });
            if (days < 0) return 'expired ' + date;
            if (days === 0) return 'expires today';
            return 'expires in ' + days + 'd (' + date + ')';
        },
        formatRelative(iso) {
            if (!iso) return 'never';
            const when = new Date(iso);
            if (isNaN(when.getTime())) return iso;
            const diff = Math.max(0, Math.floor((Date.now() - when.getTime()) / 1000));
            if (diff < 60) return 'just now';
            if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
            if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
            if (diff < 30 * 86400) return Math.floor(diff / 86400) + 'd ago';
            if (diff < 365 * 86400) return Math.floor(diff / (30 * 86400)) + 'mo ago';
            return Math.floor(diff / (365 * 86400)) + 'y ago';
        },
        formatPurgeEta(iso) {
            if (!iso) return 'eligible';
            const when = new Date(iso);
            if (isNaN(when.getTime())) return iso;
            const diff = Math.floor((when.getTime() - Date.now()) / 1000);
            if (diff <= 0) return 'eligible now';
            const days = Math.ceil(diff / 86400);
            return 'in ' + days + 'd';
        },
        formatTimestamp(iso) {
            if (!iso) return '';
            const when = new Date(iso);
            if (isNaN(when.getTime())) return iso;
            return when.toLocaleString(undefined, {
                month: 'short', day: 'numeric',
                hour: '2-digit', minute: '2-digit', second: '2-digit',
            });
        },
        formatAuditDetails(obj) {
            if (obj == null) return '';
            try {
                return JSON.stringify(obj, null, 2);
            } catch (_e) {
                return String(obj);
            }
        },

        // ── API Keys: open/close ──
        openApiKeys() {
            this.showSettingsMenu = false;
            this.showApiKeys = true;
            this.apiKeyJustCreated = null;
            this.apiKeyRotateContext = null;
            this.apiKeyDraftOpen = false;
            this.apiKeyDraftError = '';
            this.apiKeyConfirm = null;
            this.fetchApiKeys();
        },
        closeApiKeys() {
            this.showApiKeys = false;
            // Belt-and-braces: scrub any plaintext we may still hold.
            this._clearJustCreated();
            this.apiKeyConfirm = null;
            this.apiKeyEditId = null;
        },
        _clearJustCreated() {
            if (this.apiKeyJustCreated) {
                // Overwrite the string before nulling so the residue
                // is harder to scrape from a heap dump. Best-effort
                // — JS strings are immutable, but the reference is
                // cleared either way.
                try { this.apiKeyJustCreated.key = ''; } catch (_e) {}
            }
            this.apiKeyJustCreated = null;
            this.apiKeyRotateContext = null;
            this._cancelClipboardClear();
        },
        _cancelClipboardClear() {
            if (this._apiKeyClipboardTimer) {
                clearTimeout(this._apiKeyClipboardTimer);
                this._apiKeyClipboardTimer = null;
            }
            if (this._apiKeyClipboardInterval) {
                clearInterval(this._apiKeyClipboardInterval);
                this._apiKeyClipboardInterval = null;
            }
            this.apiKeyClipboardCountdown = 0;
            this._apiKeyClipboardText = '';
        },

        // ── API Keys: list ──
        async fetchApiKeys() {
            this.apiKeysLoading = true;
            this.apiKeysError = '';
            try {
                const data = await this.api('GET', '/api-keys');
                this.apiKeys = (data && data.keys) || [];
            } catch (e) {
                this.apiKeysError = e.message || 'Failed to load keys';
            }
            this.apiKeysLoading = false;
        },
        get filteredApiKeys() {
            const q = (this.apiKeysSearch || '').toLowerCase().trim();
            const f = this.apiKeysFilter;
            return (this.apiKeys || []).filter((k) => {
                if (q && !(k.name || '').toLowerCase().includes(q)) return false;
                if (f === 'all') return true;
                return k.status === f;
            });
        },
        canRevoke(k) {
            if (!k || k.status === 'revoked') return false;
            // Refuse to revoke / disable the only remaining active
            // admin key — same intent as the bootstrap-key safeguard.
            if (k.is_admin && k.is_active) {
                const otherActiveAdmin = (this.apiKeys || []).some((other) =>
                    other.id !== k.id && other.is_admin && other.is_active && other.status !== 'revoked'
                );
                if (!otherActiveAdmin) return false;
            }
            return true;
        },
        canPurge(k) {
            if (!k || k.status !== 'revoked') return false;
            if (!k.purge_eligible_at) return false;
            return new Date(k.purge_eligible_at).getTime() <= Date.now();
        },
        canDemote(k) {
            // Refuse to demote the only remaining active admin key.
            // Same shape as ``canRevoke`` — losing the last admin
            // means losing the ability to mint new keys via the
            // admin REST surface.
            if (!k || !k.is_admin || k.status === 'revoked') return false;
            const otherActiveAdmin = (this.apiKeys || []).some((other) =>
                other.id !== k.id && other.is_admin && other.is_active && other.status !== 'revoked'
            );
            return otherActiveAdmin;
        },
        // True when the inventory has exactly one key and it is an
        // active admin — the bootstrap-key empty-state CTA per
        // plan. Heuristic (no ``bootstrap_api_key_name``
        // setting exists), but matches the typical first-run state.
        get isBootstrapOnly() {
            const live = (this.apiKeys || []).filter((k) => k.status !== 'revoked');
            return live.length === 1 && live[0].is_admin && live[0].is_active;
        },
        // Friendly one-liner for a scope tier (key-created summary).
        scopeLabel(scope) {
            if (scope === 'admin') return 'admin (full control)';
            if (scope === 'spend') return 'spend (pay & withdraw)';
            return 'monitor + receive';
        },
        // Compact pill text for the key list.
        scopePillText(scope) {
            if (scope === 'admin') return 'admin';
            if (scope === 'spend') return 'spend';
            return 'monitor';
        },
        // True when the operator may change this key's scope at all.
        // The only blocked transition is demoting the last active admin
        // (it would strip the system of any admin-capable key); every
        // other key can move freely between tiers.
        canChangeScope(k) {
            return !!k && (!k.is_admin || this.canDemote(k));
        },

        // ── API Keys: create ──
        openApiKeyDraft() {
            this.apiKeyDraftOpen = true;
            this.apiKeyDraft = { name: '', scope: 'monitor', expires_in_days: 365 };
            this.apiKeyDraftError = '';
        },
        closeApiKeyDraft() {
            this.apiKeyDraftOpen = false;
            this.apiKeyDraftError = '';
        },
        async createApiKey() {
            const name = (this.apiKeyDraft.name || '').trim();
            if (!name) {
                this.apiKeyDraftError = 'Name is required';
                return;
            }
            const days = Number(this.apiKeyDraft.expires_in_days);
            if (!Number.isFinite(days) || days < 1 || days > 3650) {
                this.apiKeyDraftError = 'Expires in days must be between 1 and 3650';
                return;
            }
            this.apiKeyDraftError = '';
            this.apiKeyDraftSubmitting = true;
            try {
                const data = await this.api('POST', '/api-keys', {
                    name,
                    scope: this.apiKeyDraft.scope,
                    expires_in_days: days,
                });
                this.apiKeyJustCreated = data;
                this.apiKeyDraftOpen = false;
                this.fetchApiKeys();
            } catch (e) {
                this.apiKeyDraftError = e.message || 'Create failed';
            }
            this.apiKeyDraftSubmitting = false;
        },
        copyJustCreatedKey() {
            if (this.apiKeyJustCreated && this.apiKeyJustCreated.key) {
                this._copyApiKeyPlaintext(this.apiKeyJustCreated.key);
            }
        },
        // Copy a freshly minted API key to the clipboard, then
        // schedule a 60-second wipe. We don't use
        // ``copyText()`` because that handles ordinary strings —
        // here we want the auto-clear behaviour and the visible
        // countdown so the operator knows the secret won't linger
        // in the OS clipboard if they walk away.
        _copyApiKeyPlaintext(text) {
            if (!this._copyToClipboard(text)) {
                this.apiKeysError = 'Copy failed — select the key and copy manually.';
                return;
            }
            this._cancelClipboardClear();
            this._apiKeyClipboardText = text;
            this.apiKeyClipboardCountdown = 60;
            this.toast = 'Copied! Clipboard will clear in 60s.';
            setTimeout(() => { this.toast = ''; }, 2500);
            this._apiKeyClipboardInterval = setInterval(() => {
                if (this.apiKeyClipboardCountdown > 0) {
                    this.apiKeyClipboardCountdown -= 1;
                }
            }, 1000);
            this._apiKeyClipboardTimer = setTimeout(() => {
                // Best-effort: only blank the clipboard if it still
                // holds the key we put there. ``readText()`` may be
                // denied (Firefox in particular often refuses
                // without explicit permission) — in that case we
                // wipe unconditionally, since an over-eager wipe of
                // unrelated content is the safer trade for a key
                // that authorises spending real funds.
                const expected = this._apiKeyClipboardText;
                this._cancelClipboardClear();
                let p;
                try {
                    p = navigator.clipboard.readText();
                } catch (_e) {
                    p = Promise.reject();
                }
                Promise.resolve(p).then((current) => {
                    if (current === expected) {
                        navigator.clipboard.writeText('');
                    }
                }).catch(() => {
                    try { navigator.clipboard.writeText(''); } catch (_e2) {}
                });
            }, 60000);
        },
        async confirmKeyCaptured() {
            // Rotate flow: now that the user has captured the new
            // plaintext, soft-delete the old key. If that fails we
            // surface the error and leave the new key in place — the
            // operator can still retire the old one manually from the
            // inventory.
            const ctx = this.apiKeyRotateContext;
            if (ctx) {
                try {
                    await this.api('DELETE', '/api-keys/' + encodeURIComponent(ctx.oldId));
                    this.toast = 'Rotated: ' + ctx.oldName + ' revoked';
                    setTimeout(() => { this.toast = ''; }, 3000);
                } catch (e) {
                    this.apiKeysError = 'Old key not revoked: ' + (e.message || 'unknown error');
                }
            }
            this._clearJustCreated();
            this.fetchApiKeys();
        },

        // ── API Keys: rename ──
        startRenameApiKey(k) {
            this.apiKeyEditId = k.id;
            this.apiKeyEditName = k.name;
        },
        async saveApiKeyName(id) {
            const name = (this.apiKeyEditName || '').trim();
            if (!name) {
                this.apiKeyEditId = null;
                return;
            }
            try {
                await this.api('PATCH', '/api-keys/' + encodeURIComponent(id), { name });
                this.apiKeyEditId = null;
                this.fetchApiKeys();
            } catch (e) {
                this.apiKeysError = e.message || 'Rename failed';
            }
        },

        // ── API Keys: enable / disable / rotate / revoke / purge ──
        async toggleApiKeyActive(k) {
            const next = !k.is_active;
            // Confirm only when going active → disabled on a recently
            // used key.
            if (!next && k.last_used_at) {
                this.apiKeyConfirm = {
                    kind: 'disable',
                    key: k,
                    icon: 'pause',
                    tone: 'warn',
                    title: 'Disable ' + k.name + '?',
                    message: 'This key was used ' + this.formatRelative(k.last_used_at) +
                        '. Anyone using it will start getting 401s immediately. You can re-enable later.',
                    confirmLabel: 'Disable',
                };
                this.apiKeyConfirmAcknowledged = false;
                return;
            }
            await this._setApiKeyActive(k.id, next);
        },
        async _setApiKeyActive(id, value) {
            try {
                await this.api('PATCH', '/api-keys/' + encodeURIComponent(id), { is_active: value });
                this.fetchApiKeys();
            } catch (e) {
                this.apiKeysError = e.message || 'Update failed';
            }
        },
        async rotateApiKey(k) {
            // Step 1 of rotate: mint a replacement (same scope, same
            // expiry window). The "save your key" view then handles
            // step 2 (soft-delete the old one once the operator
            // confirms they captured the new plaintext).
            this.apiKeyDraftError = '';
            this.apiKeyDraftSubmitting = true;
            try {
                const expiresIn = k.expires_at
                    ? Math.max(1, Math.ceil((new Date(k.expires_at).getTime() - Date.now()) / 86400000))
                    : 365;
                const replacementName = k.name + ' (rotated)';
                const data = await this.api('POST', '/api-keys', {
                    name: replacementName,
                    scope: k.scope,
                    expires_in_days: expiresIn,
                });
                this.apiKeyJustCreated = data;
                this.apiKeyRotateContext = { oldId: k.id, oldName: k.name };
                this.fetchApiKeys();
            } catch (e) {
                this.apiKeysError = e.message || 'Rotation failed';
            }
            this.apiKeyDraftSubmitting = false;
        },
        async cancelRotation() {
            // Clean up the new key the operator decided not to keep.
            const created = this.apiKeyJustCreated;
            const ctx = this.apiKeyRotateContext;
            if (created && ctx) {
                try {
                    await this.api('DELETE', '/api-keys/' + encodeURIComponent(created.id));
                } catch (_e) {
                    // Surface the orphaned key in the inventory rather
                    // than blocking the close.
                }
            }
            this._clearJustCreated();
            this.fetchApiKeys();
        },
        confirmRevokeApiKey(k) {
            const lastActiveAdmin = k.is_admin && !(this.apiKeys || []).some((other) =>
                other.id !== k.id && other.is_admin && other.is_active && other.status !== 'revoked'
            );
            if (lastActiveAdmin) {
                // canRevoke() already disables the button, but guard
                // here too in case the state changed since render.
                this.apiKeysError = 'Refusing to revoke the only active admin key.';
                return;
            }
            this.apiKeyConfirm = {
                kind: 'revoke',
                key: k,
                icon: 'trash-2',
                tone: 'danger',
                title: 'Revoke ' + k.name + '?',
                message: 'Soft-deletes the key (audit history preserved). ' +
                    (k.last_used_at ? 'Last used ' + this.formatRelative(k.last_used_at) + '. ' : '') +
                    'It will no longer authenticate API requests. You can purge it from the database after audit retention elapses.',
                confirmLabel: 'Revoke',
                requireCheckbox: k.is_admin ? 'I have another working admin key' : null,
            };
            this.apiKeyConfirmAcknowledged = false;
        },
        confirmPurgeApiKey(k) {
            this.apiKeyConfirm = {
                kind: 'purge',
                key: k,
                icon: 'trash-2',
                tone: 'danger',
                title: 'Purge ' + k.name + '?',
                message: 'Hard-deletes this revoked key from the database. The audit log entries that reference it remain intact. This cannot be undone.',
                confirmLabel: 'Purge',
                requireCheckbox: 'I understand this is irreversible',
            };
            this.apiKeyConfirmAcknowledged = false;
        },
        // Triggered by the per-key scope <select>. The target tier is
        // already chosen, so the confirm modal is a pure yes/no — no
        // reactivity gymnastics. The select displays the pending value
        // until the action resolves; cancelApiKeyConfirm() refetches to
        // snap it back if the operator backs out.
        requestScopeChange(k, to) {
            if (!k || !to || to === k.scope) return;
            const demoting = k.is_admin && to !== 'admin';
            if (demoting && !this.canDemote(k)) {
                this.apiKeysError = 'Refusing to demote the only active admin key.';
                this.fetchApiKeys();  // revert the <select> to the server value
                return;
            }
            const promoting = to === 'admin' && k.scope !== 'admin';
            this.apiKeyConfirm = {
                kind: 'set_scope',
                key: k,
                scope: to,
                icon: promoting ? 'shield' : 'shield-half',
                tone: 'warn',
                title: 'Set ' + k.name + ' to ' + this.scopePillText(to) + '?',
                message: to === 'admin'
                    ? 'Grants this key full admin scope — spending funds, opening channels, and managing other API keys. Only do this for trusted callers.'
                    : to === 'spend'
                        ? 'Lets this key send payments and withdraw to cold storage, but not open/close channels, sign messages, or manage keys.'
                        : 'Monitor + receive: this key can read state and receive funds (generate addresses, create invoices) but cannot send or withdraw.',
                confirmLabel: 'Set ' + this.scopePillText(to),
                requireCheckbox: promoting ? 'I trust this caller with admin scope' : null,
            };
            this.apiKeyConfirmAcknowledged = false;
        },
        // Dismiss the confirm modal. A pending scope <select> shows its
        // optimistic value, so refetch to restore the server truth.
        cancelApiKeyConfirm() {
            const wasScope = this.apiKeyConfirm && this.apiKeyConfirm.kind === 'set_scope';
            this.apiKeyConfirm = null;
            if (wasScope) this.fetchApiKeys();
        },
        async executeApiKeyConfirm() {
            const c = this.apiKeyConfirm;
            if (!c) return;
            const k = c.key;
            this.apiKeyConfirm = null;
            try {
                if (c.kind === 'revoke') {
                    await this.api('DELETE', '/api-keys/' + encodeURIComponent(k.id));
                    this.toast = 'Revoked ' + k.name;
                } else if (c.kind === 'purge') {
                    await this.api('POST', '/api-keys/' + encodeURIComponent(k.id) + '/purge');
                    this.toast = 'Purged ' + k.name;
                } else if (c.kind === 'disable') {
                    await this._setApiKeyActive(k.id, false);
                    this.toast = 'Disabled ' + k.name;
                } else if (c.kind === 'set_scope') {
                    await this.api('PATCH', '/api-keys/' + encodeURIComponent(k.id), { scope: c.scope });
                    this.toast = k.name + ' → ' + this.scopePillText(c.scope);
                }
                setTimeout(() => { this.toast = ''; }, 2500);
            } catch (e) {
                this.apiKeysError = e.message || 'Action failed';
            }
            this.fetchApiKeys();
        },

        // ── Tor Health panel ──
        async openTorHealth() {
            this.showSettingsMenu = false;
            this.showTorHealth = true;
            await this.torHealthRefresh();
        },
        async torHealthRefresh() {
            // Only show the spinner on a cold open. The background poll
            // usually has fresh data already, so the panel shows the
            // status (and its plain-language verdict) the instant it
            // opens instead of flashing "Loading…".
            this.torHealthLoading = !this.torHealthData;
            this.torHealthError = '';
            try {
                const data = await this.api('GET', '/tor-status', null, { timeoutMs: 10000 });
                this.torHealthData = data;
                // Cache the breaker state for the header indicator dot so
                // it stays accurate even after the modal closes. —
                // in split mode the dot reflects the WORSE of the two
                // pools (open beats half_open beats closed) so the
                // operator notices either pool wedging.
                this.torHealthIndicatorState = this._torHealthAggregateState(data);
            } catch (e) {
                this.torHealthError = (e && e.message) || 'Failed to load Tor health.';
                this.torHealthData = null;
            } finally {
                this.torHealthLoading = false;
                this.initIcons();
            }
        },
        /** Background tick that keeps the Settings dot live without the
         *  user opening the panel. Reads the breaker state cheaply and,
         *  when the status can't be read at all, treats Tor as wedged so
         *  the dot warns rather than going stale. */
        async _torHealthIndicatorTick() {
            try {
                const data = await this.api('GET', '/tor-status', null, { timeoutMs: 8000 });
                this.torHealthIndicatorState = this._torHealthAggregateState(data);
                // If the panel is open, refresh its full view too.
                if (this.showTorHealth) {
                    this.torHealthData = data;
                    this.$nextTick(() => this.initIcons());
                }
            } catch (_e) {
                // Couldn't even reach the status endpoint → surface a problem.
                this.torHealthIndicatorState = 'open';
            }
        },

        torHealthToggleDetails() {
            this.torHealthDetailsOpen = !this.torHealthDetailsOpen;
            this.$nextTick(() => this.initIcons());
        },

        /** Plain-language verdict for the Tor Health panel (non-technical
         *  audience). Returns {tone, headline, detail} derived from the
         *  full status payload; the technical breakdown stays below. */
        get torHealthSummary() {
            const d = this.torHealthData;
            if (!d) return null;
            // The breaker state is always known and is the primary signal;
            // circuit/liveness/bootstrap only count against health when
            // they're a *known* bad value (null/"unknown" don't penalise).
            const worst = this._torHealthAggregateState(d) || 'closed';
            const bootKnown = d.bootstrap_progress !== null && d.bootstrap_progress !== undefined;
            const notBootstrapped = bootKnown && Number(d.bootstrap_progress) < 100;
            const circuitDown = d.circuit_established === false;
            const networkDown = d.network_liveness === 'down';
            if (worst === 'open' || circuitDown || networkDown) {
                return {
                    tone: 'down',
                    headline: 'Tor is having trouble connecting',
                    detail: 'Your wallet may not be able to send, receive, or refresh balances right now. '
                        + 'This usually clears up on its own within a minute or two. If it persists, restart the Tor service.',
                };
            }
            if (worst === 'half_open' || notBootstrapped) {
                return {
                    tone: 'warn',
                    headline: 'Tor is reconnecting',
                    detail: 'Things may be a little slow for a moment, then return to normal. No action needed.',
                };
            }
            return {
                tone: 'ok',
                headline: 'Connected through Tor',
                detail: "Your wallet's traffic is private and working normally.",
            };
        },

        /** Tooltip for the Settings dot — the verdict in a few words. */
        get torHealthIndicatorTitle() {
            const s = this.torHealthIndicatorState;
            if (s === 'open') return 'Tor connection problem — click for details';
            if (s === 'half_open') return 'Tor is reconnecting — click for details';
            if (s === 'closed') return 'Tor connection healthy — click for details';
            return 'Checking Tor connection…';
        },

        _torHealthAggregateState(data) {
            // Returns the "worst" breaker state across pools so the
            // header indicator reflects either pool wedging.
            if (!data) return null;
            const rank = { 'closed': 0, 'half_open': 1, 'open': 2 };
            const candidates = [data.tor_breaker_state];
            if (data.tor_split_mode_enabled) {
                candidates.push(data.tor_lnd_breaker_state);
            }
            let worst = null;
            let worstRank = -1;
            for (const s of candidates) {
                if (!s) continue;
                const r = rank[s];
                if (r === undefined) continue;
                if (r > worstRank) { worst = s; worstRank = r; }
            }
            return worst;
        },
        torHealthBreakerClass(state) {
            // Two-tier breakers report 'closed' | 'half_open' | 'open'.
            if (state === 'open') return 'text-neon-pink';
            if (state === 'half_open') return 'text-yellow-400';
            if (state === 'closed') return 'text-neon-green';
            return 'text-gray-500';
        },
        torHealthAgeText(seconds) {
            // Returns a compact human-readable age for the watchdog
            // timestamps. Tolerates ``null`` (never ticked) without
            // throwing in the template.
            if (seconds === null || seconds === undefined) return 'never';
            const s = Math.round(seconds);
            if (s < 60) return s + 's ago';
            if (s < 3600) return Math.round(s / 60) + 'm ago';
            return Math.round(s / 3600) + 'h ago';
        },
        get torHealthIndicatorClass() {
            // Header indicator dot. Reflects only the *Tor* breaker so a
            // wedged Tor stands out; LND-only failures show through other
            // existing dashboard surfaces.
            const s = this.torHealthIndicatorState;
            if (s === 'open') return 'bg-neon-pink';
            if (s === 'half_open') return 'bg-yellow-400';
            if (s === 'closed') return 'bg-neon-green';
            return 'bg-gray-600';
        },
        get torHealthBootstrapText() {
            const d = this.torHealthData;
            if (!d) return '';
            if (d.bootstrap_progress === null || d.bootstrap_progress === undefined) {
                return 'unknown';
            }
            return d.bootstrap_progress + '%';
        },
        get torHealthCircuitEstablishedText() {
            const d = this.torHealthData;
            if (!d) return '';
            if (d.circuit_established === null || d.circuit_established === undefined) {
                return 'unknown';
            }
            return d.circuit_established ? 'yes' : 'no';
        },
        torHealthListenerClass(ok) {
            // Three-state colour (gray = untested, green =
            // last probe succeeded, pink = last probe failed).
            if (ok === true) return 'text-neon-green';
            if (ok === false) return 'text-neon-pink';
            return 'text-gray-500';
        },
        async torHealthReload() {
            // Confirm in JS since the @alpinejs/csp build
            // can't evaluate window.confirm from an inline @click.
            if (!window.confirm(
                'Reload Tor configuration via SIGNAL HUP?\n\n'
                + 'This re-reads torrc without restarting Tor. '
                + 'A bad torrc means Tor refuses to reload and '
                + 'stays running on the previous config.'
            )) return;
            this.torHealthReloading = true;
            this.torHealthReloadStatus = 'Reloading…';
            try {
                const data = await this.api(
                    'POST', '/tor-reload', null, { timeoutMs: 15000 },
                );
                if (data && data.ok) {
                    this.torHealthReloadStatus = 'Reloaded successfully.';
                } else {
                    const err = (data && data.error) || 'unknown';
                    this.torHealthReloadStatus = 'Reload rejected: ' + err;
                }
            } catch (e) {
                this.torHealthReloadStatus = 'Reload failed: '
                    + ((e && e.message) || 'request failed');
            } finally {
                this.torHealthReloading = false;
                // Refresh the panel so the operator sees post-reload state.
                this.torHealthRefresh();
            }
        },
        torHealthListenerLabel(listener) {
            if (!listener) return 'unknown';
            if (listener.ok === true) return 'ok';
            if (listener.ok === false) {
                // Truncate the error string aggressively — the
                // mono row only has ~30 chars before wrap.
                const err = (listener.last_error || 'failed').slice(0, 40);
                return err;
            }
            return 'untested';
        },

        // ── Audit log ──
        openAuditLog() {
            this.showSettingsMenu = false;
            this.showAuditLog = true;
            this.auditEntries = [];
            this.auditNextCursor = null;
            this.auditExpanded = {};
            this.auditError = '';
            this.auditVerifyResult = null;
            this.auditFilter = { action: '', api_key_name: '', range: '24h' };
            this._loadAuditActions();
            this.reloadAuditLog();
        },
        closeAuditLog() {
            this.showAuditLog = false;
        },
        async _loadAuditActions() {
            try {
                const data = await this.api('GET', '/audit-log/actions');
                this.auditActions = (data && data.actions) || [];
            } catch (_e) {
                // Non-fatal — the dropdown just stays empty.
                this.auditActions = [];
            }
        },
        _auditQueryString(cursor) {
            const params = new URLSearchParams();
            params.set('limit', '50');
            if (cursor) params.set('cursor', cursor);
            if (this.auditFilter.action) params.set('action', this.auditFilter.action);
            if (this.auditFilter.api_key_name) {
                params.set('api_key_name', this.auditFilter.api_key_name.trim());
            }
            const range = this.auditFilter.range || '24h';
            if (range !== 'all') {
                const map = { '1h': 3600, '24h': 86400, '7d': 7 * 86400, '30d': 30 * 86400 };
                const secs = map[range];
                if (secs) {
                    const since = new Date(Date.now() - secs * 1000).toISOString();
                    params.set('since', since);
                }
            }
            return params.toString();
        },
        async reloadAuditLog() {
            this.auditEntries = [];
            this.auditNextCursor = null;
            this.auditExpanded = {};
            this.auditError = '';
            await this._fetchAuditPage(null);
        },
        async loadMoreAuditLog() {
            if (!this.auditNextCursor) return;
            await this._fetchAuditPage(this.auditNextCursor);
        },
        async _fetchAuditPage(cursor) {
            this.auditLoading = true;
            try {
                const qs = this._auditQueryString(cursor);
                const data = await this.api('GET', '/audit-log?' + qs);
                const entries = (data && data.entries) || [];
                if (cursor) {
                    this.auditEntries = this.auditEntries.concat(entries);
                } else {
                    this.auditEntries = entries;
                }
                this.auditNextCursor = (data && data.next_cursor) || null;
            } catch (e) {
                this.auditError = e.message || 'Failed to load audit log';
            }
            this.auditLoading = false;
        },
        toggleAuditRow(id) {
            this.auditExpanded = { ...this.auditExpanded, [id]: !this.auditExpanded[id] };
        },
        async verifyAuditChain() {
            this.auditVerifyResult = null;
            try {
                const data = await this.api('GET', '/audit-log/verify');
                this.auditVerifyResult = data;
            } catch (e) {
                this.auditVerifyResult = {
                    ok: false, checked: 0,
                    first_bad_id: '?', first_bad_reason: e.message || 'verify failed',
                };
            }
        },
        async reanchorAuditChain() {
            if (!confirm('Re-anchor the audit chain under the current key? Use this only after a database restore or SECRET_KEY rotation. The action is recorded in the audit log.')) {
                return;
            }
            this.auditReanchoring = true;
            try {
                await this.api('POST', '/audit-log/reanchor');
                await this.verifyAuditChain();
            } catch (e) {
                this.auditVerifyResult = {
                    ok: false, checked: 0,
                    first_bad_id: '?', first_bad_reason: e.message || 're-anchor failed',
                };
            } finally {
                this.auditReanchoring = false;
            }
        },
    }));
});
