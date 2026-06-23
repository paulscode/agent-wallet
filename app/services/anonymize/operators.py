# SPDX-License-Identifier: MIT
"""Multi-operator registry loader + signature verification + pair sampler.

The LN-source path uses a single-entry registry (the configured
Boltz reverse operator). The operator-pair sampler becomes meaningful
only on the on-chain self-source path when ``BOLTZ_SUBMARINE_API_URL``
is configured and the registry has ≥3 audited entries.

Curated registry shipped in repo at
``app/services/anonymize/operators.json``. — the registry is
loaded only when its detached signature ``operators.sig`` verifies
against the pinned release-key fingerprint.

``make_create_swap_request()`` is the single Boltz request
builder so CI tests can assert no extra fields / no internal IDs leak.

``sample_operator_pair()`` is the single sampling site;
selection uses ``secrets.SystemRandom`` over the eligible-pair set
(distinct operators only, neither degraded).
"""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from app.core.config import settings

from .http import EgressFingerprintError
from .metadata import ANONYMIZE_FORBIDDEN_EGRESS_FIELDS


@dataclass(frozen=True)
class OperatorEntry:
    """One row of ``operators.json`` (schema)."""

    operator_id: str
    onion: str
    public_key_hex: str
    attested_min_24h_volume_satoshis: int = 0
    clearnet_fallback: str | None = None  # informational only
    last_audit_date: str | None = None
    # Optional capability declaration — set of Boltz chain-swap pair
    # ids (e.g. ``"BTC/LBTC"``) the operator advertises. When EMPTY
    # the loader treats the operator as a capability-undeclared
    # legacy registry entry; the Liquid-leg selector falls back to
    # registry-inclusion as implicit capability so older signed
    # registries keep working without re-signing. Populate this
    # field at the next signing rotation to make capability gating
    # authoritative.
    chain_swap_pairs: tuple[str, ...] = ()


# documented Boltz create-swap fields. The set is conservative
# — anything not in here is a fingerprint-grade "this wallet sends
# extra fields" beacon to the operator.
_REVERSE_SWAP_ALLOWED_FIELDS: frozenset[str] = frozenset(
    {
        "type",  # "reversesubmarine"
        "pairId",  # "BTC/BTC"
        "orderSide",  # "buy"
        "invoiceAmount",  # binned amount in sat
        "preimageHash",  # hex
        "claimPublicKey",  # hex
        "pairHash",  # operator-supplied
        "address",  # destination address (only when claim_address mode)
        "addressSignature",
    }
)
_SUBMARINE_SWAP_ALLOWED_FIELDS: frozenset[str] = frozenset(
    {
        "type",  # "submarine"
        "pairId",
        "orderSide",  # "sell"
        "invoice",  # BOLT11
        "refundPublicKey",
        "pairHash",
    }
)


def make_create_swap_request(
    *,
    swap_type: Literal["reverse", "submarine"],
    fields: dict[str, Any],
) -> dict[str, Any]:
    """Build a Boltz create-swap request body.

    Strict shape gate — only fields listed in the per-direction
    allow-list above are admitted. The function refuses to build a
    request body that includes:

    * any field outside the allow-list (: no ``referralId``,
      no custom preimage-hash algorithm, no internal IDs).
    * any of:data:`ANONYMIZE_FORBIDDEN_EGRESS_FIELDS` (:
      ``session_id``, ``quote_token``, ``idempotency_key``,
      ``internal_swap_id``, ``our_node_pubkey``, etc.).

    The output is a fresh dict the caller can pass to ``json.dumps``;
    the function does not perform the egress itself (that lives in
    :mod:`http`). LN-source deployments use only the ``"reverse"``
    path (``"submarine"`` accompanies the on-chain self-source
    operator-registry).
    """
    if swap_type == "reverse":
        allowed = _REVERSE_SWAP_ALLOWED_FIELDS
    elif swap_type == "submarine":
        allowed = _SUBMARINE_SWAP_ALLOWED_FIELDS
    else:
        raise ValueError(f"unknown swap_type: {swap_type!r}")

    extras = set(fields.keys()) - allowed
    if extras:
        raise EgressFingerprintError(
            f"create-swap body contains disallowed extra field(s): "
            f"{sorted(extras)}. Boltz pinned-shape policy admits only "
            f"{sorted(allowed)}."
        )
    forbidden = ANONYMIZE_FORBIDDEN_EGRESS_FIELDS & set(fields.keys())
    if forbidden:
        raise EgressFingerprintError(f"create-swap body contains forbidden egress field(s): {sorted(forbidden)}")
    # Return a new dict so the caller's mutation can't affect us.
    return dict(fields)


class RegistryLoadError(RuntimeError):
    """Raised when ``operators.json`` cannot be loaded or is malformed."""


def load_operator_registry(
    path: str | Path | None = None,
    *,
    text: str | None = None,
) -> list[OperatorEntry]:
    """Load and parse ``operators.json``.

    A single-operator deployment ships an empty file (or no file at
    all) — the wallet then uses the legacy ``BOLTZ_API_URL`` flow.
    The curated registry accompanies the on-chain self-source path;
    its startup wires the ``operators.sig`` detached-signature
    verification in front of this loader.

    When ``text`` is supplied the parser uses those exact bytes instead
    of re-reading ``path`` — the signed loader passes the bytes it just
    verified so the verified content and the parsed content cannot differ
    (closes a verify-then-reread TOCTOU).

    Returns ``[]`` when the file is absent or empty so callers can
    fall back to the single-entry path without raising.
    """
    if path is None:
        path = settings.anonymize_boltz_operator_registry_path
    p = Path(path)
    if text is None:
        if not p.is_file():
            return []
        try:
            text = p.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise RegistryLoadError(f"could not read {p}: {exc}") from exc
    else:
        text = text.strip()
    if not text:
        return []
    try:
        raw = json.loads(text)
    except json.JSONDecodeError as exc:
        raise RegistryLoadError(f"{p} is not valid JSON: {exc}") from exc

    if not isinstance(raw, list):
        raise RegistryLoadError(f"{p} must be a JSON array of operator entries")
    out: list[OperatorEntry] = []
    seen_ids: set[str] = set()
    seen_keys: set[str] = set()
    for i, item in enumerate(raw):
        if not isinstance(item, dict):
            raise RegistryLoadError(f"{p}[{i}]: entry is not an object")
        try:
            raw_pairs = item.get("chain_swap_pairs") or ()
            if isinstance(raw_pairs, str):
                # Tolerate a single string for forward-compat.
                raw_pairs = (raw_pairs,)
            chain_swap_pairs = tuple(str(p).strip() for p in raw_pairs if str(p).strip())
            entry = OperatorEntry(
                operator_id=item["operator_id"],
                onion=item["onion"],
                public_key_hex=item["public_key_hex"],
                attested_min_24h_volume_satoshis=int(item.get("attested_min_24h_volume_satoshis", 0)),
                clearnet_fallback=item.get("clearnet_fallback"),
                last_audit_date=item.get("last_audit_date"),
                chain_swap_pairs=chain_swap_pairs,
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise RegistryLoadError(f"{p}[{i}]: malformed entry ({exc})") from exc
        if entry.operator_id in seen_ids:
            raise RegistryLoadError(f"{p}: duplicate operator_id {entry.operator_id!r}")
        # Skip dedupe for blank ``public_key_hex`` — an empty value is
        # not a signing key but a "operator hasn't opted into
        # response signing yet" marker (see boltz_egress.py:205). Two
        # operators that both omit the key are not collision-equivalent
        # in any meaningful sense.
        if entry.public_key_hex and entry.public_key_hex in seen_keys:
            raise RegistryLoadError(f"{p}: duplicate public_key_hex for operator_id {entry.operator_id!r}")
        # Operators must publish a v3 onion. The clearnet_fallback
        # field exists for documentation only (never selected). The field
        # accepts both a raw hostname (legacy / test fixtures) and a full
        # URL with API path suffix (production — canonical Boltz mounts at
        # ``/api/v2`` and the community operators mount at ``/v2``).
        from urllib.parse import urlsplit

        _raw = entry.onion.strip().lower()
        if "://" in _raw:
            _host = (urlsplit(_raw).hostname or "").lower()
        else:
            # No scheme — treat the value as a raw hostname.
            _host = _raw.split("/", 1)[0]
        if not _host.endswith(".onion"):
            raise RegistryLoadError(f"{p}[{i}]: operator {entry.operator_id!r} `onion` is not a v3 .onion hostname")
        seen_ids.add(entry.operator_id)
        if entry.public_key_hex:
            seen_keys.add(entry.public_key_hex)
        out.append(entry)
    return out


def sample_operator_pair(
    registry: list[OperatorEntry],
    *,
    excluded_ids: frozenset[str] = frozenset(),
) -> tuple[OperatorEntry, OperatorEntry] | None:
    """Sample ``(submarine, reverse)`` ordered pair.

    Returns ``None`` when fewer than 2 eligible operators are
    available — single-operator deployments have a single-entry
    registry, so this path is the common case. The orchestrator falls
    back to
    the legacy single-operator flow on ``None``.

    The sample uses ``secrets.SystemRandom`` so that:
    1. Operator pair selection is unpredictable to anyone not running
       our process (denies a "predict the next pair after a
       restart" attack).
    2. The selection is uniform over the ordered-pair space, not just
       over each operator independently.
    """
    eligible = [op for op in registry if op.operator_id not in excluded_ids]
    if len(eligible) < 2:
        return None
    rng = secrets.SystemRandom()
    submarine = rng.choice(eligible)
    # Reverse must differ from submarine (distinct-host invariant).
    reverse_candidates = [op for op in eligible if op.operator_id != submarine.operator_id]
    reverse = rng.choice(reverse_candidates)
    return submarine, reverse


def canonicalize_operator_url(raw: str) -> str:
    """onion-canonicalization for operator-distinctness comparison.

    Returns the lowercased hostname of the URL. Two raw URLs that
    differ only in casing, scheme, port, or path produce the same
    canonical form. The empty / unparsable case returns ``""``.

    The distinct-operator invariant is enforced by comparing
    canonical hostnames; with a curated registry the *operator_id*
    + *public_key_hex* are the authoritative tuple, but the URL-level
    comparison catches the common mis-config where an operator runs
    multiple front-ends pointing at the same backend.
    """
    if not raw:
        return ""
    from urllib.parse import urlparse

    candidate = raw.strip()
    if "://" not in candidate:
        candidate = "http://" + candidate
    parsed = urlparse(candidate)
    return (parsed.hostname or "").lower()


def resolve_operator_url_from_registry(operator_id: str | None) -> str | None:
    """Return the onion
    URL for ``operator_id`` from the loaded signed registry, or
    ``None`` when the operator isn't in the registry.

    Used by :mod:`hop_dispatcher` to route per-session swap egress to
    the URL of the operator the chain selector actually picked.
    Without this, the chain selection would be decorative — the swap
    would always egress through ``BOLTZ_SUBMARINE_ONION_URL`` /
    ``BOLTZ_REVERSE_ONION_URL`` regardless of which operator the
    selector chose, defeating the distinct-operator splitting
    that the chain is supposed to enforce.
    """
    if not operator_id:
        return None
    try:
        registry = load_signed_operator_registry()
    except Exception:  # noqa: BLE001
        return None
    for entry in registry:
        if entry.operator_id == operator_id:
            return entry.onion
    return None


def resolve_submarine_leg_url(prefer_onion: bool = True) -> str:
    """Return the Boltz URL the submarine leg should target.

    Falls back to the shared ``boltz_*_url`` when the leg-specific
    setting is empty (single-operator deployment).
    """
    if prefer_onion:
        if settings.boltz_submarine_onion_url:
            return settings.boltz_submarine_onion_url
        return settings.boltz_onion_url
    if settings.boltz_submarine_api_url:
        return settings.boltz_submarine_api_url
    return settings.boltz_api_url


def resolve_reverse_leg_url(prefer_onion: bool = True) -> str:
    """Return the Boltz URL the reverse leg should target.

    Falls back to the shared ``boltz_*_url`` when the leg-specific
    setting is empty (single-operator deployment).
    """
    if prefer_onion:
        if settings.boltz_reverse_onion_url:
            return settings.boltz_reverse_onion_url
        return settings.boltz_onion_url
    if settings.boltz_reverse_api_url:
        return settings.boltz_reverse_api_url
    return settings.boltz_api_url


# ── Liquid-leg operator selection ────────────────────────────────

# Pair id Boltz advertises for the LN↔L-BTC chain-swap on the
# public ``/v2/pairs/chain`` endpoint. Operators that declare this
# in ``chain_swap_pairs`` are eligible for the Liquid hop.
LIQUID_CHAIN_SWAP_PAIR: str = "BTC/LBTC"


def _operator_supports_liquid_chain_swap(entry: "OperatorEntry") -> bool:
    """True iff ``entry`` advertises L-BTC chain-swap support.

    Backwards-compat: an empty ``chain_swap_pairs`` tuple means the
    registry entry pre-dates the capability-declaration schema. In
    that case we fall back to registry-inclusion as implicit support
    so older signed registries don't need an immediate re-sign just
    to use the Liquid hop. Populate the field at the next signing
    rotation to make gating authoritative.
    """
    if not entry.chain_swap_pairs:
        return True
    return LIQUID_CHAIN_SWAP_PAIR in entry.chain_swap_pairs


def _sort_key_liquid_candidate(entry: "OperatorEntry") -> tuple[int, str, int]:
    """Same ordering policy as
    :func:`operator_selection._sort_key_last_audit` — most-recently-
    audited first, then by attested 24h volume descending. Inlined
    here to avoid the cross-module import; the two helpers MUST
    return equivalent rankings for the same input.
    """
    raw = (entry.last_audit_date or "").strip()
    if not raw:
        date_key: tuple[int, str] = (1, "")
    else:
        flipped = "".join(str(9 - int(ch)) if ch.isdigit() else ch for ch in raw)
        date_key = (0, flipped)
    return (
        date_key[0],
        date_key[1],
        -int(entry.attested_min_24h_volume_satoshis or 0),
    )


@dataclass(frozen=True)
class LiquidLegSelection:
    """Resolved (LN→L-BTC, L-BTC→LN) operator pair for the Liquid hop.

    The two operator slots MAY collide on ``boltz-canonical`` when
    only one Liquid-capable operator is in the registry (or when
    one of the env-pin overrides points at the canonical URL); the
    caller chooses whether to refuse the session or accept reduced
    diversity. The default in :func:`build_default_liquid_hop_deps`
    is to log a warning and proceed — the Liquid hop is opt-in and
    the operator who chose to enable it is presumed to accept the
    minimum-diversity deployment.
    """

    ln_to_lbtc_url: str
    lbtc_to_ln_url: str
    ln_to_lbtc_operator_id: str | None
    lbtc_to_ln_operator_id: str | None
    legs_distinct: bool


def select_liquid_leg_urls(
    registry: list["OperatorEntry"] | None = None,
) -> LiquidLegSelection:
    """Pick (LN→L-BTC, L-BTC→LN) Boltz operators for the Liquid hop.

    Policy mirrors :func:`operator_selection._compute_chain` for the
    LN↔on-chain swap chain:

    * **LN→L-BTC** (reverse-analog — the leg that lands in the
      L-BTC dwell pool whose anonymity set dominates the hop's
      privacy gain): prefer ``boltz-canonical`` (largest L-BTC
      mempool throughput).
    * **L-BTC→LN** (submarine-analog): prefer the
      most-recently-audited non-canonical operator by attested 24h
      volume desc, then the next, then fall back to
      ``boltz-canonical`` when no diverse operator is available.

    Env overrides win over registry resolution:

    * ``BOLTZ_CHAIN_LN_TO_LBTC_API_URL`` pins the reverse-analog leg.
    * ``BOLTZ_CHAIN_LBTC_TO_LN_API_URL`` pins the submarine-analog leg.

    Returns a :class:`LiquidLegSelection` whose URL fields are
    guaranteed non-empty. Raises :class:`RuntimeError` when no URL
    can be resolved (registry empty AND env unset) — the caller
    surfaces that to the operator at startup.
    """
    env_ln_to_lbtc = (settings.boltz_chain_ln_to_lbtc_api_url or "").strip()
    env_lbtc_to_ln = (settings.boltz_chain_lbtc_to_ln_api_url or "").strip()

    if registry is None:
        try:
            registry = load_signed_operator_registry()
        except Exception:  # noqa: BLE001 — env-only deployments
            registry = []

    eligible = [e for e in registry if _operator_supports_liquid_chain_swap(e)]

    # Reverse-analog leg (LN→L-BTC). Prefer the env pin, then the
    # canonical Boltz entry, then the highest-ranked eligible
    # operator (which usually is canonical anyway).
    ln_to_lbtc_url = env_ln_to_lbtc
    ln_to_lbtc_op: str | None = None
    if not ln_to_lbtc_url:
        canonical = next(
            (e for e in eligible if e.operator_id == "boltz-canonical"),
            None,
        )
        if canonical is not None:
            ln_to_lbtc_url = canonical.onion
            ln_to_lbtc_op = canonical.operator_id
        elif eligible:
            top = sorted(eligible, key=_sort_key_liquid_candidate)[0]
            ln_to_lbtc_url = top.onion
            ln_to_lbtc_op = top.operator_id

    # Submarine-analog leg (L-BTC→LN). Prefer the env pin, then the
    # highest-ranked non-canonical operator (Middleway → Eldamar),
    # then canonical as last resort.
    lbtc_to_ln_url = env_lbtc_to_ln
    lbtc_to_ln_op: str | None = None
    if not lbtc_to_ln_url:
        non_canonical = sorted(
            [e for e in eligible if e.operator_id != "boltz-canonical"],
            key=_sort_key_liquid_candidate,
        )
        if non_canonical:
            top = non_canonical[0]
            lbtc_to_ln_url = top.onion
            lbtc_to_ln_op = top.operator_id
        else:
            canonical = next(
                (e for e in eligible if e.operator_id == "boltz-canonical"),
                None,
            )
            if canonical is not None:
                lbtc_to_ln_url = canonical.onion
                lbtc_to_ln_op = canonical.operator_id

    if not ln_to_lbtc_url or not lbtc_to_ln_url:
        raise RuntimeError(
            "select_liquid_leg_urls: no Liquid chain-swap operator "
            "URL available. Either populate the signed operator "
            "registry with a Liquid-capable entry, or set "
            "BOLTZ_CHAIN_LN_TO_LBTC_API_URL and "
            "BOLTZ_CHAIN_LBTC_TO_LN_API_URL as explicit overrides."
        )

    legs_distinct = canonicalize_operator_url(ln_to_lbtc_url) != canonicalize_operator_url(lbtc_to_ln_url)
    return LiquidLegSelection(
        ln_to_lbtc_url=ln_to_lbtc_url,
        lbtc_to_ln_url=lbtc_to_ln_url,
        ln_to_lbtc_operator_id=ln_to_lbtc_op,
        lbtc_to_ln_operator_id=lbtc_to_ln_op,
        legs_distinct=legs_distinct,
    )


def assert_distinct_leg_urls_configured() -> None:
    """Refuse on-chain sources unless the two Boltz legs
    point at distinct hosts after onion-canonicalization.

    Raises :class:`ValueError` when both legs resolve to the same
    canonical hostname. The caller (admission gate / startup) maps
    the error onto a structured response (``distinct_operators=False``
    in the pipeline env so the scorer hard-caps the session, or a
    startup gate refusal).

    Lightning-only deployments that never use on-chain sources can leave
    both leg URLs unset (both resolve to the shared ``boltz_*_url``);
    this helper does NOT raise in that case unless the caller has
    explicitly asserted that on-chain sources are enabled — that's
    the caller's job. Here we only compare what's configured.
    """
    sub = canonicalize_operator_url(resolve_submarine_leg_url(prefer_onion=True))
    rev = canonicalize_operator_url(resolve_reverse_leg_url(prefer_onion=True))
    if sub and sub == rev:
        raise ValueError(
            f"submarine and reverse Boltz legs resolve to the same "
            f"hostname {sub!r}; configure BOLTZ_SUBMARINE_ONION_URL "
            "and BOLTZ_REVERSE_ONION_URL to distinct operator URLs "
            "before enabling on-chain anonymize sources."
        )


def has_distinct_legs_configured() -> bool:
    """True iff at least one leg-specific URL is set AND the two legs
    resolve to distinct hostnames. On-chain sources gate on
    this being True via the ``distinct_operators`` env flag."""
    sub = canonicalize_operator_url(resolve_submarine_leg_url(prefer_onion=True))
    rev = canonicalize_operator_url(resolve_reverse_leg_url(prefer_onion=True))
    if not sub or not rev:
        return False
    return sub != rev


def assert_operators_distinct(
    submarine: OperatorEntry,
    reverse: OperatorEntry,
) -> None:
    """Refuse a session whose two legs share an operator.

    Two operators are "distinct" when:
    1. Their ``operator_id`` differs (registry-level).
    2. Their ``public_key_hex`` differs (signature-key-level — even
       a malicious operator that publishes two ``operator_id`` rows
       pointing at the same backend cannot share a signing key).
    3. Their canonicalized onion hostnames differ.

    Raises :class:`ValueError` on any collision. The orchestrator
    routes the offending session to ``failed`` rather than admitting
    a single-operator on-chain pipeline.
    """
    if submarine.operator_id == reverse.operator_id:
        raise ValueError(f"submarine and reverse operators share operator_id {submarine.operator_id!r}")
    if submarine.public_key_hex == reverse.public_key_hex:
        raise ValueError("submarine and reverse operators share public_key_hex")
    sub_host = canonicalize_operator_url(submarine.onion)
    rev_host = canonicalize_operator_url(reverse.onion)
    if sub_host and sub_host == rev_host:
        raise ValueError(f"submarine and reverse operators share onion host {sub_host!r}")


class RegistrySignatureError(RuntimeError):
    """Raised when ``operators.json``'s detached signature does not verify."""


def _canonicalize_registry_for_signing(text: str | bytes) -> bytes:
    """Return the bytes that the release key signs.

    The signature is computed over the *exact bytes* of ``operators.json``
    after stripping trailing whitespace + a single trailing newline. This
    avoids editor-introduced whitespace breaking the signature without
    requiring the operator to know how their editor was configured.
    """
    return (
        text.rstrip(b"\n " if isinstance(text, bytes) else "\n ").encode("utf-8")
        if isinstance(text, str)
        else text.rstrip(b"\n ")
    )


def verify_operator_api_response(
    *,
    operator: "OperatorEntry",
    response_body: bytes,
    signature_bytes: bytes,
) -> bool:
    """Verify a Boltz API response signature against the
    operator's pinned ``public_key_hex``.

    Boltz operators in the curated registry sign each response with
    their pinned ed25519 key. The anonymize HTTP wrapper extracts the
    signature from a documented header (``X-Operator-Signature``,
    raw hex of the 64-byte ed25519 signature) and calls this helper
    before admitting the response.

    Returns False — never raises — on any verification failure so
    the caller can route the session through reconciliation with a
    structured ``operator_response_unverified`` event.
    """
    if not signature_bytes:
        return False
    pub_hex = (operator.public_key_hex or "").strip()
    if not pub_hex:
        return False
    return verify_detached_signature(
        canonical_bytes=response_body,
        signature_bytes=signature_bytes,
        fingerprint=pub_hex,
    )


def _decode_release_key_fingerprint(fingerprint: str) -> bytes | None:
    """Decode a release-key fingerprint into the raw 32-byte ed25519
    public key.

    The trust-set is a list of release-key fingerprints —
    each is the hex-encoded 32-byte ed25519 public key (64 hex chars).
    Returns ``None`` for malformed input so the verify path can skip
    that fingerprint without raising.
    """
    if not fingerprint:
        return None
    candidate = fingerprint.strip().replace(":", "").replace(" ", "")
    if len(candidate) != 64:
        return None
    try:
        return bytes.fromhex(candidate)
    except ValueError:
        return None


def _looks_like_pgp_armored_signature(signature_bytes: bytes) -> bool:
    """True iff ``signature_bytes`` starts with the OpenPGP armored
    detached-signature header.

    The wallet's signed-registry path accepts two signature formats:

    * **Raw 32-byte ed25519** — single-purpose key generated for
      ``operators.json``; fingerprint is the 64-char hex of the raw
      public key. Verification delegates to
      ``cryptography.hazmat.primitives.asymmetric.ed25519``.
    * **OpenPGP detached signature** (RSA or EdDSA) — produced by
      ``gpg --armor --detach-sign``; fingerprint is the GPG v4 (40
      hex) or v5 (64 hex) key fingerprint. Verification shells out
      to the system ``gpg`` against an isolated keyring that imports
      the bundled ``app/services/anonymize/maintainer.asc``.

    This predicate routes the verifier to the right path. A signature
    that is neither raw ed25519 nor armored OpenPGP returns False from
    the verifier without raising.
    """
    if not signature_bytes:
        return False
    head = signature_bytes[:32].lstrip()
    return head.startswith(b"-----BEGIN PGP SIGNATURE-----")


# Bundled in-repo maintainer pubkey. The release-engineering
# workflow signs ``operators.json`` with the matching private half on
# an air-gapped system; the wallet imports this public half into an
# isolated GPG keyring at verify time so the host's own keyring is
# never consulted. Path is resolved relative to this module so a
# subset-install (e.g., pytest tmp dir) still finds it.
_MAINTAINER_PUBKEY_PATH = Path(__file__).resolve().parent / "maintainer.asc"


def _verify_gpg_armored_signature(
    *,
    canonical_bytes: bytes,
    signature_bytes: bytes,
    fingerprint: str,
) -> bool:
    """Verify an armored OpenPGP detached signature via
    a system ``gpg`` running against an isolated keyring.

    The keyring is built fresh per call from
    ``app/services/anonymize/maintainer.asc`` so the verification does
    not depend on whatever's in the deployment host's main keyring,
    and so a compromised host keyring (where an attacker added a
    public key the wallet hadn't whitelisted) cannot influence the
    decision.

    The ``fingerprint`` is matched against the ``VALIDSIG`` line in
    gpg's status-fd output — both v4 (40 hex) and v5 (64 hex) GPG
    fingerprints are supported. Returns ``False`` (never raises) on
    any failure so the caller can iterate the allow-list cleanly.
    """
    if not signature_bytes:
        return False
    if not fingerprint:
        return False
    want_fp = fingerprint.strip().replace(":", "").replace(" ", "").upper()
    if not want_fp or any(c not in "0123456789ABCDEF" for c in want_fp):
        return False
    if not _MAINTAINER_PUBKEY_PATH.is_file():
        return False

    import shutil
    import subprocess
    import tempfile

    gpg_bin = shutil.which("gpg") or shutil.which("gpg2")
    if gpg_bin is None:
        # System has no gpg available — refuse but don't crash; the
        # caller may fall back to other fingerprints in the allow-list
        # (e.g., a raw ed25519 fingerprint paired with a raw .sig).
        # Emit a single log line so deployments shipping an armored
        # signature against a gpg-less image surface a clear hint
        # instead of the generic "no fingerprint matched" error.
        import logging as _logging

        _logging.getLogger(__name__).error(
            "operators.sig.asc is OpenPGP-armored but no gpg/gpg2 binary "
            "was found on PATH — install ``gnupg`` in the runtime image "
            "or switch to a raw ed25519 signature."
        )
        return False

    with tempfile.TemporaryDirectory(prefix="anonymize-gpg-") as gpg_home:
        # Lock down the gpg home directory (gpg refuses 0700 enforcement
        # when permissions are too open).
        import os as _os

        _os.chmod(gpg_home, 0o700)

        # Import the bundled maintainer pubkey into the isolated keyring.
        import_proc = subprocess.run(
            [
                gpg_bin,
                "--homedir",
                gpg_home,
                "--batch",
                "--no-tty",
                "--no-default-keyring",
                "--keyring",
                str(Path(gpg_home) / "trusted.gpg"),
                "--import",
                str(_MAINTAINER_PUBKEY_PATH),
            ],
            capture_output=True,
            timeout=10,
        )
        if import_proc.returncode != 0:
            return False

        # Verify with --status-fd so we get a machine-readable VALIDSIG
        # line that contains the SIGNING-key fingerprint. The signature
        # + canonical bytes are passed via temp files; gpg's stdin
        # interface for detached verification is awkward across versions.
        with (
            tempfile.NamedTemporaryFile(
                mode="wb",
                suffix=".sig",
                delete=False,
            ) as sig_f,
            tempfile.NamedTemporaryFile(
                mode="wb",
                suffix=".bin",
                delete=False,
            ) as data_f,
        ):
            sig_f.write(signature_bytes)
            data_f.write(canonical_bytes)
            sig_path = sig_f.name
            data_path = data_f.name

        try:
            verify_proc = subprocess.run(
                [
                    gpg_bin,
                    "--homedir",
                    gpg_home,
                    "--batch",
                    "--no-tty",
                    "--status-fd",
                    "1",
                    "--keyring",
                    str(Path(gpg_home) / "trusted.gpg"),
                    "--verify",
                    sig_path,
                    data_path,
                ],
                capture_output=True,
                timeout=15,
            )
        finally:
            _os.unlink(sig_path)
            _os.unlink(data_path)

        if verify_proc.returncode != 0:
            return False

        # Parse status-fd output for VALIDSIG <fingerprint> ...
        # Reference: doc/DETAILS in the gnupg source.
        for line in verify_proc.stdout.decode(
            "utf-8",
            errors="replace",
        ).splitlines():
            if not line.startswith("[GNUPG:] VALIDSIG"):
                continue
            parts = line.split()
            if len(parts) < 3:
                continue
            got_fp = parts[2].upper()
            if got_fp == want_fp:
                return True
        return False


def verify_detached_signature(
    *,
    canonical_bytes: bytes,
    signature_bytes: bytes,
    fingerprint: str,
) -> bool:
    """Verify a detached signature against ``fingerprint``.

    Dispatches based on the signature format:

    * Armored OpenPGP (``-----BEGIN PGP SIGNATURE-----``) → shells out
      to system ``gpg`` via :func:`_verify_gpg_armored_signature` with
      an isolated keyring loaded from the bundled
      ``app/services/anonymize/maintainer.asc``. Supports RSA + EdDSA
      keys; fingerprint format is the GPG v4 (40 hex) or v5 (64 hex)
      key fingerprint.
    * Anything else → treated as a raw 64-byte ed25519 signature with
      a 64-hex-char ed25519 public-key fingerprint.

    The ``ANONYMIZE_REGISTRY_RELEASE_KEY_FINGERPRINTS`` allow-list may
    contain BOTH formats simultaneously (a maintainer who rotates from
    GPG to raw ed25519 or vice versa keeps both pinned during the
    overlap window). The verifier walks each pinned fingerprint and
    accepts the registry iff any one verifies.

    Returns False — never raises — on any verification failure so the
    caller can iterate the fingerprint allow-list cleanly.
    """
    if not signature_bytes:
        return False
    if not fingerprint:
        return False

    if _looks_like_pgp_armored_signature(signature_bytes):
        return _verify_gpg_armored_signature(
            canonical_bytes=canonical_bytes,
            signature_bytes=signature_bytes,
            fingerprint=fingerprint,
        )

    # Raw ed25519 fallback path (also used by response-signature
    # verification, which always uses raw ed25519 against the
    # operator's pinned ``public_key_hex``).
    public_bytes = _decode_release_key_fingerprint(fingerprint)
    if public_bytes is None:
        return False
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )
    except ImportError:
        # The project already depends on ``cryptography``; this guard
        # keeps the helper testable in stripped-down dev environments.
        return False

    try:
        pub = Ed25519PublicKey.from_public_bytes(public_bytes)
        pub.verify(bytes(signature_bytes), bytes(canonical_bytes))
        return True
    except (InvalidSignature, ValueError):
        return False
    except Exception:  # noqa: BLE001
        return False


def load_signed_operator_registry(
    *,
    registry_path: str | None = None,
    signature_path: str | None = None,
    fingerprints: list[str] | None = None,
) -> list[OperatorEntry]:
    """Load + signature-verify ``operators.json``.

    Single-operator deployments often run with an empty / missing
    registry file (the legacy single-operator flow), so the function
    honors a
    documented escape hatch: when the registry is empty AND the
    signature path is empty, the loader returns ``[]`` without
    requiring a signature. As soon as the registry has at least one
    entry, the signature is mandatory.

    Failure modes:
    * ``operators.json`` non-empty but ``operators.sig`` missing →
      :class:`RegistrySignatureError`.
    * Signature does not verify against any pinned fingerprint →
      :class:`RegistrySignatureError`.
    * Registry parse error → existing :class:`RegistryLoadError`.

    The returned list is identical to :func:`load_operator_registry`
    when verification passes; the wrapper exists so the orchestrator
    has a single signed-load entry point.

    When ``ANONYMIZE_REGISTRY_REQUIRE_THRESHOLD_SIG`` is set, this
    wrapper transparently enforces the configured k-of-n threshold by
    delegating to :func:`load_threshold_signed_operator_registry`. This
    makes the threshold the *default* enforcement for every call site —
    previously only the (unused) ``load_operator_registry_dispatching``
    honored the flag, so threshold mode was silently a no-op. (security
    review follow-up H3)
    """
    from app.core.config import settings as _settings

    if _settings.anonymize_registry_require_threshold_sig:
        return load_threshold_signed_operator_registry(
            registry_path=registry_path,
            signature_path=signature_path,
            fingerprints=fingerprints,
        )

    if registry_path is None:
        registry_path = _settings.anonymize_boltz_operator_registry_path
    if signature_path is None:
        signature_path = _settings.anonymize_registry_sig_path
    if fingerprints is None:
        fingerprints = _settings.anonymize_registry_release_key_fingerprints_list

    from pathlib import Path

    reg_p = Path(registry_path)
    sig_p = Path(signature_path)
    # Accept both armored OpenPGP (``.sig.asc``) and raw
    # ed25519 (``.sig``) signature file extensions. The verifier
    # auto-detects the format. When both are present (e.g., a
    # rotation overlap), the armored signature takes precedence;
    # the raw ed25519 path remains as fallback.
    sig_asc_p = sig_p.with_suffix(sig_p.suffix + ".asc")
    if sig_asc_p.is_file():
        sig_p = sig_asc_p

    if not reg_p.is_file() or not reg_p.read_text(encoding="utf-8").strip():
        # Empty / missing registry — single-operator deployment
        # without a curated registry. No signature required.
        return []

    canonical = reg_p.read_text(encoding="utf-8").rstrip("\n ").encode("utf-8")

    if not sig_p.is_file():
        raise RegistrySignatureError(
            f"operators.json present but signature file is missing "
            f"(checked {sig_asc_p} and {sig_p}) — refusing to load the "
            "registry without a detached signature."
        )
    sig_bytes = sig_p.read_bytes()

    if not fingerprints:
        raise RegistrySignatureError(
            "operators.json + operators.sig are present but "
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
        raise RegistrySignatureError(
            "operators.sig does not verify against any pinned release "
            f"key fingerprint ({len(fingerprints)} fingerprint(s) tried)."
        )

    # Parse the exact bytes we verified — never re-read the file (TOCTOU).
    return load_operator_registry(reg_p, text=canonical.decode("utf-8"))


def count_distinct_verifying_fingerprints(
    *,
    canonical_bytes: bytes,
    signature_paths: list[str],
    fingerprints: list[str],
) -> int:
    """Count k-of-n threshold-sig verifications.

    For each signature file, find which (if any) pinned fingerprint
    verifies against it. Return the number of *distinct* fingerprints
    that have at least one verifying signature.

    A maintainer who provides two signatures under the same key only
    counts once; this is what makes k-of-n meaningful (k *distinct*
    maintainers must sign).

    Signature files that don't exist or don't verify under any pinned
    fingerprint are silently skipped — the caller decides whether the
    final count meets the threshold.
    """
    from pathlib import Path

    distinct: set[str] = set()
    for path_str in signature_paths:
        p = Path(path_str)
        if not p.is_file():
            continue
        try:
            sig_bytes = p.read_bytes()
        except OSError:
            continue
        for fp in fingerprints:
            if fp in distinct:
                continue
            if verify_detached_signature(
                canonical_bytes=canonical_bytes,
                signature_bytes=sig_bytes,
                fingerprint=fp,
            ):
                distinct.add(fp)
                break
    return len(distinct)


def load_threshold_signed_operator_registry(
    *,
    registry_path: str | None = None,
    signature_path: str | None = None,
    extra_signature_paths: list[str] | None = None,
    fingerprints: list[str] | None = None,
    threshold_k: int | None = None,
) -> list[OperatorEntry]:
    """k-of-n threshold-signed registry loader.

    Requires at least ``threshold_k`` *distinct* maintainer fingerprints
    to have a verifying signature. The main ``operators.sig`` is loaded
    alongside each additional path from ``extra_signature_paths``.

    Raises :class:`RegistrySignatureError` when fewer than ``k`` distinct
    fingerprints verify. The k-of-n contract is strict: a single
    maintainer who submits two signatures under the same key counts
    once.

    Opt-in via ``ANONYMIZE_REGISTRY_REQUIRE_THRESHOLD_SIG=true``
    and ``ANONYMIZE_REGISTRY_THRESHOLD_K``.
    """
    from pathlib import Path

    from app.core.config import settings as _settings

    if registry_path is None:
        registry_path = _settings.anonymize_boltz_operator_registry_path
    if signature_path is None:
        signature_path = _settings.anonymize_registry_sig_path
    if fingerprints is None:
        fingerprints = _settings.anonymize_registry_release_key_fingerprints_list
    if extra_signature_paths is None:
        extra_signature_paths = _settings.anonymize_registry_threshold_sig_paths_list
    if threshold_k is None:
        threshold_k = int(_settings.anonymize_registry_threshold_k)

    if threshold_k <= 0:
        raise RegistrySignatureError("threshold-signed registry mode requires ANONYMIZE_REGISTRY_THRESHOLD_K >= 1.")

    reg_p = Path(registry_path)
    if not reg_p.is_file() or not reg_p.read_text(encoding="utf-8").strip():
        return []

    canonical = reg_p.read_text(encoding="utf-8").rstrip("\n ").encode("utf-8")

    if not fingerprints:
        raise RegistrySignatureError(
            "operators.json is present but "
            "ANONYMIZE_REGISTRY_RELEASE_KEY_FINGERPRINTS is unset — "
            "the loader cannot decide which release keys to trust."
        )
    if len(fingerprints) < threshold_k:
        raise RegistrySignatureError(
            f"threshold k={threshold_k} exceeds the number of pinned "
            f"fingerprints ({len(fingerprints)}); the threshold is "
            "unsatisfiable as configured."
        )

    sig_paths: list[str] = []
    if signature_path:
        sig_paths.append(str(signature_path))
    sig_paths.extend(str(p) for p in (extra_signature_paths or []))

    distinct = count_distinct_verifying_fingerprints(
        canonical_bytes=canonical,
        signature_paths=sig_paths,
        fingerprints=fingerprints,
    )
    if distinct < threshold_k:
        raise RegistrySignatureError(
            f"threshold-signed registry requires k={threshold_k} distinct "
            f"verifying fingerprints, found {distinct} of "
            f"{len(fingerprints)} pinned."
        )

    # Parse the exact bytes we verified — never re-read the file (TOCTOU).
    return load_operator_registry(reg_p, text=canonical.decode("utf-8"))


def load_operator_registry_dispatching(
    *,
    registry_path: str | None = None,
    signature_path: str | None = None,
    fingerprints: list[str] | None = None,
) -> list[OperatorEntry]:
    """Phase-aware loader: dispatches to threshold mode when the flag is on.

    The orchestrator's startup invokes this helper so the at-least-one
    vs. k-of-n choice is centralized at the config layer.
    """
    from app.core.config import settings as _settings

    if _settings.anonymize_registry_require_threshold_sig:
        return load_threshold_signed_operator_registry(
            registry_path=registry_path,
            signature_path=signature_path,
            fingerprints=fingerprints,
        )
    return load_signed_operator_registry(
        registry_path=registry_path,
        signature_path=signature_path,
        fingerprints=fingerprints,
    )


def assert_url_pair_distinct(submarine_url: str, reverse_url: str) -> None:
    """URL-level pre-check before registry lookup.

    Used at startup when the operator has configured
    ``BOLTZ_SUBMARINE_API_URL`` and ``BOLTZ_REVERSE_API_URL`` directly
    (single-operator deployments without the curated registry). The
    canonical-hostname comparison catches the common mis-config where
    both URLs point at the same backend.
    """
    sub_host = canonicalize_operator_url(submarine_url)
    rev_host = canonicalize_operator_url(reverse_url)
    if not sub_host or not rev_host:
        # If either is empty, we can't say they're distinct *or* equal
        # at the URL layer. Single-operator deployments have
        # both URLs configured the same way, so an empty-URL pre-check
        # is fine; the real enforcement lives at registry-entry layer.
        return
    if sub_host == rev_host:
        raise ValueError(
            "BOLTZ_SUBMARINE_API_URL and BOLTZ_REVERSE_API_URL share "
            f"hostname {sub_host!r}; on-chain pipelines require distinct "
            "operators"
        )


# The
# ``lowest_attested_volume`` / ``operator_pair_caps_at_moderate``
# helpers modeled the joint-min volume cap, which explicitly
# rejects: only the reverse-leg operator's logs contain the
# destination, so per-operator-compromise attacks turn on the
# reverse operator's anonymity set only. The reverse-only cap
# lives directly in ``policy.score()`` against the new
# ``PipelineEnv.reverse_attested_volume_satoshis`` field. The
# helpers are removed rather than kept around because their model
# is no longer supported.


__all__ = [
    "LIQUID_CHAIN_SWAP_PAIR",
    "LiquidLegSelection",
    "OperatorEntry",
    "RegistryLoadError",
    "RegistrySignatureError",
    "load_operator_registry",
    "load_signed_operator_registry",
    "verify_detached_signature",
    "verify_operator_api_response",
    "sample_operator_pair",
    "make_create_swap_request",
    "canonicalize_operator_url",
    "assert_operators_distinct",
    "assert_url_pair_distinct",
    "resolve_operator_url_from_registry",
    "resolve_submarine_leg_url",
    "resolve_reverse_leg_url",
    "select_liquid_leg_urls",
    "assert_distinct_leg_urls_configured",
    "has_distinct_legs_configured",
]
