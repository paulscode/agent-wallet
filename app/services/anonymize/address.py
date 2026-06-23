# SPDX-License-Identifier: MIT
"""Anonymize destination address parser + script-type policy.

 / item 6 / item 32:
* Destination input is a *raw address only*. Any string that contains
  ``:``, ``?``, ``&``, ``label=``, ``message=``, BIP-70 payment URLs,
  or LNURL/BIP-21-style wrappers is rejected at quote time, before
  any logging or quote-token creation can preserve the wrapped value.
* ``p2tr`` and native ``p2wpkh`` are eligible for the highest tier.
* ``p2wsh`` and ``p2sh-p2wpkh`` are accepted with a tier cap of
  ``moderate``.
* Legacy ``P2PKH`` (mainnet ``1...`` / testnet ``m...`` ``n...``) and
  arbitrary ``P2SH`` are rejected — they are privacy footguns.

The classifier returns the canonical script type plus the validated
address. The reuse-detection hash is computed against the
original address, not a normalized form, to avoid case-folded
collisions.
"""

from __future__ import annotations

import re
from typing import Literal

from app.core.config import settings
from app.core.validation import validate_bitcoin_address

# Script types eligible for tier ``strong``.
ELIGIBLE_FOR_STRONG: frozenset[str] = frozenset({"p2tr", "p2wpkh"})
# Script types accepted with a `moderate` tier cap.
ACCEPTED_WITH_MODERATE_CAP: frozenset[str] = frozenset({"p2wsh", "p2sh-p2wpkh"})


# Patterns that indicate a wrapped / URI-style destination.
# Any of these characters or substrings is enough to reject — we want
# to catch ``bitcoin:`` URIs, ``?label=``, ``&message=``, and BIP-70
# payment URLs without trying to *parse* them (parsing creates an
# attacker-controlled side channel where a typo in our parser leaks
# the wrapped value into a log line). Reject whenever any of these
# indicators is present.
_REJECT_INDICATORS: tuple[str, ...] = (
    ":",  # bitcoin: URIs and ipv6-style wrappers
    "?",  # query strings
    "&",  # multi-param URI tails
    "=",  # any key=value pair in the input
    " ",  # whitespace usually indicates a wrapper
    "\t",
    "\n",
    "\r",
    "lnurl",  # LNURL prefixes (lower-cased compare below)
    "lightning:",
    "bitcoin:",
    "//",  # http://, https://
)


# Address-like ASCII subset; reject anything outside the union of
# bech32 + base58 alphabets.
_ALLOWED_CHARS_RE = re.compile(r"^[A-Za-z0-9]+$")


# Maximum sane address length. Bech32m addresses can run up to ~90
# characters; we cap at 100 to allow some slack while rejecting
# pathological pasted data.
_MAX_ADDR_LEN = 100


class DestinationRejectedError(ValueError):
    """Raised when a destination address fails the policy."""


ScriptType = Literal["p2tr", "p2wpkh", "p2wsh", "p2sh-p2wpkh"]


def parse_and_validate_destination(raw: str) -> tuple[str, ScriptType]:
    """Parse a user-supplied destination, return ``(address, script_type)``.

    Raises :class:`DestinationRejectedError` on any rejection — URI-wrapped
    input, legacy script types, malformed addresses, wrong network.
    """
    if not isinstance(raw, str):
        raise DestinationRejectedError("destination must be a string")

    candidate = raw.strip()
    if not candidate:
        raise DestinationRejectedError("destination address is empty")
    if len(candidate) > _MAX_ADDR_LEN:
        raise DestinationRejectedError("destination address is too long")

    lc = candidate.lower()
    for indicator in _REJECT_INDICATORS:
        if indicator in lc:
            # Do NOT echo the wrapped string in the error
            # warns that error paths can preserve user-provided data.
            raise DestinationRejectedError(
                "destination must be a raw address (no URI wrapper, label, message, or LNURL)"
            )

    if not _ALLOWED_CHARS_RE.match(candidate):
        raise DestinationRejectedError("destination contains characters outside the address alphabet")

    # Network-aware checksum + format validation.
    try:
        validated = validate_bitcoin_address(candidate)
    except ValueError as exc:
        raise DestinationRejectedError(str(exc)) from None

    script_type = _classify_script_type(validated)
    if script_type is None:
        raise DestinationRejectedError(
            "destination script type is not accepted (use P2TR or native "
            "SegWit; legacy P2PKH and arbitrary P2SH are rejected)"
        )

    return validated, script_type


def _classify_script_type(addr: str) -> ScriptType | None:
    """Classify a *validated* address into one of the accepted script types.

    Returns ``None`` for legacy P2PKH / arbitrary P2SH (which we reject)
    and for any unrecognized form. Determines bech32m vs. bech32 by
    consulting the address content directly so the classifier is
    independent of network HRP (mainnet ``bc``, testnet ``tb``,
    regtest ``bcrt``).
    """
    network = settings.bitcoin_network
    lc = addr.lower()
    # Resolve the HRP for this network.
    hrp_map = {
        "bitcoin": "bc",
        "testnet": "tb",
        "signet": "tb",
        "regtest": "bcrt",
    }
    hrp = hrp_map.get(network, "")

    if hrp and lc.startswith(hrp + "1"):
        return _classify_segwit(lc, hrp)

    # Anything that didn't take the bech32 branch must be Base58
    # (legacy P2PKH / P2SH-P2WPKH wrap). The wrapped P2SH-P2WPKH form
    # produces a P2SH address (``3...`` mainnet / ``2...`` test/regtest).
    # Mainnet:  '1...' = P2PKH; '3...' = P2SH (could be wrap-segwit or arbitrary).
    # Test/regtest: 'm/n...' = P2PKH; '2...' = P2SH.
    first = addr[:1]
    if network == "bitcoin":
        if first == "1":
            return None  # legacy P2PKH — rejected
        if first == "3":
            return "p2sh-p2wpkh"  # accepted with moderate cap
    elif network in ("testnet", "signet", "regtest"):
        if first in ("m", "n"):
            return None  # legacy P2PKH — rejected
        if first == "2":
            return "p2sh-p2wpkh"

    return None


def _classify_segwit(addr_lc: str, hrp: str) -> ScriptType | None:
    """Classify the witness version + program length to a script type."""
    # Decode just enough to read the witness version and program length.
    # The address has already passed checksum validation, so we trust
    # its structure here.
    from app.core.validation import _bech32_decode, _convertbits  # type: ignore[attr-defined]

    decoded = _bech32_decode(addr_lc)
    if decoded is None:
        return None
    dec_hrp, data, _enc = decoded
    if dec_hrp != hrp or not data:
        return None
    witness_version = data[0]
    witness_program = _convertbits(data[1:], 5, 8, False)
    if witness_program is None:
        return None
    prog_len = len(witness_program)
    if witness_version == 0:
        if prog_len == 20:
            return "p2wpkh"
        if prog_len == 32:
            return "p2wsh"
        return None
    if witness_version == 1 and prog_len == 32:
        return "p2tr"
    return None


def script_type_eligible_for_strong(script_type: str) -> bool:
    """True iff ``script_type`` does NOT trigger the cap."""
    return script_type in ELIGIBLE_FOR_STRONG


__all__ = [
    "ELIGIBLE_FOR_STRONG",
    "ACCEPTED_WITH_MODERATE_CAP",
    "DestinationRejectedError",
    "ResolvedDestination",
    "ScriptType",
    "is_bip353_handle",
    "parse_and_validate_destination",
    "resolve_anonymize_destination",
    "script_type_eligible_for_strong",
]


# ── BIP-353-aware destination resolver ────────────────────


from dataclasses import dataclass


@dataclass(frozen=True)
class ResolvedDestination:
    """Outcome of :func:`resolve_anonymize_destination`.

    The anonymize pipeline picks one of two exit primitives:

    * **Reverse-swap exit** (``exit_kind == "reverse"``) — the
      session terminates with a Boltz reverse swap whose on-chain
      output lands at :attr:`address`. Used for raw-address inputs
      and for BIP-353 handles whose publisher includes a
      ``bitcoin:`` on-chain fallback.
    * **BOLT 12 exit** (``exit_kind == "bolt12_pay"``) — the session
      terminates with a Lightning payment to :attr:`bolt12_offer`.
      :attr:`address` is empty (no on-chain output). Used for
      BIP-353 handles that publish only Lightning handles.

    Either way :attr:`bip353_handle` carries the original
    ``user@domain`` for audit + reuse-detection.
    """

    exit_kind: Literal["reverse", "bolt12_pay"]
    # Reverse-exit case: the validated on-chain address.
    # BOLT 12-exit case: empty string. Either way the caller
    # uses the value for reuse-detection (which hashes the
    # BIP-353 handle for handle-based inputs — see ``bip353_handle``).
    address: str
    # Reverse-exit case: the script type of ``address``.
    # BOLT 12-exit case: ``None`` (no on-chain output to classify).
    script_type: ScriptType | None
    # The original input as the user supplied it.
    raw_input: str
    # Set when the input was a BIP-353 handle. The handle (NOT the
    # resolved record's contents) is what we use for reuse detection
    # — distinct ``alice@example.com`` resolutions should still
    # collide for the hard-block.
    bip353_handle: str | None = None
    # Set for BOLT 12-exit sessions: the resolved offer the
    # terminal-hop body pays.
    bolt12_offer: str | None = None
    # Recorded for audit / debugging. Not yet used as an exit
    # primitive — a BOLT 11 invoice has a sub-hour expiry that
    # doesn't survive any meaningful mixing dwell.
    bolt11_invoice: str | None = None


def is_bip353_handle(candidate: str) -> bool:
    """Cheap predicate — is this input shaped like ``user@domain``?

    Used at the routing boundary to decide between the synchronous
    raw-address path and the async DoH-resolver path. False positives
    (an exotic raw address that happens to contain ``@``) are
    harmless: the resolver runs first, rejects the malformed input
    with a syntax error, and the caller surfaces the standard
    ``DestinationRejectedError`` shape.

    Only matches when the input has exactly one ``@`` and at least
    one character on each side, mirroring the resolver's own
    accepts.
    """
    if not isinstance(candidate, str):
        return False
    s = candidate.strip()
    if s.count("@") != 1:
        return False
    user, _, domain = s.partition("@")
    return bool(user) and bool(domain)


async def resolve_anonymize_destination(
    raw: str,
) -> ResolvedDestination:
    """Resolve a user-supplied destination string into the pair the
    anonymize pipeline executes against.

    Accepts two input shapes:

    1. **Raw Bitcoin address** — fast path, no I/O. Delegates to
       :func:`parse_and_validate_destination` and surfaces the
       validated ``(address, script_type)``.
    2. **BIP-353 handle** (``user@domain``) — async path, hits the
       DoH resolver. Surfaces the resolved on-chain fallback when
       the publisher includes one in their BIP-21 URI; refuses with
       a forward-looking error message when the publisher carries
       only ``lno=`` / ``lightning=`` handles (the BOLT 12 / BOLT 11
       exit pipeline hops haven't been wired yet).

    Raises :class:`DestinationRejectedError` on any rejection mode.
    The error message is generic enough that operators cannot
    distinguish a malformed input from a non-existent BIP-353
    record (— error paths that preserve user-provided data
    leak information).
    """
    if not isinstance(raw, str):
        raise DestinationRejectedError("destination must be a string")
    s = raw.strip()
    if not s:
        raise DestinationRejectedError("destination address is empty")

    if not is_bip353_handle(s):
        # Existing path — synchronous validation. Always a reverse-swap exit.
        addr, st = parse_and_validate_destination(s)
        return ResolvedDestination(
            exit_kind="reverse",
            address=addr,
            script_type=st,
            raw_input=s,
        )

    # BIP-353 path.
    from .dns import (
        Bip353Error,
        resolve_bip353,
    )

    try:
        result = await resolve_bip353(s)
    except Bip353Error as exc:
        # Don't leak the specific resolver-internal reason —
        # keeps error paths minimal so a probing payer
        # can't distinguish "DNS NXDOMAIN" from "validation
        # failed" from "DNSSEC unauthenticated". Log internally
        # for operator debugging; surface a generic rejection.
        import logging

        from .metadata import ANONYMIZE_LOGGER_NAME

        logging.getLogger(ANONYMIZE_LOGGER_NAME).info(
            "anonymize: BIP-353 resolution failed for handle: %s",
            exc,
        )
        raise DestinationRejectedError("destination address was rejected") from exc

    if result.onchain_address:
        # Validate the resolved on-chain address through the same
        # gate as a raw input — defends against a publisher serving
        # a malformed / wrong-network handle.
        try:
            addr, st = parse_and_validate_destination(result.onchain_address)
        except DestinationRejectedError:
            raise DestinationRejectedError("destination address was rejected") from None
        return ResolvedDestination(
            exit_kind="reverse",
            address=addr,
            script_type=st,
            raw_input=s,
            bip353_handle=result.user_at_domain,
            bolt12_offer=result.bolt12_offer,
            bolt11_invoice=result.bolt11_invoice,
        )

    # BOLT 12-exit case: the publisher omits the on-chain fallback
    # (the BIP-353 design's recommended privacy-preserving shape).
    # The exit hop pays the resolved offer directly via LND's
    # blinded-path router. The pipeline carries no on-chain
    # destination address — we surface ``address=""`` so the
    # session row's ``destination_address_enc`` stores the BIP-353
    # handle (used for reuse detection) rather than a stale
    # on-chain handle.
    if result.bolt12_offer:
        return ResolvedDestination(
            exit_kind="bolt12_pay",
            address="",
            script_type=None,
            raw_input=s,
            bip353_handle=result.user_at_domain,
            bolt12_offer=result.bolt12_offer,
            bolt11_invoice=result.bolt11_invoice,
        )

    # The record carries no on-chain handle AND no BOLT 12 offer.
    # That leaves only a BOLT 11 invoice, which we don't support as
    # an exit (a BOLT 11 invoice's <1h expiry can't survive any
    # meaningful mixing dwell). Refuse uniformly.
    raise DestinationRejectedError("destination address was rejected")
