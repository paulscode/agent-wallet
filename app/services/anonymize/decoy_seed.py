# SPDX-License-Identifier: MIT
"""Anonymize-decoy seed (/ item 110).

Decoy outputs in the consolidation tx must NOT
derive from the LND wallet's primary xpub. An adversary who holds
the xpub (a backup tool, a paired hardware-wallet, a desktop
companion) can otherwise distinguish wallet-internal decoys from
external outputs trivially, defeating the shape-disguise
mitigation.

This module owns the *separate* decoy seed:

* The seed is loaded from ``ANONYMIZE_DECOY_SEED_FERNET`` at startup
  (Fernet-encrypted bytes; same key-set rules as ``FERNET_KEYS``).
* Per-decoy-output addresses derive from the seed using BIP-86
  taproot at path
  ``m/86'/<coin>'/0'/<session_account>/<derivation_index>``.
* ``session_account`` is HMAC-derived from the session id
  under ``ANONYMIZE_DECOY_SEED_ACCOUNT_KEY`` so a seed-holder cannot
  enumerate addresses by walking sequential session ids.
* The reserved sentinel ``session_account = 2**31 - 1`` is the
  startup canary — its absence indicates a fresh deployment.

The on-chain self-source path is *receive-only*; spending decoy
outputs requires importing the seed into a separately-instantiated
single-sig signer. The strongest tier adds the in-process spending
path with step-up re-auth.

The actual key-derivation + ``anonymize_decoy_output`` table writes
land alongside the ``coin_control.py`` consolidation flow.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING
from uuid import UUID

from app.core.config import settings

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

from .crypto import MultiFernetBundle
from .metadata import ANONYMIZE_LOGGER_NAME

logger = logging.getLogger(ANONYMIZE_LOGGER_NAME)


# Reserved sentinel session_account for the canary row.
DECOY_CANARY_SESSION_ACCOUNT: int = (2**31) - 1


class DecoySeedError(RuntimeError):
    """Raised when the decoy seed is mis-configured or unrecoverable."""


@dataclass(frozen=True)
class DecoyDerivationPath:
    """One per-output derivation path."""

    coin_type: int  # 0 mainnet, 1 testnet/regtest
    session_account: int
    derivation_index: int

    def to_bip86_path(self) -> str:
        """BIP-86 taproot derivation path string."""
        return f"m/86'/{int(self.coin_type)}'/0'/{int(self.session_account)}/{int(self.derivation_index)}"


def _coin_type_for_network() -> int:
    """BIP-44 coin type for the configured Bitcoin network."""
    network = (settings.bitcoin_network or "regtest").lower()
    if network == "bitcoin":
        return 0
    return 1  # testnet, signet, regtest


def derive_session_account(
    session_id: UUID,
    *,
    account_key: bytes,
) -> int:
    """Derive ``session_account`` from the session id.

    HMAC-SHA256 over the 16-byte session UUID under the
    ``ANONYMIZE_DECOY_SEED_ACCOUNT_KEY`` bytes; the result is reduced
    mod ``2**31`` so it fits in a signed 32-bit BIP-32 path component
    *and* leaves the canary sentinel ``2**31 - 1`` reserved.

    A seed-holder who does not also hold the account key cannot
    enumerate per-session addresses sequentially; without the
    HMAC the derivation index alone would walk addresses
    by session order.
    """
    if not isinstance(account_key, bytes) or len(account_key) < 16:
        raise DecoySeedError("ANONYMIZE_DECOY_SEED_ACCOUNT_KEY must be at least 16 bytes")
    digest = hmac.new(account_key, session_id.bytes, hashlib.sha256).digest()
    # Fold the full 256-bit digest (not just the first 32 bits) before
    # reducing into the BIP-32 account range, so two sessions are far less
    # likely to collide onto the same decoy account at the birthday bound.
    n = int.from_bytes(digest, "big")
    out = n % (2**31)
    # Avoid colliding with the canary sentinel.
    if out == DECOY_CANARY_SESSION_ACCOUNT:
        out = (out + 1) % (2**31)
    return out


def make_derivation_path(
    *,
    session_id: UUID,
    derivation_index: int,
    account_key: bytes,
) -> DecoyDerivationPath:
    """Produce one per-output derivation path."""
    if derivation_index < 0:
        raise DecoySeedError("derivation_index must be non-negative")
    return DecoyDerivationPath(
        coin_type=_coin_type_for_network(),
        session_account=derive_session_account(session_id, account_key=account_key),
        derivation_index=int(derivation_index),
    )


def make_canary_path() -> DecoyDerivationPath:
    """Reserved canary row at ``session_account = 2**31 - 1``.

    The on-chain (decoy) startup pass derives this address and
    confirms the seed is decryptable end-to-end; absence of the canary
    indicates a fresh deployment.
    """
    return DecoyDerivationPath(
        coin_type=_coin_type_for_network(),
        session_account=DECOY_CANARY_SESSION_ACCOUNT,
        derivation_index=0,
    )


def is_decoy_seed_required() -> bool:
    """The default requires the seed; opt-out is a regression.

    When ``ANONYMIZE_DECOY_SEED_REQUIRED=true`` (default), startup
    refuses to admit anonymize sessions without a valid decoy seed.
    Opt-out is documented as residual #30 — decoy outputs derive from
    the LND primary xpub, defeating against any xpub-holding
    adversary.
    """
    return bool(settings.anonymize_decoy_seed_required)


def load_decoy_seed_bundle() -> MultiFernetBundle | None:
    """Resolve the Fernet bundle that decrypts the decoy seed.

    Returns ``None`` when ``ANONYMIZE_DECOY_SEED_FERNET`` is unset.
    The caller decides whether to refuse to start (default)
    or proceed with the documented regression
    (``ANONYMIZE_DECOY_SEED_REQUIRED=false``).
    """
    raw = (settings.anonymize_decoy_seed_fernet or "").strip()
    if not raw:
        return None
    from .crypto import parse_fernet_bundle_config

    keys = parse_fernet_bundle_config(raw)
    if not keys:
        return None
    return MultiFernetBundle(keys=keys)


class DecoyCanaryCollisionError(DecoySeedError):
    """Orphan canary detected.

    Raised when the freshly-derived canary address (under the
    currently-loaded seed) does NOT match the address stored at the
    canary row in ``anonymize_decoy_output``. This indicates the
    loaded seed differs from the one that wrote the existing rows —
    typically a backup restore that brought back decoy outputs the
    current seed cannot spend.
    """


def detect_canary_collision(
    *,
    observed_canary_address: str | None,
    freshly_derived_canary_address: str,
) -> bool:
    """Predicate for the startup orphan-detection scan.

    Returns ``True`` when there is a *collision* (= the observed
    address exists but differs from the freshly-derived one).

    Two non-collision cases pass:
    * Fresh deployment — no canary row exists yet
      (``observed_canary_address is None``).
    * Identical seed — observed address matches the fresh derivation.

    The orchestrator's startup pass invokes the actual scan over
    ``anonymize_decoy_output WHERE session_account = DECOY_CANARY_SESSION_ACCOUNT``;
    this helper is the pure decision the caller wraps.
    """
    if observed_canary_address is None:
        return False
    return observed_canary_address.strip() != freshly_derived_canary_address.strip()


def assert_no_canary_collision(
    *,
    observed_canary_address: str | None,
    freshly_derived_canary_address: str,
) -> None:
    """Startup gate.

    Refuses to start when the canary address under the loaded seed
    differs from the address stored at the canary row in
    ``anonymize_decoy_output``. The runbook pointer the error
    surfaces is ``tools/anonymize_decoy_seed_reset.py``.
    """
    if not detect_canary_collision(
        observed_canary_address=observed_canary_address,
        freshly_derived_canary_address=freshly_derived_canary_address,
    ):
        return
    raise DecoyCanaryCollisionError(
        "anonymize_decoy_output canary row address does not match the "
        "freshly-derived address under the currently-loaded "
        "ANONYMIZE_DECOY_SEED_FERNET. This usually means a backup "
        "restore brought back decoy outputs the current seed cannot "
        "spend. See tools/anonymize_decoy_seed_reset.py for the "
        "documented recovery path."
    )


async def record_decoy_output(
    db: AsyncSession,
    *,
    session_id: UUID,
    derivation_index: int,
    address: str,
    value_sat: int,
    outpoint: str | None = None,
) -> None:
    """Write an:class:`AnonymizeDecoyOutput` row.

    Called by the consolidation flow each time it appends a decoy
    output (BIP-86 taproot address derived from the
    ``ANONYMIZE_DECOY_SEED_FERNET`` material). The ``session_account``
    is HMAC-derived from ``session_id`` so a seed-holder
    cannot enumerate decoy addresses by walking sequential session
    IDs.

    ``outpoint`` (``txid:vout``) is supplied when the consolidation
    tx broadcast lands; left ``None`` for the pre-broadcast row
    that records the intent.

    The decoy is *receive-only*: the wallet records the decoy but
    never includes it in coin selection (the do-not-spend
    contract applies via the orchestrator's label assignment).

    The caller is responsible for committing.
    """
    from app.models.anonymize_session import AnonymizeDecoyOutput

    if value_sat <= 0:
        raise ValueError("decoy value_sat must be positive")
    if not address:
        raise ValueError("decoy address must be a non-empty string")

    account_key_str = (settings.anonymize_decoy_seed_account_key or "").strip()
    if not account_key_str:
        raise DecoySeedError(
            "ANONYMIZE_DECOY_SEED_ACCOUNT_KEY is unset; cannot derive session_account for decoy output"
        )
    account_key = account_key_str.encode("utf-8")
    session_account = derive_session_account(
        session_id,
        account_key=account_key,
    )

    db.add(
        AnonymizeDecoyOutput(
            session_id=session_id,
            session_account=session_account,
            derivation_index=int(derivation_index),
            address=address,
            value_sat=int(value_sat),
            outpoint=outpoint,
            seed_orphaned=False,
        )
    )


def assert_decoy_seed_configured() -> None:
    """On-chain (decoy) startup gate.

    Refuses to start when:
    * ``ANONYMIZE_DECOY_SEED_REQUIRED=true`` AND
    * ``ANONYMIZE_DECOY_SEED_FERNET`` is unset / unparseable.

    Logs at CRITICAL when the regression is opted into; the operator
    runbook documents that decoy outputs in the regression mode
    derive from the LND wallet's primary xpub.
    """
    if not is_decoy_seed_required():
        bundle = load_decoy_seed_bundle()
        if bundle is None:
            logger.critical(
                "anonymize decoy seed is unset and ANONYMIZE_DECOY_SEED_REQUIRED=false; "
                "decoy outputs will derive from the LND primary xpub (residual #30). "
                "This is a documented privacy regression."
            )
        return

    bundle = load_decoy_seed_bundle()
    if bundle is None:
        raise DecoySeedError(
            "on-chain anonymize requires ANONYMIZE_DECOY_SEED_FERNET to be set "
            "with a valid Fernet bundle. Either configure the seed or set "
            "ANONYMIZE_DECOY_SEED_REQUIRED=false to opt into the documented "
            "privacy regression."
        )


__all__ = [
    "DECOY_CANARY_SESSION_ACCOUNT",
    "DecoyDerivationPath",
    "DecoySeedError",
    "DecoyCanaryCollisionError",
    "derive_session_account",
    "make_derivation_path",
    "make_canary_path",
    "is_decoy_seed_required",
    "load_decoy_seed_bundle",
    "assert_decoy_seed_configured",
    "detect_canary_collision",
    "assert_no_canary_collision",
    "record_decoy_output",
]
