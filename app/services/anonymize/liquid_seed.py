# SPDX-License-Identifier: MIT
"""Anonymize Liquid blinding seed.

Liquid Confidential Transactions blind amounts to passive
observers, but the blinding itself uses pubkeys we derive. Reusing a
blinding pubkey across two Liquid txs links them; deriving Liquid
keys from the LND wallet seed (a tempting code-reuse) leaks if the
xpub escapes.

This module owns the *separate* Liquid seed:

* The seed is loaded from ``ANONYMIZE_LIQUID_SEED_FERNET`` at startup
  (Fernet-encrypted bytes; same key-set rules as ``FERNET_KEYS``).
* Per-session blinding pubkeys derive from this seed; no code path
  derives Liquid keys from the LND wallet seed.
* Per-session derivation index is recorded in the session row's
  ``liquid_blinding_seed_enc`` column (the per-session Fernet wrap
  ensures a DB-snapshot adversary cannot enumerate sessions by
  walking the derivation index).

This module ships the loader + startup gate; the actual blinding
derivation lands alongside the `hops/liquid.py` body.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
from dataclasses import dataclass
from typing import TYPE_CHECKING
from uuid import UUID

import wallycore as _wally

from app.core.config import settings

from .crypto import MultiFernetBundle
from .metadata import ANONYMIZE_LOGGER_NAME

if TYPE_CHECKING:  # pragma: no cover — type-only import to avoid cycles
    from .liquid_address import LiquidNetwork

logger = logging.getLogger(ANONYMIZE_LOGGER_NAME)


class LiquidSeedError(RuntimeError):
    """Raised when the Liquid seed is mis-configured or unrecoverable."""


@dataclass(frozen=True)
class LiquidBlindingPath:
    """One per-session Liquid blinding derivation path.

    ``coin_type=1776`` is the SLIP-44 Liquid Bitcoin coin type. The
    derivation index is per-session.
    """

    coin_type: int = 1776
    derivation_index: int = 0

    def to_path(self) -> str:
        return f"m/84'/{int(self.coin_type)}'/0'/0/{int(self.derivation_index)}"


def liquid_enabled() -> bool:
    """True iff the operator has opted into the Liquid hop."""
    return bool(getattr(settings, "anonymize_liquid_enabled", False))


def load_liquid_seed_bundle() -> MultiFernetBundle | None:
    """Resolve the Fernet bundle that decrypts the Liquid seed.

    Returns ``None`` when ``ANONYMIZE_LIQUID_SEED_FERNET`` is unset.
    The caller decides whether to refuse to start (the default
    when the Liquid hop is enabled).
    """
    raw = (settings.anonymize_liquid_seed_fernet or "").strip()
    if not raw:
        return None
    from .crypto import parse_fernet_bundle_config

    keys = parse_fernet_bundle_config(raw)
    if not keys:
        return None
    return MultiFernetBundle(keys=keys)


def assert_liquid_seed_configured() -> None:
    """startup gate.

    Refuses to start when the Liquid hop is enabled AND
    ``ANONYMIZE_LIQUID_SEED_FERNET`` is unset / unparseable. When the
    hop is disabled, the seed is optional — operators can flip the
    feature on later without rolling new config.
    """
    if not liquid_enabled():
        return
    bundle = load_liquid_seed_bundle()
    if bundle is None:
        raise LiquidSeedError(
            "Liquid hop is enabled but ANONYMIZE_LIQUID_SEED_FERNET "
            "is unset with a valid Fernet bundle. Either configure the "
            "seed or set ANONYMIZE_LIQUID_ENABLED=false."
        )


def make_blinding_path(*, derivation_index: int) -> LiquidBlindingPath:
    """Produce a Liquid blinding-derivation path."""
    if derivation_index < 0:
        raise LiquidSeedError("derivation_index must be non-negative")
    return LiquidBlindingPath(derivation_index=int(derivation_index))


# HKDF domain separator for the v1 SLIP-77 seed derivation. Binding the
# info string to a version means the v1 seed is independent of the
# Fernet encryption key bytes, so exposure of the at-rest key alone does
# not yield Liquid spend authority.
_LIQUID_SLIP77_HKDF_INFO_V1 = b"agent-wallet/liquid-slip77/v1"

# Derivation versions for the SLIP-77 master seed:
#   0 — the Fernet first-key bytes are used verbatim as the seed.
#   1 — the seed is HKDF-derived from those bytes with domain separation.
# Selected by ``ANONYMIZE_LIQUID_SEED_DERIVATION_VERSION``. The default is
# 0 so an existing deployment keeps deriving the same on-chain Liquid
# addresses; an operator moves to 1 only while no Liquid funds are in
# flight (a Liquid dwell output lives only inside an active session).
LIQUID_SEED_DERIVATION_VERSIONS = (0, 1)


def liquid_seed_derivation_version() -> int:
    """Configured SLIP-77 seed derivation version (0 or 1)."""
    return int(getattr(settings, "anonymize_liquid_seed_derivation_version", 0) or 0)


def _slip77_seed_for_version(seed_bytes: bytes, version: int) -> bytes:
    """Map the raw Fernet first-key bytes to the SLIP-77 seed for ``version``."""
    if version == 0:
        return seed_bytes
    if version == 1:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF

        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=_LIQUID_SLIP77_HKDF_INFO_V1,
        ).derive(seed_bytes)
    raise LiquidSeedError(f"unsupported ANONYMIZE_LIQUID_SEED_DERIVATION_VERSION: {version}")


def load_liquid_master_blinding_key(version: int | None = None) -> bytes | None:
    """Derive the SLIP-77 master blinding key from
    ``ANONYMIZE_LIQUID_SEED_FERNET``.

    Returns ``None`` when the setting is unset (the Liquid hop is
    opt-in; absence is not an error in itself).

    The Fernet bundle config is a comma-separated list of urlsafe-base64
    keys; the **first key's raw 32 bytes** seed the derivation. Under
    derivation version 0 those bytes are the SLIP-77 seed directly, which
    couples the seed to the at-rest encryption key. Version 1 instead
    runs them through a domain-separated HKDF, so the Liquid spend
    authority no longer follows from the encryption key alone. ``version``
    defaults to the configured
    ``ANONYMIZE_LIQUID_SEED_DERIVATION_VERSION``.
    """
    import base64

    from .liquid_ct import derive_slip77_master_blinding_key

    if version is None:
        version = liquid_seed_derivation_version()
    if version not in LIQUID_SEED_DERIVATION_VERSIONS:
        raise LiquidSeedError(f"unsupported ANONYMIZE_LIQUID_SEED_DERIVATION_VERSION: {version}")

    raw = (settings.anonymize_liquid_seed_fernet or "").strip()
    if not raw:
        return None
    # Take the first comma-separated key.
    first = raw.split(",", 1)[0].strip()
    if not first:
        return None
    try:
        seed_bytes = base64.urlsafe_b64decode(first.encode("ascii"))
    except Exception as exc:  # noqa: BLE001 — base64 raises a variety
        raise LiquidSeedError(f"first key of ANONYMIZE_LIQUID_SEED_FERNET is not valid urlsafe-base64: {exc}") from exc
    if len(seed_bytes) < 16:
        raise LiquidSeedError(
            f"first key of ANONYMIZE_LIQUID_SEED_FERNET decodes to {len(seed_bytes)} bytes; need ≥ 16 for SLIP-77"
        )
    return derive_slip77_master_blinding_key(_slip77_seed_for_version(seed_bytes, version))


# ── Liquid network + asset-id resolution ────────────────────────────


def resolve_liquid_network() -> "LiquidNetwork":
    """Pick the Liquid network matching the wallet's ``BITCOIN_NETWORK``.

    Bitcoin mainnet → Liquid mainnet (liquidv1), Bitcoin testnet →
    Liquid testnet (liquidv1t), Bitcoin regtest/signet → Liquid
    regtest. The mapping mirrors what operators expect: the wallet
    targets one network family on both chains.
    """
    from .liquid_address import LiquidNetwork

    n = (settings.bitcoin_network or "").strip().lower()
    if n in ("bitcoin", "mainnet"):
        return LiquidNetwork.MAINNET
    if n == "testnet":
        return LiquidNetwork.TESTNET
    # signet + regtest both fall under operator-config Liquid regtest.
    return LiquidNetwork.REGTEST


def resolve_liquid_btc_asset_id() -> bytes:
    """Return the L-BTC asset id for the wallet's current network.

    Precedence:

    1. If ``ANONYMIZE_LIQUID_BTC_ASSET_ID`` is set, parse + use it
       (64-char lowercase hex; raises on malformed input).
    2. Otherwise, use the built-in default for the resolved network
       (mainnet + testnet have well-known constants; regtest raises
       so the missing operator-config is visible immediately).

    Raises :class:`LiquidSeedError` on any unrecoverable mis-config.
    """
    from .liquid_address import LiquidNetwork
    from .liquid_ct import (
        ASSET_ID_LEN,
        LiquidCTError,
        lbtc_asset_id_for_network,
    )

    raw = (settings.anonymize_liquid_btc_asset_id or "").strip().lower()
    if raw:
        if len(raw) != ASSET_ID_LEN * 2:  # 32 bytes = 64 hex chars
            raise LiquidSeedError(f"ANONYMIZE_LIQUID_BTC_ASSET_ID must be {ASSET_ID_LEN * 2} hex chars; got {len(raw)}")
        try:
            return bytes.fromhex(raw)
        except ValueError as exc:
            raise LiquidSeedError(f"ANONYMIZE_LIQUID_BTC_ASSET_ID is not valid hex: {exc}") from exc

    network = resolve_liquid_network()
    network_str = {
        LiquidNetwork.MAINNET: "mainnet",
        LiquidNetwork.TESTNET: "testnet",
        LiquidNetwork.REGTEST: "regtest",
    }[network]
    try:
        return lbtc_asset_id_for_network(network_str)
    except LiquidCTError as exc:
        # Regtest with no operator-supplied asset id ends up here.
        raise LiquidSeedError(str(exc)) from exc


def assert_liquid_btc_asset_id_configured() -> None:
    """startup gate for the asset-id allow-list.

    No-op when the Liquid hop is disabled. When enabled, attempts the
    resolution: regtest deployments without
    ``ANONYMIZE_LIQUID_BTC_ASSET_ID`` set raise; mainnet/testnet
    deployments succeed using the built-in constants.
    """
    if not liquid_enabled():
        return
    asset_id = resolve_liquid_btc_asset_id()
    logger.info(
        "anonymize Liquid hop: resolved L-BTC asset id = %s",
        asset_id.hex(),
    )


# ── Per-session Liquid output derivation (Liquid hop body) ──────────


@dataclass(frozen=True)
class SessionLiquidOutput:
    """All the material needed to receive + spend a per-session L-BTC UTXO.

    Produced by :func:`derive_session_liquid_output` for the Liquid
    hop's intermediate residency. The wallet:

    * Hands the ``ct_address`` to the Boltz cooperative claim
      subprocess as ``destinationAddress`` so the claim TX outputs the
      L-BTC to a wallet-controlled CT output.
    * Uses ``script_pubkey`` to fetch the resulting UTXO via the
      Liquid backend (``get_address_utxos``).
    * Uses ``blinding_privkey`` to locally unblind that UTXO.
    * Uses ``spending_privkey`` to sign the eventual lock TX (the
      L-BTC→LN submarine leg).
    """

    derivation_index: int
    spending_privkey: bytes  # 32 bytes — single-sig p2wpkh keypath
    spending_pubkey: bytes  # 33 bytes compressed
    script_pubkey: bytes  # p2wpkh witness program (22 bytes)
    blinding_privkey: bytes  # 32 bytes — SLIP-77 for ``script_pubkey``
    blinding_pubkey: bytes  # 33 bytes compressed
    ct_address: str  # confidential bech32(m) address


def _derive_spending_privkey(
    *,
    master_blinding_key: bytes,
    session_id: UUID,
    derivation_index: int,
) -> bytes:
    """Derive a deterministic 32-byte spending privkey for the session.

    Tags the HMAC input with a domain separator so the spending key
    never collides with the SLIP-77 blinding key derivation (different
    libwally surface, but defense in depth).
    """
    if len(master_blinding_key) != 64:
        raise LiquidSeedError("master_blinding_key must be 64 bytes (SLIP-77 master)")
    sid_bytes = (
        session_id.bytes
        if hasattr(session_id, "bytes")
        else hashlib.blake2b(str(session_id).encode("utf-8"), digest_size=16).digest()
    )
    salt = b"anonymize-liquid-spend|" + sid_bytes + int(derivation_index).to_bytes(8, "big")
    priv = hmac.new(master_blinding_key, salt, hashlib.sha256).digest()
    # Reject the (statistically impossible) all-zero / >= curve_order
    # cases by re-trying with an extra round of HMAC. Real-world rate:
    # 2^-128. Defensive only.
    try:
        _wally.ec_private_key_verify(priv)
    except Exception:  # noqa: BLE001
        priv = hmac.new(master_blinding_key, salt + b"|retry", hashlib.sha256).digest()
        _wally.ec_private_key_verify(priv)
    return priv


def _p2wpkh_script(spending_pubkey: bytes) -> bytes:
    """Build the witness-v0 p2wpkh script from a 33-byte compressed pubkey."""
    if len(spending_pubkey) != 33:
        raise LiquidSeedError(f"spending_pubkey must be 33 bytes; got {len(spending_pubkey)}")
    pkh = bytes(_wally.hash160(bytes(spending_pubkey)))
    # OP_0 + 0x14 + 20-byte hash160
    return b"\x00\x14" + pkh


def derive_session_liquid_output(
    *,
    master_blinding_key: bytes,
    session_id: UUID,
    derivation_index: int,
    network: "LiquidNetwork",
) -> SessionLiquidOutput:
    """Build the per-session L-BTC receive+spend material.

    ``derivation_index`` is the per-session integer persisted (Fernet-
    wrapped at rest) in ``anonymize_session.liquid_blinding_seed_enc``.
    Given the master blinding key + index + session id, the function
    is deterministic: a crash between claim and spend doesn't lose the
    keypair.
    """
    from .liquid_address import encode_confidential_segwit
    from .liquid_ct import (
        derive_script_blinding_privkey,
        derive_script_blinding_pubkey,
    )

    spending_priv = _derive_spending_privkey(
        master_blinding_key=master_blinding_key,
        session_id=session_id,
        derivation_index=derivation_index,
    )
    spending_pub = bytes(_wally.ec_public_key_from_private_key(spending_priv))
    script = _p2wpkh_script(spending_pub)
    blinding_priv = derive_script_blinding_privkey(master_blinding_key, script)
    blinding_pub = derive_script_blinding_pubkey(master_blinding_key, script)
    ct_address = encode_confidential_segwit(
        script,
        blinding_pub,
        network=network,
    )
    return SessionLiquidOutput(
        derivation_index=int(derivation_index),
        spending_privkey=spending_priv,
        spending_pubkey=spending_pub,
        script_pubkey=script,
        blinding_privkey=blinding_priv,
        blinding_pubkey=blinding_pub,
        ct_address=ct_address,
    )


def generate_session_blinding_seed_index(
    *,
    rng: secrets.SystemRandom | None = None,
) -> int:
    """Pick a uniform-random 31-bit derivation index.

    Bounded below 2^31 so the index serializes into a positive signed
    32-bit field on every backend without sign-bit ambiguity.
    """
    rng = rng or secrets.SystemRandom()
    return rng.randrange(1, 1 << 31)


def encrypt_session_blinding_seed_index(index: int) -> bytes:
    """Fernet-wrap the per-session derivation index for at-rest storage.

    Stored in ``anonymize_session.liquid_blinding_seed_enc`` so a
    DB-snapshot adversary cannot enumerate Liquid hops by walking the
    index sequence.
    """
    from app.core.encryption import encrypt_field

    return encrypt_field(str(int(index))).encode("ascii")


def decrypt_session_blinding_seed_index(ciphertext: bytes) -> int:
    """Decrypt the persisted derivation index.

    Raises :class:`LiquidSeedError` on any decode / decryption error so
    the hop body can route the session to reconciliation instead of
    silently producing the wrong address.
    """
    from app.core.encryption import decrypt_field

    try:
        plain = decrypt_field(ciphertext.decode("ascii"))
        return int(plain.strip())
    except Exception as exc:  # noqa: BLE001
        raise LiquidSeedError(f"failed to decrypt liquid_blinding_seed_enc: {exc}") from exc


__all__ = [
    "LIQUID_SEED_DERIVATION_VERSIONS",
    "LiquidBlindingPath",
    "LiquidSeedError",
    "SessionLiquidOutput",
    "liquid_seed_derivation_version",
    "assert_liquid_btc_asset_id_configured",
    "assert_liquid_seed_configured",
    "decrypt_session_blinding_seed_index",
    "derive_session_liquid_output",
    "encrypt_session_blinding_seed_index",
    "generate_session_blinding_seed_index",
    "liquid_enabled",
    "load_liquid_master_blinding_key",
    "load_liquid_seed_bundle",
    "make_blinding_path",
    "resolve_liquid_btc_asset_id",
    "resolve_liquid_network",
]
