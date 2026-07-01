# SPDX-License-Identifier: MIT
"""
Boltz Swap Service — Reverse Submarine Swap orchestration.

Manages the lifecycle of Boltz reverse swaps (Lightning → On-chain) for
cold storage withdrawals. All Boltz API traffic is routed via Tor by default.

Key improvements over earlier implementations:
- All crypto material encrypted at rest (Fernet)
- Comprehensive exception handling for Node.js subprocess calls
- Tiered retry with max_retries=200 (~16hrs cap)
- Tor fallback catches ProxyError/ReadTimeout/ConnectError
- Status history tracks every state transition
- Recovery on startup for interrupted swaps
"""

import hashlib
import hmac
import json
import asyncio
import logging
import os
import secrets
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from urllib.parse import quote
from uuid import UUID

import httpx
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.encryption import decrypt_field, encrypt_field
from app.core.http_limits import request_capped
from app.core.net_guard import BlockedHostError, is_onion_host, pin_request_args
from app.core.resilience import (
    BreakerOpenError,
    CircuitBreaker,
    with_retry,
)
from app.core.utils import force_remote_dns_socks
from app.models.boltz_swap import BoltzSwap, SwapStatus
from app.services.boltz_lockup_verify import (
    verify_reverse_lockup_address,
    verify_submarine_lockup_address,
)
from app.services.health import register_health

logger = logging.getLogger(__name__)

BOLTZ_MIN_AMOUNT_SATS = 25_000
BOLTZ_MAX_AMOUNT_SATS = 25_000_000

# Retry + circuit breaker. Boltz is not on the synchronous critical
# path for everyday wallet operations (only cold-storage withdrawals
# go through it), so the breaker is a little more permissive: we
# tolerate a couple more failures before opening because the Tor
# path is genuinely flaky.
_BOLTZ_BREAKER = CircuitBreaker(
    name="boltz",
    failure_threshold=8,
    open_duration_s=60.0,
)
_BOLTZ_HEALTH = register_health("boltz", breaker=_BOLTZ_BREAKER)

_BOLTZ_RETRYABLE_EXC: tuple[type[BaseException], ...] = (
    httpx.ConnectError,
    httpx.ConnectTimeout,
    httpx.ReadTimeout,
    httpx.ProxyError,
    httpx.RemoteProtocolError,
    httpx.PoolTimeout,
)


class _BoltzRetryable5xxError(Exception):
    """Internal sentinel — a 5xx response we want the retry loop to see."""

    def __init__(self, status_code: int, body: str) -> None:
        super().__init__(f"Boltz {status_code}: {body}")
        self.status_code = status_code
        self.body = body


CLAIM_SCRIPT_DIR = Path(__file__).parent.parent.parent / "scripts"
CLAIM_SCRIPT_PATH = CLAIM_SCRIPT_DIR / "boltz_claim.js"
REFUND_SCRIPT_PATH = CLAIM_SCRIPT_DIR / "submarine_refund.js"

# Absolute path to the Node.js binary, resolved once at import. Invoking it
# by absolute path (rather than letting the child resolve ``node`` against an
# inherited ``PATH``) removes the PATH-hijack vector where a ``node`` shim in
# an earlier, writable ``PATH`` entry would be executed instead. Falls back to
# the bare name only if resolution fails (mis-provisioned host), which then
# surfaces as a clear subprocess error rather than running an unexpected binary.
_NODE_BIN = shutil.which("node") or "node"
_NODE_BIN_DIR = str(Path(_NODE_BIN).parent) if os.path.sep in _NODE_BIN else "/usr/local/bin"

# Minimal environment for Node.js subprocesses — avoids leaking
# SECRET_KEY, DATABASE_URL, and other sensitive env vars. ``PATH`` is pinned
# to the resolved node directory plus the standard system bins rather than the
# operator's full inherited ``PATH``, so a binary planted earlier in that
# ``PATH`` cannot be picked up by the child or anything it spawns.
_SUBPROCESS_ENV = {
    "PATH": f"{_NODE_BIN_DIR}:/usr/local/bin:/usr/bin:/bin",
    "HOME": os.environ.get("HOME", "/tmp"),
    "NODE_PATH": str(CLAIM_SCRIPT_DIR / "node_modules"),
}


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _extract_claim_pubkey_from_swap_tree(
    swap_tree_json: Optional[dict],
) -> Optional[str]:
    """Extract Boltz's claim x-only pubkey from a persisted submarine
    swap tree.

    Boltz's submarine taproot claim leaf has the fixed shape:
        OP_HASH160 <20 bytes preimage-hash> OP_EQUALVERIFY
        <32 bytes x-only claim pubkey> OP_CHECKSIG
    which serializes as 57 bytes: ``a914<20>88 20<32> ac``. The
    x-only pubkey sits at offset 24 (1 opcode + 1 push-len + 20
    hash + 1 opcode + 1 push-len). Returns the 32-byte x-only pubkey
    as a 64-char hex string. The y-parity isn't recoverable from the
    script, so the refund script tries both ``02``-prefix and
    ``03``-prefix candidates when consuming this value. Returns
    ``None`` if the script doesn't match the expected template.
    """
    if not isinstance(swap_tree_json, dict):
        return None
    claim_leaf = swap_tree_json.get("claimLeaf")
    if not isinstance(claim_leaf, dict):
        return None
    output_hex = claim_leaf.get("output")
    if not isinstance(output_hex, str):
        return None
    try:
        script = bytes.fromhex(output_hex)
    except ValueError:
        return None
    # OP_HASH160(0xa9) <20-byte push 0x14> OP_EQUALVERIFY(0x88)
    # <32-byte push 0x20> <pubkey 32> OP_CHECKSIG(0xac) = 57 bytes
    if (
        len(script) != 57
        or script[0] != 0xA9
        or script[1] != 0x14
        or script[22] != 0x88
        or script[23] != 0x20
        or script[56] != 0xAC
    ):
        return None
    return script[24:56].hex()


def _tx_pays_address(verified_tx: dict, expected_address: str) -> bool:
    """Return True iff any vout in ``verified_tx`` pays ``expected_address``.

    ``verified_tx`` is the verbose Electrum/mempool transaction dict
    (shape produced by :class:`ElectrumChainBackend.get_transaction`).
    Used as a defence-in-depth sanity check that the lockup TX Boltz
    points us at actually pays the address Boltz committed to during
    swap creation.
    """
    expected = (expected_address or "").strip()
    if not expected:
        return False
    for v in verified_tx.get("vout") or []:
        if not isinstance(v, dict):
            continue
        # The Electrum / mempool backends key the decoded output address
        # as ``scriptpubkey_address``; accept a bare ``address`` too for
        # any other shape.
        addr = v.get("scriptpubkey_address") or v.get("address")
        if isinstance(addr, str) and addr == expected:
            return True
    return False


def _generate_preimage() -> tuple[str, str]:
    """Generate a 32-byte random preimage and its SHA-256 hash."""
    preimage = secrets.token_bytes(32)
    preimage_hash = hashlib.sha256(preimage).digest()
    return preimage.hex(), preimage_hash.hex()


def _generate_keypair() -> tuple[str, str]:
    """Generate an ephemeral secp256k1 keypair for claim signing.

    Uses Node.js boltz-core for correct EC math.
    Private key is passed via stdin (never appears in process listing).
    """
    private_key = secrets.token_bytes(32)

    try:
        result = subprocess.run(
            [
                _NODE_BIN,
                "-e",
                """
                const { ECPairFactory } = require('ecpair');
                const ecc = require('tiny-secp256k1');
                const ECPair = ECPairFactory(ecc);
                let data = '';
                process.stdin.on('data', c => data += c);
                process.stdin.on('end', () => {
                    const kp = ECPair.fromPrivateKey(Buffer.from(data.trim(), 'hex'));
                    console.log(JSON.stringify({
                        privateKey: kp.privateKey.toString('hex'),
                        publicKey: kp.publicKey.toString('hex')
                    }));
                });
                """,
            ],
            input=private_key.hex(),
            capture_output=True,
            text=True,
            timeout=10,
            cwd=str(CLAIM_SCRIPT_DIR),
            env=_SUBPROCESS_ENV,
        )
        if result.returncode == 0:
            data = json.loads(result.stdout.strip())
            return data["privateKey"], data["publicKey"]
        else:
            logger.error("Keypair generation failed (non-zero exit)")
            raise RuntimeError("EC keypair generation failed (non-zero exit)")
    except subprocess.TimeoutExpired:
        raise RuntimeError("EC keypair generation timed out (10s). Node.js may be hanging or overloaded.")
    except (json.JSONDecodeError, KeyError) as e:
        raise RuntimeError(f"EC keypair generation returned invalid data: {e}")
    except FileNotFoundError:
        raise RuntimeError(
            "Node.js not found. Required for Boltz claim signing. Install Node.js or ensure it is in the Docker image."
        )


class BoltzSwapService:
    """Manages Boltz Reverse Submarine Swaps for cold storage withdrawals."""

    def __init__(self) -> None:
        self._client: Optional[httpx.AsyncClient] = None
        # Two-slot pair-info cache. ``_fresh`` is the
        # cache-hit slot subject to TTL; ``_stale`` is updated on
        # every successful refill and never expires, so when
        # Boltz is briefly unreachable we can keep serving the
        # last-known limits/fees with a ``stale=true`` flag rather
        # than failing every cold-storage withdrawal.
        self._pair_info_cache: Optional[dict] = None
        self._pair_info_cached_at: Optional[datetime] = None
        self._pair_info_stale: Optional[dict] = None
        # Submarine-side pair-info cache (on-chain → LN).
        self._submarine_pair_info_cache: Optional[dict] = None
        self._submarine_pair_info_cached_at: Optional[datetime] = None
        self._submarine_pair_info_stale: Optional[dict] = None
        # Boltz LN node pubkeys (``/v2/nodes``). Used by the on-chain
        # deposit routability probe (Tier 2). Long TTL — node pubkeys
        # change very rarely. Same two-slot fresh/stale shape.
        self._nodes_cache: Optional[list] = None
        self._nodes_cached_at: Optional[datetime] = None
        self._nodes_stale: Optional[list] = None
        # Tor circuit-skip backoff. If Tor connection attempts
        # have been failing we exponentially extend the window in
        # which we skip the Tor attempt entirely and go straight to
        # clearnet (when fallback is enabled). Reset on the next
        # successful Tor request.
        self._tor_backoff_until: float = 0.0
        self._tor_backoff_seconds: float = 0.0

    @property
    def _boltz_url(self) -> str:
        if settings.boltz_use_tor and settings.lnd_tor_proxy:
            return settings.boltz_onion_url
        return settings.boltz_api_url

    @property
    def _proxy(self) -> Optional[str]:
        if settings.boltz_use_tor and settings.lnd_tor_proxy:
            return force_remote_dns_socks(settings.lnd_tor_proxy)
        return None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                proxy=self._proxy,
                timeout=httpx.Timeout(30.0, connect=15.0),
                verify=True,
                headers={"Content-Type": "application/json"},
                # Never chase a redirect off the configured endpoint — a
                # 30x must not bounce a swap request (which carries the
                # destination address/amount) to an arbitrary host.
                follow_redirects=False,
            )
        return self._client

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    async def _request(
        self,
        method: str,
        path: str,
        json_data: Optional[dict] = None,
        *,
        allow_clearnet_fallback: bool = True,
    ) -> tuple[Optional[dict], Optional[str]]:
        """Make a request to the Boltz API.

        Wraps the call in retry + circuit breaker. Falls back to
        clearnet if Tor is unavailable and fallback is enabled.
        Catches ConnectError, ProxyError, and ReadTimeout for Tor
        resilience.

        Mutating calls (POST) get *one* attempt — re-issuing them
        could create duplicate swaps. The breaker still fast-fails
        them when open. GET calls are retried via :func:`with_retry`.

        ``allow_clearnet_fallback`` is set ``False`` for swap-creation
        calls, whose request body carries the withdrawal address and
        amount. Routing those over clearnet on a Tor failure would
        correlate the wallet's public IP with the on-chain destination —
        the exact deanonymization the Tor routing exists to prevent — so
        such a call surfaces the Tor error instead of degrading to
        clearnet.
        """
        idempotent = method.upper() == "GET"
        url = f"{self._boltz_url}{path}"

        # If a recent Tor failure put us in a backoff window,
        # skip the Tor attempt entirely and go straight to clearnet
        # (when fallback is enabled). Avoids wasting one request
        # timeout per call while Tor is wedged.
        import time as _time

        if (
            settings.boltz_use_tor
            and settings.boltz_fallback_clearnet
            and allow_clearnet_fallback
            and self._tor_backoff_until > _time.monotonic()
        ):
            return await self._request_clearnet(method, path, json_data)

        async def _attempt() -> dict:
            client = await self._get_client()
            response = await request_capped(client, method, url, json=json_data)
            if 500 <= response.status_code < 600:
                raise _BoltzRetryable5xxError(response.status_code, response.text)
            response.raise_for_status()
            return response.json()  # type: ignore[no-any-return]

        try:
            if idempotent:
                data = await with_retry(
                    _attempt,
                    retryable=_BOLTZ_RETRYABLE_EXC + (_BoltzRetryable5xxError,),
                    breaker=_BOLTZ_BREAKER,
                    op_name=f"boltz {method} {path}",
                )
            else:
                await _BOLTZ_BREAKER.before_call()
                try:
                    data = await _attempt()
                except BaseException as e:
                    _BOLTZ_BREAKER.record_failure(f"{type(e).__name__}: {e}")
                    raise
                else:
                    _BOLTZ_BREAKER.record_success()
            _BOLTZ_HEALTH.record_success()
            # Successful Tor request — clear any backoff.
            if settings.boltz_use_tor:
                self._tor_backoff_until = 0.0
                self._tor_backoff_seconds = 0.0
            return data, None
        except BreakerOpenError as e:
            logger.warning("Boltz breaker is open: %s", e)
            _BOLTZ_HEALTH.record_failure(str(e))
            return None, "Boltz temporarily unavailable (circuit breaker open)"
        except _BoltzRetryable5xxError as e:
            _BOLTZ_HEALTH.record_failure(f"5xx: {e.status_code}")
            return None, f"Boltz API error {e.status_code}: {e.body}"
        except (httpx.ConnectError, httpx.ProxyError, httpx.ReadTimeout) as e:
            _BOLTZ_HEALTH.record_failure(f"{type(e).__name__}: {e}")
            if settings.boltz_fallback_clearnet and settings.boltz_use_tor and allow_clearnet_fallback:
                # Extend the Tor backoff window exponentially
                # (1s → 2s → 4s → … capped at 5 min). Reset to 0 on
                # the next Tor success.
                next_backoff = max(1.0, self._tor_backoff_seconds * 2.0)
                if next_backoff > 300.0:
                    next_backoff = 300.0
                self._tor_backoff_seconds = next_backoff
                self._tor_backoff_until = _time.monotonic() + next_backoff
                logger.warning(
                    "Tor connection to Boltz failed, trying clearnet (next Tor attempt skipped for %.1fs): %s",
                    next_backoff,
                    e,
                )
                try:
                    import asyncio

                    from app.services.alert_service import send_alert

                    asyncio.ensure_future(
                        send_alert(
                            "tor_fallback",
                            f"Boltz Tor connection failed, falling back to clearnet: {e}",
                        )
                    )
                except Exception:
                    pass
                # Clearnet fallback inserts a small inter-attempt delay
                # so we don't fire it immediately at the same instant
                # the Tor attempt failed. The breaker has
                # already recorded a failure for the Tor attempt; if
                # clearnet succeeds the next call will close it.
                import asyncio as _asyncio

                await _asyncio.sleep(0.5)
                return await self._request_clearnet(method, path, json_data)
            error_type = type(e).__name__
            return None, f"Connection failed ({error_type}): {e}"
        except httpx.HTTPStatusError as e:
            body = e.response.text
            try:
                error_body = e.response.json()
                body = error_body.get("error", body)
            except Exception:
                pass
            _BOLTZ_HEALTH.record_failure(f"{e.response.status_code}: {body[:120]}")
            return None, f"Boltz API error {e.response.status_code}: {body}"
        except Exception as e:
            _BOLTZ_HEALTH.record_failure(f"{type(e).__name__}: {e}")
            return None, f"Boltz request failed: {e}"

    async def _request_clearnet(
        self,
        method: str,
        path: str,
        json_data: Optional[dict] = None,
    ) -> tuple[Optional[dict], Optional[str]]:
        """Fallback clearnet request (no Tor proxy).

        The destination IP is resolved once and pinned, with the original
        ``Host`` and the real SNI preserved, so the address that passes the
        egress check is the address the socket connects to (a host whose DNS
        answer changes between resolution and connect cannot redirect the
        request at internal infrastructure).
        """
        url = f"{settings.boltz_api_url}{path}"
        request_url = url
        headers: dict[str, str] = {}
        extensions: dict[str, str] = {}
        host = httpx.URL(url).host
        if not is_onion_host(host or ""):
            try:
                request_url, headers, extensions = pin_request_args(url)
            except BlockedHostError as exc:
                return None, f"refusing to connect to Boltz clearnet host: {exc}"
            except ValueError:
                request_url = url
        try:
            async with httpx.AsyncClient(timeout=30.0, verify=True, follow_redirects=False) as client:
                response = await request_capped(
                    client,
                    method,
                    request_url,
                    json=json_data,
                    headers=headers,
                    extensions=extensions,
                )
                response.raise_for_status()
                return response.json(), None
        except httpx.HTTPStatusError as e:
            body = e.response.text
            try:
                body = e.response.json().get("error", body)
            except Exception:
                pass
            return None, f"Boltz API error {e.response.status_code}: {body}"
        except Exception as e:
            return None, f"Boltz clearnet request failed: {e}"

    # ─── Public API ───────────────────────────────────────────────────

    async def get_reverse_pair_info(self) -> tuple[Optional[dict], Optional[str]]:
        """Fetch current BTC/BTC reverse swap fees and limits.

        Cached for 60 s in the fresh slot. On a fetch failure we
        fall back to the never-expiring stale slot (last successful
        response) and decorate the result with ``stale=True`` so
        callers can flag it to the user. If neither slot is filled
        we propagate the error.
        """
        now = _utc_now()
        if (
            self._pair_info_cache
            and self._pair_info_cached_at
            and (now - self._pair_info_cached_at).total_seconds() < 60
        ):
            return self._pair_info_cache, None

        data, error = await self._request("GET", "/swap/reverse")
        if error:
            if self._pair_info_stale is not None:
                logger.warning(
                    "Boltz pair-info fetch failed (%s) — serving stale cache from %s",
                    error,
                    self._pair_info_cached_at,
                )
                return {**self._pair_info_stale, "stale": True}, None
            return None, error
        assert data is not None

        try:
            btc_pair = data.get("BTC", {}).get("BTC", {})
            if not btc_pair:
                return None, "BTC/BTC reverse pair not found in Boltz response"
            info = {
                "min": btc_pair.get("limits", {}).get("minimal", BOLTZ_MIN_AMOUNT_SATS),
                "max": btc_pair.get("limits", {}).get("maximal", BOLTZ_MAX_AMOUNT_SATS),
                "fees_percentage": btc_pair.get("fees", {}).get("percentage", 0.5),
                "fees_miner_lockup": btc_pair.get("fees", {}).get("minerFees", {}).get("lockup", 462),
                "fees_miner_claim": btc_pair.get("fees", {}).get("minerFees", {}).get("claim", 333),
                "hash": btc_pair.get("hash", ""),
            }
            self._pair_info_cache = info
            self._pair_info_cached_at = now
            self._pair_info_stale = info
            return info, None
        except Exception as e:
            return None, f"Failed to parse pair info: {e}"

    async def get_submarine_pair_info(self) -> tuple[Optional[dict], Optional[str]]:
        """Fetch current BTC/BTC submarine swap fees and limits
        (on-chain → Lightning). Same caching shape as the reverse
        pair-info helper.

        Submarine swaps go ``/swap/submarine`` (the inverse direction
        of reverse swaps): the user funds an on-chain lockup, Boltz
        pays the wallet's Lightning invoice. The fee structure mirrors
        reverse swaps but the miner-fee fields are slightly different
        (``lockup`` is paid by the user on the funding tx; ``claim``
        is paid by Boltz to claim the lockup after settlement).
        """
        now = _utc_now()
        if (
            self._submarine_pair_info_cache
            and self._submarine_pair_info_cached_at
            and (now - self._submarine_pair_info_cached_at).total_seconds() < 60
        ):
            return self._submarine_pair_info_cache, None

        data, error = await self._request("GET", "/swap/submarine")
        if error:
            if self._submarine_pair_info_stale is not None:
                logger.warning(
                    "Boltz submarine pair-info fetch failed (%s) — serving stale cache from %s",
                    error,
                    self._submarine_pair_info_cached_at,
                )
                return {**self._submarine_pair_info_stale, "stale": True}, None
            return None, error
        assert data is not None

        try:
            btc_pair = data.get("BTC", {}).get("BTC", {})
            if not btc_pair:
                return None, "BTC/BTC submarine pair not found in Boltz response"
            info = {
                "min": btc_pair.get("limits", {}).get("minimal", BOLTZ_MIN_AMOUNT_SATS),
                "max": btc_pair.get("limits", {}).get("maximal", BOLTZ_MAX_AMOUNT_SATS),
                "fees_percentage": btc_pair.get("fees", {}).get("percentage", 0.1),
                "fees_miner_lockup": btc_pair.get("fees", {}).get("minerFees", 462)
                if isinstance(btc_pair.get("fees", {}).get("minerFees"), int)
                else btc_pair.get("fees", {}).get("minerFees", {}).get("lockup", 462),
                "hash": btc_pair.get("hash", ""),
            }
            self._submarine_pair_info_cache = info
            self._submarine_pair_info_cached_at = now
            self._submarine_pair_info_stale = info
            return info, None
        except Exception as e:
            return None, f"Failed to parse submarine pair info: {e}"

    async def get_ln_node_pubkeys(self) -> tuple[Optional[list], Optional[str]]:
        """Fetch Boltz's BTC Lightning node public keys (``/v2/nodes``).

        Returns a deduplicated list of lowercase hex pubkeys (Boltz runs
        more than one implementation — e.g. LND and CLN — so there can be
        several). Used by the on-chain deposit routability probe to ask
        LND "is there a route from Boltz → us?".

        Cached for 1 h in the fresh slot (node pubkeys change rarely),
        with a never-expiring stale slot served when Boltz is briefly
        unreachable. Best-effort: callers treat a ``(None, err)`` result
        as "probe unavailable" rather than fatal.
        """
        now = _utc_now()
        if self._nodes_cache and self._nodes_cached_at and (now - self._nodes_cached_at).total_seconds() < 3600:
            return self._nodes_cache, None

        data, error = await self._request("GET", "/nodes")
        if error:
            if self._nodes_stale is not None:
                logger.warning(
                    "Boltz nodes fetch failed (%s) — serving stale cache from %s",
                    error,
                    self._nodes_cached_at,
                )
                return self._nodes_stale, None
            return None, error
        assert data is not None

        try:
            btc = data.get("BTC", {}) or {}
            pubkeys: list[str] = []
            for impl in btc.values():
                if not isinstance(impl, dict):
                    continue
                pk = impl.get("publicKey")
                if isinstance(pk, str) and pk:
                    pk_l = pk.strip().lower()
                    if pk_l not in pubkeys:
                        pubkeys.append(pk_l)
            if not pubkeys:
                return None, "No BTC Lightning node pubkeys in Boltz response"
            self._nodes_cache = pubkeys
            self._nodes_cached_at = now
            self._nodes_stale = pubkeys
            return pubkeys, None
        except Exception as e:
            return None, f"Failed to parse Boltz nodes: {e}"

    async def create_submarine_swap(
        self,
        db: AsyncSession,
        *,
        api_key_id: UUID,
        invoice: str,
        invoice_amount_sats: int,
        pair_hash: Optional[str] = None,
    ) -> tuple[Optional[BoltzSwap], Optional[str]]:
        """Create a Boltz submarine swap (on-chain → Lightning).

        The wallet supplies a BOLT11 invoice it wants paid; Boltz
        returns the on-chain lockup address the wallet then funds.
        Once Boltz observes the funding tx, it pays the invoice.

        Differs from the reverse swap creation: there is no preimage
        for the wallet to mint — the BOLT11 invoice already carries
        the payment hash, and Boltz reveals the preimage by paying.
        The wallet keeps a refund keypair so a stuck swap can be
        recovered via Boltz's cooperative-refund endpoint or the
        script-path spend after timeout.

        Persists a ``BoltzSwap`` row with ``direction=REVERSE`` (we
        reuse the existing model — the original direction was an
        over-narrow concept; both swap kinds use the same
        schema and the reverse/submarine distinction is captured by
        which fields are populated). Returns ``(swap, None)`` on
        success or ``(None, error)``.
        """
        if invoice_amount_sats <= 0:
            return None, "invoice_amount_sats must be positive"

        # Bind the fairness bound to the actual obligation Boltz will
        # settle, not just the caller-supplied amount. The BOLT11
        # invoice's encoded principal is what Boltz pays; if it diverges
        # from ``invoice_amount_sats`` the lockup ceiling computed below
        # would be keyed off the wrong figure. An amountless invoice
        # (no principal) cannot be priced, so refuse it. Fails closed.
        from app.core.bolt11 import principal_sats_from_bolt11

        invoice_principal = principal_sats_from_bolt11(invoice)
        if invoice_principal is None:
            return None, "invoice does not encode an amount; cannot price the swap"
        if invoice_principal != invoice_amount_sats:
            return None, (
                f"invoice principal ({invoice_principal:,} sats) does not match "
                f"requested amount ({invoice_amount_sats:,} sats)"
            )

        pair_info, err = await self.get_submarine_pair_info()
        if err or pair_info is None:
            return None, f"Failed to fetch submarine pair info: {err or 'no data'}"
        min_amt = int(pair_info.get("min", BOLTZ_MIN_AMOUNT_SATS))
        max_amt = int(pair_info.get("max", BOLTZ_MAX_AMOUNT_SATS))
        if invoice_amount_sats < min_amt or invoice_amount_sats > max_amt:
            return None, (f"Amount must be between {min_amt:,} and {max_amt:,} sats")

        try:
            refund_private_key_hex, refund_public_key_hex = _generate_keypair()
        except RuntimeError as e:
            return None, str(e)

        swap_request: dict = {
            "from": "BTC",
            "to": "BTC",
            "invoice": invoice,
            "refundPublicKey": refund_public_key_hex,
        }
        # NOTE: ``pairHash`` is intentionally omitted. Boltz treats
        # ``pairHash`` as an opt-in freshness assertion — if the
        # echoed hash doesn't match Boltz's current pair config the
        # request is rejected with "invalid pair hash". The pair info
        # is cached for 60s on our side, and Boltz periodically
        # updates submarine fees, so any cache-vs-live drift turns a
        # legitimate user submission into a hard failure with no
        # automatic recovery. Omitting ``pairHash`` makes Boltz
        # price the swap at current rates instead. The anonymize
        # submarine path (boltz_egress.create_submarine_swap) takes
        # the same approach and has been running cleanly in
        # production.

        data, error = await self._request(
            "POST",
            "/swap/submarine",
            swap_request,
            allow_clearnet_fallback=False,
        )
        if error:
            return None, f"Boltz submarine-swap creation failed: {error}"
        assert data is not None
        if "id" not in data:
            return None, "Boltz response missing 'id' field"

        # ── Verify the lockup address ──
        # The on-chain deposit funds ``data["address"]`` directly. Before
        # we persist (and the deposit flow funds) it, prove the address
        # commits to the swap tree + OUR refund key, exactly like the
        # anonymize submarine path does. A malicious
        # Boltz that returns an address it solely controls — not a real
        # swap output — is rejected here, so funds are never sent to an
        # unrecoverable destination. Fails closed on any verifier error.
        lockup_address = data.get("address")
        if not lockup_address:
            return None, "Boltz response missing lockup 'address' field"
        ok, reason = verify_submarine_lockup_address(
            swap_tree_json=data.get("swapTree"),
            refund_public_key_hex=refund_public_key_hex,
            lockup_address=lockup_address,
            network=settings.bitcoin_network,
        )
        if not ok:
            return None, f"Boltz submarine lockup address failed verification: {reason}"

        # ── Bound the funded amount ──
        # We fund Boltz's returned ``expectedAmount`` verbatim. Cap it to
        # the locally-computed fair lockup (invoice + pct fee + lockup
        # miner fee) plus a small slack so a malicious/compromised Boltz
        # can't inflate ``expectedAmount`` and make us silently over-fund.
        expected_amount = int(data.get("expectedAmount", 0) or 0)
        try:
            pct_val = float(pair_info.get("fees_percentage", "0.1"))
        except (TypeError, ValueError):
            pct_val = 0.1
        pct_fee_est = int(invoice_amount_sats * pct_val / 100.0 + 0.999)
        miner_lockup_est = int(pair_info.get("fees_miner_lockup", 0) or 0)
        fair_lockup = invoice_amount_sats + pct_fee_est + miner_lockup_est
        lockup_slack = max(1000, int(invoice_amount_sats * 0.01))
        if expected_amount > fair_lockup + lockup_slack:
            return None, (
                "Boltz expectedAmount "
                f"({expected_amount:,} sats) exceeds the quoted lockup "
                f"({fair_lockup:,} sats + {lockup_slack:,} slack)"
            )

        # The submarine flow reuses the BoltzSwap row shape — most
        # fields map cleanly. ``preimage_hex`` / ``preimage_hash_hex``
        # are unused (the invoice carries the hash; Boltz reveals the
        # preimage by paying). Encrypt the refund key the same way
        # reverse swaps encrypt the claim key.
        miner_fee_sats = int(pair_info.get("fees_miner_lockup", 0) or 0)
        try:
            pct_str = str(pair_info.get("fees_percentage", "0.1"))
        except Exception:
            pct_str = "0.1"
        swap = BoltzSwap(
            boltz_swap_id=data["id"],
            api_key_id=api_key_id,
            invoice_amount_sats=invoice_amount_sats,
            onchain_amount_sats=int(data.get("expectedAmount", 0) or 0),
            destination_address=data.get("address") or "",
            fee_percentage=pct_str,
            miner_fee_sats=miner_fee_sats,
            preimage_hex=encrypt_field("00" * 32),  # unused for submarine
            preimage_hash_hex="00" * 32,
            claim_private_key_hex=encrypt_field(refund_private_key_hex),
            claim_public_key_hex=refund_public_key_hex,
            boltz_invoice=invoice,
            boltz_lockup_address=data.get("address"),
            boltz_refund_public_key_hex=refund_public_key_hex,
            # Boltz's side of the Musig2 key set — persisted now so
            # we can construct cooperative-refund Musig2 sessions
            # later without re-fetching swap state from Boltz.
            boltz_claim_public_key_hex=data.get("claimPublicKey"),
            boltz_swap_tree_json=data.get("swapTree"),
            timeout_block_height=data.get("timeoutBlockHeight"),
            boltz_blinding_key=data.get("blindingKey"),
            status=SwapStatus.CREATED,
            boltz_status="swap.created",
            status_history=[
                {
                    "status": "created",
                    "boltz_status": "swap.created",
                    "timestamp": _utc_now().isoformat(),
                    "kind": "submarine",
                }
            ],
        )
        db.add(swap)
        await db.commit()
        await db.refresh(swap)

        logger.info(
            "Boltz submarine swap created: id=%s, invoice_amount=%d sats, lockup=%s..., expected_onchain=%d sats",
            swap.boltz_swap_id,
            invoice_amount_sats,
            (swap.boltz_lockup_address or "")[:12],
            swap.onchain_amount_sats or 0,
        )
        return swap, None

    async def create_reverse_swap(
        self,
        db: AsyncSession,
        api_key_id: UUID,
        invoice_amount_sats: int,
        destination_address: str,
        outgoing_chan_id: Optional[str] = None,
    ) -> tuple[Optional[BoltzSwap], Optional[str]]:
        """Create a Boltz reverse swap for cold storage withdrawal.

        1. Validates amount within Boltz limits
        2. Generates preimage + claim keypair
        3. Calls Boltz /swap/reverse
        4. Persists complete swap state (encrypted crypto material)
        """
        pair_info, err = await self.get_reverse_pair_info()
        if err:
            return None, f"Failed to fetch Boltz pair info: {err}"
        assert pair_info is not None

        min_amt = pair_info["min"]
        max_amt = pair_info["max"]
        if invoice_amount_sats < min_amt or invoice_amount_sats > max_amt:
            return None, f"Amount must be between {min_amt:,} and {max_amt:,} sats"

        try:
            preimage_hex, preimage_hash_hex = _generate_preimage()
            claim_private_key_hex, claim_public_key_hex = _generate_keypair()
        except RuntimeError as e:
            return None, str(e)

        swap_request = {
            "from": "BTC",
            "to": "BTC",
            "preimageHash": preimage_hash_hex,
            "claimPublicKey": claim_public_key_hex,
            "invoiceAmount": invoice_amount_sats,
            "claimAddress": destination_address,
        }
        # NOTE: ``pairHash`` is intentionally omitted — same rationale as the
        # submarine path (see ``create_submarine_swap``). Boltz treats
        # ``pairHash`` as an opt-in freshness assertion; if the echoed hash
        # doesn't match Boltz's current reverse-pair config the request is
        # rejected with "invalid pair hash". The pair info is cached for 60s
        # on our side and Boltz rotates its fee/limit config frequently, so
        # any cache-vs-live (or even fetch-vs-create) drift turned a
        # legitimate withdrawal/Braiins-deposit into a hard failure with no
        # recovery. Omitting ``pairHash`` makes Boltz price the swap at
        # current rates. Safety is unaffected: the returned hold-invoice is
        # still bound to OUR preimage hash and amount below before we pay it.

        data, error = await self._request(
            "POST",
            "/swap/reverse",
            swap_request,
            allow_clearnet_fallback=False,
        )
        if error:
            return None, f"Boltz swap creation failed: {error}"
        assert data is not None

        # Bind the returned hold-invoice to OUR preimage hash before paying
        # it. A reverse swap is only trustless when the invoice we pay
        # commits to sha256(preimage) we generated; otherwise a malicious
        # Boltz returns an invoice whose payment hash it already knows the
        # preimage for, settles the HTLC to take our LN funds, and never
        # reveals the preimage we need to claim the on-chain lockup.
        from app.core.bolt11 import (
            payment_hash_from_bolt11,
            principal_sats_from_bolt11,
        )

        returned_invoice = data.get("invoice")
        invoice_payment_hash = payment_hash_from_bolt11(returned_invoice) if isinstance(returned_invoice, str) else None
        if invoice_payment_hash is None or not hmac.compare_digest(invoice_payment_hash, preimage_hash_hex.lower()):
            return None, "Boltz reverse invoice payment_hash does not commit to our preimage hash"

        # Bind the invoice principal to the amount we asked to send. The
        # operator picks the hold-invoice amount, so without this an
        # inflated principal would have LND pay more than the swap pays
        # back on-chain. The fairness band below keys off our requested
        # amount, not the invoice, so it does not catch principal
        # inflation.
        invoice_principal = principal_sats_from_bolt11(returned_invoice) if isinstance(returned_invoice, str) else None
        if invoice_principal is None or invoice_principal != int(invoice_amount_sats):
            return None, (
                f"Boltz reverse invoice principal {invoice_principal} does not match "
                f"requested amount {int(invoice_amount_sats)}; refusing"
            )

        # Fairness band: the on-chain amount Boltz will lock up must be at
        # least (invoice − declared fees), or a malicious operator could
        # quote a fair LN invoice but deliver far less on-chain.
        try:
            onchain_amount = int(data.get("onchainAmount"))
        except (TypeError, ValueError):
            return None, "Boltz reverse response missing/invalid onchainAmount"
        pct_fee = int(invoice_amount_sats * float(pair_info["fees_percentage"]) / 100.0)
        miner_fee = int(pair_info["fees_miner_lockup"]) + int(pair_info["fees_miner_claim"])
        fair_min = invoice_amount_sats - pct_fee - miner_fee
        slack = max(1000, int(invoice_amount_sats * 0.01))  # tolerate fee-estimate drift
        if onchain_amount < fair_min - slack:
            return None, (
                f"Boltz reverse onchainAmount {onchain_amount} below fair minimum "
                f"{fair_min} (invoice {invoice_amount_sats} − fees); refusing"
            )

        # Reconstruct the lockup taproot from the swap tree + our claim key
        # and confirm the claim leaf commits to OUR claim key and the
        # derived address equals the returned lockupAddress. The
        # preimage-hash binding above already blocks LN-settlement theft;
        # this rejects a lockup whose claim path the operator controls
        # before the hold invoice is paid, mirroring the submarine path.
        reverse_lockup_address = data.get("lockupAddress")
        if not reverse_lockup_address:
            return None, "Boltz reverse response missing lockupAddress"
        ok, reason = verify_reverse_lockup_address(
            swap_tree_json=data.get("swapTree"),
            claim_public_key_hex=claim_public_key_hex,
            refund_public_key_hex=data.get("refundPublicKey"),
            lockup_address=reverse_lockup_address,
            network=settings.bitcoin_network,
        )
        if not ok:
            return None, f"Boltz reverse lockup address failed verification: {reason}"

        swap = BoltzSwap(
            boltz_swap_id=data["id"],
            api_key_id=api_key_id,
            invoice_amount_sats=invoice_amount_sats,
            onchain_amount_sats=data.get("onchainAmount"),
            destination_address=destination_address,
            fee_percentage=str(pair_info["fees_percentage"]),
            miner_fee_sats=pair_info["fees_miner_lockup"] + pair_info["fees_miner_claim"],
            outgoing_chan_id=outgoing_chan_id,
            preimage_hex=encrypt_field(preimage_hex),
            preimage_hash_hex=preimage_hash_hex,
            claim_private_key_hex=encrypt_field(claim_private_key_hex),
            claim_public_key_hex=claim_public_key_hex,
            boltz_invoice=data.get("invoice"),
            boltz_lockup_address=data.get("lockupAddress"),
            boltz_refund_public_key_hex=data.get("refundPublicKey"),
            boltz_swap_tree_json=data.get("swapTree"),
            timeout_block_height=data.get("timeoutBlockHeight"),
            boltz_blinding_key=data.get("blindingKey"),
            status=SwapStatus.CREATED,
            boltz_status="swap.created",
            status_history=[
                {
                    "status": "created",
                    "boltz_status": "swap.created",
                    "timestamp": _utc_now().isoformat(),
                }
            ],
        )
        db.add(swap)
        await db.commit()
        await db.refresh(swap)

        logger.info(
            "Boltz reverse swap created: %s, amount=%d sats, dest=%s...",
            swap.boltz_swap_id,
            invoice_amount_sats,
            destination_address[:12],
        )
        return swap, None

    async def get_swap_status_from_boltz(
        self, boltz_swap_id: str
    ) -> tuple[Optional[str], Optional[dict], Optional[str]]:
        """Query Boltz for current swap status."""
        data, error = await self._request("GET", f"/swap/{quote(boltz_swap_id, safe='')}")
        if error:
            return None, None, error
        assert data is not None
        return data.get("status"), data, None

    async def get_lockup_transaction(self, boltz_swap_id: str) -> tuple[Optional[str], Optional[str]]:
        """Fetch the lockup transaction hex from Boltz."""
        data, error = await self._request(
            "GET",
            f"/swap/reverse/{quote(boltz_swap_id, safe='')}/transaction",
        )
        if error:
            return None, error
        assert data is not None
        return data.get("hex") or data.get("transactionHex"), None

    async def _verify_claim_output(self, swap: BoltzSwap, tx_hex: str) -> Optional[str]:
        """Cross-check that a claim tx pays the swap's intended destination.

        ``boltz_claim.js`` builds the claim output from our own
        ``destinationAddress``, so this guards against a subprocess bug
        sending the claim somewhere else: it reconstructs the expected
        ``scriptPubKey`` from ``swap.destination_address`` and confirms the
        tx pays it within a sane value band. Returns an error string (after
        raising an alert) on mismatch, or ``None`` when the tx checks out
        or the expected script cannot be derived (in which case the check
        is skipped rather than failing a good claim).
        """
        try:
            from app.services.chain.electrum_protocol import address_to_script_pubkey

            expected_spk_hex = address_to_script_pubkey(swap.destination_address, settings.bitcoin_network).hex()
        except Exception as exc:  # noqa: BLE001 — can't derive ⇒ skip the cross-check
            logger.warning(
                "claim output cross-check skipped for swap %s (could not derive script: %s)",
                swap.boltz_swap_id,
                exc,
            )
            return None

        onchain = int(swap.onchain_amount_sats or 0)
        # The output is the lockup value less the claim miner fee. The
        # script match is the theft-relevant property; the band only
        # rejects a grossly-short or inflated delivery, so it is kept loose
        # to avoid failing a correctly-addressed claim over fee variance.
        band = (max(1, onchain - 25_000), onchain * 2) if onchain > 0 else (1, 21_000_000 * 100_000_000)

        from app.services.anonymize.cooperative_claim import (
            ClaimTxValidationError,
            validate_cooperative_claim_tx,
        )

        try:
            validate_cooperative_claim_tx(
                tx_hex=tx_hex,
                expected_output_script_hex=expected_spk_hex,
                expected_output_band_sat=band,
            )
        except ClaimTxValidationError as exc:
            logger.error(
                "Claim tx output cross-check FAILED for swap %s: %s",
                swap.boltz_swap_id,
                exc,
            )
            try:
                from app.services.alert_service import send_alert

                await send_alert(
                    "cold_storage_claim_misaddressed",
                    f"Claim tx for swap {swap.boltz_swap_id} failed output cross-check.",
                    details={"swap_id": swap.boltz_swap_id, "reason": str(exc)},
                )
            except Exception:  # noqa: BLE001 — alerting must not mask the result
                logger.debug("claim-misaddressed alert emit failed", exc_info=True)
            return f"claim output validation failed: {exc}"
        return None

    async def cooperative_claim(
        self,
        swap: BoltzSwap,
        lockup_tx_hex: str,
    ) -> tuple[Optional[str], Optional[str]]:
        """Construct and broadcast a cooperative Taproot claim transaction.

        Delegates to Node.js boltz-core for Musig2 signing.
        Routes through Tor when configured.
        """
        if not CLAIM_SCRIPT_PATH.exists():
            return None, f"Claim script not found at {CLAIM_SCRIPT_PATH}"

        claim_input = {
            "boltzUrl": self._boltz_url,
            "swapId": swap.boltz_swap_id,
            "preimage": decrypt_field(swap.preimage_hex),  # type: ignore[arg-type]
            "claimPrivateKey": decrypt_field(swap.claim_private_key_hex),  # type: ignore[arg-type]
            "refundPublicKey": swap.boltz_refund_public_key_hex,
            "swapTree": swap.boltz_swap_tree_json,
            "lockupTxHex": lockup_tx_hex,
            "destinationAddress": swap.destination_address,
            # Return the broadcast claim-tx hex on stdout so we can
            # cross-check the output script against our destination.
            "emitTxHexStdout": True,
        }

        proxy = self._proxy
        if proxy:
            claim_input["socksProxy"] = proxy

        script_timeout = 120 if proxy else 60
        # Use ``asyncio.create_subprocess_exec`` so the 60-120 s wait
        # for the Node.js claim script does NOT block the event loop.
        # The previous ``subprocess.run`` froze every coroutine in this
        # loop for the script's lifetime — including any open DB
        # session — which is what wedged 30 connections in ``idle in
        # transaction`` and exhausted the SQLAlchemy pool. Other
        # callers' HTTP requests + LND/Boltz timeouts now get to
        # observe their own deadlines instead of starving.
        stdout_bytes = b""
        stderr_bytes = b""
        try:
            proc = await asyncio.create_subprocess_exec(
                _NODE_BIN,
                str(CLAIM_SCRIPT_PATH),
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(CLAIM_SCRIPT_DIR),
                env=_SUBPROCESS_ENV,
            )
        except FileNotFoundError:
            return None, "Node.js not found for claim script execution"
        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(input=json.dumps(claim_input).encode()),
                timeout=script_timeout,
            )
        except asyncio.TimeoutError:
            # ``proc.communicate`` doesn't kill the child on its own
            # timeout — drain explicitly so the subprocess doesn't
            # outlive its handle.
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            try:
                await proc.wait()
            except Exception:  # noqa: BLE001
                pass
            return None, f"Claim script timed out ({script_timeout}s)"
        if proc.returncode != 0:
            stderr_safe = stderr_bytes[:500].decode("utf-8", errors="replace") if stderr_bytes else ""
            logger.error("Claim script failed (exit %d)", proc.returncode)
            return None, f"Claim script failed: {stderr_safe}"
        stdout_text = stdout_bytes.decode("utf-8", errors="replace")
        try:
            output = json.loads(stdout_text.strip())
        except json.JSONDecodeError:
            return None, f"Claim script returned invalid JSON: {stdout_text[:500]}"
        txid = output.get("txid")
        if not txid:
            return None, f"Claim script returned no txid: {output}"
        tx_hex = output.get("txHex")
        if tx_hex:
            verr = await self._verify_claim_output(swap, tx_hex)
            if verr:
                return None, verr
        else:
            logger.warning(
                "claim script returned no txHex; output cross-check skipped for swap %s",
                swap.boltz_swap_id,
            )
        return txid, None

    async def unilateral_claim(
        self,
        swap: BoltzSwap,
        lockup_tx_hex: str,
    ) -> tuple[Optional[str], Optional[str]]:
        """Construct and broadcast a unilateral script-path claim.

        Used as the post-timeout escape hatch when Boltz cooperative
        signing is unavailable. Spends the lockup via the swap's
        claim leaf (preimage + claim key + script-path Taproot witness)
        rather than the cooperative key-path.

        Delegates to the same Node.js script as :py:meth:`cooperative_claim`
        but with ``mode="unilateral"`` in the input envelope. The script
        broadcasts via Boltz's ``/chain/BTC/transaction`` endpoint, same
        as the cooperative path.
        """
        if not CLAIM_SCRIPT_PATH.exists():
            return None, f"Claim script not found at {CLAIM_SCRIPT_PATH}"

        claim_input = {
            "mode": "unilateral",
            "boltzUrl": self._boltz_url,
            "swapId": swap.boltz_swap_id,
            "preimage": decrypt_field(swap.preimage_hex),  # type: ignore[arg-type]
            "claimPrivateKey": decrypt_field(swap.claim_private_key_hex),  # type: ignore[arg-type]
            "refundPublicKey": swap.boltz_refund_public_key_hex,
            "swapTree": swap.boltz_swap_tree_json,
            "lockupTxHex": lockup_tx_hex,
            "destinationAddress": swap.destination_address,
            # Return the broadcast claim-tx hex on stdout for the output
            # cross-check (see cooperative_claim).
            "emitTxHexStdout": True,
        }
        proxy = self._proxy
        if proxy:
            claim_input["socksProxy"] = proxy

        script_timeout = 120 if proxy else 60
        # See ``cooperative_claim``: blocking ``subprocess.run`` here
        # froze the event loop for up to 120 s and was the upstream
        # cause of leaked ``idle in transaction`` connections.
        try:
            proc = await asyncio.create_subprocess_exec(
                _NODE_BIN,
                str(CLAIM_SCRIPT_PATH),
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(CLAIM_SCRIPT_DIR),
                env=_SUBPROCESS_ENV,
            )
        except FileNotFoundError:
            return None, "Node.js not found for unilateral claim script execution"
        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(input=json.dumps(claim_input).encode()),
                timeout=script_timeout,
            )
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            try:
                await proc.wait()
            except Exception:  # noqa: BLE001
                pass
            return None, f"Unilateral claim script timed out ({script_timeout}s)"
        if proc.returncode != 0:
            stderr_safe = stderr_bytes[:500].decode("utf-8", errors="replace") if stderr_bytes else ""
            logger.error("Unilateral claim script failed (exit %d)", proc.returncode)
            return None, f"Unilateral claim script failed: {stderr_safe}"
        stdout_text = stdout_bytes.decode("utf-8", errors="replace")
        # The unilateral mode emits the same event envelope as
        # the cooperative path: ``{"event": "claim_broadcast_complete", "txid": "..."}``.
        for line in stdout_text.strip().splitlines():
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, dict) and parsed.get("txid"):
                tx_hex = parsed.get("txHex")
                if tx_hex:
                    verr = await self._verify_claim_output(swap, tx_hex)
                    if verr:
                        return None, verr
                else:
                    logger.warning(
                        "unilateral claim script returned no txHex; output cross-check skipped for swap %s",
                        swap.boltz_swap_id,
                    )
                return parsed["txid"], None
        return None, f"Unilateral claim script returned no txid: {stdout_text[:500]}"

    async def retry_cooperative_claim(
        self,
        db: AsyncSession,
        swap: BoltzSwap,
    ) -> tuple[Optional[str], Optional[str]]:
        """Operator-driven retry of the cooperative claim path.

        Intended for the recovery surface in the dashboard / cold
        storage API: when a swap is stuck in ``CLAIMING`` with no
        ``claim_txid`` (typically because a prior cooperative-claim
        attempt failed transiently), this method re-fetches the
        lockup transaction and re-runs the cooperative claim
        subprocess. On success it persists ``claim_txid``, clears
        ``error_message``, and transitions the swap to ``CLAIMED``.
        On failure it bumps ``recovery_count`` and records the
        error.
        """
        if swap.claim_txid:
            return swap.claim_txid, None
        if swap.status != SwapStatus.CLAIMING:
            return None, (
                f"Swap is in status {swap.status.value}; "
                "cooperative claim retry is only valid while the swap is claiming."
            )

        lockup_hex, lockup_err = await self.get_lockup_transaction(swap.boltz_swap_id)
        if lockup_err or not lockup_hex:
            return None, lockup_err or "Lockup transaction unavailable"

        # Concurrent-claim guard — same as ``advance_swap``. The row lock
        # serializes a concurrent recovery/retry so only one claim broadcasts.
        existing = (
            await db.execute(select(BoltzSwap.claim_txid).where(BoltzSwap.id == swap.id).with_for_update())
        ).scalar()
        if existing:
            swap.claim_txid = existing
            swap.status = SwapStatus.CLAIMED
            await db.commit()
            return existing, None

        claim_txid, claim_err = await self.cooperative_claim(swap, lockup_hex)
        if claim_err:
            swap.recovery_count = (swap.recovery_count or 0) + 1
            swap.recovery_attempted_at = _utc_now()
            swap.error_message = claim_err
            await db.commit()
            return None, claim_err

        post_existing = (await db.execute(select(BoltzSwap.claim_txid).where(BoltzSwap.id == swap.id))).scalar()
        if post_existing:
            swap.claim_txid = post_existing
        else:
            swap.claim_txid = claim_txid
        swap.status = SwapStatus.CLAIMED
        swap.error_message = None
        await db.commit()
        return swap.claim_txid, None

    async def retry_unilateral_claim(
        self,
        db: AsyncSession,
        swap: BoltzSwap,
        *,
        btc_tip_height: Optional[int] = None,
    ) -> tuple[Optional[str], Optional[str]]:
        """Operator-driven unilateral (script-path) claim.

        Refuses to run unless the Boltz lockup timeout has passed —
        the script-path is only safe to use once Boltz's refund
        window expires, otherwise we risk racing Boltz's refund.
        When ``btc_tip_height`` is
        ``None`` the safety check can't be performed, so we now refuse
        (fail closed) rather than proceeding — the caller must fetch the
        chain tip and pass it through. A cold tip cache (``None``) no
        longer silently bypasses the timeout guard.
        """
        if swap.claim_txid:
            return swap.claim_txid, None
        if swap.status not in (SwapStatus.CLAIMING, SwapStatus.INVOICE_PAID):
            return None, (
                f"Swap is in status {swap.status.value}; "
                "unilateral claim is only valid for swaps with funds in the lockup."
            )
        if swap.timeout_block_height is None:
            return None, "Swap has no recorded timeout height; cannot verify safety."
        if btc_tip_height is None:
            return None, (
                "Chain tip is unavailable; cannot verify the lockup timeout has "
                "passed. Refusing the unilateral claim until the tip is known."
            )
        if btc_tip_height < swap.timeout_block_height:
            blocks_remaining = swap.timeout_block_height - btc_tip_height
            return None, (
                f"Lockup timeout has not passed yet ({blocks_remaining} blocks "
                "remaining). Use the cooperative claim retry instead."
            )

        lockup_hex, lockup_err = await self.get_lockup_transaction(swap.boltz_swap_id)
        if lockup_err or not lockup_hex:
            return None, lockup_err or "Lockup transaction unavailable"

        # Concurrent-claim guard — row lock serializes concurrent attempts.
        existing = (
            await db.execute(select(BoltzSwap.claim_txid).where(BoltzSwap.id == swap.id).with_for_update())
        ).scalar()
        if existing:
            swap.claim_txid = existing
            swap.status = SwapStatus.CLAIMED
            await db.commit()
            return existing, None

        claim_txid, claim_err = await self.unilateral_claim(swap, lockup_hex)
        if claim_err:
            swap.recovery_count = (swap.recovery_count or 0) + 1
            swap.recovery_attempted_at = _utc_now()
            swap.error_message = claim_err
            await db.commit()
            return None, claim_err

        post_existing = (await db.execute(select(BoltzSwap.claim_txid).where(BoltzSwap.id == swap.id))).scalar()
        if post_existing:
            swap.claim_txid = post_existing
        else:
            swap.claim_txid = claim_txid
        swap.status = SwapStatus.CLAIMED
        swap.error_message = None
        await db.commit()
        return swap.claim_txid, None

    async def broadcast_transaction(self, tx_hex: str) -> tuple[Optional[str], Optional[str]]:
        """Broadcast a raw transaction via Boltz API."""
        data, error = await self._request("POST", "/chain/BTC/transaction", {"hex": tx_hex})
        if error:
            return None, error
        assert data is not None
        return data.get("id"), None

    async def get_submarine_lockup_transaction(
        self,
        boltz_swap_id: str,
    ) -> tuple[Optional[str], Optional[str]]:
        """Fetch the lockup transaction hex for a submarine swap.

        Mirrors ``get_lockup_transaction`` (reverse swaps) but hits
        the ``/swap/submarine/{id}/transaction`` endpoint. Used by
        the cooperative-refund flow to rebuild the input outpoint
        from the on-chain UTXO the wallet locked at swap funding
        time.
        """
        data, error = await self._request(
            "GET",
            f"/swap/submarine/{quote(boltz_swap_id, safe='')}/transaction",
        )
        if error:
            return None, error
        assert data is not None
        return data.get("hex") or data.get("transactionHex"), None

    async def get_submarine_swap_info(
        self,
        boltz_swap_id: str,
    ) -> tuple[Optional[dict], Optional[str]]:
        """Fetch full swap details from Boltz.

        Used by the cooperative-refund flow to backfill
        ``claimPublicKey`` for swaps that were created before the
        wallet started persisting it (i.e. before migration 034).

        Boltz exposes the type-agnostic ``GET /v2/swap/{id}``
        endpoint for this — there is no ``/v2/swap/submarine/{id}``
        (returns 404). Same endpoint ``get_swap_status_from_boltz``
        already uses successfully.
        """
        data, error = await self._request(
            "GET",
            f"/swap/{quote(boltz_swap_id, safe='')}",
        )
        if error:
            return None, error
        return data, None

    async def cooperative_refund_submarine(
        self,
        swap: BoltzSwap,
        refund_address: str,
        lockup_tx_hex: Optional[str] = None,
        claim_public_key_hex: Optional[str] = None,
        fee_rate_sat_vb: Optional[float] = None,
    ) -> tuple[Optional[str], Optional[str]]:
        """Construct and broadcast a cooperative submarine refund.

        Sends our refund-side Musig2 pubNonce + unsigned refund tx
        to Boltz, receives Boltz's partial signature, aggregates,
        broadcasts via ``/chain/BTC/transaction``.

        Returns ``(txid, None)`` on success, ``(None, error)`` on
        failure. Caller is responsible for transitioning the swap
        row to ``SwapStatus.REFUNDED`` and any related session.
        """
        if not REFUND_SCRIPT_PATH.exists():
            return None, f"Refund script not found at {REFUND_SCRIPT_PATH}"

        if not swap.claim_private_key_hex:
            return None, "swap is missing the encrypted refund private key"
        if not swap.boltz_swap_tree_json:
            return None, "swap is missing the persisted swap tree"

        # Backfill missing pieces from Boltz for legacy rows created
        # before we persisted ``boltzClaimPublicKey`` / the lockup tx.
        claim_pubkey = claim_public_key_hex or swap.boltz_claim_public_key_hex
        if not claim_pubkey:
            # Try the type-agnostic status endpoint first. Some
            # Boltz API revisions echo ``claimPublicKey`` back here;
            # most do not (it's only guaranteed on the create
            # response). On miss, fall through to a swap-tree
            # extraction — the claim leaf script embeds the x-only
            # pubkey at a fixed offset for the boltz-core submarine
            # taproot template.
            info, err = await self.get_submarine_swap_info(swap.boltz_swap_id)
            if not err and info:
                candidate = info.get("claimPublicKey")
                if candidate:
                    claim_pubkey = candidate
        if not claim_pubkey:
            claim_pubkey = _extract_claim_pubkey_from_swap_tree(swap.boltz_swap_tree_json)
        if not claim_pubkey:
            return None, (
                "cannot determine Boltz claim public key "
                "(missing on row, not returned by Boltz status endpoint, "
                "and could not be extracted from the persisted swap tree)"
            )

        if lockup_tx_hex is None:
            lockup_tx_hex, lookup_err = await self.get_submarine_lockup_transaction(swap.boltz_swap_id)
            if lookup_err or not lockup_tx_hex:
                return None, (f"cannot fetch lockup tx for cooperative refund: {lookup_err}")

        refund_input: dict[str, Any] = {
            "mode": "cooperative",
            "boltzUrl": self._boltz_url,
            "swapId": swap.boltz_swap_id,
            "refundPrivateKey": decrypt_field(swap.claim_private_key_hex),
            "refundPublicKey": swap.claim_public_key_hex,
            "claimPublicKey": claim_pubkey,
            "swapTree": swap.boltz_swap_tree_json,
            "lockupTxHex": lockup_tx_hex,
            "refundAddress": refund_address,
            "timeoutBlockHeight": swap.timeout_block_height,
            "network": settings.bitcoin_network,
        }
        proxy = self._proxy
        if proxy:
            refund_input["socksProxy"] = proxy
        if fee_rate_sat_vb is not None and fee_rate_sat_vb > 0:
            # Clamp to the same sane ceiling the on-chain send path uses, so
            # an untrusted feerate ever forwarded here cannot inflate the
            # refund's miner fee and burn the locked funds.
            from app.services.chain.backend import clamp_feerate_sat_per_vb

            clamped = clamp_feerate_sat_per_vb(fee_rate_sat_vb)
            if clamped is not None:
                refund_input["feeRate"] = float(clamped)

        script_timeout = 120 if proxy else 60
        try:
            proc = await asyncio.create_subprocess_exec(
                _NODE_BIN,
                str(REFUND_SCRIPT_PATH),
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(CLAIM_SCRIPT_DIR),
                env=_SUBPROCESS_ENV,
            )
        except FileNotFoundError:
            return None, "Node.js not found for refund script execution"
        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(input=json.dumps(refund_input).encode()),
                timeout=script_timeout,
            )
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            try:
                await proc.wait()
            except Exception:  # noqa: BLE001
                pass
            return None, f"Refund script timed out ({script_timeout}s)"
        if proc.returncode != 0:
            stderr_safe = stderr_bytes[:500].decode("utf-8", errors="replace") if stderr_bytes else ""
            logger.error(
                "Refund script failed (exit %d): %s",
                proc.returncode,
                stderr_safe,
            )
            return None, (f"Refund script failed (exit {proc.returncode}): {stderr_safe}")
        stdout_text = stdout_bytes.decode("utf-8", errors="replace")
        try:
            output = json.loads(stdout_text.strip().splitlines()[-1])
        except (ValueError, IndexError):
            return None, (f"Refund script returned invalid JSON: {stdout_text[:500]}")
        txid = output.get("txid")
        if not txid:
            return None, f"Refund script returned no txid: {output}"
        return txid, None

    async def unilateral_refund_submarine(
        self,
        swap: BoltzSwap,
        refund_address: str,
        btc_tip_height: Optional[int],
        lockup_tx_hex: Optional[str] = None,
        fee_rate_sat_vb: Optional[float] = None,
    ) -> tuple[Optional[str], Optional[str]]:
        """Construct and broadcast a unilateral (script-path) submarine refund.

        The post-timeout escape hatch for when Boltz cooperative signing is
        unavailable (e.g. it returns ``cooperative signatures are disabled``).
        Spends the lockup via the swap's refund leaf using only our refund key,
        so it needs no Boltz cooperation — but the leaf carries a
        CHECKLOCKTIMEVERIFY, so it is only spendable once the chain tip has
        reached ``timeout_block_height``. We refuse early (with a clear
        ``blocks remaining`` message) so a premature broadcast can't waste fees
        on a tx the network will reject.

        Returns ``(txid, None)`` on success, ``(None, error)`` on failure. The
        caller transitions the swap row to ``SwapStatus.REFUNDED``.
        """
        if not REFUND_SCRIPT_PATH.exists():
            return None, f"Refund script not found at {REFUND_SCRIPT_PATH}"
        if not swap.claim_private_key_hex:
            return None, "swap is missing the encrypted refund private key"
        if not swap.boltz_swap_tree_json:
            return None, "swap is missing the persisted swap tree"
        if swap.timeout_block_height is None:
            return None, "Swap has no recorded timeout height; cannot verify refund safety."
        if btc_tip_height is None:
            return None, (
                "Chain tip is unavailable; cannot verify the lockup timeout has "
                "passed. Refusing the unilateral refund until the tip is known."
            )
        if btc_tip_height < swap.timeout_block_height:
            blocks_remaining = swap.timeout_block_height - btc_tip_height
            return None, (
                f"Lockup timeout has not passed yet ({blocks_remaining} blocks "
                "remaining); the unilateral refund only becomes valid at the "
                "timeout. The cooperative refund is the only option until then."
            )

        if lockup_tx_hex is None:
            lockup_tx_hex, lookup_err = await self.get_submarine_lockup_transaction(swap.boltz_swap_id)
            if lookup_err or not lockup_tx_hex:
                return None, (f"cannot fetch lockup tx for unilateral refund: {lookup_err}")

        # Same envelope as the cooperative path, minus the claim pubkey
        # (the script-path refund needs no Musig2 co-signing); ``mode`` plus
        # ``currentBlockHeight`` route the JS subprocess to the refund leaf.
        refund_input: dict[str, Any] = {
            "mode": "unilateral",
            "boltzUrl": self._boltz_url,
            "swapId": swap.boltz_swap_id,
            "refundPrivateKey": decrypt_field(swap.claim_private_key_hex),
            "refundPublicKey": swap.claim_public_key_hex,
            "swapTree": swap.boltz_swap_tree_json,
            "lockupTxHex": lockup_tx_hex,
            "refundAddress": refund_address,
            "timeoutBlockHeight": swap.timeout_block_height,
            "currentBlockHeight": btc_tip_height,
            "network": settings.bitcoin_network,
        }
        proxy = self._proxy
        if proxy:
            refund_input["socksProxy"] = proxy
        if fee_rate_sat_vb is not None and fee_rate_sat_vb > 0:
            from app.services.chain.backend import clamp_feerate_sat_per_vb

            clamped = clamp_feerate_sat_per_vb(fee_rate_sat_vb)
            if clamped is not None:
                refund_input["feeRate"] = float(clamped)

        script_timeout = 120 if proxy else 60
        try:
            proc = await asyncio.create_subprocess_exec(
                _NODE_BIN,
                str(REFUND_SCRIPT_PATH),
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(CLAIM_SCRIPT_DIR),
                env=_SUBPROCESS_ENV,
            )
        except FileNotFoundError:
            return None, "Node.js not found for refund script execution"
        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(input=json.dumps(refund_input).encode()),
                timeout=script_timeout,
            )
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            try:
                await proc.wait()
            except Exception:  # noqa: BLE001
                pass
            return None, f"Unilateral refund script timed out ({script_timeout}s)"
        if proc.returncode != 0:
            stderr_safe = stderr_bytes[:500].decode("utf-8", errors="replace") if stderr_bytes else ""
            logger.error(
                "Unilateral refund script failed (exit %d): %s",
                proc.returncode,
                stderr_safe,
            )
            return None, (f"Unilateral refund script failed (exit {proc.returncode}): {stderr_safe}")
        stdout_text = stdout_bytes.decode("utf-8", errors="replace")
        try:
            output = json.loads(stdout_text.strip().splitlines()[-1])
        except (ValueError, IndexError):
            return None, (f"Unilateral refund script returned invalid JSON: {stdout_text[:500]}")
        txid = output.get("txid")
        if not txid:
            return None, f"Unilateral refund script returned no txid: {output}"
        return txid, None

    async def _backfill_claim_txid_from_wallet(self, swap: BoltzSwap) -> None:
        """Best-effort recovery of a reverse-swap ``claim_txid`` that was
        never persisted.

        The cooperative-claim Node subprocess constructs + broadcasts the
        claim atomically; if it broadcasts but then errors (Tor/LND blip),
        :meth:`cooperative_claim` returns an error and ``claim_txid`` is
        left empty even though the tx is on-chain. Boltz then settles the
        invoice (the preimage is on-chain) and the swap reaches COMPLETED
        with no recorded claim.

        The claim pays ``swap.destination_address``. For wallet-controlled
        destinations (Braiins deposit, inbound liquidity) that output is in
        ``list_unspent``, so we can recover the txid. No-op for external
        destinations (cold storage) or an already-spent output — consumers
        tolerate a missing txid. Never raises.
        """
        if swap.claim_txid or not swap.destination_address:
            return
        try:
            from app.services.lnd_service import lnd_service

            utxos, err = await lnd_service.list_unspent(min_confs=0)
            if err or not utxos:
                return
            for u in utxos:
                if u.get("address") != swap.destination_address:
                    continue
                outpoint: Any = u.get("outpoint") or {}
                txid = outpoint.get("txid_str")
                if not txid:
                    continue
                swap.claim_txid = txid
                if not swap.claim_broadcast_at:
                    swap.claim_broadcast_at = _utc_now()
                logger.info(
                    "Swap %s: backfilled claim_txid=%s from wallet UTXO at "
                    "destination (settled without a recorded claim)",
                    swap.boltz_swap_id,
                    txid,
                )
                return
        except Exception as exc:  # noqa: BLE001
            logger.debug(
                "claim_txid backfill failed for %s: %s",
                swap.boltz_swap_id,
                exc,
            )

    async def advance_swap(
        self,
        db: AsyncSession,
        swap: BoltzSwap,
    ) -> tuple[BoltzSwap, Optional[str]]:
        """Check swap status and advance the lifecycle.

        Called by the Celery monitoring task. Handles all state transitions
        from CREATED through COMPLETED, including failure and refund states.
        """
        boltz_status, boltz_data, err = await self.get_swap_status_from_boltz(swap.boltz_swap_id)
        if err:
            logger.warning("Failed to check Boltz status for %s: %s", swap.boltz_swap_id, err)
            return swap, err

        old_boltz_status = swap.boltz_status
        swap.boltz_status = boltz_status
        swap.updated_at = _utc_now()

        if boltz_status != old_boltz_status:
            history = swap.status_history or []
            history.append(
                {
                    "status": swap.status.value,
                    "boltz_status": boltz_status,
                    "timestamp": _utc_now().isoformat(),
                }
            )
            swap.status_history = history

        # Terminal failure states
        if boltz_status in ("invoice.expired", "swap.expired", "transaction.failed"):
            swap.status = SwapStatus.FAILED
            swap.error_message = f"Boltz swap ended: {boltz_status}"
            swap.completed_at = _utc_now()
            logger.warning("Swap %s failed: %s", swap.boltz_swap_id, boltz_status)

        elif boltz_status == "transaction.refunded":
            swap.status = SwapStatus.REFUNDED
            # Reverse-swap semantics (all rows in this table are
            # direction=REVERSE today): the hold-invoice the wallet
            # paid only settles when the preimage is revealed on-chain
            # via our claim. If Boltz refunded the on-chain lockup it
            # means the preimage was never revealed, Boltz cannot
            # settle the hold invoice, and LND will auto-cancel the
            # in-flight HTLC. The user's LN sats stay liquid; no
            # action required.
            swap.error_message = (
                "Boltz refunded the on-chain lockup. The on-chain leg "
                "of this swap did not complete; your Lightning HTLC "
                "will be cancelled and your sats remain in your "
                "channel balance. No further action required."
            )
            swap.completed_at = _utc_now()
            logger.warning(
                "Swap %s was refunded by Boltz (on-chain leg incomplete; LN HTLC will auto-cancel)",
                swap.boltz_swap_id,
            )

        elif boltz_status == "invoice.settled":
            swap.status = SwapStatus.COMPLETED
            # Clear stale transient pay-invoice copy if any.
            if swap.error_message and swap.error_message.startswith("Payment attempt encountered a transient"):
                swap.error_message = None
            swap.completed_at = _utc_now()
            # ``invoice.settled`` can race ahead of the claim branch:
            # the cooperative-claim subprocess may broadcast the claim
            # but then error (Tor/LND blip) before ``claim_txid`` is
            # persisted, and Boltz settles the moment the preimage
            # hits the chain. That leaves a COMPLETED swap with no
            # ``claim_txid`` — which strands consumers that need it
            # (Braiins deposit's ``_project_funded_utxo`` raised).
            # Best-effort backfill the txid from the wallet's own UTXO
            # set so the record is complete. See incident 2026-06-16.
            if not swap.claim_txid:
                await self._backfill_claim_txid_from_wallet(swap)
            logger.info("Swap %s completed successfully", swap.boltz_swap_id)

        # Defensive completion via on-chain confirmation. Boltz
        # reports ``invoice.settled`` once the LN HTLC is settled
        # (which requires our claim to be on-chain). In a healthy
        # Boltz, that report follows the on-chain claim within
        # seconds. But Boltz outages (their status feed has
        # occasional drops) can leave a successful swap stuck in
        # ``CLAIMED`` forever from our perspective — eventually
        # max_retries fires and we'd mark the swap FAILED even
        # though the user already has the on-chain funds.
        #
        # If we have a claim_txid and it has at least 3 chain
        # confirmations (best-effort via the optional electrum
        # backend), promote the swap to COMPLETED regardless of
        # what Boltz is reporting. This is the same threshold the
        # rest of the wallet treats as "settled enough" to count
        # as confirmed.
        elif swap.status == SwapStatus.CLAIMED and swap.claim_txid and boltz_status != "invoice.settled":
            try:
                from app.services.mempool_fee_service import (
                    mempool_fee_service,
                )

                confs = await mempool_fee_service.optional_confirmations(swap.claim_txid)
                if confs and (confs.get("confirmations") or 0) >= 3:
                    swap.status = SwapStatus.COMPLETED
                    swap.completed_at = _utc_now()
                    logger.info(
                        "Swap %s marked complete via on-chain "
                        "confirmation (Boltz settlement not yet "
                        "reported, claim_txid=%s)",
                        swap.boltz_swap_id,
                        swap.claim_txid,
                    )
            except Exception as exc:  # noqa: BLE001
                logger.debug(
                    "swap %s on-chain confirmation check failed: %s",
                    swap.boltz_swap_id,
                    exc,
                )

        # Lockup transaction appeared — attempt claim
        elif boltz_status in ("transaction.mempool", "transaction.confirmed"):
            if swap.status in (SwapStatus.INVOICE_PAID, SwapStatus.PAYING_INVOICE, SwapStatus.CREATED):
                # Clear any transient pay-invoice error message a
                # prior tick may have left on the row — the swap
                # has visibly advanced past PAYING_INVOICE on the
                # Boltz side so the "retrying automatically" copy
                # is no longer accurate.
                if swap.error_message and swap.error_message.startswith("Payment attempt encountered a transient"):
                    swap.error_message = None
                swap.status = SwapStatus.CLAIMING

            # defence-in-depth — independently verify the lockup TX via
            # electrs when available. An unavailable backend or a probe
            # error degrades silently (the cooperative co-signature still
            # constrains the claim), but a *positive* mismatch — electrs
            # reachable and the lockup tx does NOT pay the address
            # committed at swap creation — withholds the claim this tick
            # and surfaces the swap for operator review.
            lockup_addr_mismatch = False
            try:
                lockup_id = None
                tx_block = (boltz_data or {}).get("transaction") or {}
                if isinstance(tx_block, dict):
                    lockup_id = tx_block.get("id")
                if isinstance(lockup_id, str) and len(lockup_id) == 64:
                    # Persist the lockup txid the first time we see it
                    # so the dashboard can surface a Mempool link while
                    # the user waits for it to confirm. Reverse-swap
                    # lockups are broadcast by Boltz, not us — until
                    # this commit they were only referenced in the
                    # ephemeral verification path below.
                    if not swap.lockup_txid:
                        swap.lockup_txid = lockup_id
                    from app.services.mempool_fee_service import (
                        mempool_fee_service,
                    )

                    verified = await mempool_fee_service.optional_verify_tx(lockup_id)
                    if verified is None:
                        logger.debug(
                            "swap %s: lockup %s not independently verified (electrum unavailable or breaker open)",
                            swap.boltz_swap_id,
                            lockup_id,
                        )
                    elif swap.boltz_lockup_address and not _tx_pays_address(verified, swap.boltz_lockup_address):
                        lockup_addr_mismatch = True
                        logger.error(
                            "swap %s: lockup %s does NOT pay expected address %s — withholding claim for review",
                            swap.boltz_swap_id,
                            lockup_id,
                            swap.boltz_lockup_address,
                        )
                    else:
                        logger.info(
                            "swap %s: lockup %s independently verified",
                            swap.boltz_swap_id,
                            lockup_id,
                        )
            except Exception as exc:  # noqa: BLE001
                logger.debug("optional lockup verification failed: %s", exc)

            if lockup_addr_mismatch:
                swap.error_message = (
                    "Independent verification found the Boltz lockup transaction does "
                    "not pay the address committed at swap creation; the claim is "
                    "withheld pending operator review."
                )
                await db.commit()
                return swap, swap.error_message

            if swap.status == SwapStatus.CLAIMING and not swap.claim_txid:
                lockup_hex, lockup_err = await self.get_lockup_transaction(swap.boltz_swap_id)
                if lockup_err:
                    logger.warning("Failed to fetch lockup tx: %s", lockup_err)
                    await db.commit()
                    return swap, lockup_err

                # Concurrent-claim guard. ``advance_swap`` can be
                # invoked simultaneously for the same swap by the
                # user-driven ``process_boltz_swap`` retry task
                # and the periodic ``recover_boltz_swaps`` task.
                # Both could pass the earlier ``status == CLAIMING``
                # gate using the in-memory ``swap`` object loaded
                # at the top of advance_swap — by the time this
                # branch runs (after a Boltz round-trip for the
                # lockup tx), one worker may have already broadcast
                # the claim and written the txid in a separate
                # session. The row is locked ``FOR UPDATE`` (a narrow
                # SELECT on ``claim_txid`` only, so it does not revert
                # the uncommitted in-memory ``status = CLAIMING``
                # transition that ``db.refresh`` would): a second
                # worker blocks here until the first commits its
                # ``claim_txid``, then reads it and aborts the
                # duplicate claim, so only one claim subprocess runs
                # per swap. (On SQLite the lock clause is a no-op; the
                # mempool's double-spend rejection remains the backstop
                # there.)
                pre_claim_existing = (
                    await db.execute(select(BoltzSwap.claim_txid).where(BoltzSwap.id == swap.id).with_for_update())
                ).scalar()
                if pre_claim_existing:
                    logger.info(
                        "Swap %s: another worker already claimed (claim_txid=%s); aborting duplicate claim attempt",
                        swap.boltz_swap_id,
                        pre_claim_existing,
                    )
                    # Promote the in-memory swap to match the DB so
                    # the caller's response payload is accurate.
                    swap.claim_txid = pre_claim_existing
                    swap.status = SwapStatus.CLAIMED
                    return swap, None

                claim_txid, claim_err = await self.cooperative_claim(swap, lockup_hex)  # type: ignore[arg-type]
                if claim_err:
                    logger.error("Claim failed for %s: %s", swap.boltz_swap_id, claim_err)
                    swap.recovery_count = (swap.recovery_count or 0) + 1
                    swap.recovery_attempted_at = _utc_now()
                    await db.commit()
                    return swap, claim_err

                # One more check before persisting — if a concurrent
                # worker broadcast a different claim tx while our
                # subprocess was running, theirs may have won on
                # chain. Keep whichever was already written; the
                # mempool decides which tx confirms.
                post_claim_existing = (
                    await db.execute(select(BoltzSwap.claim_txid).where(BoltzSwap.id == swap.id))
                ).scalar()
                if post_claim_existing:
                    logger.info(
                        "Swap %s: concurrent claim already wrote txid=%s; not overwriting with %s",
                        swap.boltz_swap_id,
                        post_claim_existing,
                        claim_txid,
                    )
                    swap.claim_txid = post_claim_existing
                    swap.status = SwapStatus.CLAIMED
                    return swap, None
                swap.claim_txid = claim_txid
                swap.status = SwapStatus.CLAIMED
                logger.info("Swap %s claimed: txid=%s", swap.boltz_swap_id, claim_txid)

                # Auto-label the resulting UTXO so it shows up in the
                # dashboard's UTXO tab with sensible provenance. The
                # Boltz claim script always sweeps to a single output
                # at index 0. Failures here must not break the swap.
                try:
                    from app.models.utxo_label import UtxoLabel, UtxoLabelSource

                    amt = swap.onchain_amount_sats or swap.invoice_amount_sats
                    # Reached only after the `if claim_err: return` guard
                    # above, so a successful claim always has a txid.
                    assert claim_txid is not None
                    db.add(
                        UtxoLabel(
                            txid=claim_txid.lower(),
                            vout=0,
                            label=f"Loop-out: {amt} sats",
                            source=UtxoLabelSource.AUTO_SWAP,
                        )
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.warning("auto-label for claim %s failed: %s", claim_txid, exc)

        await db.commit()
        return swap, None

    async def recover_pending_swaps(self, db: AsyncSession) -> list[dict]:
        """Recover swaps interrupted by crash/restart."""
        result = await db.execute(
            select(BoltzSwap).where(
                or_(
                    BoltzSwap.status == SwapStatus.CREATED,
                    BoltzSwap.status == SwapStatus.PAYING_INVOICE,
                    BoltzSwap.status == SwapStatus.INVOICE_PAID,
                    BoltzSwap.status == SwapStatus.CLAIMING,
                    BoltzSwap.status == SwapStatus.CLAIMED,
                )
            )
        )
        pending_swaps = result.scalars().all()

        if not pending_swaps:
            return []

        logger.info("Recovering %d pending Boltz swap(s)", len(pending_swaps))
        results = []
        for swap in pending_swaps:
            try:
                # Pre-payment states (CREATED / PAYING_INVOICE) need the full
                # pay driver, not just reconciliation: a swap interrupted at
                # the pay step (worker restart / app redeploy) has no live LN
                # payment, and advance_swap can only poll Boltz — which never
                # progresses because Boltz never saw an HTLC. Re-enqueue
                # process_boltz_swap so its (re-entrant, double-pay-safe) pay
                # step runs. advance_swap alone is right for post-payment
                # states (INVOICE_PAID / CLAIMING / CLAIMED), which only need
                # reconciliation and the claim.
                if swap.status in (SwapStatus.CREATED, SwapStatus.PAYING_INVOICE):
                    from app.tasks.boltz_tasks import process_boltz_swap

                    process_boltz_swap.delay(str(swap.id))
                    results.append(
                        {
                            "boltz_swap_id": swap.boltz_swap_id,
                            "status": swap.status.value,
                            "error": None,
                            "requeued": True,
                        }
                    )
                    continue
                _, err = await self.advance_swap(db, swap)
                results.append(
                    {
                        "boltz_swap_id": swap.boltz_swap_id,
                        "status": swap.status.value,
                        "error": err,
                    }
                )
            except Exception as e:
                logger.error("Recovery failed for %s: %s", swap.boltz_swap_id, e)
                results.append(
                    {
                        "boltz_swap_id": swap.boltz_swap_id,
                        "status": swap.status.value,
                        "error": str(e),
                    }
                )
        return results

    async def get_swap_by_id(self, db: AsyncSession, swap_id: UUID) -> Optional[BoltzSwap]:
        """Fetch a swap by its internal UUID."""
        result = await db.execute(select(BoltzSwap).where(BoltzSwap.id == swap_id))
        return result.scalar_one_or_none()

    async def get_swaps_for_key(
        self,
        db: AsyncSession,
        api_key_id: UUID,
        limit: int = 20,
    ) -> list[BoltzSwap]:
        """Fetch recent swaps for an API key."""
        result = await db.execute(
            select(BoltzSwap)
            .where(BoltzSwap.api_key_id == api_key_id)
            .order_by(BoltzSwap.created_at.desc())
            .limit(limit)
        )
        return list(result.scalars().all())

    async def cancel_swap(
        self,
        db: AsyncSession,
        swap: BoltzSwap,
    ) -> tuple[bool, Optional[str]]:
        """Cancel a swap if still in early stages."""
        if swap.status not in (SwapStatus.CREATED,):
            return False, f"Cannot cancel swap in status '{swap.status.value}'. Only 'created' swaps can be cancelled."

        swap.status = SwapStatus.CANCELLED
        swap.completed_at = _utc_now()
        swap.error_message = "Cancelled by API client"
        history = swap.status_history or []
        history.append({"status": "cancelled", "timestamp": _utc_now().isoformat()})
        swap.status_history = history
        await db.commit()
        logger.info("Swap %s cancelled", swap.boltz_swap_id)
        return True, None


boltz_service = BoltzSwapService()
