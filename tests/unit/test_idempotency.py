# SPDX-License-Identifier: MIT
"""Unit tests for :mod:`app.core.idempotency`.

These cover the Redis-backed Idempotency-Key reservation logic used
by money-moving endpoints. They pin the contracts called out in
:

* — atomic reservation: a TTL-expiry race between two
  concurrent retries must never let both callers execute.
* — fingerprint comparison must use ``hmac.compare_digest``
  so a malicious caller cannot infer the stored fingerprint via
  response timing on repeated 409 probes.

The module is mocked end-to-end against a fake Redis client; no real
Redis instance is required.
"""

from __future__ import annotations

import hmac
import json
import logging
import threading
import time
from typing import Any, Optional
from unittest.mock import patch

import pytest
from fastapi import HTTPException

from app.core import idempotency


class _FakeRedis:
    """Minimal in-memory Redis emulator covering ``set(nx, ex)`` /
    ``get`` semantics used by :func:`lookup_or_reserve` /
    :func:`store_result`.

    Implements the SETNX+TTL semantics deterministically so race
    tests don't depend on wall-clock timing.
    """

    def __init__(self) -> None:
        self._store: dict[str, tuple[str, Optional[float]]] = {}
        self._lock = threading.Lock()

    def _expired(self, key: str) -> bool:
        entry = self._store.get(key)
        if entry is None:
            return True
        _, exp = entry
        return exp is not None and exp <= time.time()

    def set(
        self,
        key: str,
        value: str,
        *,
        nx: bool = False,
        ex: Optional[int] = None,
    ) -> Optional[bool]:
        with self._lock:
            if nx and not self._expired(key):
                return None
            exp = time.time() + ex if ex is not None else None
            self._store[key] = (value, exp)
            return True

    def get(self, key: str) -> Optional[bytes]:
        with self._lock:
            if self._expired(key):
                self._store.pop(key, None)
                return None
            return self._store[key][0].encode("utf-8")

    def eval(self, script: str, _numkeys: int, key: str, *argv: Any) -> Optional[bytes]:
        """Emulate the Lua scripts used by the idempotency module.

        ``string.find`` only appears in the compare-and-set store script;
        everything else is the atomic get-or-claim reservation.
        """
        with self._lock:
            if "string.find" in script:
                # store: (payload, ttl, sentinel) — write only when the
                # slot is absent or still holds an in-flight marker.
                payload, ttl, sentinel = argv[0], argv[1], argv[2]
                existing = None if self._expired(key) else self._store[key][0]
                if existing is None or sentinel in existing:
                    self._store[key] = (payload, time.time() + int(ttl))
                    return 1
                return 0
            # reserve: (marker, ttl)
            marker, ttl = argv[0], argv[1]
            if not self._expired(key):
                return self._store[key][0].encode("utf-8")
            self._store[key] = (marker, time.time() + int(ttl))
            return None

    def delete(self, key: str) -> int:
        with self._lock:
            return 1 if self._store.pop(key, None) is not None else 0

    def expire(self, key: str) -> None:
        """Test helper: force-expire ``key``."""
        with self._lock:
            if key in self._store:
                value, _ = self._store[key]
                self._store[key] = (value, time.time() - 1)


@pytest.fixture()
def fake_redis(monkeypatch: pytest.MonkeyPatch) -> _FakeRedis:
    """Patch :func:`idempotency._redis_client` to return a shared
    ``_FakeRedis`` so calls within a single test see the same state.
    """
    client = _FakeRedis()
    monkeypatch.setattr(idempotency, "_redis_client", lambda: client)
    return client


# ── happy paths ────────────────────────────────────────────────────


def test_lookup_or_reserve_first_caller_reserves_slot(
    fake_redis: _FakeRedis,
) -> None:
    """The first caller for a fresh key must get ``None`` (execute)
    and the slot must be marked in-flight afterwards."""
    out = idempotency.lookup_or_reserve(
        api_key_id="k1",
        idem_key="11111111-1111-1111-1111-111111111111",
        request_body={"amt": 1000},
    )
    assert out is None
    raw = fake_redis.get(idempotency._redis_key("k1", "11111111-1111-1111-1111-111111111111"))
    assert raw is not None
    assert json.loads(raw)["state"] == "inflight"


def test_lookup_or_reserve_honours_per_request_inflight_ttl(
    fake_redis: _FakeRedis,
) -> None:
    """The in-flight marker's lifetime follows the caller-supplied
    ``inflight_ttl`` so it outlives the operation it guards."""
    before = time.time()
    idempotency.lookup_or_reserve(
        api_key_id="k1",
        idem_key="22222222-2222-2222-2222-222222222222",
        request_body={"amt": 1000},
        inflight_ttl=300,
    )
    key = idempotency._redis_key("k1", "22222222-2222-2222-2222-222222222222")
    _value, expiry = fake_redis._store[key]
    assert expiry is not None
    assert expiry - before >= 300 - 1


def test_store_result_does_not_overwrite_completed_slot(
    fake_redis: _FakeRedis,
) -> None:
    """Once a slot holds a completed response, a second ``store_result``
    for the same key leaves the first response in place — a slow finisher
    whose reservation was reclaimed cannot clobber a newer cached result."""
    key_id, idem = "k1", "33333333-3333-3333-3333-333333333333"
    body = {"amt": 1000}
    idempotency.lookup_or_reserve(api_key_id=key_id, idem_key=idem, request_body=body)
    idempotency.store_result(api_key_id=key_id, idem_key=idem, request_body=body, response={"txid": "first"})
    # A second completion attempt must not replace the stored response.
    idempotency.store_result(api_key_id=key_id, idem_key=idem, request_body=body, response={"txid": "second"})
    raw = fake_redis.get(idempotency._redis_key(key_id, idem))
    assert raw is not None
    assert json.loads(raw)["response"] == {"txid": "first"}


def test_default_inflight_ttl_covers_max_payment_timeout() -> None:
    """The default in-flight TTL must exceed the longest payment timeout
    (``timeout_seconds`` ceiling of 300 s) so a slow payment's marker
    cannot lapse mid-flight and let a retry double-execute."""
    assert idempotency._INFLIGHT_TTL >= 300


def test_lookup_or_reserve_replay_with_same_body_returns_cached(
    fake_redis: _FakeRedis,
) -> None:
    """After ``store_result``, a replay with the SAME body must
    receive the cached response."""
    body = {"amt": 1000}
    idempotency.lookup_or_reserve(
        api_key_id="k1",
        idem_key="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        request_body=body,
    )
    idempotency.store_result(
        api_key_id="k1",
        idem_key="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        request_body=body,
        response={"ok": True},
    )
    out = idempotency.lookup_or_reserve(
        api_key_id="k1",
        idem_key="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        request_body=body,
    )
    assert out == {"ok": True}


def test_lookup_or_reserve_replay_with_different_body_returns_409(
    fake_redis: _FakeRedis,
) -> None:
    """Same key, different body → IETF idempotency-draft 409."""
    idempotency.lookup_or_reserve(
        api_key_id="k1",
        idem_key="bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
        request_body={"amt": 1000},
    )
    idempotency.store_result(
        api_key_id="k1",
        idem_key="bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
        request_body={"amt": 1000},
        response={"ok": True},
    )
    with pytest.raises(HTTPException) as exc:
        idempotency.lookup_or_reserve(
            api_key_id="k1",
            idem_key="bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            request_body={"amt": 999},
        )
    assert exc.value.status_code == 409
    assert "different request body" in exc.value.detail


def test_lookup_or_reserve_inflight_marker_returns_409(
    fake_redis: _FakeRedis,
) -> None:
    """Concurrent retry against an in-flight key returns 409 even
    when the body fingerprints match (state=inflight, not
    completed)."""
    body = {"amt": 1000}
    idempotency.lookup_or_reserve(
        api_key_id="k1",
        idem_key="cccccccc-cccc-cccc-cccc-cccccccccccc",
        request_body=body,
    )
    with pytest.raises(HTTPException) as exc:
        idempotency.lookup_or_reserve(
            api_key_id="k1",
            idem_key="cccccccc-cccc-cccc-cccc-cccccccccccc",
            request_body=body,
        )
    assert exc.value.status_code == 409
    assert "in flight" in exc.value.detail


def test_get_idempotency_key_rejects_non_uuid() -> None:
    from fastapi import Request

    scope = {
        "type": "http",
        "method": "POST",
        "headers": [(b"idempotency-key", b"not-a-uuid")],
    }
    request = Request(scope)
    with pytest.raises(HTTPException) as exc:
        idempotency.get_idempotency_key(request)
    assert exc.value.status_code == 400


# ──: constant-time fingerprint compare ─────────────────────────


def test_lookup_or_reserve_fingerprint_compare_uses_compare_digest(
    fake_redis: _FakeRedis,
) -> None:
    """The replay-conflict fingerprint check must route through
    ``hmac.compare_digest`` so timing-side-channel probes cannot
    extract the stored fingerprint byte-by-byte.

    Asserted by patching :func:`hmac.compare_digest` and checking
    it was called with the stored and submitted fingerprints.
    """
    idempotency.lookup_or_reserve(
        api_key_id="k1",
        idem_key="dddddddd-dddd-dddd-dddd-dddddddddddd",
        request_body={"amt": 1000},
    )
    idempotency.store_result(
        api_key_id="k1",
        idem_key="dddddddd-dddd-dddd-dddd-dddddddddddd",
        request_body={"amt": 1000},
        response={"ok": True},
    )

    calls: list[tuple[str, str]] = []
    real = hmac.compare_digest

    def _spy(a: Any, b: Any) -> bool:
        calls.append((str(a), str(b)))
        return real(a, b)

    with patch.object(idempotency.hmac, "compare_digest", _spy):
        with pytest.raises(HTTPException):
            idempotency.lookup_or_reserve(
                api_key_id="k1",
                idem_key="dddddddd-dddd-dddd-dddd-dddddddddddd",
                request_body={"amt": 999},
            )

    assert calls, "compare_digest was never called on the fingerprint compare path"
    # Both args must be hex digests (sha256 → 64 hex chars).
    a, b = calls[-1]
    assert len(a) == 64 and len(b) == 64
    assert a != b


# ──: TTL-race reservation atomicity ────────────────────────────


def test_lookup_or_reserve_race_after_setnx_expiry_only_one_executes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two concurrent retries
    against an expired slot must not both be authorised to
    execute. The Lua-script reservation collapses "get-or-claim"
    into one atomic Redis call, eliminating the SETNX+GET
    interleaving window that previously let two callers slip
    through.

    We inject a fake client whose ``eval`` returns ``None`` (slot
    fresh) for the FIRST caller and the just-installed marker for
    the second caller — exactly what the real Lua script would do
    under contention. The pre-fix code path did not call ``eval``
    at all, so this test additionally guards against a regression
    that drops Lua and falls back to the racy SETNX+GET.
    """

    class _AtomicClient:
        def __init__(self) -> None:
            self._lock = threading.Lock()
            self._store: dict[str, str] = {}

        def eval(self, _script: str, _numkeys: int, key: str, marker: str, _ttl: int) -> Optional[bytes]:
            # Emulate the Lua semantics: atomically get-or-claim.
            with self._lock:
                existing = self._store.get(key)
                if existing is not None:
                    return existing.encode("utf-8")
                self._store[key] = marker
                return None

        def get(self, key: str) -> Optional[bytes]:
            val = self._store.get(key)
            return val.encode("utf-8") if val is not None else None

        def set(self, *_a: Any, **_kw: Any) -> None:
            raise AssertionError(
                "set() must not be called — the fix routes "
                "reservation through eval() to keep it atomic. "
                "If you see this, the racy SETNX fallback has "
                "been resurrected."
            )

    client = _AtomicClient()
    monkeypatch.setattr(idempotency, "_redis_client", lambda: client)

    barrier = threading.Barrier(2)
    results: list[Any] = []
    errors: list[BaseException] = []

    def _worker() -> None:
        try:
            barrier.wait()
            results.append(
                idempotency.lookup_or_reserve(
                    api_key_id="k1",
                    idem_key="eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee",
                    request_body={"amt": 1000},
                )
            )
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    t1 = threading.Thread(target=_worker)
    t2 = threading.Thread(target=_worker)
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    # The "in flight" branch raises 409 — that's the expected
    # outcome for the LOSING caller. Filter those out before
    # counting executes.
    none_count = sum(1 for r in results if r is None)
    http_errors = [e for e in errors if isinstance(e, HTTPException)]
    other_errors = [e for e in errors if not isinstance(e, HTTPException)]

    assert not other_errors, f"unexpected exceptions: {other_errors!r}"
    assert none_count == 1, (
        f": exactly one caller must be authorised to execute; got {none_count} (results={results!r})"
    )
    assert len(http_errors) == 1, (
        f": exactly one caller must hit the in-flight 409; "
        f"got {len(http_errors)} (results={results!r}, errors={errors!r})"
    )
    assert http_errors[0].status_code == 409


def test_lookup_or_reserve_fails_closed_when_eval_unsupported(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Against a Redis that doesn't support EVAL, the atomic
    reserve-or-return primitive is unavailable. The non-atomic fallback
    has a double-execute window on a money-moving reservation, so
    ``lookup_or_reserve`` fails closed (503) and logs the cause."""

    class _NoEvalClient:
        def eval(self, *_a: Any, **_kw: Any) -> None:
            raise RuntimeError("ERR command 'EVAL' is not allowed")

        def set(self, *_a: Any, **_kw: Any) -> Optional[bool]:  # pragma: no cover - must not be reached
            raise AssertionError("non-atomic fallback must not run")

        def get(self, *_a: Any, **_kw: Any) -> Optional[bytes]:  # pragma: no cover - must not be reached
            raise AssertionError("non-atomic fallback must not run")

    client = _NoEvalClient()
    monkeypatch.setattr(idempotency, "_redis_client", lambda: client)
    caplog.set_level(logging.ERROR, logger="app.core.idempotency")

    with pytest.raises(HTTPException) as exc:
        idempotency.lookup_or_reserve(
            api_key_id="k1",
            idem_key="11111111-2222-3333-4444-555555555555",
            request_body={"amt": 1},
        )
    assert exc.value.status_code == 503
    assert any("EVAL unavailable" in r.getMessage() for r in caplog.records)


def test_lookup_or_reserve_no_redis_fails_closed_by_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With the default fail-closed policy an unavailable store returns
    503 so a retry cannot double-execute the protected operation."""
    from app.core.config import settings

    monkeypatch.setattr(idempotency, "_redis_client", lambda: None)
    monkeypatch.setattr(settings, "rate_limit_fail_policy", "closed")
    with pytest.raises(HTTPException) as exc:
        idempotency.lookup_or_reserve(
            api_key_id="k1",
            idem_key="ffffffff-ffff-ffff-ffff-ffffffffffff",
            request_body={"amt": 1},
        )
    assert exc.value.status_code == 503


def test_lookup_or_reserve_redis_dies_midop_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A store that connects but then errors mid-operation fails closed
    under the default policy (does not silently pass through)."""
    from app.core.config import settings

    class _DyingClient:
        def eval(self, *a, **k):
            raise ConnectionError("redis dropped mid-operation")

        def set(self, *a, **k):
            raise ConnectionError("redis dropped mid-operation")

        def get(self, *a, **k):
            raise ConnectionError("redis dropped mid-operation")

    monkeypatch.setattr(idempotency, "_redis_client", lambda: _DyingClient())
    monkeypatch.setattr(settings, "rate_limit_fail_policy", "closed")
    with pytest.raises(HTTPException) as exc:
        idempotency.lookup_or_reserve(
            api_key_id="k1",
            idem_key="ffffffff-ffff-ffff-ffff-ffffffffffff",
            request_body={"amt": 1},
        )
    assert exc.value.status_code == 503


def test_lookup_or_reserve_no_redis_passes_through_when_open(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Under the ``open`` policy an unavailable store degrades to a
    no-op (no idempotency protection) rather than blocking traffic."""
    from app.core.config import settings

    monkeypatch.setattr(idempotency, "_redis_client", lambda: None)
    monkeypatch.setattr(settings, "rate_limit_fail_policy", "open")
    out = idempotency.lookup_or_reserve(
        api_key_id="k1",
        idem_key="ffffffff-ffff-ffff-ffff-ffffffffffff",
        request_body={"amt": 1},
    )
    assert out is None


def test_store_result_no_redis_no_raise(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(idempotency, "_redis_client", lambda: None)
    idempotency.store_result(
        api_key_id="k1",
        idem_key="ffffffff-ffff-ffff-ffff-ffffffffffff",
        request_body={},
        response={"ok": True},
    )


# ── pending-slot reconciliation (ambiguous send outcomes) ──────────


def test_mark_pending_records_payment_hash_and_holds_slot(
    fake_redis: _FakeRedis,
) -> None:
    """An ambiguous send converts the reservation into a pending slot that
    records the payment hash and is recognised by ``peek``."""
    key_id, idem = "k1", "10101010-1010-1010-1010-101010101010"
    body = {"amt": 1000}
    idempotency.lookup_or_reserve(api_key_id=key_id, idem_key=idem, request_body=body)
    idempotency.mark_pending(api_key_id=key_id, idem_key=idem, request_body=body, payment_hash="deadbeef")
    record = idempotency.peek(api_key_id=key_id, idem_key=idem)
    assert record is not None
    assert record["state"] == "pending"
    assert record["payment_hash"] == "deadbeef"


def test_pending_slot_returns_409_on_retry(
    fake_redis: _FakeRedis,
) -> None:
    """A same-key retry against a pending slot is rejected with 409 rather
    than re-executing the money-moving operation."""
    key_id, idem = "k1", "20202020-2020-2020-2020-202020202020"
    body = {"amt": 1000}
    idempotency.lookup_or_reserve(api_key_id=key_id, idem_key=idem, request_body=body)
    idempotency.mark_pending(api_key_id=key_id, idem_key=idem, request_body=body, payment_hash="abc")
    with pytest.raises(HTTPException) as exc:
        idempotency.lookup_or_reserve(api_key_id=key_id, idem_key=idem, request_body=body)
    assert exc.value.status_code == 409
    assert "in flight" in exc.value.detail


def test_release_inflight_does_not_drop_pending_slot(
    fake_redis: _FakeRedis,
) -> None:
    """``release_inflight`` must leave a pending slot intact so an unknown
    outcome cannot be retried into a double-send before reconciliation."""
    key_id, idem = "k1", "30303030-3030-3030-3030-303030303030"
    body = {"amt": 1000}
    idempotency.lookup_or_reserve(api_key_id=key_id, idem_key=idem, request_body=body)
    idempotency.mark_pending(api_key_id=key_id, idem_key=idem, request_body=body, payment_hash="abc")
    idempotency.release_inflight(api_key_id=key_id, idem_key=idem)
    record = idempotency.peek(api_key_id=key_id, idem_key=idem)
    assert record is not None and record["state"] == "pending"


def test_release_pending_clears_slot_for_retry(
    fake_redis: _FakeRedis,
) -> None:
    """Once an operation is known to have failed, ``release_pending`` drops
    the slot so the client can retry."""
    key_id, idem = "k1", "40404040-4040-4040-4040-404040404040"
    body = {"amt": 1000}
    idempotency.lookup_or_reserve(api_key_id=key_id, idem_key=idem, request_body=body)
    idempotency.mark_pending(api_key_id=key_id, idem_key=idem, request_body=body, payment_hash="abc")
    idempotency.release_pending(api_key_id=key_id, idem_key=idem)
    assert idempotency.peek(api_key_id=key_id, idem_key=idem) is None
    # A fresh reservation now succeeds.
    out = idempotency.lookup_or_reserve(api_key_id=key_id, idem_key=idem, request_body=body)
    assert out is None


def test_store_result_overwrites_pending_slot(
    fake_redis: _FakeRedis,
) -> None:
    """A settled outcome resolves a pending slot to a completed result so a
    retry returns the result instead of re-sending."""
    key_id, idem = "k1", "50505050-5050-5050-5050-505050505050"
    body = {"amt": 1000}
    idempotency.lookup_or_reserve(api_key_id=key_id, idem_key=idem, request_body=body)
    idempotency.mark_pending(api_key_id=key_id, idem_key=idem, request_body=body, payment_hash="abc")
    idempotency.store_result(api_key_id=key_id, idem_key=idem, request_body=body, response={"payment_hash": "abc"})
    out = idempotency.lookup_or_reserve(api_key_id=key_id, idem_key=idem, request_body=body)
    assert out == {"payment_hash": "abc"}


# ── corrupt / unexpected slot contents ─────────────────────────────


def test_lookup_or_reserve_corrupt_cache_falls_through_to_execute(
    fake_redis: _FakeRedis,
) -> None:
    """A slot holding non-JSON bytes is treated as absent: the caller is
    authorised to execute rather than crash on the decode."""
    key = idempotency._redis_key("k1", "60606060-6060-6060-6060-606060606060")
    fake_redis.set(key, "}{not json", ex=60)
    out = idempotency.lookup_or_reserve(
        api_key_id="k1",
        idem_key="60606060-6060-6060-6060-606060606060",
        request_body={"amt": 1},
    )
    assert out is None


def test_lookup_or_reserve_unknown_state_returns_none(
    fake_redis: _FakeRedis,
) -> None:
    """A slot in neither completed/inflight/pending (matching fingerprint)
    falls through to re-execute rather than returning a stale payload."""
    body = {"amt": 1}
    fp = idempotency._fingerprint(body)
    key = idempotency._redis_key("k1", "70707070-7070-7070-7070-707070707070")
    fake_redis.set(key, json.dumps({"state": "weird", "fp": fp}), ex=60)
    out = idempotency.lookup_or_reserve(
        api_key_id="k1",
        idem_key="70707070-7070-7070-7070-707070707070",
        request_body=body,
    )
    assert out is None


# ── store_result fallback when EVAL is unavailable ─────────────────


def test_store_result_falls_back_to_set_when_eval_unavailable() -> None:
    """On a Redis without EVAL, ``store_result`` writes the result with a
    plain ``SET`` so successful responses are still cached."""
    written: dict[str, Any] = {}

    class _NoEvalSetClient:
        def eval(self, *_a: Any, **_kw: Any) -> None:
            raise RuntimeError("ERR EVAL not allowed")

        def set(self, key: str, value: str, ex: Optional[int] = None) -> bool:
            written["key"] = key
            written["value"] = value
            written["ex"] = ex
            return True

    with patch.object(idempotency, "_redis_client", lambda: _NoEvalSetClient()):
        idempotency.store_result(
            api_key_id="k1",
            idem_key="80808080-8080-8080-8080-808080808080",
            request_body={"amt": 1},
            response={"ok": True},
        )
    assert written["ex"] == idempotency._TTL_SECONDS
    assert json.loads(written["value"])["response"] == {"ok": True}


# ── release_inflight / release_pending state guards ────────────────


def test_release_inflight_clears_only_inflight_slot(
    fake_redis: _FakeRedis,
) -> None:
    """A terminal failure drops the in-flight marker so the client can
    retry; a fresh reservation then succeeds."""
    key_id, idem = "k1", "90909090-9090-9090-9090-909090909090"
    body = {"amt": 1}
    idempotency.lookup_or_reserve(api_key_id=key_id, idem_key=idem, request_body=body)
    idempotency.release_inflight(api_key_id=key_id, idem_key=idem)
    assert idempotency.peek(api_key_id=key_id, idem_key=idem) is None
    assert idempotency.lookup_or_reserve(api_key_id=key_id, idem_key=idem, request_body=body) is None


def test_release_inflight_leaves_completed_slot_untouched(
    fake_redis: _FakeRedis,
) -> None:
    """``release_inflight`` must not drop a completed result slot."""
    key_id, idem = "k1", "a1a1a1a1-a1a1-a1a1-a1a1-a1a1a1a1a1a1"
    body = {"amt": 1}
    idempotency.lookup_or_reserve(api_key_id=key_id, idem_key=idem, request_body=body)
    idempotency.store_result(api_key_id=key_id, idem_key=idem, request_body=body, response={"ok": True})
    idempotency.release_inflight(api_key_id=key_id, idem_key=idem)
    record = idempotency.peek(api_key_id=key_id, idem_key=idem)
    assert record is not None and record["state"] == "completed"


def test_release_inflight_no_record_is_noop(fake_redis: _FakeRedis) -> None:
    """Releasing a key that has no slot is a safe no-op."""
    idempotency.release_inflight(api_key_id="k1", idem_key="b2b2b2b2-b2b2-b2b2-b2b2-b2b2b2b2b2b2")


def test_release_pending_leaves_non_pending_slot(fake_redis: _FakeRedis) -> None:
    """``release_pending`` only drops a pending slot; an in-flight
    reservation is left in place."""
    key_id, idem = "k1", "c3c3c3c3-c3c3-c3c3-c3c3-c3c3c3c3c3c3"
    body = {"amt": 1}
    idempotency.lookup_or_reserve(api_key_id=key_id, idem_key=idem, request_body=body)
    idempotency.release_pending(api_key_id=key_id, idem_key=idem)
    record = idempotency.peek(api_key_id=key_id, idem_key=idem)
    assert record is not None and record["state"] == "inflight"


def test_release_pending_no_record_is_noop(fake_redis: _FakeRedis) -> None:
    idempotency.release_pending(api_key_id="k1", idem_key="d4d4d4d4-d4d4-d4d4-d4d4-d4d4d4d4d4d4")


# ── no-Redis no-ops for the auxiliary helpers ──────────────────────


def test_peek_no_redis_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(idempotency, "_redis_client", lambda: None)
    assert idempotency.peek(api_key_id="k1", idem_key="e5e5e5e5-e5e5-e5e5-e5e5-e5e5e5e5e5e5") is None


def test_peek_corrupt_slot_returns_none(fake_redis: _FakeRedis) -> None:
    """A corrupt slot makes ``peek`` swallow the decode error and return
    ``None`` rather than propagate."""
    key = idempotency._redis_key("k1", "f6f6f6f6-f6f6-f6f6-f6f6-f6f6f6f6f6f6")
    fake_redis.set(key, "}{nope", ex=60)
    assert idempotency.peek(api_key_id="k1", idem_key="f6f6f6f6-f6f6-f6f6-f6f6-f6f6f6f6f6f6") is None


def test_mark_pending_no_redis_is_noop(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(idempotency, "_redis_client", lambda: None)
    idempotency.mark_pending(
        api_key_id="k1",
        idem_key="07070707-0707-0707-0707-070707070707",
        request_body={},
        payment_hash="abc",
    )


def test_release_inflight_no_redis_is_noop(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(idempotency, "_redis_client", lambda: None)
    idempotency.release_inflight(api_key_id="k1", idem_key="18181818-1818-1818-1818-181818181818")


def test_release_pending_no_redis_is_noop(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(idempotency, "_redis_client", lambda: None)
    idempotency.release_pending(api_key_id="k1", idem_key="29292929-2929-2929-2929-292929292929")


# ── pure-helper branches ───────────────────────────────────────────


def test_validate_key_accepts_uuid_returns_value() -> None:
    """A well-formed UUID is returned unchanged by ``_validate_key``."""
    raw = "3a3a3a3a-3a3a-3a3a-3a3a-3a3a3a3a3a3a"
    assert idempotency._validate_key(raw) == raw


def test_get_idempotency_key_returns_none_without_header() -> None:
    """A request lacking the header yields ``None`` (idempotency opt-in)."""
    from fastapi import Request

    request = Request({"type": "http", "method": "POST", "headers": []})
    assert idempotency.get_idempotency_key(request) is None


def test_fingerprint_falls_back_to_repr_for_unserialisable_body() -> None:
    """A body that ``json.dumps`` cannot serialise even with ``default=str``
    falls back to ``repr`` so fingerprinting never raises."""

    class _Unserialisable:
        def __repr__(self) -> str:
            return "<unserialisable>"

        # Force json.dumps to fail: a dict key that is not a primitive and
        # whose default=str still leaves a non-string key raises TypeError.
        def __iter__(self):  # pragma: no cover - structural only
            raise TypeError("nope")

    body = {("tuple", "key"): _Unserialisable()}
    fp = idempotency._fingerprint(body)
    assert len(fp) == 64  # sha256 hex digest


# ── corrupt-slot tolerance in the release helpers ──────────────────


def test_release_inflight_tolerates_corrupt_slot(fake_redis: _FakeRedis) -> None:
    """A corrupt (non-JSON) slot is left untouched by ``release_inflight``
    rather than raising on the decode."""
    key = idempotency._redis_key("k1", "4b4b4b4b-4b4b-4b4b-4b4b-4b4b4b4b4b4b")
    fake_redis.set(key, "}{garbage", ex=60)
    idempotency.release_inflight(api_key_id="k1", idem_key="4b4b4b4b-4b4b-4b4b-4b4b-4b4b4b4b4b4b")
    assert fake_redis.get(key) is not None


def test_release_pending_tolerates_corrupt_slot(fake_redis: _FakeRedis) -> None:
    """A corrupt slot is left untouched by ``release_pending``."""
    key = idempotency._redis_key("k1", "5c5c5c5c-5c5c-5c5c-5c5c-5c5c5c5c5c5c")
    fake_redis.set(key, "}{garbage", ex=60)
    idempotency.release_pending(api_key_id="k1", idem_key="5c5c5c5c-5c5c-5c5c-5c5c-5c5c5c5c5c5c")
    assert fake_redis.get(key) is not None


def test_store_result_skips_unserialisable_response() -> None:
    """A response that cannot be JSON-encoded is silently dropped (the slot
    is not written) rather than raising out of the best-effort store."""
    writes: list[Any] = []

    class _RecordingClient:
        def eval(self, *_a: Any, **_kw: Any) -> int:
            writes.append("eval")
            return 1

        def set(self, *_a: Any, **_kw: Any) -> bool:
            writes.append("set")
            return True

    class _Boom:
        def __repr__(self) -> str:
            raise RuntimeError("cannot stringify")

    with patch.object(idempotency, "_redis_client", lambda: _RecordingClient()):
        idempotency.store_result(
            api_key_id="k1",
            idem_key="6d6d6d6d-6d6d-6d6d-6d6d-6d6d6d6d6d6d",
            request_body={},
            response={"bad": _Boom()},
        )
    assert writes == []  # encode failed before any Redis write


# ── bytes-valued slots (real redis returns bytes, not str) ─────────


def test_lookup_or_reserve_decodes_bytes_slot(monkeypatch: pytest.MonkeyPatch) -> None:
    """A real Redis client returns ``bytes`` from ``eval``; the cached
    completed response must still be decoded and returned."""
    body = {"amt": 1}
    fp = idempotency._fingerprint(body)
    completed = json.dumps({"state": "completed", "fp": fp, "response": {"ok": True}}).encode("utf-8")

    class _BytesClient:
        def eval(self, *_a: Any, **_kw: Any) -> bytes:
            return completed

    monkeypatch.setattr(idempotency, "_redis_client", lambda: _BytesClient())
    out = idempotency.lookup_or_reserve(
        api_key_id="k1",
        idem_key="7e7e7e7e-7e7e-7e7e-7e7e-7e7e7e7e7e7e",
        request_body=body,
    )
    assert out == {"ok": True}


def test_peek_decodes_bytes_slot(monkeypatch: pytest.MonkeyPatch) -> None:
    """``peek`` decodes a ``bytes`` payload from a real Redis client."""
    payload = json.dumps({"state": "pending", "payment_hash": "abc"}).encode("utf-8")

    class _BytesGetClient:
        def get(self, *_a: Any, **_kw: Any) -> bytes:
            return payload

    monkeypatch.setattr(idempotency, "_redis_client", lambda: _BytesGetClient())
    record = idempotency.peek(api_key_id="k1", idem_key="8f8f8f8f-8f8f-8f8f-8f8f-8f8f8f8f8f8f")
    assert record is not None and record["payment_hash"] == "abc"


# ── best-effort helpers swallow mid-op store errors ────────────────


def test_mark_pending_swallows_store_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """``mark_pending`` is best-effort: an error from the store is logged
    and swallowed, never raised into the caller's terminal path."""

    class _DyingClient:
        def eval(self, *_a: Any, **_kw: Any) -> None:
            raise ConnectionError("redis dropped")

    monkeypatch.setattr(idempotency, "_redis_client", lambda: _DyingClient())
    idempotency.mark_pending(
        api_key_id="k1",
        idem_key="9a9a9a9a-9a9a-9a9a-9a9a-9a9a9a9a9a9a",
        request_body={},
        payment_hash="abc",
    )


def test_release_inflight_swallows_store_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """``release_inflight`` swallows a mid-op store error."""

    class _DyingClient:
        def get(self, *_a: Any, **_kw: Any) -> None:
            raise ConnectionError("redis dropped")

    monkeypatch.setattr(idempotency, "_redis_client", lambda: _DyingClient())
    idempotency.release_inflight(api_key_id="k1", idem_key="abababab-abab-abab-abab-abababababab")


def test_release_pending_swallows_store_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """``release_pending`` swallows a mid-op store error."""

    class _DyingClient:
        def get(self, *_a: Any, **_kw: Any) -> None:
            raise ConnectionError("redis dropped")

    monkeypatch.setattr(idempotency, "_redis_client", lambda: _DyingClient())
    idempotency.release_pending(api_key_id="k1", idem_key="bcbcbcbc-bcbc-bcbc-bcbc-bcbcbcbcbcbc")


def test_lookup_or_reserve_unexpected_error_after_reserve_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unexpected (non-HTTP) error raised while decoding the slot is
    caught and converted to the fail-closed 503 under the default policy,
    rather than leaking as a 500."""
    from app.core.config import settings

    # eval returns a slot whose JSON decodes to a non-dict, so the
    # subsequent ``.get`` attribute access raises AttributeError inside
    # the try block — exercising the broad mid-op failure handler.
    class _OddClient:
        def eval(self, *_a: Any, **_kw: Any) -> bytes:
            return b"12345"  # valid JSON, decodes to int (no .get)

    monkeypatch.setattr(idempotency, "_redis_client", lambda: _OddClient())
    monkeypatch.setattr(settings, "rate_limit_fail_policy", "closed")
    with pytest.raises(HTTPException) as exc:
        idempotency.lookup_or_reserve(
            api_key_id="k1",
            idem_key="cdcdcdcd-cdcd-cdcd-cdcd-cdcdcdcdcdcd",
            request_body={"amt": 1},
        )
    assert exc.value.status_code == 503


def test_redis_client_builds_from_settings_url(monkeypatch: pytest.MonkeyPatch) -> None:
    """``_redis_client`` constructs a client from the configured URL with a
    bounded socket timeout when the ``redis`` package is importable."""
    import sys
    import types

    built: dict[str, Any] = {}

    class _FakeRedisCls:
        @classmethod
        def from_url(cls, url: str, socket_timeout: float | None = None) -> object:
            built["url"] = url
            built["socket_timeout"] = socket_timeout
            return object()

    fake_module = types.SimpleNamespace(Redis=_FakeRedisCls)
    monkeypatch.setitem(sys.modules, "redis", fake_module)  # type: ignore[arg-type]
    client = idempotency._redis_client()
    assert client is not None
    assert built["socket_timeout"] == 2.0


def test_redis_client_returns_none_when_redis_unimportable(monkeypatch: pytest.MonkeyPatch) -> None:
    """If the ``redis`` package cannot be imported, ``_redis_client``
    degrades to ``None`` rather than raising."""
    import builtins

    real_import = builtins.__import__

    def _no_redis(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "redis":
            raise ImportError("no redis")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _no_redis)
    assert idempotency._redis_client() is None


def test_store_result_swallows_unexpected_store_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """``store_result`` is best-effort: an unexpected error from building the
    fingerprint is logged and swallowed, never raised into the caller."""

    class _Client:
        pass

    def _boom(_b: Any) -> str:
        raise RuntimeError("boom")

    monkeypatch.setattr(idempotency, "_redis_client", lambda: _Client())
    monkeypatch.setattr(idempotency, "_fingerprint", _boom)
    idempotency.store_result(
        api_key_id="k1",
        idem_key="dededede-dede-dede-dede-dededededede",
        request_body={},
        response={"ok": True},
    )
