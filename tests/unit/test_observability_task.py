# SPDX-License-Identifier: MIT
"""Tests for ``app.tasks.observability``.

Celery task run/success/failure metadata recorded in Redis. The
module's contract is "best-effort": a missing or broken Redis must
never break a task body. These tests pin (a) the blob mutations
each recorder makes, (b) the consecutive-failure / reset bookkeeping,
(c) the decorator's re-raise-on-failure invariant, and (d) the
fail-open behaviour when Redis is unavailable or raises.
"""

from __future__ import annotations

from typing import Any

import pytest

from app.tasks import observability as obs


class _FakeRedis:
    """In-memory stand-in for the synchronous redis client surface
    the module uses: get/set/sadd/expire/smembers."""

    def __init__(self) -> None:
        self.kv: dict[str, str] = {}
        self.sets: dict[str, set[str]] = {}

    def get(self, key: str) -> Any:
        return self.kv.get(key)

    def set(self, key: str, value: str, ex: int | None = None) -> None:
        self.kv[key] = value

    def sadd(self, key: str, member: str) -> None:
        self.sets.setdefault(key, set()).add(member)

    def expire(self, key: str, ttl: int) -> None:
        return None

    def smembers(self, key: str) -> set[str]:
        return self.sets.get(key, set())


@pytest.fixture
def fake_redis(monkeypatch) -> _FakeRedis:
    """Install a fake redis client and clear the process-global
    known-tasks set so cross-test bleed can't inflate assertions."""
    client = _FakeRedis()
    monkeypatch.setattr(obs, "_get_redis", lambda: client)
    monkeypatch.setattr(obs, "_known_tasks", set())
    return client


def test_record_run_then_success_clears_failures(fake_redis) -> None:
    """A success after a run records last_success_at, nulls the
    error, and zeroes consecutive_failures — the green-path reset."""
    obs.record_task_run("beat.demo")
    obs.record_task_success("beat.demo", result={"sent": 3, "skip": "x"})

    blob = obs._read(fake_redis, "beat.demo")
    assert blob["name"] == "beat.demo"
    assert blob["last_run_at"] is not None
    assert blob["last_success_at"] is not None
    assert blob["last_error"] is None
    assert blob["consecutive_failures"] == 0
    # Only scalar result fields are previewed.
    assert blob["last_result_preview"] == {"sent": 3, "skip": "x"}


def test_record_failure_increments_consecutive_counter(fake_redis) -> None:
    """Successive failures accumulate ``consecutive_failures`` and
    store a bounded error string of the form ``Type: message``."""
    obs.record_task_failure("beat.demo", ValueError("boom"))
    obs.record_task_failure("beat.demo", ValueError("boom2"))

    blob = obs._read(fake_redis, "beat.demo")
    assert blob["consecutive_failures"] == 2
    assert blob["last_error"] == "ValueError: boom2"
    assert blob["last_failure_at"] is not None


def test_failure_then_success_resets_counter(fake_redis) -> None:
    """A success after a failure streak resets the consecutive
    counter to 0 — the recovery transition operators watch for."""
    obs.record_task_failure("beat.demo", RuntimeError("x"))
    obs.record_task_failure("beat.demo", RuntimeError("y"))
    obs.record_task_success("beat.demo")

    blob = obs._read(fake_redis, "beat.demo")
    assert blob["consecutive_failures"] == 0
    assert blob["last_error"] is None


def test_error_message_is_length_bounded(fake_redis) -> None:
    """The stored error is truncated to 500 chars so a giant
    exception repr can't bloat the Redis blob."""
    obs.record_task_failure("beat.demo", ValueError("z" * 5000))
    blob = obs._read(fake_redis, "beat.demo")
    assert len(blob["last_error"]) == 500


def test_track_task_decorator_records_success_and_returns_value(fake_redis) -> None:
    """The decorator records run+success around a passing body and
    returns the body's value unchanged."""

    @obs.track_task("beat.wrapped")
    def _body(x: int) -> int:
        return x * 2

    assert _body(21) == 42
    blob = obs._read(fake_redis, "beat.wrapped")
    assert blob["last_success_at"] is not None
    assert blob["consecutive_failures"] == 0


def test_track_task_decorator_reraises_and_records_failure(fake_redis) -> None:
    """On a raising body the decorator records a failure AND
    re-raises so Celery's retry machinery still sees the exception."""

    @obs.track_task("beat.boom")
    def _body() -> None:
        raise KeyError("nope")

    with pytest.raises(KeyError):
        _body()

    blob = obs._read(fake_redis, "beat.boom")
    assert blob["consecutive_failures"] == 1
    assert "KeyError" in blob["last_error"]


def test_get_all_task_status_lists_known_and_available(fake_redis) -> None:
    """``get_all_task_status`` surfaces a recorded task as
    available=True and an index-only task with no blob as
    available=False."""
    obs.record_task_run("beat.has_blob")
    # An index member with no stored blob → reported unavailable.
    fake_redis.sets.setdefault(obs._KEY_INDEX, set()).add("beat.no_blob")

    out = {row["name"]: row for row in obs.get_all_task_status()}
    assert out["beat.has_blob"]["available"] is True
    assert out["beat.no_blob"]["available"] is False


# ── Fail-open behaviour when Redis is missing or broken ────────────


def test_recorders_no_op_when_redis_unavailable(monkeypatch) -> None:
    """Every recorder must early-return (never raise) when
    ``_get_redis`` yields None — a stripped-down env without redis-py
    must not break the task body."""
    monkeypatch.setattr(obs, "_get_redis", lambda: None)
    monkeypatch.setattr(obs, "_known_tasks", set())

    obs.record_task_run("beat.x")
    obs.record_task_success("beat.x")
    obs.record_task_failure("beat.x", ValueError("e"))
    # The task is still remembered for enumeration even with no Redis.
    assert "beat.x" in obs._known_tasks


def test_get_all_task_status_without_redis_marks_unavailable(monkeypatch) -> None:
    """With no Redis the read-side returns the known-task names all
    flagged available=False instead of raising."""
    monkeypatch.setattr(obs, "_get_redis", lambda: None)
    monkeypatch.setattr(obs, "_known_tasks", {"beat.a", "beat.b"})

    out = obs.get_all_task_status()
    assert {r["name"] for r in out} == {"beat.a", "beat.b"}
    assert all(r["available"] is False for r in out)


def test_read_swallows_corrupt_json(fake_redis) -> None:
    """``_read`` returns an empty dict on undecodable JSON rather
    than propagating — a corrupt key must not wedge the read path."""
    fake_redis.kv[obs._KEY_PREFIX + "beat.corrupt"] = "{not json"
    assert obs._read(fake_redis, "beat.corrupt") == {}


def test_read_decodes_bytes_payload(fake_redis) -> None:
    """Redis may return bytes; ``_read`` decodes them before
    json.loads so the bytes/str client configs behave identically."""
    fake_redis.kv[obs._KEY_PREFIX + "beat.b"] = b'{"name": "beat.b", "consecutive_failures": 4}'  # type: ignore[assignment]
    blob = obs._read(fake_redis, "beat.b")
    assert blob["consecutive_failures"] == 4


def test_write_swallows_client_errors(monkeypatch) -> None:
    """``_write`` must swallow a raising client so a Redis hiccup
    mid-task can't surface into the task body."""

    class _Boom:
        def set(self, *a, **k):
            raise ConnectionError("redis down")

        def sadd(self, *a, **k):
            raise ConnectionError("redis down")

        def expire(self, *a, **k):
            raise ConnectionError("redis down")

    # Must not raise.
    obs._write(_Boom(), "beat.x", {"name": "beat.x"})


def test_get_all_task_status_swallows_read_side_error(monkeypatch) -> None:
    """If the index read raises, ``get_all_task_status`` falls back
    to the known-task list flagged unavailable rather than blowing
    up the admin endpoint."""

    class _BoomClient:
        def smembers(self, *a, **k):
            raise ConnectionError("redis down")

    monkeypatch.setattr(obs, "_get_redis", lambda: _BoomClient())
    monkeypatch.setattr(obs, "_known_tasks", {"beat.only"})

    out = obs.get_all_task_status()
    assert out == [{"name": "beat.only", "available": False}]


def test_success_result_preview_drops_non_scalar_fields(fake_redis) -> None:
    """The result preview keeps only scalar fields so a large/nested
    result object can't bloat the stored blob."""
    obs.record_task_success(
        "beat.preview",
        result={"count": 5, "ok": True, "nested": {"a": 1}, "items": [1, 2, 3]},
    )
    blob = obs._read(fake_redis, "beat.preview")
    assert blob["last_result_preview"] == {"count": 5, "ok": True}
