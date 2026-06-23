# SPDX-License-Identifier: MIT
"""/ items 71 + 93 — three-budget rate-limit primitive."""

from __future__ import annotations

import time

from app.core.config import settings
from app.services.anonymize.rate_limit import (
    RequestIdentity,
    ReuseCheckDecision,
    SlidingWindowCounter,
    ThreeBudgetLimiter,
    resolve_identity_keys,
)


def test_sliding_window_count_increments_with_hit() -> None:
    c = SlidingWindowCounter(window_seconds=60)
    now = time.monotonic()
    assert c.count(now=now) == 0
    c.hit(now=now)
    assert c.count(now=now) == 1
    c.hit(now=now)
    assert c.count(now=now) == 2


def test_sliding_window_drops_expired_entries() -> None:
    c = SlidingWindowCounter(window_seconds=10)
    now = 1_000_000.0
    c.hit(now=now)
    # 60 s later, the entry is well past the 10-s window.
    assert c.count(now=now + 60) == 0


def test_resolve_identity_walks_cookie_then_user_then_ip(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_reuse_check_allow_coarse_identity", True)
    keys = resolve_identity_keys(
        RequestIdentity(
            cookie_id="abc",
            authenticated_user_id="u-1",
            source_ip="203.0.113.7",
        )
    )
    assert keys == ("cookie:abc", "user:u-1", "ip:203.0.113.0/24")


def test_resolve_identity_skips_coarse_ip_unless_opted_in(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_reuse_check_allow_coarse_identity", False)
    keys = resolve_identity_keys(
        RequestIdentity(
            cookie_id="abc",
            authenticated_user_id=None,
            source_ip="203.0.113.7",
        )
    )
    assert keys == ("cookie:abc",)


def test_resolve_identity_handles_ipv6(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_reuse_check_allow_coarse_identity", True)
    keys = resolve_identity_keys(
        RequestIdentity(
            cookie_id=None,
            authenticated_user_id=None,
            source_ip="2001:db8:0001:0002::1",
        )
    )
    assert keys == ("ip:2001:db8:0001:0002::/64",)


def test_resolve_identity_no_keys_when_all_missing() -> None:
    assert resolve_identity_keys(RequestIdentity(cookie_id=None, authenticated_user_id=None, source_ip=None)) == ()


def test_three_budget_admits_under_limit() -> None:
    lim = ThreeBudgetLimiter(limit_per_window=3, window_seconds=60)
    ident = RequestIdentity(
        cookie_id="abc",
        authenticated_user_id=None,
        source_ip=None,
    )
    for _ in range(3):
        assert lim.check_and_consume(ident) is True


def test_three_budget_rejects_over_limit() -> None:
    lim = ThreeBudgetLimiter(limit_per_window=3, window_seconds=60)
    ident = RequestIdentity(
        cookie_id="abc",
        authenticated_user_id=None,
        source_ip=None,
    )
    for _ in range(3):
        lim.check_and_consume(ident)
    # Fourth request exhausts the cookie bucket.
    assert lim.check_and_consume(ident) is False


def test_three_budget_cookie_rotation_blocked_via_user_bucket(monkeypatch) -> None:
    """An attacker rotating cookies but staying authenticated still hits
    the per-user bucket."""
    lim = ThreeBudgetLimiter(limit_per_window=3, window_seconds=60)
    for cookie in ("c1", "c2", "c3"):
        assert (
            lim.check_and_consume(
                RequestIdentity(
                    cookie_id=cookie,
                    authenticated_user_id="u-1",
                    source_ip=None,
                )
            )
            is True
        )
    # Fourth attempt under a *new* cookie still fails because the
    # per-user budget is exhausted.
    assert (
        lim.check_and_consume(
            RequestIdentity(
                cookie_id="c4",
                authenticated_user_id="u-1",
                source_ip=None,
            )
        )
        is False
    )


def test_three_budget_refuses_anonymous_request() -> None:
    """No identity at all ⇒ refuse (fail-closed)."""
    lim = ThreeBudgetLimiter(limit_per_window=10, window_seconds=60)
    assert lim.check_and_consume(RequestIdentity(cookie_id=None, authenticated_user_id=None, source_ip=None)) is False


def test_three_budget_resets_after_window_elapses() -> None:
    lim = ThreeBudgetLimiter(limit_per_window=2, window_seconds=10)
    ident = RequestIdentity(
        cookie_id="abc",
        authenticated_user_id=None,
        source_ip=None,
    )
    now = time.monotonic()
    assert lim.check_and_consume(ident, now=now) is True
    assert lim.check_and_consume(ident, now=now) is True
    assert lim.check_and_consume(ident, now=now) is False
    # 60 s later, the counter is empty again.
    assert lim.check_and_consume(ident, now=now + 60) is True


# ── check_and_consume_with_reason — the API the create endpoint hits ──


def test_with_reason_admits_under_limit() -> None:
    """The reason-returning path matches plain check on the admit side."""
    lim = ThreeBudgetLimiter(limit_per_window=3, window_seconds=60)
    ident = RequestIdentity(
        cookie_id="abc",
        authenticated_user_id=None,
        source_ip=None,
    )
    decision = lim.check_and_consume_with_reason(ident)
    assert decision == ReuseCheckDecision(admitted=True, exhausted_bucket=None)


def test_with_reason_reports_cookie_bucket_exhaustion() -> None:
    """Audit event records which bucket type tripped."""
    lim = ThreeBudgetLimiter(limit_per_window=2, window_seconds=60)
    ident = RequestIdentity(
        cookie_id="abc",
        authenticated_user_id=None,
        source_ip=None,
    )
    lim.check_and_consume_with_reason(ident)
    lim.check_and_consume_with_reason(ident)
    decision = lim.check_and_consume_with_reason(ident)
    assert decision.admitted is False
    assert decision.exhausted_bucket == "cookie"


def test_with_reason_reports_user_bucket_exhaustion() -> None:
    """An attacker who rotates the cookie still trips the user bucket."""
    lim = ThreeBudgetLimiter(limit_per_window=2, window_seconds=60)
    for cookie in ("c1", "c2"):
        lim.check_and_consume_with_reason(
            RequestIdentity(
                cookie_id=cookie,
                authenticated_user_id="u-1",
                source_ip=None,
            )
        )
    decision = lim.check_and_consume_with_reason(
        RequestIdentity(
            cookie_id="c3",
            authenticated_user_id="u-1",
            source_ip=None,
        )
    )
    assert decision.admitted is False
    assert decision.exhausted_bucket == "user"


def test_with_reason_reports_ip_bucket_exhaustion(monkeypatch) -> None:
    """When coarse-IP fallback is opted-in, exhaustion surfaces ``ip``."""
    monkeypatch.setattr(
        settings,
        "anonymize_reuse_check_allow_coarse_identity",
        True,
    )
    lim = ThreeBudgetLimiter(limit_per_window=2, window_seconds=60)
    # No cookie, no user — only IP. Two hits fill the bucket.
    for _ in range(2):
        lim.check_and_consume_with_reason(
            RequestIdentity(
                cookie_id=None,
                authenticated_user_id=None,
                source_ip="203.0.113.10",
            )
        )
    # A different host inside the same /24 still trips it.
    decision = lim.check_and_consume_with_reason(
        RequestIdentity(
            cookie_id=None,
            authenticated_user_id=None,
            source_ip="203.0.113.99",
        )
    )
    assert decision.admitted is False
    assert decision.exhausted_bucket == "ip"


def test_with_reason_returns_none_bucket_for_anonymous() -> None:
    """A request with no identity at all has no bucket to name."""
    lim = ThreeBudgetLimiter(limit_per_window=10, window_seconds=60)
    decision = lim.check_and_consume_with_reason(
        RequestIdentity(cookie_id=None, authenticated_user_id=None, source_ip=None)
    )
    assert decision == ReuseCheckDecision(admitted=False, exhausted_bucket=None)


def test_with_reason_does_not_consume_when_already_exhausted() -> None:
    """A failed check must NOT increment the counter further — otherwise
    the bucket would refill at a longer window than configured."""
    lim = ThreeBudgetLimiter(limit_per_window=1, window_seconds=10)
    ident = RequestIdentity(
        cookie_id="abc",
        authenticated_user_id=None,
        source_ip=None,
    )
    assert lim.check_and_consume_with_reason(ident).admitted is True
    # Several rejected calls — internal counter should still be at 1.
    for _ in range(5):
        assert lim.check_and_consume_with_reason(ident).admitted is False
    bucket = lim._bucket("cookie:abc")
    assert bucket.count() == 1


def test_three_budget_reset_clears_all_buckets() -> None:
    """``reset()`` recreates the counters dict so a stale identity
    can't survive a manual orchestrator reset."""
    lim = ThreeBudgetLimiter(limit_per_window=1, window_seconds=60)
    ident = RequestIdentity(
        cookie_id="abc",
        authenticated_user_id=None,
        source_ip=None,
    )
    lim.check_and_consume(ident)
    assert lim.check_and_consume(ident) is False
    lim.reset()
    assert lim.check_and_consume(ident) is True


# ── ThreeBudgetLimiter.check_and_consume_with_reason ────────────


def test_three_budget_decision_admits_under_limit() -> None:
    from app.services.anonymize.rate_limit import (
        RequestIdentity,
        ReuseCheckDecision,
        ThreeBudgetLimiter,
    )

    lim = ThreeBudgetLimiter(limit_per_window=3, window_seconds=60)
    out = lim.check_and_consume_with_reason(
        RequestIdentity(cookie_id="a", authenticated_user_id=None, source_ip=None),
        now=100.0,
    )
    assert isinstance(out, ReuseCheckDecision)
    assert out.admitted is True
    assert out.exhausted_bucket is None


def test_three_budget_decision_blames_cookie_first() -> None:
    """Cookie bucket is consumed before user/ip; it exhausts first under
    a single-cookie pattern."""
    from app.services.anonymize.rate_limit import (
        RequestIdentity,
        ThreeBudgetLimiter,
    )

    lim = ThreeBudgetLimiter(limit_per_window=2, window_seconds=60)
    ident = RequestIdentity(cookie_id="a", authenticated_user_id=None, source_ip=None)
    assert lim.check_and_consume_with_reason(ident, now=100.0).admitted
    assert lim.check_and_consume_with_reason(ident, now=100.0).admitted
    out = lim.check_and_consume_with_reason(ident, now=100.0)
    assert out.admitted is False
    assert out.exhausted_bucket == "cookie"


def test_three_budget_decision_blames_user_when_cookie_rotates(monkeypatch) -> None:
    """Cookie rotation cannot evade the per-user budget."""
    from app.services.anonymize.rate_limit import (
        RequestIdentity,
        ThreeBudgetLimiter,
    )

    monkeypatch.setattr(settings, "anonymize_reuse_check_allow_coarse_identity", False)
    lim = ThreeBudgetLimiter(limit_per_window=2, window_seconds=60)
    # Rotate cookies under the same authenticated user.
    for cookie in ("c1", "c2", "c3"):
        ident = RequestIdentity(
            cookie_id=cookie,
            authenticated_user_id="u-1",
            source_ip=None,
        )
        result = lim.check_and_consume_with_reason(ident, now=100.0)
        if not result.admitted:
            break
    # The third attempt fails; user budget is what exhausted (not cookie,
    # because each cookie has its own bucket).
    assert result.admitted is False
    assert result.exhausted_bucket == "user"


def test_three_budget_decision_no_identity_refuses() -> None:
    from app.services.anonymize.rate_limit import (
        RequestIdentity,
        ThreeBudgetLimiter,
    )

    lim = ThreeBudgetLimiter(limit_per_window=3, window_seconds=60)
    out = lim.check_and_consume_with_reason(
        RequestIdentity(cookie_id=None, authenticated_user_id=None, source_ip=None),
        now=100.0,
    )
    assert out.admitted is False
    assert out.exhausted_bucket is None  # "no identity at all" signal
