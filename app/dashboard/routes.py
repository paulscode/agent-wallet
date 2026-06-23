# SPDX-License-Identifier: MIT
"""
Dashboard page routes — serves the HTML pages.

- GET  /dashboard/login  → login page
- POST /dashboard/login  → login form handler
- GET  /dashboard/       → main dashboard SPA (requires auth)
- POST /dashboard/logout → clear session and redirect (CSRF-protected)
"""

import logging
from pathlib import Path
from urllib.parse import urlparse

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.responses import Response

from app.core.config import settings
from app.core.database import get_db_context
from app.core.limiter import limiter
from app.dashboard import DASHBOARD_KEY_ID
from app.dashboard.auth import (
    COOKIE_NAME,
    CSRF_OK,
    check_csrf_token,
    check_login_lockout,
    clear_login_failures,
    clear_session_cookie,
    create_session_cookie,
    generate_login_nonce,
    get_csrf_token,
    record_login_failure,
    revoke_session,
    verify_login_nonce,
    verify_login_origin,
    verify_session,
    verify_token,
)
from app.services.audit_service import log_dashboard_action

logger = logging.getLogger(__name__)

_dir = Path(__file__).parent
templates = Jinja2Templates(directory=str(_dir / "templates"))

router = APIRouter()


def _nonce(request: Request) -> str:
    """Get the CSP nonce from request state (set by csp_nonce_middleware)."""
    return getattr(request.state, "csp_nonce", "")


def _resolve_mempool_public_url() -> str:
    """Resolve the URL the dashboard UI should use for transaction links.

    Order of precedence:

    1. ``MEMPOOL_PUBLIC_URL`` if explicitly configured.
    2. ``LND_MEMPOOL_URL`` when it's a URL a user's browser can actually
       follow — i.e. not a ``.onion`` and not an orchestrator-internal
       host (a docker/StartOS service name like ``mempool-rdts.embassy``
       or a loopback address resolves only on the server, never in the
       user's browser).
    3. ``https://mempool.space`` as a final fallback.

    Onion users — or anyone whose mempool is reached at an internal
    address server-side — can set ``MEMPOOL_PUBLIC_URL`` to the address
    their browser uses (e.g. their mempool's own ``.onion`` or LAN URL).
    """
    # Only ``http(s)`` values are allowed through — this string is bound into
    # the dashboard's ``:href`` attributes, where a ``javascript:`` scheme
    # would execute. The value is operator-controlled (env), so this is
    # belt-and-suspenders, but it keeps a misconfiguration from becoming an
    # injection sink.
    explicit = (settings.mempool_public_url or "").strip().rstrip("/")
    if explicit and _is_http_url(explicit):
        return explicit
    server_url = (settings.lnd_mempool_url or "").strip().rstrip("/")
    if server_url and _is_user_reachable_http_url(server_url):
        return server_url
    return "https://mempool.space"


def _is_http_url(value: str) -> bool:
    """True only for an ``http://`` or ``https://`` URL."""
    return value.lower().startswith(("http://", "https://"))


def _is_user_reachable_http_url(value: str) -> bool:
    """True for an ``http(s)`` URL a user's browser can actually follow.

    Rejects ``.onion`` (needs Tor) and non-routable hosts: orchestrator
    service names (``*.embassy`` / ``*.startos`` and dot-less single
    labels like ``mempool``) and loopback, all of which resolve only on
    the server. A LAN/private address is kept — a user on the same
    network can reach it. Keeps an internal backend URL out of the
    dashboard's clickable explorer links.
    """
    if not _is_http_url(value):
        return False
    host = (urlparse(value).hostname or "").lower()
    if not host or host.endswith(".onion"):
        return False
    if host.endswith((".embassy", ".startos")):
        return False
    if host == "localhost" or host == "::1" or host.startswith("127."):
        return False
    if "." not in host:  # dot-less single-label service name (docker/compose)
        return False
    return True


_ERROR_MESSAGES: dict[str, str] = {
    "invalid": "Invalid password",
    "expired": "Session expired",
}


@router.get("/dashboard/login", response_class=HTMLResponse)
async def login_page(request: Request, error: str = "") -> Response:
    if await verify_session(request):
        return RedirectResponse(url="/dashboard/", status_code=302)
    error_msg = _ERROR_MESSAGES.get(error, "")
    return templates.TemplateResponse(
        request,
        name="login.html",
        context={
            "error": error_msg,
            "csp_nonce": _nonce(request),
            "login_nonce": generate_login_nonce(),
        },
    )


@router.post("/dashboard/login", response_class=HTMLResponse)
@limiter.limit("5/minute")
async def login_submit(request: Request) -> Response:
    form = await request.form()
    # The HTML form posts the field as ``password``; older callers may
    # still send ``token`` — accept either for backward compatibility.
    password = str(form.get("password") or form.get("token") or "")
    submitted_nonce = str(form.get("login_nonce", ""))
    ip = request.client.host if request.client else None
    if ip and await check_login_lockout(ip):
        return templates.TemplateResponse(
            request,
            name="login.html",
            context={
                "error": "Too many failed attempts. Try again later.",
                "csp_nonce": _nonce(request),
                "login_nonce": generate_login_nonce(),
            },
            status_code=429,
        )
    # Reject cross-origin form submissions and stale/forged login nonces
    # to defeat login-CSRF (an attacker logging a victim into the
    # attacker's account by submitting a third-party form).
    if not verify_login_origin(request) or not verify_login_nonce(submitted_nonce):
        if ip:
            await record_login_failure(ip)
        return templates.TemplateResponse(
            request,
            name="login.html",
            context={
                "error": "Invalid request — please reload and try again.",
                "csp_nonce": _nonce(request),
                "login_nonce": generate_login_nonce(),
            },
            status_code=403,
        )
    if not verify_token(password):
        if ip:
            await record_login_failure(ip)
        try:
            async with get_db_context() as db:
                await log_dashboard_action(
                    db,
                    DASHBOARD_KEY_ID,
                    "dashboard_login_failed",
                    "auth",
                    success=False,
                    error_message="Invalid dashboard password",
                    ip_address=ip,
                )
        except Exception:
            pass
        return templates.TemplateResponse(
            request,
            name="login.html",
            context={
                "error": "Invalid password",
                "csp_nonce": _nonce(request),
                "login_nonce": generate_login_nonce(),
            },
            status_code=401,
        )
    if ip:
        await clear_login_failures(ip)
    try:
        async with get_db_context() as db:
            await log_dashboard_action(
                db,
                DASHBOARD_KEY_ID,
                "dashboard_login",
                "auth",
                ip_address=ip,
            )
    except Exception:
        pass
    response = RedirectResponse(url="/dashboard/", status_code=302)
    # No
    # ``csrf_token`` cookie. The dashboard pages render the token
    # into a ``<meta name="csrf-token">`` tag (see ``base.html``),
    # so the SPA picks it up from there after the redirect. Keeping
    # the token out of cookies removes the JS-readable copy that
    # made XSS able to mint arbitrary writes.
    await create_session_cookie(response, request)
    return response


@router.post("/dashboard/logout")
async def logout(request: Request) -> Response:
    if not await verify_session(request):
        return RedirectResponse(url="/dashboard/login", status_code=303)
    if (await check_csrf_token(request)) != CSRF_OK:
        # Refuse cross-site forced logouts. Use 303 to land on the
        # login page rather than echoing a 4xx for the form submitter.
        return RedirectResponse(url="/dashboard/", status_code=303)
    await revoke_session(request)
    response = RedirectResponse(url="/dashboard/login", status_code=303)
    clear_session_cookie(response)
    return response


@router.get("/dashboard/", response_class=HTMLResponse)
@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request) -> Response:
    if not await verify_session(request):
        # If the user had a session cookie (now invalid — expired,
        # idle-timed-out, revoked, IP-mismatched), surface a
        # "Session expired" hint on the login page so they aren't
        # silently bounced without explanation. A bare visit (no
        # cookie at all) lands on a clean login page with no message.
        had_cookie = request.cookies.get(COOKIE_NAME) is not None
        target = "/dashboard/login?error=expired" if had_cookie else "/dashboard/login"
        return RedirectResponse(url=target, status_code=302)
    return templates.TemplateResponse(
        request,
        name="dashboard.html",
        context={
            "csp_nonce": _nonce(request),
            "csrf_token": await get_csrf_token(request) or "",
            "mempool_public_url": _resolve_mempool_public_url(),
            "braiins_deposit_enabled": settings.braiins_deposit_enabled,
            "anonymize_enabled": settings.anonymize_enabled,
            "tip_lightning_address": settings.dashboard_tip_lightning_address,
        },
    )
