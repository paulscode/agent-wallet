#!/usr/bin/env python3
"""peer_probe/probe.py — walk candidates.json trying small channel opens.

Behavior, per the design:
* Reads ``candidates.json`` (produced by ``recon.py``).
* Reads ``probe_state.json`` — list of pubkeys already attempted.
* For each unattempted candidate, in rank order:
    1. Attempt LN peer connect (via /v1/peers).
    2. If connect succeeds, attempt a sync channel open of ``--chan-sat``
       sats (default 150000), public, push_sat=0, sat_per_vbyte=1.
    3. Record the outcome in ``probe_state.json``.
    4. On open success: STOP. The script exits 0 and tells the operator
       to log the hit, close the channel manually, and re-run to continue.
    5. On open failure: disconnect peer, move to next candidate.
* On any subsequent run, candidates already in ``probe_state.json`` are
  skipped — the walk resumes from where it left off.

Self-contained (Python stdlib only).
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import ssl
import sys
import tempfile
import urllib.error
import urllib.request


def find_uvicorn_pid() -> int | None:
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/cmdline", "rb") as f:
                cmd = f.read().decode("utf-8", errors="replace")
        except OSError:
            continue
        if "uvicorn" in cmd and "app.main" in cmd:
            return int(entry)
    return None


def load_env_from_pid(pid: int) -> dict[str, str]:
    with open(f"/proc/{pid}/environ", "rb") as f:
        env_blob = f.read().decode("utf-8", errors="replace")
    out: dict[str, str] = {}
    for kv in env_blob.split("\x00"):
        if "=" in kv:
            k, v = kv.split("=", 1)
            out[k] = v
    return out


def make_lnd_client() -> tuple[str, dict[str, str], ssl.SSLContext]:
    pid = find_uvicorn_pid()
    if pid is None:
        sys.exit("uvicorn (api) process not found — is the wallet running?")
    env = load_env_from_pid(pid)
    rest_url = env.get("LND_REST_URL")
    mac = env.get("LND_MACAROON_HEX")
    tls_b64 = env.get("LND_TLS_CERT")
    if not (rest_url and mac and tls_b64):
        sys.exit("LND_REST_URL / LND_MACAROON_HEX / LND_TLS_CERT not in api env")
    pem = base64.b64decode(tls_b64).decode("utf-8")
    cert_file = tempfile.NamedTemporaryFile(
        mode="w", suffix=".pem", delete=False
    )
    cert_file.write(pem)
    cert_file.close()
    ctx = ssl.create_default_context(cafile=cert_file.name)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    headers = {"Grpc-Metadata-macaroon": mac, "Content-Type": "application/json"}
    return rest_url, headers, ctx


def lnd_request(
    rest_url: str, headers: dict[str, str], ctx: ssl.SSLContext,
    method: str, path: str, body: dict | None = None,
    *, timeout: int = 60,
) -> tuple[int, dict | str]:
    """Issue an LND REST request. Returns ``(http_code, body)`` where body
    is a dict for valid JSON, else a string snippet."""
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        rest_url + path, data=data, headers=headers, method=method,
    )
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
            payload = resp.read().decode("utf-8")
            try:
                return resp.status, json.loads(payload)
            except json.JSONDecodeError:
                return resp.status, payload
    except urllib.error.HTTPError as e:
        body_str = e.read().decode("utf-8", errors="replace")
        try:
            return e.code, json.loads(body_str)
        except json.JSONDecodeError:
            return e.code, body_str
    except (urllib.error.URLError, OSError) as e:
        return -1, f"transport error: {e}"


def is_already_connected_error(body: dict | str) -> bool:
    text = json.dumps(body) if isinstance(body, dict) else str(body)
    return "already connected" in text.lower()


# Substrings that prove the failure was OURS, not the peer's. Recording
# the peer as "rejected" in this case would poison the candidate's
# record — we'd never re-probe them. Each pattern below has been
# observed in production from LND's REST responses.
_OUR_SIDE_FAILURE_PATTERNS = (
    "reserved wallet balance invalidated",   # on-chain wallet headroom
    "insufficient funds",                    # broader on-chain shortage
    "not enough witness outputs to create funding transaction",
    "insufficient on-chain funds",
)

# Substrings that prove the failure was transport-level (peer
# unreachable / Tor flake / network blip), NOT a willful rejection.
# Skip recording so the candidate is re-probed on the next run.
_TRANSIENT_FAILURE_PATTERNS = (
    "connection refused",
    "network is unreachable",
    "i/o timeout",
    "operation timed out",
    "read operation timed out",
    "no route to host",
    "transport error",
    "disconnected",  # peer disconnected mid-handshake
)


def _matches_any(text: str, patterns: tuple[str, ...]) -> bool:
    lo = text.lower()
    return any(p in lo for p in patterns)


def is_our_side_failure(body: dict | str) -> bool:
    text = json.dumps(body) if isinstance(body, dict) else str(body)
    return _matches_any(text, _OUR_SIDE_FAILURE_PATTERNS)


def is_transient_failure(body: dict | str) -> bool:
    text = json.dumps(body) if isinstance(body, dict) else str(body)
    return _matches_any(text, _TRANSIENT_FAILURE_PATTERNS)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--candidates", default="/data/probe/candidates.json",
        help="path to candidates.json (default: /data/probe/candidates.json)",
    )
    ap.add_argument(
        "--state", default="/data/probe/probe_state.json",
        help="path to probe state file (default: /data/probe/probe_state.json)",
    )
    ap.add_argument(
        "--chan-sat", type=int, default=150_000,
        help="channel size in sats (default: 150000)",
    )
    ap.add_argument(
        "--sat-per-vbyte", type=int, default=1,
        help="on-chain feerate for the open tx (default: 1 sat/vB)",
    )
    ap.add_argument(
        "--limit", type=int, default=0,
        help="stop after probing this many candidates this run (0 = no "
             "limit; default 0). Use to test slowly without burning the list.",
    )
    ap.add_argument(
        "--dry-run", action="store_true",
        help="list what would be probed without contacting any peer",
    )
    ap.add_argument(
        "--reset", action="store_true",
        help="wipe the state file before starting (re-probes everything)",
    )
    args = ap.parse_args()

    if args.reset and os.path.exists(args.state):
        os.unlink(args.state)
        print(f"[reset] removed {args.state}", file=sys.stderr)

    with open(args.candidates) as f:
        cdata = json.load(f)
    candidates = cdata.get("candidates") or []
    if not candidates:
        sys.exit(f"no candidates in {args.candidates}")
    print(f"loaded {len(candidates)} candidates from {args.candidates}")

    try:
        with open(args.state) as f:
            state = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        state = {"attempts": {}}

    def save_state() -> None:
        os.makedirs(os.path.dirname(args.state), exist_ok=True)
        with open(args.state, "w") as f:
            json.dump(state, f, indent=2)

    pending = [c for c in candidates if c["pubkey"] not in state["attempts"]]
    print(
        f"  attempted previously: {len(state['attempts'])}, "
        f"pending: {len(pending)}"
    )
    if args.dry_run:
        print("\n(--dry-run) would probe the following in order:")
        for i, c in enumerate(pending[: args.limit or 20], 1):
            print(
                f"  {i:2}. {c['alias']!r:<28} {c['pubkey'][:24]}…  "
                f"chans={c['chan_count']:>4} cap={c['capacity_sat']/1e8:>5.2f}BTC "
                f"hub={c['top_hub_connections']:>2} addr={c['address']}"
            )
        return 0

    rest_url, headers, ctx = make_lnd_client()
    probed_this_run = 0
    for c in pending:
        if args.limit and probed_this_run >= args.limit:
            print(f"\nreached --limit={args.limit}; stopping for this run.")
            break
        pk = c["pubkey"]
        alias = c.get("alias") or "(no alias)"
        addr = c["address"]
        probed_this_run += 1
        print(
            f"\n=== [{probed_this_run}] {alias!r}  {pk[:24]}…  @{addr}  "
            f"(chans={c['chan_count']}, hub={c['top_hub_connections']}, "
            f"score={c['score']}) ==="
        )

        # 1) connect peer
        print("  connect …", end=" ", flush=True)
        code, body = lnd_request(
            rest_url, headers, ctx, "POST", "/v1/peers",
            body={"addr": {"pubkey": pk, "host": addr}, "perm": False},
            timeout=30,
        )
        if code != 200 and not (
            isinstance(body, dict) and is_already_connected_error(body)
        ):
            err = json.dumps(body)[:240] if isinstance(body, dict) else str(body)[:240]
            print(f"FAIL [{code}]")
            print(f"    {err}")
            # Transport-level / unreachable failures look like rejection
            # in the response shape, but they're really "couldn't reach
            # the peer right now". Don't poison the candidate's record —
            # re-probe on next run when conditions might be different.
            if is_transient_failure(body):
                print("    (transient transport error — NOT recording; will re-probe)")
            else:
                state["attempts"][pk] = {
                    "alias": alias, "address": addr, "outcome": "connect_failed",
                    "detail": err,
                }
                save_state()
            continue
        print("ok")

        # 2) open channel — sync form returns funding_txid in the response.
        print(f"  open {args.chan_sat:,} sat …", end=" ", flush=True)
        open_body = {
            "node_pubkey_string": pk,
            "local_funding_amount": str(args.chan_sat),
            "push_sat": "0",
            "sat_per_vbyte": str(args.sat_per_vbyte),
            "private": False,
            "spend_unconfirmed": False,
        }
        code, body = lnd_request(
            rest_url, headers, ctx, "POST", "/v1/channels",
            body=open_body, timeout=90,
        )
        if code == 200 and isinstance(body, dict) and (
            body.get("funding_txid_str") or body.get("funding_txid_bytes")
        ):
            txid = body.get("funding_txid_str") or body.get("funding_txid_bytes")
            print(f"SUCCESS  funding_txid={txid}")
            state["attempts"][pk] = {
                "alias": alias, "address": addr, "outcome": "open_succeeded",
                "funding_txid": txid,
                "chan_count": c["chan_count"],
                "top_hub_connections": c["top_hub_connections"],
            }
            state["last_success"] = state["attempts"][pk] | {"pubkey": pk}
            save_state()
            print(
                "\n*** opened a channel. Log this candidate, close the test\n"
                "*** channel via the dashboard or `lncli closechannel`, then\n"
                "*** re-run this script to continue with the next candidate.\n"
            )
            return 0
        # open failed
        err = json.dumps(body)[:240] if isinstance(body, dict) else str(body)[:240]
        print(f"FAIL [{code}]")
        print(f"    {err}")

        # If LND refused on OUR side (on-chain headroom exhausted etc.),
        # the peer never even saw the open — recording them as rejected
        # would falsely retire them. Abort the whole run since the next
        # attempt would fail for the same reason.
        if is_our_side_failure(body):
            # Try to be polite before exiting.
            lnd_request(
                rest_url, headers, ctx, "DELETE", f"/v1/peers/{pk}",
                timeout=10,
            )
            print(
                "\n*** ABORTING RUN — this is OUR LND refusing the open, not\n"
                "*** the peer rejecting us. NOT recording this attempt; the\n"
                "*** candidate stays in the pending queue. Fix the on-chain\n"
                "*** side (wait for closes to confirm, top up the on-chain\n"
                "*** wallet, etc.) and re-run probe.py to continue."
            )
            return 0

        # Transient transport blip — peer disconnected mid-handshake,
        # i/o timed out, etc. Same logic as the connect-step transient
        # path: don't record, re-probe on the next run.
        if is_transient_failure(body):
            print("    (transient — NOT recording; will re-probe)")
            lnd_request(
                rest_url, headers, ctx, "DELETE", f"/v1/peers/{pk}",
                timeout=10,
            )
            continue

        # Legitimate peer-side rejection (e.g. "below min chan size",
        # "channel size too small", policy guards). Record and move on.
        state["attempts"][pk] = {
            "alias": alias, "address": addr, "outcome": "open_failed",
            "http_code": code, "detail": err,
        }
        save_state()

        # 3) be polite — drop the peer connection on failure
        lnd_request(
            rest_url, headers, ctx, "DELETE", f"/v1/peers/{pk}",
            timeout=10,
        )

    succ = sum(
        1 for v in state["attempts"].values()
        if v.get("outcome") == "open_succeeded"
    )
    print(
        f"\nrun complete. attempts total={len(state['attempts'])}, "
        f"successes={succ}, candidates remaining={len(pending) - probed_this_run}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
