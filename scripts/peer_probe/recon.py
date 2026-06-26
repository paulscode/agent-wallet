#!/usr/bin/env python3
"""peer_probe/recon.py — rank candidate LN peers for small-channel probes.

Run inside the agent-wallet container. Pulls the gossip graph via the
running api process's LND credentials, then ranks every node that is:

* Not us
* Not in the SKIP set (Megalithic — already saturated — plus a small
  denylist of known custodial wallet pubkeys that always reject opens)
* Reachable (has at least one socket address in gossip)
* Above ``--min-chan-count`` channels (default 30)

Composite score: ``top_hub_conn * 100 + chan_count + capacity_btc``.
"top hubs" = the network's top-20 nodes by channel count, which Ocean's
CLN almost certainly has gossip about — so a candidate well-connected to
those hubs is highly likely routable from Ocean.

Output: ``/data/probe/candidates.json``. Self-contained (Python stdlib
only — no requests/httpx dependencies).
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import ssl
import sys
import tempfile
import time
import urllib.error
import urllib.request


# Known pubkeys to skip even if they appear well-connected. Either
# self-rejecting (Megalithic) or custodial-wallet (never accept opens).
SKIP_PUBKEYS = {
    # Megalithic main (large channels) and small-channels sibling —
    # the latter is the one we're trying to find alternatives to.
    "02a98c86ef366ce226aad6e7706959456e1701058915c3cbf527b37da143bb1441",
    # Wallet of Satoshi — custodial.
    "035e4ff418fc8b5554c5d9eea66396c227bd429a3251c8cbc711002ba215bfc226",
}


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
    """Resolve LND credentials from the api process env, return a tuple
    of ``(rest_url, headers, ssl_context)`` ready for urllib calls."""
    pid = find_uvicorn_pid()
    if pid is None:
        sys.exit(
            "uvicorn (api) process not found — is the wallet running?"
        )
    env = load_env_from_pid(pid)
    rest_url = env.get("LND_REST_URL")
    mac = env.get("LND_MACAROON_HEX")
    tls_b64 = env.get("LND_TLS_CERT")
    if not (rest_url and mac and tls_b64):
        sys.exit(
            "LND_REST_URL / LND_MACAROON_HEX / LND_TLS_CERT not in api env"
        )
    pem = base64.b64decode(tls_b64).decode("utf-8")
    cert_file = tempfile.NamedTemporaryFile(
        mode="w", suffix=".pem", delete=False
    )
    cert_file.write(pem)
    cert_file.close()
    ctx = ssl.create_default_context(cafile=cert_file.name)
    # LND's cert is for ``lnd.embassy`` etc.; hostname check works under
    # StartOS but disable as a safety net for non-canonical setups.
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    headers = {"Grpc-Metadata-macaroon": mac}
    return rest_url, headers, ctx


def lnd_get(
    rest_url: str, headers: dict[str, str], ctx: ssl.SSLContext, path: str,
    *, timeout: int = 120,
) -> dict:
    req = urllib.request.Request(rest_url + path, headers=headers)
    with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def pick_address(addresses: list[dict]) -> tuple[str | None, bool]:
    """Pick the best address from a node's gossiped address list.

    Returns ``(host, is_clearnet)``. Prefer clearnet IPv4 → clearnet IPv6
    → Tor. ``None`` if no usable address. ``addresses`` items have the
    shape ``{"network": "tcp"|"ipv4"|"ipv6"|"tor", "addr": "host:port"}``.
    """
    cn4 = cn6 = tor = None
    for a in addresses:
        addr = (a.get("addr") or "").strip()
        if not addr:
            continue
        lo = addr.lower()
        if ".onion:" in lo or lo.endswith(".onion"):
            tor = tor or addr
        elif addr.count(":") == 1:  # host:port with single colon → ipv4
            cn4 = cn4 or addr
        elif addr.startswith("["):  # ipv6 in brackets, [::1]:9735
            cn6 = cn6 or addr
        else:
            # Likely ipv6 without brackets — ambiguous, skip
            continue
    if cn4:
        return cn4, True
    if cn6:
        return cn6, True
    if tor:
        return tor, False
    return None, False


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--out", default="/data/probe/candidates.json",
        help="output path (default: /data/probe/candidates.json)",
    )
    ap.add_argument(
        "--top-n", type=int, default=150,
        help="how many candidates to keep (default: 150)",
    )
    ap.add_argument(
        "--min-chan-count", type=int, default=30,
        help="exclude nodes with fewer than N channels (default: 30)",
    )
    ap.add_argument(
        "--hub-count", type=int, default=20,
        help="number of top-by-channel-count nodes to treat as 'hubs' for "
             "the connectivity bonus (default: 20)",
    )
    ap.add_argument(
        "--include-tor-only", action="store_true",
        help="keep nodes whose only address is .onion. Default skips "
             "them since Ocean-side routability through Tor is unreliable.",
    )
    args = ap.parse_args()

    rest_url, headers, ctx = make_lnd_client()

    # Step 1: our pubkey + sanity check.
    print("[1/4] fetching /v1/getinfo …", file=sys.stderr)
    info = lnd_get(rest_url, headers, ctx, "/v1/getinfo", timeout=30)
    our_pubkey = info.get("identity_pubkey", "")
    print(
        f"      our_pubkey = {our_pubkey[:16]}… alias = {info.get('alias','')!r}",
        file=sys.stderr,
    )

    # Step 2: full gossip graph. Can be 10MB+ — give it time.
    print("[2/4] fetching /v1/graph (this can take 30-90s) …", file=sys.stderr)
    t0 = time.monotonic()
    graph = lnd_get(rest_url, headers, ctx, "/v1/graph", timeout=180)
    elapsed = time.monotonic() - t0
    nodes_raw = graph.get("nodes", []) or []
    edges_raw = graph.get("edges", []) or []
    print(
        f"      {len(nodes_raw)} nodes, {len(edges_raw)} edges in {elapsed:.1f}s",
        file=sys.stderr,
    )

    # Step 3: build per-node summary (channel count, capacity, addresses).
    print("[3/4] tabulating channel counts …", file=sys.stderr)
    by_pk: dict[str, dict] = {}
    for n in nodes_raw:
        pk = n.get("pub_key")
        if not pk:
            continue
        by_pk[pk] = {
            "pubkey": pk,
            "alias": n.get("alias", ""),
            "chan_count": 0,
            "capacity_sat": 0,
            "addresses": n.get("addresses", []) or [],
        }
    for e in edges_raw:
        cap = int(e.get("capacity") or 0)
        for pk_field in ("node1_pub", "node2_pub"):
            pk = e.get(pk_field)
            if pk in by_pk:
                by_pk[pk]["chan_count"] += 1
                by_pk[pk]["capacity_sat"] += cap

    all_nodes = list(by_pk.values())
    all_nodes.sort(key=lambda r: r["chan_count"], reverse=True)

    # Top-N hubs by channel count — these are the gossip-ubiquitous
    # routing anchors that Ocean's CLN almost certainly knows about.
    top_hub_set = {n["pubkey"] for n in all_nodes[: args.hub_count]}
    print(
        f"      top-{args.hub_count} hubs identified — top 3: "
        + ", ".join(
            f"{n['alias']!r}({n['chan_count']} chans)"
            for n in all_nodes[:3]
        ),
        file=sys.stderr,
    )

    # Per-node count of edges that touch a top-hub.
    hub_conn = {pk: 0 for pk in by_pk}
    for e in edges_raw:
        n1 = e.get("node1_pub")
        n2 = e.get("node2_pub")
        if n1 in top_hub_set and n2 in hub_conn and n2 not in top_hub_set:
            hub_conn[n2] += 1
        if n2 in top_hub_set and n1 in hub_conn and n1 not in top_hub_set:
            hub_conn[n1] += 1

    # Step 4: filter + score + rank.
    print("[4/4] filtering, scoring, ranking …", file=sys.stderr)
    candidates = []
    for n in all_nodes:
        pk = n["pubkey"]
        if pk == our_pubkey or pk in SKIP_PUBKEYS:
            continue
        if n["chan_count"] < args.min_chan_count:
            break  # sorted descending — no more above threshold
        addr, is_clearnet = pick_address(n["addresses"])
        if addr is None:
            continue
        if not is_clearnet and not args.include_tor_only:
            continue
        hub = hub_conn.get(pk, 0)
        capacity_btc = n["capacity_sat"] / 100_000_000
        score = hub * 100 + n["chan_count"] + capacity_btc
        candidates.append({
            "pubkey": pk,
            "alias": n["alias"],
            "address": addr,
            "is_clearnet": is_clearnet,
            "chan_count": n["chan_count"],
            "capacity_sat": n["capacity_sat"],
            "top_hub_connections": hub,
            "score": round(score, 1),
        })

    # Re-sort by composite score (hub connectivity dominates).
    candidates.sort(key=lambda c: c["score"], reverse=True)
    candidates = candidates[: args.top_n]

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    payload = {
        "our_pubkey": our_pubkey,
        "generated_at": int(time.time()),
        "hub_count": args.hub_count,
        "top_hubs": [
            {"pubkey": n["pubkey"], "alias": n["alias"], "chan_count": n["chan_count"]}
            for n in all_nodes[: args.hub_count]
        ],
        "count": len(candidates),
        "candidates": candidates,
    }
    with open(args.out, "w") as f:
        json.dump(payload, f, indent=2)
    print(
        f"\nwrote {len(candidates)} candidates → {args.out}",
        file=sys.stderr,
    )
    print(f"\ntop 10 by composite score:", file=sys.stderr)
    for i, c in enumerate(candidates[:10], 1):
        print(
            f"  {i:2}. {c['alias']!r:<28}  "
            f"chans={c['chan_count']:>4}  "
            f"cap={c['capacity_sat']/1e8:>6.2f}BTC  "
            f"hub_conn={c['top_hub_connections']:>3}  "
            f"score={c['score']:>7.1f}",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
