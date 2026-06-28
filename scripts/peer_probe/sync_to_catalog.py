#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Sync the probe state + curated prose into the bundled catalog JSON.

Reads two inputs and produces an updated
``app/services/small_channel_peers.json``:

1. ``--probe-state PATH`` — the JSON file the deployed ``probe.py``
   maintains (typically ``/data/probe/probe_state.json`` on the
   operator's box). Source of truth for the empirical fields:
   ``channels_count``, ``capacity_btc``, ``top_20_hub_connections``,
   ``outbound_enabled_ratio``, ``funding_txid``, plus the verified-at
   date.

2. ``--curated-from PATH`` — the in-repo bundled
   ``small_channel_peers.json`` whose curated prose fields
   (``summary``, ``location``, ``tags``, ``caveats``, ``fee_tier``,
   ``connectivity_tier``, ``min_channel_size_sats``) the script
   carries forward verbatim. Operators editing the catalog mostly
   update those prose fields here.

The script never invents prose — it only refreshes the empirical
metrics. If the probe state contains a pubkey that isn't in the
curated file, the script logs a warning and skips it (the operator
must add the prose fields by hand before the entry will appear in the
bundle).

Usage::

    python3 -m scripts.peer_probe.sync_to_catalog \\
        --probe-state /data/probe/probe_state.json \\
        --curated-from app/services/small_channel_peers.json \\
        --output app/services/small_channel_peers.json

The script writes the output atomically (write-then-rename) so a
crash mid-write can't corrupt the bundled catalog. Pass
``--dry-run`` to print the resulting JSON to stdout instead.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import date
from pathlib import Path
from typing import Any, Mapping

logger = logging.getLogger("sync_to_catalog")


def _today_iso() -> str:
    return date.today().isoformat()


def _refresh_one(curated: dict, probe_entry: dict) -> dict:
    """Project the probe-state entry's empirical fields onto the curated
    entry. Returns a fresh dict (doesn't mutate ``curated``)."""
    out = dict(curated)

    # Empirical fields: take from probe_entry when present, else keep
    # the curated value.
    if "chan_count" in probe_entry:
        out["channels_count"] = int(probe_entry["chan_count"])
    if "capacity_sat" in probe_entry:
        out["capacity_btc"] = round(int(probe_entry["capacity_sat"]) / 100_000_000, 4)
    if "top_hub_connections" in probe_entry:
        out["top_20_hub_connections"] = int(probe_entry["top_hub_connections"])
    if "outbound_enabled_ratio" in probe_entry and probe_entry["outbound_enabled_ratio"] is not None:
        out["outbound_enabled_ratio"] = float(probe_entry["outbound_enabled_ratio"])
    if "funding_txid" in probe_entry and probe_entry["funding_txid"]:
        out["funding_txid"] = str(probe_entry["funding_txid"])
    # Refresh the verified date when the probe entry has a more recent
    # timestamp. Probe entries don't carry a verified_at today; fall back
    # to today's date so a re-sync moves the freshness signal forward.
    out["verified_at"] = probe_entry.get("verified_at") or _today_iso()
    return out


def _build(curated_path: Path, probe_path: Path) -> dict[str, Any]:
    curated_doc = json.loads(curated_path.read_text(encoding="utf-8"))
    probe_doc = json.loads(probe_path.read_text(encoding="utf-8"))

    curated_by_pub: dict[str, dict] = {p["node_id_hex"].lower(): p for p in curated_doc["peers"]}
    probe_attempts: Mapping[str, dict] = probe_doc.get("attempts") or {}

    refreshed: list[dict] = []
    missed_from_probe: list[str] = []
    for pub_lower, curated_entry in curated_by_pub.items():
        # Probe state keys are full pubkey hex (lowercase).
        probe_entry = probe_attempts.get(pub_lower)
        if probe_entry is None:
            missed_from_probe.append(curated_entry["alias"])
            refreshed.append(curated_entry)
            continue
        if probe_entry.get("outcome") not in ("open_succeeded", "open_success"):
            # The peer is in the curated list but the probe didn't
            # actually succeed against it — leave the curated entry
            # untouched and surface the surprise so the operator can
            # investigate.
            logger.warning(
                "%s in curated catalog but probe outcome was %r; leaving curated entry as-is",
                curated_entry["alias"],
                probe_entry.get("outcome"),
            )
            refreshed.append(curated_entry)
            continue
        refreshed.append(_refresh_one(curated_entry, probe_entry))

    if missed_from_probe:
        logger.warning(
            "no probe data for %d curated peer(s): %s",
            len(missed_from_probe),
            ", ".join(missed_from_probe),
        )

    # Peers in the probe state but NOT in the curated file: log them so
    # the operator knows there's a new hit waiting for prose, but don't
    # auto-add. The catalog's prose fields (summary, tags, etc.) require
    # human judgement.
    extra_pubs = {pub for pub, e in probe_attempts.items() if e.get("outcome") in ("open_succeeded", "open_success")}
    extra_pubs -= set(curated_by_pub)
    if extra_pubs:
        logger.warning(
            "%d probe-confirmed pubkey(s) absent from curated catalog (add prose by hand to include): %s",
            len(extra_pubs),
            ", ".join(f"{p[:16]}…" for p in sorted(extra_pubs)),
        )

    return {
        "snapshot_date": _today_iso(),
        "schema_version": int(curated_doc.get("schema_version", 1)),
        "peers": refreshed,
    }


def _write_atomic(path: Path, payload: str) -> None:
    """Write ``payload`` to ``path`` via a same-directory tmp file
    + rename so a crash mid-write can't corrupt the file."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(payload, encoding="utf-8")
    tmp.replace(path)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument(
        "--probe-state",
        type=Path,
        required=True,
        help="path to the deployed probe.py's probe_state.json",
    )
    ap.add_argument(
        "--curated-from",
        type=Path,
        default=Path("app/services/small_channel_peers.json"),
        help="path to the curated catalog JSON whose prose fields are carried forward",
    )
    ap.add_argument(
        "--output",
        type=Path,
        default=Path("app/services/small_channel_peers.json"),
        help="path to write the synced catalog (default overwrites the curated file in place)",
    )
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="print the resulting JSON to stdout instead of writing it",
    )
    ap.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="enable DEBUG-level logging",
    )
    args = ap.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )

    if not args.probe_state.is_file():
        ap.error(f"probe-state file not found: {args.probe_state}")
    if not args.curated_from.is_file():
        ap.error(f"curated-from file not found: {args.curated_from}")

    out_doc = _build(args.curated_from, args.probe_state)
    payload = json.dumps(out_doc, indent=2, ensure_ascii=False) + "\n"

    if args.dry_run:
        sys.stdout.write(payload)
        return 0

    _write_atomic(args.output, payload)
    logger.info("wrote %d peers to %s", len(out_doc["peers"]), args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
