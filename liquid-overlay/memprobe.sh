#!/usr/bin/env bash
# memprobe.sh — sample cgroup v2 memory for the Liquid indexer containers and
# emit a CSV + a peak summary. Supports the §5 measurement methodology of
# internal_docs/liquid_indexer_memory_reduction_plan.md.
#
# Because the StartOS `elements-electrs` package runs elementsd + electrs in ONE
# cgroup, the figure that matters for budgeting is the SUM of the two dev-harness
# containers' RSS (they peak in the same index-build window). This script reports
# per-container peaks AND the combined peak.
#
# Usage:
#   ./liquid-overlay/memprobe.sh [container ...]
# Defaults to the two liquid-overlay containers. Env:
#   INTERVAL=5   sampling period (seconds)
#   OUT=path     CSV output (default: ./memprobe-<UTC timestamp>.csv)
#
# cgroup v2 only (this box is cgroup2fs). memory.peak is the kernel's own
# high-water mark since container start (or since last reset); we best-effort
# reset it at launch so the run starts from a clean peak.
set -euo pipefail

INTERVAL="${INTERVAL:-5}"
OUT="${OUT:-memprobe-$(date -u +%Y%m%d-%H%M%SZ).csv}"
CONTAINERS=("$@")
if [ "${#CONTAINERS[@]}" -eq 0 ]; then
  CONTAINERS=(agent-wallet-elementsd-1 agent-wallet-electrs-liquid-1)
fi

if [ "$(stat -fc %T /sys/fs/cgroup 2>/dev/null)" != "cgroup2fs" ]; then
  echo "memprobe: requires cgroup v2 (cgroup2fs); aborting." >&2
  exit 1
fi

# Resolve a container name to its cgroup dir (try the common layouts).
cgroup_dir() {
  local cid; cid="$(docker inspect -f '{{.Id}}' "$1" 2>/dev/null)" || return 1
  [ -n "$cid" ] || return 1
  local p
  for p in "/sys/fs/cgroup/system.slice/docker-$cid.scope" \
           "/sys/fs/cgroup/docker/$cid"; do
    [ -r "$p/memory.peak" ] && { echo "$p"; return 0; }
  done
  return 1
}

read_mib() { # $1 = file; prints MiB (integer), or empty if unreadable
  local v; v="$(cat "$1" 2>/dev/null)" || return 0
  [[ "$v" =~ ^[0-9]+$ ]] && echo $(( v / 1048576 )) || echo ""
}

# Anon (unreclaimable) bytes from memory.stat, in MiB. This — not memory.current,
# which counts reclaimable file-backed page cache from reading the block files —
# is the OOM-relevant figure: under a hard cap the kernel reclaims cache first and
# only OOM-kills when anon can't fit.
read_anon() { # $1 = cgroup dir; prints MiB (integer) or ""
  local v; v="$(awk '/^anon /{print $2}' "$1/memory.stat" 2>/dev/null)" || return 0
  [[ "$v" =~ ^[0-9]+$ ]] && echo $(( v / 1048576 )) || echo ""
}

# Last electrs index-build progress line, as a bare percentage (or "").
electrs_pct() {
  docker logs --tail 40 "${CONTAINERS[-1]}" 2>&1 \
    | grep -oE 'processing blocks [0-9]+/[0-9]+ \([0-9.]+%\)' \
    | tail -1 | grep -oE '[0-9.]+%' | tr -d '%' || true
}

declare -A DIR
hdr="ts_utc,elapsed_s"
for c in "${CONTAINERS[@]}"; do
  d="$(cgroup_dir "$c")" || { echo "memprobe: cannot resolve cgroup for '$c' (running?)" >&2; exit 1; }
  DIR["$c"]="$d"
  # Best-effort reset of the kernel high-water mark (needs root on kernel >= 6.8).
  # When not writable, memory.peak reflects usage since CONTAINER start, so for a
  # clean per-run peak start this probe right after recreating the electrs container.
  if [ -w "$d/memory.peak" ]; then echo "0" > "$d/memory.peak" 2>/dev/null || true; fi
  hdr+=",${c}_cur_mib,${c}_anon_mib,${c}_peak_mib"
done
hdr+=",combined_cur_mib,combined_anon_mib,electrs_pct"

echo "$hdr" > "$OUT"
echo "memprobe: sampling ${CONTAINERS[*]} every ${INTERVAL}s -> $OUT (Ctrl-C to stop)"

declare -A MAXPEAK MAXANON; for c in "${CONTAINERS[@]}"; do MAXPEAK["$c"]=0; MAXANON["$c"]=0; done
COMBINED_MAX=0          # peak combined memory.current (cache-inclusive)
COMBINED_ANON_MAX=0     # peak combined anon (OOM-relevant)
START="$(date +%s)"

summary() {
  echo
  echo "===== memprobe summary ($OUT) ====="
  for c in "${CONTAINERS[@]}"; do
    printf '  %-30s anon-peak %6s MiB | mem.peak %6s MiB\n' "$c" "${MAXANON[$c]}" "${MAXPEAK[$c]}"
  done
  printf '  %-30s anon-peak %6s MiB  <-- OOM-relevant, budget against this\n' "COMBINED (one-cgroup equiv)" "$COMBINED_ANON_MAX"
  printf '  %-30s mem.peak  %6s MiB  (cache-inclusive; not the OOM figure)\n' "COMBINED" "$COMBINED_MAX"
  echo "==================================="
}
trap 'summary; exit 0' INT TERM

while true; do
  now="$(date +%s)"; elapsed=$(( now - START ))
  line="$(date -u +%Y-%m-%dT%H:%M:%SZ),$elapsed"
  combined_cur=0; combined_anon=0
  for c in "${CONTAINERS[@]}"; do
    cur="$(read_mib "${DIR[$c]}/memory.current")"; an="$(read_anon "${DIR[$c]}")"; pk="$(read_mib "${DIR[$c]}/memory.peak")"
    line+=",${cur:-},${an:-},${pk:-}"
    [ -n "${cur:-}" ] && combined_cur=$(( combined_cur + cur ))
    [ -n "${an:-}" ]  && combined_anon=$(( combined_anon + an ))
    if [ -n "${pk:-}" ] && [ "$pk" -gt "${MAXPEAK[$c]}" ]; then MAXPEAK["$c"]=$pk; fi
    if [ -n "${an:-}" ] && [ "$an" -gt "${MAXANON[$c]}" ]; then MAXANON["$c"]=$an; fi
  done
  [ "$combined_cur"  -gt "$COMBINED_MAX" ]      && COMBINED_MAX=$combined_cur
  [ "$combined_anon" -gt "$COMBINED_ANON_MAX" ] && COMBINED_ANON_MAX=$combined_anon
  line+=",${combined_cur},${combined_anon},$(electrs_pct)"
  echo "$line" >> "$OUT"
  sleep "$INTERVAL"
done
