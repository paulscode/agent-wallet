#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════
# Agent Wallet — Interactive Setup & Launcher
# ══════════════════════════════════════════════════════════════════════
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

ENV_FILE=".env"
VENV_DIR=".venv"
TOR_PID_FILE=".tor.pid"
TOR_DATA_DIR=".tor-data"

# ── Colors ───────────────────────────────────────────────────────────
BOLD='\033[1m'
DIM='\033[2m'
CYAN='\033[36m'
YELLOW='\033[33m'
GREEN='\033[32m'
RED='\033[31m'
RESET='\033[0m'

banner() {
    echo ""
    echo -e "${CYAN}${BOLD}  ₿  Agent Wallet${RESET}"
    echo -e "${DIM}  ─────────────────────────────────────${RESET}"
    echo ""
}

info()    { echo -e "  ${GREEN}✓${RESET} $*"; }
warn()    { echo -e "  ${YELLOW}!${RESET} $*"; }
err()     { echo -e "  ${RED}✗${RESET} $*"; }
header()  { echo -e "\n  ${CYAN}${BOLD}$*${RESET}"; }

# ── Mask a value for display (show first 4 chars + stars) ────────────
mask_value() {
    local val="$1"
    local len=${#val}
    if [[ $len -le 4 ]]; then
        printf '%s' '********'
    elif [[ $len -le 12 ]]; then
        printf '%s' "${val:0:4}********"
    else
        printf '%s' "${val:0:4}$(printf '*%.0s' $(seq 1 $((len - 4))))"
    fi
}

# ── Read a config value, with optional masking ──────────────────────
# Usage: prompt_value VARNAME "Prompt text" "default" [masked]
prompt_value() {
    local varname="$1"
    local prompt_text="$2"
    local default_val="${3:-}"
    local masked="${4:-}"
    local display_default=""

    if [[ -n "$default_val" ]]; then
        if [[ "$masked" == "masked" ]]; then
            display_default="$(mask_value "$default_val")"
        else
            display_default="$default_val"
        fi
    fi

    if [[ -n "$display_default" ]]; then
        echo -en "  ${prompt_text} ${DIM}[${display_default}]${RESET}: "
    else
        echo -en "  ${prompt_text}: "
    fi

    local input
    if [[ "$masked" == "masked" ]]; then
        # Read without echo for sensitive values
        read -rs input
        echo ""  # newline after hidden input
    else
        read -r input
    fi

    # If empty, keep current value
    if [[ -z "$input" ]]; then
        printf -v "$varname" '%s' "$default_val"
    else
        printf -v "$varname" '%s' "$input"
    fi
}

# ── Read a yes/no value ─────────────────────────────────────────────
prompt_bool() {
    local varname="$1"
    local prompt_text="$2"
    local default_val="${3:-true}"
    local yn="Y/n"
    [[ "$default_val" == "false" ]] && yn="y/N"

    echo -en "  ${prompt_text} ${DIM}[${yn}]${RESET}: "
    local input
    read -r input

    if [[ -z "$input" ]]; then
        printf -v "$varname" '%s' "$default_val"
    elif [[ "$input" =~ ^[Yy] ]]; then
        printf -v "$varname" '%s' "true"
    else
        printf -v "$varname" '%s' "false"
    fi
}

# ── Read a value with preset choices ─────────────────────────────────
prompt_choice() {
    local varname="$1"
    local prompt_text="$2"
    local default_val="$3"
    shift 3
    local choices=("$@")

    local display_choices=""
    for c in "${choices[@]}"; do
        if [[ "$c" == "$default_val" ]]; then
            display_choices+="${BOLD}${c}${RESET}${DIM} | "
        else
            display_choices+="${c} | "
        fi
    done
    display_choices="${display_choices% | }"

    echo -e "  ${prompt_text} ${DIM}(${display_choices}${DIM})${RESET}"
    echo -en "  ${DIM}[${default_val}]${RESET}: "
    local input
    read -r input

    if [[ -z "$input" ]]; then
        printf -v "$varname" '%s' "$default_val"
    else
        printf -v "$varname" '%s' "$input"
    fi
}

# ── Load existing .env into variables ────────────────────────────────
load_env() {
    if [[ -f "$ENV_FILE" ]]; then
        # Read .env line by line. Do NOT use ``IFS='=' read -r key val``
        # — bash's read strips the trailing IFS character from the last
        # variable, which silently mangles values ending in ``=`` (every
        # base64-padded Fernet key, for example). Parameter expansion is
        # split-on-first-``=``-and-keep-the-rest-verbatim safe.
        while IFS= read -r line || [[ -n "$line" ]]; do
            # Skip comments and empty lines
            [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
            # No ``=`` → not a KEY=value line.
            [[ "$line" != *=* ]] && continue
            local key val
            key="${line%%=*}"
            val="${line#*=}"
            # Remove leading/trailing whitespace from key
            key="$(echo "$key" | xargs)"
            # Remove surrounding quotes from value
            val="${val#\"}"
            val="${val%\"}"
            val="${val#\'}"
            val="${val%\'}"
            # Handle ${VAR} references — expand REDIS_PASSWORD / POSTGRES_PASSWORD
            # Skip lines with unexpanded ${...} references
            if [[ "$val" == *'${'* ]]; then
                continue
            fi
            export "ENV_$key=$val"
        done < "$ENV_FILE"
    fi
}

# ── Get an env value (from loaded vars) ──────────────────────────────
get_env() {
    local key="$1"
    local default="${2:-}"
    local envvar="ENV_$key"
    echo "${!envvar:-$default}"
}

# ══════════════════════════════════════════════════════════════════════
# Setup: venv + dependencies
# ══════════════════════════════════════════════════════════════════════
setup_venv() {
    header "Python Environment"

    if [[ ! -d "$VENV_DIR" ]]; then
        echo -e "  Creating virtual environment..."
        python3 -m venv "$VENV_DIR"
        info "Virtual environment created at ${VENV_DIR}/"
    else
        info "Virtual environment exists at ${VENV_DIR}/"
    fi

    # Use the venv's own Python/pip directly (immune to stale shebangs)
    local PIP="$VENV_DIR/bin/python -m pip"

    echo -e "  Installing dependencies..."
    if ! $PIP install -q --upgrade pip > /dev/null 2>&1; then
        warn "pip upgrade failed (non-critical, continuing)"
    fi
    if ! $PIP install -q -e "." 2>&1 | tail -5; then
        err "Failed to install dependencies. Check pyproject.toml and try:"
        echo -e "    ${DIM}$VENV_DIR/bin/python -m pip install -e .${RESET}"
        exit 1
    fi
    info "Dependencies installed"

    # Activate for subsequent commands (uvicorn, etc.)
    # shellcheck disable=SC1091
    source "$VENV_DIR/bin/activate"
}

# ══════════════════════════════════════════════════════════════════════
# Tor proxy management (standalone mode)
# ══════════════════════════════════════════════════════════════════════
_is_onion_url() {
    [[ "$1" == *".onion"* ]]
}

_tor_is_available() {
    command -v tor &>/dev/null
}

_tor_is_running() {
    [[ -f "$TOR_PID_FILE" ]] && kill -0 "$(cat "$TOR_PID_FILE" 2>/dev/null)" 2>/dev/null
}

_install_tor() {
    header "Installing Tor"
    if command -v apt-get &>/dev/null; then
        info "Installing via apt..."
        sudo apt-get update -qq && sudo apt-get install -y -qq tor > /dev/null 2>&1
    elif command -v dnf &>/dev/null; then
        info "Installing via dnf..."
        sudo dnf install -y -q tor > /dev/null 2>&1
    elif command -v pacman &>/dev/null; then
        info "Installing via pacman..."
        sudo pacman -S --noconfirm tor > /dev/null 2>&1
    elif command -v brew &>/dev/null; then
        info "Installing via brew..."
        brew install tor > /dev/null 2>&1
    else
        err "Could not detect package manager. Please install tor manually."
        return 1
    fi
    if _tor_is_available; then
        info "Tor installed successfully"
    else
        err "Tor installation failed"
        return 1
    fi
}

_start_tor() {
    if _tor_is_running; then
        info "Tor proxy already running (PID $(cat "$TOR_PID_FILE"))"
        return 0
    fi

    mkdir -p "$TOR_DATA_DIR"

    # Write a full-featured standalone torrc that mirrors the
    # bundled tor-proxy container. Without these directives the api
    # process's watchdog/event-stream/per-listener-probe machinery
    # silently degrades (no ControlPort → no NEWNYM, no GETINFO,
    # no SETEVENTS; single SocksPort → no per-call-site isolation).
    local torrc="$TOR_DATA_DIR/torrc"
    local tor_ctrl_pwd
    tor_ctrl_pwd="$(get_env TOR_CONTROL_PASSWORD "")"
    local hashed_ctrl_line="# ControlPort unauthenticated (TOR_CONTROL_PASSWORD unset)"
    if [[ -n "$tor_ctrl_pwd" ]]; then
        local hashed
        hashed="$(tor --hash-password "$tor_ctrl_pwd" 2>/dev/null | tail -1)"
        if [[ -n "$hashed" ]]; then
            hashed_ctrl_line="HashedControlPassword $hashed"
        else
            warn "tor --hash-password failed; ControlPort will be unauthenticated."
        fi
    fi
    # The 8 SocksPorts match the layout in app/core/config.py
    # (anonymize_tor_socks_ports default). LND traffic uses 9050
    # which it shares with the boltz_submarine listener in single-
    # Tor mode.
    cat > "$torrc" << TORRC
# Standalone Tor for Agent Wallet (host-mode). Mirrors the
# bundled tor-proxy/torrc with 127.0.0.1 bindings instead of
# 0.0.0.0 since this Tor lives on the host alongside the api.
# Re-generated by start.sh on $(date -u '+%Y-%m-%d %H:%M UTC').

# Eight isolated SOCKS listeners, one per
# anonymize call site, each with destination-isolation + per-
# call-auth-isolation. IsolateSOCKSAuth is what makes the
# per-call (user,pass) pairs in app/services/anonymize/http.py
# trigger Tor's stream isolation — without it the directive in
# the application code is a no-op.
SocksPort 127.0.0.1:9050 IsolateDestAddr IsolateDestPort IsolateSOCKSAuth
SocksPort 127.0.0.1:9051 IsolateDestAddr IsolateDestPort IsolateSOCKSAuth
SocksPort 127.0.0.1:9052 IsolateDestAddr IsolateDestPort IsolateSOCKSAuth
SocksPort 127.0.0.1:9053 IsolateDestAddr IsolateDestPort IsolateSOCKSAuth
SocksPort 127.0.0.1:9054 IsolateDestAddr IsolateDestPort IsolateSOCKSAuth
SocksPort 127.0.0.1:9055 IsolateDestAddr IsolateDestPort IsolateSOCKSAuth
SocksPort 127.0.0.1:9056 IsolateDestAddr IsolateDestPort IsolateSOCKSAuth
SocksPort 127.0.0.1:9057 IsolateDestAddr IsolateDestPort IsolateSOCKSAuth

# Persistent DataDirectory (already the case in
# standalone mode: --DataDirectory points at .tor-data/, which
# survives api restarts so consensus + guards don't get
# re-fetched on every wallet boot).
DataDirectory $(pwd)/$TOR_DATA_DIR

# Guard + circuit-build tuning to recover from
# the 2026-05-21 single-guard exclusion failure mode.
NumEntryGuards 3
GuardLifetime 6 weeks
LearnCircuitBuildTimeout 1
MaxCircuitDirtiness 600

# LongLivedPorts. Keeps LN streams (8080 LND REST, 9735
# LN p2p) from being torn down aggressively by the CBT learner.
LongLivedPorts 21,22,706,1863,5050,5190,5222,5223,6523,6667,6697,8080,8332,8333,8334,9735

# Scrub onion addresses + peer fingerprints from notice
# logs so pasting logs into bug reports doesn't leak HS contacts.
SafeLogging 1

# Disable exit relay (we only need client functionality).
ExitRelay 0

# Reduce log noise.
Log notice stderr

# Control port for the wallet's bootstrap probes,
# circuit-status reads, NEWNYM watchdog, and SETEVENTS stream.
# Bound to 127.0.0.1 only — never expose to other interfaces.
ControlPort 127.0.0.1:9100
$hashed_ctrl_line
TORRC

    info "Starting Tor SOCKS proxy on 127.0.0.1:9050 (with ControlPort 9100)..."
    tor -f "$torrc" --DataDirectory "$TOR_DATA_DIR" --PidFile "$(pwd)/$TOR_PID_FILE" --RunAsDaemon 1 --quiet 2>/dev/null

    # Wait for Tor to be ready (up to 30s)
    local waited=0
    while ! nc -z 127.0.0.1 9050 2>/dev/null; do
        sleep 1
        waited=$((waited + 1))
        if [[ $waited -ge 30 ]]; then
            err "Tor failed to start within 30s"
            return 1
        fi
    done
    info "Tor proxy ready (PID $(cat "$TOR_PID_FILE" 2>/dev/null))"
}

_stop_tor() {
    if [[ -f "$TOR_PID_FILE" ]]; then
        local pid
        pid="$(cat "$TOR_PID_FILE" 2>/dev/null)"
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            info "Tor proxy stopped (PID $pid)"
        fi
        rm -f "$TOR_PID_FILE"
    fi
}

_ensure_tor() {
    # Called before starting standalone mode when .onion URL is detected
    if ! _tor_is_available; then
        warn "Tor is not installed but your LND URL is a .onion address"
        echo ""
        local install_tor
        prompt_bool install_tor "Install Tor automatically?" "true"
        if [[ "$install_tor" == "true" ]]; then
            _install_tor || return 1
        else
            err "Tor is required for .onion connections. Install it manually or use Docker Compose mode."
            return 1
        fi
    fi
    _start_tor
}

# ══════════════════════════════════════════════════════════════════════
# Narrow encryption-key backup files
#
# When the wizard *generates* a fresh value for either SECRET_KEY or
# ANONYMIZE_LIQUID_SEED_FERNET, write a narrow backup file next to
# .env that contains ONLY that key (plus the PREVIOUS variant when
# rotating). The file is mode 0600.
#
# Why a narrow file instead of cp .env .env.backup:
# .env also holds the LND admin macaroon, dashboard token, Boltz
# gateway token, alert webhook URL, etc. An operator who casually
# places that on a USB stick or shared drive leaks far more than the
# encryption key they meant to back up. The narrow file is small,
# self-describing, and safe to print on paper.
#
# After writing, prompt ENTER-to-continue so the operator must
# acknowledge the file exists before the wizard finishes.
# ══════════════════════════════════════════════════════════════════════
_write_secret_key_backup() {
    local value="$1"
    local previous="${2:-}"
    local stamp dest
    stamp="$(date -u +%Y-%m-%dT%H-%M-%SZ)"
    dest="$(dirname "$ENV_FILE")/secret-key-backup-${stamp}.txt"
    {
        echo "# Agent Wallet — SECRET_KEY backup"
        echo "# Generated: ${stamp}"
        echo "# PURPOSE: required to decrypt Boltz swap private keys /"
        echo "# preimages at rest in the database. Without this value,"
        echo "# in-flight swaps cannot be cooperatively claimed or"
        echo "# refunded."
        echo "#"
        echo "# STORE THIS OFFLINE (USB, paper, password manager)."
        echo "# This file does NOT contain LND macaroons, API tokens, or"
        echo "# other operational secrets — those live in .env and have"
        echo "# their own lifecycle."
        echo ""
        echo "SECRET_KEY=${value}"
        if [[ -n "$previous" ]]; then
            echo "SECRET_KEY_PREVIOUS=${previous}"
        fi
    } > "$dest"
    chmod 600 "$dest"
    echo ""
    warn "⚠ A SECRET_KEY backup was written to"
    echo -e "    ${BOLD}${dest}${RESET} (mode 0600)."
    echo ""
    echo "  This file contains ONLY the encryption key used for Boltz"
    echo "  swap material — NOT your LND macaroon or other secrets."
    echo "  Move it to offline storage now (USB / paper / password"
    echo "  manager)."
    echo ""
    read -r -p "  Press ENTER once you have backed up the file… " _ack
}

_write_liquid_seed_backup() {
    local value="$1"
    local stamp dest
    stamp="$(date -u +%Y-%m-%dT%H-%M-%SZ)"
    dest="$(dirname "$ENV_FILE")/liquid-seed-backup-${stamp}.txt"
    {
        echo "# Agent Wallet — ANONYMIZE_LIQUID_SEED_FERNET backup"
        echo "# Generated: ${stamp}"
        echo "# PURPOSE: encrypts the SLIP-77 Liquid master blinding"
        echo "# key used to unblind in-flight Liquid hop outputs."
        echo "# Without this value the wallet cannot construct claims"
        echo "# or cooperative refunds for in-flight Liquid sessions."
        echo "#"
        echo "# STORE THIS OFFLINE alongside (but in a separate envelope"
        echo "# from) the SECRET_KEY backup. This file does NOT contain"
        echo "# LND macaroons, API tokens, or other operational secrets."
        echo ""
        echo "ANONYMIZE_LIQUID_SEED_FERNET=${value}"
    } > "$dest"
    chmod 600 "$dest"
    echo ""
    warn "⚠ A Liquid blinding-seed backup was written to"
    echo -e "    ${BOLD}${dest}${RESET} (mode 0600)."
    echo ""
    echo "  This value is required to recover in-flight Liquid hop"
    echo "  outputs. Move it to offline storage now (USB / paper /"
    echo "  password manager), separate from the SECRET_KEY backup."
    echo ""
    read -r -p "  Press ENTER once you have backed up the file… " _ack
}

# ══════════════════════════════════════════════════════════════════════
# Configuration wizard
# ══════════════════════════════════════════════════════════════════════
run_config() {
    load_env

    # Tracks whether the wizard generated a fresh encryption key on
    # this run. When true (and the operator accepts the generated
    # value), we write a narrow backup file + prompt ENTER-to-
    # continue after .env is on disk. Declared here so the
    # post-write block can read them even if the relevant prompt
    # path was not entered (e.g. Liquid disabled).
    local fresh_secret_key="false"
    local fresh_liquid_seed="false"

    # ── Generate defaults ──
    # Robust random-hex generator: python3 → openssl → /dev/urandom.
    # NEVER fall back to a known/weak placeholder for a security secret —
    # a predictable SECRET_KEY / DB / Redis password is worse than a hard
    # failure.
    _rand_hex() {
        python3 -c "import secrets; print(secrets.token_hex($1))" 2>/dev/null \
            || openssl rand -hex "$1" 2>/dev/null \
            || (head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n')
    }
    local gen_secret gen_dashboard_token gen_pg_pass gen_redis_pass
    gen_secret="$(_rand_hex 32)"
    gen_dashboard_token="$(_rand_hex 32)"
    gen_pg_pass="$(_rand_hex 24)"
    gen_redis_pass="$(_rand_hex 16)"
    if [ -z "$gen_secret" ] || [ -z "$gen_pg_pass" ] || [ -z "$gen_redis_pass" ]; then
        echo "ERROR: could not generate secure random secrets (need one of: python3, openssl, /dev/urandom)." >&2
        echo "       Refusing to continue with weak/empty credentials. Install python3 or openssl and re-run." >&2
        exit 1
    fi
    # Tor control-port password. Auto-generated so
    # operators don't have to remember to do it; can be overridden
    # in the wizard. Empty value leaves the control port
    # unauthenticated (acceptable for dev, warned at boot).
    local gen_tor_ctrl_pwd
    gen_tor_ctrl_pwd="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))' 2>/dev/null || echo '')"
    # BOLT 12 gateway bearer token. The wallet refuses to dial the
    # gateway unauthenticated when DEBUG=false (see
    # ``app/services/bolt12/runtime.py``), so we auto-generate one
    # for fresh installs. Same value flows into both the API
    # container and the bolt12-gateway sidecar via the single
    # ``BOLT12_GATEWAY_TOKEN`` env var, so they always match.
    local gen_bolt12_token
    gen_bolt12_token="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))' 2>/dev/null || echo '')"

    # ── Section: LND Connection (most important) ──
    header "LND Node Connection"
    echo -e "  ${DIM}Connect to your Lightning node's REST API${RESET}\n"

    local lnd_rest_url lnd_macaroon_hex lnd_tls_verify lnd_tls_cert lnd_tor_proxy

    prompt_value  lnd_rest_url      "LND REST URL"        "$(get_env LND_REST_URL "https://your-lnd-host:8080")"
    prompt_value  lnd_macaroon_hex  "Macaroon (hex)"      "$(get_env LND_MACAROON_HEX "")" masked
    prompt_bool   lnd_tls_verify    "Verify TLS cert?"    "$(get_env LND_TLS_VERIFY "true")"
    prompt_value  lnd_tls_cert      "TLS cert (base64, optional)" "$(get_env LND_TLS_CERT "")" masked

    # ── Tor proxy — auto-detect .onion and configure accordingly ──
    local tor_control_password
    if _is_onion_url "$lnd_rest_url"; then
        echo ""
        info "Detected .onion address — Tor proxy will be configured automatically"
        echo -e "  ${DIM}Docker Compose: uses built-in tor-proxy container (socks5://tor-proxy:9050)${RESET}"
        echo -e "  ${DIM}Standalone:     uses local Tor on socks5://127.0.0.1:9050 (auto-managed)${RESET}"
        echo ""
        # Default depends on likely launch mode; Docker Compose sets LND_TOR_PROXY via env override.
        # We store the standalone default here; docker-compose.yml overrides it at runtime.
        local current_proxy
        current_proxy="$(get_env LND_TOR_PROXY "socks5://127.0.0.1:9050")"
        prompt_value lnd_tor_proxy "Tor SOCKS proxy" "$current_proxy"
        # ControlPort password. Auto-suggested with a
        # 32-char token; empty leaves the control port
        # unauthenticated (acceptable for dev, warned at boot).
        # The same value is consumed by tor-proxy/entrypoint.sh
        # (Docker mode) and start.sh's standalone torrc generator.
        prompt_value tor_control_password \
            "Tor ControlPort password (blank = unauthenticated)" \
            "$(get_env TOR_CONTROL_PASSWORD "$gen_tor_ctrl_pwd")" masked
    else
        echo -e "\n  ${DIM}If your LND is behind Tor (.onion), provide the SOCKS proxy address${RESET}"
        prompt_value  lnd_tor_proxy     "Tor SOCKS proxy (blank=none)" "$(get_env LND_TOR_PROXY "")"
        # Even clearnet deploys may want the bundled tor-proxy for
        # anonymize / Boltz onion endpoints, so we still offer the
        # password knob — but default it to empty (keeps the dev-
        # default behavior for operators who don't have Tor).
        tor_control_password="$(get_env TOR_CONTROL_PASSWORD "")"
    fi

    # ── Section: Dashboard ──
    header "Dashboard"
    echo -e "  ${DIM}Web UI for monitoring your node at /dashboard/${RESET}\n"

    local enable_dashboard dashboard_token

    prompt_bool   enable_dashboard  "Enable dashboard?"   "$(get_env ENABLE_DASHBOARD "true")"
    if [[ "$enable_dashboard" == "true" ]]; then
        local current_dash_token
        current_dash_token="$(get_env DASHBOARD_TOKEN "$gen_dashboard_token")"
        prompt_value  dashboard_token "Dashboard token"    "$current_dash_token" masked
    else
        dashboard_token=""
    fi

    # ── Section: Database & Redis ──
    header "Database & Redis"
    echo -e "  ${DIM}Docker Compose manages these services automatically${RESET}\n"

    local postgres_password redis_password database_url redis_url

    prompt_value  postgres_password "PostgreSQL password"  "$(get_env POSTGRES_PASSWORD "$gen_pg_pass")" masked
    prompt_value  redis_password    "Redis password"       "$(get_env REDIS_PASSWORD "$gen_redis_pass")" masked

    database_url="postgresql+asyncpg://postgres:${postgres_password}@postgres:5432/agent_btc_wallet"
    redis_url="redis://:${redis_password}@redis:6379/0"

    # ── Section: Security ──
    header "Application Security"

    local secret_key
    local current_secret
    local prior_secret
    prior_secret="$(get_env SECRET_KEY "")"
    current_secret="$(get_env SECRET_KEY "$gen_secret")"
    # If it's still the placeholder, use the generated one
    if [[ "$current_secret" == "change-me-to-a-random-64-char-string" ]]; then
        current_secret="$gen_secret"
        prior_secret=""
    fi
    prompt_value  secret_key  "Secret key (auto-generated)" "$current_secret" masked
    # A "fresh" SECRET_KEY is one where the prior .env had no usable
    # value (empty or placeholder) — i.e. the operator did not bring
    # an existing value forward. The narrow backup file is written
    # only in this case so successive wizard runs don't accumulate
    # stale copies in the install directory.
    if [[ -z "$prior_secret" || "$prior_secret" == "change-me-to-a-random-64-char-string" ]]; then
        fresh_secret_key="true"
    fi

    # ── Section: Network & Safety ──
    header "Network & Safety Limits"

    local bitcoin_network lnd_max_payment_sats lnd_mempool_url mempool_public_url

    prompt_choice bitcoin_network      "Bitcoin network"          "$(get_env BITCOIN_NETWORK "bitcoin")" "bitcoin" "testnet" "signet" "regtest"
    prompt_value  lnd_max_payment_sats "Max payment (sats)"       "$(get_env LND_MAX_PAYMENT_SATS "10000")"
    prompt_value  lnd_mempool_url      "Mempool URL"              "$(get_env LND_MEMPOOL_URL "https://mempool.space")"

    # Most home-node users (Start9 / Umbrel / myNode) have a local
    # mempool web UI on the same LAN. The UI link defaults to the
    # server-side URL when it's clearnet, but for onion/local-IP
    # configurations we ask for an explicit public URL so the
    # browser-side "View on mempool" links resolve to something the
    # user can actually open.
    echo ""
    echo -e "  ${DIM}If you run a local mempool (e.g. Start9, Umbrel), enter its${RESET}"
    echo -e "  ${DIM}browser-reachable URL here. Leave blank to use mempool.space.${RESET}"
    prompt_value  mempool_public_url   "Public mempool URL (UI links)" "$(get_env MEMPOOL_PUBLIC_URL "")"

    # ── Optional electrs backend ──
    # Privacy upgrade: route every address/transaction/Boltz-timeout
    # lookup through the operator's own electrs instead of mempool.space.
    # Strictly opt-in; blank = disabled (current behaviour).
    echo ""
    echo -e "  ${DIM}Optional: route chain lookups through your own electrs${RESET}"
    echo -e "  ${DIM}server (Start9 default port 50001). Leave blank to keep${RESET}"
    echo -e "  ${DIM}using mempool.space only. Accepted formats:${RESET}"
    echo -e "  ${DIM}  tcp://localhost:50001${RESET}"
    echo -e "  ${DIM}  ssl://electrs.local:50002${RESET}"
    echo -e "  ${DIM}  abcd…xyz.onion:50001:t   (StartOS copy/paste, :t=TCP :s=SSL)${RESET}"
    echo -e "  ${DIM}  abcd…xyz.onion           (bare host — port/scheme inferred)${RESET}"
    local lnd_electrum_url
    prompt_value  lnd_electrum_url     "Electrum/electrs URL (blank=disabled)" "$(get_env LND_ELECTRUM_URL "")"
    # Normalise the many shapes operators copy/paste:
    #   * StartOS-style "host:port:t" / "host:port:s" → strip the trailing
    #     scheme tag and prefix with tcp:// or ssl:// accordingly.
    #   * "host:port" (no scheme)   → assume tcp://
    #   * "host" (no port, no scheme) → assume tcp:// + default port
    #     (50002 if scheme already ssl, else 50001).
    # The pydantic validator strictly requires tcp:// or ssl://, so we
    # fix it up here rather than push validation noise onto the user.
    if [[ -n "$lnd_electrum_url" ]]; then
        local _orig="$lnd_electrum_url"
        # Strip a StartOS trailing :t / :s tag, mapping it to a scheme.
        local _forced_scheme=""
        if [[ "$lnd_electrum_url" =~ :[tT]$ ]]; then
            _forced_scheme="tcp"
            lnd_electrum_url="${lnd_electrum_url%:[tT]}"
        elif [[ "$lnd_electrum_url" =~ :[sS]$ ]]; then
            _forced_scheme="ssl"
            lnd_electrum_url="${lnd_electrum_url%:[sS]}"
        fi
        # If the user already supplied a scheme, the trailing tag (if any)
        # is informational; honour the explicit scheme.
        if [[ "$lnd_electrum_url" != tcp://* && "$lnd_electrum_url" != ssl://* ]]; then
            local _scheme="${_forced_scheme:-tcp}"
            # If host has no :port, append the protocol default.
            if [[ "$lnd_electrum_url" != *:* ]]; then
                if [[ "$_scheme" == "ssl" ]]; then
                    lnd_electrum_url="${lnd_electrum_url}:50002"
                else
                    lnd_electrum_url="${lnd_electrum_url}:50001"
                fi
            fi
            lnd_electrum_url="${_scheme}://${lnd_electrum_url}"
        fi
        if [[ "$_orig" != "$lnd_electrum_url" ]]; then
            warn "Normalised electrum URL → ${lnd_electrum_url}"
        fi
    fi

    # ── BOLT 12 (offered to all users; details live under Advanced) ──
    echo ""
    echo -e "  ${DIM}BOLT 12 lets payers (e.g. the Ocean mining pool) send Lightning payouts${RESET}"
    echo -e "  ${DIM}to a single reusable offer string. Recommended for most users.${RESET}"
    local bolt12_enabled_initial
    bolt12_enabled_initial="$(get_env BOLT12_ENABLED "true")"
    prompt_bool bolt12_enabled_initial "Enable BOLT 12 offers?" "$bolt12_enabled_initial"

    # ── Anonymize feature (offered to all users; details under Advanced) ──
    echo ""
    echo -e "  ${DIM}Anonymize: privacy-preserving UTXO and Lightning mixing via Boltz${RESET}"
    echo -e "  ${DIM}submarine/reverse swaps, Tor isolation, amount binning, randomized${RESET}"
    echo -e "  ${DIM}delays. Single-operator deployments work; tier caps at \"moderate\".${RESET}"
    echo -e "  ${DIM}See docs/anonymize.md for the full operator runbook.${RESET}"
    local anonymize_enabled_initial
    anonymize_enabled_initial="$(get_env ANONYMIZE_ENABLED "true")"
    prompt_bool anonymize_enabled_initial "Enable anonymize feature?" "$anonymize_enabled_initial"

    # ── Braiins Deposit (offered to all users; defaults are good) ──
    echo ""
    echo -e "  ${DIM}Braiins Deposit: guided round-amount deposit flow for Braiins Hashpower${RESET}"
    echo -e "  ${DIM}(and similar services). Converts Lightning balance to a fresh Taproot${RESET}"
    echo -e "  ${DIM}UTXO via Boltz, then sends a clean round amount on-chain — bypassing${RESET}"
    echo -e "  ${DIM}Braiins' anti-fraud manual-review delay. See docs/braiins_deposit.md.${RESET}"
    local braiins_deposit_enabled_initial
    braiins_deposit_enabled_initial="$(get_env BRAIINS_DEPOSIT_ENABLED "true")"
    prompt_bool braiins_deposit_enabled_initial "Enable Braiins Deposit?" "$braiins_deposit_enabled_initial"

    # ── Generate / preserve at-rest encryption keys ──
    # The anonymize feature requires several Fernet bundles + an HMAC
    # account key. Generate any that are unset; preserve existing keys
    # so re-running the wizard doesn't invalidate in-flight sessions.
    local anonymize_reuse_detection_key_fernet
    local anonymize_hop_idempotency_key_fernet
    local anonymize_quote_token_hmac_key_fernet
    local anonymize_quote_cache_signing_key_fernet
    local anonymize_stepup_cookie_hmac_key_fernet
    local anonymize_decoy_seed_fernet
    local anonymize_decoy_seed_account_key
    local anonymize_liquid_seed_fernet
    local _gen_fernet _gen_b64

    # Lazy helper — the cryptography wheel is already a transitive
    # dependency of the wallet, so this works in any env that has
    # successfully booted the wallet itself.
    _gen_fernet='python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"'
    _gen_b64='python3 -c "import secrets; print(secrets.token_urlsafe(32))"'

    # _fernet_valid: 0 if ``$1`` is a syntactically-valid Fernet key
    # (44 chars, base64-decodes to exactly 32 bytes), 1 otherwise.
    # Used to detect existing malformed values (e.g. unpadded
    # ``secrets.token_urlsafe(32)`` output from older wizard runs) so
    # we regenerate instead of preserving them — without this check
    # the wizard would silently propagate a broken key forever.
    _fernet_valid() {
        local val="$1"
        [[ -z "$val" ]] && return 1
        python3 -c "
import base64, sys
val = sys.argv[1]
try:
    decoded = base64.urlsafe_b64decode(val)
except Exception:
    sys.exit(1)
sys.exit(0 if len(decoded) == 32 else 1)
" "$val" 2>/dev/null
    }

    # _preserve_or_gen_fernet: read existing value; if missing OR
    # malformed AND anonymize is enabled, generate a fresh Fernet key.
    # Single helper so every Fernet env knob is handled identically
    # — no copy-pasted divergence between knobs.
    _preserve_or_gen_fernet() {
        local env_key="$1"
        local existing
        existing="$(get_env "$env_key" "")"
        if _fernet_valid "$existing"; then
            echo "$existing"
            return 0
        fi
        if [[ -n "$existing" ]]; then
            warn "${env_key} value is malformed; regenerating."
        fi
        if [[ "$anonymize_enabled_initial" == "true" ]]; then
            eval "$_gen_fernet" 2>/dev/null || echo ""
        else
            echo ""
        fi
    }

    anonymize_reuse_detection_key_fernet="$(_preserve_or_gen_fernet ANONYMIZE_REUSE_DETECTION_KEY_FERNET)"
    anonymize_hop_idempotency_key_fernet="$(_preserve_or_gen_fernet ANONYMIZE_HOP_IDEMPOTENCY_KEY_FERNET)"
    anonymize_quote_token_hmac_key_fernet="$(_preserve_or_gen_fernet ANONYMIZE_QUOTE_TOKEN_HMAC_KEY_FERNET)"
    anonymize_quote_cache_signing_key_fernet="$(_preserve_or_gen_fernet ANONYMIZE_QUOTE_CACHE_SIGNING_KEY_FERNET)"
    anonymize_stepup_cookie_hmac_key_fernet="$(_preserve_or_gen_fernet ANONYMIZE_STEPUP_COOKIE_HMAC_KEY_FERNET)"
    anonymize_decoy_seed_fernet="$(_preserve_or_gen_fernet ANONYMIZE_DECOY_SEED_FERNET)"
    anonymize_decoy_seed_account_key="$(get_env ANONYMIZE_DECOY_SEED_ACCOUNT_KEY "")"
    if [[ -z "$anonymize_decoy_seed_account_key" ]] && [[ "$anonymize_enabled_initial" == "true" ]]; then
        anonymize_decoy_seed_account_key="$(eval "$_gen_b64" 2>/dev/null || echo "")"
    fi
    # Liquid seed only generated when the Liquid hop is enabled
    # (advanced setting below); keys are generated lazily so a
    # disabled-Liquid deployment doesn't fill .env with unused secrets.
    anonymize_liquid_seed_fernet="$(get_env ANONYMIZE_LIQUID_SEED_FERNET "")"

    if [[ "$anonymize_enabled_initial" == "true" ]]; then
        # Operator-facing reminder. The Fernet keys above ARE the
        # encryption keys for destination addresses, hop-idempotency
        # state, and the decoy-output seed. Losing them is equivalent
        # to losing access to in-flight session state.
        echo ""
        warn "Anonymize at-rest keys generated and written to .env."
        warn "Back up .env separately from your LND wallet seed —"
        warn "  these keys + your LND seed together are required to"
        warn "  recover in-flight anonymize sessions across deployments."
    fi

    # ── Section: Advanced (optional) ──
    header "Advanced Settings"

    local show_advanced
    prompt_bool show_advanced "Configure advanced settings?" "false"

    local api_host api_port enable_docs log_level debug enable_hsts
    local lnd_rate_limit_sats lnd_rate_limit_window lnd_velocity_max lnd_velocity_window
    local boltz_use_tor boltz_fallback_clearnet
    local cors_origins
    local enable_sign_address_api enable_sign_node_api
    local sign_message_max_chars sign_audit_record_message
    local sign_rate_limit_per_hour sign_rate_limit_dashboard_per_hour
    local sign_address_autocomplete
    local bolt12_enabled bolt12_gateway_grpc bolt12_gateway_token
    local bolt12_accept_offerless_invreqs
    local bolt12_inbound_rate_limit_count bolt12_inbound_rate_limit_window_seconds
    local bolt12_inbound_max_amount_msat
    local bolt12_max_pending_requests bolt12_max_payload_bytes
    local bolt12_max_tlv_records bolt12_max_tlv_value_bytes
    local bolt12_max_outbound_invoice_bytes
    local bolt12_bip353_validate_resolver
    local bolt12_blinded_path_min_real_hops bolt12_blinded_path_max_paths
    local bolt12_blinded_path_omit_nodes
    local bolt12_gateway_node_address_refresh_interval_s
    local bolt12_gateway_node_address_max_nodes
    local bolt12_inbound_rate_limit_global_count
    local bolt12_inbound_max_concurrent_mints bolt12_inbound_mint_acquire_timeout_s
    local bolt12_settlement_subscriber_enabled
    local bolt12_request_retention_days bolt12_invoice_retention_days
    local bolt12_htlc_max_drift_ratio_alert
    local bolt12_htlc_event_subscriber_enabled bolt12_channel_snapshot_at_mint_enabled
    local bolt12_invoice_settle_watchdog_minutes
    local bolt12_htlc_max_safety_buffer_ppm bolt12_drop_undersized_paths
    local bolt12_probe_paths_before_mint bolt12_path_diversity_enforce
    local bolt12_path_breaker_enabled bolt12_path_breaker_failures_to_open
    local bolt12_path_breaker_initial_cooldown_s bolt12_path_breaker_cooldown_cap_s
    local bolt12_path_pigeonhole_pairing_enabled
    local bolt12_adaptive_depth_fallback_enabled
    local bolt12_subscriber_newnym_on_transport_error
    local bolt12_subscriber_transport_error_backoff_s
    local bolt12_subscriber_polling_mode_enabled
    local bolt12_subscriber_polling_interval_s
    local bolt12_subscriber_polling_mode_auto_detect
    local bolt12_subscriber_heartbeat_interval_s
    local bolt12_subscriber_warmup_probe_enabled
    local lnd_hs_descriptor_probe_interval_s
    local lnd_channel_uptime_track_interval_s
    local lnd_channel_flap_detect_interval_s
    local bolt12_inbound_supervisor_enabled
    local bolt12_inbound_supervisor_tick_interval_s
    local bolt12_inbound_supervisor_window_s
    local bolt12_inbound_supervisor_failure_threshold
    local bolt12_inbound_supervisor_healthy_lifetime_s
    local bolt12_inbound_supervisor_sighup_throttle_s
    local bolt12_inbound_supervisor_flap_threshold
    local bolt12_inbound_supervisor_hs_fetch_failure_threshold
    local lnd_hs_descriptor_failure_supervisor_threshold
    local lnd_inbound_burst_newnym_threshold
    local lnd_inbound_burst_window_s
    local tor_probe_url
    local trusted_proxies cookie_secure database_require_ssl
    local mempool_tls_verify mempool_allow_internal
    local chain_backend lnd_electrum_tls_verify lnd_electrum_ca_cert
    local lnd_electrum_ping_interval lnd_electrum_request_timeout
    local lnd_electrum_connect_timeout lnd_electrum_max_subscriptions
    local rate_limit_fail_policy api_key_max_ttl_days
    local dashboard_session_hours dashboard_idle_timeout_minutes dashboard_max_payment_sats
    local alert_webhook_url alert_webhook_events audit_log_retention_days
    local lnurl_force_tor lnurl_allow_http lnurl_allow_private_hosts
    local lnurl_max_response_bytes lnurl_resolve_timeout_seconds
    local lnurl_handle_ttl_seconds lnurl_invoice_cache_ttl_seconds

    # ── Anonymize advanced (set in the Advanced section below) ──
    local anonymize_enabled anonymize_require_tor anonymize_enforce_onion_only_egress
    local anonymize_min_sat anonymize_max_sat anonymize_amount_bins_sat
    local anonymize_tor_socks_ports
    local boltz_submarine_onion_url boltz_reverse_onion_url
    local anonymize_destination_retention_days anonymize_hard_delete_after_days
    local anonymize_tier_concurrency_cap
    local anonymize_decoy_seed_required
    local anonymize_refuse_decoy_override_spends anonymize_refuse_refund_override_spends
    local anonymize_registry_release_key_fingerprints anonymize_registry_sig_path
    local anonymize_registry_require_threshold_sig anonymize_registry_threshold_k
    local anonymize_registry_threshold_sig_paths
    local anonymize_liquid_enabled anonymize_liquid_electrum_url
    local anonymize_liquid_btc_asset_id anonymize_liquid_integration_verified
    local enable_liquid elementsd_rpc_user elementsd_rpc_password elementsd_rpc_allow_cidr
    local anonymize_bip353_doh_endpoint anonymize_bip353_cache_min_ttl_s
    local anonymize_bip353_deposit_domain anonymize_ext_lightning_deposit_method

    api_host="$(get_env API_HOST "127.0.0.1")"
    api_port="$(get_env API_PORT "8100")"
    enable_docs="$(get_env ENABLE_DOCS "false")"
    log_level="$(get_env LOG_LEVEL "info")"
    debug="$(get_env DEBUG "false")"
    enable_hsts="$(get_env ENABLE_HSTS "false")"
    lnd_rate_limit_sats="$(get_env LND_RATE_LIMIT_SATS "100000")"
    lnd_rate_limit_window="$(get_env LND_RATE_LIMIT_WINDOW_SECONDS "3600")"
    lnd_velocity_max="$(get_env LND_VELOCITY_MAX_TXNS "5")"
    lnd_velocity_window="$(get_env LND_VELOCITY_WINDOW_SECONDS "900")"
    boltz_use_tor="$(get_env BOLTZ_USE_TOR "true")"
    boltz_fallback_clearnet="$(get_env BOLTZ_FALLBACK_CLEARNET "false")"
    # ── Braiins Deposit defaults ──
    braiins_deposit_enabled="$braiins_deposit_enabled_initial"
    braiins_deposit_confirmations_before_send="$(get_env BRAIINS_DEPOSIT_CONFIRMATIONS_BEFORE_SEND "1")"
    braiins_deposit_confirmations_for_completion="$(get_env BRAIINS_DEPOSIT_CONFIRMATIONS_FOR_COMPLETION "1")"
    braiins_deposit_broadcast_stuck_blocks="$(get_env BRAIINS_DEPOSIT_BROADCAST_STUCK_BLOCKS "144")"
    braiins_deposit_safety_buffer_sats="$(get_env BRAIINS_DEPOSIT_SAFETY_BUFFER_SATS "1000")"
    braiins_deposit_quote_staleness_pct="$(get_env BRAIINS_DEPOSIT_QUOTE_STALENESS_PCT "10")"
    braiins_deposit_lnd_transient_max_age_s="$(get_env BRAIINS_DEPOSIT_LND_TRANSIENT_MAX_AGE_S "3600")"
    braiins_deposit_created_ttl_s="$(get_env BRAIINS_DEPOSIT_CREATED_TTL_S "300")"
    braiins_deposit_send_fee_priority="$(get_env BRAIINS_DEPOSIT_SEND_FEE_PRIORITY "medium")"
    cors_origins="$(get_env CORS_ORIGINS "")"
    enable_sign_address_api="$(get_env ENABLE_SIGN_ADDRESS_API "true")"
    enable_sign_node_api="$(get_env ENABLE_SIGN_NODE_API "true")"
    sign_message_max_chars="$(get_env SIGN_MESSAGE_MAX_CHARS "4096")"
    sign_audit_record_message="$(get_env SIGN_AUDIT_RECORD_MESSAGE "false")"
    sign_rate_limit_per_hour="$(get_env SIGN_RATE_LIMIT_PER_HOUR "30")"
    sign_rate_limit_dashboard_per_hour="$(get_env SIGN_RATE_LIMIT_DASHBOARD_PER_HOUR "60")"
    sign_address_autocomplete="$(get_env SIGN_ADDRESS_AUTOCOMPLETE "txn_history")"
    bolt12_enabled="$bolt12_enabled_initial"
    bolt12_gateway_grpc="$(get_env BOLT12_GATEWAY_GRPC "bolt12-gateway:50061")"
    # Auto-generate a bearer token when missing so a fresh
    # install with BOLT12_ENABLED=true and DEBUG=false (the typical
    # production combo) doesn't trip the runtime's refuse-to-dial-
    # unauthenticated guard. Existing tokens are preserved.
    bolt12_gateway_token="$(get_env BOLT12_GATEWAY_TOKEN "$gen_bolt12_token")"
    if [[ -z "$bolt12_gateway_token" ]]; then
        bolt12_gateway_token="$gen_bolt12_token"
    fi
    bolt12_accept_offerless_invreqs="$(get_env BOLT12_ACCEPT_OFFERLESS_INVREQS "false")"
    bolt12_inbound_rate_limit_count="$(get_env BOLT12_INBOUND_RATE_LIMIT_COUNT "30")"
    bolt12_inbound_rate_limit_window_seconds="$(get_env BOLT12_INBOUND_RATE_LIMIT_WINDOW_SECONDS "60")"
    bolt12_inbound_max_amount_msat="$(get_env BOLT12_INBOUND_MAX_AMOUNT_MSAT "100000000")"
    bolt12_max_pending_requests="$(get_env BOLT12_MAX_PENDING_REQUESTS "64")"
    bolt12_max_payload_bytes="$(get_env BOLT12_MAX_PAYLOAD_BYTES "65536")"
    bolt12_max_outbound_invoice_bytes="$(get_env BOLT12_MAX_OUTBOUND_INVOICE_BYTES "32768")"
    bolt12_inbound_rate_limit_global_count="$(get_env BOLT12_INBOUND_RATE_LIMIT_GLOBAL_COUNT "300")"
    bolt12_inbound_max_concurrent_mints="$(get_env BOLT12_INBOUND_MAX_CONCURRENT_MINTS "16")"
    bolt12_inbound_mint_acquire_timeout_s="$(get_env BOLT12_INBOUND_MINT_ACQUIRE_TIMEOUT_S "5")"
    bolt12_settlement_subscriber_enabled="$(get_env BOLT12_SETTLEMENT_SUBSCRIBER_ENABLED "true")"
    bolt12_request_retention_days="$(get_env BOLT12_REQUEST_RETENTION_DAYS "90")"
    bolt12_invoice_retention_days="$(get_env BOLT12_INVOICE_RETENTION_DAYS "90")"
    bolt12_htlc_max_drift_ratio_alert="$(get_env BOLT12_HTLC_MAX_DRIFT_RATIO_ALERT "1.5")"
    bolt12_htlc_event_subscriber_enabled="$(get_env BOLT12_HTLC_EVENT_SUBSCRIBER_ENABLED "true")"
    bolt12_channel_snapshot_at_mint_enabled="$(get_env BOLT12_CHANNEL_SNAPSHOT_AT_MINT_ENABLED "true")"
    bolt12_invoice_settle_watchdog_minutes="$(get_env BOLT12_INVOICE_SETTLE_WATCHDOG_MINUTES "5")"
    bolt12_htlc_max_safety_buffer_ppm="$(get_env BOLT12_HTLC_MAX_SAFETY_BUFFER_PPM "10000")"
    bolt12_drop_undersized_paths="$(get_env BOLT12_DROP_UNDERSIZED_PATHS "true")"
    bolt12_blinded_path_refresh_policy_from_gossip="$(get_env BOLT12_BLINDED_PATH_REFRESH_POLICY_FROM_GOSSIP "true")"
    bolt12_blinded_path_payinfo_safety_margin_ppm="$(get_env BOLT12_BLINDED_PATH_PAYINFO_SAFETY_MARGIN_PPM "1000")"
    bolt12_blinded_path_payinfo_safety_margin_base_msat="$(get_env BOLT12_BLINDED_PATH_PAYINFO_SAFETY_MARGIN_BASE_MSAT "1500")"
    bolt12_probe_paths_before_mint="$(get_env BOLT12_PROBE_PATHS_BEFORE_MINT "false")"
    bolt12_path_diversity_enforce="$(get_env BOLT12_PATH_DIVERSITY_ENFORCE "true")"
    bolt12_path_breaker_enabled="$(get_env BOLT12_PATH_BREAKER_ENABLED "true")"
    bolt12_path_breaker_failures_to_open="$(get_env BOLT12_PATH_BREAKER_FAILURES_TO_OPEN "2")"
    bolt12_path_breaker_initial_cooldown_s="$(get_env BOLT12_PATH_BREAKER_INITIAL_COOLDOWN_S "600")"
    bolt12_path_breaker_cooldown_cap_s="$(get_env BOLT12_PATH_BREAKER_COOLDOWN_CAP_S "86400")"
    bolt12_path_pigeonhole_pairing_enabled="$(get_env BOLT12_PATH_PIGEONHOLE_PAIRING_ENABLED "true")"
    bolt12_adaptive_depth_fallback_enabled="$(get_env BOLT12_ADAPTIVE_DEPTH_FALLBACK_ENABLED "true")"
    bolt12_subscriber_newnym_on_transport_error="$(get_env BOLT12_SUBSCRIBER_NEWNYM_ON_TRANSPORT_ERROR "true")"
    bolt12_subscriber_transport_error_backoff_s="$(get_env BOLT12_SUBSCRIBER_TRANSPORT_ERROR_BACKOFF_S "2.0")"
    bolt12_subscriber_polling_mode_enabled="$(get_env BOLT12_SUBSCRIBER_POLLING_MODE_ENABLED "false")"
    bolt12_subscriber_polling_interval_s="$(get_env BOLT12_SUBSCRIBER_POLLING_INTERVAL_S "5")"
    bolt12_subscriber_polling_mode_auto_detect="$(get_env BOLT12_SUBSCRIBER_POLLING_MODE_AUTO_DETECT "true")"
    bolt12_subscriber_heartbeat_interval_s="$(get_env BOLT12_SUBSCRIBER_HEARTBEAT_INTERVAL_S "300")"
    bolt12_subscriber_warmup_probe_enabled="$(get_env BOLT12_SUBSCRIBER_WARMUP_PROBE_ENABLED "true")"
    lnd_hs_descriptor_probe_interval_s="$(get_env LND_HS_DESCRIPTOR_PROBE_INTERVAL_S "600")"
    lnd_channel_uptime_track_interval_s="$(get_env LND_CHANNEL_UPTIME_TRACK_INTERVAL_S "30")"
    lnd_channel_flap_detect_interval_s="$(get_env LND_CHANNEL_FLAP_DETECT_INTERVAL_S "5")"
    bolt12_inbound_supervisor_enabled="$(get_env BOLT12_INBOUND_SUPERVISOR_ENABLED "true")"
    bolt12_inbound_supervisor_tick_interval_s="$(get_env BOLT12_INBOUND_SUPERVISOR_TICK_INTERVAL_S "30")"
    bolt12_inbound_supervisor_window_s="$(get_env BOLT12_INBOUND_SUPERVISOR_WINDOW_S "300")"
    bolt12_inbound_supervisor_failure_threshold="$(get_env BOLT12_INBOUND_SUPERVISOR_FAILURE_THRESHOLD "10")"
    bolt12_inbound_supervisor_healthy_lifetime_s="$(get_env BOLT12_INBOUND_SUPERVISOR_HEALTHY_LIFETIME_S "30.0")"
    bolt12_inbound_supervisor_sighup_throttle_s="$(get_env BOLT12_INBOUND_SUPERVISOR_SIGHUP_THROTTLE_S "3600")"
    bolt12_inbound_supervisor_flap_threshold="$(get_env BOLT12_INBOUND_SUPERVISOR_FLAP_THRESHOLD "3")"
    bolt12_inbound_supervisor_hs_fetch_failure_threshold="$(get_env BOLT12_INBOUND_SUPERVISOR_HS_FETCH_FAILURE_THRESHOLD "1")"
    lnd_hs_descriptor_failure_supervisor_threshold="$(get_env LND_HS_DESCRIPTOR_FAILURE_SUPERVISOR_THRESHOLD "3")"
    lnd_inbound_burst_newnym_threshold="$(get_env LND_INBOUND_BURST_NEWNYM_THRESHOLD "2")"
    lnd_inbound_burst_window_s="$(get_env LND_INBOUND_BURST_WINDOW_S "300")"
    tor_probe_url="$(get_env TOR_PROBE_URL "https://1.1.1.1/cdn-cgi/trace")"
    bolt12_max_tlv_records="$(get_env BOLT12_MAX_TLV_RECORDS "512")"
    bolt12_max_tlv_value_bytes="$(get_env BOLT12_MAX_TLV_VALUE_BYTES "8192")"
    bolt12_bip353_validate_resolver="$(get_env BOLT12_BIP353_VALIDATE_RESOLVER "true")"
    bolt12_blinded_path_min_real_hops="$(get_env BOLT12_BLINDED_PATH_MIN_REAL_HOPS "2")"
    bolt12_blinded_path_max_paths="$(get_env BOLT12_BLINDED_PATH_MAX_PATHS "2")"
    bolt12_blinded_path_omit_nodes="$(get_env BOLT12_BLINDED_PATH_OMIT_NODES "026165850492521f4ac8abd9bd8088123446d126f648ca35e60f88177dc149ceb2")"
    bolt12_gateway_node_address_refresh_interval_s="$(get_env BOLT12_GATEWAY_NODE_ADDRESS_REFRESH_INTERVAL_S "3600")"
    bolt12_gateway_node_address_max_nodes="$(get_env BOLT12_GATEWAY_NODE_ADDRESS_MAX_NODES "5000")"

    trusted_proxies="$(get_env TRUSTED_PROXIES "")"
    cookie_secure="$(get_env COOKIE_SECURE "true")"
    database_require_ssl="$(get_env DATABASE_REQUIRE_SSL "false")"
    mempool_tls_verify="$(get_env MEMPOOL_TLS_VERIFY "true")"
    mempool_allow_internal="$(get_env MEMPOOL_ALLOW_INTERNAL "false")"
    # Chain backend (electrs) — URL was prompted above; the rest are
    # passed through as advanced defaults.
    chain_backend="$(get_env CHAIN_BACKEND "auto")"
    lnd_electrum_tls_verify="$(get_env LND_ELECTRUM_TLS_VERIFY "true")"
    lnd_electrum_ca_cert="$(get_env LND_ELECTRUM_CA_CERT "")"
    lnd_electrum_ping_interval="$(get_env LND_ELECTRUM_PING_INTERVAL_S "30")"
    lnd_electrum_request_timeout="$(get_env LND_ELECTRUM_REQUEST_TIMEOUT_S "8")"
    lnd_electrum_connect_timeout="$(get_env LND_ELECTRUM_CONNECT_TIMEOUT_S "10")"
    lnd_electrum_max_subscriptions="$(get_env LND_ELECTRUM_MAX_SUBSCRIPTIONS "256")"
    rate_limit_fail_policy="$(get_env RATE_LIMIT_FAIL_POLICY "closed")"
    api_key_max_ttl_days="$(get_env API_KEY_MAX_TTL_DAYS "365")"
    dashboard_session_hours="$(get_env DASHBOARD_SESSION_HOURS "4")"
    dashboard_idle_timeout_minutes="$(get_env DASHBOARD_IDLE_TIMEOUT_MINUTES "30")"
    dashboard_max_payment_sats="$(get_env DASHBOARD_MAX_PAYMENT_SATS "-1")"
    alert_webhook_url="$(get_env ALERT_WEBHOOK_URL "")"
    alert_webhook_events="$(get_env ALERT_WEBHOOK_EVENTS "login_failed,tor_fallback,lnd_disconnect,rate_limit_bypass,auth_brute_force,csrf_violation")"
    audit_log_retention_days="$(get_env AUDIT_LOG_RETENTION_DAYS "90")"
    lnurl_force_tor="$(get_env LNURL_FORCE_TOR "auto")"
    lnurl_allow_http="$(get_env LNURL_ALLOW_HTTP "false")"
    lnurl_allow_private_hosts="$(get_env LNURL_ALLOW_PRIVATE_HOSTS "false")"
    lnurl_max_response_bytes="$(get_env LNURL_MAX_RESPONSE_BYTES "100000")"
    lnurl_resolve_timeout_seconds="$(get_env LNURL_RESOLVE_TIMEOUT_SECONDS "15.0")"
    lnurl_handle_ttl_seconds="$(get_env LNURL_HANDLE_TTL_SECONDS "300")"
    lnurl_invoice_cache_ttl_seconds="$(get_env LNURL_INVOICE_CACHE_TTL_SECONDS "30")"

    # ── Anonymize defaults ──
    anonymize_enabled="$anonymize_enabled_initial"
    anonymize_require_tor="$(get_env ANONYMIZE_REQUIRE_TOR "true")"
    anonymize_enforce_onion_only_egress="$(get_env ANONYMIZE_ENFORCE_ONION_ONLY_EGRESS "true")"
    anonymize_min_sat="$(get_env ANONYMIZE_MIN_SAT "50000")"
    anonymize_max_sat="$(get_env ANONYMIZE_MAX_SAT "10000000")"
    anonymize_amount_bins_sat="$(get_env ANONYMIZE_AMOUNT_BINS_SAT "10000,25000,50000,100000,250000,500000,1000000,2500000,5000000,10000000")"
    anonymize_tor_socks_ports="$(get_env ANONYMIZE_TOR_SOCKS_PORTS "boltz_submarine=9050,boltz_reverse=9051,liquid=9052,chain_backend=9053,bip353_dns=9054,quote_cache_refresh=9055,chain_backend_general=9056,chain_backend_anonymize=9057")"
    boltz_submarine_onion_url="$(get_env BOLTZ_SUBMARINE_ONION_URL "")"
    boltz_reverse_onion_url="$(get_env BOLTZ_REVERSE_ONION_URL "")"
    # Chain-composition env vars (blank → default-computation rule).
    anonymize_submarine_operator_primary="$(get_env ANONYMIZE_SUBMARINE_OPERATOR_PRIMARY "")"
    anonymize_submarine_operator_secondary="$(get_env ANONYMIZE_SUBMARINE_OPERATOR_SECONDARY "")"
    anonymize_reverse_operator="$(get_env ANONYMIZE_REVERSE_OPERATOR "")"
    # Chain-selector probe timing. Defaults are calibrated
    # for typical Tor cold-start; tighten only if circuits are fast.
    anonymize_operator_probe_timeout_s="$(get_env ANONYMIZE_OPERATOR_PROBE_TIMEOUT_S "6.0")"
    anonymize_operator_probe_cache_ttl_s="$(get_env ANONYMIZE_OPERATOR_PROBE_CACHE_TTL_S "60.0")"
    anonymize_destination_retention_days="$(get_env ANONYMIZE_DESTINATION_RETENTION_DAYS "7")"
    anonymize_hard_delete_after_days="$(get_env ANONYMIZE_HARD_DELETE_AFTER_DAYS "365")"
    anonymize_tier_concurrency_cap="$(get_env ANONYMIZE_TIER_CONCURRENCY_CAP "weak=3,moderate=2,strong=1")"
    anonymize_decoy_seed_required="$(get_env ANONYMIZE_DECOY_SEED_REQUIRED "true")"
    anonymize_refuse_decoy_override_spends="$(get_env ANONYMIZE_REFUSE_DECOY_OVERRIDE_SPENDS "false")"
    anonymize_refuse_refund_override_spends="$(get_env ANONYMIZE_REFUSE_REFUND_OVERRIDE_SPENDS "false")"
    # Default to the v1 release-maintainer fingerprint (Paul Lamb,
    # https://paulscode.com); forks should replace this + maintainer.asc.
    anonymize_registry_release_key_fingerprints="$(get_env ANONYMIZE_REGISTRY_RELEASE_KEY_FINGERPRINTS "FF76D4843EBD7FA06D92DC0CB8AB7B8E7E280E1A")"
    anonymize_registry_sig_path="$(get_env ANONYMIZE_REGISTRY_SIG_PATH "app/services/anonymize/operators.sig")"
    anonymize_registry_require_threshold_sig="$(get_env ANONYMIZE_REGISTRY_REQUIRE_THRESHOLD_SIG "false")"
    anonymize_registry_threshold_k="$(get_env ANONYMIZE_REGISTRY_THRESHOLD_K "2")"
    anonymize_registry_threshold_sig_paths="$(get_env ANONYMIZE_REGISTRY_THRESHOLD_SIG_PATHS "")"
    anonymize_liquid_enabled="$(get_env ANONYMIZE_LIQUID_ENABLED "false")"
    anonymize_liquid_electrum_url="$(get_env ANONYMIZE_LIQUID_ELECTRUM_URL "")"
    anonymize_liquid_btc_asset_id="$(get_env ANONYMIZE_LIQUID_BTC_ASSET_ID "")"
    # Default true: the in-repo regtest E2E harness (see
    # tests/integration/anonymize/test_liquid_e2e_regtest.py) gates
    # any release that flips defaults, so downstream operators don't
    # each re-validate. Flipping to false is a kill-switch.
    anonymize_liquid_integration_verified="$(get_env ANONYMIZE_LIQUID_INTEGRATION_VERIFIED "true")"
    # Umbrella overlay flag — drives whether start.sh's compose-up
    # commands include docker-compose.liquid.yml. Defaults to mirror
    # the master switch.
    enable_liquid="$(get_env ENABLE_LIQUID "$anonymize_liquid_enabled")"
    # Whether to also activate the ``liquid-indexer`` compose
    # profile (electrs-liquid container). Off by default because
    # the embedded indexer is the heavy component: ~19 GiB IBD
    # peak, ~16 GiB structural floor at every boot (Liquid
    # mainnet rust-elements headers are 1–4 KiB each and the
    # full header index is held in RAM), ~75 GB disk. Unsuitable
    # for small-VPS deployments. See docs/anonymize.md "Sizing
    # the host" for the full breakdown.
    # When ``false``, only ``elementsd`` is brought up by the
    # overlay and ``ANONYMIZE_LIQUID_ELECTRUM_URL`` MUST point
    # at an external Liquid Electrum endpoint.
    enable_liquid_indexer="$(get_env ENABLE_LIQUID_INDEXER "false")"
    elementsd_rpc_user="$(get_env ELEMENTSD_RPC_USER "elements")"
    elementsd_rpc_password="$(get_env ELEMENTSD_RPC_PASSWORD "")"
    elementsd_rpc_allow_cidr="$(get_env ELEMENTSD_RPC_ALLOW_CIDR "172.16.0.0/12")"
    anonymize_bip353_doh_endpoint="$(get_env ANONYMIZE_BIP353_DOH_ENDPOINT "https://dns.mullvad.net/dns-query")"
    anonymize_bip353_cache_min_ttl_s="$(get_env ANONYMIZE_BIP353_CACHE_MIN_TTL_S "86400")"
    anonymize_bip353_deposit_domain="$(get_env ANONYMIZE_BIP353_DEPOSIT_DOMAIN "")"
    anonymize_ext_lightning_deposit_method="$(get_env ANONYMIZE_EXT_LIGHTNING_DEPOSIT_METHOD "bolt11")"

    if [[ "$show_advanced" == "true" ]]; then
        prompt_value  api_port             "API port"                        "$api_port"
        prompt_bool   enable_docs          "Enable API docs (/docs)?"       "$enable_docs"
        prompt_choice log_level            "Log level"                      "$log_level" "debug" "info" "warning" "error"
        prompt_bool   debug                "Debug mode?"                    "$debug"
        prompt_bool   enable_hsts          "Enable HSTS?"                  "$enable_hsts"
        echo ""
        prompt_value  lnd_rate_limit_sats  "Rate limit (sats/window)"      "$lnd_rate_limit_sats"
        prompt_value  lnd_rate_limit_window "Rate limit window (seconds)"  "$lnd_rate_limit_window"
        prompt_value  lnd_velocity_max     "Max txns per velocity window"  "$lnd_velocity_max"
        prompt_value  lnd_velocity_window  "Velocity window (seconds)"     "$lnd_velocity_window"
        echo ""
        prompt_bool   boltz_use_tor        "Route Boltz via Tor?"          "$boltz_use_tor"
        prompt_bool   boltz_fallback_clearnet "Boltz clearnet fallback?"   "$boltz_fallback_clearnet"
        echo ""
        prompt_value  cors_origins         "CORS origins (JSON array)"     "$cors_origins"
        echo ""
        echo -e "  ${DIM}Sign / Verify Message: opt-in API for signing arbitrary messages${RESET}"
        echo -e "  ${DIM}with on-chain or LN node keys. Dashboard modal works regardless.${RESET}"
        prompt_bool   enable_sign_address_api "Enable on-chain sign API?"   "$enable_sign_address_api"
        prompt_bool   enable_sign_node_api    "Enable node-identity sign API?" "$enable_sign_node_api"
        prompt_bool   sign_audit_record_message "Store plaintext signed messages in audit log?" "$sign_audit_record_message"
        prompt_value  sign_message_max_chars  "Max signed-message length"   "$sign_message_max_chars"
        prompt_value  sign_rate_limit_per_hour "Sign rate limit per API key (per hour)" "$sign_rate_limit_per_hour"
        prompt_value  sign_rate_limit_dashboard_per_hour "Sign rate limit per dashboard session (per hour)" "$sign_rate_limit_dashboard_per_hour"
        prompt_choice sign_address_autocomplete "Dashboard address autocomplete source" "$sign_address_autocomplete" "txn_history" "wallet_addresses" "off"
        echo ""
        echo -e "  ${DIM}BOLT 12 (offers): pairs with the bolt12-gateway sidecar.${RESET}"
        echo -e "  ${DIM}Docker Compose builds + runs the gateway automatically.${RESET}"
        echo -e "  ${DIM}Standalone mode requires the gateway to be running externally.${RESET}"
        prompt_bool   bolt12_enabled       "Enable BOLT 12 offers?"        "$bolt12_enabled"
        if [[ "$bolt12_enabled" == "true" ]]; then
            prompt_value bolt12_gateway_grpc "BOLT 12 gateway gRPC target"  "$bolt12_gateway_grpc"
        fi
        echo ""
        echo -e "  ${DIM}LNURL-pay / Lightning Address: outbound HTTP fetches to recipient${RESET}"
        echo -e "  ${DIM}servers. ``auto`` mirrors LND's Tor posture (recommended).${RESET}"
        prompt_choice lnurl_force_tor       "Route LNURL fetches via Tor?" "$lnurl_force_tor" "auto" "true" "false"
        prompt_bool   lnurl_allow_http      "Allow plain http:// for clearnet recipients?" "$lnurl_allow_http"
        prompt_bool   lnurl_allow_private_hosts "Allow RFC1918/loopback recipients (regtest only)?" "$lnurl_allow_private_hosts"

        # ── Anonymize advanced prompts ──
        if [[ "$anonymize_enabled" == "true" ]]; then
            echo ""
            echo -e "  ${DIM}Anonymize: privacy-preserving UTXO + LN mixing. The bare-minimum${RESET}"
            echo -e "  ${DIM}deployment is a single Boltz operator + auto-generated Fernet keys${RESET}"
            echo -e "  ${DIM}(handled above). The settings below tune the threat model.${RESET}"
            prompt_bool  anonymize_require_tor               "Require Tor for anonymize egress?"            "$anonymize_require_tor"
            prompt_bool  anonymize_enforce_onion_only_egress "Refuse non-.onion endpoints at startup?"      "$anonymize_enforce_onion_only_egress"
            prompt_value anonymize_min_sat                   "Anonymize min amount (sat)"                   "$anonymize_min_sat"
            prompt_value anonymize_max_sat                   "Anonymize max amount (sat)"                   "$anonymize_max_sat"
            prompt_value anonymize_destination_retention_days "Destination retention (days)"                "$anonymize_destination_retention_days"

            echo ""
            echo -e " ${DIM}Operator-diversity: one operator per swap leg avoids${RESET}"
            echo -e "  ${DIM}giving either operator both ends of the mix. The default chain${RESET}"
            echo -e "  ${DIM}puts canonical Boltz on the REVERSE leg (where it sees only${RESET}"
            echo -e "  ${DIM}the destination address) and curated alt operators on the${RESET}"
            echo -e "  ${DIM}SUBMARINE leg, with a pre-funding fallback chain so a single${RESET}"
            echo -e "  ${DIM}alt outage doesn't force you to abandon a session.${RESET}"
            echo -e "  ${DIM}See docs/anonymize_operator_diversity.md for the full rationale.${RESET}"

            # ── Curated alt-operator picks (offered when both URLs are blank
            # AND no explicit ANONYMIZE_*_OPERATOR_* override is set).
            #
            # IMPORTANT: the default install leaves both BOLTZ_*_ONION_URL vars
            # blank so the chain-selection logic (operator_selection.py)
            # governs the picks. Setting either URL var bypasses the chain
            # and disables the fallback — exposed below as a power-user
            # override only.
            local _mw_onion="http://middlwayksj5gak7pgaag32kcslzkjrpois57qtquiydpaqpy5fhzhqd.onion/v2"
            local _eldamar_onion="http://mnyazp2duhs3jewqzw7g6vv44g73ijiujdmk5z6js72fn3epybup2yqd.onion/v2"
            local acknowledge_chain="false"

            if [[ -z "$boltz_submarine_onion_url" && -z "$boltz_reverse_onion_url" \
                  && -z "$anonymize_submarine_operator_primary" \
                  && -z "$anonymize_submarine_operator_secondary" \
                  && -z "$anonymize_reverse_operator" ]]; then
                echo ""
                echo -e "  ${BOLD}Default operator chain (as of 2026-05-13):${RESET}"
                echo ""
                echo -e "  ${BOLD}Submarine leg, primary:${RESET}  ${DIM}Middle Way${RESET}"
                echo -e "     ${DIM}6 channels, 300M sat capacity, max-send 25M${RESET}"
                echo -e "     ${YELLOW}!${RESET} contact link (igit.me/middleway) is unreachable —"
                echo -e "       ${DIM}if a session stalls, you have no operator-side recourse${RESET}"
                echo ""
                echo -e "  ${BOLD}Submarine leg, secondary:${RESET}  ${DIM}Eldamar${RESET}"
                echo -e "     ${GREEN}✓${RESET} operator is contactable"
                echo -e "     ${YELLOW}!${RESET} sessions ≥ 2.5M sat will fail at this operator —"
                echo -e "       ${DIM}the chain logic skips Eldamar for unsupported bins${RESET}"
                echo ""
                echo -e "  ${BOLD}Reverse leg:${RESET}  ${DIM}Boltz canonical${RESET}"
                echo -e "     ${GREEN}✓${RESET} highest volume; sees only the destination address"
                echo ""
                echo -e "  ${DIM}If both alts are unreachable at quote time, the wizard${RESET}"
                echo -e "  ${DIM}asks you whether to fall back to single-operator (Boltz on${RESET}"
                echo -e "  ${DIM}both legs, capped at moderate tier) or try again later.${RESET}"
                echo ""
                prompt_bool acknowledge_chain "Use the default chain (recommended)?" "true"

                if [[ "$acknowledge_chain" == "true" ]]; then
                    info "Default chain acknowledged. No env vars written — the chain logic"
                    info "in app/services/anonymize/operator_selection.py picks Middleway →"
                    info "Eldamar → single-operator-with-consent at quote time."
                    info "After install, verify reachability via:"
                    echo -e "    ${DIM}curl --socks5-hostname 127.0.0.1:9050 ${_mw_onion}/version${RESET}"
                    echo -e "    ${DIM}curl --socks5-hostname 127.0.0.1:9050 ${_eldamar_onion}/version${RESET}"
                else
                    echo ""
                    echo -e "  ${DIM}Skipped — you'll be prompted to set explicit operator IDs${RESET}"
                    echo -e "  ${DIM}below, or you can leave them blank to pick the defaults${RESET}"
                    echo -e "  ${DIM}at runtime regardless.${RESET}"
                fi
            else
                echo ""
                echo -e "  ${DIM}Existing operator configuration detected — skipping curated${RESET}"
                echo -e "  ${DIM}defaults. Manual override below.${RESET}"
            fi

            # Explicit operator-id override (registry-aware, fallback-preserving).
            echo ""
            prompt_value anonymize_submarine_operator_primary "Submarine primary operator_id (blank=Middleway via default-rule)" "$anonymize_submarine_operator_primary"
            prompt_value anonymize_submarine_operator_secondary "Submarine secondary operator_id (blank=Eldamar via default-rule)" "$anonymize_submarine_operator_secondary"
            prompt_value anonymize_reverse_operator "Reverse operator_id (blank=boltz-canonical via default-rule)" "$anonymize_reverse_operator"

            # Power-user URL pin (DISABLES the chain logic for that leg).
            echo ""
            echo -e "  ${DIM}WARNING: setting either URL below pins that leg to a single${RESET}"
            echo -e "  ${DIM}operator and disables the pre-funding fallback chain. Leave${RESET}"
            echo -e "  ${DIM}blank to keep the chain-driven defaults.${RESET}"
            prompt_value boltz_submarine_onion_url "Submarine-leg Boltz onion URL pin (disables chain — blank recommended)" "$boltz_submarine_onion_url"
            prompt_value boltz_reverse_onion_url   "Reverse-leg Boltz onion URL pin (disables chain — blank recommended)" "$boltz_reverse_onion_url"

            echo ""
            echo -e "  ${DIM}BIP-353 deposit handles: when a domain is configured, ext-lightning${RESET}"
            echo -e "  ${DIM}BOLT 12 sessions also emit a <random>@<domain> handle + DNS TXT${RESET}"
            echo -e "  ${DIM}record fragment for the operator to publish.${RESET}"
            prompt_value  anonymize_bip353_deposit_domain        "BIP-353 deposit domain (blank=disabled)" "$anonymize_bip353_deposit_domain"
            prompt_choice anonymize_ext_lightning_deposit_method "Default ext-lightning deposit method"   "$anonymize_ext_lightning_deposit_method" "bolt11" "bolt12"

            echo ""
            echo -e " ${DIM}Operator registry: comma-separated maintainer-key${RESET}"
            echo -e "  ${DIM}fingerprints trusted to sign operators.json. Default is the${RESET}"
            echo -e "  ${DIM}v1 release-maintainer GPG fingerprint (Paul Lamb / paulscode.com);${RESET}"
            echo -e "  ${DIM}the matching public key is bundled at app/services/anonymize/${RESET}"
            echo -e "  ${DIM}maintainer.asc. Forks should replace BOTH the fingerprint here${RESET}"
            echo -e "  ${DIM}AND the bundled maintainer.asc with their own.${RESET}"
            prompt_value anonymize_registry_release_key_fingerprints "Release-key fingerprints (comma-separated)" "$anonymize_registry_release_key_fingerprints"

            echo ""
            echo -e "  ${DIM}Liquid round-trip hop: CT-blinded L-BTC dwell between the${RESET}"
            echo -e "  ${DIM}submarine and reverse legs. When enabled, start.sh automatically${RESET}"
            echo -e "  ${DIM}adds docker-compose.liquid.yml to the compose invocation so an${RESET}"
            echo -e "  ${DIM}elementsd daemon comes up alongside the wallet.${RESET}"
            echo -e "  ${DIM}First boot does a multi-hour Liquid chain sync (~75 GB disk).${RESET}"
            echo -e "  ${DIM}Off by default.${RESET}"
            prompt_bool anonymize_liquid_enabled "Enable Liquid hop?" "$anonymize_liquid_enabled"
            if [[ "$anonymize_liquid_enabled" == "true" ]]; then
                echo ""
                echo -e "  ${DIM}Embedded electrs-liquid indexer: provides the Electrum API the${RESET}"
                echo -e "  ${DIM}wallet uses for Liquid chain reads.${RESET}"
                echo -e "  ${YELLOW}  ⚠  Heavy: ~19 GiB RAM IBD peak, ~16 GiB structural floor at${RESET}"
                echo -e "  ${DIM}    every boot (rust-elements Liquid headers are 1-4 KiB each${RESET}"
                echo -e "  ${DIM}    × ~3.9 M; the full header index is held in RAM). ~75 GB disk.${RESET}"
                echo -e "  ${DIM}    Plan for ~1 h IBD + ~30-60 min post-IBD compaction.${RESET}"
                echo -e "  ${DIM}    If your host has < 48 GiB RAM (with bitcoind/electrs/LND${RESET}"
                echo -e "  ${DIM}    alongside), answer 'no' here and point the URL below at an${RESET}"
                echo -e "  ${DIM}    external Liquid Electrum endpoint (Blockstream operates${RESET}"
                echo -e "  ${DIM}    public ones; or self-host on a separate beefier host).${RESET}"
                echo -e "  ${DIM}    See docs/anonymize.md 'Sizing the host'. Off by default.${RESET}"
                prompt_bool enable_liquid_indexer "Run embedded electrs-liquid indexer? (~19 GiB IBD peak / ~16 GiB structural floor)" "$enable_liquid_indexer"
                # Default the electrum URL based on the indexer choice
                # so the wizard's "press Enter to accept" path produces a
                # working config out of the box: indexer on → internal
                # hostname; indexer off → leave blank so the operator
                # is forced to point at an external endpoint they
                # actually have.
                if [[ -z "$anonymize_liquid_electrum_url" ]]; then
                    if [[ "$enable_liquid_indexer" == "true" ]]; then
                        anonymize_liquid_electrum_url="tcp://electrs-liquid:50001"
                    fi
                fi
                prompt_value anonymize_liquid_electrum_url           "Liquid Electrum URL"                "$anonymize_liquid_electrum_url"
                prompt_value anonymize_liquid_btc_asset_id           "L-BTC asset id (blank=network default)" "$anonymize_liquid_btc_asset_id"
                # Generate (or repair) the Liquid seed lazily when
                # enabled. Same validation as the other Fernet keys —
                # an unpadded base64 string from an older wizard run
                # gets regenerated instead of silently preserved.
                if ! _fernet_valid "$anonymize_liquid_seed_fernet"; then
                    if [[ -n "$anonymize_liquid_seed_fernet" ]]; then
                        warn "ANONYMIZE_LIQUID_SEED_FERNET value is malformed; regenerating."
                    fi
                    anonymize_liquid_seed_fernet="$(eval "$_gen_fernet" 2>/dev/null || echo "")"
                    if [[ -n "$anonymize_liquid_seed_fernet" ]]; then
                        warn "ANONYMIZE_LIQUID_SEED_FERNET generated — back up SEPARATELY from the primary LND seed."
                        fresh_liquid_seed="true"
                    fi
                fi
                # Auto-generate the elementsd RPC password when the
                # overlay is enabled and no existing value is present.
                # The placeholder rejection in _validate_env_secrets
                # refuses to launch with the legacy "change-me-in-
                # production" string, so an empty/missing value MUST
                # be regenerated here.
                if [[ -z "$elementsd_rpc_password" \
                      || "$elementsd_rpc_password" == "change-me-in-production" \
                      || "$elementsd_rpc_password" == "__REPLACE_ME__" ]]; then
                    elementsd_rpc_password="$(eval "$_gen_b64" 2>/dev/null || echo "")"
                    if [[ -n "$elementsd_rpc_password" ]]; then
                        warn "ELEMENTSD_RPC_PASSWORD generated for the Liquid overlay."
                    fi
                fi
                # Mirror into ENABLE_LIQUID so the compose-up logic
                # below knows to include docker-compose.liquid.yml.
                enable_liquid="true"
            else
                enable_liquid="false"
            fi
        fi
    fi

    # Derive the elementsd RPC auth line (user:salt$hmac) so the daemon
    # authenticates against a salted hash rather than carrying the
    # cleartext password on its command line, where it would be visible
    # in /proc/<pid>/cmdline and `docker inspect`. The salt rotates each
    # run; any salt validates the same password, so RPC clients continue
    # to use ELEMENTSD_RPC_USER/PASSWORD unchanged.
    #
    # The literal ``$`` between salt and hash is written to .env as ``$$``:
    # docker compose performs ``${VAR}`` interpolation on .env values, so a
    # bare ``$`` would be eaten (``salt$hash`` → ``salt``) and corrupt the
    # rpcauth. compose un-escapes ``$$`` back to a single ``$`` when it
    # passes the value to the container, restoring the real auth line.
    elementsd_rpc_auth=""
    if [[ -n "$elementsd_rpc_password" ]]; then
        elementsd_rpc_auth="$(python3 -c "
import hmac, os, sys
user, password = sys.argv[1], sys.argv[2]
salt = os.urandom(16).hex()
digest = hmac.new(salt.encode(), password.encode(), 'sha256').hexdigest()
print(f'{user}:{salt}\$\${digest}')
" "$elementsd_rpc_user" "$elementsd_rpc_password" 2>/dev/null || echo "")"
    fi

    # ── Write .env ──
    header "Writing .env"

    # Create the file with owner-only permissions before writing any
    # secrets, so there is no window where it is world-readable.
    ( umask 077; : > "$ENV_FILE" )

    cat > "$ENV_FILE" << ENVEOF
# ══════════════════════════════════════════════════════════════════════
# Agent Wallet — Environment Configuration
# Generated by start.sh on $(date -u '+%Y-%m-%d %H:%M UTC')
# ══════════════════════════════════════════════════════════════════════

# ── Application ──
SECRET_KEY=${secret_key}
DEBUG=${debug}
LOG_LEVEL=${log_level}
LOG_FORMAT=text
API_HOST=${api_host}
API_PORT=${api_port}
ENABLE_DOCS=${enable_docs}
ENABLE_HSTS=${enable_hsts}
# Set the Secure flag on auth cookies. Set to false ONLY for plain-HTTP
# local development; leave true behind any TLS terminator.
COOKIE_SECURE=${cookie_secure}
# Maximum API key lifetime in days (server-side cap on requested expiry).
API_KEY_MAX_TTL_DAYS=${api_key_max_ttl_days}

# Reverse-proxy CIDRs allowed to set X-Forwarded-For. REQUIRED when the
# dashboard is exposed behind a reverse proxy (nginx, Caddy, Cloudflare).
# Without this, request.client.host is the proxy's address — identical for
# every user — and dashboard session IP-binding silently provides no
# protection. Comma-separated CIDRs or JSON array.
TRUSTED_PROXIES=${trusted_proxies}

# ── Database (PostgreSQL) ──
DATABASE_URL=${database_url}
POSTGRES_PASSWORD=${postgres_password}
# Require SSL/TLS for non-localhost database connections (recommended for
# remote/managed databases).
DATABASE_REQUIRE_SSL=${database_require_ssl}

# ── Redis ──
REDIS_PASSWORD=${redis_password}
REDIS_URL=${redis_url}

# ── LND Node Connection ──
LND_REST_URL=${lnd_rest_url}
LND_MACAROON_HEX=${lnd_macaroon_hex}
LND_TLS_VERIFY=${lnd_tls_verify}
LND_TLS_CERT=${lnd_tls_cert}
LND_TOR_PROXY=${lnd_tor_proxy}

# ── Tor robustness knobs ──
# All have safe defaults; the wizard generates TOR_CONTROL_PASSWORD
# automatically. The standalone torrc that start.sh writes for non-
# Docker deploys consumes these same env vars (see _start_tor). The
# bundled tor-proxy entrypoint shim reads TOR_CONTROL_PASSWORD too,
# so one knob covers both launch modes.
# ControlPort auth password.
TOR_CONTROL_PASSWORD=${tor_control_password}
# Preventive age rotation cadence (days); 0 disables.
TOR_ROTATION_INTERVAL_DAYS=7
# Minimum seconds between watchdog NEWNYM signals.
TOR_NEWNYM_MIN_INTERVAL_S=60
# Watchdog tick cadence (seconds).
TOR_WATCHDOG_INTERVAL_S=30
# Tor breaker failure threshold.
TOR_BREAKER_FAILURE_THRESHOLD=5
# LND HS descriptor freshness check cadence (seconds).
TOR_HS_DESCRIPTOR_CHECK_INTERVAL_S=21600
# DataDirectory growth threshold (MB).
TOR_DATA_DIR_WARN_MB=100
# DataDirectory mount path. Empty disables the growth check
# (operators running their own Tor outside the compose stack).
TOR_DATA_DIR_MOUNT_PATH=/var/lib/tor
# Startup exit-relay diversity smoke test: blocking = refuse
# to start on observed circuit collision. Default non-blocking.
TOR_DIVERSITY_SMOKE_BLOCKING=false
# Split-mode Tor (separate tor-lnd + tor-anonymize). Default
# off; requires the docker-compose.tor-split.yml override to be in
# effect, NOT just this flag. See docs/operator_tor_runbook.md.
TOR_SPLIT_MODE=false
ANONYMIZE_TOR_SOCKS_HOST=tor-proxy
TOR_PROBE_URL=${tor_probe_url}
# Tor ControlPort host + port the wallet connects to for
# probes / watchdog / event stream. Default points at the bundled
# tor-proxy sibling container.
ANONYMIZE_TOR_CONTROL_HOST=tor-proxy
ANONYMIZE_TOR_CONTROL_PORT=9100
LND_TOR_CONTROL_HOST=
LND_TOR_CONTROL_PORT=9100

# ── LND Tor supervisor (stale-HS-descriptor auto-recovery) ──
# The supervisor watches _LND_BREAKER + corroborating signals and
# runs a staggered HSFETCH → NEWNYM → SIGHUP → healthcheck ladder
# when LND's hidden service goes unreachable via our Tor proxy.
# See docs/anonymize_troubleshooting.md "Request timed out — the node
# may be unreachable" for the operator runbook.
# Driver: 2026-06-01 stale-descriptor incident.
#
# Master kill switch. ``false`` reverts to the legacy single-watchdog behaviour:
# the existing tor_watchdog still fires NEWNYM on a Tor-classified
# LND failure, but the supervisor's surgical HSFETCH step + cycle-
# cap policy stay off.
LND_TOR_RECOVERY_ENABLED=true
# How long _LND_BREAKER must be open before signature detection
# considers it sustained.
LND_TOR_RECOVERY_DETECT_WINDOW_S=60
# Step 1 (HSFETCH) maximum wall time.
LND_TOR_RECOVERY_HSFETCH_TIMEOUT_S=60
# After step 2 (NEWNYM), wait this long for the breaker to close
# before escalating to step 3 (SIGHUP).
LND_TOR_RECOVERY_NEWNYM_WAIT_S=90
# After step 3 (SIGHUP), wait this long before yielding to the
# Docker healthcheck (step 4).
LND_TOR_RECOVERY_SIGHUP_WAIT_S=120
# Rolling 24 h cycle cap. 4+ cycles in 24 h disables the
# supervisor for the rest of the window — chronic LND-side
# issues should not look like a healthy auto-recovery loop.
LND_TOR_RECOVERY_MAX_CYCLES_PER_DAY=4
# C3 corroborating probe target. Empty → auto-resolve from
# LND_MEMPOOL_URL / LND_ELECTRUM_URL (first .onion wins). The
# supervisor probes up to 2 endpoints per detection; ≥1 success
# clears C3.
LND_TOR_RECOVERY_OTHER_ONION_PROBE_URL=
# Per-probe timeout for the C3 onion reachability check.
LND_TOR_RECOVERY_OTHER_ONION_TIMEOUT_S=10
# Backoff durations between cycles. Cycle 1 → 2 uses _15M_S,
# 2 → 3 uses _45M_S, 3 → 4 uses _2H_S; 4+ → disabled until the
# rolling 24 h window slides.
LND_TOR_RECOVERY_COOLDOWN_15M_S=900
LND_TOR_RECOVERY_COOLDOWN_45M_S=2700
LND_TOR_RECOVERY_COOLDOWN_2H_S=7200

# ── Mempool Explorer ──
LND_MEMPOOL_URL=${lnd_mempool_url}
# Disable only for self-hosted instances with self-signed certs.
MEMPOOL_TLS_VERIFY=${mempool_tls_verify}
# SSRF guard: refuses startup if LND_MEMPOOL_URL resolves to a
# private/loopback/link-local address. Set true ONLY when deliberately
# pointing at a self-hosted internal instance. Onion / .local hostnames
# are always allowed.
MEMPOOL_ALLOW_INTERNAL=${mempool_allow_internal}
# Public mempool URL the dashboard UI links to. Leave empty to derive
# from LND_MEMPOOL_URL when it's clearnet, falling back to mempool.space
# for onion configs (so links remain usable from a normal browser).
MEMPOOL_PUBLIC_URL=${mempool_public_url}

# ── Chain backend (optional electrs / Electrum server) ──
# auto = electrs primary with mempool HTTP fallback (recommended);
# electrum = strict, no fallback; mempool = legacy HTTP only.
CHAIN_BACKEND=${chain_backend}
LND_ELECTRUM_URL=${lnd_electrum_url}
# TLS verification for ssl:// URLs. Ignored for tcp:// and .onion.
LND_ELECTRUM_TLS_VERIFY=${lnd_electrum_tls_verify}
# Optional pinned CA bundle (PEM file path or base64-encoded PEM).
LND_ELECTRUM_CA_CERT=${lnd_electrum_ca_cert}
LND_ELECTRUM_PING_INTERVAL_S=${lnd_electrum_ping_interval}
LND_ELECTRUM_REQUEST_TIMEOUT_S=${lnd_electrum_request_timeout}
LND_ELECTRUM_CONNECT_TIMEOUT_S=${lnd_electrum_connect_timeout}
LND_ELECTRUM_MAX_SUBSCRIPTIONS=${lnd_electrum_max_subscriptions}

# ── Safety Limits ──
LND_MAX_PAYMENT_SATS=${lnd_max_payment_sats}
LND_RATE_LIMIT_SATS=${lnd_rate_limit_sats}
LND_RATE_LIMIT_WINDOW_SECONDS=${lnd_rate_limit_window}
LND_VELOCITY_MAX_TXNS=${lnd_velocity_max}
LND_VELOCITY_WINDOW_SECONDS=${lnd_velocity_window}
# Behaviour when Redis is unavailable: "closed" (default) refuses
# rate-limited and dashboard-session requests so caps cannot be bypassed;
# "open" allows them through. Leave as "closed" for production.
RATE_LIMIT_FAIL_POLICY=${rate_limit_fail_policy}

# ── Boltz Exchange ──
BOLTZ_API_URL=https://api.boltz.exchange/v2
BOLTZ_ONION_URL=http://boltzzzbnus4m7mta3cxmflnps4fp7dueu2tgurstbvrbt6xswzcocyd.onion/api/v2
BOLTZ_USE_TOR=${boltz_use_tor}
BOLTZ_FALLBACK_CLEARNET=${boltz_fallback_clearnet}

# ── Braiins Deposit (round-amount Hashpower deposit flow) ──
# See docs/braiins_deposit.md.
# Master kill-switch; hides the On-chain-tab button and 404s the API
# when false.
BRAIINS_DEPOSIT_ENABLED=${braiins_deposit_enabled}
# Confirmations required on the fresh Boltz claim UTXO before we send
# to the destination. 1 is reasonable on mainnet; raise for noisy
# chains or paranoid setups.
BRAIINS_DEPOSIT_CONFIRMATIONS_BEFORE_SEND=${braiins_deposit_confirmations_before_send}
# Confirmation threshold for the BROADCAST -> COMPLETED transition of
# the final send-to-Braiins tx.
BRAIINS_DEPOSIT_CONFIRMATIONS_FOR_COMPLETION=${braiins_deposit_confirmations_for_completion}
# Blocks-since-broadcast before we surface a non-fatal "tx hasn't
# confirmed" warning on the session detail. ~144 ≈ 1 day.
BRAIINS_DEPOSIT_BROADCAST_STUCK_BLOCKS=${braiins_deposit_broadcast_stuck_blocks}
# Extra headroom on the Boltz invoice amount above the round deposit
# + estimated send fee, to absorb fee drift between quote and send.
BRAIINS_DEPOSIT_SAFETY_BUFFER_SATS=${braiins_deposit_safety_buffer_sats}
# Percent drift between the wizard's submitted quote and a fresh
# server-side re-quote before we 409 and force re-confirmation.
BRAIINS_DEPOSIT_QUOTE_STALENESS_PCT=${braiins_deposit_quote_staleness_pct}
# Continuous LND-unavailability window before a "stuck for Ns" warning
# is appended to the session's error_message (never auto-FAIL).
BRAIINS_DEPOSIT_LND_TRANSIENT_MAX_AGE_S=${braiins_deposit_lnd_transient_max_age_s}
# Max dwell time in CREATED before a non-fatal warning is surfaced on
# the session detail.
BRAIINS_DEPOSIT_CREATED_TTL_S=${braiins_deposit_created_ttl_s}
# Default on-chain fee priority for the final send (low|medium|high).
# Operators can override per-session via the wizard's Advanced disclosure.
BRAIINS_DEPOSIT_SEND_FEE_PRIORITY=${braiins_deposit_send_fee_priority}

# ── Network ──
BITCOIN_NETWORK=${bitcoin_network}

# ── Dashboard ──
DASHBOARD_TOKEN=${dashboard_token}
ENABLE_DASHBOARD=${enable_dashboard}
# Session lifetime in hours (1–24). Idle timeout is clamped to this.
DASHBOARD_SESSION_HOURS=${dashboard_session_hours}
DASHBOARD_IDLE_TIMEOUT_MINUTES=${dashboard_idle_timeout_minutes}
# Optional per-payment cap for dashboard operations (-1 = no limit).
DASHBOARD_MAX_PAYMENT_SATS=${dashboard_max_payment_sats}

# ── Alerting (optional webhook for security events) ──
# Slack/Discord-compatible webhook for security alerts. Leave empty to
# disable. DNS for the host is re-resolved at request time to defeat
# rebind attacks; private/loopback targets are refused.
ALERT_WEBHOOK_URL=${alert_webhook_url}
ALERT_WEBHOOK_EVENTS=${alert_webhook_events}

# ── Audit Log ──
# Days to retain audit log entries. A daily Celery task prunes expired
# rows and rewrites the hash chain. 0 = keep forever.
AUDIT_LOG_RETENTION_DAYS=${audit_log_retention_days}

# ── CORS ──
CORS_ORIGINS=${cors_origins}

# ── Sign / Verify Message ──
ENABLE_SIGN_ADDRESS_API=${enable_sign_address_api}
ENABLE_SIGN_NODE_API=${enable_sign_node_api}
SIGN_MESSAGE_MAX_CHARS=${sign_message_max_chars}
SIGN_AUDIT_RECORD_MESSAGE=${sign_audit_record_message}
SIGN_RATE_LIMIT_PER_HOUR=${sign_rate_limit_per_hour}
SIGN_RATE_LIMIT_DASHBOARD_PER_HOUR=${sign_rate_limit_dashboard_per_hour}
SIGN_ADDRESS_AUTOCOMPLETE=${sign_address_autocomplete}

# ── BOLT 12 (Offers) ──
# The bolt12-gateway sidecar is built + started automatically by
# docker compose. In standalone (uvicorn-only) mode you must run
# the gateway yourself and point BOLT12_GATEWAY_GRPC at it.
BOLT12_ENABLED=${bolt12_enabled}
BOLT12_GATEWAY_GRPC=${bolt12_gateway_grpc}
# Shared bearer token for the gateway gRPC channel. Empty on both ends =
# unauthenticated channel — only safe inside a private docker network.
BOLT12_GATEWAY_TOKEN=${bolt12_gateway_token}
# Allow inbound invreqs that don't reference one of your published offers
# (BOLT 12 "refund" / direct-payment flow). Off by default — when on, any
# onion-message peer can ask the wallet to mint a BOLT 12 invoice.
BOLT12_ACCEPT_OFFERLESS_INVREQS=${bolt12_accept_offerless_invreqs}
# Per-payer rate limit for inbound BOLT 12 invreqs (count per window seconds;
# count=0 disables).
BOLT12_INBOUND_RATE_LIMIT_COUNT=${bolt12_inbound_rate_limit_count}
BOLT12_INBOUND_RATE_LIMIT_WINDOW_SECONDS=${bolt12_inbound_rate_limit_window_seconds}
# Hard cap (msat) on individual inbound BOLT 12 invoices the responder will
# mint. Defends inbound liquidity against abusive offer-less peers. 0 = off.
BOLT12_INBOUND_MAX_AMOUNT_MSAT=${bolt12_inbound_max_amount_msat}
# Cap on in-flight outbound invoice_request calls the orchestrator holds at
# once. Surfaces as 503 at the REST layer when exceeded.
BOLT12_MAX_PENDING_REQUESTS=${bolt12_max_pending_requests}
# Defence-in-depth caps on TLV decoding for inbound onion-message payloads.
BOLT12_MAX_PAYLOAD_BYTES=${bolt12_max_payload_bytes}
# Defensive ceiling on the encoded BOLT 12 invoice the responder
# returns. Bounded [4096, 65536]. Default 32 KB.
BOLT12_MAX_OUTBOUND_INVOICE_BYTES=${bolt12_max_outbound_invoice_bytes}
# Global cap on inbound invreq rate (across all payers). Defends
# against per-payer-id rotation bypass on the per-peer cap.
# Bounded [0, 10000]. 0 disables.
BOLT12_INBOUND_RATE_LIMIT_GLOBAL_COUNT=${bolt12_inbound_rate_limit_global_count}
# Concurrent inbound-mint cap. Defends LND mint endpoint against
# burst load that bypasses the rate-limit bucket. Bounded [1, 256].
BOLT12_INBOUND_MAX_CONCURRENT_MINTS=${bolt12_inbound_max_concurrent_mints}
# Acquire-timeout (seconds) for the inbound-mint semaphore. Bounded
# [1, 60]. Past this, the invreq is dropped with an audit row.
BOLT12_INBOUND_MINT_ACQUIRE_TIMEOUT_S=${bolt12_inbound_mint_acquire_timeout_s}
# Kill switch for the real-time LND settlement subscriber. When
# false, OPEN → PAID transitions happen only via the reconcile
# Celery beat (60 s cadence).
BOLT12_SETTLEMENT_SUBSCRIBER_ENABLED=${bolt12_settlement_subscriber_enabled}
# Retention (days) for terminal Bolt12InvoiceRequest / Bolt12Invoice
# rows. Bounded [7, 3650]. Default 90 days.
BOLT12_REQUEST_RETENTION_DAYS=${bolt12_request_retention_days}
BOLT12_INVOICE_RETENTION_DAYS=${bolt12_invoice_retention_days}
BOLT12_HTLC_MAX_DRIFT_RATIO_ALERT=${bolt12_htlc_max_drift_ratio_alert}
BOLT12_HTLC_EVENT_SUBSCRIBER_ENABLED=${bolt12_htlc_event_subscriber_enabled}
BOLT12_CHANNEL_SNAPSHOT_AT_MINT_ENABLED=${bolt12_channel_snapshot_at_mint_enabled}
BOLT12_INVOICE_SETTLE_WATCHDOG_MINUTES=${bolt12_invoice_settle_watchdog_minutes}
BOLT12_HTLC_MAX_SAFETY_BUFFER_PPM=${bolt12_htlc_max_safety_buffer_ppm}
BOLT12_DROP_UNDERSIZED_PATHS=${bolt12_drop_undersized_paths}
BOLT12_BLINDED_PATH_REFRESH_POLICY_FROM_GOSSIP=${bolt12_blinded_path_refresh_policy_from_gossip}
BOLT12_BLINDED_PATH_PAYINFO_SAFETY_MARGIN_PPM=${bolt12_blinded_path_payinfo_safety_margin_ppm}
BOLT12_BLINDED_PATH_PAYINFO_SAFETY_MARGIN_BASE_MSAT=${bolt12_blinded_path_payinfo_safety_margin_base_msat}
BOLT12_PROBE_PATHS_BEFORE_MINT=${bolt12_probe_paths_before_mint}
BOLT12_PATH_DIVERSITY_ENFORCE=${bolt12_path_diversity_enforce}
BOLT12_PATH_BREAKER_ENABLED=${bolt12_path_breaker_enabled}
BOLT12_PATH_BREAKER_FAILURES_TO_OPEN=${bolt12_path_breaker_failures_to_open}
BOLT12_PATH_BREAKER_INITIAL_COOLDOWN_S=${bolt12_path_breaker_initial_cooldown_s}
BOLT12_PATH_BREAKER_COOLDOWN_CAP_S=${bolt12_path_breaker_cooldown_cap_s}
BOLT12_PATH_PIGEONHOLE_PAIRING_ENABLED=${bolt12_path_pigeonhole_pairing_enabled}
BOLT12_ADAPTIVE_DEPTH_FALLBACK_ENABLED=${bolt12_adaptive_depth_fallback_enabled}
BOLT12_SUBSCRIBER_NEWNYM_ON_TRANSPORT_ERROR=${bolt12_subscriber_newnym_on_transport_error}
BOLT12_SUBSCRIBER_TRANSPORT_ERROR_BACKOFF_S=${bolt12_subscriber_transport_error_backoff_s}
BOLT12_SUBSCRIBER_POLLING_MODE_ENABLED=${bolt12_subscriber_polling_mode_enabled}
BOLT12_SUBSCRIBER_POLLING_INTERVAL_S=${bolt12_subscriber_polling_interval_s}
BOLT12_SUBSCRIBER_POLLING_MODE_AUTO_DETECT=${bolt12_subscriber_polling_mode_auto_detect}
BOLT12_SUBSCRIBER_HEARTBEAT_INTERVAL_S=${bolt12_subscriber_heartbeat_interval_s}
BOLT12_SUBSCRIBER_WARMUP_PROBE_ENABLED=${bolt12_subscriber_warmup_probe_enabled}
LND_HS_DESCRIPTOR_PROBE_INTERVAL_S=${lnd_hs_descriptor_probe_interval_s}
LND_CHANNEL_UPTIME_TRACK_INTERVAL_S=${lnd_channel_uptime_track_interval_s}
LND_CHANNEL_FLAP_DETECT_INTERVAL_S=${lnd_channel_flap_detect_interval_s}
BOLT12_INBOUND_SUPERVISOR_ENABLED=${bolt12_inbound_supervisor_enabled}
BOLT12_INBOUND_SUPERVISOR_TICK_INTERVAL_S=${bolt12_inbound_supervisor_tick_interval_s}
BOLT12_INBOUND_SUPERVISOR_WINDOW_S=${bolt12_inbound_supervisor_window_s}
BOLT12_INBOUND_SUPERVISOR_FAILURE_THRESHOLD=${bolt12_inbound_supervisor_failure_threshold}
BOLT12_INBOUND_SUPERVISOR_HEALTHY_LIFETIME_S=${bolt12_inbound_supervisor_healthy_lifetime_s}
BOLT12_INBOUND_SUPERVISOR_SIGHUP_THROTTLE_S=${bolt12_inbound_supervisor_sighup_throttle_s}
BOLT12_INBOUND_SUPERVISOR_FLAP_THRESHOLD=${bolt12_inbound_supervisor_flap_threshold}
BOLT12_INBOUND_SUPERVISOR_HS_FETCH_FAILURE_THRESHOLD=${bolt12_inbound_supervisor_hs_fetch_failure_threshold}
LND_HS_DESCRIPTOR_FAILURE_SUPERVISOR_THRESHOLD=${lnd_hs_descriptor_failure_supervisor_threshold}
LND_INBOUND_BURST_NEWNYM_THRESHOLD=${lnd_inbound_burst_newnym_threshold}
LND_INBOUND_BURST_WINDOW_S=${lnd_inbound_burst_window_s}
BOLT12_MAX_TLV_RECORDS=${bolt12_max_tlv_records}
BOLT12_MAX_TLV_VALUE_BYTES=${bolt12_max_tlv_value_bytes}
# When true, BIP-353 resolution probes ``dnssec-failed.org`` and refuses
# rubber-stamp validators. One extra DNS round-trip per process at startup.
BOLT12_BIP353_VALIDATE_RESOLVER=${bolt12_bip353_validate_resolver}
# Minimum real (non-dummy) hops in blinded paths the responder embeds in
# minted invoices. 1 = introduction node is our direct peer (a routability
# dead end when that peer is a small-graph LSP endpoint). 2 = introduction
# node is a peer-of-peer, so payers aim at a hub. Auto-falls-back to 1
# when LND can't build any path at the requested length. Bounded [1, 8].
BOLT12_BLINDED_PATH_MIN_REAL_HOPS=${bolt12_blinded_path_min_real_hops}
# Max number of blinded paths LND embeds per minted invoice. 2 is the
# sweet spot: one primary + one fallback intro. Going higher bait-traps
# CLN's MPP splitter into fragmenting small payments; on small-graph
# topologies LND often only finds 1-2 unique introductions anyway, so
# extra slots just pad with duplicates. Bounded [1, 8].
BOLT12_BLINDED_PATH_MAX_PATHS=${bolt12_blinded_path_max_paths}
# Comma-separated (or JSON array) hex pubkeys LND must NOT use as an
# intermediate in any blinded path. Default = Boltz (gossips itself as a
# routing node but reserves outbound for its swap engine, returns
# temporary_channel_failure on third-party forwarding). Extend with any
# other swap-only / non-routing nodes you discover.
BOLT12_BLINDED_PATH_OMIT_NODES=${bolt12_blinded_path_omit_nodes}
# Periodic push of LND-known peer addresses to the gateway's in-memory
# cache. Load-bearing for ConnectionNeeded recovery on outbound onion
# replies. 0 disables the task. Bounded [0, 86400] s.
BOLT12_GATEWAY_NODE_ADDRESS_REFRESH_INTERVAL_S=${bolt12_gateway_node_address_refresh_interval_s}
# Hard ceiling on entries per push (top-N by channel count). ~5000
# entries × ~100 B = ~500 KB per push. Bounded [100, 50000].
BOLT12_GATEWAY_NODE_ADDRESS_MAX_NODES=${bolt12_gateway_node_address_max_nodes}

# ── LNURL-pay / Lightning Address ──
# Outbound HTTP fetches for LNURL-pay and Lightning Address resolution.
# Tri-state Tor preference:
#   auto  → use LND_TOR_PROXY iff LND_REST_URL is a .onion address (default).
#   true  → always route LNURL HTTP via LND_TOR_PROXY.
#   false → never force Tor for clearnet hosts (.onion still goes via Tor).
LNURL_FORCE_TOR=${lnurl_force_tor}
# Accept plain http:// for clearnet recipients. Onion hosts allow http://
# unconditionally because Tor terminates the encryption.
LNURL_ALLOW_HTTP=${lnurl_allow_http}
# SSRF defence: block RFC1918 / loopback / link-local / ULA hosts.
LNURL_ALLOW_PRIVATE_HOSTS=${lnurl_allow_private_hosts}
# Hard cap on response body bytes from any LNURL endpoint.
LNURL_MAX_RESPONSE_BYTES=${lnurl_max_response_bytes}
# Per-request timeout (seconds) for resolve + invoice callbacks.
LNURL_RESOLVE_TIMEOUT_SECONDS=${lnurl_resolve_timeout_seconds}
# Server-side opaque-handle TTL bridging /lnurl/resolve and /lnurl/invoice.
LNURL_HANDLE_TTL_SECONDS=${lnurl_handle_ttl_seconds}
# Idempotency cache for /lnurl/invoice (0 disables).
LNURL_INVOICE_CACHE_TTL_SECONDS=${lnurl_invoice_cache_ttl_seconds}

# ══════════════════════════════════════════════════════════════════════
# Anonymize (privacy-preserving UTXO + LN mixing — docs/anonymize.md)
# ══════════════════════════════════════════════════════════════════════
ANONYMIZE_ENABLED=${anonymize_enabled}
ANONYMIZE_REQUIRE_TOR=${anonymize_require_tor}
ANONYMIZE_ENFORCE_ONION_ONLY_EGRESS=${anonymize_enforce_onion_only_egress}
ANONYMIZE_MIN_SAT=${anonymize_min_sat}
ANONYMIZE_MAX_SAT=${anonymize_max_sat}
ANONYMIZE_AMOUNT_BINS_SAT=${anonymize_amount_bins_sat}
# Each call-site class (Boltz submarine, reverse, Liquid, chain backend,
# BIP-353 DoH, quote-cache refresh, etc.) uses a distinct SOCKS listener
# so the operator cannot fingerprint the wallet across calls. The
# listener ports MUST match your tor daemon's torrc — see
# docs/anonymize.md "Per-call-site Tor isolation".
ANONYMIZE_TOR_SOCKS_PORTS=${anonymize_tor_socks_ports}
# Distinct-operator splitting. The default policy puts canonical
# Boltz on the REVERSE leg and curated alt operators on the SUBMARINE leg
# (Middleway → Eldamar → user-consented single-operator-Boltz). Set the
# operator_id env vars below to override the default chain; setting either
# BOLTZ_*_ONION_URL pins that leg to a single operator and DISABLES the
# fallback chain. See docs/anonymize_operator_diversity.md.
ANONYMIZE_SUBMARINE_OPERATOR_PRIMARY=${anonymize_submarine_operator_primary}
ANONYMIZE_SUBMARINE_OPERATOR_SECONDARY=${anonymize_submarine_operator_secondary}
ANONYMIZE_REVERSE_OPERATOR=${anonymize_reverse_operator}
ANONYMIZE_OPERATOR_PROBE_TIMEOUT_S=${anonymize_operator_probe_timeout_s}
ANONYMIZE_OPERATOR_PROBE_CACHE_TTL_S=${anonymize_operator_probe_cache_ttl_s}
BOLTZ_SUBMARINE_ONION_URL=${boltz_submarine_onion_url}
BOLTZ_REVERSE_ONION_URL=${boltz_reverse_onion_url}
ANONYMIZE_DESTINATION_RETENTION_DAYS=${anonymize_destination_retention_days}
ANONYMIZE_HARD_DELETE_AFTER_DAYS=${anonymize_hard_delete_after_days}
ANONYMIZE_TIER_CONCURRENCY_CAP=${anonymize_tier_concurrency_cap}

# ── At-rest encryption keys (auto-generated by start.sh) ──
# These are the encryption keys for destination ciphertext, hop-idempotency
# state, the decoy-output seed, and the step-up re-auth nonces. Treat the
# .env file as secret material — back it up SEPARATELY from your LND seed.
ANONYMIZE_REUSE_DETECTION_KEY_FERNET=${anonymize_reuse_detection_key_fernet}
ANONYMIZE_HOP_IDEMPOTENCY_KEY_FERNET=${anonymize_hop_idempotency_key_fernet}
ANONYMIZE_QUOTE_TOKEN_HMAC_KEY_FERNET=${anonymize_quote_token_hmac_key_fernet}
ANONYMIZE_QUOTE_CACHE_SIGNING_KEY_FERNET=${anonymize_quote_cache_signing_key_fernet}
ANONYMIZE_STEPUP_COOKIE_HMAC_KEY_FERNET=${anonymize_stepup_cookie_hmac_key_fernet}
ANONYMIZE_DECOY_SEED_FERNET=${anonymize_decoy_seed_fernet}
ANONYMIZE_DECOY_SEED_ACCOUNT_KEY=${anonymize_decoy_seed_account_key}
ANONYMIZE_DECOY_SEED_REQUIRED=${anonymize_decoy_seed_required}

# ── Operator-registry signing ──
ANONYMIZE_REGISTRY_RELEASE_KEY_FINGERPRINTS=${anonymize_registry_release_key_fingerprints}
ANONYMIZE_REGISTRY_SIG_PATH=${anonymize_registry_sig_path}
ANONYMIZE_REGISTRY_REQUIRE_THRESHOLD_SIG=${anonymize_registry_require_threshold_sig}
ANONYMIZE_REGISTRY_THRESHOLD_K=${anonymize_registry_threshold_k}
ANONYMIZE_REGISTRY_THRESHOLD_SIG_PATHS=${anonymize_registry_threshold_sig_paths}

# ── Liquid round-trip hop ──
ANONYMIZE_LIQUID_ENABLED=${anonymize_liquid_enabled}
ANONYMIZE_LIQUID_SEED_FERNET=${anonymize_liquid_seed_fernet}
ANONYMIZE_LIQUID_ELECTRUM_URL=${anonymize_liquid_electrum_url}
ANONYMIZE_LIQUID_BTC_ASSET_ID=${anonymize_liquid_btc_asset_id}
ANONYMIZE_LIQUID_INTEGRATION_VERIFIED=${anonymize_liquid_integration_verified}
# Overlay-launch umbrella + elementsd RPC credentials. ``start.sh``
# adds docker-compose.liquid.yml to its compose invocation when
# ENABLE_LIQUID=true, bringing up elementsd alongside the wallet.
# ENABLE_LIQUID_INDEXER additionally activates the ``liquid-indexer``
# compose profile (the embedded electrs-liquid container). The
# indexer is off by default because it's the heavy component:
# ~19 GiB IBD peak, ~16 GiB structural floor at every boot, ~75 GB
# disk. See docs/anonymize.md "Sizing the host" for the full
# breakdown. When off, ANONYMIZE_LIQUID_ELECTRUM_URL must point
# at an external Liquid Electrum endpoint.
ENABLE_LIQUID=${enable_liquid}
ENABLE_LIQUID_INDEXER=${enable_liquid_indexer}
ELEMENTSD_RPC_USER=${elementsd_rpc_user}
ELEMENTSD_RPC_PASSWORD=${elementsd_rpc_password}
ELEMENTSD_RPC_AUTH=${elementsd_rpc_auth}
ELEMENTSD_RPC_ALLOW_CIDR=${elementsd_rpc_allow_cidr}

# ── BIP-353 destination + deposit ──
ANONYMIZE_BIP353_DOH_ENDPOINT=${anonymize_bip353_doh_endpoint}
ANONYMIZE_BIP353_CACHE_MIN_TTL_S=${anonymize_bip353_cache_min_ttl_s}
ANONYMIZE_BIP353_DEPOSIT_DOMAIN=${anonymize_bip353_deposit_domain}
ANONYMIZE_EXT_LIGHTNING_DEPOSIT_METHOD=${anonymize_ext_lightning_deposit_method}

# Hard-refusal flags. Default false (step-up re-auth required);
# intended true once a deployment has matured.
ANONYMIZE_REFUSE_DECOY_OVERRIDE_SPENDS=${anonymize_refuse_decoy_override_spends}
ANONYMIZE_REFUSE_REFUND_OVERRIDE_SPENDS=${anonymize_refuse_refund_override_spends}
ENVEOF

    chmod 600 "$ENV_FILE"
    info ".env written successfully"

    # Narrow backup files for freshly-generated encryption keys.
    # See _write_secret_key_backup / _write_liquid_seed_backup for
    # rationale on why this is NOT a full .env copy.
    if [[ "$fresh_secret_key" == "true" ]]; then
        _write_secret_key_backup "$secret_key"
    fi
    if [[ "$fresh_liquid_seed" == "true" && -n "$anonymize_liquid_seed_fernet" ]]; then
        _write_liquid_seed_backup "$anonymize_liquid_seed_fernet"
    fi
    echo ""
}

# ══════════════════════════════════════════════════════════════════════
# Compose-file selection
#
# Emits the ``-f file.yml`` flags that every docker-compose invocation
# should use. The base docker-compose.yml is always included; the
# Liquid overlay is added when ``ENABLE_LIQUID=true`` so the wallet
# brings up elementsd + electrs-liquid alongside its other services.
#
# Used by start_service, stop_service, and any other ad-hoc compose
# command this script issues. Keeping the selection in one place avoids
# drift between "up" and "down" — a mismatched stop would orphan the
# overlay containers.
# ══════════════════════════════════════════════════════════════════════
_compose_files() {
    local files=("-f" "docker-compose.yml")
    if [[ "$(get_env ENABLE_LIQUID "false")" == "true" ]]; then
        files+=("-f" "docker-compose.liquid.yml")
    fi
    printf '%s\n' "${files[@]}"
}

# Compose profiles to activate for the current invocation. The
# only profile we use today is ``liquid-indexer``, which gates the
# memory-hungry electrs-liquid container behind ENABLE_LIQUID_INDEXER.
# Export the result as ``COMPOSE_PROFILES`` so it propagates through
# every ``docker compose`` invocation in this script (including the
# ones we don't manage directly such as ``logs`` / ``ps``).
_export_compose_profiles() {
    local profiles=""
    if [[ "$(get_env ENABLE_LIQUID "false")" == "true" \
       && "$(get_env ENABLE_LIQUID_INDEXER "false")" == "true" ]]; then
        profiles="liquid-indexer"
    fi
    export COMPOSE_PROFILES="$profiles"
}

# ══════════════════════════════════════════════════════════════════════
# Secret-placeholder guard (,
#). Refuses to launch while any required credential is still
# at its checked-in placeholder.
# ══════════════════════════════════════════════════════════════════════
_validate_env_secrets() {
    load_env
    local bad=0
    local v

    for key in POSTGRES_PASSWORD REDIS_PASSWORD; do
        v="$(get_env "$key" "")"
        if [[ -z "$v" || "$v" == "__REPLACE_ME__" \
                       || "$v" == "change-me-strong-password" \
                       || "$v" == "change-me-redis-password" ]]; then
            err "$key is unset or still the placeholder. Run \`./start.sh config\` and set a strong value."
            bad=1
        fi
    done

    v="$(get_env SECRET_KEY "")"
    if [[ -z "$v" || "$v" == "change-me-to-a-random-64-char-string" || "$v" == "__REPLACE_ME__" ]]; then
        err "SECRET_KEY is unset or still the placeholder."
        bad=1
    fi

    # Refuse to launch the Liquid overlay with the shipped placeholder
    # elementsd RPC password. Only enforced when the operator opted into
    # the liquid stack via ENABLE_LIQUID=true.
    if [[ "$(get_env ENABLE_LIQUID "false")" == "true" ]]; then
        v="$(get_env ELEMENTSD_RPC_PASSWORD "")"
        if [[ -z "$v" || "$v" == "change-me-in-production" || "$v" == "__REPLACE_ME__" ]]; then
            err "ELEMENTSD_RPC_PASSWORD is unset or still the placeholder while ENABLE_LIQUID=true."
            bad=1
        fi

        # When the embedded indexer is disabled, the wallet still
        # needs SOMEWHERE to point its ElectrumLiquidBackend.
        # Refuse to launch if ENABLE_LIQUID_INDEXER=false and the
        # URL is empty OR still points at the internal hostname
        # (which won't resolve because the container isn't started
        # by the liquid-indexer profile gating).
        if [[ "$(get_env ENABLE_LIQUID_INDEXER "false")" != "true" ]]; then
            v="$(get_env ANONYMIZE_LIQUID_ELECTRUM_URL "")"
            if [[ -z "$v" ]]; then
                err "ANONYMIZE_LIQUID_ELECTRUM_URL is empty while ENABLE_LIQUID_INDEXER=false."
                err "Either set ENABLE_LIQUID_INDEXER=true (~19 GiB IBD peak, ~16 GiB floor) or"
                err "set ANONYMIZE_LIQUID_ELECTRUM_URL to an external Liquid Electrum endpoint."
                bad=1
            elif [[ "$v" == *"electrs-liquid:"* ]]; then
                err "ANONYMIZE_LIQUID_ELECTRUM_URL points at the internal electrs-liquid hostname"
                err "but ENABLE_LIQUID_INDEXER=false (so that container is not started)."
                err "Either set ENABLE_LIQUID_INDEXER=true or change the URL to an external endpoint."
                bad=1
            fi
        fi
    fi

    if [[ "$bad" -ne 0 ]]; then
        err "Refusing to start with default/placeholder credentials."
        exit 1
    fi
}

# ══════════════════════════════════════════════════════════════════════
# Stop the service
# ══════════════════════════════════════════════════════════════════════
stop_service() {
    header "Stopping Service"

    # Stop Docker Compose if running
    local -a compose_args
    _export_compose_profiles
    mapfile -t compose_args < <(_compose_files)
    if docker compose "${compose_args[@]}" ps --status running 2>/dev/null | grep -q .; then
        info "Stopping Docker Compose services..."
        docker compose "${compose_args[@]}" down
        info "Docker Compose services stopped"
    else
        info "No Docker Compose services running"
    fi

    # Stop local Tor if managed by us
    if _tor_is_running; then
        _stop_tor
    fi
}

# ══════════════════════════════════════════════════════════════════════
# Start the service (blocks until Ctrl+C)
# ══════════════════════════════════════════════════════════════════════
start_service() {
    load_env
    local port
    port="$(get_env API_PORT 8100)"

    header "Start Service"
    echo -e "  ${DIM}How would you like to run the service?${RESET}\n"
    echo -e "  ${BOLD}1${RESET}  Docker Compose ${DIM}(recommended — runs everything)${RESET}"
    echo -e "  ${BOLD}2${RESET}  Uvicorn only   ${DIM}(API server — needs external DB/Redis)${RESET}"
    echo -e "  ${BOLD}3${RESET}  Exit"
    echo ""
    echo -en "  Choice ${DIM}[1]${RESET}: "
    local choice
    read -r choice
    choice="${choice:-1}"

    case "$choice" in
        1)
            _validate_env_secrets
            header "Starting Docker Compose"
            local -a compose_args
            _export_compose_profiles
            mapfile -t compose_args < <(_compose_files)
            if [[ "$(get_env ENABLE_LIQUID "false")" == "true" ]]; then
                if [[ "$(get_env ENABLE_LIQUID_INDEXER "false")" == "true" ]]; then
                    info "Liquid overlay enabled with embedded indexer (ENABLE_LIQUID=true, ENABLE_LIQUID_INDEXER=true)"
                    info "First boot may take several hours while elementsd + electrs-liquid sync the Liquid chain."
                    info "electrs-liquid IBD peaks at ~19 GiB RAM (16 GiB structural floor + working set);"
                    info "compose caps it at 20 GiB. Ensure host has ≥24 GiB free for IBD."
                else
                    info "Liquid overlay enabled with EXTERNAL indexer (ENABLE_LIQUID=true, ENABLE_LIQUID_INDEXER=false)"
                    info "ANONYMIZE_LIQUID_ELECTRUM_URL=$(get_env ANONYMIZE_LIQUID_ELECTRUM_URL "<unset>")"
                fi
            fi
            info "Running: docker compose ${compose_args[*]} up --build"
            echo ""
            docker compose "${compose_args[@]}" up -d --build
            echo ""
            echo -e "${DIM}  ─────────────────────────────────────${RESET}"
            echo ""
            info "Services are running"
            echo ""
            echo -e "  ${BOLD}API${RESET}        http://localhost:${port}"
            if [[ "$(get_env ENABLE_DOCS "false")" == "true" ]]; then
                echo -e "  ${BOLD}API Docs${RESET}   http://localhost:${port}/docs"
            fi
            if [[ "$(get_env ENABLE_DASHBOARD "true")" == "true" ]]; then
                echo -e "  ${BOLD}Dashboard${RESET}  http://localhost:${port}/dashboard/"
            fi
            echo ""
            echo -e "${DIM}  ─────────────────────────────────────${RESET}"
            echo -e "  ${DIM}Press Ctrl+C to shut down${RESET}"
            echo ""

            # Trap Ctrl+C for clean shutdown
            trap '_shutdown_docker' INT TERM
            # Follow only API logs (blocks until interrupted)
            docker compose "${compose_args[@]}" logs -f api 2>/dev/null || true
            # If logs exited on their own, wait for interrupt
            wait 2>/dev/null || true
            ;;
        2)
            _validate_env_secrets
            header "Starting Uvicorn"
            # Activate venv if not already
            if [[ -z "${VIRTUAL_ENV:-}" ]]; then
                source "$VENV_DIR/bin/activate"
            fi

            # Auto-start Tor if LND uses .onion
            local lnd_url
            lnd_url="$(get_env LND_REST_URL "")"
            if _is_onion_url "$lnd_url"; then
                _ensure_tor || { err "Cannot start without Tor for .onion LND"; return 1; }
            fi

            warn "Make sure PostgreSQL and Redis are running externally"
            if [[ "$(get_env BOLT12_ENABLED "true")" == "true" ]]; then
                warn "BOLT 12 enabled — ensure bolt12-gateway is reachable at $(get_env BOLT12_GATEWAY_GRPC "bolt12-gateway:50061")"
            fi
            echo ""
            echo -e "${DIM}  ─────────────────────────────────────${RESET}"
            echo ""
            echo -e "  ${BOLD}API${RESET}        http://localhost:${port}"
            if [[ "$(get_env ENABLE_DOCS "false")" == "true" ]]; then
                echo -e "  ${BOLD}API Docs${RESET}   http://localhost:${port}/docs"
            fi
            if [[ "$(get_env ENABLE_DASHBOARD "true")" == "true" ]]; then
                echo -e "  ${BOLD}Dashboard${RESET}  http://localhost:${port}/dashboard/"
            fi
            if _tor_is_running; then
                echo -e "  ${BOLD}Tor Proxy${RESET}  socks5://127.0.0.1:9050"
            fi
            echo ""
            echo -e "${DIM}  ─────────────────────────────────────${RESET}"
            echo -e "  ${DIM}Press Ctrl+C to shut down${RESET}"
            echo ""

            # Trap to stop Tor on exit, then exec uvicorn
            trap '_stop_tor' EXIT
            exec uvicorn app.main:app --host 0.0.0.0 --port "$port"
            ;;
        3)
            info "Exiting. Run ./start.sh again when ready."
            ;;
        *)
            err "Invalid choice"
            ;;
    esac
}

_shutdown_docker() {
    echo ""
    header "Shutting down"
    info "Stopping Docker Compose services..."
    local -a compose_args
    _export_compose_profiles
    mapfile -t compose_args < <(_compose_files)
    docker compose "${compose_args[@]}" down
    info "All services stopped"
    exit 0
}

# ══════════════════════════════════════════════════════════════════════
# Main menu
# ══════════════════════════════════════════════════════════════════════
main() {
    banner

    # Always ensure venv + deps
    setup_venv

    if [[ -f "$ENV_FILE" ]]; then
        load_env
        echo ""
        info "Existing .env found"
        echo ""
        echo -e "  ${BOLD}1${RESET}  Start the service"
        echo -e "  ${BOLD}2${RESET}  Reconfigure .env"
        echo -e "  ${BOLD}3${RESET}  Stop the service"
        echo -e "  ${BOLD}4${RESET}  Exit"
        echo ""
        echo -en "  Choice ${DIM}[1]${RESET}: "
        local choice
        read -r choice
        choice="${choice:-1}"

        case "$choice" in
            1)
                start_service
                ;;
            2)
                run_config
                start_service
                ;;
            3)
                stop_service
                ;;
            4)
                info "Exiting. Run ./start.sh again when ready."
                ;;
            *)
                err "Invalid choice"
                exit 1
                ;;
        esac
    else
        echo -e "  ${DIM}No .env file found — starting initial configuration${RESET}"
        run_config
        start_service
    fi
}

main "$@"
