#!/bin/sh
# Tor entrypoint shim.
#
# Renders the final torrc by replacing the placeholder line with a
# real HashedControlPassword directive derived from
# $TOR_CONTROL_PASSWORD. If the env var is unset, the placeholder is
# replaced with a comment (control port left unauthenticated — the
# SocksPolicy + container isolation are the only protection in that
# case; documented as the dev-default in the operator runbook).
#
# Why a shim and not a literal HashedControlPassword in the
# checked-in torrc? Because the hash is per-password — committing
# one would commit the corresponding plaintext (or fix it for all
# operators). The shim lets each deployment derive its own.
#
# Tor's --hash-password takes a plaintext and prints a one-line
# salted hash starting with "16:". The shim captures that, sed-
# injects it into the placeholder, and execs tor.

set -eu

# TOR_ROLE selects which default torrc to load. Single-mode
# stays the "unified" default (everything in one Tor instance);
# split-mode operators set TOR_ROLE=lnd / TOR_ROLE=anonymize on
# the respective containers. The fallback (unset) is "unified" so
# the existing single-mode compose stack works unchanged.
TOR_ROLE="${TOR_ROLE:-unified}"
case "$TOR_ROLE" in
    unified)    DEFAULTS_SOURCE=/etc/tor/torrc.d/00-default.conf ;;
    lnd)        DEFAULTS_SOURCE=/etc/tor/torrc.d/00-default.conf.lnd ;;
    anonymize)  DEFAULTS_SOURCE=/etc/tor/torrc.d/00-default.conf.anonymize ;;
    *)
        echo "tor-proxy entrypoint: unknown TOR_ROLE=$TOR_ROLE" >&2
        exit 1
        ;;
esac

# Layered torrc paths. The defaults file is the one we
# render (HashedControlPassword injection); the operator override
# is consumed verbatim. Both are passed to Tor.
TORRC_IN="$DEFAULTS_SOURCE"
TORRC_OUT=/etc/tor/torrc.d/00-default.conf.rendered
TORRC_OPERATOR=/etc/tor/torrc.d/99-operator.conf
PLACEHOLDER='#__HASHED_CONTROL_PASSWORD_LINE__'

if [ -n "${TOR_CONTROL_PASSWORD:-}" ]; then
    # tor --hash-password emits one line of the form "16:HEX...".
    # We strip any trailing whitespace / blank lines defensively.
    HASHED=$(tor --hash-password "$TOR_CONTROL_PASSWORD" 2>/dev/null | tail -1)
    if [ -z "$HASHED" ]; then
        echo "tor-proxy entrypoint: failed to derive HashedControlPassword" >&2
        exit 1
    fi
    # The sed escape protects against `&` and `/` inside the hash
    # (hash chars are [0-9A-F] so this is paranoia, but cheap).
    HASHED_ESCAPED=$(printf '%s' "$HASHED" | sed 's/[\\/&]/\\&/g')
    sed "s|${PLACEHOLDER}|HashedControlPassword ${HASHED_ESCAPED}|" \
        "$TORRC_IN" > "$TORRC_OUT"
    echo "tor-proxy entrypoint: ControlPort auth = HashedControlPassword" >&2
else
    # Fail closed
    # outside development. Without a TOR_CONTROL_PASSWORD the
    # ControlPort would accept GETINFO / SETEVENTS / SIGNAL NEWNYM
    # from any sidecar on the docker network, enabling circuit
    # manipulation. The wallet host's start.sh generates the
    # password before bringing the stack up, so the only way to land
    # here in production is misconfiguration — and we'd rather die
    # loudly than boot an open control port.
    TOR_ENVIRONMENT="${TOR_ENVIRONMENT:-${ENVIRONMENT:-production}}"
    case "$TOR_ENVIRONMENT" in
        development|dev|test|regtest)
            sed "s|${PLACEHOLDER}|# ControlPort unauthenticated (TOR_CONTROL_PASSWORD unset at container start)|" \
                "$TORRC_IN" > "$TORRC_OUT"
            echo "tor-proxy entrypoint: WARNING — ControlPort is unauthenticated (TOR_ENVIRONMENT=$TOR_ENVIRONMENT)" >&2
            ;;
        *)
            echo "tor-proxy entrypoint: REFUSING to boot — TOR_CONTROL_PASSWORD is unset and TOR_ENVIRONMENT=$TOR_ENVIRONMENT (set TOR_ENVIRONMENT=development to opt into an unauthenticated ControlPort for local testing)." >&2
            exit 1
            ;;
    esac
fi

# Use tini as PID 1 so SIGTERM propagates cleanly to tor
# (which then publishes a "service withdrawing" signal before exit
# rather than getting SIGKILLed by Docker after the 10s grace).
# Pass both the rendered defaults and the operator override.
# Tor merges them at load: directives in the operator file replace
# matching directives in the defaults.
exec /sbin/tini -- tor \
    --defaults-torrc "$TORRC_OUT" \
    -f "$TORRC_OPERATOR"
