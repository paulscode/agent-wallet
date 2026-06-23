# Tor SOCKS5 proxy for the wallet. Provides 8 isolated SOCKS listeners
# on ports 9050-9057 — one per anonymize call-site, plus the shared LND
# listener on 9050. See ./torrc for the listener/port assignments and
# the anonymize design notes for the threat-model rationale.
#
# Tor version pin (Alpine 3.20 ships tor=0.4.8.x). Bumping
# requires re-validating log patterns + control-protocol shape.
# Track CVEs and update deliberately, not opportunistically.

# Pinned base + tor version. Bumping the major version
# requires re-validating the log-pattern matchers + the
# control-protocol shape used by app/services/anonymize/tor.py.
# Alpine 3.20 currently ships tor=0.4.8.13-r0; this pin is
# verified by tests/unit/test_tor_proxy_compose_and_dockerfile.py.
FROM alpine:3.20

# - tor:  the daemon itself, version-pinned via APK.
# - tini: PID-1 init so SIGTERM forwards cleanly to tor.
# - curl: required by the circuit-validating healthcheck;
#         alpine's busybox wget doesn't support --socks5-hostname.
# - dcron + ca-certificates: not installed (avoid bloat); curl --insecure
#         is used in the healthcheck since we hit clearnet mempool.space.
#
# Note: ``apk add tor=$version-r$revision`` would lock the patch
# release, but Alpine bumps the -rN suffix on backport patches we
# WANT. We rely on the Alpine 3.20 stable channel (which only ships
# security backports) and pin via the test mentioned above.
RUN apk add --no-cache tor tini curl ca-certificates

# Layered torrc. The wallet's defaults ship at
# ``/etc/tor/torrc.d/00-default.conf`` (loaded via Tor's
# ``--defaults-torrc`` flag — values can be overridden, not appended).
# Operators may mount their own overrides at
# ``/etc/tor/torrc.d/99-operator.conf`` via a docker-compose volume.
# An empty stub ships in the image so Tor can boot when no override
# is mounted (Tor's ``-f`` requires the file to exist; an empty file
# is fine — it just contributes nothing to the merged config).
COPY torrc /etc/tor/torrc.d/00-default.conf
# Role-specific defaults for split-mode deployments. The
# entrypoint shim picks which one to load based on $TOR_ROLE.
# Single-mode (TOR_ROLE unset) keeps using 00-default.conf above.
COPY torrc.lnd /etc/tor/torrc.d/00-default.conf.lnd
COPY torrc.anonymize /etc/tor/torrc.d/00-default.conf.anonymize
COPY operator.conf /etc/tor/torrc.d/99-operator.conf
COPY entrypoint.sh /usr/local/bin/entrypoint.sh

# The entrypoint shim needs to be readable + executable by the tor
# user. We also need the tor user to be able to write the rendered
# defaults torrc (the shim writes to
# /etc/tor/torrc.d/00-default.conf.rendered).
RUN chmod 755 /usr/local/bin/entrypoint.sh \
    && chown -R tor:tor /etc/tor \
    && mkdir -p /var/lib/tor \
    && chown -R tor:tor /var/lib/tor \
    && chmod 700 /var/lib/tor

# Tor runs as non-root
USER tor

# 9100 is the ControlPort (torrc) used by the wallet's
# bootstrap probes / NEWNYM watchdog. Bound to the container network
# only; not exposed to the host.
EXPOSE 9050 9051 9052 9053 9054 9055 9056 9057 9100

# Circuit-validating healthcheck. Verifies (a) every SOCKS
# listener has its TCP port bound (catches torrc typos) AND (b) a
# majority of three independent clearnet targets complete a SOCKS5
# round-trip (catches wedged-circuit failures the old port-bind
# healthcheck silently missed).
#
# Majority-of-3 mitigation against single-target outage. A
# mempool.space hiccup alone wouldn't restart tor-proxy unnecessarily;
# only a real Tor wedge fails all three targets. We pick diverse
# providers (mempool.space, blockstream.info, example.com) so a
# correlated provider failure doesn't false-positive either.
#
# Start_period 180s gives Tor time to bootstrap on first
# boot before we start counting healthcheck failures.
#
# The clearnet
# probes now validate the TLS chain (the image bundles
# ca-certificates). A malicious Tor exit serving a forged 200 on
# `https://mempool.space/...` would have masked a real Tor wedge
# under the previous --insecure behaviour.
HEALTHCHECK --interval=60s --timeout=20s --retries=3 --start-period=180s \
  CMD for p in 9050 9051 9052 9053 9054 9055 9056 9057; do \
        nc -z 127.0.0.1 $p || exit 1; \
      done \
  && SUCCESS=0; \
     for url in https://mempool.space/api/blocks/tip/height \
                https://blockstream.info/api/blocks/tip/height \
                https://example.com/; do \
       curl -sf --max-time 5 \
            --socks5-hostname 127.0.0.1:9050 "$url" > /dev/null 2>&1 \
         && SUCCESS=$(expr $SUCCESS + 1); \
     done; \
     [ "$SUCCESS" -ge 2 ]

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
