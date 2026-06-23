# SPDX-License-Identifier: MIT
"""Regression guards for tor-proxy compose + Dockerfile shape.

Pins the Group A infrastructure changes so a future rewrite can't
silently drop:

  * Circuit-validating healthcheck (must include
    ``--socks5-hostname`` AND ``nc -z`` for both port-bind + circuit
    validation).
  * ``start_period`` so first deploy doesn't loop on the
    healthcheck.
  * Explicit resource limits.
  * Tini + entrypoint shim wiring.
  * TOR_CONTROL_PASSWORD env passthrough.
"""

from __future__ import annotations

from pathlib import Path

_COMPOSE = Path(__file__).resolve().parents[2] / "docker-compose.yml"
_DOCKERFILE = Path(__file__).resolve().parents[2] / "tor-proxy" / "Dockerfile"
_ENTRYPOINT = Path(__file__).resolve().parents[2] / "tor-proxy" / "entrypoint.sh"
_TORRC = Path(__file__).resolve().parents[2] / "tor-proxy" / "torrc"


def _tor_proxy_block() -> str:
    text = _COMPOSE.read_text(encoding="utf-8")
    start = text.find("tor-proxy:")
    assert start != -1
    # The next top-level service starts ~30 lines later; we slice to
    # the next "^  ":-prefixed service block.
    rest = text[start:]
    # Use the second occurrence of a top-level service line as the
    # delimiter — pattern "^  XXX:" where XXX != "tor-proxy".
    end = len(rest)
    import re

    matches = list(re.finditer(r"\n  [a-z][a-z0-9-]*:\n", rest))
    if matches:
        # First match is the start of tor-proxy itself (already in).
        # Second is the next service.
        if len(matches) >= 2:
            end = matches[1].start()
    return rest[:end]


# ── resource limits ─────────────────────────────────────────


def test_tor_proxy_has_explicit_memory_limit() -> None:
    block = _tor_proxy_block()
    assert "memory:" in block, "tor-proxy must declare a memory limit. Add deploy.resources.limits.memory."


def test_tor_proxy_has_explicit_cpu_limit() -> None:
    block = _tor_proxy_block()
    assert "cpus:" in block, "tor-proxy must declare a CPU limit."


# ── TOR_CONTROL_PASSWORD env passthrough ────────────────────


def test_tor_proxy_passes_control_password_env() -> None:
    block = _tor_proxy_block()
    assert "TOR_CONTROL_PASSWORD" in block, (
        "tor-proxy compose service must forward $TOR_CONTROL_PASSWORD "
        "to the container so the entrypoint shim can derive "
        "HashedControlPassword."
    )


# ── circuit-validating healthcheck ───────────────────────────


def test_dockerfile_healthcheck_includes_socks5_round_trip() -> None:
    text = _DOCKERFILE.read_text(encoding="utf-8")
    healthcheck_section = text[text.find("HEALTHCHECK") :]
    assert "HEALTHCHECK" in text, "Dockerfile missing HEALTHCHECK directive"
    assert "--socks5-hostname" in healthcheck_section, (
        "Healthcheck must include a curl --socks5-hostname round-trip "
        ". Port-bind-only checks miss wedged circuits — the "
        "2026-05-21 incident proved this."
    )
    assert "nc -z" in healthcheck_section, "Healthcheck must still verify all SOCKS ports are bound."


def test_dockerfile_healthcheck_probes_majority_of_three_targets() -> None:
    """Single-target healthcheck restarts tor-proxy on every
    mempool.space hiccup, disrupting in-flight payments. The
    documented mitigation is "probe list with majority-success
    requirement (≥2 of 3 known-good clearnet targets)." Pin both
    the count (3 targets) and the threshold (≥2 successes)."""
    text = _DOCKERFILE.read_text(encoding="utf-8")
    healthcheck_section = text[text.find("HEALTHCHECK") :]
    # Three diverse targets — Bitcoin explorers + a generic-clearnet
    # control. A correlated outage at a single provider can't false-
    # positive when at least one provider stays up.
    assert "mempool.space" in healthcheck_section, "healthcheck must probe mempool.space."
    assert "blockstream.info" in healthcheck_section, (
        "healthcheck must include a second Bitcoin-explorer target (blockstream.info) for provider diversity."
    )
    assert "example.com" in healthcheck_section, (
        "healthcheck must include a generic-clearnet control (example.com) to detect Bitcoin-API-wide outages."
    )
    # Threshold ≥ 2.
    assert "$SUCCESS" in healthcheck_section and "ge 2" in healthcheck_section, (
        "healthcheck must require a majority of three targets to "
        "succeed (≥2). Without the threshold a single-target outage "
        "would restart tor-proxy and disrupt in-flight payments "
        "(critical-risk mitigation)."
    )


def test_dockerfile_healthcheck_has_start_period() -> None:
    text = _DOCKERFILE.read_text(encoding="utf-8")
    assert "--start-period" in text, (
        "HEALTHCHECK must use --start-period so the first deploy doesn't loop while Tor bootstraps."
    )


# ── tini + entrypoint shim ──────────────────────────────────


def test_dockerfile_installs_tini() -> None:
    text = _DOCKERFILE.read_text(encoding="utf-8")
    assert "tini" in text, "Dockerfile must install tini so SIGTERM propagates cleanly to Tor on docker stop."


def test_dockerfile_uses_entrypoint_shim() -> None:
    text = _DOCKERFILE.read_text(encoding="utf-8")
    assert "ENTRYPOINT" in text and "entrypoint.sh" in text, (
        "Dockerfile must use the entrypoint shim so HashedControlPassword can be rendered from $TOR_CONTROL_PASSWORD."
    )


def test_entrypoint_shim_handles_both_password_set_and_unset() -> None:
    text = _ENTRYPOINT.read_text(encoding="utf-8")
    # Set path: derive hash + sed-inject.
    assert "tor --hash-password" in text, "Entrypoint must derive HashedControlPassword via tor --hash-password"
    # Unset path: leave the placeholder as a comment.
    assert "unauthenticated" in text.lower(), "Entrypoint must warn when TOR_CONTROL_PASSWORD is unset"


# ── Tor version pin ─────────────────────────────────────────


def test_dockerfile_pins_alpine_base() -> None:
    """The Dockerfile must pin the Alpine base image to a
    specific minor version. Bumping requires re-validating the
     log-pattern matchers + the control-protocol shape used
    by app/services/anonymize/tor.py. The Dockerfile's own
    comment claims this is verified by this test — keep that
    contract honest."""
    text = _DOCKERFILE.read_text(encoding="utf-8")
    # Match any ``FROM alpine:N.M`` line. The specific version
    # number is intentionally loose here so a deliberate bump
    # doesn't churn this test for the new line — but the bump
    # MUST be deliberate (no ``FROM alpine`` or ``FROM alpine:latest``).
    import re

    match = re.search(r"^FROM\s+alpine:(\d+\.\d+)", text, re.MULTILINE)
    assert match is not None, (
        "Dockerfile must pin Alpine to a specific minor version "
        "(``FROM alpine:N.M``) so apk's tor package is reproducible "
        "across rebuilds. ``FROM alpine`` or ``alpine:latest`` "
        "would let the next Alpine release silently bump tor to a "
        "version with a different control-protocol shape."
    )
    # Currently 3.20 — bumping requires re-validating.
    pinned = match.group(1)
    assert pinned == "3.20", (
        f"Alpine pin moved to {pinned!r}. Before flipping this assertion: "
        "re-validate the WARN/ERR log-pattern matchers in "
        "tor_event_stream.py against the new Tor version's emit format, "
        "AND smoke-test the control-protocol shape "
        "(GETINFO bootstrap-phase, circuit-status, entry-guards, "
        "network-liveness)."
    )


# ── ControlPort exposed ──────────────────────────────────────


def test_torrc_exposes_control_port() -> None:
    text = _TORRC.read_text(encoding="utf-8")
    assert "ControlPort" in text, (
        "torrc must expose a ControlPort. Without it the "
        "watchdog can't issue NEWNYM and all the probe machinery "
        "stays dormant."
    )


def test_torrc_has_password_placeholder() -> None:
    text = _TORRC.read_text(encoding="utf-8")
    assert "__HASHED_CONTROL_PASSWORD_LINE__" in text, (
        "torrc must contain the entrypoint shim's placeholder so "
        "the derived HashedControlPassword can be injected at "
        "container start."
    )


# ── Group B: persistent DataDirectory + volume ──


def test_compose_declares_tor_data_named_volume() -> None:
    text = _COMPOSE.read_text(encoding="utf-8")
    # The named volume must appear in the top-level ``volumes:`` block
    # — without it docker-compose would refuse to mount it.
    assert "\ntor_data:" in text or "tor_data:\n" in text, (
        "docker-compose must declare a ``tor_data`` named volume  so the Tor DataDirectory survives container restarts."
    )


def test_tor_proxy_mounts_data_volume() -> None:
    block = _tor_proxy_block()
    assert "tor_data:/var/lib/tor" in block, (
        "tor-proxy must mount the tor_data volume at /var/lib/tor "
        "to persist consensus cache + guard selections across "
        "restarts."
    )


def test_api_mounts_tor_data_read_only_for_statvfs() -> None:
    text = _COMPOSE.read_text(encoding="utf-8")
    # The watchdog runs in the api container and calls statvfs()
    # against /var/lib/tor. The mount is read-only so the api can't
    # mutate Tor's state cache.
    api_idx = text.find("  api:")
    assert api_idx != -1
    next_svc = text.find("\n  celery-worker:", api_idx)
    api_block = text[api_idx : next_svc if next_svc != -1 else len(text)]
    assert "tor_data:/var/lib/tor:ro" in api_block, (
        "api service must mount tor_data:/var/lib/tor read-only "
        " so the watchdog can statvfs() the volume to detect "
        "DataDirectory growth."
    )


def test_compose_does_not_override_dockerfile_healthcheck() -> None:
    """A compose-level ``healthcheck:`` overrides the Dockerfile
    HEALTHCHECK silently, dropping the circuit round-trip. If
    you need to tune the intervals, update the Dockerfile so the
    SOCKS5 round-trip stays in effect."""
    block = _tor_proxy_block()
    assert "healthcheck:" not in block, (
        "tor-proxy service must NOT declare a compose-level "
        "healthcheck — the Dockerfile's curl --socks5-hostname "
        "round-trip is the source of truth and a compose override "
        "silently weakens it."
    )


# ── Group B: guard tuning ────────────────────────────────────


def test_torrc_pins_num_entry_guards_for_diversity() -> None:
    text = _TORRC.read_text(encoding="utf-8")
    # Tor's default NumEntryGuards is 1; raising it to 3 lets
    # the second/third guard handle a path-restricted circuit when
    # the primary guard can't satisfy the constraint (the failure
    # mode that wedged us on 2026-05-21).
    assert "NumEntryGuards 3" in text, (
        "torrc must set NumEntryGuards 3 to recover from the single-guard exclusion failure mode."
    )


def test_torrc_lengthens_guard_lifetime() -> None:
    text = _TORRC.read_text(encoding="utf-8")
    # 6 weeks is the upstream-recommended guard rotation
    # window for stable clients.
    assert "GuardLifetime 6 weeks" in text


def test_torrc_tunes_circuit_build_timeout_learner() -> None:
    text = _TORRC.read_text(encoding="utf-8")
    assert "LearnCircuitBuildTimeout 1" in text, (
        "torrc must enable Tor's CBT learner so circuit-build "
        "timeouts adapt to actual latency instead of the hard-coded "
        "default."
    )


def test_torrc_bounds_circuit_dirtiness_for_lnp2p() -> None:
    text = _TORRC.read_text(encoding="utf-8")
    # 600s is short enough that a stuck circuit recycles
    # quickly without churning LN streams (LongLivedPorts protects
    # those even when MaxCircuitDirtiness is hit mid-payment).
    assert "MaxCircuitDirtiness 600" in text


# ── Group B: LongLivedPorts ─────────────────────────────────


def test_torrc_marks_lnd_ports_as_long_lived() -> None:
    text = _TORRC.read_text(encoding="utf-8")
    assert "LongLivedPorts" in text, (
        "torrc must declare LongLivedPorts so the CBT learner gives LN streams more patience before tearing them down."
    )
    # Must include 8080 (LND REST) and 9735 (LN p2p) — the patience
    # is for these specifically; the default list omits them.
    long_lived_line = next(ln for ln in text.splitlines() if ln.strip().startswith("LongLivedPorts"))
    assert "8080" in long_lived_line
    assert "9735" in long_lived_line


# ── Group B: SafeLogging ────────────────────────────────────


def test_torrc_scrubs_sensitive_log_identifiers() -> None:
    text = _TORRC.read_text(encoding="utf-8")
    assert "SafeLogging 1" in text, (
        "torrc must enable SafeLogging 1 so notice-level logs "
        "don't leak target onion addresses / peer fingerprints when "
        "operators paste container logs into bug reports."
    )


# ── Group B: SocksPort isolation flags ──────────────────────


def test_every_socks_listener_has_destination_isolation() -> None:
    text = _TORRC.read_text(encoding="utf-8")
    # Every SocksPort line must include IsolateDestAddr + IsolateDestPort
    # + IsolateSOCKSAuth so the anonymize per-call-site isolation holds
    # even when two requests share a listener AND so that the existing
    # per-call (username,password) pairs in anonymize/http.py actually
    # trigger Tor's stream-isolation.
    socks_lines = [ln for ln in text.splitlines() if ln.strip().startswith("SocksPort ") and "0.0.0.0:" in ln]
    assert socks_lines, "torrc must declare at least one SocksPort"
    for ln in socks_lines:
        assert "IsolateDestAddr" in ln, f"SocksPort line missing IsolateDestAddr: {ln!r}"
        assert "IsolateDestPort" in ln, f"SocksPort line missing IsolateDestPort: {ln!r}"
        assert "IsolateSOCKSAuth" in ln, (
            f"SocksPort line missing IsolateSOCKSAuth. The "
            f"anonymize stack already issues per-call (user,pass) "
            f"pairs — without this directive Tor ignores them and "
            f"the per-session isolation contract collapses: {ln!r}"
        )


# ——: tor-proxy hardening ——————————


_TORRC_LND = Path(__file__).resolve().parents[2] / "tor-proxy" / "torrc.lnd"
_TORRC_ANONYMIZE = Path(__file__).resolve().parents[2] / "tor-proxy" / "torrc.anonymize"


class TestTorProxySecurityReviewHardening:
    """Pins the hardening posture so a later refactor can't
    silently regress the curl-insecure or unauthenticated-ControlPort
    posture."""

    def test_healthcheck_does_not_use_insecure_curl(self) -> None:
        """The clearnet probes must validate the TLS chain so a
        malicious Tor exit can't mask a real wedge with a forged 200."""
        text = _DOCKERFILE.read_text(encoding="utf-8")
        # Strip comment lines so prose explaining the *previous*
        # behaviour doesn't false-positive.
        directive_lines = [line for line in text.splitlines() if not line.lstrip().startswith("#")]
        joined = "\n".join(directive_lines)
        assert "--insecure" not in joined, (
            "tor-proxy healthcheck must not pass --insecure to curl; "
            "install ca-certificates and validate the TLS chain."
        )

    def test_image_installs_ca_certificates(self) -> None:
        """Ca-certificates is required for the healthcheck's
        TLS validation."""
        text = _DOCKERFILE.read_text(encoding="utf-8")
        assert "ca-certificates" in text, (
            "tor-proxy image must install ca-certificates so the healthcheck's https probes can validate certs."
        )

    def test_entrypoint_fails_closed_when_control_password_missing_in_prod(self) -> None:
        """Outside development the entrypoint must `exit 1`
        rather than render an unauthenticated ControlPort."""
        text = _ENTRYPOINT.read_text(encoding="utf-8")
        assert "TOR_ENVIRONMENT" in text, (
            "entrypoint.sh must branch on TOR_ENVIRONMENT (or "
            "ENVIRONMENT) to decide whether to allow an "
            "unauthenticated ControlPort."
        )
        # The fail-closed branch must be present.
        assert "exit 1" in text and "REFUSING" in text, (
            "entrypoint.sh must `exit 1` with a REFUSING message when no TOR_CONTROL_PASSWORD is set in production."
        )

    def test_torrc_socksport_has_defense_in_depth_policy(self) -> None:
        """Even though the SocksPort bind line uses 0.0.0.0
        inside the container, every shipped torrc must include
        `SocksPolicy` directives that reject connections from outside
        the docker bridge ranges so a misconfigured port mapping
        cannot expose Tor to the world."""
        for torrc_path in (_TORRC, _TORRC_LND, _TORRC_ANONYMIZE):
            text = torrc_path.read_text(encoding="utf-8")
            assert "SocksPolicy" in text, (
                f"{torrc_path.name} must include SocksPolicy directives (defense-in-depth allow-list)."
            )
            assert "SocksPolicy reject *" in text, (
                f"{torrc_path.name} must end its SocksPolicy chain with `SocksPolicy reject *` to default-deny."
            )
