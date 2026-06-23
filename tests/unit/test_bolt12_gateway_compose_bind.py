# SPDX-License-Identifier: MIT
"""Regression guard: the bolt12-gateway service in docker-compose.yml
must override the gRPC bind address to ``0.0.0.0`` inside the
container.

Background: the mounted ``bolt12-gateway/config.example.toml``
defaults ``grpc_listen`` to ``127.0.0.1:50061``. That default is
correct for someone running the gateway binary directly on a host
(safe-by-default — not silently exposed on a public interface), but
inside Docker Compose it's actively broken: peer services (api,
celery-worker) reach the gateway via its private-network IP, not
via loopback inside the gateway's own container. With the TOML
default in effect, every wallet probe lands as ``Connection
refused`` and the BOLT 12 runtime never establishes a working
session.

The 2026-05-22 incident caught this — a fresh deployment logged
``failed to connect to all addresses ... ipv4:172.19.0.5:50061:
Failed to connect to remote host: Connection refused`` on every
health probe.  The fix sets ``BOLT12_GATEWAY_GRPC_LISTEN=0.0.0.0:50061``
in the gateway service environment, which the Rust gateway reads
and uses to override the TOML default.

Why this test exists: a future "security hardening" pass could
easily revert the override back to 127.0.0.1 on the (incorrect)
assumption that loopback is always safer — re-introducing the same
outage. No host port is published, so the bind address alone is
not the security boundary; the bearer token
(``BOLT12_GATEWAY_TOKEN``) is.
"""

from __future__ import annotations

from pathlib import Path

_COMPOSE = Path(__file__).resolve().parents[2] / "docker-compose.yml"


def test_bolt12_gateway_binds_all_interfaces_inside_container() -> None:
    text = _COMPOSE.read_text(encoding="utf-8")
    service_start = text.find("bolt12-gateway:")
    assert service_start != -1, "bolt12-gateway service missing from docker-compose.yml"
    # The next top-level service or trailing ``volumes:`` block
    # marks the end. We accept either delimiter.
    next_api = text.find("\n  api:", service_start)
    next_volumes = text.find("\nvolumes:", service_start)
    candidates = [pos for pos in (next_api, next_volumes) if pos != -1]
    assert candidates, "compose file structure changed unexpectedly"
    block_end = min(candidates)
    service_block = text[service_start:block_end]

    assert "BOLT12_GATEWAY_GRPC_LISTEN" in service_block, (
        "The bolt12-gateway service must set "
        "``BOLT12_GATEWAY_GRPC_LISTEN`` to override the TOML's "
        "loopback default. Without this, peer containers can't "
        "reach the gateway and every BOLT 12 probe logs "
        "'Connection refused'. See the 2026-05-22 incident note in "
        "docker-compose.yml and bolt12-gateway/config.example.toml."
    )
    # Accept any 0.0.0.0:* form (port number is not the load-
    # bearing piece; the all-interfaces bind is).
    assert "0.0.0.0:" in service_block, (
        "``BOLT12_GATEWAY_GRPC_LISTEN`` must bind to 0.0.0.0 inside "
        "the container so peer Compose services can reach the "
        "gateway over the private docker network. A 127.0.0.1 bind "
        "is only reachable from inside the gateway container itself "
        "and breaks the wallet↔gateway channel. The bearer token "
        "(BOLT12_GATEWAY_TOKEN) provides the auth boundary; the "
        "bind address does not."
    )
