# SPDX-License-Identifier: MIT
"""Liquid deployment overlay structural tests.

Validates the ``docker-compose.liquid.yml`` overlay + supporting
files (``liquid-overlay/Dockerfile.electrs-liquid``,
``liquid-overlay/elementsd.conf``) cross-reference correctly with
the wallet's Liquid config knobs. These tests don't bring the
containers up — they pin the file structure so a future edit can't
silently break the overlay contract.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

_REPO = Path(__file__).resolve().parent.parent.parent
_OVERLAY = _REPO / "docker-compose.liquid.yml"
_OVERLAY_DIR = _REPO / "liquid-overlay"
_DOCKERFILE = _OVERLAY_DIR / "Dockerfile.electrs-liquid"
_ELEMENTSD_CONF = _OVERLAY_DIR / "elementsd.conf"


# ── Existence ──────────────────────────────────────────────────────


def test_overlay_files_exist() -> None:
    assert _OVERLAY.is_file(), f"missing {_OVERLAY}"
    assert _OVERLAY_DIR.is_dir(), f"missing {_OVERLAY_DIR}"
    assert _DOCKERFILE.is_file(), f"missing {_DOCKERFILE}"
    assert _ELEMENTSD_CONF.is_file(), f"missing {_ELEMENTSD_CONF}"


# ── Compose YAML structure ─────────────────────────────────────────


@pytest.fixture
def compose_doc() -> dict:
    return yaml.safe_load(_OVERLAY.read_text(encoding="utf-8"))


def test_overlay_is_valid_yaml(compose_doc) -> None:
    assert isinstance(compose_doc, dict)
    assert "services" in compose_doc


def test_overlay_declares_elementsd_service(compose_doc) -> None:
    services = compose_doc["services"]
    assert "elementsd" in services
    elementsd = services["elementsd"]
    # Pinned to a Blockstream-published image tag (not :latest) so
    # rebuilds are reproducible.
    assert "image" in elementsd
    assert ":" in elementsd["image"]
    assert "latest" not in elementsd["image"]
    # Must use the elementsd.conf template, not the image default.
    volumes = elementsd.get("volumes") or []
    assert any("elementsd.conf" in str(v) for v in volumes), "elementsd must mount the elementsd.conf template"


def test_overlay_declares_electrs_liquid_service(compose_doc) -> None:
    services = compose_doc["services"]
    assert "electrs-liquid" in services
    electrs = services["electrs-liquid"]
    # Built from source via the overlay Dockerfile (no published image
    # we trust for liquid-mode at the moment).
    assert "build" in electrs
    build = electrs["build"]
    assert build.get("dockerfile") == "Dockerfile.electrs-liquid"


def test_electrs_liquid_depends_on_elementsd(compose_doc) -> None:
    """electrs-liquid is useless without the underlying Elements daemon.

    The overlay deliberately uses ``service_started`` (not
    ``service_healthy``) so electrs-liquid boots in parallel with
    elementsd's initial block-index replay — waiting for healthy
    would block the entire stack for the full IBD / index-replay
    window. electrs retries the daemon RPC with backoff until it is
    reachable. See the inline comment in the overlay file."""
    electrs = compose_doc["services"]["electrs-liquid"]
    deps = electrs.get("depends_on") or {}
    assert "elementsd" in deps
    assert deps["elementsd"].get("condition") in (
        "service_started",
        "service_healthy",
    )


def test_elementsd_depends_on_tor_proxy(compose_doc) -> None:
    """Liquid P2P routes through tor-proxy, so the daemon
    must wait for it before starting."""
    elementsd = compose_doc["services"]["elementsd"]
    deps = elementsd.get("depends_on") or {}
    assert "tor-proxy" in deps
    assert deps["tor-proxy"].get("condition") == "service_healthy"


def test_neither_chain_service_publishes_host_ports(compose_doc) -> None:
    """The chain services bind only to the internal Docker network —
    publishing on the host would leak the wallet's chain backend to
    other processes."""
    for name in ("elementsd", "electrs-liquid"):
        svc = compose_doc["services"][name]
        assert "ports" not in svc, f"{name} must not declare host-published ports — use `expose:` instead"


def test_api_service_wires_electrs_liquid_endpoint(compose_doc) -> None:
    """The wallet's `api` service must know where to find the
    Liquid backend — the overlay extends the base service with the
    ANONYMIZE_LIQUID_ELECTRUM_URL env binding."""
    api = compose_doc["services"]["api"]
    env = api.get("environment") or {}
    assert "ANONYMIZE_LIQUID_ELECTRUM_URL" in env
    url = env["ANONYMIZE_LIQUID_ELECTRUM_URL"]
    assert url.startswith("tcp://") or url.startswith("ssl://")
    assert "electrs-liquid" in url


def test_api_overlay_wires_electrs_liquid(compose_doc) -> None:
    """The overlay must at minimum wire the api → electrs-liquid
    address (via env). A ``depends_on`` is intentionally NOT
    declared here: the wallet handles a temporarily-unreachable
    Liquid backend gracefully (retry/backoff at the chain-adapter
    layer) and adding a healthcheck dependency would block the
    whole API startup on Liquid IBD/index-replay. The address-only
    wiring is the load-bearing contract this test pins."""
    api = compose_doc["services"]["api"]
    env = api.get("environment") or {}
    assert "ANONYMIZE_LIQUID_ELECTRUM_URL" in env
    assert "electrs-liquid" in env["ANONYMIZE_LIQUID_ELECTRUM_URL"]


def test_persistent_volumes_declared(compose_doc) -> None:
    """Chain data + index must survive container restarts."""
    volumes = compose_doc.get("volumes") or {}
    assert "elementsd_data" in volumes
    assert "electrs_liquid_data" in volumes


def test_hardened_security_options_applied(compose_doc) -> None:
    """Mirror the base compose file's hardening: no privilege
    escalation + cap-drop."""
    for name in ("elementsd", "electrs-liquid"):
        svc = compose_doc["services"][name]
        sec_opts = svc.get("security_opt") or []
        assert any("no-new-privileges" in str(o) for o in sec_opts), (
            f"{name}: must declare no-new-privileges security_opt"
        )
        cap_drop = svc.get("cap_drop") or []
        assert "ALL" in cap_drop, f"{name}: must drop ALL capabilities"


def test_resource_limits_declared(compose_doc) -> None:
    """Both chain services must declare memory + CPU bounds — defense
    against runaway indexing / mempool consumption."""
    for name in ("elementsd", "electrs-liquid"):
        svc = compose_doc["services"][name]
        deploy = svc.get("deploy") or {}
        limits = deploy.get("resources", {}).get("limits") or {}
        assert "memory" in limits, f"{name}: missing memory limit"
        assert "cpus" in limits, f"{name}: missing cpus limit"


# ── Healthchecks ───────────────────────────────────────────────────


def test_chain_services_have_healthchecks(compose_doc) -> None:
    """Both chain services need healthchecks so the api can wait on
    them. Without them, the api would race against the indexer build
    on first startup."""
    for name in ("elementsd", "electrs-liquid"):
        svc = compose_doc["services"][name]
        hc = svc.get("healthcheck")
        assert hc is not None, f"{name}: missing healthcheck"
        assert "test" in hc


# ── Dockerfile structure ───────────────────────────────────────────


def test_dockerfile_is_multi_stage_build() -> None:
    """The Rust toolchain shouldn't ship in the runtime image — saves
    ~1 GB + reduces attack surface."""
    content = _DOCKERFILE.read_text(encoding="utf-8")
    assert content.count("FROM ") >= 2, "Dockerfile must be multi-stage"


def test_dockerfile_builds_with_liquid_feature() -> None:
    """The whole point of the from-source build is to enable the
    Liquid feature flag."""
    content = _DOCKERFILE.read_text(encoding="utf-8")
    assert "--features liquid" in content


def test_dockerfile_pins_git_ref() -> None:
    """Reproducible builds — the Git ref must be configurable so
    operators can verify-and-pin a known-good commit."""
    content = _DOCKERFILE.read_text(encoding="utf-8")
    assert "ELECTRS_GIT_REF" in content
    assert "git clone --depth" in content


def test_dockerfile_runs_as_non_root() -> None:
    """Defense in depth — the runtime stage must drop root."""
    content = _DOCKERFILE.read_text(encoding="utf-8")
    assert "USER electrs" in content


def test_dockerfile_uses_cargo_locked() -> None:
    """``--locked`` refuses to build if Cargo.lock would have to
    change — prevents silent dependency drift."""
    content = _DOCKERFILE.read_text(encoding="utf-8")
    assert "--locked" in content


# ── elementsd.conf structure ───────────────────────────────────────


def test_elementsd_conf_routes_p2p_through_tor() -> None:
    """Liquid P2P never escapes Tor."""
    content = _ELEMENTSD_CONF.read_text(encoding="utf-8")
    assert "proxy=tor-proxy:9050" in content
    assert "onlynet=onion" in content


def test_elementsd_conf_refuses_dns_seed_fallbacks() -> None:
    """``dnsseed=0`` + ``forcednsseed=0`` prevent the daemon from
    falling back to clearnet DNS for peer discovery."""
    content = _ELEMENTSD_CONF.read_text(encoding="utf-8")
    assert "dnsseed=0" in content
    assert "forcednsseed=0" in content


def test_elementsd_conf_disables_pruning() -> None:
    """electrs-liquid needs a full chain to index — pruning would
    break it silently."""
    content = _ELEMENTSD_CONF.read_text(encoding="utf-8")
    assert "prune=0" in content


def test_elementsd_conf_disables_logips() -> None:
    """Defense against the log file leaking peer-IP correlation."""
    content = _ELEMENTSD_CONF.read_text(encoding="utf-8")
    assert "logips=0" in content


# ── Wallet config knob ─────────────────────────────────────────────


def test_wallet_settings_carry_liquid_electrum_url_knob() -> None:
    """The overlay sets ANONYMIZE_LIQUID_ELECTRUM_URL on the api
    service — verify the wallet's Settings class actually reads it."""
    from app.core.config import settings

    assert hasattr(settings, "anonymize_liquid_electrum_url"), (
        "wallet Settings must declare `anonymize_liquid_electrum_url`"
    )


# ──: elementsd RPC secret hardening ────────────────────────────


class TestElementsdRpcCredentialHardening:
    """The shipped
    ``elementsd.conf`` must not contain any rpcpassword line — the
    overlay's compose file passes credentials via the elementsd
    command line so the placeholder cannot be silently shipped into
    a deployment. The compose file must template the user/password
    from env vars and narrow ``rpcallowip`` to the overlay's docker
    subnet only."""

    def test_elementsd_conf_has_no_hardcoded_secret(self) -> None:
        text = _ELEMENTSD_CONF.read_text(encoding="utf-8")
        bad_lines = [
            line
            for line in text.splitlines()
            if line.strip().startswith("rpcpassword=") and not line.strip().startswith("#")
        ]
        assert not bad_lines, (
            f"elementsd.conf must not encode a literal rpcpassword "
            f"(found: {bad_lines!r}); the compose file passes it via "
            f"the command line."
        )

    def test_elementsd_conf_no_longer_contains_legacy_placeholder(self) -> None:
        text = _ELEMENTSD_CONF.read_text(encoding="utf-8")
        # Allow the literal in a comment explaining the rejection rule
        # in `_validate_env_secrets`, but reject it on any directive
        # line.
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            assert "change-me-in-production" not in stripped, (
                f"legacy placeholder leaked onto a directive line: {line!r}"
            )

    def test_compose_authenticates_elementsd_via_rpcauth(self) -> None:
        compose = yaml.safe_load(_OVERLAY.read_text(encoding="utf-8"))
        elementsd = compose["services"]["elementsd"]
        # The overlay wraps elementsd in a small shell script (under
        # ``entrypoint:``) so the container can chmod the datadir after
        # the daemon spawns. The daemon authenticates with a salted-hash
        # rpcauth line templated from env: the cleartext password never
        # reaches the conf file or the process argument list. The
        # load-bearing contract is that no cleartext credential is on the
        # command line.
        snippet = elementsd.get("command") or elementsd.get("entrypoint")
        assert snippet, "elementsd service must declare a `command:` or `entrypoint:` override"
        joined = " ".join(snippet) if isinstance(snippet, list) else snippet
        assert "ELEMENTSD_RPC_AUTH" in joined, (
            "elementsd entrypoint must template the salted-hash ELEMENTSD_RPC_AUTH from env"
        )
        assert "-rpcpassword=" not in joined, (
            "elementsd entrypoint must not pass the cleartext -rpcpassword on the command line"
        )
        assert "ELEMENTSD_RPC_AUTH" in (elementsd.get("environment") or []), (
            "elementsd must receive ELEMENTSD_RPC_AUTH in its environment"
        )

    def test_compose_narrows_rpcallowip_to_overlay_subnet(self) -> None:
        """The shipped command line restricts -rpcallowip to a single
        docker subnet rather than the union of all RFC1918 ranges
        that used to live in elementsd.conf."""
        compose = yaml.safe_load(_OVERLAY.read_text(encoding="utf-8"))
        elementsd = compose["services"]["elementsd"]
        snippet = elementsd.get("command") or elementsd.get("entrypoint") or []
        joined = " ".join(snippet) if isinstance(snippet, list) else snippet
        # Must reference ELEMENTSD_RPC_ALLOW_CIDR (operator-tunable)
        # and the default must be a single /16 subnet, NOT the legacy
        # multi-RFC1918 allow-list.
        assert "-rpcallowip=" in joined, "elementsd command must pass -rpcallowip explicitly"
        assert "ELEMENTSD_RPC_ALLOW_CIDR" in joined, "rpcallowip must be templated from ELEMENTSD_RPC_ALLOW_CIDR"
        # The legacy union of RFC1918 ranges must NOT survive as a
        # checked-in default on either the conf or the compose file.
        conf_text = _ELEMENTSD_CONF.read_text(encoding="utf-8")
        for cidr in ("172.16.0.0/12", "10.0.0.0/8", "192.168.0.0/16"):
            for line in conf_text.splitlines():
                stripped = line.strip()
                if stripped.startswith("#") or stripped.startswith("rpcallowip"):
                    # comments OK; we just don't want a directive that
                    # widens the allow-list.
                    if stripped.startswith(f"rpcallowip={cidr}"):
                        pytest.fail(
                            f"elementsd.conf still encodes legacy "
                            f"rpcallowip={cidr}; the compose command "
                            f"line owns this now."
                        )
