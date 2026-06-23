# SPDX-License-Identifier: MIT
"""Regression tests for ``start.sh`` env-parsing + Fernet-key handling.

The wizard's ``load_env`` function ROUND-TRIPS values through a
bash variable read; an earlier ``IFS='=' read -r key val`` pattern
silently stripped trailing ``=`` characters, mangling every base64-
padded Fernet key on every wizard re-run. The fix uses parameter
expansion to split-on-first-``=`` while preserving the rest of the
line verbatim.

Pinning the contract here keeps the bug from regressing: a future
edit that swaps the parameter expansion back for ``read`` would
fail these tests before reaching production.

The tests shell out to bash because ``load_env`` is a bash function
— there's no Python equivalent to validate against. Each test
writes a temp .env, invokes a small bash harness that sources the
relevant functions from ``start.sh``, then captures the exported
variables for inspection.
"""

from __future__ import annotations

import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
_START_SH = _REPO / "start.sh"


def _extract_bash_function(name: str) -> str:
    """Extract ``name()``'s body from start.sh as a standalone
    bash function definition. Sourcing start.sh directly runs the
    top-level CLI dispatch (``main "$@"`` at EOF) which hangs on
    an interactive prompt; we just need the function definitions
    in isolation.

    bash idiom: a function definition's closing brace is the
    first ``}`` at the SAME indentation as the opening ``name() {``
    line. Top-level functions close at column 0; nested helpers
    (defined inside ``run_config()``) close at the parent's
    indent + 4. Match by indentation rather than brace-counting
    so ``${...}`` shell expansions in the body don't confuse us."""
    text = _START_SH.read_text(encoding="utf-8")
    lines = text.splitlines()
    out: list[str] = []
    in_fn = False
    opening_indent = ""
    for line in lines:
        stripped = line.lstrip()
        leading = line[: len(line) - len(stripped)]
        if not in_fn:
            # Match ``name() {`` OR ``name()`` at the start of the
            # stripped line. Indentation can be anything (top-level
            # or nested).
            if stripped.startswith(f"{name}() {{") or stripped.startswith(f"{name}() ") or stripped == f"{name}()":
                in_fn = True
                opening_indent = leading
                # Keep the original line verbatim. bash is
                # whitespace-insensitive for function bodies, so
                # we don't need to re-indent. Crucially, we must
                # NOT strip leading whitespace from BODY lines
                # because some bodies embed multi-line Python
                # heredocs whose Python indentation matters.
                out.append(line)
            continue
        # The closing line is ``<opening_indent>}`` exactly. Match
        # by indentation so a stray ``}`` inside a string literal
        # in the body doesn't terminate extraction early.
        if line == f"{opening_indent}}}":
            out.append(line)
            break
        out.append(line)
    if not out:
        raise RuntimeError(f"could not extract bash function {name!r} from start.sh")
    return "\n".join(out)


def _run_load_env_then_print(env_text: str, var_to_print: str) -> str:
    """Write ``env_text`` to a temp .env, define load_env + get_env
    in a fresh bash, run load_env, then print the requested
    ``ENV_<var>`` value."""
    import tempfile

    tmpdir = tempfile.mkdtemp()
    try:
        env_path = Path(tmpdir) / ".env"
        env_path.write_text(env_text, encoding="utf-8")
        load_env_src = _extract_bash_function("load_env")
        get_env_src = _extract_bash_function("get_env")
        harness = f"""\
ENV_FILE="{env_path}"
{load_env_src}
{get_env_src}
load_env
echo "${{ENV_{var_to_print}-__UNSET__}}"
"""
        result = subprocess.run(
            ["bash", "-c", harness],
            capture_output=True,
            text=True,
            check=False,
            timeout=15,
        )
        assert result.returncode == 0, f"bash harness failed: stderr={result.stderr!r}\nstdout={result.stdout!r}"
        # The last non-empty stdout line is the printed value.
        lines = [ln for ln in result.stdout.splitlines() if ln != ""]
        return lines[-1] if lines else ""
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# ── load_env: trailing = preservation ─────────────────────────────


@pytest.mark.skipif(not shutil.which("bash"), reason="bash not available")
def test_load_env_preserves_trailing_equals() -> None:
    """The canonical regression: a value ending in ``=`` (every
    base64-padded Fernet key looks like this) must survive the
    round-trip through load_env. If load_env reverts to
    ``IFS='=' read -r key val``, the trailing ``=`` would be
    stripped and downstream code would treat the 43-char value
    as malformed."""
    env = "ANONYMIZE_QUOTE_TOKEN_HMAC_KEY_FERNET=Ho8XdXTbySMcxhHLB3ZpIl5P4hs6n7qgtP4rq9vcNRE=\n"
    got = _run_load_env_then_print(
        env,
        "ANONYMIZE_QUOTE_TOKEN_HMAC_KEY_FERNET",
    )
    assert got == "Ho8XdXTbySMcxhHLB3ZpIl5P4hs6n7qgtP4rq9vcNRE=", (
        "load_env stripped the trailing ``=`` from a Fernet key — "
        "the 2026-05-21 start.sh bug has regressed. The fix uses "
        "parameter expansion (``${line%%=*}`` / ``${line#*=}``) "
        "instead of ``read -r``."
    )


@pytest.mark.skipif(not shutil.which("bash"), reason="bash not available")
def test_load_env_preserves_value_with_embedded_equals() -> None:
    """A value containing one or more interior ``=`` characters
    (e.g. base64 with multiple ``==`` padding) must survive
    intact — split must be on the FIRST ``=`` only."""
    env = "WEIRD_KEY=foo=bar==baz\n"
    got = _run_load_env_then_print(env, "WEIRD_KEY")
    assert got == "foo=bar==baz", f"load_env mangled an embedded-= value: {got!r}"


@pytest.mark.skipif(not shutil.which("bash"), reason="bash not available")
def test_load_env_handles_normal_value_without_equals() -> None:
    """A plain value without any ``=`` must still load — the
    parameter-expansion fix shouldn't break the common case."""
    env = "SIMPLE_KEY=plain-value-no-equals\n"
    got = _run_load_env_then_print(env, "SIMPLE_KEY")
    assert got == "plain-value-no-equals"


@pytest.mark.skipif(not shutil.which("bash"), reason="bash not available")
def test_load_env_skips_comments_and_blank_lines() -> None:
    """The file may contain comments + blank lines; they must not
    leak as exported variables. Pinned because a regression that
    started exporting comment lines would clutter the environment
    and could even override real settings."""
    env = textwrap.dedent("""\
        # This is a comment
        REAL_KEY=real-value=

        # Another comment
    """)
    got = _run_load_env_then_print(env, "REAL_KEY")
    assert got == "real-value="
    # The comment line itself must NOT have been exported as a key.
    got_comment = _run_load_env_then_print(env, "_This_is_a_comment")
    assert got_comment == "__UNSET__"


# ── Fernet key validator ──────────────────────────────────────────


def _run_fernet_valid(value: str) -> str:
    """Define ``_fernet_valid`` standalone in a fresh bash + invoke
    it on ``value``. Returns the harness's stdout (``valid`` /
    ``invalid``). Same extraction pattern as load_env."""
    fernet_valid_src = _extract_bash_function("_fernet_valid")
    # The function uses python3; assert python3 is callable here.
    harness = f"""\
{fernet_valid_src}
if _fernet_valid "{value}"; then
    echo "valid"
else
    echo "invalid"
fi
"""
    result = subprocess.run(
        ["bash", "-c", harness],
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )
    assert result.returncode == 0, f"bash harness failed: stderr={result.stderr!r}"
    return result.stdout.strip().splitlines()[-1]


@pytest.mark.skipif(not shutil.which("bash"), reason="bash not available")
def test_fernet_valid_accepts_padded_44char_key() -> None:
    """``_fernet_valid`` must return 0 for a real Fernet key (44
    chars, base64-decodes to 32 bytes)."""
    assert (
        _run_fernet_valid(
            "Ho8XdXTbySMcxhHLB3ZpIl5P4hs6n7qgtP4rq9vcNRE=",
        )
        == "valid"
    )


@pytest.mark.skipif(not shutil.which("bash"), reason="bash not available")
def test_fernet_valid_rejects_unpadded_43char_key() -> None:
    """``_fernet_valid`` must return non-zero for the 43-char
    unpadded form. The wizard's regen-on-invalid path depends on
    this rejection — without it, the broken 43-char keys from
    older start.sh runs would be silently preserved."""
    got = _run_fernet_valid(
        "Ho8XdXTbySMcxhHLB3ZpIl5P4hs6n7qgtP4rq9vcNRE",
    )
    assert got == "invalid", f"_fernet_valid accepted the broken 43-char form: {got!r}"


@pytest.mark.skipif(not shutil.which("bash"), reason="bash not available")
def test_fernet_valid_rejects_empty_and_garbage() -> None:
    """Empty + obvious garbage both return non-zero — empty so the
    wizard generates a fresh key, garbage so it doesn't silently
    use whatever the operator pasted."""
    for bad in ("", "short"):
        got = _run_fernet_valid(bad)
        assert got == "invalid", f"_fernet_valid accepted garbage value {bad!r}: {got}"


# ──: placeholder-credential guard ───────────────────────


def _run_validate_secrets(env_text: str) -> subprocess.CompletedProcess:
    """Invoke ``_validate_env_secrets`` in a fresh bash with the
    supplied .env contents. Returns the full CompletedProcess so
    tests can inspect both exit code and stderr."""
    import tempfile

    tmpdir = tempfile.mkdtemp()
    try:
        env_path = Path(tmpdir) / ".env"
        env_path.write_text(env_text, encoding="utf-8")
        load_env_src = _extract_bash_function("load_env")
        get_env_src = _extract_bash_function("get_env")
        validate_src = _extract_bash_function("_validate_env_secrets")
        harness = f"""\
ENV_FILE="{env_path}"
err() {{ echo "ERR: $*" >&2; }}
{load_env_src}
{get_env_src}
{validate_src}
_validate_env_secrets
echo "ok"
"""
        return subprocess.run(
            ["bash", "-c", harness],
            capture_output=True,
            text=True,
            check=False,
            timeout=15,
        )
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


@pytest.mark.skipif(not shutil.which("bash"), reason="bash not available")
def test_start_sh_refuses_replace_me_placeholder_passwords() -> None:
    """Start.sh must refuse to launch with placeholder
    credentials. Tests every variable that flows into the docker
    network or the dashboard."""
    env = textwrap.dedent("""\
        POSTGRES_PASSWORD=__REPLACE_ME__
        REDIS_PASSWORD=actual-strong-redis-password
        SECRET_KEY=an-actual-64-char-secret-key-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    """)
    result = _run_validate_secrets(env)
    assert result.returncode != 0, "_validate_env_secrets accepted POSTGRES_PASSWORD=__REPLACE_ME__"
    assert "POSTGRES_PASSWORD" in result.stderr


@pytest.mark.skipif(not shutil.which("bash"), reason="bash not available")
def test_start_sh_refuses_legacy_change_me_password_strings() -> None:
    """Legacy placeholders from prior `.env.example` revisions
    (``change-me-strong-password`` / ``change-me-redis-password``)
    must also trigger the refusal so an old operator who never
    rotated isn't silently allowed to boot."""
    env = textwrap.dedent("""\
        POSTGRES_PASSWORD=change-me-strong-password
        REDIS_PASSWORD=change-me-redis-password
        SECRET_KEY=an-actual-64-char-secret-key-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    """)
    result = _run_validate_secrets(env)
    assert result.returncode != 0


@pytest.mark.skipif(not shutil.which("bash"), reason="bash not available")
def test_start_sh_refuses_default_elementsd_password_when_liquid_enabled() -> None:
    """When the operator enables the Liquid overlay, the
    elementsd RPC password must not still be the shipped
    placeholder."""
    env = textwrap.dedent("""\
        POSTGRES_PASSWORD=strong-pg-pw
        REDIS_PASSWORD=strong-redis-pw
        SECRET_KEY=an-actual-64-char-secret-key-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
        ENABLE_LIQUID=true
        ELEMENTSD_RPC_PASSWORD=change-me-in-production
    """)
    result = _run_validate_secrets(env)
    assert result.returncode != 0, (
        "_validate_env_secrets accepted the shipped elementsd placeholder while ENABLE_LIQUID=true"
    )


@pytest.mark.skipif(not shutil.which("bash"), reason="bash not available")
def test_start_sh_validate_secrets_accepts_real_credentials() -> None:
    """The happy path: real (non-placeholder) credentials succeed."""
    env = textwrap.dedent("""\
        POSTGRES_PASSWORD=actually-a-strong-pg-password
        REDIS_PASSWORD=actually-a-strong-redis-password
        SECRET_KEY=an-actual-64-char-secret-key-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    """)
    result = _run_validate_secrets(env)
    assert result.returncode == 0, f"_validate_env_secrets rejected valid credentials: stderr={result.stderr!r}"


def test_env_example_uses_replace_me_placeholders() -> None:
    """``.env.example`` must use obvious ``__REPLACE_ME__``
    placeholders for both PostgreSQL and Redis passwords. The
    matching guard in ``_validate_env_secrets`` only fires for
    those exact literals; a regression that loosens the example
    would silently weaken the boot-time check."""
    env_example = _REPO / ".env.example"
    text = env_example.read_text(encoding="utf-8")
    # The two lines we care about. Use exact-substring assertions
    # so a future cosmetic edit can't quietly reintroduce a real-
    # looking password.
    assert "POSTGRES_PASSWORD=__REPLACE_ME__" in text
    assert "REDIS_PASSWORD=__REPLACE_ME__" in text
    # And the old defaults are gone.
    assert "change-me-strong-password" not in text
    assert "change-me-redis-password" not in text
