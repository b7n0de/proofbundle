"""CI's test job gives the plugin tests the pinned verifier from a filled uv cache (review package -1, question T-2).

The gate and the plugin server start the verifier with `uv run --script`, which installs the package pinned in the
server's header (plugins/proofbundle/server/proofbundle_mcp.py, proofbundle==6.3.0). The plugin tests pass UV_CACHE_DIR
and UV_OFFLINE through to every process they start (tests/_plugin_env.py, FIXED), so they read the verifier from the
cache their caller names. Measured on 2026-10-26: with UV_OFFLINE=1 and without UV_CACHE_DIR, seven plugin tests were
red with "the verifier did not initialise". CI's test job installed no uv, named no cache and filled none.

The property held here, read from .github/workflows/ci.yml: the test job installs a pinned uv, names one UV_CACHE_DIR
and runs offline, and fills that cache before the Test step by starting the plugin server once with the network on.
"""
from __future__ import annotations

import pathlib
import re

import pytest

yaml = pytest.importorskip("yaml")

ROOT = pathlib.Path(__file__).resolve().parent.parent
CI = ROOT / ".github" / "workflows" / "ci.yml"
SERVER = "plugins/proofbundle/server/proofbundle_mcp.py"


def _test_job() -> dict:
    return yaml.safe_load(CI.read_text(encoding="utf-8"))["jobs"]["test"]


def _test_step_index(steps: list) -> int:
    return [s.get("name") for s in steps].index("Test")


def test_the_test_job_names_one_uv_cache_and_runs_offline():
    env = _test_job().get("env") or {}
    assert env.get("UV_CACHE_DIR"), env
    assert str(env.get("UV_OFFLINE")).lower() in ("1", "true"), env


def test_the_test_job_installs_a_pinned_uv_before_the_test_step():
    steps = _test_job()["steps"]
    installs = [i for i, s in enumerate(steps) if re.search(r"\bpip install uv==\d+\.\d+\.\d+$", str(s.get("run", "")))]
    assert installs and installs[0] < _test_step_index(steps), [s.get("run") for s in steps]


def test_the_cache_is_filled_with_the_servers_pinned_verifier_before_the_test_step():
    steps = _test_job()["steps"]
    fills = [i for i, s in enumerate(steps)
             if f"uv run --no-config --quiet --script {SERVER} < /dev/null" == str(s.get("run", "")).strip()]
    assert fills and fills[0] < _test_step_index(steps), [s.get("run") for s in steps]
    assert str((steps[fills[0]].get("env") or {}).get("UV_OFFLINE")).lower() in ("0", "false"), steps[fills[0]]
