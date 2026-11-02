"""CI's test job gives the plugin tests the pinned verifier from a filled uv cache (review package -1, question T-2).

The gate and the plugin server start the verifier with `uv run --script`, which installs the package pinned in the
server's header (plugins/proofbundle/server/proofbundle_mcp.py, proofbundle==6.3.0). The plugin tests pass UV_CACHE_DIR
and UV_OFFLINE through to every process they start (tests/_plugin_env.py, FIXED), so they read the verifier from the
cache their caller names. Measured on 2026-10-26: with UV_OFFLINE=1 and without UV_CACHE_DIR, seven plugin tests were
red with "the verifier did not initialise". CI's test job installed no uv, named no cache and filled none.

The property held here, read from .github/workflows/ci.yml: the test job installs a pinned uv, names one UV_CACHE_DIR
and runs offline, and fills that cache before the Test step by starting the plugin server once with the network on.

Finding Z2 of the first reading of G-4 (sol-pro, P1): the parts contract (tests/test_ci_test_parts_cover_the_suite.py)
knows the fill step by its name, this file by its command, and neither tied the two together. The real step renamed and
put under `if: matrix.part == 1`, beside a step that runs `true` under the fill step's name, passed both, and parts 2 to
K ran without a filled cache. Exactly one step runs the fill command, it is the one step of the name the contract
counts, and it carries no `if`.
"""
from __future__ import annotations

import copy
import pathlib
import re

import pytest

import test_ci_test_parts_cover_the_suite as parts

yaml = pytest.importorskip("yaml")

ROOT = pathlib.Path(__file__).resolve().parent.parent
CI = ROOT / ".github" / "workflows" / "ci.yml"
SERVER = "plugins/proofbundle/server/proofbundle_mcp.py"
FILL_COMMAND = f"uv run --no-config --quiet --script {SERVER} < /dev/null"


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
    fills = [i for i, s in enumerate(steps) if str(s.get("run", "")).strip() == FILL_COMMAND]
    assert fills and fills[0] < _test_step_index(steps), [s.get("run") for s in steps]
    assert str((steps[fills[0]].get("env") or {}).get("UV_OFFLINE")).lower() in ("0", "false"), steps[fills[0]]


def fill_findings(steps: list) -> list[str]:
    """Where the step that fills the cache is not the one the parts contract counts in every part, or may not run in
    one: exactly one step runs FILL_COMMAND, it is the one step named parts.FILL, and it carries no `if`. Pure."""
    fills = [s for s in steps if str(s.get("run", "")).strip() == FILL_COMMAND]
    named = [s for s in steps if s.get("name") == parts.FILL]
    found = [] if len(fills) == 1 else [f"{len(fills)} steps run the fill command"]
    if named != fills:
        found.append(f"the step named {parts.FILL!r} is not the step that runs the fill command")
    found += ["the step that fills the cache carries `if`" for s in fills if "if" in s]
    return found


def test_the_step_that_fills_the_cache_is_the_one_the_parts_contract_counts_and_runs_in_every_part():
    assert fill_findings(_test_job()["steps"]) == []


def test_planted_a_renamed_fill_step_under_if_beside_an_empty_step_of_its_name_is_found():
    """The reproducer of Z2. The parts contract alone accepts this job, which is why the check above is needed."""
    job = copy.deepcopy(_test_job())
    steps = job["steps"]
    i = [s.get("name") for s in steps].index(parts.FILL)
    steps[i] = dict(steps[i], name="Fill uv's cache, renamed", **{"if": parts.PART_ONE})
    steps.insert(i, {"name": parts.FILL, "run": "true"})
    assert parts.job_findings(job) == []
    assert fill_findings(steps) == [f"the step named {parts.FILL!r} is not the step that runs the fill command",
                                    "the step that fills the cache carries `if`"]
