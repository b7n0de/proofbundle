"""The mutation gate runs its test child under an address-space ceiling (owner answer of 2026-09-27, patch A).

THE FINDING. Shard 26 of the CI dispatch run 36285011022 (claude/magical-goodall-bhfu70 at a19885e, which
carries main 1e95b19) ended twice with exit 143, "The runner has received a shutdown signal", both times
while the operator `budget: data_digests-Schranke praktisch entfernt` ran (job logs 108529778965 and
108542942157). That operator raises the data_digests bound from 2000 to 2000000000, and the cost curve
of tests/test_budget_kostenkurve.py builds its load from the raised bound. Reproduced on main 1e95b19
with the operator applied and every process capped at 6 GiB: 9 MemoryErrors at
tests/test_budget_kostenkurve.py:970. Without a cap the child grows until the runner goes down, and the
shard writes no verdict line at all.

THE PROPERTY held here: every run of the gate's child (`_red_count`, which carries the baseline, the
mutant runs and the confirmations) stands under `CHILD_ADDRESS_SPACE_CAP`, so a load past it is a red
test inside the child and the run is still counted. The cases drive the real `_red_count` on a small
tree, not a copy of its command line.

Oracle: the kernel. RLIMIT_AS as the child reads it back, and an anonymous mapping past the ceiling that
the kernel refuses under the limit and grants lazily without it (no page is touched).
"""
from __future__ import annotations

import importlib.util
import subprocess
import sys
import textwrap
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
GATE = REPO / "scripts" / "mutation_check.py"


def _gate():
    spec = importlib.util.spec_from_file_location("_mc_child_memory_cap", str(GATE))
    module = importlib.util.module_from_spec(spec)
    sys.modules["_mc_child_memory_cap"] = module
    spec.loader.exec_module(module)
    return module


def _tree(tmp_path: Path, body: str) -> Path:
    (tmp_path / "src").mkdir(exist_ok=True)
    (tmp_path / "tests").mkdir(exist_ok=True)
    (tmp_path / "tests" / "test_probe.py").write_text(textwrap.dedent(body), encoding="utf-8")
    return tmp_path


def test_the_child_of_the_gate_reads_the_ceiling_back(tmp_path):
    """Red without the ceiling: RLIMIT_AS in the child is unlimited, and the probe test is red."""
    gate = _gate()
    cap = gate.CHILD_ADDRESS_SPACE_CAP
    tree = _tree(tmp_path, f"""
        import resource

        def test_the_ceiling_is_set():
            soft, hard = resource.getrlimit(resource.RLIMIT_AS)
            assert soft != resource.RLIM_INFINITY and soft <= {cap}, (soft, hard)
            assert hard != resource.RLIM_INFINITY and hard <= {cap}, (soft, hard)
        """)
    assert gate._red_count(tree) == 0, (
        f"the gate's child does not stand under the ceiling of {cap} bytes: a mutant that raises a "
        f"resource bound can take the runner down instead of turning a test red")


def test_a_load_past_the_ceiling_is_a_red_test_and_the_run_is_counted(tmp_path):
    """Red without the ceiling: the kernel grants the mapping lazily, and the probe test passes."""
    gate = _gate()
    past = gate.CHILD_ADDRESS_SPACE_CAP + (1 << 30)
    tree = _tree(tmp_path, f"""
        import mmap

        def test_a_load_past_the_ceiling():
            mmap.mmap(-1, {past}, flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS)
        """)
    assert gate._red_count(tree) == 1, (
        "a load past the ceiling must end as one red test in a counted run; 0 means the child ran "
        "without the ceiling, None means the run left no verdict")


def test_a_load_under_the_ceiling_stays_green(tmp_path):
    """The control: the ceiling does not turn a test red that stays well below it."""
    gate = _gate()
    tree = _tree(tmp_path, """
        def test_a_load_under_the_ceiling():
            load = bytearray(256 << 20)
            load[::4096] = b"x" * len(load[::4096])
            assert len(load) == 256 << 20
        """)
    assert gate._red_count(tree) == 0


def test_the_ceiling_lowers_a_limit_and_never_raises_one():
    """A limit the caller set below the ceiling stays; without one the ceiling is set."""
    code = textwrap.dedent(f"""
        import importlib.util, resource, sys
        spec = importlib.util.spec_from_file_location("_gate", {str(GATE)!r})
        gate = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gate)
        lower = int(sys.argv[1])
        if lower:
            resource.setrlimit(resource.RLIMIT_AS, (lower, lower))
        gate._cap_the_address_space_of_the_child()
        print(*resource.getrlimit(resource.RLIMIT_AS))
        """)
    cap = _gate().CHILD_ADDRESS_SPACE_CAP
    for lower, want in ((0, (cap, cap)), (2 << 30, (2 << 30, 2 << 30))):
        out = subprocess.run([sys.executable, "-c", code, str(lower)], capture_output=True, text=True,
                             timeout=120, check=True).stdout.split()
        assert tuple(int(x) for x in out) == want, (lower, out)
