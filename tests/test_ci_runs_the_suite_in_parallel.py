"""CI runs the suite in parallel, with every guard it had, and cannot skip the Rust verifier away.

Owner decision 2026-09-28 (Z281): the test matrix and the coverage job run pytest with pytest-xdist,
pytest stays the normative runner, coverage is combined across workers, and the locked test
manifest, the F4 type-confusion matrix and the hermetic cleanroom stay. Owner note of the same day:
the jobs that run the suite build pb_verify_rs first, pin it, and require it, so a test that would
skip for a missing binary fails there instead.
"""
from __future__ import annotations

import pathlib
import re

import pytest

yaml = pytest.importorskip("yaml")

REPO = pathlib.Path(__file__).resolve().parents[1]
WORKFLOWS = REPO / ".github" / "workflows"
SUITE_JOBS = ("test", "coverage", "crypto-floor")
BUILD = "cd tools/pb_verify_rs && cargo build --release"
PINNED = "${{ github.workspace }}/tools/pb_verify_rs/target/release/pb_verify_rs"


def _jobs(name: str = "ci.yml") -> dict:
    return yaml.safe_load((WORKFLOWS / name).read_text(encoding="utf-8"))["jobs"]


def _runs(job: dict) -> list[str]:
    return [str(s.get("run", "")) for s in job.get("steps", [])]


def _index(job: dict, needle: str) -> int:
    hits = [i for i, run in enumerate(_runs(job)) if needle in run]
    assert hits, f"no step runs {needle!r}"
    return hits[0]


def _suite_step(name: str) -> int:
    needle = "unittest discover" if name == "crypto-floor" else "-m pytest"
    return _index(_jobs()[name], needle)


@pytest.mark.parametrize("name", ["test", "coverage"])
def test_xdist_is_installed_at_an_exact_version(name):
    installs = " ".join(r for r in _runs(_jobs()[name]) if "pip install" in r)
    assert re.search(r"(?<![\w-])pytest-xdist==\d+\.\d+\.\d+(?![\w.])", installs), installs


def test_the_coverage_job_pins_pytest_cov():
    installs = " ".join(r for r in _runs(_jobs()["coverage"]) if "pip install" in r)
    assert re.search(r"(?<![\w-])pytest-cov==\d+\.\d+\.\d+(?![\w.])", installs), installs


@pytest.mark.parametrize("name", ["test", "coverage"])
def test_the_suite_runs_on_every_worker_the_runner_has(name):
    run = _runs(_jobs()[name])[_suite_step(name)]
    assert "--numprocesses=auto" in run and "--dist=worksteal" in run, run


def test_coverage_is_combined_across_workers_and_the_floor_stays():
    run = _runs(_jobs()["coverage"])[_suite_step("coverage")]
    assert "--cov=src/proofbundle" in run, run
    report = [r for r in _runs(_jobs()["coverage"]) if "coverage report" in r]
    assert report and "--fail-under=83" in report[0], report


@pytest.mark.parametrize("name", SUITE_JOBS)
def test_every_suite_job_requires_and_pins_the_rust_verifier(name):
    env = _jobs()[name].get("env") or {}
    assert str(env.get("PROOFBUNDLE_REQUIRE_PB_VERIFY_RS")) == "1", env
    assert env.get("PROOFBUNDLE_PB_VERIFY_RS") == PINNED, env


@pytest.mark.parametrize("name", SUITE_JOBS)
def test_every_suite_job_builds_the_binary_before_the_suite(name):
    job = _jobs()[name]
    assert _index(job, BUILD) < _suite_step(name)


@pytest.mark.parametrize("needle", ["python scripts/test_manifest_gate.py",
                                    "python scripts/type_confusion_gate.py --strict"])
def test_the_matrix_keeps_its_guards_after_the_suite(needle):
    job = _jobs()["test"]
    assert _index(job, needle) > _suite_step("test")


def test_the_hermetic_cleanroom_runs_the_shipped_suite_unchanged_and_requires_no_rust():
    """The sdist carries no Rust sources, so the cleanroom must not require the binary."""
    job = _jobs("published-artifact-gate.yml")["hermetic-cleanroom"]
    runs = "\n".join(_runs(job))
    assert "/tmp/clean/bin/python -m pytest tests/ -q -p no:cacheprovider" in runs
    assert "PROOFBUNDLE_REQUIRE_PB_VERIFY_RS" not in yaml.safe_dump(job)
