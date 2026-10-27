"""Behavioural contracts for the workflow build-path rules; no builds are run."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import shutil

import pytest

yaml = pytest.importorskip("yaml")


@pytest.fixture
def rules(tmp_path, monkeypatch):
    repo = Path(__file__).resolve().parents[1]
    path = repo / "tests/test_every_build_path_pins_its_backend.py"
    spec = importlib.util.spec_from_file_location("_build_path_rules_contract", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    workflows = tmp_path / "workflows"
    workflows.mkdir()
    for source in (repo / ".github/workflows").iterdir():
        if source.suffix in {".yml", ".yaml"}:
            shutil.copy2(source, workflows / source.name)
    monkeypatch.setattr(module, "ABLAEUFE", workflows)
    return module


def put_job(rules, command, *, pin=True, depth=0, level="step", suffix="yml"):
    step = {"name": "contract candidate", "run": command}
    job = {
        "runs-on": "ubuntu-latest",
        "steps": [
            {"uses": "actions/checkout@contract-fixture", "with": {"fetch-depth": depth}},
            step,
        ],
    }
    document = {"jobs": {"contract_candidate": job}}
    if pin:
        {"workflow": document, "job": job, "step": step}[level]["env"] = {
            "PIP_CONSTRAINT": rules.PIN_ENV,
        }
    path = rules.ABLAEUFE / ("contract-extra." + suffix)
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    return path, document


@pytest.mark.parametrize("python", ["python", "python3"])
def test_direct_sdist_needs_pin_and_full_history(rules, python):
    command = f"{python} -m build --sdist"
    pin_rule = rules.test_every_step_that_installs_the_frontend_or_builds_reads_the_pins
    history_rule = rules.test_every_job_that_builds_takes_the_epoch_from_the_full_history
    put_job(rules, command)
    pin_rule()
    history_rule()
    put_job(rules, command, pin=False)
    with pytest.raises(AssertionError):
        pin_rule()
    put_job(rules, command, depth=1)
    with pytest.raises(AssertionError):
        history_rule()


@pytest.mark.parametrize("requirement", ["build", '"build[uv]"'])
def test_frontend_install_with_extras_needs_pin(rules, requirement):
    rule = rules.test_every_step_that_installs_the_frontend_or_builds_reads_the_pins
    command = f"pip install {requirement}"
    put_job(rules, command)
    rule()
    put_job(rules, command, pin=False)
    with pytest.raises(AssertionError):
        rule()


@pytest.mark.parametrize("command", ["uv build", "pipx run build"])
def test_unmeasured_build_frontends_are_rejected_even_with_pip_constraint(rules, command):
    rule = rules.test_every_step_that_installs_the_frontend_or_builds_reads_the_pins
    put_job(rules, "python scripts/build_reproducible.py --check")
    rule()
    put_job(rules, command)
    with pytest.raises(AssertionError):
        rule()


@pytest.mark.parametrize("level", ["step", "job", "workflow"])
def test_effective_pin_inherits_and_step_override_wins(rules, level):
    rule = rules.test_every_step_that_installs_the_frontend_or_builds_reads_the_pins
    path, document = put_job(
        rules, "python scripts/build_reproducible.py --check", level=level,
    )
    rule()
    document["jobs"]["contract_candidate"]["steps"][1]["env"] = {
        "PIP_CONSTRAINT": "wrong.txt",
    }
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    with pytest.raises(AssertionError):
        rule()


@pytest.mark.parametrize("suffix", ["yml", "yaml"])
def test_both_workflow_suffixes_enforce_pins_and_history(rules, suffix):
    pin_rule = rules.test_every_step_that_installs_the_frontend_or_builds_reads_the_pins
    history_rule = rules.test_every_job_that_builds_takes_the_epoch_from_the_full_history
    command = "python scripts/build_reproducible.py --check"
    put_job(rules, command, suffix=suffix)
    pin_rule()
    history_rule()
    put_job(rules, command, pin=False, suffix=suffix)
    with pytest.raises(AssertionError):
        pin_rule()
    put_job(rules, command, depth=1, suffix=suffix)
    with pytest.raises(AssertionError):
        history_rule()
