"""The example under examples/otel_scitt_agent_record/: OpenTelemetry spans to a signed record anchored in SCITT.

The tests run the example's own scripts as the README names them, each in a subprocess with this tree's src/ first
on PYTHONPATH, so another example's modules of the same name and an installed proofbundle cannot stand in. They
hold that out/ is what make_example.py writes, that SHA256SUMS names every file, that the check ends in OPEN
without the disclosure and in PASSED with it, and that every case of cases.md ends in its expected state at its
expected check when measure_cases.py builds it again, with the table byte for byte the committed one.
"""
from __future__ import annotations

import hashlib
import importlib.util
import os
import pathlib
import subprocess
import sys

import pytest

# The anchoring is checked with the scitt-ccf reader, which refuses every input without the [scitt] extra.
pytestmark = pytest.mark.skipif(importlib.util.find_spec("cbor2") is None,
                                reason="the example's anchoring check needs the [scitt] extra")

REPO = pathlib.Path(__file__).resolve().parents[1]
FOLDER = REPO / "examples" / "otel_scitt_agent_record"


def _env() -> dict:
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(p for p in (str(REPO / "src"), os.environ.get("PYTHONPATH", "")) if p)
    return env


def _run(*args) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, *map(str, args)], capture_output=True, text=True, env=_env(),
                          cwd=str(FOLDER) if FOLDER.is_dir() else str(REPO))


def _tree(root: pathlib.Path) -> dict:
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file()}


def test_out_is_what_the_producer_writes(tmp_path):
    r = _run(FOLDER / "make_example.py", "--out", tmp_path / "out")
    assert r.returncode == 0, r.stderr
    assert _tree(tmp_path / "out") == _tree(FOLDER / "out")


def test_sha256sums_names_every_file_of_the_example():
    listed = {}
    for line in (FOLDER / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
        digest, name = line.split("  ", 1)
        listed[name] = digest
    files = {k: v for k, v in _tree(FOLDER).items() if not k.startswith("cases/") and k != "SHA256SUMS"
             and "__pycache__" not in k}
    assert set(listed) == set(files)
    for name, data in files.items():
        assert hashlib.sha256(data).hexdigest() == listed[name], name


def test_the_check_is_open_without_the_disclosure_and_passed_with_it():
    r = _run(FOLDER / "check_example.py", FOLDER / "out")
    assert (r.returncode, r.stdout.split()[0]) == (3, "OPEN"), r.stdout + r.stderr
    r = _run(FOLDER / "check_example.py", FOLDER / "out", "--disclosure", FOLDER / "out" / "disclosure")
    assert (r.returncode, r.stdout.split()[0]) == (0, "PASSED"), r.stdout + r.stderr


def _rows(text: str) -> dict:
    rows = {}
    for line in text.splitlines():
        if line.startswith("| ") and not line.startswith("| Case "):
            cells = [c.strip() for c in line.strip("|").split(" | ")]
            rows[cells[0]] = {"expected": cells[3], "result": cells[4], "exit": cells[5], "same": cells[6],
                              "as_expected": cells[7]}
    return rows


def test_every_case_of_cases_md_meets_its_expectation(tmp_path):
    committed = (FOLDER / "cases.md").read_text(encoding="utf-8")
    r = _run(FOLDER / "measure_cases.py", "--cases", tmp_path / "cases", "--out", tmp_path / "cases.md")
    assert r.returncode == 0, r.stdout + r.stderr
    measured = (tmp_path / "cases.md").read_text(encoding="utf-8")
    want, got = _rows(committed), _rows(measured)
    assert want and set(want) == set(got)
    states = {"OPEN": "3", "PASSED": "0", "FAILED": "1"}
    for cid, row in got.items():
        assert row["result"] == want[cid]["expected"] == row["expected"], cid
        assert (row["same"], row["as_expected"]) == ("yes", "yes"), cid
        assert row["exit"] == states[row["result"].split()[0]], cid
    assert {"P0", "P1"} <= set(got) and got["P0"]["result"] == "OPEN" and got["P1"]["result"] == "PASSED"
    assert measured == committed


def test_no_private_key_in_the_example():
    files = _tree(FOLDER)
    assert "out/test-keys.json" in files            # the example is there, so the search below is not empty
    for name, data in files.items():
        assert b"PRIVATE " + b"KEY" not in data, name
