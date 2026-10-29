"""The cbor2 pin of the scitt extra has a measured run of exactly that version.

WHERE THIS COMES FROM. pyproject.toml pins the `scitt` extra to the measured cbor2 version and says "A bump needs
the same measurement again". On 2026-10-28 an automated bump from 6.1.4 to 6.1.5 (pull request 431) passed every
check without that measurement, because the rule was only a comment. tools/scitt_ccf_external/reader_crosscheck.py
records one run per cbor2 version in reader_crosscheck.json, so the rule can be held against the file.

THE PROPERTY:
* cbor2 is required only by the `scitt` and `dev` extras, and both pin it exactly to the same version; a cbor2
  requirement in `project.dependencies`, in another extra, in a `dependency-groups` table or in
  `build-system.requires` is named;
* reader_crosscheck.json carries the run `cbor2-<that version>`, made with that cbor2;
* the run names the bytes it read under `inputs`, and they are the files fetch_external.py pins, by size and sha256;
* in that run the strict options were used and the data-hash recomputed from cbor2's values equals the receipt's on
  every real statement the run measured, and there are four of them, as in the run of 6.1.4.

The pyproject is read as TOML, not searched as text (tests/conftest.py, `_projektname`, says why).

SECOND READING (2026-10-29, counter-reading of e6087bb4): the first version looked only at
`project.optional-dependencies`, so an unmeasured cbor2 in `project.dependencies` passed, and the run did not name
its inputs, so "made on the files fetch_external.py verified" was a sentence and not a property of the record.
"""
from __future__ import annotations

import importlib.util
import json
import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools" / "scitt_ccf_external"
RECORD = TOOLS / "reader_crosscheck.json"
STRICT = ["allow_duplicate_keys", "allow_indefinite"]
STATEMENTS = 4
#: the extras that carry the measured pin
EXTRAS = ["dev", "scitt"]
#: the files a run reads, as reader_crosscheck.py names them
INPUTS = ["cbor-header.cose", "mst-test-scitt-keys.cbor", "nested-sign1.cose", "transparent-statement.cose",
          "uvm_0.2.10.cose"]


def _toml():
    try:
        import tomllib  # noqa: PLC0415
    except ModuleNotFoundError:            # Python 3.10; pytest itself depends on tomli there
        import tomli as tomllib  # noqa: PLC0415
    return tomllib


def _names_cbor2(requirement: str) -> bool:
    """Whether a requirement string names the distribution cbor2, by its normalised name (PEP 503)."""
    m = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)", requirement)
    return bool(m) and re.sub(r"[-_.]+", "-", m.group(1)).lower() == "cbor2"


def _pins(pyproject_text: str) -> dict:
    """The cbor2 requirements of every requirement list pyproject.toml can carry, as written.

    An extra is keyed by its name; any other list by where it stands."""
    doc = _toml().loads(pyproject_text)
    project = doc.get("project") or {}
    lists = {"project.dependencies": project.get("dependencies") or []}
    lists.update(project.get("optional-dependencies") or {})
    lists.update({f"dependency-groups.{name}": [r for r in reqs if isinstance(r, str)]
                  for name, reqs in (doc.get("dependency-groups") or {}).items()})
    lists["build-system.requires"] = (doc.get("build-system") or {}).get("requires") or []
    return {name: [r for r in reqs if _names_cbor2(r)] for name, reqs in lists.items()
            if any(_names_cbor2(r) for r in reqs)}


def _fetch_pins() -> dict:
    spec = importlib.util.spec_from_file_location("_fetch_external_pins_test", TOOLS / "fetch_external.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return {name: {"size": size, "sha256": digest} for name, (_s, _p, size, digest) in module.EXPECTED.items()}


def _unmeasured(pyproject_text: str, record: dict) -> list:
    """Why the pin is not covered by a measured run; empty when it is."""
    pins = _pins(pyproject_text)
    why = []
    if sorted(pins) != EXTRAS:
        why.append(f"cbor2 is required by {sorted(pins)}, expected only the extras dev and scitt")
    exact = {r.replace(" ", "") for reqs in pins.values() for r in reqs}
    if len(exact) != 1 or not next(iter(exact)).startswith("cbor2=="):
        return why + [f"the cbor2 requirements {sorted(exact)} are not one exact pin"]
    version = next(iter(exact)).split("==", 1)[1]
    run = (record.get("runs") or {}).get(f"cbor2-{version}")
    if run is None:
        return why + [f"reader_crosscheck.json has no run cbor2-{version}"]
    if (run.get("environment") or {}).get("cbor2") != version:
        why.append(f"the run cbor2-{version} was made with cbor2 {(run.get('environment') or {}).get('cbor2')}")
    inputs = run.get("inputs")
    if not isinstance(inputs, dict) or sorted(inputs) != INPUTS:
        why.append(f"the run cbor2-{version} does not name the files it read")
    else:
        pinned = _fetch_pins()
        why += [f"{name}: the run read {inputs[name]}, fetch_external.py pins {pinned.get(name)}"
                for name in INPUTS if inputs[name] != pinned.get(name)]
    hashes = run.get("datahash_via_cbor2") or {}
    if len(hashes) != STATEMENTS:
        why.append(f"the run measured {len(hashes)} statements, expected {STATEMENTS}")
    for name, row in sorted(hashes.items()):
        if row.get("equal") is not True:
            why.append(f"{name}: the recomputed data-hash does not equal the receipt's")
        if row.get("strict_options_used") != STRICT:
            why.append(f"{name}: strict options {row.get('strict_options_used')}")
    return why


def _record() -> dict:
    return json.loads(RECORD.read_text(encoding="utf-8"))


def _pyproject(scitt: str, dev: str, extra: str = "", project: str = "") -> str:
    """`project` goes into [project] itself, `extra` after the two extras (another extra, or a later table)."""
    return (f'[project]\nname = "x"\n{project}[project.optional-dependencies]\n'
            f'scitt = ["{scitt}"]\ndev = ["pytest>=7", "{dev}"]\n{extra}')


def _pinned_version() -> str:
    return _pins((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["scitt"][0].replace(" ", "").split("==", 1)[1]


def test_the_scitt_pin_has_a_measured_run():
    assert _unmeasured((ROOT / "pyproject.toml").read_text(encoding="utf-8"), _record()) == []


def test_the_reader_reads_what_this_test_holds_against_the_pins():
    """INPUTS here is the list reader_crosscheck.py reads, so a new input there is not left unchecked here."""
    spec = importlib.util.spec_from_file_location("_reader_crosscheck_test", TOOLS / "reader_crosscheck.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert sorted(module.INPUTS) == INPUTS


@pytest.mark.parametrize("scitt, dev, expected", [
    ("cbor2==9.9.9", "cbor2==9.9.9", "no run cbor2-9.9.9"),
    ("cbor2>=6.1", "cbor2>=6.1", "not one exact pin"),
    ("cbor2==6.1.5", "cbor2==6.1.4", "not one exact pin"),
])
def test_ANTI_a_pin_without_its_run_is_named(scitt, dev, expected):
    why = _unmeasured(_pyproject(scitt, dev), _record())
    assert any(expected in w for w in why), why


@pytest.mark.parametrize("project, extra, where", [
    ('dependencies = ["cbor2==9.9.9"]\n', "", "project.dependencies"),
    ("", 'tooling = ["CBOR2 == 9.9.9"]\n', "tooling"),
    ("", '[dependency-groups]\ntooling = ["cbor2==9.9.9", {include-group = "x"}]\n', "dependency-groups.tooling"),
    ("", '[build-system]\nrequires = ["cbor2>=5"]\n', "build-system.requires"),
])
def test_ANTI_cbor2_outside_the_two_extras_is_named(project, extra, where):
    """Counter-reading of e6087bb4, finding 2: these passed while only the extras were read."""
    version = _pinned_version()
    why = _unmeasured(_pyproject(f"cbor2=={version}", f"cbor2=={version}", extra, project), _record())
    assert any(where in w for w in why), why


def test_ANTI_a_run_with_a_failed_data_hash_is_named():
    record = _record()
    version = _pinned_version()
    run = record["runs"][f"cbor2-{version}"]
    first = sorted(run["datahash_via_cbor2"])[0]
    run["datahash_via_cbor2"][first]["equal"] = False
    why = _unmeasured(_pyproject(f"cbor2=={version}", f"cbor2=={version}"), record)
    assert why == [f"{first}: the recomputed data-hash does not equal the receipt's"], why


def test_ANTI_a_run_that_does_not_name_its_inputs_is_named():
    """Counter-reading of e6087bb4, finding 1: the run of 6.1.5 as committed there carried no inputs."""
    record = _record()
    version = _pinned_version()
    del record["runs"][f"cbor2-{version}"]["inputs"]
    why = _unmeasured(_pyproject(f"cbor2=={version}", f"cbor2=={version}"), record)
    assert why == [f"the run cbor2-{version} does not name the files it read"], why


def test_ANTI_a_run_made_from_other_bytes_is_named():
    record = _record()
    version = _pinned_version()
    record["runs"][f"cbor2-{version}"]["inputs"]["uvm_0.2.10.cose"]["sha256"] = "0" * 64
    why = _unmeasured(_pyproject(f"cbor2=={version}", f"cbor2=={version}"), record)
    assert len(why) == 1 and why[0].startswith("uvm_0.2.10.cose: the run read"), why
