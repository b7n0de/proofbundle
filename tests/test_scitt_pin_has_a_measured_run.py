"""The cbor2 pin of the scitt extra has a measured run of exactly that version.

WHERE THIS COMES FROM. pyproject.toml pins the `scitt` extra to the measured cbor2 version and says "A bump needs
the same measurement again". On 2026-10-28 an automated bump from 6.1.4 to 6.1.5 (pull request 431) passed every
check without that measurement, because the rule was only a comment. tools/scitt_ccf_external/reader_crosscheck.py
records one run per cbor2 version in reader_crosscheck.json, so the rule can be held against the file.

THE PROPERTY:
* `scitt` and `dev` pin cbor2 exactly, both to the same version;
* reader_crosscheck.json carries the run `cbor2-<that version>`, made with that cbor2;
* in that run the strict options were used and the data-hash recomputed from cbor2's values equals the receipt's on
  every real statement the run measured, and there are four of them, as in the run of 6.1.4.

The pyproject is read as TOML, not searched as text (tests/conftest.py, `_projektname`, says why).
"""
from __future__ import annotations

import json
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
RECORD = ROOT / "tools" / "scitt_ccf_external" / "reader_crosscheck.json"
STRICT = ["allow_duplicate_keys", "allow_indefinite"]
STATEMENTS = 4


def _toml():
    try:
        import tomllib  # noqa: PLC0415
    except ModuleNotFoundError:            # Python 3.10; pytest itself depends on tomli there
        import tomli as tomllib  # noqa: PLC0415
    return tomllib


def _pins(pyproject_text: str) -> dict:
    """The cbor2 requirement of each extra that names cbor2, as written."""
    extras = _toml().loads(pyproject_text)["project"]["optional-dependencies"]
    return {name: [r for r in reqs if r.replace(" ", "").lower().startswith("cbor2")]
            for name, reqs in extras.items() if any(r.replace(" ", "").lower().startswith("cbor2") for r in reqs)}


def _unmeasured(pyproject_text: str, record: dict) -> list:
    """Why the pin is not covered by a measured run; empty when it is."""
    pins = _pins(pyproject_text)
    why = []
    if sorted(pins) != ["dev", "scitt"]:
        why.append(f"cbor2 is named by the extras {sorted(pins)}, expected dev and scitt")
    exact = {r.replace(" ", "") for reqs in pins.values() for r in reqs}
    if len(exact) != 1 or not next(iter(exact)).startswith("cbor2=="):
        return why + [f"the cbor2 requirements {sorted(exact)} are not one exact pin"]
    version = next(iter(exact)).split("==", 1)[1]
    run = (record.get("runs") or {}).get(f"cbor2-{version}")
    if run is None:
        return why + [f"reader_crosscheck.json has no run cbor2-{version}"]
    if (run.get("environment") or {}).get("cbor2") != version:
        why.append(f"the run cbor2-{version} was made with cbor2 {(run.get('environment') or {}).get('cbor2')}")
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


def _pyproject(scitt: str, dev: str) -> str:
    return ('[project]\nname = "x"\n[project.optional-dependencies]\n'
            f'scitt = ["{scitt}"]\ndev = ["pytest>=7", "{dev}"]\n')


def test_the_scitt_pin_has_a_measured_run():
    assert _unmeasured((ROOT / "pyproject.toml").read_text(encoding="utf-8"), _record()) == []


@pytest.mark.parametrize("scitt, dev, expected", [
    ("cbor2==9.9.9", "cbor2==9.9.9", "no run cbor2-9.9.9"),
    ("cbor2>=6.1", "cbor2>=6.1", "not one exact pin"),
    ("cbor2==6.1.5", "cbor2==6.1.4", "not one exact pin"),
])
def test_ANTI_a_pin_without_its_run_is_named(scitt, dev, expected):
    why = _unmeasured(_pyproject(scitt, dev), _record())
    assert any(expected in w for w in why), why


def test_ANTI_a_run_with_a_failed_data_hash_is_named():
    record = _record()
    pins = _pins((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    version = pins["scitt"][0].replace(" ", "").split("==", 1)[1]
    run = record["runs"][f"cbor2-{version}"]
    first = sorted(run["datahash_via_cbor2"])[0]
    run["datahash_via_cbor2"][first]["equal"] = False
    why = _unmeasured(_pyproject(f"cbor2=={version}", f"cbor2=={version}"), record)
    assert why == [f"{first}: the recomputed data-hash does not equal the receipt's"], why
