"""Follow-up note 51, point 2: the test gap C9 that the review session's mutants of PLUGIN_N46 found.

pin-state.json is read as strict JSON (strict_json), so a key given twice makes the whole file pin nothing. The case of
PLUGIN_N46 gave `klone` twice with two empty lists, which pins nothing under json.loads as well, so the mutant that
reads the file with json.loads lived. Here the last of the repeated values is a valid pin: json.loads keeps it and
frees the call, strict_json refuses the file.

The gate does not change in this point. RED against the mutant `json.loads` in _pin_state_entries (measured,
mutants_n51.py); green at d3ce27a2 and at the head. The control shows that the same pin without the repeated key is
free.
"""
from __future__ import annotations

import json

import pytest

import test_plugin_n29_work_profile_d71 as d71
import test_plugin_n46_pinned_state_d114_d115 as d114

gate = d71.gate
pytestmark = d71.pytestmark
_clean = d71._clean

SCHEMA = "proofbundle-plugin/pin-state/v0.1"


def _entry_text(entry: dict) -> str:
    return json.dumps(entry)


def _repeated(entry: dict, where: str) -> str:
    """The text of pin-state.json with one key given twice, the valid value last."""
    valid = _entry_text(entry)
    if where == "klone":
        return '{"schema": "%s", "klone": [], "klone": [%s]}' % (SCHEMA, valid)
    if where == "schema":
        return '{"schema": "proofbundle-plugin/pin-state/v0.2", "schema": "%s", "klone": [%s]}' % (SCHEMA, valid)
    if where == "pfad":
        return '{"schema": "%s", "klone": [{"pfad": "/elsewhere", %s]}' % (SCHEMA, valid[1:])
    if where == "konfig":
        return '{"schema": "%s", "klone": [{"konfig": "%s", %s]}' % (SCHEMA, "0" * 64, valid[1:])
    raise ValueError(where)


@pytest.mark.parametrize("where", ["klone", "schema", "pfad", "konfig"])
def test_C9_a_key_given_twice_in_the_pin_pins_nothing_even_where_the_last_value_is_valid(tmp_path, where):
    repo = d114._repo(tmp_path)
    text = _repeated(d114._entry(repo), where)
    assert json.loads(text)["schema"] == SCHEMA   # what a reader that keeps the last value would see
    d114._pin([], text=text)
    answer = d114.answered(repo, "git commit -m work")
    assert not d114._free(answer), (where, answer)


def test_C9_control_the_same_pin_without_the_repeated_key_is_free(tmp_path):
    repo = d114._repo(tmp_path)
    d114._pin([], text='{"schema": "%s", "klone": [%s]}' % (SCHEMA, _entry_text(d114._entry(repo))))
    assert d114._free(d114.answered(repo, "git commit -m work"))
