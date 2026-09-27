"""The integration docs name only defaults the code has.

INTEGRATIONS.md said `PROOFBUNDLE_THRESHOLD` defaults to `>= 0`. 5.0.0 made the threshold required
(CHANGELOG 5.0.0, BREAKING): the Inspect lifecycle hook and the pytest plugin skip the receipt when it
is unset (tests/test_pytest_plugin.py, TestThresholdRequired). A reader who followed the text got no
receipt and a message they had no reason to expect. docs/INSPECT_HAPPY_PATH.md listed the threshold
among the optional settings, the same contradiction in the walkthrough.

The defaults the code has are measured here, by calling `emit_config` with no PROOFBUNDLE_* variable
set, not copied from a docstring. Every default a doc states for a PROOFBUNDLE_* variable must be one
of them; a variable the table does not know fails the test until its default is measured and added.
"""
from __future__ import annotations

import os
import re
import unittest
from pathlib import Path
from unittest import mock

from proofbundle._integration import emit_config

REPO = Path(__file__).resolve().parents[1]
_VARIABLE = re.compile(r"PROOFBUNDLE_[A-Z][A-Z_]*")
#: A stated default: the word, optionally "to", "is" or a colon, then a value in backticks, in double
#: quotes, or a bare number.
_DEFAULT = re.compile(r"\bdefaults?(?:\s+to|\s+is|:)?\s*(?:`([^`]*)`|\"([^\"]*)\"|([0-9][0-9.]*))", re.IGNORECASE)


def _measured_defaults() -> dict:
    """What the emission config is when the user sets nothing: None means the code has no default."""
    ohne = {k: v for k, v in os.environ.items() if not k.startswith("PROOFBUNDLE_")}
    with mock.patch.dict(os.environ, ohne, clear=True):
        cfg = emit_config()
    return {"PROOFBUNDLE_METRIC": cfg["metric"], "PROOFBUNDLE_COMPARATOR": cfg["comparator"],
            "PROOFBUNDLE_THRESHOLD": cfg["threshold"]}


def _stated_defaults(text: str) -> list:
    """(variable, stated value) for every stated default in `text`, each attributed to the nearest
    PROOFBUNDLE_* variable named before it in the same paragraph; a default with none before it is not
    about a variable and is left out."""
    gefunden = []
    for absatz in re.split(r"\n\s*\n", text):
        for treffer in _DEFAULT.finditer(absatz):
            davor = _VARIABLE.findall(absatz[:treffer.start()])
            if davor:
                wert = next(g for g in treffer.groups() if g is not None)
                gefunden.append((davor[-1], wert.strip()))
    return gefunden


class TheReaderOfStatedDefaults(unittest.TestCase):
    """Controls: without them the contract below could pass by finding nothing."""

    def test_it_reads_the_sentence_as_it_stood_at_0ace3039(self) -> None:
        alt = ("Config via env: `PROOFBUNDLE_KEY` (a 32-byte Ed25519\nseed; else an ephemeral key, with a warning), "
               "`PROOFBUNDLE_OUT` (file or directory), `PROOFBUNDLE_METRIC` /\n`PROOFBUNDLE_COMPARATOR` / "
               "`PROOFBUNDLE_THRESHOLD` (the pass/fail assertion; default `>= 0`). The model and")
        self.assertEqual(_stated_defaults(alt), [("PROOFBUNDLE_THRESHOLD", ">= 0")])

    def test_it_reads_the_other_spellings(self) -> None:
        self.assertEqual(_stated_defaults('`PROOFBUNDLE_COMPARATOR` defaults to ">="'),
                         [("PROOFBUNDLE_COMPARATOR", ">=")])
        self.assertEqual(_stated_defaults("PROOFBUNDLE_THRESHOLD, default 0.5"), [("PROOFBUNDLE_THRESHOLD", "0.5")])
        self.assertEqual(_stated_defaults("a default `x` before any variable"), [])

    def test_the_measured_defaults(self) -> None:
        self.assertEqual(_measured_defaults(), {"PROOFBUNDLE_METRIC": None, "PROOFBUNDLE_COMPARATOR": ">=",
                                                "PROOFBUNDLE_THRESHOLD": None})


class IntegrationsMdNamesOnlyDefaultsTheCodeHas(unittest.TestCase):
    """PROPERTY: every default INTEGRATIONS.md states for a PROOFBUNDLE_* variable is the default the code
    has; a variable without one (the threshold) is stated as required, never given a value."""

    def test_every_stated_default_is_the_codes(self) -> None:
        gemessen = _measured_defaults()
        text = (REPO / "INTEGRATIONS.md").read_text(encoding="utf-8")
        for variable, wert in _stated_defaults(text):
            with self.subTest(variable=variable, stated=wert):
                self.assertIn(variable, gemessen, f"INTEGRATIONS.md states a default for {variable}; measure the "
                                                  "code's default and add it to _measured_defaults")
                self.assertIsNotNone(gemessen[variable], f"INTEGRATIONS.md states the default {wert!r} for "
                                                         f"{variable}, and the code has none")
                self.assertEqual(wert, gemessen[variable])

    def test_the_threshold_is_stated_as_required(self) -> None:
        text = (REPO / "INTEGRATIONS.md").read_text(encoding="utf-8")
        absaetze = [a for a in re.split(r"\n\s*\n", text) if "PROOFBUNDLE_THRESHOLD" in a]
        self.assertTrue(absaetze)
        self.assertTrue(any(re.search(r"\brequired\b", a) for a in absaetze), absaetze)

    def test_every_command_that_turns_emission_on_sets_the_threshold(self) -> None:
        # A block that turns emission on and sets no threshold emits nothing, as written.
        text = (REPO / "INTEGRATIONS.md").read_text(encoding="utf-8")
        bloecke = [b for b in re.findall(r"```[a-z]*\n(.*?)```", text, re.DOTALL) if "PROOFBUNDLE_EMIT=1" in b]
        self.assertTrue(bloecke)
        for block in bloecke:
            with self.subTest(block=block.strip()[:60]):
                self.assertIn("PROOFBUNDLE_THRESHOLD=", block)


class TheInspectHappyPathSetsTheThreshold(unittest.TestCase):
    """The same contradiction in the walkthrough: it listed the threshold as optional, and following it
    as written emits no receipt."""

    def test_the_threshold_is_not_listed_as_optional(self) -> None:
        text = (REPO / "docs" / "INSPECT_HAPPY_PATH.md").read_text(encoding="utf-8")
        optional = [z for z in text.splitlines() if re.search(r"\boptional\b", z, re.IGNORECASE)]
        self.assertFalse([z for z in optional if "PROOFBUNDLE_THRESHOLD" in z], optional)

    def test_the_walkthrough_sets_the_threshold(self) -> None:
        text = (REPO / "docs" / "INSPECT_HAPPY_PATH.md").read_text(encoding="utf-8")
        self.assertRegex(text, r"export PROOFBUNDLE_THRESHOLD=")

    def test_no_stated_default_contradicts_the_code(self) -> None:
        gemessen = _measured_defaults()
        text = (REPO / "docs" / "INSPECT_HAPPY_PATH.md").read_text(encoding="utf-8")
        for variable, wert in _stated_defaults(text):
            with self.subTest(variable=variable, stated=wert):
                self.assertIn(variable, gemessen)
                self.assertEqual(wert, gemessen[variable])


if __name__ == "__main__":
    unittest.main()
