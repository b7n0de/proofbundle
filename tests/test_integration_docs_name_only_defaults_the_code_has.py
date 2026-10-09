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


#: The three variables whose defaults `_measured_defaults` knows. A word boundary on both sides, so the
#: SVR property string `PROOFBUNDLE_THRESHOLD_MET`, which a plain grep also finds, is not the variable.
_THE_VARIABLES = re.compile(r"\bPROOFBUNDLE_(?:THRESHOLD|COMPARATOR|METRIC)\b")

#: Documents that describe how the code behaves now: the contract applies to them.
CURRENT = {
    "INTEGRATIONS.md": "the integration guide; tells a user how to configure emission",
    "docs/INSPECT_HAPPY_PATH.md": "the walkthrough; a reader follows it command by command",
    "COMPATIBILITY.md": "the compatibility policy; its worked example names the 5.0.0 threshold change",
}
#: Documents that record a past state and are not rewritten when the code moves on. Each names why.
HISTORIC = {
    "CHANGELOG.md": "release history; the 5.0.0 entry quotes the removed default \"0\" as the old behaviour",
    "docs/release_scope/5.0.0.md": "the scope record of the 5.0.0 release; names the old default it removed",
    "audit_artifacts/500/PRE_REGISTRATION_DEEP_500_ITER6.md": "a frozen pre-registration of a past audit run",
    "audit_artifacts/500/PRE_REGISTRATION_DEEP_500_ITER7.md": "a frozen pre-registration of a past audit run",
    "audit_artifacts/500/PRE_REGISTRATION_DEEP_500_ITER8.md": "a frozen pre-registration of a past audit run",
}
_SKIP_PARTS = {".git", "node_modules", "target", ".venv", "venv", "__pycache__", ".tox", "build", "dist"}


def _documents_naming_the_variables() -> dict:
    """{relative posix path: text} for every Markdown file under the repository that names one of them."""
    gefunden = {}
    for pfad in sorted(REPO.rglob("*.md")):
        rel = pfad.relative_to(REPO)
        if any(teil in _SKIP_PARTS for teil in rel.parts):
            continue
        try:
            text = pfad.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if _THE_VARIABLES.search(text):
            gefunden[rel.as_posix()] = text
    return gefunden


def _lists_the_threshold_as_optional(zeile: str) -> bool:
    """A line that names the threshold and calls it optional, without saying it is required."""
    return bool(re.search(r"\bPROOFBUNDLE_THRESHOLD\b", zeile) and re.search(r"\boptional\b", zeile, re.I)
                and not re.search(r"\brequire", zeile, re.I))


class EveryDocumentThatNamesTheVariables(unittest.TestCase):
    """Owner addendum of 2026-09-28: the contract covers every document that names the variables, not
    only INTEGRATIONS.md. A document is either current, and then states only the code's defaults and
    never lists the threshold as optional, or historic, with the reason it is not rewritten. A new
    document that is neither fails here until it is classified."""

    def test_the_reader_tells_the_variable_from_the_svr_property(self) -> None:
        self.assertTrue(_THE_VARIABLES.search("export PROOFBUNDLE_THRESHOLD=0.8"))
        self.assertFalse(_THE_VARIABLES.search("sets `PROOFBUNDLE_THRESHOLD_MET` in the SVR"))

    def test_every_document_that_names_them_is_classified(self) -> None:
        gefunden = set(_documents_naming_the_variables())
        self.assertTrue(gefunden)
        offen = sorted(gefunden - set(CURRENT) - set(HISTORIC))
        self.assertEqual(offen, [], "a document names PROOFBUNDLE_THRESHOLD/COMPARATOR/METRIC and is neither "
                                    "current nor historic; classify it with a reason")
        self.assertFalse(set(CURRENT) & set(HISTORIC))

    def test_no_classified_document_has_stopped_naming_them(self) -> None:
        gefunden = _documents_naming_the_variables()
        for rel in sorted(set(CURRENT) | set(HISTORIC)):
            if not (REPO / rel).exists():
                continue          # a distribution without the repository's docs
            with self.subTest(document=rel):
                self.assertIn(rel, gefunden, "classified but no longer names the variables; drop the entry")

    def test_every_current_document_states_only_the_codes_defaults(self) -> None:
        gemessen = _measured_defaults()
        gefunden = _documents_naming_the_variables()
        for rel in sorted(CURRENT):
            if rel not in gefunden:
                continue
            for variable, wert in _stated_defaults(gefunden[rel]):
                with self.subTest(document=rel, variable=variable, stated=wert):
                    self.assertIn(variable, gemessen)
                    self.assertIsNotNone(gemessen[variable], f"{rel} states the default {wert!r} for {variable}, "
                                                             "and the code has none")
                    self.assertEqual(wert, gemessen[variable])

    def test_the_optional_reader_tells_a_listing_from_the_requirement(self) -> None:
        # Controls for the rule below: the walkthrough's line at 0ace3039 listed the threshold as
        # optional; COMPATIBILITY.md's worked example says it was optional and is now required.
        alt = "    # optional: PROOFBUNDLE_OUT=<file-or-dir>, PROOFBUNDLE_METRIC, PROOFBUNDLE_THRESHOLD"
        richtig = ("now **require** `PROOFBUNDLE_THRESHOLD` instead of silently defaulting it to `0` - an "
                   "optional obligation made required.")
        self.assertTrue(_lists_the_threshold_as_optional(alt))
        self.assertFalse(_lists_the_threshold_as_optional(richtig))

    def test_no_current_document_lists_the_threshold_as_optional(self) -> None:
        gefunden = _documents_naming_the_variables()
        for rel in sorted(CURRENT):
            if rel not in gefunden:
                continue
            for zeile in gefunden[rel].splitlines():
                if _lists_the_threshold_as_optional(zeile):
                    with self.subTest(document=rel, line=zeile.strip()[:60]):
                        self.fail(f"{rel} lists the threshold as optional: {zeile.strip()!r}")

    def test_step_2_of_the_happy_path_sets_the_threshold_in_its_own_example(self) -> None:
        text = (REPO / "docs" / "INSPECT_HAPPY_PATH.md").read_text(encoding="utf-8")
        schritt = re.search(r"^## 2\..*?(?=^## 3\.)", text, re.MULTILINE | re.DOTALL)
        self.assertIsNotNone(schritt, "the happy path has no step 2 before step 3")
        self.assertRegex(schritt.group(0), r"export PROOFBUNDLE_THRESHOLD=[0-9]",
                         "step 2 runs the eval with the receipt hook and must set the threshold itself")


if __name__ == "__main__":
    unittest.main()
