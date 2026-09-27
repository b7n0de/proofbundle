"""The capability and release matrix binds no capability to a package that does not carry it.

docs/capability_matrix/matrix.json records, per capability, what was measured in the v6.1.0 wheel and
sdist from PyPI and at a main commit, and the status derived from it. These cases hold the recorded data
to the rule the measuring script states (tools/capability_matrix/measure.py): a release cell says
published or experimental only for what the published wheel carries, byte-identical to the tag; a main
cell says main only only for what no release carries; the rendered tables are the data's; and a new user
in a fresh environment signed a receipt that verified and saw a tampered copy refused.

The main column is stamped with its commit, so the matrix does not go stale when main moves; it answers
for that commit. Re-measuring is `tools/capability_matrix/measure.py`, with network for PyPI.
"""
from __future__ import annotations

import importlib.util
import json
import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
_MATRIX = REPO / "docs/capability_matrix/matrix.json"
_README = REPO / "docs/capability_matrix/README.md"
_SCRIPT = REPO / "tools/capability_matrix/measure.py"


def _load():
    spec = importlib.util.spec_from_file_location("_capability_matrix_measure", _SCRIPT)
    modul = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(modul)
    return modul


class TheRecordedArtifactsAreThePublishedOnes(unittest.TestCase):
    def setUp(self) -> None:
        self.d = json.loads(_MATRIX.read_text(encoding="utf-8"))

    def test_the_release_column_is_measured_on_pypis_bytes(self) -> None:
        rel = self.d["release"]
        self.assertEqual((rel["version"], self.d["tag"]), ("6.1.0", "v6.1.0"))
        self.assertEqual(set(rel["files"]), {"bdist_wheel", "sdist"})
        for art, datei in rel["files"].items():
            with self.subTest(artifact=art):
                self.assertTrue(datei["digest_matches_pypi"])
                self.assertEqual(datei["sha256"], datei["sha256_pypi"])
                self.assertRegex(datei["sha256"], r"^[0-9a-f]{64}$")

    def test_the_wheel_is_the_tag(self) -> None:
        vergleich = self.d["release"]["wheel_against_tag"]
        self.assertEqual((vergleich["different"], vergleich["absent_at_tag"]), ([], []))
        paket = [n for n in self.d["release"]["wheel_files"] if n.startswith("proofbundle/")]
        self.assertEqual(vergleich["identical"], len(paket))

    def test_both_commits_are_named_in_full(self) -> None:
        self.assertRegex(self.d["tag_commit"], r"^[0-9a-f]{40}$")
        self.assertRegex(self.d["main_commit"], r"^[0-9a-f]{40}$")


class NoRowBindsACapabilityToAPackageThatLacksIt(unittest.TestCase):
    """PROPERTY: a release cell reads published or experimental only when the published wheel carries
    every module, subcommand and entry point of the capability (or, for a repository capability, the tag
    carries its paths); main only and planned never appear with a release that carries the capability."""

    def setUp(self) -> None:
        self.d = json.loads(_MATRIX.read_text(encoding="utf-8"))
        self.rel = self.d["release"]

    def test_every_status_is_in_the_closed_vocabulary(self) -> None:
        erlaubt = set(self.d["statuses"])
        self.assertEqual(erlaubt, {"published", "experimental", "main only", "planned", "from elsewhere", "absent"})
        for z in self.d["rows"]:
            with self.subTest(row=z["id"]):
                self.assertIn(z["release"]["status"], erlaubt - {"main only", "planned"})
                self.assertIn(z["main"]["status"], erlaubt - {"absent"})

    def test_a_published_or_experimental_release_cell_is_carried_by_the_wheel(self) -> None:
        for z in self.d["rows"]:
            if z["release"]["status"] not in ("published", "experimental"):
                continue
            ev = z["evidence"]
            with self.subTest(row=z["id"]):
                for m in ev["modules"]:
                    self.assertIn(m, self.rel["wheel_files"])
                for c in ev["subcommands"]:
                    self.assertIn(c, self.rel["wheel_subcommands"])
                for e in ev["entry_points"]:
                    self.assertIn(e, self.rel["wheel_entry_points"])
                if not ev["modules"]:
                    self.assertTrue(ev["repo_paths"])
                    self.assertTrue(all(z["release"]["measured"]["repo_paths_at_tag"].values()))
                    self.assertNotEqual(z["channel"], "PyPI wheel")
                else:
                    self.assertEqual(z["channel"], "PyPI wheel")

    def test_main_only_and_planned_are_absent_from_the_release(self) -> None:
        for z in self.d["rows"]:
            if z["main"]["status"] not in ("main only", "planned"):
                continue
            with self.subTest(row=z["id"]):
                self.assertEqual(z["release"]["status"], "absent")
                for m in z["evidence"]["modules"]:
                    self.assertNotIn(m, self.rel["wheel_files"])
                    self.assertFalse(z["release"]["measured"]["modules_in_sdist"][m])
                self.assertNotEqual(z["channel"], "PyPI wheel")
                if z["main"]["status"] == "planned":
                    self.assertRegex(z["main"]["branch"]["head"], r"^[0-9a-f]{40}$")
                    self.assertFalse(any(z["main"]["measured"]["modules_at_main"].values()))

    def test_every_status_is_the_rule_applied_to_what_was_measured(self) -> None:
        status = _load().status
        for z in self.d["rows"]:
            anderswo = bool(z["evidence"]["elsewhere"])
            with self.subTest(row=z["id"]):
                rel_da = anderswo or z["release"]["status"] not in ("absent",)
                self.assertEqual(z["release"]["status"], status(rel_da, z["release"]["label"], elsewhere=anderswo))
                main_da = anderswo or z["main"]["status"] not in ("planned",)
                self.assertEqual(z["main"]["status"],
                                 status(main_da, z["main"]["label"], main_only=main_da and not rel_da,
                                        elsewhere=anderswo, planned=z["main"]["branch"] is not None))

    def test_a_present_capability_without_a_label_is_not_given_a_status(self) -> None:
        modul = _load()
        with self.assertRaises(modul.LabelMissing):
            modul.status(True, None)
        self.assertEqual(modul.status(True, "EXPERIMENTAL (3.2.0)"), "experimental")
        self.assertEqual(modul.status(True, "shipped (2.1.0)"), "published")
        self.assertEqual(modul.status(False, None), "absent")


class TheReadmeTablesAreTheData(unittest.TestCase):
    def test_both_rendered_blocks_equal_the_recorded_data(self) -> None:
        modul = _load()
        d = json.loads(_MATRIX.read_text(encoding="utf-8"))
        text = _README.read_text(encoding="utf-8")
        for name, render in modul.BLOECKE.items():
            begin, end = modul._marken(name)
            with self.subTest(block=name):
                block = text[text.index(begin) + len(begin):text.index(end)]
                self.assertEqual(block.strip(), render(d).strip())


class ANewUserSignsAndSeesATamperRefused(unittest.TestCase):
    """The acceptance of the order: in a fresh environment, from the published wheel, a new user creates a
    receipt that verifies and has a tampered copy refused."""

    def setUp(self) -> None:
        self.d = json.loads(_MATRIX.read_text(encoding="utf-8"))

    def _schritte(self, name: str) -> dict:
        lauf = self.d["fresh_venv"][name]
        self.assertEqual(lauf["pip_install_exit"], 0)
        return {s["command"].split()[0]: s for s in lauf["steps"] if s["command"].split()[0] != "verify"} | {
            "verify-valid": next(s for s in lauf["steps"] if s["command"] == "verify receipt.json"),
            "verify-tampered": next(s for s in lauf["steps"] if s["command"] == "verify tampered.json")}

    def test_the_published_wheel(self) -> None:
        lauf = self.d["fresh_venv"]["release_wheel"]
        self.assertEqual(lauf["wheel_sha256"], self.d["release"]["files"]["bdist_wheel"]["sha256"])
        s = self._schritte("release_wheel")
        self.assertEqual(s["--version"]["output_head"][0], "proofbundle 6.1.0")
        self.assertEqual((s["emit"]["exit"], s["verify-valid"]["exit"], s["demo"]["exit"]), (0, 0, 0))
        self.assertEqual(s["verify-tampered"]["exit"], 1)
        self.assertIn("invalid signature", " ".join(s["verify-tampered"]["output_head"]))

    def test_a_wheel_built_from_main_carries_the_same_version_and_main_only_code(self) -> None:
        lauf = self.d["fresh_venv"]["main_wheel"]
        self.assertEqual(lauf["built_from"], self.d["main_commit"])
        self.assertNotEqual(lauf["wheel_sha256"], self.d["release"]["files"]["bdist_wheel"]["sha256"])
        s = self._schritte("main_wheel")
        self.assertEqual(s["--version"]["output_head"][0], "proofbundle 6.1.0")
        main_only = sorted(m for z in self.d["rows"] if z["main"]["status"] == "main only"
                           for m in z["evidence"]["modules"])
        self.assertTrue(main_only)
        self.assertEqual(lauf["main_only_modules_inside"], main_only)
        self.assertEqual(s["verify-tampered"]["exit"], 1)

    def test_the_readme_names_both_findings(self) -> None:
        text = _README.read_text(encoding="utf-8")
        self.assertIn("A wheel built from main is also called 6.1.0", text)
        self.assertRegex(text, re.escape("uses: b7n0de/proofbundle/action@v1.0.0"))


if __name__ == "__main__":
    unittest.main()
