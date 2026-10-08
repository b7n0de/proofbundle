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

import hashlib
import importlib.util
import io
import json
import re
import tarfile
import tempfile
import unittest
import zipfile
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
                gemessen = z["release"]["measured"]
                for feld in ("repo_paths_in_sdist", "repo_paths_at_tag", "subcommands_at_tag"):
                    self.assertFalse(any(gemessen[feld].values()), feld)
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


_MAIN = "a" * 40
_HEAD = "b" * 40
_X = {"id": "x", "name": "the x capability", "modules": ["proofbundle/x.py"]}
_X_SRC = "src/proofbundle/x.py"


def _measure(cap: dict, *, wheel=(), sdist=(), tag=(), main=(), branch=()) -> dict:
    """The script's row for one capability, measured over refs held in memory instead of git.

    Each argument is what that place carries: repository paths (src/proofbundle/...), and "cli:<name>"
    for a console subcommand. The wheel is given as package paths (proofbundle/...) and the sdist as
    repository paths, the way the script reads them. `branch` is the tree at the named branch's head.
    """
    modul = _load()
    orte = {modul.TAG: set(tag), _MAIN: set(main), _HEAD: set(branch)}

    def git_bytes(ref: str, pfad: str):
        if pfad == "NOTES.md":
            return b"the x capability, stable\n"
        if pfad == "src/proofbundle/cli.py":
            return "".join(f'sub.add_parser("{e[4:]}")\n' for e in sorted(orte[ref]) if e.startswith("cli:")).encode()
        return b"" if pfad in orte[ref] else None

    def git(*args: str) -> str:
        if args[:2] == ("rev-parse", f"origin/{cap.get('branch')}"):
            return _HEAD + "\n"
        if args[0] == "diff":
            return ""
        raise AssertionError(f"a git call the fixture does not serve: {args}")

    modul._git_bytes, modul._git = git_bytes, git
    modul.CAPABILITIES = [dict(cap, label=[("NOTES.md", r"(the x capability[^\n]*)")])]
    artefakte = {"wheel_files": {p: "0" * 64 for p in wheel if not p.startswith("cli:")},
                 "wheel_subcommands": sorted(p[4:] for p in wheel if p.startswith("cli:")),
                 "wheel_entry_points": [], "sdist_files": sorted(sdist)}
    return modul.measure_rows(artefakte, _MAIN)[0]


class MainOnlyIsAbsentFromEveryReleaseArtifact(unittest.TestCase):
    """PROPERTY (the vocabulary in measure.py): main only is present on main and absent from every v6.1.0
    artifact and from the tag. The release column reads the wheel, so a capability the wheel lacks and the
    sdist or the tag carries has no status in the vocabulary: the measurement stops instead of writing
    main only. Each case leaves the other places empty, so only the check it names can stop it."""

    def test_absent_from_the_wheel_the_sdist_and_the_tag_it_is_main_only(self) -> None:
        # The catch proof: this fixture reaches the main-only rule, so a stop below is the absence check.
        for cap, pfad in ((_X, _X_SRC), ({"id": "x", "name": "x", "repo_paths": ["tools/x/x.rs"]}, "tools/x/x.rs")):
            with self.subTest(pfad):
                z = _measure(cap, main={pfad})
                self.assertEqual((z["release"]["status"], z["main"]["status"]), ("absent", "main only"))
                # Codex thread 4217983178: only v6.1.0 was inspected, so the channel says so and not "in no release"
                self.assertEqual(z["channel"], "main tree only, not in v6.1.0")

    def test_a_module_the_sdist_carries_stops_the_measurement(self) -> None:
        with self.assertRaisesRegex(SystemExit, r"^x: .*carried by the sdist"):
            _measure(_X, sdist={_X_SRC}, main={_X_SRC})

    def test_a_repository_path_the_sdist_carries_stops_the_measurement(self) -> None:
        cap = {"id": "x", "name": "x", "repo_paths": ["tools/x/x.rs"]}
        with self.assertRaisesRegex(SystemExit, r"^x: .*carried by the sdist"):
            _measure(cap, sdist={"tools/x/x.rs"}, main={"tools/x/x.rs"})

    def test_a_capability_the_tag_carries_stops_the_measurement(self) -> None:
        with self.assertRaisesRegex(SystemExit, r"^x: .*carried by the tag"):
            _measure(dict(_X, cli=["x"]), tag={_X_SRC, "cli:x"}, main={_X_SRC, "cli:x"})


class PlannedIsMeasuredAtTheRecordedBranchHead(unittest.TestCase):
    """PROPERTY (the vocabulary in measure.py): planned is absent from the tag and from main and present on
    the named branch, measured at the head the row records. That a branch of the name exists says nothing
    about what its head carries. A branch head without the capability, a capability the release carries
    and main lacks, and one present nowhere have no main cell in the vocabulary: the measurement stops."""

    def test_a_branch_head_that_carries_the_capability_is_planned_at_that_head(self) -> None:
        # The catch proof: this fixture reaches the planned rule, so a stop below is the branch check.
        z = _measure(dict(_X, cli=["x"], branch="feat/x"), branch={_X_SRC, "cli:x"})
        self.assertEqual((z["release"]["status"], z["main"]["status"]), ("absent", "planned"))
        self.assertEqual(z["main"]["branch"], {"name": "feat/x", "head": _HEAD})
        self.assertEqual(z["channel"], "branch feat/x, not in v6.1.0 or on main")

    def test_a_branch_head_without_the_capability_stops_the_measurement(self) -> None:
        for fall, zweig in (("module missing", {"cli:x"}), ("subcommand missing", {_X_SRC}), ("empty", set())):
            with self.subTest(fall), self.assertRaisesRegex(SystemExit, rf"^x: branch feat/x at {_HEAD} "):
                _measure(dict(_X, cli=["x"], branch="feat/x"), branch=zweig)

    def test_a_capability_the_release_carries_and_main_lacks_is_not_planned(self) -> None:
        with self.assertRaisesRegex(SystemExit, r"^x: present in v6\.1\.0, absent from main "):
            _measure(dict(_X, branch="feat/x"), wheel={"proofbundle/x.py"}, sdist={_X_SRC}, tag={_X_SRC},
                     branch={_X_SRC})

    def test_a_capability_present_nowhere_gets_no_main_cell(self) -> None:
        with self.assertRaisesRegex(SystemExit, r"^x: absent from v6\.1\.0 and from main "):
            _measure(_X)


class EveryStatusThatPointsSomewhereNeedsItsLabel(unittest.TestCase):
    """Codex thread 4217201386: `planned` and `from elsewhere` returned before the label check, so a row whose
    label had gone kept asserting its branch or its provider. Each needs the project's words now, a planned row
    read at the branch head it records."""

    def test_the_rule_refuses_both_without_a_label(self) -> None:
        modul = _load()
        for args, kwargs in (((False, None), {"planned": True}), ((True, None), {"elsewhere": True}),
                             ((False, None), {"elsewhere": True})):
            with self.subTest(args=args, kwargs=kwargs), self.assertRaises(modul.LabelMissing):
                modul.status(*args, **kwargs)
        self.assertEqual(modul.status(False, "**Status:** proposed.", planned=True), "planned")
        self.assertEqual(modul.status(True, "Optional, complementary", elsewhere=True), "from elsewhere")

    def test_a_planned_row_reads_its_label_at_the_branch_head(self) -> None:
        modul = _load()
        orte = {modul.TAG: set(), _MAIN: set(), _HEAD: {_X_SRC}}
        notizen = {_HEAD: b"the x capability, proposed\n"}

        def git_bytes(ref: str, pfad: str):
            if pfad == "NOTES.md":
                return notizen.get(ref)
            return b"" if pfad in orte[ref] else None

        def git(*args: str) -> str:
            if args[:2] == ("rev-parse", "origin/feat/x"):
                return _HEAD + "\n"
            raise AssertionError(f"a git call the fixture does not serve: {args}")
        modul._git_bytes, modul._git = git_bytes, git
        modul.CAPABILITIES = [dict(_X, branch="feat/x", label=[("NOTES.md", r"(the x capability[^\n]*)")])]
        artefakte = {"wheel_files": {}, "wheel_subcommands": [], "wheel_entry_points": [], "sdist_files": []}
        z = modul.measure_rows(artefakte, _MAIN)[0]
        self.assertEqual((z["main"]["status"], z["main"]["label"]), ("planned", "the x capability, proposed"))
        notizen.clear()
        with self.assertRaisesRegex(SystemExit, r"^x: planned on a branch, but the project's label"):
            modul.measure_rows(artefakte, _MAIN)


class TheDocsAreReadForProviderAndTag(unittest.TestCase):
    """Codex threads 4217983161 and 4217983172: the provider of a from-elsewhere row and the tag the docs pin for the
    GitHub Action came from the table in measure.py, so docs that stopped naming them kept the cells. Both are read
    from the docs at the release and at main now, and the measurement stops when they say nothing or two things."""

    def _modul(self, texte: dict):
        modul = _load()
        modul._git_bytes = lambda ref, pfad: texte.get((ref, pfad))
        return modul

    _AKTION = {"id": "ga", "label": [("INTEGRATIONS.md", r"(A composite action is prepared[^\n]*)")],
               "git_tag_from": r"uses: b7n0de/proofbundle/action@(\S+)"}
    _SLSA = {"id": "slsa", "label": [("INTEGRATIONS.md", r"(\*\*Optional, complementary\*\* [^\n]*)")],
             "provider": "actions/attest-build-provenance"}
    _BEISPIEL = ("## GitHub Action\n\nA composite action is prepared. Usage:\n\n```yaml\n"
                 "- uses: b7n0de/proofbundle/action@v2.0.0\n```\n\n**Optional, complementary** - a provenance over\n"
                 "the receipt. Add:\n\n```yaml\n- uses: actions/attest-build-provenance@sha\n```\n\n## promptfoo\n")

    def test_the_documented_tag_is_the_one_the_cited_passage_pins(self) -> None:
        modul = self._modul({("r", "INTEGRATIONS.md"): self._BEISPIEL.encode()})
        self.assertEqual(modul._documented_tag("r", self._AKTION), "v2.0.0")
        anderswo = "A composite action is prepared.\n\n## Other\n\n- uses: b7n0de/proofbundle/action@v9\n"
        for fall, text in (("no uses line", "A composite action is prepared\n"),
                           ("two tags", "A composite action is prepared.\n```\nuses: b7n0de/proofbundle/action@v1\n"
                                        "uses: b7n0de/proofbundle/action@v2\n```\n"),
                           # Codex thread 4218719393, the sibling of the provider: a tag outside the cited passage
                           ("the tag only in another section", anderswo),
                           ("no label", "- uses: b7n0de/proofbundle/action@v1\n")):
            with self.subTest(fall), self.assertRaisesRegex(SystemExit, "the channel is not measured"):
                self._modul({("r", "INTEGRATIONS.md"): text.encode()})._documented_tag("r", self._AKTION)

    def test_the_provider_must_be_named_in_the_cited_passage(self) -> None:
        """Codex thread 4218719393: the provider was searched in the whole file. It must stand in the passage the
        label cites, the paragraph and its example; a mention anywhere else does not keep the cell."""
        modul = self._modul({("r", "INTEGRATIONS.md"): self._BEISPIEL.encode()})
        self.assertTrue(modul._names_provider("r", self._SLSA))
        ohne = self._BEISPIEL.replace("actions/attest-build-provenance@sha", "actions/upload-artifact@sha")
        for fall, text in (("not named at all", ohne),
                           ("named in an unrelated section", ohne + "\nSee actions/attest-build-provenance.\n"),
                           ("named in a later paragraph of the same section",
                            ohne.replace("## promptfoo", "It works with actions/attest-build-provenance.\n\n## promptfoo"))):
            with self.subTest(fall):
                self.assertFalse(self._modul({("r", "INTEGRATIONS.md"): text.encode()})._names_provider("r", self._SLSA))

    def test_a_documented_tag_must_carry_the_action(self) -> None:
        """Codex thread 4219207478: the tags were read from the docs and never looked up, so a tag that does not
        exist, or one from before the action was added, became the channel of a published row."""
        def messe(tags_am_ziel, tags=("v1", "v2")):
            modul = _load()
            texte = {modul.TAG: "the x capability, stable\n```\nuses: x@v1\n```\n",
                     _MAIN: "the x capability, stable\n```\nuses: x@v2\n```\n"}

            def git_bytes(ref, pfad):
                if pfad == "NOTES.md":
                    return texte[ref].encode() if ref in texte else None
                if pfad == "action/action.yml":
                    return b"" if ref in (modul.TAG, _MAIN) or ref.removeprefix("refs/tags/") in tags_am_ziel else None
                return None
            modul._git_bytes = git_bytes
            modul._git = lambda *args: ""
            modul._tag_ref = lambda tag: _HEAD if tag in tags else None
            modul.CAPABILITIES = [{"id": "x", "name": "x", "repo_paths": ["action/action.yml"],
                                   "git_tag_from": r"uses: x@(\S+)", "label": [("NOTES.md", r"(the x capability[^\n]*)")]}]
            artefakte = {"wheel_files": {}, "wheel_subcommands": [], "wheel_entry_points": [], "sdist_files": []}
            return modul.measure_rows(artefakte, _MAIN)[0]
        self.assertEqual(messe({"v1", "v2"})["channel"], "git tag v1 at v6.1.0, v2 at main")
        for fall, tags in (("main's tag lacks the action", {"v1"}), ("the release's tag lacks it", {"v2"}),
                           ("neither tag carries it", set())):
            with self.subTest(fall), self.assertRaisesRegex(SystemExit, "does not carry action/action.yml"):
                messe(tags)
        # Codex thread 4219678084: a branch or a commit id that carries the path is not a tag
        with self.assertRaisesRegex(SystemExit, "the documented ref v2 is not a tag"):
            messe({"v1", "v2"}, tags=("v1",))

    def test_two_documented_tags_are_both_named_in_the_channel(self) -> None:
        """Codex thread 4218719408: the channel was built from the release's tag alone, so docs at main that pin
        another tag stood beside a column that named the release's."""
        for main_tag, kanal in (("v2", "git tag v1 at v6.1.0, v2 at main"), ("v1", "git tag v1")):
            with self.subTest(main_tag=main_tag):
                modul = _load()
                texte = {modul.TAG: "the x capability, stable\n```\nuses: x@v1\n```\n",
                         _MAIN: f"the x capability, stable\n```\nuses: x@{main_tag}\n```\n"}

                def git_bytes(ref, pfad, texte=texte):
                    if pfad == "NOTES.md":
                        return texte[ref].encode() if ref in texte else None
                    return b"" if pfad == "action/action.yml" else None
                modul._git_bytes = git_bytes
                modul._git = lambda *args: ""
                modul._tag_ref = lambda tag: _HEAD
                modul.CAPABILITIES = [{"id": "x", "name": "x", "repo_paths": ["action/action.yml"],
                                       "git_tag_from": r"uses: x@(\S+)",
                                       "label": [("NOTES.md", r"(the x capability[^\n]*)")]}]
                artefakte = {"wheel_files": {}, "wheel_subcommands": [], "wheel_entry_points": [], "sdist_files": []}
                self.assertEqual(modul.measure_rows(artefakte, _MAIN)[0]["channel"], kanal)

    def test_the_recorded_rows_carry_what_the_docs_say(self) -> None:
        d = json.loads(_MATRIX.read_text(encoding="utf-8"))
        reihen = {z["id"]: z for z in d["rows"]}
        ga = reihen["github-action"]
        self.assertEqual(ga["channel"], f"git tag {ga['release']['measured']['documented_tag']}")
        self.assertEqual(ga["main"]["measured"]["documented_tag_at_main"], ga["release"]["measured"]["documented_tag"])
        sl = reihen["slsa-provenance"]
        self.assertIs(sl["release"]["measured"]["provider_named_in_docs"], True)
        self.assertIs(sl["main"]["measured"]["provider_named_in_docs"], True)


class FromElsewhereSaysWhatWasMeasured(unittest.TestCase):
    """Codex thread 4219678096: the status said another project provides the capability, and what is measured is that
    the cited docs name the provider. The vocabulary and the README say so and claim no availability."""

    def test_the_vocabulary_claims_no_availability(self) -> None:
        modul = _load()
        doc = " ".join(modul.__doc__.split())
        self.assertIn("the docs name a component outside this project as the provider", doc)
        self.assertIn("Whether that project provides it is not measured", doc)
        readme = " ".join(_README.read_text(encoding="utf-8").split())
        self.assertIn("`from elsewhere` when the docs name another project as the provider, whose own availability "
                      "is not measured here", readme)
        self.assertNotIn("when another project provides it", readme)


class AFailedProvenanceCheckStopsTheMeasurement(unittest.TestCase):
    """Codex thread 4218719417: a SHA-256 that is not PyPI's, and wheel files that differ from the tag or are absent
    there, were recorded and the release column was derived from the local bytes all the same."""

    def _artefakte(self, d: Path, *, pypi_digest=None, am_tag=b"print('cli')\n"):
        modul = _load()
        cli = b"print('cli')\n"
        rad = d / "proofbundle-6.1.0-py3-none-any.whl"
        with zipfile.ZipFile(rad, "w") as z:
            z.writestr("proofbundle/cli.py", cli)
            z.writestr("proofbundle-6.1.0.dist-info/entry_points.txt", "[console_scripts]\nproofbundle = x\n")
        sdist = d / "proofbundle-6.1.0.tar.gz"
        with tarfile.open(sdist, "w:gz") as t:
            info = tarfile.TarInfo("proofbundle-6.1.0/README.md")
            info.size = 1
            t.addfile(info, io.BytesIO(b"x"))
        urls = []
        for datei, art in ((rad, "bdist_wheel"), (sdist, "sdist")):
            digest = hashlib.sha256(datei.read_bytes()).hexdigest()
            urls.append({"filename": datei.name, "packagetype": art, "url": "https://example.invalid/" + datei.name,
                         "upload_time_iso_8601": "2026-09-27T00:00:00Z",
                         "digests": {"sha256": (pypi_digest or {}).get(art, digest)}})
        modul._git_bytes = lambda ref, pfad: am_tag if pfad == "src/proofbundle/cli.py" else None
        return modul, {"urls": urls}

    def test_consistent_artifacts_are_measured(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            modul, pypi = self._artefakte(Path(tmp))
            ergebnis = modul.measure_artifacts(Path(tmp), pypi)
            self.assertEqual(modul.provenance_problems(ergebnis), [])
            self.assertEqual(ergebnis["wheel_against_tag"], {"identical": 1, "different": [], "absent_at_tag": []})

    def test_each_failed_check_stops_it(self) -> None:
        for fall, kwargs, wort in (("a wheel digest that is not PyPI's", {"pypi_digest": {"bdist_wheel": "0" * 64}},
                                    "is not PyPI's"),
                                   ("an sdist digest that is not PyPI's", {"pypi_digest": {"sdist": "0" * 64}},
                                    "sdist proofbundle-6.1.0.tar.gz"),
                                   ("a wheel file that differs from the tag", {"am_tag": b"print('other')\n"},
                                    "differ from v6.1.0"),
                                   ("a wheel file absent at the tag", {"am_tag": None}, "absent at v6.1.0")):
            with self.subTest(fall), tempfile.TemporaryDirectory() as tmp:
                modul, pypi = self._artefakte(Path(tmp), **kwargs)
                with self.assertRaisesRegex(SystemExit, wort):
                    modul.measure_artifacts(Path(tmp), pypi)


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
        self.assertIn("A wheel built from main at `0ace3039` was also called 6.1.0", text)
        self.assertRegex(text, re.escape("uses: b7n0de/proofbundle/action@v1.0.0"))


if __name__ == "__main__":
    unittest.main()
