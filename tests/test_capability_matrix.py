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
    for a console subcommand (what `_subcommands_at` would find there by running the console
    script). The wheel is given as package paths (proofbundle/...) and the sdist as
    repository paths, the way the script reads them. `branch` is the tree at the named branch's head.
    """
    modul = _load()
    orte = {modul.TAG: set(tag), _MAIN: set(main), _HEAD: set(branch)}

    def git_bytes(ref: str, pfad: str):
        if pfad == "NOTES.md":
            return b"the x capability, stable\n"
        return b"" if pfad in orte[ref] else None

    def git(*args: str) -> str:
        if args[:2] == ("rev-parse", f"origin/{cap.get('branch')}"):
            return _HEAD + "\n"
        if args[0] == "diff":
            return ""
        raise AssertionError(f"a git call the fixture does not serve: {args}")

    modul._git_bytes, modul._git = git_bytes, git
    # the console subcommands a run of the console script finds there, held in memory as the rest
    modul._subcommands_at = lambda ref: {e[4:] for e in orte[ref] if e.startswith("cli:")}
    modul.CAPABILITIES = [dict(cap, label=[("NOTES.md", r"(the x capability[^\n]*)")])]
    artefakte = {"wheel_files": {p: "0" * 64 for p in wheel if not p.startswith("cli:")},
                 "wheel_subcommands": sorted(p[4:] for p in wheel if p.startswith("cli:")),
                 "wheel_entry_points": [], "sdist_files": sorted(sdist)}
    return modul.measure_rows(artefakte, _MAIN)[0]


def _cli(rumpf: str, *, kopf: str = "", fuss: str = "") -> str:
    """A cli.py whose build_parser registers on `sub` what `rumpf` does, and whose main parses with the parser
    build_parser gives when main runs. `kopf` stands before build_parser, `fuss` after it."""
    return ("import argparse\n" + kopf + "\n\ndef build_parser():\n"
            "    p = argparse.ArgumentParser(prog='proofbundle')\n"
            "    sub = p.add_subparsers(dest='command')\n" + rumpf + "    return p\n" + fuss
            + "\n\ndef main(argv=None):\n    return build_parser().parse_args(argv)\n")


def _unterbefehle(modul, quelle: str, ziel: str = "proofbundle.cli:main") -> set:
    """What `modul` measures by running the console script `ziel` of a package tree whose cli.py is `quelle`."""
    with tempfile.TemporaryDirectory() as tmp:
        paket = Path(tmp) / "proofbundle"
        paket.mkdir()
        (paket / "__init__.py").write_text("", encoding="utf-8")
        (paket / "cli.py").write_text(quelle, encoding="utf-8")
        return modul._subcommands_in_tree(Path(tmp), ziel)


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
    _SLSA = {"id": "slsa", "label": [("INTEGRATIONS.md", r"^(Optional, complementary [^\n]*)")],
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
                    return b"" if ref in (modul.TAG, _MAIN) or ref in {f"commit of {t}" for t in tags_am_ziel} else None
                return None
            modul._git_bytes = git_bytes
            modul._git = lambda *args: ""
            modul._tag_ref = lambda tag: f"commit of {tag}" if tag in tags else None
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


class ATagIsATagAsWritten(unittest.TestCase):
    """Codex thread 4220245923: rev-parse resolved refs/tags/v1~1 to the parent of v1, so documentation pinning a
    revision expression could produce the channel `git tag v1~1`. `_tag_ref` takes a tag only as written, in a
    repository built here, so the case does not depend on the tags a checkout fetched."""

    def test_only_an_existing_tag_name_resolves(self) -> None:
        import subprocess
        import tempfile
        modul = _load()
        with tempfile.TemporaryDirectory() as d:
            git = ["git", "-C", d, "-c", "user.name=t", "-c", "user.email=t@example.org", "-c", "commit.gpgsign=false",
                   "-c", "tag.gpgsign=false"]
            subprocess.run(["git", "init", "-q", d], check=True)
            for n in ("1", "2"):
                subprocess.run(git + ["commit", "-q", "--allow-empty", "-m", n], check=True)
            subprocess.run(git + ["tag", "v1"], check=True)
            subprocess.run(git + ["tag", "-a", "-m", "a", "v1-annotated"], check=True)
            subprocess.run(git + ["branch", "b1"], check=True)
            kopf = subprocess.run(git + ["rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
            modul.REPO = Path(d)
            self.assertEqual(modul._tag_ref("v1"), kopf, "control: a lightweight tag")
            self.assertEqual(modul._tag_ref("v1-annotated"), kopf, "control: an annotated tag, peeled to its commit")
            for ausdruck in ("v1~1", "v1^", "v1^{commit}", "v1@{0}", "v1:", "b1", "HEAD", kopf, kopf[:12], "v2", ""):
                with self.subTest(ref=ausdruck):
                    self.assertIsNone(modul._tag_ref(ausdruck))


class WhatIsReadIsReadByItsMeaning(unittest.TestCase):
    """Round seven of Codex on pull request 304: a value read from the docs or the source was used by its spelling."""

    def test_the_diff_takes_the_resolved_commit_never_the_documented_name(self) -> None:
        """Thread 4220770798: an exact tag named --output=clobbered passed every check and became an option of git diff,
        which wrote a file and gave an empty shortstat. The diff takes the commit the tag resolved to."""
        modul = _load()
        name = "--output=clobbered"
        texte = {modul.TAG: f"the x capability, stable\n```\nuses: x@{name}\n```\n",
                 _MAIN: f"the x capability, stable\n```\nuses: x@{name}\n```\n"}
        aufrufe = []

        def git_bytes(ref, pfad):
            if pfad == "NOTES.md":
                return texte[ref].encode() if ref in texte else None
            return b"" if pfad == "action/action.yml" else None

        def git(*args):
            aufrufe.append(args)
            return " 1 file changed"
        modul._git_bytes, modul._git = git_bytes, git
        modul._tag_ref = lambda tag: f"commit of {tag}"
        modul.CAPABILITIES = [{"id": "x", "name": "x", "repo_paths": ["action/action.yml"],
                               "git_tag_from": r"uses: x@(\S+)", "label": [("NOTES.md", r"(the x capability[^\n]*)")]}]
        artefakte = {"wheel_files": {}, "wheel_subcommands": [], "wheel_entry_points": [], "sdist_files": []}
        modul.measure_rows(artefakte, _MAIN)
        diffs = [a for a in aufrufe if a and a[0] == "diff"]
        self.assertTrue([a for a in diffs if f"commit of {name}" in a], aufrufe)
        self.assertFalse([x for a in aufrufe for x in a if x.startswith("--output")], aufrufe)

    def test_a_subcommand_is_one_the_console_script_registers_not_its_text(self) -> None:
        """Thread 4220770815: a pattern over the text found a commented-out registration. The subcommands are those of
        the parser the console script builds when it runs (thread 4222126486), so a comment, a string and a nested
        parser's registration are none, and a source that does not even parse stops the measurement."""
        modul = _load()
        quelle = _cli('    # sub.add_parser("decision") was removed\n'
                      '    hinweis = \'sub.add_parser("outcome")\'\n'
                      '    sub.add_parser("verify", help="x")\n'
                      '    sub.add_parser("policy").add_subparsers().add_parser("nested")\n')
        self.assertEqual(_unterbefehle(modul, quelle), {"verify", "policy"})
        with self.assertRaisesRegex(SystemExit, "does not run here"):
            _unterbefehle(modul, 'sub.add_parser("verify"\n')
        modul._git_bytes = lambda ref, pfad: b'[project]\nname = "x"\n' if pfad == "pyproject.toml" else None
        self.assertEqual(modul._subcommands_at("r"), set(), "control: no console script gives no subcommand")

    def test_a_label_that_negates_experimental_is_not_experimental(self) -> None:
        """Thread 4220770827: the keyword alone was read, so a graduation note reversed the status."""
        modul = _load()
        for label, erwartet in (("EXPERIMENTAL (3.2.0)", "experimental"),
                                ("The Rust cross verifier is experimental and advisory.", "experimental"),
                                ("**the `[experimental]` extra** — the TEE-attestation bridge", "experimental"),
                                ("Published; no longer experimental", "published"),
                                ("stable, not experimental", "published"), ("non-experimental", "published"),
                                ("Published", "published")):
            with self.subTest(label=label):
                self.assertEqual(modul.status(True, label), erwartet)
        with self.assertRaises(modul.LabelMissing):
            modul.status(True, "experimental in 6.0, no longer experimental in 6.1")


class WhatAStaticReadingCannotDecideStops(unittest.TestCase):
    """Round eight of Codex on pull request 304: each reader read a spelling, and what it cannot read now stops."""

    def test_a_computed_or_guarded_registration_is_read_as_it_runs(self) -> None:
        """Thread 4221179837: `if False:` above a registration counted it, and a computed name was dropped. Read by
        running the console script (thread 4222126486), a branch not taken registers nothing and a computed name is
        the name it computes."""
        modul = _load()
        for rumpf, erwartet in (('    if False:\n        sub.add_parser("decision")\n', set()),
                                ('    name = "decision"\n    sub.add_parser(name)\n', {"decision"}),
                                ('    x = sub.add_parser("decision") if 0 else None\n', set()),
                                ('    while False:\n        sub.add_parser("decision")\n', set()),
                                ('    if True:\n        sub.add_parser("decision")\n', {"decision"})):
            with self.subTest(source=rumpf):
                self.assertEqual(_unterbefehle(modul, _cli(rumpf)), erwartet)

    def test_only_what_the_parser_registers_when_main_runs_counts(self) -> None:
        """Thread 4221639819: `if enabled:` above a registration counted whatever enabled was, and a registration in a
        function nobody calls counted too. Run, a branch counts when it is taken, a loop for what it loops over, and a
        function nobody calls registers nothing; a source that fails when it runs stops the measurement."""
        modul = _load()
        for kopf, rumpf, fuss, erwartet in (
                ("ENABLED = False", '    if ENABLED:\n        sub.add_parser("decision")\n', "", set()),
                ("ENABLED = True", '    if ENABLED:\n        sub.add_parser("decision")\n', "", {"decision"}),
                ('NAMES = ["decision", "outcome"]', '    for n in NAMES:\n        sub.add_parser(n)\n', "",
                 {"decision", "outcome"}),
                ("", '    try:\n        sub.add_parser("decision")\n    except ValueError:\n        pass\n', "",
                 {"decision"}),
                ("", "", '\n\ndef other(sub):\n    sub.add_parser("decision")\n', set())):
            with self.subTest(kopf=kopf, rumpf=rumpf, fuss=fuss):
                self.assertEqual(_unterbefehle(modul, _cli(rumpf, kopf=kopf, fuss=fuss)), erwartet)
        with self.assertRaisesRegex(SystemExit, "does not run here"):
            _unterbefehle(modul, _cli('    sub.add_parser(UNDEFINED)\n'))

    def test_a_provider_or_label_inside_an_html_comment_is_not_read(self) -> None:
        """Thread 4221639836: a provider named only inside an HTML comment counted; the label reader read comments
        too. Every reader of the docs reads the text without its comments."""
        modul = _load()
        cap = {"id": "x", "provider": "actions/attest", "label": [("NOTES.md", r"(the x capability[^\n]*)")]}
        modul._git_bytes = lambda ref, pfad: (b"the x capability\n<!-- actions/attest provides this -->\n"
                                              if pfad == "NOTES.md" else None)
        self.assertFalse(modul._names_provider("v6.1.0", cap))
        modul._git_bytes = lambda ref, pfad: b"<!-- the x capability, stable -->\n" if pfad == "NOTES.md" else None
        self.assertEqual(modul._label_at("v6.1.0", cap["label"]), (None, None))
        modul._git_bytes = lambda ref, pfad: b"the x capability\nProvenance from actions/attest.\n" if pfad == "NOTES.md" else None
        self.assertTrue(modul._names_provider("v6.1.0", cap), "control: a visible naming counts")

    def test_a_commented_out_pin_is_no_channel(self) -> None:
        """Thread 4221179850: a cited fenced block holding only `# uses: ...@v1.0.0` was read as the documented tag."""
        modul = _load()
        cap = {"id": "x", "git_tag_from": r"uses: x@(\S+)", "label": [("NOTES.md", r"(the x capability[^\n]*)")]}
        for kommentiert in ("```yaml\n# uses: x@v1\n```\n", "```yaml\n  #   - uses: x@v1\n```\n",
                            "<!-- uses: x@v1 -->\n"):
            modul._git_bytes = lambda ref, pfad, k=kommentiert: (f"the x capability\n{k}".encode()
                                                                 if pfad == "NOTES.md" else None)
            with self.subTest(text=kommentiert), self.assertRaisesRegex(SystemExit, "pins no tag"):
                modul._documented_tag("v6.1.0", cap)
        modul._git_bytes = lambda ref, pfad: b"the x capability\n```yaml\n- uses: x@v1\n```\n" if pfad == "NOTES.md" else None
        self.assertEqual(modul._documented_tag("v6.1.0", cap), "v1", "control: an active pin is read")

    def test_a_provider_named_in_a_negated_sentence_stops_the_measurement(self) -> None:
        """Thread 4221179864: "Do not use actions/attest-build-provenance" counted as naming it as the provider."""
        modul = _load()
        cap = {"id": "x", "provider": "actions/attest", "label": [("NOTES.md", r"(the x capability[^\n]*)")]}
        for satz in ("Do not use actions/attest; it is unsupported.", "actions/attest is deprecated here.",
                     "Use our step instead of actions/attest."):
            modul._git_bytes = lambda ref, pfad, t=satz: f"the x capability\n{t}\n".encode() if pfad == "NOTES.md" else None
            with self.subTest(sentence=satz), self.assertRaisesRegex(SystemExit, "negated sentence"):
                modul._names_provider("v6.1.0", cap)
        modul._git_bytes = lambda ref, pfad: b"the x capability\nProvenance comes from actions/attest.\n" if pfad == "NOTES.md" else None
        self.assertTrue(modul._names_provider("v6.1.0", cap), "control: a plain naming counts")


class EveryFormatIsReadByTheReaderItsConsumerUses(unittest.TestCase):
    """Round ten of Codex on pull request 304: four more spellings a hand reader took for what its format says. The
    console subcommands are read by running the console script, pyproject.toml by a TOML parser, entry_points.txt by
    importlib.metadata and the docs by a CommonMark parser, and what such a reader refuses stops the measurement."""

    def test_the_build_parser_main_calls_is_the_one_measured(self) -> None:
        """Thread 4222126486: a registration in a build_parser under `if False:` counted, although main calls a later
        one that registers nothing; a second definition and a later assignment are its siblings. A main that parses
        nothing, and a console script whose module is not the tree's, stop the measurement."""
        modul = _load()
        tot = ('\nif False:\n    def build_parser():\n        p = argparse.ArgumentParser()\n'
               '        p.add_subparsers().add_parser("decision")\n        return p\n')
        frueher = ('\ndef build_parser():\n    p = argparse.ArgumentParser()\n'
                   '    p.add_subparsers().add_parser("decision")\n    return p\n')
        spaeter = ('\n\ndef _andere():\n    p = argparse.ArgumentParser()\n'
                   '    p.add_subparsers().add_parser("outcome")\n    return p\n\n\nbuild_parser = _andere\n')
        for fall, quelle, erwartet in (("a definition under if False", _cli('    sub.add_parser("verify")\n', kopf=tot),
                                        {"verify"}),
                                       ("an earlier definition", _cli('    sub.add_parser("verify")\n', kopf=frueher),
                                        {"verify"}),
                                       ("a later assignment", _cli('    sub.add_parser("verify")\n', fuss=spaeter),
                                        {"outcome"})):
            with self.subTest(fall):
                self.assertEqual(_unterbefehle(modul, quelle), erwartet)
        with self.assertRaisesRegex(SystemExit, "parsed no arguments"):
            _unterbefehle(modul, "def main():\n    return 0\n")
        with self.assertRaisesRegex(SystemExit, "outside the tree"):
            _unterbefehle(modul, _cli(""), ziel="json:dumps")

    def test_pyproject_toml_is_read_by_a_toml_parser(self) -> None:
        """Threads 4221179857 and 4221639830 found spellings a hand reader missed, and round ten two more: a comment
        holding a bracket after a table header (4222126499) and a key with no value (4222126493). Every form the build
        reads is read, and a document or a declaration the build refuses stops the measurement."""
        modul = _load()
        ins, kon = {"inspect_ai:proofbundle"}, {"console_scripts:proofbundle"}
        for text, erwartet in (('[project.entry-points.inspect_ai] # active\nproofbundle = "x"\n', ins),
                               ('[project.entry-points.inspect_ai] # [active]\nproofbundle = "x"\n', ins),
                               ("[project.entry-points.inspect_ai]\n'proofbundle' = 'x'\n", ins),
                               ('[project.entry-points."inspect_ai"]\n"proofbundle" = "x"\n', ins),
                               ("[ project . entry-points . 'inspect_ai' ]\nproofbundle = 'x'\n", ins),
                               ('project.entry-points.inspect_ai.proofbundle = "x"\n', ins),
                               ("[project]\n'entry-points'.inspect_ai.proofbundle = 'x'\n", ins),
                               ('[project.entry-points]\ninspect_ai = {proofbundle = "x"}\n', ins),
                               ('[project]\n"scripts".proofbundle = "x"\n', kon),
                               ('[project]\nscripts = {proofbundle = "x"}\n', kon),
                               ('[project.scripts] # [x]\nproofbundle = "proofbundle.cli:main"\n', kon),
                               ('[project.gui-scripts]\npb = "x:y"\n', {"gui_scripts:pb"}),
                               ("", set())):
            with self.subTest(text=text):
                self.assertEqual(modul._entry_points_in_pyproject(text), erwartet)
        for text in ("[project.entry-points.inspect_ai]\nproofbundle = # removed\n",
                     '[project.entry-points.inspect_ai]\nproofbundle = "x"\nproofbundle = "y"\n',
                     "[project.entry-points.inspect_ai]\nproofbundle = 1\n",
                     '[project]\ndynamic = ["entry-points"]\n',
                     '[project.entry-points.console_scripts]\nproofbundle = "x"\n',
                     "project = 1\n"):
            with self.subTest(refused=text), self.assertRaisesRegex(SystemExit, "not measured"):
                modul._entry_points_in_pyproject(text)

    def test_an_entry_points_file_is_read_as_importlib_metadata_reads_it(self) -> None:
        """The wheel's entry_points.txt was read by a hand reader too, the sibling of the TOML reader; it is read as
        the plugin loaders read it."""
        modul = _load()
        text = ("[console_scripts]\nproofbundle = proofbundle.cli:main\n\n# commented = out\n"
                "[pytest11]\n  proofbundle = proofbundle.pytest_plugin\n")
        self.assertEqual(modul._entry_points(text), {"console_scripts:proofbundle", "pytest11:proofbundle"})

    _CAP = {"id": "x", "provider": "actions/attest", "git_tag_from": r"uses: x@(\S+)",
            "label": [("NOTES.md", r"(the x capability[^\n]*)")]}

    def _modul(self, text: str):
        modul = _load()
        modul._git_bytes = lambda ref, pfad: text.encode() if pfad == "NOTES.md" else None
        return modul

    def test_a_reference_definition_is_hidden_where_commonmark_takes_it_for_one(self) -> None:
        """Thread 4222126509: a link reference definition renders into nothing, and a provider named only there
        counted. CommonMark takes a definition before a paragraph for one; after a line of a paragraph it cannot
        interrupt it and is paragraph text, which renders. A label or a pin only in a definition is none either."""
        self.assertFalse(self._modul("[unused]: https://github.com/actions/attest\nthe x capability\n")
                         ._names_provider("r", self._CAP))
        self.assertTrue(self._modul("the x capability\n[unused]: https://github.com/actions/attest\n")
                        ._names_provider("r", self._CAP), "control: the same line inside the paragraph renders")
        self.assertEqual(self._modul("[the x capability, stable]: https://example.org\n")._label_at(
            "r", self._CAP["label"]), (None, None))
        with self.assertRaisesRegex(SystemExit, "pins no tag"):
            self._modul("[uses: x@v1]: https://example.org\nthe x capability\n")._documented_tag("r", self._CAP)

    def test_the_cited_passage_is_the_blocks_commonmark_renders(self) -> None:
        """The passage was found by lines of three backticks, the sibling reader of the same class: a fence of tildes,
        a fence of four backticks that holds a line of three and an indented code block are code blocks of the passage
        as they render; a paragraph after them ends it."""
        for text, erwartet in (("the x capability\n\n~~~yaml\n- uses: x@v1\n~~~\n", "v1"),
                               ("the x capability\n\n````md\n```\nnot the end\n```\n- uses: x@v2\n````\n", "v2"),
                               ("the x capability\n\n    - uses: x@v3\n", "v3"),
                               ("the x capability\n\n```\n- uses: x@v4\n```\n\nThen - uses: x@v9\n", "v4")):
            with self.subTest(text=text):
                self.assertEqual(self._modul(text)._documented_tag("r", self._CAP), erwartet)

    def test_an_html_element_in_the_cited_text_stops_the_measurement(self) -> None:
        """What an element's attributes hide is not decided here: a label or a cited passage that holds an HTML element
        stops the measurement. An HTML block elsewhere renders no text that is read and stops nothing."""
        for text in ("the x capability\n<span hidden>Provenance from actions/attest.</span>\n",
                     "the x capability <b>stable</b>\n"):
            with self.subTest(text=text), self.assertRaisesRegex(SystemExit, "HTML element"):
                modul = self._modul(text)
                modul._label_at("r", self._CAP["label"])
                modul._names_provider("r", self._CAP)
        anderswo = '<div align="center">\nactions/attest\n</div>\n\nthe x capability\nProvenance from actions/attest.\n'
        self.assertTrue(self._modul(anderswo)._names_provider("r", self._CAP))
        self.assertFalse(self._modul('<div align="center">\nactions/attest\n</div>\n\nthe x capability\n')
                         ._names_provider("r", self._CAP), "control: the HTML block is not read")


class TheDocsAreReadAsTheyRender(unittest.TestCase):
    """Round eleven of Codex on pull request 304, thread 4222919983: CommonMark chose the lines and a pattern still read
    their Markdown, so `## **promptfoo**` lost its label and `exper&#105;mental` read as published. Every reader of the
    docs reads the text a block renders: entities decoded, emphasis, link and code marks gone, a soft line break a
    space, a table row its cells, and what a reader cannot decide in it stops the measurement."""

    def _modul(self, text: str):
        modul = _load()
        modul._git_bytes = lambda ref, pfad: text.encode() if pfad == "NOTES.md" else None
        return modul

    def test_a_label_is_its_rendered_text(self) -> None:
        heading = [("NOTES.md", r"^(## promptfoo[^\n]*)")]
        for text in ("## promptfoo (adapter)\n", "## **promptfoo** (adapter)\n", "## *promptfoo* (adapter)\n",
                     "## `promptfoo` (adapter)\n", "## pro&#109;ptfoo (adapter)\n", "## promptfoo \\(adapter\\)\n",
                     "promptfoo (adapter)\n---\n", "## [promptfoo](https://example.org) (adapter)\n"):
            with self.subTest(text=text):
                self.assertEqual(self._modul(text)._label_at("r", heading), ("## promptfoo (adapter)", "NOTES.md"))
        zeile = [("NOTES.md", ("row", r"x/v1", 1))]
        for text in ("| name | status |\n|---|---|\n| `x/v1` | **EXPERIMENTAL** (3.2) |\n",
                     "| name | status |\n|---|---|\n| x/v1 | EXPERIMENTAL (3.2) |\n"):
            with self.subTest(table=text):
                self.assertEqual(self._modul(text)._label_at("r", zeile)[0], "EXPERIMENTAL (3.2)")

    def test_a_table_label_is_its_cell(self) -> None:
        """Thread 4224150092: the cells were joined into a row again with an escaped pipe, and a pattern over that row
        found no label in `stable \\| EXPERIMENTAL`. A table label is a cell, named by its row's first cell and its
        column, so a pipe the cell renders is the cell's text."""
        zeile = [("NOTES.md", ("row", r"x/v1", 1))]
        modul = self._modul("| name | status |\n|---|---|\n| x/v1 | stable \\| EXPERIMENTAL |\n")
        label, _ = modul._label_at("r", zeile)
        self.assertEqual(label, "stable | EXPERIMENTAL")
        self.assertEqual(_load().status(True, label), "experimental")
        for text in ("| name | status |\n|---|---|\n| x/v10 | stable |\n", "| name |\n|---|\n| x/v1 |\n",
                     "x/v1 | stable\n"):
            with self.subTest(no_label=text):
                self.assertEqual(self._modul(text)._label_at("r", zeile), (None, None))

    def test_a_label_is_found_once_by_its_whole_name_or_not_at_all(self) -> None:
        """Thread 4224371692: the row key matched a prefix, so an earlier `... legacy` row gave its cell, and the first
        match won. A row key matches the whole first cell, and a pattern that finds a label in two blocks stops."""
        zeile = [("NOTES.md", ("row", r"x/v1", 1))]
        tabelle = "| name | status |\n|---|---|\n| x/v1 legacy | stable |\n| x/v1 | EXPERIMENTAL |\n"
        self.assertEqual(self._modul(tabelle)._label_at("r", zeile)[0], "EXPERIMENTAL")
        doppelt = "| name | status |\n|---|---|\n| x/v1 | stable |\n| x/v1 | EXPERIMENTAL |\n"
        with self.assertRaisesRegex(SystemExit, "not decided here"):
            self._modul(doppelt)._label_at("r", zeile)
        ueberschrift = [("NOTES.md", r"^(## promptfoo[^\n]*)")]
        with self.assertRaisesRegex(SystemExit, "not decided here"):
            self._modul("## promptfoo legacy\n\nold\n\n## promptfoo (adapter)\n")._label_at("r", ueberschrift)
        self.assertEqual(self._modul("## promptfoo (adapter)\n\n## lm-eval\n")._label_at("r", ueberschrift)[0],
                         "## promptfoo (adapter)", "control: one heading of the name is read")

    def test_the_status_reads_the_word_that_renders(self) -> None:
        cap = [("NOTES.md", r"^(the x capability[^\n]*)")]
        for text, erwartet in (("the x capability, exper&#105;mental\n", "experimental"),
                               ("the x capability, *experi*mental\n", "experimental"),
                               ("the x capability, no longer\nexperimental\n", "published"),
                               ("the x capability, stable\n", "published")):
            with self.subTest(text=text):
                label, _ = self._modul(text)._label_at("r", cap)
                self.assertEqual(_load().status(True, label), erwartet)

    def test_a_pin_and_a_provider_are_read_as_they_render(self) -> None:
        cap = {"id": "x", "provider": "actions/attest", "git_tag_from": r"uses: x@(\S+)",
               "label": [("NOTES.md", r"^(the x capability[^\n]*)")]}
        self.assertEqual(self._modul("the x capability, uses: x@v1&#46;2\n")._documented_tag("r", cap), "v1.2")
        self.assertEqual(self._modul("the x capability\n\n```\n- uses: x@v1&#46;2\n```\n")._documented_tag("r", cap),
                         "v1&#46;2", "control: a code block renders its content as written")
        self.assertTrue(self._modul("the x capability, from actions&#47;attest.\n")._names_provider("r", cap))
        self.assertTrue(self._modul("the x capability, from **actions/attest**.\n")._names_provider("r", cap))
        self.assertTrue(self._modul("the x capability, from `actions/attest`.\n")._names_provider("r", cap))

    def test_what_a_reader_cannot_decide_in_the_rendered_text_stops(self) -> None:
        cap = [("NOTES.md", r"^(the x capability[^\n]*)")]
        for text in ("the x capability, ~~experimental~~ stable\n", "the x capability ![experimental](badge.svg)\n",
                     "the x capability <b>stable</b>\n"):
            with self.subTest(text=text), self.assertRaisesRegex(SystemExit, "not decided here"):
                self._modul(text)._label_at("r", cap)

    def test_an_html_block_ends_a_passage_and_a_comment_does_not(self) -> None:
        cap = {"id": "x", "git_tag_from": r"uses: x@(\S+)", "label": [("NOTES.md", r"^(the x capability[^\n]*)")]}
        self.assertEqual(self._modul("the x capability\n\n<!-- note -->\n\n```\n- uses: x@v1\n```\n")
                         ._documented_tag("r", cap), "v1")
        with self.assertRaisesRegex(SystemExit, "pins no tag"):
            self._modul("the x capability\n\n<div>\nother\n</div>\n\n```\n- uses: x@v1\n```\n")._documented_tag("r", cap)

    def test_every_recorded_label_is_what_the_reader_reads_at_the_recorded_refs(self) -> None:
        """The labels in matrix.json are re-read here at the commits the file names, so a reader change that alters a
        label cannot leave the recorded data behind. Needs those commits in the checkout."""
        import subprocess
        d = json.loads(_MATRIX.read_text(encoding="utf-8"))
        koepfe = [d["tag_commit"], d["main_commit"]] + [z["main"]["branch"]["head"] for z in d["rows"]
                                                        if z["main"].get("branch")]
        if any(subprocess.run(["git", "-C", str(REPO), "cat-file", "-e", f"{k}^{{commit}}"]).returncode for k in koepfe):
            self.skipTest("the commits matrix.json names are not in this checkout")
        modul = _load()
        caps = {c["id"]: c for c in modul.CAPABILITIES}
        for z in d["rows"]:
            kopf = z["main"]["branch"]["head"] if z["main"].get("branch") else d["main_commit"]
            with self.subTest(row=z["id"]):
                self.assertEqual(modul._label_at(d["tag_commit"], caps[z["id"]]["label"])[0], z["release"]["label"])
                self.assertEqual(modul._label_at(kopf, caps[z["id"]]["label"])[0], z["main"]["label"])


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

    _CLI = _cli('    sub.add_parser("verify")\n').encode()

    def _artefakte(self, d: Path, *, pypi_digest=None, am_tag=_CLI):
        modul = _load()
        rad = d / "proofbundle-6.1.0-py3-none-any.whl"
        with zipfile.ZipFile(rad, "w") as z:
            z.writestr("proofbundle/__init__.py", b"")
            z.writestr("proofbundle/cli.py", self._CLI)
            z.writestr("proofbundle-6.1.0.dist-info/entry_points.txt",
                       "[console_scripts]\nproofbundle = proofbundle.cli:main\n")
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
        am_tag_dateien = {"src/proofbundle/cli.py": am_tag, "src/proofbundle/__init__.py": b""}
        modul._git_bytes = lambda ref, pfad: am_tag_dateien.get(pfad)
        return modul, {"urls": urls}

    def test_consistent_artifacts_are_measured(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            modul, pypi = self._artefakte(Path(tmp))
            ergebnis = modul.measure_artifacts(Path(tmp), pypi)
            self.assertEqual(modul.provenance_problems(ergebnis), [])
            self.assertEqual(ergebnis["wheel_against_tag"], {"identical": 2, "different": [], "absent_at_tag": []})
            # the wheel's console script was run, after its provenance held, and its parser read
            self.assertEqual(ergebnis["wheel_subcommands"], ["verify"])
            self.assertEqual(ergebnis["wheel_entry_points"], ["console_scripts:proofbundle"])

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


def _registry_suffix(z: dict) -> str:
    zahlen = z["release"]["measured"].get("parity_registry_at_tag")
    return _load()._registry_text(zahlen) if zahlen else ""


class TheReadmeTablesAreTheData(unittest.TestCase):
    def test_every_label_cell_renders_the_label_it_was_read_as(self) -> None:
        """A label is rendered text (thread 4222919983), and written back into the Markdown table it must render as
        that text again: a `*`, `_`, `[` or `<` in it would otherwise start Markdown in the cell. The table is parsed
        by the reader the docs are read with, and each release cell is its status and the label, as recorded."""
        modul = _load()
        d = json.loads(_MATRIX.read_text(encoding="utf-8"))
        zeilen = {}
        for z in d["rows"]:
            z = json.loads(json.dumps(z))
            z["release"]["label"] = (z["release"]["label"] or "x") + " *a* _b_ [c] <d> &amp; `e` ~~f~~ | g \\ h"
            zeilen[z["name"]] = z
        tabelle = modul.render_table(dict(d, rows=list(zeilen.values())))
        modul._git_bytes = lambda ref, pfad: tabelle.encode()
        gelesen = [zellen for art, _e, _t, zellen in modul._bloecke("r", "README.md") if art == "row"][1:]
        self.assertEqual(len(gelesen), len(zeilen))
        gezeigt = 0
        for name, _kanal, zelle, *_rest in gelesen:
            z = zeilen[name]
            if z["release"]["status"] == "absent":
                continue                                    # an absent cell shows no label
            erwartet = z["release"]["status"] + " — " + re.sub(r"^#+ ", "", z["release"]["label"])
            with self.subTest(row=z["id"]):
                # the cell is the status and the label, then at most the parity registry's counts
                self.assertTrue(zelle.startswith(erwartet), zelle)
                self.assertIn(zelle[len(erwartet):], ("", _registry_suffix(z)))
                gezeigt += 1
        self.assertGreaterEqual(gezeigt, 10, "control: most release cells show a label")

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
