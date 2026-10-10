"""Contract for the release-body renderer.

THE STRONGEST CASE IN THIS FILE is the last one: rendering the real 6.1.0 source reproduces the
owner-reviewed body BYTE FOR BYTE. A renderer tested only against fixtures it also shaped proves
that it is self-consistent; measured against a body a human wrote independently, it proves that the
source and the renderer together say what the human said.

WHY GROUPING COMES FROM A SOURCE AND NOT FROM A TITLE PREFIX, pinned by a case below and measured
over all 48 entries rather than asserted: five prefixes span more than one group in this release,
and ``fix`` alone spans three. So the grouping is a reviewed decision in ``release-source.json``
and the renderer never infers it.
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SKRIPT = REPO / "scripts" / "render_release.py"
QUELLE = REPO / "release_notes" / "release-source.json"

# THE PATH FORM, NOT A BLANK IMPORT, and the house had already decided this before I arrived.
# `render_release.py` is deliberately NOT in the sdist: `MANIFEST.in` names every shipped `scripts/`
# file one by one, by owner requirement of 2026-09-06, and a release-notes renderer is a maintainer
# tool no consumer of the package needs. Measured on 2026-09-24, the hermetic cleanroom job installed
# the extracted sdist, ran `pytest --collect-only`, hit this module's blank `import render_release`
# and exited 2. A check that cannot START is not a check that fails on its subject.
#
# MY FIRST FIX WAS A MODULE-LEVEL `pytest.skip`, AND IT WAS THE WRONG ONE. The full suite then failed
# `tests/test_kein_blanker_import_eines_nicht_ausgelieferten.py`, which is the class guard for exactly
# this and prescribes the path form: with `spec_from_file_location` the module name carries its
# directory, so `conftest` can recognise the file as not-shipped and report an honest SKIP instead of
# every module inventing its own. I built a neighbour rule without first looking for the rule that
# was already there.
_spec = importlib.util.spec_from_file_location("_render_release", SKRIPT)
_rr = importlib.util.module_from_spec(_spec)
sys.modules["_render_release"] = _rr
_spec.loader.exec_module(_rr)
lade, pruefe, rendere = _rr.lade, _rr.pruefe, _rr.rendere


def _fahre(*args: str) -> subprocess.CompletedProcess:
    """The CLI, with the tree binding satisfied unless a case sets it itself.

    WHY THE HELPER STATES THE HEAD. Since 2026-09-23 the render refuses when the tree it runs in is
    not the tree the source describes, which is the point of that check and correct here: these cases
    run on a branch that sits beyond the release tag. A case about anything ELSE should not be
    measuring that, so the helper passes the declared commit; the cases that ARE about the binding
    pass their own `--kopf` and are named accordingly.
    """
    vorgabe = () if any(x == "--kopf" for x in args) else ("--kopf", _erklaerter_kopf())
    return subprocess.run([sys.executable, str(SKRIPT), *args, *vorgabe],
                          capture_output=True, text=True, timeout=60)


def _quelle() -> dict:
    return json.loads(QUELLE.read_text(encoding="utf-8"))


def _erklaerter_kopf() -> str:
    return _quelle()["release_commit"]


def _version() -> str:
    """The version the source in this tree declares.

    THE CASES READ IT RATHER THAN TYPING 6.1.0. Every source is bound to one version on purpose, so
    the next release replaces this file and its reviewed body under `release_notes/`. Cases that
    typed the version would then have to change in the same commit, and the commit that carries the
    notes may change nothing outside `release_notes/` (`render_release.liefert_dasselbe_paket`).
    What the cases assert stays the same: the declared version renders, another one is refused."""
    return _quelle()["version"]


def _marke() -> str:
    """The heading only a body of the source's own form carries, so a case reads the form instead of
    assuming it. The grouped form of 6.1.0 and 6.2.0 lists its pull requests under `## All changes`;
    the two-level form of 6.2.1 opens with `## Highlights` and has no such list."""
    return "## Highlights" if _quelle().get("form") == "zwei_ebenen" else "## All changes"


def _gruppiert() -> dict:
    """A source of the grouped form that shares nothing with a released one.

    THE GROUP CASES MEASURED THE REAL SOURCE, and from 6.2.1 the real source has no groups. The rules
    for groups stay in the renderer for every grouped source, so their cases measure one here, the
    same synthetic source the cases without the golden body already use."""
    return DerRendererWirdAuchOHNEDieGoldeneVorlageGEMESSEN._synthetisch(None)


class DieVersionsbindungIstKeineHoeflichkeit(unittest.TestCase):
    """A source carries statements measured for ONE tree. Reusing them is a false claim."""

    def test_fang_falsche_version_wird_abgewiesen(self):
        r = _fahre("--version", _version() + ".9")
        self.assertEqual(r.returncode, 2)
        self.assertIn("refusing", r.stderr)
        self.assertNotIn(_marke(), r.stdout, "nothing may be rendered on a refusal")

    def test_fang_fehlende_quelle_wird_abgewiesen(self):
        r = _fahre("--version", _version(), "--quelle", "/nonexistent/source.json")
        self.assertEqual(r.returncode, 2)

    def test_gegenrichtung_die_erklaerte_version_rendert(self):
        """WITHOUT THIS CASE a renderer that refuses everything would pass both catches above."""
        r = _fahre("--version", _version())
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(_marke(), r.stdout)


class DieQuelleNANNTEDenBaumUndNichtsVerglichIhn(unittest.TestCase):
    """THE RECORDED COMMIT WAS NOT A BINDING until something compared it.

    Codex, review of 2026-09-23 on this pull request. `release_commit` had always carried the commit
    the 48 entries describe, and the render bound the VERSION and never the TREE. Measured on this
    branch at the time: HEAD sat 12 commits beyond `dcac5aee`, including the first-parent merges
    #245, #247 and #253, the source names none of the three, and the render exited 0 regardless. The
    workflow triggers on a tag push, so a tag pushed from such a tree would ship those descendants
    while publishing detail links for the older one.

    It is the same class as the digest this pull request already closed one layer up, where a sha256
    was written and nothing ran `sha256sum -c` over it. A value nobody compares is not a binding.
    """

    def test_fang_ein_fremder_baum_wird_abgewiesen(self):
        r = _fahre("--version", _version(), "--kopf", "0" * 40)
        self.assertEqual(r.returncode, 2, r.stdout)
        self.assertIn("different tree than the artefacts", r.stderr)
        self.assertIn(_erklaerter_kopf()[:12], r.stderr, "the refusal must name the declared tree")
        self.assertNotIn(_marke(), r.stdout, "nothing may be rendered on a refusal")

    def test_gegenrichtung_der_erklaerte_baum_rendert(self):
        """WITHOUT THIS a check that refuses every tree would pass the catch above."""
        r = _fahre("--version", _version(), "--kopf", _erklaerter_kopf())
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(_marke(), r.stdout)

    def test_fang_eine_quelle_ohne_release_commit_kann_den_baum_nicht_nennen(self):
        d = _quelle()
        d.pop("release_commit", None)
        befunde = pruefe(d, kopf="a" * 40)
        self.assertTrue(any("release_commit" in b for b in befunde), befunde)

    def test_ohne_gemessenen_kopf_wird_die_bindung_NICHT_still_uebersprungen(self):
        """The honest half of the design, stated as a case rather than as a comment.

        `pruefe` without a head does not check the binding, because a caller that cannot measure the
        tree has nothing to compare. That is only safe because the CLI always supplies one, and
        `kopf_des_baums` returning None is itself treated as a finding by the check. This case pins
        that second half: an unmeasurable tree is a refusal, not a pass.
        """
        self.assertEqual(pruefe(_quelle()), [], "no head given means the binding is not measured")
        befunde = pruefe({**_quelle(), "release_commit": "kurz"}, kopf="b" * 40)
        self.assertTrue(befunde, "a malformed release_commit with a measured head must be refused")


class JederPullRequestGenauEinmal(unittest.TestCase):
    """A number in two groups makes the total larger than the set, and the total is what a reader
    takes for the size of the release."""

    def test_fang_ein_pr_in_zwei_gruppen(self):
        d = _gruppiert()
        doppelt = dict(d["gruppen"][0]["eintraege"][0])
        d["gruppen"][1]["eintraege"].append(doppelt)
        befunde = pruefe(d)
        self.assertTrue(any(f"#{doppelt['nr']}" in b for b in befunde), befunde)

    def test_fang_ein_eintrag_ohne_originaltitel(self):
        """The short form must not be the only thing that survives."""
        d = _gruppiert()
        d["gruppen"][0]["eintraege"][0]["originaltitel"] = ""
        self.assertTrue(any("originaltitel" in b for b in pruefe(d)))

    def test_fang_eine_fehlende_gruppe(self):
        d = _gruppiert()
        weg = d["gruppen"].pop()
        self.assertTrue(any(weg["name"] in b for b in pruefe(d)))

    def test_fang_eine_unbekannte_gruppe(self):
        """An unknown group would be rendered and silently widen the release's shape."""
        d = _gruppiert()
        d["gruppen"].append({"name": "Other", "eintraege": []})
        self.assertTrue(any("does not know" in b for b in pruefe(d)))

    def test_gegenrichtung_die_echte_quelle_hat_keine_befunde(self):
        """WITHOUT THIS CASE a check that reports findings for everything would pass above. The
        grouped source is the one the catches above plant their defects in; the real one is measured
        as well, whatever its form."""
        self.assertEqual(pruefe(_gruppiert()), [])
        self.assertEqual(pruefe(_quelle()), [])

    def test_jeder_pull_request_genau_einmal_und_so_viele_wie_die_gepruefte_vorlage_nennt(self):
        """The count comes from the reviewed body, not from a number typed here. The case said 48, the
        count of 6.1.0; a typed count would have to change with the next source, in a commit that may
        change nothing outside `release_notes/`. The reviewed body states its own count ("N pull
        requests, grouped by area"), written by a human independently of this renderer."""
        import re
        d = _quelle()
        vorlage = REPO / "release_notes" / f"RELEASE_NOTES_v{_version()}.md"
        if d.get("form") == "zwei_ebenen":
            # THE SAME RULE IN THE OTHER FORM: the reviewed body states how many fixes it lists, and
            # the source must carry exactly that many.
            if not vorlage.is_file():
                self.skipTest("NOT MEASURED: the reviewed body is not in the tree")
            m = re.search(r"<summary>All (\d+) fix(?:es)?, one line each",
                          vorlage.read_text(encoding="utf-8"))
            self.assertIsNotNone(m, "the reviewed body names no count of fixes")
            self.assertEqual(len(d["fixes"]), int(m.group(1)))
            return
        nummern = [e["nr"] for g in d["gruppen"] for e in g["eintraege"]]
        self.assertEqual(len(nummern), len(set(nummern)), "a pull request appears twice")
        if not vorlage.is_file():
            self.skipTest("NOT MEASURED: the reviewed body is not in the tree")
        m = re.search(r"^(\d+) pull requests, grouped by area", vorlage.read_text(encoding="utf-8"), re.M)
        self.assertIsNotNone(m, "the reviewed body names no count of pull requests")
        self.assertEqual(len(nummern), int(m.group(1)))


class DasTitelpraefixGruppiertNicht(unittest.TestCase):
    """Measured on this release, not asserted in prose."""

    def test_praefixe_verteilen_sich_ueber_mehrere_gruppen(self):
        """THE PROPERTY over the whole set, not over two hand-picked numbers.

        An earlier version of this case named #214 and #231 and asserted both start with `fix`.
        That was guessed rather than measured, and it was wrong — the case failed on its first run.
        Measured over all 48 entries: five prefixes span more than one group, and `fix` alone spans
        three. That is the real statement, and it is stronger than the guess.
        """
        import re
        from collections import defaultdict
        d = _quelle()
        if d.get("form") == "zwei_ebenen":
            self.skipTest("NOT APPLICABLE: the source in this tree is of the two-level form, which "
                          "lists fixes and groups nothing; the spread was measured on 6.1.0 and 6.2.0")
        nach_praefix = defaultdict(set)
        for g in d["gruppen"]:
            for e in g["eintraege"]:
                m = re.match(r"^([a-z]+)", e["originaltitel"])
                if m:
                    nach_praefix[m.group(1)].add(g["name"])
        geteilt = {p: gs for p, gs in nach_praefix.items() if len(gs) > 1}
        self.assertTrue(
            geteilt,
            "if no prefix ever spanned two groups, the prefix COULD be the grouping rule and this "
            "renderer would be solving a problem that does not exist")
        self.assertIn("fix", geteilt, "measured 2026-09-23: `fix` spans three groups")

    def test_gegenrichtung_die_gruppen_sind_nicht_alle_gleich(self):
        """WITHOUT THIS CASE the assertion above would also hold for a source with ONE group."""
        d = _quelle()
        if d.get("form") == "zwei_ebenen":
            self.skipTest("NOT APPLICABLE: the source in this tree is of the two-level form")
        self.assertGreater(len({g["name"] for g in d["gruppen"]}), 1)


class DerLaufIstDeterministisch(unittest.TestCase):

    def test_zwei_laeufe_sind_bitgleich(self):
        a = rendere(lade(QUELLE, _version()))
        b = rendere(lade(QUELLE, _version()))
        self.assertEqual(a, b)


class DasGerenderteIstDerVomOwnerGEPRUEFTEBody(unittest.TestCase):
    """THE CASE THIS FILE EXISTS FOR.

    The body in ``release_notes/RELEASE_NOTES_v6.1.0.md`` was written and reviewed by a human,
    independently of this renderer. If the render ever stops matching it byte for byte, either the
    source drifted from the reviewed text or the renderer changed its shape — and both are things a
    reader of the published note would never see.
    """

    def test_bytegleich_mit_der_gepruefte_vorlage(self):
        vorlage = REPO / "release_notes" / f"RELEASE_NOTES_v{_version()}.md"
        if not vorlage.is_file():
            self.skipTest("the reviewed body is not in the tree")
        self.assertEqual(rendere(lade(QUELLE, _version())),
                         vorlage.read_text(encoding="utf-8"),
                         "the render no longer reproduces the reviewed body")


if __name__ == "__main__":
    unittest.main()


class DerRendererWirdAuchOHNEDieGoldeneVorlageGEMESSEN(unittest.TestCase):
    """An adversarial counter-reading called the byte-identity case a partial circle, and it was
    half right.

    The source was extracted FROM the reviewed body, so a renderer bug could in principle have been
    compensated by the extraction. What the extraction pulled is semantic — group names, short
    forms, pull request numbers — while the layout came from reading the body, so byte identity
    still says the layout was read correctly. But that argument is an argument, and these cases are
    a measurement: the renderer is exercised here against a SYNTHETIC source that shares nothing
    with 6.1.0, so its structural behaviour is checked without the golden output.
    """

    def _synthetisch(self) -> dict:
        eintraege = lambda n, s: [  # noqa: E731 — a fixture builder, not production code
            {"nr": i, "kurz": f"Do thing {i}", "originaltitel": f"feat: thing {i}",
             "autor": "someone", "url": f"https://example.test/pull/{i}"}
            for i in range(s, s + n)]
        return {
            "schema": "b7n0de.release_source.v1", "version": "9.9.9",
            "vorheriger_tag": "v9.9.8", "tag": "v9.9.9",
            "release_commit": "0" * 40, "readme_commit": "1" * 40,
            "kopfsatz": "A synthetic release. **Beta. Closing audit not run.**",
            "was_sich_aenderte": [{"bereich": "Area", "aenderung": "Change", "beleg": "Evidence"}],
            "vor_dem_upgrade": [{"titel": "Thing.", "text": "Some consequence."}],
            "auditstatus": "Nothing was audited here.",
            "gruppen": [
                {"name": "Verifier and receipt formats", "eintraege": eintraege(1, 1)},
                {"name": "Build, CI and test infrastructure", "eintraege": eintraege(2, 10)},
                {"name": "Audit and evidence", "eintraege": eintraege(1, 20)},
                {"name": "Documentation and interoperability", "eintraege": eintraege(1, 30)},
                {"name": "Dependencies", "eintraege": eintraege(1, 40)},
            ],
            "danke": ["someone"],
        }

    def test_die_struktur_stimmt_ohne_jede_6_1_0_beruehrung(self):
        d = self._synthetisch()
        self.assertEqual(pruefe(d), [])
        text = rendere(d)
        self.assertIn("6 pull requests, grouped by area", text)
        self.assertEqual(text.count("<details>"), 6, "five groups plus the audit block")
        self.assertEqual(text.count("</details>"), 6)
        self.assertIn("Verifier and receipt formats · 1 pull request</summary>", text)
        self.assertIn("Build, CI and test infrastructure · 2 pull requests</summary>", text)
        self.assertNotIn("6.1.0", text, "a synthetic render must not carry 6.1.0 anywhere")

    def test_der_zaehler_folgt_der_quelle_und_nicht_einer_konstanten(self):
        """Change the source, the count changes. A hard-coded 48 would survive this."""
        d = self._synthetisch()
        d["gruppen"][1]["eintraege"].pop()
        self.assertIn("5 pull requests, grouped by area", rendere(d))

    def test_einzahl_und_mehrzahl_folgen_der_zahl(self):
        d = self._synthetisch()
        text = rendere(d)
        self.assertIn("· 1 pull request<", text)
        self.assertIn("· 2 pull requests<", text)


class DieVerweigerungIstDASVerhaltenUndKeinUnfall(unittest.TestCase):
    """The same counter-reading asked what breaks on a tag like v6.1.0-rc1. Measured: nothing
    breaks — it REFUSES, which is the designed outcome. A release candidate that has no source
    written for it must not be published under the statements of another tree."""

    def test_ein_rc_tag_ohne_eigene_quelle_wird_abgewiesen(self):
        r = _fahre("--version", _version() + "-rc1")
        self.assertEqual(r.returncode, 2)
        self.assertIn(_version() + "-rc1", r.stderr)

    def test_ein_versehentlich_mitgeschlepptes_v_wird_abgewiesen(self):
        """`${GITHUB_REF_NAME#v}` strips ONE leading v; a source that kept it would not match."""
        r = _fahre("--version", "v" + _version())
        self.assertEqual(r.returncode, 2)


class DieDoppelungDerGruppennamenIstDieRATSCHE(unittest.TestCase):
    """Named rather than removed, and pinned so the reason survives the next reader.

    If `pruefe` read the group set from the source instead of from `ERWARTETE_GRUPPEN`, a source
    that had lost four of five groups would pass every check — it would be measured against itself.
    """

    def test_fang_eine_quelle_mit_nur_einer_gruppe_faellt(self):
        d = _gruppiert()
        d["gruppen"] = d["gruppen"][:1]
        befunde = pruefe(d)
        self.assertTrue(befunde, "a source reduced to one group must not pass")
        self.assertTrue(any("missing" in b for b in befunde), befunde)

    def test_die_reihenfolge_kommt_aus_der_quelle_nicht_aus_der_konstanten(self):
        """Membership is decided by the constant, ORDER by the source."""
        d = _gruppiert()
        d["gruppen"] = list(reversed(d["gruppen"]))
        self.assertEqual(pruefe(d), [], "reordering is not a structural finding")
        text = rendere(d)
        zuerst = text.split("## All changes", 1)[1].split("<summary>", 1)[1].split(" ·", 1)[0]
        self.assertEqual(zuerst, "Dependencies", "the render followed the source order")

    def test_ein_zweites_mal_derselbe_gruppenname_faellt(self):
        """A MEMBERSHIP CHECK DOES NOT COUNT, and the two checks above are membership checks.

        Codex, review of 2026-09-23 on this pull request. Appending a second empty group whose name
        is ALREADY KNOWN passes both of them: nothing is missing, nothing is unknown. Reproduced
        before the fix, `pruefe` returned no findings, the CLI exited 0, and the rendered note carried
        that section twice — measured as two occurrences of the group heading in the output.

        The five groups ARE the declared boundary of the release, so a sixth section widens what the
        note claims to cover. The shape was already correct one level down, where pull-request numbers
        are COUNTED rather than tested for membership; this is that rule at the group level.
        """
        d = _gruppiert()
        zweite = dict(d["gruppen"][0])
        zweite["eintraege"] = []
        d["gruppen"] = list(d["gruppen"]) + [zweite]
        befunde = pruefe(d)
        self.assertTrue(any("more than once" in b for b in befunde), befunde)
        self.assertTrue(any(d["gruppen"][0]["name"] in b for b in befunde),
                        f"the finding must name the duplicated group: {befunde}")

    def test_fang_die_unveraenderte_quelle_bleibt_ohne_befund(self):
        """THE COUNTER-DIRECTION for the line above. A duplicate check that fires on the real
        source would refuse every release, and a case that only ever sees the planted defect cannot
        tell a working check from one that reports everything."""
        self.assertEqual(pruefe(_gruppiert()), [],
                         "an unchanged grouped source must still pass, or the duplicate rule is too wide")
        self.assertEqual(pruefe(_quelle()), [],
                         "the real source must still pass, or the duplicate rule is too wide")


def _baum_mit_quelle(wurzel: Path, schreib_fremdes: bool = False, eltern_zurueck: int = 1) -> Path:
    """A throwaway repository: the renderer as it is, a base commit X, then the commit S that carries a
    source naming X (or an older commit, `eltern_zurueck` steps back). With `schreib_fremdes` S also
    changes a file outside `release_notes/`. Returns the root; HEAD is S."""
    import os
    import shutil
    (wurzel / "scripts").mkdir(parents=True)
    (wurzel / "release_notes").mkdir()
    shutil.copy2(SKRIPT, wurzel / "scripts" / "render_release.py")
    (wurzel / "code.txt").write_text("the tree the notes describe\n", encoding="utf-8")
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)

    def git(*a: str) -> str:
        return subprocess.run(["git", "-C", str(wurzel), "-c", "user.name=t", "-c", "user.email=t@t",
                               "-c", "commit.gpgsign=false", *a], check=True, capture_output=True,
                              text=True, env=env, timeout=60).stdout.strip()

    git("init", "-q")
    git("add", "-A")
    git("commit", "-qm", "base")
    for i in range(eltern_zurueck - 1):
        (wurzel / "code.txt").write_text(f"a later change {i}\n", encoding="utf-8")
        git("commit", "-qam", f"later {i}")
    beschrieben = git("rev-parse", f"HEAD~{eltern_zurueck - 1}")
    quelle = DerRendererWirdAuchOHNEDieGoldeneVorlageGEMESSEN._synthetisch(None)
    quelle["release_commit"] = beschrieben
    (wurzel / "release_notes" / "release-source.json").write_text(json.dumps(quelle, indent=2),
                                                                  encoding="utf-8")
    if schreib_fremdes:
        (wurzel / "code.txt").write_text("changed in the carrier commit\n", encoding="utf-8")
    git("add", "-A")
    git("commit", "-qm", "the source for 9.9.9")
    return wurzel


def _render_im(wurzel: Path) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(wurzel / "scripts" / "render_release.py"),
                           "--version", "9.9.9", "--aus", str(wurzel / "notes.md")],
                          capture_output=True, text=True, timeout=60, cwd=str(wurzel))


class DerGetaggteCommitKannSichNichtSelbstNennen(unittest.TestCase):
    """THE SOURCE CANNOT NAME THE COMMIT THAT CARRIES IT, and the release workflow asked it to.

    `release.yml` renders the body in the checkout of the tag, and the render refused unless the
    source's `release_commit` was that checkout's HEAD. The source is a file of the tagged commit, and
    a commit cannot hold its own id: measured on 2026-09-28 in a throwaway repository, three times
    writing HEAD into the source and committing gave three new heads and three refusals, exit 2. So
    no release after 6.1.0 could pass that step. The binding stays, and it now reads what it can
    mean: the tagged commit is the one that carries the notes, directly on top of the tree they
    describe, and changes nothing else. The house draws the same line for the tree digest, where
    `MUTABLE_EVIDENCE_RELS` keeps the evidence out of the tree it binds.
    """

    def test_RED_der_traeger_direkt_ueber_dem_beschriebenen_baum_rendert(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            r = _render_im(_baum_mit_quelle(Path(d)))
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_fang_ein_traeger_der_auch_code_aendert_wird_abgewiesen(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            r = _render_im(_baum_mit_quelle(Path(d), schreib_fremdes=True))
        self.assertEqual(r.returncode, 2, r.stdout)
        self.assertIn("outside release_notes/", r.stderr)

    def test_fang_eine_quelle_die_einen_aelteren_baum_nennt_wird_abgewiesen(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            r = _render_im(_baum_mit_quelle(Path(d), eltern_zurueck=2))
        self.assertEqual(r.returncode, 2, r.stdout)
        self.assertIn("different tree than the artefacts", r.stderr)


class EinUngemessenerKopfIstKeinPassenderKopf(unittest.TestCase):
    """THE DOCSTRING SAID IT AND THE CLI DID NOT DO IT. `kopf_des_baums` returns None when the tree
    cannot be measured, "and the caller treats it as a finding". The CLI passed that None to `pruefe`,
    which checks the binding only when a head is given, so a render outside a git checkout skipped
    the binding and exited 0: measured on 2026-09-28 with the source of 6.1.0, 48 pull requests
    rendered. A head that cannot be read is not a head that matches."""

    def test_RED_ohne_git_verweigert_der_render(self):
        import shutil
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            w = Path(d)
            (w / "scripts").mkdir()
            (w / "release_notes").mkdir()
            shutil.copy2(SKRIPT, w / "scripts" / "render_release.py")
            shutil.copy2(QUELLE, w / "release_notes" / "release-source.json")
            r = subprocess.run([sys.executable, str(w / "scripts" / "render_release.py"),
                                "--version", _version(), "--aus", str(w / "n.md")],
                               capture_output=True, text=True, timeout=60, cwd=str(w))
        self.assertEqual(r.returncode, 2, r.stdout)
        self.assertIn("cannot be measured", r.stderr)


class DieNotizFolgtDerVersionUndNichtDer610(unittest.TestCase):
    """THE KNOWN-LIMITATIONS LINK WAS 6.1.0's. `rendere` wrote `RESTRISIKO_610.md` into every body, so
    a 6.2.0 source would have published a link to the residual-risk record of the release before it.
    The record is named after its version, `RESTRISIKO_<digits of the version>.md`, and the link is
    now derived from the source's version. The golden 6.1.0 body stays byte for byte (the case above)."""

    def test_RED_eine_andere_version_verlinkt_ihr_eigenes_restrisiko(self):
        d = DerRendererWirdAuchOHNEDieGoldeneVorlageGEMESSEN._synthetisch(None)
        text = rendere(d)
        self.assertIn("/RESTRISIKO_999.md)", text)
        self.assertNotIn("RESTRISIKO_610", text)


class DerSicherheitsabschnittIstOptionalUndVollstaendig(unittest.TestCase):
    """OWNER DECISION OF 2026-09-28 (Z296, option A): the 6.2.0 notes name, for each finding in the
    released versions, the affected versions, the effect and what fixes it. The source carries that as
    `sicherheit`; a source without it renders as before, so 6.1.0 does not move. A section with an
    incomplete row is refused, because a finding without its affected versions tells a user nothing
    they can act on."""

    def _mit_sicherheit(self) -> dict:
        d = DerRendererWirdAuchOHNEDieGoldeneVorlageGEMESSEN._synthetisch(None)
        d["sicherheit"] = {
            "titel": "Security fixes for 9.9.8",
            "einleitung": "Measured on the released tree. **Upgrade to 9.9.9.**",
            "zeilen": [{"befund": "A thing that verified", "betroffen": "9.9.8",
                        "wirkung": "It answered ok.", "behoben": "[#1](https://example.test/pull/1)"}],
            "schluss": "The measurements are in the record."}
        return d

    def test_RED_der_abschnitt_steht_vor_what_changed(self):
        text = rendere(self._mit_sicherheit())
        self.assertIn("## Security fixes for 9.9.8", text)
        self.assertIn("| Finding | Affected | Effect | Fixed by |", text)
        self.assertIn("| **A thing that verified** | 9.9.8 | It answered ok. | "
                      "[#1](https://example.test/pull/1) |", text)
        self.assertLess(text.index("## Security fixes"), text.index("## What changed"))
        self.assertEqual(pruefe(self._mit_sicherheit()), [])

    def test_fang_eine_zeile_ohne_betroffene_versionen_wird_abgewiesen(self):
        d = self._mit_sicherheit()
        d["sicherheit"]["zeilen"][0]["betroffen"] = ""
        self.assertTrue(any("betroffen" in b for b in pruefe(d)), pruefe(d))

    def test_ohne_abschnitt_rendert_nichts_davon(self):
        text = rendere(DerRendererWirdAuchOHNEDieGoldeneVorlageGEMESSEN._synthetisch(None))
        self.assertNotIn("## Security fixes", text)


class DieKetteDes610ReleaseMussRendern(unittest.TestCase):
    """THE ONE-CARRIER RULE WAS TOO NARROW, measured against the release it would have to serve.

    `v6.1.0` points at `dcac5aee`, a MERGE commit (pull request 244, the receipt ceremony) whose first
    parent is the frozen head `618f4b4b`; between them lie only files under `audit_artifacts/`. A
    rule that accepts one single-parent carrier changing only `release_notes/` refuses that shape.
    What the binding means is that the tagged tree ships the package the notes describe: the
    described commit is an ancestor of HEAD, and everything between them lies under paths the package
    does not ship (`release_notes/`, which MANIFEST.in never lists, and `audit_artifacts/`, which it
    prunes)."""

    def test_RED_ein_merge_mit_belegen_ueber_dem_beschriebenen_baum_rendert(self):
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            w = _baum_mit_quelle(Path(d))
            env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
            env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)

            def git(*a: str) -> str:
                return subprocess.run(["git", "-C", str(w), "-c", "user.name=t", "-c",
                                       "user.email=t@t", "-c", "commit.gpgsign=false", *a],
                                      check=True, capture_output=True, text=True, env=env,
                                      timeout=60).stdout.strip()

            git("checkout", "-q", "-b", "beleg", "HEAD")
            (w / "audit_artifacts").mkdir()
            (w / "audit_artifacts" / "pre_tag_receipt.json").write_text("{}\n", encoding="utf-8")
            git("add", "-A")
            git("commit", "-qm", "receipt")
            git("checkout", "-q", "-")
            git("merge", "-q", "--no-ff", "-m", "merge the receipt", "beleg")
            r = _render_im(w)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_RED_zwei_traeger_nacheinander_rendern(self):
        """The notes, then the evidence: two single-parent commits over the described tree."""
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            w = _baum_mit_quelle(Path(d))
            env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
            env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
            (w / "audit_artifacts").mkdir()
            (w / "audit_artifacts" / "soak.json").write_text("{}\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(w), "-c", "user.name=t", "-c", "user.email=t@t",
                            "-c", "commit.gpgsign=false", "commit", "-qam", "x", "--allow-empty"],
                           check=True, capture_output=True, env=env, timeout=60)
            subprocess.run(["git", "-C", str(w), "-c", "user.name=t", "-c", "user.email=t@t",
                            "-c", "commit.gpgsign=false", "add", "-A"], check=True, env=env)
            subprocess.run(["git", "-C", str(w), "-c", "user.name=t", "-c", "user.email=t@t",
                            "-c", "commit.gpgsign=false", "commit", "-qm", "evidence"],
                           check=True, capture_output=True, env=env, timeout=60)
            r = _render_im(w)
        self.assertEqual(r.returncode, 0, r.stderr)


def _zwei_ebenen() -> dict:
    """A two-level source that shares nothing with a released one."""
    return {
        "schema": "b7n0de.release_source.v1", "form": "zwei_ebenen", "version": "9.9.9",
        "vorheriger_tag": "v9.9.8", "tag": "v9.9.9", "release_commit": "0" * 40,
        "kopfsatz": "**A synthetic update for everyone on 9.9.8.** Two checks refuse more.",
        "highlights": [{"kern": "One.", "text": "The first thing is safer."},
                       {"kern": "Two.", "text": "The second thing is safer."},
                       {"kern": "Three.", "text": "The third thing is safer."}],
        "selbst_pruefen": ("How to check it is in "
                           "[Verifying](RELEASE.md#verifying-a-published-release-anyone)."),
        "nicht_bewiesen": "A valid signature does not make a reported result true.",
        "fixes": ["**A first input is refused.** `first` refuses it.",
                  "**A second input is refused.** `second` refuses it."],
        "restrisiko": "RESTRISIKO_998.md",
        "weitere_links": [{"text": "example.test", "url": "https://example.test"}],
        "schlusssatz": "Created for a test.",
    }


class DieZweiEbenenForm(unittest.TestCase):
    """OWNER DECISION OF 2026-10-09: from 6.2.1 the release page reads in two levels. On top one
    sentence on what the release brings, the install line, three or four highlights, how to verify it
    and what a receipt does not prove; further down every fix as its CHANGELOG line; the links and
    a closing sentence at the end. The page names no internal process."""

    def test_RED_die_seite_steht_in_dieser_reihenfolge(self):
        d = _zwei_ebenen()
        self.assertEqual(pruefe(d), [])
        text = rendere(d)
        self.assertTrue(text.startswith("**A synthetic update for everyone on 9.9.8.**"), text[:80])
        orte = [text.index(s) for s in (
            "python -m pip install --upgrade proofbundle==9.9.9", "## Highlights",
            "- **One.** The first thing is safer.", "## Verify this release yourself",
            "## What a receipt still does not prove", "## Details",
            "<summary>All 2 fixes, one line each, as in the CHANGELOG</summary>",
            "- **A first input is refused.** `first` refuses it.", "[Full changelog]",
            "[example.test](https://example.test)", "Created for a test.")]
        self.assertEqual(orte, sorted(orte), "the sections are out of order")
        self.assertTrue(text.endswith("\n\nCreated for a test.\n"), text[-60:])
        self.assertNotIn("## All changes", text, "the two-level page has no list of pull requests")
        self.assertEqual(text.count("<details>"), 1)
        self.assertEqual(text.count("</details>"), 1)

    def test_RED_die_installzeile_folgt_der_version_der_quelle(self):
        """The line is built from the version, so the source carries no pin of its own: a pin in the
        source would be one more file the version gate's sweep has to hold in step."""
        d = _zwei_ebenen()
        d["version"] = "9.9.10"
        self.assertIn("proofbundle==9.9.10\n", rendere(d))

    def test_RED_ein_relativer_link_wird_an_den_beschriebenen_commit_gebunden(self):
        """A relative link on a release page resolves against the page, not the repository."""
        text = rendere(_zwei_ebenen())
        basis = "](https://github.com/b7n0de/proofbundle/blob/" + "0" * 40
        self.assertIn(basis + "/RELEASE.md#verifying-a-published-release-anyone)", text)
        self.assertIn(basis + "/RESTRISIKO_998.md)", text)
        self.assertNotIn("](RELEASE.md", text)

    def test_einzahl_und_mehrzahl_folgen_der_zahl_der_fixes(self):
        d = _zwei_ebenen()
        d["fixes"] = d["fixes"][:1]
        self.assertIn("<summary>All 1 fix, one line each", rendere(d))

    def test_fang_zwei_oder_fuenf_highlights(self):
        for n in (2, 5):
            with self.subTest(highlights=n):
                d = _zwei_ebenen()
                d["highlights"] = [{"kern": f"K{i}.", "text": "T."} for i in range(n)]
                self.assertTrue(any("three or four highlights" in b for b in pruefe(d)), pruefe(d))

    def test_gegenrichtung_vier_highlights_bestehen(self):
        d = _zwei_ebenen()
        d["highlights"].append({"kern": "Four.", "text": "The fourth thing is safer."})
        self.assertEqual(pruefe(d), [])

    def test_fang_ein_fix_ohne_fetten_satz(self):
        d = _zwei_ebenen()
        d["fixes"][0] = "`first` refuses it."
        self.assertIn("fix 1 is not one CHANGELOG line that opens with its bold sentence", pruefe(d))

    def test_fang_ohne_schlusssatz_oder_restrisiko(self):
        for feld in ("schlusssatz", "restrisiko"):
            with self.subTest(feld=feld):
                d = _zwei_ebenen()
                d.pop(feld)
                self.assertIn(f"the two-level source needs a non-empty {feld}", pruefe(d))

    def test_fang_ein_feld_der_gruppierten_form_fiele_still_weg(self):
        """A reviewed text the form does not render would be dropped with nothing refusing it."""
        d = _zwei_ebenen()
        d["vor_dem_upgrade"] = [{"titel": "Thing.", "text": "Some consequence."}]
        befunde = pruefe(d)
        self.assertTrue(any("vor_dem_upgrade" in b for b in befunde), befunde)

    def test_fang_eine_unbekannte_form(self):
        d = _zwei_ebenen()
        d["form"] = "drei_ebenen"
        befunde = pruefe(d)
        self.assertEqual(len(befunde), 1, befunde)
        self.assertIn("drei_ebenen", befunde[0])

    def test_fang_ein_interner_ablauf_auf_der_seite(self):
        for marke in ("order Z309", "card OA-0123456789", "a Codex finding", "finding R6b-1",
                      "the fifth review round", "a class search"):
            with self.subTest(marke=marke):
                d = _zwei_ebenen()
                d["highlights"][1]["text"] = f"Found by {marke}."
                self.assertTrue(any("the page names" in b for b in pruefe(d)), (marke, pruefe(d)))

    def test_gegenrichtung_fachwoerter_sind_kein_interner_ablauf(self):
        """WITHOUT THIS CASE a rule that refused every page would pass the catch above."""
        d = _zwei_ebenen()
        d["highlights"][1]["text"] = ("Ed25519 and ML-DSA keys, RFC 7515 section 4.1.11, SHA256SUMS, "
                                      "a review of the receipt, and SLSA level 3 stay as they are.")
        self.assertEqual(pruefe(d), [])


_CHANGELOG_999 = ("# Changelog\n\n## [9.9.9] - 2026-10-09\n\n### Fixed\n\n"
                  "- **A first input is refused.** `first` refuses it.\n"
                  "- **A second input is refused.** `second` refuses it.\n\n## [9.9.8] - 2026-10-01\n")
_RELEASE_MD = "# Release\n\n## Verifying a published release (anyone)\n\nSteps.\n"


def _baum_zwei_ebenen(wurzel: Path, ohne: str | None = None, ersetze: dict | None = None) -> Path:
    """A throwaway repository whose described commit carries the files a two-level page links,
    except `ohne`, with the content `ersetze` gives for a path; HEAD carries the source on top."""
    import os
    import shutil
    (wurzel / "scripts").mkdir(parents=True)
    (wurzel / "release_notes").mkdir()
    (wurzel / "docs" / "release_scope").mkdir(parents=True)
    shutil.copy2(SKRIPT, wurzel / "scripts" / "render_release.py")
    dateien = {"CHANGELOG.md": _CHANGELOG_999, "RESTRISIKO_998.md": "known limitations\n",
               "docs/release_scope/9.9.9.md": "scope\n", "RELEASE.md": _RELEASE_MD, **(ersetze or {})}
    for rel, inhalt in dateien.items():
        if rel != ohne:
            (wurzel / rel).write_text(inhalt, encoding="utf-8")
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)

    def git(*a: str) -> str:
        return subprocess.run(["git", "-C", str(wurzel), "-c", "user.name=t", "-c", "user.email=t@t",
                               "-c", "commit.gpgsign=false", *a], check=True, capture_output=True,
                              text=True, env=env, timeout=60).stdout.strip()

    git("init", "-q")
    git("add", "-A")
    git("commit", "-qm", "base")
    quelle = _zwei_ebenen()
    quelle["release_commit"] = git("rev-parse", "HEAD")
    (wurzel / "release_notes" / "release-source.json").write_text(json.dumps(quelle, indent=2),
                                                                  encoding="utf-8")
    git("add", "-A")
    git("commit", "-qm", "the source for 9.9.9")
    return wurzel


class JedeVerlinkteDateiStehtImBeschriebenenBaum(unittest.TestCase):
    """A LINK TO A FILE THE TREE LACKS IS A PROMISE NOBODY CHECKED. The grouped form linked
    `RESTRISIKO_610.md` from every later body until a reader noticed; the two-level page checks every
    path and anchor it links in the commit it describes, and that its fixes are the CHANGELOG lines."""

    def test_RED_eine_fehlende_verlinkte_datei_verweigert_den_render(self):
        import tempfile
        for ohne in ("RESTRISIKO_998.md", "docs/release_scope/9.9.9.md", "RELEASE.md"):
            with self.subTest(ohne=ohne), tempfile.TemporaryDirectory() as d:
                r = _render_im(_baum_zwei_ebenen(Path(d), ohne=ohne))
                self.assertEqual(r.returncode, 2, r.stdout)
                self.assertIn(f"the page links {ohne}", r.stderr)

    def test_RED_ein_anker_ohne_ueberschrift_verweigert_den_render(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            w = _baum_zwei_ebenen(Path(d), ersetze={
                "RELEASE.md": "# Release\n\n## Verifying a published release\n\nSteps.\n"})
            r = _render_im(w)
        self.assertEqual(r.returncode, 2, r.stdout)
        self.assertIn("no heading with that anchor", r.stderr)

    def test_RED_fixes_die_nicht_die_changelog_zeilen_sind_verweigern_den_render(self):
        import tempfile
        for name, inhalt in (
                ("andere Reihenfolge", _CHANGELOG_999.replace(
                    "- **A first input is refused.** `first` refuses it.\n"
                    "- **A second input is refused.** `second` refuses it.\n",
                    "- **A second input is refused.** `second` refuses it.\n"
                    "- **A first input is refused.** `first` refuses it.\n")),
                ("ein Wort anders", _CHANGELOG_999.replace("`first` refuses it", "`first` rejects it")),
                ("kein Abschnitt", "# Changelog\n\n## [9.9.8] - 2026-10-01\n")):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as d:
                r = _render_im(_baum_zwei_ebenen(Path(d), ersetze={"CHANGELOG.md": inhalt}))
                self.assertEqual(r.returncode, 2, r.stdout)
                self.assertIn("CHANGELOG.md at", r.stderr)

    def test_gegenrichtung_mit_allen_dateien_rendert(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            w = _baum_zwei_ebenen(Path(d))
            r = _render_im(w)
            text = (w / "notes.md").read_text(encoding="utf-8") if r.returncode == 0 else ""
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("2 fixes", r.stdout)
        self.assertIn("## Highlights", text)
