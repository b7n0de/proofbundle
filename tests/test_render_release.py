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

import json
import subprocess
import sys
import unittest
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SKRIPT = REPO / "scripts" / "render_release.py"
QUELLE = REPO / "release_notes" / "release-source.json"

# A MISSING MAINTAINER SCRIPT IS A SKIP, NOT A COLLECTION ERROR. `render_release.py` is deliberately
# NOT in the sdist: `MANIFEST.in` names every shipped `scripts/` file one by one, by owner
# requirement of 2026-09-06, and a release-notes renderer is a maintainer tool that no consumer of
# the package needs. Measured on 2026-09-24: the hermetic cleanroom job installs the extracted sdist
# and runs `pytest --collect-only`, this module's module-level import of that absent file raised,
# and the whole job exited 2. A check that cannot START is not a check that fails on its subject.
#
# The guard comes BEFORE the import, which is the same ordering rule the bare-install sweep
# enforces for optional dependencies, and for the same reason: a guard placed after the import is
# never reached.
if not SKRIPT.is_file():
    pytest.skip(f"NOT MEASURABLE: {SKRIPT.name} is not in this tree — it is a maintainer script and "
                f"is not shipped in the sdist, so these cases have nothing to measure here",
                allow_module_level=True)

sys.path.insert(0, str(REPO / "scripts"))
from render_release import lade, pruefe, rendere  # noqa: E402


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


class DieVersionsbindungIstKeineHoeflichkeit(unittest.TestCase):
    """A source carries statements measured for ONE tree. Reusing them is a false claim."""

    def test_fang_falsche_version_wird_abgewiesen(self):
        r = _fahre("--version", "6.2.0")
        self.assertEqual(r.returncode, 2)
        self.assertIn("refusing", r.stderr)
        self.assertNotIn("## All changes", r.stdout, "nothing may be rendered on a refusal")

    def test_fang_fehlende_quelle_wird_abgewiesen(self):
        r = _fahre("--version", "6.1.0", "--quelle", "/nonexistent/source.json")
        self.assertEqual(r.returncode, 2)

    def test_gegenrichtung_die_erklaerte_version_rendert(self):
        """WITHOUT THIS CASE a renderer that refuses everything would pass both catches above."""
        r = _fahre("--version", "6.1.0")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("## All changes", r.stdout)


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
        r = _fahre("--version", "6.1.0", "--kopf", "0" * 40)
        self.assertEqual(r.returncode, 2, r.stdout)
        self.assertIn("different tree than the artefacts", r.stderr)
        self.assertIn(_erklaerter_kopf()[:12], r.stderr, "the refusal must name the declared tree")
        self.assertNotIn("## All changes", r.stdout, "nothing may be rendered on a refusal")

    def test_gegenrichtung_der_erklaerte_baum_rendert(self):
        """WITHOUT THIS a check that refuses every tree would pass the catch above."""
        r = _fahre("--version", "6.1.0", "--kopf", _erklaerter_kopf())
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("## All changes", r.stdout)

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
        d = _quelle()
        doppelt = dict(d["gruppen"][0]["eintraege"][0])
        d["gruppen"][1]["eintraege"].append(doppelt)
        befunde = pruefe(d)
        self.assertTrue(any(f"#{doppelt['nr']}" in b for b in befunde), befunde)

    def test_fang_ein_eintrag_ohne_originaltitel(self):
        """The short form must not be the only thing that survives."""
        d = _quelle()
        d["gruppen"][0]["eintraege"][0]["originaltitel"] = ""
        self.assertTrue(any("originaltitel" in b for b in pruefe(d)))

    def test_fang_eine_fehlende_gruppe(self):
        d = _quelle()
        weg = d["gruppen"].pop()
        self.assertTrue(any(weg["name"] in b for b in pruefe(d)))

    def test_fang_eine_unbekannte_gruppe(self):
        """An unknown group would be rendered and silently widen the release's shape."""
        d = _quelle()
        d["gruppen"].append({"name": "Other", "eintraege": []})
        self.assertTrue(any("does not know" in b for b in pruefe(d)))

    def test_gegenrichtung_die_echte_quelle_hat_keine_befunde(self):
        """WITHOUT THIS CASE a check that reports findings for everything would pass above."""
        self.assertEqual(pruefe(_quelle()), [])

    def test_alle_achtundvierzig_genau_einmal(self):
        d = _quelle()
        nummern = [e["nr"] for g in d["gruppen"] for e in g["eintraege"]]
        self.assertEqual(len(nummern), 48)
        self.assertEqual(len(set(nummern)), 48, "a pull request appears twice")


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
        self.assertGreater(len({g["name"] for g in d["gruppen"]}), 1)


class DerLaufIstDeterministisch(unittest.TestCase):

    def test_zwei_laeufe_sind_bitgleich(self):
        a = rendere(lade(QUELLE, "6.1.0"))
        b = rendere(lade(QUELLE, "6.1.0"))
        self.assertEqual(a, b)


class DasGerenderteIstDerVomOwnerGEPRUEFTEBody(unittest.TestCase):
    """THE CASE THIS FILE EXISTS FOR.

    The body in ``release_notes/RELEASE_NOTES_v6.1.0.md`` was written and reviewed by a human,
    independently of this renderer. If the render ever stops matching it byte for byte, either the
    source drifted from the reviewed text or the renderer changed its shape — and both are things a
    reader of the published note would never see.
    """

    def test_bytegleich_mit_der_gepruefte_vorlage(self):
        vorlage = REPO / "release_notes" / "RELEASE_NOTES_v6.1.0.md"
        if not vorlage.is_file():
            self.skipTest("the reviewed body is not in the tree")
        self.assertEqual(rendere(lade(QUELLE, "6.1.0")),
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
        r = _fahre("--version", "6.1.0-rc1")
        self.assertEqual(r.returncode, 2)
        self.assertIn("6.1.0-rc1", r.stderr)

    def test_ein_versehentlich_mitgeschlepptes_v_wird_abgewiesen(self):
        """`${GITHUB_REF_NAME#v}` strips ONE leading v; a source that kept it would not match."""
        r = _fahre("--version", "v6.1.0")
        self.assertEqual(r.returncode, 2)


class DieDoppelungDerGruppennamenIstDieRATSCHE(unittest.TestCase):
    """Named rather than removed, and pinned so the reason survives the next reader.

    If `pruefe` read the group set from the source instead of from `ERWARTETE_GRUPPEN`, a source
    that had lost four of five groups would pass every check — it would be measured against itself.
    """

    def test_fang_eine_quelle_mit_nur_einer_gruppe_faellt(self):
        d = _quelle()
        d["gruppen"] = d["gruppen"][:1]
        befunde = pruefe(d)
        self.assertTrue(befunde, "a source reduced to one group must not pass")
        self.assertTrue(any("missing" in b for b in befunde), befunde)

    def test_die_reihenfolge_kommt_aus_der_quelle_nicht_aus_der_konstanten(self):
        """Membership is decided by the constant, ORDER by the source."""
        d = _quelle()
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
        d = _quelle()
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
        self.assertEqual(pruefe(_quelle()), [],
                         "the real source must still pass, or the duplicate rule is too wide")
