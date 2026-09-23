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

REPO = Path(__file__).resolve().parents[1]
SKRIPT = REPO / "scripts" / "render_release.py"
QUELLE = REPO / "release_notes" / "release-source.json"

sys.path.insert(0, str(REPO / "scripts"))
from render_release import lade, pruefe, rendere  # noqa: E402


def _fahre(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(SKRIPT), *args],
                          capture_output=True, text=True, timeout=60)


def _quelle() -> dict:
    return json.loads(QUELLE.read_text(encoding="utf-8"))


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
