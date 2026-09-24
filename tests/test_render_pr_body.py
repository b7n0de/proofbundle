"""The house form for pull request bodies and issues comes out of data, and the data is checked.

WHERE THIS CAME FROM. Owner order of 2026-09-24, QITEM-PROOFBUNDLE-HAUSFORM-PR-ISSUE-ERZEUGER-AUS-DATEN-01,
after PR 260 went out hand-written: 27 hard wraps at a maximum line length of 104 and zero H2
headings, against PR 259 with a maximum line length of 352 and five headings. Both bodies were set
with the SAME command, so the command was never the difference; 260's body had been cut out of its
own commit message, and a commit message is hand-wrapped at about a hundred characters.

THE TWO FIXTURES ARE THE MEASUREMENT, not an illustration. `pr260_alt_handgeschrieben.md` is the
body as it actually stood on GitHub before the repair, pulled from the API, and it is the red probe.
`pr259_referenzform.md` is the reference body, likewise pulled, and it is the green one. A rule that
only fires on invented input is a rule nobody has aimed at anything.

WHAT THE GREEN PROBE CAUGHT IN THE RULE ITSELF, which is why it is here and not only in a docstring:
a first version tested the first character of a line and reported three findings against PR 259, all
three inside a fenced code block. The body was right and the rule was wrong. A fence has a state, and
a rule that tests characters cannot see a state.
"""
from __future__ import annotations

import importlib.util
import json
import pathlib
import subprocess
import sys
import unittest

REPO = pathlib.Path(__file__).resolve().parents[1]
SKRIPT = REPO / "scripts" / "render_pr_body.py"
FIXTUREN = pathlib.Path(__file__).resolve().parent / "fixtures" / "pr_bodies"
QUELLE_260 = REPO / "pr_bodies" / "pr-260-source.json"


# DER MODUL-LADEVORGANG STEHT AUF MODUL-EBENE UND IN DIESER FORM, weil es dafuer eine Hausregel gibt
# und `tests/test_kein_blanker_import_eines_nicht_ausgelieferten.py` sie bewacht. `render_pr_body.py`
# wird NICHT im sdist ausgeliefert (MANIFEST.in nennt den Grund), und mit `spec_from_file_location`
# traegt der Modulname sein Verzeichnis, sodass `conftest` die Datei als nicht-ausgeliefert erkennt
# und einen ehrlichen SKIP meldet, statt dass die Sammlung abbricht. Ein Laden je Testmethode wuerde
# stattdessen `FileNotFoundError` werfen: ein Fehlschlag, der nach einem Defekt am Gegenstand aussieht
# und keiner ist. Das Schwesterwerkzeug `test_render_release.py` traegt dieselbe Form mitsamt der
# Notiz, dass ein modul-weiter `pytest.skip` hier die FALSCHE Loesung war.
_spec = importlib.util.spec_from_file_location("_render_pr_body", SKRIPT)
_rp = importlib.util.module_from_spec(_spec)
sys.modules["_render_pr_body"] = _rp
_spec.loader.exec_module(_rp)


def _modul():
    return _rp


def _harte_umbrueche(text: str) -> list[int]:
    """The owner's own check, transcribed: a non-empty line whose predecessor is non-empty and which
    does not open a block form is a source line break inside a paragraph."""
    z = text.split("\n")
    return [i + 1 for i in range(1, len(z))
            if z[i].strip() and z[i - 1].strip()
            and not z[i].lstrip().startswith(("|", "#", "-", "*", "`", ">"))]


def _quelle(**felder) -> dict:
    """A minimal renderable PR source; each case overrides exactly what it measures."""
    basis = {
        "kind": "pr",
        "head": "Head of this branch: `abc1234`, on top of `def5678`. One file, 3 added lines.",
        "came_from": "A sentence that stands as one paragraph on one line.",
        "defect": "Another sentence that stands as one paragraph on one line.",
        "fix": "A third sentence that stands as one paragraph on one line.",
        "measured": [{"what": "a count", "value": "1", "source": "tests/x.py", "commit": "abc1234"}],
        "not_changed": "A fourth sentence that stands as one paragraph on one line.",
    }
    basis.update(felder)
    return basis


class TestDieBloeckeStehenFest(unittest.TestCase):
    def test_reihenfolge_und_titel_der_bloecke(self):
        m = _modul()
        text = m.rendere(_quelle(), "pr")
        titel = [z[3:] for z in text.split("\n") if z.startswith("## ")]
        self.assertEqual(titel, ["Where this came from", "The defect", "The fix", "Measured",
                                 "Not changed", "Marking"])

    def test_change_ersetzt_defect_fuer_ein_feature(self):
        m = _modul()
        q = _quelle(change="A feature states a change.")
        q.pop("defect")
        titel = [z[3:] for z in m.rendere(q, "pr").split("\n") if z.startswith("## ")]
        self.assertIn("The change", titel)
        self.assertNotIn("The defect", titel)

    def test_beides_zugleich_ist_ein_befund(self):
        """Neither and both are findings, because the renderer must not pick for the author."""
        m = _modul()
        self.assertTrue(m.pruefe(_quelle(change="x"), "pr"))
        ohne = _quelle()
        ohne.pop("defect")
        self.assertTrue(m.pruefe(ohne, "pr"))

    def test_issue_traegt_seine_eigenen_fuenf_bloecke(self):
        m = _modul()
        q = {"kind": "issue", "observed": "One line.", "expected": "One line.", "scope": "One line.",
             "measured": [{"what": "a", "value": "b", "source": "c", "commit": "d"}]}
        titel = [z[3:] for z in m.rendere(q, "issue").split("\n") if z.startswith("## ")]
        self.assertEqual(titel, ["Observed", "Measured", "Expected", "Scope", "Marking"])


class TestEinAbsatzEineZeile(unittest.TestCase):
    def test_rotprobe_der_alte_rumpf_von_260_faellt(self):
        """THE CATCH PROOF, against the body that actually went out."""
        m = _modul()
        alt = (FIXTUREN / "pr260_alt_handgeschrieben.md").read_text(encoding="utf-8")
        befunde = m._absatzfehler("rotprobe", alt)
        self.assertGreaterEqual(len(befunde), 20, "the hand-wrapped body passed the paragraph rule")
        self.assertTrue(all("source line break" in b for b in befunde))

    def test_gruenprobe_pr_259_faellt_nicht(self):
        """THE GUARD. Without it the rule could reject everything and the red probe would still pass.
        259 carries fenced code blocks, and those lines are lines on purpose."""
        m = _modul()
        gruen = (FIXTUREN / "pr259_referenzform.md").read_text(encoding="utf-8")
        self.assertEqual(m._absatzfehler("gruenprobe", gruen), [])

    def test_die_erzeugung_ist_nach_der_owner_regel_sauber(self):
        m = _modul()
        self.assertEqual(_harte_umbrueche(m.rendere(_quelle(), "pr")), [])

    def test_fliesstext_mit_umbruch_wird_abgewiesen_nicht_geglaettet(self):
        m = _modul()
        q = _quelle(came_from="A paragraph that was wrapped\nby hand at some width.")
        befunde = m.pruefe(q, "pr")
        self.assertTrue(any("came_from" in b and "source line break" in b for b in befunde))


class TestDieTabelleUndDieGrenzen(unittest.TestCase):
    def test_messtabelle_traegt_alle_vier_spalten(self):
        m = _modul()
        text = m.rendere(_quelle(), "pr")
        self.assertIn("| What | Value | Source | Commit |", text)
        self.assertIn("| a count | 1 | tests/x.py | `abc1234` |", text)

    def test_eine_fehlende_spalte_ist_ein_befund(self):
        m = _modul()
        for fehlt in ("what", "value", "source", "commit"):
            with self.subTest(spalte=fehlt):
                e = {"what": "a", "value": "b", "source": "c", "commit": "d"}
                e.pop(fehlt)
                befunde = m.pruefe(_quelle(measured=[e]), "pr")
                self.assertTrue(any(fehlt in b for b in befunde), befunde)

    def test_leeres_pflichtfeld_bricht_ab(self):
        m = _modul()
        for feld in ("head", "came_from", "fix", "not_changed"):
            with self.subTest(feld=feld):
                self.assertTrue(any(feld in b for b in m.pruefe(_quelle(**{feld: ""}), "pr")))

    def test_lange_ausgabe_geht_ab_sechzehn_zeilen_in_details(self):
        m = _modul()
        kurz = "\n".join(f"line {i}" for i in range(m.DETAILS_AB))
        lang = "\n".join(f"line {i}" for i in range(m.DETAILS_AB + 1))
        self.assertNotIn("<details>", "\n".join(m._block(kurz)))
        self.assertIn("<details>", "\n".join(m._block(lang)))


class TestDerFussblockIstEineKonstante(unittest.TestCase):
    def test_fussblock_byte_gleich(self):
        m = _modul()
        erwartet = ("Written by an AI session of b7n0de under owner review.\n\n"
                    "Measurement, not certification.")
        self.assertEqual(m.FUSSBLOCK, erwartet)
        self.assertTrue(m.rendere(_quelle(), "pr").rstrip("\n").endswith(erwartet))

    def test_der_torschlusssatz_ist_nicht_der_vorgabewert(self):
        """The bridge is off unless asked for. A body that carries a thread-reply provenance line by
        default would describe its own surface wrongly."""
        m = _modul()
        self.assertNotIn(m.TOR_SCHLUSSSATZ, m.rendere(_quelle(), "pr"))


class TestDieQuelleWirdGeprueft(unittest.TestCase):
    def test_eine_issue_quelle_wird_nicht_als_pr_gerendert(self):
        m = _modul()
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as fh:
            json.dump({"kind": "issue"}, fh)
            pfad = pathlib.Path(fh.name)
        with self.assertRaises(m.QuellenFehler):
            m.lade(pfad, "pr")
        pfad.unlink()


class TestDerLaufAmEchtenFall(unittest.TestCase):
    """The end-to-end arm: the source that describes PR 260 renders, and renders clean."""

    def test_die_quelle_von_260_ist_renderbar_und_sauber(self):
        if not QUELLE_260.is_file():                      # pragma: no cover - source not in this tree
            self.skipTest(f"{QUELLE_260} is not in this tree")
        r = subprocess.run([sys.executable, str(SKRIPT), "--quelle", str(QUELLE_260)],
                           capture_output=True, text=True, timeout=120)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(_harte_umbrueche(r.stdout), [])
        self.assertIn("## Marking", r.stdout)


if __name__ == "__main__":
    unittest.main()


class TestDreiFundeAusDerDurchsichtVonPR261(unittest.TestCase):
    """Drei P2-Funde aus der Codex-Durchsicht dieses PR, je als Fangnachweis. Alle drei waren echt.

    Der zweite ist der unangenehmste: er ist die Klasse R-B4 in meinem eigenen neuen Code, am selben
    Tag, an dem drei Commits desselben Zweiges sie anderswo geschlossen haben.
    """

    def test_ein_inhaltsfeld_darf_keine_blockgrenze_setzen(self):
        """FUND 1. `fix: "## Marking"` rendert sonst einen ZWEITEN Marking-Block, und der Fussblock
        steht danach doppelt — obwohl das Modul Reihenfolge und Zugehoerigkeit besitzt."""
        m = _modul()
        befunde = m.pruefe(_quelle(fix="## Marking"), "pr")
        self.assertTrue(any("top-level heading" in b for b in befunde), befunde)

    def test_tiefere_ueberschriften_bleiben_erlaubt(self):
        """GUARD zur Gegenrichtung: `###` setzt keine Blockgrenze dieses Formats und darf bleiben."""
        m = _modul()
        self.assertEqual(m.pruefe(_quelle(fix="### a detail"), "pr"), [])

    def test_eine_messzelle_mit_umbruch_wird_abgewiesen(self):
        """FUND 1, zweite Haelfte: `1\\n## Forged` in einer Zelle bricht die Tabelle auf."""
        m = _modul()
        e = {"what": "a", "value": "1\n## Forged", "source": "c", "commit": "d"}
        self.assertTrue(any("line break" in b for b in m.pruefe(_quelle(measured=[e]), "pr")))

    def test_null_ist_ein_messwert_und_kein_fehlendes_feld(self):
        """FUND 2, und er ist die Klasse R-B4: `e.get(spalte) or ""` verwechselt Wahrheitswert mit
        Anwesenheit. Eine Null ist eine anwesende, gueltige Messung."""
        m = _modul()
        for wert in (0, False, 0.0):
            with self.subTest(wert=wert):
                e = {"what": "a", "value": wert, "source": "c", "commit": "d"}
                self.assertEqual(m.pruefe(_quelle(measured=[e]), "pr"), [])

    def test_ein_wirklich_fehlendes_feld_faellt_weiterhin(self):
        """GUARD: die Lockerung darf nicht dazu fuehren, dass None oder Leertext durchgehen."""
        m = _modul()
        for wert in (None, "", "   "):
            with self.subTest(wert=wert):
                e = {"what": "a", "value": wert, "source": "c", "commit": "d"}
                self.assertTrue(any("lacks value" in b for b in m.pruefe(_quelle(measured=[e]), "pr")))

    def test_geordnete_listen_und_plus_sind_blockformen(self):
        """FUND 3. `1. erstens / 2. zweitens` und `+ a / + b` sind Listen, keine umgebrochene Prosa."""
        m = _modul()
        for text in ("1. first\n2. second", "1) first\n2) second", "+ first\n+ second",
                     "10. tenth\n11. eleventh"):
            with self.subTest(text=text.split("\n")[0]):
                self.assertEqual(m._absatzfehler("f", text), [])

    def test_umgebrochene_prosa_faellt_weiterhin(self):
        """GUARD zur Gegenrichtung: die Erweiterung darf echte Umbrueche nicht durchlassen."""
        m = _modul()
        self.assertTrue(m._absatzfehler("f", "a paragraph that was wrapped\nby hand at some width"))
