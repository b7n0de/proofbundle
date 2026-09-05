"""The from-sdist skip set is DERIVED, so a test added tomorrow is covered without being remembered.

THE CLASS (deep gate wf_cfe249d0-ee8, finding L6-01, P1). ``tests/conftest.py`` carried a frozenset of
44 test ids that SKIP outside a git checkout. That list IS the defect: commit 2c5e7a5 had already
appended ids to it once, and the gate still measured six MORE tests failing from an extracted sdist at
HEAD — because a list cannot know about the method somebody adds tomorrow to a module already on it.

Measured against the real sdist (built with ``python -m build --sdist``, extracted, run with the repo
interpreter):

    old conftest (enumerated list): 7 failed, 2060 passed, 49 skipped
    new conftest (derived):         0 failed, 1827 passed, 289 skipped

Six of those seven are the ones the finding names (test_intoto_spec_diff). The seventh came from a test
file written in the SAME session as this fix — nobody had added it to any list, and the derivation
covered it anyway. That is the difference between the two designs, in one data point.

THE META-TEST the finding demands is below: a method planted inside an ALREADY-covered module must be
covered too. A guard that merely re-lists module names does not survive it.
"""
from __future__ import annotations

import importlib.util
import pathlib
import shutil
import tempfile
import unittest

REPO = pathlib.Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location("_cf", REPO / "tests" / "conftest.py")
cf = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(cf)


class AbgeleiteteSkipMenge(unittest.TestCase):

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        (self.tmp / "tests").mkdir()
        (self.tmp / "vorhanden.md").write_text("da", encoding="utf-8")

    def _modul(self, name: str, quelle: str) -> pathlib.Path:
        p = self.tmp / "tests" / name
        p.write_text(quelle, encoding="utf-8")
        return p

    def test_ein_modul_das_einen_fehlenden_wurzelpfad_liest_ist_repo_kontext(self):
        for form in (
            'REPO = Path(__file__).parents[1]\nX = REPO / "SPEC.md"\n',
            '_REPO_ROOT = Path(__file__).resolve().parent.parent\nX = _REPO_ROOT / ".github"\n',
            'ROOT = Path(__file__).parents[1]\nX = ROOT / "tools" / "pb_verify_rs"\n',
            'X = Path(__file__).resolve().parents[1] / "audit_artifacts"\n',
        ):
            with self.subTest(form=form.splitlines()[-1][:44]):
                p = self._modul("test_x.py", "from pathlib import Path\n" + form)
                self.assertTrue(cf.modul_ist_repo_kontext(p, wurzel=self.tmp),
                                "ein fehlender Wurzelpfad wurde nicht erkannt")

    def test_META_eine_neu_gepflanzte_methode_im_selben_modul_ist_mitgedeckt(self):
        """DER META-TEST (vom Fund verlangt).

        Der alte Riegel haette hier NICHTS getan: die neue Methode steht auf keiner Liste. Weil die
        Entscheidung am MODUL haengt und aus seinen Pfaden abgeleitet wird, ist sie ab der ersten Zeile
        gedeckt — es muss sich niemand an sie erinnern.
        """
        quelle = ('from pathlib import Path\nREPO = Path(__file__).parents[1]\n\n'
                  'class T:\n    def test_alt(self):\n        assert (REPO / "SPEC.md").is_file()\n')
        p = self._modul("test_gepflanzt.py", quelle)
        self.assertTrue(cf.modul_ist_repo_kontext(p, wurzel=self.tmp))
        # jetzt eine NEUE Methode anhaengen, die eine weitere geprunte Datei liest
        p.write_text(quelle + '\n    def test_neu(self):\n        assert (REPO / "docs/PRUNED.md").is_file()\n',
                     encoding="utf-8")
        self.assertTrue(cf.modul_ist_repo_kontext(p, wurzel=self.tmp),
                        "die gepflanzte Methode ist nicht gedeckt — der Riegel zaehlt wieder auf")

    def test_gegenrichtung_ein_modul_mit_nur_vorhandenen_pfaden_ist_kein_repo_kontext(self):
        """Ohne das waere ein Riegel, der ALLES ueberspringt, von einem richtigen nicht zu unterscheiden —
        und aus dem sdist liefe dann gar nichts mehr, was wie 'gruen' aussaehe."""
        p = self._modul("test_ok.py",
                        'from pathlib import Path\nREPO = Path(__file__).parents[1]\n'
                        'X = REPO / "vorhanden.md"\n')
        self.assertFalse(cf.modul_ist_repo_kontext(p, wurzel=self.tmp))

    def test_gegenrichtung_ein_modul_ganz_ohne_wurzelpfade_ist_kein_repo_kontext(self):
        p = self._modul("test_rein.py", "import json\n\ndef test_x():\n    assert json.dumps({}) == '{}'\n")
        self.assertFalse(cf.modul_ist_repo_kontext(p, wurzel=self.tmp))

    def test_ein_unlesbares_modul_gilt_als_repo_kontext(self):
        """Nicht bestimmbar ist keine Freigabe: wer nicht zeigen kann, dass er paketrein ist, wird
        ausserhalb des Checkouts uebersprungen statt blind ausgefuehrt."""
        self.assertTrue(cf.modul_ist_repo_kontext(self.tmp / "tests" / "gibt_es_nicht.py", wurzel=self.tmp))

    @unittest.skipUnless(cf.running_in_repo_checkout(),
                         "prueft eine Eigenschaft DES CHECKOUTS — ausserhalb eines Checkouts hat sie "
                         "keinen Gegenstand")
    def test_im_echten_checkout_ist_die_ableitung_ein_no_op(self):
        """In einem echten Checkout existiert jeder Wurzelpfad — nichts darf uebersprungen werden."""
        self.assertTrue(cf.running_in_repo_checkout(), "die Vorrichtung laeuft nicht in einem Checkout")
        uebersprungen = [p.stem for p in sorted((REPO / "tests").glob("test_*.py"))
                         if cf.modul_ist_repo_kontext(p, wurzel=REPO)]
        self.assertEqual(uebersprungen, [],
                         f"im Checkout wuerden Module uebersprungen: {uebersprungen}")

    def test_die_restliche_liste_ist_ein_dokumentierter_rueckfall(self):
        """Der Fund erlaubt _REPO_CONTEXT_TESTS ausdruecklich NUR noch als begruendete Ausnahmeliste.

        Die Menge ist GEMESSEN, nicht geschaetzt: Liste im entpackten sdist leeren, Suite fahren, und was
        faellt, gehoert hinein. Mein erster Versuch schaetzte drei Module — sieben Tests fielen daraufhin.
        Es sind sechs.

        Die Gleichheit steht hier bewusst in BEIDE Richtungen: waechst die Liste, hat jemand wieder
        aufgezaehlt statt abzuleiten; schrumpft sie, faellt aus dem sdist wieder etwas durch.
        """
        rueckfall = {"test_audit_candidate_360", "test_claims_hygiene", "test_fork_pr_secret_isolation",
                     "test_roadmap_frontload_foundations", "test_rust_parity_gate"}
        gelistet = {e.split("::")[0] for e in cf._REPO_CONTEXT_TESTS}
        self.assertEqual(gelistet, rueckfall,
                         "die Rueckfall-Liste weicht von der gemessenen Menge ab — sie darf weder "
                         "wachsen (Aufzaehlung kehrt zurueck) noch schrumpfen (aus dem sdist faellt etwas durch)")


if __name__ == "__main__":
    unittest.main()


def _in_git_checkout() -> bool:
    """Ist DIESER Baum das Repository? Gemessen, nicht aus der Verzeichnisform geraten.

    Im entpackten sdist gibt es weder `.git` noch das Kommando — und genau dort ist die Ignore-Regel
    nicht befragbar. Die Bedingung des Tests IST die des Codes: beide fragen ueber
    `conftest._dieser_baum_ist_das_repo`, damit sie nicht auseinanderlaufen koennen.

    KORRIGIERT (Tiefen-Gate 2026-09-05, Fund L6-600-01): hier stand `--is-inside-work-tree`, und das
    ist wahr fuer JEDES Unterverzeichnis eines FREMDEN Repositoriums. Ein in `vendor/` oder `src_deps/`
    eines Consumer-Checkouts entpacktes sdist meldete damit "im Checkout", der Test lief statt zu
    ueberspringen, und `_ist_bauartefakt` beantwortete seine Frage aus den Ignore-Regeln des fremden
    Baums. Dieselbe Verwechslung, gegen die diese Datei steht, eine Ebene hoeher."""
    return cf._dieser_baum_ist_das_repo(REPO)


class BauartefakteZaehlenNicht(unittest.TestCase):
    """ZWEI ARTEN VON ABWESENHEIT, und die erste Fassung hatte eine Regel fuer beide.

    `tests/test_relation_statement_rust_parity.py` nennt
    `tools/pb_verify_rs/target/release/pb_verify_rs`. Diese Datei fehlt auch im VOLLSTAENDIGEN
    Checkout — bis jemand `cargo build` laeuft. Ihre Abwesenheit sagt nichts darueber, ob wir in
    einem sdist sind, und genau das ist die einzige Frage dieser Ableitung. Gemessen: die Ableitung
    uebersprang deshalb dieses eine Modul, und `test_im_echten_checkout_ist_die_ableitung_ein_no_op`
    fiel in allen fuenf Python-Matrix-Laeufen plus coverage, crypto-floor und mutation — acht rote
    Checks fuer EINEN Test.

    Die trennende Eigenschaft ist die Ignore-Regel des Repos selbst, nicht eine Liste von
    Verzeichnisnamen: `target/` ist ignoriert, `tools/pb_verify_rs/crosscheck.py` nicht, und
    `docs/IN_TOTO_PROFILE.md` — der geprunte Blattfall, fuer den diese Ableitung existiert — auch
    nicht. Verzeichnisnamen aufzuzaehlen waere wieder Formen sammeln, wovor der Kommentar in
    `modul_ist_repo_kontext` selbst warnt.
    """

    def test_ein_ungebautes_artefakt_macht_kein_repo_kontext_modul(self):
        """NUR IM CHECKOUT AUSSAGEKRAEFTIG, und die erste Fassung hat das vergessen.

        Sie behauptete `True` unbedingt — und fiel im hermetic-cleanroom-Job, der die Suite aus dem
        ENTPACKTEN sdist faehrt. Dort gibt es kein git, also gibt `_ist_bauartefakt` fail-safe `False`
        zurueck. Das ist genau das Verhalten, das der dritte Test dieser Klasse VORHERSAGT; ich hatte
        die Bedingung nur im ersten nicht gesetzt. Der Test mass damit die UMGEBUNG statt der
        Eigenschaft — dieselbe Klasse, gegen die diese ganze Datei steht, eine Ebene hoeher.

        Ausgelassen wird hier NICHT stillschweigend: ohne git ist die Frage nicht messbar, und der
        Skip sagt das. Die Eigenschaft selbst haelt der Cleanroom-Job ueber
        `test_ohne_git_bleibt_das_strengere_alte_verhalten` weiter, nur von der anderen Seite.
        """
        if not _in_git_checkout():
            self.skipTest("kein git-Checkout (entpacktes sdist) — die Ignore-Regel ist hier nicht "
                          "messbar, und nicht messbar ist keine Freigabe")
        self.assertFalse(cf._ist_bauartefakt(REPO, "tools/pb_verify_rs/crosscheck.py"),
                         "eine echte Quelldatei gilt als Bauartefakt — die Ableitung wuerde blind")
        self.assertTrue(cf._ist_bauartefakt(REPO, "tools/pb_verify_rs/target/release/pb_verify_rs"),
                        "das Rust-Binary gilt nicht als Bauartefakt — der Fall kehrt zurueck")

    def test_der_geprunte_blattfall_bleibt_ein_signal(self):
        """Die Gegenrichtung. Ohne sie waere ein Fix, der ALLES entschaerft, ebenfalls gruen —
        und die Ableitung haette aufgehoert, den sdist zu erkennen."""
        self.assertFalse(cf._ist_bauartefakt(REPO, "docs/IN_TOTO_PROFILE.md"),
                         "der geprunte Blattfall gilt als Bauartefakt — dann misst die Ableitung nichts mehr")

    def test_ohne_git_bleibt_das_strengere_alte_verhalten(self):
        """In einem entpackten sdist gibt es kein git. Dort IST Abwesenheit das richtige Signal,
        also faellt die Pruefung fail-safe auf 'kein Bauartefakt' zurueck."""
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            self.assertFalse(cf._ist_bauartefakt(pathlib.Path(d), "irgendwas/target/x"),
                             "ohne git wird etwas als Bauartefakt entschuldigt — das entschaerft "
                             "die Ableitung genau dort, wo sie gebraucht wird")


class LokaleWurzelUndSchleifenwerte(unittest.TestCase):
    """Die Ableitung erkennt eine Wurzel an ihrer HERKUNFT, nicht an ihrem NAMEN.

    ANLASS (2026-08-30, hermetic-cleanroom auf PR #159): ein Test las
    ``docs/RECEIPT_ENVELOPE_PROFILE.md`` und fiel im sdist mit FileNotFoundError. Die Ableitung sah
    in dem Modul NULL Pfade — zwei Ursachen, gemessen. (1) ``_ROOT_NAMEN`` ist eine
    grossgeschriebene Allowlist, die lokale Variable hiess ``root``: damit war das GANZE Modul
    unsichtbar. (2) Der Pfad stand hinter einer Schleifenvariable, und ``_kette`` verwirft ein
    variables Segment.

    WARUM NICHT EINFACH DIE NAMENSLISTE OEFFNEN: die Grossschreibung ist der UNTERSCHEIDER zwischen
    einer modulweiten Konstante (meint konventionell die Wurzel) und einer lokalen Variable (meint
    meist etwas anderes). Gemessen kostet das Oeffnen 14 Falsch-Positiv-Pfade in zwei Modulen, deren
    lokale Variable ein kopiertes Korpus- bzw. ein Temp-Verzeichnis ist — die wuerden ausserhalb
    eines Checkouts still uebersprungen. Deshalb wird die HERKUNFT geprueft: nur was nachweislich
    aus ``__file__`` abgeleitet ist und dabei die richtige ZAHL VON SCHRITTEN nimmt, ist die Wurzel.
    """

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        (self.tmp / "tests").mkdir()
        (self.tmp / "vorhanden.md").write_text("da", encoding="utf-8")

    def _modul(self, name: str, quelle: str) -> pathlib.Path:
        p = self.tmp / "tests" / name
        p.write_text(quelle, encoding="utf-8")
        return p

    def test_eine_lokale_kleingeschriebene_wurzel_wird_erkannt(self):
        p = self._modul("test_lokal.py",
                        'from pathlib import Path\n'
                        'def test_x():\n'
                        '    root = Path(__file__).resolve().parent.parent\n'
                        '    (root / "docs/FEHLT.md").read_text()\n')
        self.assertTrue(cf.modul_ist_repo_kontext(p, wurzel=self.tmp),
                        "eine lokale Wurzel darf nicht am Namen scheitern")

    def test_ein_pfad_hinter_einer_schleife_ueber_konstanten_wird_erkannt(self):
        p = self._modul("test_schleife.py",
                        'from pathlib import Path\n'
                        'def test_x():\n'
                        '    root = Path(__file__).resolve().parent.parent\n'
                        '    for rel in ("docs/FEHLT.md", "vorhanden.md"):\n'
                        '        (root / rel).read_text()\n')
        self.assertTrue(cf.modul_ist_repo_kontext(p, wurzel=self.tmp),
                        "der entscheidbare Schleifenfall wurde nicht aufgeloest")

    def test_ein_schritt_zu_wenig_ist_NICHT_die_wurzel(self):
        """``Path(__file__).parent`` ist das tests-Verzeichnis. 29 Stellen im Baum schreiben das."""
        p = self._modul("test_flach.py",
                        'from pathlib import Path\n'
                        'def test_x():\n'
                        '    hier = Path(__file__).resolve().parent\n'
                        '    (hier / "fixtures").iterdir()\n')
        self.assertFalse(cf.modul_ist_repo_kontext(p, wurzel=self.tmp),
                         "ein tests-relativer Pfad wurde als wurzelrelativ gelesen")

    def test_eine_lokale_variable_ohne_dateiherkunft_ist_keine_wurzel(self):
        """``root = self._copy_corpus()`` und ``repo = tmp_path / 'r'`` sind KEINE Repo-Wurzeln."""
        for form in ('    root = irgendwas()\n    (root / "docs/FEHLT.md").read_text()\n',
                     '    repo = tmp / "r"\n    (repo / "docs/FEHLT.md").read_text()\n'):
            with self.subTest(form=form.strip().splitlines()[0][:40]):
                p = self._modul("test_fremd.py",
                                'from pathlib import Path\ndef test_x(tmp, irgendwas):\n' + form)
                self.assertFalse(cf.modul_ist_repo_kontext(p, wurzel=self.tmp),
                                 "eine fremde lokale Variable wurde als Wurzel gelesen")

    def test_eine_im_koerper_neu_zugewiesene_schleifenvariable_bindet_nicht(self):
        """Die Kopfbindung gilt im Koerper nicht mehr — dann lieber nichts binden."""
        p = self._modul("test_neuzuweisung.py",
                        'from pathlib import Path\n'
                        'def test_x():\n'
                        '    root = Path(__file__).resolve().parent.parent\n'
                        '    for rel in ("docs/FEHLT.md",):\n'
                        '        rel = "vorhanden.md"\n'
                        '        (root / rel).read_text()\n')
        self.assertFalse(cf.modul_ist_repo_kontext(p, wurzel=self.tmp),
                         "eine ueberschriebene Schleifenvariable wurde weiter gebunden")

    def test_zwei_schleifen_mit_demselben_namen_lecken_nicht(self):
        """Gemeint ist nie 'der Name', immer 'diese Schleife'."""
        p = self._modul("test_zwei.py",
                        'from pathlib import Path\n'
                        'def test_x(faelle):\n'
                        '    root = Path(__file__).resolve().parent.parent\n'
                        '    for rel in faelle:\n'
                        '        (root / "unter" / rel / "case.json").read_text()\n'
                        '    for rel in ("vorhanden.md",):\n'
                        '        (root / rel).read_text()\n')
        gefunden = cf._wurzel_relative_pfade(p.read_text(encoding="utf-8"), 2)
        self.assertNotIn("unter/vorhanden.md", gefunden,
                         "die Werte der einen Schleife erschienen in der Kette der anderen")
