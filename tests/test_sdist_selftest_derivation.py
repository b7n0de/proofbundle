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

    def test_eine_IMPORTIERTE_wurzelkonstante_wird_am_namen_erkannt(self):
        """``_ROOT_NAMEN`` hatte keinen einzigen Test (Gegenlesung 07.09.2026, Linse 3, Mutant M6).

        Die vier Formen im ersten Test dieser Klasse leiten ihre Wurzel alle LOKAL aus ``__file__``
        ab — das fuellt ``_gebunden`` und funktioniert unabhaengig vom Namen. Die Allowlist leeren
        liess die Datei deshalb bei 16 passed stehen, obwohl damit jedes Modul unsichtbar wird, das
        seine Wurzel IMPORTIERT statt sie selbst zu bilden. Genau dafuer ist die Liste da, und genau
        das misst dieser Test.
        """
        p = self._modul("test_importiert.py",
                        'from irgendwo import REPO\nX = REPO / "docs/FEHLT.md"\n')
        self.assertTrue(cf.modul_ist_repo_kontext(p, wurzel=self.tmp),
                        "eine importierte Wurzelkonstante wurde nicht erkannt — die Namens-Allowlist "
                        "ist wirkungslos, und importierende Module laufen ausserhalb des Checkouts blind")

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

        EIN DRITTER GRUND FUER WACHSTUM, seit 06.09.2026, und er ist keiner der beiden oben: das
        Paket kann ABSICHTLICH etwas verlieren. Die Owner-Auflage zur Karte OA-8b1a31cc4f nimmt
        ``scripts/pre_tag_receipt.py`` aus dem sdist, weil es den Inline-Signierweg traegt.
        ``test_pre_tag_receipt_commit_flow`` faehrt genau dieses Skript als Prozess und hat im
        Paket damit keinen Gegenstand mehr. Gemessen, bevor der Eintrag gesetzt wurde: die
        Ableitung ``modul_ist_repo_kontext`` faengt den Fall NICHT — sie sieht in dem Modul nur die
        Verzeichnisse ``scripts`` und ``src``, und die existieren im sdist beide; die einzelne
        fehlende Datei steht hinter einer Schleifenvariablen ueber ``SCRIPTS / s``. Der Rueckfall
        ist hier also nicht Bequemlichkeit, sondern die Stelle, an der die Ableitung nachweislich
        endet — und genau dafuer ist er da.

        DER VIERTE GRUND, 07.09.2026, und er ist der, den ``conftest`` seit jeher als Zweck der
        Liste nennt: die Repo-Abhaengigkeit steht nicht im Testmodul, sondern eine Ebene tiefer im
        Skript, das es faehrt. GEMESSEN mit ``_wurzel_relative_pfade`` an beiden Modulen, nicht
        vermutet. ``test_not_after_gilt_auch_auf_dem_registerpfad`` nennt genau ``scripts``, ``src``
        und ``scripts/audit_candidate_matrix.py`` — alle drei liegen im sdist (MANIFEST.in Zeile 88),
        die Ableitung sieht also nichts fehlen und liefert ``False``. Der Anker
        ``audit_artifacts/readiness_trusted_pubkeys.txt`` steht in
        ``scripts/audit_candidate_matrix.py`` Zeile 273 — und er wird dort ueber
        ``git show HEAD:…`` gelesen (:352-357), nicht von der Platte. Das ist der TRAGENDE Grund,
        und meine erste Fassung nannte nur die schwaechere Haelfte: der Anker waere auch dann
        unlesbar, wenn das Paket ihn MITLIEFERTE, weil kein sdist ein ``.git`` mitbringt (gemessen
        im entpackten Baum, in dem die Datei noch physisch lag: ``zustand='unmeasurable'``, Ursache
        ``fatal: not a git repository``). Dass ``audit_artifacts`` zusaetzlich geprunt ist
        (MANIFEST.in Zeile 119), ist die zweite Absicherung, nicht der Grund.
        ``test_release_text_hygiene`` nennt nur
        ``scripts`` und faehrt ``betreffs_seit("HEAD")``, also git ueber den Baum; im entpackten sdist
        gibt es kein Repository, und ein leerer Commitbereich ist dort der Normalzustand statt des
        Fehlerfalls, den der Test misst. Beides ist woertlich der in ``conftest`` beschriebene Fall:
        "modules whose repo dependency is not visible as a path literal (an env probe, a subprocess
        into the tree)". Kein Wachstum durch Aufzaehlung, sondern die Stelle, an der eine statische
        Messung AM MODUL endet.

        Die Gegenprobe dazu liefert nicht diese Datei, sondern der Job ``hermetic-cleanroom``: er
        faehrt die Suite aus dem entpackten sdist. Auf VIER der fuenf Koepfe (7c9826d, 733a8c4,
        83a25e6, 5e9aa66) waren dort genau diese neun Tests rot — acht mit
        ``'unmeasurable' != 'ok'``, der neunte (``test_release_text_hygiene``) mit einem eigenen
        git-Fehlerbild. Auf dem fuenften, aelteren Kopf 37eab91 existierte
        ``tests/test_release_text_hygiene.py`` noch nicht (Erstcommit 38fa7937 am 07.09.), dort
        waren es die acht vorhandenen, alle acht rot. Keiner stammt aus der Arbeit dieses Tages.
        ENTSCHAERFT nach der Gegenlesung 07.09.2026 (Linse 4): die erste Fassung schrieb "auf fuenf
        Koepfen genau diese neun" und behauptete damit mehr, als die Messung traegt — die Substanz
        blieb, die Ueberpraezisierung ist weg.

        DER FUENFTE GRUND, 08.09.2026, und er ist eine FOLGE des Fixes zu L6-600-01: seit dem wird
        ein Modul, dessen Import an einer nicht ausgelieferten Datei scheitert, in einer Verteilung
        uebersprungen statt das Sammeln abzubrechen. `tests/test_budget_axis_measurement.py` liefert
        aus dem sdist damit NULL Tests — und `test_mutationstor_sammler_sieht_die_freigabeflaeche`
        verlangt, dass jede Testdatei dem Sammler des Mutationstors mindestens einen liefert.

        DIESER FALL GEHOERT AUS DREI GRUENDEN IN DEN RUECKFALL UND NICHT IN EINE AUSNAHMELISTE DES
        TORS. Erstens ist sein Gegenstand das MUTATIONSTOR, und das laeuft im Checkout, nie aus
        einer Verteilung. Zweitens erreicht er den Baum ueber einen UNTERPROZESS
        (`_gesehene_dateien` faehrt `pytest --collect-only` gegen `tests`) — woertlich der in
        `conftest` beschriebene Fall, und eine statische Ableitung kann ihn nicht sehen, weil das
        einzige Literal `tests` ist und das gibt es hier. Drittens waere die naheliegende Loesung
        falsch: das Tor bietet `_OHNE_TESTS_ERLAUBT` an, aber dort steht "diese Datei darf DAUERHAFT
        keinen Test liefern" — und im Checkout liefert sie fuenf. Gemessen am 08.09.2026:
        `pytest tests/test_budget_axis_measurement.py --collect-only` ergibt `5 tests collected`,
        und der Sammelaufruf des Tors selbst zaehlt fuer diese Datei ebenfalls genau 5. Ein Eintrag
        dort haette echte Abdeckung stillgelegt, um eine Messung an der falschen Flaeche gruen zu
        bekommen.
        """
        rueckfall = {"test_audit_candidate_360", "test_claims_hygiene", "test_fork_pr_secret_isolation",
                     "test_roadmap_frontload_foundations", "test_rust_parity_gate",
                     "test_pre_tag_receipt_commit_flow",
                     "test_not_after_gilt_auch_auf_dem_registerpfad", "test_release_text_hygiene",
                     "test_mutationstor_sammler_sieht_die_freigabeflaeche"}
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


class DerHookWendetDieAbleitungAUCH_AN(unittest.TestCase):
    """DIE ABLEITUNG KANN RICHTIG SEIN UND TROTZDEM NICHT ANGEWANDT WERDEN.

    SCHWERSTER FUND der Gegenlesung 07.09.2026 (Linse 3, Mutant M5): ``pytest_collection_modifyitems``
    — die Stelle, die die Ableitung tatsaechlich in Skip-Marker uebersetzt — hatte in dieser Datei
    KEINEN EINZIGEN Aufruf. Ihr ``or`` zu einem ``and`` zu machen schaltet den kompletten
    Ableitungspfad ab, sodass wieder ALLEIN die Liste entscheidet — exakt die Klasse, gegen die diese
    Datei laut ihrem eigenen Kopf steht. Die Datei blieb dabei bei ``16 passed``: drei Mutationen an
    der Ableitungsfunktion wurden gefangen, die eine an ihrer ANWENDUNG nicht.

    Die Lehre ist allgemeiner als der eine Operator: eine Funktion zu pruefen und ihren einzigen
    Aufrufer nicht, prueft die Haelfte, die nicht wirkt. Deshalb misst diese Klasse den Hook selbst,
    und zwar in beide Richtungen — er muss ueberspringen, wenn er soll, und NICHT ueberspringen,
    wenn er nicht soll.
    """

    class _Posten:
        """Das Minimum, das der Hook von einem pytest-Item liest: Datei, Name, add_marker."""

        def __init__(self, datei, name):
            self.fspath = datei
            self.name = name
            self.originalname = name
            self.marker = []

        def add_marker(self, m):
            self.marker.append(m)

    def _marker(self, *, abgeleitet, liste, im_checkout=False,
                stem="test_irgendwas", methode="test_x"):
        """Faehrt den echten Hook mit gesetzten Antworten seiner beiden Quellen."""
        alt = (cf.running_in_repo_checkout, cf.modul_ist_repo_kontext, cf._REPO_CONTEXT_TESTS)
        cf.running_in_repo_checkout = lambda: im_checkout
        cf.modul_ist_repo_kontext = lambda pfad, wurzel=None: abgeleitet
        cf._REPO_CONTEXT_TESTS = frozenset(liste)
        try:
            posten = self._Posten(f"/nirgends/tests/{stem}.py", methode)
            cf.pytest_collection_modifyitems(None, [posten])
            return posten.marker
        finally:
            (cf.running_in_repo_checkout, cf.modul_ist_repo_kontext,
             cf._REPO_CONTEXT_TESTS) = alt

    def test_die_ABLEITUNG_allein_genuegt_fuer_den_skip(self):
        """DER MUTANTENTOETER. Ohne diesen Test ist ``or`` von ``and`` nicht zu unterscheiden."""
        self.assertEqual(len(self._marker(abgeleitet=True, liste=[])), 1,
                         "ein Modul, das die Ableitung als repo-kontext erkennt, bekommt keinen Skip "
                         "— der Ableitungspfad ist abgeschaltet, es entscheidet wieder die Liste allein")

    def test_die_LISTE_allein_genuegt_ebenfalls(self):
        """Die zweite Haelfte derselben Verknuepfung: der dokumentierte Rueckfall muss wirken."""
        self.assertEqual(
            len(self._marker(abgeleitet=False, liste=["test_irgendwas::test_x"])), 1,
            "ein gelisteter Eintrag bekommt keinen Skip — der Rueckfall ist wirkungslos")

    def test_gegenrichtung_ohne_beides_wird_NICHTS_uebersprungen(self):
        """Ohne diese Richtung waere ein Hook, der ALLES markiert, von einem richtigen nicht zu
        unterscheiden — und aus dem sdist liefe nichts mehr, was wie 'gruen' aussaehe."""
        self.assertEqual(self._marker(abgeleitet=False, liste=[]), [],
                         "ein Modul ohne jeden Grund wurde uebersprungen")

    def test_im_checkout_bleibt_der_hook_ein_no_op(self):
        """Im echten Checkout darf NICHTS uebersprungen werden, egal was die Quellen sagen —
        sonst faellt in CI stillschweigend Deckung weg."""
        self.assertEqual(
            self._marker(abgeleitet=True, liste=["test_irgendwas::test_x"], im_checkout=True), [],
            "im Checkout wurde uebersprungen — die Deckung faellt still weg")


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
        # ZWEITE BEDINGUNG (deep gate Lauf 8, Fund L6-600-04): `_in_git_checkout` fragt, ob HIER
        # ein Repositorium wurzelt — eine FORM. Ein Paketierer, der im entpackten sdist `git init`
        # ausfuehrt (dpkg-source, gbp, Nix/Guix, oder wer lokale Patches verfolgt), macht die Form
        # wahr, waehrend die EIGENSCHAFT falsch bleibt: das sdist liefert weder `tools/` noch
        # `.gitignore`, und ohne Ignore-Datei kann `_ist_bauartefakt` gar nicht antworten. Gemessen:
        # in dieser Lage FIEL der Fall, statt zu ueberspringen. `running_in_repo_checkout` fragt
        # genau die Eigenschaft (Marker .github/tools/SPEC.md) und liegt eine Datei weiter.
        if not (_in_git_checkout() and cf.running_in_repo_checkout()):
            self.skipTest("kein Quell-Checkout dieses Projekts (entpacktes sdist, ggf. mit eigenem "
                          "git init) — die Ignore-Regel ist hier nicht messbar, und nicht messbar "
                          "ist keine Freigabe")
        self.assertFalse(cf._ist_bauartefakt(REPO, "tools/pb_verify_rs/crosscheck.py"),
                         "eine echte Quelldatei gilt als Bauartefakt — die Ableitung wuerde blind")
        self.assertTrue(cf._ist_bauartefakt(REPO, "tools/pb_verify_rs/target/release/pb_verify_rs"),
                        "das Rust-Binary gilt nicht als Bauartefakt — der Fall kehrt zurueck")

    @unittest.skipUnless(shutil.which("git"), "ohne git ist die Frage nicht messbar")
    def test_ein_unterverzeichnis_eines_FREMDEN_repos_ist_nicht_dieser_baum(self):
        """DIE REGRESSIONSPROBE ZU L6-600-01, die bis 07.09.2026 fehlte.

        Gefunden von der Gegenlesung (Linse 3, Mutant M4): ``_dieser_baum_ist_das_repo`` auf
        ``--is-inside-work-tree`` zurueckzudrehen — also exakt der Fehler, den der Docstring dieser
        Funktion als behoben beschreibt — liess die Datei bei 16 passed. Kein Test rief die Funktion
        je mit einer Wurzel auf, die Unterverzeichnis eines FREMDEN Repositoriums ist; alle nutzten
        entweder das echte Toplevel oder ein Tempverzeichnis ganz ohne git. Der behobene Fall hatte
        keinen Waechter, und ein Fix ohne Waechter faellt beim naechsten Umbau still zurueck.

        Nachgestellt wird die reale Lage: ein Konsument entpackt das sdist unter ``vendor/`` SEINES
        Checkouts, dessen ``.gitignore`` ``target/`` ignoriert. Unter dem alten Verhalten meldete
        ``check-ignore`` dort fuer jeden Pfad "ignoriert", die Ableitung las alles als ungebautes
        Bauartefakt und schaltete sich selbst ab.
        """
        import subprocess  # noqa: PLC0415
        tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        fremd = tmp / "fremd"
        (fremd / "vendor" / "entpacktes_sdist").mkdir(parents=True)
        (fremd / ".gitignore").write_text("target/\n", encoding="utf-8")
        subprocess.run(["git", "init", "-q", str(fremd)], check=True, capture_output=True)

        self.assertTrue(cf._dieser_baum_ist_das_repo(fremd),
                        "die Wurzel des fremden Baums wurde nicht als Baum erkannt — dann misst der "
                        "Test die falsche Sache")
        self.assertFalse(cf._dieser_baum_ist_das_repo(fremd / "vendor" / "entpacktes_sdist"),
                         "ein Unterverzeichnis eines FREMDEN Repositoriums gilt als dieser Baum — "
                         "die Verwechslung aus L6-600-01 ist zurueck")
        self.assertFalse(cf._ist_bauartefakt(fremd / "vendor" / "entpacktes_sdist",
                                             "tools/pb_verify_rs/target/release/pb_verify_rs"),
                         "die Ignore-Regel des FREMDEN Baums wurde befragt — damit liest jeder "
                         "geprunte Pfad als ungebautes Artefakt und die Ableitung schaltet sich ab")

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

    def test_eine_GEMISCHTE_schleife_bleibt_unbestimmbar(self):
        """Die Schranke "ALLE Elemente konstant" hatte keinen Test (Linse 3, Mutant M7).

        Sie auf "mindestens eines konstant" abzuschwaechen liess die Datei bei 16 passed. Die
        Schranke ist aber die Grenze zwischen Aufloesen und Raten: bei ``(konstant, variabel)``
        nimmt die Variable auch Werte an, die hier nirgends stehen, und ein daraus gebauter Pfad
        waere erfunden. Erfundene fehlende Pfade lassen ein Modul ausserhalb eines Checkouts STILL
        ausfallen — die schaedliche Richtung. Unbestimmbar heisst deshalb: nicht binden.
        """
        p = self._modul("test_gemischt.py",
                        'from pathlib import Path\n'
                        'def test_x(fall):\n'
                        '    root = Path(__file__).resolve().parent.parent\n'
                        '    for rel in ("docs/FEHLT.md", fall):\n'
                        '        (root / rel).read_text()\n')
        self.assertFalse(cf.modul_ist_repo_kontext(p, wurzel=self.tmp),
                         "eine gemischte Schleife wurde aufgeloest — die Ableitung raet jetzt, statt "
                         "unbestimmbar zu bleiben")

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
