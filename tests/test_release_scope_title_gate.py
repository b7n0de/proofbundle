"""A scope line without its identifier in the title is invisible to the count that tracks it.

`docs/release_scope/<version>.md` maps one identifier to one branch to one pull request. The
landing card counts what landed by reading identifiers out of pull-request titles on main. A title
without its identifier therefore does not merely look untidy — it drops the item out of the count
that is supposed to prove it landed. Owner decision 2026-09-14 fixed the form:
`[<version> <ID>] type(scope): subject`, English, exactly one identifier.

The riders are an exception BY CONSTRUCTION: scope lines with no branch of their own can never be
a pull request, so they can never trigger the gate. That is derived from the file, not copied out
of it — a copied list is a second truth that ages the moment the file moves.
"""
import importlib.util
import pathlib
import unittest

REPO = pathlib.Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    "scope_title_gate", REPO / "scripts" / "b7_release_scope_title_gate.py")
GATE = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(GATE)

UMFANG = """# Release scope — 9.9.9 (Probe)

## In — Spalte 1

| Punkt | Zweig |
|---|---|
| N3-1 Der Beleg verlaesst den geprueften Baum | `feat/999-beleg` |
| N3-2 Commit und Baum gemeinsam binden | `feat/999-commit` |
| C1 sdist bitreproduzierbar | `fix/999-sdist` |
| C2 Release-Notiz fortschreiben | mit C1 |
| N14 Emit und assemble | = B1/B2 |

## Out — und jedes Out nennt seinen Grund

| Punkt | Zweig |
|---|---|
| X9 Gestrichen, steht hier nur als Begruendung | `feat/999-gestrichen` |
"""


class TestUmfangGelesen(unittest.TestCase):
    def setUp(self):
        import tempfile
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)          # `enterContext` gibt es erst ab 3.11, Boden ist 3.10
        self.p = pathlib.Path(td.name)
        self.datei = self.p / "9.9.9.md"
        self.datei.write_text(UMFANG, encoding="utf-8")

    def test_nur_der_in_abschnitt_zaehlt(self):
        """Eine Zeile unter Out ist ausdruecklich NICHT gebaut. Wer sie mitzaehlt, verlangt eine
        Kennung fuer etwas, das es nicht geben soll."""
        zu_zweig, mitlaeufer, zustand = GATE.lies_umfang(self.datei)
        self.assertEqual(zustand, "gemessen")
        self.assertIn("feat/999-beleg", zu_zweig)
        self.assertEqual(zu_zweig["feat/999-beleg"], ["N3-1"])
        self.assertNotIn("feat/999-gestrichen", zu_zweig,
                         "die Out-Zeile darf nicht in der Pruefmenge stehen")

    def test_die_mitlaeufer_haben_keinen_zweig_und_koennen_nie_ausloesen(self):
        zu_zweig, mitlaeufer, _ = GATE.lies_umfang(self.datei)
        self.assertEqual(sorted(mitlaeufer), ["C2", "N14"])
        alle = {k for ks in zu_zweig.values() for k in ks}
        self.assertNotIn("C2", alle, "ein Mitlaeufer mit Zweig waere kein Mitlaeufer")

    def test_eine_fehlende_datei_ist_nicht_messbar_statt_leer(self):
        """Eine leere Abbildung aus einer fehlenden Datei sieht aus wie eine aus einem leeren
        Umfang, und die beiden bedeuten das Gegenteil voneinander."""
        _, _, zustand = GATE.lies_umfang(self.p / "gibtsnicht.md")
        self.assertIn("NICHT MESSBAR", zustand)


class TestDasTorUrteilt(unittest.TestCase):
    def setUp(self):
        import tempfile
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)          # `enterContext` gibt es erst ab 3.11, Boden ist 3.10
        self.p = pathlib.Path(td.name)
        self.datei = self.p / "9.9.9.md"
        self.datei.write_text(UMFANG, encoding="utf-8")

    def _u(self, branch, title, datei=None):
        return GATE.pruefe(branch=branch, title=title, version="9.9.9",
                           scope_pfad=datei or self.datei)

    def test_richtige_kennung_ist_gruen(self):
        d = self._u("feat/999-beleg", "[9.9.9 N3-1] feat(receipt): it leaves the tree")
        self.assertEqual(d["urteil"], "gruen", d["gruende"])
        self.assertEqual(d["kennung_des_zweigs"], "N3-1")

    def test_fehlende_kennung_ist_ROT(self):
        d = self._u("feat/999-beleg", "feat(receipt): it leaves the tree")
        self.assertEqual(d["urteil"], "ROT")
        self.assertTrue(any("keine Umfangskennung" in g for g in d["gruende"]), d["gruende"])

    def test_die_FALSCHE_kennung_ist_ROT(self):
        """Der gefaehrlichere Fall: eine Kennung IST da, sie zeigt nur woanders hin. Ein Tor, das
        nur die Anwesenheit prueft, faellt hier nicht — und die Landekarte zaehlt die falsche Zeile."""
        d = self._u("feat/999-beleg", "[9.9.9 N3-2] feat(receipt): wrong line")
        self.assertEqual(d["urteil"], "ROT")
        self.assertTrue(any("verschiedene Zeilen" in g for g in d["gruende"]), d["gruende"])

    def test_zwei_kennungen_sind_ROT(self):
        d = self._u("feat/999-beleg", "[9.9.9 N3-1] [9.9.9 N3-2] feat(x): two at once")
        self.assertEqual(d["urteil"], "ROT")
        self.assertTrue(any("genau eine je" in g for g in d["gruende"]), d["gruende"])

    def test_ein_fremder_zweig_wird_als_AUSSERHALB_gemeldet_nicht_als_bestanden(self):
        """Der Unterschied traegt: 'nicht geprueft' ist keine Aussage ueber den Inhalt."""
        d = self._u("chore/etwas-anderes", "chore: unrelated")
        self.assertEqual(d["urteil"], "gruen")
        self.assertTrue(d["ausserhalb_des_umfangs"])
        self.assertIsNone(d["kennung_des_zweigs"])

    def test_ein_mitlaeufer_kann_das_tor_nicht_ausloesen(self):
        """C2 faehrt mit C1. Es gibt keinen Zweig, der auf C2 zeigt, also auch keinen Pull Request."""
        zu_zweig, _, _ = GATE.lies_umfang(self.datei)
        self.assertNotIn("C2", zu_zweig)
        d = self._u("fix/999-sdist", "[9.9.9 C1] fix(sdist): reproducible")
        self.assertEqual(d["urteil"], "gruen", d["gruende"])
        self.assertEqual(d["kennung_des_zweigs"], "C1")

    def test_eine_fehlende_umfangsdatei_sperrt_statt_durchzulassen(self):
        d = self._u("feat/999-beleg", "[9.9.9 N3-1] feat(x): y", datei=self.p / "weg.md")
        self.assertEqual(d["urteil"], "ROT")
        self.assertTrue(any("Unkenntnis sperrt" in g for g in d["gruende"]), d["gruende"])

    def test_ein_zweig_bei_zwei_zeilen_ist_ROT(self):
        doppelt = UMFANG.replace("| N3-2 Commit und Baum gemeinsam binden | `feat/999-commit` |",
                                 "| N3-2 Commit und Baum gemeinsam binden | `feat/999-beleg` |")
        p = self.p / "doppelt.md"
        p.write_text(doppelt, encoding="utf-8")
        d = self._u("feat/999-beleg", "[9.9.9 N3-1] feat(x): y", datei=p)
        self.assertEqual(d["urteil"], "ROT")
        self.assertTrue(any("MEHREREN" in g for g in d["gruende"]), d["gruende"])

    def test_es_gibt_nur_zwei_urteile(self):
        for b, t in [("feat/999-beleg", "x"), ("chore/x", "y"),
                     ("feat/999-beleg", "[9.9.9 N3-1] ok")]:
            self.assertIn(self._u(b, t)["urteil"], {"gruen", "ROT"})


class TestDieDateiSelbst(unittest.TestCase):
    """Eine Kennung, die zwei Zeilen anfuehrt, macht den Titel mehrdeutig — und die Landekarte
    zaehlt zwei Zeilen als eine. Das ist ein Befund ueber die DATEI, nicht ueber den Pull Request."""

    def setUp(self):
        import tempfile
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.p = pathlib.Path(td.name)

    def _datei(self, text):
        d = self.p / "s.md"
        d.write_text(text, encoding="utf-8")
        return d

    def test_eindeutige_kennungen_sind_gruen(self):
        d = GATE.pruefe_umfangsdatei(self._datei(UMFANG))
        self.assertEqual(d["urteil"], "gruen", d["gruende"])
        self.assertEqual(d["kollisionen"], {})

    def test_eine_doppelt_vergebene_kennung_ist_ROT(self):
        doppelt = UMFANG.replace(
            "| N3-2 Commit und Baum gemeinsam binden | `feat/999-commit` |",
            "| N3-1 Etwas ganz anderes mit derselben Kennung | `feat/999-commit` |")
        d = GATE.pruefe_umfangsdatei(self._datei(doppelt))
        self.assertEqual(d["urteil"], "ROT")
        self.assertIn("N3-1", d["kollisionen"])
        self.assertEqual(len(d["kollisionen"]["N3-1"]), 2)

    def test_die_zaehleinheit_ist_die_ZEILE(self):
        """Wer ueber Kennungen zaehlt, zaehlt bei Kollisionen zu wenig; wer ueber Zweige zaehlt,
        laesst die Mitlaeufer weg. Beide Zahlen sind kleiner als die Zeilenzahl."""
        zeilen, zustand = GATE.fuehrende_kennungen(self._datei(UMFANG))
        self.assertEqual(zustand, "gemessen")
        zu_zweig, mit, _ = GATE.lies_umfang(self._datei(UMFANG))
        self.assertEqual(len(zeilen), 5, "fuenf In-Zeilen in der Vorrichtung")
        self.assertEqual(len(zu_zweig) + len(mit), 5)
        self.assertGreaterEqual(len(zeilen), len({k for k, _, _ in zeilen}))

    def test_eine_fehlende_datei_ist_ROT_nicht_leer_gruen(self):
        d = GATE.pruefe_umfangsdatei(self.p / "weg.md")
        self.assertEqual(d["urteil"], "ROT")
        self.assertEqual(d["zeilen"], 0)

    def test_eine_mehrdeutige_kennung_faellt_ROT(self):
        """DIESER FALL HAT SEIN VORZEICHEN GEWECHSELT, und das gehoert hierher statt in ein Archiv.

        Die erste Fassung liess so einen Pull Request GRUEN durch, mit einem Vermerk, und begruendete
        das damit, der Autor koenne ja nur die eine Kennung schreiben, die es gibt. Die Gegenlesung
        der fremden Modellfamilie (qwen3.8:27b, 16.09.2026) hat das widerlegt, und der Einwand
        traegt: der ZWECK dieses Riegels ist die eindeutige Zaehlbarkeit. Ein Titel, den die
        Landekarte nicht zuordnen kann, verfehlt ihn — gleich wem die Schuld gehoert. Gruen hiesse
        hier: der Pull Request ist in Ordnung, obwohl sein Landen nicht zaehlbar ist.

        Die Reparatur steht dem Autor offen, sie ist nur nicht im Titel: die Kennung in der
        Umfangsdatei aufteilen. Der Grund sagt das, statt ihn ratlos stehen zu lassen.
        """
        doppelt = UMFANG.replace(
            "| N3-2 Commit und Baum gemeinsam binden | `feat/999-commit` |",
            "| N3-1 Etwas ganz anderes mit derselben Kennung | `feat/999-commit` |")
        d = GATE.pruefe(branch="feat/999-beleg", title="[9.9.9 N3-1] feat(x): y",
                        version="9.9.9", scope_pfad=self._datei(doppelt))
        self.assertEqual(d["urteil"], "ROT", d["gruende"])
        self.assertTrue(d["kennung_mehrdeutig"])
        self.assertTrue(any("nicht zuordenbar" in g for g in d["gruende"]), d["gruende"])
        self.assertTrue(any("die Kennung aufteilen" in g for g in d["gruende"]), d["gruende"])

    def test_ohne_den_Out_abschnitt_ist_der_umfang_NICHT_MESSBAR(self):
        """Der zweite Befund derselben Gegenlesung: ohne die Grenze galt die GANZE Datei als
        Umfang, samt der Zeilen, die ausdruecklich nicht gebaut werden. Ein Riegel, der bei
        fehlender Struktur seine Pruefmenge VERGROESSERT, urteilt danach ueber Zeilen, die niemand
        bauen wollte — und nennt das eine Messung."""
        ohne = UMFANG.split("## Out")[0]
        d = self._datei(ohne)
        zu_zweig, _, zustand = GATE.lies_umfang(d)
        self.assertIn("NICHT MESSBAR", zustand)
        self.assertEqual(zu_zweig, {})
        zeilen, z2 = GATE.fuehrende_kennungen(d)
        self.assertIn("NICHT MESSBAR", z2)
        self.assertEqual(zeilen, [])
        u = GATE.pruefe(branch="feat/999-beleg", title="[9.9.9 N3-1] feat(x): y",
                        version="9.9.9", scope_pfad=d)
        self.assertEqual(u["urteil"], "ROT", u["gruende"])


class TestGegenDieECHTEUmfangsdatei(unittest.TestCase):
    """Die Probe gegen den wirklichen 6.1.0-Umfang, falls er im Baum liegt.

    Ohne sie prueft alles oben nur eine selbstgebaute Vorrichtung — und eine Vorrichtung, die nur
    sich selbst kennt, ist genau die Koinzidenz, gegen die dieses Haus sonst antritt.
    """

    def setUp(self):
        """Die echte Datei, egal ob sie gerade im Arbeitsbaum ausgecheckt ist.

        WARUM NICHT EINFACH UEBERSPRINGEN. Bis 2026-09-16 tat dieser Aufbau genau das: liegt
        `docs/release_scope/6.1.0.md` nicht im Baum, skipTest. Gemessen: die Datei liegt auf 33
        Zweigen, aber nicht auf `main`, also sprangen alle drei Faelle immer. Ein uebersprungener
        Fall kann nicht fallen — der Mutationsnachweis gegen sie blieb gruen und belegte nichts.
        Dieselbe Klasse, gegen die dieser ganze Riegel steht: Abwesenheit liest sich als Ordnung.

        Deshalb wird die Datei aus dem OBJEKTSPEICHER geholt, wenn der Arbeitsbaum sie nicht
        auscheckt. Uebersprungen wird nur noch, wenn sie in KEINEM Zweig existiert — und das waere
        eine Aussage ueber das Repository, nicht ueber den Arbeitsbaum.
        """
        import subprocess
        import tempfile
        im_baum = REPO / "docs" / "release_scope" / "6.1.0.md"
        if im_baum.is_file():
            self.echt = im_baum
            return
        zweige = subprocess.run(
            ["git", "-C", str(REPO), "for-each-ref", "--format=%(refname:short)",
             "refs/heads", "refs/remotes"], capture_output=True, text=True).stdout.split()
        for b in zweige:
            if b.endswith("/HEAD"):
                continue
            r = subprocess.run(["git", "-C", str(REPO), "show",
                                f"{b}:docs/release_scope/6.1.0.md"],
                               capture_output=True, text=True)
            if r.returncode == 0 and r.stdout.strip():
                td = tempfile.TemporaryDirectory()
                self.addCleanup(td.cleanup)
                self.echt = pathlib.Path(td.name) / "6.1.0.md"
                self.echt.write_text(r.stdout, encoding="utf-8")
                self.aus_zweig = b
                return
        self.skipTest("docs/release_scope/6.1.0.md existiert in KEINEM Zweig dieses "
                      "Repositorys — NICHT MESSBAR, und das ist eine Aussage ueber das "
                      "Repository, nicht ueber den Arbeitsbaum")

    def test_der_echte_umfang_liest_sich_und_traegt_neun_mitlaeufer(self):
        zu_zweig, mitlaeufer, zustand = GATE.lies_umfang(self.echt)
        self.assertEqual(zustand, "gemessen")
        self.assertGreater(len(zu_zweig), 30)
        self.assertEqual(len(mitlaeufer), 9,
                         f"der Auftrag nennt neun Mitlaeufer, gelesen {sorted(mitlaeufer)}")

    def test_die_zeilenzahl_des_echten_umfangs_ist_die_zahl_des_auftrags(self):
        """Der Auftrag nennt 55. Gemessen sind es 55 ZEILEN — nicht 52 Kennungen und nicht 44
        Zweige. Die Zaehleinheit war die Stelle, an der meine erste Rechnung danebenlag."""
        zeilen, zustand = GATE.fuehrende_kennungen(self.echt)
        self.assertEqual(zustand, "gemessen")
        self.assertEqual(len(zeilen), 55)

    def test_der_echte_umfang_traegt_drei_doppelt_vergebene_kennungen(self):
        """A1, A2 und A3 stehen je zweimal: einmal aus dem Sammelauftrag, einmal aus
        RESTRISIKO_600. Solange das so ist, ist ein Titel [6.1.0 A1] nicht eindeutig."""
        d = GATE.pruefe_umfangsdatei(self.echt)
        self.assertEqual(d["urteil"], "ROT")
        self.assertEqual(sorted(d["kollisionen"]), ["A1", "A2", "A3"], d["kollisionen"])


if __name__ == "__main__":
    unittest.main()


# ---------------------------------------------------------------------------------------------
# CODEX ROUND ONE, 2026-09-16. Two findings on this pull request's own head, each reproduced here
# before it was fixed. The first has no test, because its subject is the absence of a caller and
# that lives in the workflow file; it is covered by the wiring case at the bottom.
# ---------------------------------------------------------------------------------------------

def _gruen(tmp_path, title, branch="feat/a", kennung="A1"):
    pfad = tmp_path / "scope.md"
    pfad.write_text(
        "| Punkt | Zweig |\n|---|---|\n"
        f"| **{kennung}** etwas | `{branch}` |\n\n## Out\n", encoding="utf-8")
    return GATE.pruefe(branch=branch, title=title, version="6.1.0", scope_pfad=pfad)["urteil"]


def test_ROT_codex_runde_eins_p2_ein_falsches_praefix_faellt(tmp_path):
    """Reported and re-measured: `WRONG PREFIX [6.1.0 A1] nonsense` was green.

    The old expression was an unanchored `findall` and asked only WHETHER the bracket occurs.
    """
    assert _gruen(tmp_path, "WRONG PREFIX [6.1.0 A1] nonsense") == "ROT"


def test_ROT_codex_runde_eins_p2_eine_zweite_kennung_fremder_version_faellt(tmp_path):
    """The old version counted ONLY matches of the current version, so the second stayed invisible."""
    assert _gruen(tmp_path, "[6.1.0 A1] [6.0.1 R1] feat(scope): subject") == "ROT"


def test_ROT_ein_titel_ohne_betreffform_faellt(tmp_path):
    """NOT in the Codex report, found while re-measuring: a bracket at the END was green as well."""
    assert _gruen(tmp_path, "irgendwas [6.1.0 A1]") == "ROT"


def test_ROT_eine_fremde_version_am_anfang_faellt(tmp_path):
    """The shape holds, the version does not. That needs its own sentence, not a shape message."""
    d_titel = "[6.0.1 A1] feat(scope): subject"
    assert _gruen(tmp_path, d_titel) == "ROT"


def test_GRUEN_die_vertragsform_bleibt_gruen(tmp_path):
    assert _gruen(tmp_path, "[6.1.0 A1] feat(scope): subject") == "gruen"


def test_GRUEN_der_bereich_ist_optional(tmp_path):
    """`type: subject` without a scope is valid Conventional Commits form and stays green."""
    assert _gruen(tmp_path, "[6.1.0 A1] feat: subject") == "gruen"


def test_codex_runde_eins_p1_das_tor_hat_einen_aufrufer():
    """The first finding was that nothing calls this module. This case is the guard against that.

    It checks the EFFECT, not a file name: a workflow step that starts the script. Move the job or
    rename it and this stays green; remove the call and it goes red. Exactly the class that has hit
    this house three times already, where a mechanism without a caller is a promise, not a bound.
    """
    import pathlib as _p
    wurzel = _p.Path(__file__).resolve().parents[1]
    treffer = []
    for w in sorted((wurzel / ".github" / "workflows").glob("*.yml")):
        text = w.read_text(encoding="utf-8")
        for zeile in text.splitlines():
            if "b7_release_scope_title_gate.py" in zeile and "run:" in zeile:
                treffer.append(f"{w.name}: {zeile.strip()[:70]}")
    assert treffer, ("kein Workflow-Schritt startet b7_release_scope_title_gate.py — das Tor "
                     "haette wieder keinen Aufrufer, und ein Tor ohne Aufrufer ist nur eine Datei")


# ---------------------------------------------------------------------------------------------
# Found by running the first fix rather than by reading it, 2026-09-16. `\s` in Python matches
# U+00A0 and U+2009 as readily as a space, and it matches a newline, so the anchored expression
# bound the first line and said nothing about the rest.
#
# The first version of these very cases was toothless: the separators were typed as ordinary
# spaces in the source, so every case passed against BOTH versions of the expression and
# distinguished nothing. They carry escapes now.
# ---------------------------------------------------------------------------------------------

def test_ROT_ein_schmales_leerzeichen_ist_kein_trenner(tmp_path):
    assert _gruen(tmp_path, "[6.1.0\u2009A1] feat(scope): subject") == "ROT"


def test_ROT_ein_geschuetztes_leerzeichen_ist_kein_trenner(tmp_path):
    assert _gruen(tmp_path, "[6.1.0\u00a0A1] feat(scope): subject") == "ROT"


def test_ROT_ein_geschuetztes_leerzeichen_nach_der_klammer_faellt(tmp_path):
    """Every separator of the form, not just the first, or the gap merely moves along."""
    assert _gruen(tmp_path, "[6.1.0 A1]\u00a0feat(scope): subject") == "ROT"


def test_ROT_was_nach_einem_zeilenumbruch_steht_ist_teil_des_titels(tmp_path):
    """A title is ONE line. A rule that ends at the first break checks a prefix, not a title."""
    assert _gruen(tmp_path, "[6.1.0 A1] feat(scope): subject\nzweite Zeile") == "ROT"


def test_ROT_auch_ein_wagenruecklauf_beendet_den_titel_nicht(tmp_path):
    assert _gruen(tmp_path, "[6.1.0 A1] feat(scope): subject\r\nzweite") == "ROT"


def test_ROT_ein_tabulator_ist_kein_trenner(tmp_path):
    assert _gruen(tmp_path, "[6.1.0 A1]\tfeat(scope): subject") == "ROT"


def test_GRUEN_der_vertragstitel_bleibt_nach_der_verengung_gruen(tmp_path):
    """The narrowing must not take the intended form with it. This is the counterweight."""
    assert _gruen(tmp_path, "[6.1.0 A1] feat(scope): subject") == "gruen"


def test_die_genannte_grenze_ein_unsichtbares_zeichen_im_BETREFF_faellt_nicht(tmp_path):
    """Recorded EXPLICITLY as a limit, not as an assurance.

    The narrowing concerns the SEPARATORS of the form. A subject is free text, and a zero-width
    space inside one stays green. Changing that would change a decision about subjects rather
    than this expression, and a case that pins the limit is more honest than a claim about
    characters nobody checked.
    """
    assert _gruen(tmp_path, "[6.1.0 A1] feat(scope): sub\u200bject") == "gruen"

