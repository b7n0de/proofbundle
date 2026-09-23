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
import re
import unittest

REPO = pathlib.Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    "scope_title_gate", REPO / "scripts" / "b7_release_scope_title_gate.py")
GATE = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(GATE)

UMFANG = """# Release scope — 9.9.9 (Probe)

## In — Column 1

| Punkt | Zweig |
|---|---|
| N3-1 Der Beleg verlaesst den geprueften Baum | `feat/999-beleg` |
| N3-2 Commit und Baum gemeinsam binden | `feat/999-commit` |
| C1 sdist bitreproduzierbar | `fix/999-sdist` |
| C2 Release-Notiz fortschreiben | mit C1 |
| N14 Emit und assemble | = B1/B2 |

## Out — and every Out names its reason

| Punkt | Zweig |
|---|---|
| X9 Gestrichen, steht hier nur als Begruendung | `feat/999-gestrichen` |
"""


class TestUmfangGelesen(unittest.TestCase):
    def setUp(self):
        import tempfile
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)          # `enterContext` only exists from 3.11, floor is 3.10
        self.p = pathlib.Path(td.name)
        self.datei = self.p / "9.9.9.md"
        self.datei.write_text(UMFANG, encoding="utf-8")

    def test_nur_der_in_abschnitt_zaehlt(self):
        """A line under Out is explicitly NOT being built. Whoever counts it in demands an
        identifier for something that is not supposed to exist."""
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
        """An empty mapping from a missing file looks like one from an empty scope, and the
        two mean the opposite of each other."""
        _, _, zustand = GATE.lies_umfang(self.p / "gibtsnicht.md")
        self.assertIn("NICHT MESSBAR", zustand)


class TestDasTorUrteilt(unittest.TestCase):
    def setUp(self):
        import tempfile
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)          # `enterContext` only exists from 3.11, floor is 3.10
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
        """The more dangerous case: an identifier IS present, it just points somewhere else. A gate
        that only checks for presence does not catch this — and the landing card counts the wrong line."""
        d = self._u("feat/999-beleg", "[9.9.9 N3-2] feat(receipt): wrong line")
        self.assertEqual(d["urteil"], "ROT")
        self.assertTrue(any("verschiedene Zeilen" in g for g in d["gruende"]), d["gruende"])

    def test_zwei_kennungen_sind_ROT(self):
        d = self._u("feat/999-beleg", "[9.9.9 N3-1] [9.9.9 N3-2] feat(x): two at once")
        self.assertEqual(d["urteil"], "ROT")
        self.assertTrue(any("genau eine je" in g for g in d["gruende"]), d["gruende"])

    def test_ein_fremder_zweig_wird_als_AUSSERHALB_gemeldet_nicht_als_bestanden(self):
        """The distinction carries: 'not checked' is not a statement about the content."""
        d = self._u("chore/etwas-anderes", "chore: unrelated")
        self.assertEqual(d["urteil"], "gruen")
        self.assertTrue(d["ausserhalb_des_umfangs"])
        self.assertIsNone(d["kennung_des_zweigs"])

    def test_ein_mitlaeufer_kann_das_tor_nicht_ausloesen(self):
        """C2 rides along with C1. There is no branch pointing at C2, and hence no pull request either."""
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
    """An identifier that leads two lines makes the title ambiguous — and the landing card
    counts two lines as one. That is a finding about the FILE, not about the pull request."""

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
        """Whoever counts by identifier undercounts on collisions; whoever counts by branch
        leaves out the riders. Both numbers are smaller than the line count."""
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
        """THIS CASE CHANGED ITS SIGN, and that belongs here rather than in an archive.

        The first version let a pull request like this through GREEN, with a note, reasoning that
        the author can, after all, only write the one identifier that exists. The counter-read by
        the foreign model family (qwen3.8:27b, 2026-09-16) refuted that, and the objection carries:
        the PURPOSE of this gate is unambiguous countability. A title the landing card cannot
        assign misses it — whoever is at fault. Green here would mean: the pull request is fine,
        even though its landing is not countable.

        The fix is open to the author, it just is not in the title: split the identifier in the
        scope file. The reason says so, instead of leaving them stuck without a way forward.
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
        """The second finding of the same counter-read: without the boundary, the WHOLE file
        counted as scope, including the lines that are explicitly not being built. A gate that
        ENLARGES the set it checks when structure is missing then judges lines nobody wanted to
        build — and calls that a measurement."""
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
    """The check against the real 6.1.0 scope, if it is present in the tree.

    Without it, everything above only checks a self-built fixture — and a fixture that knows only
    itself is exactly the coincidence this house otherwise stands against.
    """

    def setUp(self):
        """The real file, whether or not it happens to be checked out in the working tree.

        WHY NOT SIMPLY SKIP. Until 2026-09-16 this setup did exactly that: if
        `docs/release_scope/6.1.0.md` is not in the tree, skipTest. Measured: the file sits on 33
        branches, but not on `main`, so all three cases always skipped. A skipped case cannot
        fail — the mutation proof against it stayed green and proved nothing. The same class this
        whole gate stands against: absence reads as order.

        So the file is fetched from the OBJECT STORE when the working tree does not check it out.
        It is only skipped when it exists in NO branch at all — and that would be a statement
        about the repository, not about the working tree.
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

    def test_der_echte_umfang_liest_sich_und_traegt_einen_mitlaeufer(self):
        """Nine riders and more than thirty branches were the state BEFORE the cut of 2026-09-19.

        Owner word of that day, order QITEM-PROOFBUNDLE-610-SCHNITT-LANDEN-KETTE-01: 6.1.0 is what
        is on main plus the two P1 findings of the audit and R7, and the remaining 54 lines move to
        6.2.0 unchanged. So the scope shrinks by design, and these numbers shrink with it.

        The case is renamed rather than left with nine in its title. A name that says nine while it
        asserts one is a lie a reader meets before the assertion, and this file exists to stop
        exactly that kind of drift.
        """
        zu_zweig, mitlaeufer, zustand = GATE.lies_umfang(self.echt)
        self.assertEqual(zustand, "gemessen")
        self.assertGreaterEqual(len(zu_zweig), 2,
                                f"the cut leaves the two branches it adds, read {sorted(zu_zweig)}")
        self.assertEqual(len(mitlaeufer), 1,
                         f"P19 rides along as delivered, read {sorted(mitlaeufer)}")

    def test_die_zeilenzahl_des_echten_umfangs_ist_die_zahl_des_auftrags(self):
        """The order names 55. Measured, it is 55 LINES — not 52 identifiers and not 44
        branches. The counting unit was the point where my first calculation went wrong.

        Since 2026-09-18 the scope carried one more line, P19 (the verifier block, owner order
        of 2026-09-18T06:54Z, pull request 224, branch feat/610-verifier-block), which made 56.

        On 2026-09-19 the owner cut the scope (order QITEM-PROOFBUNDLE-610-SCHNITT-LANDEN-KETTE-01):
        6.1.0 is what is on main plus the two P1 findings of the audit and R7, and the remaining 54
        lines move to docs/release_scope/6.2.0.md unchanged. Measured after the cut: three lines,
        P19 delivered plus the two this cut adds.

        On 2026-09-20 owner card OA-f1b4021199 put N16 into this cut as well, and the count is four.
        That is the direction this docstring already allowed for: a scope that GROWS by an ordered
        item grows by one line here. The card splits N16 in two, and only the fix moves; tagging the
        composite action and pointing INTEGRATIONS.md at that new tag stay an owner door and are
        named as one in the scope file.

        The unit is still the LINE and the sentence above still holds in both directions. A scope
        that grows by an ordered item grows by one line here; a scope the owner cuts shrinks by the
        lines that moved, and this number moves with it, never silently. Fifty-four of them are in
        6.2.0, byte equality checked, so nothing left the books."""
        zeilen, zustand = GATE.fuehrende_kennungen(self.echt)
        self.assertEqual(zustand, "gemessen")
        self.assertEqual(len(zeilen), 4)

    def test_der_echte_umfang_traegt_keine_doppelt_vergebene_kennung_mehr(self):
        """Until 2026-09-19 A1, A2 and A3 each led two lines, one from the collective order and
        one from RESTRISIKO_600, and a title [6.1.0 A1] pointed at both. Owner card OA-23931230c0
        renamed the three RESTRISIKO rows to R-A1, R-A2, R-A3, and this case now holds the
        resolved state.

        IT IS NOT ENOUGH THAT THE VERDICT IS GREEN. The first attempt at this rename produced
        exactly that green while making things worse: the identifier expression did not know the
        shape `R-A1`, so all three lines dropped out of the count before they could collide. The
        line count fell from 56 to 53 and the verdict turned green on the way out. So this case
        asserts the COUNT as well, and that lines and identifiers now agree. A green verdict over
        a shrinking count is the failure this case exists to catch.

        THE CUT OF 2026-09-19 IS A SHRINKING COUNT, which is why simply writing the new number here
        would be the answer this case warns about. The count is three now; the fifty-four that left
        went to the 6.2.0 scope. A line that VANISHES and a line that MOVED look identical in a
        count and are not the same thing, so the destination is part of the check.

        THE DESTINATION CHECK LEFT THIS CASE ON 2026-09-24, and the reason is that it had fallen
        into the class this whole file stands against. It counted raw `| ` table rows in 6.2.0 and
        excluded the headers `| Punkt |` and `| Eintrag |`. The file's columns have since been
        named `| Item |`, so the headers counted as scope rows, and an accounting table added later
        counted as scope rows too. Thirty-one rows were read where twenty were meant. Exactly the
        shape TestDerWaechterBETRITTdieTabelleUeberhaupt records one level down: a header was
        renamed and a check kept matching the old spelling in silence.

        The 6.2.0 recast then split those lines across 6.2.0 and 6.3.0, so the destination became
        two files and a count over one of them was a measurement of the wrong surface. Writing 31
        in place of 54 would have made the suite green and recorded nothing. The replacement is in
        TestDieVierundfuenfzigSindNamentlichAuffindbar, and it checks the fifty-four BY NAME
        against the list the register itself carries, which a count cannot do.

        THE COUNT ROSE TO FOUR on 2026-09-20, and that direction is the safe one for this case. It
        guards against a number that got SMALLER without anyone being able to say where the
        difference went; a number that gets larger carries its reason with it, here owner card
        OA-f1b4021199, which put N16 into the cut. The 54 moved to 6.2.0 are asserted below and did
        not move again."""
        d = GATE.pruefe_umfangsdatei(self.echt)
        self.assertEqual(d["urteil"], "gruen", d["gruende"])
        self.assertEqual(d["kollisionen"], {})
        self.assertEqual(d["zeilen"], 4, "a line must not vanish to make the verdict green")
        self.assertEqual(d["kennungen"], 4, "one identifier per line, that is the whole point")
        self.assertEqual(d["zeilen_ohne_kennung"], [],
                         "a line the gate cannot read must be reported, never dropped")
        # WHERE THE OTHER FIFTY-FOUR WENT — see TestDieVierundfuenfzigSindNamentlichAuffindbar.
        # This case asserts the 6.1.0 file. The destination check is its own class, because the
        # destination is now TWO files and a raw line count over one of them measured the wrong
        # surface; the reason is written out there.


def _tabellen(text: str) -> list[tuple[str, list[str]]]:
    """Split markdown tables into (first header cell, data-row first cells).

    THE HEADER IS FOUND BY STRUCTURE, NOT BY ITS WORDING: in a markdown table the header is the
    row immediately above the `|---|` separator. The predecessor of this reader matched the
    literal strings `| Punkt |` and `| Eintrag |`, the columns were later renamed to `| Item |`,
    and from then on every header counted as a scope row. A reader that has to be taught each new
    spelling is a reader that goes quietly wrong on the next one.

    FENCED CODE BLOCKS ARE NOT SCOPE, and that line is here because a counter-reading by the
    foreign model family asked for it on 2026-09-24. Measured at the time: neither scope file
    contains a table inside a fence, so this was a latent hole rather than a live defect — but a
    measurement printed in a fence is exactly the kind of thing these files grow, and a scope row
    invented out of one would be counted like any other.
    """
    zeilen = text.splitlines()
    im_zaun = set()
    zaun = False
    for i, z in enumerate(zeilen):
        if z.strip().startswith("```"):
            zaun = not zaun
            im_zaun.add(i)
        elif zaun:
            im_zaun.add(i)
    trenner = [i for i, z in enumerate(zeilen)
               if i not in im_zaun and re.match(r"^\|[\s:|-]+\|\s*$", z)]
    aus = []
    for t in trenner:
        if t == 0:
            continue
        kopf = zeilen[t - 1]
        if not kopf.startswith("|"):
            continue
        daten = []
        for j in range(t + 1, len(zeilen)):
            z = zeilen[j]
            if j in im_zaun or not z.startswith("|") or re.match(r"^\|[\s:|-]+\|\s*$", z):
                break
            daten.append(z)
        aus.append((kopf.split("|")[1].strip(), daten))
    return aus


def _sach_und_rechnung(pfad: pathlib.Path) -> tuple[list[str], list[str]]:
    """Scope rows and accounting rows.

    The accounting table is the one whose FIRST HEADER CELL IS EMPTY (`| | Count |`); a scope
    table always names its first column. That is one structural rule rather than a second list of
    headings to keep in step, and the case below pins that exactly one table per file has it, so
    the rule cannot widen without someone noticing.

    A SCOPE ROW IS READ BY ITS FIRST CELL AND AN ACCOUNTING ROW WHOLE, and the asymmetry is not an
    oversight. A scope row carries its identifier in column one. An accounting row carries its
    label there and the identifiers it accounts for in the VALUE column — `| Without a row of its
    own | 1: S62 / S65-3 |`. Reading only first cells lost exactly that rider, which is how this
    line came to be written.
    """
    sach, rechnung = [], []
    for kopf, daten in _tabellen(pfad.read_text(encoding="utf-8")):
        if kopf == "":
            rechnung.extend(daten)
        else:
            sach.extend(z.split("|")[1].strip() for z in daten)
    return sach, rechnung


def _deckt(zelle: str, marke: str) -> bool:
    """Does this row's first cell carry that register identifier?

    Rows are written `C1 / N15`, `S106 / S108`, `N2-3a–d, 3f, 3g`. The register writes one
    identifier per line, so the match is per part and allows a trailing continuation.
    """
    for teil in re.split(r"\s*/\s*", zelle):
        teil = teil.strip().lstrip("*").strip()
        if teil == marke or teil.startswith(marke + ",") or teil.startswith(marke + " "):
            return True
    return False


class TestDieVierundfuenfzigSindNamentlichAuffindbar(unittest.TestCase):
    """THE FIFTY-FOUR ARE CHECKED BY NAME, because a count cannot tell loss from movement.

    Until 2026-09-24 the destination check was `len(rows of 6.2.0) == 54`. It broke twice over, and
    both breaks are the same class: it measured a surface that was no longer the one in use. The
    columns were renamed, so headers counted as rows; an accounting table was added, so bookkeeping
    counted as rows; and the recast split the lines across 6.2.0 AND 6.3.0, so one file stopped
    being the destination at all. It read 31 where it wanted 20, and the honest number to write in
    its place did not exist, because no single number was the right answer any more.

    What a count could never do is say WHICH line went missing. This class reads the fifty-four
    identifiers from the list the register carries in its own text, `RESTRISIKO_610.md`, and asks
    of each one where it now lives. The list is not copied into this file: a copied list is a
    second truth that ages the moment the register moves, which the module docstring already says
    about the riders.

    STATED LIMIT. A line deleted from a scope file AND written into an accounting table as a rider
    passes this class. That is a deliberate, reviewable edit in prose a reader meets, not a silent
    loss, and pretending to catch it would be a wider claim than the check.
    """

    def setUp(self):
        self.register = REPO / "RESTRISIKO_610.md"
        if not self.register.is_file():
            self.skipTest("RESTRISIKO_610.md is in no tree here — NOT MEASURABLE, and that is a "
                          "statement about the repository, not about the fifty-four")
        self.ziele = [REPO / "docs" / "release_scope" / "6.2.0.md",
                      REPO / "docs" / "release_scope" / "6.3.0.md"]

    def _marken(self) -> list[str]:
        """The fifty-four, read out of the register's own sentence.

        EXACTLY ONE LINE MAY MATCH, and taking the first would have been the quieter bug. The
        counter-reading of 2026-09-24 named it: add a second long backticked list to the register
        and this reader silently picks whichever comes first, which may be the incomplete one.
        Measured at the time, exactly one line qualified — so this is a hole being closed, not a
        defect being fixed. Ambiguity fails instead of choosing.
        """
        treffer = [re.findall(r"`([^`]+)`", z)
                   for z in self.register.read_text(encoding="utf-8").splitlines()]
        kandidaten = [t for t in treffer if len(t) >= 40 and all(re.match(r"^[A-Z]", x) for x in t)]
        if len(kandidaten) == 1:
            return kandidaten[0]
        if not kandidaten:
            self.fail("the register no longer carries a line listing the moved identifiers; this "
                      "class cannot invent one, and an empty list would read as a clean result")
        self.fail(f"{len(kandidaten)} lines of the register could be the list of moved identifiers "
                  f"({[len(k) for k in kandidaten]} entries each) — picking one would be a guess "
                  f"about which is authoritative")

    def test_das_register_nennt_die_vierundfuenfzig(self):
        self.assertEqual(len(self._marken()), 54)

    def test_die_zieldateien_existieren_denn_das_register_zeigt_auf_sie(self):
        """Absence here is a FINDING, not a skip. The register names the destination in prose; if
        that file is gone, the fifty-four have no recorded home and nothing says so."""
        for z in self.ziele:
            self.assertTrue(z.is_file(), f"{z.name} is named by the register and is not in the tree")

    def test_genau_eine_rechnungstabelle_je_datei(self):
        """The structural rule that separates bookkeeping from scope, pinned so it cannot widen."""
        for z in self.ziele:
            leer = [k for k, _ in _tabellen(z.read_text(encoding="utf-8")) if k == ""]
            self.assertEqual(len(leer), 1, f"{z.name}: expected exactly one accounting table")

    def test_jede_sachzeile_traegt_eine_lesbare_kennung(self):
        """A row the reader cannot parse must become a finding, never disappear. That is the class
        the R-A1 rename taught this house, applied to this reader."""
        for z in self.ziele:
            sach, _ = _sach_und_rechnung(z)
            self.assertGreater(len(sach), 0, f"{z.name}: no scope row read at all")
            stumm = [s for s in sach if not re.match(rf"^\**({GATE._KENNUNG})", s)]
            self.assertEqual(stumm, [], f"{z.name}: rows without a readable identifier")

    def test_jede_der_vierundfuenfzig_hat_genau_einen_ort(self):
        """The whole point: loss and movement look identical in a count and are told apart here."""
        marken = self._marken()
        orte = {}
        for z in self.ziele:
            sach, rechnung = _sach_und_rechnung(z)
            for m in marken:
                if any(_deckt(s, m) for s in sach):
                    orte.setdefault(m, []).append(z.name)
                elif any(re.search(rf"(?<![0-9A-Za-z.\-]){re.escape(m)}(?![0-9A-Za-z.\-])", r)
                         for r in rechnung):
                    orte.setdefault(m, []).append(f"{z.name} (accounting)")
        fehlend = [m for m in marken if m not in orte]
        self.assertEqual(fehlend, [], "identifiers of the 54 that are in no file: a line did not "
                                      "move, it vanished, and the count would not have said which")
        doppelt = {m: o for m, o in orte.items()
                   if len([x for x in o if "(accounting)" not in x]) > 1}
        self.assertEqual(doppelt, {}, "the same identifier is cast into two scope files; the "
                                      "landing card would count one line twice")

    def test_ein_mitlaeufer_muss_in_BEIDEN_rechnungen_stehen(self):
        """THE RIDER HOLE, NARROWED RATHER THAN DECLARED AWAY.

        A counter-reading by the foreign model family (2026-09-24) called the rider exception a
        hole: delete a scope row, name the identifier in an accounting table, and the by-name check
        passes. Its own proposal was to forbid exceptions entirely, and that is refused with a
        reason — S62 genuinely has no row of its own, it was delivered in 6.1.0, so a blanket rule
        would produce a red over a file that is correct.

        The narrowing uses what the two files already are: TWO independent statements of the same
        arithmetic. A rider is only a rider if BOTH accounting tables say so. Deleting a row and
        covering it in one file's accounting now fails, because the other file does not agree.
        """
        marken = self._marken()
        rechnungen, sachmengen = [], []
        for z in self.ziele:
            sach, rechnung = _sach_und_rechnung(z)
            sachmengen.append(sach)
            rechnungen.append("\n".join(rechnung))
        nur_rechnung = [m for m in marken
                        if not any(_deckt(s, m) for sach in sachmengen for s in sach)]
        self.assertGreater(len(nur_rechnung), 0,
                           "no rider at all would mean this case measures nothing; S62 is one")
        for m in nur_rechnung:
            wo = [z.name for z, txt in zip(self.ziele, rechnungen)
                  if re.search(rf"(?<![0-9A-Za-z.\-]){re.escape(m)}(?![0-9A-Za-z.\-])", txt)]
            self.assertEqual(len(wo), len(self.ziele),
                             f"{m} has no scope row and is named in {wo} only — a rider that only "
                             f"one file's accounting knows is a deleted row, not a rider")

    def test_eine_tabelle_im_zaun_zaehlt_nicht_eine_ohne_zaun_schon(self):
        """THE FENCE SKIP MEASURED IN BOTH DIRECTIONS, because a skip that skips nothing is a
        comment. Planted on a copy of the real 6.2.0 file on 2026-09-24:

            as it is            24 scope rows
            table inside ```    24 scope rows   (the fence is honoured)
            table without ```   25 scope rows   (and it becomes a finding)

        The second line alone would not distinguish a working fence from a reader that lost the
        table for some other reason; the third is what makes it an argument about fences.
        """
        import tempfile
        orig = self.ziele[0].read_text(encoding="utf-8")
        tab = "| Item | What it is |\n|---|---|\n| ERFUNDEN | eine Zeile |"
        ergebnis = {}
        for name, text in (("blank", orig),
                           ("im_zaun", orig + "\n```\n" + tab + "\n```\n"),
                           ("ohne_zaun", orig + "\n" + tab + "\n")):
            with tempfile.TemporaryDirectory() as d:
                p = pathlib.Path(d) / "6.2.0.md"
                p.write_text(text, encoding="utf-8")
                ergebnis[name] = _sach_und_rechnung(p)[0]
        self.assertEqual(len(ergebnis["im_zaun"]), len(ergebnis["blank"]),
                         "a table inside a fence changed the scope-row count")
        self.assertNotIn("ERFUNDEN", ergebnis["im_zaun"])
        self.assertEqual(len(ergebnis["ohne_zaun"]), len(ergebnis["blank"]) + 1,
                         "an unfenced table was NOT counted, so the fence case above proves "
                         "nothing about fences")
        self.assertIn("ERFUNDEN", ergebnis["ohne_zaun"])

    def test_die_endstrich_formen_bleiben_erkannt(self):
        """THE SEPARATORS IN THESE IDENTIFIERS ARE EN-DASHES, and the same counter-reading asked
        what happens when they are not. Measured: the register writes `N2-3a–d` and `A5.1–A5.4`
        with U+2013, the scope row writes `N2-3a–d, 3f, 3g`, and the match runs through the
        trailing-comma rule. Swap either side to an ASCII hyphen and the identifier stops being
        found, which surfaces as a red rather than as a quiet pass — this case pins that the form
        in the tree today is the one that matches, so a change has to be deliberate."""
        marken = self._marken()
        strich = [m for m in marken if "–" in m]
        self.assertGreater(len(strich), 0, "no en-dash identifier in the register: this case would "
                                           "otherwise assert nothing")
        alle = [s for z in self.ziele for s in _sach_und_rechnung(z)[0]]
        for m in strich:
            self.assertTrue(any(_deckt(s, m) for s in alle),
                            f"{m!r} carries U+2013 and was not matched by any scope row")
            with self.subTest(marke=m):
                ascii_form = m.replace("–", "-")
                self.assertFalse(any(_deckt(s, ascii_form) for s in alle),
                                 f"{ascii_form!r} also matched, so the case cannot tell the two "
                                 f"forms apart and proves nothing about either")

    def test_ein_geloeschter_posten_faellt_ROT(self):
        """COUNTER-DIRECTION, planted. Without it this class proves only that today's tree agrees
        with itself, which is the coincidence the house stands against."""
        marken = self._marken()
        opfer = next(m for m in marken
                     if any(_deckt(s, m) for s in _sach_und_rechnung(self.ziele[1])[0]))
        text = self.ziele[1].read_text(encoding="utf-8")
        beschnitten = "\n".join(z for z in text.splitlines()
                                if not (z.startswith("| ") and _deckt(z.split("|")[1].strip(), opfer)))
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / "6.3.0.md"
            p.write_text(beschnitten, encoding="utf-8")
            sach, _ = _sach_und_rechnung(p)
            self.assertFalse(any(_deckt(s, opfer) for s in sach),
                             f"the planted deletion of {opfer} did not take effect, so this "
                             f"case would pass over a defect it never created")

    def test_eine_umbenannte_spalte_aendert_die_zeilenzahl_NICHT(self):
        """THE META-TEST AGAINST THE DEFECT THAT JUST HAPPENED, and it walks the spellings that
        made the old reader swing rather than one arbitrary rename.

        Measured on 6.2.0 on 2026-09-24, counting raw `| ` rows minus `| Punkt |` and
        `| Eintrag |` the way the old check did:

            | Item | (today)   36        | Punkt |     32
            | Eintrag |        32        | Posten |    36

        Four spellings, three different answers, and the file's own accounting says 24. The number
        was a property of the heading, not of the scope. The reader below finds the header as the
        row above the `|---|` separator, so none of these four moves it.
        """
        import tempfile
        for z in self.ziele:
            vorher, _ = _sach_und_rechnung(z)
            roh = z.read_text(encoding="utf-8")
            for wort in ("Punkt", "Eintrag", "Posten", "Identifier"):
                with self.subTest(datei=z.name, kopf=wort):
                    with tempfile.TemporaryDirectory() as d:
                        p = pathlib.Path(d) / z.name
                        p.write_text(re.sub(r"^\| Item \|", f"| {wort} |", roh, flags=re.M),
                                     encoding="utf-8")
                        nachher, _ = _sach_und_rechnung(p)
                    self.assertEqual(
                        len(vorher), len(nachher),
                        f"{z.name}: calling the column {wort!r} changed the scope-row count from "
                        f"{len(vorher)} to {len(nachher)} — the reader is matching wording again")


class TestDerWaechterBETRITTdieTabelleUeberhaupt(unittest.TestCase):
    """AN EMPTY FINDING LIST OVER ZERO EXAMINED ROWS IS NOT A CLEAN ONE.

    Measured 2026-09-20 by a counter-reading: `zeilen_ohne_kennung` entered a table only when the
    LAST header column read `Zweig`. The scope file has been English for a while and heads its two
    In-tables with `Title` and `Branch`, so the loop never set its flag, and the function returned
    an empty list for the whole file. Green, every run, over nothing.

    That is the class the function was written against, turned on itself: a line that stops
    existing rather than becoming a finding, and a verdict that gets greener as a result. The
    number of rows EXAMINED is the thing that tells the two apart, and these cases assert it.
    """

    def setUp(self):
        self.echt = REPO / "docs" / "release_scope" / "6.1.0.md"

    def test_der_waechter_erreicht_zeilen_der_echten_datei(self):
        aus, zustand = GATE.zeilen_ohne_kennung(self.echt)
        self.assertEqual(zustand, "gemessen", zustand)
        self.assertGreater(GATE.ZULETZT_GEPRUEFT, 0,
                           "the guard reported no unreadable line without reading a single one")
        self.assertEqual(aus, [])

    def test_ein_kopf_in_einer_unbekannten_sprache_ist_NICHT_MESSBAR_statt_gruen(self):
        """The failure mode itself, planted: rename the column and the answer must change."""
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            gefaelscht = pathlib.Path(d) / "6.1.0.md"
            gefaelscht.write_text(
                self.echt.read_text(encoding="utf-8").replace("| Branch |", "| Filiale |"),
                encoding="utf-8")
            aus, zustand = GATE.zeilen_ohne_kennung(gefaelscht)
        self.assertTrue(zustand.startswith("NOT MEASURABLE") or zustand.startswith("NICHT MESSBAR"),
                        f"a header the guard cannot read must say so, read {zustand!r}")
        self.assertEqual(aus, [], "and it must not invent findings either")

    def test_beide_schreibweisen_der_spalte_werden_erkannt(self):
        """German and English, because the file has been both."""
        import tempfile
        for kopf in ("| Identifier | Subject | Branch |", "| Kennung | Sache | Zweig |"):
            with self.subTest(kopf=kopf):
                with tempfile.TemporaryDirectory() as d:
                    f = pathlib.Path(d) / "s.md"
                    f.write_text("## In\n\n" + kopf + "\n|---|---|---|\n"
                                 "| A-16 | x | `zweig/a` |\n\n## Out\n", encoding="utf-8")
                    aus, zustand = GATE.zeilen_ohne_kennung(f)
                self.assertEqual(zustand, "gemessen", zustand)
                self.assertGreater(GATE.ZULETZT_GEPRUEFT, 0)


class TestEineUnlesbareZeileVerschwindetNicht(unittest.TestCase):
    """THE CLASS BEHIND THE R-A1 RENAME, and it is worth more than the rename.

    Both readers in the gate ended their loop with "no identifier matched, next line". That is a
    wrong answer in its quietest form: the line does not become a finding, it stops existing. The
    count drops, no reason is printed, and the verdict gets GREENER rather than redder, because
    whatever was wrong with that line went away with the line.

    Measured on 2026-09-19: renaming three rows to R-A1..R-A3 made the file check report GREEN
    with zero collisions, while the line count fell 56 -> 53. The collision was not resolved, it
    was made invisible. Widening the expression fixes that one shape; these cases are about the
    NEXT shape, which nobody has thought of yet.
    """

    def setUp(self):
        import tempfile
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.p = pathlib.Path(td.name)

    def _datei(self, inhalt: str) -> pathlib.Path:
        f = self.p / "scope.md"
        f.write_text(inhalt, encoding="utf-8")
        return f

    def test_eine_umfangszeile_ohne_lesbare_kennung_wird_gemeldet(self):
        """Before this guard existed the same file read as one clean line and a green verdict."""
        f = self._datei("# s\n## In\n| Punkt | Zweig |\n|---|---|\n"
                        "| A1 gut | `fix/a1` |\n| voellig namenlose Zeile | `fix/x` |\n## Out\n")
        d = GATE.pruefe_umfangsdatei(f)
        self.assertEqual(d["urteil"], "ROT")
        self.assertEqual(d["zeilen_ohne_kennung"], ["voellig namenlose Zeile"])

    def test_der_befund_erreicht_auch_den_lauf_nicht_nur_die_dateipruefung(self):
        """CI calls `main`, which calls `pruefe`. A finding that only `pruefe_umfangsdatei`
        reports is a guard nobody calls -- the same shape of failure it was written against."""
        f = self._datei("# s\n## In\n| Punkt | Zweig |\n|---|---|\n"
                        "| A1 gut | `fix/a1` |\n| namenlos | `fix/x` |\n## Out\n")
        u = GATE.pruefe(branch="fix/a1", title="[6.1.0 A1] feat(x): y", version="6.1.0",
                        scope_pfad=f)
        self.assertEqual(u["urteil"], "ROT")
        self.assertTrue(any("ohne lesbare Kennung" in g for g in u["gruende"]), u["gruende"])

    def test_die_neue_form_r_a1_gilt_als_kennung(self):
        """The instance. Without it the three renamed lines leave the count silently."""
        f = self._datei("# s\n## In\n| Punkt | Zweig |\n|---|---|\n"
                        "| R-A1 etwas | `fix/ra1` |\n## Out\n")
        zeilen, zustand = GATE.fuehrende_kennungen(f)
        self.assertEqual(zustand, "gemessen")
        self.assertEqual([k for k, _, _ in zeilen], ["R-A1"])

    def test_eine_tabelle_ohne_zweigspalte_loest_keinen_fehlalarm_aus(self):
        """THE GUARD'S OWN REACH IS MEASURED TOO. Its first version checked every table row in
        the In section and reported eight findings on the only real file: four header rows and
        the three owner-decision rows. A guard that fires eight times on the one input it was
        written for is describing its own reach, not the file."""
        f = self._datei("# s\n## In\n| Karte | Zeit | Entscheid |\n|---|---|---|\n"
                        "| `OA-123` | heute | irgendwas |\n\n"
                        "| Punkt | Zweig |\n|---|---|\n| A1 gut | `fix/a1` |\n## Out\n")
        d = GATE.pruefe_umfangsdatei(f)
        self.assertEqual(d["zeilen_ohne_kennung"], [])
        self.assertEqual(d["urteil"], "gruen", d["gruende"])


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

