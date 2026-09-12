"""Acceptance tests for scripts/restrisiko_archiv.py.

Owner order 20260911T2233Z, decision one, item one and its prohibition: the archive excerpts are
byte-identical with the published record, nothing shortened, nothing translated, and not one byte
of them is touched. A tool that cuts them is only worth more than a careful hand if something
refuses a wrong cut — so every rule below appears as a planted defect first.

The same three-step contract as the register tests: the defect must be REFUSED, the clean state
must pass, and removing the check must let the defect through.
"""
import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "restrisiko_archiv.py"
ARCHIV = REPO / "audit_artifacts" / "600" / "restrisiko"

spec = importlib.util.spec_from_file_location("restrisiko_archiv_ut", SCRIPT)
ra = importlib.util.module_from_spec(spec)
sys.modules["restrisiko_archiv_ut"] = ra
spec.loader.exec_module(ra)

# A miniature record with all three carrier shapes AND both traps that the real one sprang:
# a collection heading, and an addendum sitting inside a neighbour's section.
QUELLE = """# Record

## S1 — the first finding
body one

## S2 — the second finding
body two

### S1, Nachtrag — measured again
the addendum, written into S2's section

## S10 bis S12 — a collection heading, not a finding
prelude

### S10 · the tenth
body ten

### S11 · the eleventh
body eleven

## S20 — a finding whose section carries a code example
prose before

```python
LATTE = "median"            # way A
#     = "fastest_end"       # way B — a COMMENT, not a heading
```

prose after the block, which belongs to S20

## The table

| Id | What |
|---|---|
| N1 | a row-carried finding |
| N2 | another one |

## S21 — a finding with a table inside a code fence

```
| N9 | this looks like a row but is inside a fence |
```

last line of S21
"""


class Basis(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        cls.quelle = cls.tmp / "record.md"
        cls.quelle.write_text(QUELLE, encoding="utf-8")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def frisch(self) -> Path:
        d = Path(tempfile.mkdtemp(dir=self.tmp))
        ra.main(["--quelle", str(self.quelle), "--ordner", str(d), "--schreiben"])
        return d


class TestDieRegelTrifftDieDreiTraegerformen(Basis):
    def test_jeder_ausschnitt_ist_byte_gleich_mit_seinem_bereich(self):
        roh = QUELLE.encode("utf-8")
        for e in ra.bereiche(QUELLE):
            a, b = e["byte_range"]
            with self.subTest(id=e["id"], part=e["part"]):
                self.assertEqual(ra.schneide(roh, e), roh[a:b])

    def test_eine_SAMMELUEBERSCHRIFT_ist_kein_fund(self):
        """`## S10 bis S12` is about a range. Taking it made S102's excerpt 17 KB of the record."""
        s10 = [e for e in ra.bereiche(QUELLE) if e["id"] == "S10" and e["part"] == "main"][0]
        stueck = QUELLE.encode("utf-8")[s10["byte_range"][0]:s10["byte_range"][1]].decode("utf-8")
        self.assertTrue(stueck.startswith("### S10 ·"), f"took the collection heading: {stueck[:40]!r}")
        self.assertNotIn("the eleventh", stueck, "S10's excerpt swallowed S11")

    def test_ein_NACHTRAG_ist_nicht_der_hauptabschnitt(self):
        """S1's addendum sits inside S2's section. "Deepest wins" picked the addendum."""
        teile = {e["part"]: e for e in ra.bereiche(QUELLE) if e["id"] == "S1"}
        self.assertIn("main", teile)
        self.assertIn("addendum-1", teile)
        haupt = QUELLE.encode("utf-8")[teile["main"]["byte_range"][0]:
                                       teile["main"]["byte_range"][1]].decode("utf-8")
        self.assertTrue(haupt.startswith("## S1 —"), f"main is not the section: {haupt[:30]!r}")
        self.assertIn("body one", haupt)

    def test_ein_NACHTRAG_geht_nicht_verloren(self):
        """Nothing shortened: the addendum is kept, as its own file rather than glued on."""
        d = self.frisch()
        self.assertTrue((d / "S1.addendum-1.md").is_file())
        self.assertIn("the addendum", (d / "S1.addendum-1.md").read_text(encoding="utf-8"))

    def test_eine_TABELLENZEILE_traegt_einen_fund(self):
        n1 = [e for e in ra.bereiche(QUELLE) if e["id"] == "N1"][0]
        self.assertEqual(n1["carrier"], "row")
        stueck = QUELLE.encode("utf-8")[n1["byte_range"][0]:n1["byte_range"][1]].decode("utf-8")
        self.assertEqual(stueck, "| N1 | a row-carried finding |\n")

    def test_bytebereiche_sind_BYTES_keine_zeichen(self):
        """The manifest promises bytes. On ASCII the two agree, which is why it needs a case."""
        text = "## S1 — ä\nbody\n"
        e = [x for x in ra.bereiche(text) if x["id"] == "S1"][0]
        self.assertEqual(e["byte_range"][1], len(text.encode("utf-8")))
        self.assertNotEqual(e["byte_range"][1], len(text), "character count, not byte count")


class TestCodebloeckeSindKeinMarkup(Basis):
    """Found by an adversarial lens on 12.09.2026 and confirmed AT THE DELIVERED ARTEFACT.

    `ALLE_UEBERSCHRIFTEN` matched `#                     = "schnellstes_ende"  # way B — stays red`
    inside a ```python block of RESTRISIKO_600.md and ended S19's section there. S19.md was written
    533 bytes long instead of 2427; S37.md 6757 instead of 11959. "Nothing shortened" was false for
    two findings in the delivered archive — and `pruefen()` said OK, because it re-derived the
    ranges with the same function that had cut them.
    """

    def test_eine_KOMMENTARZEILE_im_codeblock_beendet_den_abschnitt_NICHT(self):
        e = [x for x in ra.bereiche(QUELLE) if x["file"] == "S20.md"][0]
        stueck = QUELLE.encode("utf-8")[e["byte_range"][0]:e["byte_range"][1]].decode("utf-8")
        self.assertIn("prose after the block", stueck,
                      "the section was cut at the comment line inside the fence")
        self.assertEqual(stueck.count("```"), 2, "the excerpt must carry the WHOLE fenced block")

    def test_eine_TABELLENZEILE_im_codeblock_traegt_keinen_fund(self):
        """The same blindness in the other pattern: `| N9 |` inside a fence is not a carrier."""
        self.assertNotIn("N9", {x["id"] for x in ra.bereiche(QUELLE)})

    def test_ein_ausschnitt_endet_NIE_in_einem_offenen_codeblock(self):
        """The independent property — it does NOT re-derive the range.

        This is the check that would have caught S19 even if the cutting rule had stayed broken:
        an odd number of fence markers means the cut lies inside a block. Derivation compared
        against derivation always agrees with itself; this asks the excerpt itself.
        """
        roh = QUELLE.encode("utf-8")
        for e in ra.bereiche(QUELLE):
            stueck = roh[e["byte_range"][0]:e["byte_range"][1]].decode("utf-8")
            with self.subTest(file=e["file"]):
                self.assertEqual(len(ra._FENCE.findall(stueck)) % 2, 0,
                                 f"{e['file']} ends inside a fenced block")

    def test_die_unabhaengige_pruefung_faengt_einen_ABGESCHNITTENEN_ausschnitt(self):
        """Planted: cut an excerpt short inside its fence. The range check and the fence check must
        BOTH speak — and the fence one must speak about the file, not about the range."""
        d = self.frisch()
        f = d / "S20.md"
        text = f.read_text(encoding="utf-8")
        f.write_text(text[:text.index("```python") + 30], encoding="utf-8")
        fehler = ra.pruefen(QUELLE, d)
        self.assertTrue(any("ENDS INSIDE a fenced block" in x for x in fehler),
                        f"the independent property did not fire: {fehler}")

    def test_META_ohne_die_maskierung_wird_der_abschnitt_wieder_abgeschnitten(self):
        quelle = SCRIPT.read_text(encoding="utf-8")
        alt = "    frei = ausserhalb_der_codebloecke(text)"
        self.assertIn(alt, quelle, "the mutation template no longer matches the source")
        ns = {"__name__": "ra_mut_fence", "__file__": str(SCRIPT)}
        exec(compile(quelle.replace(alt, "    frei = lambda _pos: True"),
                     "<mutiert: ohne maskierung>", "exec"), ns)
        e = [x for x in ns["bereiche"](QUELLE) if x["file"] == "S20.md"][0]
        stueck = QUELLE.encode("utf-8")[e["byte_range"][0]:e["byte_range"][1]].decode("utf-8")
        self.assertNotIn("prose after the block", stueck,
                         "removing the masking changed nothing — it never masked anything")


class TestAusgezeichneteSammelueberschriften(Basis):
    """Von Juror A reproduziert (12.09.2026), nachdem die Sammelueberschrift bereits als behoben galt.

    `## **S102** bis S114 — …` liess `BEREICHSWORT` nicht greifen: der Rest nach der Kennung beginnt
    mit `**`, nicht mit Leerraum. Folge: die Sammlung galt wieder als Fund, und weil sie flacher
    steht als `### S102`, verschluckte ihr Ausschnitt S103 und S104 — genau der Fehler, den der
    Docstring als behoben beschreibt. Gemessen wurde byte_range [10, 217], also der ganze Abschnitt.

    Im Bestand steht heute keine fett gesetzte Sammelueberschrift. Latent im BESTAND ist nicht
    behoben in der REGEL — deshalb diese Faelle.

    Zwei Haertungen waren noetig, und die zweite lag nicht an der Auszeichnung:
      * `[*_]*` statt `\**` in beiden Mustern — Markdown zeichnet mit BEIDEN Zeichen aus, und eine
        Haertung an einer von zwei Stellen laesst die andere offen.
      * `(?![A-Za-z0-9])` statt `\b` nach der Kennung — `_` IST ein Wortzeichen, zwischen `S102` und
        dem schliessenden `__` steht also gar keine Wortgrenze. `\b` griff dort nie.
    """

    def _ist_sammlung(self, kopf: str) -> bool:
        m = ra.ID_UEBERSCHRIFT_VOLL.match(kopf)
        return bool(m and ra.BEREICHSWORT.match(m.group(3)))

    def test_eine_AUSGEZEICHNETE_sammelueberschrift_gilt_als_sammlung(self):
        for kopf in ("## **S102** bis S114 — Sammelfund",
                     "## __S102__ bis S114 — Sammelfund",
                     "## *S102* bis S114",
                     "## _S102_ bis S114",
                     "## S102 bis S114 — ohne Auszeichnung"):
            with self.subTest(kopf=kopf[:40]):
                self.assertTrue(self._ist_sammlung(kopf), f"nicht als Sammlung erkannt: {kopf}")

    def test_ein_GEVIERTSTRICH_macht_aus_einem_fund_keine_sammlung(self):
        """Die Gegenrichtung, und sie entscheidet: der Geviertstrich ist die uebliche Titeltrennung.

        Wer ihn in die Zeichenklasse aufnaehme, machte aus `### Z5 — S51 haelt …` eine Sammlung und
        loeschte damit Z5s eigenen Abschnitt. Eine Haertung, die jede Ueberschrift zur Sammlung
        macht, ist keine Haertung."""
        for kopf in ("### Z5 — S51 haelt, mit zwei Praezisierungen",
                     "## S22 — Rohmatrix und signiertes Differential-Artefakt",
                     "### S102 · Ein AST-Scanner sieht keine dynamische Form",
                     "## S7b — eine Kennung mit Buchstabensuffix"):
            with self.subTest(kopf=kopf[:40]):
                self.assertFalse(self._ist_sammlung(kopf), f"faelschlich Sammlung: {kopf}")

    def test_eine_AUSGEZEICHNETE_kennung_wird_ueberhaupt_erkannt(self):
        """Vor der zweiten Haertung fiel `## __S102__ …` GANZ aus der Erkennung — nicht als
        Sammlung, sondern gar nicht. Ein Fund, den kein Muster sieht, hat keinen Ausschnitt."""
        for kopf, soll in (("## __S102__ bis S114", "S102"), ("## **S22** — Titel", "S22"),
                           ("## _S7b_ — Titel", "S7b")):
            with self.subTest(kopf=kopf):
                m = ra.ID_UEBERSCHRIFT_VOLL.match(kopf)
                self.assertIsNotNone(m, f"Kennung nicht erkannt: {kopf}")
                self.assertEqual(m.group(2), soll)

    def test_die_haertung_aendert_den_ECHTEN_bestand_NICHT(self):
        """Eine Regelaenderung, die den ausgelieferten Bestand verschiebt, waere ein zweiter Fund.

        Gemessen: 154 Ausschnitte vorher wie nachher, null geaenderte Bereiche."""
        import json
        import subprocess
        man_p = ARCHIV / "MANIFEST.json"
        if not man_p.is_file():
            self.skipTest("Archiv nicht in diesem Baum")
        man = json.loads(man_p.read_text(encoding="utf-8"))
        ref = man["source"]["path"].split("@")[-1]
        r = subprocess.run(["git", "show", f"{ref}:RESTRISIKO_600.md"], cwd=str(REPO),
                           capture_output=True)
        if r.returncode:
            self.skipTest(f"der gepinnte Stand {ref} ist in diesem Klon nicht da")
        neu = {e["file"]: e["byte_range"] for e in ra.bereiche(r.stdout.decode("utf-8"))}
        alt = {e["file"]: e["byte_range"] for e in man["excerpts"]}
        self.assertEqual(sorted(neu), sorted(alt), "die Menge der Ausschnitte hat sich geaendert")
        self.assertEqual([k for k in alt if alt[k] != neu[k]], [],
                         "die Haertung hat Bereiche im ausgelieferten Bestand verschoben")


class TestDiePruefungFaengtEinGeaendertesByte(Basis):
    def test_EIN_BYTE_im_ausschnitt_laesst_die_pruefung_scheitern(self):
        d = self.frisch()
        f = d / "S1.md"
        b = bytearray(f.read_bytes())
        b[len(b) // 2] = ord("X") if b[len(b) // 2] != ord("X") else ord("Y")
        f.write_bytes(bytes(b))
        fehler = ra.pruefen(QUELLE, d)
        self.assertTrue(any("NOT byte-identical" in x for x in fehler))

    def test_die_UNVERAENDERTE_ablage_besteht(self):
        self.assertEqual(ra.pruefen(QUELLE, self.frisch()), [])

    def test_eine_FREMDE_quelle_wird_abgewiesen_BEVOR_irgendetwas_sonst_geprueft_wird(self):
        d = self.frisch()
        fehler = ra.pruefen(QUELLE + "\n## S3 — later\n", d)
        self.assertEqual(len(fehler), 1, "a wrong source must stop the check, not colour it")
        self.assertIn("not the one this archive was cut from", fehler[0])

    def test_ein_FEHLENDER_ausschnitt_wird_gemeldet(self):
        d = self.frisch()
        (d / "S2.md").unlink()
        self.assertTrue(any("missing" in x for x in ra.pruefen(QUELLE, d)))

    def test_ein_VERSCHOBENER_bereich_wird_gefangen_auch_wenn_datei_und_digest_stimmen(self):
        """Der Angreifer faelscht Manifest UND Datei zusammen — gefunden von Linse 3 (Mutation M12).

        Die bis dahin einzige Absicherung war `ist != soll`: sie vergleicht die Datei auf der
        Platte mit dem Schnitt AUS DEM MANIFEST-BEREICH. Wer den Bereich im Manifest mitverschiebt,
        die Datei mit den Bytes des neuen Bereichs fuellt und Digest und Laenge nachzieht, ist in
        sich stimmig — und das Werkzeug sagte OK. Gemessen: mit herausmutiertem Bereichsvergleich
        meldete `pruefen()` eine leere Fundliste, obwohl S1.md den Inhalt von S2 trug.

        Der Bereichsvergleich ist also die Stelle, die den Bezug zur QUELLE haelt. Ohne Test war er
        eine Zusage ohne Deckung — genau die Klasse, gegen die dieses Werkzeug gebaut ist.
        """
        d = self.frisch()
        man = json.loads((d / "MANIFEST.json").read_text(encoding="utf-8"))
        roh = QUELLE.encode("utf-8")
        eins = next(e for e in man["excerpts"] if e["file"] == "S1.md")
        zwei = next(e for e in man["excerpts"] if e["file"] == "S2.md")
        fremd = roh[zwei["byte_range"][0]:zwei["byte_range"][1]]
        eins["byte_range"] = list(zwei["byte_range"])
        eins["bytes"] = len(fremd)
        eins["sha256"] = hashlib.sha256(fremd).hexdigest()
        (d / "S1.md").write_bytes(fremd)
        (d / "MANIFEST.json").write_text(json.dumps(man, indent=2, ensure_ascii=False) + "\n",
                                         encoding="utf-8")
        fehler = ra.pruefen(QUELLE, d)
        self.assertTrue(any("range moved" in x for x in fehler),
                        f"in sich stimmige Faelschung kam durch: {fehler}")

    def test_META_ohne_den_bereichsvergleich_kommt_die_faelschung_durch(self):
        """Und der Gegenbeweis, dass genau DIESE Zeile es traegt."""
        quelle = SCRIPT.read_text(encoding="utf-8")
        alt = '        if frisch[kid]["byte_range"] != e["byte_range"]:'
        self.assertIn(alt, quelle, "the mutation template no longer matches the source")
        ns = {"__name__": "ra_mut_range", "__file__": str(SCRIPT)}
        exec(compile(quelle.replace(alt, "        if False:"), "<mutiert: range>", "exec"), ns)
        d = self.frisch()
        man = json.loads((d / "MANIFEST.json").read_text(encoding="utf-8"))
        roh = QUELLE.encode("utf-8")
        eins = next(e for e in man["excerpts"] if e["file"] == "S1.md")
        zwei = next(e for e in man["excerpts"] if e["file"] == "S2.md")
        fremd = roh[zwei["byte_range"][0]:zwei["byte_range"][1]]
        eins["byte_range"] = list(zwei["byte_range"])
        eins["bytes"] = len(fremd)
        eins["sha256"] = hashlib.sha256(fremd).hexdigest()
        (d / "S1.md").write_bytes(fremd)
        (d / "MANIFEST.json").write_text(json.dumps(man, indent=2, ensure_ascii=False) + "\n",
                                         encoding="utf-8")
        self.assertEqual([x for x in ns["pruefen"](QUELLE, d) if "range moved" in x], [],
                         "ohne die Zeile muesste die Faelschung durchkommen — sonst misst der Fall etwas anderes")

    def test_META_ohne_den_byte_vergleich_kommt_ein_geaendertes_byte_durch(self):
        quelle = SCRIPT.read_text(encoding="utf-8")
        alt = "        if ist != soll:"
        self.assertIn(alt, quelle, "the mutation template no longer matches the source")
        ns = {"__name__": "ra_mut", "__file__": str(SCRIPT)}
        exec(compile(quelle.replace(alt, "        if False:"), "<mutiert>", "exec"), ns)
        d = self.frisch()
        f = d / "S1.md"
        b = bytearray(f.read_bytes())
        b[len(b) // 2] = ord("X") if b[len(b) // 2] != ord("X") else ord("Y")
        f.write_bytes(bytes(b))
        uebrig = [x for x in ns["pruefen"](QUELLE, d) if "byte-identical" in x]
        self.assertEqual(uebrig, [], "removing the comparison changed nothing — it never compared")


class TestUeberlappungIstEineMessung(Basis):
    def test_eine_GEWACHSENE_spanne_faellt_als_ueberlappung_auf(self):
        """Both earlier versions of the cutting rule produced an excerpt that was too large.

        Too large still looks like an excerpt: it opens with the right heading and contains the
        right text. The overlap count is what noticed, twice, so it is recorded and re-derived.
        """
        eintraege = ra.bereiche(QUELLE)
        self.assertEqual(ra.ueberlappungen(eintraege),
                         ra.ueberlappungen(list(reversed(eintraege))),
                         "the result must not depend on input order")
        gewachsen = [dict(e) for e in eintraege]
        gewachsen[0]["byte_range"] = [gewachsen[0]["byte_range"][0], len(QUELLE.encode("utf-8"))]
        self.assertGreater(len(ra.ueberlappungen(gewachsen)), len(ra.ueberlappungen(eintraege)))

    def test_eine_NEUE_ueberlappung_laesst_die_pruefung_scheitern(self):
        d = self.frisch()
        m = json.loads((d / "MANIFEST.json").read_text(encoding="utf-8"))
        m["overlaps"] = []
        (d / "MANIFEST.json").write_text(json.dumps(m, indent=2, ensure_ascii=False) + "\n",
                                         encoding="utf-8")
        self.assertTrue(any("overlap set changed" in x for x in ra.pruefen(QUELLE, d)))


class TestDasWIRKLICHE_archiv(unittest.TestCase):
    """The archive this branch ships, measured against the published record it claims to quote."""

    @unittest.skipUnless((ARCHIV / "MANIFEST.json").is_file(), "archive not in this tree")
    def test_das_ausgelieferte_archiv_ist_byte_gleich_mit_dem_veroeffentlichten_stand(self):
        man = json.loads((ARCHIV / "MANIFEST.json").read_text(encoding="utf-8"))
        ref = man["source"]["path"].split("@")[-1]
        p = subprocess.run(["git", "show", f"{ref}:RESTRISIKO_600.md"],
                           cwd=str(REPO), capture_output=True)
        if p.returncode != 0:
            self.skipTest(f"the pinned source state {ref} is not in this clone")
        self.assertEqual(hashlib.sha256(p.stdout).hexdigest(), man["source"]["sha256"],
                         "the pinned source state does not carry the recorded digest")
        self.assertEqual(ra.pruefen(p.stdout.decode("utf-8"), ARCHIV), [])

    @unittest.skipUnless((ARCHIV / "LIESMICH.md").is_file(), "archive not in this tree")
    def test_die_liesmich_gehoert_nicht_zu_den_ausschnitten(self):
        """It is the folder's own text, not a quotation — so no rule may bind it to a byte range."""
        man = json.loads((ARCHIV / "MANIFEST.json").read_text(encoding="utf-8"))
        self.assertNotIn("LIESMICH.md", {e["file"] for e in man["excerpts"]})


if __name__ == "__main__":
    unittest.main(verbosity=2)
