"""Eine Sammelzahl aus bestanden und uebersprungen darf nicht sagen, die Eigenschaft sei gemessen.

HERKUNFT, Codex-Kommentar r3999283100 in PR 197, gemessen am Kopf, den er nennt
(`1d3ad78e928867f7d6770010d0222776d4ecb271`, `docs/RESEARCH_PROGRAM.md`, Zeile 65). Der Abschnitt
T5 trug `**State:** **MEASURED, partially**` und belegte das mit `23 passed, 1 skipped`. Der EINE
Uebersprungene war `test_crosscheck_relation_differential_green`, und er ist der einzige der 24,
der Uebereinstimmung zwischen Python und Rust ueberhaupt misst. Die Tabelle daneben behauptete in
derselben Zeile, das Differential „agrees". Keiner der 23 bestandenen Faelle stuetzt das.

DIE KLASSE, und sie ist nicht auf dieses Dokument beschraenkt: **eine Sammelzahl verdeckt, WELCHER
Fall uebersprungen wurde.** `23 passed, 1 skipped` liest sich wie ein guter Lauf. Ob der eine
uebersprungene Fall der belanglose oder der entscheidende war, steht in der Zahl nicht. Dieselbe
Form kann ueberall stehen, wo eine gemischte Bilanz als Beleg fuer eine Eigenschaft zitiert wird.

ZWEI KNOTEN, wie das Fehlerbuch sie verlangt, und beide laufen VOR jeder Jury:

  Knoten 1, REPRODUKTION. Gegen den EINGEFROHRENEN Text von vor dem Fix
  (`tests/fixtures/t5_vor_dem_fix_1d3ad78e.md`, sha256 65451f47…, 1560 B, wortwoertlich aus
  `git show 1d3ad78e:docs/RESEARCH_PROGRAM.md` geschnitten). Fester Sollwert, NICHT gegen frisch
  erzeugte Ausgabe — eine Reproduktion, die ihren eigenen Gegenstand herstellt, reproduziert nichts.

  Knoten 2, EIGENSCHAFT. Gegen das heutige Dokument im Baum. Wo eine Zustandszeile eine Messung
  behauptet und im selben Abschnitt eine Sammelzahl mit Uebersprungenen zitiert wird, MUSS der
  uebersprungene Fall beim Namen genannt sein.

EHRLICHE GRENZE. Gemessen wird die Form `N passed, M skipped` und die Nennung eines Testnamens im
selben Abschnitt. Ob der genannte Name der RICHTIGE ist, entscheidet dieser Riegel nicht — das
kann er aus dem Text nicht. Er schliesst die stumme Sammelzahl aus, nicht die falsche Zuordnung.
"""
from __future__ import annotations

import hashlib
import pathlib
import re

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
DOKUMENT = REPO / "docs" / "RESEARCH_PROGRAM.md"
EINGEFROREN = REPO / "tests" / "fixtures" / "t5_vor_dem_fix_1d3ad78e.md"

#: Der Sollwert der eingefrorenen Grundlage. Aendert sich die Datei, ist der Beweis ein anderer,
#: und das soll auffallen statt still durchzugehen.
EINGEFROREN_SHA256 = "65451f47803abff81486517a1f4c0c07a241a5921f1dd9e4ffd4b9982cd5cee3"

#: Eine Sammelzahl aus einem Testlauf, mit mindestens einem Uebersprungenen.
_SAMMELZAHL = re.compile(r"\b(\d+)\s+passed,\s*(\d+)\s+skipped\b")

#: Eine Zustandszeile, die eine Messung behauptet. `NOT MEASURED` ist ausdruecklich keine.
_BEHAUPTET_GEMESSEN = re.compile(r"\*\*State:\*\*.*?\bMEASURED\b", re.S)
_NICHT_GEMESSEN = re.compile(r"\*\*State:\*\*[^\n]*?\bNOT\s+MEASURED\b")

#: Ein Testname, wie pytest ihn meldet — MIT seinem Parameter, falls er einen traegt.
#:
#: ZWEITE FASSUNG, Fund der Fremdfamilie (Codex r3999991254) gegen diesen Riegel selbst. Die erste
#: schnitt den Parameter ab: `test_first[a]` und `test_first[b]` wurden beide zu `test_first`, die
#: Menge fiel auf EINS zusammen, und ein Abschnitt, der BEIDE uebersprungenen Faelle ordentlich
#: benennt, wurde zu Unrecht gemeldet. Eine Stueckpflicht, die Stuecke zusammenfasst, ist keine.
#: In pytest ist der parametrierte Fall der Fall; `test_first` ohne Parameter ist kein Knoten,
#: sondern seine Familie.
_TESTNAME = re.compile(r"\btest_[A-Za-z0-9_]+(?:\[[^\]\s`]*\])?")

#: Ein Satz, der vom Ueberspringen handelt. Satzgrenze ist Punkt oder Zeilenumbruch.
_SKIP_SATZ = re.compile(r"[^.\n]*\bskip(?:ped)?\b[^.\n]*", re.I)


def benannte_uebersprungene(rumpf: str) -> set[str]:
    """Die Testnamen, die der Abschnitt AUSDRUECKLICH als uebersprungen ausweist.

    Gefragt ist die VERBINDUNG, nicht die Erwaehnung: ein Satz, der vom Ueberspringen handelt UND
    einen Testnamen traegt. Die Sammelzahl selbst zaehlt nicht als solcher Satz, sonst genuegte
    `1 skipped` sich selbst.
    """
    namen: set[str] = set()
    for m in _SKIP_SATZ.finditer(rumpf):
        satz = m.group(0)
        gefunden = set(_TESTNAME.findall(satz))
        if not gefunden:
            continue
        if _SAMMELZAHL.search(satz) and not gefunden:
            continue
        namen |= gefunden
    return namen


def uebersprungene_gesamt(rumpf: str) -> int:
    """Die Summe ALLER uebersprungenen Faelle des Abschnitts, ueber alle zitierten Laeufe."""
    return sum(int(m.group(2)) for m in _SAMMELZAHL.finditer(rumpf))


def nennt_den_uebersprungenen_fall(rumpf: str) -> bool:
    """Sagt der Abschnitt, WELCHER Fall uebersprungen wurde?

    ERSTE FASSUNG WAR FALSCH, und der Reproduktionsknoten hat sie widerlegt, nicht ich. Sie fragte
    `_TESTNAME.search(rumpf)` — ob irgendwo im Abschnitt ein Testname steht. Der Stand VOR dem Fix
    nennt `test_crosscheck_relation_differential_green` sehr wohl: in der Tabelle, als Beleg
    dafuer, dass das Differential „agrees". Genau dieser Test war der uebersprungene. Die Erwaehnung
    war also nicht nur kein Gegenbeweis, sie war Teil des Fehlers.

    DRITTE FASSUNG, und diesmal kam der Fund von der Fremdfamilie (Codex r3999958440, am Kopf
    af0d6f9, also an GENAU DIESER Datei). Die zweite Fassung fragte, ob EIN Satz ueber das
    Ueberspringen einen Testnamen traegt — und liess damit einen Abschnitt durch, der
    `22 passed, 2 skipped` zitiert und nur EINEN der beiden erklaert. Die Pflicht gilt JE
    UEBERSPRUNGENEM FALL, nicht je Abschnitt. Nachgemessen reichte der Fund weiter als der
    Kommentar sagte: auch ein Abschnitt mit ZWEI Sammelzahlen, von denen nur eine aufgeschluesselt
    ist, kam durch. Gezaehlt wird deshalb jetzt: benannte uebersprungene Faelle gegen die SUMME
    aller uebersprungenen Faelle des Abschnitts.

    Dreimal dieselbe Klasse an derselben Funktion, und jedes Mal eine Ebene feiner: Erwaehnung,
    dann Verbindung, jetzt Abdeckung. Eine Existenzpruefung erfuellt keine Stueckpflicht.
    """
    return len(benannte_uebersprungene(rumpf)) >= uebersprungene_gesamt(rumpf)


def abschnitte(text: str) -> list[tuple[str, str]]:
    """Der Text in Abschnitte, je Ueberschrift der Ebene drei. -> [(Titel, Rumpf)]"""
    teile = re.split(r"^(### .+)$", text, flags=re.M)
    raus = []
    for i in range(1, len(teile), 2):
        raus.append((teile[i].strip(), teile[i + 1] if i + 1 < len(teile) else ""))
    return raus or [("(ohne Ueberschrift)", text)]


def stumme_sammelzahlen(text: str) -> list[str]:
    """Abschnitte, die eine Messung behaupten und die Sammelzahl NICHT aufschluesseln.

    Leer heisst gruen. Die Rueckgabe nennt je Fund den Abschnitt und die Zahl, damit die Meldung
    sagt, WO etwas fehlt, statt nur DASS.
    """
    funde = []
    for titel, rumpf in abschnitte(text):
        zahlen = [m for m in _SAMMELZAHL.finditer(rumpf) if int(m.group(2)) > 0]
        if not zahlen:
            continue
        if _NICHT_GEMESSEN.search(rumpf):
            continue                      # der Abschnitt sagt selbst, dass nicht gemessen wurde
        if not _BEHAUPTET_GEMESSEN.search(rumpf):
            continue                      # keine Messbehauptung, keine Pflicht
        if nennt_den_uebersprungenen_fall(rumpf):
            continue                      # der uebersprungene Fall ist benannt
        soll = uebersprungene_gesamt(rumpf)
        ist = benannte_uebersprungene(rumpf)
        funde.append(
            f"{titel[:70]}: zitiert {soll} uebersprungene(n) Fall/Faelle, benannt sind "
            f"{len(ist)} ({sorted(ist) or 'keiner'})")
    return funde


# ── KNOTEN 1, REPRODUKTION ────────────────────────────────────────────────────────────────

def test_knoten1_die_eingefrorene_grundlage_ist_unveraendert():
    """[ZAEHLT] Ein Beweis gegen eine Datei, die sich aendern darf, ist kein Beweis."""
    if not EINGEFROREN.is_file():
        pytest.fail(f"die eingefrorene Grundlage fehlt: {EINGEFROREN}")
    ist = hashlib.sha256(EINGEFROREN.read_bytes()).hexdigest()
    assert ist == EINGEFROREN_SHA256, (
        f"die eingefrorene Grundlage traegt {ist[:16]}, erwartet {EINGEFROREN_SHA256[:16]}. "
        f"Damit misst Knoten 1 einen anderen Gegenstand als den, den Codex gemessen hat.")


def test_knoten1_der_stand_vor_dem_fix_wird_GEFANGEN():
    """[ZAEHLT] Der Fund selbst, reproduziert. Rot am alten Stand, und das ist die Zusage."""
    funde = stumme_sammelzahlen(EINGEFROREN.read_text(encoding="utf-8"))
    assert funde, (
        "der Riegel faengt den Stand von vor dem Fix NICHT — dann prueft er nicht das, wofuer er "
        "gebaut ist. Erwartet war ein Fund fuer T5 mit `23 passed, 1 skipped`.")
    # AM GEGENSTAND, NICHT AM MELDUNGSTEXT. Die erste Fassung dieser Zeile prueft, ob der String
    # "23 passed, 1 skipped" in der Meldung vorkommt — und fiel um, sobald die Meldung praeziser
    # wurde (sie nennt jetzt Zahlen statt der zitierten Zeile). Ein Orakel, das an der Prosa seines
    # Gegenstands haengt, misst dessen Schreibweise. Genau die Klasse, gegen die diese Datei steht.
    assert any(f.startswith("### T5") for f in funde), funde
    assert all("benannt sind 0" in f for f in funde if f.startswith("### T5")), funde


# ── KNOTEN 2, EIGENSCHAFT ─────────────────────────────────────────────────────────────────

def test_knoten2_das_heutige_dokument_haelt_die_eigenschaft():
    """[ZAEHLT] Keine stumme Sammelzahl im Baum. Gruen am neuen Stand."""
    if not DOKUMENT.is_file():
        pytest.skip(f"NICHT MESSBAR: {DOKUMENT} liegt nicht im Baum")
    funde = stumme_sammelzahlen(DOKUMENT.read_text(encoding="utf-8"))
    assert not funde, "\n".join(
        [f"{len(funde)} Zustandszeile(n) behaupten eine Messung und zitieren eine Sammelzahl mit "
         f"Uebersprungenen, ohne den uebersprungenen Fall zu nennen:"] + funde)


def test_knoten2_T5_nennt_den_uebersprungenen_fall_beim_namen():
    """[ZAEHLT] Die Instanz, positiv formuliert statt nur als Abwesenheit eines Fundes."""
    if not DOKUMENT.is_file():
        pytest.skip(f"NICHT MESSBAR: {DOKUMENT} liegt nicht im Baum")
    t5 = [r for t, r in abschnitte(DOKUMENT.read_text(encoding="utf-8")) if t.startswith("### T5")]
    assert t5, "der Abschnitt T5 fehlt im Dokument"
    rumpf = t5[0]
    assert "test_crosscheck_relation_differential_green" in rumpf, (
        "T5 nennt den uebersprungenen Fall nicht beim Namen")
    assert "pb_verify_rs not cargo-built" in rumpf, (
        "T5 nennt den GRUND des Ueberspringens nicht; ein Name ohne Grund laesst offen, ob der "
        "Fall faellt oder nur nicht laufen konnte")


# ── ANTI-PARITAET, damit der Riegel nicht alles meldet ────────────────────────────────────

def test_ANTI_ein_abschnitt_der_NOT_MEASURED_sagt_wird_nicht_gemeldet():
    """[ZAEHLT] Wer selbst sagt, er habe nicht gemessen, behauptet nichts Falsches."""
    text = ("### TX — Probe\n\n- **State:** **NOT MEASURED** in the run cited below.\n\n"
            "  Measured run, both files: **23 passed, 1 skipped**.\n")
    assert stumme_sammelzahlen(text) == []


def test_ANTI_ein_testname_OHNE_bezug_zum_ueberspringen_genuegt_NICHT():
    """[ZAEHLT] Genau die Lage vor dem Fix, auf das Kleinste eingedampft.

    Der Name steht da, aber als Beleg fuer das Gegenteil. Eine Fassung, die nur nach dem Namen
    sucht, meldet hier nichts — und liesse den Fund durch, den Codex gefunden hat.
    """
    text = ("### TZ — Probe\n\n- **State:** **MEASURED, partially**.\n\n"
            "  | `tests/a.py` | `test_crosscheck_relation_differential_green` agrees |\n\n"
            "  Measured run, both files: **23 passed, 1 skipped**.\n")
    assert stumme_sammelzahlen(text), "ein Name ohne Bezug zum Ueberspringen darf nicht genuegen"


def test_ANTI_eine_sammelzahl_OHNE_uebersprungene_wird_nicht_gemeldet():
    """[ZAEHLT] `24 passed, 0 skipped` verdeckt nichts, es gibt nichts zu verdecken."""
    text = ("### TY — Probe\n\n- **State:** **MEASURED**.\n\n"
            "  Measured run, both files: **24 passed, 0 skipped**.\n")
    assert stumme_sammelzahlen(text) == []


# ── DRITTE ITERATION, Fund der Fremdfamilie (Codex r3999958440) ───────────────────────────

def test_FANG_zwei_uebersprungene_und_nur_EINER_benannt_wird_gemeldet():
    """[ZAEHLT] Der Fund von Codex, auf das Kleinste eingedampft."""
    text = ("### TA\n\n- **State:** **MEASURED**.\n\n  Run: **22 passed, 2 skipped**.\n"
            "  One of them, `test_first`, was skipped because the binary is absent.\n")
    assert stumme_sammelzahlen(text), "eine Stueckpflicht wird von einer Existenzpruefung nicht erfuellt"


def test_FANG_zwei_uebersprungene_und_BEIDE_benannt_ist_gruen():
    """[ZAEHLT] Gegenrichtung, sonst meldet der Riegel jeden Abschnitt mit mehreren Skips."""
    text = ("### TB\n\n- **State:** **MEASURED**.\n\n  Run: **22 passed, 2 skipped**.\n"
            "  Skipped were `test_first` and `test_second`, both for the same reason.\n")
    assert stumme_sammelzahlen(text) == []


def test_FANG_zwei_sammelzahlen_und_nur_eine_erklaert_wird_gemeldet():
    """[ZAEHLT] Weiter als der Kommentar sagte, beim Nachmessen gefunden.

    Der Kommentar nannte den Fall EIN Abschnitt mit EINER Sammelzahl und zwei Skips. Gemessen kam
    auch ein Abschnitt mit ZWEI Sammelzahlen durch, von denen nur eine aufgeschluesselt ist.
    """
    text = ("### TC\n\n- **State:** **MEASURED**.\n\n  First run: **10 passed, 1 skipped**, "
            "`test_a` skipped.\n  Second run: **12 passed, 1 skipped**.\n")
    assert stumme_sammelzahlen(text), "zwei Laeufe, eine Erklaerung, das genuegt nicht"


def test_FANG_zwei_PARAMETRIERTE_faelle_beide_benannt_ist_gruen():
    """[ZAEHLT] Der Fund von Codex, auf das Kleinste eingedampft."""
    text = ("### TP\n\n- **State:** **MEASURED**.\n\n  Run: **22 passed, 2 skipped**.\n"
            "  Skipped were `test_first[a]` and `test_first[b]`, both for the same reason.\n")
    assert stumme_sammelzahlen(text) == [], (
        "zwei parametrierte Faelle, beide benannt, duerfen nicht gemeldet werden")


def test_FANG_zwei_parametrierte_und_nur_EINER_benannt_bleibt_rot():
    """[ZAEHLT] Gegenrichtung: der Fix darf die Stueckpflicht nicht aufweichen."""
    text = ("### TQ\n\n- **State:** **MEASURED**.\n\n  Run: **22 passed, 2 skipped**.\n"
            "  One of them, `test_first[a]`, was skipped because the binary is absent.\n")
    assert stumme_sammelzahlen(text), "eine von zwei benannt genuegt weiterhin nicht"
