"""Eine Zahl neben einer wachsenden Menge veraltet lautlos — also wird sie nachgerechnet.

FUND, Codex 4000296671 (P2). Das signierte Register `audit_artifacts/findings_register_361.json`
traegt 21 Eintraege und endet auf N21, waehrend `audit_artifacts/600/README.md` an zwei Stellen
weiter 20 nannte — einmal in der Prosa ueber den Traeger, einmal in der Zeile, die das
release-entscheidende C12.2-Urteil traegt. Der hinzugefuegte Eintrag verschob die genannte
Pruefgrenze, ohne die abhaengige Zahl mitzunehmen.

DIE KLASSE steht in DIESEM DOKUMENT bereits ueber sich selbst geschrieben, ein paar Zeilen unter
der falschen Zahl: "A number beside a growing set goes stale in silence — the class this document
names about others and missed about itself." Damals war es die Zahl der gescannten Dokumente,
49 statt 53. Jetzt dieselbe Klasse, dieselbe Datei, eine andere Zahl. Eine Klasse, die man nur
BESCHREIBT, faengt nichts.

THE DOCUMENT IS CHOSEN BY THE REGISTER'S VERSION (2026-09-21): `audit_artifacts/600/README.md`
is frozen with the released 6.0.0, so a register scoped to 6.1.0 is measured against
`audit_artifacts/610/README.md`, and a document that says NOT MEASURED for C12.2 still has to
name the right population.

TWO FORMS SINCE THE TEXT REVIEW OF 6.3.0 (owner decision of 2026-10-13, review texts taken word for
word). The page of 6.3.0 states the population in one sentence, "N register entries for version `V`,
with N closed, N open and no open P0 or P1 entries", and carries no C12.2 line, because the review
replaced that line and the claim of a recount on every run. The numbers stay under this guard in
either form: the sentence of the new form is recomputed like the old one, its version must be the
register's, and a page of the old form still has to carry its C12.2 line. What is no longer demanded
is a C12.2 line on a page that names no gate verdict.

DESHALB STEHT DIE ZAHL JETZT UNTER EINEM RIEGEL statt unter einer Mahnung. Dieser Vertrag rechnet
sie aus dem Register aus und haelt sie gegen das, was die Prosa sagt. Wer einen Eintrag hinzufuegt,
sieht die Abweichung hier, nicht erst in einem fremden Review.
"""
from __future__ import annotations

import json
import pathlib
import re

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
REGISTER = REPO / "audit_artifacts" / "findings_register_361.json"


def _readme_der_registerfassung() -> pathlib.Path:
    """The document that speaks about THIS register, chosen by the register's own version.

    The first version of this file named `audit_artifacts/600/README.md`. That document is the
    record of the released 6.0.0 and is frozen with it, so the moment the register is scoped to
    the next cut its figures stop describing the register and this guard would fail a correct
    document. The token of a cut is its version without the dots (6.1.0 -> 610), the same rule
    `audit_candidate_matrix` applies to the artefact folder, read from the register rather than
    typed here.
    """
    if not REGISTER.is_file():
        pytest.skip(f"NICHT MESSBAR: {REGISTER} fehlt")
    version = str(json.loads(REGISTER.read_text(encoding="utf-8")).get("version", ""))
    return REPO / "audit_artifacts" / version.replace(".", "") / "README.md"


def _gemessen() -> dict:
    if not REGISTER.is_file():
        pytest.skip(f"NICHT MESSBAR: {REGISTER} fehlt")
    register = json.loads(REGISTER.read_text(encoding="utf-8"))
    f = register["findings"]
    zu = [x for x in f if x.get("status") == "closed"]
    hoch_offen = [x for x in f
                  if x.get("severity") in ("P0", "P1") and x.get("status") != "closed"]
    return {"gesamt": len(f), "zu": len(zu), "offen": len(f) - len(zu),
            "hoch_offen": len(hoch_offen), "version": str(register.get("version", ""))}


def _text() -> str:
    readme = _readme_der_registerfassung()
    if not readme.is_file():
        pytest.skip(f"NICHT MESSBAR: {readme} fehlt")
    return readme.read_text(encoding="utf-8")


#: The sentence of the 6.3.0 page (text review of 2026-10-13): population, version, closed, open, and the
#: statement about open P0 and P1 in one sentence.
NEUE_FORM = re.compile(r"(\d+) register entries for version `([^`]+)`, with (\d+) closed, (\d+) open "
                       r"and no open P0 or P1 entries")


#: The sentence of the pages of 6.0.0 to 6.2.1.
ALTE_FORM = re.compile(r"(\d+) entries, (\d+) closed, (\d+) open")

#: The release line of the old form, in any dash a writer may type between the gate and the number.
GATE_ZEILE = re.compile(r"(?:PASS|NOT MEASURED) via C12\.2\s*[\u2014\u2013-]+\s*(\d+) findings")


def abweichungen(text: str, g: dict) -> list[str]:
    """Which stated numbers differ from the measured ones? ONE checker for both directions.

    EVERY OCCURRENCE OF EVERY FORM (adversarial reading of 2026-10-13). The first version of the two-form
    reader read the first match of one form and stopped: a correct sentence of the new form hid a stale
    sentence of the old form on the same page, a second sentence of the new form was never read, and a
    gate line typed with a hyphen instead of the dash was neither found nor compared. What this guard
    holds is that every count the page states is the register's, so it reads them all."""
    raus = []
    neue = list(NEUE_FORM.finditer(text))
    alte = list(ALTE_FORM.finditer(text))
    if not neue and not alte:
        raus.append("der Satz ueber den Traeger ist nicht auffindbar")
    soll = (g["gesamt"], g["zu"], g["offen"])
    for n in neue:
        zahlen = (int(n.group(1)), int(n.group(3)), int(n.group(4)))
        if zahlen != soll:
            raus.append(f"Prosa nennt {zahlen}, gemessen {soll}")
        if g.get("version") and n.group(2) != g["version"]:
            raus.append(f"Prosa nennt die Version {n.group(2)}, das Register traegt {g['version']}")
    for m in alte:
        zahlen = tuple(int(x) for x in m.groups())
        if zahlen != soll:
            raus.append(f"Prosa nennt {zahlen}, gemessen {soll}")
    # Two forms of the release line, and both carry the number: `PASS via C12.2 — N findings
    # evaluated` once the gate has run on the candidate, `NOT MEASURED via C12.2 — N findings` in
    # the document of a cut whose pre-tag round has not run yet. A document that says NOT MEASURED
    # still names the population, and the population is what goes stale.
    zeilen = list(GATE_ZEILE.finditer(text))
    if not zeilen and not neue:
        # A page of the new form names no gate verdict, so it needs no such line. A page of the old form
        # without it has lost the line this guard was built for. Any line that IS there is compared.
        raus.append("die C12.2-Zeile ist nicht auffindbar")
    for r in zeilen:
        if int(r.group(1)) != g["gesamt"]:
            raus.append(f"Release-Zeile nennt {r.group(1)}, Register traegt {g['gesamt']}")
    return raus


def sagt_kein_p0_p1_offen(text: str) -> bool:
    """The page states that no P0 or P1 is open, in the words of either form."""
    return "0 open P0/P1" in text or bool(NEUE_FORM.search(text))


def test_die_prosa_nennt_die_gemessenen_zahlen():
    """[ZAEHLT] Der Fund selbst: drei Zahlen in einem Satz, aus dem Register gerechnet."""
    offen = [x for x in abweichungen(_text(), _gemessen()) if "Prosa" in x or "Traeger" in x]
    assert not offen, offen


def test_die_release_zeile_nennt_die_gemessene_zahl():
    """[ZAEHLT] Die Zeile, die das release-entscheidende Urteil traegt, zaehlt doppelt."""
    offen = [x for x in abweichungen(_text(), _gemessen()) if "C12.2" in x or "Release" in x]
    assert not offen, offen


def test_die_zusicherung_0_offene_P0_P1_stimmt_noch():
    """[ZAEHLT] Die Aussage selbst, nicht nur die Zahl daneben."""
    g = _gemessen()
    assert g["hoch_offen"] == 0, f"{g['hoch_offen']} offene P0/P1 im Register — die Zusicherung faellt"
    text = _text()
    assert sagt_kein_p0_p1_offen(text), "die Seite sagt nicht, dass kein P0/P1 offen ist"


def test_FANG_eine_veraltete_zahl_faellt_hier_durch():
    """[ZAEHLT] Gegenrichtung am ECHTEN Text: genau der gemeldete Zustand, wiederhergestellt.

    Die erste Fassung baute sich eine Zeichenkette und verglich sie mit sich selbst — gruen, ohne
    den Pruefer je auf den echten Text zu lassen. Zweimal heute dieselbe Form, deshalb hier
    ausdruecklich: genommen wird die echte Datei, die Zahl auf den Stand VOR dem Fix zurueckgedreht,
    und der Pruefer MUSS das melden.
    """
    g, t = _gemessen(), _text()
    assert abweichungen(t, g) == [], "Vorbedingung: der heutige Text stimmt"
    if NEUE_FORM.search(t):
        vorher = t.replace(f"{g['gesamt']} register entries", f"{g['gesamt'] - 1} register entries", 1)
        vorher = vorher.replace(f"with {g['zu']} closed, {g['offen']} open",
                                f"with {g['zu']} closed, {g['offen'] - 1} open", 1)
        assert vorher != t, "die Ruecknahme hat nichts veraendert — dann misst dieser Fall nichts"
        gemeldet = abweichungen(vorher, g)
        assert len(gemeldet) == 1 and "Prosa" in gemeldet[0], f"erwartet eine Abweichung, gemessen {gemeldet}"
        return
    vorher = t.replace(f"{g['gesamt']} entries, {g['zu']} closed, {g['offen']} open",
                       f"{g['gesamt'] - 1} entries, {g['zu']} closed, {g['offen'] - 1} open", 1)
    vorher = re.sub(rf"((?:PASS|NOT MEASURED) via C12\.2 — ){g['gesamt']} findings",
                    rf"\g<1>{g['gesamt'] - 1} findings", vorher, count=1)
    assert vorher != t, "die Ruecknahme hat nichts veraendert — dann misst dieser Fall nichts"
    gemeldet = abweichungen(vorher, g)
    assert len(gemeldet) == 2, f"erwartet zwei Abweichungen, gemessen {gemeldet}"


def test_der_letzte_eintrag_ist_der_hoechste():
    """[GETRENNT] Eine Luecke in der Nummerierung waere eine andere Klasse, hier nur benannt."""
    if not REGISTER.is_file():
        pytest.skip(f"NICHT MESSBAR: {REGISTER} fehlt")
    ids = [x["id"] for x in json.loads(REGISTER.read_text(encoding="utf-8"))["findings"]]
    nummern = [int(i[1:]) for i in ids if i[1:].isdigit()]
    assert nummern == sorted(nummern), f"die Kennungen stehen nicht in Reihenfolge: {ids}"


def test_FANG_die_neue_form_mit_fremder_version_faellt_durch():
    """[ZAEHLT] The version in the sentence of the new form is the register's, not a copied one."""
    g = {"gesamt": 36, "zu": 19, "offen": 17, "hoch_offen": 0, "version": "6.3.0"}
    satz = ("reports 36 register entries for version `6.3.0`, with 19 closed, 17 open and no open P0 or P1 "
            "entries")
    assert abweichungen(satz, g) == [], "Vorbedingung: der Satz stimmt"
    gemeldet = abweichungen(satz.replace("`6.3.0`", "`6.2.1`"), g)
    assert len(gemeldet) == 1 and "Version" in gemeldet[0], gemeldet


def test_die_alte_form_wird_weiter_gelesen_und_verlangt_ihre_C12_2_zeile():
    """[ZAEHLT] The pages of 6.0.0 to 6.2.1 stay under the same guard when the register no longer selects
    them: sentence and line are recomputed, and a page without the line is a finding."""
    g = {"gesamt": 26, "zu": 9, "offen": 17, "hoch_offen": 0, "version": "6.2.1"}
    text = "26 entries, 9 closed, 17 open. PASS via C12.2 — 26 findings evaluated."
    assert abweichungen(text, g) == []
    alt = text.replace("26 entries, 9 closed, 17 open", "25 entries, 9 closed, 16 open")
    assert len(abweichungen(alt.replace("— 26 findings", "— 25 findings"), g)) == 2
    assert abweichungen("26 entries, 9 closed, 17 open.", g) == ["die C12.2-Zeile ist nicht auffindbar"]
    assert abweichungen("nothing", g) == ["der Satz ueber den Traeger ist nicht auffindbar",
                                          "die C12.2-Zeile ist nicht auffindbar"]


def test_FANG_jede_fundstelle_jeder_form_wird_nachgerechnet():
    """[ZAEHLT] The counter-case of the adversarial reading of 2026-10-13: beside a correct sentence of the new
    form, a stale sentence of the old form, a second stale sentence of the new form, and a stale gate line
    typed with a hyphen instead of a dash each fail on their own."""
    g = {"gesamt": 36, "zu": 19, "offen": 17, "hoch_offen": 0, "version": "6.3.0"}
    satz = ("reports 36 register entries for version `6.3.0`, with 19 closed, 17 open and no open P0 or P1 "
            "entries")
    assert abweichungen(satz, g) == [], "Vorbedingung: der Satz stimmt"
    for zusatz in (" Earlier text: 30 entries, 10 closed, 20 open.",
                   " Also 30 register entries for version `6.3.0`, with 10 closed, 20 open and no open P0 or "
                   "P1 entries.",
                   " | findings register | PASS via C12.2 - 30 findings evaluated |"):
        gemeldet = abweichungen(satz + zusatz, g)
        assert len(gemeldet) == 1, (zusatz, gemeldet)


def test_FANG_ohne_die_klausel_sagt_die_seite_nichts_ueber_p0_p1():
    """[ZAEHLT] The clause 'and no open P0 or P1 entries' is the statement itself. A sentence without it does
    not meet the assurance, and a pattern without it would let every page pass."""
    mit = ("reports 36 register entries for version `6.3.0`, with 19 closed, 17 open and no open P0 or P1 "
           "entries")
    assert sagt_kein_p0_p1_offen(mit)
    assert not sagt_kein_p0_p1_offen(mit.replace(" and no open P0 or P1 entries", " and two open P1 entries"))
