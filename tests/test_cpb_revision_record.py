"""Vertrag: was das Mapping ueber die CPB-Entwuerfe behauptet, muss zum Messbeleg passen.

WARUM ES DIESEN VERTRAG GIBT. Am 15.09.2026 fielen drei Aussagen von
`docs/SCITT_CPB_MAPPING.md` ueber `draft-mih-sokolov-scitt-payload-binding` bei einer
Nachmessung durch. Alle drei gehoeren EINER Klasse an: **eine Aussage ueber fremden
Normtext wurde fortgeschrieben, ohne sie gegen die Vorgaengerfassung zu messen.**

  1. 4.1 sei in `-05` "schaerfer" als in `-02` — die Saetze sind identisch bis auf
     `P` -> `the payload`. Die Runde hatte den NEUEN Satz im ALTEN Text gesucht, ihn
     nicht gefunden und die Fehlanzeige als Aenderung gelesen.
  2. "nothing moved" — `Verification Scope` wanderte von 8.2 nach 8.5.
  3. Ein Zitat "no normative change" aus einem Abschnitt namens "Changes from -04"
     stand als Beleg fuer die Spanne `-02`..`-05`.

EHRLICHE GRENZE, und sie ist der Punkt. Dieser Vertrag prueft die INNERE STIMMIGKEIT
zwischen dem Blatt und `conformance/cpb_revision_record.json`. Er prueft NICHT, ob der
Beleg die Entwuerfe richtig wiedergibt — ein Pruefer, der nur sein eigenes Artefakt
liest, beglaubigt auch dessen Fehler. Dafuer fuehrt der Beleg `bytes` und `sha256` je
Revision: wer zweifelt, holt den Text und rechnet nach. Was der Vertrag leistet, ist
das Fortschreiben OHNE Neumessung teuer zu machen.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

WURZEL = Path(__file__).resolve().parents[1]
BELEG = WURZEL / "conformance" / "cpb_revision_record.json"
BLATT = WURZEL / "docs" / "SCITT_CPB_MAPPING.md"


def _beleg() -> dict:
    return json.loads(BELEG.read_text(encoding="utf-8"))


def _blatt() -> str:
    """Das Blatt mit normalisiertem Whitespace.

    Ohne das findet keine Suche einen Satz, der ueber einen Zeilenumbruch laeuft — und
    genau daran scheiterte am 15.09. ein `grep` nach der All-Aussage im Kopf.
    """
    return re.sub(r"\s+", " ", BLATT.read_text(encoding="utf-8"))


# Wortfeld der RUECKNAHME. Eine zurueckgenommene Aussage muss auf dieser Seite zitierbar
# bleiben — sonst kann das Blatt seinen eigenen Irrtum nicht protokollieren, und der Waechter
# bestrafte genau die Ehrlichkeit, fuer die er gebaut ist. Gemessen 15.09.2026: die erste Fassung
# dieses Wortfeldes war so eng, dass sie bei der ersten protokollierten Rueckname rot wurde.
_RUECKNAHME = (
    "no tightening",
    "first version",
    "earlier version",
    "withdrawn",
    "did not hold",
    "said",
)


def _ist_zuruecknahme(satz: str) -> bool:
    """Markiert der Satz die Aussage selbst als nicht (mehr) geltend?"""
    klein = satz.lower()
    return any(w in klein for w in _RUECKNAHME)


def _einheiten() -> list[str]:
    """Das Blatt in Einheiten, in denen eine Ruecknahme noch beim Zitat steht.

    EINE TABELLENZEILE IST EINE EINHEIT, ein Prosa-Satz ist eine Einheit. Die erste Fassung
    dieser Tests schnitt am Punkt und uebersah dabei, dass eine Abschnittsnummer wie `4.1`
    selbst einen Punkt traegt: der Treffer endete mitten in der Tabellenzeile, VOR dem
    "did NOT hold" in derselben Zelle, und der Waechter wurde rot an einer korrekt
    protokollierten Ruecknahme. Gemessen 15.09.2026 am eigenen Blatt.
    """
    roh = BLATT.read_text(encoding="utf-8")
    zeilen, prosa = [], []
    for z in roh.split("\n"):
        (zeilen if z.lstrip().startswith("|") else prosa).append(z)
    text = re.sub(r"\s+", " ", " ".join(prosa))
    # Satzgrenze: Punkt gefolgt von Leerzeichen und Grossbuchstabe/Sternchen — eine
    # Abschnittsnummer wie 4.1 loest das nicht aus.
    saetze = re.split(r"(?<=[.!?])\s+(?=[A-Z*`])", text)
    return [z for z in zeilen if z.strip()] + [s for s in saetze if s.strip()]


def test_der_beleg_traegt_alle_vier_revisionen() -> None:
    rev = _beleg()["revisionen"]
    assert set(rev) == {"-02", "-03", "-04", "-05"}, (
        "Der Beleg muss die Spanne tragen, ueber die das Blatt Aussagen macht. Fehlt eine "
        "Revision, kann niemand pruefen, in welcher eine Aenderung ankam."
    )
    for name, r in rev.items():
        assert r["bytes"] > 0, name
        assert re.fullmatch(r"[0-9a-f]{64}", r["sha256"]), f"{name}: kein voller sha256"
        assert r["abschnitte"], name


def test_jede_byte_zahl_im_blatt_steht_so_im_beleg() -> None:
    """Das Blatt nennt Byte-Zahlen als Beleg. Wandern sie, ist eine Aussage veraltet."""
    text = _blatt()
    rev = _beleg()["revisionen"]
    genannt = {int(m) for m in re.findall(r"\*\*(\d{5,7}) bytes\*\*", text)}
    assert genannt, "Das Blatt nennt keine einzige Byte-Zahl mehr — dann fehlt ihm der Beleg."
    bekannt = {r["bytes"] for r in rev.values()}
    fremd = genannt - bekannt
    assert not fremd, (
        f"Byte-Zahlen im Blatt, die zu keiner belegten Revision gehoeren: {sorted(fremd)}. "
        f"Belegt sind {sorted(bekannt)}."
    )


def test_jeder_digest_im_blatt_gehoert_zu_einer_belegten_revision() -> None:
    text = _blatt()
    rev = _beleg()["revisionen"]
    # Das Blatt zitiert Digests voll oder als Praefix mit Auslassungszeichen.
    genannt = set(re.findall(r"`([0-9a-f]{8,64})(?:\.\.\.|…)?`", text))
    treffer = {g for g in genannt if any(r["sha256"].startswith(g) for r in rev.values())}
    ohne = {g for g in genannt if len(g) >= 16 and g not in treffer}
    # Das Blatt fuehrt auch fremde Digests (andere Entwuerfe, Merkle-Wurzeln). Gepruefte
    # Aussage ist daher: mindestens die CPB-Digests muessen vorkommen, und ein Praefix,
    # das ZU EINEM CPB-Digest passen soll, muss wirklich passen.
    assert treffer, "Kein einziger belegter CPB-Digest steht mehr im Blatt."
    for r in rev.values():
        pass
    assert len(treffer) >= 2, (
        f"Nur {len(treffer)} belegte CPB-Digests im Blatt gefunden; erwartet werden "
        f"mindestens die beiden Endpunkte der gemessenen Spanne. Ohne Zuordnung: {sorted(ohne)}"
    )


def test_die_pflichtwortzahlen_im_blatt_stehen_so_im_beleg() -> None:
    """Behauptet das Blatt einen Sprung, muss der Beleg ihn tragen."""
    text = _blatt()
    rev = _beleg()["revisionen"]
    summen = {r["pflichtwoerter"]["summe_must_familie"] for r in rev.values()}
    paare = re.findall(r"from \*\*(\d{2,4}) to (\d{2,4})\*\*", text)
    assert paare, "Das Blatt nennt keinen Pflichtwort-Sprung mehr."
    for a, b in paare:
        assert int(a) in summen and int(b) in summen, (
            f"Das Blatt behauptet einen Sprung {a} -> {b}; belegt sind {sorted(summen)}."
        )


def test_jede_abschnittsnummer_im_blatt_gibt_es_in_05() -> None:
    """Eine zitierte Nummer, die es nicht gibt, zeigt ins Leere.

    Die gefaehrliche Form ist die andere: eine Nummer, die es NOCH gibt, aber mit anderem
    Inhalt (8.2 trug in -02 `Verification Scope`, in -05 `Carriage Selection`). Dagegen
    hilft kein Vertrag, nur die Messung — deshalb steht der Fall im Beleg.
    """
    text = _blatt()
    rev = _beleg()["revisionen"]["-05"]["abschnitte"]
    # Nur der CPB-Teil des Blattes; ab "Mapping 2" geht es um andere Entwuerfe.
    ende = text.find("## Mapping 2")
    kopf = text[: ende if ende > 0 else len(text)]
    genannt = set(re.findall(r"[Ss]ection (\d+(?:\.\d+)*)", kopf))
    assert genannt, "Der CPB-Teil zitiert keinen Abschnitt mehr."
    fehlend = {g for g in genannt if g not in rev}
    assert not fehlend, (
        f"Das Blatt zitiert Abschnitte, die es in -05 nicht gibt: {sorted(fehlend)}."
    )


def test_ein_verschobener_abschnitt_ist_im_beleg_als_solcher_erkennbar() -> None:
    """8.2 -> 8.5: gleicher Titel, andere Nummer. Der Beleg muss das hergeben."""
    rev = _beleg()["revisionen"]
    alt, neu = rev["-02"]["abschnitte"], rev["-05"]["abschnitte"]
    verschoben = {
        t: (n_alt, n_neu)
        for n_alt, t in alt.items()
        for n_neu, t2 in neu.items()
        if t == t2 and n_alt != n_neu
    }
    assert "Verification Scope" in verschoben, (
        "Der Beleg gibt die gemessene Verschiebung nicht mehr her. Sie ist der Grund, "
        "warum die Aussage 'nothing moved' zurueckgezogen wurde."
    )
    assert verschoben["Verification Scope"] == ("8.2", "8.5")
    assert neu["8.2"] != alt["8.2"], (
        "8.2 muss in -05 einen anderen Titel tragen als in -02 — das ist die Falle: die "
        "alte Nummer loest weiter auf, nur auf etwas anderes."
    )


@pytest.mark.parametrize("schluessel", ["ausschlussmenge_4_1"])
def test_wo_der_beleg_gleiche_regel_sagt_ist_es_genau_ein_getauschtes_wort(schluessel: str) -> None:
    """Die Klasse, an der es scheiterte: eine Wortersetzung als Regelaenderung gelesen.

    Der Beleg BEHAUPTET nicht, die Regel sei gleich — der Vertrag RECHNET es nach. Sagt
    das Urteil 'gleiche Regel', muss der Wortdiff genau eine Ersetzung sein. Wer den
    Beleg so aendert, dass die Saetze wirklich auseinandergehen, bekommt hier Rot.
    """
    satz = _beleg()["saetze"][schluessel]
    assert satz["urteil"].startswith("gleiche Regel"), schluessel
    a, b = satz["-02"].split(), satz["-05"].split()
    import difflib

    ops = [o for o in difflib.SequenceMatcher(a=a, b=b).get_opcodes() if o[0] != "equal"]
    assert len(ops) == 1, f"erwartet genau eine Abweichung, gemessen {len(ops)}: {ops}"
    art, i1, i2, j1, j2 = ops[0]
    assert art == "replace", f"erwartet eine Ersetzung, gemessen {art}"
    assert (i2 - i1, j2 - j1) == (1, 2), (
        f"erwartet 'P' -> 'the payload', gemessen {a[i1:i2]} -> {b[j1:j2]}"
    )


def test_das_blatt_behauptet_keine_verschaerfung_in_4_1() -> None:
    """Die zurueckgenommene Aussage darf nicht zurueckkehren.

    Das ist der einzige Test hier, der Prosa liest, und er ist eng gehalten: er sucht die
    Wendung, mit der die Aussage dastand, im selben Satz wie die Abschnittsnummer.
    """
    treffer = [e for e in _einheiten() if "more tightly" in e and "4.1" in e]
    erlaubt = [t for t in treffer if _ist_zuruecknahme(t)]
    assert len(treffer) == len(erlaubt), (
        "Das Blatt behauptet wieder, 4.1 sei in -05 schaerfer gefasst. Gemessen sind die "
        f"Saetze identisch bis auf ein Token. Fundstellen: {treffer}"
    )


def test_das_blatt_behauptet_nicht_unqualifiziert_dass_nichts_sich_verschob() -> None:
    """Befund 2: eine Allaussage ueber fremden Normtext, die eine Messung widerlegt.

    Gemessen sind ZWEI Inhaltsverschiebungen von `-02` nach `-05`. Die Wendung darf nur
    stehen, wo sie ausdruecklich zurueckgenommen wird.
    """
    treffer = [e for e in _einheiten() if "nothing moved" in e]
    erlaubt = [t for t in treffer if _ist_zuruecknahme(t)]
    assert len(treffer) == len(erlaubt), (
        "Das Blatt behauptet wieder unqualifiziert, nichts habe sich verschoben. Gemessen: "
        "Verification Scope 8.2 -> 8.5, und zwei Absaetze aus 14.1 nach 14.1.1. "
        f"Fundstellen: {treffer}"
    )


def test_wer_das_aenderungsprotokoll_zitiert_nennt_seine_reichweite() -> None:
    """Befund 3: ein Aenderungsprotokoll deckt die Revision, die in seiner Ueberschrift steht.

    Das Blatt darf `-05`s "no normative change" zitieren — aber dann muss dabeistehen, dass
    der Abschnitt "Changes from -04" heisst. Sonst liest es sich als Aussage ueber die
    ganze Spanne, ueber die es gerade misst.
    """
    text = _blatt()
    if "no normative change" not in text:
        pytest.skip("Das Blatt zitiert den Satz nicht mehr; dann gibt es nichts einzuordnen.")
    assert "Changes from -04" in text, (
        'Das Blatt zitiert "no normative change" aus Abschnitt 2 von -05, ohne zu sagen, dass '
        'dieser Abschnitt "Changes from -04" heisst und damit EINE Revision deckt. Ueber die '
        "Spanne, die das Blatt misst (-02 bis -05), stiegen die Pflichtwoerter von 68 auf 113."
    )
    rev = _beleg()["revisionen"]
    spanne = (rev["-02"]["pflichtwoerter"]["summe_must_familie"],
              rev["-05"]["pflichtwoerter"]["summe_must_familie"])
    assert f"{spanne[0]} to {spanne[1]}" in text, (
        f"Die Einordnung fehlt die gemessene Zahl: erwartet '{spanne[0]} to {spanne[1]}'."
    )


def test_die_editorial_zusage_gilt_genau_fuer_den_schritt_in_dem_sie_steht() -> None:
    """Die feinere Aufloesung der Spanne (nachgeholt 15.09.2026).

    Die Seite zitiert aus `-04` die Zusage, die Revision sei editorial und aendere keinen normativen
    Text. Die Frage, die dieser Fall festhaelt, ist nicht ob die Zusage STIMMT — sie stimmt —,
    sondern WIE WEIT sie reicht. Gemessen: in `-03` und `-04` sind alle vier Pflichtwortzahlen
    identisch, die Zusage traegt also fuer ihren eigenen Schritt. Die 45 zusaetzlichen Pflichtwoerter
    der Spanne `-02` bis `-05` kamen alle im Schritt davor, und der ist in `-03` beschrieben.

    Der Fall faellt in beide Richtungen: veraendert jemand eine der Zahlen in `-03` oder `-04`,
    stimmt die Zusage nicht mehr mit dem Beleg ueberein; verschwindet der Satz aus dem Beleg, ist
    die Aussage der Seite nicht mehr gedeckt.
    """
    beleg = _beleg()
    a = beleg["revisionen"]["-03"]["pflichtwoerter"]
    b = beleg["revisionen"]["-04"]["pflichtwoerter"]
    assert a == b, (
        f"-03 und -04 tragen verschiedene Pflichtwortzahlen ({a} vs {b}) — dann ist die Zusage "
        "'editorial, kein normativer Text' fuer diesen Schritt NICHT gedeckt.")

    satz = beleg["saetze"]["editorial_zusage_04"]
    assert "no normative text" in satz["-04"], satz["-04"]
    assert "Changes from -03" in satz["fundort"], satz["fundort"]

    # Und die Spanne davor traegt den GANZEN Zuwachs — sonst waere die Eingrenzung der Seite falsch.
    zwei = beleg["revisionen"]["-02"]["pflichtwoerter"]["summe_must_familie"]
    drei = beleg["revisionen"]["-03"]["pflichtwoerter"]["summe_must_familie"]
    fuenf = beleg["revisionen"]["-05"]["pflichtwoerter"]["summe_must_familie"]
    assert drei - zwei == fuenf - zwei, (
        f"Der Zuwachs der Spanne (-02 -> -05: {fuenf - zwei}) kommt NICHT vollstaendig aus dem "
        f"Schritt -02 -> -03 ({drei - zwei}) — dann reicht die Zusage aus -04 weiter oder weniger "
        "weit als die Seite sagt, und der Satz dort gehoert nachgezogen.")


def test_die_spanne_03_04_ist_charakterisiert_und_nicht_nur_gezaehlt() -> None:
    """Eine Zahl ohne Inhalt beantwortet die Frage nicht, die jemand stellt.

    `-04` ist 1438 Byte groesser als `-03` und traegt kein zusaetzliches Pflichtwort. Ohne die
    Aufzaehlung daneben bleibt offen, WAS diese 1438 Byte sind — und die naheliegende Vermutung
    (Neupaginierung) ist nachweislich falsch, weil der Beleg entpaginiert gemessen wurde.
    """
    sp = _beleg()["spanne_03_04"]
    assert sp["pflichtwortunterschied"] == 0
    assert sp["roher_byteunterschied"] > 0
    assert "entpaginiert" in sp["methode"], "die Methode muss nennen, dass entpaginiert wurde"
    assert len(sp["aenderungen"]) >= 5, (
        f"nur {len(sp['aenderungen'])} Aenderungen aufgezaehlt — eine Charakterisierung, die die "
        "Haelfte weglaesst, liest sich wie eine vollstaendige.")
    # Die beiden Stellen, an denen der Entwurf seine EIGENE Aussage enger zieht, sind der
    # interessante Teil und duerfen nicht aus der Liste fallen.
    text = " ".join(sp["aenderungen"])
    assert "ENGER" in text, "die Eingrenzungen des Entwurfs fehlen in der Aufzaehlung"
    assert "third computation" in text, "der ausdrueckliche Nicht-Traegt-Satz fehlt"
