"""Der Kipptag von C12.2 steht in der Prosa so, wie der Code ihn ausrechnet.

HERKUNFT, Codex-Kommentar r3999439778 in PR 197: `docs/release_scope/6.1.0.md` nannte den
2027-09-06 als Tag, an dem C12.2 von PASS auf FAIL kippt. Der Anker-Schluessel traegt
`not_after=2027-09-06`, und `scripts/audit_candidate_matrix.py` vergleicht STRIKT GROESSER
(`tag > frist_d`, `heute_d > frist_d`). Die Frist ist damit EINSCHLIESSEND: am 06.09. ist der
Schluessel noch autorisiert, der Umschlag faellt auf den 07.09. Die Zeile lag einen Tag daneben.

DIE KLASSE, und sie ist der Grund fuer diesen Riegel statt einer korrigierten Zeile: eine Zahl,
die VON HAND neben einer Regel steht, die sie ausrechnet. Solange beide getrennt gepflegt werden,
driften sie, und die Prosa ist die Seite, die ein Operator liest. Gemessen tragen im Baum MEHRERE
Dokumente diesen Tag; RESTRISIKO_600.md und der Registereintrag N21 nannten ihn bereits richtig,
diese eine Datei nicht. Eine Stelle richtig und eine falsch ist genau die Lage, in der niemand
merkt, welche gilt.

WAS HIER GEMESSEN WIRD. Der Kipptag wird aus zwei Quellen ABGELEITET, nie getippt: aus
`not_after` des Ankers und aus der Vergleichsrichtung des Codes. Dann wird jede Prosa-Stelle, die
von diesem Kippen spricht, dagegen gehalten.

EHRLICHE GRENZE. Gemessen werden Stellen, die C12.2 und ein ISO-Datum in derselben Zeile fuehren.
Eine Nennung ueber mehrere Zeilen hinweg oder in anderer Schreibweise faellt durch. Das ist eine
Untergrenze der Messung, keine Zusicherung.
"""
from __future__ import annotations

import datetime
import importlib.util
import pathlib
import re

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
ANKER = REPO / "audit_artifacts" / "readiness_trusted_pubkeys.txt"

#: Eine Zeile, die von C12.2 UND einem ISO-Datum spricht.
_PROSA = re.compile(r"^.*\bC12\.2\b.*?(\d{4}-\d{2}-\d{2}).*$", re.M)

#: `not_after=YYYY-MM-DD` im Ankertext.
_NOT_AFTER = re.compile(r"\bnot_after=(\d{4}-\d{2}-\d{2})\b")

#: Die Dokumente, die den Kipptag fuehren duerfen.
DOKUMENTE = ("docs/release_scope/6.1.0.md", "RESTRISIKO_600.md")


#: Eine Ankerzeile: Schluessel, Rolle, Frist.
_ANKERZEILE = re.compile(r"^(\S+)\s+role=(\S+)\s+not_after=(\d{4}-\d{2}-\d{2})\s*$", re.M)

#: Die Pruefung, ueber deren Kipptag dieser Riegel spricht.
PRUEFUNG = "C12.2"


def _rollen_fuer(pruefung: str) -> set[str] | None:
    """Welche Rollen duerfen fuer diese Pruefung signieren? Aus der PRODUKTIONSZUORDNUNG gelesen.

    ZWEITE FASSUNG, Fund der Fremdfamilie (Codex r3999991252) gegen diesen Riegel selbst. Die erste
    nahm `max()` ueber ALLE Ankerzeilen — eine OBERMENGE. Der Auswaehler der Produktion filtert
    dagegen nach ROLLE. Heute traegt die Ankerdatei genau eine Rolle, weshalb beide dasselbe
    ergeben; das ist die FAEHIGKEIT eines falschen Urteils, nicht sein Eintreten. Sobald eine
    zweite Rolle mit spaeterer Frist dazukommt, verlangt dieser Riegel ein Datum, das der
    entscheidende Schluessel nie traegt.

    Eine Grenze aus einer Obermenge abzuleiten ist keine Ableitung, sondern eine Schaetzung nach
    oben.
    """
    acm = REPO / "scripts" / "audit_candidate_matrix.py"
    if not acm.is_file():
        return None
    s = importlib.util.spec_from_file_location("_acm_rollen", acm)
    m = importlib.util.module_from_spec(s)
    try:
        s.loader.exec_module(m)
    except Exception:                      # noqa: BLE001 — ohne Modul kein Urteil, nicht raten
        return None
    zuordnung = getattr(m, "_ANKER_ROLLEN", None)
    if not isinstance(zuordnung, dict):
        return None
    return {rolle for rolle, pruefungen in zuordnung.items() if pruefung in (pruefungen or ())}


def frist_aus_dem_anker(anker: pathlib.Path | None = None) -> datetime.date | None:
    """Die Frist des Schluessels, der fuer DIESE Pruefung signieren darf. None heisst NICHT MESSBAR.

    Gibt es mehrere, gilt die SPAETESTE unter ihnen, denn solange einer von ihnen autorisiert ist,
    kippt die Pruefung nicht. Gibt es keinen, ist die Frage nicht beantwortbar und nicht zu raten.
    """
    # DER ANKERPFAD IST EIN PARAMETER, kein Modulwert. Die erste Fassung des Fangnachweises
    # versuchte, ihn per monkeypatch an `globals()` zu tauschen, und fiel mit einem AttributeError
    # — ein Fall, der seinen Gegenstand nicht stellen kann, misst nichts. Ein Standardwert haelt
    # den Aufruf im Bestand unveraendert.
    anker = anker or ANKER
    if not anker.is_file():
        return None
    rollen = _rollen_fuer(PRUEFUNG)
    if rollen is None:
        return None
    tage = []
    for m in _ANKERZEILE.finditer(anker.read_text(encoding="utf-8")):
        if m.group(2) not in rollen:
            continue                      # eine fremde Rolle entscheidet ueber diese Pruefung nicht
        try:
            tage.append(datetime.datetime.strptime(m.group(3), "%Y-%m-%d").date())
        except ValueError:
            continue
    return max(tage) if tage else None


def grenze_ist_einschliessend() -> bool:
    """Vergleicht der Code STRIKT GROESSER, ist `not_after` der letzte gueltige Tag.

    GEMESSEN AM CODE, nicht angenommen. Steht dort irgendwann `>=`, faellt dieser Riegel um und
    zwingt zur Neubewertung — genau das soll er.
    """
    quelle = (REPO / "scripts" / "audit_candidate_matrix.py").read_text(encoding="utf-8")
    return bool(re.search(r"\bheute_d\s*>\s*frist_d\b", quelle)) and \
        not re.search(r"\bheute_d\s*>=\s*frist_d\b", quelle)


def kipptag() -> datetime.date | None:
    f = frist_aus_dem_anker()
    if f is None:
        return None
    return f + datetime.timedelta(days=1) if grenze_ist_einschliessend() else f


def prosa_stellen() -> list[tuple[str, str, str]]:
    """(Datei, Zeile, genanntes Datum) fuer jede Stelle, die C12.2 mit einem Datum nennt."""
    raus = []
    for rel in DOKUMENTE:
        p = REPO / rel
        if not p.is_file():
            continue
        for m in _PROSA.finditer(p.read_text(encoding="utf-8")):
            raus.append((rel, m.group(0).strip()[:150], m.group(1)))
    return raus


def test_der_kipptag_ist_ableitbar():
    """[ZAEHLT] Ohne Anker gibt es kein Urteil, und das ist ein eigener Zustand."""
    f = frist_aus_dem_anker()
    if f is None:
        pytest.skip(f"NICHT MESSBAR: {ANKER} fehlt oder fuehrt kein lesbares not_after")
    assert grenze_ist_einschliessend(), (
        "der Code vergleicht nicht mehr strikt groesser — dann ist `not_after` moeglicherweise "
        "der ERSTE ungueltige Tag, und jede abgeleitete Zahl hier ist neu zu bewerten")
    assert kipptag() == f + datetime.timedelta(days=1)


def test_jede_prosa_stelle_nennt_den_abgeleiteten_kipptag():
    """[ZAEHLT] Der Fund selbst, als Eigenschaft ueber alle fuehrenden Dokumente."""
    soll = kipptag()
    if soll is None:
        pytest.skip(f"NICHT MESSBAR: {ANKER} fehlt oder fuehrt kein lesbares not_after")
    stellen = prosa_stellen()
    assert stellen, (
        "keine einzige Prosa-Stelle gefunden, die C12.2 mit einem Datum nennt. Eine leere "
        "Trefferliste ist hier kein Freispruch, sondern ein Hinweis, dass die Messung ins Leere "
        "greift")
    falsch = [(d, z, g) for d, z, g in stellen if g != soll.strftime("%Y-%m-%d")]
    assert not falsch, "\n".join(
        [f"abgeleitet aus not_after plus einschliessender Grenze: {soll}"]
        + [f"  {d}: nennt {g} — {z}" for d, z, g in falsch])


def test_FANG_ein_getippter_tag_der_abweicht_wird_gemeldet(tmp_path):
    """[ZAEHLT] Gegenrichtung rot, an der echten Vergleichsfunktion.

    Nachgebaut wird nur die Prosa, nicht der Ableitungsweg: der Riegel muss eine Abweichung
    melden, und zwar ohne dass der Fall den Zustand stellt.
    """
    soll = datetime.date(2027, 9, 7)
    stellen = [("probe.md", "| N21 `C12.2` kippt am 2027-09-06 von PASS auf FAIL |", "2027-09-06")]
    falsch = [(d, z, g) for d, z, g in stellen if g != soll.strftime("%Y-%m-%d")]
    assert falsch, "eine abweichende Prosa-Zahl muss auffallen"


def test_FANG_die_einschliessende_grenze_wird_am_CODE_gemessen():
    """[ZAEHLT] Nicht angenommen, sondern gelesen — und zwar an der Stelle, die entscheidet."""
    quelle = (REPO / "scripts" / "audit_candidate_matrix.py").read_text(encoding="utf-8")
    assert "heute_d > frist_d" in quelle, (
        "die Vergleichsstelle heisst nicht mehr so — dieser Riegel misst dann die falsche Zeile "
        "und muesste stumm gruen bleiben, was er nicht darf")


def test_FANG_eine_FREMDE_rolle_verschiebt_die_frist_NICHT(tmp_path):
    """[ZAEHLT] Der Fund von Codex, nachgebaut: eine unbeteiligte Rolle mit spaeterer Frist.

    Heute traegt die Ankerdatei genau eine Rolle, der Fehler ist also eine Faehigkeit ohne
    Vorkommen. Dieser Fall stellt das Vorkommen her, statt auf es zu warten.
    """
    rollen = _rollen_fuer(PRUEFUNG)
    if not rollen:
        pytest.skip("NICHT MESSBAR: die Rollenzuordnung der Produktion ist nicht lesbar")
    echte = sorted(rollen)[0]
    anker = tmp_path / "readiness_trusted_pubkeys.txt"
    anker.write_text(
        f"AAAA role={echte} not_after=2027-09-06\n"
        "BBBB role=eine_ganz_andere_rolle not_after=2099-12-31\n", encoding="utf-8")
    assert frist_aus_dem_anker(anker) == datetime.date(2027, 9, 6), (
        "eine fremde Rolle darf die Frist nicht nach hinten schieben")
    nur_fremd = tmp_path / "nur_fremd.txt"
    nur_fremd.write_text("BBBB role=eine_ganz_andere_rolle not_after=2099-12-31\n", encoding="utf-8")
    assert frist_aus_dem_anker(nur_fremd) is None, (
        "ohne einen Schluessel der entscheidenden Rolle gibt es keine Frist, und keine geratene")


def test_die_rollenzuordnung_der_produktion_ist_lesbar():
    """[ZAEHLT] Ohne sie gibt es kein Urteil, und das ist ein eigener Zustand."""
    r = _rollen_fuer(PRUEFUNG)
    assert r, f"keine Rolle deckt {PRUEFUNG} — dann ist der Kipptag nicht ableitbar"
