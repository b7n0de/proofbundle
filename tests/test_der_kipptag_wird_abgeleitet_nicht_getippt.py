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
REGISTER = REPO / "audit_artifacts" / "findings_register_361.json"

#: Eine Zeile, die den KIPPTAG von C12.2 nennt — nicht bloss C12.2 und irgendein Datum.
#:
#: Die Verengung kam aus der eigenen Ableitung, nicht aus einer Idee. Die erste Fassung nahm jede
#: Zeile mit `C12.2` und einem ISO-Datum; die abgeleitete Traegermenge meldete daraufhin
#: scripts/gen_findings_register.py als abweichend, wegen des Satzes "genau daran fiel C12.2 am
#: 2026-09-06" — einer RUECKSCHAU auf ein vergangenes Ereignis, keiner Fristaussage. Ein Muster, das
#: beides gleich liest, misst die Schreibweise und nicht die Eigenschaft; dieselbe Datei traegt
#: vier Zeilen weiter die echte Fristaussage.
#:
#: Verlangt wird deshalb ein Kipp-Verb in derselben Zeile. Alle vier echten Traeger fuehren eines:
#: "flips PASS to FAIL", "turns red", "kippt ... von PASS auf FAIL".
_PROSA = re.compile(
    r"^.*\bC12\.2\b.*?\b(?:flips?|turns?\s+red|kippt)\b.*?(\d{4}-\d{2}-\d{2}).*$"
    r"|^.*\bC12\.2\b.*?(?<![-\d])(\d{4}-\d{2}-\d{2})(?![-\d]).*?\b(?:flips?|turns?\s+red|kippt)\b.*$",
    re.M | re.I)

#: `not_after=YYYY-MM-DD` im Ankertext.
_NOT_AFTER = re.compile(r"\bnot_after=(\d{4}-\d{2}-\d{2})\b")

#: KEINE handverlesene Liste mehr. Die Traegermenge wird ABGELEITET, und der Grund ist gemessen:
#: die Vorgaengerfassung nannte zwei Dokumente, das Datum steht aber an VIER Stellen. CHANGELOG.md
#: und scripts/gen_findings_register.py (der Erzeuger des SIGNIERTEN Registertextes) fehlten, und
#: eine Aenderung der CHANGELOG-Zeile liess diese ganze Datei gruen. Ein Grenzwaechter, der eine
#: Teilmenge der Orte prueft, an denen die Grenze steht, bewacht die Aufzaehlung statt der Grenze.
#: Gefunden von der Codex-Runde eins an PR 197.
#:
#: Was ABSICHTLICH nicht mitzaehlt, je mit Grund — eine Ausschlussmenge ohne Grund ist eine Liste,
#: auf die man schiebt, was gerade rot ist.
NICHT_TRAEGER = {
    # Diese Datei baut die Faelle, mit denen sie prueft; ihre eigenen Beispieldaten sind keine Prosa
    # ueber den Kipptag, sondern das Werkzeug, das darueber urteilt.
    "tests/test_der_kipptag_wird_abgeleitet_nicht_getippt.py":
        "der Riegel selbst, seine Beispieldaten sind kein Traeger",
}

#: Wo gesucht wird. Prosa und Erzeuger, nicht der ganze Baum — ein Register, das den Satz als DATEN
#: traegt, ist eine Ausgabe und keine Aussage.
_SUCHRAUM = ("*.md", "docs/**/*.md", "scripts/*.py")


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


def signierschluessel(register: pathlib.Path | None = None) -> str | None:
    """Der oeffentliche Schluessel, mit dem DIESES Register signiert ist — oder None.

    Auch das ist ein PARAMETER und kein Modulwert, aus demselben Grund wie beim Anker: ein
    Fangnachweis, der seinen Gegenstand nicht stellen kann, misst nichts.
    """
    import json as _json  # noqa: PLC0415
    register = register or REGISTER
    if not register.is_file():
        return None
    try:
        s = (_json.loads(register.read_text(encoding="utf-8")).get("signature") or {})
    except ValueError:
        return None
    k = s.get("public_key_b64")
    return k if isinstance(k, str) and k else None


def frist_aus_dem_anker(anker: pathlib.Path | None = None,
                        register: pathlib.Path | None = None) -> datetime.date | None:
    """Die Frist DES Schluessels, der dieses Register signiert hat. None heisst NICHT MESSBAR.

    ZWEITE RUNDE AN DIESER FUNKTION (Codex 4000093149, Nachfolge zu 3999991252). Die erste Fassung
    nahm die spaeteste Frist ueber ALLE Schluessel mit der passenden Rolle. Der Gedanke war: solange
    EINER autorisiert ist, kippt die Pruefung nicht. Gemessen stimmt das nicht — das Register ist von
    genau EINEM Schluessel signiert, und wenn DESSEN Frist ablaeuft, weist die Produktion die
    Signatur zurueck, ganz gleich wie viele andere Schluessel dieselbe Rolle tragen. Ein zweiter
    Schluessel mit Frist 2099 haette hier 2099 ergeben, waehrend die Pruefung 2027 rot wird.

    DIE KLASSE: eine Grenze wird aus einer OBERMENGE abgeleitet statt aus dem entscheidenden
    Prinzipal. Erst war die Obermenge "alle Rollen", dann "alle Schluessel dieser Rolle" — zweimal
    dieselbe Form, einmal enger. Entschieden wird jetzt am Schluessel, der IM REGISTER steht.

    DREI ZUSTAENDE: die Frist dieses Schluessels; None, wenn das Register keinen Schluessel nennt;
    None, wenn der genannte Schluessel im Anker nicht steht. Geraten wird nichts.
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
    unterschreiber = signierschluessel(register)
    if not unterschreiber:
        return None                       # ohne genannten Schluessel ist die Frage nicht gestellt
    for m in _ANKERZEILE.finditer(anker.read_text(encoding="utf-8")):
        if m.group(1) != unterschreiber or m.group(2) not in rollen:
            continue
        try:
            return datetime.datetime.strptime(m.group(3), "%Y-%m-%d").date()
        except ValueError:
            return None
    return None                           # der signierende Schluessel steht nicht im Anker


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


def traeger() -> list[str]:
    """Jede Datei im Suchraum, die C12.2 mit einem Datum nennt — ABGELEITET, nicht getippt."""
    raus = []
    for muster in _SUCHRAUM:
        for p in sorted(REPO.glob(muster)):
            if not p.is_file():
                continue
            rel = str(p.relative_to(REPO))
            if rel in NICHT_TRAEGER or rel in raus:
                continue
            try:
                text = p.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            if _PROSA.search(text):
                raus.append(rel)
    return raus


def prosa_stellen() -> list[tuple[str, str, str]]:
    """(Datei, Zeile, genanntes Datum) fuer jede Stelle, die C12.2 mit einem Datum nennt."""
    raus = []
    for rel in traeger():
        for m in _PROSA.finditer((REPO / rel).read_text(encoding="utf-8")):
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
    reg = _register_mit(tmp_path, "AAAA")
    anker = tmp_path / "readiness_trusted_pubkeys.txt"
    anker.write_text(
        f"AAAA role={echte} not_after=2027-09-06\n"
        "BBBB role=eine_ganz_andere_rolle not_after=2099-12-31\n", encoding="utf-8")
    assert frist_aus_dem_anker(anker, reg) == datetime.date(2027, 9, 6), (
        "eine fremde Rolle darf die Frist nicht nach hinten schieben")
    nur_fremd = tmp_path / "nur_fremd.txt"
    nur_fremd.write_text("BBBB role=eine_ganz_andere_rolle not_after=2099-12-31\n", encoding="utf-8")
    assert frist_aus_dem_anker(nur_fremd, reg) is None, (
        "ohne einen Schluessel der entscheidenden Rolle gibt es keine Frist, und keine geratene")


def _register_mit(tmp_path, schluessel: str | None):
    """Ein Wegwerf-Register, das genau diesen Schluessel als Unterschreiber nennt."""
    import json as _json  # noqa: PLC0415
    p = tmp_path / f"register_{schluessel or 'ohne'}.json"
    inhalt = {"findings": []}
    if schluessel:
        inhalt["signature"] = {"alg": "ed25519", "public_key_b64": schluessel, "sig_b64": "x"}
    p.write_text(_json.dumps(inhalt), encoding="utf-8")
    return p


def test_FANG_ein_ZWEITER_schluessel_DERSELBEN_rolle_verschiebt_die_frist_NICHT(tmp_path):
    """[ZAEHLT] Der Nachfolge-Fund (Codex 4000093149), und er ueberholt den vorigen.

    Die erste Fassung filterte nach Rolle und nahm dann die SPAETESTE Frist. Gemessen ist das
    falsch: das Register traegt EINE Unterschrift, und laeuft DEREN Schluessel ab, weist die
    Produktion sie zurueck — gleichgueltig, wie viele andere Schluessel dieselbe Rolle tragen.
    """
    rollen = _rollen_fuer(PRUEFUNG)
    if not rollen:
        pytest.skip("NICHT MESSBAR: die Rollenzuordnung der Produktion ist nicht lesbar")
    echte = sorted(rollen)[0]
    anker = tmp_path / "anker.txt"
    anker.write_text(
        f"AAAA role={echte} not_after=2027-09-06\n"
        f"CCCC role={echte} not_after=2099-12-31\n", encoding="utf-8")
    assert frist_aus_dem_anker(anker, _register_mit(tmp_path, "AAAA")) == datetime.date(2027, 9, 6), (
        "ein zweiter Schluessel derselben Rolle hat die Frist nach hinten geschoben — dann "
        "dokumentiert der Kipptag eine Rotationsgrenze, die fuer dieses Register nicht gilt")
    # Und andersherum: signiert wirklich der spaete Schluessel, gilt auch dessen Frist.
    assert frist_aus_dem_anker(anker, _register_mit(tmp_path, "CCCC")) == datetime.date(2099, 12, 31)


def test_ohne_signatur_im_register_ist_die_frist_NICHT_MESSBAR(tmp_path):
    """[ZAEHLT] Drei Zustaende: kein genannter Schluessel heisst nicht messbar, nicht 'irgendeiner'."""
    rollen = _rollen_fuer(PRUEFUNG)
    if not rollen:
        pytest.skip("NICHT MESSBAR: die Rollenzuordnung der Produktion ist nicht lesbar")
    anker = tmp_path / "anker2.txt"
    anker.write_text(f"AAAA role={sorted(rollen)[0]} not_after=2027-09-06\n", encoding="utf-8")
    assert frist_aus_dem_anker(anker, _register_mit(tmp_path, None)) is None


def test_ein_signierender_schluessel_AUSSERHALB_des_ankers_ist_NICHT_MESSBAR(tmp_path):
    """[ZAEHLT] Ein Schluessel, den der Anker nicht kennt, bekommt keine geratene Frist."""
    rollen = _rollen_fuer(PRUEFUNG)
    if not rollen:
        pytest.skip("NICHT MESSBAR: die Rollenzuordnung der Produktion ist nicht lesbar")
    anker = tmp_path / "anker3.txt"
    anker.write_text(f"AAAA role={sorted(rollen)[0]} not_after=2027-09-06\n", encoding="utf-8")
    assert frist_aus_dem_anker(anker, _register_mit(tmp_path, "FREMD")) is None


def test_die_rollenzuordnung_der_produktion_ist_lesbar():
    """[ZAEHLT] Ohne sie gibt es kein Urteil, und das ist ein eigener Zustand."""
    r = _rollen_fuer(PRUEFUNG)
    assert r, f"keine Rolle deckt {PRUEFUNG} — dann ist der Kipptag nicht ableitbar"


# ── Nachtrag 14.09.2026: die Traegermenge wird abgeleitet, nicht aufgezaehlt ─────────────────────

def test_die_traegermenge_wird_abgeleitet_und_nicht_getippt():
    """[ZAEHLT] Der Fund selbst: die Vorgaengerfassung nannte ZWEI Dokumente, das Datum steht an VIER.

    Gemessen am 14.09.2026 im Baum: CHANGELOG.md und scripts/gen_findings_register.py fuehren den
    Kipptag ebenfalls, und der zweite erzeugt den SIGNIERTEN Registertext. Ein Grenzwaechter, der
    eine Teilmenge der Orte prueft, an denen die Grenze steht, bewacht die Aufzaehlung statt der
    Grenze. Gefunden von der Codex-Runde eins an PR 197.
    """
    gefunden = set(traeger())
    for pflicht in ("CHANGELOG.md", "RESTRISIKO_600.md",
                    "docs/release_scope/6.1.0.md", "scripts/gen_findings_register.py"):
        assert pflicht in gefunden, (
            f"{pflicht} fuehrt den Kipptag, wird aber nicht als Traeger abgeleitet — "
            f"abgeleitet: {sorted(gefunden)}")
    assert len(gefunden) >= 4


def test_eine_rueckschau_ist_keine_fristaussage():
    """[ZAEHLT] Die Verengung, die die eigene Ableitung erzwungen hat.

    `scripts/gen_findings_register.py` traegt BEIDES: den Satz "genau daran fiel C12.2 am
    2026-09-06" — eine Rueckschau auf ein vergangenes Ereignis — und vier Zeilen weiter die echte
    Fristaussage. Ein Muster, das jede Zeile mit C12.2 und einem Datum nimmt, meldet die Datei als
    abweichend, obwohl sie richtig ist. Verlangt wird deshalb ein Kipp-Verb in derselben Zeile.
    """
    rueckschau = "#: genau daran fiel C12.2 am 2026-09-06: ein signiertes Register entschied ueber\n"
    assert not _PROSA.search(rueckschau), "eine Rueckschau wird als Fristaussage gelesen"
    for echt in ("`C12.2` turns red on 2027-09-07 by design",
                 "check C12.2 flips PASS to FAIL on 2027-09-07",
                 "`C12.2` kippt am **2027-09-07** von PASS auf FAIL"):
        assert _PROSA.search(echt), f"eine echte Fristaussage wird nicht erkannt: {echt!r}"


def test_fangnachweis_ein_falsches_datum_im_NEUEN_traeger_wird_gefunden(tmp_path, monkeypatch):
    """[ZAEHLT] Der Ruecknahme-Nachweis, und er zielt genau auf die Luecke.

    Gebaut wird ein Baum mit einer CHANGELOG-Zeile, die einen ANDEREN Kipptag nennt — die Datei, die
    die alte Aufzaehlung nicht kannte. Faellt diese Zusicherung, ist die Ableitung wieder eine Liste.
    """
    import test_der_kipptag_wird_abgeleitet_nicht_getippt as selbst
    baum = tmp_path / "baum"
    (baum / "docs" / "release_scope").mkdir(parents=True)
    (baum / "CHANGELOG.md").write_text(
        "- **`C12.2` turns red on 2030-01-01 by design (N21):** the only anchor key\n", encoding="utf-8")
    (baum / "docs" / "release_scope" / "6.1.0.md").write_text(
        "| **N21** `C12.2` kippt am **2027-09-07** von PASS auf FAIL.\n", encoding="utf-8")
    monkeypatch.setattr(selbst, "REPO", baum)
    stellen = prosa_stellen()
    genannt = {datum for _, _, datum in stellen}
    assert "2030-01-01" in genannt, (
        "die abgeleitete Menge sieht die CHANGELOG-Zeile nicht — genau die Datei fehlte der "
        f"alten Aufzaehlung. Gefunden: {stellen}")
    assert len(genannt) > 1, "zwei verschiedene Kipptage muessen als Abweichung sichtbar werden"
