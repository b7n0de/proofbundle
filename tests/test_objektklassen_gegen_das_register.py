"""Die Objektklassen-Datei wird mit dem Register VERGLICHEN, und ihr Kopf mit ihrer eigenen Liste.

DIE KLASSE, gegen die dieser Riegel steht, ist die, gegen die die Datei selbst gebaut wurde — und
sie hat die Datei eingeholt. `RESTRISIKO_600_OBJEKTKLASSEN.json` existiert, weil drei Zahlen im
Umlauf waren (139, 140, 143) und keine falsch gezaehlt war; ihr eigener Kopf sagt woertlich „ab dem
Tag, an dem diese Datei existiert, ist SIE die Quelle der Grundgesamtheit". Gemessen am 12.09.2026
lieferte dieselbe Datei wieder drei Zahlen:

    ihr Kopf (`grundgesamtheit.kennungen_gesamt`)                        142
    ihre eigene Liste (`len(eintraege)`)                                 141
    ihre eigene Extraktionsregel, auf das Register angewandt             145

Der Unterschied zwischen Kopf und Liste war EIN fehlender Eintrag (`G2` — die Zeile wurde an das
Register angehaengt und der Kopf hochgezaehlt, der Listeneintrag nie geschrieben). Der Unterschied
zwischen Regel und Liste sind vier Kennungen: `G2` plus `S7b`, `S7c`, `S7d`, die im Register eigene
Ueberschriften tragen und in keiner der beiden Zaehlungen als eigene Kennung gefuehrt werden.

WARUM DAS NICHT VON SELBST AUFFIEL: eine Datei, die ihre Grundgesamtheit im Kopf TRAEGT und in der
Liste FUEHRT, hat zwei Wahrheiten und keinen Vergleich. Wer den Kopf liest, bekommt 142; wer die
Liste zaehlt, 141. Beide Zahlen sind „aus der Datei", und genau deshalb faellt die Differenz
niemandem auf, der nur eine von beiden ansieht.

DIE DREI FRAGEN, die dieser Riegel trennt, weil sie verschieden sind:

  1. Stimmt der Kopf mit der Liste?          — die Datei gegen sich selbst
  2. Kennt die Liste jede Kennung des Registers? — die Datei gegen ihren Gegenstand
  3. Deckt jede Ausnahme noch etwas?         — die Ausnahmemenge gegen die Wirklichkeit

Frage 2 ist die, die still altert: das Register waechst, die Liste nicht, und keine Zahl im Kopf
merkt es. Frage 3 ist die Gegenrichtung dazu — ohne sie waechst die Ausnahmeliste monoton und
traegt irgendwann eine Erlaubnis fuer nichts (dieselbe Bauart wie `UNBESTIMMBAR_MIT_GRUND` und
`_REPO_CONTEXT_TESTS` in diesem Baum).

RICHTUNG DES URTEILS, bewusst asymmetrisch — wie im Nachbarn
`tests/test_register_population_gegen_restrisiko.py`: eine Kennung im Register, die in der Liste
FEHLT, ist ein Fehler (die Datei behauptet dann eine Vollstaendigkeit, die sie nicht hat). Ein
Eintrag in der Liste ohne Fundstelle im Register wird GEMELDET und faellt nicht — er kann aus einer
Quelle stammen, die dieser Test nicht kennt.

KEINE ZWEITE GETIPPTE AUFZAEHLUNG: die Praefixe kommen aus `klassen` der Datei selbst, nicht aus
einer Liste in diesem Test. Eine neue Objektklasse wirkt damit sofort, ohne dass jemand hier etwas
nachtraegt — der Fehler, den dieses Repo als
`aufzaehlung_statt_existenzfrage_bindet_nur_die_listeneintraege` fuehrt.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
OBJEKTKLASSEN = REPO / "RESTRISIKO_600_OBJEKTKLASSEN.json"
REGISTER = REPO / "RESTRISIKO_600.md"


def _daten() -> dict:
    if not OBJEKTKLASSEN.is_file():
        pytest.skip("RESTRISIKO_600_OBJEKTKLASSEN.json liegt hier nicht (sdist ohne Repo-Kontext)")
    return json.loads(OBJEKTKLASSEN.read_text(encoding="utf-8"))


def _register_text() -> str:
    if not REGISTER.is_file():
        pytest.skip("RESTRISIKO_600.md liegt hier nicht (sdist ohne Repo-Kontext)")
    return REGISTER.read_text(encoding="utf-8")


def kennungen_aus_dem_register(text: str, praefixe) -> set[str]:
    """Die Extraktionsregel der Datei, ausgefuehrt statt zitiert.

    Woertlich aus ihrem Feld `regel_der_extraktion`: „Kennung am Anfang einer Ueberschrift ODER in
    der ersten Tabellenspalte." Beide Formen sind an den ZEILENANFANG gebunden — im Fliesstext
    kommt `S25` als Verweis vielfach vor, und ein Verweis ist keine Deklaration.
    """
    p = "|".join(sorted(praefixe))
    ueberschrift = re.compile(rf"^#{{1,6}}\s+({p})(\d+[a-z]?)\b", re.M)
    tabellenzelle = re.compile(rf"^\|\s*({p})(\d+[a-z]?)\s*\|", re.M)
    return {a + b for a, b in ueberschrift.findall(text)} | {
        a + b for a, b in tabellenzelle.findall(text)}


def _liste(d: dict) -> set[str]:
    return {str(e["kennung"]) for e in d["eintraege"]}


def _ausnahmen(d: dict) -> dict:
    """Kennungen, die die Regel findet und die BEWUSST keine eigene Kennung sind, je mit Grund.

    Fehlt das Feld, ist die Menge leer — eine fehlende Ausnahmeliste ist keine Erlaubnis.
    """
    roh = d.get("nicht_eigene_kennungen") or {}
    return {str(k): str(v) for k, v in roh.items()}


# ── Frage 1: die Datei gegen sich selbst ──────────────────────────────────────────────────────

def test_der_kopf_zaehlt_dieselbe_menge_wie_die_liste():
    d = _daten()
    kopf = int(d["grundgesamtheit"]["kennungen_gesamt"])
    liste = len(d["eintraege"])
    assert kopf == liste, (
        f"`grundgesamtheit.kennungen_gesamt` sagt {kopf}, `eintraege` traegt {liste}. Eine Datei, "
        f"die ihre Grundgesamtheit im Kopf BEHAUPTET und in der Liste FUEHRT, hat zwei Wahrheiten. "
        f"Die Zahl im Kopf wird gerechnet, nicht gepflegt — oder sie ist die naechste Zahl im "
        f"Umlauf, gegen die diese Datei gebaut wurde.")


def test_je_praefix_zaehlt_der_kopf_dieselbe_menge_wie_die_liste():
    d = _daten()
    kopf = {str(k): int(v) for k, v in d["grundgesamtheit"]["je_praefix"].items()}
    ist: dict[str, int] = {}
    for e in d["eintraege"]:
        ist[str(e["praefix"])] = ist.get(str(e["praefix"]), 0) + 1
    abweichend = {p: (kopf.get(p), ist.get(p, 0)) for p in set(kopf) | set(ist)
                  if kopf.get(p) != ist.get(p, 0)}
    assert not abweichend, (
        f"je_praefix im Kopf gegen die Liste, (Kopf, Liste): {abweichend}. Eine Gesamtzahl kann "
        f"stimmen, waehrend zwei Praefixe sich gegenseitig ausgleichen — deshalb wird hier je "
        f"Praefix verglichen und nicht nur die Summe.")


def test_die_fundzahl_des_kopfes_stimmt_mit_der_liste():
    d = _daten()
    funde = sum(1 for e in d["eintraege"] if e.get("zaehlt_als_fund") is True)
    keine = sum(1 for e in d["eintraege"] if e.get("zaehlt_als_fund") is False)
    assert (int(d["grundgesamtheit"]["funde"]), int(d["grundgesamtheit"]["keine_funde"])) \
        == (funde, keine), (
        f"Kopf sagt funde={d['grundgesamtheit']['funde']} / "
        f"keine_funde={d['grundgesamtheit']['keine_funde']}, die Liste ergibt {funde} / {keine}. "
        f"Die Fundzahl ist die Zahl, die nach aussen geht — sie gehoert gerechnet.")


def test_jeder_eintrag_traegt_eine_deklarierte_klasse():
    d = _daten()
    namen = {str(v["name"]) for v in d["klassen"].values()}
    fremd = sorted({str(e["klasse"]) for e in d["eintraege"]} - namen)
    assert not fremd, f"Eintraege mit einer Klasse, die `klassen` nicht deklariert: {fremd}"


def _erlaubte_ausnahmen(d) -> dict:
    """Kennung -> abweichender `zaehlt_als_fund`, aus dem DEKLARIERTEN Ausnahmeblock.

    Eintraege ohne Beleg und ohne Grund zaehlen NICHT als erlaubt: eine Ausnahme, die sich selbst
    genehmigt, ist keine.
    """
    raus = {}
    for name, a in (d.get("ausnahmen_von_der_klasse") or {}).items():
        if name.startswith("_") or not isinstance(a, dict):
            continue
        if not a.get("warum") or not a.get("beleg"):
            continue
        for k in a.get("kennungen") or []:
            if (a.get("beleg") or {}).get(k):
                raus[str(k)] = bool(a.get("zaehlt_als_fund"))
    return raus


def test_zaehlt_als_fund_stimmt_mit_der_klassendeklaration():
    """Ein Eintrag darf seine eigene Klasse nicht STILL ueberstimmen.

    ERWEITERT AM 13.09.2026, und die Eigenschaft wird dabei staerker, nicht schwaecher. Die erste
    Fassung liess GAR KEINE Abweichung zu, und dadurch konnte das Modell einen gemessenen
    NICHT-Fund nicht ausdruecken: S3 traegt in seiner eigenen Quellueberschrift "NO FINDING,
    measured in both directions" und wurde trotzdem als Fund gezaehlt, weil sein Praefix es so
    vorsah (Codex r3999944594). Der Vertrag war erfuellt und die Aussage falsch.
    Eine Abweichung ist jetzt zulaessig, wenn sie im Block `ausnahmen_von_der_klasse` steht, MIT
    Grund und MIT Belegstelle. Was dort nicht steht, faellt weiter um.
    """
    d = _daten()
    nach_name = {str(v["name"]): bool(v["zaehlt_als_fund"]) for v in d["klassen"].values()}
    ausnahmen = _erlaubte_ausnahmen(d)
    abweichend = []
    for e in d["eintraege"]:
        ist, soll = bool(e.get("zaehlt_als_fund")), nach_name.get(str(e["klasse"]))
        if ist == soll:
            continue
        if ausnahmen.get(str(e["kennung"])) == ist:
            continue                      # deklariert, mit Grund und Beleg
        abweichend.append(e["kennung"])
    assert not abweichend, (
        f"Diese Eintraege widersprechen der `zaehlt_als_fund`-Deklaration ihrer eigenen Klasse, "
        f"ohne im Block `ausnahmen_von_der_klasse` mit Grund und Beleg zu stehen: {abweichend}")


def test_eine_ausnahme_OHNE_grund_oder_beleg_zaehlt_NICHT_als_deklariert():
    """MUSS-FEHLSCHLAG: sonst genehmigt sich eine Ausnahme selbst, indem sie bloss existiert."""
    for fehlt in ("warum", "beleg"):
        block = {"probe": {"zaehlt_als_fund": False, "kennungen": ["X1"],
                           "warum": "ein Grund", "beleg": {"X1": "eine Stelle"}}}
        del block["probe"][fehlt]
        assert _erlaubte_ausnahmen({"ausnahmen_von_der_klasse": block}) == {}, (
            f"eine Ausnahme ohne {fehlt} darf nicht als deklariert gelten")
    ohne_beleg_fuer_die_kennung = {"probe": {"zaehlt_als_fund": False, "kennungen": ["X1", "X2"],
                                             "warum": "ein Grund", "beleg": {"X1": "eine Stelle"}}}
    assert _erlaubte_ausnahmen({"ausnahmen_von_der_klasse": ohne_beleg_fuer_die_kennung}) == {"X1": False}, (
        "eine Kennung ohne eigene Belegstelle darf nicht mitlaufen")


# ── Frage 2: die Datei gegen ihren Gegenstand ─────────────────────────────────────────────────

def test_keine_kennung_des_registers_fehlt_in_der_liste():
    d, text = _daten(), _register_text()
    gefunden = kennungen_aus_dem_register(text, d["klassen"].keys())
    assert gefunden, "die Extraktionsregel findet im Register NICHTS — dann misst dieser Test nichts"
    fehlend = sorted(gefunden - _liste(d) - set(_ausnahmen(d)))
    assert not fehlend, (
        f"{len(fehlend)} Kennung(en) stehen im Register, aber weder in `eintraege` noch in "
        f"`nicht_eigene_kennungen`: {fehlend}. Entweder gehoeren sie in die Liste, oder sie sind "
        f"bewusst keine eigene Kennung — dann gehoeren sie mit GRUND in die Ausnahmemenge und "
        f"nicht ins Schweigen.")


def test_jede_ausnahme_deckt_eine_kennung_die_die_regel_findet():
    """Die Gegenrichtung zur Ausnahmemenge: ohne sie waechst sie monoton und deckt irgendwann nichts."""
    d, text = _daten(), _register_text()
    gefunden = kennungen_aus_dem_register(text, d["klassen"].keys())
    tot = sorted(k for k in _ausnahmen(d) if k not in gefunden)
    assert not tot, (
        f"Diese Ausnahmen decken keine Kennung mehr, die die Regel im Register findet: {tot}. Eine "
        f"Erlaubnis fuer nichts ist der Anfang einer Liste, der niemand mehr traut.")


def test_jede_ausnahme_traegt_einen_GRUND():
    d = _daten()
    ohne = sorted(k for k, v in _ausnahmen(d).items() if not v.strip())
    assert not ohne, f"Ausnahme ohne Grund: {ohne}. Ohne Grund ist es eine Auslassung mit Schluessel."


def test_die_gegenrichtung_wird_gemeldet_nicht_bestraft(capsys):
    """Ein Listeneintrag ohne Fundstelle im Register kann legitim sein — er wird genannt, nicht bestraft."""
    d, text = _daten(), _register_text()
    nur_liste = sorted(_liste(d) - kennungen_aus_dem_register(text, d["klassen"].keys()))
    if nur_liste:
        print(f"HINWEIS, kein Fehler: {len(nur_liste)} Eintrag/Eintraege stehen nur in der Liste: "
              f"{nur_liste}")
    assert True


# ── Der Fangnachweis: faengt der Riegel eine eingepflanzte Instanz seiner Klasse? ──────────────

def _pruefe_paar(daten: dict, text: str) -> list[str]:
    """Dieselbe Pruefung wie oben, aber ueber uebergebene Daten — damit der Meta-Test einen
    KUENSTLICHEN Stand pruefen kann, ohne den echten Baum anzufassen."""
    gefunden = kennungen_aus_dem_register(text, daten["klassen"].keys())
    return sorted(gefunden - {str(e["kennung"]) for e in daten["eintraege"]}
                  - set((daten.get("nicht_eigene_kennungen") or {})))


def test_META_eine_eingepflanzte_kennung_wird_GEFANGEN():
    """Eine neue Ueberschrift im Register ohne Listeneintrag MUSS auffallen."""
    d, text = _daten(), _register_text()
    praefix = sorted(d["klassen"])[0]
    gepflanzt = f"{praefix}9997"
    # Vorbedingung: die Kennung darf vorher nicht schon im Befund stehen — sonst misst der
    # Meta-Test die Einpflanzung gar nicht, sondern einen Altbestand.
    assert gepflanzt not in _pruefe_paar(d, text), \
        f"Vorbedingung verletzt: {gepflanzt} steht schon ohne Einpflanzung im Befund"
    befund = _pruefe_paar(d, text + f"\n\n### {gepflanzt} · eine eingepflanzte Zeile\n")
    assert gepflanzt in befund, (
        f"Der Riegel hat eine eingepflanzte Kennung NICHT gefangen. Gefunden: {befund}")


def test_META_gegenrichtung_eine_eingepflanzte_kennung_MIT_eintrag_wird_nicht_gefangen():
    """Wird sie ordentlich eingetragen, darf der Riegel schweigen — sonst faengt er alles."""
    d, text = _daten(), _register_text()
    praefix = sorted(d["klassen"])[0]
    gepflanzt = f"{praefix}9998"
    kopie = json.loads(json.dumps(d))
    muster = dict(kopie["eintraege"][0])
    muster["kennung"] = gepflanzt
    kopie["eintraege"].append(muster)
    befund = _pruefe_paar(kopie, text + f"\n\n### {gepflanzt} · eine eingepflanzte Zeile\n")
    assert gepflanzt not in befund, (
        f"Der Riegel meldet eine Kennung, die ordentlich in der Liste steht: {befund}")


def test_META_eine_eingepflanzte_kennung_MIT_ausnahme_wird_nicht_gefangen():
    """Die zweite zulaessige Antwort: bewusst keine eigene Kennung, mit Grund."""
    d, text = _daten(), _register_text()
    praefix = sorted(d["klassen"])[0]
    gepflanzt = f"{praefix}9999"
    kopie = json.loads(json.dumps(d))
    kopie["nicht_eigene_kennungen"] = dict(kopie.get("nicht_eigene_kennungen") or {})
    kopie["nicht_eigene_kennungen"][gepflanzt] = "Probe des Meta-Tests"
    befund = _pruefe_paar(kopie, text + f"\n\n### {gepflanzt} · eine eingepflanzte Zeile\n")
    assert gepflanzt not in befund, (
        f"Der Riegel meldet eine Kennung, die mit Grund als Ausnahme deklariert ist: {befund}")
