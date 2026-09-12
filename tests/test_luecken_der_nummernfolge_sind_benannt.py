"""Eine Luecke in der Nummernfolge muss benannt sein — sonst ist sie stumm.

DER BEFUND, gemessen am 2026-09-12. `RESTRISIKO_600_OBJEKTKLASSEN.json` ist seit ihrem
ersten Tag "die Quelle der Grundgesamtheit"; jede Zahl soll aus ihr kommen. Sie fuehrt
S85 und S102, aber kein S86 bis S101 — und sagte darueber NICHTS. Wer S86 sucht und
nichts findet, kann nicht unterscheiden zwischen "gibt es nicht" und "wurde nicht
gemessen". Dieselbe Stille lag ueber Z1.

Aufgefallen ist es an der Fremdzaehlung (Beilage 20260912T1316Z, 140 Kennungen), die
beide Luecken ausdruecklich benennt. Die eigene Datei tat es nicht — die Auflage aus
Auftrag 20260912T1317Z ("die Luecke traegt GENAU EINE Zeile, NOT MEASURED mit Grund,
nicht sechzehn leere") war unerfuellt.

WARUM DIESER RIEGEL ALLGEMEINER IST ALS DIE AUFLAGE. Die Auflage nennt S86 bis S101.
Ein Riegel, der genau diese Zeichenkette prueft, faengt die naechste Luecke nicht —
und es wird eine geben, sobald ein zweiter Baum weitere Nummern vergibt. Geprueft wird
deshalb die EIGENSCHAFT: jede Unterbrechung der Nummernfolge je Praefix ist entweder
in `luecken_in_der_nummernfolge` benannt oder ein Fehler. Die Klasse dahinter steht im
Haus-Ledger als EINE-NUMMER-DIE-ICH-VERGEBE-KANN-IN-EINEM-ANDEREN-BAUM-SCHON-WEG-SEIN.

Die Marken sind die drei des Hauses: NOT MEASURED, NOT MEASURABLE, NOT APPLICABLE —
je mit Grund daneben, nie allein.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

WURZEL = Path(__file__).resolve().parents[1]
DATEI = WURZEL / "RESTRISIKO_600_OBJEKTKLASSEN.json"
MARKEN = {"NOT MEASURED", "NOT MEASURABLE", "NOT APPLICABLE"}


def _daten() -> dict:
    return json.loads(DATEI.read_text(encoding="utf-8"))


def _nummern_je_praefix(d: dict) -> dict[str, list[int]]:
    aus: dict[str, list[int]] = {}
    for e in d["eintraege"]:
        m = re.fullmatch(r"([A-Z]+)(\d+)", str(e["kennung"]))
        if m:
            aus.setdefault(m.group(1), []).append(int(m.group(2)))
    return {k: sorted(v) for k, v in aus.items()}


def _luecken(nummern: list[int]) -> list[tuple[int, int]]:
    """Zusammenhaengende Unterbrechungen zwischen der kleinsten und groessten Nummer.

    Die Zaehlung beginnt bewusst bei 1, nicht bei der kleinsten vorhandenen Nummer:
    ein fehlendes Z1 ist genauso eine Luecke wie ein fehlendes S90, und nur so faellt
    ein Praefix auf, das erst bei 2 beginnt.
    """
    if not nummern:
        return []
    da = set(nummern)
    fehlend = [n for n in range(1, max(nummern) + 1) if n not in da]
    luecken, start = [], None
    for n in fehlend:
        if start is None:
            start = vorher = n
        elif n == vorher + 1:
            vorher = n
        else:
            luecken.append((start, vorher)); start = vorher = n
    if start is not None:
        luecken.append((start, vorher))
    return luecken


def _benannte_spannen(d: dict) -> list[tuple[str, int, int, dict]]:
    """Was die Datei als Luecke deklariert, als (praefix, von, bis, eintrag)."""
    aus = []
    for name, e in (d.get("luecken_in_der_nummernfolge") or {}).items():
        if name.startswith("_") or not isinstance(e, dict):
            continue
        m = re.fullmatch(r"([A-Z]+)(\d+)(?:_bis_[A-Z]+(\d+))?", name)
        if not m:
            continue
        p, von = m.group(1), int(m.group(2))
        bis = int(m.group(3)) if m.group(3) else von
        aus.append((p, von, bis, e))
    return aus


def test_jede_luecke_der_nummernfolge_ist_benannt():
    d = _daten()
    benannt = {(p, v, b) for p, v, b, _ in _benannte_spannen(d)}
    offen = []
    for praefix, nummern in _nummern_je_praefix(d).items():
        for von, bis in _luecken(nummern):
            if (praefix, von, bis) not in benannt:
                offen.append(f"{praefix}{von}..{praefix}{bis}")
    assert not offen, (
        "stille Luecke in der Nummernfolge, in `luecken_in_der_nummernfolge` nicht benannt: "
        + ", ".join(offen)
        + " — eine Quelle der Grundgesamtheit, die ihre Luecken verschweigt, laesst den Leser "
          "nicht unterscheiden zwischen 'gibt es nicht' und 'wurde nicht gemessen'.")


def test_jede_benannte_luecke_traegt_marke_und_grund():
    d = _daten()
    spannen = _benannte_spannen(d)
    assert spannen, "keine einzige Luecke benannt — bei S85/S102 im Bestand ist das nicht plausibel"
    for p, von, bis, e in spannen:
        name = f"{p}{von}..{p}{bis}"
        assert e.get("marke") in MARKEN, f"{name}: Marke {e.get('marke')!r} ist keine der drei"
        grund = str(e.get("grund") or "")
        assert len(grund) >= 40, f"{name}: Grund fehlt oder ist zu duenn ({len(grund)} Zeichen)"
        assert e.get("anzahl") == bis - von + 1, (
            f"{name}: `anzahl` {e.get('anzahl')} passt nicht zur Spanne {bis - von + 1}")


def test_keine_benannte_luecke_ist_in_wahrheit_belegt():
    """Die Gegenrichtung: was als Luecke gilt, darf nicht als Eintrag existieren."""
    d = _daten()
    vorhanden = {str(e["kennung"]) for e in d["eintraege"]}
    for p, von, bis, _ in _benannte_spannen(d):
        belegt = [f"{p}{n}" for n in range(von, bis + 1) if f"{p}{n}" in vorhanden]
        assert not belegt, (f"als Luecke deklariert, aber im Bestand vorhanden: {belegt} — "
                            f"die Deklaration ist dann falsch, nicht der Bestand")


def test_die_gegenrechnung_gegen_die_fremdzaehlung_ist_in_sich_stimmig():
    d = _daten()
    g = d.get("gegenrechnung_gegen_die_sollliste")
    assert g, ("die Gegenrechnung gegen die Fremdzaehlung fehlt — Auflage aus Auftrag "
               "20260912T1317Z, drei Zahlen: gleich, fehlt, zu viel")
    assert re.fullmatch(r"[0-9a-f]{64}", str(g.get("sha256_der_sollliste") or "")), \
        "die Gegenrechnung nennt keinen sha256 der Fremdzaehlung — ohne ihn ist sie nicht nachrechenbar"
    gleich, fehlt, zu_viel = g.get("gleich"), g.get("fehlt"), g.get("zu_viel")
    assert gleich + zu_viel == len(d["eintraege"]), (
        f"gleich {gleich} + zu viel {zu_viel} != {len(d['eintraege'])} Eintraege")
    welche = g.get("zu_viel_welche") or []
    assert len(welche) == zu_viel, f"zu_viel={zu_viel}, aber {len(welche)} benannt"
    vorhanden = {str(e["kennung"]) for e in d["eintraege"]}
    assert set(welche) <= vorhanden, f"als ueberzaehlig benannt, aber nicht im Bestand: {set(welche)-vorhanden}"
    if fehlt:
        assert g.get("fehlt_welche"), "fehlende Kennungen sind nicht benannt"


def test_META_eine_eingepflanzte_luecke_wird_GEFANGEN():
    """Beweise, dass der Riegel eine NEUE stille Luecke faengt — sonst ist er Zierde.

    Geprueft wird die LOGIK mit gestellten Daten, nicht ueber einen Dateitausch: ein
    monkeypatch auf das Modulattribut haengt am Importnamen und war beim ersten Anlauf
    genau deshalb still. Die Logik ist der Gegenstand, nicht der Dateipfad.
    """
    d = _daten()
    hoechste = max(int(re.fullmatch(r"S(\d+)", e["kennung"]).group(1))
                   for e in d["eintraege"] if re.fullmatch(r"S\d+", str(e["kennung"])))
    gepflanzt = dict(d)
    gepflanzt["eintraege"] = list(d["eintraege"]) + [
        {"kennung": f"S{hoechste + 2}", "klasse": "fund_riegel", "praefix": "S",
         "zaehlt_als_fund": True, "warum_diese_klasse": "gepflanzt",
         "titel_im_register": "gepflanzt"}]

    benannt = {(p, v, b) for p, v, b, _ in _benannte_spannen(gepflanzt)}
    offen = [f"{p}{v}..{p}{b}"
             for p, nummern in _nummern_je_praefix(gepflanzt).items()
             for v, b in _luecken(nummern) if (p, v, b) not in benannt]
    assert offen == [f"S{hoechste + 1}..S{hoechste + 1}"], (
        f"die eingepflanzte Luecke S{hoechste + 1} wurde NICHT gefangen, gefunden: {offen}")


def test_META_gegenrichtung_eine_benannte_luecke_wird_nicht_gemeldet():
    """Die Gegenrichtung: was benannt ist, darf nicht als offen gelten — sonst meldet
    der Riegel jede Luecke fuer immer und wird abgeschaltet."""
    d = _daten()
    benannt = {(p, v, b) for p, v, b, _ in _benannte_spannen(d)}
    offen = [f"{p}{v}..{p}{b}"
             for p, nummern in _nummern_je_praefix(d).items()
             for v, b in _luecken(nummern) if (p, v, b) not in benannt]
    assert not offen, f"benannte Luecken werden trotzdem gemeldet: {offen}"
