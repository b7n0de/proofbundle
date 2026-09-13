#!/usr/bin/env python3
"""Die Budget-Kostenachse, gemessen auf der REFERENZMASCHINE — der dritte Beleg des Buendels.

WARUM ES DIESES WERKZEUG GIBT (Owner-Karte `OA-dc37e26295`, 08.09.2026, „C, mit Bedingung"):

    „Die Budget-Achse wird auf der Referenzmaschine im Release-Buendel gemessen und im
     Freigabebericht als dort gemessen gefuehrt, in CI sichtbar uebersprungen mit dem gemessenen
     Maschinenfaktor als Grund, keine getippte Zahl."

Die zweite Haelfte — das sichtbare Ueberspringen auf einem Bauhost — steht in
``tests/test_budget_kostenkurve.py`` und wirkt dort. Die ERSTE Haelfte hatte bis hierher keine
Flaeche: die Zusicherung lief auf der Referenzmaschine, aber ihr Ergebnis verliess den Testlauf
nicht. Damit waere die Achse in CI stumm und im Buendel unbelegt gewesen — zusammen also
NIRGENDS, und das ist schlechter als der Zustand, den die Karte reparieren soll.

WAS ER AUFZEICHNET UND WAS NICHT. Er rechnet KEIN Urteil nach. Er ruft die echten Zusicherungen
auf und schreibt auf, was sie getan haben — bestanden, ueberspruengen (mit Grund) oder gerissen
(mit Meldung). Eine zweite Fassung derselben Logik waere eine zweite Wahrheit: sie koennte gruen
melden, waehrend die Zusicherung rot ist, und niemand saehe den Unterschied. Deshalb ist der
Testlauf hier die Quelle und dieses Werkzeug nur sein Schreiber.

EHRLICHE GRENZE, und sie steht im Artefakt selbst. ``bauhost_marke`` sagt, ob hier eine Bauhost-
Marke gesetzt war; ist sie es, sind alle Achsen uebersprungen und der Beleg taugt NICHT als
Referenzmaschinen-Messung. ``maschinenfaktor`` sagt, wie weit diese Maschine von der Aufzeichnung
entfernt war. Ein Leser kann an beiden Zahlen erkennen, ob er eine Referenzmessung vor sich hat —
er muss es nicht glauben.

Der rohe Ausgang geht danach durch ``scripts/sign_readiness_artifact.py`` (Kandidatenbindung +
Signatur beim Schluesselhalter), genau wie Soak und Differential.
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCHEMA = "proofbundle.budget_axis_measurement.v1"


def _testmodul():
    """Das Testmodul als Quelle — nicht seine Logik nachgebaut."""
    sys.path.insert(0, str(REPO / "tests"))
    sys.path.insert(0, str(REPO / "src"))
    import test_budget_kostenkurve as t  # noqa: PLC0415
    return t


def _ausgang(ruf) -> tuple[str, str]:
    """(urteil, meldung) — genau das, was die echte Zusicherung getan hat.

    VIER AUSGAENGE, NICHT DREI (Gegenlesung 08.09.2026): der erste Anlauf fing nur `Skipped` und
    `AssertionError`. `pytest.fail` wirft `Failed`, eine `OutcomeException` und KEINE
    `AssertionError`; ein `KeyError` aus einem umbenannten Messfeld ebenso wenig. Beides waere
    ungefangen durch `messe()` und `main()` gegangen, der Prozess waere gestorben — und die alte,
    GRUENE Belegdatei von einem frueheren Lauf waere unveraendert liegengeblieben. Ein Leser, der
    nur die Datei sieht und nicht den Exit-Code, haette einen aktuellen Referenzbeleg vor sich
    gehabt, den nie jemand gemessen hat.

    `ABGEBROCHEN` ist deshalb ein eigenes Urteil und faerbt `ok` rot — es ist keine Abstinenz und
    kein Fehlschlag der Achse, sondern ein Ausfall der MESSUNG, und der gehoert benannt.
    """
    from _pytest.outcomes import Failed, Skipped  # noqa: PLC0415
    try:
        ruf()
    except Skipped as s:
        return "UEBERSPRUNGEN", str(s)
    except (AssertionError, Failed) as a:
        return "GERISSEN", f"{type(a).__name__}: {a}"
    except Exception as e:                       # noqa: BLE001 - Absicht, siehe Docstring
        return "ABGEBROCHEN", f"{type(e).__name__}: {e}"
    return "BESTANDEN", ""


def zusicherungen_je_fall(klasse, stellen: int) -> list[str]:
    """Alle Zusicherungen einer Testklasse, die mit `stellen` Argumenten urteilen — ABGELEITET.

    WARUM ABGELEITET UND NICHT GENANNT. Bis zum 14.09.2026 fuhr `messe()` je Dimension GENAU EINE
    Zusicherung, `test_kosten_am_limit_unter_der_obergrenze`, und schrieb deren Ergebnis als Urteil
    der ACHSE. Die Klasse fuehrt aber fuenf, darunter "die Last erreicht das Limit wirklich" und die
    Speichergrenze. Ein Lastgenerator, der auf eine winzige Eingabe zurueckfaellt, laesst jene
    fallen — und die CPU-Zusicherung bleibt schnell und meldet BESTANDEN. Der Beleg haette
    `ok: true` fuer eine Budget-Suite ausgewiesen, die rot ist. Gefunden von der Codex-Runde eins an
    PR 199, an der Klasse gegengeprueft.
    """
    import inspect                                            # noqa: PLC0415
    raus = []
    for name in sorted(dir(klasse)):
        if not name.startswith("test_"):
            continue
        fn = getattr(klasse, name)
        if not callable(fn):
            continue
        if len(inspect.signature(fn).parameters) == stellen:
            raus.append(name)
    return raus


def _alle_ausgaenge(fall, namen: list[str], args: tuple) -> tuple[str, str, dict]:
    """Jede Zusicherung fahren und ZUSAMMENFASSEN. Bestanden heisst: alle bestanden.

    Die erste nicht bestandene bestimmt das Urteil und traegt ihren NAMEN in die Meldung — ohne den
    Namen sagt ein `GERISSEN` nicht, WAS gerissen ist.
    """
    einzeln: dict[str, str] = {}
    urteil, meldung = "BESTANDEN", ""
    for name in namen:
        u, m = _ausgang(lambda n=name: getattr(fall, n)(*args))
        einzeln[name] = u
        if u != "BESTANDEN" and urteil == "BESTANDEN":
            urteil, meldung = u, f"{name}: {m}"
    return urteil, meldung, einzeln


def messe() -> dict:
    t = _testmodul()
    marke = t._bauhost()
    achsen = []
    for dim in t.DIMENSIONEN:
        m = t._messung(dim)
        klammer = m["referenz_klammer"]
        faktor = (t._maschinenfaktor(klammer) if t.LATTE_AUS_DER_KLAMMER == "median"
                  else t._faktor_spanne(klammer)[0])
        _deckel = t._faktor_deckel(ausser=dim.name)
        fall = t.TestObergrenzeAmGroesstenZugelassenenWert()
        namen = zusicherungen_je_fall(t.TestObergrenzeAmGroesstenZugelassenenWert, 2)
        urteil, meldung, einzelurteile = _alle_ausgaenge(fall, namen, (dim,))
        achsen.append({
            "name": dim.name,
            "flaeche": dim.was,
            "limit": m["limit"],
            "eingabeachsen": dim.achsen,
            "kosten_am_limit_max_s": round(m["kosten_am_limit_max"], 6),
            "kosten_am_limit_min_s": round(m["kosten_am_limit"], 6),
            "latte_s": round(dim.achsen * t.GRENZE_S * faktor, 6),
            # NACH DER ACHSE BENANNT (Gegenlesung 08.09.2026): dieses Dokument fuehrt DREI Faktoren
            # — diesen hier aus der Klammer DIESER Achse, und zwei sitzungsweite weiter unten. Wer
            # sie gleich nennt, laedt den Leser ein, die falsche fuer die Latte zu halten; die
            # Latte daneben haengt an DIESER.
            "maschinenfaktor_dieser_achse": round(faktor, 4),
            # EIN Aufruf, nicht zwei (derselbe Fund): `_faktor_deckel` fuellt ein Modul-Global mit
            # Eigentuemer-Stempel. Zweimal zu rufen hiess, den Stempel zweimal zu setzen — und die
            # Aufrufzahl haette sich je nach `inf`/endlich unterschieden.
            "deckel": (None if _deckel == float("inf") else round(_deckel, 4)),
            "exponent_zeit": (None if m["exponent_zeit"] != m["exponent_zeit"]
                              else round(m["exponent_zeit"], 4)),
            "exponent_arbeit": (None if m["exponent_arbeit"] != m["exponent_arbeit"]
                                else round(m["exponent_arbeit"], 4)),
            "arbeit_empfindlich": m["arbeit_empfindlich"],
            "speicher_peak_bytes": m["speicher_peak_am_limit"],
            "urteil": urteil,
            "meldung": meldung,
            # JE ZUSICHERUNG, damit das Urteil nachrechenbar ist statt behauptet.
            "zusicherungen": einzelurteile,
        })
    kombis = []
    for name, n_achsen, bau in t.KOMBIS:
        m = t._kombi_messung(name, bau)
        fall = t.TestKombinierteAchsen()
        # DIESELBE LUECKE wie bei den Achsen, eine Zeile tiefer: die Schleife fuhr nur die
        # Summen-Zusicherung und liess "erreicht jede benannte Dimension" sowie die Speichergrenze
        # aus. Codex-Runde eins an PR 199 nennt beide ausdruecklich als Geschwister des Fundes.
        k_namen = zusicherungen_je_fall(t.TestKombinierteAchsen, 4)
        urteil, meldung, k_einzeln = _alle_ausgaenge(fall, k_namen, (name, n_achsen, bau))
        kombis.append({
            "name": name, "eingabeachsen": n_achsen,
            "dauer_max_s": round(m["dauer_max"], 6),
            "erreicht": m["erreicht"],
            "speicher_peak_bytes": m["speicher_peak"],
            "urteil": urteil, "meldung": meldung,
            "zusicherungen": k_einzeln,
        })
    hier = list(t._REFERENZ_HIER) or t._referenz_werte()
    return {
        "schema": SCHEMA,
        "owner_karten": ["OA-0646ecdf70", "OA-133b901337", "OA-dc37e26295"],
        "latte_aus_der_klammer": t.LATTE_AUS_DER_KLAMMER,
        "bauhost_marke": marke,
        "ist_referenzmessung": not marke,
        "grenze_s": t.GRENZE_S,
        "exponent_max": t.EXPONENT_MAX,
        "speicher_grenze_bytes": t.SPEICHER_GRENZE_BYTES,
        "referenzlast_hier_s": [round(w, 6) for w in hier],
        "referenzlast_aufzeichnung_s": list(t._REFERENZ_FARMER_S),
        "maschinenfaktor_median": round(t._maschinenfaktor(hier), 4),
        "maschinenfaktor_schnellstes_ende": round(
            max(1.0, min(hier) / statistics.median(t._REFERENZ_FARMER_S)), 4),
        "achsen": achsen,
        "kombinationen": kombis,
        "achsen_bestanden": sum(1 for a in achsen if a["urteil"] == "BESTANDEN"),
        "achsen_uebersprungen": sum(1 for a in achsen if a["urteil"] == "UEBERSPRUNGEN"),
        "achsen_gerissen": sum(1 for a in achsen if a["urteil"] == "GERISSEN"),
        # WELCHE Achsen erwartet wurden — sonst ist `ok` ueber einer leeren Liste WAHR.
        # Gefunden von einer Gegenlesung (08.09.2026): `all(... for a in [])` ist in Python
        # vakuos true. Ein kaputter Filter in `DIMENSIONEN` haette einen signierbaren, gruenen
        # Beleg ueber NULL gemessene Achsen erzeugt. Der Beleg nennt die Sollmenge deshalb selbst
        # und vergleicht sie — eine Zahl allein ("12") waere wieder eine getippte Erwartung.
        "achsen_erwartet": [d.name for d in t.DIMENSIONEN],
        "kombinationen_erwartet": [k[0] for k in t.KOMBIS],
        "ok": (not marke
               and bool(achsen) and bool(kombis)
               and [a["name"] for a in achsen] == [d.name for d in t.DIMENSIONEN]
               and [k["name"] for k in kombis] == [k[0] for k in t.KOMBIS]
               and all(a["urteil"] == "BESTANDEN" for a in achsen)
               and all(k["urteil"] == "BESTANDEN" for k in kombis)),
        "note": ("ok=true heisst: auf einer Maschine OHNE Bauhost-Marke hat JEDE erwartete Achse "
                 "und JEDE erwartete Kombination ihr Urteil GEFAELLT und bestanden. Eine "
                 "uebersprungene Achse macht ok=false — ein Beleg, der Abstinenzen als Erfolg "
                 "zaehlt, waere genau der stumme Riegel, gegen den diese Datei gebaut ist. Eine "
                 "LEERE Achsenliste ebenso: `all()` ueber nichts ist wahr, und ein gruener Beleg "
                 "ueber null Messungen ist die stillste Luege von allen."),
    }


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--out", type=Path, default=REPO / "audit_artifacts/360/budget_axis_latest.json")
    p.add_argument("--no-write", action="store_true")
    a = p.parse_args(argv)
    # DER ALTE BELEG STIRBT ZUERST (Gegenlesung 08.09.2026). Ohne diese Zeile ueberlebt eine
    # fruehere, GRUENE Datei jeden Absturz dieses Laufs — mit ihrem alten `produced_at_measured`
    # und `ok: true`. Wer nur die Datei liest und nicht den Exit-Code, saehe einen aktuellen
    # Referenzbeleg fuer eine Messung, die nie zu Ende lief. Lieber gar keine Datei als eine
    # veraltete, die aussieht wie eine frische.
    if not a.no_write and a.out.exists():
        a.out.unlink()
    d = messe()
    d["produced_at_measured"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    text = json.dumps(d, indent=2, ensure_ascii=False) + "\n"
    if not a.no_write:
        a.out.parent.mkdir(parents=True, exist_ok=True)
        a.out.write_text(text, encoding="utf-8")
    print(f"[budget-axis] {d['achsen_bestanden']} bestanden / {d['achsen_uebersprungen']} "
          f"uebersprungen / {d['achsen_gerissen']} gerissen · Faktor "
          f"{d['maschinenfaktor_schnellstes_ende']} · Referenzmessung="
          f"{d['ist_referenzmessung']} · ok={d['ok']}"
          + ("" if a.no_write else f" -> {a.out}"))
    return 0 if d["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
