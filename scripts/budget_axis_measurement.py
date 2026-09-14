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


def _gesamtausgang(rufe: list[tuple[str, object]]) -> tuple[str, str]:
    """ALLE Zusicherungen einer Flaeche fahren und zu EINEM Urteil verdichten.

    Codex r4001145754 (P1), am Kopf c53ee88370ee03b08238925d9fb73e2ff31d8bdc nachgestellt. Je
    Achse lief GENAU EINE der sechs Zusicherungen, die das Quellmodul fuer eine Achse fuehrt, und
    ihr Ausgang wurde als `urteil` der ganzen Achse ausgegeben. Reisst der Lastbau, bleibt der
    CPU-Test schnell und meldet BESTANDEN — ein gruenes Urteil ueber eine Flaeche, auf der nicht
    gemessen wurde.

    DIE KOMBIS HATTEN DENSELBEN DEFEKT und standen in keinem Kommentar. Dort lief eine von drei.
    Deshalb ein gemeinsamer Ausgang statt zweier Reparaturen. Ein Fix an einer von zwei Stellen
    laesst die zweite still zurueckkehren.

    FAIL-CLOSED und ohne Abkuerzung: es wird NICHT beim ersten Riss abgebrochen, sonst haetten die
    uebrigen Zusicherungen wieder nicht gemessen und der Bericht naehme die Antwort vorweg. Das
    schwerste Urteil gewinnt, ABGEBROCHEN vor GERISSEN vor UEBERSPRUNGEN vor BESTANDEN, und die
    Meldung nennt JEDE Zusicherung, die nicht bestanden hat, mit ihrem Namen.
    """
    # ZWEI WEITERE EINWAENDE DERSELBEN GEGENLESUNG, beide gemessen:
    #
    # NEBENWIRKUNGEN durch den Sammelaufruf (gemeinsamer Zustand, Reihenfolge, doppelte Messung).
    # WIDERLEGT ueber den Syntaxbaum: KEINE der sechs Zusicherungen schreibt fremden Zustand,
    # weder per Attributzuweisung noch per global. Sie koennen einander in keiner Reihenfolge
    # beeinflussen. Die Linse hatte das ausdruecklich als Vermutung formuliert ("wahrscheinlich",
    # "wenn", "angenommen"), weil sie nur den Diff sah und nicht die aufgerufenen Zusicherungen.
    #
    # LAUFZEIT: der Einwand ist arithmetisch richtig, je Achse laufen jetzt SECHS statt einer
    # Zusicherung und je Kombi DREI statt einer. Fuer CI ist er trotzdem gegenstandslos, und aus
    # einem Grund, den weder die Linse noch ich auf dem Schirm hatte: budget_axis_measurement wird
    # in KEINEM Workflow unter .github/ aufgerufen. Es gibt hier keinen Zeitdeckel zu reissen.
    # Wer das Modul spaeter in CI haengt, hat die Vervielfachung ab dann zu messen.
    #
    # GEGENGELESEN VON EINER FREMDEN FAMILIE (14.09.2026, qwen3.8:27b). Ihr Einwand: eine
    # Nebenpruefung koenne mit ABGEBROCHEN fallen waehrend die Kostenmessung bestand, und das
    # Sammelurteil behaupte dann faelschlich, die MESSUNG sei ausgefallen.
    #
    # WIDERLEGT, gemessen: ABGEBROCHEN entsteht in _ausgang NIE aus einer gefallenen Zusicherung.
    # Eine gerissene Zusicherung wirft AssertionError oder Failed und ergibt GERISSEN; ABGEBROCHEN
    # gibt es nur bei einer ANDEREN Ausnahme, also wenn die Messung selbst umfaellt. Der
    # beschriebene Fall existiert nicht. Drei Faelle nachgefahren: Nebenpruefung reisst -> GERISSEN,
    # Messung bricht -> ABGEBROCHEN, Kostenpruefung reisst -> GERISSEN.
    #
    # WORAUF SIE ABER ZU RECHT ZEIGT: Fall eins und Fall drei sind beide GERISSEN, das Urteil
    # unterscheidet also nicht, WELCHE Zusicherung fiel. Das ist hier gewollt — eine Achse, auf der
    # irgendeine ihrer Zusicherungen reisst, ist nicht bestanden — und die Meldung nennt jede
    # nicht bestandene namentlich. Wer das Urteil je nach Zusicherung abstufen will, aendert eine
    # Aussage ueber die Achse und nicht nur eine Rangfolge.
    rang = {"ABGEBROCHEN": 3, "GERISSEN": 2, "UEBERSPRUNGEN": 1, "BESTANDEN": 0}
    ergebnisse = [(name, *_ausgang(ruf)) for name, ruf in rufe]
    schlimmste = max(ergebnisse, key=lambda e: rang[e[1]])[1]
    schlecht = [f"{n}: {u}{(' — ' + m) if m else ''}" for n, u, m in ergebnisse if u != "BESTANDEN"]
    if not schlecht:
        return "BESTANDEN", f"{len(ergebnisse)} Zusicherungen, alle bestanden"
    return schlimmste, f"{len(schlecht)} von {len(ergebnisse)} nicht bestanden — " + " | ".join(schlecht)


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
        kurve = t.TestKostenkurve()
        urteil, meldung = _gesamtausgang([
            ("last_erreicht_das_limit",
             lambda d=dim: fall.test_die_last_erreicht_das_limit_wirklich(d)),
            ("l_minus_eins_l_und_l_plus_eins",
             lambda d=dim: fall.test_l_minus_eins_l_und_l_plus_eins(d)),
            ("kosten_am_limit_unter_der_obergrenze",
             lambda d=dim: fall.test_kosten_am_limit_unter_der_obergrenze(d)),
            ("speicher_am_limit_unter_der_grenze",
             lambda d=dim: fall.test_speicher_am_limit_unter_der_grenze(d)),
            ("prozessspitze_gemessen_und_messweg_genannt",
             lambda d=dim: fall.test_die_prozessspitze_wird_gemessen_und_ihr_messweg_genannt(d)),
            ("kurve_ist_nicht_ueberlinear",
             lambda d=dim: kurve.test_die_kurve_ist_nicht_ueberlinear(d)),
        ])
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
        })
    kombis = []
    for name, n_achsen, bau in t.KOMBIS:
        m = t._kombi_messung(name, bau)
        fall = t.TestKombinierteAchsen()
        urteil, meldung = _gesamtausgang([
            ("kombi_erreicht_jede_benannte_dimension",
             lambda n=name, a=n_achsen, b=bau: fall.test_kombi_erreicht_jede_benannte_dimension(n, a, b)),
            ("kombi_bleibt_unter_der_summe_der_obergrenzen",
             lambda n=name, a=n_achsen, b=bau: fall.test_kombi_bleibt_unter_der_summe_der_obergrenzen(n, a, b)),
            ("kombi_speicher_bleibt_unter_der_grenze",
             lambda n=name, a=n_achsen, b=bau: fall.test_kombi_speicher_bleibt_unter_der_grenze(n, a, b)),
        ])
        kombis.append({
            "name": name, "eingabeachsen": n_achsen,
            "dauer_max_s": round(m["dauer_max"], 6),
            "erreicht": m["erreicht"],
            "speicher_peak_bytes": m["speicher_peak"],
            "urteil": urteil, "meldung": meldung,
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
