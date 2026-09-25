#!/usr/bin/env python3
"""site-data.json: jeder Wert mit Quelle und Messzeit, jede Luecke mit Grund.

OWNER-AUFTRAG Z193: „Vertragstest, fehlende Quelle ergibt nicht_messbar, eine manipulierte
Quittung ergibt failed, die Datei ist byte-stabil bei unveraenderten Quellen."

DER VIERTE FALL STEHT HIER, WEIL ER GEFEHLT HAT. Beim Bau des Erzeugers rief ich
`verify_ed25519(pubkey, message, signature)` statt `(pubkey, signature, message)`. Der Aufruf
gelang, gab einen bool zurueck, und der bool war falsch: ALLE VIER echten Release-Quittungen
meldeten „die ed25519-Signatur haelt nicht", und das waere als Anschuldigung auf eine oeffentliche
Seite gegangen. Aufgefallen ist es nur, weil vier unabhaengig erzeugte Quittungen identisch
fehlschlugen — eine einzige haette ich moeglicherweise fuer einen echten Befund genommen.

`test_eine_echte_quittung_gilt_als_passed` ist der Fall, der das sofort gezeigt haette. Er steht
VOR dem Manipulationsfall, weil eine Pruefung, die alles abweist, den Manipulationsfall ebenfalls
besteht — und dann prueft der Manipulationsfall nichts.

DREI ZUSTAENDE, NIE ZWEI, und das ist die tragende Zusage dieser Datei: `passed` ·
`failed` · `nicht_pruefbar`. `failed` heisst „geprueft und durchgefallen". Es fuer eine Artefaktart
zu schreiben, die man mit dem falschen Werkzeug angefasst hat, ist eine Anschuldigung ohne Messung.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]


def _erzeuger():
    s = importlib.util.spec_from_file_location("_rsd", REPO / "scripts" / "render_site_data.py")
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m


RSD = _erzeuger()

ECHTE_QUITTUNG = REPO / "audit_artifacts" / "610" / "pre_tag_receipt_v6.1.0.json"


def _quittung() -> dict:
    return json.loads(ECHTE_QUITTUNG.read_text(encoding="utf-8"))


class TestDieQuittungWirdMitIHREMPrueferGeprueft:

    @pytest.mark.skipif(not ECHTE_QUITTUNG.is_file(), reason="keine echte Quittung im Baum")
    def test_eine_echte_quittung_gilt_als_passed(self):
        # DER FALL, DER DAS VERTAUSCHTE ARGUMENT SOFORT GEZEIGT HAETTE. Ohne ihn besteht der
        # Manipulationsfall auch dann, wenn die Pruefung ALLES abweist — und prueft damit nichts.
        e = RSD._quittung_pruefen(_quittung())
        assert e["zustand"] == "passed", (
            "eine echte, signierte Release-Quittung gilt nicht als passed. Erster Verdacht: die "
            "Argumentreihenfolge von verify_ed25519 ist (pubkey, signature, message). "
            f"Ergebnis: {e}")
        assert "signatur_durch_vertrauten_schluessel" in e["geprueft"]
        assert "audit_exit_code_0" in e["geprueft"]

    @pytest.mark.skipif(not ECHTE_QUITTUNG.is_file(), reason="keine echte Quittung im Baum")
    def test_eine_manipulierte_quittung_ergibt_failed(self):
        d = _quittung()
        # EIN Zeichen in einem SIGNIERTEN Feld. Der Auftrag verlangt genau das: eine manipulierte
        # Quittung ergibt failed.
        d["subject_tree_digest"] = "0" * len(str(d.get("subject_tree_digest") or "0"))
        e = RSD._quittung_pruefen(d)
        assert e["zustand"] == "failed", f"eine manipulierte Quittung ging durch: {e}"
        assert "Signatur" in e["grund"], e

    @pytest.mark.skipif(not ECHTE_QUITTUNG.is_file(), reason="keine echte Quittung im Baum")
    def test_ein_fehlgeschlagener_audit_ergibt_failed_auch_mit_gueltiger_signatur(self):
        # Eine gueltig signierte Quittung ueber einen FEHLGESCHLAGENEN Lauf ist kein Beleg. Die
        # Signatur sagt „das hat jemand bezeugt", nicht „es ist gutgegangen".
        d = _quittung()
        d["audit_exit_code"] = 1
        e = RSD._quittung_pruefen(d)
        assert e["zustand"] == "failed", f"ein fehlgeschlagener Audit ging durch: {e}"
        # Der Grund nennt entweder den Exit-Code oder die dadurch gebrochene Signatur; beides ist
        # ein ehrliches failed, aber es darf nicht passed sein.
        assert "audit_exit_code" in e["grund"] or "Signatur" in e["grund"], e

    def test_eine_fremde_artefaktart_ist_NICHT_PRUEFBAR_und_nicht_failed(self):
        # DER UNTERSCHIED, DER DEN ERSTEN ENTWURF FALSCH MACHTE: der Buendel-Verifier auf eine
        # Pre-Tag-Quittung gab keine Pruefnamen, und der Code schrieb `failed`. `failed` ist eine
        # Anschuldigung; fuer eine Art ohne erklaerten Pruefer gehoert `nicht_pruefbar` hin.
        for fremd in ({"schema": "b7n0de.etwas_anderes.v1"}, {}, {"schema": None}):
            e = RSD._quittung_pruefen(fremd)
            assert e["zustand"] == "nicht_pruefbar", f"{fremd} ergab {e['zustand']!r}"
            assert e["zustand"] != "failed"
            assert "grund" in e and e["grund"]

    @pytest.mark.skipif(not ECHTE_QUITTUNG.is_file(), reason="keine echte Quittung im Baum")
    def test_die_baumbindung_wird_als_nicht_gepruefbar_benannt_und_nicht_behauptet(self):
        # Ehrliche Grenze: verify_receipt verlangt den ERWARTETEN Baum-Digest, und eine historische
        # Quittung gegen den HEUTIGEN Baum zu halten muesste fehlschlagen. Sie steht deshalb als
        # nicht gepruefbar da, statt zu fehlen oder als geprueft zu gelten.
        e = RSD._quittung_pruefen(_quittung())
        assert e.get("baumbindung") == "nicht_gepruefbar_ohne_auscheckung_am_tag", e
        assert "baumbindung" not in (e.get("geprueft") or [])


class TestEineFehlendeQuelleErgibtNichtMessbar:

    def test_interop_ohne_datei_ist_nicht_messbar_mit_grund(self):
        # `docs/interop_status.json` liegt in diesem Baum nicht. Das Feld darf NICHT als leere
        # Liste erscheinen — der Auftrag verbietet 0, leere Liste und letzten bekannten Wert, und
        # alle drei haben dieselbe Eigenschaft: sie lesen sich wie eine Messung.
        d = RSD.interop()
        if (REPO / "docs" / "interop_status.json").is_file():
            pytest.skip("die gepflegte Liste liegt inzwischen — dieser Fall prueft ihr Fehlen")
        assert d.get("nicht_messbar") is True, d
        assert d.get("grund"), "eine Luecke ohne Grund ist eine Luecke, die wie ein Wert aussieht"
        assert "wert" not in d, "eine Luecke darf keinen Wert tragen"

    def test_die_luecke_traegt_nie_null_oder_eine_leere_liste(self):
        luecke = RSD._luecke(quelle="x", grund="y")
        assert luecke.get("wert", "FEHLT") == "FEHLT"
        assert luecke["nicht_messbar"] is True and luecke["grund"] == "y"

    def test_scorecard_ohne_netz_ist_nicht_messbar_mit_genau_diesem_grund(self):
        d = RSD.scorecard(netz=False)
        assert d.get("nicht_messbar") is True
        assert "nicht gefragt" in d["grund"], d
        assert d.get("stabil") is False, "ein Netzfeld ist nie als stabil ausgewiesen"


class TestByteStabilUeberDieBaumFelder:
    """Die Zusage gilt fuer die Felder aus dem BAUM und ausdruecklich nicht fuer die aus dem Netz.

    Wer sie ueber alles pruefte, haette einen Test, der bei jedem zweiten Lauf rot ist und darum
    abgeschaltet wird. Ein Netzfeld hat keine Quellzeit im Baum; seine Messzeit IST die Laufzeit.
    """

    def test_zwei_laeufe_ohne_quellenaenderung_geben_dieselben_baum_felder(self):
        a = RSD.baum_felder(RSD.baue(netz=False, verify=False))
        b = RSD.baum_felder(RSD.baue(netz=False, verify=False))
        assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True), (
            "zwei Laeufe ohne Quellenaenderung gaben verschiedene Baum-Felder — irgendwo steht "
            "eine Laufzeit, wo eine Quellzeit stehen muesste")

    def test_ein_netzfeld_ist_ausdruecklich_nicht_teil_der_zusage(self):
        d = RSD.baue(netz=False, verify=False)
        assert d["scorecard"].get("stabil") is False
        assert "scorecard" not in RSD.baum_felder(d), (
            "das Netzfeld steht in der Stabilitaetszusage — dann ist sie nicht haltbar")

    def test_eine_geaenderte_quelle_aendert_das_feld(self, tmp_path, monkeypatch):
        # GEGENPROBE: ohne sie wuerde ein Erzeuger, der IMMER dasselbe schreibt, den
        # Stabilitaetstest bestehen. Gemessen wird an der Zaehlregel, die als Daten neben der Zahl
        # steht — aendert sie sich, muss das Feld sich aendern.
        vorher = RSD.testflaeche()["tests_functions"]
        monkeypatch.setattr(RSD, "_TEST_ZAEHLREGEL", "eine andere Regel")
        nachher = RSD.testflaeche()["tests_functions"]
        assert vorher != nachher, "eine geaenderte Zaehlregel liess das Feld unveraendert"


class TestJederWertNenntSeineQuelleUndSeineMesszeit:

    def test_jedes_feld_traegt_quelle_und_gemessen_am(self):
        d = RSD.baue(netz=False, verify=False)
        felder = {k: v for k, v in d.items() if isinstance(v, dict) and "stabil" in v}
        assert felder, "der Erzeuger lieferte kein einziges Feld"
        for k, v in felder.items():
            assert v.get("quelle"), f"{k} nennt keine Quelle"
            if v.get("nicht_messbar"):
                assert v.get("gemessen_am") is None, f"{k} ist nicht messbar und traegt eine Zeit"
                assert v.get("grund"), f"{k} ist nicht messbar ohne Grund"
            else:
                assert "wert" in v, f"{k} traegt keinen Wert"

    def test_der_erklaerungsblock_zaehlt_NICHT_als_gemessenes_feld(self):
        # GEMESSEN AM ERSTEN LAUF: der Block hiess mit denselben Schluesseln wie die Datenfelder
        # (`messzeit`, `stabil`, `nicht_messbar`), und die Luecken-Schleife hielt ihn fuer ein Feld
        # ohne Grund — KeyError. Behoben an der KOLLISION, nicht mit einem Sonderfall.
        d = RSD.baue(netz=False, verify=False)
        lesart = d["lesart"]
        assert "stabil" not in lesart and "nicht_messbar" not in lesart, (
            "der Erklaerungsblock traegt wieder Datenfeld-Namen und wird als Feld gezaehlt: "
            f"{sorted(lesart)}")
        assert all(k.endswith("_bedeutet") for k in lesart), sorted(lesart)
        assert "lesart" not in RSD.baum_felder(d)

    def test_checks_nennt_das_buendel_an_dem_gemessen_wurde(self):
        # Eine Zahl ohne ihren Gegenstand ist die Konstante, die der Auftrag ausschliesst, nur mit
        # einem Umweg. Gemessen 25.09.2026 sind es an einem Envelope-Buendel ZWEI und nicht drei.
        d = RSD.verifier_pruefungen()
        if d.get("nicht_messbar"):
            assert d.get("grund")
            return
        assert "bundle.json" in d["quelle"], d["quelle"]
        assert d.get("pruefungen"), "die Zahl steht ohne die Liste, aus der sie kommt"
        assert d["wert"] == len(d["pruefungen"])

    def test_die_testzahl_traegt_ihre_zaehlregel(self):
        d = RSD.testflaeche()
        for k in ("tests_files", "tests_functions"):
            if d[k].get("nicht_messbar"):
                continue
            assert d[k].get("zaehlregel"), f"{k} nennt keine Zaehlregel — dann ist die Zahl ohne "
            assert "def test_" in d[k]["zaehlregel"]


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
