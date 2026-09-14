"""Der Traeger sagt, wie seine Bytebereiche ENDEN — und die Verteilung wird nachgerechnet.

WOZU. `byte_range` und `fundart` standen im Traeger, die Frage, ob der Bereich den Trenner zur
naechsten Ueberschrift einschliesst, stand nirgends. Er schliesst ihn ein: `schneide_beleg` setzt
das Ende auf den Beginn der naechsten Ueberschrift, und `^` trifft unter `re.M` hinter dem
Zeilenumbruch. GEMESSEN am Bestand: 118 von 145 Bereichen enden mit einer Leerzeile.

WAS DIE LUECKE GEKOSTET HAT: `docs/register/G1.md` traegt 3669 B und ist mit der Mail vom 12.09.
nach aussen gebunden, die Belegdatei 3670 B. Der eine Unterschied IST dieser Trenner. Ohne die
Deklaration liest sich die Differenz wie ein Defekt in einer der beiden Fassungen — und genau so
wurde sie einmal gelesen, mit einem Angleich, der die aeussere Bindung brach.

`pruefe_v2` laesst den Block ABWESEND durchgehen, weil eine fehlende Angabe keine falsche ist und
zwei Vertraege minimale Wegwerf-Traeger bauen. Dass der ECHTE Bestand ihn fuehrt, ist deshalb
diese Zusicherung hier.
"""
from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import pathlib

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
TRAEGER = REPO / "audit_artifacts/600/findings_register_v2.json"
QUELLE = REPO / "RESTRISIKO_600.md"

pytestmark = pytest.mark.skipif(not TRAEGER.is_file() or not QUELLE.is_file(),
                                reason="Traeger oder Quelle liegen in diesem Baum nicht vor")


def _gen():
    s = importlib.util.spec_from_file_location(
        "_gfr", REPO / "scripts" / "gen_findings_register.py")
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m


def _doc():
    return json.loads(TRAEGER.read_text(encoding="utf-8"))


def _endform(bytes_: bytes) -> str:
    if bytes_.endswith(b"\n\n"):
        return "ends_with_blank_line"
    return "ends_with_one_newline" if bytes_.endswith(b"\n") else "ends_without_newline"


def _neu_abgeleitet(doc) -> dict:
    """Die Verteilung aus der QUELLE geschnitten, nicht aus dem Block gelesen."""
    gez = {"ends_with_blank_line": 0, "ends_with_one_newline": 0, "ends_without_newline": 0}
    for r in doc["records"]:
        for b in r["evidence"]:
            if b.get("role") == "sent":
                continue          # traegt keinen Bytebereich, gehoert nicht in die Verteilung
            roh = (REPO / b["source_path"]).read_bytes()
            von, bis = b["byte_range"]
            gez[_endform(roh[von:bis])] += 1
    return gez


def test_der_traeger_fuehrt_die_schnittkonvention():
    sk = _doc()["inventory"].get("evidence_cut")
    assert isinstance(sk, dict), "das Inventar nennt keine Schnittkonvention"
    assert sk.get("interval"), "die Konvention nennt kein Intervall"
    regeln = sk.get("rule_by_fundart") or {}
    assert set(regeln) == {"ueberschrift", "tabelle_spalte1"}, (
        f"je Fundart eine Regel, gefunden {sorted(regeln)}")
    assert all(isinstance(v, str) and len(v) > 40 for v in regeln.values())
    assert sk.get("consequence_for_the_reader"), "ohne die Folge fuer den Leser ist es eine Notiz"


def test_die_gezaehlte_verteilung_laesst_sich_nachrechnen():
    doc = _doc()
    sk = doc["inventory"]["evidence_cut"]
    assert sk["measured_endings"] == _neu_abgeleitet(doc), (
        "der Block behauptet eine andere Verteilung, als die Quelle hergibt")
    assert sum(sk["measured_endings"].values()) == doc["inventory"]["identifiers_in_this_register"]
    assert sk["population"] == doc["inventory"]["identifiers_in_this_register"]


def test_die_leerzeile_ist_die_regel_nicht_die_ausnahme():
    """Wer den Block liest, soll die dominierende Form auch sehen."""
    sk = _doc()["inventory"]["evidence_cut"]
    me = sk["measured_endings"]
    assert me["ends_with_blank_line"] > sum(v for k, v in me.items() if k != "ends_with_blank_line")


def test_G1_ist_der_gemessene_fall_hinter_dieser_konvention():
    """Die aeussere Fassung und der Beleg unterscheiden sich um GENAU den Trenner."""
    gebunden = REPO / "docs/register/G1.md"
    beleg = REPO / "audit_artifacts/600/register_evidence/G1.md"
    if not (gebunden.is_file() and beleg.is_file()):
        pytest.skip("die G1-Fassungen liegen in diesem Baum nicht vor")
    a, z = gebunden.read_bytes(), beleg.read_bytes()
    assert z == a + b"\n", "die Abweichung ist nicht mehr der eine Trenner"
    assert hashlib.sha256(a).hexdigest().startswith("9cc21817"), (
        "die nach aussen gebundene Fassung traegt ihren versendeten Digest nicht mehr")


def test_ein_verfaelschter_block_wird_abgewiesen():
    """FANGNACHWEIS: der Riegel faengt eine gefaelschte Verteilung."""
    gen = _gen()
    doc = _doc()
    doc["inventory"]["evidence_cut"]["measured_endings"]["ends_with_blank_line"] -= 1
    fehler = gen.pruefe_v2(doc, REPO)
    assert [f for f in fehler if "[SK-NEUABLEITUNG]" in f], (
        f"eine verfaelschte Verteilung kam durch: {fehler}")


def test_eine_fehlende_angabe_ist_kein_fehler():
    """KEINE Angabe ist nicht dasselbe wie eine FALSCHE — minimale Traeger bleiben gueltig."""
    gen = _gen()
    doc = _doc()
    doc["inventory"].pop("evidence_cut")
    assert not [f for f in gen.pruefe_v2(doc, REPO) if f.startswith("[SK-")], (
        "ein Traeger ohne die Angabe wird faelschlich abgewiesen")


# ── K3, Owner-Auflage vom 14.09.2026: Rolle `sent`, zweiter evidence-Eintrag an G1 ───────────

def _g1():
    return next(r for r in _doc()["records"] if r["id"] == "G1")


def test_die_rolle_sent_steht_im_schema():
    gen = _gen()
    assert "sent" in gen.BELEGROLLE, "das role-Enum kennt `sent` nicht"


def test_G1_traegt_einen_zweiten_beleg_mit_der_rolle_sent():
    ev = _g1()["evidence"]
    assert len(ev) == 2, f"erwartet zwei Belege an G1, gefunden {len(ev)}"
    assert ev[0]["role"] == "historical_record", "die alte Aussage muss lesbar bleiben"
    s = ev[1]
    assert s["role"] == "sent"
    assert s["path"] == "docs/register/G1.md"
    assert s["sha256"] == s["measured_sha256"], "deklariert und gemessen weichen ab"
    assert s["sha256"].startswith("9cc21817")
    assert s["bytes"] == 3669
    assert s["sent_at"] == "2026-09-12", "das Datum der Bindung fehlt"
    assert s.get("reason"), "zwei Digests ohne Grund sind ein Widerspruch, keine Auskunft"
    assert "byte_range" not in s, "ein `sent`-Beleg zitiert die Quelle nicht"


def test_die_revision_des_datensatzes_ist_nicht_die_des_registers():
    """K3: record_revision plus eins AN G1, register_revision 1 — nicht ueberall."""
    doc = _doc()
    assert doc["register_revision"] == 1
    erhoeht = [r["id"] for r in doc["records"] if r["record_revision"] != 0]
    assert erhoeht == ["G1"], f"revidiert wurden {erhoeht}, erwartet nur G1"


def test_die_kennung_steht_in_den_daten_nicht_im_erzeuger():
    """Ein Erzeuger, der 'G1' kennt, waere eine Punktfixtur."""
    # OHNE KOMMENTARE UND DOCSTRINGS GEMESSEN. Die erste Fassung suchte das Wort im Quelltext
    # und fand es in meiner eigenen Erklaerung, die K3 zitiert — sie mass die Schreibweise statt
    # der Eigenschaft. `ast.unparse` wirft Kommentare weg; Docstrings werden geleert. Was dann
    # bleibt, ist ausfuehrbarer Code samt seiner Zeichenketten.
    baum = ast.parse((REPO / "scripts/gen_findings_register.py").read_text(encoding="utf-8"))
    for knoten in ast.walk(baum):
        leib = getattr(knoten, "body", None)
        if isinstance(leib, list) and leib and isinstance(leib[0], ast.Expr) \
                and isinstance(getattr(leib[0], "value", None), ast.Constant) \
                and isinstance(leib[0].value.value, str):
            leib[0].value.value = ""
    code = ast.unparse(baum)
    assert "G1" not in code, "die Kennung steht im ausfuehrbaren Code statt in der Deklaration"
    ok = json.loads((REPO / "RESTRISIKO_600_OBJEKTKLASSEN.json").read_text(encoding="utf-8"))
    erklaert = ok["ausnahmen_von_der_klasse"]["gebundene_aussenfassung"]["kennungen"]
    assert "G1" in erklaert and erklaert["G1"].get("warum")


def test_der_alte_traeger_des_zweiten_digests_ist_weg():
    """Zwei Traeger derselben Angabe driften — es darf nur EINEN Ort geben."""
    assert "bound_external_copy" not in _g1()
    # Gemessen wird, ob der Erzeuger das Feld noch SCHREIBT — nicht, ob der Name irgendwo faellt.
    # Die Erklaerung, warum es weg ist, darf ihn nennen; genau das ist ihr Zweck.
    quelle = (REPO / "scripts/gen_findings_register.py").read_text(encoding="utf-8")
    assert '"bound_external_copy":' not in quelle, "der Erzeuger schreibt das alte Feld noch"


def test_eine_gebrochene_aussenbindung_wird_abgewiesen():
    """FANGNACHWEIS: neu abgeleitet statt dem gespeicherten Wert geglaubt."""
    gen, doc = _gen(), _doc()
    g1 = next(r for r in doc["records"] if r["id"] == "G1")
    g1["evidence"][1]["sha256"] = "0" * 64
    assert [f for f in gen.pruefe_v2(doc, REPO) if "[SENT-ABWEICHEND]" in f], (
        "ein verfaelschter Digest der versendeten Fassung kam durch")


def test_ein_sent_beleg_ohne_grund_oder_datum_wird_abgewiesen():
    gen = _gen()
    for feld, code in (("reason", "[SENT-GRUND]"), ("sent_at", "[SENT-DATUM]")):
        doc = _doc()
        next(r for r in doc["records"] if r["id"] == "G1")["evidence"][1].pop(feld)
        assert [f for f in gen.pruefe_v2(doc, REPO) if code in f], f"{feld} ungeprueft"


# ── Punkt 2 der Fuenferliste: der Messer je Objektklasse ─────────────────────────────────────

_MESSZUSTAENDE = {"INTEGRITY_VERIFIED", "NOT MEASURED", "NOT MEASURABLE",
                  "NOT APPLICABLE"}


def test_jeder_eintrag_traegt_einen_messzustand_mit_grund():
    for r in _doc()["records"]:
        m = r.get("measurement")
        assert isinstance(m, dict), f"{r['id']} ohne Messzustand"
        assert m["state"] in _MESSZUSTAENDE, f"{r['id']}: {m['state']!r}"
        assert m.get("reason"), f"{r['id']}: Zustand ohne Grund ist eine leere Marke"


def test_der_messzustand_steht_nicht_im_klassenfeld():
    """`class_state` beantwortet eine ANDERE Frage und bleibt unberuehrt."""
    for r in _doc()["records"]:
        assert r["class_state"] == "NOT MEASURED"
        assert "class identifier" in r["class_reason"]


def test_die_verteilung_laesst_sich_aus_der_klassenkarte_nachrechnen():
    doc = _doc()
    ok = json.loads((REPO / "RESTRISIKO_600_OBJEKTKLASSEN.json").read_text(encoding="utf-8"))
    kein_fund = {e["kennung"] for e in ok["eintraege"] if not e.get("zaehlt_als_fund", True)}
    erwartet = {}
    for r in doc["records"]:
        b = r["evidence"][0]
        traegt = (REPO / b["path"]).is_file() and \
                 (REPO / b["path"]).read_bytes() == (REPO / b["source_path"]).read_bytes()[
                     b["byte_range"][0]:b["byte_range"][1]]
        z = ("NOT APPLICABLE" if r["id"] in kein_fund
             else "INTEGRITY_VERIFIED" if traegt else "NOT MEASURABLE")
        erwartet[z] = erwartet.get(z, 0) + 1
    ms = doc["inventory"]["measurement_summary"]
    assert ms["states"] == erwartet, f"Traeger {ms['states']}, nachgerechnet {erwartet}"
    assert sum(ms["states"].values()) == doc["inventory"]["identifiers_in_this_register"]


def test_die_wand3_regel_nennt_ihren_gegenstand_und_keine_erfundene_zahl():
    """un-Gegenlesung 15.09.: `applied_to 0` mit `MEASURED` war eine Null, die wie ein Ergebnis
    aussah. env_blocked ist eine Eigenschaft von Gate-Komponenten, nicht von Funden."""
    w3 = _doc()["inventory"]["measurement_summary"]["wall_3_class_rule"]
    assert "wall 3 is NO" in w3["decision"]
    assert "none counts as passed" in w3["consequence"]
    assert w3["subject"], "eine Regel ohne benannten Gegenstand zielt auf alles und nichts"
    assert "NOT records of this findings register" in w3["subject"]
    assert w3["reach_state"] == "NOT APPLICABLE", w3["reach_state"]
    assert w3["reach_over_records"] is None, "eine Zahl, die nicht gemessen wurde, steht nicht da"
    assert w3.get("reach_reason")


def test_der_traeger_nennt_die_reichweite_seiner_eigenen_pruefung():
    """un-Gegenlesung 15.09., Punkt D: Anker gegen Driften, keine Authentisierung."""
    ms = _doc()["inventory"]["measurement_summary"]
    assert "not authentication" in ms["what_this_check_is"]
    assert "same" in ms["what_this_check_is"] and "repository" in ms["what_this_check_is"]


def test_eine_verfaelschte_messsumme_wird_abgewiesen():
    """FANGNACHWEIS."""
    gen, doc = _gen(), _doc()
    doc["inventory"]["measurement_summary"]["states"]["INTEGRITY_VERIFIED"] += 1
    assert [f for f in gen.pruefe_v2(doc, REPO) if "[MS-NEUABLEITUNG]" in f]


def test_ein_messzustand_ohne_grund_wird_abgewiesen():
    gen, doc = _gen(), _doc()
    doc["records"][0]["measurement"].pop("reason")
    assert [f for f in gen.pruefe_v2(doc, REPO) if "[MS-GRUND]" in f]


# ── un-Gegenlesung Punkt A: eine Groesse, die ein schreibender Lauf nicht herstellen kann ─────

def test_jeder_eintrag_hat_einen_zweiten_leser_aus_dem_commit():
    for r in _doc()["records"]:
        z = (r["measurement"] or {}).get("second_reader")
        assert isinstance(z, dict), f"{r['id']} ohne zweiten Leser"
        assert z["state"] in ("VERIFIED", "NOT MEASURABLE", "DEVIATING"), z["state"]
        assert z.get("reason")


def test_der_zweite_leser_oeffnet_keine_arbeitskopie():
    """Punkt A: der erste Leser vergleicht mit einer Datei, die derselbe Lauf schreibt.

    Der zweite liest Objekt-IDs aus dem Commit. Ein Lauf kann diese Gleichheit nicht durch
    SCHREIBEN herstellen, nur durch COMMITTEN — und genau das macht ihn unabhaengig.
    """
    quelle = (REPO / "scripts/gen_findings_register.py").read_text(encoding="utf-8")
    kopf = quelle.split("def _zweiter_leser", 1)[1].split("\ndef ", 1)[0]
    for verboten in ("read_bytes", "is_file", "open("):
        assert verboten not in kopf, f"der zweite Leser greift auf die Arbeitskopie zu: {verboten}"


def test_die_beiden_leser_widersprechen_sich_wenn_die_arbeitskopie_driftet():
    """FANGNACHWEIS der Unabhaengigkeit, an einem Eintrag der WIRKLICH ein Fund ist."""
    gen = _gen()
    doc = _doc()
    kand = next((r for r in doc["records"]
                 if r["measurement"]["state"] == "INTEGRITY_VERIFIED"), None)
    if kand is None:
        pytest.skip("kein Eintrag im Zustand INTEGRITY_VERIFIED vorhanden")
    p = REPO / kand["evidence"][0]["path"]
    orig = p.read_bytes()
    try:
        p.write_bytes(orig + b"X")
        neu = gen.baue_v2(REPO, "2026-01-01T00:00:00Z", 1)
        m = next(r for r in neu["records"] if r["id"] == kand["id"])["measurement"]
        assert m["state"] == "NOT MEASURABLE", m["state"]
        assert m["second_reader"]["state"] == "VERIFIED", m["second_reader"]["state"]
    finally:
        p.write_bytes(orig)


def test_ein_abweichender_zweiter_leser_ist_ein_fehler():
    gen, doc = _gen(), _doc()
    doc["records"][0]["measurement"]["second_reader"]["state"] = "DEVIATING"
    assert [f for f in gen.pruefe_v2(doc, REPO) if "[ZL-ABWEICHEND]" in f]


# ── Punkt 2a, die vier Belegwege (die sechs Bedingungen fehlen, Owner-Karte laeuft) ──────────

def test_die_vier_belegwege_stehen_vollstaendig_im_traeger():
    e = _doc()["inventory"]["evidence_paths"]
    assert set(e["paths"]) == {"executable_product_defect", "mechanically_checkable_doc_error",
                               "substantive_doc_error", "decision_or_boundary"}, sorted(e["paths"])
    assert e["never_counts_as_repaired"] == "decision_or_boundary"
    assert "NEVER counts as repaired" in e["paths"]["decision_or_boundary"]


def test_jeder_datensatz_traegt_einen_belegweg_oder_eine_benannte_luecke():
    gen = _gen()
    for r in _doc()["records"]:
        b = r.get("evidence_path")
        assert isinstance(b, dict), f"{r['id']} ohne Belegweg"
        if b.get("value") is None:
            assert b["state"] in gen.LUECKENWOERTER and b.get("reason"), r["id"]
        else:
            assert b["value"] in gen.BELEGWEGE, f"{r['id']}: {b['value']!r}"
            assert b.get("source"), f"{r['id']}: Zuordnung ohne Quelle"


def test_der_vierte_weg_zaehlt_nie_als_repariert():
    gen = _gen()
    for r in _doc()["records"]:
        b = r["evidence_path"]
        if b.get("value") == gen.NIE_REPARIERT:
            assert b.get("counts_as_repaired") is False, r["id"]


def test_die_zahl_der_zuordnungen_ist_die_aussage():
    """2 von 145 — und die 143 sind der Arbeitsauftrag von 2b, kein Mangel."""
    doc = _doc()
    e = doc["inventory"]["evidence_paths"]
    ok = json.loads((REPO / "RESTRISIKO_600_OBJEKTKLASSEN.json").read_text(encoding="utf-8"))
    grenzen = sum(1 for x in ok["eintraege"] if x["klasse"] == "benannte_grenze")
    assert e["assigned"]["decision_or_boundary"] == grenzen, (e["assigned"], grenzen)
    assert sum(e["assigned"].values()) + e["not_measured"] == \
        doc["inventory"]["identifiers_in_this_register"]
    assert e.get("why_so_few"), "eine auffaellige Zahl ohne Begruendung ist eine offene Frage"


def test_ein_erfundener_belegweg_wird_abgewiesen():
    gen, doc = _gen(), _doc()
    doc["records"][0]["evidence_path"] = {"value": "weil_ich_es_sage", "source": "x"}
    assert [f for f in gen.pruefe_v2(doc, REPO) if "[BW-UNBEKANNT]" in f]


def test_eine_grenze_die_sich_als_repariert_ausgibt_wird_abgewiesen():
    gen, doc = _gen(), _doc()
    z = next(r for r in doc["records"]
             if r["evidence_path"].get("value") == gen.NIE_REPARIERT)
    z["evidence_path"]["counts_as_repaired"] = True
    assert [f for f in gen.pruefe_v2(doc, REPO) if "[BW-REPARIERT]" in f]


# ── Punkt 2a: subject fuehrt Identifikator und Inhaltsdigest GETRENNT ────────────────────────

def test_subject_trennt_identifikator_und_inhalt():
    s = _doc()["subject"]
    assert s["identifier"]["name"] == "proofbundle"
    assert s["identifier"]["version"] and s["identifier"]["tag"]
    assert "content" in s and "action" in s
    assert s.get("why_separate"), "die Trennung ohne Begruendung ist eine Formalie"


def test_der_inhaltsdigest_wird_nie_aus_der_quelle_GEWAEHLT():
    """Die Eigenschaft, nicht der Zustand.

    Erste Fassung schrieb `state == "NOT MEASURABLE"` fest — und wurde rot, als die Bindung
    gegen die veroeffentlichten Bytes gelang. Ein Test, der einen ZUSTAND pinnt, blockt genau
    den Fortschritt, den er begleiten soll. Geschuetzt werden sollte etwas anderes: dass kein
    Digest aus dem Quellregister zum Release-Digest ERKLAERT wird. Das gilt in beiden Zustaenden.
    """
    c = _doc()["subject"]["content"]
    assert c["state"] in ("VERIFIED", "NOT MEASURABLE"), c["state"]
    assert c.get("reason")
    if c["state"] == "VERIFIED":
        # gebunden wird gegen eine benannte, datierte Messung — nie gegen die Quelle
        assert c["verified_against"]["path"].endswith("released_artifacts.json")
        quell = {k["sha256"] for k in c.get("candidates_in_source") or []}
        veroeff = {a["sha256"] for a in c["artifacts"]}
        assert not (quell & veroeff), "ein Quellkandidat wurde zum Release-Digest erklaert"
    for k in c.get("candidates_in_source") or []:
        assert len(k["sha256"]) == 64 and k["filename"].startswith("proofbundle-")
        assert isinstance(k["source_line"], int)


def test_die_kandidaten_stehen_wirklich_in_der_quelle():
    """Zweiter Messweg: jede genannte Zeile wird in RESTRISIKO_600.md nachgeschlagen."""
    zeilen = (REPO / "RESTRISIKO_600.md").read_text(encoding="utf-8").splitlines()
    for k in _doc()["subject"]["content"]["candidates_in_source"]:
        z = zeilen[k["source_line"] - 1]
        assert k["sha256"] in z and k["filename"] in z, (k, z[:120])


def test_die_action_ist_gerechnet_nicht_zitiert():
    """N16: die Datei liegt im Baum, also wird ihr Digest hier gerechnet."""
    import hashlib as _h
    a = _doc()["subject"]["action"]
    p = REPO / "action/action.yml"
    if not p.is_file():
        assert a["state"] == "NOT MEASURABLE" and a.get("reason")
        return
    assert a["state"] == "VERIFIED"
    assert a["sha256"] == _h.sha256(p.read_bytes()).hexdigest()
    assert a["bytes"] == p.stat().st_size


def test_ein_verifizierter_inhalt_ohne_bindung_wird_abgewiesen():
    """FANGNACHWEIS: VERIFIED ohne `verified_against` ist ein Digest ohne Bindung."""
    gen, doc = _gen(), _doc()
    doc["subject"]["content"] = {"state": "VERIFIED", "reason": "weil ich es sage"}
    assert [f for f in gen.pruefe_v2(doc, REPO) if "[SU-BINDUNG]" in f]


def test_ein_subject_ohne_grund_wird_abgewiesen():
    gen, doc = _gen(), _doc()
    doc["subject"]["content"].pop("reason")
    assert [f for f in gen.pruefe_v2(doc, REPO) if "[SU-GRUND]" in f]


# ── Punkt 2a: der Abschlussvertrag, sechs Bedingungen (Owner-Antwort OA-34798a68c3) ──────────

def test_der_abschlussvertrag_fuehrt_sechs_bedingungen_mit_wortlaut():
    c = _doc()["inventory"]["closing_contract"]
    b = c["conditions"]
    assert len(b) == 6, len(b)
    assert [x["nr"] for x in b] == [1, 2, 3, 4, 5, 6]
    for x in b:
        assert x.get("requires") and x.get("name")
        assert x["state"] in ("MET", "NOT MET")
        assert x.get("reason"), f"Bedingung {x['nr']} ohne Grund"


def test_die_quelle_des_vertrags_ist_benannt_und_als_unerreichbar_markiert():
    """Die Aufarbeitung liegt im kraxo-Baum am Mac; eine Farmer-Sitzung sieht sie erst nach Push."""
    c = _doc()["inventory"]["closing_contract"]
    assert c["source"].endswith("AUFARBEITUNG_review_fundregister_beleg_je_fund_20260913.md")
    assert c["source_sha256_prefix"].startswith("84f0787c")
    assert c["source_state"] == "NOT MEASURABLE"
    assert "commit and push" in c["source_reason"]


def test_der_vertrag_meldet_sich_nicht_gruen_solange_der_traeger_unsigniert_ist():
    """Bedingung 3 und 4 verlangen eine gepruefte Signatur; der Traeger ist UNSIGNED."""
    doc = _doc()
    assert doc["signature"]["state"] == "UNSIGNED"
    b = {x["nr"]: x for x in doc["inventory"]["closing_contract"]["conditions"]}
    assert b[3]["state"] == "NOT MET" and b[4]["state"] == "NOT MET"


def test_ein_gruen_gemeldeter_vertrag_ohne_signatur_wird_abgewiesen():
    """FANGNACHWEIS: genau der Selbstbetrug, gegen den der Vertrag gebaut ist."""
    gen, doc = _gen(), _doc()
    for x in doc["inventory"]["closing_contract"]["conditions"]:
        if x["nr"] == 4:
            x["met"], x["state"] = True, "MET"
    assert [f for f in gen.pruefe_v2(doc, REPO) if "[AV-SIGNATUR]" in f]


def test_eine_bedingung_ohne_grund_wird_abgewiesen():
    gen, doc = _gen(), _doc()
    doc["inventory"]["closing_contract"]["conditions"][0].pop("reason")
    assert [f for f in gen.pruefe_v2(doc, REPO) if "[AV-GRUND]" in f]


def test_die_vier_belegwege_tragen_ihre_woertliche_fassung():
    """Owner-Antwort OA-34798a68c3: je Weg steht, WAS ihn traegt."""
    gen = _gen()
    assert "FROZEN property test" in gen.BELEGWEGE["executable_product_defect"]
    assert "rejection of the old version" in gen.BELEGWEGE["mechanically_checkable_doc_error"]
    assert "NO test claim" in gen.BELEGWEGE["substantive_doc_error"]
    assert "NEVER counts as repaired" in gen.BELEGWEGE["decision_or_boundary"]


# ── un-Gegenlesung 15.09., zweite Runde: vier Urteile, alle eingearbeitet ────────────────────

def test_der_inhalt_ist_gegen_die_veroeffentlichten_bytes_gebunden():
    """Punkt 1: 'nicht bindbar' war zu frueh gesagt — der Paketindex entscheidet es."""
    c = _doc()["subject"]["content"]
    if c["state"] == "NOT MEASURABLE":
        assert "not that it is impossible" in c["reason"]
        pytest.skip("released_artifacts.json liegt in diesem Baum nicht vor")
    assert c["state"] == "VERIFIED"
    va = c["verified_against"]
    assert va["path"].endswith("released_artifacts.json") and va["source"] and va["measured_utc"]
    arten = {a["packagetype"] for a in c["artifacts"]}
    assert {"bdist_wheel", "sdist"} <= arten, arten


def test_kein_digest_der_quelle_ist_ein_veroeffentlichtes_artefakt():
    """Gemessener Fund: alle drei Kandidaten der Quelle sind Bauversuche."""
    c = _doc()["subject"]["content"]
    if c["state"] != "VERIFIED":
        pytest.skip("ohne Bindung ist der Vergleich nicht messbar")
    assert c["source_candidates_that_match"] == []
    assert "would bind the wrong bytes" in c["what_that_means"]


def test_die_kandidatenzahl_ist_als_untergrenze_deklariert():
    """Punkt 1b: ein Zeilen-Regex sieht keine mehrzeilige Tabelle."""
    c = _doc()["subject"]["content"]
    assert "lower_bound" in " ".join(c.keys()) or c.get("candidate_count_is_a_lower_bound")


def test_bedingung_1_und_2_sind_abgeleitet_nicht_verdrahtet():
    """Punkt 2, die Bruchstelle: eine Konstante, die immer NOT MET sagt, ist kein Riegel."""
    doc = _doc()
    b = {x["nr"]: x for x in doc["inventory"]["closing_contract"]["conditions"]}
    n = len(doc["records"])
    assert str(n) in b[1]["reason"], b[1]["reason"]
    ohne_weg = sum(1 for r in doc["records"]
                   if (r.get("evidence_path") or {}).get("value") is None)
    assert str(ohne_weg) in b[2]["reason"], b[2]["reason"]


def test_der_vertrag_kann_sich_bewegen():
    """Punkt 2b: mindestens eine Bedingung wechselt durch eine MESSUNG, nicht durch Code."""
    b = _doc()["inventory"]["closing_contract"]["conditions"]
    assert any(x["met"] for x in b), "kein einziger Zustand erreichbar — dann ist es kein Vertrag"
    assert any(not x["met"] for x in b), "alle gruen waere hier ein falsches Bestehen"


def test_bedingung_6_nennt_ihre_vakuitaet():
    b = {x["nr"]: x for x in _doc()["inventory"]["closing_contract"]["conditions"]}
    if b[6]["met"]:
        assert "VACUOUSLY" in b[6]["reason"], b[6]["reason"]


def test_der_signaturriegel_rechnet_statt_zu_lesen():
    """Punkt 3: `_signatur_lage` verifiziert kryptografisch; ein gesetztes Feld genuegt nicht."""
    gen, doc = _gen(), _doc()
    doc["signature"] = {"state": "VERIFIED", "reason": "x", "alg": "ed25519",
                        "public_key_b64": "not base64", "sig_b64": "not a signature"}
    for x in doc["inventory"]["closing_contract"]["conditions"]:
        if x["nr"] == 4:
            x["met"], x["state"] = True, "MET"
    f = gen.pruefe_v2(doc, REPO)
    assert [z for z in f if "[AV-SIGNATUR]" in z], f"konsistente Faelschung kam durch: {f[:3]}"


def test_die_grenze_der_belegweg_zuordnung_ist_benannt():
    """Punkt 4: geprueft wird die Klasse, nicht ob die Grenze selbst nachgewiesen ist."""
    gen = _gen()
    for r in _doc()["records"]:
        b = r["evidence_path"]
        if b.get("value") == gen.NIE_REPARIERT:
            assert "whether the boundary is itself evidenced" in b["not_checked"]


# ── Punkt 2a, Rest: drei Zeiten und additive Revision ────────────────────────────────────────

def test_der_traeger_fuehrt_drei_zeiten():
    gen = _gen()
    z = _doc()["times"]
    assert set(z) >= {"first_seen", "measured", "issued"}
    for name in ("first_seen", "measured", "issued"):
        b = z[name]
        if b.get("value") is None:
            assert b["state"] in gen.LUECKENWOERTER and b.get("reason"), name
        else:
            assert b.get("source"), f"{name} traegt einen Wert ohne Quelle"


def test_die_messzeit_kommt_nicht_aus_der_uhr_des_laufs():
    """Derselbe Fehler wie einst bei der Bewertungsgrenze — die Uhr wuerde den Stand vordatieren."""
    doc = _doc()
    m = doc["times"]["measured"]
    if m.get("value"):
        assert m["value"] != doc["generated_at"]
        assert "gemessen_an" in m["source"]


def test_die_erstsichtung_fehlt_mit_grund():
    f = _doc()["times"]["first_seen"]
    assert f["value"] is None and f["state"] == "NOT MEASURED"
    assert "the round, not the finding" in f["reason"]


def test_nur_revidierte_datensaetze_loesen_etwas_ab():
    for r in _doc()["records"]:
        if r.get("record_revision", 0) == 0:
            assert r.get("supersedes") is None, r["id"]
        else:
            s = r["supersedes"]
            assert s["record_revision"] == r["record_revision"] - 1
            assert s["additive"] is True
            assert s.get("added")


def test_die_alte_aussage_bleibt_neben_der_neuen_lesbar():
    """Additiv heisst: der historische Beleg wird nicht ersetzt."""
    for r in _doc()["records"]:
        if r.get("supersedes"):
            rollen = [b["role"] for b in r["evidence"]]
            assert rollen[0] == "historical_record", rollen
            assert len(rollen) > 1, "additiv, aber nichts hinzugefuegt"


def test_eine_nicht_additive_revision_wird_abgewiesen():
    gen, doc = _gen(), _doc()
    r = next(x for x in doc["records"] if x.get("supersedes"))
    r["supersedes"]["additive"] = False
    assert [f for f in gen.pruefe_v2(doc, REPO) if "[SP-ADDITIV]" in f]


def test_eine_gerissene_revisionskette_wird_abgewiesen():
    gen, doc = _gen(), _doc()
    r = next(x for x in doc["records"] if x.get("supersedes"))
    r["supersedes"]["record_revision"] = 99
    assert [f for f in gen.pruefe_v2(doc, REPO) if "[SP-KETTE]" in f]


def test_eine_messzeit_aus_der_laufuhr_wird_abgewiesen():
    gen, doc = _gen(), _doc()
    doc["times"]["measured"] = {"value": doc["generated_at"], "source": "die Uhr"}
    assert [f for f in gen.pruefe_v2(doc, REPO) if "[ZT-UHR]" in f]


# ── Punkt 2b: drei Zahlen getrennt, Mengenabstimmung voran ───────────────────────────────────

def test_die_drei_zahlen_stehen_getrennt():
    """Eine Sammelzahl liesse einen historischen Abschluss wie eine heutige Reparatur aussehen."""
    f = _doc()["inventory"]["progress_view"]
    assert "value" not in f, "die Fortschrittssicht traegt eine Sammelzahl"
    for name in ("historical_closures", "evidenced_repairs", "evidence_gaps"):
        assert name in f, name


def test_die_mengenabstimmung_steht_voran_und_ist_gerechnet():
    doc = _doc()
    a = doc["inventory"]["progress_view"]["reconciliation_first"]
    assert a["records_in_register"] == doc["inventory"]["identifiers_in_this_register"]
    assert a["identifiers_in_tally"] == \
        doc["inventory"]["cross_count"]["gerechnet_aus"]["sollliste"]
    assert a["difference_to_that_example"] == \
        a["identifiers_in_tally"] - a["example_1109_named_in_point_2b"]
    assert "not a target" in a["why_it_stands_first"]


def test_die_historischen_abschluesse_sind_abgeleitet():
    gen = _gen()
    h = _doc()["inventory"]["progress_view"]["historical_closures"]
    erwartet = [f["id"] for f in gen.FINDINGS if f["status"] == "closed"]
    assert h["value"] == len(erwartet) and h["ids"] == erwartet
    assert "none of them is a repair evidenced by this carrier" in h["what_it_is_not"]


def test_belegte_reparaturen_starten_bei_nicht_gemessen():
    gen = _gen()
    r = _doc()["inventory"]["progress_view"]["evidenced_repairs"]
    if r["value"] is None:
        assert r["state"] in gen.LUECKENWOERTER and r.get("reason")
        assert "by construction" in r["reason"]


def test_die_evidenzluecken_werden_getrennt_gezaehlt():
    """Drei verschiedene Luecken, nicht eine Zahl."""
    g = _doc()["inventory"]["progress_view"]["evidence_gaps"]
    for k in ("without_find_site", "not_measurable", "without_determined_evidence_path"):
        assert isinstance(g[k], int), k
    assert "counted apart" in g["reason"]


def test_eine_gemischte_fortschrittszahl_wird_abgewiesen():
    gen, doc = _gen(), _doc()
    doc["inventory"]["progress_view"]["value"] = 13
    assert [f for f in gen.pruefe_v2(doc, REPO) if "[FS-GEMISCHT]" in f]


def test_eine_nicht_nachrechenbare_abschlusszahl_wird_abgewiesen():
    gen, doc = _gen(), _doc()
    doc["inventory"]["progress_view"]["historical_closures"]["value"] = 99
    assert [f for f in gen.pruefe_v2(doc, REPO) if "[FS-NEUABLEITUNG]" in f]
