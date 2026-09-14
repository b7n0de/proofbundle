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

_MESSZUSTAENDE = {"MEASURED", "NOT MEASURED", "NOT MEASURABLE", "NOT APPLICABLE"}


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
             else "MEASURED" if traegt else "NOT MEASURABLE")
        erwartet[z] = erwartet.get(z, 0) + 1
    ms = doc["inventory"]["measurement_summary"]
    assert ms["states"] == erwartet, f"Traeger {ms['states']}, nachgerechnet {erwartet}"
    assert sum(ms["states"].values()) == doc["inventory"]["identifiers_in_this_register"]


def test_die_wand3_regel_nennt_ihre_gemessene_reichweite():
    w3 = _doc()["inventory"]["measurement_summary"]["wall_3_class_rule"]
    assert "wall 3 is NO" in w3["decision"]
    assert "none counts as passed" in w3["consequence"]
    assert w3["reach_state"] in _MESSZUSTAENDE
    assert w3.get("reach_reason"), "eine Regel ohne gemessene Reichweite ist eine Absichtserklaerung"


def test_eine_verfaelschte_messsumme_wird_abgewiesen():
    """FANGNACHWEIS."""
    gen, doc = _gen(), _doc()
    doc["inventory"]["measurement_summary"]["states"]["MEASURED"] += 1
    assert [f for f in gen.pruefe_v2(doc, REPO) if "[MS-NEUABLEITUNG]" in f]


def test_ein_messzustand_ohne_grund_wird_abgewiesen():
    gen, doc = _gen(), _doc()
    doc["records"][0]["measurement"].pop("reason")
    assert [f for f in gen.pruefe_v2(doc, REPO) if "[MS-GRUND]" in f]
