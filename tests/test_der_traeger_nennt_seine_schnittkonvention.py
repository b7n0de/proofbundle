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


# ── K2, Owner-Auflage vom 14.09.2026: der Grund steht AM DATENSATZ, nicht in einem Kommentar ──

def test_der_datensatz_G1_nennt_seine_gebundene_aussenfassung():
    g1 = next(r for r in _doc()["records"] if r["id"] == "G1")
    b = g1.get("bound_external_copy")
    assert isinstance(b, dict), "der Datensatz G1 nennt seine gebundene Aussenfassung nicht"
    assert b["path"] == "docs/register/G1.md"
    assert b["state"] == "VERIFIED", f"Zustand {b.get('state')!r}, erwartet VERIFIED"
    assert b["declared_sha256"] == b["measured_sha256"]
    assert b["declared_sha256"].startswith("9cc21817")
    assert b["bytes"] == 3669
    assert b.get("declared_reason"), "zwei Digests ohne Grund sind ein Widerspruch, keine Auskunft"
    assert "plus 1 byte" in b["relation_to_evidence"], b["relation_to_evidence"]


def test_die_kennung_steht_in_den_daten_nicht_im_erzeuger():
    """Ein Erzeuger, der 'G1' kennt, waere eine Punktfixtur."""
    quelle = (REPO / "scripts/gen_findings_register.py").read_text(encoding="utf-8")
    kopf = quelle.split("def _gebundene_fassung", 1)[1].split("\ndef ", 1)[0]
    assert "G1" not in kopf, "die Kennung steht im Code statt in der Deklaration"
    ok = json.loads((REPO / "RESTRISIKO_600_OBJEKTKLASSEN.json").read_text(encoding="utf-8"))
    erklaert = ok["ausnahmen_von_der_klasse"]["gebundene_aussenfassung"]["kennungen"]
    assert "G1" in erklaert and erklaert["G1"].get("warum")


def test_eine_gebrochene_aussenbindung_wird_abgewiesen():
    """FANGNACHWEIS: der Riegel leitet neu ab statt dem gespeicherten Zustand zu glauben."""
    gen, doc = _gen(), _doc()
    g1 = next(r for r in doc["records"] if r["id"] == "G1")
    g1["bound_external_copy"]["declared_sha256"] = "0" * 64   # state bleibt VERIFIED
    assert [f for f in gen.pruefe_v2(doc, REPO) if "[BA-NEUABLEITUNG]" in f], (
        "ein verfaelschter Digest kam durch, weil der Zustand geglaubt statt gerechnet wurde")
