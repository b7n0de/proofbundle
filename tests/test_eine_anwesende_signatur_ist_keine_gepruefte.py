"""Anwesenheit ist keine Pruefung.

Codex r4001142831 (P2), am Kopf fc2bdc57 nachgestellt. `pruefe_v2` verlangte bei vorhandenem
`sig_b64` nur, dass `alg` und `public_key_b64` DA sind. Mit dem Block

    {"alg": "ed25519", "public_key_b64": "not base64", "sig_b64": "not a signature"}

meldete der Pruefer NULL Fehler, und `_signaturzeile` schrieb "Signed, ed25519." — eine
Faelschung aenderte kein einziges Urteil.

Diese Vertraege pruefen die EIGENSCHAFT, nicht die Schreibweise der Meldung: sie zaehlen, ob
ein Fehler entsteht und welchen Zustand `_signatur_lage` meldet, nicht welcher Satz dabei
herauskommt. BEIDE Richtungen stehen hier. Ein Pruefer, der jede Signatur abweist, waere
genauso falsch wie einer, der jede annimmt, und nur die erste Richtung zu pruefen haette
genau das durchgelassen.
"""
from __future__ import annotations

import base64
import copy
import importlib.util
import json
import pathlib
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
TRAEGER = REPO / "audit_artifacts" / "600" / "findings_register_v2.json"


def _modul():
    sys.path.insert(0, str(REPO / "src"))
    s = importlib.util.spec_from_file_location("gfr_sig", REPO / "scripts" / "gen_findings_register.py")
    m = importlib.util.module_from_spec(s)
    sys.modules["gfr_sig"] = m
    s.loader.exec_module(m)
    return m


@pytest.fixture(scope="module")
def m():
    return _modul()


@pytest.fixture(scope="module")
def doc():
    return json.loads(TRAEGER.read_text(encoding="utf-8"))


def _signatur_fehler(m, d) -> list[str]:
    return [f for f in m.pruefe_v2(d, REPO) if f.startswith("Signatur")]


def _echt_signiert(m, d):
    from cryptography.hazmat.primitives import serialization as ser
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    sk = Ed25519PrivateKey.generate()
    roh = copy.deepcopy(d)
    roh.pop("signature", None)
    sig = sk.sign(m.canonical_bytes(roh))
    pub = sk.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
    roh["signature"] = {"alg": "ed25519",
                        "public_key_b64": base64.b64encode(pub).decode(),
                        "sig_b64": base64.b64encode(sig).decode()}
    return roh


def test_eine_muellsignatur_wird_gefangen(m, doc):
    """DER FANGNACHWEIS. Vor dem Fix meldete genau dieser Fall null Fehler."""
    k = copy.deepcopy(doc)
    k["signature"] = {"alg": "ed25519", "public_key_b64": "not base64", "sig_b64": "not a signature"}
    assert _signatur_fehler(m, k), "eine unlesbare Signatur ging durch"
    assert m._signatur_lage(k)[0] == "GEBROCHEN"


def test_die_ansicht_nennt_eine_muellsignatur_nicht_signiert(m, doc):
    """Die Ansicht ist die Flaeche, die der Leser sieht. Sie sagte 'Signed, ed25519.'."""
    k = copy.deepcopy(doc)
    k["signature"] = {"alg": "ed25519", "public_key_b64": "not base64", "sig_b64": "not a signature"}
    zeile = m._signaturzeile(k)
    assert "does NOT verify" in zeile
    assert not zeile.startswith("Signed")


def test_eine_echte_signatur_besteht(m, doc):
    """DIE GEGENRICHTUNG. Ein Riegel, der alles abweist, ist kein Riegel."""
    g = _echt_signiert(m, doc)
    assert _signatur_fehler(m, g) == []
    assert m._signatur_lage(g)[0] == "VERIFIZIERT"
    assert m._signaturzeile(g).startswith("Signed and verified")


def test_eine_echte_signatur_bricht_wenn_der_rumpf_sich_aendert(m, doc):
    """Die Signatur muss an den BYTES haengen, nicht am Vorhandensein des Blocks."""
    g = _echt_signiert(m, doc)
    g["records"][0]["id"] = g["records"][0]["id"] + "X"
    assert _signatur_fehler(m, g), "eine Aenderung am Rumpf blieb folgenlos"
    assert m._signatur_lage(g)[0] == "GEBROCHEN"


def test_unsigniert_bleibt_unveraendert_zulaessig(m, doc):
    """Der Bestand ist UNSIGNED mit Grund und Folge. Das war und bleibt zulaessig."""
    assert _signatur_fehler(m, doc) == []
    assert m._signatur_lage(doc)[0] == "UNSIGNED"


def test_ein_unbekanntes_verfahren_ist_nicht_pruefbar_nicht_gruen(m, doc):
    """NICHT PRUEFBAR ist ein Fehler, kein Bestehen."""
    k = copy.deepcopy(doc)
    k["signature"] = {"alg": "rsa-9000", "public_key_b64": "AA==", "sig_b64": "AA=="}
    assert m._signatur_lage(k)[0] == "NICHT_PRUEFBAR"
    assert _signatur_fehler(m, k)


def test_pruefer_und_ansicht_haengen_an_EINEM_ausgang(m, doc):
    """Zwei getrennte Antworten auf dieselbe Frage driften. Diese duerfen es nicht."""
    quelle = pathlib.Path(REPO / "scripts" / "gen_findings_register.py").read_text(encoding="utf-8")
    assert quelle.count("def _signatur_lage(") == 1
    for stelle in ("def pruefe_v2(", "def _signaturzeile("):
        i = quelle.index(stelle)
        j = quelle.index("\ndef ", i + 1)
        assert "_signatur_lage(" in quelle[i:j], f"{stelle} fragt nicht den gemeinsamen Ausgang"
