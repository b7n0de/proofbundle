"""Die ZWOELF VERTRAGSPROBEN aus Punkt 2c der Fuenferliste.

Der Auftrag woertlich: "Falsche Fundzuordnung, unvollstaendige Erfassung, Digestverwechslung,
falsche Herkunft, falscher Stand, schwaches Pruefinstrument, Historie ohne Wirkung, Squash oder
Cherry-pick, fremder Laufzustand, fehlerhafte Auslieferung, Abbruch oder Konkurrenz, fehlende
Uebernahme. Je Probe Sicherung entfernt rot, wiederhergestellt gruen. Bestandspruefung in beide
Richtungen."

WAS DIESE DATEI IST UND WAS NICHT. Sie prueft NICHT, ob das Register stimmt — das tun die
Vertraege daneben. Sie prueft, ob die RIEGEL etwas fangen: je Probe wird ein Defekt der
benannten Klasse in eine KOPIE des Traegers gepflanzt und verlangt, dass `pruefe_v2` rot wird.
Ein Riegel, der seinen eigenen Defekt nicht faengt, ist eine Datei.

BEIDE RICHTUNGEN, und das ist die Haelfte, die man vergisst: jede Probe prueft AUCH, dass der
unveraenderte Traeger gruen bleibt. Ein Orakel, das immer rot meldet, faengt jeden Defekt und
ist trotzdem wertlos — es unterscheidet nichts.

SELBSTBEZUG: die Proben arbeiten auf einer Kopie im Speicher und schreiben nie in den Baum. Der
Traeger, ueber den sie urteilen, wird von ihnen nicht veraendert.
"""
from __future__ import annotations

import copy
import importlib.util
import json
import pathlib

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
TRAEGER = REPO / "audit_artifacts/600/findings_register_v2.json"

pytestmark = pytest.mark.skipif(not TRAEGER.is_file(),
                                reason="der Traeger liegt in diesem Baum nicht vor")


def _gen():
    s = importlib.util.spec_from_file_location(
        "_gfr_proben", REPO / "scripts" / "gen_findings_register.py")
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m


@pytest.fixture(scope="module")
def gen():
    return _gen()


@pytest.fixture(scope="module")
def echt():
    return json.loads(TRAEGER.read_text(encoding="utf-8"))


def _rot(gen, doc, marke: str) -> list:
    return [f for f in gen.pruefe_v2(doc, REPO) if marke in f]


# ── Die Gegenrichtung, EINMAL und fuer alle: der unveraenderte Traeger ist gruen ─────────────

def test_00_bestandspruefung_der_unveraenderte_traeger_ist_gruen(gen, echt):
    """[ZAEHLT] Ohne diese Zeile faengt jede Probe auch einen Riegel, der immer rot meldet."""
    fehler = gen.pruefe_v2(copy.deepcopy(echt), REPO)
    assert fehler == [], f"der Bestand ist nicht gruen: {fehler[:3]}"


# ── Die zwoelf, je in der Reihenfolge des Auftrags ───────────────────────────────────────────

def test_01_falsche_fundzuordnung(gen, echt):
    """Ein Eintrag wird als belegte Reparatur gezaehlt, ohne dass ein Beleg geprueft ist."""
    d = copy.deepcopy(echt)
    r = next(x for x in d["records"] if x.get("classification"))
    r["classification"] = {"bucket": "evidenced_repair", "derived_from": "behauptet"}
    assert _rot(gen, d, "[EO-REPARATUR]")


def test_02_unvollstaendige_erfassung(gen, echt):
    """Ein Datensatz verschwindet, das Inventar zaehlt weiter wie zuvor."""
    d = copy.deepcopy(echt)
    d["records"].pop()
    # [IV-MENGE] gibt es, WEIL diese Probe zuerst nichts fand: die Inventarzahlen waren
    # untereinander stimmig und niemand hielt sie gegen die Liste.
    assert _rot(gen, d, "[IV-MENGE]")


def test_03_digestverwechslung(gen, echt):
    """Zwei Belege tauschen ihren Digest — beide Zahlen existieren, beide stehen falsch."""
    d = copy.deepcopy(echt)
    a, b = d["records"][0]["evidence"][0], d["records"][1]["evidence"][0]
    a["sha256"], b["sha256"] = b["sha256"], a["sha256"]
    assert _rot(gen, d, "Beleg veraendert")


def test_04_falsche_herkunft(gen, echt):
    """Der Beleg nennt eine Quelle, die diese Bytes nie hatte."""
    d = copy.deepcopy(echt)
    d["records"][0]["evidence"][0]["source_sha256"] = "0" * 64
    assert _rot(gen, d, "die Quelle hat sich seit dem Schnitt geaendert")


def test_05_falscher_stand(gen, echt):
    """Der Traeger datiert sich in die Zukunft."""
    d = copy.deepcopy(echt)
    d["generated_at"] = "2099-01-01T00:00:00Z"
    assert _rot(gen, d, "Zeitmarke")


def test_06_schwaches_pruefinstrument(gen, echt):
    """Eine Signatur, die dasteht und nicht haelt — und ein Vertrag, der sich darauf beruft."""
    d = copy.deepcopy(echt)
    d["signature"] = {"state": "VERIFIED", "reason": "x", "alg": "ed25519",
                      "public_key_b64": "kein base64", "sig_b64": "keine Signatur"}
    for b in d["inventory"]["closing_contract"]["conditions"]:
        if b["nr"] == 4:
            b["met"], b["state"] = True, "MET"
    assert _rot(gen, d, "[AV-SIGNATUR]")


def test_07_historie_ohne_wirkung(gen, echt):
    """Die Zahl der historischen Abschluesse laesst sich nicht mehr nachrechnen."""
    d = copy.deepcopy(echt)
    d["inventory"]["progress_view"]["historical_closures"]["value"] = 99
    assert _rot(gen, d, "[FS-NEUABLEITUNG]")


def test_08_squash_oder_cherry_pick(gen, echt):
    """Der committete Beleg ist nicht mehr der committete Quellbereich."""
    d = copy.deepcopy(echt)
    d["records"][0]["measurement"]["second_reader"]["state"] = "DEVIATING"
    assert _rot(gen, d, "[ZL-ABWEICHEND]")


def test_09_fremder_laufzustand(gen, echt):
    """Die Messzeit kommt aus der Uhr dieses Laufs statt aus der Quelle."""
    d = copy.deepcopy(echt)
    d["times"]["measured"] = {"value": d["generated_at"], "source": "die Uhr des Laufs"}
    assert _rot(gen, d, "[ZT-UHR]")


def test_10_fehlerhafte_auslieferung(gen, echt):
    """Die ausgelieferten Bytes gelten als geprueft, ohne dass gesagt waere wogegen."""
    d = copy.deepcopy(echt)
    d["subject"]["content"] = {"state": "VERIFIED", "reason": "behauptet"}
    assert _rot(gen, d, "[SU-BINDUNG]")


def test_11_abbruch_oder_konkurrenz(gen, echt):
    """Ein Schnitt, der waehrend des Laufs zerriss: der Bereich ist umgedreht."""
    d = copy.deepcopy(echt)
    b = d["records"][0]["evidence"][0]
    b["byte_range"] = [b["byte_range"][1], b["byte_range"][0]]
    assert _rot(gen, d, "Bytebereich unmoeglich")


def test_12_fehlende_uebernahme(gen, echt):
    """Ein Datensatz ist revidiert und sagt nicht, was er abloest."""
    d = copy.deepcopy(echt)
    r = next((x for x in d["records"] if x.get("record_revision", 0)), None)
    if r is None:
        pytest.skip("kein revidierter Datensatz im Bestand")
    r.pop("supersedes", None)
    assert _rot(gen, d, "[SP-FEHLT]")


# ── Der Meta-Test ueber die Proben selbst ────────────────────────────────────────────────────

def test_99_alle_zwoelf_klassen_sind_abgedeckt():
    """[ZAEHLT] Punkt 2c nennt ZWOELF Klassen; fehlt eine, ist die Probenreihe unvollstaendig."""
    quelle = pathlib.Path(__file__).read_text(encoding="utf-8")
    nummern = {f"test_{i:02d}_" for i in range(1, 13)}
    fehlend = sorted(x for x in nummern if x not in quelle)
    assert not fehlend, f"Proben fehlen: {fehlend}"
