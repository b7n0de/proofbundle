"""Der Konformitaets-Korpus muss aus seinem Generator reproduzierbar sein.

GEMESSEN am 01.09.2026, und beides ist wirklich passiert:

1. Der Fall `agent-review-positive-control-emit-verify-roundtrip` wurde am selben Tag von Hand
   angelegt. Er lag danach auf der Platte UND im Manifest, aber NICHT im Generator — ein Neulauf
   haette ihn nicht erzeugt.
2. Der K-D-Fix (die fehlende `expectedSubjectDigest`-Erwartung in
   `agent-review-counter-proof-findings-root-covers-the-list`) wurde ebenfalls von Hand am
   ERZEUGTEN Artefakt gemacht. Der erste Neulauf des Generators hat ihn STILL GELOESCHT. Nichts
   hat es gemeldet; aufgefallen ist es nur, weil danach ein Vergleich gegen eine Sicherung lief.

DIE KLASSE ist nicht "ein Fall fehlte", sondern: **eine Aenderung am erzeugten Artefakt statt an
seiner Quelle ist unsichtbar und wird beim naechsten Lauf verworfen.** Ein Korpus, der seine
Quelle nicht mehr abbildet, ist kein Korpus, sondern ein Stand.

Der Test erzeugt den Korpus NEBEN den echten (`AGENT_REVIEW_CORPUS_ROOT`) und vergleicht
bytegenau. Er fasst den echten Korpus nicht an — ein Pruefwerkzeug, das seinen Prueflig
ueberschreibt, ist selbst die naechste stille Loeschung.
"""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
KORPUS = REPO / "conformance" / "agent_review"
GENERATOR = KORPUS / "_generator" / "build_vectors.py"


def _erzeuge_daneben(ziel: pathlib.Path) -> None:
    umgebung = dict(os.environ, AGENT_REVIEW_CORPUS_ROOT=str(ziel))
    p = subprocess.run([sys.executable, str(GENERATOR)], cwd=REPO, env=umgebung,
                       capture_output=True, text=True, timeout=300)
    assert p.returncode == 0, f"Generator rc={p.returncode}\n{p.stdout}\n{p.stderr}"


def _dateien(wurzel: pathlib.Path) -> dict[str, bytes]:
    return {str(f.relative_to(wurzel)): f.read_bytes()
            for f in sorted(wurzel.rglob("*")) if f.is_file() and "_generator" not in f.parts}


@pytest.fixture(scope="module")
def frisch(tmp_path_factory):
    if not GENERATOR.is_file():
        pytest.skip("Generator liegt nicht vor (sdist ohne _generator)")
    ziel = tmp_path_factory.mktemp("korpus")
    _erzeuge_daneben(ziel)
    return ziel


def test_der_generator_schreibt_wirklich_woandershin(frisch):
    """Ohne das misst der Vergleich unten sich selbst — und ueberschriebe nebenbei den Korpus."""
    assert (frisch / "publickey.hex").is_file(), "der Generator hat das Ziel nicht benutzt"
    assert frisch.resolve() != KORPUS.resolve()


def test_jeder_fall_auf_der_platte_stammt_aus_dem_generator(frisch):
    auf_platte = {d.name for d in KORPUS.iterdir() if (d / "case.json").is_file()}
    erzeugt = {d.name for d in frisch.iterdir() if (d / "case.json").is_file()}
    assert auf_platte, "kein Fall gefunden — der Test saehe nichts"
    nur_platte = sorted(auf_platte - erzeugt)
    assert not nur_platte, (
        f"von Hand angelegt, nicht im Generator: {nur_platte} — ein Neulauf wuerde sie nicht "
        f"erzeugen, und der Korpus bildet seine Quelle nicht mehr ab")


def test_der_korpus_ist_bytegenau_das_was_der_generator_erzeugt(frisch):
    ist, soll = _dateien(KORPUS), _dateien(frisch)
    gemeinsam = sorted(set(ist) & set(soll))
    assert gemeinsam, "keine gemeinsame Datei — der Vergleich saehe nichts"
    abweichend = [n for n in gemeinsam if ist[n] != soll[n]]
    assert not abweichend, (
        f"von Hand geaendert statt an der Quelle: {abweichend} — der naechste Generatorlauf "
        f"verwirft diese Aenderung stillschweigend")


def test_das_manifest_nennt_genau_die_faelle_die_es_gibt():
    manifest = json.loads((REPO / "conformance" / "manifest.json").read_text(encoding="utf-8"))
    genannt = {c.split("/", 1)[1] for c in manifest.get("cases", []) if c.startswith("agent_review/")}
    auf_platte = {d.name for d in KORPUS.iterdir() if (d / "case.json").is_file()}
    assert genannt, "das Manifest nennt keinen agent_review-Fall — der Test saehe nichts"
    assert genannt == auf_platte, (
        f"nur im Manifest: {sorted(genannt - auf_platte)} · "
        f"nur auf der Platte: {sorted(auf_platte - genannt)} — ein Fall, den das Manifest nicht "
        f"nennt, wird nie ausgefuehrt")
