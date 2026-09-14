"""Punkt 2d: DER EINE vollstaendige Fall, nachgefahren statt geglaubt.

"r3999283100 (PR 197, Fix 8373204), vom Fund ueber Reproduktion, Reparatur, aktuelle Geltung,
Belegpruefung nach 2a, nachgelesene Antwort bis zur Uebernahme in die Registersicht durch den
zustaendigen Schreiber (Publisher, E3), dann Mengenabgleich. Erst wenn dieser Weg steht, weitere
Faelle."

WAS HIER GEPRUEFT WIRD: die Glieder, die OHNE Netz nachrechenbar sind — Commit, Vorfahrenschaft,
Dateiinhalt und die Reproduktion. Die Glieder, die an GitHub haengen (Kommentartext, Autor),
tragen im Traeger ihre Herkunft und werden hier NICHT nachgeholt; ein Vertrag, der Netz braucht,
ist offline kein Vertrag und meldet dann faelschlich rot.

DIE REPRODUKTION IST DAS HERZ. Der Fund behauptet eine Zahl und einen Testnamen. Wer das nur
zitiert, hat die Kette an ihrer wichtigsten Stelle nicht angefasst.
"""
from __future__ import annotations

import json
import pathlib
import subprocess

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
FALL = REPO / "audit_artifacts/600/vollstaendiger_fall_r3999283100.json"

pytestmark = pytest.mark.skipif(not FALL.is_file(), reason="der Fall liegt in diesem Baum nicht vor")


@pytest.fixture(scope="module")
def fall():
    return json.loads(FALL.read_text(encoding="utf-8"))


def test_die_reparatur_ist_der_genannte_commit(fall):
    r = fall["3_reparatur"]
    aus = subprocess.run(["git", "-C", str(REPO), "log", "-1", "--format=%H%n%s", r["commit"]],
                         capture_output=True, text=True)
    assert aus.returncode == 0, "der Reparatur-Commit ist nicht auffindbar"
    sha, titel = aus.stdout.strip().splitlines()[:2]
    assert sha == r["commit"] and titel == r["titel"]


def test_die_reparatur_gilt_heute_noch(fall):
    """Vorfahrenschaft UND Wortlaut — eine Reparatur, die zurueckgerollt wurde, gilt nicht."""
    g = fall["4_aktuelle_geltung"]
    vor = subprocess.run(["git", "-C", str(REPO), "merge-base", "--is-ancestor",
                          fall["3_reparatur"]["commit"], "origin/main"], capture_output=True)
    assert (vor.returncode == 0) == g["auf_origin_main"]
    text = (REPO / fall["3_reparatur"]["datei"]).read_text(encoding="utf-8")
    assert ("Skipped unless `tools/pb_verify_rs` has been cargo-built" in text) == \
        g["text_steht_noch"]


def test_die_reproduktion_laesst_sich_nachfahren(fall):
    """[ZAEHLT] Die Zahl UND der Name des uebersprungenen Tests, beides neu gemessen."""
    import re
    r = fall["2_reproduktion"]
    aus = subprocess.run(
        # WOMIT gemessen wird, ist Teil der Messung: derselbe Interpreter, der diesen Test
        # faehrt. "python" waere das, was PATH gerade dafuer haelt.
        [__import__("sys").executable, "-m", "pytest", "-rs", "-v",
         # GEMESSEN, nicht angenommen: `-q` und `-v` zaehlen am SELBEN Schalter und heben
         # sich auf; bei Netto-Null druckt pytest keine Test-Ids. Mit `-q -rs -v` gab es
         # NULL Treffer auf den Testnamen, mit `-rs -v` steht er. Und: die zwei Versuche
         # davor waren STILLE Fehlschlaege — `str.replace` ohne Trefferpruefung aendert
         # nichts und sagt es nicht.
         "tests/test_relation_statement_rust_parity.py", "tests/test_rust_parity_gate.py"],
        capture_output=True, text=True, cwd=str(REPO),
        env={**__import__("os").environ, "PYTHONPATH": "src"})
    m = re.search(r"(\d+) passed, (\d+) skipped", aus.stdout)
    assert m, f"keine Zusammenfassungszeile: {aus.stdout[-300:]}"
    passed, skipped = int(m.group(1)), int(m.group(2))
    assert passed == r["selbst_gemessen"]["passed"], (passed, r["selbst_gemessen"]["passed"])
    assert skipped == r["selbst_gemessen"]["skipped"]
    # DER NAME STEHT NICHT IN DER `-rs`-ZEILE. Die erste Fassung suchte ihn dort und wurde rot:
    # `-rs` druckt `SKIPPED [1] datei.py:25: grund` — Datei, Zeile und Grund, keinen Testnamen.
    # Mit `-v` steht die Test-Id je Zeile, und DANN ist der Name messbar. Wer die Ausgabe eines
    # Werkzeugs nach einem Wort absucht, muss wissen, welches Wort es ueberhaupt druckt.
    assert r["selbst_gemessen"]["skip"] in aus.stdout, \
        f"der uebersprungene Test heisst anders: {aus.stdout[-400:]}"
    assert r["selbst_gemessen"]["skip_grund"].split("(")[0].strip() in aus.stdout


def test_der_fall_sagt_was_die_reproduktion_NICHT_zeigt(fall):
    """Die Zahlen stimmen — Uebereinstimmung misst genau der Test, der uebersprungen wird."""
    assert "dass Python und Rust uebereinstimmen" in fall["2_reproduktion"]["was_das_nicht_zeigt"]


def test_die_belegpruefung_nennt_je_bedingung_einen_grund(fall):
    p = fall["5_belegpruefung_nach_2a"]
    bedingungen = [k for k in p if k[0].isdigit()]
    assert len(bedingungen) == 6, bedingungen
    for k in bedingungen:
        assert isinstance(p[k]["haelt"], bool) and p[k].get("warum"), k
    # Die Zahl im Text wird GEGEN die Eintraege gerechnet, nicht festgeschrieben — die erste
    # Fassung dieses Falls sagte 2 und hatte 3; genau das soll hier auffallen.
    n = sum(1 for k in bedingungen if p[k]["haelt"])
    assert p["summe"].startswith(f"{n} von 6"), (n, p["summe"][:30])


def test_die_uebernahme_ist_fremde_bahn_und_sagt_es(fall):
    u = fall["7_uebernahme_in_die_registersicht"]
    assert u["im_register"] is False
    assert u["state"] == "NOT APPLICABLE"
    # KLEINSCHREIBUNG GEMESSEN, nicht angenommen: der Traeger schreibt "NICHT meine Bahn".
    assert "E3" in u["warum"] and "nicht meine bahn" in u["warum"].lower()


def test_jedes_glied_traegt_einen_zustand_oder_eine_summe(fall):
    glieder = [k for k in fall if k[0].isdigit()]
    assert len(glieder) == 8, sorted(glieder)
    for k in glieder:
        v = fall[k]
        assert v.get("state") or v.get("summe") or v.get("warum"), k
