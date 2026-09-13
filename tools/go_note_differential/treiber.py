# -*- coding: utf-8 -*-
"""ECHTES Go-Differential: proofbundle gegen golang.org/x/mod/sumdb/note.Open, Fall fuer Fall.

Geltungsbereich, ausdruecklich: note.Open kennt nur Ed25519 (Algorithmusbyte 0x01). Dieser Lauf
misst deshalb den Ed25519-Arm des Korpus gegen das PRAEDIKAT "Rahmung kanonisch UND mindestens eine
Signatur eines bekannten Schluessels verifiziert" — dasselbe Praedikat wie
proofbundle.verify_checkpoint(...)["ok"] is True. Fuer ML-DSA-44 ist Go nicht zustaendig; dort bleibt
das Spezifikationsorakel aus Auflage A3 die Referenz.
"""
import base64
import json
import pathlib
import subprocess
import sys
import tempfile

W = str(pathlib.Path(__file__).resolve().parents[2])
GT = str(pathlib.Path(__file__).resolve().parent)
sys.path.insert(0, W + "/src")
sys.path.insert(0, W + "/tests")
from test_note_rahmung_kanonisch import _Aufbau, _impl_nimmt_an  # noqa: E402

a = _Aufbau()
faelle = a.faelle

# Fuer die Uebergabe: UTF-8 mit surrogatepass, damit auch der Surrogat-Fall echte Bytes bekommt,
# die Go dann als ungueltiges UTF-8 sieht — genau die Frage, die gestellt werden soll.
cases = []
for kennung, text in faelle:
    roh = text.encode("utf-8", "surrogatepass")
    cases.append({"id": kennung, "b64": base64.b64encode(roh).decode("ascii")})

ein = {"vkey": a.vkey, "cases": cases}
pfad = pathlib.Path(tempfile.mkdtemp()) / "cases.json"
pfad.write_text(json.dumps(ein), encoding="utf-8")

p = subprocess.run(["go", "run", ".", str(pfad)], cwd=GT,
                   capture_output=True, text=True)
if p.returncode != 0:
    print("GO-LAUF FEHLGESCHLAGEN, exit", p.returncode)
    print(p.stderr.strip())
    raise SystemExit(1)

go = {}
for zeile in p.stdout.splitlines():
    if not zeile.strip():
        continue
    teile = zeile.split("\t")
    go[teile[0]] = (teile[1], teile[2] if len(teile) > 2 else "")

print(f"{'Fall':34s} {'python.ok':>9s}  {'go.note.Open':>12s}  {'einig':>5s}  Go-Grund")
print("-" * 118)
einig = uneinig = 0
abweichungen = []
for kennung, text in faelle:
    py = _impl_nimmt_an(text, a.vkey)
    g_verdikt, g_grund = go.get(kennung, ("FEHLT", ""))
    g = (g_verdikt == "ACCEPT")
    ok = (py == g)
    einig += ok
    uneinig += (not ok)
    if not ok:
        abweichungen.append(kennung)
    print(f"{kennung:34s} {str(py):>9s}  {('ACCEPT' if g else 'REJECT'):>12s}  {'ja' if ok else 'NEIN':>5s}  {g_grund[:52]}")
print("-" * 118)
print(f"Faelle {len(faelle)} · einig {einig} · UNEINIG {uneinig}"
      + (f" -> {abweichungen}" if abweichungen else ""))
# Antiparitaet ausdruecklich
print(f"Antiparitaet: die ECHTE Note -> python.ok={_impl_nimmt_an(a.note, a.vkey)}, "
      f"go={go.get('echt', ('?',))[0]}")
raise SystemExit(0 if uneinig == 0 else 1)
