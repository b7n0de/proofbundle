"""Fangnachweis fuer den Paket-Riegel, BEIDE Richtungen (OA-7186ff7a75, Weg A).

Ein Riegel, der nur in der freigebenden Richtung gemessen ist, ist von einem kaputten Riegel nicht
zu unterscheiden: er sagt immer gruen. Deshalb steht hier je Sorte ein ROTER Fall UND ein gruener
Gegenfall, und dazu die zwei Faelle, die ein Freispruch aus Nichtmessung waeren.

ANGESAGT, bevor der Lauf faehrt:
  sauberes Archiv                 -> gruen
  privater Schluessel (K)         -> ROT
  Seed-Zuweisung (S)              -> ROT
  Token-Praefix (T)               -> ROT
  leeres Archiv                   -> ROT (NICHT MESSBAR, kein Freispruch)
  kaputtes Archiv                 -> ROT (NICHT MESSBAR, kein Freispruch)
  Riegel prueft sich selbst nicht -> gruen (die eine benannte Ausnahme)
"""
from __future__ import annotations

import importlib.util
import pathlib
import tarfile
import zipfile

HIER = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location(
    "paketriegel", HIER.parent / "scripts" / "b7_paketinhalt_ohne_schluesselmaterial.py")
riegel = importlib.util.module_from_spec(spec)
spec.loader.exec_module(riegel)

# Die roten Lasten werden ZUSAMMENGESETZT, nie als ganzer String getippt — sonst traegt diese
# Testdatei selbst ein Muster, und der Riegel wuerde sie im naechsten sdist fangen.
LAST_K = b"-----BEGIN " + b"PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIA\n-----END PRIVATE KEY-----\n"
LAST_S = b'seed = "' + b"x" * 20 + b'"\n'
LAST_T = b"AKIA" + b"A" * 16 + b"\n"


def _sdist(tmp_path, dateien: dict[str, bytes]) -> str:
    p = tmp_path / "paket-1.0.0.tar.gz"
    with tarfile.open(p, "w:gz") as t:
        for name, roh in dateien.items():
            info = tarfile.TarInfo(f"paket-1.0.0/{name}")
            info.size = len(roh)
            t.addfile(info, __import__("io").BytesIO(roh))
    return str(p)


def test_sauberes_archiv_ist_gruen(tmp_path):
    e = riegel.pruefe(_sdist(tmp_path, {"src/a.py": b"print('hallo')\n", "README.md": b"# paket\n"}))
    assert e["urteil"] == "SAUBER" and e["bau_erlaubt"] is True
    assert e["dateien"] == 2, "die Groesse der gesuchten Menge gehoert ins Urteil"


def test_privater_schluessel_ist_rot(tmp_path):
    e = riegel.pruefe(_sdist(tmp_path, {"src/a.py": b"x=1\n", "misc/key.pem": LAST_K}))
    assert e["bau_erlaubt"] is False and "K" in e["treffer"]


def test_seed_zuweisung_ist_rot(tmp_path):
    e = riegel.pruefe(_sdist(tmp_path, {"conf/settings.py": LAST_S}))
    assert e["bau_erlaubt"] is False and "S" in e["treffer"]


def test_token_praefix_ist_rot(tmp_path):
    e = riegel.pruefe(_sdist(tmp_path, {"deploy/env.txt": LAST_T}))
    assert e["bau_erlaubt"] is False and "T" in e["treffer"]


def test_leeres_archiv_ist_nicht_messbar_und_nicht_frei(tmp_path):
    """Null Treffer in null Dateien ist KEIN Freispruch — gemessen 13.09.2026 an einem echten Fall."""
    e = riegel.pruefe(_sdist(tmp_path, {}))
    assert e["urteil"] == "NICHT MESSBAR" and e["bau_erlaubt"] is False


def test_kaputtes_archiv_ist_nicht_messbar_und_nicht_frei(tmp_path):
    p = tmp_path / "kaputt.tar.gz"
    p.write_bytes(b"das ist kein gzip")
    e = riegel.pruefe(str(p))
    assert e["urteil"] == "NICHT MESSBAR" and e["bau_erlaubt"] is False


def test_der_riegel_faengt_sich_nicht_selbst(tmp_path):
    """Die eine benannte Ausnahme: die Musterdatei selbst traegt die Muster."""
    eigen = (HIER.parent / "scripts" / "b7_paketinhalt_ohne_schluesselmaterial.py").read_bytes()
    e = riegel.pruefe(_sdist(tmp_path, {riegel.EIGENER_PFAD: eigen, "src/a.py": b"x=1\n"}))
    assert e["bau_erlaubt"] is True, "die Ausnahme gilt genau fuer diese eine Datei"


def test_wheel_wird_genauso_geprueft(tmp_path):
    p = tmp_path / "paket-1.0.0-py3-none-any.whl"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("paket/a.py", b"x=1\n")
        z.writestr("paket/leak.pem", LAST_K)
    e = riegel.pruefe(str(p))
    assert e["bau_erlaubt"] is False and "K" in e["treffer"]
