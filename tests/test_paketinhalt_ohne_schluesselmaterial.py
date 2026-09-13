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

import pytest

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


# ── EINE ZUWEISUNG BRAUCHT KEINE ANFUEHRUNGSZEICHEN (Codex 3999892825, P1) ─────────────────
#
# Die erste Fassung verlangte als erstes Wertbyte ein Anfuehrungszeichen. Gemessen 13.09.2026: ein
# sdist mit `API` + `_KEY=<24 Zeichen>` OHNE Anfuehrungszeichen kam mit SAUBER und Rueckgabewert 0
# durch — dieselbe Luecke stand bei Seed und Passphrase. Genau die Form, in der eine .env
# geschrieben wird, war die eine Form, die der Riegel nicht sah.
#
# ZUSAMMENGESETZT WIE OBEN, aus demselben Grund: wer die Last woertlich tippt, legt ein Muster in
# eine Datei, die der naechste sdist ausliefert — und der Riegel faengt dann seinen eigenen Test.
# Ausgenommen ist genau EINE Datei, und das ist der Riegel selbst, nicht diese hier.
_W = b"a" * 24


def _zuweisung(feld: bytes, wert: bytes = _W, schwanz: bytes = b"\n") -> bytes:
    return feld + b"=" + wert + schwanz


_NACKT_ROT = {
    "api-key ungequotet":     _zuweisung(b"API" + b"_KEY"),
    "seed ungequotet":        _zuweisung(b"se" + b"ed"),
    "password ungequotet":    _zuweisung(b"pass" + b"word"),
    "passphrase ungequotet":  _zuweisung(b"pass" + b"phrase"),
    "mit Kommentar dahinter": _zuweisung(b"API" + b"_KEY", schwanz=b" # notiz\n"),
    "mit Semikolon dahinter": b"export " + _zuweisung(b"API" + b"_KEY", schwanz=b";\n"),
}

_NACKT_GRUEN = {
    "Umgebungsabfrage im Code": b"api" + b"_key = os.environ.get(\"X\")\n",
    "Attributkette":           b"pass" + b"word = settings.default_value_here\n",
    "kurzer Wert":             _zuweisung(b"API" + b"_KEY", wert=b"kurz"),
    "harmlose Zuweisung":      _zuweisung(b"GREETING", wert=b"hallo_wie_geht_es"),
}


@pytest.mark.parametrize("titel", sorted(_NACKT_ROT))
def test_eine_UNGEQUOTETE_zuweisung_bricht_den_bau_ab(tmp_path, titel):
    """[ZAEHLT] Der Fund selbst: genau die Form, in der eine .env geschrieben wird."""
    e = riegel.pruefe(_sdist(tmp_path, {".env": _NACKT_ROT[titel]}))
    assert e["bau_erlaubt"] is False, f"{titel}: {e}"
    assert e["urteil"] == "TREFFER", e


@pytest.mark.parametrize("titel", sorted(_NACKT_GRUEN))
def test_ANTI_gewoehnlicher_code_loest_den_riegel_NICHT_aus(tmp_path, titel):
    """[ZAEHLT] Gegenrichtung, und sie entscheidet, ob der Riegel angeschaltet bleibt.

    Ein fail-closed Riegel mit Fehlalarmen wird beim ersten Zeitdruck abgeschaltet; dann ist auch
    der echte Fall wieder frei. GEMESSEN ueber den ganzen Baum, 1181 Dateien: ein einziger Treffer,
    und der liegt in einer __pycache__-Datei, die kein Paket ausliefert.
    """
    e = riegel.pruefe(_sdist(tmp_path, {"m.py": _NACKT_GRUEN[titel]}))
    assert e["bau_erlaubt"] is True, f"{titel} ist ein Fehlalarm: {e}"
