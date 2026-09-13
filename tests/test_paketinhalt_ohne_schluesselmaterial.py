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
    """KEINE Ausnahme mehr, sondern eine EIGENSCHAFT — und das ist der Unterschied.

    Die frueherere Fassung nahm diese eine Datei ganz vom Scan aus, weil sie die Muster traegt und
    sich zu fangen SCHIEN. GEMESSEN 14.09.2026 ueber die eigene Quelle: null Treffer in allen drei
    Sorten. Die Definitionen sind zusammengesetzt und die Token-Muster sind Regexe, keine Vorkommen.
    Die Verteidigung wurde also nie gebraucht — und seit MANIFEST.in die Datei ausliefert, war sie
    ein Loch. Dieser Fall haelt fest, dass sie unnoetig BLEIBT: wer ein Muster kuenftig als LITERAL
    schreibt, faellt hier und nicht erst beim Nutzer.
    """
    eigen = (HIER.parent / "scripts" / "b7_paketinhalt_ohne_schluesselmaterial.py").read_bytes()
    for sorte, muster in riegel.MUSTER.items():
        treffend = [m.pattern[:60] for m in muster if m.search(eigen)]
        assert not treffend, (
            f"die Quelle des Riegels trifft ihr eigenes Muster der Sorte {sorte}: {treffend} — "
            "dann muss die Definition ausweichen (zusammensetzen), nicht der Riegel")
    e = riegel.pruefe(_sdist(tmp_path, {"scripts/b7_paketinhalt_ohne_schluesselmaterial.py": eigen, "src/a.py": b"x=1\n"}))
    assert e["bau_erlaubt"] is True, "die eigene Quelle ist sauber, also darf der Bau laufen"


def test_ein_zugangsdatum_IN_der_riegeldatei_wird_gefunden(tmp_path):
    """Der Ruecknahme-Nachweis fuer die entfernte Ausnahme, und der Fall, den sie verdeckte.

    MANIFEST.in liefert diese Datei ausdruecklich aus. Mit der alten Ganzdatei-Ausnahme kam ein hier
    abgelegtes Zugangsdatum an einem Riegel vorbei, dessen erklaerte Eigenschaft "JEDER Treffer
    bricht ab" lautet. Gefunden von der Codex-Runde eins an PR 200.
    """
    eigen = (HIER.parent / "scripts" / "b7_paketinhalt_ohne_schluesselmaterial.py").read_bytes()
    vergiftet = eigen + b"\n# " + b"AKIA" + b"B" * 16 + b"\n"
    e = riegel.pruefe(_sdist(tmp_path, {"scripts/b7_paketinhalt_ohne_schluesselmaterial.py": vergiftet, "src/a.py": b"x=1\n"}))
    assert e["bau_erlaubt"] is False and "T" in e["treffer"], (
        "ein Zugangsdatum in der Riegeldatei selbst muss den Bau abbrechen wie ueberall sonst")


def test_ein_feingranulares_github_token_wird_gefunden(tmp_path):
    """Seit 2022 die zweite und heute empfohlene Form. Die Aufzaehlung kannte nur `gh[pousr]_`."""
    last = b"github" + b"_pat_" + b"A" * 82 + b"\n"
    e = riegel.pruefe(_sdist(tmp_path, {"deploy/env.txt": last}))
    assert e["bau_erlaubt"] is False and "T" in e["treffer"]


def test_ein_benanntes_privates_schluesselfeld_wird_gefunden(tmp_path):
    """Die Sorte K faengt die PEM-RAHMUNG. Dasselbe Material ohne Rahmen, als benanntes Feld, lief
    durch — obwohl diese Datei den privaten Schluessel als ihre Grenze fuehrt."""
    last = b"SIGNING_PRIVATE" + b"_KEY=" + b"c" * 44 + b"\n"
    e = riegel.pruefe(_sdist(tmp_path, {"conf/settings.py": last}))
    assert e["bau_erlaubt"] is False and "T" in e["treffer"]


def test_ANTI_die_drei_neuen_muster_machen_keinen_fehlalarm(tmp_path):
    """Gegenrichtung: gewoehnlicher Code mit denselben WOERTERN, aber ohne Wert, bleibt gruen."""
    harmlos = (b"# der Ablauf liest github_pat aus der Umgebung\n"
               b"private_key_path = os.environ['KEY_PATH']\n"
               b"def lies_private_key(pfad):\n    return pfad\n")
    e = riegel.pruefe(_sdist(tmp_path, {"src/a.py": harmlos}))
    assert e["urteil"] == "SAUBER" and e["bau_erlaubt"] is True


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


# ── EIN NAME MIT PRAEFIX IST DERSELBE NAME (Codex 4000270134, P1) ──────────────────────────
#
# Die Muster begannen mit `\b`, und eine Wortgrenze gibt es zwischen `_` und `A` NICHT — beide sind
# Wortzeichen. GEMESSEN: ein sdist mit `OPENAI` + `_API_KEY=<24 Zeichen>` kam mit SAUBER und
# Rueckgabewert 0 durch, ebenso `STRIPE_SECRET_KEY`, `DATABASE_PASSWORD` und `WALLET_SEED`. Genau
# die Schreibweise, in der solche Namen in der Praxis vorkommen, war die, die der Riegel nicht sah.
#
# DIE KLASSE, zum zweiten Mal an derselben Datei: eine Formvorgabe am Muster (erst das
# Anfuehrungszeichen im Wert, jetzt die Wortgrenze im Namen) schliesst die haeufigste Gestalt aus.
# Beide Male sah der Riegel die kuenstliche Form und uebersah die echte.

_PRAEFIX_ROT = {
    "anbieter vor api-key":   b"OPENAI_" + b"API_KEY=" + _W + b"\n",
    "anbieter vor secret":    b"STRIPE_" + b"SECRET_KEY=" + _W + b"\n",
    "dienst vor password":    b"DATABASE_" + b"PASS" + b"WORD=" + _W + b"\n",
    "dienst vor seed":        b"WALLET_" + b"SE" + b"ED=" + _W + b"\n",
    "zwei silben praefix":    b"MY_APP_" + b"API_KEY=" + _W + b"\n",
    "praefix und gequotet":   b"OPENAI_" + b'API_KEY="' + _W + b'"\n',
}

_PRAEFIX_GRUEN = {
    "umgebungsabfrage":  b"openai_" + b"api_key = os.environ.get(\"X\")\n",
    "attributkette":     b"db_" + b"pass" + b"word = settings.default_value_here\n",
    "kurzer wert":       b"OPENAI_" + b"API_KEY=kurz\n",
    "KEYWORD ist kein Feld": b"API" + b"_KEYWORD=" + _W + b"\n",
}


@pytest.mark.parametrize("titel", sorted(_PRAEFIX_ROT))
def test_ein_praefixierter_name_bricht_den_bau_ab(tmp_path, titel):
    """[ZAEHLT] Der Fund selbst, in den vier Gestalten, die der Bericht nennt, plus zwei."""
    e = riegel.pruefe(_sdist(tmp_path, {".env": _PRAEFIX_ROT[titel]}))
    assert e["bau_erlaubt"] is False, f"{titel}: {e}"


@pytest.mark.parametrize("titel", sorted(_PRAEFIX_GRUEN))
def test_ANTI_der_praefix_macht_keinen_fehlalarm(tmp_path, titel):
    """[ZAEHLT] Gegenrichtung. `API_KEYWORD=` ist der Fall, der die Grenze zeigt.

    Nach dem Feldnamen steht dort kein Zuweisungszeichen, sondern weiterer Name — der Anker haelt.
    GEMESSEN ueber den ganzen Baum, 1198 Dateien: ein einziger Treffer, in einer __pycache__-Datei,
    die kein Paket ausliefert.
    """
    e = riegel.pruefe(_sdist(tmp_path, {"m.py": _PRAEFIX_GRUEN[titel]}))
    assert e["bau_erlaubt"] is True, f"{titel} ist ein Fehlalarm: {e}"
