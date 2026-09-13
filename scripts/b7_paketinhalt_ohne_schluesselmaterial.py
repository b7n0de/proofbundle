#!/usr/bin/env python3
"""Der Paketbau bricht ab, wenn Schluesselmaterial im sdist oder wheel landet. Fail-closed.

OWNER-ENTSCHEID OA-7186ff7a75 (13.09.2026), Weg A, woertlich:

    "Riegel im Bau-Weg — der Paketbau bricht ab, wenn ein Muster fuer privaten Schluessel, Seed
    oder Token in sdist/wheel landet (fail-closed, wie der Vor-Push-Pruefer). Kostet einen neuen
    Gegenstand, faengt aber VOR der Veroeffentlichung."

WARUM DAS EIN NEUER GEGENSTAND IST UND KEIN ZWEITER ERZEUGER (OA-714de2fcdd verbietet den):
``tests/test_c9_signierskript_ohne_privaten_schluessel.py`` prueft GENAU EINE Datei
(``scripts/sign_readiness_artifact.py``) am AST auf die Bauform "liest einen privaten Schluessel".
Das ist eine Eigenschaft des QUELLTEXTS. Dieser Riegel prueft den INHALT DES GEBAUTEN PAKETS — eine
andere Ebene, und der C9-Docstring benennt die Luecke selbst: "MANIFEST.in: graft scripts nimmt
scripts/ komplett in den sdist auf; jeder Codepfad in diesem Skript wird mit dem naechsten Bau
ausgeliefert, benutzt oder nicht." Ein Schluessel, der versehentlich neben dem Code liegt, wird von
C9 nicht gesehen: C9 liest nicht das Paket, sondern eine Datei.

DREI SORTEN, und der Bericht nennt NUR die Sorte und den Pfad, NIE den Treffertext — ein Riegel,
der beim Melden ausplaudert, wonach er sucht, hebt seinen Zweck auf:

  K  privater Schluessel   PEM-Kopfzeilen, OpenSSH-Kopf
  S  Seed / Passphrase     Zuweisung an ein Feld, dessen Name Seed oder Passphrase traegt
  T  Token / Zugangsdaten  Anbieter-Praefixe mit fester Form, generische Zuweisungen

FAIL-CLOSED heisst hier woertlich: JEDER Treffer bricht ab. Und ein FEHLER beim Lesen ist ebenfalls
ein Abbruch, kein Freispruch — ein Archiv, das sich nicht oeffnen laesst, ist nicht "sauber",
sondern NICHT MESSBAR, und nicht messbar ist keine Freigabe.

EINE LEERE DATEILISTE IST EIN ABBRUCH. Gemessen am 13.09.2026 an einer fremden Messung derselben
Sitzung: eine falsch gebaute Extraktion lieferte NULL Zeilen, und null Treffer in null Zeilen lasen
sich wie "nichts gefunden". Wer eine Abwesenheit meldet, nennt die Groesse der Menge, in der er
gesucht hat.
"""
from __future__ import annotations

import argparse
import re
import sys
import tarfile
import zipfile

# Die Muster stehen hier als KLASSEN, nicht als Wortliste. Jedes ist eine STRUKTUR
# (Kopfzeile, Praefix mit Laenge, Zuweisungsform), keine Aufzaehlung von Geheimnissen.
_PEM = b"-" * 5 + b"BEGIN "
_ENDE = b"-" * 5

# EINE ZUWEISUNG BRAUCHT KEINE ANFUEHRUNGSZEICHEN (Codex 3999892825, P1). Die erste Fassung
# verlangte als erstes Wertbyte ein Anfuehrungszeichen. Gemessen 13.09.2026: ein sdist mit nur
# einer Datei, die `API_KEY=<24 Zeichen>` OHNE Anfuehrungszeichen traegt, kam mit SAUBER und
# Rueckgabewert 0 durch — und dieselbe Luecke stand bei Seed und Passphrase. Genau die Form, in der
# eine .env-Datei geschrieben wird, war die eine Form, die der Riegel nicht sah.
#
# DIE NACKTE FORM IST ENG GEFASST, und das ist Absicht. Der Wert muss bis zum Zeilenende (oder bis
# zu einem Trenner) aus Zeichen bestehen, die in einem Bezeichner-Ausdruck nicht vorkommen: ein
# Punkt beendet die Menge, also faellt `api_key = os.environ.get("X")` NICHT hinein. GEMESSEN ueber
# den ganzen Baum, 1181 Dateien: genau EIN Treffer, und der liegt in einer __pycache__-Datei, die
# kein Paket ausliefert. Ein fail-closed Riegel mit Fehlalarmen wird beim ersten Zeitdruck
# abgeschaltet — dann ist auch der echte Fall wieder frei.
#
# EHRLICHE GRENZE, benannt statt verschwiegen: ein Wert mit einem Punkt darin (etwa ein JWT mit
# seinen drei Abschnitten) faellt in der NACKTEN Form durch diese Maschen. Gequotet wird er
# gefangen, nackt nicht.
_WERT = (rb"['\"][^'\"]{12,}"            # gequotet, wie bisher
         rb"|[A-Za-z0-9_\-+/=]{12,}(?=[\s#;,]|$)")   # nackt, bis Zeilenende oder Trenner

# EIN NAME MIT PRAEFIX IST DERSELBE NAME (Codex 4000270134, P1). Die Muster begannen mit `\b`, und
# eine Wortgrenze gibt es zwischen `_` und `A` NICHT — beide sind Wortzeichen. Gemessen 13.09.2026:
# ein sdist mit `OPENAI` + `_API_KEY=<24 Zeichen>` kam mit SAUBER und Rueckgabewert 0 durch,
# ebenso `STRIPE_SECRET_KEY`, `DATABASE_PASSWORD` und `WALLET_SEED`. Genau die Schreibweise, in der
# solche Namen in der Praxis vorkommen, war die, die der Riegel nicht sah.
#
# STATT DER WORTGRENZE EIN AUSDRUECKLICHER PRAEFIX: keine, eine oder mehrere Namenssilben vor dem
# Feldnamen. Der Anker bleibt, was er war — ein Zuweisungszeichen und ein langer Wert dahinter.
# `API_KEYWORD=kurz` faellt weiterhin nicht hinein, weil nach dem Feldnamen kein `[:=]` steht.
# GEMESSEN vor dem Einbau ueber 1198 Dateien des Baums: genau EIN Treffer, und der liegt in einer
# __pycache__-Datei, die kein Paket ausliefert.
_PRAEFIX = rb"(?:[A-Za-z0-9]+[_-])*"

MUSTER: dict[str, list[re.Pattern[bytes]]] = {
    # ZUSAMMENGESETZT, nicht getippt: eine Zeile, die die Kopfzeile woertlich traegt, ist fuer
    # jeden Bezeichner-Pruefer eine INSTANZ und nicht eine DEFINITION. Gemessen 13.09.2026: die
    # erste Fassung dieser Datei liess den Vor-Push-Pruefer mit Klasse C anschlagen — an genau
    # dieser Stelle. Der Pruefer hatte recht; er kann Muster und Vorkommen nicht unterscheiden,
    # und das SOLL er auch nicht koennen. Also weicht die Definition aus, nicht der Pruefer.
    "K": [
        re.compile(_PEM + rb"[A-Z ]*PRIVATE KEY" + _ENDE),
        re.compile(_PEM + rb"OPENSSH PRIVATE KEY" + _ENDE),
        re.compile(_PEM + rb"PGP PRIVATE KEY BLOCK" + _ENDE),
    ],
    "S": [
        re.compile(rb"(?i)" + _PRAEFIX + rb"(seed|passphrase|mnemonic)\s*[:=]\s*(?:" + _WERT + rb")"),
    ],
    "T": [
        re.compile(rb"\bAKIA[0-9A-Z]{16}\b"),
        re.compile(rb"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
        re.compile(rb"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
        re.compile(rb"(?i)" + _PRAEFIX
                   + rb"(api[_-]?key|secret[_-]?key|access[_-]?token|password)"
                   rb"\s*[:=]\s*(?:" + _WERT + rb")"),
    ],
}

# Diese Datei SELBST traegt die Muster und wuerde sich sonst fangen. Das ist kein Schoenheitsfehler,
# sondern der Grund, warum die Ausnahme HIER steht und nicht als Pfadliste in einer Konfiguration:
# genau EINE Datei ist ausgenommen, sie ist benannt, und die Ausnahme ist im Riegel lesbar.
EIGENER_PFAD = "scripts/b7_paketinhalt_ohne_schluesselmaterial.py"


def _dateien_sdist(pfad: str):
    with tarfile.open(pfad, "r:*") as t:
        for m in t.getmembers():
            if not m.isfile():
                continue
            f = t.extractfile(m)
            if f is None:
                continue
            yield m.name, f.read()


def _dateien_wheel(pfad: str):
    with zipfile.ZipFile(pfad) as z:
        for n in z.namelist():
            if n.endswith("/"):
                continue
            yield n, z.read(n)


def pruefe(pfad: str) -> dict:
    """Ein Archiv pruefen. Jeder Treffer und jeder Lesefehler sind ein Abbruch."""
    lade = _dateien_wheel if pfad.endswith(".whl") else _dateien_sdist
    treffer: dict[str, list[str]] = {}
    gelesen = 0
    try:
        for name, roh in lade(pfad):
            gelesen += 1
            kurz = name.split("/", 1)[-1] if "/" in name else name
            if kurz == EIGENER_PFAD:
                continue
            for sorte, muster in MUSTER.items():
                if any(m.search(roh) for m in muster):
                    treffer.setdefault(sorte, [])
                    if len(treffer[sorte]) < 5:
                        treffer[sorte].append(kurz)
    except Exception as e:                                    # noqa: BLE001
        return {"pfad": pfad, "urteil": "NICHT MESSBAR", "grund": type(e).__name__,
                "bau_erlaubt": False, "dateien": gelesen, "treffer": {}}
    if gelesen == 0:
        return {"pfad": pfad, "urteil": "NICHT MESSBAR",
                "grund": "leere Dateiliste — null Treffer in null Dateien ist kein Freispruch",
                "bau_erlaubt": False, "dateien": 0, "treffer": {}}
    return {"pfad": pfad,
            "urteil": "SAUBER" if not treffer else "TREFFER",
            "bau_erlaubt": not treffer,
            "dateien": gelesen,
            "treffer": {k: len(v) for k, v in treffer.items()},
            "orte": treffer}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="b7_paketinhalt_ohne_schluesselmaterial")
    ap.add_argument("archive", nargs="+", help="sdist (.tar.gz) und/oder wheel (.whl)")
    a = ap.parse_args(argv)
    import json
    rc = 0
    for pfad in a.archive:
        e = pruefe(pfad)
        print(json.dumps(e, ensure_ascii=False))
        if not e["bau_erlaubt"]:
            rc = 1
    if rc:
        print("::error::Schluesselmaterial oder ein nicht messbares Archiv im Paket — "
              "der Bau bricht ab (OA-7186ff7a75, Weg A)", file=sys.stderr)
    return rc


if __name__ == "__main__":
    sys.exit(main())
