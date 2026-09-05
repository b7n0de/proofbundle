"""Das ECHTE Differential gegen die Referenz: golang.org/x/mod/sumdb/note.Open, Fall fuer Fall.

WARUM DAS HIER STEHT UND NICHT NUR IM BERICHT. ``tests/test_note_rahmung_kanonisch.py`` misst gegen ein
aus der Spezifikation NEU GESCHRIEBENES Orakel. Das ist ein starkes Orakel, aber es ist MEINE Lesart der
Spezifikation: haette ich ``note.Open`` an derselben Stelle falsch verstanden wie die Implementierung,
haetten sich zwei Fehler in dieselbe Richtung aufgehoben und das Differential haette nichts gesehen.
Dieser Test ersetzt die Lesart durch die Referenz selbst.

DASS DIESE SORGE BERECHTIGT WAR, IST GEMESSEN. Der Reproducer des Gates trug eine eigene, KURZE
Python-Nachbildung von ``note.Open`` (Feld ``go_reference``) — sie prueft nur die Rahmung. Gegen echtes
Go gefahren war sie auf 7 von 66 Faellen ZU MILD: ``steuerzeichen-in-zusatzzeile``,
``surrogat-in-zusatzzeile``, ``junk-hinter-em-dash``, ``leerer-name``, ``plus-im-namen``,
``nutzlast-zu-kurz``, ``leere-nutzlast`` haette sie angenommen, echtes Go nennt alle sieben
``malformed note``. Genau diese sieben sind die Regeln, die ueber die Rahmung hinausgehen (Steuerzeichen,
Surrogate, Zeilensyntax). Wer die Nachbildung fuer die Referenz haelt, laesst sie offen.

GELTUNGSBEREICH, ausdruecklich und eng: ``note.Open`` kennt NUR Ed25519 (Algorithmusbyte 0x01). Dieser
Test misst deshalb ausschliesslich den Ed25519-Arm des Korpus, gegen das Praedikat "Rahmung kanonisch
UND mindestens eine Signatur eines bekannten Schluessels verifiziert" — dasselbe Praedikat wie
``verify_checkpoint(...)["ok"] is True``. Fuer ML-DSA-44 (0x06) ist Go NICHT zustaendig; dort bleibt das
Spezifikations-Orakel in ``test_note_rahmung_kanonisch.py`` die Referenz, und dieser Test behauptet
darueber nichts.

WANN ER LAEUFT: nur wenn eine Go-Toolchain erreichbar ist (``$PB_GO_BIN`` oder ``go`` im PATH) UND der
Modul-Cache ``golang.org/x/mod`` schon hat oder geholt werden kann. Sonst SKIP mit Begruendung — nie ein
stilles Gruen. Gemessen am 2026-09-05 mit go1.27.1 linux/amd64 und golang.org/x/mod v0.29.0:
66 Faelle, 66 einig, 0 uneinig.
"""
from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from proofbundle import checkpoint as cp
from proofbundle.errors import ProofBundleError

GO_DIR = Path(__file__).resolve().parent.parent / "tools" / "go_note_differential"


def _go_bin() -> "str | None":
    kandidat = os.environ.get("PB_GO_BIN") or shutil.which("go")
    return kandidat if kandidat and os.access(kandidat, os.X_OK) else None


def _impl_nimmt_an(note: str, vkey: str) -> bool:
    try:
        return cp.verify_checkpoint(note, vkey)["ok"] is True
    except ProofBundleError:
        return False


@unittest.skipUnless(GO_DIR.is_dir(), "tools/go_note_differential fehlt")
class DasEchteGoDifferential(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.go = _go_bin()
        if not cls.go:
            raise unittest.SkipTest(
                "keine Go-Toolchain (weder $PB_GO_BIN noch `go` im PATH) — das Differential gegen "
                "note.Open kann nicht gefahren werden; der Spezifikations-Orakel-Test laeuft weiter")
        # Der Korpus kommt aus DEMSELBEN Generator wie das Spezifikations-Orakel — zwei Korpora waeren
        # zwei Messungen und keine Gegenprobe.
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from test_note_rahmung_kanonisch import _Aufbau            # noqa: PLC0415
        cls.a = _Aufbau()

    def _go_lauf(self, faelle, vkey):
        with tempfile.TemporaryDirectory() as tmp:
            cases = [{"id": k, "b64": base64.b64encode(t.encode("utf-8", "surrogatepass")).decode()}
                     for k, t in faelle]
            pfad = Path(tmp) / "cases.json"
            pfad.write_text(json.dumps({"vkey": vkey, "cases": cases}), encoding="utf-8")
            umgebung = {**os.environ}
            umgebung.setdefault("GOCACHE", str(Path(tmp) / "gocache"))
            p = subprocess.run([self.go, "run", ".", str(pfad)], cwd=str(GO_DIR),
                               capture_output=True, text=True, timeout=600, env=umgebung)
        if p.returncode != 0:
            fehler = (p.stderr or "").strip()
            if "dial tcp" in fehler or "proxy.golang.org" in fehler or "module lookup disabled" in fehler:
                raise unittest.SkipTest(
                    "golang.org/x/mod ist nicht im Modul-Cache und kann nicht geholt werden "
                    f"(kein Netz) — SKIP statt stillem Gruen. Meldung: {fehler[:300]}")
            self.fail(f"go run scheiterte (exit {p.returncode}): {fehler[:800]}")
        aus = {}
        for zeile in p.stdout.splitlines():
            if zeile.strip():
                teile = zeile.split("\t")
                aus[teile[0]] = teile[1]
        return aus

    def test_python_und_go_sind_sich_ueber_den_ganzen_ed25519_korpus_einig(self):
        go = self._go_lauf(self.a.faelle, self.a.vkey)
        self.assertEqual(len(go), len(self.a.faelle), "Go hat nicht jeden Fall beantwortet")
        abweichungen = []
        for kennung, text in self.a.faelle:
            py = _impl_nimmt_an(text, self.a.vkey)
            g = go.get(kennung) == "ACCEPT"
            if py != g:
                abweichungen.append(f"{kennung}: python={py} go={g}")
        self.assertEqual(abweichungen, [], "\n".join(abweichungen))

    def test_antiparitaet_die_echte_note_wird_von_beiden_angenommen(self):
        go = self._go_lauf([("echt", self.a.note)], self.a.vkey)
        self.assertEqual(go["echt"], "ACCEPT", "die echte Note faellt bei der Referenz durch")
        self.assertIs(_impl_nimmt_an(self.a.note, self.a.vkey), True)

    def test_meta_die_kurze_nachbildung_ist_nachweislich_milder_als_die_referenz(self):
        """ANTITAUTOLOGIE gegen die eigene Begruendung: wenn die kurze Nachbildung genauso streng waere
        wie echtes Go, waere dieser ganze Test Zierde. Sie ist es nicht — und das wird hier gemessen,
        nicht behauptet."""
        EM = cp.EM_DASH

        def nachbildung(msg):                      # woertlich der Port aus dem Gate-Reproducer
            i = msg.rfind("\n\n")
            if i < 0:
                return None
            text_, data = msg[:i + 1], msg[i + 2:]
            if not data or not data.endswith("\n"):
                return None
            for line in data.rstrip("\n").split("\n"):
                if not line.startswith(EM + " "):
                    return None
            return text_

        echt_text = self.a.note[:self.a.note.rfind("\n\n") + 1]
        go = self._go_lauf(self.a.faelle, self.a.vkey)
        milder = [k for k, t in self.a.faelle
                  if (nachbildung(t) == echt_text) and go.get(k) != "ACCEPT"]
        self.assertGreaterEqual(
            len(milder), 5,
            "die kurze Nachbildung war hier nicht milder als die Referenz — dann traegt die "
            f"Begruendung dieses Tests nicht mehr (gefunden: {milder})")


if __name__ == "__main__":
    unittest.main()
