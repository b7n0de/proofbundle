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
Modul-Cache ``golang.org/x/mod`` schon hat oder geholt werden kann. Beides wird VORAB mit eigenen
Kommandos festgestellt, deren Exit-Code die Klasse IST (siehe ``_modul_beschaffung``); sonst SKIP mit
Begruendung — nie ein stilles Gruen. Ein Fehlschlag des eigentlichen Laufs ist danach IMMER ein echter
Fehler und wird hart gemeldet. Gemessen am 2026-09-05 mit go1.27.1 linux/amd64 und golang.org/x/mod v0.29.0:
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


BESCHAFFT = "beschafft"
NICHT_BESCHAFFBAR = "nicht_beschaffbar"      # -> SKIP, ehrlich
WERKZEUG_DEFEKT = "werkzeug_defekt"          # -> harter Fehler, sichtbar


def _modulverzeichnis(gomodcache: str) -> "Path | None":
    """Der Ort, an dem das benoetigte Modul liegen MUESSTE — aus ``go.mod`` gelesen, nicht geraten."""
    gomod = GO_DIR / "go.mod"
    if not gomodcache or not gomod.is_file():
        return None
    for zeile in gomod.read_text(encoding="utf-8").splitlines():
        teile = zeile.split()
        if len(teile) >= 3 and teile[0] == "require" and "/" in teile[1]:
            return Path(gomodcache) / f"{teile[1]}@{teile[2]}"
    return None


def _beschaffungslage(go: str) -> "tuple[str, str]":
    """Klassifiziert die Lage in DREI Klassen, ohne je einen Meldungstext zu lesen.

    WARUM DREI UND NICHT ZWEI. Die erste Fassung dieser Funktion kannte nur "beschafft" und
    "nicht beschaffbar" und schickte JEDEN Fehlschlag von ``go mod download`` in den SKIP. Eine
    Gegenlesung (07.09.2026) hat das zu Recht verworfen: sie nannte vier reale, netzunabhaengige
    Ursachen — ``GOTOOLCHAIN=local`` mit einer Binary aelter als die Anforderung in ``go.mod``,
    ``GOFLAGS=-mod=vendor`` ohne ``vendor/``, ein fehlender Schreibzugriff auf den Modul-Cache,
    und ein PRUEFSUMMENFEHLER gegen ``go.sum``. Der letzte ist der schlimmste: das ist ein
    Integritaetssignal, und ausgerechnet in einem Werkzeug, dessen Zweck die Pruefung von
    Signaturen ist, waere er als harmloses "nicht beschaffbar" verschwunden. Die alte
    Meldungspruefung war in diesem einen Punkt strenger als mein Ersatz — sie skippte nur bei drei
    benannten Netzsignalen und liess alles andere hart scheitern.

    WIE DIE URSACHE JETZT BESTIMMT WIRD: positiv, mit eigenen Kommandos, nie aus einem Text.
    Scheitern beide Beschaffungsstufen, wird gefragt, ob das Werkzeug ueberhaupt arbeitsfaehig ist
    und ob das Modul in Wahrheit doch schon liegt. Liegt es da, dann ist "nicht beschaffbar" als
    Erklaerung widerlegt — der Fehlschlag hat einen anderen Grund und gehoert nach oben, nicht in
    einen SKIP.
    """
    offline = subprocess.run([go, "mod", "download"], cwd=str(GO_DIR), capture_output=True,
                             text=True, timeout=600, env={**os.environ, "GOPROXY": "off"})
    if offline.returncode == 0:
        return BESCHAFFT, "im Modul-Cache vorhanden, ohne Netz"
    mit_netz = subprocess.run([go, "mod", "download"], cwd=str(GO_DIR), capture_output=True,
                              text=True, timeout=600)
    if mit_netz.returncode == 0:
        return BESCHAFFT, "ueber das Netz geholt"

    version = subprocess.run([go, "version"], capture_output=True, text=True, timeout=60)
    if version.returncode != 0:
        return WERKZEUG_DEFEKT, f"`go version` endete mit {version.returncode}"
    cache = subprocess.run([go, "env", "GOMODCACHE"], capture_output=True, text=True, timeout=60)
    if cache.returncode != 0:
        return WERKZEUG_DEFEKT, f"`go env GOMODCACHE` endete mit {cache.returncode}"
    ziel = _modulverzeichnis(cache.stdout.strip())
    if ziel is not None and ziel.is_dir():
        return WERKZEUG_DEFEKT, (
            f"das Modul liegt bereits unter {ziel}, die Beschaffung ist also NICHT die Ursache "
            "(Pruefsumme, Toolchain-Anforderung oder vendor-Vorgabe kommen in Frage)")
    return NICHT_BESCHAFFBAR, (mit_netz.stderr or offline.stderr or "").strip()[:300]


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
        klasse, grund = _beschaffungslage(cls.go)
        if klasse == WERKZEUG_DEFEKT:
            raise AssertionError(
                "die Go-Umgebung ist nicht arbeitsfaehig, und das ist KEIN Grund zu ueberspringen: "
                f"{grund}")
        if klasse == NICHT_BESCHAFFBAR:
            raise unittest.SkipTest(
                "golang.org/x/mod ist weder im Modul-Cache noch holbar — SKIP statt stillem "
                f"Gruen. Meldung: {grund}")
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
            # Die Beschaffung ist in setUpClass geklaert. Ein Fehlschlag hier ist deshalb IMMER ein
            # echter Fehler — es gibt keinen Pfad mehr, auf dem ein Meldungstext ihn zu einem SKIP
            # macht.
            self.fail(f"go run scheiterte (exit {p.returncode}): {(p.stderr or '').strip()[:800]}")
        aus = {}
        for zeile in p.stdout.splitlines():
            if zeile.strip():
                teile = zeile.split("\t")
                aus[teile[0]] = teile[1]
        # DIE VOLLSTAENDIGKEIT DER FREMDAUSGABE WIRD HIER ERZWUNGEN, NICHT IM EINZELNEN TEST.
        # Befund META-TEST-BESTEHT-AUCH-WENN-DAS-FREMDE-ORAKEL-SCHWEIGT-01 (2026-09-05): der Meta-Test
        # unten urteilte mit ``go.get(k) != "ACCEPT"`` ueber die Inhalte, ohne vorher zu verlangen, dass
        # ueberhaupt etwas gelesen wurde. Bei leerer Go-Ausgabe ist "Schluessel fehlt" von "Go hat
        # abgelehnt" nicht unterscheidbar, und die Aussage wird WAHR, ohne dass je ein Go-Verdikt
        # existierte — gemessen mit einem main.go, das vor der ersten Ausgabezeile os.Exit(0) macht.
        # Der Riegel sitzt deshalb an der EINEN Stelle, durch die jede Frage an Go laeuft: ein neuer
        # Test kann ihn gar nicht mehr vergessen. (Klassenfix statt Instanzfix, B7_STANDING_FIX_THE_CLASS.)
        fehlend = [k for k, _ in faelle if k not in aus]
        if fehlend:
            self.fail(f"die Go-Ausgabe ist unvollstaendig: {len(aus)} von {len(faelle)} Verdikten, "
                      f"es fehlen u.a. {fehlend[:5]} — ueber eine schweigende Gegenseite wird hier "
                      "NICHT geurteilt")
        return aus

    def test_python_und_go_sind_sich_ueber_den_ganzen_ed25519_korpus_einig(self):
        go = self._go_lauf(self.a.faelle, self.a.vkey)   # _go_lauf erzwingt die Vollstaendigkeit
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


@unittest.skipUnless(GO_DIR.is_dir(), "tools/go_note_differential fehlt")
class DieKlassentrennungIstGemessen(unittest.TestCase):
    """FANGNACHWEIS fuer ``_beschaffungslage`` — mit einem gestellten ``go``, dessen Exit-Codes wir
    setzen, das die Umgebung LIEST und jeden Aufruf protokolliert.

    Die erste Fassung dieses Nachweises war zu schwach, und das wurde ihr in einer Gegenlesung
    nachgewiesen: ihr Stub verzweigte nur nach ``$1``, antwortete beiden Beschaffungsstufen gleich
    und zaehlte die Aufrufe nicht. Zwei ausgefuehrte Mutationen des Produktivpfads blieben dabei
    gruen. Jede der Pruefungen hier haengt deshalb an einer Achse, die eine dieser Mutationen
    sichtbar macht.
    """

    def _gestelltes_go(self, *, offline_rc: int, netz_rc: int = 1, run_rc: int = 0,
                       version_rc: int = 0, modul_liegt_da: bool = False):
        """Rueckgabe: (Pfad zum gestellten ``go``, Pfad zum Aufrufprotokoll)."""
        verz = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, str(verz), True)
        protokoll = verz / "aufrufe.txt"
        cache = verz / "gomodcache"
        if modul_liegt_da:
            ziel = _modulverzeichnis(str(cache))
            self.assertIsNotNone(ziel, "go.mod muss eine require-Zeile tragen, sonst misst das nichts")
            ziel.mkdir(parents=True)
        pfad = verz / "go"
        pfad.write_text(
            "#!/bin/sh\n"
            f'echo "$1 GOPROXY=${{GOPROXY:-ungesetzt}}" >> "{protokoll}"\n'
            'case "$1" in\n'
            f'  version) exit {version_rc} ;;\n'
            f'  env) echo "{cache}"; exit 0 ;;\n'
            '  mod)\n'
            f'    if [ "$GOPROXY" = "off" ]; then exit {offline_rc}; fi\n'
            f'    exit {netz_rc} ;;\n'
            'esac\n'
            'echo "dial tcp: lookup proxy.golang.org: no such host" >&2\n'
            f"exit {run_rc}\n", encoding="utf-8")
        pfad.chmod(0o755)
        return str(pfad), protokoll

    @staticmethod
    def _stufen(protokoll: Path) -> "list[str]":
        if not protokoll.exists():
            return []
        return [z.split("GOPROXY=", 1)[1]
                for z in protokoll.read_text(encoding="utf-8").splitlines() if z.startswith("mod ")]

    def _setup_mit(self, go: str):
        """Ruft die ECHTE setUpClass mit dem gestellten ``go`` und raeumt hinter sich auf."""
        def zuruecksetzen():
            if "go" in DasEchteGoDifferential.__dict__:
                delattr(DasEchteGoDifferential, "go")
        self.addCleanup(zuruecksetzen)
        vorher = os.environ.get("PB_GO_BIN")
        os.environ["PB_GO_BIN"] = go
        self.addCleanup(lambda: os.environ.__setitem__("PB_GO_BIN", vorher)
                        if vorher is not None else os.environ.pop("PB_GO_BIN", None))
        return DasEchteGoDifferential.setUpClass

    # -- die Beschaffung selbst -------------------------------------------------------------

    def test_warmer_cache_genuegt_und_es_wird_kein_netz_versucht(self):
        """FAENGT die Mutation "GOPROXY=off weggelassen": dann traegt die erste Stufe nicht mehr
        offline, und das Protokoll zeigt statt ``off`` ein ``ungesetzt``."""
        go, protokoll = self._gestelltes_go(offline_rc=0, netz_rc=1)
        klasse, _ = _beschaffungslage(go)
        self.assertEqual(klasse, BESCHAFFT)
        self.assertEqual(self._stufen(protokoll), ["off"],
                         "genau EIN Versuch, und zwar offline — sonst haengt der warme Cache am Netz")

    def test_kalter_cache_mit_netz_wird_geholt_statt_uebersprungen(self):
        """FAENGT die Mutation "Netz-Rueckfall ersatzlos entfernt": ohne ihn wuerde eine Umgebung
        mit kaltem Cache und Netz uebersprungen, obwohl "schon da ODER holbar" versprochen ist."""
        go, protokoll = self._gestelltes_go(offline_rc=1, netz_rc=0)
        klasse, _ = _beschaffungslage(go)
        self.assertEqual(klasse, BESCHAFFT)
        self.assertEqual(self._stufen(protokoll), ["off", "ungesetzt"],
                         "erst offline, dann mit Netz — genau in dieser Reihenfolge")

    # -- die drei Klassen -------------------------------------------------------------------

    def test_wirklich_nicht_beschaffbar_wird_uebersprungen(self):
        go, protokoll = self._gestelltes_go(offline_rc=1, netz_rc=1, modul_liegt_da=False)
        with self.assertRaises(unittest.SkipTest):
            self._setup_mit(go)()
        self.assertEqual(self._stufen(protokoll), ["off", "ungesetzt"],
                         "vor dem SKIP muessen BEIDE Stufen versucht worden sein")

    def test_ein_fehlschlag_bei_LIEGENDEM_modul_ist_KEIN_grund_zu_ueberspringen(self):
        """DER FUND DER GEGENLESUNG. Beide Stufen scheitern, aber das Modul liegt in Wahrheit da —
        also ist die Beschaffung nicht die Ursache. Reale Faelle: Pruefsummenfehler gegen go.sum,
        eine Toolchain aelter als die Anforderung in go.mod, ``-mod=vendor`` ohne ``vendor/``.
        Der erste ist ein Integritaetssignal und darf in einem Signaturpruef-Werkzeug niemals als
        harmloses "nicht beschaffbar" verschwinden."""
        go, _ = self._gestelltes_go(offline_rc=1, netz_rc=1, modul_liegt_da=True)
        klasse, grund = _beschaffungslage(go)
        self.assertEqual(klasse, WERKZEUG_DEFEKT,
                         "ein liegendes Modul widerlegt 'nicht beschaffbar' als Erklaerung")
        aufruf = self._setup_mit(go)
        try:
            aufruf()
        except unittest.SkipTest as s:
            self.fail(f"als SKIP durchgewunken, obwohl das Modul da liegt: {s}")
        except AssertionError as f:
            self.assertIn("nicht arbeitsfaehig", str(f))
        else:
            self.fail("weder SKIP noch Fehler — der Fall blieb ganz unbemerkt")

    def test_unbrauchbare_toolchain_ist_kein_grund_zu_ueberspringen(self):
        go, _ = self._gestelltes_go(offline_rc=1, netz_rc=1, version_rc=1)
        klasse, grund = _beschaffungslage(go)
        self.assertEqual(klasse, WERKZEUG_DEFEKT)
        self.assertIn("go version", grund)

    # -- der Lauf selbst --------------------------------------------------------------------

    def test_ein_fehlschlag_der_nach_netz_klingt_ist_trotzdem_ein_fehler(self):
        """DIE SCHARFE RICHTUNG. Der Lauf scheitert, und seine Meldung traegt woertlich die Worte,
        an denen die frueheste Fassung einen SKIP festmachte."""
        inst = DasEchteGoDifferential("test_antiparitaet_die_echte_note_wird_von_beiden_angenommen")
        inst.go, _ = self._gestelltes_go(offline_rc=0, run_rc=1)
        try:
            inst._go_lauf([("x", "irgendein text")], "vkey")
        except unittest.SkipTest as s:
            self.fail(f"ein echter Fehlschlag wurde als SKIP durchgewunken: {s}")
        except AssertionError as f:
            self.assertIn("go run scheiterte", str(f))
        else:
            self.fail("der Fehlschlag blieb voellig unbemerkt")


if __name__ == "__main__":
    unittest.main()