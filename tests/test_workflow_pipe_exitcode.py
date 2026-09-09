"""Klassen-Riegel: kein Workflow-Schritt darf einen Exit-Code durch eine Pipe verlieren.

DIE KLASSE (nicht die Instanz): GitHub faehrt `run:`-Schritte ohne `shell:` als
`/usr/bin/bash -e {0}` -- GEMESSEN am Job `mutation (2)` des Laufs 34235429542, Log-Zeile
direkt unter dem Schritt. `-e` OHNE `-o pipefail` heisst: der Exit-Code einer Pipeline ist
der ihres LETZTEN Glieds. Steht links ein Programm, dessen Fehlschlag ein Tor traegt, und
rechts ein `tee`/`sort`/`wc`, das immer gelingt, dann ist das Tor still.

WARUM EIN TEST UND NICHT NUR DER FIX: der Fix an `ci.yml` schliesst eine Instanz. Die
naechste Pipe, die jemand in einen Pflicht-Schritt schreibt, bringt die Klasse zurueck --
und sie ist unsichtbar, weil ihr Symptom "gruen" ist.

ALLOWLIST MIT GRUND statt pauschaler Ausnahme: EINE Zeile im Sammel-Job fuellt eine Variable,
die UNMITTELBAR DANACH gegen eine Erwartung verglichen wird. Faellt die Pipe still auf 0,
schlaegt der Vergleich fehl -- fail-closed durch den Nachbarn. Jede Allowlist-Zeile traegt
diesen Grund, und ein WAISEN-Test faellt um, sobald eine Zeile verschwindet: eine Ausnahme,
die niemand mehr braucht, ist eine Ausnahme, die niemand mehr prueft.
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

try:
    import yaml
except ImportError:  # PB-2026-0718-L6-01: PyYAML ist dev-only -- sauberer Skip aus einer
    import pytest    # nackten sdist-Installation, NIE ein Collection-Error (L6-600-01).
    pytest.skip("PyYAML not installed (dev-only dependency)", allow_module_level=True)

WURZEL = Path(__file__).resolve().parents[1]
WF_DIR = WURZEL / ".github" / "workflows"

# ---------------------------------------------------------------- die Eigenschaft

PIPE = re.compile(r"(?<![|&>])\|(?!\|)")
# Kommandos, deren Exit-Code KEINE Aussage traegt: reine Textquellen und -filter.
# `grep` gehoert AUSDRUECKLICH NICHT dazu -- sein Exit 1 heisst "kein Treffer", und das
# ist eine Aussage, die ein Tor tragen kann. Genau diese Unterscheidung ist die Klasse.
HARMLOS = re.compile(
    r"^\s*(echo|printf|true|:|tr|sort|uniq|wc|cut|rev|head|tail|nl|column|fold)\b"
)


SETZT_PIPEFAIL = re.compile(r"^\s*set\s+-[a-zA-Z]*o?\s*[a-zA-Z]*\s*pipefail|^\s*set\s+-o\s+pipefail")


def _hat_pipefail(shell: str | None, skript: str | None = None) -> bool | None:
    """None = keine Shell-Pipes (python/node). False = `bash -e` ohne pipefail.

    DAS SKRIPT ZAEHLT MIT (Gegenlesung 09.09.2026, Fund P2). Die erste Fassung las
    AUSSCHLIESSLICH den YAML-Schluessel `shell:`. Ein Schritt, der in seinem eigenen Skript
    `set -euo pipefail` setzt, galt damit als ungeschuetzt — und die einzige Ausnahme in
    ERLAUBT_MIT_GRUND trug deshalb eine faktisch falsche Begruendung: sie erklaerte einen
    „stille 0"-Fall, der dort gar nicht eintreten kann. Dieselbe Wurzel wie der P0, von der
    anderen Seite: die Lage wurde an einem MERKMAL abgelesen statt an der EIGENSCHAFT.
    """
    if skript and any(SETZT_PIPEFAIL.search(z) for z in skript.splitlines()):
        return True
    if shell is None:
        return False
    s = shell.strip()
    if s in ("bash", "pwsh", "powershell") or "pipefail" in s:
        return True
    if s.startswith(("python", "node")):
        return None
    return False


def _logische_zeilen(skript: str) -> list[str]:
    """`\\`-Fortsetzungen zu EINER Zeile. Ohne das liegt ein entschaerfendes
    `|| true` in der naechsten physischen Zeile und wird nicht gesehen."""
    aus: list[str] = []
    puffer = ""
    for roh in skript.splitlines():
        puffer += roh
        if puffer.rstrip().endswith("\\"):
            puffer = puffer.rstrip()[:-1] + " "
            continue
        if puffer.strip():
            aus.append(puffer)
        puffer = ""
    if puffer.strip():
        aus.append(puffer)
    return aus


def _linke_seiten_harmlos(zeile: str) -> bool:
    """Die harmlose Quelle steckt oft in `x="$(echo … | …)"` -- dann ist der
    Zeilenanfang `x="$(`, nicht `echo`. Geprueft wird jedes Segment links einer Pipe."""
    segmente = PIPE.split(zeile)[:-1]
    if not segmente:
        return False
    for seg in segmente:
        kern = re.sub(r'^[^=]*=\s*"?\$\(', "", seg)
        kern = re.sub(r"^.*\$\(", "", kern)
        kern = kern.lstrip("[ \"'")
        if not HARMLOS.search(kern):
            return False
    return True


# Kommandos, die IMMER gelingen. Steht eine Kommandosubstitution mit Pipe INNERHALB eines
# solchen Kommandos, ist ihr Exit-Code verloren — auch unter `pipefail`.
IMMER_GELINGT = re.compile(r"^\s*(echo|printf|true|:)\b")


def _ohne_kommentar(zeile: str) -> str:
    """Schneidet einen Shell-Kommentar ab, ohne `${VAR#muster}` zu zerteilen.

    HIER STAND `zeile.split("#", 1)[0]` (Gegenlesung 09.09.2026, Fund P1). Das schneidet mitten
    in eine Parametererweiterung: `release.yml` nutzt `${GITHUB_REF_NAME#v}` zweimal. Teilt sich
    eine solche Erweiterung eine Zeile mit einer echten Pipe, wird die Pipe unsichtbar — der
    Riegel schweigt, ohne dass irgendetwas danach aussieht. Heute nicht ausgeloest, gemessen an
    beiden Vorkommen (Zeilen 76 und 225, keine Pipe daneben); eine strukturelle Mine bleibt es
    trotzdem, und sie zu entschaerfen kostet diesen Scanner.

    Ein `#` beginnt einen Kommentar nur, wenn es ein Wort EROEFFNET (Zeilenanfang oder Leerraum
    davor), nicht in Anfuehrungszeichen steht und nicht in einer `${...}`-Erweiterung liegt.
    """
    einfach = doppelt = False
    tiefe = 0
    i = 0
    while i < len(zeile):
        c = zeile[i]
        if c == "\\" and not einfach:
            i += 2
            continue
        if c == "'" and not doppelt:
            einfach = not einfach
        elif c == '"' and not einfach:
            doppelt = not doppelt
        elif not einfach and c == "$" and zeile[i + 1:i + 2] == "{":
            tiefe += 1
            i += 2
            continue
        elif not einfach and c == "}" and tiefe > 0:
            tiefe -= 1
        elif c == "#" and not einfach and not doppelt and tiefe == 0:
            if i == 0 or zeile[i - 1].isspace():
                return zeile[:i]
        i += 1
    return zeile


def _pipe_in_substitution(zeile: str) -> bool:
    """Liegt in einer `$( ... )`-Substitution eine Pipe auf oberster Ebene?"""
    i = 0
    while True:
        start = zeile.find("$(", i)
        if start < 0:
            return False
        tiefe = 1
        j = start + 2
        while j < len(zeile) and tiefe:
            if zeile[j] == "(":
                tiefe += 1
            elif zeile[j] == ")":
                tiefe -= 1
            j += 1
        if PIPE.search(zeile[start + 2:j - 1]):
            return True
        i = start + 2


def huelle_verliert_exitcode(zeile: str) -> bool:
    """Die ZWEITE Art, auf der ein Exit-Code verschwindet — und `pipefail` rettet sie NICHT.

    GEMESSEN 09.09.2026 mit Kontrollzeile:

        bash --noprofile --norc -eo pipefail -c \
          'echo "sdist=$(sha256sum FEHLT | cut -d" " -f1)" > out; echo WEITER'
            -> RC=0, WEITER wird gedruckt, out enthaelt `sdist=` (LEER)
        dieselbe Pipe OHNE die echo-Huelle
            -> RC=1, Abbruch

    `pipefail` gilt fuer die Pipe INNERHALB der Substitution, aber ihr Exit-Code wird verworfen,
    weil das aeussere Kommando `echo` ist und immer gelingt; `set -e` sieht nur den Erfolg von
    echo. Eine ZUWEISUNG (`x="$(a | b)"`) ist NICHT betroffen: dort ist der Status der Zuweisung
    der der Substitution. `test "$(a | b)" = x` ebenfalls nicht: `test` gelingt nicht immer, und
    der Vergleich faellt ueber den WERT um.

    WARUM DAS EIN EIGENER MELDER IST: der Riegel wies bis heute jede Datei mit `pipefail`
    komplett ab (Zeile 104 alt, `is not False: continue`). Damit war die gepruefte Menge nach dem
    MERKMAL `hat pipefail` gewaehlt statt nach der EIGENSCHAFT `kann einen Exit-Code verlieren` —
    und `.github/workflows/reusable-build-attest.yml:73` fiel durch, obwohl der Nachbar
    `release.yml` seit 2026-08-16 den Handfix genau dafuer traegt.
    """
    return bool(IMMER_GELINGT.match(zeile)) and _pipe_in_substitution(zeile)


def sammle_riskante_pipes(wf_dir: Path) -> list[dict]:
    befunde = []
    for f in sorted(list(wf_dir.glob("*.yml")) + list(wf_dir.glob("*.yaml"))):
        doc = yaml.safe_load(f.read_text(encoding="utf-8"))
        if not isinstance(doc, dict):
            continue
        wf_shell = ((doc.get("defaults") or {}).get("run") or {}).get("shell")
        for jobname, job in (doc.get("jobs") or {}).items():
            if not isinstance(job, dict):
                continue
            job_shell = ((job.get("defaults") or {}).get("run") or {}).get("shell")
            for i, step in enumerate(job.get("steps") or []):
                if not isinstance(step, dict) or "run" not in step:
                    continue
                skript = str(step["run"])
                # ZWEI MELDER, WEIL ES ZWEI WEGE GIBT (09.09.2026). Bis hierher stand
                # `is not False: continue` — eine Datei mit pipefail wurde KOMPLETT
                # uebersprungen. pipefail schliesst aber nur den einen Weg (die Pipe als
                # aeusseres Kommando), nicht den zweiten (die Pipe in einer Substitution
                # innerhalb eines immer-gelingenden Kommandos). `None` heisst weiterhin
                # python/node: dort gibt es keine Shell-Pipes.
                lage = _hat_pipefail(step.get("shell") or job_shell or wf_shell, skript)
                if lage is None:
                    continue
                for zeile in _logische_zeilen(skript):
                    nackt = _ohne_kommentar(zeile)
                    if not PIPE.search(nackt):
                        continue
                    if any(x in nackt for x in ("|| true", "|| echo", "|| :")):
                        continue
                    eintrag = {
                        "datei": f.name, "job": jobname,
                        "schritt": step.get("name", f"#{i}"),
                        "zeile": " ".join(zeile.split()),
                    }
                    if huelle_verliert_exitcode(nackt):
                        befunde.append({**eintrag, "art": "huelle_verwirft_code"})
                        continue
                    if lage is True:
                        continue          # pipefail deckt die uebrigen Formen ab
                    if _linke_seiten_harmlos(nackt):
                        continue
                    befunde.append({**eintrag, "art": "kein_pipefail"})
    return befunde


# ------------------------------------------------- Ausnahmen, jede mit ihrem Grund

# LEER, UND ZWAR GEMESSEN — nicht aus Nachlaessigkeit (09.09.2026).
#
# Hier stand genau eine Ausnahme, fuer eine Zeile in ci.yml, mit der Begruendung "fail-closed
# durch den Nachbarn". Die Gegenlesung hat sie widerlegt und die Messung bestaetigt es: der
# Schritt `mutation-summary / Fail closed on missing, red or incomplete shards` traegt zwar
# KEINEN `shell:`-Schluessel, seine erste Skriptzeile lautet aber `set -euo pipefail`. Der
# beschriebene "stille 0"-Fall kann dort gar nicht eintreten; die Begruendung beschrieb einen
# Mechanismus, den es an dieser Stelle nicht gibt. Seit `_hat_pipefail` auch das SKRIPT liest,
# taucht die Zeile nicht mehr in den Funden auf, und `test_keine_waise_in_der_ausnahmeliste`
# hat sie als gegenstandslos gemeldet — der Waisen-Riegel hat also genau das getan, wofuer er
# gebaut wurde, an meiner eigenen Ausnahme.
#
# Dass die Menge jetzt leer ist, macht `test_jede_ausnahme_traegt_einen_grund` trivial wahr.
# Das ist hier in Ordnung, weil der Waisen-Riegel die andere Richtung haelt: eine Ausnahme ohne
# Gegenstand faellt auf, und eine noetige Ausnahme fehlt nicht still — sie erscheint als Fund.
ERLAUBT_MIT_GRUND: dict[tuple[str, str], str] = {}


@unittest.skipUnless(WF_DIR.is_dir(), "keine .github/workflows -- ausgelieferte sdist")
class WorkflowPipesVerlierenKeinenExitcode(unittest.TestCase):
    def test_keine_ungeschuetzte_pipe_in_einem_pflicht_schritt(self):
        offen = [
            b for b in sammle_riskante_pipes(WF_DIR)
            if (b["datei"], b["zeile"]) not in ERLAUBT_MIT_GRUND
        ]
        self.assertEqual(
            offen, [],
            "Pipe ohne pipefail, deren linke Seite einen Exit-Code traegt:\n"
            + "\n".join(f"  {b['datei']} · {b['job']} · {b['schritt']}\n      {b['zeile']}"
                        for b in offen)
            + "\n\nEntweder `shell: bash` an den Schritt (setzt -eo pipefail), oder "
              "`… > \"$LOG\" 2>&1; rc=$?; cat \"$LOG\"; exit $rc`, oder -- wenn der "
              "Fehlschlag wirklich egal ist -- mit BEGRUENDUNG in ERLAUBT_MIT_GRUND.",
        )

    def test_keine_waise_in_der_ausnahmeliste(self):
        """Eine Ausnahme fuer eine Zeile, die es nicht mehr gibt, ist eine Ausnahme,
        die niemand mehr prueft -- und sie deckt beim naechsten Mal etwas anderes."""
        vorhanden = {(b["datei"], b["zeile"]) for b in sammle_riskante_pipes(WF_DIR)}
        waisen = [k for k in ERLAUBT_MIT_GRUND if k not in vorhanden]
        self.assertEqual(waisen, [], f"Ausnahme ohne Gegenstand: {waisen}")

    def test_jede_ausnahme_traegt_einen_grund(self):
        for schluessel, grund in ERLAUBT_MIT_GRUND.items():
            self.assertGreater(len(grund), 40, f"Grund zu duenn: {schluessel}")


class GateMetaTest(unittest.TestCase):
    """Beweist, dass der Riegel einen eingepflanzten Defekt DIESER Klasse faengt --
    an echten YAML-Baeumen, nicht an gesetzten Attributen."""

    def _baum(self, yaml_text: str) -> Path:
        import tempfile
        d = Path(tempfile.mkdtemp(prefix="wfpipe_"))
        (d / "x.yml").write_text(yaml_text, encoding="utf-8")
        return d

    def test_faengt_die_ungeschuetzte_pipe(self):
        d = self._baum(
            "on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - name: Tor\n        run: |\n          python pruef.py | tee log\n"
        )
        self.assertEqual(len(sammle_riskante_pipes(d)), 1)

    def test_schweigt_bei_shell_bash(self):
        d = self._baum(
            "on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - name: Tor\n        shell: bash\n        run: |\n"
            "          python pruef.py | tee log\n"
        )
        self.assertEqual(sammle_riskante_pipes(d), [])

    def test_schweigt_bei_defaults_am_job(self):
        d = self._baum(
            "on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n"
            "    defaults:\n      run:\n        shell: bash\n    steps:\n"
            "      - name: Tor\n        run: |\n          python pruef.py | tee log\n"
        )
        self.assertEqual(sammle_riskante_pipes(d), [])

    def test_fortsetzungszeile_wird_als_eine_zeile_gelesen(self):
        """Der Defekt der ersten Fassung: `|| true` in der Fortsetzungszeile uebersehen,
        6 von 7 Befunden waren dadurch Fehlalarme."""
        d = self._baum(
            "on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - name: Zaehlen\n        run: |\n"
            "          n=\"$(grep -oE 'x' log \\\n            | tail -1 || true)\"\n"
        )
        self.assertEqual(sammle_riskante_pipes(d), [])

    def test_faengt_die_huelle_TROTZ_pipefail(self):
        """Der P0 vom 09.09.2026 als Fall: pipefail und trotzdem verloren.

        Vorher uebersprang der Riegel jede Datei mit pipefail komplett, dieser Fall war blind.
        """
        d = self._baum(
            "on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n"
            "    defaults:\n      run:\n        shell: bash\n    steps:\n"
            "      - name: Digest\n        run: |\n"
            "          echo \"sdist=$(sha256sum dist/x.tar.gz | cut -d' ' -f1)\" >> \"$GITHUB_OUTPUT\"\n"
        )
        b = sammle_riskante_pipes(d)
        self.assertEqual(len(b), 1, b)
        self.assertEqual(b[0]["art"], "huelle_verwirft_code")

    def test_zuweisung_mit_pipefail_ist_KEIN_fund(self):
        """Die Gegenprobe zur Huelle, und sie entscheidet ueber Fehlalarme: bei einer Zuweisung
        IST der Status der Zuweisung der der Substitution, `set -e` greift. Ohne diesen Fall
        wuerde der neue Melder die vorgeschriebene Reparaturform selbst anschwaerzen."""
        d = self._baum(
            "on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n"
            "    defaults:\n      run:\n        shell: bash\n    steps:\n"
            "      - name: Digest\n        run: |\n"
            "          sdist=\"$(sha256sum dist/x.tar.gz | cut -d' ' -f1)\"\n"
            "          test -n \"$sdist\"\n"
        )
        self.assertEqual(sammle_riskante_pipes(d), [])

    def test_parametererweiterung_verdeckt_die_pipe_nicht(self):
        """Fund P1 der Gegenlesung: `zeile.split(\"#\", 1)[0]` schnitt mitten in `${VAR#muster}`
        und liess alles dahinter verschwinden — samt einer echten Pipe."""
        d = self._baum(
            "on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - name: Tor\n        run: |\n"
            "          v=\"${GITHUB_REF_NAME#v}\"; python pruef.py \"$v\" | tee log\n"
        )
        self.assertEqual(len(sammle_riskante_pipes(d)), 1, sammle_riskante_pipes(d))

    def test_set_pipefail_im_skript_zaehlt(self):
        """Fund P2 der Gegenlesung: `_hat_pipefail` las nur den YAML-Schluessel. Ein Schritt,
        der `set -euo pipefail` in seinem eigenen Skript setzt, galt als ungeschuetzt."""
        d = self._baum(
            "on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - name: Tor\n        run: |\n          set -euo pipefail\n"
            "          python pruef.py | tee log\n"
        )
        self.assertEqual(sammle_riskante_pipes(d), [])

    def test_echo_in_substitution_ist_harmlos(self):
        d = self._baum(
            "on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - name: Rechnen\n        run: |\n"
            "          k=\"$(echo $x | tr ' ' '\\n' | wc -l)\"\n"
        )
        self.assertEqual(sammle_riskante_pipes(d), [])


if __name__ == "__main__":
    unittest.main()
