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


# EIN KONTEXTBEWUSSTER DURCHGANG STATT DREI LEXIKALISCHER SCANNER (09.09.2026).
#
# Die erste Fassung dieses Melders hatte drei Leser: `PIPE` (Regex), `_ohne_kommentar` (mit
# Quote- und ${...}-Kontext) und `_pipe_in_substitution` (nackte Klammerzaehlung). Nur der
# mittlere kannte Kontext, und genau der hielt in ~20 adversarialen Proben gegen echtes bash.
# Die beiden anderen fielen: drei Falschpositive (`$((5|2))` ist Arithmetik, ein `|` in
# Anfuehrungszeichen ist Text, ein `\|` ist escapt) und sechs Falschnegative (export/declare/
# readonly/local verwerfen den Code wie echo — ShellCheck SC2155 —, und Backticks wurden gar
# nicht gesucht). Alle neun mit `bash --noprofile --norc -eo pipefail` gegengemessen.
#
# DIE KLASSE dahinter ist dieselbe wie beim urspruenglichen P0, nur eine Ebene hoeher: wer eine
# Shell-Zeile nach MUSTERN liest statt nach ihrer STRUKTUR, trifft die Eigenschaft nicht. Es gibt
# genau eine Struktur, also gibt es hier jetzt genau einen Durchgang, und alle drei Fragen
# (wo endet der Kommentar, wo steht eine echte Pipe, steckt eine Pipe in einer Substitution)
# werden aus SEINEM Zustand beantwortet.
IMMER_GELINGT = re.compile(r"^\s*(echo|printf|true|:|export|declare|readonly|local|typeset)\b")


class _Lage:
    """Das Ergebnis EINES Durchgangs durch eine logische Zeile."""

    __slots__ = ("nackt", "pipe_oben", "pipe_in_substitution")

    def __init__(self, nackt: str, pipe_oben: bool, pipe_in_substitution: bool):
        self.nackt = nackt
        self.pipe_oben = pipe_oben
        self.pipe_in_substitution = pipe_in_substitution


def analysiere(zeile: str) -> _Lage:
    r"""Geht die Zeile EINMAL zeichenweise ab und fuehrt den Shell-Kontext mit.

    Gefuehrt werden: Escape (`\`), einfache und doppelte Anfuehrungszeichen, `${...}`-Tiefe,
    Arithmetik `$((...))`, Kommandosubstitution `$(...)` und Backtick-Substitution. Daraus
    ergeben sich alle drei Fragen ohne eine zweite Lesart:

      nackt                 die Zeile ohne ihren Kommentar. Ein `#` beginnt einen Kommentar nur,
                            wenn es unquotiert, unescapt, auf oberster Ebene steht UND ein Wort
                            eroeffnet (Zeilenanfang oder Leerraum davor). `${V#muster}` und
                            `x=a#b` sind damit keine Kommentare — an echtem bash geprueft.
      pipe_oben             eine echte Pipe auf oberster Ebene (nicht `||`, nicht in Quotes,
                            nicht escapt, nicht in Arithmetik).
      pipe_in_substitution  eine echte Pipe INNERHALB einer Kommandosubstitution. Arithmetik
                            zaehlt ausdruecklich NICHT: `$((5|2))` ist ein Bit-Oder ohne
                            Subprozess.
    """
    nackt_bis = len(zeile)
    einfach = doppelt = False
    escape = False
    geschweift = 0                       # ${...}
    arith = 0                            # $((...))
    subst: list[int] = []                # Klammertiefe je offener $( ... )
    quote_stapel: list[tuple[bool, bool]] = []   # Quote-Lage VOR jeder offenen Substitution
    backtick = False
    pipe_oben = pipe_sub = False
    i = 0
    while i < len(zeile):
        c = zeile[i]
        if escape:
            escape = False
            i += 1
            continue
        if c == "\\" and not einfach:
            escape = True
            i += 1
            continue
        if einfach:
            if c == "'":
                einfach = False
            i += 1
            continue
        if c == "'" and not doppelt:
            einfach = True
            i += 1
            continue
        if c == '"':
            doppelt = not doppelt
            i += 1
            continue
        if c == "$" and zeile[i + 1:i + 3] == "((":
            arith += 1
            i += 3
            continue
        if arith:
            if c == ")" and zeile[i + 1:i + 2] == ")":
                arith -= 1
                i += 2
                continue
            i += 1
            continue                      # in der Arithmetik ist | ein Bit-Oder, keine Pipe
        if c == "$" and zeile[i + 1:i + 2] == "(":
            # EINE SUBSTITUTION EROEFFNET EINEN NEUEN QUOTE-KONTEXT (09.09.2026, an der eigenen
            # Messung gefunden). In `"$(printf 'a|b')"` gelten die AEUSSEREN Doppelquotes
            # innerhalb von $( ) nicht — das `'a|b'` ist dort ein echter einfach-quotierter
            # String, und sein `|` ist Text. Ohne diese Rettung las der Laeufer `doppelt=True`
            # weiter, uebersprang das `'` und meldete einen Fehlalarm. Genau der Fall, den die
            # zweite Linse als Falschpositiv 2 nachgewiesen hat.
            quote_stapel.append((einfach, doppelt))
            einfach = doppelt = False
            subst.append(1)
            i += 2
            continue
        if c == "$" and zeile[i + 1:i + 2] == "{":
            geschweift += 1
            i += 2
            continue
        if c == "}" and geschweift:
            geschweift -= 1
            i += 1
            continue
        if c == "`":
            backtick = not backtick
            i += 1
            continue
        if subst:
            if c == "(":
                subst[-1] += 1
            elif c == ")":
                subst[-1] -= 1
                if subst[-1] == 0:
                    subst.pop()
                    if quote_stapel:
                        einfach, doppelt = quote_stapel.pop()
                i += 1
                continue
        if c == "|":
            if zeile[i + 1:i + 2] == "|":
                i += 2
                continue                  # ODER-Operator, keine Pipe
            if subst or backtick:
                pipe_sub = True
            elif not doppelt and not geschweift:
                pipe_oben = True
            i += 1
            continue
        if (c == "#" and not doppelt and not geschweift and not subst and not backtick
                and (i == 0 or zeile[i - 1].isspace())):
            nackt_bis = i
            break
        i += 1
    return _Lage(zeile[:nackt_bis], pipe_oben, pipe_sub)


def _ohne_kommentar(zeile: str) -> str:
    """Duenne Huelle ueber `analysiere` — der Name bleibt, weil Faelle auf ihn zeigen."""
    return analysiere(zeile).nackt


def huelle_verliert_exitcode(zeile: str) -> bool:
    """Die ZWEITE Art, auf der ein Exit-Code verschwindet — und `pipefail` rettet sie NICHT.

    GEMESSEN mit Kontrollzeile:

        bash --noprofile --norc -eo pipefail -c \
          'echo "sdist=$(sha256sum FEHLT | cut -d\" \" -f1)" > out; echo WEITER'
            -> RC=0, WEITER wird gedruckt, out enthaelt `sdist=` (LEER)
        dieselbe Pipe OHNE die echo-Huelle
            -> RC=1, Abbruch

    `pipefail` gilt fuer die Pipe INNERHALB der Substitution, aber ihr Exit-Code wird verworfen,
    weil das aeussere Kommando immer gelingt; `set -e` sieht nur dessen Erfolg. Die MENGE dieser
    Kommandos ist groesser als `echo`: `export`, `declare`, `readonly`, `local` und `typeset`
    tragen ihren EIGENEN Status, nicht den der Substitution — in ShellCheck als SC2155 gefuehrt,
    von einer adversarialen Linse am 09.09.2026 an allen vier Formen ausgefuehrt nachgewiesen.
    Eine nackte ZUWEISUNG (`x="$(a | b)"`) ist NICHT betroffen und ausdruecklich kein Fund:
    dort IST der Status der Zuweisung der der Substitution (gegengemessen, RC=1).
    """
    lage = analysiere(zeile)
    return bool(IMMER_GELINGT.match(zeile)) and lage.pipe_in_substitution


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
                pipefail = _hat_pipefail(step.get("shell") or job_shell or wf_shell, skript)
                if pipefail is None:
                    continue
                for zeile in _logische_zeilen(skript):
                    lage = analysiere(zeile)
                    nackt = lage.nackt
                    # AUS DEM EINEN DURCHGANG, nicht aus einem zweiten Regex-Blick: eine Pipe
                    # zaehlt nur, wenn sie wirklich eine ist — nicht in Anfuehrungszeichen,
                    # nicht escapt, nicht `||`, nicht das Bit-Oder in `$(( ))`.
                    if not (lage.pipe_oben or lage.pipe_in_substitution):
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
                    if pipefail is True:
                        continue          # pipefail deckt die uebrigen Formen ab
                    if not lage.pipe_oben:
                        continue          # nur in einer Substitution, ohne Huelle: die Zuweisung traegt
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

    def _mit_pipefail(self, zeile: str) -> Path:
        return self._baum(
            "on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n"
            "    defaults:\n      run:\n        shell: bash\n    steps:\n"
            "      - name: T\n        run: |\n          " + zeile + "\n"
        )

    def test_weitere_huellen_tragen_ihren_eigenen_status(self):
        """export/declare/readonly/local sind Huellen wie echo — ShellCheck SC2155.

        Von einer adversarialen Linse am 09.09.2026 an allen vier Formen mit echtem
        `bash -eo pipefail` nachgewiesen: RC=0, der Code der Pipe ist weg. Die erste Fassung
        des Melders kannte nur echo/printf/true/: und schwieg zu allen vieren.
        """
        for zeile in ('export x="$(a | b)"', 'declare x="$(a | b)"',
                      'readonly x="$(a | b)"', 'local x="$(a | b)"'):
            b = sammle_riskante_pipes(self._mit_pipefail(zeile))
            self.assertEqual(len(b), 1, f"{zeile} -> {b}")
            self.assertEqual(b[0]["art"], "huelle_verwirft_code", zeile)

    def test_backtick_substitution_zaehlt_auch(self):
        """`a | b` verliert den Code genauso wie $(a | b); der erste Melder suchte nur nach `$(`."""
        b = sammle_riskante_pipes(self._mit_pipefail('echo "x=`a | b`"'))
        self.assertEqual(len(b), 1, b)
        self.assertEqual(b[0]["art"], "huelle_verwirft_code")

    def test_arithmetik_ist_keine_pipe(self):
        """`$((5|2))` ist ein Bit-Oder ohne Subprozess. Falschpositiv 1 der zweiten Linse:
        `$((` ist praefixgleich mit `$(`, und eine nackte Klammerzaehlung merkt es nicht."""
        self.assertEqual(sammle_riskante_pipes(self._mit_pipefail('echo "$((5|2))"')), [])

    def test_pipe_in_anfuehrungszeichen_ist_text(self):
        """Falschpositiv 2, und der Fall trug zusaetzlich einen echten Semantikfehler: eine
        Substitution eroeffnet einen NEUEN Quote-Kontext. In `"$(printf 'a|b')"` gilt das
        aeussere Doppelquote drinnen nicht, das `'a|b'` ist ein echter Textstring.
        Giftprobe der Linse: `printf 'a|nonexistent_cmd_xyz123'` laeuft RC=0 ohne
        'command not found' — es gibt keine zweite Pipeline-Stufe."""
        self.assertEqual(sammle_riskante_pipes(self._mit_pipefail(
            """echo "$(printf 'a|b')\"""")), [])

    def test_escaptes_pipezeichen_ist_keine_pipe(self):
        r"""Falschpositiv 3. Kontrollpaar der Linse: `true \| nichtexistent` -> RC=0,
        `true | nichtexistent` -> RC=127. Das escapte Zeichen wird nie als Stufe gefahren."""
        self.assertEqual(sammle_riskante_pipes(self._mit_pipefail(
            'echo "$(true \\| true)"')), [])

    def test_echte_pipe_neben_einem_textkoeder_wird_gemeldet(self):
        """Die Gegenprobe zu den drei Falschpositiven: ein Textkoeder darf den Melder nicht
        taub machen. Hier steht eine ECHTE Pipe (printf|sed) neben dem Koeder `a|b`."""
        b = sammle_riskante_pipes(self._mit_pipefail(
            """echo "$(printf 'x' | sed -n 's/a|b/c/p')\""""))
        self.assertEqual(len(b), 1, b)

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
