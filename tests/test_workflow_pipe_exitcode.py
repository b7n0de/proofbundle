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


def _hat_pipefail(shell: str | None) -> bool | None:
    """None = keine Shell-Pipes (python/node). False = `bash -e` ohne pipefail."""
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
                if _hat_pipefail(step.get("shell") or job_shell or wf_shell) is not False:
                    continue
                for zeile in _logische_zeilen(str(step["run"])):
                    nackt = zeile.split("#", 1)[0]
                    if not PIPE.search(nackt):
                        continue
                    if any(x in nackt for x in ("|| true", "|| echo", "|| :")):
                        continue
                    if _linke_seiten_harmlos(nackt):
                        continue
                    befunde.append({
                        "datei": f.name, "job": jobname,
                        "schritt": step.get("name", f"#{i}"),
                        "zeile": " ".join(zeile.split()),
                    })
    return befunde


# ------------------------------------------------- Ausnahmen, jede mit ihrem Grund

ERLAUBT_MIT_GRUND: dict[tuple[str, str], str] = {
    ("ci.yml", "n_eindeutig=\"$(echo $alle_idx | tr ' ' '\\n' | grep . | sort -n | uniq | wc -l)\""):
        "fail-closed durch den Nachbarn: `grep .` liefert bei leerer Eingabe 1, ohne "
        "pipefail wird daraus `0` -- und der folgende Vergleich gegen ERWARTET faellt um.",
}


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

    def test_echo_in_substitution_ist_harmlos(self):
        d = self._baum(
            "on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - name: Rechnen\n        run: |\n"
            "          k=\"$(echo $x | tr ' ' '\\n' | wc -l)\"\n"
        )
        self.assertEqual(sammle_riskante_pipes(d), [])


if __name__ == "__main__":
    unittest.main()
