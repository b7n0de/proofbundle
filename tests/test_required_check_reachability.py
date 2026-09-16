"""Contracts for the required-check reachability gate.

The defect these guard against is not a red check. It is an ABSENT one: a context the ruleset
demands and no workflow ever produces. It shows up as a pull request that stays BLOCKED with
nothing red on it, which reads like "nothing is wrong". Measured in this repository on
2026-09-16 across four open pull requests at once.

Every case below can go red. Several plant the defect explicitly and assert the gate catches it,
because a test that cannot fall proves nothing about the gate.
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

# PFADFORM STATT BLANKEM IMPORT, und das ist nicht Geschmack. Das Skript steht mit Begruendung
# NICHT in der Verteilung (es liest `.github/`, das MANIFEST.in prunt), `scripts/` liegt im
# installierten Paket ohnehin nicht auf dem Pfad, und ein blanker `import` braeche dort das
# SAMMELN — nicht diesen einen Test, sondern die ganze Suite. Ueber die Pfadform meldet conftest
# stattdessen ein ehrliches SKIP. Gefunden 2026-09-16 vom Riegel
# tests/test_kein_blanker_import_eines_nicht_ausgelieferten.py, der genau diese Klasse bewacht,
# als Folge meiner eigenen Ausschluss-Entscheidung eine Datei weiter.
_PFAD = Path(__file__).resolve().parents[1] / "scripts" / "required_check_reachability_gate.py"
_spec = importlib.util.spec_from_file_location("_required_check_reachability_gate", str(_PFAD))
G = importlib.util.module_from_spec(_spec)
sys.modules["_required_check_reachability_gate"] = G
_spec.loader.exec_module(G)

CI = """
name: CI
on:
  pull_request:
    branches: [main]
jobs:
  coverage:
    runs-on: ubuntu-latest
    steps: [{run: "true"}]
  test:
    strategy:
      matrix:
        python-version: >-
          ${{ fromJSON(
            ( github.event_name == 'workflow_dispatch'
              || contains(github.event.pull_request.labels.*.name, 'landung') )
            && '["3.10","3.11","3.12"]'
            || '["3.12"]' ) }}
    runs-on: ubuntu-latest
    steps: [{run: "true"}]
"""


class Baum:
    """A throwaway workflow directory plus its declaration."""

    def __init__(self, fall: unittest.TestCase, workflows: dict[str, str], verlangt: list[str]):
        tmp = tempfile.TemporaryDirectory()
        fall.addCleanup(tmp.cleanup)
        self.wurzel = Path(tmp.name)
        self.wf = self.wurzel / "workflows"
        self.wf.mkdir()
        for name, inhalt in workflows.items():
            (self.wf / name).write_text(inhalt, encoding="utf-8")
        self.decl = self.wurzel / "required_status_checks.json"
        self.decl.write_text(json.dumps({"ruleset": "t", "branch": "main",
                                         "required_contexts": verlangt}), encoding="utf-8")

    def urteil(self) -> dict:
        return G.pruefe(self.decl, self.wf)

    def rc(self, *argv: str) -> int:
        return G.main(["--declaration", str(self.decl), "--workflows", str(self.wf), *argv])


class TestAbsentIsNotGreen(unittest.TestCase):

    def test_a_required_context_no_job_produces_is_caught(self):
        """THE defect. Before the gate existed this was invisible: no check red, PR blocked forever."""
        b = Baum(self, {"ci.yml": CI}, ["coverage", "test (3.12)", "gibt-es-nicht"])
        r = b.urteil()
        self.assertEqual(r["verdict"], G.ABSENT)
        fehlend = [e["context"] for e in r["per_context"] if e["state"] == G.ABSENT]
        self.assertEqual(fehlend, ["gibt-es-nicht"])
        self.assertEqual(b.rc(), 1, "an unreachable required context must not exit 0")

    def test_the_planted_absence_is_the_only_difference(self):
        """Catch proof: the same tree WITHOUT the planted context passes. Otherwise the case above
        could be green for an unrelated reason."""
        b = Baum(self, {"ci.yml": CI}, ["coverage", "test (3.12)"])
        self.assertEqual(b.urteil()["verdict"], G.ALWAYS)
        self.assertEqual(b.rc(), 0)

    def test_allow_gated_never_rescues_an_absent_context(self):
        """--allow-gated softens the CONDITIONAL case. It must not soften the absent one."""
        b = Baum(self, {"ci.yml": CI}, ["coverage", "fehlt-ganz"])
        self.assertEqual(b.rc("--allow-gated"), 1)


class TestConditionalIsNamed(unittest.TestCase):

    def test_a_context_only_under_a_condition_is_reported_with_that_condition(self):
        b = Baum(self, {"ci.yml": CI}, ["test (3.10)"])
        r = b.urteil()
        self.assertEqual(r["verdict"], G.GATED)
        e = r["per_context"][0]
        self.assertEqual(e["state"], G.GATED)
        self.assertIn("landung", e["condition"],
                      "the condition must be NAMED, not merely flagged as conditional")

    def test_gated_is_not_a_pass_by_default(self):
        """A condition nobody sets is a pull request nobody can merge."""
        b = Baum(self, {"ci.yml": CI}, ["test (3.10)"])
        self.assertEqual(b.rc(), 1)
        self.assertEqual(b.rc("--allow-gated"), 0)

    def test_the_ordinary_arm_is_the_else_arm(self):
        """3.12 is in both arms and therefore unconditional; 3.10 only in the gated one."""
        b = Baum(self, {"ci.yml": CI}, ["test (3.12)", "test (3.10)"])
        zustand = {e["context"]: e["state"] for e in b.urteil()["per_context"]}
        self.assertEqual(zustand["test (3.12)"], G.ALWAYS)
        self.assertEqual(zustand["test (3.10)"], G.GATED)


class TestKnownExpressionTraps(unittest.TestCase):

    def test_an_empty_true_arm_is_named_as_a_dead_condition(self):
        """`cond && A || B` falls through to B whenever A is falsy. Emptying the true arm disables
        the condition completely -- and the produced context set then looks EXACTLY as it would
        without the condition, so counting contexts can never reveal it. Only a note in words can.

        This case was written first as an assertion on the context states alone, and a mutant that
        deleted the guard survived it: both paths yielded the same states. Measured 2026-09-16.
        The assertion now binds to the thing the guard actually produces."""
        leer = CI.replace("""&& '["3.10","3.11","3.12"]'""", """&& '[]'""")
        b = Baum(self, {"ci.yml": leer}, ["test (3.12)", "test (3.10)"])
        r = b.urteil()
        zustand = {e["context"]: e["state"] for e in r["per_context"]}
        self.assertEqual(zustand["test (3.12)"], G.ALWAYS)
        self.assertEqual(zustand["test (3.10)"], G.ABSENT,
                         "with an empty true arm 3.10 can never be produced, under any condition")
        self.assertTrue(r["dead_conditions"],
                        "a condition that can never take effect must be named, not merely implied "
                        "by the context set it leaves behind")
        self.assertIn("dead code", r["dead_conditions"][0])
        self.assertEqual(b.rc(), 1, "a dead condition must not exit 0")

    def test_a_dead_condition_alone_fails_even_when_every_context_is_produced(self):
        """The dead-condition branch must be the DECIDING one somewhere, or it is decoration.

        The case above asserts exit 1 for a tree whose true arm is empty -- but that tree also has
        an absent required context, and the absent one already forces exit 1. A mutant deleting the
        dead-condition branch therefore survived it: the assertion held for a different reason than
        the one it names. Measured 2026-09-16, the same class as the finding this whole gate is
        about. Here only `test (3.12)` is required, it IS produced, the verdict is 'produced', and
        the exit code can only come from the dead condition."""
        leer = CI.replace("""&& '["3.10","3.11","3.12"]'""", """&& '[]'""")
        b = Baum(self, {"ci.yml": leer}, ["coverage", "test (3.12)"])
        r = b.urteil()
        self.assertEqual(r["verdict"], G.ALWAYS,
                         "every declared context is produced, so the verdict itself is clean")
        self.assertTrue(r["dead_conditions"])
        self.assertEqual(b.rc(), 1, "the dead condition alone must fail the gate")
        self.assertEqual(b.rc("--allow-gated"), 1,
                         "--allow-gated softens a NAMED condition, never a dead one")

    def test_a_live_condition_produces_no_dead_condition_note(self):
        """Catch proof for the case above: the unmodified tree must NOT raise the note, otherwise
        the assertion would hold for every input and test nothing."""
        b = Baum(self, {"ci.yml": CI}, ["test (3.12)"])
        self.assertEqual(b.urteil()["dead_conditions"], [])

    def test_a_reusable_workflow_is_declared_unreadable_not_skipped(self):
        """Its context is '<caller job id> / <called job name>'. Reading only the called file gives
        the wrong name, so the gate must decline rather than guess."""
        ruf = ("name: X\non:\n  pull_request:\n    branches: [main]\n"
               "jobs:\n  aufruf:\n    uses: ./.github/workflows/andere.yml\n")
        b = Baum(self, {"ci.yml": CI, "ruf.yml": ruf}, ["coverage"])
        r = b.urteil()
        self.assertTrue(any("reusable" in u for u in r["unreadable"]),
                        "a reusable-workflow job must appear in the unreadable list")

    def test_a_job_name_interpolating_the_matrix_is_expanded(self):
        benannt = CI.replace("  test:\n", "  test:\n    name: py ${{ matrix.python-version }}\n")
        b = Baum(self, {"ci.yml": benannt}, ["py 3.12"])
        self.assertEqual(b.urteil()["verdict"], G.ALWAYS)


class TestJobLevelIf(unittest.TestCase):
    """Ein Job hinter einem `if:` laeuft nicht immer, seine Kontexte sind also nicht unbedingt da.

    Gefunden 2026-09-16 von einer fremden Modellfamilie in der Gegenlesung, auf die Frage, wo der
    Waechter STILL falsch urteilen wuerde statt not-measurable zu sagen. Die Antwort war genau
    hier: ein Pflicht-Job mit `if: false` wurde als `produced` gemeldet. Kein Fehlschlag, kein
    Hinweis, ein glattes Falschurteil.

    Die Haerte dahinter, aus der Recherche desselben Tages: ein durch `if:` uebersprungener Job
    meldet GitHub ein SUCCESS. Ein Pflichtkontext auf einem solchen Job blockiert also nie und
    beweist auch nichts — er sieht nur so aus, als wuerde er etwas sichern.
    """

    def _baum(self, joblines, verlangt):
        return Baum(self, {"ci.yml": "name: CI\non: {pull_request: {branches: [main]}}\njobs:\n"
                           + joblines}, verlangt)

    def test_a_required_job_that_can_never_run_is_not_produced(self):
        b = self._baum('  coverage:\n    if: false\n    runs-on: ubuntu-latest\n'
                       '    steps: [{run: "true"}]\n', ["coverage"])
        r = b.urteil()
        self.assertEqual(r["verdict"], G.ABSENT,
                         "`if: false` heisst: dieser Job laeuft NIE, also entsteht sein Kontext nie")
        self.assertTrue(r["dead_conditions"], "und das muss in Worten dastehen, nicht nur im Zustand")
        self.assertEqual(b.rc(), 1)

    def test_a_conditional_job_names_its_condition_instead_of_claiming_produced(self):
        b = self._baum("  coverage:\n    if: github.event_name == 'push'\n"
                       '    runs-on: ubuntu-latest\n    steps: [{run: "true"}]\n', ["coverage"])
        r = b.urteil()
        self.assertEqual(r["verdict"], G.GATED)
        self.assertIn("github.event_name", r["per_context"][0]["condition"],
                      "die Bedingung muss BENANNT sein, nicht nur als bedingt markiert")

    def test_without_an_if_nothing_changes(self):
        """Fangnachweis fuer die zwei Faelle darueber: ohne `if:` bleibt es bei produced. Ohne
        diesen Fall koennte die neue Logik jeden Job herabstufen und die zwei oben waeren trotzdem
        gruen."""
        b = self._baum('  coverage:\n    runs-on: ubuntu-latest\n    steps: [{run: "true"}]\n',
                       ["coverage"])
        self.assertEqual(b.urteil()["verdict"], G.ALWAYS)
        self.assertEqual(b.rc(), 0)


class TestUnknownIsNotFine(unittest.TestCase):

    def test_a_matrix_that_is_not_literal_is_unreadable_not_reachable(self):
        dyn = CI.replace("""python-version: >-
          ${{ fromJSON(
            ( github.event_name == 'workflow_dispatch'
              || contains(github.event.pull_request.labels.*.name, 'landung') )
            && '["3.10","3.11","3.12"]'
            || '["3.12"]' ) }}""", "python-version: ${{ fromJSON(needs.vorher.outputs.liste) }}")
        b = Baum(self, {"ci.yml": dyn}, ["coverage", "test (3.12)"])
        r = b.urteil()
        self.assertTrue(any("matrix values not readable" in u for u in r["unreadable"]))
        self.assertEqual(r["verdict"], G.ABSENT,
                         "an unreadable matrix must not make its contexts count as produced")

    def test_broken_yaml_is_reported_not_treated_as_an_empty_file(self):
        b = Baum(self, {"ci.yml": CI, "kaputt.yml": "jobs: [this: is: not: a: mapping\n"},
                 ["coverage"])
        r = b.urteil()
        self.assertTrue(r["unreadable"], "a file that does not parse must be named, not ignored")

    def test_a_missing_declaration_is_not_measurable_and_not_a_pass(self):
        b = Baum(self, {"ci.yml": CI}, ["coverage"])
        b.decl.unlink()
        self.assertEqual(b.urteil()["verdict"], G.UNKNOWN)
        self.assertEqual(b.rc(), 1)

    def test_an_empty_required_list_is_not_measurable(self):
        b = Baum(self, {"ci.yml": CI}, [])
        self.assertEqual(b.urteil()["verdict"], G.UNKNOWN)


class TestDeclarationAgainstRuleset(unittest.TestCase):
    """Die Erklaerung ist eine KOPIE des Regelsatzes, und eine Kopie driftet.

    Wer den Regelsatz aendert und die Datei vergisst, bekommt vom Offline-Tor weiter ein Urteil,
    das sich auf gestrige Pflichten bezieht: alles gruen, gemessen an der falschen Menge. Diese
    Faelle brauchen KEIN Netz — sie legen ein falsches `gh` auf den PATH und pruefen damit den
    echten Unterprozess-Pfad statt einer nachgebauten Kulisse.
    """

    def _mit_gh(self, ausgabe: str, rc: int = 0):
        """Ein `gh` auf dem PATH, das genau diese Ausgabe liefert."""
        import os
        import stat
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        p = Path(tmp.name) / "gh"
        p.write_text("#!/bin/sh\ncat <<'JSON'\n" + ausgabe + "\nJSON\nexit " + str(rc) + "\n",
                     encoding="utf-8")
        p.chmod(p.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
        alt = os.environ.get("PATH", "")
        os.environ["PATH"] = f"{tmp.name}:{alt}"
        self.addCleanup(lambda: os.environ.__setitem__("PATH", alt))
        return Path(tmp.name)

    def _erklaerung(self, kontexte, *, rs_id=1) -> Path:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        p = Path(tmp.name) / "required_status_checks.json"
        d = {"ruleset": "t", "branch": "main", "required_contexts": kontexte}
        if rs_id is not None:
            d["ruleset_id"] = rs_id
        p.write_text(json.dumps(d), encoding="utf-8")
        return p

    @staticmethod
    def _regelsatz(kontexte) -> str:
        return json.dumps({"name": "protect-main", "rules": [
            {"type": "required_status_checks",
             "parameters": {"required_status_checks": [{"context": c} for c in kontexte]}}]})

    def test_no_drift_is_a_pass(self):
        self._mit_gh(self._regelsatz(["a", "b"]))
        d = G.erklaerung_gegen_regelsatz(self._erklaerung(["a", "b"]), "o/r")
        self.assertEqual(d["verdict"], G.ALWAYS)
        self.assertEqual(d["declared_only"], [])
        self.assertEqual(d["ruleset_only"], [])

    def test_a_context_the_ruleset_requires_but_nobody_declared_is_caught(self):
        """Die gefaehrliche Richtung: der Regelsatz verlangt mehr, als die Datei kennt. Das
        Offline-Tor wuerde die neue Pflicht gar nicht pruefen und trotzdem gruen melden."""
        self._mit_gh(self._regelsatz(["a", "b", "neu"]))
        d = G.erklaerung_gegen_regelsatz(self._erklaerung(["a", "b"]), "o/r")
        self.assertEqual(d["verdict"], G.ABSENT)
        self.assertEqual(d["ruleset_only"], ["neu"])

    def test_a_context_declared_but_no_longer_required_is_caught(self):
        self._mit_gh(self._regelsatz(["a"]))
        d = G.erklaerung_gegen_regelsatz(self._erklaerung(["a", "alt"]), "o/r")
        self.assertEqual(d["verdict"], G.ABSENT)
        self.assertEqual(d["declared_only"], ["alt"])

    def test_a_failing_gh_is_not_measurable_and_never_a_pass(self):
        self._mit_gh("nichts", rc=1)
        d = G.erklaerung_gegen_regelsatz(self._erklaerung(["a"]), "o/r")
        self.assertEqual(d["verdict"], G.UNKNOWN)
        self.assertIn("gh api exited", d["reason"])

    def test_output_that_is_not_json_is_not_measurable(self):
        self._mit_gh("kein json")
        d = G.erklaerung_gegen_regelsatz(self._erklaerung(["a"]), "o/r")
        self.assertEqual(d["verdict"], G.UNKNOWN)

    def test_a_declaration_without_a_ruleset_id_cannot_be_compared(self):
        d = G.erklaerung_gegen_regelsatz(self._erklaerung(["a"], rs_id=None), "o/r")
        self.assertEqual(d["verdict"], G.UNKNOWN)
        self.assertIn("ruleset_id", d["reason"])

    def test_the_drift_check_never_touches_the_offline_verdict(self):
        """Zwei Wege, ein Werkzeug. Der Netzweg darf das Offline-Urteil nicht faerben."""
        self._mit_gh(self._regelsatz(["gibt-es-nicht"]))
        b = Baum(self, {"ci.yml": CI}, ["coverage", "test (3.12)"])
        self.assertEqual(b.urteil()["verdict"], G.ALWAYS,
                         "das Offline-Urteil haengt an den Workflows, nicht am Regelsatz")


class TestAgainstThisRepository(unittest.TestCase):

    def test_the_real_declaration_matches_what_was_measured_by_hand(self):
        """Not a fixture: the gate is run against this repository's own files and must reproduce
        the measurement of 2026-09-16 -- three contexts unconditional, four behind the label."""
        r = G.pruefe()
        if r["verdict"] == G.UNKNOWN:
            self.skipTest(f"declaration not readable here: {r.get('reason')}")
        zustand = {e["context"]: e["state"] for e in r["per_context"]}
        self.assertEqual(zustand.get("coverage"), G.ALWAYS)
        self.assertEqual(zustand.get("guard"), G.ALWAYS)
        self.assertEqual(zustand.get("test (3.12)"), G.ALWAYS)
        for v in ("3.10", "3.11", "3.13", "3.14"):
            self.assertEqual(zustand.get(f"test ({v})"), G.GATED,
                             f"test ({v}) was measured as produced only under the landung label")


if __name__ == "__main__":
    unittest.main()
