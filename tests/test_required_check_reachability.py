"""Contracts for the required-check reachability gate.

The defect these guard against is not a red check. It is an ABSENT one: a context the ruleset
demands and no workflow ever produces. It shows up as a pull request that stays BLOCKED with
nothing red on it, which reads like "nothing is wrong". Measured in this repository on
2026-09-16 across four open pull requests at once.

Every case below can go red. Several plant the defect explicitly and assert the gate catches it,
because a test that cannot fall proves nothing about the gate.
"""
from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _deutsche_prosa as _dp  # noqa: E402  (Helfer neben dieser Datei, wie _beinahe_treffer)

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

# The events the live cases below run on are events this workflow runs on: since the gate reads
# `on:` (lens on ac05d85d), a context arrives only on an event its workflow is triggered by.
CI = """
name: CI
on:
  pull_request:
    branches: [main]
  push:
  workflow_dispatch:
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

    def test_an_empty_true_arm_is_not_a_fallthrough(self):
        """`cond && '[]' || B` was read as B for every cond and the condition as dead code, after the survey
        of 2026-09-16. GitHub's `&&` returns its first falsy operand, else its last, and a string is falsy
        only when it is empty (actions/runner at 15231bede4aa, src/Sdk/Expressions/Sdk/Operators/And.cs:
        39-50, src/Sdk/Expressions/EvaluationResult.cs:51-72, read, not measured): `'[]'` is truthy, so
        under the condition the matrix vector is empty, which GitHub refuses
        (WorkflowTemplateConverter.cs:970-974). The job is not measurable, and nothing of it is produced;
        on fb6eda0d `test (3.12)` read as produced (lens on fb6eda0d, A)."""
        leer = CI.replace("""&& '["3.10","3.11","3.12"]'""", """&& '[]'""")
        b = Baum(self, {"ci.yml": leer}, ["test (3.12)", "test (3.10)"])
        r = b.urteil()
        zustand = {e["context"]: e["state"] for e in r["per_context"]}
        self.assertEqual(zustand, {"test (3.12)": G.ABSENT, "test (3.10)": G.ABSENT})
        self.assertEqual(r["dead_conditions"], [], "the condition is live, it is the arm that GitHub refuses")
        self.assertTrue(any("true arm" in u and "refuses a matrix vector" in u for u in r["newly_unreadable"]),
                        r["newly_unreadable"])
        self.assertEqual(b.rc(), 1)

    #: The CI matrix under a condition false on every event: `false && A || B` is always B.
    KONSTANT = CI.replace("( github.event_name == 'workflow_dispatch'\n"
                          "              || contains(github.event.pull_request.labels.*.name, 'landung') )",
                          "false")

    def test_a_dead_condition_alone_fails_even_when_every_context_is_produced(self):
        """The dead-condition branch must be the DECIDING one somewhere, or it is decoration.

        A tree with an absent required context already exits 1, so a mutant deleting the dead-condition
        branch survived a case built on one: the assertion held for a different reason than the one it
        names. Measured 2026-09-16, the same class as the finding this whole gate is about. Here only
        `coverage` and `test (3.12)` are required, both ARE produced, the verdict is 'produced', and the
        exit code can only come from the dead condition. Since the lens on fb6eda0d the dead condition is
        a constant one (`false && A || B`), not an empty true arm, which is no fallthrough (see above)."""
        self.assertNotEqual(self.KONSTANT, CI, "the planted condition is in the tree")
        b = Baum(self, {"ci.yml": self.KONSTANT}, ["coverage", "test (3.12)"])
        r = b.urteil()
        self.assertEqual(r["verdict"], G.ALWAYS,
                         "every declared context is produced, so the verdict itself is clean")
        self.assertTrue(r["dead_conditions"])
        self.assertIn("dead code", r["dead_conditions"][0])
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


class TestRatchetNotPermanentRed(unittest.TestCase):
    """The ratchet: what is known today is the floor, every REGRESSION turns red.

    Why it exists: an advisory job that is red from its first run teaches people to look away, and
    a gate that is habitually stepped over checks nothing any more.

    The ratchet is NOT an exemption. The report still names every conditional context with its
    condition and every limit with its reason; only the exit code follows the floor. Two earlier
    drafts were weaker and both were found by review rather than by the tests here:

      - The floor applied to conditional contexts alone and stayed red forever anyway because of
        ONE permanent unmeasurable case. That moved the permanent red instead of removing it.
      - The floor bound to the context NAME. A name once on the list was immune for good: a
        context that ran unconditionally could disappear behind an `if:`, and a condition could be
        narrowed from "one label" to "that label AND a second one nobody ever sets", both with no
        change in the verdict. The acceptance now carries the sha256 of the accepted condition.
    """

    KOPF = "name: CI\non: {pull_request: {branches: [main]}}\njobs:\n"
    COVERAGE_IMMER = '  coverage:\n    runs-on: ubuntu-latest\n    steps: [{run: "true"}]\n'
    COVERAGE_GEGATED = ('  coverage:\n    if: contains(github.event.pull_request.labels.*.name, '
                        "'landung')\n    runs-on: ubuntu-latest\n    steps: [{run: \"true\"}]\n")

    @staticmethod
    def _matrix(bedingung: str, wahr: str) -> str:
        return ("  test:\n    strategy:\n      matrix:\n        python-version: >-\n"
                f"          ${{{{ fromJSON( {bedingung}\n"
                f"            && '{wahr}' || '[\"3.12\"]' ) }}}}\n"
                '    runs-on: ubuntu-latest\n    steps: [{run: "true"}]\n')

    LABEL = "contains(github.event.pull_request.labels.*.name, 'landung')"
    ENGER = ("( contains(github.event.pull_request.labels.*.name, 'landung')\n"
             "            && contains(github.event.pull_request.labels.*.name, 'nie-gesetzt') )")

    def _lauf(self, workflow: str, verlangt, akzeptiert=None, akzeptiert_unlesbar=None):
        """Baut einen Miniaturbaum und gibt den Exit-Code zurueck.

        `akzeptiert` nimmt Paare (Kontext, Bedingungstext). Der Digest wird aus dem TEXT gerechnet,
        den der Test selbst in den Workflow geschrieben hat -- nicht aus dem, was das Tor gerade
        misst. Andernfalls sagte die Erklaerung nur "akzeptiere, was du siehst", und der Vertrag
        waere eine Tautologie.
        """
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        wurzel = Path(tmp.name)
        wf = wurzel / "workflows"
        wf.mkdir()
        (wf / "ci.yml").write_text(workflow, encoding="utf-8")
        d = {"ruleset": "t", "branch": "main", "required_contexts": verlangt}
        if akzeptiert is not None:
            d["accepted_gated"] = [
                e if isinstance(e, str)
                else {"context": e[0], "condition_sha256": G.bedingungs_digest(e[1])}
                for e in akzeptiert]
        if akzeptiert_unlesbar is not None:
            d["accepted_unreadable"] = akzeptiert_unlesbar
        decl = wurzel / "d.json"
        decl.write_text(json.dumps(d), encoding="utf-8")
        return G.main(["--declaration", str(decl), "--workflows", str(wf)])

    VERLANGT = ["coverage", "test (3.12)", "test (3.10)"]

    def _mit_matrix(self, bedingung, wahr='["3.10","3.12"]', coverage=None):
        return self.KOPF + (coverage or self.COVERAGE_IMMER) + self._matrix(bedingung, wahr)

    def test_the_known_state_is_not_red(self):
        rc = self._lauf(self._mit_matrix(self.LABEL), self.VERLANGT,
                        [("test (3.10)", self.LABEL)])
        self.assertEqual(rc, 0)

    def test_a_newly_gated_context_turns_it_red(self):
        """Ein bedingter Kontext, der NICHT auf der Sohle steht, MUSS fallen.

        Die Liste ist ABSICHTLICH nicht leer. Ein frueherer Anlauf uebergab `[]` und zog sein Rot
        aus der leeren Liste statt aus dem neu bedingten Kontext; ein Mutant, der `newly_gated`
        fest auf leer setzte, ueberlebte ihn deshalb."""
        wf = self._mit_matrix(self.LABEL, '["3.10","3.11","3.12"]')
        verlangt = ["coverage", "test (3.12)", "test (3.10)", "test (3.11)"]
        self.assertEqual(self._lauf(wf, verlangt, [("test (3.10)", self.LABEL),
                                                   ("test (3.11)", self.LABEL)]), 0,
                         "beide bedingten Kontexte zugesagt -- das ist die Sohle")
        self.assertEqual(self._lauf(wf, verlangt, [("test (3.10)", self.LABEL)]), 1,
                         "test (3.11) ist neu bedingt und steht nicht auf der Sohle")

    def test_an_always_produced_context_that_becomes_gated_is_red(self):
        """DER FUND DER GEGENLESUNG, ausfuehrbar: Vorabfreigabe eines Namens darf nicht immun machen.

        `coverage` laeuft im ersten Baum UNBEDINGT und steht trotzdem schon in der Zusage. Im
        zweiten Baum verschwindet es hinter einem `if:`. Bei Namensbindung blieb das gruen. Die
        Zusage nennt hier die Bedingung des ANDEREN Kontexts, also genau das, was eine
        vorsorgliche Freigabe in der Praxis enthaelt: einen Namen ohne den passenden Zustand."""
        zusage = [("coverage", self.LABEL), ("test (3.10)", self.LABEL)]
        self.assertEqual(self._lauf(self._mit_matrix(self.LABEL), self.VERLANGT, zusage), 0,
                         "coverage laeuft unbedingt, die Vorabzeile schadet nicht")
        rc = self._lauf(self._mit_matrix(self.LABEL, coverage=self.COVERAGE_GEGATED),
                        self.VERLANGT, zusage)
        self.assertEqual(rc, 1, "coverage ist hinter ein `if:` gewandert -- das ist die Regression")

    def test_a_narrowed_condition_under_the_same_name_is_red(self):
        """DER ZWEITE FUND: dieselbe Kennung, engere Bedingung, unveraenderte Zusage.

        Aus "das Label" wird "das Label UND ein zweites, das nie gesetzt wird". Die Erreichbarkeit
        faellt praktisch auf null, der Name bleibt gleich. Bei Namensbindung blieb das gruen."""
        zusage = [("test (3.10)", self.LABEL)]
        self.assertEqual(self._lauf(self._mit_matrix(self.LABEL), self.VERLANGT, zusage), 0)
        self.assertEqual(self._lauf(self._mit_matrix(self.ENGER), self.VERLANGT, zusage), 1,
                         "die zugesagte Bedingung ist nicht mehr die gemessene")

    def test_a_name_without_a_digest_does_not_carry(self):
        """Fail closed: die alte, namensgebundene Form ist keine Zusage mehr, sondern ein Mangel."""
        self.assertEqual(self._lauf(self._mit_matrix(self.LABEL), self.VERLANGT,
                                    ["test (3.10)"]), 1)

    def test_a_stale_name_only_entry_is_red_even_when_it_gates_nothing(self):
        """Der Ausgang prueft `unbound_acceptances` EIGENSTAENDIG, und dieser Fall laesst ihn entscheiden.

        Die Zeile nennt einen Kontext, der gar nicht bedingt ist. Ueber `newly_gated` kommt also
        kein Rot: der einzige wirklich bedingte Kontext ist ordentlich zugesagt. Rot kommt allein
        daher, dass die Erklaerung noch eine nackte Kennung mitfuehrt. Ohne diesen Fall waere das
        UND-Glied `not unbound_acceptances` im Ausgang ungebunden -- ein Mutant, der es entfernte,
        ueberlebte am 2026-09-16 alle damaligen Vertraege, weil jeder andere Fall sein Rot schon
        aus `newly_gated` zog. Eine veraltete Form still weiterleben zu lassen ist genau der Weg,
        auf dem aus einer Zusage ein Freibrief wird."""
        zusage = [("test (3.10)", self.LABEL), "coverage"]
        self.assertEqual(self._lauf(self._mit_matrix(self.LABEL), self.VERLANGT, zusage), 1,
                         "die nackte Kennung `coverage` ist der einzige Mangel -- und sie zaehlt")
        self.assertEqual(self._lauf(self._mit_matrix(self.LABEL), self.VERLANGT,
                                    [("test (3.10)", self.LABEL)]), 0,
                         "ohne sie ist derselbe Baum gruen: das Rot kam wirklich von ihr")

    def test_a_wrong_entry_of_the_right_length_is_still_red(self):
        """Die IDENTITAET der Zusage zaehlt, nicht ihre ANZAHL.

        Gefunden von der Vertrags-Gegenlesung am 2026-09-16: ein Mutant, der `newly_gated` ueber
        `len(gegated) <= len(zusagen)` statt ueber die Mengendifferenz bildete, ueberlebte ALLE
        damaligen Vertraege. Grund: jede Fixture waehlte Anzahl und Inhalt so, dass sie
        zusammenfielen. Ein veralteter oder vertippter Eintrag bei zufaellig gleicher Anzahl ist
        der wahrscheinlichste Pflegefehler an einer handgefuehrten Liste, und genau er blieb
        unsichtbar. Dieselbe Zahl-statt-Menge-Falle ist in diesem Tor schon einmal aufgetreten."""
        rc = self._lauf(self._mit_matrix(self.LABEL), self.VERLANGT,
                        [("test (3.99)-gibt-es-nicht-mehr", self.LABEL)])
        self.assertEqual(rc, 1, "eine Zusage auf einen fremden Namen deckt test (3.10) nicht")

    def test_a_right_name_with_a_foreign_digest_is_still_red(self):
        """Der Gegenfall dazu auf der anderen Achse: richtiger Name, fremder Digest."""
        rc = self._lauf(self._mit_matrix(self.LABEL), self.VERLANGT,
                        [("test (3.10)", "irgendeine ganz andere Bedingung")])
        self.assertEqual(rc, 1)

    def test_the_unbound_form_is_named_in_the_report(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        wurzel = Path(tmp.name)
        wf = wurzel / "workflows"
        wf.mkdir()
        (wf / "ci.yml").write_text(self._mit_matrix(self.LABEL), encoding="utf-8")
        decl = wurzel / "d.json"
        decl.write_text(json.dumps({"ruleset": "t", "branch": "main",
                                    "required_contexts": self.VERLANGT,
                                    "accepted_gated": ["test (3.10)"]}), encoding="utf-8")
        r = G.pruefe(decl, wf)
        self.assertEqual(r["unbound_acceptances"], ["test (3.10)"])
        self.assertEqual(r["accepted_gated"], [], "eine nackte Kennung ist keine Zusage")

    def test_a_context_nobody_produces_is_red_despite_the_ratchet(self):
        self.assertEqual(self._lauf(self._mit_matrix(self.LABEL),
                                    ["coverage", "gibt-es-nicht"],
                                    [("test (3.10)", self.LABEL)]), 1)

    def test_a_new_unreadable_is_red_even_when_another_one_is_accepted(self):
        """Symmetry: a KNOWN limit lowers the floor, a NEW one still fails."""
        wf = self._mit_matrix(self.LABEL) + "  aufruf:\n    uses: ./.github/workflows/andere.yml\n"
        self.assertEqual(self._lauf(wf, self.VERLANGT, [("test (3.10)", self.LABEL)],
                                    ["ci.yml:gibt-es-nicht"]), 1)

    def test_the_report_still_names_every_gated_context(self):
        """The ratchet may quieten the exit code, never the REPORT."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        wurzel = Path(tmp.name)
        wf = wurzel / "workflows"
        wf.mkdir()
        (wf / "ci.yml").write_text(self._mit_matrix(self.LABEL), encoding="utf-8")
        decl = wurzel / "d.json"
        decl.write_text(json.dumps({"ruleset": "t", "branch": "main",
            "required_contexts": self.VERLANGT,
            "accepted_gated": [{"context": "test (3.10)",
                                "condition_sha256": G.bedingungs_digest(self.LABEL)}]}),
            encoding="utf-8")
        r = G.pruefe(decl, wf)
        zustand = {e["context"]: e["state"] for e in r["per_context"]}
        self.assertEqual(zustand["test (3.10)"], G.GATED, "accepted does not mean relabelled")
        self.assertEqual(r["newly_gated"], [])
        digest = [e.get("condition_sha256") for e in r["per_context"]
                  if e["context"] == "test (3.10)"][0]
        self.assertEqual(digest, G.bedingungs_digest(self.LABEL),
                         "der Digest im Bericht ist der, an den die Zusage bindet")


class TestTheOfflineRunSaysWhetherTheDriftCheckRan(unittest.TestCase):
    """Ein Urteil, das nicht weiss, worauf es ruht, sagt mehr als es prueft.

    Eine Gegenlesung des gelandeten Standes fand es: das Offline-Tor konnte gruen melden, ohne zu
    wissen, ob `--verify-declaration` jemals gegen den echten Regelsatz gelaufen war. Die
    Erklaerung ist eine KOPIE, und eine Kopie driftet; ein gruenes Offline-Urteil ueber eine
    gedriftete Kopie misst die falsche Pflichtmenge.

    Der Netz-Lauf legt darum seinen Marker ab, der Offline-Lauf liest ihn und NENNT ihn. Er blockt
    NICHT darauf, und das ist Absicht: ein fehlender Token oder ein totes Netz wuerden den
    beratenden Job sonst aus Umweltgruenden rot faerben, also genau das Dauerrot herstellen, gegen
    das die Sohle gebaut ist. Gesagt wird es trotzdem — eine Pruefung, die nicht lief, ist keine
    bestandene, und ihre ABWESENHEIT muss im Bericht stehen, nicht nur ihr Rot.
    """

    def _marker(self, inhalt=None):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        p = Path(tmp.name) / "m.json"
        if inhalt is not None:
            p.write_text(inhalt, encoding="utf-8")
        return str(p)

    def _paar(self, **felder):
        """Ein Marker MIT der Erklaerung, auf die er sich beruft — korrekt aneinander gebunden.

        Alle Faelle unten laufen ueber dieses Paar, weil ein ungebundener Marker seit der
        Zustandsbindung gar nicht mehr zu seinem Urteil kommt: er ist STALE, egal was drinsteht.
        Wer hier `declaration_sha256` selbst setzt, loest die Bindung absichtlich — das tun genau
        die Angriffsfaelle.
        """
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        erklaerung = Path(tmp.name) / "required_status_checks.json"
        erklaerung.write_bytes(b'{"ruleset": "t", "required_contexts": ["coverage"]}')
        felder.setdefault("declaration_sha256",
                          hashlib.sha256(erklaerung.read_bytes()).hexdigest())
        if felder["declaration_sha256"] is None:
            del felder["declaration_sha256"]
        m = Path(tmp.name) / "m.json"
        m.write_text(json.dumps(felder), encoding="utf-8")
        return str(m), erklaerung

    def test_no_marker_is_reported_as_not_run(self):
        lage = G.drift_lage(self._marker())
        self.assertEqual(lage["state"], "absent")
        self.assertIn("NOT RUN", G._drift_zeile(self._marker()))

    def test_an_empty_marker_path_is_also_not_run(self):
        """Wer den Marker abschaltet, bekommt keine stille Zustimmung."""
        self.assertEqual(G.drift_lage("")["state"], "absent")
        self.assertEqual(G.drift_lage(None)["state"], "absent")

    def test_a_readable_marker_is_reported_with_its_verdict(self):
        """Die Gegenkontrolle zu allem, was unten rot wird: ein sauber gebundener Marker MUSS
        durchkommen. Ein Waechter, der jeden Marker verwirft, prueft nichts, er schweigt nur
        lauter."""
        p, decl = self._paar(verdict="produced", ruleset="protect-main",
                             at="2026-09-16T04:59:53Z")
        lage = G.drift_lage(p, decl)
        self.assertEqual(lage["state"], "ran")
        self.assertEqual(lage["verdict"], "produced")
        zeile = G._drift_zeile(p, decl)
        self.assertIn("checked at 2026-09-16T04:59:53Z", zeile)
        self.assertIn("protect-main", zeile)

    def test_a_run_that_measured_nothing_is_not_called_checked(self):
        """GELAUFEN IST NICHT GEMESSEN — und die erste Fassung sagte trotzdem 'ran'.

        Gemessen 2026-09-16 ohne Token: der Netz-Lauf legte einen Marker mit dem Urteil
        `not-measurable` ab, und die Zeile begann mit 'ran at ...'. Wer den Zeilenanfang liest und
        weitergeht, haelt die Drift-Pruefung fuer erledigt. Genau diese Verwechslung ist der Grund,
        aus dem dieses Tor ueberhaupt existiert; sie steckte in dem Werkzeug, das sie bekaempfen
        soll."""
        p, decl = self._paar(verdict=G.UNKNOWN, ruleset=None,
                             reason="gh api exited 4", at="2026-09-16T05:09:07Z")
        zeile = G._drift_zeile(p, decl)
        self.assertIn("NOT MEASURABLE", zeile)
        self.assertNotIn("checked at", zeile, "ein Lauf ohne Messung darf nicht gepruefte heissen")
        self.assertIn("2026-09-16T05:09:07Z", zeile, "der Versuch bleibt sichtbar")

    def test_a_measured_drift_is_called_drift_not_checked(self):
        """Die dritte Lage: gemessen UND abweichend. Sie darf nicht wie ein Treffer klingen."""
        p, decl = self._paar(verdict=G.ABSENT, ruleset="protect-main",
                             reason="required but NOT declared: test (3.15)",
                             at="2026-09-16T05:00:00Z")
        zeile = G._drift_zeile(p, decl)
        self.assertIn("DRIFT", zeile)
        self.assertIn("test (3.15)", zeile)
        self.assertNotIn("matches the live ruleset", zeile)

    def test_a_reason_that_spans_lines_does_not_cut_the_report(self):
        """Ein mehrzeiliger Grund zerschnitt die Zeile mitten im Satz.

        Gemessen an der echten Meldung von `gh`, die einen Zeilenumbruch traegt: der Leser sah die
        halbe Begruendung und hielt sie fuer die ganze. Gefaltet und gekappt, mit Kappmarke."""
        p, decl = self._paar(verdict=G.UNKNOWN, at="x",
                             reason="erste Zeile\nzweite Zeile\ndritte Zeile")
        zeile = G._drift_zeile(p, decl)
        self.assertEqual(zeile.count("\n"), 0, "die Berichtszeile ist mehrzeilig geworden")
        self.assertIn("erste Zeile zweite Zeile dritte Zeile", zeile)

    def test_a_very_long_reason_is_capped_with_a_visible_mark(self):
        p, decl = self._paar(verdict=G.UNKNOWN, at="x", reason="x" * 500)
        zeile = G._drift_zeile(p, decl)
        self.assertLess(len(zeile), 260, "die Zeile ist unbegrenzt gewachsen")
        self.assertIn("\u2026", zeile, "gekappt, aber ohne sichtbare Marke")

    def test_a_drifted_verdict_is_carried_into_the_line_not_swallowed(self):
        """Der interessante Fall: der Netz-Lauf fand eine Drift. Sie muss im Bericht stehen."""
        p, decl = self._paar(verdict="never-produced", ruleset="protect-main",
                             reason="required but NOT declared: test (3.15)",
                             at="2026-09-16T05:00:00Z")
        zeile = G._drift_zeile(p, decl)
        self.assertIn("never-produced", zeile)
        self.assertIn("test (3.15)", zeile)

    def test_a_broken_marker_is_not_measurable_and_not_silently_absent(self):
        """NICHT MESSBAR und NICHT GELAUFEN sind zwei Lagen mit zwei Gegenmassnahmen."""
        for kaputt in ("kein json", "[]", '{"ohne": "verdict"}', "null"):
            with self.subTest(kaputt):
                lage = G.drift_lage(self._marker(kaputt))
                self.assertEqual(lage["state"], "unreadable", kaputt)
                self.assertIn("NOT MEASURABLE", G._drift_zeile(self._marker(kaputt)))

    # --- die Zustandsbindung: WORAN das Urteil haengt, nicht DASS es existiert ---------------
    #
    # Drei Angriffe gegen die erste Fassung gingen am 2026-09-16 alle drei durch. Sie stehen
    # einzeln darunter, weil sie einzeln fallen muessen: ein Sammelfall verdeckt, welcher Weg
    # wieder offen ist, sobald einer davon zurueckkommt.

    def test_a_marker_that_names_no_declaration_is_stale(self):
        """ANGRIFF 1: ein Marker von 2020 meldete `checked ... matches the live ruleset`.

        Er war lesbar, hatte ein Urteil und einen Zeitpunkt - und sagte nirgends, WORUEBER er
        geurteilt hatte. Gebunden war die Existenz der Datei, nicht der gepruefte Zustand. Wer
        keinen Gegenstand nennt, hat nichts geprueft, das hier noch gilt."""
        p, decl = self._paar(verdict="produced", ruleset="protect-main",
                             at="2020-01-01T00:00:00Z", declaration_sha256=None)
        lage = G.drift_lage(p, decl)
        self.assertEqual(lage["state"], "stale")
        zeile = G._drift_zeile(p, decl)
        self.assertIn("STALE", zeile)
        self.assertNotIn("checked at", zeile, "ein Urteil ohne Gegenstand heisst nicht geprueft")
        self.assertIn("2020-01-01T00:00:00Z", zeile, "wann behauptet wurde, bleibt sichtbar")
        # DER WORTLAUT GEHOERT DAZU, und zwar aus einem gemessenen Grund: ohne ihn faellt die
        # Lage mit der naechsten zusammen. Ein Marker ohne Digest wird auch dann `stale`, wenn
        # man diese Verzweigung ganz entfernt (None ist nie gleich einem Digest) -- nur die
        # Begruendung waere dann falsch und spraeche von einer Aenderung, die niemand gemacht hat.
        self.assertIn("does not say WHICH declaration", zeile)
        self.assertNotIn("changed after the check", zeile,
                         "ein Marker ohne Gegenstand ist kein geaenderter Gegenstand")

    def test_a_declaration_changed_after_the_check_is_stale_and_names_both_digests(self):
        """ANGRIFF 3 in seiner scharfen Form: erst pruefen lassen, dann die Erklaerung aendern.

        Das ist der Normalfall im Betrieb, nicht nur der Angriff - eine Pflichtmenge wird
        erweitert, der Marker von vorhin bleibt liegen. Die Zeile muss BEIDE Digests nennen,
        sonst kann der Leser nicht sehen, ob der Marker alt ist oder die Erklaerung neu."""
        p, decl = self._paar(verdict="produced", ruleset="protect-main",
                             at="2026-09-16T05:00:00Z")
        gemessen = hashlib.sha256(decl.read_bytes()).hexdigest()
        decl.write_bytes(b'{"ruleset": "t", "required_contexts": ["coverage", "neu"]}')
        jetzt = hashlib.sha256(decl.read_bytes()).hexdigest()
        self.assertNotEqual(gemessen, jetzt)
        self.assertEqual(G.drift_lage(p, decl)["state"], "stale")
        zeile = G._drift_zeile(p, decl)
        self.assertIn(gemessen[:12], zeile, "der gepruefte Stand fehlt in der Zeile")
        self.assertIn(jetzt[:12], zeile, "der jetzige Stand fehlt in der Zeile")
        self.assertNotIn("matches the live ruleset", zeile)

    def test_a_marker_without_a_timestamp_is_not_measurable(self):
        """ANGRIFF 2: ohne Zeitpunkt las sich die Zeile als `checked at None`.

        Ein Urteil ohne Zeitpunkt ist von einem nie gelaufenen nicht unterscheidbar, und `None`
        im Bericht sah aus wie ein Formatierungsfehler, nicht wie ein fehlender Beleg."""
        p, decl = self._paar(verdict="produced", ruleset="protect-main")
        self.assertEqual(G.drift_lage(p, decl)["state"], "unreadable")
        zeile = G._drift_zeile(p, decl)
        self.assertIn("NOT MEASURABLE", zeile)
        self.assertNotIn("None", zeile, "ein fehlender Beleg darf nicht als Wert auftreten")

    def test_an_unreadable_declaration_does_not_pass_the_binding(self):
        """Die unmessbare Seite der Bindung darf nicht die bestandene sein.

        Fiele die Bindung aus, sobald der Digest der Erklaerung nicht zu holen ist, liesse sie
        sich abschalten, indem man die Erklaerung wegnimmt - der Marker wuerde wieder unbesehen
        zitiert. Das ist dieselbe Klasse wie der Marker selbst, eine Ebene tiefer.

        Der Fall pinnt auch die BEGRUENDUNG, und nicht aus Ordnungsliebe: das Urteil `stale`
        faellt hier ohnehin, weil ein 64-stelliger Digest nie gleich dem leeren ist. Ohne die
        eigene Lage haette der Leser stattdessen `checked was abc..., present here is ...` gesehen,
        mit nichts hinter `present here is` - eine fehlende Erklaerung als geaenderte.
        Gemessen am 2026-09-16: der Mutant, der diese Lage entfernt, ueberlebte alle Vertraege."""
        p, decl = self._paar(verdict="produced", ruleset="protect-main",
                             at="2026-09-16T05:00:00Z")
        self.assertEqual(G.drift_lage(p, decl)["state"], "ran", "Gegenkontrolle vor dem Entzug")
        decl.unlink()
        self.assertEqual(G.drift_lage(p, decl)["state"], "stale")
        zeile = G._drift_zeile(p, decl)
        self.assertIn("STALE", zeile)
        self.assertIn("not readable", zeile)
        self.assertNotIn("changed after the check", zeile,
                         "eine fehlende Erklaerung ist keine geaenderte")

    def test_a_stale_marker_still_does_not_change_the_exit_code(self):
        """Die Sohle gilt auch fuer den neuen Zustand: lauter berichten, nicht strenger urteilen.

        Sonst waere mit `stale` genau das Dauerrot zurueck, gegen das die Sohle gebaut ist - und
        zwar aus einem Umweltgrund, denn eine geaenderte Erklaerung ist im Betrieb normal."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        wurzel = Path(tmp.name)
        wf = wurzel / "workflows"
        wf.mkdir()
        (wf / "ci.yml").write_text(
            "name: CI\non: {pull_request: {branches: [main]}}\njobs:\n"
            '  coverage:\n    runs-on: ubuntu-latest\n    steps: [{run: "true"}]\n',
            encoding="utf-8")
        decl = wurzel / "d.json"
        decl.write_text(json.dumps({"ruleset": "t", "branch": "main",
                                    "required_contexts": ["coverage"]}), encoding="utf-8")
        veraltet, _ = self._paar(verdict="produced", at="2026-09-16T05:00:00Z",
                                 declaration_sha256="0" * 64)
        self.assertEqual(G.drift_lage(veraltet, decl)["state"], "stale")
        self.assertEqual(
            G.main(["--declaration", str(decl), "--workflows", str(wf),
                    "--drift-marker", veraltet]), 0)

    def test_the_marker_never_changes_the_exit_code(self):
        """Der Bericht wird lauter, das Urteil nicht strenger — sonst waere das Dauerrot zurueck."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        wurzel = Path(tmp.name)
        wf = wurzel / "workflows"
        wf.mkdir()
        (wf / "ci.yml").write_text(
            "name: CI\non: {pull_request: {branches: [main]}}\njobs:\n"
            '  coverage:\n    runs-on: ubuntu-latest\n    steps: [{run: "true"}]\n',
            encoding="utf-8")
        decl = wurzel / "d.json"
        decl.write_text(json.dumps({"ruleset": "t", "branch": "main",
                                    "required_contexts": ["coverage"]}), encoding="utf-8")
        ohne = G.main(["--declaration", str(decl), "--workflows", str(wf),
                       "--drift-marker", str(wurzel / "fehlt.json")])
        mit = G.main(["--declaration", str(decl), "--workflows", str(wf),
                      "--drift-marker", self._marker(json.dumps({"verdict": "produced"}))])
        self.assertEqual(ohne, 0)
        self.assertEqual(mit, ohne, "der Marker hat den Exit-Code bewegt — das war nicht der Auftrag")


class TestTheReportGoesOutInEnglish(unittest.TestCase):
    """Was dieses Werkzeug druckt, steht im GitHub-Actions-Protokoll eines oeffentlichen Repos.

    Der Standard dazu ist nicht Geschmack: ein Text ist GANZ englisch oder er geht nicht hinaus.
    Gemischt ist er fuer den Leser schlechter als in jeder der beiden Sprachen, und er faellt
    ausgerechnet dort auf, wo Fremde zusehen.

    Gemessen 2026-09-16 an genau diesem Tor: ELF Ausgabe-Zeichenketten waren deutsch, darunter die
    komplette Begruendung der Drift-Zeile ("die Erklaerung hat sich seit der Pruefung geaendert")
    und die Warnung ueber einen Job mit `if: false`. Die Kommentare und Docstrings der Datei sind
    deutsch und sollen es bleiben - die gehen nicht hinaus. Der Unterschied zwischen beidem war
    nirgends geprueft, und deshalb ist er hier geprueft.

    KLASSE, nicht Instanz: der Fall liest die GERENDERTE Ausgabe aller Lagen, nicht die Quelle.
    Eine neue Lage mit einem neuen deutschen Satz faellt hier auf, ohne dass jemand daran denkt.
    """

    # DIE WORTLISTE STEHT NICHT HIER, und das ist der Punkt. Der erste Entwurf dieses Falls trug
    # eine eigene Liste mit Teilzeichenketten statt Wortgrenzen; gemessen traf `"und "` darin
    # `"background "` und `"refund "`. Den Pruefer dafuer gab es im Repo laengst
    # (test_aussenflaeche_des_registers_ist_englisch, 2026-09-12), samt der Grenze, die
    # Bezeichner und Backtick-Zitate ausnimmt. Zwei Listen fuer eine Frage driften; jetzt ist es
    # eine, in tests/_deutsche_prosa.py, und beide Vertraege lesen sie.
    def _pruefe(self, text: str, wo: str):
        gefunden = _dp.treffer(text)
        self.assertFalse(gefunden, f"deutsche Funktionswoerter {gefunden} in {wo}: {text!r}")

    def _paar(self, **felder):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        erklaerung = Path(tmp.name) / "required_status_checks.json"
        erklaerung.write_bytes(b'{"ruleset": "t"}')
        felder.setdefault("declaration_sha256",
                          hashlib.sha256(erklaerung.read_bytes()).hexdigest())
        if felder["declaration_sha256"] is None:
            del felder["declaration_sha256"]
        m = Path(tmp.name) / "m.json"
        m.write_text(json.dumps(felder), encoding="utf-8")
        return str(m), erklaerung

    def test_every_state_of_the_drift_line_is_english(self):
        fehlt = str(Path(tempfile.mkdtemp()) / "weg.json")
        faelle = {
            "absent": (fehlt, None),
            "unreadable ohne Urteil": self._paar(at="2026-09-16T05:00:00Z"),
            "unreadable ohne Zeitpunkt": self._paar(verdict="produced"),
            "stale ohne Bindung": self._paar(verdict="produced", at="x",
                                             declaration_sha256=None),
            "ran": self._paar(verdict=G.ALWAYS, ruleset="protect-main", at="x"),
            "ran not-measurable": self._paar(verdict=G.UNKNOWN, at="x", reason="gh api exited 4"),
            "ran drift": self._paar(verdict=G.ABSENT, ruleset="protect-main", at="x",
                                    reason="required but NOT declared: test (3.15)"),
        }
        m, decl = self._paar(verdict="produced", at="x")
        Path(decl).write_bytes(b"anders")           # Bindung bricht -> stale mit beiden Digests
        faelle["stale geaendert"] = (m, decl)
        for name, (marker, decl2) in faelle.items():
            with self.subTest(name):
                self._pruefe(G._drift_zeile(marker, decl2), f"drift-Zeile ({name})")

    def test_the_whole_report_is_english(self):
        """Nicht nur die Drift-Zeile: der ganze Bericht, inklusive der Hinweise ueber Jobs.

        Der Lauf enthaelt absichtlich einen Job mit `if: false` - genau die Zeile, die am
        2026-09-16 deutsch war und in der Quelle niemandem auffiel."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        wurzel = Path(tmp.name)
        wf = wurzel / "workflows"
        wf.mkdir()
        (wf / "ci.yml").write_text(
            "name: CI\non: {pull_request: {branches: [main]}}\njobs:\n"
            '  coverage:\n    runs-on: ubuntu-latest\n    steps: [{run: "true"}]\n'
            '  tot:\n    if: false\n    runs-on: ubuntu-latest\n    steps: [{run: "true"}]\n',
            encoding="utf-8")
        decl = wurzel / "d.json"
        decl.write_text(json.dumps({"ruleset": "t", "branch": "main",
                                    "required_contexts": ["coverage", "tot"]}), encoding="utf-8")
        alt = sys.stdout
        sys.stdout = puffer = io.StringIO()
        try:
            G.main(["--declaration", str(decl), "--workflows", str(wf),
                    "--drift-marker", str(wurzel / "fehlt.json")])
        finally:
            sys.stdout = alt
        bericht = puffer.getvalue()
        self.assertIn("tot", bericht, "der Fall misst den Bericht, der den toten Job nennt")
        self._pruefe(bericht, "Gesamtbericht")

    def test_the_help_text_is_english(self):
        """`--help` landet im CI-Protokoll, sobald ein Aufruf falsch ist."""
        alt = sys.stdout
        sys.stdout = puffer = io.StringIO()
        try:
            with self.assertRaises(SystemExit):
                G.main(["--help"])
        finally:
            sys.stdout = alt
        self._pruefe(puffer.getvalue(), "--help")


class TestTheDigestSurvivesReformatting(unittest.TestCase):
    """Eine Zusage darf an der SACHE haengen, nicht an der Schreibweise der Bedingung.

    Die Gegenlesung auf der fremden Familie nannte genau das als neue Bruchstelle der
    Digest-Bindung: eine harmlose Umformatierung des Bedingungstexts erzeuge ein falsches Rot,
    das die Namensbindung nicht gehabt haette. Gemessen ist das nicht so, und diese Faelle halten
    die Antwort fest, damit sie nicht beim naechsten Umbau still verlorengeht. Der Digest laeuft
    ueber `" ".join(text.split())`, also ueber dieselbe Faltung, mit der die Bedingung auch
    gedruckt wird.

    Die Kehrseite steht als eigener Fall daneben: eine ECHTE Aenderung MUSS den Digest bewegen,
    sonst waere die Unempfindlichkeit gegen Weissraum eine Unempfindlichkeit gegen alles.
    """

    GRUND = "contains(github.event.pull_request.labels.*.name, 'landung')"

    def test_whitespace_does_not_move_the_digest(self):
        basis = G.bedingungs_digest(self.GRUND)
        for name, text in [
            ("Zeilenumbruch", "contains(github.event.pull_request.labels.*.name,\n   'landung')"),
            ("doppelte Leerzeichen",
             "contains(github.event.pull_request.labels.*.name,  'landung')"),
            ("fuehrend und abschliessend", f"   {self.GRUND}  "),
            ("Tabulator", "contains(github.event.pull_request.labels.*.name,\t'landung')"),
        ]:
            with self.subTest(name):
                self.assertEqual(G.bedingungs_digest(text), basis)

    def test_a_real_change_does_move_the_digest(self):
        self.assertNotEqual(G.bedingungs_digest(self.GRUND + " && false"),
                            G.bedingungs_digest(self.GRUND))
        self.assertNotEqual(G.bedingungs_digest(self.GRUND.replace("landung", "andere")),
                            G.bedingungs_digest(self.GRUND))


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


class TestTheAcceptedLimitIsBoundToItsReason(unittest.TestCase):
    """Der Nachbar, den der Instanz-Fix stehen liess.

    `accepted_gated` wurde am 2026-09-16 von der Namensbindung auf den Digest der Bedingung
    umgestellt, nachdem zwei unabhaengige Gegenleser dieselbe Luecke fanden. `accepted_unreadable`
    blieb dabei eine nackte Praefixliste — dieselbe Klasse, anderer Ort, im selben Durchgang
    uebersehen. Eine dritte Linse baute den Fall am selben Tag und mass ihn: derselbe Job wechselte
    von „ruft einen wiederverwendbaren Workflow" auf „Matrix nicht woertlich lesbar", zwei
    verschiedene Unmessbarkeiten unter demselben Praefix, und das Tor blieb still gruen.

    Wer eine Unmessbarkeit hinnimmt, nimmt GENAU EINE hin: die, die er gelesen hat.
    """

    def _baum(self, unlesbar_grund: str, zusage) -> tuple[Path, Path]:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        wurzel = Path(tmp.name)
        wf = wurzel / "workflows"
        wf.mkdir()
        # `coverage` laeuft unbedingt; `tot` ist der Job, dessen Unmessbarkeit zugesagt wird.
        (wf / "ci.yml").write_text(
            "name: CI\non: {pull_request: {branches: [main]}}\njobs:\n"
            '  coverage:\n    runs-on: ubuntu-latest\n    steps: [{run: "true"}]\n',
            encoding="utf-8")
        decl = wurzel / "d.json"
        inhalt = {"ruleset": "t", "branch": "main", "required_contexts": ["coverage"]}
        if zusage is not None:
            inhalt["accepted_unreadable"] = [zusage]
        decl.write_text(json.dumps(inhalt), encoding="utf-8")
        return decl, wf

    def _mit_unlesbarem(self, grund: str, zusage):
        """Der Lauf mit EINEM unlesbaren Eintrag, den wir selbst setzen.

        Der Eintrag wird ueber `erhebe` untergeschoben statt ueber eine echte Workflow-Datei:
        so ist der GRUND exakt der, den der Fall meint, und der Fall misst die Bindung, nicht die
        Kunst, eine Datei unlesbar zu machen.
        """
        decl, wf = self._baum(grund, zusage)
        echt = G.erhebe

        def gefaelscht(verzeichnis=None, zweig=None):
            e = echt(verzeichnis, zweig)
            e["unlesbar"] = [f"ci.yml:tot: {grund}"]
            return e

        G.erhebe = gefaelscht
        self.addCleanup(lambda: setattr(G, "erhebe", echt))
        return G.pruefe(decl, wf), decl, wf

    GRUND_A = "calls a reusable workflow; its context is not derived here"
    GRUND_B = "matrix values not readable literally"

    def test_the_accepted_reason_carries_when_it_is_still_the_same(self):
        """Die Gegenkontrolle: ohne sie waere jede Strenge unten auch mit einem blinden Tor
        vereinbar."""
        zusage = {"context": "ci.yml:tot", "reason_sha256": G.bedingungs_digest(self.GRUND_A)}
        r, decl, wf = self._mit_unlesbarem(self.GRUND_A, zusage)
        self.assertEqual(r["newly_unreadable"], [], r)
        self.assertEqual(r["unbound_unreadable_acceptances"], [])
        self.assertEqual(G.main(["--declaration", str(decl), "--workflows", str(wf),
                                 "--drift-marker", ""]), 0)

    def test_a_different_reason_under_the_same_prefix_does_not_carry(self):
        """DER GEMESSENE FALL. Gleicher Job, andere Unmessbarkeit — die Zusage gilt nicht."""
        zusage = {"context": "ci.yml:tot", "reason_sha256": G.bedingungs_digest(self.GRUND_A)}
        r, decl, wf = self._mit_unlesbarem(self.GRUND_B, zusage)
        self.assertEqual(len(r["newly_unreadable"]), 1, r)
        self.assertEqual(len(r["changed_reasons"]), 1, r)
        g = r["changed_reasons"][0]
        self.assertEqual(g["declared"], G.bedingungs_digest(self.GRUND_A))
        self.assertEqual(g["measured"], G.bedingungs_digest(self.GRUND_B))
        self.assertEqual(G.main(["--declaration", str(decl), "--workflows", str(wf),
                                 "--drift-marker", ""]), 1)

    def test_a_prefix_only_entry_is_an_unbound_acceptance_and_does_not_carry(self):
        """Die alte Form lebt nicht als stiller Freibrief weiter: fail closed, und sie wird
        beim Namen genannt, damit ihr Weiterleben auffaellt."""
        r, decl, wf = self._mit_unlesbarem(self.GRUND_A, "ci.yml:tot")
        self.assertEqual(r["unbound_unreadable_acceptances"], ["ci.yml:tot"])
        self.assertEqual(len(r["newly_unreadable"]), 1)
        self.assertEqual(G.main(["--declaration", str(decl), "--workflows", str(wf),
                                 "--drift-marker", ""]), 1)

    def test_a_stale_prefix_only_entry_is_red_even_when_it_covers_nothing(self):
        """Die Zusage muss den AUSGANG beruehren, nicht nur den Bericht.

        Deckt die alte Namensform zufaellig eine Stelle ab, die ohnehin gemeldet wird, faellt das
        Tor schon aus dem anderen Grund rot -- und das Glied im Ausgang sieht gebunden aus, ohne
        es zu sein. Dieser Fall nimmt ihm den zweiten Grund weg: der Eintrag passt auf gar nichts,
        `newly_unreadable` ist leer, und rot muss es trotzdem werden. Derselbe Fall existiert seit
        heute Nacht fuer die bedingte Zusage; hier ist sein Nachbar."""
        decl, wf = self._baum("egal", "es-gibt-keinen-job-dieses-namens")
        r = G.pruefe(decl, wf)
        self.assertEqual(r["newly_unreadable"], [], "der Eintrag darf nichts abdecken")
        self.assertEqual(r["unbound_unreadable_acceptances"], ["es-gibt-keinen-job-dieses-namens"])
        self.assertEqual(G.main(["--declaration", str(decl), "--workflows", str(wf),
                                 "--drift-marker", ""]), 1)

    def test_the_report_names_both_digests_of_a_changed_reason(self):
        """Ohne beide Werte kann der Leser nicht sehen, ob die Zusage alt ist oder der Grund neu —
        und er kann den neuen Wert nicht eintragen, ohne ihn zu erfinden."""
        zusage = {"context": "ci.yml:tot", "reason_sha256": G.bedingungs_digest(self.GRUND_A)}
        _, decl, wf = self._mit_unlesbarem(self.GRUND_B, zusage)
        alt_aus = sys.stdout
        sys.stdout = puffer = io.StringIO()
        try:
            G.main(["--declaration", str(decl), "--workflows", str(wf), "--drift-marker", ""])
        finally:
            sys.stdout = alt_aus
        bericht = puffer.getvalue()
        self.assertIn("reason-changed", bericht)
        self.assertIn(G.bedingungs_digest(self.GRUND_A)[:16], bericht)
        self.assertIn(G.bedingungs_digest(self.GRUND_B)[:16], bericht)


class TestNoFieldIsPrintedRaw(unittest.TestCase):
    """Ein Feld aus einer fremden Datei ist ein EINGABEWERT, kein Text.

    GEMESSEN 2026-09-16 von einer adversarialen Linse: ein Marker, dessen `ruleset` einen
    Zeilenumbruch trug, erzeugte im Bericht ZWEI zusaetzliche Zeilen, die exakt wie echte Ausgabe
    des Werkzeugs aussahen — eine gefaelschte Kontextzeile und eine zweite, erfundene Kopfzeile mit
    dem Urteil `produced`. Exit-Code 0, nichts rot, und wer den Bericht liest, sieht ein zweites
    bestandenes Urteil ueber einen Regelsatz, den niemand geprueft hat.

    Die erste Fassung faltete NUR den Grund — die Instanz, die an dem Tag aufgefallen war. Jeder
    andere Wert ging roh hinaus. Das ist dieselbe Klasse, nur an den Feldern, an die niemand
    gedacht hatte, und deshalb steht hier eine EIGENSCHAFT ueber alle Felder, keine Liste von
    Einzelfaellen.
    """

    def _baum(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        wurzel = Path(tmp.name)
        wf = wurzel / "workflows"
        wf.mkdir()
        (wf / "ci.yml").write_text(
            "name: CI\non: {pull_request: {branches: [main]}}\njobs:\n"
            '  coverage:\n    runs-on: ubuntu-latest\n    steps: [{run: "true"}]\n',
            encoding="utf-8")
        decl = wurzel / "d.json"
        decl.write_text(json.dumps({"ruleset": "t", "branch": "main",
                                    "required_contexts": ["coverage"]}), encoding="utf-8")
        return wurzel, decl, wf

    def _bericht(self, decl, wf, marker) -> tuple[str, int]:
        alt = sys.stdout
        sys.stdout = puffer = io.StringIO()
        try:
            rc = G.main(["--declaration", str(decl), "--workflows", str(wf),
                         "--drift-marker", str(marker)])
        finally:
            sys.stdout = alt
        return puffer.getvalue(), rc

    EINSCHLEUSUNG = ("protect-main\n"
                     "  never-produced     ein-frei-erfundener-pflichtcheck\n"
                     "[required-checks] ruleset FAKE on main: produced")

    def test_a_newline_in_a_marker_field_adds_no_line_to_the_report(self):
        """Der Exploit im Wortlaut, als Fall. Gezaehlt werden ZEILEN, nicht Woerter: die
        Einschleusung faellt nur auf, wenn der Bericht laenger wird."""
        wurzel, decl, wf = self._baum()
        digest = hashlib.sha256(decl.read_bytes()).hexdigest()
        sauber = wurzel / "sauber.json"
        sauber.write_text(json.dumps({"verdict": G.ALWAYS, "ruleset": "protect-main",
                                      "at": "2026-09-16T05:00:00Z",
                                      "declaration_sha256": digest}), encoding="utf-8")
        ohne, _ = self._bericht(decl, wf, sauber)
        for feld in ("ruleset", "at", "verdict"):
            with self.subTest(feld):
                m = wurzel / f"m_{feld}.json"
                inhalt = {"verdict": G.ALWAYS, "ruleset": "protect-main",
                          "at": "2026-09-16T05:00:00Z", "declaration_sha256": digest}
                inhalt[feld] = self.EINSCHLEUSUNG
                m.write_text(json.dumps(inhalt), encoding="utf-8")
                mit, _ = self._bericht(decl, wf, m)
                self.assertEqual(mit.count("\n"), ohne.count("\n"),
                                 f"ein Zeilenumbruch in {feld} hat den Bericht verlaengert:\n{mit}")
                # DIE EIGENSCHAFT, NICHT DAS WORT: der eingeschleuste Text DARF in einer Zeile
                # auftauchen (er ist ja Inhalt eines Feldes). Was nicht passieren darf, ist eine
                # eigene ZEILE in der Form des Werkzeugs -- genau daran erkennt ein Leser echte
                # Ausgabe. Eine Pruefung auf das Wort waere hier zufaellig gruen geworden, weil
                # die Kappung bei 64 Zeichen die Faelschung abschneidet; das ist Glueck, keine
                # Zusicherung.
                kopfzeilen = [z for z in mit.split("\n") if z.startswith("[required-checks]")]
                self.assertEqual(len(kopfzeilen), 1, f"zweite Kopfzeile im Bericht:\n{mit}")

    def test_a_newline_in_a_context_name_adds_no_line_to_the_report(self):
        """Dieselbe Klasse an der ANDEREN Eingabe: die Erklaerung ist auch nur eine Datei, und in
        einem Fork-PR ist sie eine, die jemand anders geschrieben hat."""
        wurzel, decl, wf = self._baum()
        ohne, _ = self._bericht(decl, wf, wurzel / "fehlt.json")
        decl.write_text(json.dumps({
            "ruleset": "t", "branch": "main",
            "required_contexts": ["coverage", "x\n[required-checks] ruleset FAKE on main: produced"],
        }), encoding="utf-8")
        mit, _ = self._bericht(decl, wf, wurzel / "fehlt.json")
        kopfzeilen = [z for z in mit.split("\n") if z.startswith("[required-checks]")]
        self.assertEqual(len(kopfzeilen), 1, f"zweite Kopfzeile im Bericht:\n{mit}")
        self.assertEqual(mit.count("\n"), ohne.count("\n") + 1,
                         f"ein Kontext mehr darf GENAU eine Zeile mehr ergeben:\n{mit}")

    def test_a_control_character_is_folded_too(self):
        """`str.split()` faengt Zeilenumbruch und Tabulator, aber kein NUL."""
        self.assertEqual(G._einzeilig("a\x00b"), "a b")
        self.assertEqual(G._einzeilig("a\rb\nc\td"), "a b c d")

    def test_a_field_of_the_wrong_type_is_a_state_not_a_crash(self):
        """GEMESSEN: `"declaration_sha256": 123456` warf `TypeError` mitten im Bericht — die
        Zeilen davor standen da, alles danach fehlte, und der Ausgang war ein Traceback."""
        wurzel, decl, wf = self._baum()
        # JEDER FALL NENNT SEINE LAGE. Ein `assertIn(state, ("unreadable", "stale"))` sieht wie
        # Abdeckung aus und ist keine: ein Digest vom falschen Typ wird auch OHNE Formpruefung
        # `stale`, weil eine Zahl nie gleich einem Digest ist. Der Unterschied steckt in der
        # Begruendung -- Formfehler oder geaenderte Erklaerung -- und nur die benannte Lage
        # unterscheidet beides.
        for feld, wert, lage_soll, wort in (
            ("declaration_sha256", 123456, "unreadable", "not text"),
            ("declaration_sha256", ["a" * 64], "unreadable", "not text"),
            ("verdict", 7, "unreadable", "no verdict"),
            ("verdict", True, "unreadable", "no verdict"),
            ("verdict", "   ", "unreadable", "no verdict"),
            ("at", ["x"], "unreadable", "no timestamp"),
            ("at", 0, "unreadable", "no timestamp"),
        ):
            with self.subTest(f"{feld}={wert!r}"):
                m = wurzel / "m.json"
                inhalt = {"verdict": G.ALWAYS, "ruleset": "protect-main", "at": "t",
                          "declaration_sha256": hashlib.sha256(decl.read_bytes()).hexdigest()}
                inhalt[feld] = wert
                m.write_text(json.dumps(inhalt), encoding="utf-8")
                lage = G.drift_lage(str(m), decl)
                self.assertEqual(lage["state"], lage_soll, lage)
                self.assertIn(wort, lage["why"], lage)
                bericht, rc = self._bericht(decl, wf, m)
                self.assertIn("drift-check", bericht)
                self.assertEqual(rc, 0, "der Marker hat den Ausgang bewegt")


class TestTheSmallHelpersAreBoundToo(unittest.TestCase):
    """Fuenf Stellen, die eine Mutationspruefung als UNGEBUNDEN meldete — und sie hatte recht.

    Eine Linse fuhr am 2026-09-16 einundvierzig Mutanten gegen dieses Werkzeug. Neunundzwanzig
    fielen, zwoelf ueberlebten, und KEINER der Ueberlebenden sass in einem toten Zweig: es waren
    durchweg Stellen, die sehr wohl entscheiden koennen, ueber die nur kein Fall etwas sagte. Das
    ist der teurere der beiden Befunde, weil er wie Abdeckung aussieht.
    """

    def test_a_match_says_it_matches_and_does_not_read_like_a_drift(self):
        """Der Treffer-Zweig war nur ueber Teilzeichenketten gebunden, die auch im DRIFT-Satz
        stehen ('checked at', der Regelsatzname). Ein Mutant, der ALWAYS durch GATED ersetzte,
        ueberlebte deshalb alle Faelle."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        decl = Path(tmp.name) / "d.json"
        decl.write_bytes(b'{"ruleset": "t"}')
        m = Path(tmp.name) / "m.json"
        m.write_text(json.dumps({
            "verdict": G.ALWAYS, "ruleset": "protect-main", "at": "2026-09-16T05:00:00Z",
            "declaration_sha256": hashlib.sha256(decl.read_bytes()).hexdigest()}), encoding="utf-8")
        zeile = G._drift_zeile(str(m), decl)
        self.assertIn("declaration matches the live ruleset", zeile)
        self.assertNotIn("DRIFT", zeile)
        self.assertNotIn("NOT MEASURABLE", zeile)

    def test_the_cap_is_bound_at_its_own_boundary(self):
        """159, 160, 161 — die einzige Stelle, an der die Grenze etwas entscheidet.

        Der vorhandene Fall benutzte 500 Zeichen, also weit jenseits jeder Grenzumgebung; vier
        Mutanten an der Grenze (160 auf 159, 160 auf 161, `<=` auf `<`, `grenze-1` auf `grenze`)
        ueberlebten ihn alle."""
        self.assertEqual(G._einzeilig("x" * 159), "x" * 159, "unterhalb der Grenze: unveraendert")
        self.assertEqual(G._einzeilig("x" * 160), "x" * 160, "AUF der Grenze: unveraendert")
        gekappt = G._einzeilig("x" * 161)
        self.assertEqual(len(gekappt), 160, "ueber der Grenze: hoechstens grenze Zeichen")
        self.assertTrue(gekappt.endswith("\u2026"), "gekappt, aber ohne sichtbare Marke")
        self.assertEqual(len(G._einzeilig("y" * 500, 40)), 40)

    def test_the_default_declaration_path_is_the_one_of_this_repository(self):
        """`_erklaerungs_digest(None)` war von keinem Fall beruehrt — der ganze Standardpfad lief
        im Testlauf nie. Genau ueber ihn laeuft aber der Marker im CI, wo niemand `--declaration`
        setzt."""
        echt = Path(G.__file__).resolve().parents[1] / ".github" / "required_status_checks.json"
        if not echt.is_file():
            self.skipTest("declaration not present here")
        self.assertEqual(G._erklaerungs_digest(None),
                         hashlib.sha256(echt.read_bytes()).hexdigest())
        self.assertNotEqual(G._erklaerungs_digest(None), "")

    def test_the_digest_of_an_absent_condition_is_not_a_crash(self):
        """Der `or ""`-Schutz in `bedingungs_digest` war ungebunden; ohne ihn wirft `None` ein
        `AttributeError` an einer Stelle, die ein Urteil liefern soll."""
        self.assertEqual(G.bedingungs_digest(None), G.bedingungs_digest(""))
        self.assertEqual(len(G.bedingungs_digest(None)), 64)

    def test_an_acceptance_of_the_wrong_shape_never_binds(self):
        """Drei Teilbedingungen der Formpruefung waren einzeln entfernbar, ohne dass ein Fall
        fiel. Jede bekommt hier ihren eigenen Fall, denn jede laesst etwas anderes durch: einen
        Eintrag OHNE Namen (der sonst unter dem Schluessel None bindet), einen Digest, der kein
        Text ist, und einen, der Text aber kein Hex ist."""
        gut = "a" * 64
        for name, eintrag in (
            ("ohne Namen", {"condition_sha256": gut}),
            ("Name leer", {"context": "", "condition_sha256": gut}),
            ("Digest ist eine Zahl", {"context": "c", "condition_sha256": 123}),
            ("Digest ist None", {"context": "c", "condition_sha256": None}),
            ("Digest ist kein Hex", {"context": "c", "condition_sha256": "kein-hex"}),
            ("Digest zu kurz", {"context": "c", "condition_sha256": "a" * 63}),
            ("Digest zu lang", {"context": "c", "condition_sha256": "a" * 65}),
            ("Digest in Grossbuchstaben", {"context": "c", "condition_sha256": "A" * 64}),
        ):
            with self.subTest(name):
                bindend, lose = G._zusagen([eintrag])
                self.assertEqual(bindend, {}, f"{name} hat gebunden: {bindend}")
                self.assertEqual(len(lose), 1, f"{name} wurde nicht einmal genannt")
        bindend, lose = G._zusagen([{"context": "c", "condition_sha256": gut}])
        self.assertEqual(bindend, {"c": gut}, "die Gegenkontrolle: eine gueltige Zusage bindet")
        self.assertEqual(lose, [])


class TestAgainstThisRepository(unittest.TestCase):

    def test_the_real_declaration_matches_what_was_measured_by_hand(self):
        """Not a fixture: the gate is run against this repository's own files and must reproduce
        the measurement of 2026-09-16 -- three contexts unconditional, four behind the label --
        or, since the ruleset switch of 2026-09-18, the measurement of that day."""
        r = G.pruefe()
        if r["verdict"] == G.UNKNOWN:
            self.skipTest(f"declaration not readable here: {r.get('reason')}")
        zustand = {e["context"]: e["state"] for e in r["per_context"]}
        verlangt = json.loads(G.DECLARATION.read_text(encoding="utf-8"))["required_contexts"]
        if "all-checks-passed" in verlangt:
            # Measured by hand on 2026-09-18 after the ruleset switch: two contexts, both
            # unconditional -- guard from fork-pr-isolation.yml, the collector as a status
            # function only (`if: ${{ !cancelled() }}`), which the gate reads as produced.
            self.assertEqual(sorted(zustand), ["all-checks-passed", "guard"])
            self.assertEqual(zustand["guard"], G.ALWAYS)
            self.assertEqual(zustand["all-checks-passed"], G.ALWAYS)
            return
        self.assertEqual(zustand.get("coverage"), G.ALWAYS)
        self.assertEqual(zustand.get("guard"), G.ALWAYS)
        self.assertEqual(zustand.get("test (3.12)"), G.ALWAYS)
        for v in ("3.10", "3.11", "3.13", "3.14"):
            self.assertEqual(zustand.get(f"test ({v})"), G.GATED,
                             f"test ({v}) was measured as produced only under the landung label")

    def test_the_gate_is_green_on_this_repository(self):
        """DER BODEN, und er fehlte. Die Fassung darueber prueft die Zustaende der Kontexte und
        sagt nichts ueber den AUSGANG — als die Zusage fuer eine unlesbare Stelle auf die
        gebundene Form umgestellt wurde, war das Tor auf dem eigenen Repo rot, und keiner der
        achtundfuenfzig Faelle merkte es. Gemessen wurde es von Hand, was genau der Zustand ist,
        den eine Vertragsdatei abschaffen soll.

        Der Marker wird ausdruecklich abgeschaltet: in einem frischen Checkout gibt es ihn nicht,
        und er darf den Ausgang ohnehin nie bewegen."""
        if G.pruefe()["verdict"] == G.UNKNOWN:
            self.skipTest("declaration not readable here")
        self.assertEqual(G.main(["--drift-marker", ""]), 0,
                         "das Tor ist auf seinem eigenen Repo rot")


class TestTheLivePullRequestIsJudgedNotOnlyTheStructure(unittest.TestCase):
    """DER WAECHTER FING SEINE KLASSE AM LEBENDEN PR NICHT. Gemessen 2026-09-17 an PR 218.

    Das Offline-Tor fragt: KANN der Workflow den Kontext unter einer benannten Bedingung erzeugen?
    Seine Sohle nimmt die vier Versionskontexte hinter der Fuenf-Zweig-Bedingung hin, also exit 0.
    Der PR 218 trug kein Label `landung`, kein release/-Kopf, kein workflow_dispatch -- die
    Bedingung war auf DIESEM Ereignis falsch, test (3.10), (3.11), (3.13), (3.14) wuerden nie
    eintreffen, und der Job `required-check-reachability` stand GRUEN darueber. Genau das Bild,
    gegen das dieses Tor geschrieben wurde, mit dem Tor selbst als Zeugen der Struktur.

    Die lebende Frage ist eine andere: WIRD dieses Ereignis die Bedingung wahr machen? Der Runner
    haelt alles dafuer bereit (GITHUB_EVENT_NAME, GITHUB_EVENT_PATH, GITHUB_HEAD_REF,
    GITHUB_REF_NAME, GITHUB_REPOSITORY). Die Faelle hier stellen das Ereignis, nicht den Zustand:
    ein Fangnachweis am Speicher beweist nichts (Gedaechtnis 2026-09-12).
    """

    LABEL = "contains(github.event.pull_request.labels.*.name, 'landung')"

    @staticmethod
    def _ereignis(event="pull_request", labels=(), head_ref="docs/x", head_repo="o/r",
                  repository="o/r", ref_name="1/merge"):
        return {"event_name": event, "repository": repository, "head_ref": head_ref,
                "ref_name": ref_name,
                "payload": {"pull_request": {"labels": [{"name": n} for n in labels],
                                             "head": {"repo": {"full_name": head_repo}}}}}

    def _baum(self, verlangt=("coverage", "test (3.12)", "test (3.10)"), zusage=True):
        b = Baum(self, {"ci.yml": CI}, list(verlangt))
        if zusage:
            bed = ("( github.event_name == 'workflow_dispatch' || "
                   "contains(github.event.pull_request.labels.*.name, 'landung') )")
            d = json.loads(b.decl.read_text(encoding="utf-8"))
            d["accepted_gated"] = [{"context": "test (3.10)",
                                    "condition_sha256": G.bedingungs_digest(bed)}]
            b.decl.write_text(json.dumps(d), encoding="utf-8")
        return b

    def _live(self, b, ereignis) -> dict:
        return G.lebend(ereignis, b.decl, b.wf)

    def test_the_offline_gate_is_green_on_the_blocked_shape_and_the_live_one_is_red(self):
        """DIE KLASSE, ausfuehrbar: derselbe Baum, dieselbe Erklaerung, zwei Antworten.

        Die erste Zusicherung hielt schon VOR dem Fix (sie IST der Befund: das alte Tor war gruen);
        die zweite gab es vorher nicht. Zusammen sagen sie, was der Job auf PR 218 sagen musste."""
        b = self._baum()
        self.assertEqual(b.rc("--drift-marker", ""), 0,
                         "die Sohle nimmt den bedingten Kontext hin -- das Offline-Tor ist gruen")
        d = self._live(b, self._ereignis(labels=()))
        self.assertEqual(d["verdict"], G.ABSENT)
        self.assertEqual(d["missing"], ["test (3.10)"])
        self.assertIn("landung", d["advice"], "die eine Handlung, die den Kontext bringt, steht da")

    def test_the_label_makes_the_context_arrive(self):
        """Die Gegenkontrolle: mit dem Label ist der lebende Lauf gruen. Ohne diesen Fall koennte
        der Auswerter jede Bedingung als falsch lesen und der Fall darueber bliebe rot-gruen."""
        d = self._live(self._baum(), self._ereignis(labels=("landung",)))
        self.assertEqual(d["verdict"], G.ALWAYS)
        self.assertEqual(d["missing"], [])

    def test_github_compares_case_insensitively_and_so_does_the_evaluator(self):
        """`contains`, `startsWith` und `==` vergleichen bei GitHub ohne Gross-Klein-Unterscheidung.
        Ein Auswerter, der `Landung` verwirft, wuerde einen PR rot melden, den GitHub gruen faehrt."""
        d = self._live(self._baum(), self._ereignis(labels=("Landung",)))
        self.assertEqual(d["verdict"], G.ALWAYS)
        self.assertTrue(G.bedingung_am_ereignis("github.event_name == 'Pull_Request'",
                                                self._ereignis()))
        self.assertTrue(G.bedingung_am_ereignis("startsWith(github.head_ref, 'RELEASE/')",
                                                self._ereignis(head_ref="release/6.1.0")))

    def test_workflow_dispatch_makes_it_arrive_without_a_label(self):
        d = self._live(self._baum(), self._ereignis(event="workflow_dispatch"))
        self.assertEqual(d["verdict"], G.ALWAYS)

    def test_and_binds_tighter_than_or(self):
        """Dieselbe Klammer-Frage wie im Workflow-Kommentar, hier am Auswerter gemessen."""
        ev = self._ereignis()
        self.assertFalse(G.bedingung_am_ereignis("false || true && false", ev))
        self.assertTrue(G.bedingung_am_ereignis("true || false && false", ev))
        self.assertFalse(G.bedingung_am_ereignis("( true || false ) && false", ev))

    def test_the_five_branch_condition_of_this_repository(self):
        """Die echte Bedingung aus ci.yml, Zweig fuer Zweig, in der Form seit der Velocity-Regel
        vom 2026-09-17: jeder PR aus dem EIGENEN Repo, ein release/-Ref, das Label, ein
        Dispatch, die Merge-Queue. Ein Fork-PR ohne Label bleibt draussen."""
        bed = ("( github.event_name == 'workflow_dispatch' || github.event.pull_request.head.repo"
               ".full_name == github.repository || startsWith(github.ref_name, 'release/') || "
               "contains(github.event.pull_request.labels.*.name, 'landung') || "
               "github.event_name == 'merge_group' )")
        self.assertTrue(G.bedingung_am_ereignis(bed, self._ereignis()),
                        "ein PR aus dem eigenen Repo faehrt die volle Matrix, auch ohne Label")
        self.assertFalse(G.bedingung_am_ereignis(bed, self._ereignis(head_repo="fremd/r")),
                         "ein Fork-PR ohne Label bleibt an der Schranke")
        self.assertTrue(G.bedingung_am_ereignis(bed, self._ereignis(head_repo="fremd/r",
                                                                    labels=("landung",))))
        self.assertTrue(G.bedingung_am_ereignis(bed, self._ereignis(event="merge_group",
                                                                    head_repo="")))
        self.assertTrue(G.bedingung_am_ereignis(bed, self._ereignis(ref_name="release/6.1.0",
                                                                    head_repo="fremd/r")))
        self.assertFalse(G.bedingung_am_ereignis(bed, self._ereignis(event="push", head_repo="")),
                         "ein gewoehnlicher Push faehrt die schnelle Schicht")

    def test_an_atom_the_evaluator_does_not_know_is_not_measurable_never_a_pass(self):
        """Ein unbekanntes Fragment darf nicht still als wahr oder falsch gelten."""
        with self.assertRaises(G.NichtAuswertbar):
            G.bedingung_am_ereignis("fromJSON(needs.vorher.outputs.x)", self._ereignis())
        with self.assertRaises(G.NichtAuswertbar):
            G.bedingung_am_ereignis("( true", self._ereignis())
        with self.assertRaises(G.NichtAuswertbar):
            G.bedingung_am_ereignis("", self._ereignis())
        fremd = CI.replace("contains(github.event.pull_request.labels.*.name, 'landung')",
                           "github.actor == 'jemand'")
        b = Baum(self, {"ci.yml": fremd}, ["coverage", "test (3.10)"])
        d = G.lebend(self._ereignis(), b.decl, b.wf)
        self.assertEqual(d["verdict"], G.UNKNOWN)
        self.assertEqual(d["not_measurable"], ["test (3.10)"])
        self.assertEqual(G.main(["--verify-live-pr", "--declaration", str(b.decl), "--workflows", str(b.wf)]), 1)

    def test_a_job_level_if_is_judged_on_the_event_too(self):
        wf = ("name: CI\non: {pull_request: {branches: [main]}, push: null}\njobs:\n"
              "  coverage:\n    if: github.event_name == 'push'\n"
              '    runs-on: ubuntu-latest\n    steps: [{run: "true"}]\n')
        b = Baum(self, {"ci.yml": wf}, ["coverage"])
        self.assertEqual(G.lebend(self._ereignis(), b.decl, b.wf)["verdict"], G.ABSENT)
        self.assertEqual(G.lebend(self._ereignis(event="push"), b.decl, b.wf)["verdict"], G.ALWAYS)

    def test_a_context_nobody_produces_will_not_arrive_and_the_advice_says_so(self):
        b = Baum(self, {"ci.yml": CI}, ["coverage", "gibt-es-nicht"])
        d = G.lebend(self._ereignis(labels=("landung",)), b.decl, b.wf)
        self.assertEqual(d["missing"], ["gibt-es-nicht"])
        self.assertIn("no workflow produces", d["advice"])
        self.assertNotIn("landung", d["advice"], "das Label hilft hier nicht, also wird es nicht geraten")

    def test_outside_actions_the_live_run_is_not_measurable(self):
        import os
        for k in ("GITHUB_EVENT_NAME", "GITHUB_EVENT_PATH"):
            alt = os.environ.pop(k, None)
            if alt is not None:
                self.addCleanup(os.environ.__setitem__, k, alt)
        self.assertIsNone(G.ereignis_aus_umgebung())
        d = G.lebend(None)
        self.assertEqual(d["verdict"], G.UNKNOWN)
        self.assertIn("not running under GitHub Actions", d["reason"])
        b = self._baum()
        self.assertEqual(G.main(["--verify-live-pr", "--declaration", str(b.decl), "--workflows", str(b.wf)]), 1)

    def test_the_event_comes_from_the_runner_variables(self):
        """Der ganze Pfad, den CI geht: Umgebungsvariablen, Nutzlastdatei, Urteil, Exit-Code."""
        import os
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        nutzlast = Path(tmp.name) / "event.json"
        nutzlast.write_text(json.dumps({"pull_request": {"labels": [],
                                                         "head": {"repo": {"full_name": "o/r"}}}}),
                            encoding="utf-8")
        env = {"GITHUB_EVENT_NAME": "pull_request", "GITHUB_EVENT_PATH": str(nutzlast),
               "GITHUB_REPOSITORY": "o/r", "GITHUB_HEAD_REF": "docs/x", "GITHUB_REF_NAME": "1/merge"}
        alt = {k: os.environ.get(k) for k in env}
        os.environ.update(env)
        self.addCleanup(lambda: [os.environ.__setitem__(k, v) if v is not None else os.environ.pop(k, None)
                                 for k, v in alt.items()])
        b = self._baum()
        self.assertEqual(G.main(["--verify-live-pr", "--declaration", str(b.decl), "--workflows", str(b.wf)]), 1,
                         "ohne Label wird test (3.10) nicht eintreffen -- rot")
        nutzlast.write_text(json.dumps({"pull_request": {"labels": [{"name": "landung"}],
                                                         "head": {"repo": {"full_name": "o/r"}}}}),
                            encoding="utf-8")
        self.assertEqual(G.main(["--verify-live-pr", "--declaration", str(b.decl), "--workflows", str(b.wf)]), 0,
                         "mit Label trifft alles ein -- gruen")
        kaputt = Path(tmp.name) / "kaputt.json"
        kaputt.write_text("kein json", encoding="utf-8")
        os.environ["GITHUB_EVENT_PATH"] = str(kaputt)
        self.assertEqual(G.main(["--verify-live-pr", "--declaration", str(b.decl), "--workflows", str(b.wf)]), 1,
                         "eine unlesbare Nutzlast ist NICHT MESSBAR, nie ein Bestehen")

    def test_the_live_report_is_english_in_every_state(self):
        b = self._baum()
        for name, ev in (("red", self._ereignis()), ("green", self._ereignis(labels=("landung",)))):
            with self.subTest(name):
                bericht = "\n".join(G._lebend_bericht(G.lebend(ev, b.decl, b.wf)))
                self.assertFalse(_dp.treffer(bericht), f"deutsche Woerter in {name}: {bericht!r}")
        self.assertFalse(_dp.treffer("\n".join(G._lebend_bericht(G.lebend(None)))))
        fremd = Baum(self, {"ci.yml": CI.replace(
            "contains(github.event.pull_request.labels.*.name, 'landung')", "github.actor == 'x'")},
            ["test (3.10)"])
        self.assertFalse(_dp.treffer("\n".join(G._lebend_bericht(
            G.lebend(self._ereignis(), fremd.decl, fremd.wf)))))

    def test_a_label_name_with_a_newline_adds_no_line_to_the_live_report(self):
        """Ein Feld aus einer fremden Datei ist ein Eingabewert: ein Label heisst, was der
        Ersteller des PR tippt."""
        b = self._baum()
        ohne = G._lebend_bericht(G.lebend(self._ereignis(labels=("a",)), b.decl, b.wf))
        mit = G._lebend_bericht(G.lebend(self._ereignis(labels=("a\n[live-checks] fake",)), b.decl, b.wf))
        self.assertEqual(len(mit), len(ohne))
        self.assertEqual(sum(z.count("\n") for z in mit), 0)

    def test_against_this_repository_the_shape_of_pull_request_218(self):
        """Nicht Kulisse, sondern die Workflows dieses Repos. Am 2026-09-17 fehlten auf PR 218 (Kopf
        aus dem eigenen Repo, kein Label) genau die vier Versionskontexte. Seit der Velocity-Regel
        desselben Tages (volle Matrix fuer jeden PR aus dem eigenen Repo) TRIFFT auf dieser Form
        alles ein; die vier fehlen nur noch auf einem FORK-PR ohne Label, und mit Label auch dort
        nicht. Der Vertrag misst beide Seiten der Regel, sonst waere er nach der Umstellung leer."""
        if G.pruefe()["verdict"] == G.UNKNOWN:
            self.skipTest("declaration not readable here")
        eigen = self._ereignis(head_ref="docs/register-head-migration-1a", repository="b7n0de/proofbundle",
                               head_repo="b7n0de/proofbundle", ref_name="218/merge")
        d = G.lebend(eigen)
        self.assertEqual(d["verdict"], G.ALWAYS, "eigenes Repo, kein Label: die volle Matrix laeuft")
        self.assertEqual(d["not_measurable"], [], "die echte Bedingung ist vollstaendig auswertbar")
        fork = self._ereignis(head_ref="docs/x", repository="b7n0de/proofbundle",
                              head_repo="fremd/proofbundle", ref_name="999/merge")
        d = G.lebend(fork)
        verlangt = json.loads(G.DECLARATION.read_text(encoding="utf-8"))["required_contexts"]
        if "all-checks-passed" in verlangt:
            # SINCE 2026-09-18 (ruleset on the collector): the four version contexts are no longer
            # required, so NO required context is absent on a fork pull request without the label.
            # The barrier moved into the collector's verdict (a skipped leg makes it red, measured
            # on pull request 223). The contract measures that nothing required is absent and that
            # the collector arrives on every event as a status function.
            self.assertEqual(d["missing"], [], "nothing required is absent on a fork pull request")
            self.assertEqual(d["verdict"], G.ALWAYS)
        else:
            self.assertEqual(d["missing"], ["test (3.10)", "test (3.11)", "test (3.13)", "test (3.14)"],
                             "ein Fork-PR ohne Label bleibt an der Schranke")
            self.assertIn("landung", d["advice"])
        fork["payload"]["pull_request"]["labels"] = [{"name": "landung"}]
        self.assertEqual(G.lebend(fork)["verdict"], G.ALWAYS, "mit Label auch auf dem Fork")

    # --- die Linsen vom 2026-09-17: zwei Funde und sechs ueberlebende Mutanten, je ein Fall ------

    def test_an_unreadable_workflow_file_makes_absence_not_measurable(self):
        """DER FUND ZWEIER LINSEN, unabhaengig: ohne PyYAML (der Schritt davor kann fehlschlagen,
        und `if: always()` faehrt den Live-Schritt trotzdem) las sich jeder Pflichtkontext als
        'WILL NOT ARRIVE, no workflow produces it', und der Rat zeigte auf den Regelsatz -- die
        eine Richtung, gegen die dieses Tor gebaut ist. Abwesenheit ist nur ein Urteil, wenn jede
        Datei GELESEN wurde."""
        b = Baum(self, {"ci.yml": CI, "kaputt.yml": "jobs: [this: is: not: a: mapping\n"},
                 ["coverage", "gibt-es-nicht"])
        d = G.lebend(self._ereignis(labels=("landung",)), b.decl, b.wf)
        zustand = {z["context"]: z["live"] for z in d["per_context"]}
        self.assertEqual(zustand["coverage"], G.ARRIVES, "eine lesbare Datei erzeugt weiter")
        self.assertEqual(zustand["gibt-es-nicht"], G.UNKNOWN,
                         "mit einer unlesbaren Datei ist Abwesenheit nicht messbar")
        self.assertEqual(d["verdict"], G.UNKNOWN)
        self.assertTrue(d["unreadable_files"] and "kaputt.yml" in d["unreadable_files"][0])
        bericht = "\n".join(G._lebend_bericht(d))
        self.assertIn("unreadable-file", bericht)
        self.assertNotIn("no workflow produces it", bericht)
        self.assertIsNone(d["advice"], "kein Rat auf den Regelsatz aus einer Lesestoerung")

    def test_without_pyyaml_nothing_is_measurable_and_nothing_is_absent(self):
        """Dieselbe Klasse an der Wurzel: fehlt der Parser, ist KEINE Datei gelesen."""
        alt = G.yaml
        G.yaml = None
        self.addCleanup(setattr, G, "yaml", alt)
        b = self._baum()
        d = G.lebend(self._ereignis(), b.decl, b.wf)
        self.assertEqual(d["verdict"], G.UNKNOWN)
        self.assertEqual(d["missing"], [], "ohne Parser ist nichts 'abwesend', nur unmessbar")
        self.assertTrue(all(z["live"] == G.UNKNOWN for z in d["per_context"]))
        self.assertIn("PyYAML", " ".join(d["unreadable_files"]))

    def test_the_label_advice_is_only_given_on_a_pull_request(self):
        """Linse 1: auf einem push gibt es nichts zu labeln."""
        b = self._baum()
        d = G.lebend(self._ereignis(event="push"), b.decl, b.wf)
        self.assertEqual(d["missing"], ["test (3.10)"])
        self.assertNotIn("landung", d["advice"] or "")
        d = G.lebend(self._ereignis(event="pull_request"), b.decl, b.wf)
        self.assertIn("landung", d["advice"])

    def test_the_two_modes_exclude_each_other(self):
        with self.assertRaises(SystemExit):
            G.main(["--verify-live-pr", "--verify-declaration"])

    def test_absent_outranks_not_measurable_in_the_verdict(self):
        """Mutant m7: ein Kontext, den niemand erzeugt, macht das Urteil rot, auch wenn ein
        anderer nebenan nicht messbar ist."""
        fremd = CI.replace("contains(github.event.pull_request.labels.*.name, 'landung')",
                           "github.actor == 'jemand'")
        b = Baum(self, {"ci.yml": fremd}, ["gibt-es-nicht", "test (3.10)"])
        d = self._live(b, self._ereignis())
        self.assertEqual(d["verdict"], G.ABSENT)
        self.assertEqual(d["missing"], ["gibt-es-nicht"])
        self.assertEqual(d["not_measurable"], ["test (3.10)"])

    def test_an_unreadable_event_payload_is_named_not_treated_as_empty(self):
        """Mutant m11: eine unlesbare Nutzlast ist ein Fehler mit Namen, keine leere Nutzlast."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        kaputt = Path(tmp.name) / "event.json"
        kaputt.write_text("kein json", encoding="utf-8")
        ereignis = G.ereignis_aus_umgebung({"GITHUB_EVENT_NAME": "pull_request",
                                           "GITHUB_EVENT_PATH": str(kaputt)})
        self.assertIn("fehler", ereignis)
        d = G.lebend(ereignis)
        self.assertEqual(d["verdict"], G.UNKNOWN)
        self.assertIn("not readable", d["reason"])

    def test_the_unknown_fragment_is_named_in_the_error(self):
        """Mutant m12: die Ausnahme sagt WAS sie nicht versteht, nicht nur DASS."""
        with self.assertRaises(G.NichtAuswertbar) as ctx:
            G.bedingung_am_ereignis("fromJSON(needs.vorher.outputs.x)", self._ereignis())
        self.assertIn("cannot evaluate", str(ctx.exception))
        self.assertIn("fromJSON", str(ctx.exception))

    def test_a_context_name_with_a_newline_adds_no_line_either(self):
        """Mutant m13: der Kontextname kommt aus der Erklaerung, also aus einer Datei."""
        b = Baum(self, {"ci.yml": CI}, ["coverage", "test (3.12)\n[live-checks] fake"])
        bericht = G._lebend_bericht(G.lebend(self._ereignis(labels=("landung",)), b.decl, b.wf))
        self.assertEqual(sum(z.count("\n") for z in bericht), 0)
        self.assertEqual(len([z for z in bericht if z.startswith("[live-checks]")]), 1)

    def test_not_equal_is_the_negation_of_equal(self):
        """Mutant m16: `!=` wurde still wie `==` gelesen; kein Fall benutzte es."""
        ev = self._ereignis(event="push")
        self.assertTrue(G.bedingung_am_ereignis("github.event_name != 'pull_request'", ev))
        self.assertFalse(G.bedingung_am_ereignis("github.event_name != 'push'", ev))

    def test_contains_is_membership_not_substring(self):
        """Mutant m17: `contains(labels.*.name, 'landung')` ist Mitgliedschaft; ein Label
        `landung-request` macht die Bedingung NICHT wahr."""
        d = self._live(self._baum(), self._ereignis(labels=("landung-request",)))
        self.assertEqual(d["verdict"], G.ABSENT)
        self.assertEqual(d["missing"], ["test (3.10)"])


class TestTheCollectorJob(unittest.TestCase):
    """ONE CONTEXT THAT ALWAYS REPORTS. Owner decision A on card OA-3c67b06ad6 (2026-09-16): an
    always-running collector job becomes the required context, so that a context nobody produces
    can no longer hold a pull request BLOCKED with nothing red on it.

    Two shapes of that job are wrong in a way this gate must see. A collector WITHOUT an
    `always()`/`!cancelled()` guard is skipped whenever a needed job fails, and a skipped required
    check reads as passed: the one job built to block on failures would block on none. And the
    first draft of this very gate called `if: ${{ !cancelled() }}` a NAMED CONDITION, which would
    have made the collector `produced-only-if` -- red from its first run, for the wrong reason.
    Every case below can go red; the planted-defect ones assert the catch.
    """

    GUARDED = CI + """
  all-checks-passed:
    needs: [test, coverage]
    if: ${{ !cancelled() }}
    runs-on: ubuntu-latest
    steps: [{run: "true"}]
"""
    ALWAYS_FORM = CI + """
  all-checks-passed:
    needs: [test, coverage]
    if: always()
    runs-on: ubuntu-latest
    steps: [{run: "true"}]
"""
    UNGUARDED = CI + """
  all-checks-passed:
    needs: [test, coverage]
    runs-on: ubuntu-latest
    steps: [{run: "true"}]
"""
    FAILURE_ONLY = CI + """
  all-checks-passed:
    needs: [test, coverage]
    if: failure()
    runs-on: ubuntu-latest
    steps: [{run: "true"}]
"""

    @staticmethod
    def _zustand(r: dict) -> dict:
        return {e["context"]: e["state"] for e in r["per_context"]}

    def test_a_status_function_only_condition_is_produced_not_gated(self):
        """The shape GitHub recommends for a summarising required check is unconditional here."""
        b = Baum(self, {"ci.yml": self.GUARDED}, ["coverage", "all-checks-passed"])
        r = b.urteil()
        self.assertEqual(self._zustand(r)["all-checks-passed"], G.ALWAYS)
        self.assertEqual(r["skipped_reads_as_passed"], [])
        self.assertTrue(any("status function" in h for h in r["status_function_conditions"]),
                        "the report must SAY the condition was read as a status function")
        self.assertEqual(b.rc("--drift-marker", ""), 0)

    def test_a_character_python_calls_whitespace_and_github_does_not_is_not_measurable(self):
        """Lens 236-B: U+001C before `always()`. Folded with `str.split()` it read as a status function
        and the collector as produced; GitHub's expression lexer skips .NET whitespace, which holds
        none of U+001C to U+001F, so it parses another condition than the one this gate judged. Each
        of the four is not measurable now, and the gate is red; a plain space stays a status function."""
        for code in range(0x1C, 0x20):
            wf = CI + f"""
  all-checks-passed:
    needs: [test, coverage]
    if: "\\x{code:02x}always()"
    runs-on: ubuntu-latest
    steps: [{{run: "true"}}]
"""
            with self.subTest(code=f"U+{code:04X}"):
                b = Baum(self, {"ci.yml": wf}, ["coverage", "all-checks-passed"])
                r = b.urteil()
                self.assertNotIn("all-checks-passed", r["produced_contexts"])
                self.assertTrue(any(f"U+{code:04X}" in u for u in r["newly_unreadable"]), r["newly_unreadable"])
                self.assertEqual(b.rc("--drift-marker", ""), 1)
        b = Baum(self, {"ci.yml": self.ALWAYS_FORM.replace("if: always()", 'if: " always()"')},
                 ["coverage", "all-checks-passed"])
        self.assertEqual(self._zustand(b.urteil())["all-checks-passed"], G.ALWAYS)

    def test_a_matrix_condition_with_such_a_character_is_not_read_literally(self):
        wf = """
name: CI
on:
  pull_request:
    branches: [main]
jobs:
  test:
    strategy:
      matrix:
        python-version: "${{ fromJSON(github.event_name == 'push' \\x1c&& '[\\"3.10\\"]' || '[\\"3.12\\"]') }}"
    runs-on: ubuntu-latest
    steps: [{run: "true"}]
"""
        r = Baum(self, {"ci.yml": wf}, ["test (3.12)"]).urteil()
        self.assertNotIn("test (3.12)", r["produced_contexts"])
        self.assertTrue(any("matrix values not readable literally" in u for u in r["unreadable"]), r["unreadable"])

    def test_a_status_function_inside_a_string_literal_is_no_guard(self):
        """`'always()'` in quotes is a string to GitHub, not a call: the implicit success() stays,
        the job is skipped when a need fails, and that skip reads as passed."""
        wf = CI + """
  all-checks-passed:
    needs: [test, coverage]
    if: github.event.head_commit.message == 'always()'
    runs-on: ubuntu-latest
    steps: [{run: "true"}]
"""
        b = Baum(self, {"ci.yml": wf}, ["coverage", "all-checks-passed"])
        r = b.urteil()
        self.assertEqual([h["context"] for h in r["skipped_reads_as_passed"]], ["all-checks-passed"])
        self.assertEqual(b.rc("--drift-marker", ""), 1)
        # the quote doubling of the grammar, a guard outside the literal, and a name that only ends
        # in a status function
        self.assertFalse(G.ohne_wache_trotz_needs({"needs": ["b"], "if": "x == 'it''s' || always()"}))
        self.assertTrue(G.ohne_wache_trotz_needs({"needs": ["b"], "if": "x == 'it''s always()'"}))
        self.assertTrue(G.ohne_wache_trotz_needs({"needs": ["b"], "if": "notalways()"}))

    def test_always_is_read_the_same_way(self):
        b = Baum(self, {"ci.yml": self.ALWAYS_FORM}, ["coverage", "all-checks-passed"])
        self.assertEqual(self._zustand(b.urteil())["all-checks-passed"], G.ALWAYS)
        self.assertEqual(b.rc("--drift-marker", ""), 0)

    def test_a_collector_without_the_guard_is_red_because_skipped_reads_as_passed(self):
        """THE PLANTED DEFECT. Same tree, the guard removed. The context is still produced -- it
        is not absent and not gated -- and the gate must be red all the same."""
        b = Baum(self, {"ci.yml": self.UNGUARDED}, ["coverage", "all-checks-passed"])
        r = b.urteil()
        self.assertEqual(self._zustand(r)["all-checks-passed"], G.ALWAYS)
        self.assertEqual([h["context"] for h in r["skipped_reads_as_passed"]], ["all-checks-passed"])
        self.assertIn("skipped", r["skipped_reads_as_passed"][0]["why"])
        self.assertEqual(b.rc("--drift-marker", ""), 1, "a required check that is skipped when "
                                                        "its needs fail must not exit 0")

    def test_the_missing_guard_is_the_only_difference(self):
        """Catch proof of the catch proof: GUARDED and UNGUARDED differ in one line, and only the
        second is red. Otherwise the case above could be red for an unrelated reason."""
        self.assertEqual(self.GUARDED.replace("    if: ${{ !cancelled() }}\n", ""), self.UNGUARDED)
        gut = Baum(self, {"ci.yml": self.GUARDED}, ["coverage", "all-checks-passed"])
        schlecht = Baum(self, {"ci.yml": self.UNGUARDED}, ["coverage", "all-checks-passed"])
        self.assertEqual((gut.rc("--drift-marker", ""), schlecht.rc("--drift-marker", "")), (0, 1))

    def test_an_unguarded_needs_job_that_nobody_requires_does_not_turn_the_gate_red(self):
        """`mutation` in this repository has needs and an event condition and is required by
        nobody. The class is about REQUIRED contexts; an advisory job may be skipped."""
        b = Baum(self, {"ci.yml": self.UNGUARDED}, ["coverage"])
        r = b.urteil()
        self.assertEqual(r["skipped_reads_as_passed"], [])
        self.assertEqual(b.rc("--drift-marker", ""), 0)

    def test_failure_alone_stays_a_named_condition(self):
        """Only `always()` and `!cancelled()` are unconditional. `failure()` runs the job only
        after a failure, which IS a condition, and the gate must keep saying so."""
        b = Baum(self, {"ci.yml": self.FAILURE_ONLY}, ["coverage", "all-checks-passed"])
        r = b.urteil()
        e = [x for x in r["per_context"] if x["context"] == "all-checks-passed"][0]
        self.assertEqual(e["state"], G.GATED)
        self.assertIn("failure()", e["condition"])

    def test_a_collector_that_vanishes_from_the_workflow_is_absent(self):
        """The second red case the owner asked for: the collector disappears from ci.yml while
        the ruleset still requires it. That is the original class, and it must still be caught."""
        b = Baum(self, {"ci.yml": CI}, ["coverage", "all-checks-passed"])
        r = b.urteil()
        self.assertEqual(self._zustand(r)["all-checks-passed"], G.ABSENT)
        self.assertEqual(b.rc("--drift-marker", ""), 1)

    def test_live_a_status_function_arrives_on_any_event(self):
        """The live evaluator reads status functions too, inside `${{ }}` and in a mix."""
        ev = TestTheLivePullRequestIsJudgedNotOnlyTheStructure._ereignis(event="pull_request")
        self.assertTrue(G.bedingung_am_ereignis("${{ !cancelled() }}", ev))
        self.assertTrue(G.bedingung_am_ereignis("always()", ev))
        self.assertFalse(G.bedingung_am_ereignis("cancelled()", ev))
        self.assertTrue(G.bedingung_am_ereignis("!cancelled() && github.event_name == 'pull_request'", ev))
        self.assertFalse(G.bedingung_am_ereignis(
            "!cancelled() && github.event_name == 'pull_request'",
            TestTheLivePullRequestIsJudgedNotOnlyTheStructure._ereignis(event="push")))

    def test_live_the_guarded_collector_arrives_on_an_unlabelled_pull_request(self):
        """The whole point: on the event that held pull request 218, the collector arrives."""
        b = Baum(self, {"ci.yml": self.GUARDED}, ["coverage", "all-checks-passed"])
        d = G.lebend(TestTheLivePullRequestIsJudgedNotOnlyTheStructure._ereignis(labels=()), b.decl, b.wf)
        self.assertEqual(d["verdict"], G.ALWAYS)
        self.assertEqual(d["missing"], [])

    MATRIX_NEEDS_UNGUARDED = """
name: CI
on:
  pull_request:
    branches: [main]
jobs:
  setup:
    runs-on: ubuntu-latest
    steps: [{run: "true"}]
  test:
    needs: [setup]
    strategy:
      matrix:
        python-version: ["3.10", "3.11"]
    runs-on: ubuntu-latest
    steps: [{run: "true"}]
"""

    def test_a_matrix_job_with_needs_and_no_guard_is_caught_under_its_expanded_name(self):
        """LENS A, P1 (2026-09-17): the trap was invisible exactly on a matrix job. The unguarded
        list was built with an empty value set, so the job reported its bare id `test`, the
        required context `test (3.10)` never matched, and the gate stayed green. Same shape,
        required by the expanded name, must be red."""
        b = Baum(self, {"ci.yml": self.MATRIX_NEEDS_UNGUARDED}, ["setup", "test (3.10)"])
        r = b.urteil()
        self.assertEqual(self._zustand(r)["test (3.10)"], G.ALWAYS)
        self.assertEqual([h["context"] for h in r["skipped_reads_as_passed"]], ["test (3.10)"])
        self.assertEqual(b.rc("--drift-marker", ""), 1)

    def test_a_compound_condition_with_a_status_function_is_guarded_but_still_named(self):
        """LENS A, P2: GitHub replaces the implicit success() as soon as ANY status function is
        in the condition, so `always() && x` is guarded against the skip trap -- and it is still a
        named condition for the event. Two questions, two answers; the first draft gave one."""
        ci = CI + """
  all-checks-passed:
    needs: [test, coverage]
    if: ${{ always() && github.event_name == 'pull_request' }}
    runs-on: ubuntu-latest
    steps: [{run: "true"}]
"""
        b = Baum(self, {"ci.yml": ci}, ["coverage", "all-checks-passed"])
        r = b.urteil()
        e = [x for x in r["per_context"] if x["context"] == "all-checks-passed"][0]
        self.assertEqual(e["state"], G.GATED, "the event part of the condition still gates")
        self.assertEqual(r["skipped_reads_as_passed"], [],
                         "a status function anywhere in the condition suppresses the implicit success()")
        self.assertFalse(G.ohne_wache_trotz_needs({"needs": ["x"], "if": "!cancelled() || false"}))
        self.assertTrue(G.ohne_wache_trotz_needs({"needs": ["x"], "if": "success()"}),
                        "an explicit success() is the default and guards nothing")
        # THE TRAP IS "does not run when a need failed". `failure()` runs on failure and can go
        # red, so it guards; a bare `cancelled()` runs only on a cancelled run and is skipped on
        # every ordinary failure, so it does not (un, round 1, 2026-09-18: the first regex
        # counted `cancelled()` as a guard because it searched for the word, not the truth value).
        self.assertFalse(G.ohne_wache_trotz_needs({"needs": ["x"], "if": "failure()"}))
        self.assertTrue(G.ohne_wache_trotz_needs({"needs": ["x"], "if": "${{ cancelled() }}"}),
                        "cancelled() alone is skipped on an ordinary failure")
        self.assertFalse(G.ohne_wache_trotz_needs({"needs": ["x"], "if": "!cancelled() && failure()"}))

    def test_whitespace_and_case_inside_the_status_function_are_tolerated(self):
        """LENS A, P3 and lens C: `always(  )` and `Always()` are what GitHub reads as always()."""
        for form in ("${{ always(  ) }}", "Always()", "${{ !CANCELLED( ) }}", "!cancelled( )"):
            with self.subTest(form=form):
                self.assertTrue(G._NUR_STATUSFUNKTION.match(" ".join(form.split())), form)
                self.assertFalse(G.ohne_wache_trotz_needs({"needs": ["x"], "if": form}), form)
        ev = TestTheLivePullRequestIsJudgedNotOnlyTheStructure._ereignis(event="push")
        self.assertTrue(G.bedingung_am_ereignis("${{ Always(  ) }}", ev))
        self.assertTrue(G.bedingung_am_ereignis("!cancelled( )", ev))

    def test_a_guard_with_a_dead_event_part_is_caught_by_the_other_two_axes(self):
        """un, round 2 (2026-09-18): `always() && false` carries a guard and never runs, so the
        guard axis alone would call it fine. MEASURED before the reply: the structure axis reported
        it `produced-only-if` (newly gated, exit 1) and the live axis WILL NOT ARRIVE (exit 1).

        Since the review of follow-up 236 (2026-09-26) the condition is evaluated: it is false on
        every run, so it is dead like a literal `false` -- the context is never produced, the
        report names the dead condition, and the guard axis catches it too, because a condition
        that never runs does not run when a needed job failed. Three axes, all three red."""
        ci = CI + """
  all-checks-passed:
    needs: [test, coverage]
    if: ${{ always() && false }}
    runs-on: ubuntu-latest
    steps: [{run: "true"}]
"""
        b = Baum(self, {"ci.yml": ci}, ["coverage", "all-checks-passed"])
        r = b.urteil()
        e = [x for x in r["per_context"] if x["context"] == "all-checks-passed"][0]
        self.assertEqual(e["state"], G.ABSENT)
        self.assertTrue(any("is false on every run" in h for h in r["dead_conditions"]), r["dead_conditions"])
        self.assertEqual([h["context"] for h in r["skipped_reads_as_passed"]], ["all-checks-passed"])
        self.assertEqual(b.rc("--drift-marker", ""), 1, "a dead condition: red")
        d = G.lebend(TestTheLivePullRequestIsJudgedNotOnlyTheStructure._ereignis(labels=()), b.decl, b.wf)
        self.assertEqual(d["verdict"], G.ABSENT)
        self.assertEqual(d["missing"], ["all-checks-passed"])

    # ---- this repository -------------------------------------------------------------------

    def _ci(self):
        pfad = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "ci.yml"
        if not pfad.is_file():
            self.skipTest("ci.yml not readable here")
        return pfad, G._lade(pfad)

    def test_this_repository_carries_a_guarded_collector_over_the_required_ci_contexts(self):
        """Not a fixture. The collector in ci.yml needs exactly the jobs that produce the contexts
        the declaration requires from ci.yml (everything but `guard`, which lives in another
        file), and it carries the guard."""
        _, doc = self._ci()
        job = doc["jobs"].get("all-checks-passed")
        self.assertIsNotNone(job, "ci.yml has no all-checks-passed job")
        self.assertTrue(G._NUR_STATUSFUNKTION.match(" ".join(str(job.get("if", "")).split())),
                        "the collector must carry an always()/!cancelled() guard")
        self.assertFalse(G.ohne_wache_trotz_needs(job))
        verlangt = json.loads(G.DECLARATION.read_text(encoding="utf-8"))["required_contexts"]
        aus_ci = [k for k in verlangt if k != "guard"]
        self.assertTrue(aus_ci, "the declaration names no ci.yml context")
        needs = set(job["needs"] if isinstance(job["needs"], list) else [job["needs"]])
        for k in aus_ci:
            job_id = k.split(" (")[0]
            if job_id == "all-checks-passed":
                # SINCE 2026-09-18 THE COLLECTOR IS ITSELF THE REQUIRED CONTEXT (ruleset switch,
                # OA-0f65aa76aa). It cannot need itself; what it must need are the legs it stands
                # for, and that set is the workflow's own EXPECTED line, measured elsewhere in this
                # file (TestTheCollectorJob). Here: the legs are needed, and nothing else is.
                self.assertEqual(needs, {"test", "coverage"},
                                 "the collector stands for exactly the test and coverage legs")
                continue
            self.assertIn(job_id, needs, f"required context {k!r} is produced by job {job_id!r}, "
                                          f"which the collector does not need")

    def test_the_full_matrix_copy_is_the_matrix_condition_byte_for_byte(self):
        """TWO COPIES OF ONE CONDITION, held together by this contract. The collector evaluates
        the matrix condition to decide whether the full matrix ran; the matrix owns the original.
        Compared through the same digest the ratchet binds to."""
        pfad, doc = self._ci()
        _, _, bedingung, _ = G.matrix_werte(doc["jobs"]["test"], pfad.read_text(encoding="utf-8"))
        self.assertTrue(bedingung, "the matrix condition was not readable")
        env = doc["jobs"]["all-checks-passed"]["steps"][0]["env"]["FULL_MATRIX"]
        kopie = " ".join(str(env).split())
        self.assertTrue(kopie.startswith("${{") and kopie.endswith("}}"))
        kopie = kopie[3:-2].strip()
        self.assertEqual(G.bedingungs_digest(kopie), G.bedingungs_digest(bedingung),
                         f"the collector's copy drifted from the matrix condition:\n"
                         f"  matrix:    {bedingung}\n  collector: {kopie}")


class TestNoPatternReadsWhatGitHubLexesDifferently(unittest.TestCase):
    """Review of follow-up 236 (F2, 2026-09-26): `matrix_werte` asked `_TERNARY.search` about a value
    holding U+001C before it asked `fremder_leerraum`. The verdict was the same either way; the
    sentence "not measurable, before any pattern reads it" was not true. Here every function that
    judges a condition gets one holding each of U+001C..U+001F, with every pattern of the module
    replaced by a recorder, and no pattern may be asked anything. An order is measured by what
    was asked, not by the verdict, which the old order reached too."""

    class _Aufnahme:
        """A compiled pattern that writes down every call before it answers."""

        def __init__(self, muster, protokoll):
            self._muster, self._protokoll = muster, protokoll

        def __getattr__(self, name):
            wert = getattr(self._muster, name)
            if not callable(wert):
                return wert

            def aufgezeichnet(*args, **kwargs):
                self._protokoll.append((self._muster.pattern, name))
                return wert(*args, **kwargs)
            return aufgezeichnet

    def _aufzeichnen(self) -> list:
        protokoll: list = []
        for name, wert in list(vars(G).items()):
            if isinstance(wert, re.Pattern):
                setattr(G, name, self._Aufnahme(wert, protokoll))
                self.addCleanup(setattr, G, name, wert)
        atome = G._ATOME
        G._ATOME = [(self._Aufnahme(a[0], protokoll),) + tuple(a[1:]) for a in atome]
        self.addCleanup(setattr, G, "_ATOME", atome)
        return protokoll

    @staticmethod
    def _matrix(zeichen: str) -> str:
        return ("${{ fromJSON(github.event_name == 'push' " + zeichen
                + "&& '[\"3.10\"]' || '[\"3.12\"]') }}")

    def test_the_recorder_sees_a_pattern_that_is_asked(self):
        """Catch proof: without the character the same calls do ask patterns, and are recorded."""
        protokoll = self._aufzeichnen()
        G.matrix_werte({"strategy": {"matrix": {"v": self._matrix(" ")}}}, "")
        self.assertTrue(protokoll)

    def test_matrix_werte_asks_no_pattern(self):
        protokoll = self._aufzeichnen()
        for code in range(0x1C, 0x20):
            with self.subTest(code=f"U+{code:04X}"):
                protokoll.clear()
                self.assertEqual(G.matrix_werte({"strategy": {"matrix": {"v": self._matrix(chr(code))}}}, ""),
                                 ({"v": []}, {"v": []}, None, None))
                self.assertEqual(protokoll, [])

    def test_the_guard_reader_asks_no_pattern_and_claims_no_guard(self):
        protokoll = self._aufzeichnen()
        for code in range(0x1C, 0x20):
            with self.subTest(code=f"U+{code:04X}"):
                protokoll.clear()
                self.assertTrue(G.ohne_wache_trotz_needs({"needs": ["b"], "if": chr(code) + "always()"}))
                self.assertEqual(protokoll, [])

    def test_the_evaluator_asks_no_pattern(self):
        ev = TestTheLivePullRequestIsJudgedNotOnlyTheStructure._ereignis()
        protokoll = self._aufzeichnen()
        for code in range(0x1C, 0x20):
            with self.subTest(code=f"U+{code:04X}"):
                protokoll.clear()
                with self.assertRaises(G.NichtAuswertbar):
                    G.bedingung_am_ereignis(chr(code) + "always()", ev)
                for frage in (G.wahrheitswerte, G.laeuft_bei_fehlschlag):
                    with self.assertRaises(G.NichtAuswertbar):
                        frage(chr(code) + "always()")
                self.assertEqual(protokoll, [])

    def test_the_survey_asks_no_pattern_about_either_condition(self):
        """erhebe over a job whose `if:` and a job whose matrix hold the character: both are not
        measurable, and nothing was asked of a pattern on the way."""
        protokoll = self._aufzeichnen()
        for code in range(0x1C, 0x20):
            flucht = "\\x%02x" % code                  # the YAML escape, read as the character
            matrix = self._matrix(flucht).replace('"', '\\"')
            wf = ("name: CI\non: {pull_request: {branches: [main]}}\njobs:\n"
                  f'  sammler:\n    if: "{flucht}always()"\n    runs-on: x\n    steps: [{{run: "true"}}]\n'
                  f'  test:\n    strategy:\n      matrix:\n        v: "{matrix}"\n'
                  '    runs-on: x\n    steps: [{run: "true"}]\n')
            with self.subTest(code=f"U+{code:04X}"):
                b = Baum(self, {"ci.yml": wf}, ["sammler"])
                protokoll.clear()
                r = G.erhebe(b.wf, "main")
                self.assertEqual(protokoll, [])
                self.assertEqual(len(r["unlesbar"]), 2, r["unlesbar"])
                self.assertEqual(r["gewoehnlich"], {})


class TestAConditionFalseOnEveryRunIsDead(unittest.TestCase):
    """Review of follow-up 236 (F3, 2026-09-26): a job condition that is false on every run, but not
    spelled `false`, read as guarded and reachable. `_TRAEGT_WACHE` found the `always()` inside
    `!always()`, so the collector below was `produced-only-if` with no skipped-is-passed finding,
    although GitHub never runs it; `always() && false` was `produced-only-if` too, while the live
    evaluator computed it to false. The file already read a literal `false` as dead. Now the
    evaluator decides it, over every result of the status functions and every value of the event
    facts it reads, and a negation is read by GitHub's semantics."""

    @staticmethod
    def _sammler(bedingung: str) -> str:
        gequotet = bedingung.replace("'", "''")          # YAML single quotes double a quote
        return CI + ("\n  all-checks-passed:\n    needs: [test, coverage]\n"
                     f"    if: '{gequotet}'\n"
                     '    runs-on: ubuntu-latest\n    steps: [{run: "true"}]\n')

    def _urteil(self, bedingung: str, verlangt=("coverage", "all-checks-passed")):
        b = Baum(self, {"ci.yml": self._sammler(bedingung)}, list(verlangt))
        r = b.urteil()
        zustand = {e["context"]: e["state"] for e in r["per_context"]}
        return b, r, zustand

    DEAD = ("!always()", "! always()", "always() && false", "false && always()",
            "${{ !Always( ) }}", "!( always() || true )")

    def test_a_condition_false_on_every_run_is_dead_like_literal_false(self):
        b_lit, r_lit, z_lit = self._urteil("false")
        for bedingung in self.DEAD:
            with self.subTest(bedingung=bedingung):
                b, r, zustand = self._urteil(bedingung)
                self.assertEqual(zustand["all-checks-passed"], G.ABSENT)
                self.assertEqual(zustand, z_lit, "read like the literal `false`")
                self.assertTrue(any("is false on every run" in h for h in r["dead_conditions"]),
                                r["dead_conditions"])
                self.assertEqual([h["context"] for h in r["skipped_reads_as_passed"]], ["all-checks-passed"])
                self.assertTrue(G.ohne_wache_trotz_needs({"needs": ["b"], "if": bedingung}))
                self.assertEqual(b.rc("--drift-marker", ""), 1)
                self.assertEqual(G.wahrheitswerte(bedingung), {False})

    def test_the_controls_keep_their_verdicts(self):
        """`always()` and `!cancelled()` stay unconditional and guarded, `success() || failure()` a
        named, guarded condition, exactly as before the change."""
        for bedingung in ("always()", "${{ !cancelled() }}"):
            with self.subTest(bedingung=bedingung):
                b, r, zustand = self._urteil(bedingung)
                self.assertEqual(zustand["all-checks-passed"], G.ALWAYS)
                self.assertEqual((r["skipped_reads_as_passed"], r["dead_conditions"]), ([], []))
                self.assertEqual(b.rc("--drift-marker", ""), 0)
        b, r, zustand = self._urteil("success() || failure()")
        self.assertEqual(zustand["all-checks-passed"], G.GATED)
        e = [x for x in r["per_context"] if x["context"] == "all-checks-passed"][0]
        self.assertEqual(e["condition"], "job `if: success() || failure()`")
        self.assertEqual((r["skipped_reads_as_passed"], r["dead_conditions"]), ([], []))

    def test_a_negated_status_function_is_read_by_github_semantics(self):
        """A needed job failed, the run was not cancelled: `success()` is false, `failure()` true.
        `!always()` never runs and `!failure()` not then, so neither guards; `!success()` runs then,
        like `failure()`; `!cancelled()` does too. Two negations cancel."""
        for bedingung, ohne_wache in (("!always()", True), ("! always()", True), ("!failure()", True),
                                      ("!success()", False), ("!cancelled()", False),
                                      ("!!always()", False), ("!(!cancelled())", True),
                                      ("!!cancelled()", True)):
            with self.subTest(bedingung=bedingung):
                self.assertEqual(G.ohne_wache_trotz_needs({"needs": ["b"], "if": bedingung}), ohne_wache)
        self.assertEqual(G.wahrheitswerte("!failure()"), {False, True}, "not dead: true when no need failed")
        self.assertEqual(G.wahrheitswerte("!success()"), {False, True})

    def test_a_condition_the_evaluator_cannot_read_is_guarded_by_its_spelling_without_a_negation(self):
        """The reading for what the evaluator cannot read (`needs.*` is no atom of it) counts a guard
        only where no `!` stands before it, and claims none under a negated group."""
        for bedingung, ohne_wache in (("always() && needs.a.result == 'x'", False),
                                      ("!always() && needs.a.result == 'x'", True),
                                      ("! always() && needs.a.result == 'x'", True),
                                      ("!failure() && needs.a.result == 'x'", True),
                                      ("!success() && needs.a.result == 'x'", False),
                                      ("!( always() && needs.a.result == 'x' )", True)):
            with self.subTest(bedingung=bedingung):
                self.assertEqual(G.ohne_wache_trotz_needs({"needs": ["b"], "if": bedingung}), ohne_wache)
                with self.assertRaises(G.NichtAuswertbar):
                    G.laeuft_bei_fehlschlag(bedingung)

    def test_an_undecided_condition_is_said_and_keeps_its_reading(self):
        """Where the evaluator cannot decide, the context stays produced under its named condition,
        and the report says that it was not decided. The exit follows the ratchet as before."""
        bedingung = "always() && needs.test.result == 'success'"
        b, r, zustand = self._urteil(bedingung)
        self.assertEqual(zustand["all-checks-passed"], G.GATED)
        self.assertEqual(r["skipped_reads_as_passed"], [])
        self.assertEqual(len(r["undecided_conditions"]), 1, r["undecided_conditions"])
        notiz = r["undecided_conditions"][0]
        self.assertIn("ci.yml:all-checks-passed", notiz)
        self.assertIn("can ever be true is not decided", notiz)
        self.assertIn("read from its spelling", notiz)
        self.assertEqual(b.rc("--drift-marker", ""), 1, "newly gated, not accepted: red")
        d = json.loads(b.decl.read_text(encoding="utf-8"))
        d["accepted_gated"] = [{"context": "all-checks-passed",
                                "condition_sha256": G.bedingungs_digest(f"job `if: {bedingung}`")}]
        b.decl.write_text(json.dumps(d), encoding="utf-8")
        alt = sys.stdout
        sys.stdout = puffer = io.StringIO()
        try:
            rc = b.rc("--drift-marker", "")
        finally:
            sys.stdout = alt
        self.assertEqual(rc, 0, "the note says what was not decided; it does not move the exit")
        self.assertIn("  undecided  ", puffer.getvalue())
        self.assertFalse(_dp.treffer(puffer.getvalue()), puffer.getvalue())
        self.assertEqual(self._urteil("always()")[1]["undecided_conditions"], [],
                         "a condition the evaluator reads is not called undecided")

    def test_a_constant_matrix_condition_leaves_one_arm_dead(self):
        """The sibling in the matrix: `true && A || B` is A on every event, so B's contexts are never
        produced; before, they read as the ordinary case and as produced. `false && A || B` is B."""
        kopf, matrix = TestRatchetNotPermanentRed.KOPF, TestRatchetNotPermanentRed._matrix
        for bedingung, da, fehlt in (("true", "test (3.10)", "test (3.12)"),
                                     ("false", "test (3.12)", "test (3.10)"),
                                     ("( github.event_name == 'push' || true )", "test (3.10)", "test (3.12)")):
            with self.subTest(bedingung=bedingung):
                b = Baum(self, {"ci.yml": kopf + matrix(bedingung, '["3.10"]')}, [da, fehlt])
                r = b.urteil()
                zustand = {e["context"]: e["state"] for e in r["per_context"]}
                self.assertEqual((zustand[da], zustand[fehlt]), (G.ALWAYS, G.ABSENT))
                self.assertTrue(any("on every event" in h and "dead code" in h for h in r["dead_conditions"]),
                                r["dead_conditions"])
                self.assertEqual(b.rc("--drift-marker", ""), 1)
        b = Baum(self, {"ci.yml": kopf + matrix("github.actor == 'x'", '["3.10"]')}, ["test (3.12)"])
        r = b.urteil()
        # A CONDITION NOT DECIDED DOES NOT MAKE ITS FALSE ARM PRODUCED (lens on fb6eda0d, A): the false arm
        # exists only when the condition does not hold, so it is named under the negation.
        self.assertEqual((r["per_context"][0]["state"], r["per_context"][0]["condition"]),
                         (G.GATED, "!(github.actor == 'x')"))
        self.assertTrue(any("matrix condition" in h and "not decided" in h for h in r["undecided_conditions"]),
                        r["undecided_conditions"])

    def test_the_live_evaluator_reads_a_negation(self):
        ev = TestTheLivePullRequestIsJudgedNotOnlyTheStructure._ereignis(event="pull_request")
        self.assertFalse(G.bedingung_am_ereignis("!always()", ev))
        self.assertTrue(G.bedingung_am_ereignis("!contains(github.event.pull_request.labels.*.name, 'landung')", ev))
        self.assertTrue(G.bedingung_am_ereignis("!(github.event_name == 'push')", ev))
        self.assertTrue(G.bedingung_am_ereignis("github.event_name != 'push'", ev))
        with self.assertRaises(G.NichtAuswertbar):
            G.bedingung_am_ereignis("!github.event_name == 'push'", ev)   # GitHub negates the name
        with self.assertRaises(G.NichtAuswertbar):
            G.bedingung_am_ereignis("failure()", ev)                       # the event says nothing of it

    def test_named_limits_of_the_enumeration(self):
        """Stated rather than hidden. Atoms vary as if independent, so a condition false only by a
        combination no run has stays live; and more than twelve free atoms are not enumerated."""
        self.assertEqual(G.wahrheitswerte("github.event_name == 'push' && github.event_name == 'pull_request'"),
                         {False, True})
        viele = " || ".join(f"contains(github.event.pull_request.labels.*.name, 'l{i}')" for i in range(13))
        with self.assertRaises(G.NichtAuswertbar):
            G.wahrheitswerte(viele)


class TestAContextIsProducedOnlyFromAFormTheGateReads(unittest.TestCase):
    """Lens on ac05d85d (F7): five forms read as `produced` with exit 0 that GitHub never produces. A
    matrix of two keys, an `exclude` that removes the value, an `include` that gives the combination a
    second value, a workflow that runs on push only, and `if: ${{ always()` without its `}}`. The class
    is "a context name or its production derived from a form the gate does not read"; each case below
    plants one form, and the verdict must be the one GitHub's rules give or NOT MEASURABLE, never
    produced. What GitHub does is read from its docs and source (see the gate), not measured."""

    KOPF = "name: CI\non:\n  pull_request:\n    branches: [main]\njobs:\n"
    PR = staticmethod(TestTheLivePullRequestIsJudgedNotOnlyTheStructure._ereignis)

    def _matrix(self, matrix: str, name: str = "") -> str:
        return (self.KOPF + "  test:\n" + (f"    name: {name}\n" if name else "")
                + "    runs-on: x\n    strategy:\n      matrix:\n" + matrix + "    steps: [{run: 'true'}]\n")

    def _zustand(self, workflow: str, verlangt, datei="ci.yml"):
        b = Baum(self, {datei: workflow}, list(verlangt))
        r = b.urteil()
        return b, r, {e["context"]: e["state"] for e in r["per_context"]}

    def test_a_matrix_of_two_keys_names_every_value(self):
        """(a) `python: ['3.10']` beside `os: [ubuntu-latest]` is ONE job, `test (3.10, ubuntu-latest)`."""
        wf = self._matrix("        python: ['3.10']\n        os: [ubuntu-latest]\n")
        b, r, zustand = self._zustand(wf, ["test (3.10)", "test (3.10, ubuntu-latest)"])
        self.assertEqual(zustand, {"test (3.10)": G.ABSENT, "test (3.10, ubuntu-latest)": G.ALWAYS})
        self.assertEqual(b.rc("--drift-marker", ""), 1)
        self.assertEqual(r["produced_contexts"], ["test (3.10, ubuntu-latest)"])
        wf = self._matrix("        python: ['3.10', '3.12']\n        os: [a, b]\n", "py ${{ matrix.python }} on ${{ Matrix.OS }}")
        _b, r, _z = self._zustand(wf, ["py 3.10 on a"])
        self.assertEqual(r["produced_contexts"], ["py 3.10 on a", "py 3.10 on b", "py 3.12 on a", "py 3.12 on b"])

    def test_exclude_removes_a_combination(self):
        """(b) The docs' own example: 12 combinations, one excluded on three keys and two on a partial
        match, nine jobs."""
        wf = self._matrix("        python: ['3.10', '3.12']\n        exclude:\n          - python: '3.10'\n")
        b, r, zustand = self._zustand(wf, ["test (3.10)", "test (3.12)"])
        self.assertEqual(zustand, {"test (3.10)": G.ABSENT, "test (3.12)": G.ALWAYS})
        self.assertEqual(b.rc("--drift-marker", ""), 1)
        docs = ("        os: [macos-latest, windows-latest]\n        version: [12, 14, 16]\n"
                "        environment: [staging, production]\n        exclude:\n"
                "          - os: macos-latest\n            version: 12\n            environment: production\n"
                "          - os: windows-latest\n            version: 16\n")
        _b, r, _z = self._zustand(self._matrix(docs), ["x"])
        self.assertEqual(len(r["produced_contexts"]), 9, r["produced_contexts"])
        self.assertNotIn("test (macos-latest, 12, production)", r["produced_contexts"])
        self.assertIn("test (macos-latest, 12, staging)", r["produced_contexts"])

    def test_include_adds_to_the_original_combinations_or_makes_its_own(self):
        """(c) An `include` entry that adds a key to the ORIGINAL combination `3.10` does not change its
        name: GitHub builds the display name (MatrixBuilder.cs:188-212) before it adds the entry's values
        to the matrix context (216-219), read in actions/runner at 15231bede4aa, not measured. The first
        form of this change named it `test (3.10, yes)`, and a lens on fb6eda0d read the source. The docs'
        example yields exactly its six combinations, `{fruit: banana, animal: cat}` not added to the
        `{fruit: banana}` another entry made; the docs list their matrix contexts, and the names follow
        the source: the values of the original keys only, and for an entry of its own its matrix keys,
        then its other keys (GetUnmatchedVectors, 365-373)."""
        wf = self._matrix("        python: ['3.10']\n        include:\n          - python: '3.10'\n"
                          "            experimental: 'yes'\n")
        b, r, zustand = self._zustand(wf, ["test (3.10)", "test (3.10, yes)"])
        self.assertEqual(zustand, {"test (3.10)": G.ALWAYS, "test (3.10, yes)": G.ABSENT})
        self.assertEqual(b.rc("--drift-marker", ""), 1)
        docs = ("        fruit: [apple, pear]\n        animal: [cat, dog]\n        include:\n"
                "          - color: green\n          - color: pink\n            animal: cat\n"
                "          - fruit: apple\n            shape: circle\n          - fruit: banana\n"
                "          - fruit: banana\n            animal: cat\n")
        _b, r, _z = self._zustand(self._matrix(docs), ["x"])
        self.assertEqual(r["produced_contexts"], sorted([
            "test (apple, cat)", "test (apple, dog)", "test (pear, cat)", "test (pear, dog)",
            "test (banana)", "test (banana, cat)"]))
        _b, r, _z = self._zustand(self._matrix("        fruit: [apple]\n        include:\n"
                                               "          - color: green\n            fruit: banana\n"), ["x"])
        self.assertEqual(r["produced_contexts"], ["test (apple)", "test (banana, green)"],
                         "an entry of its own names its matrix keys first")
        _b, r, _z = self._zustand(self._matrix("        include:\n          - site: production\n"
                                               "          - site: staging\n"), ["x"])
        self.assertEqual(r["produced_contexts"], ["test (production)", "test (staging)"])

    def test_a_value_or_a_key_it_does_not_read_is_not_measurable(self):
        """A list compared in `exclude`, a fraction and an expression in a value, a key that is another
        spelling of one (refused as a key written twice, since the lens on fb6eda0d), an exclude on no key
        of the matrix, and `strategy` written as an expression (which raised AttributeError out of the
        whole survey) are each named, and no context of theirs is produced. A boolean an `include` entry
        adds was one of these until the naming was read in GitHub's source: it is in no name now."""
        for matrix in ("        python: ['3.10']\n        exclude:\n          - python: ['3.10']\n",
                       "        python: [3.10]\n",
                       "        python: ['${{ vars.V }}']\n",
                       "        os: [a]\n        OS: [b]\n",
                       "        python: ['3.10']\n        exclude:\n          - os: a\n",
                       "        python: []\n"):
            with self.subTest(matrix=matrix):
                b, r, zustand = self._zustand(self._matrix(matrix), ["test (3.10)"])
                self.assertEqual(r["produced_contexts"], [])
                self.assertEqual(len(r["newly_unreadable"]), 1, r["newly_unreadable"])
                self.assertEqual(b.rc("--drift-marker", ""), 1)
        wf = self.KOPF + "  test:\n    runs-on: x\n    strategy: ${{ fromJSON(x) }}\n    steps: [{run: 'true'}]\n"
        _b, r, _z = self._zustand(wf, ["test"])
        self.assertTrue(any("`strategy` is str" in u for u in r["unreadable"]), r["unreadable"])

    def test_a_workflow_is_read_as_github_reads_yaml(self):
        """YAML 1.2's core schema, as both of GitHub's readers use it: `on` is the key `on`, a matrix
        value `on` is the text `on` (YAML 1.1 made it True), `010` is ten (YAML 1.1: eight)."""
        wf = self._matrix("        v: [on, '010', 010]\n")
        _b, r, _z = self._zustand(wf, ["x"])
        self.assertEqual(r["produced_contexts"], ["test (010)", "test (10)", "test (on)"])
        self.assertEqual(list(r["triggers"]["ci.yml"]), ["pull_request"])

    def test_a_workflow_that_runs_on_push_only_produces_nothing_on_a_pull_request(self):
        """(d) `on: push` to main: offline a named condition, not produced; live on a pull request it
        will not arrive, and the advice points at `on:`; on a push to main it arrives."""
        wf = "name: G\non:\n  push:\n    branches: [main]\njobs:\n  guard:\n    runs-on: x\n    steps: [{run: 'true'}]\n"
        b, r, zustand = self._zustand(wf, ["guard"])
        self.assertEqual(zustand, {"guard": G.GATED})
        self.assertIn("runs it on no pull request into main", r["per_context"][0]["condition"])
        self.assertEqual(b.rc("--drift-marker", ""), 1)
        d = G.lebend(self.PR(), b.decl, b.wf)
        self.assertEqual((d["verdict"], d["missing"]), (G.ABSENT, ["guard"]))
        self.assertIn("does not run on this event", d["advice"])
        push = dict(self.PR(event="push", ref_name="main"), ref_type="branch")
        self.assertEqual(G.lebend(push, b.decl, b.wf)["verdict"], G.ALWAYS)
        self.assertEqual(G.lebend(dict(push, ref_name="f"), b.decl, b.wf)["verdict"], G.ABSENT)
        self.assertEqual(G.lebend(dict(push, ref_type=""), b.decl, b.wf)["verdict"], G.UNKNOWN)

    def test_a_push_run_on_the_head_commit_is_not_decided_and_a_fork_gets_none(self):
        """A required check is matched by name, whatever event made it (GitHub's docs), so an unfiltered
        `on: push` MAY carry it on a pull request from this repository: not measurable. A fork's push runs
        in the fork, so on a fork pull request it will not arrive."""
        wf = "name: G\non: [push]\njobs:\n  guard:\n    runs-on: x\n    steps: [{run: 'true'}]\n"
        b, _r, zustand = self._zustand(wf, ["guard"])
        self.assertEqual(zustand, {"guard": G.GATED})
        self.assertEqual(G.lebend(self.PR(), b.decl, b.wf)["verdict"], G.UNKNOWN)
        self.assertEqual(G.lebend(self.PR(head_repo="fremd/r"), b.decl, b.wf)["verdict"], G.ABSENT)

    def test_a_trigger_filter_on_pull_requests_is_a_named_condition(self):
        """A path filter or activity types without a default one run the workflow on some pull requests
        only; a skipped workflow leaves its required checks Pending (GitHub's docs). Named, not
        produced; live not measurable. A branch filter without the protected branch runs it on none."""
        job = "jobs:\n  guard:\n    runs-on: x\n    steps: [{run: 'true'}]\n"
        for on, wort in (("{pull_request: {branches: [main], paths-ignore: ['docs/**']}}", "paths-ignore"),
                         ("{pull_request: {types: [opened, labeled]}}", "types"),
                         ("{pull_request: {branches: [develop]}}", "no pull request into main")):
            with self.subTest(on=on):
                b, r, zustand = self._zustand(f"name: G\non: {on}\n" + job, ["guard"])
                self.assertEqual(zustand, {"guard": G.GATED})
                self.assertIn(wort, r["per_context"][0]["condition"])
                self.assertEqual(b.rc("--drift-marker", ""), 1)
                self.assertNotEqual(G.lebend(self.PR(), b.decl, b.wf)["verdict"], G.ALWAYS)
        b, _r, zustand = self._zustand("name: G\non: {pull_request: {types: [opened, synchronize, reopened, "
                                       "labeled]}, merge_group: null}\n" + job, ["guard"])
        self.assertEqual(zustand, {"guard": G.ALWAYS}, "the default types and more run on every pull request")
        self.assertEqual(G.lebend(self.PR(event="merge_group"), b.decl, b.wf)["verdict"], G.ALWAYS)
        self.assertEqual(G.lebend(self.PR(event="workflow_dispatch"), b.decl, b.wf)["verdict"], G.ABSENT)

    def test_a_trigger_it_does_not_read_is_not_measurable(self):
        """A glob branch filter, a branch filter with no declared branch, a filter key it does not know
        and a workflow without `on:`: the file is not read, and live absence is not measurable."""
        job = "jobs:\n  guard:\n    runs-on: x\n    steps: [{run: 'true'}]\n"
        for kopf in ("name: G\non: {pull_request: {branches: ['releases/**']}}\n",
                     "name: G\non: {pull_request: {branches: [main], unbekannt: 1}}\n",
                     "name: G\n"):
            with self.subTest(kopf=kopf):
                b, r, zustand = self._zustand(kopf + job, ["guard"])
                self.assertEqual(zustand, {"guard": G.ABSENT})
                self.assertTrue(any("`on:` not read" in u for u in r["newly_unreadable"]), r["newly_unreadable"])
                self.assertEqual(G.lebend(self.PR(), b.decl, b.wf)["verdict"], G.UNKNOWN)
        b = Baum(self, {"ci.yml": "name: G\non: {pull_request: {branches: [main]}}\n" + job}, ["guard"])
        b.decl.write_text(json.dumps({"required_contexts": ["guard"]}), encoding="utf-8")
        self.assertTrue(any("is not known" in u for u in b.urteil()["unreadable"]))

    def test_a_context_from_two_workflows_arrives_from_either(self):
        """Produced by two workflows, the context arrives on an event either of them runs on."""
        job = "jobs:\n  guard:\n    runs-on: x\n    steps: [{run: 'true'}]\n"
        b = Baum(self, {"a.yml": "name: A\non: {pull_request: {branches: [main]}}\n" + job,
                        "b.yml": "name: B\non: {pull_request: {branches: [main]}, workflow_dispatch: null}\n" + job},
                 ["guard"])
        e = b.urteil()["per_context"][0]
        self.assertEqual((e["state"], e["sources"]), (G.ALWAYS, ["a.yml", "b.yml"]))
        self.assertEqual(G.lebend(self.PR(event="workflow_dispatch"), b.decl, b.wf)["verdict"], G.ALWAYS)

    def test_an_if_whose_expression_is_not_closed_is_not_measurable(self):
        """(e) `${{ always()` is refused by GitHub's template reader; text beside `${{ }}` is formatted
        into a string. Neither is a status function, neither job is produced. Since the lens on fb6eda0d a
        text scalar ANYWHERE whose expression is not closed refuses the whole file, as GitHub's reader
        parses every text scalar for `${{ }}` (TemplateReader.cs:486-536)."""
        for bedingung, wort in (("${{ always()", "is not closed"), ("${{ always() }} && true", "`if:` not read"),
                                ("${{ !cancelled()", "is not closed")):
            with self.subTest(bedingung=bedingung):
                wf = (self.KOPF + "  test:\n    runs-on: x\n    steps: [{run: 'true'}]\n  all:\n"
                      f"    needs: [test]\n    if: {bedingung}\n    runs-on: x\n    steps: [{{run: 'true'}}]\n")
                b, r, zustand = self._zustand(wf, ["all"])
                self.assertEqual(zustand, {"all": G.ABSENT})
                self.assertTrue(any(wort in u for u in r["newly_unreadable"]), r["newly_unreadable"])
                self.assertEqual(b.rc("--drift-marker", ""), 1)
                self.assertFalse(G._NUR_STATUSFUNKTION.match(bedingung))
                with self.assertRaises(G.NichtAuswertbar):
                    G.bedingung_am_ereignis(bedingung, self.PR())
        self.assertTrue(G._NUR_STATUSFUNKTION.match("${{ always() }}"))
        self.assertFalse(G.bedingung_am_ereignis("${{ github.event_name == 'a}}b' }}", self.PR()),
                         "a `}}` inside a string literal does not close the expression")


class TestNamesFoldInAsciiAndTheMatrixShapeIsReadWhole(unittest.TestCase):
    """Lens on ac05d85d, F4 and F5. F4: the status-function patterns used `re.I`, which folds `ı`, `İ`,
    `ſ` and the Kelvin sign onto ASCII letters, while `_schluessel` used `.lower()`: `!faılure()` read
    as a guard where `!failure()` reads as none, and an accepted digest on it exited 0. GitHub's lexer
    takes only ASCII into a keyword (read in actions/runner, not measured), so such a name is no
    function there. F5: `fromJSON(true || X && A || B)` read as the ternary, although GitHub's `||`
    binds looser than `&&` and the value is the bare `true`; a status function in `strategy`, which
    GitHub allows nowhere there, read as a constant."""

    KOPF = "name: CI\non:\n  pull_request:\n    branches: [main]\njobs:\n"
    PR = staticmethod(TestTheLivePullRequestIsJudgedNotOnlyTheStructure._ereignis)
    NICHT_ASCII = ("faılure()", "faİlure()", "succeſſ()", "alwayſ()")

    def _sammler(self, bedingung: str, akzeptiert: bool = False):
        wf = (self.KOPF + "  test:\n    runs-on: x\n    steps: [{run: 'true'}]\n  all:\n"
              f"    needs: [test]\n    if: '{bedingung}'\n    runs-on: x\n    steps: [{{run: 'true'}}]\n")
        b = Baum(self, {"ci.yml": wf}, ["all"])
        if akzeptiert:
            d = json.loads(b.decl.read_text(encoding="utf-8"))
            d["accepted_gated"] = [{"context": "all",
                                    "condition_sha256": G.bedingungs_digest(f"job `if: {bedingung}`")}]
            b.decl.write_text(json.dumps(d), encoding="utf-8")
        return b

    def test_a_status_function_spelled_outside_ascii_is_no_atom(self):
        for name in self.NICHT_ASCII:
            with self.subTest(name=name):
                for text in (name, "!" + name, "failure() && !" + name):
                    with self.assertRaises(G.NichtAuswertbar):
                        G.wahrheitswerte(text)
                    with self.assertRaises(G.NichtAuswertbar):
                        G.laeuft_bei_fehlschlag(text)
                self.assertIsNone(G._TRAEGT_WACHE.search(name))
                self.assertIsNone(G._NUR_STATUSFUNKTION.match(name))
                self.assertTrue(G.ohne_wache_trotz_needs({"needs": ["t"], "if": name}), "no guard is claimed")
                self.assertTrue(G.ohne_wache_trotz_needs({"needs": ["t"], "if": "!" + name}))
        # counter-direction: ASCII case is GitHub's case-insensitivity, and one fact under one key
        self.assertEqual(G.wahrheitswerte("!FAILURE()"), {False, True})
        self.assertEqual(G.wahrheitswerte("failure() && !FaIlUrE()"), {False})
        self.assertTrue(G._NUR_STATUSFUNKTION.match("ALWAYS()"))
        self.assertFalse(G.ohne_wache_trotz_needs({"needs": ["t"], "if": "Failure()"}))

    def test_an_accepted_guard_spelled_outside_ascii_is_red(self):
        """Measured at ac05d85d: `if: '!faılure()'` with its digest accepted exited 0, the same condition
        in ASCII exited 1 as skipped-is-passed. Both are red now."""
        for bedingung in ("!failure()", "!faılure()"):
            with self.subTest(bedingung=bedingung):
                b = self._sammler(bedingung, akzeptiert=True)
                r = b.urteil()
                self.assertEqual([h["context"] for h in r["skipped_reads_as_passed"]], ["all"])
                self.assertEqual(b.rc("--drift-marker", ""), 1)

    def test_a_value_equal_only_under_a_unicode_case_mapping_is_not_measurable(self):
        """`.lower()` makes the Kelvin sign a `k` and keeps the long s apart from `s`; how GitHub's .NET
        comparison maps either was not read. Equal in ASCII case stays equal, different stays different."""
        pr = self.PR(labels=("\u212aanary", "Landung"))   # the Kelvin sign, U+212A
        with self.assertRaises(G.NichtAuswertbar):
            G.bedingung_am_ereignis("contains(github.event.pull_request.labels.*.name, 'kanary')", pr)
        with self.assertRaises(G.NichtAuswertbar):
            G.bedingung_am_ereignis("github.event_name == 'puſh'", self.PR(event="push"))
        with self.assertRaises(G.NichtAuswertbar):
            G.bedingung_am_ereignis("startsWith(github.head_ref, 'ſ')", self.PR(head_ref="s/x"))
        self.assertTrue(G.bedingung_am_ereignis("contains(github.event.pull_request.labels.*.name, 'landung')", pr))
        self.assertFalse(G.bedingung_am_ereignis("contains(github.event.pull_request.labels.*.name, 'x')", pr))
        self.assertFalse(G.bedingung_am_ereignis("github.event_name == 'push'", self.PR()))
        self.assertTrue(G.bedingung_am_ereignis("startsWith(github.head_ref, 'DOCS/')", self.PR()))

    def _matrix(self, wert: str, verlangt=("test (3.10)", "test (3.12)")):
        wf = (self.KOPF + "  test:\n    runs-on: x\n    strategy:\n      matrix:\n"
              f"        python-version: \"{wert}\"\n    steps: [{{run: 'true'}}]\n")
        b = Baum(self, {"ci.yml": wf}, list(verlangt))
        return b, b.urteil()

    def test_an_or_before_the_and_is_not_the_ternary(self):
        """GitHub reads `true || X && A || B` as `true || (X && A) || B`: the bare `true`, no list."""
        for bedingung in ("true || github.event_name == 'push'", "github.event_name == 'push' || true",
                          "github.event_name == 'push' || github.event_name == 'merge_group'"):
            with self.subTest(bedingung=bedingung):
                b, r = self._matrix("${{ fromJSON(" + bedingung + " && '[\\\"3.10\\\"]' || '[\\\"3.12\\\"]') }}")
                self.assertEqual(r["produced_contexts"], [])
                self.assertEqual({e["state"] for e in r["per_context"]}, {G.ABSENT})
                self.assertTrue(any("not one operand" in u for u in r["newly_unreadable"]), r["newly_unreadable"])
                self.assertEqual(b.rc("--drift-marker", ""), 1)
        b, r = self._matrix("${{ fromJSON(( github.event_name == 'push' || github.event_name == 'merge_group' )"
                            " && '[\\\"3.10\\\"]' || '[\\\"3.12\\\"]') }}")
        bed = "( github.event_name == 'push' || github.event_name == 'merge_group' )"
        self.assertEqual({e["context"]: (e["state"], e["condition"]) for e in r["per_context"]},
                         {"test (3.10)": (G.GATED, bed), "test (3.12)": (G.GATED, f"!({bed})")},
                         "the parenthesised form is still the ternary, each arm under its condition")
        self.assertFalse(any("not one operand" in u for u in r["unreadable"]), r["unreadable"])

    def test_a_status_function_in_a_matrix_is_not_measurable(self):
        for bedingung in ("always()", "!cancelled()", "Failure()"):
            with self.subTest(bedingung=bedingung):
                b, r = self._matrix("${{ fromJSON(" + bedingung + " && '[\\\"3.10\\\"]' || '[\\\"3.12\\\"]') }}")
                self.assertEqual(r["produced_contexts"], [])
                self.assertTrue(any("status function" in u for u in r["newly_unreadable"]), r["newly_unreadable"])
                self.assertEqual(b.rc("--drift-marker", ""), 1)

    def test_text_beside_the_matrix_expression_is_not_the_ternary(self):
        """GitHub formats text beside `${{ }}` into one string, never a list."""
        b, r = self._matrix("x ${{ fromJSON(github.event_name == 'push' && '[\\\"3.10\\\"]' || '[\\\"3.12\\\"]') }}")
        self.assertEqual(r["produced_contexts"], [])
        self.assertEqual(b.rc("--drift-marker", ""), 1)

    def test_a_job_not_read_makes_live_absence_not_measurable(self):
        """A job whose matrix was not read may produce the context; "no workflow produces it" was a claim."""
        b, r = self._matrix("${{ fromJSON(true || github.event_name == 'push' && '[\\\"3.10\\\"]' || '[\\\"3.12\\\"]') }}",
                            verlangt=("test (3.10)",))
        d = G.lebend(self.PR(), b.decl, b.wf)
        self.assertEqual((d["verdict"], d["not_measurable"], d["missing"]), (G.UNKNOWN, ["test (3.10)"], []))
        self.assertIsNone(d["advice"])
        self.assertIn("could not be read", d["per_context"][0]["why"])


class TestTheCollectorScript(unittest.TestCase):
    """THE SCRIPT INSIDE THE JOB, executed -- not read. Lens B (2026-09-17) ran it by hand across
    eight synthetic inputs and found two things reading could not: on a `push` to main the full
    matrix condition is false, so the collector would have gone red on every commit that lands
    (the cry-wolf inverted onto main); and a key missing from `needs` read as passed. Both are
    now decided in the script and held here by running the real text out of ci.yml.
    """

    @classmethod
    def _script(cls) -> str:
        pfad = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "ci.yml"
        if not pfad.is_file():
            raise unittest.SkipTest("ci.yml not readable here")
        run = G._lade(pfad)["jobs"]["all-checks-passed"]["steps"][0]["run"]
        kopf, _, rest = run.partition("<<'PY'\n")
        body, _, _ = rest.rpartition("\nPY")
        assert "python3 -" in kopf and body.strip(), "the collector step is not the heredoc this test expects"
        return body

    def _run(self, needs: dict, full: str, event: str):
        import os
        import subprocess
        r = subprocess.run([sys.executable, "-"], input=self._script(), capture_output=True, text=True,
                           env={**os.environ, "NEEDS": json.dumps(needs), "FULL_MATRIX": full, "EVENT": event},
                           timeout=60)
        return r.returncode, r.stdout

    OK = {"test": {"result": "success"}, "coverage": {"result": "success"}}

    def test_all_success_on_the_full_matrix_passes(self):
        rc, out = self._run(self.OK, "true", "pull_request")
        self.assertEqual(rc, 0, out)
        self.assertIn("every needed job succeeded on the full matrix", out)

    def test_a_failed_needed_job_is_red(self):
        rc, out = self._run({**self.OK, "test": {"result": "failure"}}, "true", "pull_request")
        self.assertEqual(rc, 1)
        self.assertIn("::error", out)
        self.assertIn("test=failure", out)

    def test_a_skipped_needed_job_is_red_because_skipped_reads_as_passed_elsewhere(self):
        rc, out = self._run({**self.OK, "coverage": {"result": "skipped"}}, "true", "pull_request")
        self.assertEqual(rc, 1)
        self.assertIn("coverage=skipped", out)

    def test_the_fast_layer_on_a_pull_request_is_red_with_the_label_advice(self):
        rc, out = self._run(self.OK, "false", "pull_request")
        self.assertEqual(rc, 1)
        self.assertIn("landung", out)

    def test_the_fast_layer_on_a_push_to_main_is_green_and_says_so(self):
        """LENS B, P1: the push after a merge runs the fast layer (the matrix condition has no
        push branch); the merged tree was tested on the full matrix by its pull request under the
        strict ruleset. Green with a notice, never red."""
        rc, out = self._run(self.OK, "false", "push")
        self.assertEqual(rc, 0, out)
        self.assertIn("::notice", out)
        self.assertIn("push to main", out)

    def test_a_missing_or_extra_needed_job_is_red(self):
        """LENS B, P3: a key absent from `needs` read as passed. Now the key set is checked."""
        rc, out = self._run({"coverage": {"result": "success"}}, "true", "pull_request")
        self.assertEqual(rc, 1, out)
        self.assertIn("not the declared", out)
        rc, out = self._run({**self.OK, "extra": {"result": "success"}}, "true", "pull_request")
        self.assertEqual(rc, 1, out)

    def test_the_expected_key_set_equals_the_needs_line(self):
        """Two copies of one list, held together: the `needs:` of the job and the EXPECTED set in
        its script."""
        pfad = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "ci.yml"
        job = G._lade(pfad)["jobs"]["all-checks-passed"]
        import re
        m = re.search(r"EXPECTED = \{([^}]*)\}", self._script())
        self.assertIsNotNone(m, "the script names no EXPECTED set")
        im_skript = {s.strip().strip("\"'") for s in m.group(1).split(",") if s.strip()}
        self.assertEqual(im_skript, set(job["needs"]))



class TestGitHubsOwnReadingOfArmsValuesKeysAndProducers(unittest.TestCase):
    """A lens on fb6eda0d (2026-09-27) found forms this gate read as produced that GitHub never produces, or
    reads otherwise. Each rule below was read in actions/runner's source at 15231bede4aa and in GitHub's
    docs, not measured against GitHub, and each case fails on fb6eda0d."""

    KOPF = "name: CI\non:\n  pull_request:\n    branches: [main]\njobs:\n"
    JOB = "    runs-on: x\n    steps: [{run: 'true'}]\n"
    PR = staticmethod(TestTheLivePullRequestIsJudgedNotOnlyTheStructure._ereignis)
    LABEL = "contains(github.event.pull_request.labels.*.name, 'landung')"

    @staticmethod
    def _ternary(bedingung: str, wahr: str = '["3.10"]', sonst: str = '["3.12"]') -> str:
        """The matrix value `${{ fromJSON(<condition> && '<true>' || '<false>') }}`, for a YAML double-quoted
        scalar."""
        return ("${{ fromJSON(" + bedingung + " && '" + wahr.replace('"', '\\"') + "' || '"
                + sonst.replace('"', '\\"') + "') }}")

    def _test_job(self, matrix: str, job_if: str = "", name: str = "") -> str:
        return (self.KOPF + "  test:\n" + (f"    name: {name}\n" if name else "")
                + (f"    if: {job_if}\n" if job_if else "") + "    runs-on: x\n    strategy:\n      matrix:\n"
                + matrix + "    steps: [{run: 'true'}]\n")

    def _urteil(self, workflow: str, verlangt=("x",)):
        b = Baum(self, {"ci.yml": workflow}, list(verlangt))
        return b, b.urteil()

    # --- A: each arm of a matrix ternary under its condition -----------------------------------------

    def test_the_false_arm_of_a_matrix_ternary_is_named_under_the_negation(self):
        """A (P2). `fromJSON(<label> && '["3.10"]' || '["3.12"]')` read `test (3.12)` as produced with exit
        0; on a pull request carrying the label GitHub builds only `["3.10"]`. `cond && A || B` is A when
        cond is truthy and B otherwise (And.cs:39-50, Or.cs:39-50), so `test (3.12)` is produced only when
        the condition does not hold: named, bound by its digest, and false live on the labelled pull
        request."""
        b, r = self._urteil(self._test_job(f'        python: "{self._ternary(self.LABEL)}"\n'), ["test (3.12)"])
        e = r["per_context"][0]
        self.assertEqual((e["state"], e["condition"]), (G.GATED, f"!({self.LABEL})"))
        self.assertEqual(b.rc("--drift-marker", ""), 1, "newly gated: red until it is accepted")
        d = json.loads(b.decl.read_text(encoding="utf-8"))
        d["accepted_gated"] = [{"context": "test (3.12)",
                                "condition_sha256": G.bedingungs_digest(f"!({self.LABEL})")}]
        b.decl.write_text(json.dumps(d), encoding="utf-8")
        self.assertEqual(b.rc("--drift-marker", ""), 0, "the acceptance binds to the negated condition")
        mit = G.lebend(self.PR(labels=("landung",)), b.decl, b.wf)
        self.assertEqual((mit["verdict"], mit["missing"]), (G.ABSENT, ["test (3.12)"]))
        self.assertEqual(G.lebend(self.PR(), b.decl, b.wf)["verdict"], G.ALWAYS)

    def test_a_matrix_condition_the_evaluator_cannot_decide_produces_neither_arm(self):
        """A. `fromJSON(github.run_id && ...)` named the condition as undecided and then `test (3.12)` as
        produced. Each arm is named under its condition, and live neither is measurable."""
        b, r = self._urteil(self._test_job(f'        python: "{self._ternary("github.run_id")}"\n'),
                            ["test (3.10)", "test (3.12)"])
        self.assertEqual({e["context"]: (e["state"], e["condition"]) for e in r["per_context"]},
                         {"test (3.10)": (G.GATED, "github.run_id"), "test (3.12)": (G.GATED, "!(github.run_id)")})
        self.assertEqual(r["produced_contexts"], [])
        self.assertTrue(any("not decided" in h for h in r["undecided_conditions"]), r["undecided_conditions"])
        d = G.lebend(self.PR(), b.decl, b.wf)
        self.assertEqual((d["verdict"], d["not_measurable"]), (G.UNKNOWN, ["test (3.10)", "test (3.12)"]))

    def test_a_job_condition_and_a_matrix_condition_are_both_named(self):
        """A, the neighbour in the same class: with a job `if:`, the first form named the false arm's
        contexts under the job's condition alone and dropped the true arm's. Each carries both now."""
        wf = self._test_job(f'        python: "{self._ternary(self.LABEL)}"\n',
                            job_if="github.event_name == 'pull_request'")
        b, r = self._urteil(wf, ["test (3.10)", "test (3.12)"])
        job = "job `if: github.event_name == 'pull_request'`"
        self.assertEqual({e["context"]: e["condition"] for e in r["per_context"]},
                         {"test (3.10)": f"{job}; and {self.LABEL}", "test (3.12)": f"{job}; and !({self.LABEL})"})
        d = G.lebend(self.PR(labels=("landung",)), b.decl, b.wf)
        self.assertEqual({z["context"]: z["live"] for z in d["per_context"]},
                         {"test (3.10)": G.ARRIVES, "test (3.12)": G.WILL_NOT_ARRIVE})

    def test_two_conditional_keys_combine_their_arms(self):
        """A. With two conditional keys the first form kept one condition and paired true arm with true arm
        and false with false. Each choice of arms is a combination under its own condition."""
        push = "github.event_name == 'push'"
        python, os_ = self._ternary(self.LABEL), self._ternary(push, '["a"]', '["b"]')
        wf = self._test_job(f'        python: "{python}"\n        os: "{os_}"\n')
        _b, r = self._urteil(wf, ["test (3.10, b)", "test (3.12, a)"])
        self.assertEqual({e["context"]: e["condition"] for e in r["per_context"]},
                         {"test (3.10, b)": f"({self.LABEL}) && !({push})",
                          "test (3.12, a)": f"!({self.LABEL}) && ({push})"})

    # --- B: include and exclude with GitHub's `==` -----------------------------------------------------

    def test_include_and_exclude_match_with_githubs_equality(self):
        """B (P2). `exclude` and `include` matched the displayed text. GitHub builds `matrix[key] ==
        literal` (MatrixBuilder.cs:578-612), and its `==` makes a text a number beside a number, ignores the
        case of a text, and makes a boolean or null a number (EvaluationResult.cs:233-424,
        ExpressionUtility.cs:223-288). A pair this gate cannot compare exactly is not measurable."""
        for matrix, erzeugt in (
                ("        v: ['10.0', '11.0']\n        exclude:\n          - v: 10\n", ["test (11.0)"]),
                ("        v: ['10.0']\n        include:\n          - v: 10\n            extra: x\n", ["test (10.0)"]),
                ("        v: [Linux, mac]\n        exclude:\n          - v: linux\n", ["test (mac)"]),
                ("        v: [true, false]\n        exclude:\n          - v: 1\n", ["test (false)"]),
                ("        v: ['', a]\n        exclude:\n          - v: null\n", ["test (a)"]),
                ("        v: ['0x1A', b]\n        exclude:\n          - v: 26\n", ["test (b)"]),
                ("        v: ['true', b]\n        exclude:\n          - v: true\n", ["test (b)", "test (true)"])):
            with self.subTest(matrix=matrix):
                self.assertEqual(self._urteil(self._test_job(matrix))[1]["produced_contexts"], erzeugt)
        for matrix in ("        v: ['1e400']\n        exclude:\n          - v: 1\n",
                       "        v: ['0x80000000']\n        exclude:\n          - v: 1\n",
                       "        v: ['3.141592653589793']\n        exclude:\n          - v: 3.141592653589793\n",
                       "        v: [\u212aey]\n        exclude:\n          - v: key\n"):
            with self.subTest(matrix=matrix):
                b, r = self._urteil(self._test_job(matrix))
                self.assertEqual(r["produced_contexts"], [])
                self.assertEqual(len(r["newly_unreadable"]), 1, r["newly_unreadable"])
                self.assertEqual(b.rc("--drift-marker", ""), 1)

    # --- C: a key written twice, and a workflow GitHub refuses as a whole ----------------------------------

    def test_a_key_written_twice_refuses_the_whole_workflow(self):
        """C (P2). PyYAML keeps the last of two equal keys, so `if: false` then `if: always()`, the jobs
        `guard` and `Guard`, and `on:` twice each read as produced. GitHub's reader refuses a repeated key,
        ignoring case (TemplateReader.cs:182, 215-221, 309, 341-347), and converts the whole workflow to an
        empty one (WorkflowTemplateConverter.cs:31-34). The file is not read, with the reason, at every
        mapping level; live the context is not measurable."""
        faelle = {
            "if twice": self.KOPF + "  guard:\n    if: false\n" + self.JOB + "    if: always()\n",
            "guard and Guard": self.KOPF + "  guard:\n" + self.JOB + "  Guard:\n" + self.JOB,
            "on twice": "name: CI\non: push\non:\n  pull_request:\n    branches: [main]\njobs:\n  guard:\n" + self.JOB,
            "an env key twice in a step": (self.KOPF + "  guard:\n    runs-on: x\n    steps:\n"
                                           "      - run: 'true'\n        env: {A: 1, a: 2}\n"),
            "a key given as an expression literal": self.KOPF + "  guard:\n" + self.JOB + "    ${{ 'Runs-On' }}: y\n",
        }
        for name, wf in faelle.items():
            with self.subTest(fall=name):
                b, r = self._urteil(wf, ["guard"])
                self.assertEqual(r["produced_contexts"], [])
                self.assertTrue(any("WorkflowNotRead" in u and "repeats" in u for u in r["unreadable_files"]),
                                r["unreadable_files"])
                self.assertEqual(b.rc("--drift-marker", ""), 1)
                self.assertEqual(G.lebend(self.PR(), b.decl, b.wf)["verdict"], G.UNKNOWN)
        _b, r = self._urteil(self.KOPF + "  guard:\n    runs-on: x\n    env: {\u212a: 1, k: 2}\n"
                                         "    steps: [{run: 'true'}]\n", ["guard"])
        self.assertTrue(any("outside ASCII" in u for u in r["unreadable_files"]), r["unreadable_files"])
        _b, r = self._urteil(self.KOPF + "  guard:\n    runs-on: x\n    env: {A: 1, B: 2}\n"
                                         "    steps: [{run: 'true'}]\n", ["guard"])
        self.assertEqual(r["produced_contexts"], ["guard"], "distinct keys are read as before")

    def test_an_expression_not_closed_anywhere_refuses_the_whole_workflow(self):
        """C, one step over: GitHub's reader parses every text scalar for `${{ }}`, so a `run:` holding a
        `${{` that is not closed refuses the whole workflow (TemplateReader.cs:486-536); the gate looked for
        it in an `if:` only and produced the job."""
        _b, r = self._urteil(self.KOPF + "  guard:\n    runs-on: x\n    steps: [{run: 'echo ${{ github.sha'}]\n",
                             ["guard"])
        self.assertEqual(r["produced_contexts"], [])
        self.assertTrue(any("is not closed" in u for u in r["unreadable_files"]), r["unreadable_files"])
        _b, r = self._urteil(self.KOPF + "  guard:\n    runs-on: x\n    steps: [{run: 'echo ${{ github.sha }}'}]\n",
                             ["guard"])
        self.assertEqual(r["produced_contexts"], ["guard"])

    # --- D: an integer past Int32 ------------------------------------------------------------------------

    def test_an_integer_past_int32_is_not_read(self):
        """D (P3). GitHub reads a hex scalar with Int32.TryParse and an octal one with Convert.ToInt32
        (YamlObjectReader.cs:656-692): past 0x7FFFFFFF the value is read as a negative number or refused,
        and which one was not measured. `0xFFFFFFFF` named a job `test (4294967295)`; the file is not read
        now. Within Int32 the value is the number."""
        for wert in ("0xFFFFFFFF", "0x100000000", "0o20000000000", "0x000000001"):
            with self.subTest(wert=wert):
                _b, r = self._urteil(self._test_job(f"        v: [{wert}]\n"))
                self.assertEqual(r["produced_contexts"], [])
                self.assertTrue(any("past Int32" in u for u in r["unreadable_files"]), r["unreadable_files"])
        _b, r = self._urteil(self._test_job("        v: [0x7FFFFFFF, 0o17]\n"))
        self.assertEqual(r["produced_contexts"], ["test (15)", "test (2147483647)"])

    # --- E: every producer -------------------------------------------------------------------------------

    def test_every_producer_of_a_context_is_asked(self):
        """E (P3). The live step asked only the first producer of a context. L1: two workflows on
        pull_request with opposite `if:`, the second true on a pull request; L4: one on workflow_dispatch
        only beside one on pull_request; L2: one on pull_request beside one on push, judged on a push to
        main. Each arrives now; offline, L1 names both conditions."""
        l1 = {"a.yml": "on: pull_request\njobs:\n  guard:\n    if: github.event_name == 'push'\n" + self.JOB,
              "b.yml": "on: pull_request\njobs:\n  guard:\n    if: github.event_name == 'pull_request'\n" + self.JOB}
        l4 = {"a.yml": "on: workflow_dispatch\njobs:\n  guard:\n" + self.JOB,
              "b.yml": "on: pull_request\njobs:\n  guard:\n    if: github.event_name == 'pull_request'\n" + self.JOB}
        l2 = {"a.yml": "on: pull_request\njobs:\n  guard:\n" + self.JOB,
              "c.yml": "on: push\njobs:\n  guard:\n" + self.JOB}
        push = dict(self.PR(event="push", ref_name="main"), ref_type="branch")
        for name, workflows, ereignis in (("L1", l1, self.PR()), ("L4", l4, self.PR()), ("L2", l2, push)):
            with self.subTest(fall=name):
                b = Baum(self, workflows, ["guard"])
                self.assertEqual(G.lebend(ereignis, b.decl, b.wf)["verdict"], G.ALWAYS)
        b = Baum(self, l1, ["guard"])
        e = b.urteil()["per_context"][0]
        self.assertEqual(e["condition"], "a.yml: job `if: github.event_name == 'push'` | "
                                         "b.yml: job `if: github.event_name == 'pull_request'`")
        self.assertEqual([p["from"] for p in e["producers"]], ["a.yml", "b.yml"])
        d = G.lebend(push, b.decl, b.wf)
        self.assertEqual((d["verdict"], d["per_context"][0]["why"]), (G.ABSENT, "a.yml, b.yml do not run on a push event"))

    # --- F: whitespace beside `${{ }}` ---------------------------------------------------------------------

    def test_whitespace_beside_the_expression_is_text(self):
        """F (P3). `if: |` with `${{ false }}` on the next line, and `' ${{ false }}'`, read as the dead
        `false`: the whitespace was folded before `${{ }}` was split. GitHub keeps it as a text segment and
        formats both into one string, which is true (TemplateReader.cs:566-579 and 597-627,
        WorkflowTemplateConverter.cs:1868). Not measurable now, never dead; a string literal the fold would
        change is not read either; an empty `if:` is no condition (WorkflowTemplateConverter.cs:1813-1816)."""
        for bedingung in ("|\n      ${{ false }}\n", "' ${{ false }}'\n", "'${{ false }} '\n",
                          "|\n      ${{ github.event_name == 'push' }}\n"):
            with self.subTest(bedingung=bedingung):
                b, r = self._urteil(self.KOPF + f"  guard:\n    if: {bedingung}" + self.JOB, ["guard"])
                self.assertEqual((r["dead_conditions"], r["produced_contexts"]), ([], []))
                self.assertTrue(any("whitespace counts as text" in u for u in r["newly_unreadable"]),
                                r["newly_unreadable"])
                with self.assertRaises(G.NichtAuswertbar):
                    G.bedingung_am_ereignis(G._lade(b.wf / "ci.yml")["jobs"]["guard"]["if"], self.PR())
        for bedingung in ("\"startsWith(github.head_ref, 'a  b')\"", "\"startsWith(github.head_ref, 'a\\tb')\""):
            with self.subTest(bedingung=bedingung):
                _b, r = self._urteil(self.KOPF + f"  guard:\n    if: {bedingung}\n" + self.JOB, ["guard"])
                self.assertTrue(any("folding would change" in u for u in r["newly_unreadable"]), r["newly_unreadable"])
        self.assertTrue(G.bedingung_am_ereignis("startsWith(github.head_ref, 'a b')", self.PR(head_ref="a b/x")))
        _b, r = self._urteil(self.KOPF + "  guard:\n    if: ''\n" + self.JOB, ["guard"])
        self.assertEqual(r["produced_contexts"], ["guard"])

    # --- J: a container of another shape ------------------------------------------------------------------

    def test_a_container_of_another_shape_is_named_not_raised(self):
        """J (P3). `jobs:` written as a list raised AttributeError out of `erhebe`. GitHub asserts the
        shapes the gate reads, and the whole workflow is empty when one fails (WorkflowTemplateConverter.cs:
        1251, 1259, 1386, 1390-1403, 1477, 1809, 869, 921, 970): each is a file not read, with the reason."""
        faelle = {
            "jobs a list": "name: CI\non: {pull_request: {branches: [main]}}\njobs:\n  - guard\n",
            "a job a text": self.KOPF + "  guard: x\n  other:\n" + self.JOB,
            "needs a mapping": self.KOPF + "  guard:\n    needs: {a: b}\n" + self.JOB,
            "if a list": self.KOPF + "  guard:\n    if: [a]\n" + self.JOB,
            "strategy a number": self.KOPF + "  guard:\n    strategy: 5\n" + self.JOB,
            "a matrix vector a number": self.KOPF + "  guard:\n    strategy: {matrix: {v: 5}}\n" + self.JOB,
            "a job id a number": self.KOPF + "  1:\n" + self.JOB + "  guard:\n" + self.JOB,
        }
        for name, wf in faelle.items():
            with self.subTest(fall=name):
                b, r = self._urteil(wf, ["guard"])
                self.assertEqual(r["produced_contexts"], [])
                self.assertEqual(len(r["unreadable_files"]), 1, r["unreadable_files"])
                self.assertEqual(b.rc("--drift-marker", ""), 1)
                self.assertEqual(G.lebend(self.PR(), b.decl, b.wf)["verdict"], G.UNKNOWN)

    def test_the_other_inputs_of_the_gate_are_read_by_their_shape_too(self):
        """J, the sweep beyond the workflow: a declaration that is not JSON raised, and one whose
        `required_contexts` is a text was read as a list of characters; a list of acceptances of another
        shape raised TypeError; an event payload or a ruleset answer of another shape raised
        AttributeError. Each is named now."""
        for inhalt, wort in (("not json", "not readable as JSON"), ("[1]", "not a mapping"),
                             ('{"required_contexts": "guard"}', "not a list of names")):
            with self.subTest(declaration=inhalt):
                b = Baum(self, {"ci.yml": self.KOPF + "  guard:\n" + self.JOB}, ["guard"])
                b.decl.write_text(inhalt, encoding="utf-8")
                r = b.urteil()
                self.assertEqual(r["verdict"], G.UNKNOWN)
                self.assertIn(wort, r["reason"])
                self.assertEqual(b.rc("--drift-marker", ""), 1)
        b = Baum(self, {"ci.yml": self.KOPF + "  guard:\n" + self.JOB}, ["guard"])
        d = json.loads(b.decl.read_text(encoding="utf-8"))
        d["accepted_gated"] = 5
        b.decl.write_text(json.dumps(d), encoding="utf-8")
        self.assertEqual(b.urteil()["unbound_acceptances"], ["int in place of the list of acceptances"])
        self.assertEqual(b.rc("--drift-marker", ""), 1)
        ereignis = self.PR()
        ereignis["payload"] = {"pull_request": {"labels": "landung", "head": 5}, "action": ["x"]}
        self.assertEqual((G._labels(ereignis), G._head_repo(ereignis)), ([], ""))
        ereignis["payload"]["pull_request"] = "x"
        self.assertEqual((G._labels(ereignis), G._head_repo(ereignis)), ([], ""))
        for antwort in ("[]", '{"rules": {"a": 1}}',
                        '{"rules": [{"type": "required_status_checks", "parameters": {"required_status_checks": '
                        '[{"context": 5}]}}]}'):
            with self.subTest(ruleset=antwort):
                TestDeclarationAgainstRuleset._mit_gh(self, antwort)
                d = G.erklaerung_gegen_regelsatz(TestDeclarationAgainstRuleset._erklaerung(self, ["a"]), "o/r")
                self.assertEqual(d["verdict"], G.UNKNOWN, d)

    # --- the naming, read in the runner's source -------------------------------------------------------

    def test_the_default_name_follows_githubs_job_name_builder(self):
        """The default name of a matrix job, read in JobNameBuilder.cs:33-59 and MatrixBuilder.cs:189-205
        (not measured): a null or empty value adds no segment, a boolean is `true` or `false`, a number
        without a fraction is spelled without one, and past 100 characters the name is its first 97 and
        `...`. A name built from `${{ matrix.<key> }}` past 100 characters, and a long default name holding
        a character outside the Basic Multilingual Plane, are not read."""
        for matrix, erzeugt in (("        v: ['', b]\n", ["test", "test (b)"]),
                                ("        v: [null, b]\n", ["test", "test (b)"]),
                                ("        v: [true, 10.0]\n", ["test (10)", "test (true)"]),
                                (f"        v: [{'a' * 120}]\n", ["test (" + "a" * 91 + "..."])):
            with self.subTest(matrix=matrix):
                self.assertEqual(self._urteil(self._test_job(matrix))[1]["produced_contexts"], erzeugt)
        for workflow in (self._test_job(f"        v: [{'a' * 120}]\n", name="'py ${{ matrix.v }}'"),
                         self._test_job(f"        v: ['{chr(0x1F600) * 60}']\n")):
            with self.subTest(workflow=workflow[-80:]):
                _b, r = self._urteil(workflow)
                self.assertEqual(r["produced_contexts"], [])
                self.assertEqual(len(r["newly_unreadable"]), 1, r["newly_unreadable"])


class TestATagANegativeZeroAndAnEmptyExpressionAreReadAsGitHubReadsThem(unittest.TestCase):
    """A lens on a7c9674d (2026-09-27) found scalars this gate read as valid that GitHub's YAML reader
    rejects, or reads otherwise. Each rule was read in actions/runner's source at 15231bede4aa
    (YamlObjectReader.cs, TemplateReader.cs), not measured against GitHub, and each case fails on
    a7c9674d."""

    KOPF = "name: CI\non:\n  pull_request:\n    branches: [main]\njobs:\n"
    JOB = "    runs-on: x\n    steps: [{run: 'true'}]\n"
    PR = staticmethod(TestTheLivePullRequestIsJudgedNotOnlyTheStructure._ereignis)

    def _matrix(self, zeilen: str, name: str = "") -> str:
        return (self.KOPF + "  test:\n" + (f"    name: {name}\n" if name else "") + "    runs-on: x\n"
                "    strategy:\n      matrix:\n" + zeilen + "    steps: [{run: 'true'}]\n")

    def _urteil(self, workflow: str, verlangt):
        b = Baum(self, {"ci.yml": workflow}, list(verlangt))
        return b, b.urteil()

    def _nicht_gelesen(self, workflow: str, verlangt, wort: str):
        """The file is not read, with the line and the reason; nothing of it is produced, the exit is 1,
        and live the context is not measurable."""
        b, r = self._urteil(workflow, verlangt)
        self.assertEqual(r["produced_contexts"], [])
        self.assertEqual(len(r["unreadable_files"]), 1, r["unreadable_files"])
        grund = r["unreadable_files"][0]
        self.assertIn("WorkflowNotRead: line ", grund)
        self.assertIn(wort, grund)
        self.assertEqual(b.rc("--drift-marker", ""), 1)
        self.assertEqual(G.lebend(self.PR(), b.decl, b.wf)["verdict"], G.UNKNOWN)

    def test_a_tag_github_refuses_makes_the_file_not_read(self):
        """F7-1a (P2). PyYAML read `on: {pull_request: !!null x}` as null, `[!!bool yes]` as `true`,
        `!!int 1_000` as 1000, `[!!float 1:30]` as 90, `!!null nothing`, an Arabic-Indic digit under
        `!!int`, `strategy: !!null x`, and `!!int "5"`, `exclude` with `!!int 1_1` and `!!bool "true"`:
        each context was produced with exit 0. GitHub's reader throws for a tagged text outside the forms
        of MatchBoolean, MatchFloat, MatchInteger and MatchNull, for any tag but `!!str` on a quoted
        scalar, and for a tag it does not know (YamlObjectReader.cs:39-73, 430-724), and the thrown error
        empties the whole workflow (TemplateReader.cs:53-64, WorkflowTemplateConverter.cs:31-34). A tag
        on a sequence or a mapping GitHub does not read; one PyYAML reads the same way is kept."""
        faelle = {
            "!!null x under on": ("name: CI\non:\n  pull_request: !!null x\njobs:\n  guard:\n" + self.JOB,
                                  ["guard"], "holds 'x'"),
            "!!bool yes": (self._matrix("        v: [!!bool yes]\n"), ["test (true)"], "holds 'yes'"),
            "!!int 1_000 as a name": (self.KOPF + "  build:\n    name: !!int 1_000\n" + self.JOB, ["1000"],
                                      "holds '1_000'"),
            "!!float 1:30": (self._matrix("        v: [!!float 1:30]\n"), ["test (90)"], "holds '1:30'"),
            "!!null nothing": (self._matrix("        v: ['3.10', !!null nothing]\n"), ["test (3.10)"],
                               "holds 'nothing'"),
            "an Arabic-Indic digit under !!int": (self._matrix(f"        v: [!!int {chr(0x665)}]\n"), ["test (5)"],
                                                  "the tag !!int holds"),
            "strategy: !!null x": (self.KOPF + "  guard:\n    runs-on: x\n    strategy: !!null x\n"
                                   "    steps: [{run: 'true'}]\n", ["guard"], "holds 'x'"),
            "!!int on a quoted scalar": (self._matrix('        v: [!!int "5"]\n'), ["test (5)"],
                                         "quoted or block scalar"),
            "!!int 1_1 in exclude": (self._matrix("        v: [10, 11]\n        exclude:\n          - v: !!int 1_1\n"),
                                     ["test (10)"], "holds '1_1'"),
            "!!bool on a quoted scalar": (self._matrix('        v: [!!bool "true"]\n'), ["test (true)"],
                                          "quoted or block scalar"),
            "!!int 0b101": (self._matrix("        v: [!!int 0b101, b]\n"), ["test (b)"], "holds '0b101'"),
            "a key tagged !!null": (self.KOPF + "  guard:\n    runs-on: x\n    env: {!!null x: 1}\n"
                                    "    steps: [{run: 'true'}]\n", ["guard"], "holds 'x'"),
            "!!int with a space": (self._matrix("        v: [!!int ' 5']\n"), ["test (5)"], "quoted or block scalar"),
            "!!timestamp": (self._matrix("        v: [!!timestamp 2001-01-01, b]\n"), ["test (b)"],
                            "no scalar tag GitHub's reader knows"),
            "a local tag": (self._matrix("        v: [!x 5, b]\n"), ["test (b)"], "no scalar tag GitHub's reader knows"),
            "the non-specific tag": (self._matrix("        v: [! 5, b]\n"), ["test (b)"], "non-specific tag"),
            "!!set on a mapping": (self.KOPF + "  guard:\n    runs-on: x\n    env: !!set {a}\n"
                                   "    steps: [{run: 'true'}]\n", ["guard"], "on a mapping"),
            "!!omap on a sequence": (self._matrix("        v: !!omap [{a: 1}]\n"), ["test"], "on a sequence"),
        }
        for name, (workflow, verlangt, wort) in faelle.items():
            with self.subTest(fall=name):
                self._nicht_gelesen(workflow, verlangt, wort)
        # counter-direction: a tag GitHub's reader accepts reads as it reads it
        for zeilen, erzeugt in (("        v: [!!str 5, !!str 'true']\n", ["test (5)", "test (true)"]),
                                ("        v: [!!int 0x1F, !!int +7, !!bool TRUE]\n", ["test (31)", "test (7)", "test (true)"]),
                                ("        v: ['3.10', !!null ~, !!null NULL]\n", ["test", "test (3.10)"]),
                                ("        v: [!!float 2, !!float .5e1]\n", ["test (2)", "test (5)"]),
                                ("        v: !!seq [a]\n", ["test (a)"]),
                                ("        v: ! [a]\n", ["test (a)"])):
            with self.subTest(gelesen=zeilen):
                _b, r = self._urteil(self._matrix(zeilen), ["x"])
                self.assertEqual((r["produced_contexts"], r["unreadable_files"]), (erzeugt, []))
        _b, r = self._urteil(self.KOPF + "  guard:\n    runs-on: x\n    strategy: !!map {matrix: ! {v: [a]}}\n"
                                         "    steps: [{run: 'true'}]\n", ["x"])
        self.assertEqual(r["produced_contexts"], ["guard (a)"])

    def test_an_integer_that_reads_as_negative_zero_is_not_measurable(self):
        """F7-1b. `v: [-0]` read as `test (0)` and `name: -0` as `0`, produced with exit 0. GitHub parses
        the integer as a double (YamlObjectReader.cs:647), and its `G15` formatting spells negative zero
        `-0` on .NET Core 3.0 and later (MatrixBuilder.cs:192-194, NumberExpressionData.cs:55-58; .NET's
        documentation as the lens cites it, not measured). A float `-0.0` was already not measurable; the
        integer is read as the same double now, in a value, a name, a literal of `exclude` and a
        `fromJSON` arm. `+0` and `0` are zero."""
        arm = '${{ fromJSON(github.event_name == \'push\' && \'[-0]\' || \'[-0]\') }}'
        for name, workflow, verlangt in (
                ("-0", self._matrix("        v: [-0]\n"), ["test (0)"]),
                ("-00", self._matrix("        v: [-00]\n"), ["test (0)"]),
                ("!!int -0", self._matrix("        v: [!!int -0]\n"), ["test (0)"]),
                ("name: -0", self.KOPF + "  build:\n    name: -0\n" + self.JOB, ["0"]),
                ("-0 in exclude", self._matrix("        v: [0, 1]\n        exclude:\n          - v: -0\n"),
                 ["test (1)"]),
                ("a fromJSON arm", self._matrix(f'        v: "{arm}"\n'), ["test (0)"])):
            with self.subTest(fall=name):
                b, r = self._urteil(workflow, verlangt)
                self.assertEqual(r["produced_contexts"], [])
                self.assertEqual(len(r["newly_unreadable"]), 1, r["newly_unreadable"])
                self.assertIn("-0.0", r["newly_unreadable"][0])
                self.assertEqual(b.rc("--drift-marker", ""), 1)
        _b, r = self._urteil(self._matrix("        v: [+0, 1]\n"), ["x"])
        self.assertEqual(r["produced_contexts"], ["test (0)", "test (1)"])
        _b, r = self._urteil(self.KOPF + "  build:\n    name: 0\n" + self.JOB, ["x"])
        self.assertEqual(r["produced_contexts"], ["0"])

    def test_a_lone_surrogate_in_a_matrix_value_is_not_measurable(self):
        """A lone surrogate in a matrix value raised UnicodeEncodeError out of the survey (exit 1 with a
        traceback, measured by the lens on a7c9674d), from a YAML escape and from a `fromJSON` arm alike.
        How GitHub reads either was not read: a YAML text holding one is not read, and a `fromJSON` value
        holding one is not measurable, each with its reason."""
        flucht = chr(92) + "ud800"                       # the escape, as the workflow file spells it
        yaml_wf = self._matrix(f'        v: ["{flucht}", b]\n')
        b, r = self._urteil(yaml_wf, ["test (b)"])
        self.assertEqual(r["produced_contexts"], [])
        self.assertTrue(any("lone surrogate U+D800" in u for u in r["unreadable_files"]), r["unreadable_files"])
        self.assertEqual(b.rc("--drift-marker", ""), 1)
        # a plain scalar, so that YAML keeps the escape and `fromJSON` reads it (the lens's form)
        arm = ("${{ fromJSON(contains(github.event.pull_request.labels.*.name, 'x') && '[\"" + flucht
               + "\"]' || '[\"b\"]') }}")
        b, r = self._urteil(self._matrix(f"        v: {arm}\n"), ["test (b)"])
        self.assertEqual(r["produced_contexts"], [])
        self.assertTrue(any("lone surrogate U+D800" in u for u in r["newly_unreadable"]), r["newly_unreadable"])
        self.assertEqual(b.rc("--drift-marker", ""), 1)
        self.assertEqual(G._utf16_laenge("a" + chr(0xD800) + chr(0x1F600)), 4, "counted, never raised")

    def test_an_empty_expression_is_not_read(self):
        """`if: ${{ }}` read as `success()` and its job as produced. GitHub trims the expression and reports
        an empty one as ExpectedExpression (TemplateReader.cs:637-644), an error in any text scalar, and
        the workflow is empty. An empty or blank TEXT is `success()` (WorkflowTemplateConverter.cs:
        1813-1816) and still reads so."""
        for name, zeile in (("if", "    if: ${{ }}\n"), ("if with spaces", "    if: ${{     }}\n"),
                            ("a name", "    name: ${{ }}\n"), ("an env value", "    env: {A: 'x ${{ }} y'}\n")):
            with self.subTest(fall=name):
                self._nicht_gelesen(self.KOPF + "  guard:\n" + zeile + self.JOB, ["guard"], "ExpectedExpression")
        with self.subTest(fall="U+001C inside"):
            self._nicht_gelesen(self.KOPF + '  guard:\n    if: "${{ \\x1c }}"\n' + self.JOB, ["guard"],
                                "holds only U+001C")
        for zeile in ("    if: ''\n", "    if: '   '\n"):
            with self.subTest(text=zeile):
                _b, r = self._urteil(self.KOPF + "  guard:\n" + zeile + self.JOB, ["guard"])
                self.assertEqual((r["produced_contexts"], r["unreadable"]), (["guard"], []))
        with self.assertRaises(G.NichtAuswertbar):
            G.bedingung_am_ereignis("${{ }}", self.PR())


if __name__ == "__main__":
    unittest.main()
