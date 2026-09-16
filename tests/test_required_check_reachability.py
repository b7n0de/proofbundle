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
