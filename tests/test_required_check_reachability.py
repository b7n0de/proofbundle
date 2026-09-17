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

        def gefaelscht(verzeichnis=None):
            e = echt(verzeichnis)
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


if __name__ == "__main__":
    unittest.main()
