"""An option the caller gave is read by `is not None`, never by its truth: an empty value is not an absent one.

SOURCE. The deep gate of the 6.2.0 release preparation at d97de8e5, lens L3, L3-620v3-CLI-EMPTY-OPTION-01
(P1 under Nachtrag 1 section 5, the exit code of the shipped verifier). `verify --policy ''`,
`verify --anchor-type ''`, `decision verify --policy ''` and `--anchors ''`, `outcome verify --policy ''`
and `relation-statement verify --policy ''` read the value by its truth, dropped the named restriction and
exited 0, where a nonexistent path gives 2 and a policy the receipt does not satisfy gives 3. The house rule
stands next to `--expected-origin` in cli.py: a flag whose subject is missing is a usage error, never a silent
nothing, and an empty string is a question that was asked. `verify-proof --expected-origin ''` already fails
(tests/test_verify_proof_expected_origin.py); this is the same rule for every option.

TWO PARTS. The first runs each measured site and checks the exit code against the one without the option.
The second is the class guard: it builds the parser, collects every option that takes one value, and reads
cli.py for every place that tests such a value by its truth, directly or through a local name bound to it,
in these forms: `if`, `while`, a conditional expression, `and` and `or`, `not`, `assert`, a comprehension
filter and `bool()`. Each such place must be named below with its reason, so an option added later, or a
truth read of these forms added to an old one, fails here until someone decides what an empty value means
for it. A read in another form (a truth test inside a called helper, say) is outside what it reads.
"""
from __future__ import annotations

import argparse
import ast
import base64
import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

from proofbundle import emit_bundle, generate_signer
from proofbundle.cli import build_parser, main
from proofbundle.decision import emit_decision_receipt
from proofbundle.evalclaim import build_eval_claim, emit_eval_receipt
from proofbundle.outcome import emit_outcome_receipt
from proofbundle.relation_statement import emit_relation_statement

REPO = Path(__file__).resolve().parents[1]
CLI = REPO / "src" / "proofbundle" / "cli.py"


def _run(argv: list[str]) -> int:
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        return main(argv)


class _Belege:
    """One signed artefact of each kind the verify commands read, written to a temporary directory."""

    def __init__(self, ordner: str) -> None:
        d = Path(ordner)
        signer = generate_signer()
        self.pub = base64.b64encode(signer.public_key().public_bytes_raw()).decode("ascii")

        def schreibe(name: str, obj) -> str:
            p = d / name
            p.write_text(json.dumps(obj), encoding="utf-8")
            return str(p)

        self.bundle = schreibe("bundle.json", emit_bundle(b'{"x": 1}', generate_signer()))
        claim, _ = build_eval_claim(
            suite="s", suite_version="1", metric="acc", comparator=">=", threshold="0.8", score="0.9",
            n=10, model_id="m", dataset_id="d", issuer="Lab", timestamp="2026-07-02T00:00:00Z")
        self.eval_receipt = schreibe("eval.json", emit_eval_receipt(claim, generate_signer()))
        dpred = json.loads((REPO / "examples" / "decision_receipt_deny.json").read_text(encoding="utf-8"))
        self.decision = schreibe("decision.json", emit_decision_receipt(dpred, signer, strict=True))
        opred = {"schemaVersion": "0.1.0", "outcomeId": "o1", "decisionRef": {"sha256": "e" * 64},
                 "executor": {"id": "executor:x", "keyId": "kid"}, "requestedActionDigest": {"sha256": "b" * 64},
                 "status": "executed", "performedAt": "2026-07-14T10:00:00Z",
                 "effectDigest": {"sha256": "c" * 64}}
        self.outcome = schreibe("outcome.json", emit_outcome_receipt(opred, signer))
        rpred = {"schemaVersion": "0.1.0", "statementId": "urn:uuid:empty-option",
                 "relationships": [{"relation": "retracts",
                                    "targetReceiptDigest": {"digestAlgorithm": "jcs-sha256-v1", "digest": "a" * 64},
                                    "reasonCode": "withdrawal", "reason": "x",
                                    "declaredAt": "2026-09-29T00:00:00Z"}]}
        self.relation = schreibe("relation.json", emit_relation_statement(rpred, signer))
        self.keyfile = str(d / "issuer.pub")
        Path(self.keyfile).write_text(self.pub + "\n", encoding="utf-8")


class AnEmptyValueDoesNotDropTheRestriction(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls._td = tempfile.TemporaryDirectory(prefix="pb_empty_option_")
        cls.b = _Belege(cls._td.name)

    @classmethod
    def tearDownClass(cls) -> None:
        cls._td.cleanup()

    def _faelle(self) -> list[tuple[str, list[str], list[str], set[int]]]:
        """(label, base argv, the option with an empty value, the exit codes that honour it)."""
        b = self.b
        return [
            ("verify --policy", ["verify", b.bundle], ["--policy", ""], {2}),
            ("verify --anchor-type", ["verify", b.bundle], ["--anchor-type", ""], {2, 3}),
            ("decision verify --policy", ["decision", "verify", b.decision, "--pub", b.pub], ["--policy", ""], {2}),
            ("decision verify --anchors", ["decision", "verify", b.decision, "--pub", b.pub], ["--anchors", ""], {2}),
            ("outcome verify --policy", ["outcome", "verify", b.outcome, "--pub", b.pub], ["--policy", ""], {2}),
            ("relation-statement verify --policy", ["relation-statement", "verify", b.relation, "--pub", b.pub],
             ["--policy", ""], {2}),
            ("show-eval --eat", ["show-eval", b.eval_receipt], ["--eat", ""], {2}),
            ("policy instantiate --expected-root-file",
             ["policy", "instantiate", "strict-eval-template-v1", "--issuer-key", b.keyfile,
              "--policy-id", "org/empty-option-v1", "--output", os.devnull],
             ["--expected-root-file", ""], {2}),
            ("audit-challenge --nonce", ["audit-challenge", base64.b64encode(b"\x00" * 32).decode(), "10", "3"],
             ["--nonce", ""], {2}),
        ]

    def test_the_empty_value_is_refused_or_restricts(self) -> None:
        for label, basis, option, erwartet in self._faelle():
            with self.subTest(case=label):
                self.assertIn(_run(basis + option), erwartet,
                              f"{label} '' was read like an absent option")

    def test_an_empty_decision_maker_id_is_evaluated_not_dropped(self) -> None:
        # Classified, as the jury asked: the library reads the value with `is not None` (outcome.py, role
        # separation), and an empty maker id cannot equal a non-empty executor id, so separation is checked
        # and holds. Exit 0 here is an evaluated answer, which `role_separation_ok` shows: True, not None.
        b = self.b
        basis = ["outcome", "verify", b.outcome, "--pub", b.pub, "--json"]

        def feld(argv: list[str]):
            out = io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                main(argv)
            return json.loads(out.getvalue())["role_separation_ok"]

        self.assertIsNone(feld(basis))
        self.assertIs(feld(basis + ["--decision-maker-id", ""]), True)
        self.assertIs(feld(basis + ["--decision-maker-id", "executor:x"]), False)   # control

    def test_control_each_base_command_passes_without_the_option(self) -> None:
        # Without this, a base that already fails would make every case above pass for the wrong reason.
        for label, basis, _option, _erwartet in self._faelle():
            with self.subTest(case=label):
                self.assertEqual(_run(basis), 0, f"the base of {label} does not pass on its own")


# ── the class guard ───────────────────────────────────────────────────────────────────────────────

#: Every place in cli.py that reads a one-value option by its truth, with the reason an empty value is
#: still not dropped there. Keyed by (function, option dest). A new entry needs a reason that holds.
_ERLAUBTE_WAHRHEITSLESUNGEN = {
    ("_resolve_signer", "new_key"): "an empty --new-key falls through to --key and then to the refusal, exit 2",
    ("_resolve_signer", "key"): "an empty --key falls through to the refusal 'provide --key or --new-key', exit 2",
    ("_cmd_decision_verify", "pub"): "an empty --pub is refused with exit 2 before anything is read",
    ("_cmd_outcome_verify", "pub"): "an empty --pub is refused with exit 2 before anything is read",
    ("_cmd_relation_statement_verify", "pub"): "an empty --pub is refused with exit 2 before anything is read",
    ("_cmd_decision_init", "out"): "a template printer; an empty --out prints to stdout, nothing is verified",
    ("_cmd_outcome_init", "out"): "a template printer; an empty --out prints to stdout, nothing is verified",
    ("_cmd_relation_statement_init", "out"): "a template printer; an empty --out prints to stdout",
    ("_cmd_policy_instantiate", "output"): "an empty --output writes the policy to stdout, the documented default",
    ("_cmd_svr", "policy_uri"): "emit side: content the producer writes, no restriction a verifier relies on",
    ("_cmd_svr", "policy_sha256"): "emit side: content the producer writes, no restriction a verifier relies on",
}


def _einwertige_optionen(parser: argparse.ArgumentParser) -> set[str]:
    """The dest of every option, in every subcommand, that stores exactly one value."""
    ziele: set[str] = set()
    for aktion in parser._actions:
        if isinstance(aktion, argparse._SubParsersAction):
            for unter in aktion.choices.values():
                ziele |= _einwertige_optionen(unter)
        elif (aktion.option_strings and isinstance(aktion, argparse._StoreAction)
              and aktion.nargs is None):
            ziele.add(aktion.dest)
    return ziele


def _optionsziel(knoten: ast.AST) -> str | None:
    """`args.X` or `getattr(args, "X", ...)` gives X, anything else None."""
    if (isinstance(knoten, ast.Attribute) and isinstance(knoten.value, ast.Name)
            and knoten.value.id == "args"):
        return knoten.attr
    if (isinstance(knoten, ast.Call) and isinstance(knoten.func, ast.Name) and knoten.func.id == "getattr"
            and len(knoten.args) >= 2 and isinstance(knoten.args[0], ast.Name) and knoten.args[0].id == "args"
            and isinstance(knoten.args[1], ast.Constant) and isinstance(knoten.args[1].value, str)):
        return knoten.args[1].value
    return None


def _wahrheitslesungen(quelle: str, optionen: set[str]) -> set[tuple[str, str]]:
    """(function, dest) for every truth read of a one-value option, direct or through a local alias."""
    gefunden: set[tuple[str, str]] = set()
    for funktion in ast.walk(ast.parse(quelle)):
        if not isinstance(funktion, ast.FunctionDef):
            continue
        alias: dict[str, str] = {}
        for knoten in ast.walk(funktion):
            if (isinstance(knoten, ast.Assign) and len(knoten.targets) == 1
                    and isinstance(knoten.targets[0], ast.Name)):
                ziel = _optionsziel(knoten.value)
                if ziel in optionen:
                    alias[knoten.targets[0].id] = ziel

        def ziel_von(ausdruck: ast.AST) -> str | None:
            if isinstance(ausdruck, ast.Name):
                return alias.get(ausdruck.id)
            ziel = _optionsziel(ausdruck)
            return ziel if ziel in optionen else None

        pruefstellen: list[ast.AST] = []
        for knoten in ast.walk(funktion):
            if isinstance(knoten, (ast.If, ast.IfExp, ast.While, ast.Assert)):
                pruefstellen.append(knoten.test)
            elif isinstance(knoten, ast.BoolOp):
                pruefstellen.extend(knoten.values)
            elif isinstance(knoten, ast.UnaryOp) and isinstance(knoten.op, ast.Not):
                pruefstellen.append(knoten.operand)
            elif isinstance(knoten, ast.comprehension):
                pruefstellen.extend(knoten.ifs)
            elif (isinstance(knoten, ast.Call) and isinstance(knoten.func, ast.Name) and knoten.func.id == "bool"
                  and len(knoten.args) == 1):
                pruefstellen.append(knoten.args[0])
        for stelle in pruefstellen:
            ziel = ziel_von(stelle)
            if ziel is not None:
                gefunden.add((funktion.name, ziel))
    return gefunden


class EveryTruthReadOfAnOptionIsNamed(unittest.TestCase):

    def test_the_truth_reads_are_exactly_the_named_ones(self) -> None:
        gefunden = _wahrheitslesungen(CLI.read_text(encoding="utf-8"), _einwertige_optionen(build_parser()))
        neu = sorted(gefunden - set(_ERLAUBTE_WAHRHEITSLESUNGEN))
        weg = sorted(set(_ERLAUBTE_WAHRHEITSLESUNGEN) - gefunden)
        self.assertEqual(neu, [], "a one-value option is read by its truth; read it with `is not None`, or "
                                  "name it here with the reason an empty value is still not dropped")
        self.assertEqual(weg, [], "a named truth read is gone; remove its entry so the list stays a measurement")

    def test_control_the_guard_finds_a_planted_truth_read(self) -> None:
        # The guard has to be able to fail: every form it claims to read is planted once and found.
        gepflanzt = ("def _x(args):\n"
                     "    if args.policy:\n        pass\n"
                     "    anchor_type = getattr(args, 'anchor_type', None)\n"
                     "    y = anchor_type if anchor_type else None\n"
                     "    if not getattr(args, 'anchors', None):\n        pass\n"
                     "    assert args.aud\n"
                     "    z = [1 for _ in range(1) if args.nonce]\n"
                     "    return bool(getattr(args, 'eat', None))\n")
        self.assertEqual(_wahrheitslesungen(gepflanzt, {"policy", "anchor_type", "anchors", "aud", "nonce", "eat"}),
                         {("_x", "policy"), ("_x", "anchor_type"), ("_x", "anchors"), ("_x", "aud"),
                          ("_x", "nonce"), ("_x", "eat")})

    def test_control_an_is_not_none_read_is_not_a_truth_read(self) -> None:
        sauber = ("def _x(args):\n"
                  "    if args.policy is not None:\n        pass\n"
                  "    anchor_type = getattr(args, 'anchor_type', None)\n"
                  "    y = anchor_type if anchor_type is not None else None\n")
        self.assertEqual(_wahrheitslesungen(sauber, {"policy", "anchor_type"}), set())


if __name__ == "__main__":
    unittest.main()
