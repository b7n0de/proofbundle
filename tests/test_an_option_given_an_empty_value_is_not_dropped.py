"""An option the caller gave is read by `is not None`, never by its truth: an empty value is not an absent one.

SOURCE. The deep gate of the 6.2.0 release preparation at d97de8e5, lens L3, L3-620v3-CLI-EMPTY-OPTION-01
(P1 under Nachtrag 1 section 5, the exit code of the shipped verifier). `verify --policy ''`,
`verify --anchor-type ''`, `decision verify --policy ''` and `--anchors ''`, `outcome verify --policy ''`
and `relation-statement verify --policy ''` read the value by its truth, dropped the named restriction and
exited 0, where a nonexistent path gives 2 and a policy the receipt does not satisfy gives 3. The house rule
stands next to `--expected-origin` in cli.py: a flag whose subject is missing is a usage error, never a silent
nothing, and an empty string is a question that was asked. `verify-proof --expected-origin ''` already fails
(tests/test_verify_proof_expected_origin.py); this is the same rule for every option.

THREE PARTS. The first runs each measured site and checks the exit code against the one without the option.
The second is the class guard at the end of this file: it builds the parser, collects every option that takes one value, and reads
cli.py for every place that tests such a value by its truth, directly or through a local name bound to it,
in these forms: `if`, `while`, a conditional expression, `and` and `or`, `not`, `assert`, a comprehension
filter and `bool()`. Each such place must be named below with its reason, so an option added later, or a
truth read of these forms added to an old one, fails here until someone decides what an empty value means
for it. A read in another form (a truth test inside a called helper, say) is outside what it reads.

EMPTY IS JUDGED AFTER NORMALISATION (deep gate at 99f76ceb, L3-620v4-T11-NONCE-WS-01, P1). The first fix
refused `audit-challenge --nonce ''` by comparing the spelling with "", while the command used
`bytes.fromhex(value)`, which skips ASCII whitespace: `--nonce ' '` decoded to the empty nonce, gave the
grindable self-challenge indices under the label "auditor-nonce" and exited 0. So every measured site is run
with whitespace spellings of the empty value as well, the audit challenge is checked as a property of the
bytes it uses, and the class guard also refuses a comparison of a one-value option's spelling with the literal ""
by `==` or `!=`, directly or through a local name. It reads no other form (`in`, `is`, a pattern, `b""`); none
stands in cli.py (deep gate at d388ed3d, L3-620v5-T14-GUARD-CLAIM-01, which found the wording "any comparison").

A FILE WHOSE CONTENT READS AS ABSENT (deep gate run 5 at d388ed3d, L3-620v5-T14-ANCHORS-NULL-FILE-01, two of
three jurors P1). `decision verify --anchors FILE` with the content `null` became `anchors=None`, the value of
a call without the option, and ended with exit 0 like no option, while `--anchors ''` ended with exit 2; an
empty list is what the anchor layer reads None as, and ended the same way. So the third part runs every file
option whose absence is a state of its own with a generator of contents (JSON null alone and in whitespace,
the empty collections, an empty string, and the whitespace spellings above as the whole file), and a guard
reads cli.py for every option whose value names a file a command reads: each one is a case of the generator
or named with the reason it has no absent state that a content could reach.

ONE LEVEL DOWN, AND WHAT THE GUARD DID NOT SEE (verify lane V3 on 6d674973). A valid policy that holds no section
a command evaluates (the packaged eval template, or a policy with only a schema and an id) was loaded and not
evaluated, and `decision verify`, `outcome verify` and `relation-statement verify` ended with exit 0 and output
identical to no `--policy`, at d388ed3d and at both tags; such a file is refused now, and the cases below hold it.
`prereg --check` and `evalcard --check` read their file through `decode_eval_claim`, which the guard did not
list; every content was already refused there (exit 1), and both are cases of the generator now. And
`emit --key K --new-key ''` signed with K and exited 0: the two signer options were read by their truth.
"""
from __future__ import annotations

import argparse
import ast
import base64
import contextlib
import io
import json
import os
import re
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

#: The empty value and the whitespace a command may strip or skip before it uses the value: `str.strip`
#: and `bytes.fromhex` both drop these six ASCII characters. Alone and mixed.
_LEERRAUM = ("", " ", "\t", "\n", "\r", "\x0b", "\x0c", "  \t\n ", "\r\n")


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
        enclave_claim, _ = build_eval_claim(
            suite="s", suite_version="1", metric="acc", comparator=">=", threshold="0.8", score="0.9",
            n=10, model_id="m", dataset_id="d", issuer="Lab", timestamp="2026-07-02T00:00:00Z",
            assurance_level="enclave_attested")
        self.eval_enclave = schreibe("eval_enclave.json", emit_eval_receipt(enclave_claim, generate_signer()))
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
        self.protokoll = str(d / "protocol.txt")
        Path(self.protokoll).write_text("the protocol of an eval, committed to before the run\n", encoding="utf-8")
        self.karte = str(d / "card.md")
        Path(self.karte).write_text("# An eval card\n", encoding="utf-8")
        self.seed = str(d / "seed.key")
        from proofbundle.emit import save_signer
        save_signer(generate_signer(), self.seed)
        self.nutzlast = str(d / "payload.bin")
        Path(self.nutzlast).write_bytes(b"a payload")


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

    def test_a_value_that_normalises_to_empty_is_refused_like_the_empty_value(self) -> None:
        # The generator of the class, not one more spelling: every site, every whitespace form a command may
        # strip or skip (str.strip, bytes.fromhex), alone and mixed.
        for label, basis, option, erwartet in self._faelle():
            for wert in _LEERRAUM:
                with self.subTest(case=label, value=repr(wert)):
                    self.assertIn(_run(basis + [option[0], wert]), erwartet,
                                  f"{label} {wert!r} was read like an absent option")

    def test_an_auditor_nonce_is_never_the_empty_nonce(self) -> None:
        # The property behind the audit-challenge case: exit 0 with mode "auditor-nonce" means the challenge
        # used nonce bytes, and its indices are not the self-challenge indices a producer can grind.
        from proofbundle.persample import audit_challenge
        root = base64.b64encode(bytes(range(32))).decode()
        selbst = audit_challenge(root, 1000, 20, b"")

        def aufruf(extra: list[str]) -> tuple[int, dict | None]:
            out = io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                rc = main(["audit-challenge", root, "1000", "20", "--json"] + extra)
            return rc, (json.loads(out.getvalue()) if rc == 0 else None)

        rc, ohne = aufruf([])   # control: no --nonce is the labelled self-challenge
        self.assertEqual((rc, ohne["mode"], ohne["indices"]), (0, "self-challenge", selbst))
        werte = list(_LEERRAUM) + ["ab" * 16, " ab" * 16, "\tab\n", "00", "zz", "a"]
        for wert in werte:
            with self.subTest(value=repr(wert)):
                rc, aus = aufruf(["--nonce", wert])
                if rc == 0:
                    self.assertEqual(aus["mode"], "auditor-nonce")
                    self.assertGreater(len(bytes.fromhex(wert)), 0, f"{wert!r} ran as a nonce with no bytes")
                    self.assertNotEqual(aus["indices"], selbst, f"{wert!r} gave the self-challenge indices")
                else:
                    self.assertEqual(rc, 2)
        # controls: a real nonce runs, and each whitespace form is refused
        self.assertEqual(aufruf(["--nonce", "ab" * 16])[0], 0)
        for wert in _LEERRAUM:
            with self.subTest(refused=repr(wert)):
                self.assertEqual(aufruf(["--nonce", wert])[0], 2)

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

    def test_an_empty_signer_option_is_refused(self) -> None:
        """`emit --key K --new-key ''` signed with K and exited 0, and `--key '' --new-key N` wrote N (verify lane V3
        on 6d674973): the two signer options were read by their truth. `--payload-file ''` ended in a raw traceback."""
        b = self.b
        aus = str(Path(self._td.name) / "bundle_out.json")
        neu = str(Path(self._td.name) / "new.key")
        basis = ["emit", "--payload-file", b.nutzlast, "--out", aus]
        for label, extra in (("--key K --new-key ''", ["--key", b.seed, "--new-key", ""]),
                             ("--key '' --new-key N", ["--key", "", "--new-key", neu]),
                             ("--key ''", ["--key", ""]), ("--new-key ''", ["--new-key", ""])):
            with self.subTest(case=label):
                self.assertEqual(_run(basis + extra), 2)
        with self.subTest(case="--payload-file ''"):
            self.assertEqual(_run(["emit", "--payload-file", "", "--out", aus, "--key", b.seed]), 2)
        with self.subTest(control="--key K signs"):
            self.assertEqual(_run(basis + ["--key", b.seed]), 0)

    def test_control_each_base_command_passes_without_the_option(self) -> None:
        # Without this, a base that already fails would make every case above pass for the wrong reason.
        for label, basis, _option, _erwartet in self._faelle():
            with self.subTest(case=label):
                self.assertEqual(_run(basis), 0, f"the base of {label} does not pass on its own")


# ── the file options: a content that reads as absent is refused like the empty value ──────────────

#: What a file named by an option may hold that a reader can turn into the library's "not given": JSON null
#: alone and in whitespace, the empty collections, an empty JSON string, zero and false, and every
#: whitespace spelling of `_LEERRAUM` as the whole content.
_DATEI_INHALTE = ("null", " null", "null\n", "\t null \r\n", "[]", " [ ] ", "{}", '""', "0", "false") + _LEERRAUM

#: The file options the generator runs, by command and option: every one whose absence is a state of its own.
_DATEI_FAELLE = frozenset({
    ("verify", "--policy"), ("verify", "--trusted-checkpoint"), ("verify", "--trusted-tsa-root"),
    ("show-eval", "--eat"), ("decision verify", "--policy"), ("decision verify", "--anchors"),
    ("decision verify", "--trusted-tsa-root"), ("decision verify", "--with-related"),
    ("outcome verify", "--policy"), ("outcome verify", "--with-related"),
    ("relation-statement verify", "--policy"), ("relation-statement verify", "--with-related"),
    ("policy instantiate", "--expected-root-file"), ("prereg", "--check"), ("evalcard", "--check")})

#: A syntactically valid log verifier key, for the trusted-checkpoint case (the checkpoint itself is the file).
_VKEY = "example.com/log+abcd1234+AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="


#: A line of stdout that the clock writes, not the input: `show-eval` prints the age of the claim in seconds. Two runs
#: a second apart differ there, which made the control below fail under load, and could make the generator see a
#: difference where a content read like no option (measured on 2026-09-30, 853180s against 853181s).
_UHRZEILE = re.compile(r"(?m)^age +\S+s$")


def _beobachte(argv: list[str]) -> tuple:
    """Exit code and stdout of one run: what a caller of the command can tell apart, with the line the clock writes
    (`_UHRZEILE`) kept as its label."""
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        try:
            rc = main(argv)
        except SystemExit as exc:
            rc = exc.code
    return rc, _UHRZEILE.sub("age <seconds>s", out.getvalue())


class AFileWhoseContentReadsAsAbsentIsRefused(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls._td = tempfile.TemporaryDirectory(prefix="pb_file_option_")
        cls.b = _Belege(cls._td.name)

    @classmethod
    def tearDownClass(cls) -> None:
        cls._td.cleanup()

    def _instantiate(self, extra: list[str]) -> tuple:
        """`policy instantiate` writes the policy to a file; what it wrote is the observable, beside the exit."""
        ziel = Path(self._td.name) / "instantiated.json"
        if ziel.exists():
            ziel.unlink()
        rc, _ = _beobachte(["policy", "instantiate", "strict-eval-authenticated-root-template-v1",
                            "--issuer-key", self.b.keyfile, "--policy-id", "org/file-option-v1",
                            "--output", str(ziel)] + extra)
        return rc, ziel.read_text(encoding="utf-8") if ziel.exists() else None

    def _datei_faelle(self) -> dict:
        """{(command, option): (base argv, argv beside the option, observer)} for every file option whose
        absence is a state of its own. The observer runs base + option + beside, or the base alone."""
        b = self.b
        dv = ["decision", "verify", b.decision, "--pub", b.pub]
        ov = ["outcome", "verify", b.outcome, "--pub", b.pub]
        rv = ["relation-statement", "verify", b.relation, "--pub", b.pub]
        return {
            ("verify", "--policy"): (["verify", b.bundle], [], _beobachte),
            ("verify", "--trusted-checkpoint"): (["verify", b.bundle], ["--checkpoint-vkey", _VKEY], _beobachte),
            ("verify", "--trusted-tsa-root"): (["verify", b.bundle, "--anchor-type", "rfc3161-tsa"], [], _beobachte),
            ("show-eval", "--eat"): (["show-eval", b.eval_enclave], [], _beobachte),
            ("decision verify", "--policy"): (dv, [], _beobachte),
            ("decision verify", "--anchors"): (dv, [], _beobachte),
            ("decision verify", "--trusted-tsa-root"): (dv, [], _beobachte),
            ("decision verify", "--with-related"): (dv, [], _beobachte),
            ("outcome verify", "--policy"): (ov, [], _beobachte),
            ("outcome verify", "--with-related"): (ov, [], _beobachte),
            ("relation-statement verify", "--policy"): (rv, [], _beobachte),
            ("relation-statement verify", "--with-related"): (rv, [], _beobachte),
            ("policy instantiate", "--expected-root-file"): ([], [], lambda argv: self._instantiate(argv)),
            ("prereg", "--check"): (["prereg", b.protokoll], [], _beobachte),
            ("evalcard", "--check"): (["evalcard", b.karte], [], _beobachte),
        }

    def test_the_cases_are_the_named_ones(self) -> None:
        self.assertEqual(set(self._datei_faelle()), _DATEI_FAELLE)

    def test_the_empty_value_is_told_apart_from_no_option(self) -> None:
        # Without this, a case whose empty value already ends like no option would make the generator vacuous.
        for (befehl, option), (basis, daneben, beobachte) in self._datei_faelle().items():
            with self.subTest(case=f"{befehl} {option}"):
                self.assertNotEqual(beobachte(basis + [option, ""] + daneben), beobachte(basis))

    def test_a_file_whose_content_reads_as_absent_ends_unlike_no_option(self) -> None:
        for (befehl, option), (basis, daneben, beobachte) in self._datei_faelle().items():
            ohne = beobachte(basis)
            for i, inhalt in enumerate(_DATEI_INHALTE):
                datei = Path(self._td.name) / f"inhalt_{i}.txt"
                datei.write_text(inhalt, encoding="utf-8")
                with self.subTest(case=f"{befehl} {option}", content=repr(inhalt)):
                    self.assertNotEqual(beobachte(basis + [option, str(datei)] + daneben), ohne,
                                        f"{befehl} {option} with a file holding {inhalt!r} ended like no {option}")

    def test_a_policy_that_holds_no_section_the_command_evaluates_is_refused(self) -> None:
        """One level down from `_DATEI_INHALTE` (verify lane V3 on 6d674973): a policy the loader accepts, with no
        section the command judges by, ended like no `--policy`. Each such policy is refused with exit 2; a
        policy with the section is evaluated, the control that the refusal is about the section."""
        b = self.b
        ohne_abschnitt = [
            {"schema": "proofbundle/trust-policy/v0.2", "policy_id": "org/no-section-v1"},
            {"schema": "proofbundle/trust-policy/v0.1", "policy_id": "org/no-section-v1"},
            # V6-F2 on 8f2fa980: a relations section with no rule sets nothing, and `decision verify` under it ended
            # byte-identical to a verify without the policy.
            {"schema": "proofbundle/trust-policy/v0.2", "policy_id": "org/empty-relations-v1", "relations": {}},
        ]
        vorlage = Path(self._td.name) / "template.json"
        _beobachte(["policy", "instantiate", "strict-eval-template-v1", "--issuer-key", b.keyfile,
                    "--policy-id", "org/eval-only-v1", "--output", str(vorlage)])
        dateien = [str(vorlage)]
        for i, pol in enumerate(ohne_abschnitt):
            datei = Path(self._td.name) / f"no_section_{i}.json"
            datei.write_text(json.dumps(pol), encoding="utf-8")
            dateien.append(str(datei))
        befehle = {"decision verify": ["decision", "verify", b.decision, "--pub", b.pub],
                   "outcome verify": ["outcome", "verify", b.outcome, "--pub", b.pub],
                   "relation-statement verify": ["relation-statement", "verify", b.relation, "--pub", b.pub]}
        for name, basis in befehle.items():
            ohne = _beobachte(basis)
            for datei in dateien:
                with self.subTest(command=name, policy=Path(datei).name):
                    aus = _beobachte(basis + ["--policy", datei])
                    self.assertNotEqual(aus, ohne, f"{name} ended like no --policy")
                    self.assertEqual(aus[0], 2)
            with self.subTest(command=name, control="a relations section is evaluated"):
                mit = Path(self._td.name) / "with_relations.json"
                mit.write_text(json.dumps({"schema": "proofbundle/trust-policy/v0.2", "policy_id": "org/rel-v1",
                                           "relations": {"reject_superseded": True}}), encoding="utf-8")
                self.assertNotEqual(_beobachte(basis + ["--policy", str(mit)])[0], 2)
        with self.subTest(command="decision verify", control="an empty decision_receipt section is evaluated"):
            # Its default rules apply to an empty section too (`allow_raw_inputs`), so it is no policy of nothing.
            leer = Path(self._td.name) / "empty_decision_section.json"
            leer.write_text(json.dumps({"schema": "proofbundle/trust-policy/v0.2", "policy_id": "org/dr-v1",
                                        "decision_receipt": {}}), encoding="utf-8")
            self.assertNotEqual(_beobachte(befehle["decision verify"] + ["--policy", str(leer)])[0], 2)

    def test_a_policy_with_only_an_anchors_section_applies_beside_anchors(self) -> None:
        """Verify lane V4 on 8f2fa980: the `anchors` section of a policy gives the relying party's trust for the
        anchors of `--anchors`, and a policy with only that section beside `--anchors` confirmed an anchor at
        d388ed3d; the first form of the refusal refused it. It applies beside `--anchors`, and without anchors it is
        a policy the command reads as nothing."""
        b = self.b
        politik = Path(self._td.name) / "anchors_only.json"
        politik.write_text(json.dumps({"schema": "proofbundle/trust-policy/v0.2", "policy_id": "org/anchors-only-v1",
                                       "anchors": {"bitcoin_block_headers": {"850000": "ab" * 32}}}), encoding="utf-8")
        anker = Path(self._td.name) / "one_anchor.json"
        anker.write_text(json.dumps([{"type": "unregistered-type/v1", "target": "statement",
                                      "canonicalRoot": base64.b64encode(b"\x00" * 32).decode(),
                                      "proof": base64.b64encode(b"p").decode()}]), encoding="utf-8")
        dv = ["decision", "verify", b.decision, "--pub", b.pub]

        def fehlerzeile(argv):
            err = io.StringIO()
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
                rc = main(argv)
            return rc, err.getvalue()
        rc, err = fehlerzeile(dv + ["--anchors", str(anker), "--policy", str(politik)])
        self.assertNotIn("cannot use --policy", err, "a policy whose anchors section applies was refused")
        rc_ohne, _ = fehlerzeile(dv + ["--anchors", str(anker)])
        self.assertEqual(rc, rc_ohne, "the case needs the anchors verdict itself to decide the exit, as without policy")
        rc, err = fehlerzeile(dv + ["--policy", str(politik)])
        self.assertEqual(rc, 2)
        self.assertIn("cannot use --policy", err)
        # An anchors section that gives no trust material applies nothing beside --anchors either (V6 on 8f2fa980):
        # decision verify reads only the trust material of it.
        ohne_vertrauen = Path(self._td.name) / "anchors_without_trust.json"
        ohne_vertrauen.write_text(json.dumps({"schema": "proofbundle/trust-policy/v0.2", "policy_id": "org/anc-v1",
                                              "anchors": {"require_anchor": "any"}}), encoding="utf-8")
        rc, err = fehlerzeile(dv + ["--anchors", str(anker), "--policy", str(ohne_vertrauen)])
        self.assertEqual(rc, 2)
        self.assertIn("cannot use --policy", err)

    def test_control_the_generator_sees_an_option_the_command_does_not_read(self) -> None:
        # The generator has to be able to fail: `show-eval --eat` on a receipt that declares no enclave level
        # never reads the file, so every content ends like no option, and the comparison says so.
        basis = ["show-eval", self.b.eval_receipt]
        datei = Path(self._td.name) / "unread.txt"
        datei.write_text("null", encoding="utf-8")
        self.assertEqual(_beobachte(basis + ["--eat", str(datei)]), _beobachte(basis))

    def test_the_line_the_clock_writes_is_no_difference(self) -> None:
        """The age `show-eval` prints moves with the clock, so two runs a second apart must still read as one
        observation; the label keeps the line, so its absence would still be a difference."""
        import time
        basis = ["show-eval", self.b.eval_receipt]
        erster = _beobachte(basis)
        self.assertIn("age <seconds>s", erster[1])
        time.sleep(1.1)
        self.assertEqual(_beobachte(basis), erster)


class ARelationsSectionIsHeldOnlyWhenTheCommandAppliesARuleOfIt(unittest.TestCase):
    """THE PROPERTY (deep gate run 6 at fda55f98, L3-620v6-T16-RELATIONS-RULE-NOT-APPLIED-01, three of three jurors
    P1): for each receipt verify command and each policy whose only section is `relations`, the command refuses the
    policy with exit 2 exactly when no rule of the section can change what the command answers. The guard counted a
    section as held when it held any key, so `reject_retracted: true` at `decision verify` and `outcome verify`, which
    never apply it, and `reject_superseded: false`, an empty `relation_signer` or an empty `require_relation_target`
    were accepted: `decision verify` ended byte-identical to no `--policy`, and `outcome verify` printed POLICY: OK
    over an attached, verified retraction of its receipt.

    THE ORACLE does not ask the guards. With both switched off, `cli._policy_ohne_abschnitt` and the rule that every
    rule a policy sets is one the command applies (`policy._regelfehler`, T16 after the review before run 7), a
    section counts as applied when, in one of the scenarios below, the run with the policy ends with another exit
    code than the run without it. The scenarios are
    built so that every kind of rule fails in one of them: an attached, verified retraction of the receipt
    (`reject_superseded`), an edge to a target that is not attached (`require_relation_resolution`), an edge to a
    target signed by another key (`relation_signer` in both modes, `require_relation_target`), and a statement that
    retracts an attached, verified target (`reject_retracted` at `relation-statement verify`). With the guard on, the
    case asserts refusal exactly for the sections the oracle found applying nothing. The generator takes every
    section built from the values that set no rule, and each value that sets one alone and beside all of them."""

    _V2 = "proofbundle/trust-policy/v0.2"

    @classmethod
    def setUpClass(cls) -> None:
        from proofbundle import anchors as _anchors
        from proofbundle._wire_b64 import decode_b64
        cls._td = tempfile.TemporaryDirectory(prefix="pb_relations_rule_")
        d = Path(cls._td.name)
        haupt, fremd, dritt = generate_signer(), generate_signer(), generate_signer()

        def b64(s) -> str:
            return base64.b64encode(s.public_key().public_bytes_raw()).decode("ascii")
        cls.pub, cls.fremd_pub, cls.dritt_pub = b64(haupt), b64(fremd), b64(dritt)
        zaehler = [0]

        def schreibe(obj) -> str:
            zaehler[0] += 1
            p = d / f"beleg_{zaehler[0]}.json"
            p.write_text(json.dumps(obj), encoding="utf-8")
            return str(p)

        def wurzel(env) -> str:
            return _anchors.statement_content_root(decode_b64(env["payload"])).hex()

        def kante(relation: str, ziel: str, aussage: bool = False) -> dict:
            k = {"relation": relation, "targetReceiptDigest": {"digestAlgorithm": "jcs-sha256-v1", "digest": ziel}}
            if aussage:
                k.update({"reasonCode": "withdrawal", "reason": "x", "declaredAt": "2026-09-29T00:00:00Z"})
            return k

        dpred = json.loads((REPO / "examples" / "decision_receipt_deny.json").read_text(encoding="utf-8"))
        opred = {"schemaVersion": "0.1.0", "outcomeId": "o1", "decisionRef": {"sha256": "e" * 64},
                 "executor": {"id": "executor:x", "keyId": "kid"}, "requestedActionDigest": {"sha256": "b" * 64},
                 "status": "executed", "performedAt": "2026-07-14T10:00:00Z", "effectDigest": {"sha256": "c" * 64}}

        def beleg(befehl: str, kanten: list | None, signer=haupt):
            if befehl == "decision":
                pred = dict(dpred, **({"relationships": kanten} if kanten else {}))
                return emit_decision_receipt(pred, signer, strict=True)
            if befehl == "outcome":
                return emit_outcome_receipt(dict(opred, **({"relationships": kanten} if kanten else {})), signer)
            stmt = {"schemaVersion": "0.1.0", "statementId": f"urn:uuid:rel-{zaehler[0]}",
                    "relationships": kanten or [kante("retracts", "a" * 64, aussage=True)]}
            return emit_relation_statement(stmt, signer)

        # The target an edge names in scenarios 3 and 4: a receipt signed by another key, attached with its key.
        ziel_env = emit_decision_receipt(dpred, fremd, strict=True)
        ziel_datei, ziel_wurzel = schreibe(ziel_env), wurzel(ziel_env)
        anhang_fremd = ["--with-related", ziel_datei, "--related-pub", cls.fremd_pub]
        cls.szenarien: dict = {}
        for befehl in ("decision", "outcome", "relation-statement"):
            aussage = befehl == "relation-statement"
            basis = [befehl, "verify"] if befehl != "relation-statement" else ["relation-statement", "verify"]
            ohne_kante = beleg(befehl, None)
            ruecknahme = emit_relation_statement(
                {"schemaVersion": "0.1.0", "statementId": f"urn:uuid:retract-{befehl}",
                 "relationships": [kante("retracts", wurzel(ohne_kante), aussage=True)]}, haupt)
            cls.szenarien[befehl] = [
                basis + [schreibe(ohne_kante), "--pub", cls.pub],
                basis + [schreibe(ohne_kante), "--pub", cls.pub, "--with-related", schreibe(ruecknahme)],
                basis + [schreibe(beleg(befehl, [kante("supersedes", "c" * 64, aussage)])), "--pub", cls.pub],
                basis + [schreibe(beleg(befehl, [kante("supersedes", ziel_wurzel, aussage)])), "--pub", cls.pub]
                + anhang_fremd,
                basis + [schreibe(beleg(befehl, [kante("retracts", ziel_wurzel, aussage)])), "--pub", cls.pub]
                + anhang_fremd,
            ]
        leer = {"reject_superseded": [False], "reject_retracted": [False, True], "relation_signer": [{}],
                "require_relation_target": [{}]}
        setzend = {"require_relation_resolution": [["supersedes"]], "reject_superseded": [True],
                   "relation_signer": [{"supersedes": {"mode": "same-key"}},
                                       {"supersedes": {"mode": "pinned", "keys": [cls.dritt_pub]}}],
                   "require_relation_target": [{"supersedes": "d" * 64}]}
        import itertools
        ohne_regel: list = []
        for wahl in itertools.product(*[[None] + werte for werte in leer.values()]):
            ohne_regel.append({k: v for k, v in zip(leer, wahl) if v is not None})
        cls.abschnitte = list(ohne_regel)
        for schluessel, werte in setzend.items():
            for wert in werte:
                cls.abschnitte.append({schluessel: wert})
                cls.abschnitte.append({**{k: v[0] for k, v in leer.items() if k != schluessel}, schluessel: wert})
        cls.dateien = []
        for i, abschnitt in enumerate(cls.abschnitte):
            p = d / f"policy_{i}.json"
            p.write_text(json.dumps({"schema": cls._V2, "policy_id": f"org/relations-{i}-v1", "relations": abschnitt}),
                         encoding="utf-8")
            cls.dateien.append(str(p))

    @classmethod
    def tearDownClass(cls) -> None:
        cls._td.cleanup()

    @staticmethod
    def _lauf(argv: list[str]) -> tuple:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = main(argv)
        return rc, out.getvalue(), err.getvalue()

    def _angewendet(self, befehl: str, datei: str) -> bool:
        """The oracle: with the guards off, does the policy change one scenario's exit code? A rule the command applies
        fails in one scenario and ends it with exit 3. The stdout is not compared: `outcome verify` and `relation-statement
        verify` print POLICY: OK for any policy they accept, so a line that names a passing policy is no rule applied,
        and that line over a policy of nothing is the defect itself."""
        from unittest import mock
        with mock.patch("proofbundle.cli._policy_ohne_abschnitt", lambda *a, **k: False), \
                mock.patch("proofbundle.policy._regelfehler", lambda *a, **k: None):
            for argv in self.szenarien[befehl]:
                if self._lauf(argv + ["--policy", datei])[0] != self._lauf(argv)[0]:
                    return True
        return False

    def test_a_section_is_refused_exactly_when_no_rule_of_it_applies(self) -> None:
        for befehl in self.szenarien:
            for abschnitt, datei in zip(self.abschnitte, self.dateien):
                with self.subTest(command=befehl, relations=abschnitt):
                    angewendet = self._angewendet(befehl, datei)
                    rc, _, err = self._lauf(self.szenarien[befehl][0] + ["--policy", datei])
                    abgewiesen = rc == 2 and "cannot use --policy" in err
                    self.assertEqual(abgewiesen, not angewendet,
                                     f"{befehl} verify {'refused' if abgewiesen else 'accepted'} a relations section "
                                     f"that {'changes' if angewendet else 'changes nothing of'} what it answers")

    def test_control_each_kind_of_rule_applies_in_a_scenario(self) -> None:
        # The oracle has to be able to find a rule: each value that sets one changes a scenario at every command
        # that applies it, so a scenario set that no rule fails would read every section as applying nothing.
        for befehl in self.szenarien:
            for abschnitt, datei in zip(self.abschnitte, self.dateien):
                if len(abschnitt) != 1 or next(iter(abschnitt.values())) in ([], {}, False):
                    continue
                if abschnitt == {"reject_retracted": True}:
                    continue   # applied by relation-statement verify only; the property case holds the rest
                with self.subTest(command=befehl, relations=abschnitt):
                    self.assertTrue(self._angewendet(befehl, datei), f"no scenario of {befehl} verify fails {abschnitt}")

    def test_control_reject_retracted_applies_where_a_statement_is_judged(self) -> None:
        datei = self.dateien[self.abschnitte.index({"reject_retracted": True})]
        self.assertTrue(self._angewendet("relation-statement", datei))
        self.assertFalse(self._angewendet("decision", datei))
        self.assertFalse(self._angewendet("outcome", datei))


#: Every file option without a generator case, with the reason no content of it can read as its absence.
#: Measured on the tree of this change for the optional ones: without the option the command is refused
#: (exit 2), and so is every content of `_DATEI_INHALTE`.
_OHNE_ABWESENHEIT = "no absent state: without it the command is refused (exit 2), and so is every content"
_PFLICHT = "required: argparse refuses a call without it, so there is no absent state a content could reach"
#: The statement's file options of `verify` have their case in tests/test_scitt_statement_producer.py
#: (TestAStatementFileWhoseContentReadsAsAbsentIsRefused), where the [scitt] extra the check needs is present.
_SCITT_FALL = ("a case in tests/test_scitt_statement_producer.py, where the [scitt] extra is present: no "
               "content of _DATEI_INHALTE ends like no option")
_DATEI_OPTIONEN_OHNE_FALL = {
    ("emit", "--key"): _OHNE_ABWESENHEIT + " (provide --key or --new-key)",
    ("emit-eval", "--key"): _OHNE_ABWESENHEIT + " (provide --key or --new-key)",
    ("intoto", "--key"): _OHNE_ABWESENHEIT + " (provide --key or --new-key)",
    ("svr", "--key"): _OHNE_ABWESENHEIT + " (provide --key or --new-key)",
    ("decision emit", "--key"): _OHNE_ABWESENHEIT + " (provide --key or --new-key)",
    ("outcome emit", "--key"): _OHNE_ABWESENHEIT + " (provide --key or --new-key)",
    ("relation-statement emit", "--key"): _OHNE_ABWESENHEIT + " (provide --key or --new-key)",
    ("anchor upgrade", "--target-file"): ("no absent state a content could reach: without it the command is refused "
                                          "(exit 2, provide --target-file or --canonical-root-hex), and with it the "
                                          "file's bytes are the target itself, whose hash the proof must commit to, so "
                                          "every content, the empty file included, names a target (verify lane V1)"),
    ("anchor verify-pack", "--target-file"): ("no absent state a content could reach: without it (and without "
                                              "--expected-root) the command is refused (exit 2), and with it the file's "
                                              "bytes are hashed to the expected target the pack's canonicalRoot must "
                                              "equal, so every content, the empty file included, names a target "
                                              "(Nachtrag 32, the Z309 High)"),
    ("emit", "--payload-file"): _PFLICHT + "; its bytes are the payload itself",
    ("verify-proof", "--payload-file"): _PFLICHT + "; its bytes are the payload itself",
    ("emit-eval", "--claim"): _PFLICHT,
    ("verify-enclave", "--receipt"): _PFLICHT,
    ("anchor upgrade", "--proof"): _PFLICHT,
    ("policy instantiate", "--issuer-key"): _PFLICHT,
    ("scitt sign", "--key"): _OHNE_ABWESENHEIT + " (provide --key or --new-key, or --ec-key with --x5chain)",
    ("verify", "--scitt-statement"): _SCITT_FALL,
    ("verify", "--scitt-statement-key"): _SCITT_FALL,
    ("verify", "--scitt-service-keys"): _SCITT_FALL,
}

#: The functions that read a file named by their first argument. `open` counts only in a read mode.
_DATEI_LESER = frozenset({"_open_input", "open", "load_bundle", "resolve_policy_source", "_load_related",
                          "load_signer", "_resolve_signer", "decode_eval_claim"})


def _optionsziele_in(ausdruck: ast.AST, alias: dict) -> set:
    ziele: set = set()
    for knoten in ast.walk(ausdruck):
        ziel = _optionsziel(knoten)
        if ziel is not None:
            ziele.add(ziel)
        if isinstance(knoten, ast.Name) and knoten.id in alias:
            ziele |= alias[knoten.id]
    return ziele


def _datei_ziele(quelle: str) -> set[str]:
    """The dest of every option whose value reaches a file reader of `_DATEI_LESER` as its first argument,
    directly, through a local name bound to it, or as the variable of a loop over it."""
    ziele: set[str] = set()
    for funktion in ast.walk(ast.parse(quelle)):
        if not isinstance(funktion, ast.FunctionDef):
            continue
        alias: dict = {}
        for _ in range(3):   # a name bound from a name bound from the option
            for knoten in ast.walk(funktion):
                if (isinstance(knoten, ast.Assign) and len(knoten.targets) == 1
                        and isinstance(knoten.targets[0], ast.Name)):
                    gefunden = _optionsziele_in(knoten.value, alias)
                    if gefunden:
                        alias.setdefault(knoten.targets[0].id, set()).update(gefunden)
                elif isinstance(knoten, (ast.For, ast.comprehension)) and isinstance(knoten.target, ast.Name):
                    gefunden = _optionsziele_in(knoten.iter, alias)
                    if gefunden:
                        alias.setdefault(knoten.target.id, set()).update(gefunden)
        for knoten in ast.walk(funktion):
            if not (isinstance(knoten, ast.Call) and knoten.args):
                continue
            name = (knoten.func.id if isinstance(knoten.func, ast.Name)
                    else knoten.func.attr if isinstance(knoten.func, ast.Attribute) else None)
            if name not in _DATEI_LESER:
                continue
            if name == "open":
                modus = knoten.args[1] if len(knoten.args) > 1 else next(
                    (k.value for k in knoten.keywords if k.arg == "mode"), None)
                if isinstance(modus, ast.Constant) and any(c in str(modus.value) for c in "wax"):
                    continue
            ziele |= _optionsziele_in(knoten.args[0], alias)
    return ziele


def _datei_optionen(parser: argparse.ArgumentParser, ziele: set[str], pfad: tuple = ()) -> set[tuple[str, str]]:
    """(command, longest option string) of every option, in every subcommand, whose dest is in `ziele`."""
    gefunden: set[tuple[str, str]] = set()
    gesehen: set[int] = set()
    for aktion in parser._actions:
        if isinstance(aktion, argparse._SubParsersAction):
            for name, unter in aktion.choices.items():
                if id(unter) not in gesehen:
                    gesehen.add(id(unter))
                    gefunden |= _datei_optionen(unter, ziele, pfad + (name,))
        elif aktion.option_strings and aktion.dest in ziele:
            gefunden.add((" ".join(pfad), max(aktion.option_strings, key=len)))
    return gefunden


class EveryFileOptionIsClassified(unittest.TestCase):

    def test_every_file_option_is_a_case_or_named(self) -> None:
        gefunden = _datei_optionen(build_parser(), _datei_ziele(CLI.read_text(encoding="utf-8")))
        benannt = _DATEI_FAELLE | set(_DATEI_OPTIONEN_OHNE_FALL)
        self.assertEqual(sorted(gefunden - benannt), [], "a file option that is neither a case nor named")
        self.assertEqual(sorted(benannt - gefunden), [], "a named file option that no command reads any more")

    def test_control_the_guard_finds_a_planted_file_read(self) -> None:
        gepflanzt = ("def _x(args):\n"
                     "    with _open_input(args.policy) as h:\n        pass\n"
                     "    p = getattr(args, 'anchors', None)\n"
                     "    open(p, encoding='utf-8')\n"
                     "    for k in args.issuer_key:\n        open(k)\n"
                     "    open(args.out, 'w')\n"
                     "    decode(args.pub)\n")
        self.assertEqual(_datei_ziele(gepflanzt), {"policy", "anchors", "issuer_key"})



# ── the class guard ───────────────────────────────────────────────────────────────────────────────

#: Every place in cli.py that reads a one-value option by its truth, with the reason an empty value is
#: still not dropped there. Keyed by (function, option dest). A new entry needs a reason that holds.
_ERLAUBTE_WAHRHEITSLESUNGEN = {
    ("_cmd_decision_verify", "pub"): "an empty --pub is refused with exit 2 before anything is read",
    ("_cmd_outcome_verify", "pub"): "an empty --pub is refused with exit 2 before anything is read",
    ("_cmd_relation_statement_verify", "pub"): "an empty --pub is refused with exit 2 before anything is read",
    ("_cmd_decision_init", "out"): "a template printer; an empty --out prints to stdout, nothing is verified",
    ("_cmd_outcome_init", "out"): "a template printer; an empty --out prints to stdout, nothing is verified",
    ("_cmd_relation_statement_init", "out"): "a template printer; an empty --out prints to stdout",
    ("_cmd_policy_instantiate", "output"): "an empty --output writes the policy to stdout, the documented default",
    ("_cmd_svr", "policy_uri"): "emit side: content the producer writes, no restriction a verifier relies on",
    ("_cmd_svr", "policy_sha256"): "emit side: content the producer writes, no restriction a verifier relies on",
    ("_load_scitt_inputs", "scitt_statement_kid"): "an empty --scitt-statement-kid is refused with exit 2 before "
                                                   "the statement is checked",
    ("_load_scitt_inputs", "scitt_service_issuer"): "an empty --scitt-service-issuer is refused with exit 2 before "
                                                    "anything is read",
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


def _leervergleiche(quelle: str, optionen: set[str]) -> set[tuple[str, str]]:
    """(function, dest) for every `== ""` or `!= ""` on a one-value option, direct or through a local alias.

    Such a comparison judges emptiness by the spelling, and a command that strips or decodes the value
    afterwards uses something else: `--nonce ' '` passed `== ""` and decoded to no bytes (deep gate at
    99f76ceb). Emptiness is judged on the value the command uses, so this form is refused, not named."""
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
        for knoten in ast.walk(funktion):
            if not (isinstance(knoten, ast.Compare) and all(isinstance(o, (ast.Eq, ast.NotEq)) for o in knoten.ops)):
                continue
            seiten = [knoten.left, *knoten.comparators]
            if not any(isinstance(s, ast.Constant) and s.value == "" for s in seiten):
                continue
            for seite in seiten:
                ziel = alias.get(seite.id) if isinstance(seite, ast.Name) else _optionsziel(seite)
                if ziel in optionen:
                    gefunden.add((funktion.name, ziel))
    return gefunden


class EveryTruthReadOfAnOptionIsNamed(unittest.TestCase):

    def test_no_option_is_judged_empty_by_its_spelling(self) -> None:
        gefunden = _leervergleiche(CLI.read_text(encoding="utf-8"), _einwertige_optionen(build_parser()))
        self.assertEqual(sorted(gefunden), [], "a one-value option is compared with \"\"; judge emptiness on the "
                                               "value the command uses (after strip or decode), not its spelling")

    def test_control_the_spelling_guard_finds_a_planted_comparison(self) -> None:
        gepflanzt = ("def _x(args):\n"
                     "    if args.nonce is not None and args.nonce == \"\":\n        pass\n"
                     "    p = getattr(args, 'policy', None)\n"
                     "    if \"\" != p:\n        pass\n"
                     "    if args.aud == 'x':\n        pass\n")
        self.assertEqual(_leervergleiche(gepflanzt, {"nonce", "policy", "aud"}), {("_x", "nonce"), ("_x", "policy")})


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
