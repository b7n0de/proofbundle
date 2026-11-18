"""`decision verify` reads "ok": true only when every binding the call requests was checked and held.

WHERE THIS COMES FROM. Finding B22 of the 6.6.0 landing series: `decision verify` ended with exit 2 for a
requested binding that failed, and its JSON still read `"ok": true` with `automation.referencesResolved`
true. Measured again on main 6b63cda8 (2026-11-09): every binding option `decision verify` has there folds
into `ok` and the exit, with one exception. A `--with-related` target that does not verify under its key
(the default `--pub`, or the paired `--related-pub`) was ignored when no edge of the receipt names it: exit 0,
`"ok": true`, `lineage` NOT_EVALUATED, `referencesResolved` true, although the option's help says an attached
target that does not verify FAILS lineage.

WHAT IS PINNED.
- The options of `decision verify` are read from the parser `build_parser` builds, not listed by hand. Each
  one is either a binding, with the result field that carries its outcome and a counter-case below, or named
  as no binding with the reason. An option added later that is neither fails `test_every_option_is_classified`,
  and a binding without a counter-case fails `test_every_binding_has_a_counter_case`.
- Each counter-case requests one binding that does not hold. The exit is not 0, and whenever the command
  prints JSON, `ok` is false, the binding's field is in the JSON and reads false, and `safeForAutomation` is
  false. Where the field is a reference field, `referencesResolved` is not true.
- The controls: the same calls with the binding holding exit 0, and their JSON reads `ok` true and the field
  true, or for the two relation options not false (`lineage_ok` stays None when nothing failed). Every binding
  has a control, held by `test_every_binding_has_a_control`; the control of `--anchors` uses an anchor of a test
  type that verifies. Exit and `ok` never disagree in any case of this file.
- The two relation options keep B22's own promise beyond a nonzero exit: exit 2, the error
  `relation:target_verification_failed`, and the lineage label NOT_EVALUATED the relation engine sets where no
  edge names the target, in the counter-case and in the control; their controls read `lineage_ok` null.

Run against main 6b63cda8, the counter-cases and the controls of `--with-related` and `--related-pub` fail
(exit 0 with `ok` true, and no `lineage_ok` in the JSON); every other case passes there and here. The cases
of the other options are controls for this commit and the guard for options added later.

THE GUARD AT WORK. Pull request 502 landed before this file, and on main b5e15291 `decision verify` has five
options more: `--action` (step 10 of Section 3.2), `--case` and `--approval` (Section 3.3), `--consumed` and
`--received` (Section 4). The classification test named all five as unclassified. Each folds into `ok` and the
exit there (`action_bytes_ok`, `case_ok`, `consumption_ok` in `verify_decision_receipt`), and each now has its
counter-case and its control below, built as the tests of those sections build their inputs.
"""
from __future__ import annotations

import argparse
import base64
import contextlib
import copy
import hashlib
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from proofbundle import anchors, dsse
from proofbundle.cli import build_parser, main
from proofbundle.decision import _rfc8785_bytes, emit_decision_receipt
from proofbundle.emit import generate_signer

import test_decision_case_checks_of_section_3_3 as _fall1

REPO = Path(__file__).resolve().parents[1]
EXAMPLE = REPO / "examples" / "decision_receipt_allow.json"

#: The binding options of `decision verify`: option -> the result field that carries its outcome.
BINDINGS = {
    "--pub": "crypto_ok",
    "--strict": "structure_ok",
    "--policy": "policy_ok",
    "--aud": "audience_ok",
    "--nonce": "nonce_ok",
    "--anchors": "anchors_ok",
    "--with-related": "lineage_ok",
    "--related-pub": "lineage_ok",
    "--require-derived-subject": "subject_derived_ok",
    "--verification-time": "freshness_ok",
    "--action": "action_bytes_ok",
    "--case": "case_ok",
    "--approval": "case_ok",
    "--consumed": "consumption_ok",
    "--received": "consumption_ok",
}

#: The options that request no binding of their own, each with the reason.
NO_BINDING = {
    "--json": "chooses the output form only",
    "--trusted-tsa-root": "trust material for the anchors of --anchors; refused without --anchors",
    "--bitcoin-header": "trust material for the anchors of --anchors; refused without --anchors",
}

#: An anchor type of this file, registered while the cases run (as tests/test_decision_cli.py registers its own):
#: it verifies a proof that reads OK, so the control of `--anchors` has an anchor that holds without a timestamp
#: authority or a block header (the review of 9acb494a: `--anchors` had a counter-case and no control).
_TEST_ANCHOR = "b22-guard-test-anchor"


def _test_anchor_verifier(proof, canonical_root, *, frozen, now):
    return {"ok": proof == b"OK", "detail": "test anchor of the B22 guard"}


#: The fields `automation_summary` reads as references on the decision path (decision.py).
REFERENCE_FIELDS = {"evidence_bound", "audience_ok", "nonce_ok", "anchors_ok", "subject_derived_ok", "lineage_ok",
                    "action_bytes_ok", "case_ok", "consumption_ok"}


def _verify_parser() -> argparse.ArgumentParser:
    def unter(parser: argparse.ArgumentParser, name: str) -> argparse.ArgumentParser:
        for aktion in parser._actions:
            if isinstance(aktion, argparse._SubParsersAction) and name in aktion.choices:
                return aktion.choices[name]
        raise AssertionError(f"no sub-command {name!r}")
    return unter(unter(build_parser(), "decision"), "verify")


def _options(parser: argparse.ArgumentParser | None = None) -> set[str]:
    """Every optional argument of `decision verify`, by its long spelling; -h/--help is argparse's own."""
    gefunden = set()
    for aktion in (parser or _verify_parser())._actions:
        if isinstance(aktion, argparse._HelpAction) or not aktion.option_strings:
            continue
        lang = [s for s in aktion.option_strings if s.startswith("--")]
        gefunden.add(lang[0] if lang else aktion.option_strings[0])
    return gefunden


def _run(argv: list[str]) -> tuple[int, str]:
    rc, out, _err = _run_with_stderr(argv)
    return rc, out


def _run_with_stderr(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            rc = main(argv)
        except SystemExit as exc:
            rc = exc.code
    return rc, out.getvalue(), err.getvalue()


def _self_signed_pem() -> bytes:
    """A real certificate, so that `--trusted-tsa-root` is read and the refusal under test is the one reached."""
    import datetime
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.x509.oid import NameOID
    key = generate_signer()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "b22 test root")])
    start = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(start).not_valid_after(start + datetime.timedelta(days=365))
            .sign(key, None))
    return cert.public_bytes(serialization.Encoding.PEM)


class _Fixture:
    """Receipts and inputs for the cases, signed under a fresh key in a temporary directory."""

    def __init__(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.signer = generate_signer()
        self.pub = base64.b64encode(self.signer.public_key().public_bytes_raw()).decode()
        self.other_signer = generate_signer()
        self.other_pub = base64.b64encode(self.other_signer.public_key().public_bytes_raw()).decode()
        self.pred = json.loads(EXAMPLE.read_text(encoding="utf-8"))
        self.maker = self.pred["decisionMaker"]["id"]

    def write(self, name: str, obj) -> str:
        path = self.tmp / name
        path.write_text(json.dumps(obj), encoding="utf-8")
        return str(path)

    def write_bytes(self, name: str, data: bytes) -> str:
        path = self.tmp / name
        path.write_bytes(data)
        return str(path)

    def receipt(self, name: str, *, mod=None, signer=None, strict: bool = True, **kw) -> str:
        pred = copy.deepcopy(self.pred)
        if mod is not None:
            mod(pred)
        return self.write(name, emit_decision_receipt(pred, signer or self.signer, strict=strict, **kw))

    def build(self) -> None:
        self.base = self.receipt("base.json")
        self.validity = self.receipt("validity.json", mod=lambda p: p.__setitem__(
            "validity", {"audience": ["aud-1"], "nonce": "n-1", "expiresAt": "2026-01-02T00:00:00Z"}))
        # A predicate that passes the lenient rules and lacks a field the strict rules require.
        self.lenient = self.receipt("lenient.json", mod=lambda p: p.pop("notChecked"), strict=False)
        self.external_subject = self.receipt("external.json", subject_sha256="ab" * 32)
        self.by_other_key = self.receipt("by-other-key.json", signer=self.other_signer)
        self.policy_pinning_other = self.write("policy-other.json", {
            "schema": "proofbundle/trust-policy/v0.2", "policy_id": "p",
            "decision_receipt": {"trusted_decision_makers": [{"id": self.maker, "public_key_b64": self.other_pub}]}})
        self.policy_pinning_own = self.write("policy-own.json", {
            "schema": "proofbundle/trust-policy/v0.2", "policy_id": "p",
            "decision_receipt": {"trusted_decision_makers": [{"id": self.maker, "public_key_b64": self.pub}]}})
        self.broken_anchor = self.write("anchors-broken.json", [{"type": "rfc3161", "token": "AAAA"}])
        wurzel = hashlib.sha256(dsse.load_payload(json.loads(Path(self.base).read_text(encoding="utf-8")))).digest()
        self.holding_anchor = self.write("anchors-holding.json", [{
            "type": _TEST_ANCHOR, "target": "statement", "canonicalRoot": base64.b64encode(wurzel).decode(),
            "proof": base64.b64encode(b"OK").decode(), "anchoredAt": "2026-07-10T09:00:00Z"}])
        self.tsa_root = self.write_bytes("tsa-root.pem", _self_signed_pem())
        # The inputs of pull request 502, as tests/test_decision_case_checks_of_section_3_3.py and
        # tests/test_decision_consumption_state_of_section_4.py build them: a receipt for an approval, whose
        # parametersDigest names _fall1.ACTION, and a declined one, both valid at _APPROVAL_T.
        freigabe = _fall1._freigabe()
        approval_bytes = _rfc8785_bytes(freigabe)
        self.approval_receipt = self.write("approval-receipt.json",
                                           emit_decision_receipt(_fall1._entscheidung(approval_bytes), self.signer))
        self.declined_receipt = self.write("declined-receipt.json", emit_decision_receipt(
            _fall1._entscheidung(verdict="DENY", reason=("risk.boundary.exceeded",)), self.signer))
        self.action = self.write_bytes("action.bin", _fall1.ACTION)
        self.other_action = self.write_bytes("other-action.bin", b'{"merge":"pull/1"}\n')
        self.approval = self.write_bytes("approval.json", approval_bytes)
        self.other_approval = self.write_bytes("other-approval.json",
                                               _rfc8785_bytes(_fall1._freigabe(session="sess-2")))
        kennung = {k: freigabe[k] for k in ("approvalId", "actionDigest", "session")}
        self.not_consumed = self.write("consumed-empty.json", [])
        self.consumed = self.write("consumed.json", [kennung])
        self.copy_in_time = self.write("received-in-time.json", [freigabe])
        self.copy_too_early = self.write("received-too-early.json",
                                         [_fall1._freigabe(validUntil="2026-07-16T09:00:30Z")])


_IN_WINDOW = ["--verification-time", "2026-01-01T12:00:00Z"]
#: T of the approval receipts: after decidedAt, before validity.expiresAt and before validUntil of the approval.
_APPROVAL_T = ["--verification-time", "2026-07-16T09:01:00Z"]


def _counter_cases(f: _Fixture) -> dict[str, list[str]]:
    """One call per binding option that requests the binding and the binding does not hold."""
    return {
        "--pub": [f.base, "--pub", f.other_pub],
        "--strict": [f.lenient, "--pub", f.pub, "--strict"],
        "--policy": [f.base, "--pub", f.pub, "--policy", f.policy_pinning_other],
        "--aud": [f.validity, "--pub", f.pub, "--aud", "aud-2", *_IN_WINDOW],
        "--nonce": [f.validity, "--pub", f.pub, "--nonce", "n-2", *_IN_WINDOW],
        "--anchors": [f.base, "--pub", f.pub, "--anchors", f.broken_anchor],
        # The target is signed under another key than --pub, and no edge of the receipt names it.
        "--with-related": [f.base, "--pub", f.pub, "--with-related", f.by_other_key],
        # The target is signed under --pub, and the paired --related-pub names another key.
        "--related-pub": [f.base, "--pub", f.pub, "--with-related", f.validity, "--related-pub", f.other_pub],
        "--require-derived-subject": [f.external_subject, "--pub", f.pub, "--require-derived-subject"],
        "--verification-time": [f.validity, "--pub", f.pub, "--verification-time", "2026-03-01T00:00:00Z"],
        # The bytes of another action than the one parametersDigest names.
        "--action": [f.approval_receipt, "--pub", f.pub, "--strict", "--action", f.other_action, *_APPROVAL_T],
        # A receipt with the verdict ALLOW is no declined case.
        "--case": [f.approval_receipt, "--pub", f.pub, "--strict", "--case", "declined", *_APPROVAL_T],
        # An approval record whose bytes do not hash to the entry of the receipt.
        "--approval": [f.approval_receipt, "--pub", f.pub, "--strict", "--case", "approval",
                       "--approval", f.other_approval, *_APPROVAL_T],
        # The identity of the approval is in the consumption state.
        "--consumed": [f.approval_receipt, "--pub", f.pub, "--strict", "--case", "approval", "--approval", f.approval,
                       "--consumed", f.consumed, *_APPROVAL_T],
        # A received copy of the same approval whose validUntil is before T.
        "--received": [f.approval_receipt, "--pub", f.pub, "--strict", "--case", "approval", "--approval", f.approval,
                       "--consumed", f.not_consumed, "--received", f.copy_too_early, *_APPROVAL_T],
    }


def _controls(f: _Fixture) -> dict[str, list[str]]:
    """The same bindings requested where they hold."""
    return {
        "--pub": [f.base, "--pub", f.pub],
        "--strict": [f.base, "--pub", f.pub, "--strict"],
        "--policy": [f.base, "--pub", f.pub, "--policy", f.policy_pinning_own],
        "--aud": [f.validity, "--pub", f.pub, "--aud", "aud-1", *_IN_WINDOW],
        "--nonce": [f.validity, "--pub", f.pub, "--nonce", "n-1", *_IN_WINDOW],
        "--anchors": [f.base, "--pub", f.pub, "--anchors", f.holding_anchor],
        "--with-related": [f.base, "--pub", f.pub, "--with-related", f.by_other_key,
                           "--related-pub", f.other_pub],
        "--related-pub": [f.base, "--pub", f.pub, "--with-related", f.validity, "--related-pub", f.pub],
        "--require-derived-subject": [f.base, "--pub", f.pub, "--require-derived-subject"],
        "--verification-time": [f.validity, "--pub", f.pub, *_IN_WINDOW],
        "--action": [f.approval_receipt, "--pub", f.pub, "--strict", "--action", f.action, *_APPROVAL_T],
        "--case": [f.declined_receipt, "--pub", f.pub, "--strict", "--case", "declined", *_APPROVAL_T],
        "--approval": [f.approval_receipt, "--pub", f.pub, "--strict", "--case", "approval",
                       "--approval", f.approval, *_APPROVAL_T],
        "--consumed": [f.approval_receipt, "--pub", f.pub, "--strict", "--case", "approval", "--approval", f.approval,
                       "--consumed", f.not_consumed, *_APPROVAL_T],
        "--received": [f.approval_receipt, "--pub", f.pub, "--strict", "--case", "approval", "--approval", f.approval,
                       "--consumed", f.not_consumed, "--received", f.copy_in_time, *_APPROVAL_T],
    }


class TheOptionsComeFromTheParser(unittest.TestCase):

    def test_every_option_is_classified(self):
        offen = _options() - set(BINDINGS) - set(NO_BINDING)
        self.assertEqual(offen, set(), "an option of `decision verify` is neither a binding with a counter-case "
                                       "nor named as no binding with its reason")
        self.assertEqual((set(BINDINGS) | set(NO_BINDING)) - _options(), set(),
                         "a classified option no longer exists in the parser")

    def test_every_binding_has_a_counter_case(self):
        f = _Fixture()
        try:
            f.build()
            self.assertEqual(set(_counter_cases(f)), set(BINDINGS))
        finally:
            shutil.rmtree(f.tmp, ignore_errors=True)

    def test_every_binding_has_a_control(self):
        """The controls are held to BINDINGS as the counter-cases are, so a control that goes missing fails here
        (the review of 9acb494a: fourteen controls for fifteen bindings, and nothing held their number)."""
        f = _Fixture()
        try:
            f.build()
            self.assertEqual(set(_controls(f)), set(BINDINGS))
        finally:
            shutil.rmtree(f.tmp, ignore_errors=True)

    def test_control_the_classification_sees_a_new_option(self):
        """The check is no constant: an option added to the parser is seen as unclassified by the same reading."""
        parser = _verify_parser()
        parser.add_argument("--a-new-binding")
        self.assertEqual(_options(parser) - set(BINDINGS) - set(NO_BINDING), {"--a-new-binding"})

    def test_the_reference_fields_are_the_verifiers_own(self):
        """REFERENCE_FIELDS is read against every `references` list `decision.py` hands `automation_summary`, so a
        field added there without a place here fails (the lens on a1b7d468: a hand copy without a drift guard)."""
        import ast
        import proofbundle.decision as decision
        listen = []
        for knoten in ast.walk(ast.parse(Path(decision.__file__).read_text(encoding="utf-8"))):
            if isinstance(knoten, ast.Dict):
                for k, v in zip(knoten.keys, knoten.values):
                    if isinstance(k, ast.Constant) and k.value == "references" and isinstance(v, ast.List):
                        listen.append({e.value for e in v.elts if isinstance(e, ast.Constant)})
        self.assertGreaterEqual(len(listen), 2, "the references lists of decision.py were not found")
        for liste in listen:
            self.assertEqual(liste, REFERENCE_FIELDS)


class EveryRequestedBindingDecidesOk(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.f = _Fixture()
        cls.f.build()
        anchors.register_anchor_type(_TEST_ANCHOR, _test_anchor_verifier)

    @classmethod
    def tearDownClass(cls):
        anchors._VERIFIERS.pop(_TEST_ANCHOR, None)
        shutil.rmtree(cls.f.tmp, ignore_errors=True)

    def _json(self, argv: list[str]) -> tuple[int, dict]:
        rc, out = _run(["decision", "verify", *argv, "--json"])
        return rc, json.loads(out)

    def test_a_binding_that_does_not_hold_is_not_ok(self):
        for option, argv in _counter_cases(self.f).items():
            feld = BINDINGS[option]
            with self.subTest(option=option):
                rc, j = self._json(argv)
                self.assertNotEqual(rc, 0, j)
                self.assertIs(j["ok"], False, j)
                self.assertIn(feld, j, f"the outcome of {option} is not in the JSON")
                self.assertIs(j[feld], False, j)
                self.assertIs(j["automation"]["safeForAutomation"], False, j)
                if feld in REFERENCE_FIELDS:
                    self.assertIsNot(j["automation"]["referencesResolved"], True, j)

    def test_control_a_binding_that_holds_is_ok(self):
        for option, argv in _controls(self.f).items():
            feld = BINDINGS[option]
            with self.subTest(option=option):
                rc, j = self._json(argv)
                self.assertEqual(rc, 0, j)
                self.assertIs(j["ok"], True, j)
                self.assertIn(feld, j)
                if option in ("--with-related", "--related-pub"):
                    # lineage_ok stays None when nothing failed: no edge, nothing to call VERIFIED (the review of
                    # 4c37d30f: the relation controls read no value of the field at all).
                    self.assertIsNone(j[feld], j)
                else:
                    self.assertIs(j[feld], True, j)

    def test_a_related_target_that_does_not_verify_keeps_the_promise_of_b22(self):
        """B22's own promise for both relation options, beyond a nonzero exit (the review of 9acb494a: a change of
        the exit from 2 to 3 stayed green, and neither the error nor the label was read): exit 2, the error
        relation:target_verification_failed, and the lineage label as the relation engine sets it where no edge names
        the target, NOT_EVALUATED, in the counter-case and in the control (the review of 4c37d30f: comparing the two
        labels alone stayed green when both changed together)."""
        kontrollen = _controls(self.f)
        for option, argv in _counter_cases(self.f).items():
            if option not in ("--with-related", "--related-pub"):
                continue
            with self.subTest(option=option):
                rc, j = self._json(argv)
                rc_k, j_k = self._json(kontrollen[option])
                self.assertEqual(rc, 2, j)
                self.assertEqual(rc_k, 0, j_k)
                self.assertTrue(any(isinstance(e, str) and e.startswith("relation:target_verification_failed")
                                    for e in j["errors"]), j["errors"])
                self.assertFalse(any(isinstance(e, str) and e.startswith("relation:target_verification_failed")
                                     for e in j_k["errors"]), j_k["errors"])
                self.assertEqual(j["lineage"]["lineage"], "NOT_EVALUATED", j["lineage"])
                self.assertEqual(j_k["lineage"]["lineage"], "NOT_EVALUATED", j_k["lineage"])

    def test_exit_and_ok_never_disagree(self):
        for name, faelle in (("counter", _counter_cases(self.f)), ("control", _controls(self.f))):
            for option, argv in faelle.items():
                with self.subTest(case=name, option=option):
                    rc, j = self._json(argv)
                    self.assertIs(j["ok"], rc == 0, (rc, j))

    def test_trust_material_without_anchors_prints_no_ok(self):
        """The trust options request no binding of their own; without --anchors they are refused with exit 2
        and the command prints no JSON that could read as a pass. The root is a real certificate and the refusal
        is named, so the case reaches the refusal it is about (the lens on a1b7d468: a text that is no certificate
        ended at the reader of the root, before it)."""
        for argv in (["--trusted-tsa-root", self.f.tsa_root], ["--bitcoin-header", "1:" + "00" * 32]):
            with self.subTest(option=argv[0]):
                rc, out, err = _run_with_stderr(["decision", "verify", self.f.base, "--pub", self.f.pub, "--json",
                                                 *argv])
                self.assertEqual(rc, 2)
                self.assertEqual(out.strip(), "")
                self.assertIn("without --anchors", err)

    def test_a_related_pub_without_its_target_is_refused(self):
        """`--related-pub` names the key of the `--with-related` target at its position. A key without a target was
        decoded by nothing, and the verify ended with exit 0 and `ok` true (the lens on a1b7d468, the neighbour of
        B22). It is refused with exit 2 and no JSON, also a second key for one target and a key that does not decode."""
        f = self.f
        for argv in (["--related-pub", f.other_pub], ["--related-pub", "!!not base64"],
                     ["--with-related", f.validity, "--related-pub", f.pub, "--related-pub", f.other_pub]):
            with self.subTest(argv=argv):
                rc, out, err = _run_with_stderr(["decision", "verify", f.base, "--pub", f.pub, "--json", *argv])
                self.assertEqual(rc, 2)
                self.assertEqual(out.strip(), "")
                self.assertIn("--related-pub", err)


if __name__ == "__main__":
    unittest.main()
