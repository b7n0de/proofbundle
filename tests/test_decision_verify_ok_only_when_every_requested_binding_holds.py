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
  true. Exit and `ok` never disagree in any case of this file.

Run against main 6b63cda8, the counter-cases and the controls of `--with-related` and `--related-pub` fail
(exit 0 with `ok` true, and no `lineage_ok` in the JSON); every other case passes there and here. The cases
of the other options are controls for this commit and the guard for options added later.
"""
from __future__ import annotations

import argparse
import base64
import contextlib
import copy
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from proofbundle.cli import build_parser, main
from proofbundle.decision import emit_decision_receipt
from proofbundle.emit import generate_signer

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
}

#: The options that request no binding of their own, each with the reason.
NO_BINDING = {
    "--json": "chooses the output form only",
    "--trusted-tsa-root": "trust material for the anchors of --anchors; refused without --anchors",
    "--bitcoin-header": "trust material for the anchors of --anchors; refused without --anchors",
}

#: The fields `automation_summary` reads as references on the decision path (decision.py).
REFERENCE_FIELDS = {"evidence_bound", "audience_ok", "nonce_ok", "anchors_ok", "subject_derived_ok", "lineage_ok"}


def _verify_parser() -> argparse.ArgumentParser:
    def unter(parser: argparse.ArgumentParser, name: str) -> argparse.ArgumentParser:
        for aktion in parser._actions:
            if isinstance(aktion, argparse._SubParsersAction) and name in aktion.choices:
                return aktion.choices[name]
        raise AssertionError(f"no sub-command {name!r}")
    return unter(unter(build_parser(), "decision"), "verify")


def _options() -> set[str]:
    """Every optional argument of `decision verify`, by its long spelling; -h/--help is argparse's own."""
    gefunden = set()
    for aktion in _verify_parser()._actions:
        if isinstance(aktion, argparse._HelpAction) or not aktion.option_strings:
            continue
        lang = [s for s in aktion.option_strings if s.startswith("--")]
        gefunden.add(lang[0] if lang else aktion.option_strings[0])
    return gefunden


def _run(argv: list[str]) -> tuple[int, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            rc = main(argv)
        except SystemExit as exc:
            rc = exc.code
    return rc, out.getvalue()


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
        self.tsa_root = self.write("tsa-root.pem", "not a certificate")


_IN_WINDOW = ["--verification-time", "2026-01-01T12:00:00Z"]


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
    }


def _controls(f: _Fixture) -> dict[str, list[str]]:
    """The same bindings requested where they hold."""
    return {
        "--pub": [f.base, "--pub", f.pub],
        "--strict": [f.base, "--pub", f.pub, "--strict"],
        "--policy": [f.base, "--pub", f.pub, "--policy", f.policy_pinning_own],
        "--aud": [f.validity, "--pub", f.pub, "--aud", "aud-1", *_IN_WINDOW],
        "--nonce": [f.validity, "--pub", f.pub, "--nonce", "n-1", *_IN_WINDOW],
        "--with-related": [f.base, "--pub", f.pub, "--with-related", f.by_other_key,
                           "--related-pub", f.other_pub],
        "--related-pub": [f.base, "--pub", f.pub, "--with-related", f.validity, "--related-pub", f.pub],
        "--require-derived-subject": [f.base, "--pub", f.pub, "--require-derived-subject"],
        "--verification-time": [f.validity, "--pub", f.pub, *_IN_WINDOW],
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

    def test_control_the_classification_sees_a_new_option(self):
        """The check is no constant: an option added to the parser is seen as unclassified."""
        parser = _verify_parser()
        parser.add_argument("--a-new-binding")
        neu = set()
        for aktion in parser._actions:
            neu.update(s for s in aktion.option_strings if s.startswith("--"))
        self.assertIn("--a-new-binding", neu - set(BINDINGS) - set(NO_BINDING) - {"--help"})


class EveryRequestedBindingDecidesOk(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.f = _Fixture()
        cls.f.build()

    @classmethod
    def tearDownClass(cls):
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
                if option not in ("--with-related", "--related-pub"):
                    # lineage_ok stays None when nothing failed: no edge, nothing to call VERIFIED.
                    self.assertIs(j[feld], True, j)

    def test_exit_and_ok_never_disagree(self):
        for name, faelle in (("counter", _counter_cases(self.f)), ("control", _controls(self.f))):
            for option, argv in faelle.items():
                with self.subTest(case=name, option=option):
                    rc, j = self._json(argv)
                    self.assertIs(j["ok"], rc == 0, (rc, j))

    def test_trust_material_without_anchors_prints_no_ok(self):
        """The trust options request no binding of their own; without --anchors they are refused with exit 2
        and the command prints no JSON that could read as a pass."""
        for argv in (["--trusted-tsa-root", self.f.tsa_root], ["--bitcoin-header", "1:" + "00" * 32]):
            with self.subTest(option=argv[0]):
                rc, out = _run(["decision", "verify", self.f.base, "--pub", self.f.pub, "--json", *argv])
                self.assertEqual(rc, 2)
                self.assertEqual(out.strip(), "")


if __name__ == "__main__":
    unittest.main()
