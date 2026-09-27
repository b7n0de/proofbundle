"""A verdict, flag or ``ok`` the caller builds counts only as a bool, and only the exact True passes.

The same class as ``tests/test_a_resolver_promotes_only_on_exact_true.py``, on the other surfaces that take a
value from the caller: a field of a result the caller built, and a flag of a policy dict the caller hands in
without ``load_policy``. Each of these was read by its truth, or blocked only on the one exact value that
blocks, so a value that is not a bool passed:

- ``verifier_block.build_test_result_statement`` read a case's ``ok`` with ``not r.get("ok")``: ``"false"``,
  ``"FAIL"``, ``1`` and ``[0]`` made the case and the statement PASSED, and ``sign_test_result_statement``
  signed it. Now a case ``ok`` that is not a bool is a ``VerifierBlockError`` naming the case and the field.
- ``policy.evaluate_policy`` gated on ``result.ok``, which folds the checks by their truth, and read
  ``Check.ok`` by its truth for ``require_authenticated_root``, ``require_key_binding_when_cnf_present``,
  ``require_nonce`` and ``expected_vct``: ``Check("root-authenticity", "false")`` gave ``policy_ok`` true.
  Now crypto passes only when every check's ``ok`` is the exact True; otherwise the policy is not
  evaluated and the reason names the value that is not a bool.
- ``bundle.root_authenticity_summary`` read ``Check.ok`` by its truth and blocked on ``policy_ok``,
  ``anchor_ok``, ``public_transparency_ok`` and ``replay_ok`` only when they were the exact False and on
  ``policy_expired`` / ``policy_not_yet_valid`` only when the exact True; ``requires_identity_overlay`` and
  ``policy_warnings`` by their truth. ``automation_verdict.automation_summary`` read ``crypto`` and
  ``structure`` with ``bool(value)`` and a reference as unresolved only on the exact False. Each left
  ``safeForAutomation`` true for a string. Now a value that is not a bool never passes, and the summary
  names it in ``notBooleanInputs``.
- ``policy.evaluate_decision_policy`` and ``policy.evaluate_policy`` read the boolean policy fields by their
  truth or with ``is True``: ``allow_raw_inputs: "false"`` and ``allow_pending: "false"`` opened the gate,
  ``requiresIdentityOverlay: "true"`` let a raw template authorise, and ``require_*: 0`` switched a
  requirement off. ``load_policy`` refuses all of these. The evaluators now refuse them with the loader's
  own checker and message, for every boolean field the loader knows (derived here from ``load_policy``
  itself, not from a list), so the library path and the loader agree. ``lint_policy`` and
  ``policy_warnings`` follow the same rule.
- ``bundle.verify_bundle(expected_tree_size=)`` asked ``isinstance(expected_tree_size, int)`` and then ``==``:
  a pin whose ``__class__`` says int and whose ``__eq__`` says equal passed the tree-size check, and one whose
  ``__class__`` raised escaped. The pin is now compared only as a plain int.

The recording classes show that no method of the caller's value runs. The controls show that exact bools
and a policy that went through ``load_policy`` behave as before.
"""
from __future__ import annotations

import base64
import copy
import json
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from proofbundle import anchors, dsse
from proofbundle import policy as policy_module
from proofbundle.automation_verdict import automation_summary
from proofbundle.bundle import root_authenticity_summary, verify_bundle
from proofbundle.decision import emit_decision_receipt, verify_decision_receipt
from proofbundle.emit import generate_signer
from proofbundle.errors import Check, VerificationResult
from proofbundle.evalclaim import build_eval_claim, emit_eval_receipt, issuer_fingerprint
from proofbundle.policy import (
    PolicyError,
    evaluate_decision_policy,
    evaluate_policy,
    lint_policy,
    load_policy,
    policy_warnings,
)
from proofbundle.sdjwt_issue import issue_sd_jwt, present_with_key_binding
from proofbundle.verifier_block import (
    VerifierBlockError,
    build_test_result_statement,
    sign_test_result_statement,
)

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"
_V01 = "proofbundle/trust-policy/v0.1"
_V02 = "proofbundle/trust-policy/v0.2"
_NOT_EVALUATED = "crypto verification did not pass — policy not evaluated"


class _ClaimsBool:
    """Not a bool (``type()`` says so), but its ``__class__`` says ``bool``; ``__bool__`` answers as told."""

    def __init__(self, calls: list, answer: bool):
        self._calls, self._answer = calls, answer

    @property
    def __class__(self):
        self._calls.append("__class__")
        return bool

    def __bool__(self):
        self._calls.append("__bool__")
        return self._answer


class _SaysEmpty:
    """A warnings value that is not a list; its ``__bool__`` and ``__len__`` say it is empty."""

    def __init__(self, calls: list):
        self._calls = calls

    def __bool__(self):
        self._calls.append("__bool__")
        return False

    def __len__(self):
        self._calls.append("__len__")
        return 0


def _truthy_non_bools(calls: list):
    """Values that are not a bool and read as True, each passing somewhere at 44e12b72."""
    return [("str 'false'", "false"), ("str 'FAIL'", "FAIL"), ("int 1", 1), ("list [0]", [0]),
            ("__class__ says bool, __bool__ says True", _ClaimsBool(calls, True))]


def _eval_bundle():
    sk = generate_signer()
    claim, _ = build_eval_claim(
        suite="s", suite_version="1.0.0", metric="m", comparator=">=", threshold="0.5", score="0.9", n=10,
        model_id="a/m", dataset_id="a/d", issuer=issuer_fingerprint(sk), timestamp="2026-07-05T12:00:00Z",
        model_salt=bytes(16), dataset_salt=bytes(16))
    return emit_eval_receipt(claim, sk)


def _sd_jwt_bundle(vct: str) -> dict:
    """A bundle carrying a real key-bound SD-JWT presentation with a nonce (same construction as
    ``tests/test_trust_policy.py``), so the key-binding, nonce and vct policy checks all have a real
    crypto check to read."""
    issuer, holder = generate_signer(), generate_signer()
    ev_claim, _ = build_eval_claim(
        suite="demo-suite", suite_version="1", metric="acc", comparator=">=", threshold="0.80", score="0.9",
        n=100, model_id="m", dataset_id="d", issuer="placeholder", timestamp="2026-07-09T10:00:00Z",
        assurance_level="reproduced")
    plain = emit_eval_receipt(ev_claim, issuer)
    issuer_field = json.loads(base64.b64decode(plain["payload_b64"]))["issuer"]
    compact = issue_sd_jwt({"passed": True, "threshold": "0.80", "comparator": ">=", "suite": "demo-suite",
                            "issuer": issuer_field}, issuer, root_b64=plain["merkle"]["root_b64"],
                           exact_score="0.9",
                           holder_public_key=holder.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
                           vct=vct)
    presented = present_with_key_binding(compact, holder, aud="verifier.example", nonce="n-1", iat=1_780_000_000)
    issuer_pub = issuer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return emit_eval_receipt(ev_claim, issuer, sd_jwt={
        "compact": presented, "issuer_public_key_b64": base64.b64encode(issuer_pub).decode("ascii")})


def _with_check(result: VerificationResult, name: str, ok) -> VerificationResult:
    """The same checks, with the one named ``name`` carrying ``ok`` (appended when absent)."""
    checks = [Check(c.name, ok if c.name == name else c.ok, c.detail) for c in result.checks]
    if not any(c.name == name for c in result.checks):
        checks.append(Check(name, ok))
    return VerificationResult(checks)


# ── verifier_block ────────────────────────────────────────────────────────────────────────────────


class TestATestResultCaseOkMustBeABool(unittest.TestCase):
    _BUILD = {"digest": {"sha256": "1" * 64}, "source": "source-tree"}
    _VS = {"name": "corpus", "digest": {"sha256": "2" * 64}, "cases": 1}

    def _build(self, ok, scope="full"):
        return build_test_result_statement(build=self._BUILD, vector_set=self._VS, version="6.1.0",
                                           results=[{"caseId": "case-1", "ok": ok, "scope": scope}])

    def test_an_ok_that_is_not_a_bool_is_refused_before_anything_is_built_or_signed(self):
        calls: list = []
        values = _truthy_non_bools(calls) + [("int 0", 0), ("None", None),
                                             ("__class__ says bool, __bool__ says False", _ClaimsBool(calls, False))]
        for label, ok in values:
            with self.subTest(ok=label):
                calls.clear()
                with self.assertRaises(VerifierBlockError) as cm:
                    self._build(ok)
                self.assertIn("'case-1'", str(cm.exception))
                self.assertIn("ok is not a bool", str(cm.exception))
                self.assertEqual(calls, [], "the value's own methods ran")

    def test_control_exact_bools_build_and_sign_as_before(self):
        self.assertEqual(self._build(True)["predicate"]["result"], "PASSED")
        self.assertEqual(self._build(False)["predicate"]["failedTests"], ["case-1"])
        self.assertEqual(self._build(False)["predicate"]["result"], "FAILED")
        self.assertEqual(self._build(True, scope="partial")["predicate"]["result"], "WARNED")
        env = sign_test_result_statement(self._build(True), generate_signer())
        self.assertEqual(len(env["signatures"]), 1)


# ── policy.evaluate_policy over a caller-built crypto result ──────────────────────────────────────


class TestACallerBuiltCheckPassesTheCryptoGateOnlyAsTrue(unittest.TestCase):
    """``evaluate_policy`` evaluates a policy only when every crypto check is the exact True."""

    @classmethod
    def setUpClass(cls):
        cls.bundle = _eval_bundle()
        cls.real = verify_bundle(cls.bundle)
        cls.vct = "https://example.test/vct/mine"
        cls.sd_bundle = _sd_jwt_bundle(cls.vct)
        cls.sd_real = verify_bundle(cls.sd_bundle)

    def _sites(self):
        """(label, bundle, crypto result, check name, policy) for the four reads of ``Check.ok``."""
        return [
            ("root-authenticity under require_authenticated_root", self.bundle, self.real, "root-authenticity",
             {"merkle": {"require_authenticated_root": True}}),
            ("sd-jwt-key-binding under require_key_binding_when_cnf_present", self.sd_bundle, self.sd_real,
             "sd-jwt-key-binding", {"sd_jwt": {"require_key_binding_when_cnf_present": True}}),
            ("sd-jwt-key-binding under require_nonce", self.sd_bundle, self.sd_real, "sd-jwt-key-binding",
             {"sd_jwt": {"require_nonce": True}}),
            ("sd-jwt-issuer-signature under expected_vct", self.sd_bundle, self.sd_real, "sd-jwt-issuer-signature",
             {"sd_jwt": {"expected_vct": self.vct}}),
        ]

    def test_a_check_ok_that_is_not_a_bool_leaves_the_policy_not_evaluated_and_says_why(self):
        calls: list = []
        for site, bundle, real, name, pol in self._sites():
            for label, value in _truthy_non_bools(calls) + [
                    ("__class__ says bool, __bool__ says False", _ClaimsBool(calls, False))]:
                with self.subTest(site=site, ok=label):
                    calls.clear()
                    res = evaluate_policy(bundle, _with_check(real, name, value), copy.deepcopy(pol))
                    self.assertIsNone(res["policy_ok"])
                    self.assertIn("not a bool", res["reason"])
                    self.assertIn(f"checks[{name!r}].ok", res["reason"])
                    self.assertEqual(calls, [], "the value's own methods ran")

    def test_control_the_real_result_passes_and_the_exact_false_is_not_evaluated_as_before(self):
        for site, bundle, real, name, pol in self._sites():
            with self.subTest(site=site):
                self.assertIs(evaluate_policy(bundle, _with_check(real, name, True), copy.deepcopy(pol))["policy_ok"],
                              True)
                res = evaluate_policy(bundle, _with_check(real, name, False), copy.deepcopy(pol))
                self.assertIsNone(res["policy_ok"])
                self.assertEqual(res["reason"], _NOT_EVALUATED)


# ── bundle.verify_bundle(expected_tree_size=) ──────────────────────────────────────────────────────


class _ClaimsIntEqualToAll:
    """Not an int, but its ``__class__`` says ``int``; its ``__eq__`` says it equals anything."""

    def __init__(self, calls: list):
        self._calls = calls

    @property
    def __class__(self):
        self._calls.append("__class__")
        return int

    def __eq__(self, other):
        self._calls.append("__eq__")
        return True

    __hash__ = object.__hash__


class _ClassRaises:
    def __init__(self, calls: list):
        self._calls = calls

    @property
    def __class__(self):
        self._calls.append("__class__")
        raise RuntimeError("the caller's __class__ raised")


class TestAnExpectedTreeSizeCountsOnlyAsAPlainInt(unittest.TestCase):
    """The relying party's tree-size pin is compared only as a plain int, never by the pin's own ``__eq__``."""

    @classmethod
    def setUpClass(cls):
        cls.bundle = _eval_bundle()
        cls.size = cls.bundle["merkle"]["tree_size"]

    def _tree_size(self, expected):
        r = verify_bundle(self.bundle, expected_tree_size=expected)
        return r, next(c for c in r.checks if c.name == "tree-size")

    def test_a_pin_that_only_claims_to_be_an_int_fails_the_check_and_is_never_asked(self):
        calls: list = []
        for label, pin in (("__class__ says int, __eq__ says equal (passed)", _ClaimsIntEqualToAll(calls)),
                           ("__class__ raises (escaped)", _ClassRaises(calls))):
            with self.subTest(pin=label):
                calls.clear()
                r, check = self._tree_size(pin)
                self.assertIs(check.ok, False)
                self.assertIs(r.ok, False)
                self.assertEqual(calls, [], "the pin's own methods ran")

    def test_control_plain_ints_and_the_refused_types_behave_as_before(self):
        r, check = self._tree_size(self.size)
        self.assertIs(check.ok, True)
        self.assertIs(r.ok, True)
        for label, pin in (("wrong int", self.size + 998), ("bool True", True), ("float", float(self.size))):
            with self.subTest(pin=label):
                r, check = self._tree_size(pin)
                self.assertIs(check.ok, False)
                self.assertIs(r.ok, False)


# ── bundle.root_authenticity_summary ──────────────────────────────────────────────────────────────


_ALL_PASS = [Check("ed25519-signature", True), Check("merkle-inclusion", True), Check("root-authenticity", True)]
_SAFE_KW = {"policy_ok": True, "signer_trusted": True, "tree_context_authenticated": True}


def _summary(checks=None, **over):
    kw = dict(_SAFE_KW)
    kw.update(over)
    return root_authenticity_summary(VerificationResult(list(checks if checks is not None else _ALL_PASS)), **kw)


class TestRootAuthenticitySummaryCountsOnlyBools(unittest.TestCase):
    def test_a_check_ok_that_is_not_a_bool_fails_its_verdict_and_the_crypto_verdict(self):
        calls: list = []
        for name, field in (("ed25519-signature", "payloadSignature"), ("merkle-inclusion", "merkleConsistency"),
                            ("root-authenticity", "rootAuthenticity")):
            for label, value in _truthy_non_bools(calls):
                with self.subTest(check=name, ok=label):
                    calls.clear()
                    checks = [Check(c.name, value if c.name == name else c.ok) for c in _ALL_PASS]
                    r = _summary(checks)
                    self.assertEqual(r[field], "FAIL")
                    self.assertIs(r["safeForAutomation"], False)
                    self.assertIn("CRYPTO_FAILED", r["automationBlockers"])
                    self.assertEqual(calls, [], "the value's own methods ran")

    def test_a_gate_or_flag_that_is_not_a_bool_blocks(self):
        calls: list = []
        cases = [("policy_ok", "false", "POLICY_FAILED"), ("policy_ok", 1, "POLICY_FAILED"),
                 ("anchor_ok", "false", "ANCHOR_REQUIRED_FAILED"),
                 ("public_transparency_ok", "false", "PUBLIC_TRANSPARENCY_REQUIRED_FAILED"),
                 ("replay_ok", "false", "REPLAY_BINDING_REQUIRED_FAILED"),
                 ("policy_expired", "true", "POLICY_EXPIRED"),
                 ("policy_not_yet_valid", "true", "POLICY_NOT_YET_VALID"),
                 ("requires_identity_overlay", 0, "TEMPLATE_NOT_INSTANTIATED"),
                 ("requires_identity_overlay", _ClaimsBool(calls, False), "TEMPLATE_NOT_INSTANTIATED")]
        for kw, value, blocker in cases:
            with self.subTest(argument=kw, value=repr(value) if not isinstance(value, _ClaimsBool) else "_ClaimsBool"):
                calls.clear()
                r = _summary(**{kw: value})
                self.assertIs(r["safeForAutomation"], False)
                self.assertIn(blocker, r["automationBlockers"])
                self.assertEqual(calls, [], "the value's own methods ran")

    def test_warnings_count_as_empty_only_as_none_or_an_empty_list(self):
        calls: list = []
        r = _summary(policy_warnings=_SaysEmpty(calls))
        self.assertIn("POLICY_WARNINGS_PRESENT", r["automationBlockers"])
        self.assertEqual(calls, [], "the value's own methods ran")

    def test_the_detail_names_every_value_that_is_not_a_bool(self):
        no_root_check = [Check("ed25519-signature", True), Check("merkle-inclusion", True)]
        for kw in ("policy_ok", "anchor_ok", "signer_trusted", "policy_expired", "policy_not_yet_valid",
                   "requires_identity_overlay", "public_transparency_ok", "replay_ok", "tree_context_authenticated",
                   "policy_authenticated_root"):
            with self.subTest(argument=kw):
                # policy_authenticated_root only speaks when no root-authenticity check ran.
                r = _summary(no_root_check if kw == "policy_authenticated_root" else None, **{kw: "true"})
                self.assertIs(r["safeForAutomation"], False)
                self.assertEqual(r.get("notBooleanInputs"), [kw])
        r = _summary([Check("ed25519-signature", "false"), Check("merkle-inclusion", True)])
        self.assertEqual(r.get("notBooleanInputs"), ["checks['ed25519-signature'].ok"])

    def test_control_exact_values_give_the_verdicts_and_the_shape_they_gave_before(self):
        r = _summary()
        self.assertEqual(r, {"payloadSignature": "PASS", "merkleConsistency": "PASS", "rootAuthenticity": "PASS",
                             "rootBytesAuthenticity": "PASS", "treeContextAuthenticity": "PASS",
                             "checkpointAuthenticity": "NOT_EVALUATED", "rootTrustLevel": "ROOT_AND_TREE_SIZE_PINNED",
                             "publicTransparency": "NOT_EVALUATED", "safeForAutomation": True,
                             "automationBlockers": []})
        for kw, value, blocker in (("policy_ok", False, "POLICY_FAILED"), ("policy_ok", None, "POLICY_NOT_EVALUATED"),
                                   ("anchor_ok", False, "ANCHOR_REQUIRED_FAILED"),
                                   ("policy_expired", True, "POLICY_EXPIRED"),
                                   ("requires_identity_overlay", True, "TEMPLATE_NOT_INSTANTIATED"),
                                   ("signer_trusted", False, "SIGNER_NOT_PINNED")):
            with self.subTest(argument=kw, value=value):
                r = _summary(**{kw: value})
                self.assertIn(blocker, r["automationBlockers"])
                self.assertNotIn("notBooleanInputs", r)
        for kw, value in (("anchor_ok", True), ("policy_expired", False), ("requires_identity_overlay", False),
                          ("policy_warnings", []), ("policy_warnings", None)):
            with self.subTest(argument=kw, value=value):
                self.assertIs(_summary(**{kw: value})["safeForAutomation"], True)
        r = _summary([Check("ed25519-signature", False), Check("merkle-inclusion", True)])
        self.assertEqual(r["payloadSignature"], "FAIL")
        self.assertIn("CRYPTO_FAILED", r["automationBlockers"])


# ── automation_verdict.automation_summary ─────────────────────────────────────────────────────────


_RC = {"crypto": "crypto_ok", "structure": "structure_ok", "policy": "policy_ok", "references": ["evidence_bound"]}


def _auto(**over):
    result = {"crypto_ok": True, "structure_ok": True, "policy_ok": True, "evidence_bound": True}
    result.update(over)
    return automation_summary(result, required_checks=_RC)


class TestAutomationSummaryCountsOnlyBools(unittest.TestCase):
    def test_a_crypto_or_structure_verdict_that_is_not_a_bool_is_not_valid(self):
        calls: list = []
        for field, out, blocker in (("crypto_ok", "cryptoValid", "CRYPTO_NOT_OK"),
                                    ("structure_ok", "structureValid", "STRUCTURE_NOT_OK")):
            for label, value in _truthy_non_bools(calls):
                with self.subTest(field=field, value=label):
                    calls.clear()
                    r = _auto(**{field: value})
                    self.assertIs(r[out], False)
                    self.assertIs(r["safeForAutomation"], False)
                    self.assertIn(blocker, r["automationBlockers"])
                    self.assertEqual(calls, [], "the value's own methods ran")

    def test_a_reference_that_is_not_a_bool_is_not_resolved(self):
        calls: list = []
        for label, value in _truthy_non_bools(calls) + [("int 0", 0), ("str ''", "")]:
            with self.subTest(value=label):
                calls.clear()
                r = _auto(evidence_bound=value)
                self.assertIs(r["referencesResolved"], False)
                self.assertIn("REFERENCES_NOT_RESOLVED", r["automationBlockers"])
                self.assertIs(r["safeForAutomation"], False)
                self.assertEqual(calls, [], "the value's own methods ran")

    def test_the_detail_names_every_value_that_is_not_a_bool(self):
        r = automation_summary({"crypto_ok": "false", "structure_ok": "false", "policy_ok": "true",
                                "evidence_bound": "false", "ok": "true"}, required_checks=_RC)
        self.assertEqual(r.get("notBooleanInputs"), ["crypto_ok", "structure_ok", "policy_ok", "evidence_bound", "ok"])
        self.assertIs(r["safeForAutomation"], False)

    def test_control_exact_values_give_the_verdicts_and_the_shape_they_gave_before(self):
        self.assertEqual(_auto(), {"cryptoValid": True, "structureValid": True, "policyAuthorized": True,
                                   "referencesResolved": True, "safeForAutomation": True, "automationBlockers": []})
        r = _auto(crypto_ok=False, structure_ok=None, policy_ok=None, evidence_bound=False, ok=False)
        self.assertEqual(r, {"cryptoValid": False, "structureValid": None, "policyAuthorized": False,
                             "referencesResolved": False, "safeForAutomation": False,
                             "automationBlockers": ["CRYPTO_NOT_OK", "STRUCTURE_NOT_OK", "POLICY_NOT_EVALUATED",
                                                    "REFERENCES_NOT_RESOLVED", "RECEIPT_NOT_OK"]})
        self.assertIs(_auto(evidence_bound=None)["referencesResolved"], True)


# ── policy: a boolean field of a policy dict on the library path ──────────────────────────────────


def _loader_bool_fields():
    """Every (where, key) that ``load_policy`` refuses as "must be a boolean", found by asking it.

    Each key of each section the loader knows at all (its own closed key sets) is set to a string, and the
    loader's answer decides. No list is copied, so a boolean field added to the loader is covered here."""
    sections = [(None, policy_module._TOP_KEYS - {"schema", "policy_id"}), ("signature", policy_module._SIG_KEYS),
                ("merkle", policy_module._MERKLE_KEYS), ("sd_jwt", policy_module._SDJWT_KEYS),
                ("status", policy_module._STATUS_KEYS), ("assurance", policy_module._ASSURANCE_KEYS),
                ("anchors", policy_module._ANCHORS_KEYS), ("relations", policy_module._RELATIONS_KEYS),
                ("decision_receipt", policy_module._DECISION_KEYS)]
    found = []
    for section, keys in sections:
        where = "trust policy" if section is None else section
        for key in sorted(keys):
            pol: dict = {"schema": _V02, "policy_id": "probe"}
            if section is None:
                pol[key] = "x-not-a-bool"
            else:
                pol[section] = {key: "x-not-a-bool"}
            try:
                load_policy(pol)
            except PolicyError as exc:
                message = f"{where}.{key} must be a boolean (true/false)"
                if str(exc) == message:
                    found.append((section, key, message))
    return found


class TestTheLibraryPathRefusesAPolicyFlagThatIsNotABool(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.signer = generate_signer()
        cls.pub = cls.signer.public_key().public_bytes_raw()
        cls.tdm = [{"public_key_b64": base64.b64encode(cls.pub).decode("ascii")}]
        deny = json.loads((EXAMPLES / "decision_receipt_deny.json").read_text(encoding="utf-8"))
        cls.env = emit_decision_receipt(copy.deepcopy(deny), cls.signer, strict=True)
        raw = copy.deepcopy(deny)
        raw.setdefault("privacy", {})["rawInputsIncluded"] = True
        cls.raw_env = emit_decision_receipt(raw, cls.signer, strict=True)
        cls.bundle = _eval_bundle()
        cls.real = verify_bundle(cls.bundle)
        cls.fields = _loader_bool_fields()

    _PENDING = "test-a-caller-verdict-pending/v1"

    def setUp(self):
        anchors.register_anchor_type(self._PENDING, lambda proof, root, *, frozen, now: {
            "ok": False, "warn": True, "status": "pending"})

    def tearDown(self):
        anchors._VERIFIERS.pop(self._PENDING, None)

    def _pending_anchor(self):
        root = anchors.statement_content_root(dsse.load_payload(self.env))
        return [{"type": self._PENDING, "target": "statement", "canonicalRoot": base64.b64encode(root).decode(),
                 "proof": base64.b64encode(b"p").decode()}]

    def test_the_loader_knows_boolean_fields_in_every_section_that_has_them(self):
        # The derivation below must find something, or the per-field test would pass over nothing.
        sections = {s for s, _k, _m in self.fields}
        self.assertEqual(sections, {None, "signature", "merkle", "sd_jwt", "status", "assurance", "anchors",
                                    "relations", "decision_receipt"})

    def test_the_measured_gates_now_refuse_through_verify_decision_receipt(self):
        cases = [("allow_raw_inputs 'false' over a receipt with raw inputs", self.raw_env,
                  {"decision_receipt": {"trusted_decision_makers": self.tdm, "allow_raw_inputs": "false"}}, None,
                  "decision_receipt.allow_raw_inputs must be a boolean (true/false)"),
                 ("allow_pending 'false' over a pending anchor", self.env,
                  {"decision_receipt": {"trusted_decision_makers": self.tdm, "require_external_anchor": True,
                                        "allow_pending": "false"}}, "pending",
                  "decision_receipt.allow_pending must be a boolean (true/false)"),
                 ("requiresIdentityOverlay 'true' (a raw template)", self.env,
                  {"requiresIdentityOverlay": "true", "decision_receipt": {"trusted_decision_makers": self.tdm}}, None,
                  "trust policy.requiresIdentityOverlay must be a boolean (true/false)")]
        for label, env, pol, anchor, message in cases:
            with self.subTest(case=label):
                kw = {"anchors": self._pending_anchor()} if anchor else {}
                r = verify_decision_receipt(env, self.pub, strict=True, policy=copy.deepcopy(pol), **kw)
                self.assertIs(r["policy_ok"], False)
                self.assertIs(r["ok"], False)
                self.assertIs(r["automation"]["safeForAutomation"], False)
                self.assertTrue(any(message in e for e in r["errors"]), r["errors"])
                with self.assertRaises(PolicyError) as cm:
                    load_policy({"schema": _V02, "policy_id": "p", **copy.deepcopy(pol)})
                self.assertEqual(str(cm.exception), message)

    def test_every_boolean_field_is_refused_by_both_evaluators_with_the_loaders_message(self):
        statement = json.loads(dsse.load_payload(self.env))
        signer_b64 = base64.b64encode(self.pub).decode("ascii")
        for section, key, message in self.fields:
            for label, value in (("str 'false'", "false"), ("str 'true'", "true"), ("int 0", 0), ("int 1", 1)):
                pol: dict = {"decision_receipt": {"trusted_decision_makers": self.tdm}}
                if section is None:
                    pol[key] = value
                else:
                    pol.setdefault(section, {})[key] = value
                with self.subTest(field=f"{section}.{key}", value=label, evaluator="evaluate_decision_policy"):
                    r = evaluate_decision_policy(statement, {}, copy.deepcopy(pol), signer_public_key_b64=signer_b64)
                    self.assertIs(r["policy_ok"], False)
                    self.assertTrue(any(message in e for e in r["errors"]), r["errors"])
                with self.subTest(field=f"{section}.{key}", value=label, evaluator="evaluate_policy"):
                    r = evaluate_policy(self.bundle, self.real, copy.deepcopy(pol))
                    self.assertIs(r["policy_ok"], False)
                    self.assertIn(message, r["reason"])

    def test_a_flag_whose_class_says_bool_is_refused_and_never_asked(self):
        calls: list = []
        for label, answer in (("__bool__ says False", False), ("__bool__ says True", True)):
            with self.subTest(flag=label):
                calls.clear()
                with self.assertRaises(PolicyError):
                    load_policy({"schema": _V01, "policy_id": "p",
                                 "merkle": {"require_authenticated_root": _ClaimsBool(calls, answer)}})
                calls.clear()
                r = evaluate_policy(self.bundle, self.real,
                                    {"merkle": {"require_authenticated_root": _ClaimsBool(calls, answer)}})
                self.assertIs(r["policy_ok"], False)
                self.assertIn("merkle.require_authenticated_root must be a boolean", r["reason"])
                self.assertEqual(calls, [], "the flag's own methods ran")

    def test_lint_and_warnings_follow_the_same_rule(self):
        res = lint_policy({"schema": _V01, "policy_id": "p", "sd_jwt": {"require_nonce": "false"}})
        self.assertIs(res["ok"], False)
        self.assertIn("sd_jwt.require_nonce must be a boolean (true/false)", res["errors"])
        warned = policy_warnings({"schema": _V01, "policy_id": "p", "signature": {"require_expected_signer": "false"}})
        self.assertEqual(len(warned), 1)
        self.assertIn("attributes to nobody", warned[0])

    def test_control_a_loaded_policy_with_exact_bools_behaves_as_before(self):
        base = {"schema": _V02, "policy_id": "p"}
        r = verify_decision_receipt(self.raw_env, self.pub, strict=True, policy=load_policy(
            {**base, "decision_receipt": {"trusted_decision_makers": self.tdm, "allow_raw_inputs": True}}))
        self.assertIs(r["policy_ok"], True)
        r = verify_decision_receipt(self.raw_env, self.pub, strict=True, policy=load_policy(
            {**base, "decision_receipt": {"trusted_decision_makers": self.tdm, "allow_raw_inputs": False}}))
        self.assertIs(r["policy_ok"], False)
        self.assertTrue(any("rawInputsIncluded" in e for e in r["errors"]), r["errors"])
        pending = {**base, "decision_receipt": {"trusted_decision_makers": self.tdm, "require_external_anchor": True}}
        r = verify_decision_receipt(self.env, self.pub, strict=True, anchors=self._pending_anchor(),
                                    policy=load_policy({**pending, "decision_receipt": {
                                        **pending["decision_receipt"], "allow_pending": True}}))
        self.assertIs(r["policy_ok"], True)
        r = verify_decision_receipt(self.env, self.pub, strict=True, anchors=self._pending_anchor(),
                                    policy=load_policy({**pending, "decision_receipt": {
                                        **pending["decision_receipt"], "allow_pending": False}}))
        self.assertIs(r["policy_ok"], False)
        r = verify_decision_receipt(self.env, self.pub, strict=True, policy=load_policy(
            {**base, "requiresIdentityOverlay": True, "decision_receipt": {"trusted_decision_makers": self.tdm}}))
        self.assertIs(r["policy_ok"], False)
        self.assertTrue(any("raw template" in e for e in r["errors"]), r["errors"])
        r = verify_decision_receipt(self.env, self.pub, strict=True, policy=load_policy(
            {**base, "requiresIdentityOverlay": False, "decision_receipt": {"trusted_decision_makers": self.tdm}}))
        self.assertIs(r["policy_ok"], True)
        self.assertIs(evaluate_policy(self.bundle, self.real, load_policy(
            {"schema": _V01, "policy_id": "p", "merkle": {"require_authenticated_root": False}}))["policy_ok"], True)
        res = evaluate_policy(self.bundle, self.real, load_policy(
            {"schema": _V01, "policy_id": "p", "merkle": {"require_authenticated_root": True}}))
        self.assertIs(res["policy_ok"], False)
        self.assertIs(lint_policy(load_policy({"schema": _V01, "policy_id": "p",
                                               "sd_jwt": {"require_nonce": True}}))["ok"], True)
        self.assertEqual(policy_warnings(load_policy({"schema": _V01, "policy_id": "p",
                                                      "signature": {"require_expected_signer": True},
                                                      "allowed_issuers": [{"public_key_b64": self.tdm[0][
                                                          "public_key_b64"]}]})), [])


if __name__ == "__main__":
    unittest.main()
