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

Round 3, the siblings the sweep over the whole package found:

- Permissive keyword flags (a truthy value relaxes a check) read by their truth:
  ``anchors.verify_anchors(allow_pending=)``, ``hashalg.resolve_hash_alg(allow_deprecated=)``,
  ``renewal.verify_sequence(allow_unauthenticated_anchor=)``, ``trust_pack.verify_trust_pack(
  allow_unverified_rotation=)``, ``hf_evals.to_eval_results_entry(allow_value_mismatch=)`` and
  ``agent_review.render_disclosure_line(leaf_witnessed=)``. ``"false"`` relaxed each of them. A function that
  raises a typed error for a malformed argument now raises it for a flag that is not a bool; the two
  never-raise verifiers keep the check and say in their detail that the flag is not a bool.
- ``_membership.is_bool``, ``policy``-style boolean validators in ``sdjwt_vc`` and ``public_transparency``,
  and ``errors.VerificationResult.ok`` believed ``__class__`` or read ``Check.ok`` by its truth.
- Str verdicts compared through the caller's own ``__eq__``: a test case's ``scope``,
  ``root_authenticity_summary(checkpoint_authenticity=)``, ``evaluate_decision_policy(anchor_status=)``,
  ``agent_review.evaluate_time_policy``'s axis state, and the ``resolution``, ``relation``,
  ``targetDigest`` and ``supersededByAttached`` of a lineage result in ``relation.evaluate_relations_policy``
  (which now also refuses a non-bool ``reject_superseded`` / ``reject_retracted`` with the loader's message).

Round 4, answering a review of 3a8074fc. Three switches still read their value by its truth:
``assurance.classify_digest_evidence(applicable=)`` (in the resolver contract file),
``adapters._provenance.bind_reported_version(bound=)`` (``"false"`` wrote a signed ``reported`` status) and
``agent_review.emit_agent_review(legacy_v01=)`` (``"false"`` issued a v0.1 predicate that ``False`` refuses).
The class is closed for every switch at once: a switch whose one side weakens a verdict or a check, or changes
what is signed or published, goes through ``_membership.require_switch``, and a value that is not an exact bool
is a ``SwitchTypeError``, a ``TypeError`` and a ``ProofBundleError`` whose message names the parameter and the
type. The round-3 refusals, which raised each module's own error without the type, raise it too. The sweep at
the end of this file discovers every bool keyword of the public API at run time and holds each one to its
class, so a new switch cannot enter unclassified.

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

from proofbundle import _membership, anchors, dsse, hashalg, public_transparency, relation, sdjwt_vc
from proofbundle import agent_review as ar
from proofbundle import policy as policy_module
from proofbundle.automation_verdict import automation_summary
from proofbundle.bundle import root_authenticity_summary, verify_bundle
from proofbundle.decision import emit_decision_receipt, verify_decision_receipt
from proofbundle.emit import generate_signer
from proofbundle.errors import Check, ProofBundleError, VerificationResult
from proofbundle.evalclaim import build_eval_claim, emit_eval_receipt, issuer_fingerprint
from proofbundle.hf_evals import to_eval_results_entry
from proofbundle.policy import (
    PolicyError,
    evaluate_decision_policy,
    evaluate_policy,
    lint_policy,
    load_policy,
    policy_warnings,
)
from proofbundle.renewal import build_initial_sequence, verify_sequence
from proofbundle.sdjwt_issue import issue_sd_jwt, present_with_key_binding
from proofbundle.trust_pack import sign_trust_pack, verify_trust_pack
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


# ── round 3: permissive keyword flags, the __class__ checks, and str verdicts ─────────────────────


class _ClaimsStr:
    """Not a str, but its ``__class__`` says ``str``; it equals (and hashes like) ``target`` and nothing else."""

    def __init__(self, calls: list, target: str):
        self._calls, self._target = calls, target

    @property
    def __class__(self):
        self._calls.append("__class__")
        return str

    def __eq__(self, other):
        self._calls.append("__eq__")
        return type(other) is str and other == self._target

    def __ne__(self, other):
        self._calls.append("__ne__")
        return not (type(other) is str and other == self._target)

    def __hash__(self):
        self._calls.append("__hash__")
        return hash(self._target)


class _StrSubclass(str):
    """A real str subclass; its own ``__eq__`` records itself."""

    calls: list = []

    def __eq__(self, other):
        _StrSubclass.calls.append("__eq__")
        return str.__eq__(self, other)

    __hash__ = str.__hash__


def _flag_values(calls: list):
    """Flags that are not a bool, each of which relaxed a check at 67bb104e (all but the last are truthy)."""
    return [("str 'false'", "false"), ("int 1", 1), ("list [0]", [0]),
            ("__class__ says bool, __bool__ says True", _ClaimsBool(calls, True))]


def _assert_refused_as_a_switch(test: unittest.TestCase, cm, name: str, value) -> None:
    """The refusal of a switch (round 4): ``SwitchTypeError``, a TypeError and a ProofBundleError, whose message
    names the parameter and the type of the value (the test's own ``type(value).__name__``)."""
    exc = cm.exception
    test.assertIsInstance(exc, TypeError)
    test.assertIsInstance(exc, ProofBundleError)
    test.assertIn(f"{name} must be a bool", str(exc))
    test.assertIn(f"not a value of type {type(value).__name__}", str(exc))


_STATEMENT_ROOT_PENDING = "test-a-caller-verdict-pending-r3/v1"


class TestAPermissiveFlagRelaxesOnlyAsTrue(unittest.TestCase):
    """A keyword flag whose truthy value relaxes a check relaxes it only as the exact True."""

    @classmethod
    def setUpClass(cls):
        cls.signer = generate_signer()
        env = emit_decision_receipt(copy.deepcopy(json.loads(
            (EXAMPLES / "decision_receipt_deny.json").read_text(encoding="utf-8"))), cls.signer, strict=True)
        cls.root = anchors.statement_content_root(dsse.load_payload(env))
        cls.bundle = _eval_bundle()

    def setUp(self):
        anchors.register_anchor_type(_STATEMENT_ROOT_PENDING, lambda proof, root, *, frozen, now: {
            "ok": False, "warn": True, "status": "pending"})

    def tearDown(self):
        anchors._VERIFIERS.pop(_STATEMENT_ROOT_PENDING, None)

    def _pending(self, allow_pending):
        a = {"type": _STATEMENT_ROOT_PENDING, "target": "statement",
             "canonicalRoot": base64.b64encode(self.root).decode(), "proof": base64.b64encode(b"p").decode()}
        return anchors.verify_anchors([a], target_roots={"statement": self.root}, require="any",
                                      allow_pending=allow_pending)

    def test_verify_anchors_refuses_an_allow_pending_that_is_not_a_bool(self):
        calls: list = []
        for label, value in _flag_values(calls):
            with self.subTest(allow_pending=label):
                calls.clear()
                with self.assertRaises(TypeError) as cm:
                    self._pending(value)
                _assert_refused_as_a_switch(self, cm, "allow_pending", value)
                self.assertEqual(calls, [], "the flag's own methods ran")

    def test_resolve_hash_alg_refuses_an_allow_deprecated_that_is_not_a_bool(self):
        calls: list = []
        for label, value in _flag_values(calls):
            for name, call in (("resolve_hash_alg", lambda v: hashalg.resolve_hash_alg("sha1", allow_deprecated=v)),
                               ("compute_digest", lambda v: hashalg.compute_digest(b"x", "sha1",
                                                                                   allow_deprecated=v))):
                with self.subTest(surface=name, allow_deprecated=label):
                    calls.clear()
                    with self.assertRaises(TypeError) as cm:
                        call(value)
                    _assert_refused_as_a_switch(self, cm, "allow_deprecated", value)
                    self.assertEqual(calls, [], "the flag's own methods ran")

    def test_verify_sequence_keeps_the_anchor_check_for_a_flag_that_is_not_a_bool(self):
        data = [_sha("a"), _sha("b")]
        seq = build_initial_sequence(data, hash_alg="sha256", time=1000)
        calls: list = []
        for label, value in _flag_values(calls):
            with self.subTest(allow_unauthenticated_anchor=label):
                calls.clear()
                r = verify_sequence(seq, data, allow_unauthenticated_anchor=value)
                last = next(c for c in r.checks if c.name == "renewal:last_anchor")
                self.assertIs(last.ok, False)
                self.assertIs(r.ok, False)
                self.assertIn(f"not a bool (a value of type {type(value).__name__})", last.detail)
                self.assertEqual(calls, [], "the flag's own methods ran")

    def test_verify_trust_pack_keeps_the_rotation_check_for_a_flag_that_is_not_a_bool(self):
        env, now = _rotation_pack()
        calls: list = []
        for label, value in _flag_values(calls):
            with self.subTest(allow_unverified_rotation=label):
                calls.clear()
                r = verify_trust_pack(env, strict=True, now=now, allow_unverified_rotation=value)
                self.assertIs(r["ok"], False)
                self.assertIs(r["rotation_authorized"], False)
                self.assertTrue(any(f"not a bool (a value of type {type(value).__name__})" in e
                                    for e in r["errors"]), r["errors"])
                self.assertEqual(calls, [], "the flag's own methods ran")

    def test_to_eval_results_entry_refuses_an_allow_value_mismatch_that_is_not_a_bool(self):
        calls: list = []
        for label, value in _flag_values(calls):
            with self.subTest(allow_value_mismatch=label):
                calls.clear()
                with self.assertRaises(TypeError) as cm:
                    to_eval_results_entry(self.bundle, dataset_id="d", task_id="t", value=0.1,
                                          allow_value_mismatch=value)
                _assert_refused_as_a_switch(self, cm, "allow_value_mismatch", value)
                self.assertEqual(calls, [], "the flag's own methods ran")

    def test_render_disclosure_line_refuses_a_leaf_witnessed_that_is_not_a_bool(self):
        calls: list = []
        predicate = _v02_predicate()
        for label, value in _flag_values(calls):
            with self.subTest(leaf_witnessed=label):
                calls.clear()
                with self.assertRaises(TypeError) as cm:
                    ar.render_disclosure_line(predicate, receipt_digest="0" * 64, receipt_url="https://x.invalid/r",
                                              leaf_url="https://x.invalid/leaf", leaf_witnessed=value)
                _assert_refused_as_a_switch(self, cm, "leaf_witnessed", value)
                self.assertEqual(calls, [], "the flag's own methods ran")

    def test_control_exact_flags_behave_as_before(self):
        self.assertIs(self._pending(True)["require_met"], True)
        self.assertIs(self._pending(False)["require_met"], False)
        self.assertEqual(hashalg.resolve_hash_alg("sha1", allow_deprecated=True).id, "sha1")
        with self.assertRaises(hashalg.DeprecatedHashAlg):
            hashalg.resolve_hash_alg("sha1", allow_deprecated=False)
        self.assertEqual(hashalg.resolve_hash_alg("sha256").id, "sha256")
        data = [_sha("a"), _sha("b")]
        seq = build_initial_sequence(data, hash_alg="sha256", time=1000)
        self.assertIs(verify_sequence(seq, data, allow_unauthenticated_anchor=True).ok, True)
        r = verify_sequence(seq, data, allow_unauthenticated_anchor=False)
        self.assertIs(r.ok, False)
        self.assertNotIn("not a bool", next(c for c in r.checks if c.name == "renewal:last_anchor").detail)
        env, now = _rotation_pack()
        r = verify_trust_pack(env, strict=True, now=now, allow_unverified_rotation=True)
        self.assertIs(r["ok"], True, r["errors"])
        r = verify_trust_pack(env, strict=True, now=now, allow_unverified_rotation=False)
        self.assertIs(r["ok"], False)
        self.assertFalse(any("not a bool" in e for e in r["errors"]))
        self.assertIn("verifyToken", to_eval_results_entry(self.bundle, dataset_id="d", task_id="t", value=0.1,
                                                           allow_value_mismatch=True))
        with self.assertRaises(anchors.BundleFormatError) as cm:
            to_eval_results_entry(self.bundle, dataset_id="d", task_id="t", value=0.1, allow_value_mismatch=False)
        self.assertIn("inconsistent", str(cm.exception))
        line = ar.render_disclosure_line(_v02_predicate(), receipt_digest="0" * 64, receipt_url="https://x.invalid/r",
                                         leaf_url="https://x.invalid/leaf", leaf_witnessed=False)
        self.assertIn("not yet in a witnessed checkpoint", line)
        line = ar.render_disclosure_line(_v02_predicate(), receipt_digest="0" * 64, receipt_url="https://x.invalid/r",
                                         leaf_url="https://x.invalid/leaf", leaf_witnessed=True)
        self.assertNotIn("not yet in a witnessed checkpoint", line)


def _sha(text: str) -> str:
    import hashlib  # noqa: PLC0415
    return hashlib.sha256(text.encode()).hexdigest()


def _rotation_pack():
    """A pack that claims to be a rotation (prevVersionDigest set), signed by its own root only."""
    from datetime import datetime, timezone  # noqa: PLC0415
    sk = generate_signer()
    tp = {"schemaVersion": "0.1.0", "trustPackId": "tp-r3", "version": 4, "expires": "2027-01-01T00:00:00Z",
          "prevVersionDigest": {"sha256": "a" * 64},
          "roles": {"root": {"keyIds": ["new-0"], "threshold": 1}},
          "keys": {"new-0": {"publicKey": base64.b64encode(sk.public_key().public_bytes_raw()).decode(),
                             "scheme": "ed25519"}},
          "nonClaims": ["round 3 test pack"]}
    return sign_trust_pack(tp, {"new-0": sk}), datetime(2026, 7, 14, 12, 0, 0, tzinfo=timezone.utc)


def _v02_predicate() -> dict:
    korpus = Path(__file__).resolve().parent.parent / "conformance" / "agent_review"
    env = json.loads((korpus / "agent-review-v02-positive-control-current-v02-is-marked-current" / "envelope.json")
                     .read_text(encoding="utf-8"))
    return json.loads(base64.b64decode(env["payload"], validate=True))["predicate"]


class TestATypeCheckDoesNotBelieveTheClass(unittest.TestCase):
    """``is_bool``, the boolean policy validators and ``VerificationResult.ok`` read a bool only as a bool."""

    def test_is_bool_is_false_for_an_object_that_only_claims_to_be_a_bool(self):
        calls: list = []
        for label, value in (("__class__ says bool", _ClaimsBool(calls, True)), ("__class__ raises",
                                                                                 _ClassRaises(calls))):
            with self.subTest(value=label):
                calls.clear()
                self.assertIs(_membership.is_bool(value), False)
                self.assertEqual(calls, [], "the value's own methods ran")

    def test_the_boolean_policy_validators_refuse_an_object_that_only_claims_to_be_a_bool(self):
        calls: list = []
        for name, validate, pol in (
                ("sdjwt_vc.validate_vc_policy requireKeyBinding", sdjwt_vc.validate_vc_policy,
                 lambda v: {"vctAllowlist": ["x"], "requireKeyBinding": v}),
                ("public_transparency requireSignedCheckpoint",
                 public_transparency.validate_public_transparency_policy,
                 lambda v: {"requireSignedCheckpoint": v})):
            with self.subTest(validator=name):
                calls.clear()
                errors = validate(pol(_ClaimsBool(calls, False)))
                self.assertTrue(any("must be a boolean" in e for e in errors), errors)
                self.assertEqual(calls, [], "the value's own methods ran")

    def test_verification_result_ok_counts_a_check_only_as_true(self):
        calls: list = []
        for label, value in (("str 'false'", "false"), ("int 1", 1), ("list [0]", [0]),
                             ("__class__ says bool, __bool__ says True", _ClaimsBool(calls, True))):
            with self.subTest(ok=label):
                calls.clear()
                self.assertIs(VerificationResult([Check("x", True), Check("y", value)]).ok, False)
                self.assertEqual(calls, [], "the value's own methods ran")

    def test_control_real_bools_are_read_as_before(self):
        self.assertIs(_membership.is_bool(True), True)
        self.assertIs(_membership.is_bool(False), True)
        self.assertIs(_membership.is_bool(1), False)
        self.assertEqual(sdjwt_vc.validate_vc_policy({"vctAllowlist": ["x"], "requireKeyBinding": False}), [])
        self.assertEqual(public_transparency.validate_public_transparency_policy({"requireSignedCheckpoint": True}),
                         [])
        self.assertIs(VerificationResult([Check("x", True), Check("y", True)]).ok, True)
        self.assertIs(VerificationResult([Check("x", True), Check("y", False)]).ok, False)
        self.assertIs(VerificationResult([]).ok, False)


class TestAStrVerdictIsReadOnlyAsAPlainStr(unittest.TestCase):
    """A str verdict the caller supplies is compared only as a plain str, never by its own ``__eq__``."""

    _BUILD = {"digest": {"sha256": "1" * 64}, "source": "source-tree"}
    _VS = {"name": "corpus", "digest": {"sha256": "2" * 64}, "cases": 1}

    def _scope(self, scope):
        return build_test_result_statement(build=self._BUILD, vector_set=self._VS, version="6.1.0",
                                           results=[{"caseId": "c1", "ok": True, "scope": scope}])["predicate"]

    def test_a_scope_that_only_claims_to_be_full_is_warned(self):
        calls: list = []
        _StrSubclass.calls = []
        for label, scope in (("__class__ says str, equals 'full'", _ClaimsStr(calls, "full")),
                             ("str subclass 'full'", _StrSubclass("full"))):
            with self.subTest(scope=label):
                calls.clear()
                pred = self._scope(scope)
                self.assertEqual(pred["result"], "WARNED")
                self.assertEqual(pred["warnedTests"], ["c1"])
                self.assertEqual(calls, [], "the value's own methods ran")
        self.assertEqual(_StrSubclass.calls, [], "the subclass's own __eq__ ran")

    def test_a_checkpoint_authenticity_that_only_claims_to_be_pass_is_not_evaluated(self):
        calls: list = []
        r = _summary(checkpoint_authenticity=_ClaimsStr(calls, "PASS"))
        self.assertEqual(r["checkpointAuthenticity"], "NOT_EVALUATED")
        self.assertNotEqual(r["rootTrustLevel"], "CHECKPOINT")
        self.assertEqual(calls, [], "the value's own methods ran")

    def test_an_anchor_status_that_only_claims_to_be_pass_does_not_satisfy_the_requirement(self):
        signer = generate_signer()
        pub = signer.public_key().public_bytes_raw()
        env = emit_decision_receipt(copy.deepcopy(json.loads(
            (EXAMPLES / "decision_receipt_deny.json").read_text(encoding="utf-8"))), signer, strict=True)
        statement = json.loads(dsse.load_payload(env))
        pol = {"decision_receipt": {"trusted_decision_makers": [{"public_key_b64": base64.b64encode(pub).decode()}],
                                    "require_external_anchor": True, "allow_pending": True}}
        calls: list = []
        for label, status in (("__class__ says str, equals 'PASS'", _ClaimsStr(calls, "PASS")),
                              ("__class__ says str, equals 'WARN'", _ClaimsStr(calls, "WARN"))):
            with self.subTest(anchor_status=label):
                calls.clear()
                r = evaluate_decision_policy(statement, {}, copy.deepcopy(pol),
                                             signer_public_key_b64=base64.b64encode(pub).decode(),
                                             anchor_status=status)
                self.assertIs(r["policy_ok"], False)
                self.assertEqual(calls, [], "the value's own methods ran")
        for status, want in (("PASS", True), ("WARN", True), ("FAIL", False), (None, False)):
            with self.subTest(control=status):
                r = evaluate_decision_policy(statement, {}, copy.deepcopy(pol),
                                             signer_public_key_b64=base64.b64encode(pub).decode(),
                                             anchor_status=status)
                self.assertIs(r["policy_ok"], want, r["errors"])

    def test_a_time_axis_state_that_only_claims_to_be_observed_is_not_accepted(self):
        calls: list = []
        r = ar.evaluate_time_policy({"event_time_status": _ClaimsStr(calls, "RUNNER_OBSERVED")},
                                    {"kind": "freshness"})
        self.assertEqual(r["decision"], "insufficient_evidence")
        self.assertEqual(calls, [], "the value's own methods ran")
        self.assertEqual(ar.evaluate_time_policy({"event_time_status": "RUNNER_OBSERVED"}, {"kind": "freshness"})
                         ["decision"], "accept")
        self.assertEqual(ar.evaluate_time_policy({"event_time_status": "CONFLICT"}, {"kind": "freshness"})
                         ["decision"], "reject")

    def test_control_plain_str_verdicts_behave_as_before(self):
        self.assertEqual(self._scope("full")["result"], "PASSED")
        self.assertEqual(self._scope("partial")["result"], "WARNED")
        r = _summary(checkpoint_authenticity="PASS")
        self.assertEqual((r["checkpointAuthenticity"], r["rootTrustLevel"]), ("PASS", "CHECKPOINT"))
        self.assertEqual(_summary(checkpoint_authenticity="FAIL")["checkpointAuthenticity"], "FAIL")


_KEY = base64.b64encode(b"\x07" * 32).decode()


class TestTheRelationsEvaluatorReadsALineageResultOnlyAsPlainValues(unittest.TestCase):
    """``relation.evaluate_relations_policy`` over a caller-built lineage result."""

    def _viol(self, section, lineage, key=_KEY):
        return relation.evaluate_relations_policy(section, lineage, successor_key_b64=key)

    def test_a_resolution_that_only_claims_to_be_verified_does_not_meet_a_requirement(self):
        calls: list = []
        lineage = {"edges": [{"relation": "supersedes", "resolution": _ClaimsStr(calls, "VERIFIED"),
                              "targetDigest": "a" * 64}]}
        v = self._viol({"require_relation_resolution": ["supersedes"]}, lineage)
        self.assertEqual([x["code"] for x in v], ["LINEAGE_REQUIREMENT_FAILED"])
        self.assertEqual(calls, [], "the value's own methods ran")

    def test_a_same_key_check_is_not_skipped_by_a_resolution_that_only_claims_not_to_be_verified(self):
        calls: list = []
        lineage = {"edges": [{"relation": "supersedes", "resolution": _ClaimsStr(calls, "DECLARED_UNRESOLVED"),
                              "targetDigest": "a" * 64, "verified_under": None}]}
        v = self._viol({"relation_signer": {"supersedes": {"mode": "same-key"}}}, lineage)
        self.assertEqual([x["code"] for x in v], ["RELATION_SIGNER_UNAUTHORIZED"])
        self.assertEqual(calls, [], "the value's own methods ran")

    def test_a_target_digest_that_only_claims_to_be_the_pinned_root_is_a_mismatch(self):
        calls: list = []
        lineage = {"edges": [{"relation": "supersedes", "resolution": "VERIFIED",
                              "targetDigest": _ClaimsStr(calls, "b" * 64)}]}
        v = self._viol({"require_relation_target": {"supersedes": "b" * 64}}, lineage)
        self.assertEqual([x["code"] for x in v], ["RELATION_TARGET_MISMATCH"])
        self.assertEqual(calls, [], "the value's own methods ran")

    def test_a_supersession_whose_own_bool_says_false_is_still_a_supersession(self):
        calls: list = []
        v = self._viol({"reject_superseded": True}, {"edges": [], "supersededByAttached": _SaysEmpty(calls)})
        self.assertEqual([x["code"] for x in v], ["LINEAGE_REQUIREMENT_FAILED"])
        self.assertEqual(calls, [], "the value's own methods ran")

    def test_a_reject_flag_that_is_not_a_bool_is_refused_with_the_loaders_message(self):
        for flag in ("reject_superseded", "reject_retracted"):
            for label, value in (("str 'false'", "false"), ("int 0", 0)):
                with self.subTest(flag=flag, value=label):
                    v = self._viol({flag: value}, {"edges": [], "supersededByAttached": None})
                    self.assertEqual(len(v), 1, v)
                    self.assertIn(f"relations.{flag} must be a boolean (true/false)", v[0]["message"])

    def test_control_plain_lineage_values_behave_as_before(self):
        verified = {"relation": "supersedes", "resolution": "VERIFIED", "targetDigest": "b" * 64,
                    "verified_under": _KEY}
        self.assertEqual(self._viol({"require_relation_resolution": ["supersedes"]}, {"edges": [verified]}), [])
        unresolved = dict(verified, resolution="DECLARED_UNRESOLVED")
        self.assertEqual([x["code"] for x in self._viol({"require_relation_resolution": ["supersedes"]},
                                                        {"edges": [unresolved]})], ["LINEAGE_REQUIREMENT_FAILED"])
        self.assertEqual(self._viol({"relation_signer": {"supersedes": {"mode": "same-key"}}},
                                    {"edges": [verified]}), [])
        self.assertEqual(self._viol({"relation_signer": {"supersedes": {"mode": "same-key"}}},
                                    {"edges": [unresolved]}), [])
        self.assertEqual(self._viol({"require_relation_target": {"supersedes": "b" * 64}}, {"edges": [verified]}),
                         [])
        self.assertEqual([x["code"] for x in self._viol({"reject_superseded": True},
                                                        {"edges": [], "supersededByAttached": "by X"})],
                         ["LINEAGE_REQUIREMENT_FAILED"])
        self.assertEqual(self._viol({"reject_superseded": True}, {"edges": [], "supersededByAttached": None}), [])
        self.assertEqual(self._viol({"reject_superseded": False}, {"edges": [], "supersededByAttached": "by X"}),
                         [])


# ── round 4: every switch of the public API, by its class ─────────────────────────────────────────


def _v01_predicate() -> dict:
    """A v0.1-shaped agent-review predicate: valid under the v0.1 rules, refused by the v0.2 rules (no
    ``disclosureCoreDigest``)."""
    body = "# T\n\nText.\n"
    findings = [{"id": "F1", "severity": "low", "title": "t", "disposition": "dismissed", "reason": "r"}]
    return {
        "schemaVersion": "0.1.0", "reviewId": "r",
        "subjectContext": {"kind": "githubPullRequest", "forge": "github.com", "repositoryId": "R",
                           "pullRequestNodeId": "PR", "headSha": "a" * 40, "baseSha": "b" * 40,
                           "reviewedDiffDigest": "c" * 64, "bodyCoreDigest": ar.body_core_digest(body)},
        "declaration": {"authoring": [{"assurance": "selfDeclared", "assertedBy": "x"}], "reviewRuns": [],
                        "findings": findings, "findingsTotal": 1, "findingsRoot": ar.findings_root(findings),
                        "nonClaims": ["n"]},
        "coverage": {"status": "UNKNOWN"}, "times": {"declaredAt": "2026-08-31T17:00:00Z"}, "limitations": ["l"],
    }


def _not_bools(calls: list, *, none_allowed: bool = False):
    """The values a switch is asked with that are not a bool (the review's sweep set, plus None and an object
    whose ``__class__`` says bool)."""
    values = [("str 'false'", "false"), ("str 'no'", "no"), ("int 1", 1), ("int 0", 0), ("list [0]", [0]),
              ("str ''", ""), ("__class__ says bool, __bool__ says True", _ClaimsBool(calls, True)),
              ("__class__ says bool, __bool__ says False", _ClaimsBool(calls, False))]
    if not none_allowed:
        values.append(("None", None))
    return values


class TestABoundVersionIsWrittenOnlyForABool(unittest.TestCase):
    """N2 (review of 3a8074fc): ``bind_reported_version`` read ``bound`` by its truth, so ``"false"``, ``"no"``,
    ``1`` and ``[0]`` wrote the version with status ``reported`` into a provenance block that is signed into
    the receipt, where ``bound=False`` writes ``not_bound`` with its reason."""

    def test_a_bound_that_is_not_a_bool_is_refused_before_the_block_is_touched(self):
        from proofbundle.adapters._provenance import bind_reported_version  # noqa: PLC0415
        calls: list = []
        for label, value in _not_bools(calls):
            with self.subTest(bound=label):
                calls.clear()
                block: dict = {"harness_version": "0.1.0", "harness_version_status": "reported"}
                with self.assertRaises(TypeError) as cm:
                    bind_reported_version(block, "harness_version", "0.3.1", reason="r", bound=value)
                _assert_refused_as_a_switch(self, cm, "bound", value)
                self.assertEqual(block, {"harness_version": "0.1.0", "harness_version_status": "reported"})
                self.assertEqual(calls, [], "the switch's own methods ran")

    def test_control_exact_bools_write_as_before(self):
        from proofbundle.adapters._provenance import bind_reported_version  # noqa: PLC0415
        self.assertEqual(bind_reported_version({}, "harness_version", "0.3.1", reason="r", bound=True),
                         {"harness_version": "0.3.1", "harness_version_status": "reported"})
        self.assertEqual(bind_reported_version({}, "harness_version", "0.3.1", reason="r", bound=False),
                         {"harness_version_status": "not_bound", "harness_version_status_reason": "r"})
        self.assertEqual(bind_reported_version({}, "harness_version", None, reason="r"),
                         {"harness_version_status": "not_reported", "harness_version_status_reason": "r"})


class TestTheLegacyRuleSetIsChosenOnlyByABool(unittest.TestCase):
    """N3 (review of 3a8074fc): ``_fassung_waehlen`` returned ``not legacy_v01``, so ``legacy_v01="false"`` or
    ``"no"`` made ``emit_agent_review`` issue and sign a v0.1 predicate under the v0.1 rules, which ``False``
    refuses under the v0.2 rules. The renderers' ``_fassung_fuer_renderer`` read it the same way, and ``v02``
    joins the same choice."""

    @classmethod
    def setUpClass(cls):
        cls.signer = generate_signer()
        cls.v01 = _v01_predicate()

    def _emitters(self):
        return (("emit_agent_review", lambda **kw: ar.emit_agent_review(copy.deepcopy(self.v01), self.signer, **kw)),
                ("build_agent_review_statement", lambda **kw: ar.build_agent_review_statement(
                    copy.deepcopy(self.v01), **kw)))

    def test_a_legacy_switch_that_is_not_a_bool_issues_nothing(self):
        calls: list = []
        for label, value in _not_bools(calls):
            for name, emit in self._emitters():
                with self.subTest(surface=name, legacy_v01=label):
                    calls.clear()
                    with self.assertRaises(TypeError) as cm:
                        emit(legacy_v01=value)
                    _assert_refused_as_a_switch(self, cm, "legacy_v01", value)
                    self.assertEqual(calls, [], "the switch's own methods ran")

    def test_a_v02_switch_that_is_neither_none_nor_a_bool_issues_nothing(self):
        calls: list = []
        for label, value in _not_bools(calls, none_allowed=True):
            for name, emit in self._emitters():
                with self.subTest(surface=name, v02=label):
                    calls.clear()
                    with self.assertRaises(TypeError) as cm:
                        emit(v02=value)
                    _assert_refused_as_a_switch(self, cm, "v02", value)
                    self.assertEqual(calls, [], "the switch's own methods ran")

    def test_the_renderers_refuse_a_legacy_switch_that_is_neither_none_nor_a_bool(self):
        calls: list = []
        renderers = (
            ("require_valid_agent_review_predicate_any",
             lambda v: ar.require_valid_agent_review_predicate_any(self.v01, legacy_v01=v)),
            ("render_disclosure_block", lambda v: ar.render_disclosure_block(self.v01, legacy_v01=v)),
            ("render_disclosure_line", lambda v: ar.render_disclosure_line(
                self.v01, receipt_digest="0" * 64, receipt_url="https://x.invalid/r", legacy_v01=v)))
        for label, value in _not_bools(calls, none_allowed=True):
            for name, render in renderers:
                with self.subTest(surface=name, legacy_v01=label):
                    calls.clear()
                    with self.assertRaises(TypeError) as cm:
                        render(value)
                    _assert_refused_as_a_switch(self, cm, "legacy_v01", value)
                    self.assertEqual(calls, [], "the switch's own methods ran")

    def test_control_exact_bools_choose_the_rule_set_as_before(self):
        import warnings  # noqa: PLC0415
        with self.assertRaises(ar.AgentReviewError) as cm:
            ar.emit_agent_review(copy.deepcopy(self.v01), self.signer, legacy_v01=False)
        self.assertIn("disclosureCoreDigest is required", str(cm.exception))
        env = ar.emit_agent_review(copy.deepcopy(self.v01), self.signer, legacy_v01=True)
        statement = json.loads(base64.b64decode(env["payload"]))
        self.assertEqual(statement["predicateType"], ar.AGENT_REVIEW_PREDICATE_TYPE)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            self.assertEqual(ar.build_agent_review_statement(copy.deepcopy(self.v01), v02=False)["predicateType"],
                             ar.AGENT_REVIEW_PREDICATE_TYPE)
        ar.require_valid_agent_review_predicate_any(self.v01, legacy_v01=True)
        ar.require_valid_agent_review_predicate_any(self.v01)
        with self.assertRaises(ar.AgentReviewError):
            ar.require_valid_agent_review_predicate_any(self.v01, legacy_v01=False)


class _ChecksInASubclass(list):
    """A list subclass whose own ``__iter__`` hides every check."""

    def __iter__(self):
        return iter([])


class TestTheCryptoGateReadsAListSubclassByWhatItHolds(unittest.TestCase):
    """At 3a8074fc ``bundle._checks_passed`` asked ``type(checks) is list``: a duck-typed result whose checks sat
    in a list subclass skipped the per-check test, so ``Check("root-authenticity", "false")`` there passed the
    crypto gate on the result's own ``ok`` while the same check in a plain list did not."""

    class _Result:
        ok = True

        def __init__(self, checks):
            self.checks = checks

    def test_a_check_that_is_not_a_bool_fails_the_gate_in_any_list_or_tuple(self):
        from proofbundle.bundle import _checks_passed  # noqa: PLC0415
        for label, container in (("list", list), ("tuple", tuple), ("list subclass", _ChecksInASubclass),
                                 ("tuple subclass", type("_T", (tuple,), {}))):
            with self.subTest(checks=label):
                checks = container([Check("ed25519-signature", True), Check("root-authenticity", "false")])
                self.assertEqual(_checks_passed(self._Result(checks)),
                                 (False, ["checks['root-authenticity'].ok"]))

    def test_control_exact_checks_pass_in_any_list_or_tuple(self):
        from proofbundle.bundle import _checks_passed  # noqa: PLC0415
        for label, container in (("list", list), ("list subclass", _ChecksInASubclass)):
            with self.subTest(checks=label):
                self.assertEqual(_checks_passed(self._Result(container([Check("x", True)]))), (True, []))


#: Why a switch is left as it is, by class. Every bool keyword of every public function must stand in
#: ``_SWITCHES`` under one of these, or under "relaxing" (refused with SwitchTypeError) and
#: "relaxing, refused in the verdict" / "exact True only" (never-raise surfaces).
_TIGHTENING = ("tightening: default False, and True only adds a check or a refusal, so a value read by its "
               "truth tightens or equals leaving the switch out")
_VERDICT_INPUT = ("verdict input, not a switch: a verdict the caller reports, default None, counted only as "
                  "the exact bool since round 2 (a value that is not a bool blocks and is named)")
_PRESENTATION = "presentation only: decides how a message or a demo prints, no verdict, check or signed byte"
_EXCLUDED = ("excluded here: intoto.py is closed on its own branch (the commit pattern at the verify "
             "boundary), not changed in this one")
_RELAXING = "relaxing"
_RELAXING_VERDICT = "relaxing, refused in the verdict"
_EXACT_TRUE = "exact True only"

_SWITCHES = {
    # relaxing: refused with SwitchTypeError unless an exact bool (None where the switch allows it)
    ("proofbundle.adapters._provenance", "bind_reported_version", "bound"): _RELAXING,
    ("proofbundle.adapters.eee", "from_eee_dataset", "validate"): _RELAXING,
    ("proofbundle.agent_review", "build_agent_review_statement", "legacy_v01"): _RELAXING,
    ("proofbundle.agent_review", "build_agent_review_statement", "v02"): _RELAXING,
    ("proofbundle.agent_review", "emit_agent_review", "legacy_v01"): _RELAXING,
    ("proofbundle.agent_review", "emit_agent_review", "strict"): _RELAXING,
    ("proofbundle.agent_review", "emit_agent_review", "v02"): _RELAXING,
    ("proofbundle.agent_review", "render_disclosure_block", "legacy_v01"): _RELAXING,
    ("proofbundle.agent_review", "render_disclosure_line", "leaf_witnessed"): _RELAXING,
    ("proofbundle.agent_review", "render_disclosure_line", "legacy_v01"): _RELAXING,
    ("proofbundle.agent_review", "require_valid_agent_review_predicate_any", "legacy_v01"): _RELAXING,
    ("proofbundle.anchors", "verify_anchors", "allow_pending"): _RELAXING,
    ("proofbundle.anchors_chia_add", "anchor_add", "wait"): _RELAXING,
    ("proofbundle.assurance", "classify_digest_evidence", "applicable"): _RELAXING,
    ("proofbundle.assurance", "classify_receiver_corroboration", "applicable"): _RELAXING,
    ("proofbundle.decision", "emit_decision_receipt", "strict"): _RELAXING,
    ("proofbundle.hashalg", "compute_digest", "allow_deprecated"): _RELAXING,
    ("proofbundle.hashalg", "resolve_hash_alg", "allow_deprecated"): _RELAXING,
    ("proofbundle.hf_evals", "to_eval_results_entry", "allow_value_mismatch"): _RELAXING,
    ("proofbundle.hf_evals", "to_eval_results_entry", "include_token"): _RELAXING,
    ("proofbundle.hf_evals", "to_eval_results_entry", "require_verified"): _RELAXING,
    ("proofbundle.outcome", "emit_outcome_receipt", "strict"): _RELAXING,
    ("proofbundle.run_ledger", "emit_run_ledger", "strict"): _RELAXING,
    ("proofbundle.trust_pack", "sign_trust_pack", "strict"): _RELAXING,
    ("proofbundle.verification_summary", "emit_verification_summary", "strict"): _RELAXING,
    # relaxing, on a never-raise surface: the refusal is the failed verdict, naming the parameter and type
    ("proofbundle.renewal", "verify_sequence", "allow_unauthenticated_anchor"): _RELAXING_VERDICT,
    ("proofbundle.trust_pack", "verify_trust_pack", "allow_unverified_rotation"): _RELAXING_VERDICT,
    # relaxing, read as the exact True and never raising (a host-run gate; the helper's own switch)
    ("proofbundle._integration", "emit_enabled", "flag"): _EXACT_TRUE,
    ("proofbundle._membership", "require_switch", "allow_none"): _EXACT_TRUE,
    # verdict inputs
    **{("proofbundle.bundle", "root_authenticity_summary", k): _VERDICT_INPUT for k in (
        "anchor_ok", "policy_authenticated_root", "policy_expired", "policy_not_yet_valid", "policy_ok",
        "public_transparency_ok", "replay_ok", "requires_identity_overlay", "signer_trusted",
        "tree_context_authenticated")},
    ("proofbundle.public_transparency", "evaluate_public_transparency", "consistency_confirmed"): _VERDICT_INPUT,
    # presentation
    ("proofbundle.budget", "render_safe", "quote"): _PRESENTATION,
    ("proofbundle.demo", "run_demo", "as_json"): _PRESENTATION,
    # excluded
    **{("proofbundle.intoto", f, k): _EXCLUDED for f in ("svr_properties", "export_svr_dsse")
       for k in ("anchor_verified", "prereg_verified")},
    # tightening
    **{k: _TIGHTENING for k in (
        ("proofbundle._statement_payload", "load_statement_strict", "require_canonical"),
        ("proofbundle.adapters.agt_receipt", "verify_agt_receipt", "require_external_authorization"),
        ("proofbundle.agent_review", "require_valid_agent_review_predicate", "strict"),
        ("proofbundle.agent_review", "require_valid_agent_review_predicate_any", "strict"),
        ("proofbundle.agent_review", "validate_agent_review_predicate", "strict"),
        ("proofbundle.agent_review", "validate_agent_review_v02_predicate", "strict"),
        ("proofbundle.agent_review", "validate_agent_review_v03_predicate", "strict"),
        ("proofbundle.agent_review", "verify_agent_review", "strict"),
        ("proofbundle.agent_review", "verify_agent_review_v02", "strict"),
        ("proofbundle.agent_review", "verify_agent_review_v03", "strict"),
        ("proofbundle.canonical", "canonicalize_statement", "require_statement_shape"),
        ("proofbundle.canonical", "statement_content_root", "require_statement_shape"),
        ("proofbundle.decision", "require_valid_decision_predicate", "strict"),
        ("proofbundle.decision", "validate_decision_predicate", "strict"),
        ("proofbundle.decision", "verify_decision_receipt", "_raise_on_malformed"),
        ("proofbundle.decision", "verify_decision_receipt", "require_derived_subject"),
        ("proofbundle.decision", "verify_decision_receipt", "strict"),
        ("proofbundle.decision", "verify_decision_receipt_or_raise", "require_derived_subject"),
        ("proofbundle.decision", "verify_decision_receipt_or_raise", "strict"),
        ("proofbundle.outcome", "require_valid_outcome_predicate", "strict"),
        ("proofbundle.outcome", "validate_outcome_predicate", "strict"),
        ("proofbundle.outcome", "verify_outcome_receipt", "_raise_on_malformed"),
        ("proofbundle.outcome", "verify_outcome_receipt", "require_derived_subject"),
        ("proofbundle.outcome", "verify_outcome_receipt", "strict"),
        ("proofbundle.outcome", "verify_outcome_receipt_or_raise", "require_derived_subject"),
        ("proofbundle.outcome", "verify_outcome_receipt_or_raise", "strict"),
        ("proofbundle.policy", "lint_policy", "strict"),
        ("proofbundle.public_transparency", "evaluate_public_transparency", "strict_consistency"),
        ("proofbundle.relation_statement", "verify_relation_statement", "require_derived_subject"),
        ("proofbundle.relation_statement", "verify_relation_statement", "strict"),
        ("proofbundle.renewal", "renew_hashtree", "require_verified_prior"),
        ("proofbundle.renewal", "renew_timestamp", "require_verified_prior"),
        ("proofbundle.renewal", "verify_sequence", "require_current_hash"),
        ("proofbundle.renewal", "verify_sequence", "require_external_token"),
        ("proofbundle.renewal", "verify_sequence", "require_pq"),
        ("proofbundle.run_ledger", "require_valid_run_ledger_predicate", "strict"),
        ("proofbundle.run_ledger", "validate_run_ledger_predicate", "strict"),
        ("proofbundle.run_ledger", "verify_run_ledger", "strict"),
        ("proofbundle.trust_pack", "require_valid_trust_pack_predicate", "strict"),
        ("proofbundle.trust_pack", "validate_trust_pack_predicate", "strict"),
        ("proofbundle.trust_pack", "verify_trust_pack", "strict"),
        ("proofbundle.verification_summary", "require_valid_summary_predicate", "strict"),
        ("proofbundle.verification_summary", "validate_summary_predicate", "strict"),
        ("proofbundle.verification_summary", "verify_verification_summary", "strict"))},
}

#: Switches whose ``None`` means "not given" and is accepted as such.
_NONE_ALLOWED = {("proofbundle.agent_review", "build_agent_review_statement", "v02"),
                 ("proofbundle.agent_review", "emit_agent_review", "v02"),
                 ("proofbundle.agent_review", "render_disclosure_block", "legacy_v01"),
                 ("proofbundle.agent_review", "render_disclosure_line", "legacy_v01"),
                 ("proofbundle.agent_review", "require_valid_agent_review_predicate_any", "legacy_v01")}


def _is_bool_annotation(annotation) -> bool:
    if annotation is bool:
        return True
    text = annotation if isinstance(annotation, str) else repr(annotation)
    text = text.replace(" ", "").replace("typing.", "")
    return text in ("bool", "Optional[bool]", "bool|None", "None|bool", "Union[bool,None]", "Union[bool,NoneType]")


#: Every package ``[project.optional-dependencies]`` names, by extra: its distribution name (PEP 503
#: normalised) and the top-level module it installs. ``test_the_extra_map_matches_pyproject`` holds this map to
#: pyproject.toml, so an extra or a package added there without an entry here fails instead of going stale.
_OPTIONAL_EXTRAS = {
    "sdjwt": {}, "adapters": {}, "chia": {}, "experimental": {},
    "eval": {"rfc8785": "rfc8785"},
    "anchors": {"rfc3161-client": "rfc3161_client", "opentimestamps": "opentimestamps", "rfc8785": "rfc8785"},
    "pq": {"cryptography": "cryptography"},
    "rootcommit": {"ecdsa": "ecdsa"},
    "formal": {"z3-solver": "z3"},
    "pytest": {"pytest": "pytest"},
    "test": {"pytest": "pytest", "hypothesis": "hypothesis", "pyyaml": "yaml", "jsonschema": "jsonschema",
             "sd-jwt": "sd_jwt", "rfc8785": "rfc8785"},
    "inspect": {"inspect-ai": "inspect_ai"},
    "dev": {"pytest": "pytest", "ruff": "ruff", "jsonschema": "jsonschema", "mypy": "mypy", "build": "build",
            "hypothesis": "hypothesis", "rfc8785": "rfc8785", "sd-jwt": "sd_jwt", "pyyaml": "yaml",
            "inspect-ai": "inspect_ai"},
}

#: The core dependencies (``[project].dependencies``), by the same two names. A missing core dependency is a
#: broken install, not an absent extra, so its module is never excused, even where an extra names it as well
#: (``cryptography`` in ``pq``, ``rfc8785`` in four extras).
_CORE_DEPENDENCIES = {"cryptography": "cryptography", "rfc8785": "rfc8785"}


def _is_absent(top: str) -> bool:
    """True when the top-level module ``top`` cannot be found in the running environment. A finder that raises
    is not an absence (the failure then stays a failure)."""
    import importlib.util  # noqa: PLC0415
    try:
        return importlib.util.find_spec(top) is None
    except (ImportError, ValueError):
        return False


def _not_swept_reason(exc: BaseException, *, absent=_is_absent):
    """Why a module that failed to import is not swept here, or None when the failure must fail the sweep.

    The as-shipped bare install has no optional extra, so a module that imports one at module level cannot be
    imported there (``inspect_hook`` imports ``inspect_ai``; measured in the hermetic cleanroom at c8865652).
    Exactly one failure is excused: a ``ModuleNotFoundError`` whose missing top-level module (``exc.name`` up to
    the first dot) is the import name of a package of a declared optional extra and of no core dependency, when
    that package is absent from the running environment (``absent``, by default :func:`_is_absent`). Every other
    failure fails the sweep: an ``ImportError`` for another reason, a missing module no extra declares, a
    missing core dependency, and a missing submodule of an extra that is installed."""
    if type(exc) is not ModuleNotFoundError:
        return None
    name = exc.name
    if type(name) is not str or not name:
        return None
    top = name.split(".", 1)[0]
    if top in _CORE_DEPENDENCIES.values():
        return None
    extras = sorted(extra for extra, packages in _OPTIONAL_EXTRAS.items() if top in packages.values())
    if not extras or not absent(top):
        return None
    return f"needs {top!r}, which is absent here and comes only with the optional extra(s) {', '.join(extras)}"


def _in_modules(module: str, modules) -> bool:
    """True when ``module`` is one of ``modules`` or lies inside one of them (a subpackage that did not import)."""
    return any(module == m or module.startswith(m + ".") for m in modules)


def _discover_switches():
    """Every bool keyword of every public function under ``src/proofbundle``, found at run time.

    Each module of the package is imported; a function counts when its name has no leading underscore and it
    is defined in that module. A parameter counts when its default is a bool or its annotation says bool.
    Returns ``({(module, function, parameter): default}, {module: import error}, {module: why not swept})``:
    a module that does not import lands in the second map and fails the sweep, unless
    :func:`_not_swept_reason` excuses it, and then it is named in the third."""
    import importlib  # noqa: PLC0415
    import inspect  # noqa: PLC0415
    import pkgutil  # noqa: PLC0415
    import warnings  # noqa: PLC0415

    import proofbundle  # noqa: PLC0415
    found: dict = {}
    failed: dict = {}
    not_swept: dict = {}
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        for info in pkgutil.walk_packages(proofbundle.__path__, "proofbundle."):
            try:
                module = importlib.import_module(info.name)
            except Exception as exc:  # noqa: BLE001 - classified here, never dropped silently
                reason = _not_swept_reason(exc)
                if reason is None:
                    failed[info.name] = f"{type(exc).__name__}: {exc}"
                else:
                    not_swept[info.name] = reason
                continue
            for name, obj in vars(module).items():
                if name.startswith("_") or not inspect.isfunction(obj) or obj.__module__ != module.__name__:
                    continue
                for param in inspect.signature(obj).parameters.values():
                    if type(param.default) is bool or _is_bool_annotation(param.annotation):
                        found[(module.__name__, name, param.name)] = param.default
    return found, failed, not_swept


def _probes(not_swept=()):
    """For every switch classed relaxing: a call that takes the switch's value. The switch is checked before
    anything else, so a value that is not a bool must be refused whatever the other arguments are; an exact
    bool must pass the check (the call may then fail for its own reasons, never with SwitchTypeError).

    A switch whose module is in ``not_swept`` (an optional extra absent here) gets no probe and its module is
    not imported; the caller names it."""
    import importlib  # noqa: PLC0415

    def load(module: str):
        return None if _in_modules(module, not_swept) else importlib.import_module(module)

    anchors_chia_add, assurance, decision, hashalg, hf_evals, outcome, run_ledger, trust_pack, \
        verification_summary = (load(f"proofbundle.{m}") for m in (
            "anchors_chia_add", "assurance", "decision", "hashalg", "hf_evals", "outcome", "run_ledger",
            "trust_pack", "verification_summary"))
    _provenance, eee = load("proofbundle.adapters._provenance"), load("proofbundle.adapters.eee")
    signer = generate_signer()
    v01 = _v01_predicate()
    v02 = _v02_predicate()
    deny = json.loads((EXAMPLES / "decision_receipt_deny.json").read_text(encoding="utf-8"))
    bundle = _eval_bundle()
    digest = {"sha256": "a" * 64}
    probes = {
        ("proofbundle.adapters._provenance", "bind_reported_version", "bound"):
            lambda v: _provenance.bind_reported_version({}, "harness_version", "1.0", reason="r", bound=v),
        ("proofbundle.adapters.eee", "from_eee_dataset", "validate"):
            lambda v: eee.from_eee_dataset({}, comparator=">=", threshold="0.1", validate=v),
        ("proofbundle.agent_review", "build_agent_review_statement", "legacy_v01"):
            lambda v: ar.build_agent_review_statement(copy.deepcopy(v01), legacy_v01=v),
        ("proofbundle.agent_review", "build_agent_review_statement", "v02"):
            lambda v: ar.build_agent_review_statement(copy.deepcopy(v02), v02=v),
        ("proofbundle.agent_review", "emit_agent_review", "legacy_v01"):
            lambda v: ar.emit_agent_review(copy.deepcopy(v01), signer, legacy_v01=v),
        ("proofbundle.agent_review", "emit_agent_review", "strict"):
            lambda v: ar.emit_agent_review(copy.deepcopy(v02), signer, strict=v),
        ("proofbundle.agent_review", "emit_agent_review", "v02"):
            lambda v: ar.emit_agent_review(copy.deepcopy(v02), signer, v02=v),
        ("proofbundle.agent_review", "render_disclosure_block", "legacy_v01"):
            lambda v: ar.render_disclosure_block(v01, legacy_v01=v),
        ("proofbundle.agent_review", "render_disclosure_line", "leaf_witnessed"):
            lambda v: ar.render_disclosure_line(v02, receipt_digest="0" * 64, receipt_url="https://x.invalid/r",
                                                leaf_url="https://x.invalid/leaf", leaf_witnessed=v),
        ("proofbundle.agent_review", "render_disclosure_line", "legacy_v01"):
            lambda v: ar.render_disclosure_line(v01, receipt_digest="0" * 64, receipt_url="https://x.invalid/r",
                                                legacy_v01=v),
        ("proofbundle.agent_review", "require_valid_agent_review_predicate_any", "legacy_v01"):
            lambda v: ar.require_valid_agent_review_predicate_any(v01, legacy_v01=v),
        ("proofbundle.anchors", "verify_anchors", "allow_pending"):
            lambda v: anchors.verify_anchors([], target_roots={}, require="any", allow_pending=v),
        # "zz" is no hex: an exact bool passes the switch check and stops at bytes.fromhex, before any RPC.
        ("proofbundle.anchors_chia_add", "anchor_add", "wait"):
            lambda v: anchors_chia_add.anchor_add("zz", store_id="s", wait=v),
        ("proofbundle.assurance", "classify_digest_evidence", "applicable"):
            lambda v: assurance.classify_digest_evidence(digest, applicable=v),
        ("proofbundle.assurance", "classify_receiver_corroboration", "applicable"):
            lambda v: assurance.classify_receiver_corroboration(
                digest, applicable=v, evidence_resolver=lambda d: True, independent_attestation_resolver=lambda d: True,
                executor_key_id="kid-exec", receiver_key_id="kid-recv"),
        ("proofbundle.decision", "emit_decision_receipt", "strict"):
            lambda v: decision.emit_decision_receipt(copy.deepcopy(deny), signer, strict=v),
        ("proofbundle.hashalg", "compute_digest", "allow_deprecated"):
            lambda v: hashalg.compute_digest(b"x", "sha1", allow_deprecated=v),
        ("proofbundle.hashalg", "resolve_hash_alg", "allow_deprecated"):
            lambda v: hashalg.resolve_hash_alg("sha1", allow_deprecated=v),
        ("proofbundle.hf_evals", "to_eval_results_entry", "allow_value_mismatch"):
            lambda v: hf_evals.to_eval_results_entry(bundle, dataset_id="d", task_id="t", value=0.9,
                                                     allow_value_mismatch=v),
        ("proofbundle.hf_evals", "to_eval_results_entry", "include_token"):
            lambda v: hf_evals.to_eval_results_entry(bundle, dataset_id="d", task_id="t", value=0.9, include_token=v),
        ("proofbundle.hf_evals", "to_eval_results_entry", "require_verified"):
            lambda v: hf_evals.to_eval_results_entry(bundle, dataset_id="d", task_id="t", value=0.9,
                                                     require_verified=v),
        ("proofbundle.outcome", "emit_outcome_receipt", "strict"):
            lambda v: outcome.emit_outcome_receipt({}, signer, strict=v),
        ("proofbundle.run_ledger", "emit_run_ledger", "strict"):
            lambda v: run_ledger.emit_run_ledger({}, signer, strict=v),
        ("proofbundle.trust_pack", "sign_trust_pack", "strict"):
            lambda v: trust_pack.sign_trust_pack({}, {}, strict=v),
        ("proofbundle.verification_summary", "emit_verification_summary", "strict"):
            lambda v: verification_summary.emit_verification_summary({}, signer, strict=v),
    }
    return {key: probe for key, probe in probes.items() if not _in_modules(key[0], not_swept)}


def _pyproject():
    """pyproject.toml of this tree as a dict, or None where it cannot be read: no file (an installed package
    without its source) or no TOML reader (``tomllib`` from 3.11; on 3.10 pytest itself depends on ``tomli``)."""
    try:
        import tomllib  # noqa: PLC0415
    except ModuleNotFoundError:
        try:
            import tomli as tomllib  # noqa: PLC0415
        except ModuleNotFoundError:
            return None
    try:
        text = (Path(__file__).resolve().parent.parent / "pyproject.toml").read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    return tomllib.loads(text)


def _distribution_name(requirement: str) -> str:
    """The PEP 503 normalised distribution name of a PEP 508 requirement string."""
    import re  # noqa: PLC0415
    match = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)", requirement)
    assert match is not None, f"not a requirement: {requirement!r}"
    return re.sub(r"[-_.]+", "-", match.group(1)).lower()


class TestEverySwitchOfThePublicApiHoldsItsClass(unittest.TestCase):
    """The runtime sweep. A switch whose one side weakens a verdict or a check, or changes what is signed or
    published, counts only as an exact bool; the review of 3a8074fc found three that still read their value by
    its truth (``applicable``, ``bound``, ``legacy_v01``), and the sweep found the others below.

    The sweep runs where the shipped suite runs, the as-shipped bare install included, which has no optional
    extra. There ``inspect_hook`` and ``_inspect_registry`` cannot import (they need ``inspect_ai``), and
    c8865652 counted that as a failure: the hermetic cleanroom went red. A module that needs an absent extra is
    now named as not swept here, and nothing else is excused (:func:`_not_swept_reason`); where every extra is
    installed, nothing is excused at all."""

    @classmethod
    def setUpClass(cls):
        cls.found, cls.failed, cls.not_swept = _discover_switches()

    def test_every_module_of_the_package_imports(self):
        self.assertEqual(self.failed, {}, "a module that does not import hides its switches from the sweep")

    def test_a_module_that_needs_an_absent_optional_extra_is_named_as_not_swept(self):
        """Nothing to assert beyond the classification itself: where every extra is installed this passes with
        nothing named; where one is absent it is a skip that names each module, the extra it needs, and the
        classified switches that could therefore not be checked here."""
        if self.not_swept:
            unchecked = sorted(".".join(k) for k in _SWITCHES if _in_modules(k[0], self.not_swept))
            self.skipTest("NOT SWEPT here: " + "; ".join(f"{m} {r}" for m, r in sorted(self.not_swept.items()))
                          + f"; classified switches not checked here: {unchecked or 'none'}")

    def test_the_extra_map_matches_pyproject(self):
        data = _pyproject()
        if data is None:
            self.skipTest("NOT MEASURABLE: pyproject.toml or a TOML reader is absent here, so the map of optional "
                          "extras was NOT compared with it")
        project = data["project"]
        declared = {extra: {_distribution_name(r) for r in requirements}
                    for extra, requirements in project["optional-dependencies"].items()}
        self.assertEqual(declared, {extra: set(packages) for extra, packages in _OPTIONAL_EXTRAS.items()},
                         "the map of optional extras is stale")
        self.assertEqual({_distribution_name(r) for r in project["dependencies"]}, set(_CORE_DEPENDENCIES),
                         "the map of core dependencies is stale")

    def test_every_discovered_switch_is_classified_and_every_classified_switch_exists(self):
        self.assertEqual(sorted(set(self.found) - set(_SWITCHES)), [], "a new switch: give it a class")
        not_checked_here = {k for k in _SWITCHES if _in_modules(k[0], self.not_swept)}
        self.assertEqual(sorted(set(_SWITCHES) - set(self.found) - not_checked_here), [],
                         "a classified switch no longer exists")

    def test_the_premise_of_each_class_holds_for_its_default(self):
        for key, cls in _SWITCHES.items():
            if key not in self.found:
                continue
            with self.subTest(switch=".".join(key)):
                if cls == _TIGHTENING:
                    self.assertIs(self.found[key], False, "a tightening switch must default to False")
                elif cls == _VERDICT_INPUT:
                    self.assertIsNone(self.found[key], "a verdict input defaults to None (not evaluated)")

    def test_every_relaxing_switch_refuses_a_value_that_is_not_a_bool(self):
        import warnings  # noqa: PLC0415
        probes = _probes(self.not_swept)
        relaxing = sorted(k for k, c in _SWITCHES.items()
                          if c == _RELAXING and not _in_modules(k[0], self.not_swept))
        self.assertEqual(sorted(probes), relaxing, "every relaxing switch needs a probe")
        calls: list = []
        for key in relaxing:
            for label, value in _not_bools(calls, none_allowed=key in _NONE_ALLOWED):
                with self.subTest(switch=".".join(key), value=label):
                    calls.clear()
                    with warnings.catch_warnings():
                        warnings.simplefilter("ignore")
                        with self.assertRaises(TypeError) as cm:
                            probes[key](value)
                    _assert_refused_as_a_switch(self, cm, key[2], value)
                    self.assertEqual(calls, [], "the switch's own methods ran")

    def test_control_every_relaxing_switch_lets_an_exact_bool_through(self):
        import warnings  # noqa: PLC0415
        probes = _probes(self.not_swept)
        for key, probe in sorted(probes.items()):
            for value in (True, False) + ((None,) if key in _NONE_ALLOWED else ()):
                with self.subTest(switch=".".join(key), value=value):
                    try:
                        with warnings.catch_warnings():
                            warnings.simplefilter("ignore")
                            probe(value)
                    except TypeError as exc:
                        self.assertNotIn("must be a bool", str(exc), f"an exact {value!r} was refused")
                    except Exception:  # noqa: BLE001 - the probe's other arguments may fail on their own
                        pass

    def test_the_never_raise_verifiers_refuse_in_their_verdict_and_name_the_type(self):
        data = [_sha("a"), _sha("b")]
        seq = build_initial_sequence(data, hash_alg="sha256", time=1000)
        env, now = _rotation_pack()

        def sequence(v):
            r = verify_sequence(seq, data, allow_unauthenticated_anchor=v)
            return r.ok, next(c for c in r.checks if c.name == "renewal:last_anchor").detail

        def rotation(v):
            r = verify_trust_pack(env, strict=True, now=now, allow_unverified_rotation=v)
            return r["ok"], "; ".join(r["errors"])

        surfaces = {("proofbundle.renewal", "verify_sequence", "allow_unauthenticated_anchor"): sequence,
                    ("proofbundle.trust_pack", "verify_trust_pack", "allow_unverified_rotation"): rotation}
        self.assertEqual(sorted(surfaces), sorted(k for k, c in _SWITCHES.items() if c == _RELAXING_VERDICT))
        calls: list = []
        for key, surface in surfaces.items():
            self.assertEqual(surface(True)[0], True, "control: the exact True relaxes")
            ok, text = surface(False)
            self.assertEqual(ok, False, "control: the exact False keeps the check")
            self.assertNotIn("not a bool", text)
            for label, value in _not_bools(calls):
                with self.subTest(switch=".".join(key), value=label):
                    calls.clear()
                    ok, text = surface(value)
                    self.assertIs(ok, False)
                    self.assertIn(f"{key[2]} is not a bool (a value of type {type(value).__name__})", text)
                    self.assertEqual(calls, [], "the switch's own methods ran")

    def test_the_emit_gate_opens_only_for_the_exact_true_and_never_raises(self):
        """``_integration.emit_enabled`` returned ``flag or ...``: ``"false"`` opened the gate that decides whether
        an integration writes a receipt into a host run, and the value itself came back. It never raises (an
        integration must never fail the host run), so a value that is not a bool leaves the gate closed."""
        import os  # noqa: PLC0415
        from unittest import mock  # noqa: PLC0415
        from proofbundle import _integration  # noqa: PLC0415
        calls: list = []
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("PROOFBUNDLE_EMIT", None)
            self.assertIs(_integration.emit_enabled(True), True)
            self.assertIs(_integration.emit_enabled(False), False)
            for label, value in _not_bools(calls):
                with self.subTest(flag=label):
                    calls.clear()
                    self.assertIs(_integration.emit_enabled(value), False)
                    self.assertEqual(calls, [], "the flag's own methods ran")

    def test_the_helpers_own_switch_admits_none_only_for_the_exact_true(self):
        calls: list = []
        self.assertIsNone(_membership.require_switch(None, "x", allow_none=True))
        for label, value in _not_bools(calls):
            with self.subTest(allow_none=label):
                calls.clear()
                with self.assertRaises(TypeError) as cm:
                    _membership.require_switch(None, "x", allow_none=value)
                _assert_refused_as_a_switch(self, cm, "x", None)
                self.assertEqual(calls, [], "the switch's own methods ran")


class TestOnlyAnAbsentOptionalExtraKeepsAModuleOutOfTheSweep(unittest.TestCase):
    """The excuse of the sweep, on constructed failures, so both directions are measured in every environment:
    the one failure that is excused, and each neighbour that must still fail. ``absent`` stands in for the
    environment; the last case asks the real one."""

    _ABSENT = frozenset({"inspect_ai", "opentimestamps", "zz_in_no_extra", "cryptography", "rfc8785"})

    def _reason(self, exc):
        return _not_swept_reason(exc, absent=lambda top: top in self._ABSENT)

    def test_a_missing_package_of_an_absent_extra_is_named(self):
        for missing, extra in (("inspect_ai", "inspect"), ("inspect_ai.hooks", "inspect"),
                               ("opentimestamps.core", "anchors")):
            with self.subTest(missing=missing):
                reason = self._reason(ModuleNotFoundError(f"No module named {missing!r}", name=missing))
                self.assertIsNotNone(reason)
                self.assertIn(repr(missing.split(".")[0]), reason)
                self.assertIn(extra, reason)

    def test_every_other_import_failure_fails_the_sweep(self):
        def missing(name):
            return ModuleNotFoundError(f"No module named {name!r}", name=name)

        for label, exc in (
                ("a module no extra declares", missing("zz_in_no_extra")),
                ("a module of the package itself", missing("proofbundle._zz_planted")),
                ("a core dependency that an extra names too", missing("cryptography")),
                ("rfc8785, a core dependency named by four extras", missing("rfc8785.sub")),
                ("a package of an extra that is installed here", missing("ecdsa")),
                ("an ImportError for another reason, naming an absent extra", ImportError(
                    "cannot import name 'Hooks' from 'inspect_ai'", name="inspect_ai")),
                ("a ModuleNotFoundError without a name", ModuleNotFoundError("No module named 'inspect_ai'")),
                ("a module whose own code raised", RuntimeError("inspect_ai"))):
            with self.subTest(failure=label):
                self.assertIsNone(self._reason(exc))

    def test_the_default_asks_the_running_environment(self):
        self.assertIs(_is_absent("proofbundle"), False)
        self.assertIs(_is_absent("cryptography"), False)
        self.assertIs(_is_absent("zz_no_module_of_this_name_anywhere"), True)
        self.assertIsNone(_not_swept_reason(ModuleNotFoundError("No module named 'pytest'", name="pytest")),
                          "pytest runs this test, so its extra is installed and nothing is excused")


if __name__ == "__main__":
    unittest.main()
