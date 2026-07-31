"""Verdict semantics — a published verdict field must mean what its NAME says.

Three defects from the 2026-07 adversarial deep gate, each fixed as a CLASS rather than at the site
where it was found:

* **L1-SEM-01** — ``outcome verify --policy`` enforced NOTHING except the ``relations`` section: with a
  relations section present it reported ``POLICY: OK`` under an EXPIRED, WRONG-PURPOSE, un-instantiated
  template policy that the DECISION sibling failed closed on the very same file, and any other section
  the caller supplied (``decision_receipt``, ``merkle``, ...) was silently dropped. The class is
  *"policy-level preconditions run BEFORE any section rule, and a section this path cannot honour is
  refused, never ignored"* — implemented once in
  :func:`proofbundle.automation_verdict.policy_standing_errors` and used by every covered path.
* **L1-SEM-02** — ``automation.referencesResolved`` was vacuously ``True`` whenever NOTHING was
  resolved, including on a forged envelope where every reference field is ``None``.
* **L1-SEM-03** — ``decision.py`` classified the ``actionOutcome.outcomeRef`` WRAPPER instead of the
  digest inside it, pinning ``evidence_levels['actionOutcome.outcomeRef']`` at ``CLAIMED`` for every
  receipt (including the repo's own golden example) with a detail string that is factually false.

Every fix ships a MUST-FAIL negative (red against the pre-fix behaviour) plus an ANTI-TAUTOLOGY TWIN
that blinds the detector and shows the negative stops catching the planted violation.
"""
from __future__ import annotations

import base64
import copy
import importlib
import inspect
import json
import pathlib
import pkgutil
import unittest
from unittest import mock

import proofbundle
from proofbundle import automation_verdict, decision as decision_mod
from proofbundle.assurance import EvidenceLevel
from proofbundle.automation_verdict import automation_summary, policy_standing_errors
from proofbundle.decision import emit_decision_receipt, verify_decision_receipt
from proofbundle.emit import generate_signer
from proofbundle.outcome import emit_outcome_receipt, verify_outcome_receipt

_EXAMPLES = pathlib.Path(__file__).resolve().parents[1] / "examples"
V02 = "proofbundle/trust-policy/v0.2"


def _keys():
    s = generate_signer()
    return s, s.public_key().public_bytes_raw()


def _outcome_pred(**over) -> dict:
    pred = {
        "schemaVersion": "0.1.0", "outcomeId": "urn:uuid:o", "decisionRef": {"sha256": "1" * 64},
        "executor": {"id": "ex", "keyId": "kid-exec"}, "requestedActionDigest": {"sha256": "1" * 64},
        "status": "refused", "performedAt": "2026-07-17T00:00:00Z", "policyPurpose": "outcome",
    }
    pred.update(over)
    return pred


def _decision_pred(name: str = "deny") -> dict:
    return json.loads((_EXAMPLES / f"decision_receipt_{name}.json").read_text(encoding="utf-8"))


def _bad_standing_policy(**extra) -> dict:
    """An EXPIRED, WRONG-PURPOSE, un-instantiated template policy that nevertheless carries a satisfiable
    ``relations`` section — the exact shape that used to yield POLICY: OK on the outcome path."""
    pol = {
        "schema": V02, "policy_id": "audit/expired-wrong-purpose",
        "policyPurpose": "eval",                       # bound to a DIFFERENT verifier path
        "valid_until": "2020-01-01T00:00:00Z",         # expired
        "requiresIdentityOverlay": True,               # raw, un-instantiated template
        "relations": {"reject_superseded": True},      # the ONE section the outcome path honours
    }
    pol.update(extra)
    return pol


class TestOutcomePolicyStanding(unittest.TestCase):
    """L1-SEM-01 on the surface where it was found."""

    def _verify_with(self, policy):
        s, pub = _keys()
        env = emit_outcome_receipt(_outcome_pred(), s, strict=False)
        return verify_outcome_receipt(env, pub, policy=policy)

    def test_expired_wrong_purpose_template_policy_is_never_policy_ok(self):
        # MUST-FAIL NEGATIVE: pre-fix this asserted-against value was policy_ok=True ("POLICY: OK").
        r = self._verify_with(_bad_standing_policy())
        self.assertIs(r["policy_ok"], False)
        self.assertIs(r["ok"], False)
        blob = " ".join(r["errors"])
        self.assertIn("expired", blob)
        self.assertIn("raw template", blob)
        self.assertIn("wrong purpose", blob)

    def test_each_precondition_fails_closed_on_its_own(self):
        # the corpus is generated from the DECISION SPACE of the rule (one case per precondition the
        # gate reads), not from the one combined policy that happened to refute the old code.
        for label, extra in (
            ("expired", {"valid_until": "2020-01-01T00:00:00Z"}),
            ("not-yet-valid", {"valid_from": "2099-01-01T00:00:00Z"}),
            ("raw-template", {"requiresIdentityOverlay": True}),
            ("wrong-purpose", {"policyPurpose": "decision"}),
            ("unreadable-valid-until", {"valid_until": "soon"}),
            ("unreadable-valid-from", {"valid_from": "later"}),
        ):
            with self.subTest(precondition=label):
                pol = {"schema": V02, "policy_id": "p", "relations": {"reject_superseded": True}}
                pol.update(extra)
                r = self._verify_with(pol)
                self.assertIs(r["policy_ok"], False, f"{label} must fail closed")

    def test_section_the_path_cannot_honour_is_refused_not_ignored(self):
        # Silently dropping a section the caller supplied is the fail-open: the relying party reads
        # POLICY: OK for a rule that was never even read.
        s, pub = _keys()
        env = emit_outcome_receipt(_outcome_pred(), s, strict=False)
        pol = {"schema": V02, "policy_id": "p", "policyPurpose": "outcome",
               "decision_receipt": {"allowed_verdicts": ["ALLOW"]}}
        r = verify_outcome_receipt(env, pub, policy=pol)
        self.assertIs(r["policy_ok"], False)
        self.assertTrue(any("decision_receipt" in e and "cannot be enforced" in e for e in r["errors"]),
                        r["errors"])

    def test_unknown_future_section_falls_on_the_rejected_side(self):
        # The section gate is an ALLOWLIST of honoured sections, not a blocklist of known-bad ones: a
        # section that does not exist in the schema today must not silently no-op tomorrow either.
        s, pub = _keys()
        env = emit_outcome_receipt(_outcome_pred(), s, strict=False)
        r = verify_outcome_receipt(env, pub, policy={"schema": V02, "policy_id": "p",
                                                     "policyPurpose": "outcome",
                                                     "some_section_invented_later": {"x": 1}})
        self.assertIs(r["policy_ok"], False)

    def test_honoured_relations_policy_still_authorises(self):
        # BACKWARD COMPAT / positive control: the case 3.7.0 legitimately accepted still passes, so the
        # negatives above are not passing merely because everything now fails.
        s, pub = _keys()
        env = emit_outcome_receipt(_outcome_pred(), s, strict=False)
        r = verify_outcome_receipt(env, pub, policy={"schema": V02, "policy_id": "p",
                                                     "policyPurpose": "outcome",
                                                     "relations": {"reject_superseded": True}})
        self.assertIs(r["policy_ok"], True)
        self.assertIs(r["ok"], True)

    def test_no_policy_argument_is_unchanged(self):
        s, pub = _keys()
        env = emit_outcome_receipt(_outcome_pred(), s, strict=False)
        r = verify_outcome_receipt(env, pub)
        self.assertIsNone(r["policy_ok"])
        self.assertIs(r["ok"], True)

    def test_anti_tautology_blinded_standing_gate_stops_catching_it(self):
        # ANTI-TAUTOLOGY TWIN: gut the detector (the standing gate reports nothing) and the SAME probe
        # must go back to the pre-fix verdict — proving the assertion above discriminates the fix rather
        # than passing for some unrelated reason. The axis varied is the one the rule decides on (the
        # standing verdict), not a side axis.
        with mock.patch.object(automation_verdict, "policy_standing_errors",
                               lambda *a, **k: []):
            r = self._verify_with(_bad_standing_policy())
        self.assertIs(r["policy_ok"], True, "blinded gate must reproduce the pre-fix POLICY: OK")


class TestDecisionPolicyStandingParity(unittest.TestCase):
    """L1-SEM-01 neighbour IN THE SAME FAMILY: on the decision path the preconditions lived INSIDE
    ``evaluate_decision_policy``, AFTER its `no decision_receipt section -> policy_ok=None` early return,
    so a policy with only a ``relations`` section skipped them entirely."""

    def _verify_with(self, policy):
        s, pub = _keys()
        env = emit_decision_receipt(_decision_pred(), s, strict=True)
        return verify_decision_receipt(env, pub, strict=True, policy=policy)

    def test_relations_only_expired_policy_is_not_evaluable_on_decision_path(self):
        # MUST-FAIL NEGATIVE: pre-fix policy_ok was None here (preconditions never ran) — an expired,
        # wrong-purpose policy was treated as "nothing to check" instead of "no standing".
        r = self._verify_with(_bad_standing_policy())
        self.assertIs(r["policy_ok"], False)
        blob = " ".join(r["errors"])
        self.assertIn("expired", blob)
        self.assertIn("wrong purpose", blob)

    def test_same_policy_file_is_refused_by_both_siblings(self):
        # The CLASS property: one policy file must never be refused by one verify path and affirmed by
        # its sibling. This asymmetry IS the finding.
        pol = _bad_standing_policy()
        s, pub = _keys()
        d = verify_decision_receipt(emit_decision_receipt(_decision_pred(), s, strict=True), pub,
                                    strict=True, policy=pol)
        o = verify_outcome_receipt(emit_outcome_receipt(_outcome_pred(), s, strict=False), pub,
                                   policy=pol)
        self.assertIs(d["policy_ok"], False)
        self.assertIs(o["policy_ok"], False)

    def test_instantiated_decision_policy_still_authorises(self):
        # BACKWARD COMPAT / positive control on the decision path.
        s, pub = _keys()
        env = emit_decision_receipt(_decision_pred(), s, strict=True)
        pol = {"schema": V02, "policy_id": "p", "policyPurpose": "decision",
               "decision_receipt": {"trusted_decision_makers": [
                   {"public_key_b64": base64.b64encode(pub).decode()}]}}
        r = verify_decision_receipt(env, pub, strict=True, policy=pol)
        self.assertIs(r["policy_ok"], True, r["errors"])
        self.assertIs(r["signer_trusted"], True)

    def test_anti_tautology_blinded_standing_gate_stops_catching_it(self):
        with mock.patch.object(automation_verdict, "policy_standing_errors", lambda *a, **k: []):
            r = self._verify_with(_bad_standing_policy())
        self.assertIsNot(r["policy_ok"], False,
                         "blinded gate must reproduce the pre-fix non-False verdict")


class TestPolicyStandingUnit(unittest.TestCase):
    """The shared mechanism itself — never raises, and reports each reason separately."""

    def test_non_dict_policy_is_fail_closed_not_a_crash(self):
        for bad in (None, 42, "policy", ["relations"], object()):
            with self.subTest(value=type(bad).__name__):
                errs = policy_standing_errors(bad, purpose="outcome", honoured_sections=("relations",))
                self.assertTrue(errs)

    def test_absent_purpose_is_the_documented_transitional_default(self):
        self.assertEqual(policy_standing_errors({"schema": V02, "policy_id": "p"}, purpose="outcome",
                                                honoured_sections=("relations",)), [])
        self.assertEqual(policy_standing_errors({"schema": V02, "policy_id": "p", "policyPurpose": None},
                                                purpose="outcome", honoured_sections=("relations",)), [])

    def test_metadata_keys_are_never_reported_as_unhonourable_sections(self):
        pol = {k: "x" for k in automation_verdict.POLICY_METADATA_KEYS}
        pol["policyPurpose"] = "outcome"
        pol["requiresIdentityOverlay"] = False
        pol["valid_until"] = "2099-01-01T00:00:00Z"
        pol["valid_from"] = "2000-01-01T00:00:00Z"
        self.assertEqual(policy_standing_errors(pol, purpose="outcome", honoured_sections=("relations",)),
                         [])

    def test_hostile_policy_values_do_not_break_the_rejection_path(self):
        # The rejection path must not fail harder than the check it explains: `policy` is untrusted input
        # on a never-raise verify path, so every echoed value goes through the bounded renderer. A bare
        # `{...!r}` here raised RecursionError out of verify_outcome_receipt (measured).
        deep: list = []
        cur = deep
        for _ in range(200_000):
            nxt: list = []
            cur.append(nxt)
            cur = nxt
        for label, pol in (
            ("deep valid_until", {"schema": V02, "valid_until": deep}),
            ("deep valid_from", {"schema": V02, "valid_from": deep}),
            ("deep policyPurpose", {"schema": V02, "policyPurpose": deep}),
            ("huge section name", {"schema": V02, "x" * 100_000: {}}),
        ):
            with self.subTest(case=label):
                errs = policy_standing_errors(pol, purpose="outcome", honoured_sections=("relations",))
                self.assertTrue(errs)
                for e in errs:
                    self.assertLess(len(e), 4096, "an unbounded explanation is the same class of defect")
        s, pub = _keys()
        env = emit_outcome_receipt(_outcome_pred(), s, strict=False)
        r = verify_outcome_receipt(env, pub, policy={"schema": V02, "valid_until": deep})
        self.assertIs(r["policy_ok"], False)

    def test_honoured_sections_none_skips_the_section_dimension(self):
        pol = {"schema": V02, "policy_id": "p", "merkle": {"required_hash_alg": "sha256-rfc6962"}}
        self.assertEqual(policy_standing_errors(pol, purpose="decision", honoured_sections=None), [])
        self.assertTrue(policy_standing_errors(pol, purpose="decision", honoured_sections=()))


# The FULL family of verify_* surfaces that take a `policy` argument, discovered rather than enumerated
# (a surface added later must land in one of these buckets or fail this test). Each member is either
# covered by the standing gate with an EFFECT test above, or pinned here with a non-empty reason.
_STANDING_GATE_COVERED = {
    "proofbundle.decision.verify_decision_receipt",
    "proofbundle.decision.verify_decision_receipt_or_raise",
    "proofbundle.outcome.verify_outcome_receipt",
    "proofbundle.outcome.verify_outcome_receipt_or_raise",
}
_STANDING_GATE_OPEN = {
    "proofbundle.relation_statement.verify_relation_statement":
        "SAME defect, NOT fixed in this increment: its policy block is the identical "
        "`elif isinstance(policy.get('relations'), dict)` shape with no preconditions and no section "
        "gate. relation_statement.py is owned by another lane in this run — reported, not touched.",
}
_STANDING_GATE_NOT_A_TRUST_POLICY = {
    "proofbundle.sdjwt_vc.verify_sdjwt_vc":
        "its `policy` argument is an SD-JWT VC PROFILE document (vctAllowlist / requireKeyBinding / "
        "requireIssuerSignature, validated by sdjwt_vc.validate_vc_policy), not a proofbundle trust "
        "policy — it carries no schema/policyPurpose/valid_until lifecycle to precondition.",
}
# The sections the decision path could honour but does not yet REFUSE the complement of. Pinned so the
# gap is enumerated instead of silent (see decision._DECISION_HONOURED_POLICY_SECTIONS).
_DECISION_SECTION_GATE_OPEN_REASON = (
    "the shipped decision-receipt-template-v1 profile carries `signature` + `allowed_schema_versions`, "
    "which evaluate_decision_policy never reads; refusing them would reject the repo's own instantiated "
    "profile — a breaking change for a legitimate producer, flagged instead of shipped.")


def _policy_accepting_verify_surfaces() -> set:
    found = set()
    for mod_info in pkgutil.iter_modules(proofbundle.__path__):
        name = f"proofbundle.{mod_info.name}"
        # An unimportable module is UNKNOWN scope, never "nothing to check" — surface it as a member so
        # the pinned-set assertion fails loudly rather than shrinking the scope silently.
        try:
            module = importlib.import_module(name)
        except Exception as exc:  # noqa: BLE001
            found.add(f"{name}.<unimportable: {exc!r}>")
            continue
        for attr, obj in vars(module).items():
            if attr.startswith("_") or not inspect.isfunction(obj):
                continue
            if getattr(obj, "__module__", None) != name or not attr.startswith("verify_"):
                continue
            try:
                params = inspect.signature(obj).parameters
            except (TypeError, ValueError):  # pragma: no cover - defensive
                found.add(f"{name}.{attr}.<unintrospectable>")
                continue
            if "policy" in params:
                found.add(f"{name}.{attr}")
    return found


class TestPolicyStandingClassScope(unittest.TestCase):
    """Scope by DISCOVERY, not by enumeration: every shipped verify_* surface that accepts a `policy`
    argument is either covered, or an OPEN member with a documented reason, or documented as not being a
    trust-policy surface at all. A new surface belongs to none of the three and fails here."""

    def test_every_policy_accepting_verify_surface_is_classified(self):
        classified = (_STANDING_GATE_COVERED | set(_STANDING_GATE_OPEN)
                      | set(_STANDING_GATE_NOT_A_TRUST_POLICY))
        discovered = _policy_accepting_verify_surfaces()
        self.assertEqual(discovered - classified, set(),
                         "unclassified policy-accepting verify surface(s) — cover them with the standing "
                         "gate or pin them with a reason")
        # and nothing is pinned that no longer exists (a stale exemption is a silent hole)
        self.assertEqual(classified - discovered, set(), "stale entries in the pinned sets")

    def test_open_members_carry_a_non_empty_reason(self):
        for name, reason in list(_STANDING_GATE_OPEN.items()) + list(
                _STANDING_GATE_NOT_A_TRUST_POLICY.items()):
            with self.subTest(surface=name):
                self.assertTrue(reason and reason.strip(), "an exemption without a reason is a silent gap")
        self.assertTrue(_DECISION_SECTION_GATE_OPEN_REASON.strip())
        self.assertIsNone(decision_mod._DECISION_HONOURED_POLICY_SECTIONS,
                          "the decision-side section gate is a PINNED open item; wiring it needs the "
                          "shipped-profile break to be resolved first")


class TestReferencesResolvedIsNotVacuous(unittest.TestCase):
    """L1-SEM-02 — the aggregate never fails open, but the published label lied."""

    CHECKS = {"crypto": "crypto_ok", "structure": "structure_ok", "policy": None,
              "references": ["a_ok", "b_ok"]}

    def test_nothing_resolved_is_not_applicable_not_true(self):
        # MUST-FAIL NEGATIVE: pre-fix this was True.
        s = automation_summary({"crypto_ok": True, "structure_ok": True, "a_ok": None, "b_ok": None},
                               required_checks=self.CHECKS)
        self.assertIsNone(s["referencesResolved"])

    def test_forged_envelope_does_not_claim_resolved_references(self):
        # The published shape on the never-raise fail-closed path: every reference field is None there.
        s, _pub = _keys()
        other = generate_signer().public_key().public_bytes_raw()
        env = emit_outcome_receipt(_outcome_pred(), s, strict=False)
        r = verify_outcome_receipt(env, other)          # forged: signed by a different key
        self.assertIs(r["automation"]["cryptoValid"], False)
        self.assertIs(r["automation"]["safeForAutomation"], False)
        self.assertIsNone(r["automation"]["referencesResolved"])

    def test_matrix_over_the_decision_space_of_the_rule(self):
        # generated from what the deciding property can BE (all-None / some-True / any-False), not from
        # the one case that refuted the old code.
        base = {"crypto_ok": True, "structure_ok": True}
        for label, values, expected in (
            ("all-none", {"a_ok": None, "b_ok": None}, None),
            ("one-true", {"a_ok": True, "b_ok": None}, True),
            ("all-true", {"a_ok": True, "b_ok": True}, True),
            ("one-false", {"a_ok": False, "b_ok": None}, False),
            ("false-and-true", {"a_ok": False, "b_ok": True}, False),
        ):
            with self.subTest(case=label):
                s = automation_summary({**base, **values}, required_checks=self.CHECKS)
                self.assertIs(s["referencesResolved"], expected)

    def test_no_reference_dimension_stays_none(self):
        s = automation_summary({"crypto_ok": True, "structure_ok": True},
                               required_checks={"crypto": "crypto_ok", "structure": "structure_ok",
                                                "policy": None, "references": []})
        self.assertIsNone(s["referencesResolved"])

    def test_clamp_never_changes_safe_for_automation(self):
        # the fix is a LABELLING fix — it must not add or remove a blocker in either direction.
        s = automation_summary({"crypto_ok": True, "structure_ok": True, "a_ok": None, "b_ok": None},
                               required_checks=self.CHECKS)
        self.assertTrue(s["safeForAutomation"])
        self.assertEqual(s["automationBlockers"], [])

    def test_anti_tautology_prefix_rule_reports_the_violation(self):
        # ANTI-TAUTOLOGY TWIN: restore the 3.7.0 rule (`not unresolved`, vacuously true) behind the same
        # public entry point and drive the SAME integration probe — the label goes back to True, i.e. the
        # assertion above stops catching the planted violation.
        real = automation_verdict.automation_summary

        def prefix_summary(result, *, required_checks):
            out = real(result, required_checks=required_checks)
            keys = required_checks.get("references")
            keys = keys if isinstance(keys, (list, tuple)) else ()
            out["referencesResolved"] = (
                None if not keys
                else not [k for k in keys if isinstance(k, str) and result.get(k) is False])
            return out

        s, _pub = _keys()
        other = generate_signer().public_key().public_bytes_raw()
        env = emit_outcome_receipt(_outcome_pred(), s, strict=False)
        with mock.patch.object(automation_verdict, "automation_summary", prefix_summary):
            r = verify_outcome_receipt(env, other)
        self.assertIs(r["automation"]["referencesResolved"], True,
                      "the pre-fix rule must reproduce the vacuous True on a forged envelope")


class TestOutcomeRefEvidenceLevel(unittest.TestCase):
    """L1-SEM-03 — the wrapper was classified instead of the digest, so this level was structurally
    pinned at CLAIMED for every receipt, including the repo's own golden example."""

    def _executed_pred(self) -> dict:
        pred = copy.deepcopy(_decision_pred())
        pred["actionOutcome"] = {"status": "executed", "outcomeRef": {"digest": {"sha256": "a" * 64}}}
        return pred

    def _verify(self, **kw) -> dict:
        s, pub = _keys()
        env = emit_decision_receipt(self._executed_pred(), s, strict=True)
        return verify_decision_receipt(env, pub, strict=True, **kw)

    def test_present_outcome_ref_digest_reaches_reference_well_formed(self):
        # MUST-FAIL NEGATIVE: pre-fix the level was CLAIMED (0) for this receipt.
        level = self._verify()["evidence_levels"]["actionOutcome.outcomeRef"]
        self.assertEqual(level["level"], EvidenceLevel.REFERENCE_WELL_FORMED)
        self.assertNotIn("no well-formed sha256 digest object present", level["detail"])

    def test_resolver_can_reach_content_resolved(self):
        # pre-fix this rung was STRUCTURALLY unreachable: a resolver could never lift a wrapper that
        # never passed _is_digest in the first place.
        level = self._verify(evidence_resolver=lambda d: True)["evidence_levels"]["actionOutcome.outcomeRef"]
        self.assertEqual(level["level"], EvidenceLevel.CONTENT_RESOLVED)

    def test_the_resolver_sees_the_digest_object_not_the_wrapper(self):
        seen = []
        level = self._verify(evidence_resolver=lambda d: bool(seen.append(d)) or True)
        self.assertTrue(seen)
        self.assertIn({"sha256": "a" * 64}, seen)
        self.assertNotIn({"digest": {"sha256": "a" * 64}}, seen)
        self.assertEqual(level["evidence_levels"]["actionOutcome.outcomeRef"]["level"],
                         EvidenceLevel.CONTENT_RESOLVED)

    def test_missing_or_malformed_outcome_ref_still_claimed(self):
        # the fix must not invent evidence where there is none (both directions).
        for label, ao in (
            ("no outcomeRef", {"status": "executed"}),
            ("wrapper without digest", {"status": "executed", "outcomeRef": {"uri": "x"}}),
        ):
            with self.subTest(case=label):
                pred = copy.deepcopy(_decision_pred())
                pred["actionOutcome"] = ao
                s, pub = _keys()
                env = emit_decision_receipt(pred, s, strict=True)
                r = verify_decision_receipt(env, pub, strict=True)
                self.assertEqual(r["evidence_levels"]["actionOutcome.outcomeRef"]["level"],
                                 EvidenceLevel.CLAIMED)

    def test_not_applicable_when_status_is_not_executed(self):
        pred = copy.deepcopy(_decision_pred())
        pred["actionOutcome"] = {"status": "blocked", "outcomeRef": {"digest": {"sha256": "a" * 64}}}
        s, pub = _keys()
        env = emit_decision_receipt(pred, s, strict=True)
        r = verify_decision_receipt(env, pub, strict=True)
        self.assertIsNone(r["evidence_levels"]["actionOutcome.outcomeRef"]["level"])

    def test_legacy_boolean_is_unchanged(self):
        # backward compat: the deprecated digest-presence boolean keeps its 3.x meaning.
        self.assertIs(self._verify()["action_outcome_proven"], True)

    def test_anti_tautology_blinded_unwrapping_stops_catching_it(self):
        # ANTI-TAUTOLOGY TWIN: neutralise exactly the mechanism the fix introduced (the unwrapping step)
        # and the level falls back to the pre-fix CLAIMED — the assertion above is not a decoration.
        with mock.patch.object(decision_mod, "_as_dict", lambda v: {}):
            r = self._verify()
        self.assertEqual(r["evidence_levels"]["actionOutcome.outcomeRef"]["level"],
                         EvidenceLevel.CLAIMED)


if __name__ == "__main__":
    unittest.main()
