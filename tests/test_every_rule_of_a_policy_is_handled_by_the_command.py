"""The gate before run 7, part five: every rule of a policy is handled by the command it is given to.

SOURCE. Deep gate run 6 at fda55f98, L3-620v6-T16-RELATIONS-RULE-NOT-APPLIED-01 (three of three jurors P1): a policy
whose relations section held only `reject_retracted: true` was accepted by `decision verify` and `outcome verify`,
which never apply that rule, and `outcome verify` printed POLICY: OK over an attached, verified retraction of its
receipt. The review before run 7 (F2) found the local repair too narrow: counting whether ANY rule applies keeps the
gap for a policy that mixes an applied rule with one the command ignores, and measurement 1 of 2026-10-01 confirmed it
(`relation_signer` beside `reject_retracted: true`: `outcome verify` POLICY: OK, `decision verify` ended like no
policy). The property, in the words of the review (owner point 4 of 2026-10-01, card OA-73db31053a):

    For every verify command each policy rule it is given is handled by the contract of that command. A rule the
    command does not support refuses the policy with exit 2, also beside a rule it supports. An applied requirement
    that is violated fails the policy. An explicitly allowed false is a handled deactivation, not a met requirement.
    POLICY: OK requires that no requirement given is left unattended.

The same rule holds for the library calls; metadata are no requirements. Owner point 6 adds the closed world per
check path: absence, an allowed deactivation and an invalid restriction stay apart, and the shared fields (validity,
purpose) belong to every receipt command's contract.

THE CONTRACT is data (`_VERTRAG`): per command and library function, the rules it applies. Every rule of the loader's
schema has an active value (it restricts or permits something) and, where the loader allows one, a deactivation value
(`_REGELN`). The cases:
* an active rule outside the contract, alone and beside a rule the command applies and that passes: refused (CLI exit
  2; a library verdict with policy_ok False);
* an active rule inside the contract: not refused as unsupported, a permission beside the requirement it serves;
* a permission or anchor trust without that requirement, in the policy or as a command-line flag: refused (deep gate
  run 7, the neighbours of T18; whether an applied rule acts at all is measured by
  `test_every_applied_rule_has_an_observable_effect.py`);
* a deactivation value beside a passing applied rule: the verdict of that rule alone;
* metadata beside a passing applied rule: the verdict of that rule alone;
* an unknown key, at the top and in a section: refused;
* measurement 1 itself: the mixed policy at decision and outcome verify;
* the control: with an applied rule violated, the policy fails (exit 3).

MEASURED when this file was added: at fda55f98 the unsupported-rule cases are red at every command, the CLI and the
library alike; the controls are green.
"""
from __future__ import annotations

import base64
import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]
for _p in (str(REPO / "src"), str(REPO / "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from proofbundle.cli import main  # noqa: E402
from proofbundle.errors import ProofBundleError  # noqa: E402

_V2 = "proofbundle/trust-policy/v0.2"
_HAUPT = Ed25519PrivateKey.from_private_bytes(b"\x51" * 32)
_FREMD = Ed25519PrivateKey.from_private_bytes(b"\x52" * 32)


def _b64(k) -> str:
    return base64.b64encode(k.public_key().public_bytes_raw()).decode("ascii")


def _kante(relation: str, ziel: str) -> dict:
    return {"relation": relation, "targetReceiptDigest": {"digestAlgorithm": "jcs-sha256-v1", "digest": ziel},
            "reasonCode": "withdrawal", "reason": "x", "declaredAt": "2026-09-29T00:00:00Z"}


#: (section or None for the top level, key) -> (an active value, a deactivation value or `_KEINE`).
_KEINE = object()
_REGELN: "dict[tuple[str | None, str], tuple[Any, Any]]" = {
    (None, "allowed_schema_versions"): (["proofbundle/v9"], []),
    (None, "allowed_issuers"): ([{"public_key_b64": _b64(_FREMD)}], []),
    (None, "valid_until"): ("2099-01-01T00:00:00Z", None),
    (None, "valid_from"): ("2020-01-01T00:00:00Z", None),
    (None, "policyPurpose"): ("eval", None),
    (None, "requiresIdentityOverlay"): (True, False),
    ("signature", "allowed_algs"): (["ed25519"], []),
    ("signature", "require_expected_signer"): (True, False),
    ("merkle", "required_hash_alg"): ("sha256-rfc6962", None),
    ("merkle", "require_authenticated_root"): (True, False),
    ("merkle", "trusted_roots"): ([base64.b64encode(b"\x07" * 32).decode()], []),
    ("sd_jwt", "require_key_binding_when_cnf_present"): (True, False),
    ("sd_jwt", "expected_aud"): ("rp.example", None),
    ("sd_jwt", "require_nonce"): (True, False),
    ("sd_jwt", "max_iat_age_seconds"): (10 ** 9, None),
    ("sd_jwt", "expected_vct"): ("https://example.org/vct", None),
    ("status", "reject_self_issued"): (True, False),
    ("status", "allowed_status_authorities"): (["https://status.example"], []),
    ("assurance", "minimum_level"): ("self_attested", None),
    ("assurance", "reject_self_attested_without_prereg"): (True, False),
    ("anchors", "require_anchor"): ("any", None),
    ("anchors", "require_anchor_target"): ("statement", None),
    ("anchors", "allow_pending"): (True, False),
    ("anchors", "trusted_tsa_roots"): (["QUJD"], _KEINE),
    ("anchors", "bitcoin_block_headers"): ({"850000": "ab" * 32}, _KEINE),
    ("anchors", "trusted_tsa_policy_oids"): (["1.2.3"], _KEINE),
    ("decision_receipt", "trusted_decision_makers"): ([{"public_key_b64": _b64(_HAUPT)}], []),
    ("decision_receipt", "allowed_decision_types"): (["preActionAuthorization", "postHocReview",
                                                      "humanEscalation", "policySimulation"], []),
    ("decision_receipt", "allowed_verdicts"): (["ALLOW", "DENY", "REFUSE", "ESCALATE", "DEFER", "OBSERVE"], []),
    ("decision_receipt", "required_evidence_relations"): (["never-present"], []),
    ("decision_receipt", "accepted_predicate_types"): (["https://example.org/other"], _KEINE),
    ("decision_receipt", "require_policy_digest"): (True, False),
    ("decision_receipt", "require_external_anchor"): (True, False),
    ("decision_receipt", "allow_pending"): (True, False),
    ("decision_receipt", "require_audience"): (True, False),
    ("decision_receipt", "require_nonce"): (True, False),
    ("decision_receipt", "require_not_checked"): (True, False),
    ("decision_receipt", "require_decision_change_conditions"): (True, False),
    ("decision_receipt", "require_trace_context"): (True, False),
    ("decision_receipt", "allow_raw_inputs"): (True, False),
    ("relations", "require_relation_resolution"): (["supersedes"], _KEINE),
    ("relations", "reject_superseded"): (True, False),
    ("relations", "reject_retracted"): (True, False),
    ("relations", "relation_signer"): ({"supersedes": {"mode": "same-key"}}, {}),
    ("relations", "require_relation_target"): ({"supersedes": "d" * 64}, {}),
}

#: Values the loader must refuse as an invalid restriction (closed world, owner point 6): a list that can never be met.
#: `accepted_predicate_types: []` accepts no predicate type, so every receipt fails under it, while the three sibling
#: lists of the section read an empty list as no rule; measured at fda55f98: decision verify exit 3, where the siblings
#: give the verdict of the policy without them. An empty allow-list that admits nothing is no deactivation.
_UNGUELTIG: "dict[tuple, Any]" = {("decision_receipt", "accepted_predicate_types"): []}

#: Fields that describe the policy and require nothing.
_METADATEN = {"generatedFromTemplate": "template:x", "deploymentReady": True}

#: A permission or trust input that acts only beside the requirement it serves, by rule -> that requirement. Deep gate
#: run 7 at 1a3cd672 (L3-620v7-T18-SET-RULE-NOT-APPLIED-AT-VERIFY-01, P2): `decision verify` took
#: ``decision_receipt.allow_pending: true`` without ``require_external_anchor`` and printed POLICY: OK, and `verify`
#: took the anchors permission and the anchor trust material without an anchor requirement; nothing applied them. Set
#: without its requirement, such a rule is refused (exit 2); beside it, it is a rule of the command's contract. This
#: table is the test's own reading of the rule, not a copy of the code's.
_ERLAUBNIS = {("anchors", "allow_pending"): ("anchors", "require_anchor"),
              ("anchors", "trusted_tsa_roots"): ("anchors", "require_anchor"),
              ("anchors", "bitcoin_block_headers"): ("anchors", "require_anchor"),
              ("anchors", "trusted_tsa_policy_oids"): ("anchors", "require_anchor"),
              ("decision_receipt", "allow_pending"): ("decision_receipt", "require_external_anchor")}

_GEMEINSAM = {(None, "valid_until"), (None, "valid_from"), (None, "policyPurpose"), (None, "requiresIdentityOverlay")}
_EVAL = ({k for k in _REGELN if k[0] in ("signature", "merkle", "sd_jwt", "status", "assurance")}
         | {(None, "allowed_schema_versions"), (None, "allowed_issuers")} | _GEMEINSAM)
_ANKER = {k for k in _REGELN if k[0] == "anchors"}
_ENTSCHEIDUNG = {k for k in _REGELN if k[0] == "decision_receipt"}
_RELATIONEN = {k for k in _REGELN if k[0] == "relations"} - {("relations", "reject_retracted")}

#: The rules each command and each library function applies. The purpose a command accepts is its own; the
#: generator gives each the purpose of its path as the active value (`_aktiv`).
_VERTRAG: "dict[str, set]" = {
    "verify": _EVAL | _ANKER,
    "decision verify": _ENTSCHEIDUNG | _RELATIONEN | _GEMEINSAM,
    "outcome verify": _RELATIONEN | _GEMEINSAM,
    "relation-statement verify": _RELATIONEN | {("relations", "reject_retracted")} | _GEMEINSAM,
    "verify_decision_receipt": _ENTSCHEIDUNG | _RELATIONEN | _GEMEINSAM,
    "verify_outcome_receipt": _RELATIONEN | _GEMEINSAM,
    "verify_relation_statement": _RELATIONEN | {("relations", "reject_retracted")} | _GEMEINSAM,
    "evaluate_policy": _EVAL,
    "evaluate_decision_policy": _ENTSCHEIDUNG | _GEMEINSAM,
}
_ZWECK = {"verify": "eval", "evaluate_policy": "eval", "decision verify": "decision",
          "verify_decision_receipt": "decision", "evaluate_decision_policy": "decision",
          "outcome verify": "outcome", "verify_outcome_receipt": "outcome",
          "relation-statement verify": None, "verify_relation_statement": None}


def _aktiv(ziel: str, regel: tuple) -> Any:
    wert = _REGELN[regel][0]
    if regel == (None, "policyPurpose"):
        return _ZWECK.get(ziel) or "outcome"
    return wert


def _politik(regeln: "dict[tuple, Any]", **oben: Any) -> dict:
    p: dict = {"schema": _V2, "policy_id": "org/rule-handling-v1", **oben}
    for (abschnitt, schluessel), wert in regeln.items():
        if abschnitt is None:
            p[schluessel] = wert
        else:
            p.setdefault(abschnitt, {})[schluessel] = wert
    return p


class _Welt:
    """A receipt of each kind, signed by `_HAUPT`, and the rule each command applies and the receipt passes (the
    anchor rule beside which an unsupported rule is measured)."""

    def __init__(self, ordner: str) -> None:
        from proofbundle import emit_bundle
        from proofbundle.anchors import statement_content_root
        from proofbundle.decision import emit_decision_receipt
        from proofbundle.dsse import load_payload
        from proofbundle.outcome import emit_outcome_receipt
        from proofbundle.relation_statement import emit_relation_statement
        self.d = Path(ordner)
        self.pub = _b64(_HAUPT)
        dpred = json.loads((REPO / "examples" / "decision_receipt_deny.json").read_text(encoding="utf-8"))
        self.decision = emit_decision_receipt(dpred, _HAUPT, strict=True)
        self.outcome = emit_outcome_receipt(
            {"schemaVersion": "0.1.0", "outcomeId": "o-rules", "decisionRef": {"sha256": "e" * 64},
             "executor": {"id": "executor:x", "keyId": "kid"}, "requestedActionDigest": {"sha256": "b" * 64},
             "status": "executed", "performedAt": "2026-07-14T10:00:00Z", "effectDigest": {"sha256": "c" * 64}},
            _HAUPT)
        self.aussage = emit_relation_statement(
            {"schemaVersion": "0.1.0", "statementId": "urn:uuid:rules", "relationships": [_kante("retracts", "a" * 64)]},
            _HAUPT)
        self.buendel = emit_bundle(b'{"x": 1}', _HAUPT)
        self.outcome_wurzel = statement_content_root(load_payload(self.outcome)).hex()
        self.ruecknahme = emit_relation_statement(
            {"schemaVersion": "0.1.0", "statementId": "urn:uuid:retract-outcome",
             "relationships": [_kante("retracts", self.outcome_wurzel)]}, _HAUPT)
        self.dateien = {name: self._schreibe(name, obj) for name, obj in (
            ("decision", self.decision), ("outcome", self.outcome), ("statement", self.aussage),
            ("bundle", self.buendel), ("retraction", self.ruecknahme))}
        self.zaehler = 0

    def _schreibe(self, name: str, obj: Any) -> str:
        p = self.d / f"{name}.json"
        p.write_text(json.dumps(obj), encoding="utf-8")
        return str(p)

    def politik_datei(self, politik: dict) -> str:
        self.zaehler += 1
        return self._schreibe(f"policy_{self.zaehler}", politik)

    #: The rule each command applies and the receipt passes.
    def anker(self, ziel: str) -> "dict[tuple, Any]":
        if ziel in ("verify", "evaluate_policy"):
            return {(None, "allowed_issuers"): [{"public_key_b64": self.pub}]}
        if ziel in ("decision verify", "verify_decision_receipt", "evaluate_decision_policy"):
            return {("decision_receipt", "trusted_decision_makers"): [{"public_key_b64": self.pub}]}
        return {("relations", "relation_signer"): {"supersedes": {"mode": "pinned", "keys": [self.pub]}}}

    def cli(self, ziel: str, politik: dict | None, *extra: str) -> "tuple[int, str]":
        basis = {"verify": ["verify", self.dateien["bundle"]],
                 "decision verify": ["decision", "verify", self.dateien["decision"], "--pub", self.pub],
                 "outcome verify": ["outcome", "verify", self.dateien["outcome"], "--pub", self.pub],
                 "relation-statement verify": ["relation-statement", "verify", self.dateien["statement"],
                                               "--pub", self.pub]}[ziel]
        argv = basis + list(extra) + (["--policy", self.politik_datei(politik)] if politik is not None else [])
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            rc = main(argv)
        return rc, out.getvalue()

    def bibliothek(self, ziel: str, politik: dict) -> "dict[str, Any]":
        from proofbundle.bundle import verify_bundle
        from proofbundle.decision import verify_decision_receipt
        from proofbundle.outcome import verify_outcome_receipt
        from proofbundle.policy import evaluate_decision_policy, evaluate_policy
        from proofbundle.relation_statement import verify_relation_statement
        roh = _HAUPT.public_key().public_bytes_raw()
        if ziel == "verify_decision_receipt":
            r = verify_decision_receipt(self.decision, roh, policy=politik)
        elif ziel == "verify_outcome_receipt":
            r = verify_outcome_receipt(self.outcome, roh, policy=politik)
        elif ziel == "verify_relation_statement":
            r = verify_relation_statement(self.aussage, roh, policy=politik)
        elif ziel == "evaluate_policy":
            r = evaluate_policy(self.buendel, verify_bundle(self.buendel), politik)
        else:
            from _decision_result_binding import bound_decision_result  # type: ignore
            aussage = json.loads(base64.b64decode(self.decision["payload"]))
            # Nachtrag 48/48b (F1): bind the result to this statement + signer so the rule under test is reached.
            r = evaluate_decision_policy(aussage, bound_decision_result(aussage, self.pub), politik,
                                         signer_public_key_b64=self.pub)
        return {"policy_ok": r.get("policy_ok"), "ok": r.get("ok")}


_CLI = ("verify", "decision verify", "outcome verify", "relation-statement verify")
_BIB = ("verify_decision_receipt", "verify_outcome_receipt", "verify_relation_statement", "evaluate_policy",
        "evaluate_decision_policy")


def _abschnitt_erlaubt(regel: tuple) -> bool:
    """Whether the loader takes the rule's section under schema v0.2 (all sections do)."""
    return True


class EveryRuleIsHandledByTheCommand(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls._td = tempfile.TemporaryDirectory(prefix="pb_rule_handling_")
        cls.w = _Welt(cls._td.name)

    @classmethod
    def tearDownClass(cls) -> None:
        cls._td.cleanup()

    def test_control_the_anchor_rule_passes_at_every_command(self) -> None:
        """Without this, a refusal of the anchor rule itself would make every mixed case pass for the wrong reason."""
        for ziel in _CLI:
            with self.subTest(command=ziel):
                self.assertEqual(self.w.cli(ziel, _politik(self.w.anker(ziel)))[0], 0)
        for ziel in _BIB:
            with self.subTest(function=ziel):
                self.assertIsNot(self.w.bibliothek(ziel, _politik(self.w.anker(ziel)))["policy_ok"], False)

    def test_an_unsupported_rule_is_refused_alone_and_beside_a_supported_one_at_the_cli(self) -> None:
        befunde = []
        for ziel in _CLI:
            for regel in sorted(_REGELN, key=str):
                if regel in _VERTRAG[ziel]:
                    continue
                for daneben in (False, True):
                    regeln = dict(self.w.anker(ziel)) if daneben else {}
                    regeln[regel] = _aktiv(ziel, regel)
                    rc, _ = self.w.cli(ziel, _politik(regeln))
                    if rc != 2:
                        befunde.append(f"{ziel}: {regel}{' beside a supported rule' if daneben else ''} -> exit {rc}")
        self.assertEqual(befunde, [], f"{len(befunde)} unsupported rules were not refused")

    def test_an_unsupported_rule_is_refused_beside_a_supported_one_in_the_library(self) -> None:
        befunde = []
        for ziel in _BIB:
            for regel in sorted(_REGELN, key=str):
                if regel in _VERTRAG[ziel]:
                    continue
                regeln = dict(self.w.anker(ziel))
                regeln[regel] = _aktiv(ziel, regel)
                if self.w.bibliothek(ziel, _politik(regeln))["policy_ok"] is not False:
                    befunde.append(f"{ziel}: {regel}")
        self.assertEqual(befunde, [], f"{len(befunde)} unsupported rules gave no policy failure")

    def test_a_supported_rule_is_not_refused_as_unsupported(self) -> None:
        """A permission is set beside the requirement it serves (`_ERLAUBNIS`); alone it is refused, which the next
        case measures."""
        befunde = []
        for ziel in _CLI:
            for regel in sorted(_VERTRAG[ziel], key=str):
                regeln = dict(self.w.anker(ziel))
                regeln[regel] = _aktiv(ziel, regel)
                if regel in _ERLAUBNIS:
                    regeln[_ERLAUBNIS[regel]] = _aktiv(ziel, _ERLAUBNIS[regel])
                rc, _ = self.w.cli(ziel, _politik(regeln))
                if rc == 2:
                    befunde.append(f"{ziel}: {regel}")
        self.assertEqual(befunde, [], f"{len(befunde)} rules of the command's contract were refused")

    def test_a_permission_without_its_requirement_is_refused(self) -> None:
        """Run 7, T18 neighbours: a permission or trust input without the requirement it serves is applied by nothing,
        so it is refused: exit 2 at every command whose contract holds it, beside the passing rule of the command, and
        policy_ok False in the library. Measured at 1a3cd672: `decision verify` exit 0 with POLICY: OK for
        ``decision_receipt.allow_pending`` alone, and `verify` exit 0 for each anchors permission and trust rule."""
        befunde = []
        for ziel in _CLI:
            for regel in sorted(set(_ERLAUBNIS) & _VERTRAG[ziel], key=str):
                regeln = dict(self.w.anker(ziel))
                regeln[regel] = _aktiv(ziel, regel)
                rc, _ = self.w.cli(ziel, _politik(regeln))
                if rc != 2:
                    befunde.append(f"{ziel}: {regel} without {_ERLAUBNIS[regel]} -> exit {rc}")
        for ziel in ("verify_decision_receipt", "evaluate_decision_policy"):
            regel = ("decision_receipt", "allow_pending")
            regeln = dict(self.w.anker(ziel))
            regeln[regel] = True
            if self.w.bibliothek(ziel, _politik(regeln))["policy_ok"] is not False:
                befunde.append(f"{ziel}: {regel} without its requirement -> policy_ok not False")
        self.assertEqual(befunde, [], "\n".join(befunde))

    def test_a_requirement_from_a_flag_lets_the_anchor_permission_of_the_policy_through(self) -> None:
        """The control of the refusal above at `verify`: the anchor requirement may come from the command line, and
        then the policy's anchors permission serves it. Exit 3 here (the bundle carries no anchor), never 2."""
        befunde = []
        for regel in sorted(k for k in _ERLAUBNIS if k[0] == "anchors"):
            regeln = dict(self.w.anker("verify"))
            regeln[regel] = _aktiv("verify", regel)
            rc, _ = self.w.cli("verify", _politik(regeln), "--require-anchor")
            if rc == 2:
                befunde.append(f"verify --require-anchor: {regel} -> exit 2")
        self.assertEqual(befunde, [], "\n".join(befunde))

    def test_anchor_trust_flags_without_a_requirement_are_refused(self) -> None:
        """The command-line neighbour from the sweep: `--bitcoin-header` and `--allow-pending` give trust and
        permission for anchors that are only checked under a requirement (`verify`) or for the anchors of `--anchors`
        (`decision verify`). Without them nothing applies the flag, and the verify ended as without it (measured at
        1a3cd672: exit 0 at both). Exit 2 now; with the requirement the flag is taken (exit 3, no anchor here)."""
        kopf = "850000:" + "ab" * 32
        faelle = [("verify", ("--bitcoin-header", kopf), 2), ("verify", ("--allow-pending",), 2),
                  ("decision verify", ("--bitcoin-header", kopf), 2),
                  ("verify", ("--bitcoin-header", kopf, "--require-anchor"), 3)]
        befunde = []
        for ziel, flaggen, erwartet in faelle:
            rc, _ = self.w.cli(ziel, _politik(self.w.anker(ziel)), *flaggen)
            if rc != erwartet:
                befunde.append(f"{ziel} {' '.join(flaggen)} -> exit {rc}, expected {erwartet}")
        self.assertEqual(befunde, [], "\n".join(befunde))

    def test_a_deactivation_and_metadata_change_nothing_beside_a_passing_rule(self) -> None:
        """The deactivation of the passing rule's own key is left out: it would replace that rule, and a policy that
        then sets no rule at all is refused like a missing one (exit 2, verify lane V3 on 6d674973), which is the
        rule for an absent policy and no deactivation case."""
        befunde = []
        for ziel in _CLI:
            erwartet = self.w.cli(ziel, _politik(self.w.anker(ziel)))[0]
            for regel, (_, aus) in sorted(_REGELN.items(), key=lambda e: str(e[0])):
                if aus is _KEINE or regel in self.w.anker(ziel):
                    continue
                regeln = dict(self.w.anker(ziel))
                regeln[regel] = aus
                rc, _ = self.w.cli(ziel, _politik(regeln))
                if rc != erwartet and regel in _VERTRAG[ziel]:
                    befunde.append(f"{ziel}: deactivated {regel} -> exit {rc}, the passing rule alone {erwartet}")
            rc, _ = self.w.cli(ziel, _politik(self.w.anker(ziel), **_METADATEN))
            if rc != erwartet:
                befunde.append(f"{ziel}: metadata -> exit {rc}, the passing rule alone {erwartet}")
        self.assertEqual(befunde, [], "\n".join(befunde))

    def test_an_unknown_key_is_refused(self) -> None:
        for ziel in _CLI:
            for wo in ("top", "section"):
                with self.subTest(command=ziel, where=wo):
                    politik = _politik(self.w.anker(ziel))
                    if wo == "top":
                        politik["relationz"] = {"reject_superseded": True}
                    else:
                        abschnitt = next((k for k in politik if isinstance(politik[k], dict)), None)
                        if abschnitt is None:
                            abschnitt = "signature"
                            politik[abschnitt] = {}
                        politik[abschnitt]["require_expected_signerr"] = True
                    self.assertEqual(self.w.cli(ziel, politik)[0], 2)

    def test_an_invalid_restriction_is_refused_at_every_command(self) -> None:
        befunde = []
        for ziel in _CLI:
            for regel, wert in _UNGUELTIG.items():
                regeln = dict(self.w.anker(ziel))
                regeln[regel] = wert
                rc, _ = self.w.cli(ziel, _politik(regeln))
                if rc != 2:
                    befunde.append(f"{ziel}: {regel} = {wert!r} -> exit {rc}")
        self.assertEqual(befunde, [], "an invalid restriction was not refused")

    def test_a_shared_field_that_fails_fails_the_policy_at_every_receipt_command(self) -> None:
        """Owner point 6: the shared fields (validity, purpose, the raw-template flag) belong to the contract of every
        receipt command, so each applies them. Beside the passing rule of the command, an expired policy, one not yet
        valid, one for another verifier path and a raw template each fail the policy: exit 3 at the CLI, policy_ok
        False in the library. Measured at fda55f98: `verify` and `decision verify` give 3, `outcome verify` and
        `relation-statement verify` give 0, and their library verifiers policy_ok True."""
        fehlschlaege = {"valid_until in the past": {(None, "valid_until"): "2020-01-01T00:00:00Z"},
                        "valid_from in the future": {(None, "valid_from"): "2099-01-01T00:00:00Z"},
                        "a purpose of another path": {(None, "policyPurpose"): "trust-pack"},
                        "a raw template": {(None, "requiresIdentityOverlay"): True}}
        befunde = []
        for ziel in _CLI:
            for name, regel in fehlschlaege.items():
                regeln = dict(self.w.anker(ziel))
                regeln.update(regel)
                rc, _ = self.w.cli(ziel, _politik(regeln))
                if rc != 3:
                    befunde.append(f"{ziel}: {name} -> exit {rc}")
        for ziel in _BIB:
            for name, regel in fehlschlaege.items():
                regeln = dict(self.w.anker(ziel))
                regeln.update(regel)
                if self.w.bibliothek(ziel, _politik(regeln))["policy_ok"] is not False:
                    befunde.append(f"{ziel}: {name} -> policy_ok not False")
        self.assertEqual(befunde, [], "\n".join(befunde))

    def test_a_near_miss_of_the_purpose_of_the_path_fails_or_is_refused(self) -> None:
        """Ledger class 48 (an expected identifier is compared exactly, and the corpus holds a near miss of each
        loosening): the purpose case above uses a wholly foreign purpose. Here each target gets near misses of its own
        purpose (trailing and leading space, upper case, a zero-width character, one character short, one more), and
        each must fail the policy or refuse it: exit 2 or 3 at the CLI, policy_ok False or a typed refusal in the
        library. A loosened comparison (strip, casefold, a prefix match) would let one through."""
        def beinahe(zweck: str) -> "list[str]":
            return [zweck + " ", " " + zweck, zweck.upper(), zweck + "​", zweck[:-1], zweck + "s"]
        befunde = []
        for ziel in _CLI:
            for wert in beinahe(_aktiv(ziel, (None, "policyPurpose"))):
                regeln = dict(self.w.anker(ziel))
                regeln[(None, "policyPurpose")] = wert
                rc, _ = self.w.cli(ziel, _politik(regeln))
                if rc not in (2, 3):
                    befunde.append(f"{ziel}: policyPurpose {wert!r} -> exit {rc}")
        for ziel in _BIB:
            for wert in beinahe(_aktiv(ziel, (None, "policyPurpose"))):
                regeln = dict(self.w.anker(ziel))
                regeln[(None, "policyPurpose")] = wert
                try:
                    urteil = self.w.bibliothek(ziel, _politik(regeln))["policy_ok"]
                except ProofBundleError:
                    continue
                if urteil is not False:
                    befunde.append(f"{ziel}: policyPurpose {wert!r} -> policy_ok {urteil!r}")
        self.assertEqual(befunde, [], "\n".join(befunde))

    def test_control_the_purpose_of_the_path_itself_passes(self) -> None:
        """The control of the near misses: the exact purpose of each path that has one passes beside the passing rule
        of the command, so the near-miss case above cannot pass by failing everything."""
        befunde = []
        for ziel in [z for z in _CLI if _ZWECK.get(z)]:
            regeln = dict(self.w.anker(ziel))
            regeln[(None, "policyPurpose")] = _ZWECK[ziel]
            rc, _ = self.w.cli(ziel, _politik(regeln))
            if rc != 0:
                befunde.append(f"{ziel}: policyPurpose {_ZWECK[ziel]!r} -> exit {rc}")
        for ziel in [z for z in _BIB if _ZWECK.get(z)]:
            regeln = dict(self.w.anker(ziel))
            regeln[(None, "policyPurpose")] = _ZWECK[ziel]
            if self.w.bibliothek(ziel, _politik(regeln))["policy_ok"] is not True:
                befunde.append(f"{ziel}: policyPurpose {_ZWECK[ziel]!r} -> policy_ok not True")
        self.assertEqual(befunde, [], "\n".join(befunde))

    def test_measurement_1_the_mixed_policy(self) -> None:
        """Measurement 1 of 2026-10-01: the receipt carries no edge, a verified retraction of its content root is
        attached, the policy holds `relation_signer` (applied, and it passes here) and `reject_retracted: true`
        (never applied by decision or outcome verify). outcome verify must not print POLICY: OK over the verified
        retraction; decision verify must not end like a verify without a policy."""
        politik = _politik({("relations", "relation_signer"): {"supersedes": {"mode": "same-key"}},
                            ("relations", "reject_retracted"): True})
        anhang = ("--with-related", self.w.dateien["retraction"])
        rc, out = self.w.cli("outcome verify", politik, *anhang)
        self.assertNotIn("POLICY: OK", out, "outcome verify printed POLICY: OK over a verified retraction")
        self.assertNotEqual(rc, 0)
        mit = self.w.cli("decision verify", politik)
        ohne = self.w.cli("decision verify", None)
        self.assertNotEqual(mit, ohne, "decision verify ended like a verify without a policy")
        self.assertEqual(mit[0], 2)

    def test_control_a_violated_applied_rule_fails_the_policy(self) -> None:
        """The policy layer can fail: a relations rule the command applies, violated by an attached verified
        retraction (`reject_superseded`), ends outcome verify with exit 3."""
        politik = _politik({("relations", "reject_superseded"): True})
        rc, _ = self.w.cli("outcome verify", politik, "--with-related", self.w.dateien["retraction"])
        self.assertEqual(rc, 3)


if __name__ == "__main__":
    unittest.main()
