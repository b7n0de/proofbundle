"""Every value domain the schema documents is enforced at the verify boundary.

A type is not a domain. `schemas/eval_claim_v0_1.schema.json` documents both, and the verify
boundary used to implement only part of it: `schema`, `comparator`, `threshold` and
`assurance_level` were checked, while `n`'s minimum, `metric`'s and `suite`'s minLength,
`commit_alg`'s const and the two commitment patterns were not. Measured at `bfc3f42` against
hand-signed claims: 7 of 7 were accepted, `commit_alg: "md5-plain"` among them — a signed claim
naming a commitment algorithm the receipt does not use.

THE CASES ARE DERIVED FROM THE SCHEMA, not listed here. A constraint added to the schema tomorrow
produces a case tomorrow, without anyone remembering to come back to this file. That is the
difference between closing this instance and closing the class: the previous round fixed the three
TYPES and left their own neighbours open, and an external review lens found that, not the author.

THE CLAIMS ARE HAND-SIGNED ON PURPOSE. `emit_eval_receipt` refuses several of these on its way out
(canonicalization rejects an over-large integer, for one), so a test that builds its cases through
the emitter measures the EMIT path and reports it as if it were the verify path. That confusion is
the emit-vs-verify asymmetry this module documents elsewhere; here it would have turned a real
finding into a false refutation.
"""
import json
import pathlib
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from proofbundle.emit import emit_bundle
from proofbundle.evalclaim import build_eval_claim, decode_eval_claim, issuer_fingerprint

REPO = pathlib.Path(__file__).resolve().parents[1]
SCHEMA = json.loads((REPO / "schemas" / "eval_claim_v0_1.schema.json").read_text())

# Fields the schema deliberately leaves open. Listed so the generator below cannot silently produce
# nothing for them and call that coverage.
OHNE_DOMAENE = {"ci95", "context_binding", "evaluation_card_sha256", "multiple_testing", "passed",
                "prereg_sha256", "provenance", "samples", "suite_version", "timestamp"}

# Domains the schema documents and this boundary does NOT yet enforce, each with its reason. The
# two commitment patterns are correct to enforce and `salted_commit` always produces that form, but
# five existing CLI tests sign claims with placeholder commitments (`sha256:x`), so the check turns
# them red. That is its own change with its own measurement, not a passenger on a release cut whose
# order adds no scope. Carried as COMMIT-PATTERN-DOMAIN-NOT-AT-VERIFY-BOUNDARY-01, target 6.2.0.
#
# THIS LIST FAILS IN BOTH DIRECTIONS. An entry that is still open keeps the test green and keeps the
# gap visible; an entry that has since been CLOSED fails the test and asks to be deleted. An
# allowlist that only ever grows is how a temporary exception becomes permanent, and this project
# has paid for that shape before.
BEKANNTE_LUECKEN = {
    ("model_id_commit", "pattern"),
    ("dataset_id_commit", "pattern"),
}


def _verletzungen(feld, regeln):
    """One value per documented constraint that must violate it."""
    aus = []
    if "minimum" in regeln:
        aus.append(("minimum", regeln["minimum"] - 1))
    if "maximum" in regeln:
        aus.append(("maximum", regeln["maximum"] + 1))
    if regeln.get("minLength", 0) >= 1:
        aus.append(("minLength", ""))
    if "const" in regeln:
        aus.append(("const", f"not-{regeln['const']}"))
    if "enum" in regeln:
        aus.append(("enum", "not-a-member-of-the-enum"))
    if "pattern" in regeln:
        aus.append(("pattern", "does-not-match-the-pattern"))
    return aus


class TestEveryDocumentedDomainIsEnforced(unittest.TestCase):

    def setUp(self):
        self.signer = Ed25519PrivateKey.generate()
        claim, _salts = build_eval_claim(
            suite="safety-refusal", suite_version="v1", metric="refusal_rate",
            comparator=">=", threshold="0.80", score="0.92", n=500,
            model_id="acme/model-x", dataset_id="acme/dataset-y",
            issuer=issuer_fingerprint(self.signer), timestamp="2026-09-19T12:00:00Z",
            model_salt=b"0" * 16, dataset_salt=b"1" * 16)
        self.basis = dict(claim)
        self.basis["issuer"] = issuer_fingerprint(self.signer)

    def _hand_signed(self, claim):
        # Past emit_eval_receipt's own checks, straight to a correctly signed bundle.
        roh = json.dumps(claim, sort_keys=True, separators=(",", ":")).encode()
        return emit_bundle(roh, self.signer)

    def test_control_the_hand_signed_basis_is_accepted(self):
        # Without this, every rejection below would be meaningless.
        self.assertIsInstance(decode_eval_claim(self._hand_signed(self.basis)), dict)

    def test_every_documented_domain_rejects_a_violating_value(self):
        geprueft = 0
        for feld, regeln in sorted(SCHEMA.get("properties", {}).items()):
            for art, wert in _verletzungen(feld, regeln):
                geprueft += 1
                with self.subTest(feld=feld, regel=art, wert=wert):
                    claim = dict(self.basis)
                    claim[feld] = wert
                    ergebnis = decode_eval_claim(self._hand_signed(claim))
                    if (feld, art) in BEKANNTE_LUECKEN:
                        self.assertIsNotNone(
                            ergebnis,
                            f"{feld}'s {art} is now enforced — delete its entry from "
                            f"BEKANNTE_LUECKEN, the gap it documents is closed")
                        continue
                    self.assertIsNone(ergebnis,
                                      f"{feld} violates its documented {art} and was accepted")
        # A generator that produced nothing would pass this test in silence.
        self.assertGreaterEqual(geprueft, 11, "the schema stopped yielding constraints — either it "
                                              "changed or the generator no longer reads it")

    def test_the_upper_bound_from_the_prose_spec_is_enforced_too(self):
        # EVAL_CLAIM.md states `0 <= n <= 2^53-1`; the JSON schema carries only the lower bound, so
        # this one case cannot be derived from the schema and is named here on purpose.
        claim = dict(self.basis)
        claim["n"] = 2 ** 53
        self.assertIsNone(decode_eval_claim(self._hand_signed(claim)))

    def test_the_open_fields_stay_open(self):
        # The counter-direction: a field the schema does NOT constrain must not be rejected, or the
        # guard above would be quietly stricter than the contract it claims to enforce.
        claim = dict(self.basis)
        claim["suite_version"] = ""
        self.assertIsInstance(decode_eval_claim(self._hand_signed(claim)), dict)
        self.assertTrue(OHNE_DOMAENE, "the open-field list is the documented half of this contract")


if __name__ == "__main__":
    unittest.main()
