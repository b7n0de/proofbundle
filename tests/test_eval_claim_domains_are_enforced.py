"""Every value domain the schema documents is enforced at the verify boundary.

A type is not a domain. `schemas/eval_claim_v0_1.schema.json` documents both, and the verify
boundary used to implement only part of it: `schema`, `comparator`, `threshold` and
`assurance_level` were checked, while `n`'s minimum, `metric`'s and `suite`'s minLength,
`commit_alg`'s const and the two commitment patterns were not. Measured at `bfc3f42` against
hand-signed claims: 7 of 7 were accepted, `commit_alg: "md5-plain"` among them — a signed claim
naming a commitment algorithm the receipt does not use.

The two commitment patterns closed last, with R-B1 (6.2.0), and `ci95` is the other half of that
change: it stood in the open-field list below while the schema gives it `minItems`, `maxItems` and
a pattern on its items, because the generator read only top-level keywords and so derived nothing
for it. Measured at `126ed1dc`, all three of its constraints were accepted at the boundary.

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

# Fields for which the generator below derives no case. Listed so it cannot silently produce nothing
# for them and call that coverage. Each has a TYPE and no value domain beyond it, except `samples`,
# whose constraints sit one level down in its own `properties`; the types and `samples` are held by
# tests/test_eval_claim_commitment_pattern_holds.py (with jsonschema as the oracle) and by the
# verify-side cases in tests/test_persample.py.
OHNE_DOMAENE = {"context_binding", "evaluation_card_sha256", "multiple_testing", "passed",
                "prereg_sha256", "provenance", "samples", "suite_version", "timestamp"}

# Domains the schema documents and this boundary does NOT yet enforce, each with its reason. EMPTY
# since R-B1 (6.2.0). The two commitment patterns stood here, as
# COMMIT-PATTERN-DOMAIN-NOT-AT-VERIFY-BOUNDARY-01, until the house tests that signed placeholder
# commitments (`sha256:x`) carried the form `salted_commit` produces and both boundaries enforced
# the pattern. An empty list still does its job: a gap added here that is already enforced fails.
#
# THIS LIST FAILS IN BOTH DIRECTIONS. An entry that is still open keeps the test green and keeps the
# gap visible; an entry that has since been CLOSED fails the test and asks to be deleted. An
# allowlist that only ever grows is how a temporary exception becomes permanent, and this project
# has paid for that shape before.
BEKANNTE_LUECKEN: set[tuple[str, str]] = set()


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
    # Array constraints, derived the same way. Each case keeps the array's other rules intact so it
    # is refused for the rule it names: "0" matches the decimal pattern on the schema's only array
    # (`ci95`), and the items case keeps the length at minItems.
    if regeln.get("minItems", 0) >= 1:
        aus.append(("minItems", ["0"] * (regeln["minItems"] - 1)))
    if "maxItems" in regeln:
        aus.append(("maxItems", ["0"] * (regeln["maxItems"] + 1)))
    if "pattern" in regeln.get("items", {}):
        laenge = max(regeln.get("minItems", 1), 1)
        aus.append(("items.pattern", ["does-not-match-the-pattern"] * laenge))
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
        # A generator that produced nothing would pass this test in silence. 14 is the count on the
        # schema as published: eleven top-level constraints plus the three of `ci95`.
        self.assertGreaterEqual(geprueft, 14, "the schema stopped yielding constraints — either it "
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
