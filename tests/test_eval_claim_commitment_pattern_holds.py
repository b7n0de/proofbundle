"""R-B1: the commitment pattern holds at the verify boundary and at emit, and so does the rest of
the published schema.

`schemas/eval_claim_v0_1.schema.json` documents `^sha256:[0-9a-f]{64}$` for `model_id_commit` and
`dataset_id_commit`. `salted_commit` always produces that form, and `evalclaim._COMMIT_RE` carried
the pattern with its `\\A..\\Z` anchors. Nothing called it. Measured at `126ed1dc` with correctly
signed, hand-built claims: `sha256:x`, `not-a-commitment`, upper-case hex and a bare `x` each
decoded and `classify_eval_claim` answered `valid`; `emit_eval_receipt` signed `sha256:x`; and
`proofbundle show-eval --expect-issuer <the signer>` printed `commit sha256:x` and then `=> OK`,
exit 0. Register entry `COMMIT-PATTERN-DOMAIN-NOT-AT-VERIFY-BOUNDARY-01`.

THE CLASS IS WIDER THAN THE TWO FIELDS, and the second half of this file is about the class. The
invariant: nothing `decode_eval_claim` accepts is rejected by the schema the package publishes. A
sweep of every property at `126ed1dc` found more fields the boundary carried through unchecked:
the types of `suite_version`, `timestamp`, `context_binding`, `multiple_testing`,
`prereg_sha256`, `evaluation_card_sha256` and `provenance`, the shape of `ci95` (exactly two
decimal strings), the minimum of 1 on `samples.n`, and null in an optional field, which the
boundary read as absent while the schema types the field. The oracle for that half is not this
package's own reading of the schema. It is `jsonschema`, a separate implementation, given the same
file, so a boundary and a test that shared one misreading could not agree with each other.
Measured with the corpus below (444 hand-signed claims): on `126ed1dc` the boundary accepted 171
that the schema rejects, after this change none.

The direction of that oracle is one way on purpose. The boundary is allowed to be STRICTER than
the schema, and is: it bounds `n` at 2^53-1 and requires a 32-byte samples root. What it may not do
is accept something the schema rejects. On REQUIRED fields the two must agree exactly, and did not:
the schema left `assurance_level` optional while the boundary refused a claim without it.

THE EMITTER IS THE OTHER HALF OF THE CLASS: proofbundle must not sign a claim its own verifier
refuses. After R-B1 the emitter still ran only part of the verifier's checks and signed 14 of 15
probe claims that decode refused (measured at `2290d6c1`), plus claims past the verifier's resource
limits. Both now run one validation, `_claim_violation` in the module, and the property case below
holds that emit refuses exactly when decode refuses, over the same generated corpus.

THE CLAIMS ARE HAND-SIGNED where the verify boundary is the question, for the reason
`test_eval_claim_domains_are_enforced.py` gives: a case built through the emitter measures the
emitter. The emitter is measured separately, as its own boundary.
"""
import base64
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

try:
    import jsonschema
except ImportError:  # pragma: no cover - the [test] extra carries it; a bare install skips
    jsonschema = None

from proofbundle.bundle import verify_bundle
from proofbundle.emit import emit_bundle, generate_signer
from proofbundle.evalclaim import (
    CLAIM_INVALID,
    CLAIM_VALID,
    EvalClaimError,
    build_eval_claim,
    classify_eval_claim,
    decode_eval_claim,
    emit_eval_receipt,
    issuer_fingerprint,
    salted_commit,
)

REPO = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((REPO / "schemas" / "eval_claim_v0_1.schema.json").read_text(encoding="utf-8"))

COMMIT_FIELDS = ("model_id_commit", "dataset_id_commit")
ECHT = "sha256:" + "a" * 64

# The four the finding named, then the neighbours of each: a non-string of every JSON type, the
# right prefix with the wrong length, the right length with a trailing newline (the case `$` lets
# through and `\Z` does not), another algorithm label, a capitalised label, a character outside
# hex, a leading space, and the empty string.
PLATZHALTER = (
    "sha256:x", "not-a-commitment", "sha256:" + "A" * 64, "x",
    5, 1.5, None, True, [ECHT], {"sha256": "a" * 64},
    "sha256:" + "a" * 63, "sha256:" + "a" * 65, ECHT + "\n", "SHA256:" + "a" * 64,
    "sha512:" + "a" * 64, "sha256:" + "g" * 64, " " + ECHT, "",
)

# Each value is outside what the schema documents for its field, and each was ACCEPTED at the
# verify boundary on `126ed1dc`.
NACHBARN = (
    ("suite_version", 5), ("suite_version", None),
    ("timestamp", 5), ("timestamp", None),
    ("context_binding", 5), ("multiple_testing", 5),
    ("prereg_sha256", 5), ("prereg_sha256", []),
    ("evaluation_card_sha256", 5),
    ("provenance", "x"), ("provenance", []),
    ("ci95", "x"), ("ci95", ["0.1"]), ("ci95", ["0.1", "0.2", "0.3"]),
    ("ci95", ["nan", "inf"]), ("ci95", [1, 2]),
    # null is not "absent": the schema types each of these, and null is none of the types.
    ("context_binding", None), ("prereg_sha256", None), ("ci95", None),
    ("provenance", None), ("samples", None),
)

# Values inside the schema, for the same fields. The counter-direction: a guard that refused all of
# these would pass every case above and be wrong.
GUELTIG = (
    ("suite_version", ""), ("timestamp", ""),
    ("context_binding", "run-A"), ("multiple_testing", "bonferroni"),
    ("prereg_sha256", "b" * 64), ("evaluation_card_sha256", "c" * 64),
    ("provenance", {}), ("provenance", {"harness": "inspect_ai"}),
    ("ci95", ["0.81", "0.95"]), ("ci95", ["-1", "2.50"]),
)

ROOT_B64 = base64.b64encode(bytes(range(32))).decode("ascii")

# Every JSON type, and the near-misses of the documented patterns.
PALETTE = (
    None, True, False, 0, -1, 5, 1.5, "", "x", "0.5", "sha256:x", ECHT, "SHA256:" + "a" * 64,
    [], ["0.1"], ["0.1", "0.2"], ["0.1", "0.2", "0.3"], ["x", "y"], [1, 2], {}, {"a": 1},
)


def _samples(n):
    return {"root_b64": ROOT_B64, "n": n, "leaf_alg": "sha256-rfc6962-sdjwt-v1"}


def _korpus(basis, *, mit_loeschungen):
    """(label, claim) pairs: every schema property set to every palette value, the samples cases the
    palette cannot reach (its constraints sit one level down), and optionally every property removed.
    The oracle below measures without removals, so its published numbers keep their corpus."""
    faelle = []
    for feld in sorted(SCHEMA["properties"]):
        for wert in PALETTE:
            faelle.append((f"{feld}={wert!r}", dict(basis, **{feld: wert})))
        if mit_loeschungen:
            faelle.append((f"without {feld}", {k: v for k, v in basis.items() if k != feld}))
    for s_n in (0, -1, 5):
        faelle.append((f"samples.n={s_n}", dict(basis, n=max(s_n, 0), samples=_samples(s_n))))
    return faelle


# The probes that measured the emit gap: at 2290d6c1 the emitter signed 14 of the first 15 and decode
# refused all of them. The sixteenth is samples.n == 0, which R-B1 closed at decode and not at emit.
PROBEN = (
    ("comparator", "=="), ("threshold", "inf"), ("threshold", "1e2"), ("passed", "false"),
    ("n", "5"), ("n", -1), ("n", 2 ** 53), ("metric", ""), ("suite", ""), ("suite", 5),
    ("commit_alg", "md5-plain"), ("schema", "x"),
    ("samples", {"root_b64": ROOT_B64, "n": 3, "leaf_alg": "sha256-rfc6962-sdjwt-v1"}),
    ("samples", {"root_b64": ROOT_B64, "n": 500, "leaf_alg": "md5"}),
    ("samples", {"root_b64": "c2hvcnQ=", "n": 500, "leaf_alg": "sha256-rfc6962-sdjwt-v1"}),
)


def _run(*args):
    return subprocess.run([sys.executable, "-B", "-m", "proofbundle.cli", *args],
                          capture_output=True, text=True, cwd=REPO,
                          env={"PYTHONPATH": str(REPO / "src"), "PYTHONDONTWRITEBYTECODE": "1"})


class _Basis(unittest.TestCase):

    def setUp(self):
        self.signer = generate_signer()
        claim, _salts = build_eval_claim(
            suite="safety-refusal", suite_version="v1", metric="refusal_rate",
            comparator=">=", threshold="0.80", score="0.92", n=500,
            model_id="acme/model-x", dataset_id="acme/dataset-y",
            issuer=issuer_fingerprint(self.signer), timestamp="2026-09-19T12:00:00Z",
            model_salt=b"0" * 16, dataset_salt=b"1" * 16)
        self.basis = dict(claim)

    def _hand_signed(self, claim):
        # Past emit_eval_receipt's own checks, straight to a correctly signed bundle.
        roh = json.dumps(claim, sort_keys=True, separators=(",", ":")).encode()
        return emit_bundle(roh, self.signer)


class TestTheCommitmentPatternAtTheVerifyBoundary(_Basis):

    def test_control_the_salted_commit_form_decodes_and_classifies_valid(self):
        bundle = self._hand_signed(self.basis)
        self.assertEqual(self.basis["model_id_commit"],
                         salted_commit("acme/model-x", b"0" * 16))
        self.assertIsInstance(decode_eval_claim(bundle), dict)
        self.assertEqual(classify_eval_claim(bundle)[0], CLAIM_VALID)

    def test_every_placeholder_is_refused_in_either_field(self):
        for feld in COMMIT_FIELDS:
            for wert in PLATZHALTER:
                with self.subTest(feld=feld, wert=wert):
                    claim = dict(self.basis)
                    claim[feld] = wert
                    bundle = self._hand_signed(claim)
                    self.assertTrue(verify_bundle(bundle).ok, "nothing is forged, the signature holds")
                    # decode's documented contract is None on any failure; classify is the typed one.
                    self.assertIsNone(decode_eval_claim(bundle))
                    self.assertEqual(classify_eval_claim(bundle), (CLAIM_INVALID, None))


class TestTheCommitmentPatternAtEmit(_Basis):

    def test_control_the_emitter_signs_the_salted_commit_form(self):
        decoded = decode_eval_claim(emit_eval_receipt(self.basis, self.signer))
        self.assertIsInstance(decoded, dict)
        self.assertEqual(decoded["dataset_id_commit"], self.basis["dataset_id_commit"])

    def test_the_emitter_refuses_every_placeholder_and_names_the_field(self):
        for feld in COMMIT_FIELDS:
            for wert in PLATZHALTER:
                with self.subTest(feld=feld, wert=wert):
                    claim = dict(self.basis)
                    claim[feld] = wert
                    with self.assertRaises(EvalClaimError) as ctx:
                        emit_eval_receipt(claim, self.signer)
                    self.assertIn(feld, str(ctx.exception))


class TestTheShippedCliRefusesAPlaceholder(_Basis):
    """The surface a relying party runs. `--expect-issuer` pins the signer, and the pin held on
    `126ed1dc`: the receipt WAS signed by the pinned key. What it did not do was make the claim
    well-formed, and the CLI printed the placeholder as a commitment under `=> OK`."""

    def _write(self, d, bundle, name="receipt.json"):
        pfad = os.path.join(d, name)
        Path(pfad).write_text(json.dumps(bundle), encoding="utf-8")
        return pfad

    def test_control_a_real_commitment_passes_with_the_pinned_issuer(self):
        with tempfile.TemporaryDirectory() as d:
            pfad = self._write(d, self._hand_signed(self.basis))
            r = _run("show-eval", pfad, "--expect-issuer", issuer_fingerprint(self.signer))
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("=> OK", r.stdout)

    def test_a_placeholder_fails_even_with_the_pinned_issuer(self):
        claim = dict(self.basis)
        claim["model_id_commit"] = "sha256:x"
        with tempfile.TemporaryDirectory() as d:
            pfad = self._write(d, self._hand_signed(claim))
            r = _run("show-eval", pfad, "--expect-issuer", issuer_fingerprint(self.signer))
            self.assertNotEqual(r.returncode, 0)
            self.assertEqual(r.returncode, 1, r.stderr)
            self.assertIn("FAILED", r.stderr)
            self.assertNotIn("=> OK", r.stdout)
            self.assertNotIn("sha256:x", r.stdout)
            self.assertNotIn("Traceback", r.stderr)

    def test_emit_eval_refuses_a_claim_the_verifier_refuses_and_writes_nothing(self):
        claim = dict(self.basis)
        claim["comparator"] = "=="
        with tempfile.TemporaryDirectory() as d:
            claim_pfad = os.path.join(d, "claim.json")
            Path(claim_pfad).write_text(json.dumps(claim), encoding="utf-8")
            out = os.path.join(d, "receipt.json")
            r = _run("emit-eval", "--claim", claim_pfad, "--out", out,
                     "--new-key", os.path.join(d, "k.key"))
            self.assertEqual(r.returncode, 2, r.stderr)
            self.assertIn("comparator", r.stderr)
            self.assertFalse(os.path.exists(out), "a refused claim must not leave a receipt behind")
            self.assertNotIn("Traceback", r.stderr)

    def test_emit_eval_refuses_a_placeholder_claim_file_and_writes_nothing(self):
        claim = dict(self.basis)
        claim["dataset_id_commit"] = "sha256:y"
        with tempfile.TemporaryDirectory() as d:
            claim_pfad = os.path.join(d, "claim.json")
            Path(claim_pfad).write_text(json.dumps(claim), encoding="utf-8")
            out = os.path.join(d, "receipt.json")
            r = _run("emit-eval", "--claim", claim_pfad, "--out", out,
                     "--new-key", os.path.join(d, "k.key"))
            self.assertEqual(r.returncode, 2, r.stderr)
            self.assertIn("dataset_id_commit", r.stderr)
            self.assertFalse(os.path.exists(out), "a refused claim must not leave a receipt behind")
            self.assertNotIn("Traceback", r.stderr)


class TestTheSweptNeighboursHoldAtBothBoundaries(_Basis):

    def test_the_verify_boundary_refuses_each(self):
        for feld, wert in NACHBARN:
            with self.subTest(feld=feld, wert=wert):
                claim = dict(self.basis)
                claim[feld] = wert
                self.assertIsNone(decode_eval_claim(self._hand_signed(claim)))

    def test_the_emitter_refuses_each_and_names_the_field(self):
        for feld, wert in NACHBARN:
            with self.subTest(feld=feld, wert=wert):
                claim = dict(self.basis)
                claim[feld] = wert
                with self.assertRaises(EvalClaimError) as ctx:
                    emit_eval_receipt(claim, self.signer)
                self.assertIn(feld, str(ctx.exception))

    def test_counter_direction_values_inside_the_schema_pass_both_boundaries(self):
        for feld, wert in GUELTIG:
            with self.subTest(feld=feld, wert=wert):
                claim = dict(self.basis)
                claim[feld] = wert
                self.assertIsInstance(decode_eval_claim(self._hand_signed(claim)), dict)
                self.assertIsInstance(decode_eval_claim(emit_eval_receipt(claim, self.signer)), dict)

    def test_samples_n_has_a_minimum_of_one_at_the_verify_boundary(self):
        # samples.n must equal n, so the only way to reach samples.n == 0 is n == 0 as well. The
        # equality check passed that pair; the schema's `minimum: 1` did not exist on this path.
        claim = dict(self.basis, n=0, samples={"root_b64": ROOT_B64, "n": 0,
                                                "leaf_alg": "sha256-rfc6962-sdjwt-v1"})
        self.assertIsNone(decode_eval_claim(self._hand_signed(claim)))
        kontrolle = dict(self.basis, n=5, samples={"root_b64": ROOT_B64, "n": 5,
                                                    "leaf_alg": "sha256-rfc6962-sdjwt-v1"})
        self.assertIsInstance(decode_eval_claim(self._hand_signed(kontrolle)), dict)

    def test_a_nan_interval_from_the_builder_does_not_reach_a_signature(self):
        # A-19 (P3 of the 2026-09-19 audit): build_eval_claim runs str() over ci95 before its float
        # ban, so [nan, inf] arrives as ["nan", "inf"]. The builder still does that; what changed
        # is that the emitter no longer signs the result, because it is not a decimal string.
        claim, _ = build_eval_claim(
            suite="s", suite_version="1", metric="acc", comparator=">=", threshold="0.80",
            score="0.92", n=10, model_id="m", dataset_id="d",
            issuer=issuer_fingerprint(self.signer), timestamp="2026-09-19T12:00:00Z",
            ci95=[float("nan"), float("inf")])
        self.assertEqual(claim["ci95"], ["nan", "inf"])
        with self.assertRaises(EvalClaimError) as ctx:
            emit_eval_receipt(claim, self.signer)
        self.assertIn("ci95", str(ctx.exception))


@unittest.skipIf(jsonschema is None, "jsonschema not installed (pip install -e .[test])")
class TestNothingTheBoundaryAcceptsIsRejectedByTheSchema(_Basis):
    """The class invariant, held by an independent oracle over a generated corpus.

    Every schema property is set, one at a time, to every value of a palette that covers each JSON
    type and the near-misses of the documented patterns. Whatever `decode_eval_claim` accepts is
    handed to `jsonschema`, which must find no error in it.
    """

    def setUp(self):
        super().setUp()
        self.orakel = jsonschema.Draft202012Validator(SCHEMA)

    def test_control_the_oracle_can_say_yes_and_no(self):
        self.assertEqual(list(self.orakel.iter_errors(self.basis)), [])
        falsch = dict(self.basis, model_id_commit="sha256:x")
        self.assertNotEqual(list(self.orakel.iter_errors(falsch)), [])

    def test_every_field_times_the_palette(self):
        angenommen = abgelehnt = 0
        for fall, claim in _korpus(self.basis, mit_loeschungen=False):
            decoded = decode_eval_claim(self._hand_signed(claim))
            if decoded is None:
                abgelehnt += 1
                continue
            angenommen += 1
            with self.subTest(fall=fall):
                fehler = [f.message for f in self.orakel.iter_errors(claim)]
                self.assertEqual(fehler, [], f"decode_eval_claim accepted {fall}, "
                                             f"which the published schema rejects")
        # Both outcomes must occur, or the corpus measured nothing: all-refused would make the
        # assertion above vacuous, all-accepted would mean the boundary refuses nothing.
        self.assertGreater(angenommen, 0)
        self.assertGreater(abgelehnt, 0)

    def test_the_schema_and_the_boundary_agree_on_what_is_required(self):
        """Removing a field: the oracle finds an error exactly when the boundary refuses the claim.

        Here the direction is BOTH ways, unlike the palette case above. A field the verifier cannot
        do without must be one the schema requires, or the schema tells a reader that a claim is
        complete when the verifier will refuse it. Measured at `2290d6c1`: `assurance_level` was the
        one disagreement, optional in the schema and required at the boundary since 1.9.2 (F3).
        """
        for feld in sorted(SCHEMA["properties"]):
            with self.subTest(feld=feld):
                ohne = {k: v for k, v in self.basis.items() if k != feld}
                boundary_refuses = decode_eval_claim(self._hand_signed(ohne)) is None
                schema_refuses = bool(list(self.orakel.iter_errors(ohne)))
                self.assertEqual(
                    boundary_refuses, schema_refuses,
                    f"without {feld}: the boundary {'refuses' if boundary_refuses else 'accepts'} "
                    f"and the schema {'refuses' if schema_refuses else 'accepts'}")


class TestTheEmitterSignsExactlyWhatTheVerifierAccepts(_Basis):
    """One validation for both boundaries, measured from the outside.

    The emitter makes two normalizations before it validates, and they are its documented behaviour,
    not a gap: it sets `issuer` to its own signer and defaults a missing `assurance_level` to
    `self_attested`. So the claim decode is asked about is the one the emitter would sign.
    """

    def _mit(self, feld, wert):
        claim = dict(self.basis)
        if feld == "samples":
            claim["n"] = 500
        claim[feld] = wert
        return claim

    def test_each_probe_is_refused_by_the_emitter_and_named(self):
        for feld, wert in PROBEN:
            with self.subTest(feld=feld, wert=wert):
                claim = self._mit(feld, wert)
                self.assertIsNone(decode_eval_claim(self._hand_signed(claim)),
                                  "the probe must be one the verifier refuses")
                with self.assertRaises(EvalClaimError) as ctx:
                    emit_eval_receipt(claim, self.signer)
                # The reason STARTS with the field. `assertIn("n", ...)` would pass for any English
                # sentence, and the canonicalizer's own refusal of 2**53 does not name the field.
                self.assertTrue(str(ctx.exception).startswith(feld), str(ctx.exception))

    def test_samples_n_zero_is_refused_by_the_emitter_too(self):
        # Closed at decode by R-B1 and still signed by the emitter at 2290d6c1.
        claim = dict(self.basis, n=0, samples=_samples(0))
        with self.assertRaises(EvalClaimError) as ctx:
            emit_eval_receipt(claim, self.signer)
        self.assertIn("samples.n", str(ctx.exception))

    def test_the_verifier_limits_hold_at_the_emitter(self):
        """Sizes the verifier refuses are not signed either. Measured at 2290d6c1: all three signed.

        These are refused after canonicalization and before signing, because a payload's size exists
        only once it is serialized; the emitter reads its own bytes with decode's readers."""
        def tief(k):
            x = {}
            for _ in range(k):
                x = {"a": x}
            return x
        for fall, provenance in (("nested 70 deep", tief(70)),
                                 ("250 000 list items", {"l": list(range(250_000))}),
                                 ("payload_b64 past 1 000 000 characters", {"x": "a" * 900_000})):
            with self.subTest(fall=fall):
                claim = dict(self.basis, provenance=provenance)
                self.assertIsNone(decode_eval_claim(self._hand_signed(claim)))
                with self.assertRaises(EvalClaimError) as ctx:
                    emit_eval_receipt(claim, self.signer)
                self.assertIn("limit of the verifier", str(ctx.exception))
        kontrolle = dict(self.basis, provenance=tief(62))
        self.assertIsInstance(decode_eval_claim(emit_eval_receipt(kontrolle, self.signer)), dict)

    def test_emit_refuses_exactly_when_decode_refuses(self):
        """THE PROPERTY, over the palette corpus with removals plus the probes."""
        fp = issuer_fingerprint(self.signer)
        faelle = _korpus(self.basis, mit_loeschungen=True)
        faelle += [(f"probe {f}={w!r}", self._mit(f, w)) for f, w in PROBEN]
        beide_nehmen = beide_lehnen_ab = 0
        for fall, claim in faelle:
            with self.subTest(fall=fall):
                normal = dict(claim, issuer=fp)
                normal.setdefault("assurance_level", "self_attested")
                decode_nimmt = decode_eval_claim(self._hand_signed(normal)) is not None
                try:
                    signiert = emit_eval_receipt(claim, self.signer)
                except EvalClaimError:
                    signiert = None
                self.assertEqual(signiert is not None, decode_nimmt,
                                 f"{fall}: emit {'signed' if signiert else 'refused'}, decode "
                                 f"{'accepts' if decode_nimmt else 'refuses'}")
                if signiert is not None:
                    self.assertIsInstance(decode_eval_claim(signiert), dict,
                                          f"{fall}: the emitter signed what decode refuses")
                    beide_nehmen += 1
                else:
                    beide_lehnen_ab += 1
        # Both outcomes occur, or the agreement would be vacuous.
        self.assertGreater(beide_nehmen, 0)
        self.assertGreater(beide_lehnen_ab, 0)

    def test_outside_the_canonical_profile_the_emitter_is_stricter_never_looser(self):
        """Where the two may differ, and in which direction. The emitter enforces the canonicalization
        profile (EVAL_CLAIM.md section 4: NFC strings, no floats), and the verify path never
        canonicalizes, so it does not re-check it. Measured at this commit: decode ACCEPTS a
        hand-signed claim with a decomposed `suite` or a float inside `provenance`; the emitter
        refuses both. That is the one direction a difference is allowed to run.

        NOT A CATCH PROOF: green before this change and after it. It states the direction so that the
        property above, which excludes these inputs by construction, is not read as covering them."""
        for fall, claim in (("decomposed suite", dict(self.basis, suite="cafe\u0301")),
                            ("float in provenance", dict(self.basis, provenance={"stderr": 0.5}))):
            with self.subTest(fall=fall):
                with self.assertRaises(EvalClaimError):
                    emit_eval_receipt(claim, self.signer)


if __name__ == "__main__":
    unittest.main()
