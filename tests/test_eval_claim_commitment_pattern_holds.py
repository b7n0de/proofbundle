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
the schema, and is: it requires `assurance_level`, bounds `n` at 2^53-1 and requires a 32-byte
samples root. What it may not do is accept something the schema rejects.

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

    PALETTE = (
        None, True, False, 0, -1, 5, 1.5, "", "x", "0.5", "sha256:x", ECHT, "SHA256:" + "a" * 64,
        [], ["0.1"], ["0.1", "0.2"], ["0.1", "0.2", "0.3"], ["x", "y"], [1, 2], {}, {"a": 1},
    )

    def setUp(self):
        super().setUp()
        self.orakel = jsonschema.Draft202012Validator(SCHEMA)

    def test_control_the_oracle_can_say_yes_and_no(self):
        self.assertEqual(list(self.orakel.iter_errors(self.basis)), [])
        falsch = dict(self.basis, model_id_commit="sha256:x")
        self.assertNotEqual(list(self.orakel.iter_errors(falsch)), [])

    def test_every_field_times_the_palette(self):
        angenommen = abgelehnt = 0
        faelle = [(feld, wert) for feld in sorted(SCHEMA["properties"]) for wert in self.PALETTE]
        # samples is an object whose constraints sit one level down; the palette cannot reach them.
        for s_n in (0, -1, 5):
            faelle.append(("samples+n", s_n))
        for feld, wert in faelle:
            claim = dict(self.basis)
            if feld == "samples+n":
                claim["n"] = max(wert, 0)
                claim["samples"] = {"root_b64": ROOT_B64, "n": wert,
                                    "leaf_alg": "sha256-rfc6962-sdjwt-v1"}
            else:
                claim[feld] = wert
            decoded = decode_eval_claim(self._hand_signed(claim))
            if decoded is None:
                abgelehnt += 1
                continue
            angenommen += 1
            with self.subTest(feld=feld, wert=wert):
                fehler = [f.message for f in self.orakel.iter_errors(claim)]
                self.assertEqual(fehler, [], f"decode_eval_claim accepted {feld}={wert!r}, "
                                             f"which the published schema rejects")
        # Both outcomes must occur, or the corpus measured nothing: all-refused would make the
        # assertion above vacuous, all-accepted would mean the boundary refuses nothing.
        self.assertGreater(angenommen, 0)
        self.assertGreater(abgelehnt, 0)


if __name__ == "__main__":
    unittest.main()
