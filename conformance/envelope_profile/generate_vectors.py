#!/usr/bin/env python3
"""Generate the receipt-envelope-profile conformance vectors (run ONCE, fixtures are committed bytes).

Provenance: docs/RECEIPT_ENVELOPE_PROFILE.md (v0.1, PROPOSED — an Owner decision, not adopted).
Ten vectors, one COUNTER-PROOF and one POSITIVE CONTROL per rule R1 to R5. R6 has no vector of its
own: R6 says every rule ships its counter-proof, so R6 is satisfied BY this corpus existing, not by
a case inside it — a case asserting "the cases exist" would be the tautology the profile warns about.

Every vector runs through OUR OWN emit and verify path. A profile whose vectors are checked by a
separate mock proves something about the mock.

All signing keys are FRESH THROWAWAY TEST KEYS generated at build time and never stored. Regeneration
changes bytes — rerun, re-review the diff, recommit. Never hand-edit generated fixtures.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "src"))

from proofbundle.emit import emit_bundle, generate_signer  # noqa: E402
from proofbundle.evalclaim import (  # noqa: E402
    build_eval_claim,
    canonicalize,
    decode_eval_claim,
    emit_eval_receipt,
)

HERE = pathlib.Path(__file__).resolve().parent
TS = "2026-08-30T00:00:00Z"


def _base(signer, **over):
    kw = dict(suite="safety-refusal", suite_version="v1", metric="refusal_rate", comparator=">=",
              threshold="0.80", score="0.92", n=500, model_id="acme/model-x",
              dataset_id="acme/dataset-y", issuer="ed25519:placeholder", timestamp=TS)
    kw.update(over)
    claim, _ = build_eval_claim(**kw)
    return claim


def _write(name: str, case: dict, files: dict) -> None:
    d = HERE / name
    d.mkdir(parents=True, exist_ok=True)
    (d / "case.json").write_text(json.dumps(case, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    for fn, obj in files.items():
        (d / fn).write_text(json.dumps(obj, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"  {name}")


def main() -> int:
    s = generate_signer()

    # ── R1 canonicalization ────────────────────────────────────────────────────────────────────
    # The object is deliberately non-ASCII: that is the ONLY axis on which the two serializations
    # diverge. Ordering and numbers are RFC-8785-correct in both, which is exactly why a corpus of
    # ASCII-only vectors cannot see this and an earlier pass of ours reported "no finding".
    # Covers BOTH axes that can arise in this format at once: the UTF-16 key ordering (the emoji
    # sorts FIRST by code units, LAST by code points) and non-ASCII escaping. Measured: the legacy
    # serialization gets both wrong on this one object.
    obj = {"\U0001F600": 2, "\uFF3A": 1, "café": 3, "b": 4, "a": [1, 2, 3]}
    _write("r1-positive-control-canonical-root", {
        "caseId": "envelope-profile-r1-positive-control-canonical-root",
        "kind": "envelope_profile_rule", "rule": "R1", "role": "positive_control",
        "input": "object.json",
        "attribution": "receipt-envelope-profile v0.1 R1 — one normative canonicalization (RFC 8785)",
        "expected": {"contentRootHex": hashlib.sha256(canonicalize(obj)).hexdigest()},
        "specRefs": ["docs/RECEIPT_ENVELOPE_PROFILE.md", "docs/SCITT_CPB_MAPPING.md", "RFC 8785"],
        "rationale": "Our emit path canonicalizes with the real RFC 8785 serializer and must reproduce "
                     "this content root byte for byte. An implementation that produces a different root "
                     "for this object is not running one normative canonicalization.",
    }, {"object.json": obj})

    _write("r1-counter-proof-nonconformant-serializer-diverges", {
        "caseId": "envelope-profile-r1-counter-proof-nonconformant-serializer-diverges",
        "kind": "envelope_profile_rule", "rule": "R1", "role": "counter_proof",
        "input": "object.json",
        "attribution": "receipt-envelope-profile v0.1 R1 — measured 2026-08-28 against inspect-receipts@397ae3ad",
        "expected": {"nonConformantDiffers": True},
        "specRefs": ["docs/RECEIPT_ENVELOPE_PROFILE.md", "RFC 8785"],
        "rationale": "The counter-proof that makes R1 load-bearing: a json.dumps(sort_keys=True, "
                     "ensure_ascii=True) serialization of the SAME object must produce a DIFFERENT "
                     "content root. If the two agreed, R1 would be an empty requirement. The divergence "
                     "is string escaping alone — \\uXXXX against raw UTF-8 — which is why three "
                     "ASCII-only vectors did not isolate it.",
    }, {"object.json": obj})

    # Divergence vectors 2 and 3 from the issue thread — the small exponent (1e-7) and the
    # integer-valued float (2.0) — CANNOT ARISE in this format: the claim profile refuses Python
    # floats outright and requires decimal STRINGS. Shipping a byte-comparison vector for them would
    # be theatre. The honest counter-proof for those two axes is the refusal itself, so it gets one.
    _write("r1-counter-proof-float-is-refused-so-two-axes-cannot-arise", {
        "caseId": "envelope-profile-r1-counter-proof-float-is-refused-so-two-axes-cannot-arise",
        "kind": "envelope_profile_rule", "rule": "R1", "role": "counter_proof",
        "input": "objects.json",
        "attribution": "receipt-envelope-profile v0.1 R1 — the two axes this format removes rather than resolves",
        "expected": {"canonicalizeRefuses": True},
        "specRefs": ["docs/RECEIPT_ENVELOPE_PROFILE.md", "RFC 8785"],
        "rationale": "Both objects carry a Python float: 1e-7 (divergence vector 2) and 2.0 (vector "
                     "3). Our canonicalizer must REFUSE both rather than serialize them, because the "
                     "profile requires decimal strings. That refusal is why the two axes cannot "
                     "produce a divergent content root here — not because we resolved them, but "
                     "because the format removes the shape they need. A verifier that quietly "
                     "serialized a float would reopen both axes at once.",
    }, {"objects.json": [{"x": 1e-7}, {"x": 2.0}]})

    # ── R2 the schema-id is read; refusal is a SEPARATE outcome ────────────────────────────────
    good_claim = _base(s)
    good_bundle = emit_eval_receipt(good_claim, s)
    decoded = decode_eval_claim(good_bundle)
    assert decoded is not None

    _write("r2-positive-control-known-schema-classifies-valid", {
        "caseId": "envelope-profile-r2-positive-control-known-schema-classifies-valid",
        "kind": "envelope_profile_rule", "rule": "R2", "role": "positive_control",
        "input": "bundle.json",
        "attribution": "receipt-envelope-profile v0.1 R2 — the schema-id is read before anything else",
        "expected": {"classification": "valid"},
        "specRefs": ["docs/RECEIPT_ENVELOPE_PROFILE.md"],
        "rationale": "The positive control that stops the counter-proof from passing for the wrong "
                     "reason: a verifier that refused EVERYTHING would satisfy the R2 counter-proof "
                     "and be useless.",
    }, {"bundle.json": good_bundle})

    foreign = emit_bundle(canonicalize(dict(decoded, schema="acme/other-receipt/v9")), s)
    _write("r2-counter-proof-foreign-schema-id-is-refused-not-invalid", {
        "caseId": "envelope-profile-r2-counter-proof-foreign-schema-id-is-refused-not-invalid",
        "kind": "envelope_profile_rule", "rule": "R2", "role": "counter_proof",
        "input": "bundle.json",
        "attribution": "receipt-envelope-profile v0.1 R2 — measured 2026-08-26 against inspect-receipts@397ae3ad (valid=True)",
        "expected": {"classification": "refused_unknown_schema"},
        "specRefs": ["docs/RECEIPT_ENVELOPE_PROFILE.md"],
        "rationale": "A cryptographically sound bundle declaring a schema this verifier does not know. "
                     "TWO wrong answers exist and the case excludes BOTH: `valid` (the measured defect "
                     "in the reference implementation) and `invalid` (a wrong verdict on someone else's "
                     "sound artifact). The refusal is its own outcome. NOTE, honestly: the released "
                     "`decode_eval_claim` returns None for a refusal AND for an invalid claim; the "
                     "distinction lives in the additive `classify_eval_claim`, because changing the "
                     "released return contract would be a breaking SemVer step.",
    }, {"bundle.json": foreign})

    # The sharp edge of R2, found by the meta-test and NOT by writing the vectors: a bundle that is
    # BOTH unverifiable AND foreign-schema. Every other vector classifies the same with or without
    # the authenticity-first ordering, so removing that ordering left the corpus fully green.
    kaputt = json.loads(json.dumps(foreign))
    # The SIGNATURE is corrupted, deliberately NOT the payload. A mangled payload stops being valid
    # JSON and lands on `invalid` through a completely different route, so such a vector would pass
    # with or without the ordering and discriminate nothing. Here the payload stays well-formed and
    # foreign-schema; only the signature is bad. That is the one shape on which the two orderings
    # give different answers. (First attempt corrupted the payload and was measured to prove nothing.)
    _sig = kaputt["signature"]["sig_b64"]
    kaputt["signature"] = dict(kaputt["signature"],
                               sig_b64=("B" + _sig[1:]) if _sig[0] != "B" else ("C" + _sig[1:]))
    _write("r2-counter-proof-unverifiable-is-invalid-not-refused", {
        "caseId": "envelope-profile-r2-counter-proof-unverifiable-is-invalid-not-refused",
        "kind": "envelope_profile_rule", "rule": "R2", "role": "counter_proof",
        "input": "bundle.json",
        "attribution": "receipt-envelope-profile v0.1 R2 — ordering counter-proof, added after a planted "
                       "defect survived the first ten vectors (2026-08-30)",
        "expected": {"classification": "invalid"},
        "specRefs": ["docs/RECEIPT_ENVELOPE_PROFILE.md"],
        "rationale": "A refusal says 'I cannot judge this'. A broken signature IS judgeable, so a "
                     "bundle that fails verification must be `invalid` even though its payload names a "
                     "schema this verifier does not know. Reporting `refused_unknown_schema` here would "
                     "let a forger buy silence by renaming the schema field. This case exists because a "
                     "planted defect removing the authenticity-first ordering left all ten other "
                     "vectors green — the ordering was documented and unproven.",
    }, {"bundle.json": kaputt})

    # ── R3 a reported binding is a performed binding ───────────────────────────────────────────
    tree_n = 500
    root_b64 = __import__("base64").b64encode(b"\x11" * 32).decode("ascii")
    coherent = _base(s, samples={"root_b64": root_b64, "n": tree_n, "leaf_alg": "sha256-rfc6962-sdjwt-v1"})
    _write("r3-positive-control-coherent-sample-binding", {
        "caseId": "envelope-profile-r3-positive-control-coherent-sample-binding",
        "kind": "envelope_profile_rule", "rule": "R3", "role": "positive_control",
        "input": "bundle.json",
        "attribution": "receipt-envelope-profile v0.1 R3 — a reported binding is a performed binding",
        "expected": {"classification": "valid"},
        "specRefs": ["docs/RECEIPT_ENVELOPE_PROFILE.md"],
        "rationale": "The committed tree covers exactly the samples the aggregate was computed over.",
    }, {"bundle.json": emit_eval_receipt(coherent, s)})

    lying = dict(decode_eval_claim(emit_eval_receipt(coherent, s)) or {})
    lying["samples"] = dict(lying["samples"], n=1)
    _write("r3-counter-proof-hand-signed-binding-lies-about-tree-size", {
        "caseId": "envelope-profile-r3-counter-proof-hand-signed-binding-lies-about-tree-size",
        "kind": "envelope_profile_rule", "rule": "R3", "role": "counter_proof",
        "input": "bundle.json",
        "attribution": "receipt-envelope-profile v0.1 R3 — the emit-vs-verify asymmetry class",
        "expected": {"classification": "invalid"},
        "specRefs": ["docs/RECEIPT_ENVELOPE_PROFILE.md"],
        "rationale": "The signature is VALID and the bundle verifies — this claim was hand-built and "
                     "signed, bypassing the blessed emitter. Its reported sample binding contradicts "
                     "the claim's own n. A guarantee enforced only at emit would accept this; the rule "
                     "must hold where it is CONSUMED, not only where it is produced.",
    }, {"bundle.json": emit_bundle(canonicalize(lying), s)})

    # ── R4 key resolution fails closed ─────────────────────────────────────────────────────────
    _write("r4-positive-control-issuer-is-the-signing-key", {
        "caseId": "envelope-profile-r4-positive-control-issuer-is-the-signing-key",
        "kind": "envelope_profile_rule", "rule": "R4", "role": "positive_control",
        "input": "bundle.json",
        "attribution": "receipt-envelope-profile v0.1 R4 — key resolution fails closed",
        "expected": {"classification": "valid"},
        "specRefs": ["docs/RECEIPT_ENVELOPE_PROFILE.md"],
        "rationale": "The claim's issuer fingerprint IS the key that signed the bundle.",
    }, {"bundle.json": good_bundle})

    other = generate_signer()
    mismatched = emit_bundle(canonicalize(decoded), other)   # payload names signer s, signed by `other`
    _write("r4-counter-proof-issuer-is-not-the-signing-key", {
        "caseId": "envelope-profile-r4-counter-proof-issuer-is-not-the-signing-key",
        "kind": "envelope_profile_rule", "rule": "R4", "role": "counter_proof",
        "input": "bundle.json",
        "attribution": "receipt-envelope-profile v0.1 R4 — an embedded key alone never carries valid=True",
        "expected": {"classification": "invalid"},
        "specRefs": ["docs/RECEIPT_ENVELOPE_PROFILE.md"],
        "rationale": "The bundle carries a perfectly good signature by a DIFFERENT key than the one the "
                     "payload names as issuer. It verifies as a bundle and must still not be a valid "
                     "claim: a key that travels with the receipt authenticates nothing on its own.",
    }, {"bundle.json": mismatched})

    # ── R5 — KEINE Vektoren, und das ist eine Entscheidung, keine Luecke ────────────────────────
    # Owner-Berichtigung Fassung 8 vom 30.08.2026: draft-hillier-coverage-attestation-00 (CAP-1,
    # 20.08.2026) verlangt je nicht gepruefter Einheit einen eigenen begruendeten Eintrag und weist
    # einen Rest, der sich nur durch Subtraktion ausgleicht, ausdruecklich zurueck. Genau so ein Rest
    # waren unsere drei Zahlen. Die Feldform ist damit OFFEN, und eine Gegenprobe gegen eine Form,
    # die gerade zurueckgezogen wurde, waere wertlos. Die R5-Probe entsteht, nachdem CAP-1 gelesen
    # ist — der Entwurf selbst ist bisher NICHT GELESEN, und aus einer Zusammenfassung nachgebaute
    # Felder waeren geraten.
    return 0


if __name__ == "__main__":
    sys.exit(main())
