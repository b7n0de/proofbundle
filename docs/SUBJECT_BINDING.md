# Subject binding + nested schema closure (3.2.0 O6, EXPERIMENTAL)

A verification LAYER (not a signed predicate type) that classifies how an in-toto Statement's `subject` relates
to its `predicate`, and enforces closed (no-undeclared-key) nested objects. EXPERIMENTAL: API and wire format
may change without deprecation.

Implementation: [`src/proofbundle/subject_binding.py`](../src/proofbundle/subject_binding.py).

## The problem it addresses

An in-toto Statement carries a `subject` (what the attestation is ABOUT) and a `predicate` (the claim). If the
subject digest is a free-floating value an issuer can set to anything, a verifier cannot tell whether the
subject actually corresponds to the predicate it is stapled to — an attacker could graft a trusted-looking
subject onto a different predicate. Subject binding closes that gap.

## DERIVED vs EXTERNAL_ATTESTED

- `derive_subject_digest(predicate)` = **SHA-256 over the RFC-8785 (JCS) canonical bytes of the predicate**.
- `classify_subject(statement)` re-derives that digest and compares it to the declared subject digest:
  - **`DERIVED`** — the declared subject equals the re-derived digest (`matches = True`). The subject provably
    corresponds to this exact predicate; mutate the predicate and the match breaks (a re-derive catches it).
  - **`EXTERNAL_ATTESTED`** — an override, a tamper, or a malformed subject (`matches = False`, fail-closed).
    The subject is asserting something OTHER than "I am the digest of this predicate", and the verifier is told
    so explicitly rather than silently trusting it.
- `require_derived_subject(statement)` raises `SubjectBindingError` on anything that is not `DERIVED` — for the
  strict path where only a self-describing subject is acceptable.

## Nested schema closure

`nested_closure_violations(obj, allowed_map)` walks nested objects and array items and reports any key not on
the declared allowlist for its path (e.g. `{"": ("decision",), "decision": ("verdict", "reasonCodes")}`). A
path not present in the map is **not** walked (it composes with a top-level `additionalProperties: false`
rather than duplicating it). This catches a `"sneaky": 1` smuggled into a nested object that a shallow schema
check would miss — the failure mode where extra fields ride along inside an otherwise-valid structure.

## No-Overclaim

`DERIVED` proves the subject is the digest of this predicate — not that the predicate's claims are true, nor
that the signer is trusted (that is the Trust Pack's job). `EXTERNAL_ATTESTED` is an honest label, not an
error: a legitimately external subject is allowed, it is just not silently treated as self-describing.
