# Differential matrix — Python <-> Rust, all normative relation paths

The reproducible artifact `audit_artifacts/360/rust_differential_matrix.json` is the Vector x {Python,
Rust} result matrix for the relation/v0.1 and relation-statement/v0.1 conformance vectors. Each row is
one vector verified by BOTH the Python CLI and the independent Rust verifier; `agree_python_rust`
asserts they land on the SAME common-vocabulary label (exit class + lineage), and
`rust_reproduces_expectation` asserts the Rust verifier reproduces the vector's declared expectation.

This is differential AGREEMENT on these vectors, NOT a correctness proof of either implementation (that
distinction is the honesty point, stated in the artifact itself).

## Regenerate

```
export PYTHONPATH=src
( cd tools/pb_verify_rs && cargo build )
python3 tools/pb_verify_rs/crosscheck.py --matrix audit_artifacts/360/rust_differential_matrix.json
```

The artifact carries an environment freeze (cargo / rustc / python versions) so a re-run on another box
is comparable. On the recorded run: 40 relation vectors, Python == Rust on all, and the whole 54-case
conformance corpus of that era reproduced independently by the Rust binary (the corpus has since
grown to 57 cases; the named `make conformance-crossimpl` gate re-runs the cross-check on every
invocation, 56/56 as of v3.7.0).

## Scope of coverage

The core primitives (content-root, DSSE verify, dup-key reject, RFC 6962 Merkle, Trust-Pack Ed25519
threshold) and the full relation surface are covered. The deliberately-PENDING surfaces are declared in
`rust_parity_scope.md` (No-Fake: no fake 100%).
