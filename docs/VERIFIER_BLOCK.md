# The verifier block — which build produced a receipt, and against which vector set it stood

Status: **6.1.0, self-declared.** Implemented in `src/proofbundle/verifier_block.py`, carried by
`agent-review/v0.2` receipts under `producer.verifier`, produced for a conformance run by
`conformance/run_conformance.py --test-result-out`. The module is the enforced validator; this
page explains it. Conformance cases live under `conformance/agent_review/` (rule `P19`).

## The question it answers

A relying party reading a receipt at T+n asked, on the SCITT list on 2026-09-10: how do I
establish that the verifier instance which signed this receipt was an implementation that met the
cited conformance floor, and that code and configuration at T were the tested ones? A
configuration hash prevents reconfiguration *after* the receipt; it does not show the
configuration was the *tested* one. An issuer URI says *which verifier*, not *which build*.

Measured against proofbundle 6.0.0 on 2026-09-12, the question applied to this package word for
word. proofbundle bound what **decided** (the policy, by a digest over its bytes, recomputed at
verify time rather than read from the receipt) and what was decided **about** (subject, diff,
visible block, findings root). It did not bind what it was decided **with**: no receipt and no
verify result carried the version, the wheel digest or a build digest of the verifier that produced
it. The only place a tool version reached a receipt was a CLI template writing `{"proofbundle":
"6.0.0"}` into a field the verifier never reads. Two wheels of the same version were
indistinguishable from the receipt.

## What the block carries

```json
"producer": {
  "id": "b7n0de-release-runner",
  "verifier": {
    "implementation": "proofbundle",
    "version": "6.1.0",
    "build": {"digest": {"sha256": "<64 hex>"}, "source": "installed-record", "files": 77},
    "vectorSet": {"name": "proofbundle.conformance.manifest.v1",
                  "digest": {"sha256": "<64 hex>"}, "cases": 115},
    "testResult": {"predicateType": "https://in-toto.io/attestation/test-result/v0.1",
                   "result": "PASSED", "statementDigest": {"sha256": "<64 hex>"}},
    "assurance": "selfDeclared"
  }
}
```

| Field | Measured from | Required |
|---|---|---|
| `implementation` | the package name | yes |
| `version` | `proofbundle.__version__` — a name, deliberately **not** the identity | yes |
| `build.digest` | a digest over the package's **own files**; see `build.source` | yes |
| `build.source` | `installed-record`: the sha256 of every `proofbundle/` row the installer wrote into `RECORD` (path and per-file sha256), identical for every install of the same wheel · `source-tree`: a digest over the package directory's files, for an editable install or a checkout on `PYTHONPATH` | yes |
| `build.files` | how many files went into the digest | no |
| `vectorSet` | the conformance corpus the build was held against: the manifest's schema name, the case count, and a digest over the manifest **and every file of every case directory** it names — not the manifest alone, because a manifest lists directories and a directory is not bytes | no |
| `testResult` | a reference to a **separate** signed object (below): its predicate type, its result, and the sha256 over its RFC 8785 canonical bytes | no |
| `assurance` | always `selfDeclared` | yes |

Every key set is closed. An unknown field is refused, not ignored: a field nobody validates is a
field a producer can put anything into. The two build sources are different measurements and are
compared only with themselves; neither is the sha256 of the wheel file on PyPI, and the block says
which one it is.

## The separate object: an in-toto test-result statement

`python conformance/run_conformance.py --test-result-out statement.json` writes the run as an
in-toto statement of predicate type `https://in-toto.io/attestation/test-result/v0.1`:

- **subject**: the build digest, measured the same way the block measures it;
- **configuration**: one resource descriptor for the vector set, with its digest and case count;
- **result**: the corpus rule that a skipped check is never a passed one — any failed case is
  `FAILED`; no failure but any case that ran partially or not at all is `WARNED`; `PASSED` only
  when every case ran in full;
- **passedTests / warnedTests / failedTests**: the case ids, so a reduction of scope is in the
  statement and not only in a headline.

The statement is written unsigned. Signing is the producer's step
(`verifier_block.sign_test_result_statement`, the same DSSE primitive every receipt of this package
uses); a runner signing with a key of its own would be one more identity nobody can look up. The
receipt cites the statement by the digest of its canonical bytes, and a relying party **joins the
two by equality**: `join_test_result(block, statement)` reports three equalities separately —
subject equals the block's build digest, canonical digest equals the cited one, result equals the
cited one — and `ok` only when all three hold. The issuer is not trusted for the join.

## What the verifier reports

`verify_agent_review_v02` carries a `verifier_block` axis:

| Field | Meaning |
|---|---|
| `present`, `valid` | whether the receipt carries a block, and whether its form holds |
| `build_digest`, `build_source`, `vector_set_digest`, `vector_set_cases`, `test_result` | what the block names |
| `matches_this_verifier` | `MATCH` / `MISMATCH` / `NOT_EVALUATED` — whether the build running this verification is the build the block names. Three states, and the third is not a pass: no block, no comparable measurement, or builds measured from different sources. |

The axis is **reported, never folded into `ok`**. A malformed block is a structural error and
fails the receipt, like any malformed field. A well-formed block naming another build does not
invalidate the receipt: it is a receipt whose producer you can now name.

## Version rule, stated rather than glossed

`agent-review/v0.2` **extends** its producer field set by `verifier` since 6.1.0; `v0.1` is not
loosened and refuses the block as it always refused unknown fields. A 6.0.0 verifier refuses a
v0.2 receipt that carries the block (`producer.verifier is not an allowed field`) — loudly, never by
misreading it. A producer that needs 6.0.0 readability omits the block. This is the same boundary
the predicate already states for v0.2 itself: a receipt of that version can be verified with the
published package only from 6.0.0 on.

## Honest limits

- **Self-declared.** The producing build measures itself. A producer that lies about its build
  digest signs a lie; the signature makes the lie forgery-resistant, not correct. A block observed
  by a runner or witnessed independently needs a witness outside the producer, which this version
  does not provide.
- **A digest over files, not over a wheel.** `installed-record` identifies the installed file set of
  a wheel; `source-tree` identifies a checkout. Neither is the artifact digest on PyPI. Joining the
  block to a published wheel is a further step and is not claimed here.
- **The vector set digest pins what the manifest names.** A case directory not listed in the
  manifest is not part of the corpus and not part of the digest — which is the corpus's own rule.
- **It does not make the conformance claim true.** What a relying party gains is a joinable,
  digest-bound statement instead of a version string.

## Every rule brings its counter-proof

`conformance/agent_review/` carries a positive control (a v0.2 predicate with a block is valid) and
three counter-proofs (a block that raises its own assurance, a build digest that is not a sha256,
an unknown field) plus one v0.1 counter-proof (the old version refuses the block). Each
counter-proof has a flip test in `tests/test_agent_review_conformance_runner.py` that removes
exactly its defect and expects the verdict to turn. The measured behaviour — a real build, the real
corpus, the join, the DSSE round trip — is held by `tests/test_verifier_block.py`.
