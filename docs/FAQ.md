# FAQ for skeptics

Honest answers to the hard questions. If one of these feels dodged, open an issue.

### Why not just publish a SHA-256 of the eval log?
A bare hash proves bytes didn't change *if you already trust where you got the hash*. It has no
authorship (anyone can hash anything), no issuer binding, no selective disclosure, and no way to
prove a threshold was met while hiding the model or dataset. A proofbundle receipt adds exactly
those: an Ed25519 signature (who), issuer binding (attribution), salted commitments (hide
model/dataset, still prove the verdict), and — since v1.5 — a per-sample Merkle root so an auditor
can spot-check individual samples. For pure "did these bytes change," a hash is genuinely enough;
proofbundle is for crossing a trust boundary.

### Why not just use Sigstore / Rekor?
Use both. Sigstore/Rekor give public existence in an operated transparency log — great properties,
but nothing eval-shaped: no threshold semantics, no salted model/dataset commitments, no
per-sample openings, and verification normally means talking to a log service. proofbundle is
offline, one file, eval-specific, and *interoperates* with the same RFC 6962 math — it verifies a
real Rekor inclusion proof offline (`examples/rekor_interop.py`). Anchor a receipt into Rekor if
you want the public-log properties too.

### Why not use in-toto directly?
proofbundle *does* export a DSSE-signed in-toto `test-result` statement. But that generic
predicate has no fields for a metric/threshold verdict, salted commitments, assurance level, or a
samples root — so proofbundle carries its own claim and offers in-toto as an interop view, not the
core format. If in-toto ever standardizes an eval-result predicate, proofbundle should adopt it.

### Why should I trust the issuer?
You shouldn't — and the tool says so. `assurance_level` is issuer-*declared* and `show-eval` warns
on self-attested-without-pre-registration. A receipt turns "trust my number" into "here is an
attributable, tamper-evident claim you can hold me to." It proves **attribution and integrity, not
truth**. To move toward truth you need pre-registration (`prereg`), independent reproduction, or a
per-sample audit — proofbundle supports the first and third; the second is a process, not a tool.

### Can't the issuer just run the eval 50 times and sign the best one?
Yes — without pre-registration. THREAT_MODEL.md states this plainly. `proofbundle prereg
<protocol>` commits to the plan (seeds, decision rule, sampling policy) *before* the run; the hash
goes in the signed claim, so a plan written to fit the result is detectable. The per-sample audit
(v1.5) catches *within-run* sample doctoring; best-of-many is what pre-registration addresses.

### The Merkle tree is built by the emitter — isn't that theatre?
For a single-bundle emit, the inclusion proof adds little beyond the signature, and we say so. Its
value is real in two places: a checkpoint witnessed by an independent quorum (split-view
resistance), and the v1.5 per-sample tree, where inclusion is doing real work — an auditor
challenges random indices and openings must bind to the signed root.

### What stops replaying an old receipt?
Nothing automatic — an offline verifier has no clock. Age is *reported* (`show-eval`), you set the
bound (`check_freshness`). For SD-JWT presentations, `verify_bundle(expected_aud=…,
expected_nonce=…)` binds the presentation to your challenge. For revocation, a status-list snapshot
without an `exp`/`ttl` is reported as `fresh=None` (cannot judge), never "fresh forever".

### Does the per-sample audit leak the benchmark?
Every opened sample is burned for future use — the docs bound this: k ≪ n, auditor-directed,
never published, and benchmark owners can seed canaries to detect training-set leakage. Leaves
carry content hashes / compact results, not benchmark plaintext, so an opening reveals the model's
result without necessarily revealing the item text.

### Is this post-quantum?
Only witness cosignatures (optional ML-DSA-44). Primary signatures are Ed25519 until the ecosystem
moves — a PQ adversary who breaks Ed25519 breaks the receipt. This is stated, not hidden.

### Is this EU AI Act compliance in a box?
No. See COMPLIANCE.md: a verified receipt is *supporting evidence* toward record-keeping /
traceability goals (cf. Art. 12/19) and *documentation evidence* under NIST AI RMF MEASURE. It
does not by itself establish compliance, define risk metrics, or conform to any eval-attestation
standard — because none exists yet.

### Why is it Beta / why so few stars / where's the external audit?
It's young and honest about it. The trusted core is ~600 LOC of `signature.py` + `merkle.py` +
`bundle.py`, depends only on `cryptography`, is checked against external RFC 6962 vectors and a
real Rekor proof (so correctness isn't self-referential), and gates its tests with a mutation
suite. `docs/REVIEWERS.md` is a 30-minute path to try to break it, and SECURITY.md has the private
channel for what you find. An external audit is exactly what we're asking for.

### What's real cryptography here and what's just packaging?
Real: Ed25519 (via `cryptography`), RFC 6962 Merkle inclusion/consistency (domain-separated,
constant-time compare), RFC 9901 SD-JWT digest + Key Binding, C2SP checkpoint/cosignature/tlog-proof
verification, Token Status List, per-sample Merkle + audit challenge. Packaging: the CLI, adapters,
the `pb1.` token envelope, docs. The trusted-core boundary is drawn explicitly in docs/REVIEWERS.md.
