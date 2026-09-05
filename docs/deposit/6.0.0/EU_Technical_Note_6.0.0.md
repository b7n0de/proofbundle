# Evidence Integrity for AI Evaluations

**Author:** Konrad Gruszka (ORCID [0009-0006-8947-6065](https://orcid.org/0009-0006-8947-6065)) · b7n0de: Verified AI Work · kraxo@b7n0de.com
**Date:** 2026-09-05 (manuscript, DRAFT for owner review); the software release it describes is not yet tagged, its release date is NOT MEASURED.
**DOI:** [10.5281/zenodo.21230466](https://doi.org/10.5281/zenodo.21230466) (concept DOI, resolves to the latest version; the version DOI for this 6.0.0 revision is assigned at deposit, after the tag, never before)
**Status:** technical description of the 6.0.0 release, prepared on the frozen release head; to be deposited as a new version under the concept DOI above once the release exists. Nothing in this draft is deposited.
**Tool version described:** proofbundle 6.0.0 (PyPI release, MIT-licensed), to be released from Git tag `v6.0.0`. The frozen head the release is built from is commit `049b3195def2734fe69a4ab33b64937e404dc250`; the tagged commit adds the signed pre-tag receipt on top of it and is NOT MEASURED in this draft. Reproduction commands pin the version explicitly.

**This manuscript tracks the shipped 6.0.x line.** The public Zenodo lineage under concept DOI `10.5281/zenodo.21230466` previously published the 2.0.0b3 revision (deposited 2026-07-07), the 3.2.3 revision (deposited 2026-07-16, version DOI `10.5281/zenodo.21384526`), the 4.0.0 revision (deposited 2026-08-19, version DOI `10.5281/zenodo.22004295`) and the 5.0.0 revision (deposited 2026-08-31, version DOI `10.5281/zenodo.22209091`). The software releases 5.1.0 (tagged 2026-09-02) and 5.1.0.post1 (tagged 2026-09-05) shipped without a note revision; their changes are folded into this one. Two things changed that a reader of the 5.0.0 revision should know: the receipt layer now carries a signed disclosure of AI involvement and review in a pull request or issue, and the second version of that predicate is what the emitter produces by default, which is the reason this is a major version.

---

## New in 6.0 (and what 5.1 added on the way)

**The headline change is that `agent-review/v0.2` is what the emitter produces without an argument.** 5.1.0 introduced agent review receipts: a signed self-declaration of AI involvement and review in a pull request or issue, binding the reviewed GitHub object, the declared review runs, the coverage, the findings, the limitations and the human-visible disclosure block. 6.0.0 makes the second version of that predicate the default. v0.2 requires `subjectContext.disclosureCoreDigest`, so a visible block cannot claim more than the signed predicate; it requires derived `limitationCodes`; it separates time claims by source; it accepts only the full 40-character `fixCommit`; and it carries a named policy axis: `verify_agent_review_v02` evaluates the derived codes and the coverage status against a policy that is a file, with three decisions, `accept`, `reject` and `insufficient_evidence`, and reports the policy's name and digest in the result. v0.1 stays readable and verifiable without a deadline: its verifier is byte-pinned to the 5.1.0 source, the six published v0.1 receipts run as a regression against values frozen under 5.1.0, and the dispatcher `verify_agent_review_any` reports `predicateVersionStatus: legacy` for them.

**Two things a relying party should know.** A receipt whose own time claims contradict each other is rejected with `TIME_CLAIMS_CONFLICT` regardless of policy; before the fix, measured on 2026-09-05 by a review lens, such a receipt verified with `ok=True` under the shipped standard policy. A malformed policy file is refused before it decides (`POLICY_NOT_EVALUABLE`), never read as a permissive one: `blocking: "COVERAGE_PARTIAL"`, a string where a list is expected, was read as a set of characters and blocked nothing before the fix. Non-fatal notes such as `POLICY_NOT_EVALUATED` and `AGENT_REVIEW_LEGACY_V01` live in `advisory_codes`; `reason_codes` is empty for a valid receipt.

**Why this is a major version.** A public emitter changes its default output: a caller of `build_agent_review_statement` or `emit_agent_review` that passes no version argument received `agent-review/v0.1` under 5.1.0 and receives `agent-review/v0.2` under 6.0.0, a predicate with required fields v0.1 never had. No verdict flips for published receipts. The scope list is `docs/release_scope/6.0.0.md`; the residual-risk record, frozen before the closing gate round and bound by the pre-tag receipt, is `RESTRISIKO_600.md`.

**Also shipped since the 5.0.0 revision:** an experimental adapter for provider-attested inference (`proofbundle.experimental.attested_inference`, behind the `[experimental]` extra) that normalises provider evidence without over-claiming and performs receive-time checks; the receipt envelope profile (`docs/RECEIPT_ENVELOPE_PROFILE.md`) with its ten executable conformance cases; hardened correction chains, so that an untrusted receipt cannot take over the current position in a supersession chain; the version at one source with PEP 440 read correctly (5.1.0.post1 was the first post-release); and the mutation gate comparing two numbers from the same test set.

**Carried forward from 5.0.0:** every provenance field carrying a harness-reported version also carries a `<field>_status` from the closed set `reported` / `not_reported` / `not_bound` with a mandatory reason when the status is not `reported`; the fail-closed sweep that replaced raw exceptions with typed refusals across the verify surfaces; a threshold required before a verdict is emitted; and, from 4.0.0, a log that no longer votes in its own witness quorum.

**Counts, measured on the frozen head `049b3195` on 2026-09-05.** 2,933 test functions in 230 test files (counted as `def test_` occurrences); a full run in the sibling environment (CPython 3.10.12, all extras) gives 3,236 passed, 22 skipped, 9 deselected, 770 subtests passed, exit 0, in 1,226 seconds. The 22 skips are enumerated: 13 cases of one corpus-driven property test that only applies to envelope cases, 4 OpenTimestamps vectors whose operation graph needs `ripemd160` in an interpreter without the OpenSSL legacy provider, 4 Rust-parity items recorded as not run rather than passed, and 1 wire-bytes differential arm not yet planted in the Rust corpus. 88 curated semantic mutation operators are enumerated in the mutation gate; the canonical full mutation run, all 88 operators in one process, reported `OK (88 operators, 0 gap(s))` on commit `658ed063` between 05:57 and 07:49 UTC on 2026-09-05, and `src/`, `tests/` and `scripts/` are byte-identical between that commit and the frozen head. 107 executable conformance cases in 6 kinds (agent review 30, bundle 12, decision 3, envelope profile 10, provenance 10, relation 42); 8 published agent-review receipts inside the package (6 of v0.1, 2 of v0.2); 57 public names in `proofbundle.__all__` on the installed wheel; 67 source files and 24,283 lines under `src/`. These are project-maintained release metadata under a stated counting method, not an independently certified coverage claim.

---

## Abstract

Evaluation results may form part of technical and compliance documentation under the EU AI Act, yet a number circulated in a report is usually not independently checkable as an artifact. This note describes *proofbundle*, a small MIT-licensed offline receipt layer that applies an Ed25519 signature, an RFC 6962/9162-style Merkle inclusion proof, and RFC 8785 canonicalization to an evaluation claim, with optional selective disclosure, external time-anchor evidence, and an experimental receipt chain from an evaluation result through an agent decision to an action-outcome report. Since 5.1.0 the same layer carries a signed disclosure of AI involvement and review in a pull request or issue, and 6.0.0 makes its second version the default. Two boundaries hold throughout: the identity and time-attestation layer is not uniformly post-quantum secure, and cryptographic integrity is not factual truth or methodological validity.

## 1. Introduction

Articles 53 and 55 of the EU AI Act require, respectively, technical documentation for providers of general-purpose AI models and additional evaluation, adversarial-testing, incident-reporting, and risk-management duties for providers of general-purpose AI models with systemic risk. The relevant GPAI obligations have applied since 2 August 2025, subject to the Act's transitional rules, and the Commission's and AI Office's enforcement powers for that chapter have applied since 2 August 2026. The Digital Omnibus, published in the Official Journal on 24 July 2026 and in force from 27 July 2026, deferred certain high-risk deadlines but left the general-purpose model obligations of Chapter V unchanged; a reader assessing currency in late 2026 should note that this manuscript's regulatory framing was re-checked against that instrument on 2026-08-30 and was NOT re-checked for this draft. The General-Purpose AI Code of Practice, published on 10 July 2025, is a voluntary tool intended to help providers demonstrate compliance; it is not itself a mandatory legal rule. These instruments create a practical demand for records that can be attributed, preserved, and independently checked, but they do not make any particular cryptographic receipt a compliance determination.

In practice, evaluation results often circulate as numbers in reports, spreadsheets, leaderboards, or model cards. A recipient may be unable to check, without the issuer's infrastructure, which bytes were signed, whether those bytes changed, which key signed them, or whether a disclosed sample opening matches a prior commitment. This is narrower than general software supply-chain security. in-toto, Sigstore, and the IETF SCITT architecture provide important statement, provenance, and transparency building blocks; they do not by themselves determine the evaluation-specific semantics, disclosure boundaries, or assurance vocabulary used by a relying party. K-Veritas frames the closely related research problem of nonrepudiable experimental results. proofbundle is one released, offline-oriented implementation point in this space, complementary to transparency services, trusted execution, independent reproduction, and proof-carrying computation rather than a substitute for them.

proofbundle converts an evaluation claim into a portable receipt that can be checked offline using public tooling. A core receipt carries an Ed25519 signature over canonical payload bytes and an RFC 6962/9162-style Merkle inclusion proof under a stated root. Optional extensions include SD-JWT selective disclosure of named claims; external time-anchor evidence such as RFC 3161 tokens, OpenTimestamps proofs, and chia-datalayer commitments; and, in the experimental line, signed decision and outcome statements. The tool is released at <https://github.com/b7n0de/proofbundle> and on PyPI as version 6.0.0.

Two boundaries frame everything that follows. First, RFC 8785 is a deterministic encoding scheme, not a cryptographic primitive; the system combines hash-based commitments, conventional public-key signatures, optional post-quantum signatures, and trust frameworks with different security assumptions. Second, a receipt can verify a signed claim and its bindings without establishing that the claim is factually correct, complete, legally sufficient, or methodologically sound.

> **Standing boundary.** proofbundle verifies selected cryptographic relations: that specific bytes were signed by the holder of a stated or policy-authorized key; that a leaf is included under a stated Merkle root for a stated index and tree size; and, when supplied, that relying-party root, policy, checkpoint, disclosure, or anchor conditions pass. It can carry claims about provenance, versioning, decisions, and outcomes, but does not by itself establish that those claims are true, that a real-world identity controls a key, that an evaluation was well designed, that a computation ran correctly, or that an external effect occurred.

A second kind of claim entered the same layer with 5.1.0: not "this evaluation produced this number" but "this pull request was reviewed in this way, with these tools, by these runs, and here is what the review did not cover". The agent review receipt binds the reviewed object, the declared runs, the coverage and the limitations to a signed statement, and binds the visible disclosure block to that statement by digest, so a block cannot claim more than the receipt. It proves who declared what about a review; it does not prove the review was good.

Verification therefore answers a bounded question: "Do these bytes, signatures, commitments, and supplied trust conditions verify under the named algorithms and policies?" It does not answer "Was this a good evaluation?" or "Did the reported real-world event occur?" This note is not legal advice, and proofbundle is not a compliance product by itself. It is an evidence-integrity component that may support, but cannot replace, substantive technical and legal assessment.

## 2. Threat model

A proofbundle receipt is a cryptographic commitment to a specific signed claim. Depending on the profile, that claim may contain an evaluation verdict, commitments to model, dataset, or per-sample records, an issuer identifier, a declared timestamp, and assurance metadata. Not every receipt contains the full sample set, a real-world identity binding, or independent time evidence. The core adversary is a party who alters, substitutes, reserializes, or re-anchors a record after signing, or presents selectively disclosed fields without a valid issuer-bound presentation. Backdating is addressed only when independently verifiable anchor evidence is present. A dishonest evaluator who signs a fabricated score remains outside the cryptographic guarantee.

**Adversary model.** Three actors are relevant: (1) a developer or lab that may inflate scores, omit runs, or sign incomplete claims; (2) a transport, storage, or intermediary adversary that may alter or substitute artifacts; and (3) a future adversary able to break conventional public-key algorithms. The core receipt makes unauthorized post-signing changes by (2) detectable under the stated key and tree data. It addresses (1) only through additional, explicitly scoped mechanisms such as pre-registration, externally witnessed sequence heads, run metadata, sample challenges, or independent reproduction. It addresses (3) partially through hash-based commitments, optional post-quantum signatures, and renewal; none of these retroactively proves the truth of the claim.

Let *m* be the RFC 8785 canonicalization of the payload, that is, the signed bytes; let *n* be the tree size, *i* the leaf index, *π* the ordered inclusion path, and *r* the stated root. RFC 6962 domain-separates a leaf as `h_leaf = SHA256(0x00 || m)`. The core cryptographic verdict is the conjunction of two checks, that the signature verifies for the stated public key over *m*, and that Merkle verification succeeds for *(r, n, i, π, h_leaf)*. This is deliberately weaker than an automation decision. A strong relying-party profile additionally requires that the tree context is authenticated, that the signer passed policy, and that the required gates passed. The root is not covered by the core receipt payload signature, although it can be authenticated by a separate signed checkpoint or by out-of-band relying-party pins. An external timestamp or ledger anchor at time *T* supports the bounded statement that the anchored datum or commitment existed no later than *T*, not that the underlying evaluation or record was first created at *T*.

### 2.1 What a receipt defends

**Key-level authorship.** Ed25519 verification establishes that the private key corresponding to the verified public key signed the exact payload bytes. RFC 8785 provides a deterministic JSON representation so producer and verifier can hash and sign the same bytes; canonicalization removes serialization ambiguity but supplies no authentication by itself. Attribution to a person, organization, or workload requires an authenticated key-binding process. The experimental `trust-pack/v0.1` can carry versioned, threshold-signed key and revocation policy, but the real-world authority behind its roots remains a relying-party trust assumption.

**Tamper evidence and inclusion.** The canonical payload is signed and committed as a Merkle leaf. A change to the signed bytes invalidates the signature; a change to the leaf, path, index, tree size, or stated root invalidates inclusion when the verifier evaluates the complete tree context. Inclusion proves membership under the stated root, not that the root is the root a relying party intended to trust.

**Root authenticity and atomic tree context.** A coherent one-leaf rewrap demonstrates why a producer-stated root is not self-authenticating. A relying party closes that gap by supplying an expected root and tree size together, or a signed checkpoint verified under a trusted key. A naked root pin reaches `ROOT_BYTES_ONLY`; it does not authenticate the full root-and-size context and is not automation-safe under the shipped strict model.

**Selective disclosure of a signed verdict.** A claim can carry salted commitments to model and dataset identifiers and disclose named outcome fields through SD-JWT (RFC 9901). This proves that the disclosed fields are bound to an issuer-signed presentation and the relevant bundle when those checks pass. It is not a zero-knowledge range proof, and because the raw measured score is absent from this example, it verifies a signed `passed`/threshold claim rather than recomputing that the threshold was actually met. proofbundle verifies ES256 as well as EdDSA issuer signatures for interoperability with credential ecosystems that deploy those algorithms.

**Per-sample spot checks.** When a signed claim commits a per-sample root, `audit-challenge` selects indices and `verify-opening` checks the supplied openings. This can detect tampering in challenged leaves and can provide a quantified sampling guarantee when challenge randomness, sample size, and assumed corruption rate are fixed independently of the issuer. It does not recompute or validate the aggregate score, and an issuer's refusal to answer a challenge is procedural non-cooperation rather than a cryptographic proof of fraud.

**External existence evidence.** RFC 3161 tokens and other supported anchors can establish that a datum or digest commitment was present in a trusted service or public structure by a stated time or height, under relying-party-supplied trust material and verifier rules. They do not prove the first creation time, the factual truth of the content, or authorship after the signature algorithm is no longer trustworthy.

**Reported-version state, since 5.0.0.** Where a harness reports its own version, the receipt records both the value and a status from a closed set, so a relying party can distinguish a harness that ran and reported nothing from a run with no harness bound at all. The status is recorded, never inferred, and a `not_reported` status is not an assurance that anything was checked; it is an explicit statement that a specific thing is unknown.

**Signed review disclosure, since 5.1.0, default v0.2 in 6.0.0.** An `agent-review/v0.2` statement binds the reviewed pull request or issue by digest, the declared review runs, the coverage accounting, the findings and the derived limitation codes, and it binds the human-visible disclosure block by `subjectContext.disclosureCoreDigest`. The verifier answers `ok` only when the relying party has told it which object it expects; without an expected subject digest the run reports internal consistency and a policy decision, and says so. What it proves is that a named key signed this declaration about this object; whether the review was good, and whether an identity controls the key, remain outside the guarantee, and the shipped v0.2 emits only self-declared assurance.

**Decision and outcome records (experimental).** A `decision-receipt/v0.1` signs a decision claim, action digest, policy references, reason codes, and declared omissions. An `action-outcome/v0.1` signs an executor's report over requested-action, actual-action, response, and effect digests. The verifier can check decision-reference binding and compare declared actor identifiers. It cannot infer organizational independence merely from different strings or keys, cannot turn an ALLOW record into a bearer authorization, and cannot establish a real-world effect from an executor-signed report. The shipped evidence ladder therefore leaves `EFFECT_OBSERVED` structurally unreachable.

### 2.2 What a receipt does not defend, and how weak spots are surfaced

A receipt does not detect a miscoded scorer, wrong labels, data contamination, an ill-chosen metric, benchmark reward hacking, or a dishonest issuer that signs a fabricated result. It does not re-execute the model, re-score transcripts, or appraise a TEE's evidence by itself. These are separate methodology, computation, and governance questions.

Several limitations are made explicit in the data model and CLI. The signed `assurance_level` is an issuer-declared classification unless independently corroborated. `show-eval` warns when a self-attested receipt lacks a pre-registration commitment. `prereg` commits to a protocol, and `evalcard` can hash-bind an external Evaluation Card. The experimental `run-ledger/v0.1` provides a monotone sequence and digest chain. A gap or deletion is detectably inconsistent only relative to a precommitted or externally witnessed sequence head, declared budget, or trusted transparency service; without such an external reference, an issuer can construct a selective internally consistent chain before publication. Thus the ledger can support omission detection under stated deployment assumptions, but does not prove that no unrecorded run existed.

### 2.3 Post-quantum split and longevity path

proofbundle is not uniformly post-quantum secure, and no absolute "quantum-safe" claim should be inferred. Three categories must be kept separate:

- **Conventional public-key layer:** Ed25519 receipt signatures, ES256 credentials, RFC 3161 TSA certificate signatures, and Chia's BLS transaction signatures are vulnerable to Shor's algorithm if a sufficiently capable quantum computer becomes available.
- **Hash-based commitments:** SHA-256 leaf and node hashes, Merkle roots, and hash-chain commitments rely primarily on hash-function security. Quantum search changes their security margins, so parameters and algorithms still require lifecycle review. RFC 8785 belongs to neither category: it is a deterministic encoding rule.
- **Post-quantum signature option:** ML-DSA signatures are standardized post-quantum signatures. Their presence matters only when the signature is actually verified under an authorized key and policy; a label is not evidence.

A hash-based time anchor may preserve evidence that a particular digest commitment existed before a later cryptographic break, provided the anchor's trust framework, consensus or PKI evidence, algorithm parameters, and any required renewals remain valid. It does not preserve Ed25519 authorship by itself once Ed25519 can be forged. The security statement is therefore "pre-existing commitment under maintained verification assumptions," not "the full receipt remains authenticated forever."

**The shipped longevity path (EXPERIMENTAL).** The package exposes library modules under ADR 0006. Of these, only `evidence_pack` is reachable from the command line at 6.0.0, and it is reached through the `anchor` subcommands (`upgrade`, `verify-pack`, `inspect`) rather than under a command of its own; `hashalg`, `renewal`, and `pqsig` are library-only and are not referenced by the CLI module at all (measured on the wheel built from the frozen head: zero references to each of the three, nine to `evidence_pack`). `hashalg` is an explicit algorithm registry with fail-closed resolution and dual-hash support. `renewal` models RFC 4998 Evidence Record Syntax renewal, with timestamp and hash-tree renewal and relying-party verification; since 5.0.0 a malformed input to a renewal verification reaches a typed refusal rather than a raw exception. `pqsig` provides ML-DSA and hybrid Ed25519+ML-DSA verification for signature migration. `evidence_pack` builds offline OpenTimestamps evidence material that remains evidence, not self-supplied trust. Open work includes full ASN.1/XMLERS export, signature-algorithm staleness triggers, a confirmed-receipt OpenTimestamps pack, and a post-quantum payload signature for the receipt itself; today the post-quantum coverage is witness-side rather than covering the receipt payload signature. These modules are a research and interoperability path, not an end-to-end post-quantum guarantee.

### 2.4 Defended versus not defended

| Claim | Status | Mechanism and boundary |
|---|---|---|
| These exact bytes were signed by the private key for the stated public key | Yes, if signature verifies | Ed25519 over the exact payload bytes; real-world identity requires an authenticated key binding |
| The signed payload was not modified after signing | Yes | Signature verification; JCS removes JSON serialization ambiguity but is not authentication |
| The leaf is included under the stated root, index, and tree size | Yes, if proof verifies | RFC 6962/9162-style leaf and node hashing with ordered path evaluation |
| The stated root and tree size are trusted by the relying party | Only with external trust | Expected root-and-tree-size pair or verified signed checkpoint; producer-stated root alone is insufficient |
| A disclosed threshold verdict is issuer-bound | Yes, if SD-JWT checks pass | Signed disclosure of `passed`/threshold fields; not proof that a hidden raw score was recomputed |
| A challenged sample opening matches the committed root | Yes, for that opening | Per-leaf verification; population-level assurance depends on independently chosen sampling assumptions |
| The anchored datum existed no later than time *T* | Yes, if anchor and trust validate | Existence evidence for a datum or digest commitment; not first creation time or factual truth |
| Whether a harness reported its own version | Yes, as a recorded state | Closed-set status with a mandatory reason when not `reported`; the status is recorded, never derived, and is not itself an assurance |
| The visible AI-involvement disclosure says no more than the signed predicate | Yes, in v0.2 | `disclosureCoreDigest` binds the block; the verifier reports the comparison as `disclosure_core_digest_match` when the observed block is supplied, and a block that drifts fails it |
| Two time claims of a receipt agree with each other | Yes, fatal on conflict | `TIME_CLAIMS_CONFLICT` sets `ok` to false regardless of policy |
| The review covered what it says it covered | Conditional | The coverage status is derived from the accounting the predicate carries; in 6.0.0 that accounting is the v0.2 counters, the stratified coverage language is target 6.1.0 |
| Attribution survives a future break of Ed25519 | No, not from a hash anchor alone | A pre-break hash commitment may survive; authorship requires still-valid or renewed signature evidence |
| The reported number is true | **No** | Out of scope: the receipt authenticates a claim, not its factual correctness |
| The evaluation was well designed or resistant to gaming | **No** | Requires methodology review, adversarial benchmark audit, and/or independent reproduction |
| The underlying computation ran correctly | **No** | No re-execution or proof of computation; TEE evidence adds different, assumption-bound assurance |
| The permitted action's real-world effect occurred | **No** | `status=executed` is an executor-signed report; `EFFECT_OBSERVED` is not inferred |
| No runs were omitted | Conditional only | Detectable relative to a precommitted or externally witnessed ledger state; not from a self-published chain alone |

## 3. A worked example

All commands and transcripts in this section were captured on 2026-09-05 from runs against a 6.0.0 wheel built from the frozen head `049b3195` (sha256 `ba4048d60d88d1d30a1383562b534c1fba787a927e37cb1f6dffcf52b4e20d09`) in a fresh virtual environment, and are reproduced here byte for byte; long lines wrap for print, abbreviated base64 fields are marked with their length, and run-variant lines (the challenged index, drawn from `os.urandom`, and the `age` line) are declared where they occur. **Before deposit, every transcript in this section is re-captured against the shipped 6.0.0 wheel from PyPI in a fresh virtual environment; the shipped wheel differs from the one used here because the release workflow builds at the epoch of the tagged commit, with identical source content.** That the capture came from a real run is an issuer statement, not something this document proves: the reader who wants the stronger claim runs the commands of Section 6 and compares, which is why they are pinned. The one artifact here that *is* checkable without trusting the issuer is the companion receipt, and Section 3.7 checks it without importing proofbundle. The scenario: an external evaluator runs a threshold eval and hands over a receipt; a release gate decides on that evidence; an executor reports the outcome; each step is independently verifiable offline. Section 3.9 adds the receipt kind that is new since the 5.0.0 revision, a signed review disclosure for a pull request.

### 3.1 The claim and the receipt

The eval claim (schema `proofbundle/eval-claim/v0.1`) records the outcome, not the raw score: the tool computes `passed` from the score and the comparator at build time and stores only `threshold` (a decimal string) and `passed`. Model and dataset identifiers appear only as salted commitments. This is the exact claim behind the companion receipt prepared for deposit with this manuscript:

```
{
  "schema": "proofbundle/eval-claim/v0.1",
  "suite": "arc-easy",
  "suite_version": "1.0",
  "metric": "accuracy",
  "comparator": ">=",
  "threshold": "0.80",
  "passed": true,
  "n": 2376,
  "model_id_commit": "sha256:4162cb4ec966eb511a484ae922268aa64d81fa3e0413f81a97f9de81fd6b123d",
  "dataset_id_commit": "sha256:d0b14333d425beee8426642c9327a32617e6f7fb77a2f3be212b01c410fd9362",
  "commit_alg": "sha256-salted-v1",
  "issuer": "b7n0de eval harness (technical note example)",
  "timestamp": "2026-09-05T06:00:00Z"
}
```

Emitting the signed receipt (a throwaway key is generated with `--new-key` so a reader can reproduce the flow; the tool writes the freshly generated public key back into the payload's `issuer` field):

```
$ proofbundle emit-eval --claim appendix_claim.json --new-key appendix_key.seed --out receipt.json
wrote new signing key to appendix_key.seed (keep this secret)
wrote eval receipt receipt.json
```

The receipt (schema `proofbundle/v0.1`; the long base64 payload is abbreviated here with its length, and the full artifact is reprinted byte-identically in Appendix A):

```
{
  "schema": "proofbundle/v0.1",
  "payload_b64": "eyJhc3N1cmFuY2VfbGV2ZWwiOiJzZWxmX2F0dGVzdGVk...(684B)",
  "signature": {
    "alg": "ed25519",
    "public_key_b64": "uG8s3tqIoRAm+Ot8baymCmjtKY9cuNRssrIf+YpGdNo=",
    "sig_b64": "ezBqzPa9Y9ZP1gBC7gsnQnS1D8jg7Kab2hQBBJq/...(88B)"
  },
  "merkle": {
    "hash_alg": "sha256-rfc6962",
    "leaf_index": 0,
    "tree_size": 1,
    "inclusion_proof_b64": [],
    "root_b64": "bGQENnsdUG9JcwhlKcmsQRw7Y25dxsu3LOswY6PLXVI="
  }
}
```

This example commits a single record, so the Merkle tree is the degenerate one-leaf case (`tree_size: 1`, empty inclusion path); the same RFC 6962 structure carries a non-trivial inclusion path when a receipt commits per-sample leaves, which is what the `audit-challenge` / `verify-opening` flow of Section 2.1 exercises.

### 3.2 Verify, offline

```
$ proofbundle verify receipt.json
[PASS] ed25519-signature: payload signed by stated key
[PASS] merkle-inclusion: anchored at index 0 of 1 (Merkle-consistent under the STATED root)
CRYPTO: OK
ROOT-AUTHENTICITY: NOT_EVALUATED (payload-signature PASS, merkle-consistency PASS, tree-context NOT_EVALUATED, root-trust-level NONE, safe-for-automation false)
SAFE_FOR_AUTOMATION: NO
Reason:
  The Merkle root was not authenticated against a relying-party value (--expected-root or a policy trusted_roots entry)
  Root and tree size were not authenticated ATOMICALLY from one source (a signed checkpoint via --trusted-checkpoint / policy trusted_checkpoints, or an --expected-root + --expected-tree-size pair) — a root-bytes-only pin cannot detect a tree-size/leaf-index relabel (A-P0-1)
  No trust policy was evaluated (supply --policy to authorise a signer)
POLICY: NOT_EVALUATED (no trust policy supplied)
ASSURANCE: self_attested (issuer-declared)
LIMITATIONS: NOT that the result is true, the eval well designed, the model safe/fair, or that the score generalizes (see NON_CLAIMS.md); and NOT when it happened, unless an external time anchor is present
```

No network call, no issuer infrastructure, no shared secret: verification checks the Ed25519 signature against the public key stated in the receipt and evaluates Merkle inclusion under the producer-stated root (exit 0). The key and root are not thereby authorized by a relying party; that requires pins, a checkpoint, and policy as shown below. The `SAFE_FOR_AUTOMATION: NO` verdict on a cryptographically valid receipt is the point: a signature and a self-declared root are not, by themselves, an authenticated result. `proofbundle show-eval` additionally decodes the claim and prints the assurance context, including the built-in cherry-picking warning for a self-attested receipt (the `age` line is run-variant by nature):

```
$ proofbundle show-eval receipt.json
suite      arc-easy (1.0)
metric     accuracy >= 0.80
passed     True   (n=2376)
evidence   THRESHOLD_VERDICT_VERIFIED (proves `passed` against the signed threshold, not an exact score)
note       METHODOLOGY_NOT_EVALUATED (the receipt never judges whether the suite is well designed)
assurance  self_attested
model      commit sha256:4162cb4ec966eb511a484ae922268aa64d81fa3e0413f81a97f9de81fd6b123d
dataset    commit sha256:d0b14333d425beee8426642c9327a32617e6f7fb77a2f3be212b01c410fd9362
issuer     ed25519:uG8s3tqIoRAm+Ot8baymCmjtKY9cuNRssrIf+YpGdNo=
timestamp  2026-09-05T06:00:00Z
age        9166s
WARNING    self_attested with no prereg_sha256 — the weakest assurance: trust rests entirely on the issuer, who could publish the best of many runs. Pre-register (prereg_sha256) or use a higher assurance_level (reproduced / enclave_attested) to strengthen it.
=> OK
```

### 3.3 Authenticating the root, and what a strict policy refuses

A relying party that obtained the expected root and tree size out of band pins both; the tree context is then authenticated atomically (Section 2.1), exit 0:

```
$ proofbundle verify receipt.json --expected-root bGQENnsdUG9JcwhlKcmsQRw7Y25dxsu3LOswY6PLXVI= --expected-tree-size 1
[PASS] ed25519-signature: payload signed by stated key
[PASS] merkle-inclusion: anchored at index 0 of 1 (Merkle-consistent under the STATED root)
[PASS] root-authenticity: stated root matches the expected authenticated root
[PASS] tree-size: tree_size 1 matches the expected size
CRYPTO: OK
ROOT-AUTHENTICITY: PASS (payload-signature PASS, merkle-consistency PASS, tree-context PASS, root-trust-level ROOT_AND_TREE_SIZE_PINNED, safe-for-automation false)
SAFE_FOR_AUTOMATION: NO
Reason:
  No trust policy was evaluated (supply --policy to authorise a signer)
POLICY: NOT_EVALUATED (no trust policy supplied)
ASSURANCE: self_attested (issuer-declared)
LIMITATIONS: NOT that the result is true, the eval well designed, the model safe/fair, or that the score generalizes (see NON_CLAIMS.md); and NOT when it happened, unless an external time anchor is present
```

The last blocker is the trust decision itself. A relying party instantiates a shipped policy template into an organisation policy, pinning the issuer key and the expected root:

```
$ proofbundle policy instantiate strict-eval-authenticated-root-template-v1 --issuer-key issuer.pub --policy-id b7n0de/note-example-v1 --expected-root-file root.b64 --output note_policy.json
[policy-instantiate] strict-eval-authenticated-root-template-v1 -> note_policy.json  deploymentReady=True  policy_id=b7n0de/note-example-v1
```

Verifying under that strict policy does not upgrade this receipt; it honestly refuses it (exit 3, a policy failure distinct from a cryptographic failure), because the profile demands an assurance level this self-attested example does not have:

```
$ proofbundle verify receipt.json --policy note_policy.json
[PASS] ed25519-signature: payload signed by stated key
[PASS] merkle-inclusion: anchored at index 0 of 1 (Merkle-consistent under the STATED root)
CRYPTO: OK
ROOT-AUTHENTICITY: PASS (payload-signature PASS, merkle-consistency PASS, tree-context NOT_EVALUATED, root-trust-level ROOT_BYTES_ONLY, safe-for-automation false)
SAFE_FOR_AUTOMATION: NO
Reason:
  Root and tree size were not authenticated ATOMICALLY from one source (a signed checkpoint via --trusted-checkpoint / policy trusted_checkpoints, or an --expected-root + --expected-tree-size pair) — a root-bytes-only pin cannot detect a tree-size/leaf-index relabel (A-P0-1)
  The supplied trust policy was not satisfied
POLICY: FAIL (assurance_level 'self_attested' below minimum 'reproduced')
ASSURANCE: self_attested (issuer-declared)
LIMITATIONS: NOT that the result is true, the eval well designed, the model safe/fair, or that the score generalizes (see NON_CLAIMS.md); and NOT when it happened, unless an external time anchor is present
```

Three verdicts on one receipt, and none contradicts another: the signature and stated-tree inclusion verify (exit 0); the root and tree size match the values supplied by the relying party (exit 0); and the strict policy still refuses to authorize a self-attested result for automation (exit 3). Matching supplied values is a trust decision, not an intrinsic property of the receipt. The refusal is the feature.

### 3.4 A decision receipt over that evidence (experimental)

A release gate now signs a decision that publishing the receipt is allowed. The predicate binds the proposed action parameter by digest to the exact receipt bytes (the `sha256` below is the digest of `receipt.json`) and records what the gate did *not* check with the same prominence as the verdict. Six blocks are elided for print (`agent`, `principal`, the digest-bound `policyBoundary`, `inputSnapshot`, `decisionChangeConditions`, `privacy`; `evidenceRefs` is empty); the template comes from `proofbundle decision init`. The elided `policyBoundary` carries the SHA-256 of the companion `gate_policy_example.json` (`6c8a2e170122ff8c5f2600eba92d7fd1c78a62be08f7b952f32850218d1bae1b`), so that binding is recomputable from the deposited files. In this printed example, `evidenceRefs` is empty, so the artifact binds the publication action to the receipt bytes but does not cryptographically prove that the gate evaluated that receipt as evidentiary input:

```
{
  "schemaVersion": "0.1.0",
  "decisionId": "urn:uuid:58b69bef-2a75-5991-9c56-1d9a703a94f7",
  "decisionType": "preActionAuthorization",
  "decidedAt": "2026-09-05T09:00:00Z",
  "decisionMaker": {
    "id": "https://b7n0de.com/gate/eval-publish/v1",
    "version": {
      "proofbundle": "6.0.0"
    }
  },
  "proposedAction": {
    "actionType": "tool.call",
    "target": {
      "name": "publish-eval-receipt",
      "uri": "file://artifacts/receipt.json"
    },
    "method": "POST",
    "parametersDigest": {
      "sha256": "441a3a2aa803c738776151fffc7673cf80ccb0e35f3c19dbf7f91590e8194aac"
    }
  },
  "evidenceRefs": [],
  "decision": {
    "verdict": "ALLOW",
    "reasonCodes": [
      "eval.threshold.pass"
    ],
    "humanReadableSummary": "arc-easy accuracy >= 0.80 receipt verified offline (CRYPTO OK, root and tree size pinned); publishing the receipt is allowed.",
    "obligations": [],
    "allowedScope": []
  },
  "notChecked": [
    {
      "field": "evaluation design",
      "reason": "out of scope of this gate",
      "impact": "a well-formed receipt over a poorly designed eval still passes this gate"
    }
  ]
}
```

```
$ proofbundle decision emit decision_predicate.json --new-key decision_key.seed --out decision_receipt.json
wrote new signing key to decision_key.seed (keep this secret)
wrote decision receipt decision_receipt.json
$ proofbundle decision verify decision_receipt.json --pub o6qD/8+Vgu1aGYW5F97xAyI76t8ZzpFLnWC3yIOCVKE=
CRYPTO: OK
POLICY: NOT_EVALUATED (no decision policy supplied)
STRUCTURE: OK
SUBJECT: DERIVED

This proves the signed decision claim has not been altered. It does not prove the decision was correct, legal, safe, or that the action was executed.
```

A verified ALLOW receipt is a record of a decision, never an authorization or bearer token; the executing system makes its own authorization check.

### 3.5 An outcome receipt, bound to that decision (experimental)

An executor identifier under a different public key reports that it carried the action out and signs that report. The binding value is the decision statement's content root: SHA-256 over the exact signed payload bytes of the decision receipt, which any reader recomputes with one line of Python (`hashlib.sha256(base64.b64decode(envelope["payload"])).hexdigest()`), here `1e60e75f...cfec32` (64 hex digits, in full in the `decisionRef` below). The outcome predicate digest-binds the requested action (the same `sha256` the decision authorized), the actual action, the observed response, and the claimed effect, and it declares its own limitation in the signed bytes (two housekeeping fields elided for print: `policyPurpose`, `traceContext`). As in the 5.0.0 revision, the `responseDigest` has a stated preimage among the deposited files: it is the SHA-256 of the pinned-verify transcript of Section 3.3, so a reader can recompute it rather than take it on trust; that transcript is byte-identical to its 5.0.0 counterpart, so the digest is the same value as in the 5.0.0 revision:

```
{
  "schemaVersion": "0.1.0",
  "outcomeId": "urn:uuid:698b6c0d-6a0b-59f7-8130-1c22d0128b7b",
  "decisionRef": {
    "sha256": "1e60e75f2969a58e66632a9348a028751d16c0e04e45973732ce43491ccfec32"
  },
  "executor": {
    "id": "workload://b7n0de/release-runner",
    "keyId": ""
  },
  "requestedActionDigest": {
    "sha256": "441a3a2aa803c738776151fffc7673cf80ccb0e35f3c19dbf7f91590e8194aac"
  },
  "actualActionDigest": {
    "sha256": "441a3a2aa803c738776151fffc7673cf80ccb0e35f3c19dbf7f91590e8194aac"
  },
  "responseDigest": {
    "sha256": "7cabd9748e8a115fcffcb46ee65f8a9976ab1cae2fb56669256e3c3c6f085f5b"
  },
  "effectDigest": {
    "sha256": "441a3a2aa803c738776151fffc7673cf80ccb0e35f3c19dbf7f91590e8194aac"
  },
  "status": "executed",
  "performedAt": "2026-09-05T09:02:00Z",
  "limitations": [
    "status=executed attests the executor's signature over these digests, not the external effect itself"
  ]
}
```

```
$ proofbundle outcome emit outcome_predicate.json --new-key executor_key.seed --out outcome_receipt.json
wrote new signing key to executor_key.seed (keep this secret)
wrote outcome receipt outcome_receipt.json
$ proofbundle outcome verify outcome_receipt.json --pub CoTv15VBpCw1hfh7ffod/Nexox0phKUQrRjm+Fc6x2s= --expected-decision-ref 1e60e75f2969a58e66632a9348a028751d16c0e04e45973732ce43491ccfec32 --decision-maker-id https://b7n0de.com/gate/eval-publish/v1
  ! DEPRECATED: execution_proven / receiver_bound are digest-presence booleans (evidence_levels REFERENCE_WELL_FORMED — attacker-choosable content), NOT a content proof. Use evidence_levels; only CONTENT_RESOLVED or stronger is a real binding. These legacy fields will be removed in the next breaking format version.
CRYPTO: OK
STRUCTURE: OK
DECISION_BINDING: OK
ROLE_SEPARATION: OK
SUBJECT: DERIVED

This proves who signed what happened, bound to the referenced decision. It does not prove the effect was good, correct or desired.
```

`DECISION_BINDING` fails closed on a cross-decision replay (an outcome grafted onto a different decision); `ROLE_SEPARATION` fails closed when the executor is the decision maker. The chain can therefore be read offline under three different public keys: *the evaluation receipt verifies cryptographically under its stated key and root; the gate signed an ALLOW decision for a digest-bound publication action and declared omissions; the executor signed a report bound to that decision.* Different keys do not by themselves prove organizational independence, and this example has no external time anchor or receiver-observed effect. What each layer does not prove remains explicit.

### 3.6 Tampers are caught

The bundled demonstration runs the whole story in memory and prints, verbatim (the challenged index is run-variant; every other line is word-stable):

```
$ proofbundle demo
proofbundle offline demo — in memory, no files, no network

[PASS] honest receipt verifies  => OK

tamper matrix (each must be caught → verify FAILED):
  [caught] payload rewrite (passed:true→false)
  [caught] signature graft from another key
  [caught] public-key swap to attacker key
  [caught] Merkle root replacement
  [caught] leaf-index shift
  [caught] drop merkle.hash_alg (non-canonical)

[PASS] per-sample audit: challenged index 5: honest opening OK=True, swapped-sample opening OK=False (must be False)

=> OK — every guarantee held
```

Six distinct mutation cases are each caught by the check they attack: a payload rewrite, a signature graft, and a public-key swap by the signature check; a Merkle root replacement and a leaf-index shift by the inclusion check; a dropped hash-algorithm field by canonicalization. The demo also catches the deliberately swapped sample at the challenged index. That one run is a functional example, not a population-level statistical guarantee; such a guarantee depends on the challenge protocol and sample size.

### 3.7 Independent recomputation, without proofbundle

A receipt must not require its own producer's code to be checked. The following script uses only the Python standard library and the `cryptography` package, no proofbundle import, and recomputes the two checks used by this specific one-leaf example against the companion `receipt.json`. It is intentionally not a general RFC 6962 verifier:

```
#!/usr/bin/env python3
"""Independent check for the companion ONE-LEAF example; not a general CT verifier."""
import base64, hashlib, json, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

path = sys.argv[1] if len(sys.argv) > 1 else "receipt.json"
with open(path, encoding="utf-8") as fh:
    r = json.load(fh)

def b64(value):
    return base64.b64decode(value, validate=True)

payload = b64(r["payload_b64"])
pub = b64(r["signature"]["public_key_b64"])
sig = b64(r["signature"]["sig_b64"])
Ed25519PublicKey.from_public_bytes(pub).verify(sig, payload)   # raises on failure
print("ed25519 signature over payload bytes: VALID")

m = r["merkle"]
assert m["hash_alg"] == "sha256-rfc6962"
assert m["tree_size"] == 1 and m["leaf_index"] == 0
assert m["inclusion_proof_b64"] == []
root = hashlib.sha256(b"\x00" + payload).digest()              # RFC 6962 leaf hash
stated = b64(m["root_b64"])
print("recomputed RFC 6962 root == stated root:", root == stated)
if root != stated:
    raise SystemExit("root mismatch")
```

```
$ python3 independent_check.py receipt.json
ed25519 signature over payload bytes: VALID
recomputed RFC 6962 root == stated root: True
```

### 3.8 Reproduce this yourself

```
$ pip install "proofbundle[eval]==6.0.0"
$ proofbundle demo
```

`demo` runs exactly the emit, verify(OK), tamper, verify(FAILED) sequence above end-to-end, with no model access or external service and without relying on the prose assertions in this document. Offline verification does not eliminate trust. It relies on the verifier implementation, algorithm implementations, the supplied or embedded key material, and any relying-party policy. The script of Section 3.7 independently checks the narrow one-leaf cryptographic example without importing proofbundle. This demonstrates signature validity and inclusion under the stated root for a claimed result; it does not establish the truth of the result, the quality of the evaluation, root authorization, or the completeness of the run history.

### 3.9 A signed review disclosure for a pull request (v0.2)

The two v0.2 receipts published on pull request 185 of the repository ship inside the package under `receipts/agent_review/`, together with the public keys that signed them. The agent review predicate is a library surface, not a subcommand; the companion script `agent_review_v02_check.py`, deposited with this note, verifies the second published receipt (`proofbundle_185.r2.receipt.json`) under the shipped standard policy, twice, and the transcript below is its output. The first run supplies no expectation about the reviewed object; the second supplies the subject digest, here taken from the statement itself, so that run proves internal consistency and policy acceptance, not that the receipt belongs to the pull request a reader is looking at, which is exactly the distinction the verifier insists on:

```
$ python3 agent_review_v02_check.py
subject: github-pr:b7n0de/proofbundle#185 sha256: 0dde610e4f77e6dd...
--- run 1: no expected subject digest supplied
ok                       False
crypto_ok                True
predicateVersionStatus   'current'
policy_decision          'accept'
policy_name              'agent-review/default'
policy_digest            'sha256:248daae3a72020112479b3027d1ed269606e8cecb30ecad7c4226d28826b5280'
reason_codes             []
advisory_codes           []
event_time_status        'SELF_DECLARED'
observation_time_status  'ABSENT'
time_consistency_ok      True
subject_expectation      'not_supplied'
errors                   ['ok=False because no expected subject digest was supplied']
limitation_codes         ['COVERAGE_PARTIAL', 'CURRENTNESS_UNKNOWN', 'IDENTITY_UNBOUND', 'NOT_QUALITY_ATTESTATION', 'TIME_SELF_DECLARED']
safeForAutomation        False
--- run 2: expected subject digest supplied (here taken from the statement itself)
ok                       True
crypto_ok                True
predicateVersionStatus   'current'
policy_decision          'accept'
policy_name              'agent-review/default'
policy_digest            'sha256:248daae3a72020112479b3027d1ed269606e8cecb30ecad7c4226d28826b5280'
reason_codes             []
advisory_codes           []
event_time_status        'SELF_DECLARED'
observation_time_status  'ABSENT'
time_consistency_ok      True
subject_expectation      'checked'
errors                   []
safeForAutomation        True
automationBlockers       []
```

Three things are visible at once. The signature and the structure verify in both runs (`crypto_ok`), and the standard policy accepts the receipt's derived limitation codes in both runs, with the policy named and its digest reported. `ok` is nevertheless false in the first run, with the reason spelled out: a relying party who has not said which object it expects has not verified a binding, and the verifier refuses to pretend otherwise. The five limitation codes remain in the accepted result: the coverage is partial, the currentness of the review is unknown, the signing key is bound to no identity, the receipt attests no quality, and every time claim is self-declared. That is the honest shape of a v0.2 receipt as shipped. The rendered disclosure block that the receipt binds by digest is the published `.block.md` next to it; comparing an observed block to the signed digest is the `observed_body` path of the same verifier and is not exercised in this transcript.

## 4. Related work and honest delineation

**Supply-chain statements and transparency.** in-toto and Sigstore provide mature mechanisms for signed software-supply-chain statements and public transparency. RFC 9943, published in June 2026, specifies the SCITT architecture for trustworthy and transparent digital supply chains and emphasizes that transparency holds issuers accountable but does not make their statements accurate. proofbundle reuses adjacent ideas, namely signed statements, DSSE, Merkle inclusion, checkpoints, and relying-party policy, while defining evaluation-shaped fields and offline verdicts. Its core receipt is not a SCITT Receipt, and interoperability should be demonstrated rather than implied.

**Nonrepudiable experiment records.** K-Veritas (arXiv:2605.08586, preprint) formalizes the problem of experimental results that cannot be checked after publication and provides a Go reference implementation. It is close prior work and establishes that proofbundle's problem statement is not unique. proofbundle's narrower contribution is a released Python package and a specific receipt and policy design; comparative conformance and independent evaluation remain open work.

**Evaluation methodology and reporting.** BenchJack (arXiv:2605.12673, preprint) shows that agent benchmarks can yield high scores through reward-hacking exploits without solving the intended task. Evaluation Cards (arXiv:2606.09809), Rollout Cards (arXiv:2605.12131), and Every Eval Ever (arXiv:2606.14516) are 2026 preprints proposing operational reporting, rollout preservation, and shared evaluation schemas. These works address what was evaluated, how results should be interpreted, and which records should be preserved. A proofbundle receipt can hash-bind such records but cannot supply their methodological validity.

**Cryptographic and hardware-rooted execution assurance.** Balan et al. (arXiv:2503.22573, preprint) study cryptographic verifiability of end-to-end AI pipelines. *Attestable Audits* (arXiv:2506.23706, preprint) uses trusted execution environments for benchmark auditability. A TEE can attest measurements and software state under hardware, firmware, vendor, reference-value, and verifier assumptions; it does not automatically prove semantic correctness of the computation. proofbundle can carry or bind an Attestation Result appraised by the relying party, but does not itself validate the truth of the workload's outputs.

**Agent decisions and action receipts.** Proof-Carrying Agent Actions (arXiv:2606.04104, preprint) separates several checkpoints from admissibility through outcome closure. The active IETF SCITT Working Group also lists individual Internet-Drafts for pre-execution permits, AI-agent action receipts, Agent Action Capsules, authorization receipts, and bilateral attestations. As Internet-Drafts they are work in progress and have no standards status, but they sharpen a design lesson relevant here: a dispatched attempt, a signed executor report, a receiver confirmation, and an independently observed effect are different assurance states.

**Receiver-attested records, and the limitation they address.** Notarized Agents (arXiv:2606.04193, preprint) is directly adjacent to the boundary this note draws around outcome receipts. It observes that an agent which writes its own activity log can tamper with that log undetected, and proposes a protocol in which external services, rather than the agent, sign receipts of agent actions, encrypt them to the owner, and publish them to a transparency log. That is precisely the gap Section 3.5 declares and does not close: an `action-outcome/v0.1` is an *executor*-signed report, so it attests who signed what happened, not that a receiver observed it. The same boundary holds for the review disclosure of Section 3.9: a v0.2 receipt is self-declared by the agent workspace that produced it, and a witness outside that workspace is not provided by this version. Receiver attestation is the structurally stronger answer to that question, and this note claims the weaker one.

**Evidentiary and legal interpretation.** Recent work on evidentiary adequacy for agentic AI oversight (arXiv:2607.00941, technical report) argues that integrity-preserved runtime records do not alone establish legally operative findings; the record must also encode the types and relations on which the finding depends. This is consistent with the boundary in this note: cryptographic integrity is necessary for some audit uses but not sufficient for legal or factual conclusions.

**Positioning.** proofbundle is a released Research Beta for portable, offline verification of signed evaluation and experimental agent-action claims, and since 5.1.0 of signed review disclosures. It is a lightweight complement to transparency services, reporting schemas, independent reproduction, TEE appraisal, and stronger proof-of-computation systems. The formats described as experimental should not be presented as settled standards, and the absence of an external audit limits assurance claims.

## 5. Mapping to Articles 53/55 and the Code of Practice

The table identifies ways an integrity receipt may support documentation workflows. It is not a legal opinion, a conformity assessment, or proof of compliance. Applicability depends on the actor, model, transition rules, selected Code commitments, and the evidence required by the competent authority.

| Context | Evidence need | Potential contribution | Residual question |
|---|---|---|---|
| Art. 53 and Annex XI: technical documentation for GPAI models | Preserve which evaluation claim and artifact version were supplied | Authenticates exact signed bytes and selected commitments; an optional valid anchor can show that a datum existed by a time | Whether the documentation is complete, current, accurate, and legally sufficient |
| Art. 55: evaluation and documented adversarial testing for systemic-risk GPAI | Preserve run claims and sample commitments against later alteration | Merkle commitments and challenge openings can make post-signing edits detectable and support bounded spot checks | Whether the suite was state of the art, representative, secure against gaming, and correctly executed |
| Art. 55: incident reporting and risk management | Relate a signed claim, decision record, and executor report | Experimental digest bindings can preserve the asserted chain and declared omissions | Whether reporting was complete, whether authority was valid, and whether the external effect occurred |
| Voluntary GPAI Code of Practice and external evaluation workflows | Exchange evidence without continued access to the issuer's service | Offline verification of the supplied artifact under the recipient's key, root, anchor, and policy choices | Evaluator competence and independence; scope, methodology, and interpretation of the evaluation |
| Confidentiality constraints | Reveal selected signed claims while withholding other fields | SD-JWT can verify issuer-bound disclosure of named fields and commitments | Truth of hidden identifiers, linkage risk, and whether the disclosed verdict follows from a hidden score |
| Documenting what a harness did not report | Distinguish an unreported version from an unbound harness | The reported-version status records which of the two holds, with a mandatory reason | Whether the reason given is accurate; the status is issuer-recorded, not independently corroborated |
| Documenting who reviewed an AI-assisted change and what the review did not cover (Art. 53 technical documentation, voluntary Code of Practice) | Preserve a signed declaration of AI involvement, review runs, coverage and limitations, bound to the reviewed object | The v0.2 review receipt binds object, runs, coverage, limitation codes and the visible disclosure block by digest, and a policy file decides on the derived codes | Whether the declared review actually took place as declared, whether the signing key is bound to an identity, and whether the review was any good; all three are outside the receipt |

## 6. Reproducibility and artifact availability

**Pinned software release.** Version 6.0.0 is not yet published: the tag `v6.0.0`, the PyPI page, the archived software record and the three digests below are NOT MEASURED until the release run and are filled in before deposit. The 5.0.0 revision reported, checked on 2026-08-30, one Trusted Publishing attestation bundle per distribution file issued by the GitHub workflow `release.yml` of the `b7n0de/proofbundle` repository; the same check is repeated for 6.0.0 after the release and is NOT MEASURED here.

```
proofbundle-6.0.0.tar.gz            NOT MEASURED (built at the tag with the tagged commit's epoch)
proofbundle-6.0.0-py3-none-any.whl  NOT MEASURED
receipt.json                        NOT MEASURED (re-captured against the shipped wheel)
```

Measured on the frozen head instead, as the methodological proof: two normalised sdists built with `scripts/build_reproducible.py --check` at the head's own epoch (`1788589731`) are byte-identical, sha256 `08db75e4ae55d0f0792e0ae1614d182efd91094785c7d41a8b0ab419fef5101c`; the wheel built alongside has sha256 `ba4048d60d88d1d30a1383562b534c1fba787a927e37cb1f6dffcf52b4e20d09` and is the wheel behind every transcript of Section 3. The shipped files will differ from these values because the release workflow builds at the epoch of the tagged commit, with identical content.

**Core example.** Start in a new directory, place the companion `receipt.json` in that directory, and run:

```
$ python3 -m venv venv && . venv/bin/activate
$ python -m pip install "proofbundle[eval]==6.0.0"
$ proofbundle demo
$ proofbundle verify receipt.json
$ proofbundle verify receipt.json --expected-root bGQENnsdUG9JcwhlKcmsQRw7Y25dxsu3LOswY6PLXVI= --expected-tree-size 1
$ proofbundle show-eval receipt.json
```

The `[eval]` extra installs the JCS implementation needed by demo and emit paths. The challenged index in `demo` and the wall-clock-derived `age` line vary. The companion receipt has been independently checked without importing proofbundle: its Ed25519 signature is valid, its 684-character base64 payload and 88-character signature fields match this manuscript, and its one-leaf RFC 6962 root equals `SHA256(0x00 || payload)`. The companion receipt of this draft was emitted under a key generated for the draft; it is re-emitted against the shipped wheel before deposit, and the values above change with it.

**Scope of reproducibility claim.** The PDF plus `receipt.json` are sufficient to check the narrow core example and Appendix A. They are *not* sufficient to regenerate every decision, outcome, policy, transcript, test-count, or mutation-count claim in this manuscript. A deposit seeking ACM-style artifact evaluation should therefore include the Markdown source, claim and predicate inputs, decision and outcome receipts, policy file, independent checker, exact transcripts, counting manifest, environment lock or container, and one command that validates hashes and reruns the checks. Until that complete pack is deposited and independently executed, this manuscript should claim repeatability evidence and a reproducible core receipt example, not full independent reproduction of the entire note.

**Accessibility of this document.** As in the 5.0.0 revision, this document is produced by a rendering pipeline that emits a structure tree, so assistive technology receives a reading order rather than a flat sequence of glyphs, and the pipeline disables typographic ligature substitution, so extracted and copied text contains no ligature codepoints. Both properties are measured on the rendered file rather than inferred from a build flag. Two honest limits: full conformance to PDF/UA-2 (ISO 14289-2) is *not* claimed and has not been checked with a conformance validator, and a structure tree is a necessary but not sufficient condition for that conformance.

**Archival publication.** Zenodo versioning creates a new record and persistent identifier for each file-changing version. A version DOI for this revision is reserved and inserted before archival publication under the existing concept DOI, as a new version of the existing record, after the software release exists. The concept DOI remains useful for "latest version" discovery, while scientific citations and hash manifests should identify the specific version. The document text is intended for CC-BY-4.0; proofbundle code remains MIT-licensed.

## 7. Conclusion

Evaluation results can form part of consequential technical and regulatory documentation, but the usual bare number carries little artifact-level evidence. proofbundle closes a narrower link: it lets a recipient verify exact signed bytes, inclusion under a stated tree, and selected relying-party trust, policy, disclosure, and anchor conditions. The experimental line extends those bindings to decision and outcome claims and explores long-term renewal. It does not determine whether the claim is true, the benchmark is valid, a run set is complete, authority is legally sufficient, or an external effect occurred.

That separation is the central contribution, and the 6.0.0 line applies it to a new kind of statement: a declaration about a review. The disclosure a reader sees in a pull request is bound by digest to a signed predicate that names the runs, the coverage and the limitations, so the visible text cannot claim more than the signature covers; a policy that is a file decides on the derived limitation codes and reports its own digest; and the verifier withholds `ok` until the relying party has named the object it expects. Where the 5.0.0 line replaced an ambiguous silence about a harness version with a recorded state, the 6.0.0 line replaces an unverifiable sentence in a pull request with a receipt that says what was declared and, with the same prominence, what was not.

A cryptographically valid receipt may still be unsafe for automation; a signed ALLOW may still lack an evaluated policy; a digest-bound outcome may still be only an executor report; a signed review disclosure may still describe a poor review; and a transparent ledger may still be incomplete unless its state was externally committed. For external-evaluation workflows, proofbundle can provide verifiable evidence of *what bytes and claims were signed under which keys and supplied trust conditions*. The harder conclusions, namely what was actually measured, whether it was measured correctly, who legally controlled the keys, and what the evidence means, remain questions for independent evaluators, reviewers, relying parties, and competent authorities.

## References

1. M. K. Keita and C. Homan. *Computer Science Conferences Should Require Nonrepudiable Experimental Results* (K-Veritas). arXiv:2605.08586, preprint, 2026. <https://arxiv.org/abs/2605.08586>
2. K. Balan, R. Learney, and T. Wood. *A Framework for Cryptographic Verifiability of End-to-End AI Pipelines*. arXiv:2503.22573, preprint, 2025. <https://arxiv.org/abs/2503.22573>
3. *Attestable Audits: Verifiable AI Safety Benchmarks Using Trusted Execution Environments*. arXiv:2506.23706, preprint, 2025. <https://arxiv.org/abs/2506.23706>
4. A. Ghosh et al. *Evaluation Cards: An Interpretive Layer for AI Evaluation Reporting*. arXiv:2606.09809, preprint, 2026. <https://arxiv.org/abs/2606.09809>
5. C. Masters, Z. Liu, and S. V. Albrecht. *Rollout Cards: A Reproducibility Standard for Agent Research*. arXiv:2605.12131, preprint, 2026. <https://arxiv.org/abs/2605.12131>
6. J. Batzner et al. *Every Eval Ever: A Unifying Schema and Community Repository for AI Evaluation Results*. arXiv:2606.14516, preprint, 2026. <https://arxiv.org/abs/2606.14516>
7. H. Wang et al. *Do Androids Dream of Breaking the Game? Systematically Auditing AI Agent Benchmarks with BenchJack*. arXiv:2605.12673, preprint, 2026. <https://arxiv.org/abs/2605.12673>
8. Z. Wang et al. *Proof-Carrying Agent Actions: Model-Agnostic Runtime Governance for Heterogeneous Agent Systems*. arXiv:2606.04104, preprint, 2026. <https://arxiv.org/abs/2606.04104>
9. J. Figuera et al. *Notarized Agents: Receiver-Attested Confidential Receipts for AI Agent Actions*. arXiv:2606.04193, preprint, submitted 2 June 2026. <https://arxiv.org/abs/2606.04193>
10. J. Janssen. *From Runtime Records to Legal Findings: An Evidentiary-Adequacy Criterion for Agentic AI Oversight*. arXiv:2607.00941, technical report, 2026. <https://arxiv.org/abs/2607.00941>
11. Regulation (EU) 2024/1689 (Artificial Intelligence Act), Articles 53 and 55, Annex XI. <https://eur-lex.europa.eu/eli/reg/2024/1689/oj/eng>
12. European Commission. *General-Purpose AI Code of Practice*; published 10 July 2025, voluntary compliance tool. <https://digital-strategy.ec.europa.eu/en/policies/contents-code-gpai>
13. RFC 8032 (Ed25519); RFC 6962 and RFC 9162 (Certificate Transparency); RFC 8785 (JCS); RFC 3161 (Time-Stamp Protocol); RFC 9901 (SD-JWT). <https://www.rfc-editor.org/>
14. RFC 9943. *An Architecture for Trustworthy and Transparent Digital Supply Chains* (SCITT), Standards Track, June 2026. <https://www.rfc-editor.org/rfc/rfc9943>
15. Representative active Internet-Drafts (work in progress; no standards status; revisions and dates as checked 2026-08-30 for the 5.0.0 revision, NOT re-checked for this draft): *A SCITT Profile for Pre-Execution AI Action Authorization Records* (`draft-munoz-scitt-permit-profile-01`, 18 July 2026); *A SCITT Profile for AI-Agent Action Receipts* (`draft-noa-scitt-ai-agent-receipt-01`, 14 August 2026); and *An Agent Action Capsule Profile for SCITT* (`draft-mih-scitt-agent-action-capsule-04`, 28 August 2026). <https://datatracker.ietf.org/group/scitt/>
16. RFC 4998 (Evidence Record Syntax); RFC 6283 (XMLERS); RFC 6920 (Naming Things with Hashes). <https://www.rfc-editor.org/>
17. FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA), and NIST SP 800-208 (LMS/XMSS). <https://csrc.nist.gov/>
18. ISO 14289-2:2024 (PDF/UA-2), universal accessibility for PDF 2.0; ISO 32000-2 (PDF 2.0). <https://www.iso.org/>
19. C2SP specifications and OpenTimestamps. <https://c2sp.org/> · <https://opentimestamps.org/>
20. N. P. Chue Hong et al. *FAIR Principles for Research Software (FAIR4RS Principles)*. Zenodo, 2022. <https://zenodo.org/records/6623556>
21. ACM. *Artifact Review and Badging* terminology: repeatability, reproducibility, and replicability. <https://reviewers.acm.org/training-course/artifact-review-and-badging>
22. proofbundle source and release artifacts. <https://github.com/b7n0de/proofbundle> · <https://pypi.org/project/proofbundle/6.0.0/> (exists after the release run) · archived software release (v6.0.0): its Zenodo version DOI under concept DOI 10.5281/zenodo.21110642 is minted by the release run and is NOT MEASURED in this draft; the 5.0.0 software record is <https://doi.org/10.5281/zenodo.22129220>

**Cite this note as:** K. Gruszka. *Evidence Integrity for AI Evaluations* (describing proofbundle 6.0.0). Zenodo, 2026. The concept DOI [10.5281/zenodo.21230466](https://doi.org/10.5281/zenodo.21230466) resolves to the latest version; the version DOI for this revision is assigned at deposit.

## Appendix A. A signed example receipt

The listing below is a layout-wrapped transcription of the companion `receipt.json`. That file was emitted under a throwaway key generated for this draft, so its public key differs from the key in the record's earlier attachments, and it was independently re-verified, including by the proofbundle-free one-leaf checker of Section 3.7. The inserted whitespace inside the visually wrapped base64 string means that copied PDF text is *not* a byte-preserving JSON transport. The companion file, whose SHA-256 is stated in Section 6 once measured against the shipped wheel, is the authoritative byte form. Run `proofbundle verify receipt.json` against that file to reproduce the core cryptographic check of Section 3.2 offline.

```
{
  "schema": "proofbundle/v0.1",
  "payload_b64": "eyJhc3N1cmFuY2VfbGV2ZWwiOiJzZWxmX2F0dGVzdGVkIiwiY29tbWl0X2FsZyI6InNoYTI1Ni1zYWx0ZWQtdjEiLCJj
    b21wYXJhdG9yIjoiPj0iLCJkYXRhc2V0X2lkX2NvbW1pdCI6InNoYTI1NjpkMGIxNDMzM2Q0MjViZWVlODQyNjY0MmM5
    MzI3YTMyNjE3ZTZmN2ZiNzdhMmYzYmUyMTJiMDFjNDEwZmQ5MzYyIiwiaXNzdWVyIjoiZWQyNTUxOTp1RzhzM3RxSW9S
    QW0rT3Q4YmF5bUNtanRLWTljdU5Sc3NySWYrWXBHZE5vPSIsIm1ldHJpYyI6ImFjY3VyYWN5IiwibW9kZWxfaWRfY29t
    bWl0Ijoic2hhMjU2OjQxNjJjYjRlYzk2NmViNTExYTQ4NGFlOTIyMjY4YWE2NGQ4MWZhM2UwNDEzZjgxYTk3ZjlkZTgx
    ZmQ2YjEyM2QiLCJuIjoyMzc2LCJwYXNzZWQiOnRydWUsInNjaGVtYSI6InByb29mYnVuZGxlL2V2YWwtY2xhaW0vdjAu
    MSIsInN1aXRlIjoiYXJjLWVhc3kiLCJzdWl0ZV92ZXJzaW9uIjoiMS4wIiwidGhyZXNob2xkIjoiMC44MCIsInRpbWVz
    dGFtcCI6IjIwMjYtMDktMDVUMDY6MDA6MDBaIn0=",
  "signature": {
    "alg": "ed25519",
    "public_key_b64": "uG8s3tqIoRAm+Ot8baymCmjtKY9cuNRssrIf+YpGdNo=",
    "sig_b64": "ezBqzPa9Y9ZP1gBC7gsnQnS1D8jg7Kab2hQBBJq/3X9COlBe6THhywQyNaDwDsEUszcrs24l12ltdjqRxrBNAw=="
  },
  "merkle": {
    "hash_alg": "sha256-rfc6962",
    "leaf_index": 0,
    "tree_size": 1,
    "inclusion_proof_b64": [],
    "root_b64": "bGQENnsdUG9JcwhlKcmsQRw7Y25dxsu3LOswY6PLXVI="
  }
}
```
