# Glossary — proofbundle in plain terms

For a developer without a cryptography background. No math, just what each word means here and why
it matters.

## The 30-second picture

proofbundle takes an **eval result** (a number your model scored) and wraps it in a **receipt** — a
single file that anyone can check *offline*. Checking the receipt answers one question: *were these
exact bytes signed by this key, and unchanged since?* If yes, `verify` prints `=> OK`. If anything
was altered, it prints `=> FAILED`. That's it. It does **not** tell you the number is true — only
that a specific party stands behind it and nobody tampered with it afterward.

## Five things, in order

1. **You run an eval** (with inspect_ai, lm-eval, promptfoo, or pytest) → you get a score.
2. **An adapter** turns that score into a **claim** — a small, tidy JSON statement: "suite X,
   metric Y, threshold met, over N samples."
3. **Emit** signs the claim with a private key and anchors it in a Merkle tree → a **receipt**.
4. **You share the receipt** (one file). It can hide the model/dataset behind *commitments* and
   still prove the threshold.
5. **Anyone verifies it offline** → `OK` or `FAILED`.

## Terms

- **Receipt / bundle** — the one portable JSON file. The thing you share and verify.
- **Sign / signature (Ed25519)** — a private key produces a signature over the bytes; the matching
  public key proves *who* signed and that the bytes are unchanged. proofbundle never invents its own
  crypto — it uses the `cryptography` library.
- **Verify** — check the signature (and the other pieces) with no network. Output: `OK`/`FAILED`.
- **Merkle tree / inclusion proof (RFC 6962)** — a way to prove one item belongs to a set using a
  short chain of hashes. The same math transparency logs (Sigstore, Certificate Transparency) use.
  Here it anchors the payload, and (per-sample mode) commits to every individual sample.
- **Commitment (salted)** — a hash of a secret value (the model or dataset id) plus random salt.
  It proves *the threshold was met* without revealing *which model*. You can open it later to a
  specific auditor.
- **Assurance level** — a signed label the issuer declares: `self_attested` (I ran it),
  `third_party`, `reproduced`, `enclave_attested`. It records *who claims what level* — it is not an
  accredited stamp. `show-eval` warns on the weakest case.
- **SD-JWT / selective disclosure** — a credential format that lets you reveal some fields and hide
  others. Here: prove "passed ≥ threshold" while withholding the exact score.
- **Key Binding (KB-JWT)** — proof that the party *presenting* a credential controls the key it was
  bound to — stops someone replaying a credential they merely copied.
- **Witness / checkpoint / cosignature (C2SP)** — independent parties co-sign the Merkle root, so a
  log operator can't show different views to different people. Optional; can be post-quantum
  (ML-DSA-44).
- **Status list** — an offline revocation snapshot: a signed list saying which receipts are still
  valid. (v1.9.1 flags when the list is signed by the *same* key as the receipt — weak assurance.)
- **Per-sample audit** — the receipt commits to every sample; an **auditor** picks random samples
  (with a fresh **nonce** or a public **beacon** so the producer can't cheat) and the producer must
  **open** them — reveal them and prove they're in the committed set. Catches doctored samples.
- **Pre-registration (`prereg`)** — hashing your eval *plan* before you run, so you can't later
  claim the plan matched a lucky result. The hash goes in the signed receipt.
- **Trust anchor** — a key or value *you* must supply/pin for a check to mean anything (e.g. "I know
  this is really the lab's key"). See [TRUST_ANCHORS.md](TRUST_ANCHORS.md).
- **Lineage / relationship (`relation/v0.1`, EXPERIMENTAL)** — a receipt never changes; when a result
  is corrected, re-run, retracted, or renewed, the NEW receipt carries a typed, signed *relationship
  edge* pointing at the predecessor's content root (`supersedes`, `revises`, `corrects`, `retracts`,
  `renews`, `derivedFrom`, `amends`). `verify` reports it as a `lineage` state (VERIFIED /
  DECLARED_UNRESOLVED / FAIL / NOT_EVALUATED) — replacement becomes visible instead of silent. It
  proves the issuer *declared* the derivation over exact bytes; never that the successor is better or
  true, and it never changes the crypto verdict. Attach predecessors offline with `--with-related`.
- **`relation_signer` / `require_relation_target` (relying-party policy, 3.4.0)** — two optional pins
  in a trust policy's `relations` section. `relation_signer` says WHICH issuer keys may declare a
  replacement (a `same-key` rule or a pinned set); `require_relation_target` says WHICH parent an edge
  must resolve to (rejecting a valid-but-wrong "decoy" parent). Both are *your* policy: a passing
  check proves set membership / the named parent under your pins — not that anyone is "really"
  authorized. Enforced identically on the decision and outcome verify paths.

## What `=> OK` means (and doesn't)

`OK` = the signature is valid, the payload is anchored, and any optional pieces (SD-JWT, witnesses,
status, sample openings) checked out — **given the keys you supplied**. It does **not** mean the
eval was honest, well-designed, or the only run performed. Those need pre-registration, independent
reproduction, or a trusted execution environment. proofbundle makes a claim *attributable and
tamper-evident*; it never claims to make it *true*.
