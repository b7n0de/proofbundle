# Threat model — what a proofbundle receipt catches, and what it structurally cannot

A proofbundle receipt is a **tamper-evident, signed statement of authorship and integrity** over an eval or
test result. It is deliberately *not* a proof that the number is true or that the evaluation was well
designed. This document states the boundary precisely, so a strong signature is never mistaken for a strong
assurance. (Terminology: we say *tamper-evident signed evidence*, not *proof*; *authenticity and integrity*,
not *correctness of the computation*.)

## What `verify` catches

| Threat | Caught by | Result |
|---|---|---|
| **Payload tampering** — any byte of the claim changed after signing | Ed25519 signature over the canonical payload | `verify` → FAIL |
| **Merkle-root / inclusion tampering** — a forged inclusion path, or a root that is not internally consistent with the proof | RFC 6962 inclusion + consistency proofs | FAIL |
| **Coherent root rewrap** — the SAME signed payload re-anchored under a different, internally valid root (the native root is NOT in the signature input, so inclusion proves consistency under the *stated* root, not its authenticity) | caught only with a relying-party `--expected-root` / `expected_tree_size`, or a `merkle.require_authenticated_root` / `trusted_roots` policy (ADR 0004) | `NOT_EVALUATED` by default; **FAIL** under an authenticated-root policy or a matching `--expected-root` |
| **Crypto-valid receipt misread as automation-safe** — treating a signature-valid (even root-pinned) receipt as "safe to act on automatically" without an evaluated, signer-pinning trust policy | `safeForAutomation` is a GLOBAL verdict (AP-1, 3.1.1): `true` ONLY with a PASSED policy that pins a trusted signer, an authenticated root, no blocking warning, not expired, and no failed anchor gate (the transparency/replay blockers are forward-compat/dormant today); `automationBlockers` names every missing condition, and a raw policy TEMPLATE (`requiresIdentityOverlay:true`) can never qualify (blocker `TEMPLATE_NOT_INSTANTIATED`) — enforced on BOTH the eval and `decision verify` paths | a receipt with no policy, or a signerless / expired / raw-template policy, reports `safeForAutomation: false` with the reason(s) (or exit 3 for a decision receipt); the crypto verdict (`crypto_ok`, exit 0/1) is separate and unchanged |
| **Issuer swap** — re-signing with a different key while keeping the stated `issuer` | `decode_eval_claim` binds the claim `issuer` to the signing key | FAIL |
| **Model / dataset swap** — a claim silently attributing a result to a different model | salted commitment + `verify_commitment(identifier, salt, commitment)` | mismatch is visible |
| **Filtered disclosure** — hiding claims behind SD-JWT `_sd` digests | `sd_jwt_hidden_count` surfaces the number of withheld fields | omission is visible |
| **Replay** — presenting an old receipt as new | `check_freshness` reports age; a bound flags stale receipts | not-fresh is visible |
| **Weak assurance masked by a strong signature** — a self-attested PASS shown as if reproduced | `assurance_level` is signed into the claim (tamper-evident, issuer-declared); `show-eval` displays it; `claim_warnings` warns on self_attested + no pre-registration | a third party cannot alter the level; a dishonest issuer can still self-declare a higher one |
| **Holder-binding downgrade / replay** — replaying a disclosed SD-JWT issued with a `cnf` holder key, with the Key Binding JWT stripped or tampered, or replayed to the wrong verifier | `verify_bundle` verifies an attached KB-JWT (RFC 9901 §4.3), fails when the issuer bound a `cnf` key but no KB-JWT is present, and — when the relying party passes `expected_aud`/`expected_nonce` (CLI `--aud`/`--nonce`) — enforces §7.3 audience/replay binding | a bearer replay of a proof-of-possession credential FAILs; audience/nonce binding is enforced only if the caller supplies the expected values |
| **Unsigned SD-JWT disclosures** (WP-C2) — a bundle carries an `sd_jwt_vc` but supplies no `issuer_public_key_b64`, so its disclosures were never authenticated (the block sits OUTSIDE `payload_b64`, uncovered by the bundle signature) | `verify_bundle` runs `sd-jwt-issuer-signature` unconditionally when an `sd_jwt_vc` is present; with no issuer key it FAILS (reason `unsigned`), `sd_jwt_ok=false` | an SD-JWT whose issuer signature is not checked can no longer pass; secure-by-default since rev 2026-07-11 (previously null-and-warn) |
| **Cross-receipt SD-JWT substitution** (WP-C1) — an issuer-VALID SD-JWT lifted from bundle B and grafted onto bundle A, or a forged identity: a self-signed SD-JWT that NAMES a trusted issuer while signed by the attacker's own key | `sd-jwt-bundle-binding` requires the eval-claim disclosures + committed `receipt.root_b64` to match A's own signed claim + merkle root (reason `unbound`/`mismatch`), and an eval SD-JWT that carries an eval-binding root commitment (a `receipt.root_b64` string — the real substitution vector, NOT a word-match on `passed`/`threshold`/etc.) grafted onto a NON-eval-claim payload — where there is nothing to bind against — is refused fail-closed (reason `unbindable eval SD-JWT`, N1 2026-07-13, discriminator hardened after the pre-land audit); a generic SD-JWT-VC (`iss`/`vct`, no `receipt.root_b64` commitment) carries no eval claim to substitute and is out of scope; `sd-jwt-issuer-identity` requires `fingerprint(issuer_public_key_b64) == disclosed issuer` (reason `issuer-key-mismatch`) | a valid signature over the WRONG bundle or by the WRONG signer FAILs; the disclosures must bind THIS bundle and be signed by the key they name (still pin the expected issuer key out of band — TRUST_ANCHORS.md) |
| **Time-anchor backdating via self-frozen trust material** (WP-A1) — a producer freezes its OWN self-signed TSA root (or a self-committed Bitcoin block header) into the anchor's `frozen` block and stamps a BACKDATED time, so `--require-anchor` passes on producer-controlled "trust" | anchor trust comes ONLY from the relying party: rfc3161 verifies against `--trusted-tsa-root` / policy `anchors.trusted_tsa_roots`, opentimestamps confirms only against `--bitcoin-header` / policy `anchors.bitcoin_block_headers`; the `frozen` block is reported as `frozenEvidence` but never trusted | a forged-anchor-with-own-frozen is `needs_rp_trust` (ok=False) → `--require-anchor` unmet → exit 3; a confirmed verdict is only as good as the relying party's own TSA root / Bitcoin node — proofbundle never fetches either |
| **Split view by the log operator** — a witnessed checkpoint whose quorum is stuffed by one key under many names | `verify_witnessed_checkpoint` counts DISTINCT witness public keys, not names (C2SP cosignature/v1 + ML-DSA); the log's own signature stays required | one physical key cannot satisfy `threshold>1`; real split-view resistance still needs INDEPENDENT witness operators (a deployment property) |
| **Untrusted computation (mitigated only with a TEE, v2.0 preview)** — the eval could have run on tampered software; a software receipt cannot see this | EXPERIMENTAL `assurance_level=enclave_attested`: a RATS Verifier (RFC 9334) appraises TEE evidence and signs an EAT (RFC 9711) whose `eat_nonce` binds this receipt; `verify_enclave_attestation` checks it offline. **Note:** `enclave_attested` by itself is still just an issuer-declared STRING — nothing forces a claim carrying it to actually be accompanied by a real EAT. `proofbundle.evalclaim.enclave_assurance_proven(claim, bundle, eat_jws=…, verifier_pubkey=…)` (and `show-eval --eat/--verifier-key`) optionally corroborates the declared level against a real, receipt-bound Attestation Result — returning `True` only on a verified binding, `False` when the level is declared but uncorroborated (the honesty limit), `None` when the level isn't `enclave_attested` at all. This is additive and never rewrites the signed `assurance_level` field itself | proofbundle trusts the VERIFIER's key + appraisal (a supplied anchor) — it does not appraise raw TDX/GPU evidence itself, and cannot vouch for the TEE vendor's root of trust; still says nothing about eval quality/honesty. Without an actually-supplied, actually-verified EAT, `enclave_attested` remains exactly as weak as any other self-declared `assurance_level` |
| **Edited Hub value next to a minted token** — an `.eval_results` entry whose displayed `value` was changed after the `pb1.` token was created (a Hub reader sees the value, not the token) | `verify_eval_results_entry` (v2.2): token crypto + `value <comparator> threshold == passed` against the DECODED signed claim | an inconsistent value FAILs; **boundary 1 (magnitude):** the signed claim carries `threshold`/`comparator`/`passed`, NOT the exact score, so the check binds the value to the correct SIDE of the threshold, not to a true magnitude — an inflated value on the passing side (a true `0.81` published as `99.9`, both `>= 0.80`) still verifies; only a value that CONTRADICTS the verdict fails; **boundary 2 (identity):** the entry's `dataset.id`/`task_id` are NOT bound to the receipt's salted dataset commitment — a consistent-value token replayed onto a different repo/benchmark still verifies; identity binding needs the salt opening (`verify_commitment`) |
| **Parser differential via duplicate JSON keys** — the same signed bytes parse to DIFFERENT `root_b64`/`sig_b64`/`status_list` values under first-wins vs last-wins JSON parsers (revocation split-brain, cross-verifier "consensus" on different objects) | every verify-path parse goes through the strict duplicate-rejecting parser (`_strict_json.loads_strict`, WP-C1; SPEC §2 makes rejection normative) | a duplicated key is rejected with a clear error at any depth; residual: the SD-JWT/KB-JWT payload parses (documented, needs its own pass — a naive conversion would invert a fail-closed direction) |
| **Self-issued revocation** — a status-list snapshot signed by the SAME key as the receipt, so the issuer attests its own "still valid" state and can flip it at will | `verify_status_snapshot(receipt_issuer_pubkey=…)` reports `self_issued=True` when the status key equals the receipt-signing key; unbounded snapshots (no `exp`/`ttl`) report `fresh=None` | this is REPORTED, not fatal — an independent, distinctly-operated status authority is the stronger anchor; the relying party decides whether self-issued revocation is acceptable |

## What it structurally does NOT catch

- **A dishonest self-attested issuer.** A `self_attested` receipt is only as trustworthy as its issuer. A
  valid signature binds *who said it*, not *whether it is true*. The receipt does not stop someone signing an
  invented number — it only makes that number **attributable and tamper-evident**, and (v1.1) it warns when
  the weakest combination (self_attested + no pre-registration) is used.
- **Publish-best-of-many.** Without a pre-registered protocol, an issuer can run an eval many times and
  publish only the best result. `prereg_sha256` (a commitment to the protocol *before* the run) is the
  defence; without it, `claim_warnings` flags the receipt. A higher `assurance_level` (`reproduced`,
  `enclave_attested`) is the structural fix — that is the road from *authorship* to *truth*.
- **Whether the suite measures what it claims.** That the eval is well designed, unbiased, or
  contamination-free is a human judgement the receipt does not encode.
- **Benchmark hacking / gamed benchmarks (OPEN BY DESIGN — no cryptographic fix exists here).**
  `eval_evidence_class` already separates `methodology` (always `METHODOLOGY_NOT_EVALUATED`) from
  `score_evidence` — a receipt never judges whether the *benchmark itself* is gameable, contaminated, or
  reward-hackable (see BenchJack, [arXiv:2605.12673](https://arxiv.org/abs/2605.12673), which audits exactly
  that class of problem for agent benchmarks). What proofbundle adds is **visibility, not a guarantee**: the
  optional `provenance.run_attempts`/`provenance.aborted_runs` (non-negative integers) make retry/best-of-many
  patterns visible in the SIGNED claim instead of invisible, and the optional `provenance.methodology_sha256`/
  `provenance.benchjack_audit_report_sha256` are plain sha256 references an auditor re-hashes by hand — the
  same mechanism, the same epistemic strength as `prereg_sha256`/`evaluation_card_sha256` (a match proves only
  "this is the document the issuer pointed at", never that the document is honest, complete, or that the
  benchmark resists gaming). **A fix that claimed to SOLVE benchmark-hacking would itself be a No-Overclaim
  violation** — crypto authenticates bytes, it cannot adjudicate benchmark design; that judgement stays
  human, exactly like "whether the suite measures what it claims" above.
- **Forced random sub-sampling of individual samples.** proofbundle binds at the *claim* level (the reported
  metrics + sample count), not per-sample. A verifier-forced random sample check would need a per-sample
  Merkle binding: **shipped in v1.5** (``samples`` commitment + opening/audit protocol, SPEC §7g).
  What v1.5 actually closes and what remains, stated precisely: a signed samples root makes
  **post-hoc sample swaps** and **count lies** (the signature binds n, so claiming n while committing
  fewer is caught) DETECTABLE under a k-of-n spot check with soundness 1−(1−m)^k. It does NOT detect a
  producer who **drops unfavorable samples BEFORE committing** and honestly signs the truthfully-smaller
  n — those samples leave no trace in the root; that is the same trust class as running many full evals
  and signing only the best one, and **pre-registration remains the only answer** to both. Self-challenge
  mode is grindable by re-salting (documented bound; real audits use an auditor nonce or a public
  beacon). Every opened sample is burned — openings are auditor-directed, never public.

## Assurance levels (weakest → strongest)

| Level | Meaning |
|---|---|
| `self_attested` | The issuer ran it and signed the result. Default. Trust rests on the issuer. |
| `third_party` | A third party checked the result before signing. |
| `reproduced` | The result was independently re-run and matched. |
| `enclave_attested` | Produced inside an attested trusted execution environment. |

The level is a **signed field** of the claim: tamper-evident and bound to the issuer, so a *third party*
cannot alter it. But it is **issuer-declared** — a dishonest issuer can sign `reproduced` on a self-run eval;
the signature attributes that claim to them, it does not make it true (exactly like the score). `show-eval`
always prints the level, and `claim_warnings` flags the honest self_attested-without-pre-registration case.

## Misuse: reading `OK` as truth

The single most likely *operator* error is treating a passing `verify` as a verdict it does not make.
The exit code and the output are deliberately split so this cannot happen silently (WP-B2): `verify`
prints `CRYPTO: OK` (the only thing the offline core proves), a separate `POLICY:` line, a verbatim
`ASSURANCE:` line, and a `LIMITATIONS:` line — and `--json` exposes each check as its own field. A
crypto success is never a bare `OK`. Three concrete ways the boundary still gets misread, and what
actually holds:

- **"`verify` exited 0, therefore the eval passed / the model is safe."** No. Exit 0 means the bytes
  are authentic and integral — `CRYPTO: OK`. It says nothing about whether the number is true, the
  suite well designed, or the model safe (those are the `LIMITATIONS`). A gate that blocks a deploy
  on `verify` exit-0 alone is gating on *authorship*, not on *result quality*.
- **"We logged `verify` output as a passed compliance / trust check."** Without `--policy`, `verify`
  makes NO trust decision and says so: `POLICY: NOT_EVALUATED`. Logging that as a satisfied policy is
  the misuse this line exists to stop. A real trust decision needs a supplied trust policy
  (`--policy`, WP-B3); its result is the separate `policy_ok` field and exit code `3` on failure —
  distinct from `1` (crypto failure), so "crypto fine but policy unmet" is never conflated with
  "crypto broken".
- **"`ASSURANCE: reproduced (issuer-declared)`, so an independent party reproduced it."** The
  `ASSURANCE:` line is the issuer's own signed, verbatim self-declaration — tamper-evident and bound
  to the issuer, but issuer-*declared*; the `(issuer-declared)` suffix (and the JSON's
  `assurance_declared_by: "issuer"`) says exactly that. A dishonest issuer can sign `reproduced` on a
  self-run eval (see "A dishonest self-attested issuer" above). Treat `ASSURANCE` as *what the issuer
  claims about rigour*, corroborated only by whatever out-of-band anchor (pre-registration, a
  third-party key, an enclave verifier key) you actually pinned.

Rule of thumb: **`CRYPTO: OK` answers "are these the bytes that issuer signed?" — nothing else on the
line answers "should I believe them?".** That second question is a `POLICY` decision you must supply
and an `ASSURANCE` claim you must corroborate.

## Misuse: Decision Receipts (`decision-receipt/v0.1`)

The Decision Receipt predicate widens the attestation surface with a new signed claim type, so its boundary is
as explicit as the eval-result one. What a `decision verify` PASS proves: *this decision maker signed this
verdict about this proposed action, over these digest-bound inputs and this policy boundary, at this time.*
What it does not:

- **"The verdict was correct / legal / safe."** No. A Decision Receipt proves *a decision was made and by
  whom*, not that it was right. `notChecked` is a required field precisely to stop a false completeness
  assumption.
- **"`actionOutcome: executed`, so the action ran."** Only if the outcome is separately signed by the
  tool/mediator boundary or referenced as a digest-bound tool log (`outcomeRef`). Otherwise it is the issuer's
  self-assertion; verify reports `action_outcome_proven=false` with a warning.
- **Predicate confusion — "a decision receipt counted as an eval-result (or vice versa)."** Rejected: the
  `predicate_type_ok` check fails a receipt whose `predicateType` is not `decision-receipt/v0.1`, and a v0.2
  trust policy's `accepted_predicate_types` is the belt-and-suspenders policy-layer guard.
- **"`decisionMaker.id` names the gate, so I trust it."** The `id` is a JSON claim. Trust comes from the DSSE
  signer key matched against `trusted_decision_makers` in the trust policy — never from the `id` string alone.
- **Cross-audience / replay.** `validity.audience` + `nonce` (strict interactive mode) bind a receipt to its
  intended relying party and a fresh challenge; verify checks them against `--aud`/`--nonce`.

## Related work (fair demarcation)

proofbundle attests eval/test *run* results, offline, via the standards stack (Ed25519 + RFC 6962 + optional
SD-JWT / in-toto). [ai-audit-trail](https://pypi.org/project/ai-audit-trail/) records *runtime* agent
Decision Receipts (a different layer). [ValiChord](https://github.com/topeuph-ai/ValiChord) builds
attestation bundles from inspect_ai logs post-hoc (its v1 library is unsigned — signatures are v2 scope).
Challenge-response / key-binding for forced fresh disclosure follows RFC 9901 (SD-JWT Key Binding).

## Ed25519 edge-case envelope (C2) — cross-verifier divergence on crafted signatures

Verification delegates to `cryptography` (OpenSSL): against the eprint 2020/1244 corpus it matches
the BoringSSL / Dalek (non-strict) row exactly — ACCEPT {0,1,2,3,11}, REJECT {4,5,6,7,8,9,10}
(SPEC §4a; byte-pinned by `tests/test_ed25519_semantics.py`). An honest RFC 8032 signer is
unaffected. The residual: for adversarially CRAFTED signatures, an independent verifier with a
different profile (Dalek-strict, ZIP-215) can disagree with proofbundle about validity — so "N
verifiers agreed" is only meaningful on hostile inputs when all N pin the same profile. A profile
switch would be a versioned, breaking change, never silent.

## Beacon audit mode (v1.9) — residual grinding

The beacon per-sample challenge resists grinding ONLY when the round is pre-committed (a future round) and the receipt's commit-time is corroborated from an INDEPENDENT source. It relies on the self-declared `timestamp` the issuer signs but that `verify` does not prove true — a dishonest issuer can backdate it and grind against an already-public round, so without independent corroboration it is no stronger than the self-challenge mode.
