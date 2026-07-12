# Eval-claim specification — `proofbundle/eval-claim/v0.1`

An **eval receipt** is a regular `proofbundle/v0.1` bundle (see [SPEC.md](SPEC.md))
whose payload is a canonical **eval claim**. This document specifies the claim.

## 1. What a receipt proves (and does not)

A receipt is tamper-evident signed evidence of exactly one thing: **on suite `S`, `metric` `comparator`
`threshold` held, `passed=…`** — signed by a stated issuer and anchored in a
tamper-evident Merkle tree. It carries only **salted commitments** to the model
and dataset identifiers, never the weights, the raw data, or the plaintext names.

It does **not** prove that the evaluation was well designed, that the suite
measures what it claims, or that the reported score is itself correct. Those are
human judgements. What it removes is the need to simply *trust the number*.

### 1a. Score evidence classes

The exact score is used only to compute `passed` and is then discarded, so a receipt carries a
**threshold verdict**, not an exact score. `show-eval` declares this explicitly, and the
machine-readable classifier `proofbundle.evalclaim.eval_evidence_class` returns one of:

- `THRESHOLD_VERDICT_VERIFIED` — the signed claim proves `passed` for the stated
  `comparator`/`threshold`. This is the ONLY class the frozen v0.1 schema produces.
- `EXACT_SCORE_VERIFIED` — reachable only through the optional, additive exact-score profile (a signed
  decimal-string `score` whose recomputed `passed` agrees). Not part of the frozen 3.x core; EXPERIMENTAL.
- `SCORE_COMMITMENT_PRESENT` — a signed score commitment is a **binding, not a range proof**: it does
  not prove the hidden score crossed the threshold.
- `SCORE_WITHHELD` — the exact score is deliberately withheld; only the threshold verdict is signed.
- `METHODOLOGY_NOT_EVALUATED` — always present: a receipt never judges whether the suite is well designed.

## 2. Data minimization

The payload contains only salted commitments, the threshold, and `passed` — never
weights, raw data, or plaintext model/dataset names. Each identifier appears as a
salted commitment `sha256:hex(salt ‖ utf8(identifier))` with a ≥16-byte high-entropy
salt that **stays with the issuer** and is never in the payload. Without the salt the
identifier cannot be recovered from the commitment — not even via a rainbow table over
known model names such as `gpt-4o`. The issuer may later disclose identifier + salt;
that is the path for selective disclosure in v0.5.

## 3. Fields

| field | required | type | notes |
|---|---|---|---|
| `schema` | yes | string | const `proofbundle/eval-claim/v0.1` |
| `suite` | yes | string | eval suite name |
| `suite_version` | yes | string | |
| `metric` | yes | string | e.g. `accuracy`, `refusal_rate` |
| `comparator` | yes | string | one of `>=` `>` `<=` `<` |
| `threshold` | yes | string | a **decimal string** (e.g. `"0.80"`), never a JSON float |
| `passed` | yes | boolean | computed by the emitter from `comparator`+`threshold`, not trusted from the caller |
| `n` | yes | integer | sample size, `0 ≤ n ≤ 2^53-1` |
| `model_id_commit` | yes | string | `sha256:<hex>` salted commitment to the model identifier |
| `dataset_id_commit` | yes | string | `sha256:<hex>` salted commitment to the dataset identifier |
| `commit_alg` | yes | string | const `sha256-salted-v1` |
| `issuer` | yes | string | `ed25519:<base64 of the 32-byte public key>` — part of the SIGNED payload; binds the receipt to the issuer |
| `timestamp` | yes | string | RFC 3339 |
| `assurance_level` | yes | enum | `self_attested` (default) · `third_party` · `reproduced` · `enclave_attested` — how much a PASS is worth; SIGNED (issuer-declared), always shown by `show-eval`. See THREAT_MODEL.md |
| `context_binding` | no | string | hash of an external context (e.g. a request id), against reuse in a foreign context |
| `ci95` | no | array | exactly two decimal strings |
| `multiple_testing` | no | string | e.g. `holm` |
| `prereg_sha256` | no | string | sha256 (hex) over the RAW bytes of the eval protocol file, committed BEFORE the run (`proofbundle prereg`); a verifier re-hashes the disclosed protocol and checks it |
| `provenance` | no | object | traceability metadata (not a security commitment): `harness`, `git_hash`, `harness_version`, `run_id`, `run_timestamp` (log-native), `config_hash` (`<alg>:<hex>` over canonical config JSON), plus adapter-specific keys (e.g. `task_hash`, `stderr`) |
| `samples` | no | object | per-sample Merkle commitment `{root_b64, n, leaf_alg}` — SIGNED; `samples.n` MUST equal `n`; enables the forced-random-sample audit (SPEC §7g, `proofbundle audit-challenge` / `verify-opening`) |

Machine-readable: [`schemas/eval_claim_v0_1.schema.json`](schemas/eval_claim_v0_1.schema.json).

## 4. Canonicalization (RFC 8785 JCS) — emit path only

The payload bytes are the claim canonicalized with **RFC 8785 JCS**. This profile,
enforced on the emit path:

- object keys sorted by **UTF-16 code units** (not Python code points — otherwise it
  diverges on emoji and characters beyond the BMP);
- **duplicate keys rejected** when parsing claim JSON;
- all string values **NFC-normalized** (non-NFC rejected);
- **Python floats rejected** (numbers with fractional parts are decimal strings);
- integers limited to the IEEE-754 safe range (`2^53-1`);
- compact separators, UTF-8.

A real RFC 8785 library is used **only on the emit path**. The **verify path never
canonicalizes** — `decode_eval_claim` checks the exact stored bytes that
`verify_bundle` already authenticated — so the verifier stays dependency-free
(`cryptography` + stdlib only).

## 5. Issuer binding

`emit_eval_receipt` sets `issuer` to the signer's fingerprint. `decode_eval_claim`
verifies the bundle, then checks that the bundle's signing key **equals** the claim's
`issuer` field; a mismatch fails decoding. A receipt is therefore bound to the key
that signed it — you cannot lift a claim under a different signature.
