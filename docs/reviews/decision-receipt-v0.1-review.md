# decision-receipt/v0.1 — six-lens review

Adversarial review of the PR #45 course-correction (branch `feat/decision-receipt-v0.1`), per the
Umsetzungsprompt §12 and the Kurskorrektur §6. Each lens was run as a *break-attempt* — the goal was to
falsify the fix, not to bless it. Findings were independently re-verified before being acted on. Every
confirmed defect below was fixed and locked with a regression test (`tests/test_decision_hardening.py`).

## Kurskorrektur §6 re-checks (the four that had to hold)

1. **No subset canonicalization** — HOLDS. The content root is always SHA-256 over the *full* Statement /
   the exact signed payload bytes; there is no field-subset canonicalization anywhere.
2. **Self-reference gone** — HOLDS. `anchors` is a fail-closed unknown predicate field; a decision anchor
   commits `statement_content_root(body)` over the exact DSSE payload, signature bytes excluded; anchor
   evidence for the own root is detached.
3. **Predicate-hash references replaced** — HOLDS. `evidenceRefs[].digest` is the evidence *Statement*
   content root in code, schema, docs and examples; only negative "not the bare predicate hash" mentions
   remain.
4. **Exit codes consistent with the eval path** — was **BROKEN**, now fixed. A mismatched `--aud`/`--nonce`
   used to exit 0; it now fails closed (exit 2), matching the eval verify contract.

## Lens 1 — Semantics & scope / No-Overclaim — holds (one defect fixed)

Break-attempt: tamper the signature and read what the human output asserts on a crypto FAIL. **Found:** the
positive trailer ("…has not been altered") fired even on `CRYPTO: FAIL`. **Fixed:** the trailer is guarded on
`crypto_ok`, with an explicit "did NOT verify" line otherwise. Eval-evidence vs agent-decision stay cleanly
separated; the eval `sort_keys` vs decision RFC-8785 divergence is honestly disclosed as a follow-up, not
presented as working.

## Lens 2 — Cryptography & evidence binding — holds (one fail-open fixed)

Break-attempt: forge a tampered-but-valid-root receipt; a detached anchor whose root matches a *different*
statement; a pending anchor against `require_external_anchor`; an `anchors` field smuggled into the predicate.
All four failed closed. **Found:** the crypto→policy boundary was fail-open — a wrong-key verify returned
`crypto_ok=False` but `policy_ok=True`. **Fixed:** a trust policy is never evaluated on unverified bytes
(`policy_ok`/`signer_trusted` stay `None`).

## Lens 3 — Policy & trust anchors — was broken, now fixed

Break-attempt: obtain a passing verdict / exit 0 that should be denied, and bypass every v0.2 knob. The
fail-closed *parser* is solid (mistyped bool, string-as-list, unknown field, v0.1-under-v0.2 all rejected).
**Found (broken):** `decision verify --aud <wrong>` / `--nonce <wrong>` exited 0. **Fixed:** a mismatched
requested audience/nonce is fail-closed (exit 2). **Found (medium):** a full anchor bundled with a pending one
aggregated to WARN and was wrongly rejected under `allow_pending=false`. **Fixed:** anchor satisfaction is
per-anchor (a full anchor satisfies; a broken one still fails closed).

## Lens 4 — Agent interop & runtime — holds (two overclaims fixed)

No hard dependency on OPA/MCP/A2A/OTel/CloudEvents (all reference-field mappings); `traceContext` is
correlation-only; the rfc8785 posture is coherent; the SLSA VSA `inputAttestations` ~ `evidenceRefs`
content-root mapping is accurate; the tlog-bitcoin-anchor cross-impl vectors are honestly deferred.
**Found:** `markovian-provenance/v1` (decision-receipt.md §8) and Sigstore/Rekor·SCITT (INTEROP.md) were
advertised as working decision anchors, but neither is registered by default. **Fixed:** softened to
registrable-extension wording (an unregistered anchor type is a fail-closed error, never a silent pass).

## Lens 5 — Privacy, data-minimization & evidentiary adequacy — holds (caveat)

The detached anchor path transmits only the content root (a hash) plus the timestamp proof, never payload
content, so "only digests/roots leave the system for anchoring" holds. COMPLIANCE.md makes no framework-
satisfaction claim. **Found:** `privacy={}` passed strict. **Fixed:** `rawInputsIncluded` (boolean) is
required in strict. **Honest caveat (not a code bug):** `allow_raw_inputs` is a self-attested-flag gate — it
cannot detect undeclared raw PII / chain-of-thought smuggled into free-text fields; that remains the issuer's
responsibility and a documented limitation.

## Lens 6 — DX, backward-compat & release governance — holds

The `ANCHOR_TARGETS` "statement" addition and the v0.2 `decision_receipt` knobs are strictly additive: v0.1
policies still parse, the eval path is not regressed, and the golden examples still validate. v2.0.0 is
tagged, so 2.1.0 follows SemVer. The material defects were new-surface fail-opens (Lens 3), not regressions,
and are fixed above.

## Outcome

All confirmed defects fixed; full suite **623 green** (ruff + mypy clean). Remaining honest follow-ups:
cross-predicate content-root unification (eval export → RFC-8785), the tlog-bitcoin-anchor cross-impl vectors
(WP8b), and free-text raw-input detection beyond the self-attested flag.
