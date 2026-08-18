# Pre-tag adversarial deep-gate — run record — release 4.0.0

This is the run record for the pre-tag adversarial deep-gate (DEEP 6 lenses / up to 7 iterations,
the MAJOR/external mode) whose six falsification targets were frozen, before the run, in
[PRE_REGISTRATION_DEEP_400.md](PRE_REGISTRATION_DEEP_400.md). Each target below is refuted-or-holds by
an executable probe, not an opinion. Two targets were REFUTED on the first iteration with running
exploits; both were fixed and re-gated CLOSED on the patched digest (iteration 2). The other four hold.

Attestation line (the pre-tag gate reads this file for exactly this line; the CHANGELOG text is
presentational and cannot grant it):

pre-tag-adversarial-audit: RUN | version=4.0.0

## Digests

```
iteration 1 (pre-registration, frozen BEFORE the run)
  graded commit   391eb37a9767f9b05cc57788875f649be5482f4c   (origin/main, after PR #144 merge)
  graded src tree 638c2ae0a727e73aa1c726cbcc570f7a26df6e93

iteration 2 (after the D1 + D2/D3 fixes, re-gated — the digest this verdict binds to)
  graded commit   2f6adadb793a8ef5ffd32553b20e263ea6147c18
  graded src tree 071d9836898301c891bebe130fe2d629900b2ada
  code delta      v3.8.0..HEAD under src/: 6 files, 253 insertions, 36 deletions
```

The verdict below binds to the iteration-2 digest `071d9836` / `2f6adad`. A verdict for an earlier
digest does not carry to it; the two REFUTED targets were only closed at iteration 2.

## Targets — result

| # | Target (pre-registered invariant) | Iter 1 | Fix | Iter 2 re-gate |
|---|---|---|---|---|
| D1 | A log cannot vote in its own witness quorum. | **REFUTED** | `witness_quorum` `log_key_material` → required keyword | **CLOSED** |
| D2 | Printable-ASCII identities; the whole cloaking class closed, all three slots. | rule HOLDS; **ordering REFUTED** | `verify_checkpoint` validate-before-encode | **CLOSED** |
| D3 | No public verify surface raises a raw exception on hostile identity input. | **REFUTED** (2 of 4 surfaces) | same fix as D2 | **CLOSED** |
| D4 | Nothing this release loosens an existing check; every shipped vector keeps its verdict. | HOLDS | — | HOLDS |
| D5 | The NFC-origin mutation is killed and the pre-tag gate cannot be faked; `expected_origin` is not a hole. | HOLDS | — | HOLDS |
| D6 | The record's + CHANGELOG's numbers and claims match the tree. | HOLDS | — | HOLDS |

## D1 — origin-quorum (REFUTED → CLOSED)

Refutation (iteration 1): `witness_quorum(signed_note, roster, threshold)`'s `log_key_material`
defaulted to `None`. A bare call therefore ran the name-test-only mode, under which a log cosigning
under an ALIAS (a name that is not the origin) with its OWN signing key was counted toward the quorum —
the robust key-material prong had no operand to test against. The three shipped verification surfaces
(`verify_witnessed_checkpoint`, `verify_tlog_proof`, `public_transparency`) always pass the material and
were never exposed; the primitive's silent default was.

Fix: `log_key_material` is now a REQUIRED keyword-only argument (BREAKING for a direct caller of the
primitive). The caller must state the choice — the log's key material for the full rule, or an explicit
`None` to opt into the documented name-only mode. No silent weak default.

Re-gate (iteration 2, executed): a bare `witness_quorum(note, [alias_vkey], 1)` now raises
`TypeError: witness_quorum() missing 1 required keyword-only argument: 'log_key_material'`; the same call
with `log_key_material=` the log's material returns `ok=False` with `origin_excluded=True` — the alias
self-vote is excluded. Regression pinned in `tests/test_origin_quorum_rule.py::TestOriginQuorumHardening`.

## D2 / D3 — printable-ASCII never-raise (REFUTED → CLOSED, one root cause)

Refutation (iteration 1): `verify_checkpoint` encoded the note text (`note_text.encode("utf-8")`) BEFORE
the printable-ASCII origin guard (`_origin_wellformed`). A lone/unpaired UTF-16 surrogate in the note (a
`str` survives splitting untouched but is not valid UTF-8) therefore raised a raw `UnicodeEncodeError` —
a `ValueError`, not a `ProofBundleError` — out of two named public surfaces: `verify_witnessed_checkpoint`
(no try/except around its `verify_checkpoint` call) and `evaluate_public_transparency` (its
`except ProofBundleError` does not catch `ValueError`). `verify_tlog_proof` (wraps its call in
`except (ProofBundleError, ValueError, ...)`) and `_log_key_material_of` (never touches note text) HELD.
This is the one `verify_checkpoint` instance the earlier F-8/F-10 validate-before-encode re-gate missed;
the sibling `_note_text_of` already validated first. Control: an ordinary malformed origin (`log+evil`,
forbidden `+`) already raised a typed `BundleFormatError`, proving this is an ordering defect, not a
missing guard.

Fix: the origin, size and root are validated first; the encode then runs and is fail-closed on any
residual non-UTF-8 note text (e.g. a surrogate in an extension line) — a typed `BundleFormatError`.

Re-gate (iteration 2, executed):
- `verify_witnessed_checkpoint(surrogate-origin note)` → typed `BundleFormatError` (origin printable-ASCII).
- `evaluate_public_transparency(surrogate-origin note)` → `dict` with `PUBLIC_TRANSPARENCY=FAIL`, no raise.
- surrogate in an EXTENSION line → typed `BundleFormatError` ("checkpoint note text is not valid UTF-8").
- control `+`-origin still → typed `BundleFormatError` (not a blanket swallow).

D2's positive printable-ASCII rule itself (zero-width, NBSP, full-width/NFKC, decomposed/NFD, the
log-key-name slot) was independently re-checked by an oracle that recomputes `isascii()+isprintable()`
outside the production code, and HOLDS — the REFUTED half was purely the encode/validate ordering.

## D4 — regression (HOLDS)

Every shipped external vector (Go sumdb, Rekor, rootcommit, Colin's fixtures) keeps its verdict on the
iteration-2 digest: the full suite is green — 2273 passed, 8 skipped (ML-DSA backend absent), plus the
three attestation-pending tests that pass once this record exists — 80.9 s. The `verify_checkpoint`
reorder does not change the verdict for a well-formed note (same validation, reordered), and no shipped
vector carries a non-UTF-8 note.

## D5 — mutation killed · gate not fakeable · expected_origin (HOLDS)

- The `tlogproof: origin comparison normalises canonically (NFC)` mutation operator is killed by
  `tests/test_verify_proof_expected_origin.py` (commit `6a1bdbe`): a `K`-origin + KELVIN SIGN U+212A
  near-hit distinguishes an exact compare from an NFC-normalising one (the pure-ASCII fixture origin
  could not, since NFC is the identity on ASCII). Verified against the planted operator line: `log_ok`
  flips False→True under the mutant, so the test is red on the mutant and green on real code.
- The pre-tag gate itself was driven, as `release.yml` uses it, against 18 isolated throwaway fixture
  trees (the real repo untouched): 16/16 forgery attempts (marker-only prose, wrong-version attestation,
  version-token collision, HTML-comment / trailing-inline / substring / `NOT`-prefixed forms of the
  canonical line, CHANGELOG-only claims, an independently-authored negation corpus) correctly rejected
  under `--strict`; 2/2 genuine attestations accepted. Python `evaluate()` and the CLI subprocess agreed
  on every case.
- `expected_origin` reaches only a plain `str.__eq__` against an already-validated (printable-ASCII)
  checkpoint origin, so an unvalidated value can make that compare correctly fail-to-match, never
  wrongly-match; the unsafe direction (false accept) is structurally unreachable. A near-miss oracle
  (14 prefix/suffix/case/whitespace/NFKC-fullwidth/slash forms) confirmed 0 false accepts. This is the
  maintainability class recorded as the post-4.0.0 follow-up `PB-EXPECTED-ORIGIN-ASCII-INKONSISTENZ-01`,
  not a hole in the shipped exact compare.

## D6 — fidelity (HOLDS)

The digests, the code-delta counts (6 files / 253 / 36) and the suite result (2273 passed) in this
record were measured on the iteration-2 tree, not carried from an earlier draft. The CHANGELOG [4.0.0]
claims map to the shipped code: the origin-quorum Changed bullet, the printable-ASCII Changed bullet, the
D1 required-keyword bullet, and the D2/D3 validate-before-encode bullet each name a surface that exists.

## Method compliance

Falsification-first with executable exploits (opinion does not count). Negative state including
**absent** (D1 threshold=0; D2 origin=None as the documented unconstrained sentinel). Independent oracle
+ anti-parity for the identity rule (`isascii()+isprintable()` re-checked outside the production code).
Minimal environment: as-shipped, without the `[experimental]`/`[pq]` extras (the ML-DSA cases assert
"returns a verdict, never raises" so they hold on a stock build). Gate-meta-test: D5's killed NFC
operator is the living proof that a planted defect of the mutation class turns the corpus red.
Generator-hardening over point fixtures: each fix hardens the property (D1 the API contract, D2/D3 the
whole non-UTF-8 note class, not just the origin instance).

## No-Fake boundary

`WITHSTANDS_DEEPGATE` on `071d9836` / `2f6adad` means "ready for the Owner's tag", NOT "released" or
"proven secure". The tag and the PyPI publish remain the Owner's GO-3 touch-points. This record grades
the code that ships; the Owner's merge of the release-prep PR and the tag are separate, human acts.

## Verdict

**WITHSTANDS_DEEPGATE** — release 4.0.0, digest `071d9836898301c891bebe130fe2d629900b2ada`
(commit `2f6adadb793a8ef5ffd32553b20e263ea6147c18`).
