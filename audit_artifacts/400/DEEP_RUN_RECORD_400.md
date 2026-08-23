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

iteration 2 (after the first D1 + D2/D3 fixes, re-gated by the author)
  graded commit   2f6adadb793a8ef5ffd32553b20e263ea6147c18
  graded src tree 071d9836898301c891bebe130fe2d629900b2ada

iteration 3 (an INDEPENDENT pre-merge fix-review found the D2/D3 fix was an INSTANCE fix; the UTF-8 class
             was then closed in the shared parser _note_text_of)
  graded commit   dbf1a38430c900aec5ef543d2c371167936cb3c3
  graded src tree 000dcf09b7bf15a46cab38a71807ca80ace29076

iteration 4 (a FOURTH adversarial pass found a THIRD neighbour: the shared parser returned the size/root
             FIELDS unvalidated, so cosign_checkpoint_mldsa still raised raw — field validation added)
  graded commit   3b8ceb0b2c5e1cbb2ec323a351277c11e89ec081
  graded src tree abea83543c2b7452693441b3946a9df84f7efb3e

iteration 5 (a FIFTH completeness-critic pass ran the exhaustive ~1,830-probe battery and found the last
             cluster — the identity/producer surfaces validated their args' CONTENT but not their TYPE, so a
             non-str/non-bytes/non-dict caller argument raised raw on the producer side; caller-contract
             isinstance guards added. The digest this verdict binds to.)
  graded commit   b47a80679c8a9fea7b34c4a73aa70339c2f8105d
  graded src tree 8c124b527ede58fa6333a09d38704588095b976d
  code delta      v3.8.0..HEAD under src/: 6 files, 306 insertions, 40 deletions
```

The verdict below binds to the iteration-5 digest `8c124b52` / `b47a8067`. A verdict for an earlier digest
does not carry to it. D1 and the first D2/D3 instance closed at iteration 2; the note-text UTF-8 class at
iteration 3; the note-body size/root-field class at iteration 4; the producer-side argument-TYPE
caller-contract class at iteration 5 — each found by an INDEPENDENT adversarial pass on the prior fix. THE
CONVERGENCE PROOF: the fifth pass's OWN exhaustive battery — the same one that surfaced every prior neighbour
— re-run against the iteration-5 fix reports **0 raw-exception escapes across all 1,832 probes**
(probe4_tlogproof went 63 → 23 → 0 as the producer args were closed). This is the honest record of a
never-raise class that took five passes to converge; the fifth pass's own 0-finding re-run is why the fifth
is the last, not a sixth-declared-clean-on-my-own-word.

## Targets — result

| # | Target (pre-registered invariant) | Iter 1 | Fix | Iter 2 re-gate |
|---|---|---|---|---|
| D1 | A log cannot vote in its own witness quorum. | **REFUTED** | `witness_quorum` `log_key_material` → required keyword | **CLOSED** |
| D2 | Printable-ASCII identities; the whole cloaking class closed, all three slots. | rule HOLDS; **ordering REFUTED** | validate-before-encode; **class fix in `_note_text_of` (iter 3)** | **CLOSED** |
| D3 | No public verify surface raises a raw exception on hostile identity input. | **REFUTED** (instance iter 1, neighbour iter 3) | `verify_checkpoint` + shared `_note_text_of` | **CLOSED** |
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

**Iteration 3 — the class, not the instance (independent pre-merge fix-review).** Before merge, three
independent adversarial agents re-reviewed the iteration-2 FIX code (not the original). Two converged on
the same real defect with running exploits: the iteration-2 D2/D3 fix closed only `verify_checkpoint`'s OWN
copy of the note text. The SHARED cosignature-path parser `_note_text_of` validated only `lines[0]`
(origin), never the size, root, or C2SP extension lines (`lines[3:]`) that `_cosigned_message` encodes
WHOLE — so a lone surrogate in an EXTENSION line still raised a raw `UnicodeEncodeError` out of three public
surfaces: `verify_cosignature` (top-level, `__all__`-exported), `evaluate_public_transparency`'s
witness-quorum branch (its `except ProofBundleError` does not catch a `UnicodeEncodeError`), and
`cosign_checkpoint` (signing side). A textbook fix-the-instance-not-the-class miss, three lines from a
sibling ML-DSA branch that already wrapped its equivalent encode. Class fix: `_note_text_of` now validates
the whole note body is UTF-8-safe once, for every consumer. Re-gate (executed): all three surfaces fail
closed with a typed `BundleFormatError` / FAIL verdict; a valid ASCII extension-line note still cosigns and
verifies (no false-negative). Pinned by `tests/test_origin_quorum_rule.py::TestNoteBodyExtensionLineNeverRaises`.
This is the honest record of the gate catching its own author's incomplete fix before it reached the merge.

**Iteration 5 — the last neighbour, a lower class (fifth completeness-critic pass).** The fifth pass ran the
exhaustive ~1,830-probe battery across every `__all__` public name and confirmed the pre-registered D3 target
holds — 0 findings on every VERIFY surface (`verify_checkpoint`, `verify_cosignature`,
`verify_witnessed_checkpoint`, `verify_tlog_proof`, `evaluate_public_transparency`), which derive identity
from an already-split string. It found a lower, out-of-D3-scope class on the PRODUCER side: the identity
helpers (`_origin_wellformed`, `_witness_name_wellformed`) and the tlog-proof producers validated a string's
CONTENT but never that it WAS a string, and the key/root/proof/extra byte-arguments were unguarded — so a
non-str/non-bytes/non-dict CALLER argument raised a raw `AttributeError`/`TypeError` out of `checkpoint_note`,
`key_id`, `vkey`, `sign_checkpoint`, the `cosign_*` family, `witness_quorum`, `format_tlog_proof` and
`tlog_proof_for_bundle`. This is a caller-contract type-confusion class (a JSON field that came back
null/numeric from an upstream re-packaging), NOT a relying-party hostile-input crash — LOW severity, no crypto
bypass. Fix: `isinstance` guards at the shared helpers + the remaining producer args (the same guards the
parse helpers already carried). THE CONVERGENCE PROOF: the fifth pass's own full battery, re-run against the
iteration-5 fix, reports 0 raw-exception escapes across all 1,832 probes (probe4_tlogproof 63 → 23 → 0 as
`signed_checkpoint`, then `inclusion_proof`+`extra`, were closed). Pinned by
`tests/test_origin_quorum_rule.py::TestCallerContractTypeGuards`. Two residuals are queued post-release (both
non-raise, not release-blocking): the never-raise property test does not cover the cosign/producer surfaces
(the coverage blind spot that let iterations 1–5 slip), and `public_transparency` keeps an inline note parse
that diverges from the shared strict parser (accepts a `1_000` underscore-grouped size) with no security
bypass, since the aggregate still requires a strict cryptographic check to PASS.

## D4 — regression (HOLDS)

Every shipped external vector (Go sumdb, Rekor, rootcommit, Colin's fixtures) keeps its verdict on the
iteration-5 digest: the full suite is green — 2287 passed, 8 skipped (measured: 4 Rust-parity /
cargo-not-built, 4 ripemd160 / legacy-OpenSSL — none security-relevant to this release; ML-DSA is present
in this venv and its tests pass). None of the fixes (the verify_checkpoint reorder, the `_note_text_of`
note-body validation, or the iteration-5 caller-contract isinstance guards) changes the verdict for a
well-formed input — they only add type/format checks a valid producer or verify call already satisfies —
and no shipped vector is malformed.

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

The digests, the code-delta counts (6 files / 306 / 40) and the suite result (2287 passed) in this record
were measured on the iteration-5 tree, not carried from an earlier draft (the intermediate figures — e.g.
iteration-3's 263 insertions / 2280 passed — were each corrected as the iterations advanced, never left
stale). The CHANGELOG [4.0.0] claims map to the shipped code: the origin-quorum Changed bullet, the
printable-ASCII Changed bullet, the D1 required-keyword bullet, the D2/D3 whole-note-body-validation bullet,
and the iteration-5 argument-type caller-contract bullet each name a surface that exists.

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

`WITHSTANDS_DEEPGATE` on `8c124b52` / `b47a8067` means "ready for the Owner's tag", NOT "released" or
"proven secure". The tag and the PyPI publish remain the Owner's GO-3 touch-points. This record grades
the code that ships; the Owner's merge of the release-prep PR and the tag are separate, human acts.

## Verdict

**WITHSTANDS_DEEPGATE** — release 4.0.0, iteration-5 digest `8c124b527ede58fa6333a09d38704588095b976d`
(commit `b47a80679c8a9fea7b34c4a73aa70339c2f8105d`). All six pre-registered targets hold: D1 (origin-quorum),
D2 (printable-ASCII), D3 (verify surfaces never-raise on hostile identity strings — the fifth pass confirmed
0 findings on every verify surface), D4 (regression), D5 (mutation + gate + expected_origin), D6 (fidelity).
The never-raise class discovered along the way — five neighbours across the note-text, note-body-field, and
producer-argument-type surfaces — is closed, proven by the fifth pass's own exhaustive battery reporting 0
raw-exception escapes across all 1,832 probes on the iteration-5 code. WITHSTANDS means "ready for the
Owner's tag", NOT "released": the tag and PyPI publish remain the Owner's GO-3 touch-points.
