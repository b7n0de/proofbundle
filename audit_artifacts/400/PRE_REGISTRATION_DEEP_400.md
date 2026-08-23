# Pre-registration — DEEP 6L/7I, release 4.0.0

Frozen BEFORE anything ran (the run record only cites what is fixed here).

## The graded object

```
graded code        src/ tree 638c2ae0a727e73aa1c726cbcc570f7a26df6e93
frozen at          391eb37a9767f9b05cc57788875f649be5482f4c  (origin/main, after PR #144 merge)
delta graded       v3.8.0..391eb37 under src/: 5 files, 242 insertions, 34 deletions
mode               [DEEP-GATE: DEEP 6L/7I]  (MAJOR / external release)
```

## Falsification targets (what WOULD be the defect; the executable exploit refutes it)

| # | Target (the invariant the release asserts) | Falsified by |
|---|---|---|
| D1 | **A log cannot vote in its own witness quorum.** `witness_quorum` excludes a cosignature whose key material equals the log's signing key OR whose name equals the origin line, fail-closed. | a self-cosigned roster that reaches `threshold` — via the log's key under the origin name, under an ALIAS, or a name-relabelled Ed25519 cosignature |
| D2 | **Origins and witness names are printable ASCII; the whole look-alike cloaking class is closed at once, all THREE identity slots.** | a checkpoint/vkey that carries a zero-width (Cf), NBSP (Zs), full-width (NFKC), decomposed (NFD/combining), or Default-Ignorable identity and is ACCEPTED — on origin, witness name, OR log-key-name |
| D3 | **No public verify surface terminates with a raw exception on hostile identity input** (never-raise, both directions). | a lone-surrogate / non-encodable name that escapes as a raw `UnicodeEncodeError`/traceback out of `verify_*`, `_log_key_material_of`, `public_transparency` |
| D4 | **Nothing this release adds loosens an existing check; every shipped external vector keeps its verdict bit-for-bit.** | a Go-sumdb / Rekor / rootcommit / Colin vector whose verdict CHANGED, or an input that was refused before and now passes |
| D5 | **The NFC-origin mutation operator is now killed and the pre-tag gate cannot be faked.** | the killing test staying green while the planted NFC line is active; OR a non-attestation file granting the `--strict` pass; OR the `expected_origin` inconsistency being a real hole in the shipped exact compare (not only maintainability) |
| D6 | **The record's + CHANGELOG's numbers and claims match the tree** (fidelity). | a claimed count / file / "all pass" that a fresh measurement contradicts |

## Method (fixed here)
Six lenses — correctness · No-Fake · adversarial · SOTA (C2SP / transparency-log) · regression · fidelity —
each attempts to REFUTE its target with an executable probe, not confirm it. Negative-state including
**absent** (threshold=0, origin=None). Independent oracle + anti-parity (re-check `isascii()+isprintable()`
independently of the production code). Minimal environment: as-shipped, without the `[experimental]` extra.
Gate-meta-test: a planted D2 cloaking form must turn the corpus red (D5 is the living proof for the NFC class).
Generator-hardening over point fixtures. WITHSTANDS_DEEPGATE means "ready for the Owner's tag", NOT "released".
