# Finding — the origin fix closed one instance; the class has six more members, all on `main`

**Pre-existing (`main`), reported and not silently changed**, per the implementation order for this
release: a finding on `main` is an Altbefund. It is recorded here because a gate meta-test on the
3.8.0 candidate surfaced it, and because it bears directly on what this release's own fix is worth.

**Nothing in this file asserts that a pre-tag audit ran.**

## What the release fixed, and what that revealed

3.8.0 added a near-miss corpus to the checkpoint **origin** comparison, after a meta-test showed that
loosening `==` to `.startswith()` or to a case-insensitive form was caught by none of the 2030 tests.
The reason was structural: both origin tests only ever passed a **completely foreign** value, and
against a foreign value a loosened comparison behaves exactly like an exact one.

That is not a fact about origins. It is a fact about **how expectation comparisons are tested here**.

## The class

- **class_id:** `relying_party_expectation_compared_against_an_attacker_chosen_identifier_tested_only_with_a_wholly_foreign_value`
- **invariant:** where a relying party pins an expected identifier and the counterpart is chosen by
  the party being verified, the comparison must be exact — and the *evidence* for that must include a
  **near miss**, because a foreign value cannot distinguish an exact comparison from a loose one.
- **surface_family_query:** every comparison in `src/proofbundle/` between a parameter named
  `expected_*` (or a locally pinned expectation) and a value parsed out of untrusted input.
- **oracle_predicate:** loosen the comparison to `.startswith()` (an exact match still passes; only a
  prefix additionally passes). If the suite stays green, that surface has no near-miss evidence.
- **outcome:** `class_open` — one member closed in this release, six measured open.

## The six members, measured

A gate meta-test loosened each site individually — one mutant per line, so no result is explained by
another's mutation — and ran the full suite. **All six stayed at baseline.**

| Site | What the comparison binds |
|---|---|
| `kbjwt.py:211` `expected_aud != aud` | audience binding (RFC 9901 §7.3, replay across audiences) |
| `kbjwt.py:214` `nonce != expected_nonce` | replay protection |
| `statuslist.py:162` `payload.get("sub") != expected_uri` | status-list substitution |
| `evalclaim.py:334` `claim.get("context_binding") != expected_context` | context binding |
| `intoto.py:302` `got == expected_predicate_type` | predicateType confusion |
| `policy.py:970` `got_vct == expected_vct` | credential-type confusion |

Executable evidence for the first two, each with the positive control run first so the harness is
known to produce a passing verdict:

```
Token aud   = 'verifier.example.evil.test' , verifier expects 'verifier.example'
  clean  -> ok=False  'KB-JWT aud does not match the expected audience'
  loosened -> ok=True 'key binding valid (cnf.jwk)'

Token nonce = 'n-1-alt-und-alt'           , verifier expects 'n-1'
  clean  -> ok=False
  loosened -> ok=True
```

The root cause is word-for-word the one this release fixed: `tests/test_kbjwt.py:93` checks
`expected_aud="other.example"` against a token carrying `aud="verifier.example"` — a **wholly foreign
value**. Same shape, different file.

## Why this is reported rather than changed here

The six sites are outside this release's delta: `git diff --name-only v3.7.0..HEAD -- src/` is
`cli.py` and `__init__.py`, nothing else. They are `main` findings, and the standing rule for this
release is that a `main` finding is reported, not quietly folded into a release that did not cause it.

Two further reasons, stated so the choice is not read as timidity. Closing six near-miss corpora is
not a small test addition: each needs a valid positive control built for its own surface, and a
corpus written under release pressure is exactly the kind that looks green without measuring. And the
comparisons themselves are **correct today** — what is missing is not a defence but the *evidence*
that the defence would be noticed if it were removed. That is worth doing properly and worth doing
soon; it is not worth doing hastily on the day of a tag.

## What WAS closed in this release, with the rollback probe

- The origin comparison: 17 near-miss candidates. Verified by planting each loosening in a throwaway
  copy — `startswith`, `casefold`, `in`, `strip`, `rstrip("/")` all go red, several of them caught by
  candidates nobody planted for.
- The **canonical** normalisation axis, which the first attempt missed. The full-width candidate
  catches NFKC but not NFC — measured: `NFC(fullwidth) != origin`. A second corpus was added that
  builds its own checkpoint with a decomposable origin through the shipped public API (no new
  fixture), and the rollback probe confirms it: with an NFC-normalising comparison planted, two tests
  go red where the whole suite was green before.
- The control-character neutralisation at four call sites, likewise with a per-site rollback probe.

## Honest boundary

The oracle above uses `.startswith()` as its single loosening. It is a good probe because it is the
weakest change that still passes every exact match, but it is one probe: a surface that survives it
is not thereby proven exact. A complete generator would sweep the loosening *forms* (prefix, suffix,
case, whitespace, normalisation, percent-decoding, trailing separators) across the *sites*, which is
the two-dimensional sweep this file recommends and does not perform.
