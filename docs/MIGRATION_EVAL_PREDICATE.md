# Migrating the eval-result predicate: content-root canonicalization and the vendored → official type

Tracks issue [#26 — "Roadmap: upstream an official in-toto eval predicate
(replace vendored predicate
type)"](https://github.com/b7n0de/proofbundle/issues/26). Issue #26 asks for
two genuinely different things, and this document is honest about which one
is done and which one is not yet possible:

1. **Content-root canonicalization** (`contentRootAlg`, `jcs-sha256-v1` vs.
   `legacy-sortkeys-json-v0`) — **implemented, released in 2.1.0** (ADR
   0002, WP2). This is the migration this document mainly explains: what
   changed, why, and how to move data through it safely.
2. **Replacing the vendored `predicateType` with an official, in-toto-
   upstreamed one** — issue #26's literal ask. **Not yet possible**: the
   upstream proposal ([in-toto/attestation
   #565](https://github.com/in-toto/attestation/pull/565), "New predicate
   proposal: eval-result (AI/ML evaluation results)") is still **open**,
   unmerged, as of this writing (checked via `gh api
   repos/in-toto/attestation/issues/565`: `state: open`, last updated
   2026-07-11). There is no official type to switch to yet. §"Relationship
   to issue #26" below covers exactly what remains open and why.

## 1. What the content-root migration is

Two proofbundle export paths hash an in-toto Statement before signing it,
and until 2.1.0 they disagreed on *how*:

- The **decision-receipt** predicate (`decision.py`, 2.1.0) always hashed
  the RFC 8785 (JCS) canonical Statement bytes.
- The **eval-result / test-result / SVR** in-toto export paths (`intoto.py`,
  released in 2.0.0) hashed `json.dumps(statement, sort_keys=True,
  separators=(",", ":"))` — sorted-key JSON, which is **not** full RFC 8785:
  it does not normalize number formatting or non-ASCII/mixed-case string
  escaping, so it cannot serve as a stable, cross-implementation content
  root (`intoto.py::_canonical_body`).

ADR 0002 (`docs/adr/0002-universal-content-root.md`) designed a single
shared primitive for both; **WP2 activated it** for the released
`intoto.py` paths in 2.1.0. This document is the practitioner-facing
migration guide for that activation — read ADR 0002 first for the design
rationale, this document for "what do I actually need to do."

## 2. The two algorithms, by name

| `contentRootAlg` value | Canonicalization | Needs `[eval]` extra to verify | Since |
|---|---|---|---|
| `jcs-sha256-v1` (`canonical.CONTENT_ROOT_ALG`) | RFC 8785 (JCS): SHA-256 over the canonical bytes of the **full** Statement (`_type`, `subject`, `predicateType`, `predicate`) | **yes** (`rfc8785`) | new default since 2.1.0 |
| `legacy-sortkeys-json-v0` (`intoto.LEGACY_CONTENT_ROOT_ALG`) | `json.dumps(sort_keys=True, separators=(",", ":"))` | no (stdlib only) | the released 2.0.0 wire |

The algorithm is **declared inside the signed Statement** as a top-level
`contentRootAlg` field (in-toto Statement v1 permits additional top-level
properties). Declaring it inside the signed payload, rather than as
out-of-band metadata, means it cannot be flipped after signing — a verifier
re-serializes with **exactly** the declared algorithm and rejects the
payload if it does not reproduce byte-for-byte (`intoto.py::
_content_root_binding`); it never re-canonicalizes to *compute* a root and
never silently falls back between algorithms (the same anti-confusion rule
`merkle.hash_alg` already enforces for the Merkle layer).

**Absence of `contentRootAlg` means legacy — never, silently, JCS.** This
is the one rule that makes the whole migration backward-compatible: every
already-signed 2.0.0 attestation carries no such field, so it keeps
verifying byte-for-byte under a base install with zero code or data
changes on your side.

## 3. What changed for producers

`export_eval_result_dsse`, `export_intoto_dsse`, and `export_svr_dsse`
(`intoto.py`) all gained a `content_root_alg` keyword, defaulting to
`canonical.CONTENT_ROOT_ALG` (`jcs-sha256-v1`):

```python
from proofbundle import intoto

# New default: signs the RFC-8785-canonical Statement bytes, declares
# contentRootAlg="jcs-sha256-v1" inside the signed payload. Needs
# `pip install "proofbundle[eval]"` (the rfc8785 canonicalizer) on the emit side.
envelope = intoto.export_eval_result_dsse(claim, signer, root_b64=root_b64)

# Byte-identical re-emission of the OLD (2.0.0) wire — no contentRootAlg field,
# json.dumps(sort_keys=True) preimage, stdlib-only.
legacy_envelope = intoto.export_eval_result_dsse(
    claim, signer, root_b64=root_b64, content_root_alg=intoto.LEGACY_CONTENT_ROOT_ALG)
```

If you re-sign the **same claim data** you previously exported under
2.0.0, the new default produces **different signed bytes** (a different
content root, because JCS and sorted-key `json.dumps` diverge on number
formatting and string escaping for at least some inputs) — this is
expected, not a bug, and is exactly why the algorithm is declared rather
than silently switched.

## 4. What changed for verifiers

`verify_eval_result_dsse`, `verify_intoto_dsse`, and `verify_svr_dsse`
(`intoto.py`) all read the Statement's declared `contentRootAlg` (absent ⇒
legacy) and verify canonicality under **exactly** that algorithm:

- **Verifying a `jcs-sha256-v1` Statement needs `proofbundle[eval]`**
  installed (the same `rfc8785` dependency the emit side needs). Without
  it, verification is **fail-closed** (`content_root_ok: false`, a clear
  "install proofbundle[eval]" detail) — **never** a silent pass over
  possibly-non-canonical bytes.
- **Verifying a legacy Statement needs nothing beyond the base install**
  (`cryptography` + stdlib) — this is precisely how a released 2.0.0
  attestation keeps verifying on a bare `pip install proofbundle`.
- A `json.dumps(sort_keys=True)` body offered *as* `jcs-sha256-v1` is
  **rejected** (the payload does not reproduce under JCS re-serialization),
  and the reverse — genuinely JCS-canonical bytes declared as legacy — is
  **also rejected** (it does not reproduce under `json.dumps(sort_keys=True)`
  either, for any input where the two serializers diverge). This is the P0
  activation guarantee ADR 0002 names, exercised by
  `tests/test_intoto_content_root_migration.py`.

## 5. Migrating already-emitted data

**Nothing you already published needs to change.** A previously emitted,
signed eval-result / test-result / SVR attestation has no `contentRootAlg`
field, verifies as `legacy-sortkeys-json-v0`, and will continue to do so —
this migration adds a new default for *new* signatures, it does not
retroactively invalidate or require re-signing old ones. There is no
`proofbundle migrate` command and none is needed: "migration" here means
"the next attestation you emit uses the new default," not "rewrite your
history."

If you want to re-publish an old claim under the new algorithm (e.g. to
get a content root that composes byte-for-byte with a decision receipt
citing it — the actual motivation for ADR 0002), re-emit it with the
default `content_root_alg` — this produces a **new**, differently-signed
attestation over the same claim data, not a rewrite of the old one.

## 6. Relationship to issue #26: the vendored `predicateType`

Independent of the content-root algorithm, proofbundle's eval-result export
uses its own, **vendored** `predicateType`:

```text
https://b7n0de.com/attestation/eval-result/v0.1   (intoto.EVAL_RESULT_PREDICATE_TYPE)
```

This is common, spec-conforming practice for a predicate under active
proposal (`intoto.py`'s own module docstring cites `cosign.sigstore.dev/…`
and `apko.dev/…` as precedent) — it is a fully valid in-toto predicate
type, just not (yet) one that in-toto's own attestation spec repository
has adopted as a shared, cross-tool convention.

**Current upstream status (checked at the time of writing):** [in-toto/
attestation#565](https://github.com/in-toto/attestation/pull/565) proposes
exactly this predicate shape upstream. It is **open**, with active review
comments, **not merged**. Until it merges (and is tagged with a stable
`predicateType` URI under the `in-toto.io` namespace, the way
`test-result/v0.1` — which proofbundle also supports, see SPEC.md §7b — and
the SVR predicate `svr/v0.1` already are), there is no "official" type to
migrate to. Switching `intoto.py`'s default `predicateType` to a
self-declared "official-looking" URI before the upstream PR actually merges
would misrepresent an unmerged proposal as a ratified standard — exactly
the class of overclaim this project's No-Overclaim discipline forbids.

### What proofbundle already does today, without waiting on #565

- **`to_test_result_statement` / `export_intoto_dsse`** map an eval receipt
  onto the *already-standard*, generic in-toto `test-result/v0.1` predicate
  (SPEC.md §7b) — a real, already-official predicate any generic in-toto
  verifier understands, at the cost of a coarser shape (`PASSED`/`FAILED`,
  metric details folded into a `ResourceDescriptor.annotations` map, no
  native metric/threshold fields). This is a working bridge *today*, not
  something #565 unlocks.
- **`to_eval_result_statement` / `export_eval_result_dsse`** carry the
  richer, purpose-built shape (`claims[]`, salted commitments, assurance
  level, pre-registration binding) under the vendored type — this is what
  #565 proposes standardizing.

### The migration path once #565 merges (not yet buildable)

The audit that produced this document sketches a bridge CLI:

```bash
# NOT IMPLEMENTED — sketch only, blocked on an official predicateType existing upstream.
proofbundle export intoto-eval-result receipt.json --format official
proofbundle export intoto-eval-result receipt.json --format vendored
```

This is deliberately **not built** in this change: implementing
`--format official` today would require inventing our own guess at what
in-toto's maintainers will eventually ratify and shipping it as
"`official`" — the exact overclaim this document exists to avoid. Once
in-toto/attestation#565 (or its successor) lands with a stable
`predicateType` URI, the concrete follow-up is:

1. add the official `predicateType` string as a new named
   `EVAL_RESULT_PREDICATE_TYPE_OFFICIAL` constant, distinct from the
   existing vendored one (never silently repoint the old constant — that
   would break every consumer pinning the vendored type);
2. map `to_eval_result_predicate`'s existing field set onto whatever exact
   shape #565 lands with (their PR discussion, not this document, is
   authoritative for that shape once it exists);
3. build the `export intoto-eval-result --format official|vendored` bridge
   above, defaulting to `vendored` (never silently switch an existing
   consumer's default);
4. add conformance fixtures against the upstream JSON Schema, once one is
   published;
5. update this document and `docs/IN_TOTO_PROFILE.md` together.

None of that is code-true today; this document records the readiness state
(content-root parity is already there — an official-type Statement would
canonicalize and hash exactly the same way) and the exact blocking
condition (#565 unmerged), so the next contributor does not have to
re-derive it.

## 7. Honest scope

```text
This document proves (by pointing at the code + tests):
  - the content-root algorithm declared in a Statement is what the
    verifier actually checks canonicality against, fail-closed;
  - an already-signed 2.0.0 eval-result/test-result/SVR attestation keeps
    verifying, unchanged, forever, on a base install;
  - a mismatched declaration (JCS bytes as legacy, or legacy bytes as JCS)
    is rejected, not silently accepted.

This document does NOT prove or claim:
  - that issue #26 is closed — the vendored predicateType is unchanged,
    pending an unmerged upstream proposal;
  - that any eval-result attestation, official or vendored, says anything
    about whether the underlying evaluation was well-designed or free of
    cherry-picking (see docs/NON_CLAIMS.md).
```

## Cross-references

- `docs/adr/0002-universal-content-root.md` — the design decision and its
  "Activation" section (this document is its practitioner-facing follow-up).
- `docs/IN_TOTO_PROFILE.md` — the broader in-toto interop surface
  (test-result, SVR, the vendored eval-receipt predicate).
- `SPEC.md` §7b — the standard `test-result/v0.1` mapping, usable today.
- `CHANGELOG.md` `[2.1.0]` — the activation release notes.
