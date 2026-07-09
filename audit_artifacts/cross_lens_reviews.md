# Cross-lens review — WP-B1: `merkle.hash_alg` REQUIRED + SPEC_REVISION + extended `--version`

Closes #28. Four-iteration review performed before commit, per the work-package instructions.

## A — Evidence (what proves conformance)

- `SPEC.md` §5: `hash_alg` row changed `required: no` → `yes`, MUST wording added, explicit
  anti-algorithm-confusion sentence ("a verifier MUST NOT silently default a missing value ...
  exactly where an algorithm-confusion attack would hide"). Header gains `Revision: 2026-07-09`.
- `schemas/proofbundle_v0_1.schema.json`: `hash_alg` added to `merkle.required`.
- `src/proofbundle/bundle.py`: new shared helper `_require_hash_alg(mk)` used by BOTH
  `verify_bundle` and `recompute_merkle_root_b64` (previously two independent `_require(...)`
  call sites with identical logic but no shared message) — raises `BundleFormatError` naming the
  field, the SPEC.md pointer, and the exact JSON fix.
- `src/proofbundle/__init__.py`: `SPEC_REVISION = "2026-07-09"` next to `__version__`, exported
  in `__all__`.
- `src/proofbundle/cli.py`: `--version` now emits a 4-line block (version / spec-revision /
  schema / features) via a custom `_VersionAction` (the built-in `action="version"` runs the
  string through `HelpFormatter`, which collapses embedded newlines — verified this is real by
  reading `argparse.HelpFormatter._fill_text`, which regex-collapses all whitespace including
  `\n` before wrapping); `_detect_features()` is a fail-safe, try/except-per-capability probe of
  `eval` / `sdjwt` / `anchors[beta]` / `pq` / `inspect` / `experimental`.
- Tests added (7): `tests/test_bundle_robustness.py` (missing hash_alg → error w/ migration hint,
  same in `recompute_merkle_root_b64`, wrong value → `UnsupportedError`), `tests/test_cli.py`
  (direct `main(["--version"])` content check, no-subcommand short-circuit contract preserved,
  end-to-end subprocess through the real `python -m proofbundle.cli` process boundary),
  `tests/test_docs_truth.py` (`SPEC_REVISION` == SPEC.md's own `Revision:` line, in the style of
  the existing CITATION.cff↔pyproject sync test).
- Full suite: 487/487 passed (`python -m unittest discover -s tests`, was run both before and
  after every substantive edit in this WP). `ruff check .` clean. `python -m mypy src` clean.
  Manual smoke: `proofbundle --version` (installed console script), `python -m proofbundle.cli
  --version`, `--help`, and a bare `proofbundle` (no subcommand) all behave as expected, stderr
  empty on `--version` (no stray `ExperimentalWarning`).

## B — Break (adversarial)

1. **Real bug found and fixed**: the `pq` feature probe in `_detect_features()` initially caught
   only `ImportError`. The exact pattern it mirrors, `checkpoint.py::_mldsa_module()`, catches
   `(ImportError, AttributeError)` — its own docstring documents why: a `cryptography>=48` build
   *without* an OpenSSL 3.5+ PQ backend has the `mldsa` module but not the `MLDSA44PublicKey`
   class, which is an `AttributeError`, not an `ImportError`. Left as `except ImportError`, this
   probe would have raised uncaught out of `_detect_features()` on exactly that class of install —
   crashing `--version` itself, the opposite of "fail-safe, never a traceback" the work package
   asked for. Fixed to `except (ImportError, AttributeError)`.
2. Checked whether a bundle without `hash_alg` can still reach a PASS through any emit path:
   `emit.py` always writes `"hash_alg": "sha256-rfc6962"` unconditionally (grepped, confirmed) —
   no emitter code path can produce a bundle missing it. Only a hand-authored/pre-v1.6 archived
   bundle can hit the new-required error, matching the CHANGELOG's "who this breaks" claim.
3. Checked whether the schema's `default` annotation on `hash_alg` was now misleading given the
   field is `required` and the SPEC text says a verifier MUST NOT silently default it: it was
   (`"default": "sha256-rfc6962"` sitting on a required field invites a schema-driven code
   generator or defaulting library to treat absence as safe) — removed, replaced with a
   description note pointing at the MUST-not-default rule.
4. Checked the `--help` / usage line still renders `[--version]` correctly and the custom action's
   `help=` text appears in the options list (it does — verified by running `--help`).
5. Checked `--version` still short-circuits before argparse's `command required` check (the
   original behavior of `action="version"`, which this replaces) — verified: `proofbundle
   --version` with no subcommand exits 0 with the version block, unaffected by `required=True` on
   the subparsers group.
6. Checked no doc (`README.md`, `docs/*.md`) hardcodes the old single-line `--version` format —
   none found, so no additional doc drift from this change.

## C — Fix

Both findings from B were applied directly (not deferred): the `pq` probe's except clause and the
schema's stale `default`. Both are included in this commit set, not left as follow-ups.

## D — Cross-review (2 lenses)

### Lens: Trust-UX
- **Concern**: does a user who hits the new-required error understand *why* and *how to fix it*
  without reading source?
- **Result**: the message states the missing field, cites SPEC.md §5, gives the literal JSON
  fragment to add (`"hash_alg": "sha256-rfc6962"`), and reassures that current emitters are
  unaffected — actionable without a source read.
- **Changes**: none additional; assessed sufficient as written.
- **Residual risk**: the message does not suggest *checking what produced the bundle* if the user
  didn't hand-author it (e.g. "if this wasn't hand-written, the tool that made it predates v1.6").
  Minor — left as-is; the fix instruction is already correct and self-contained.

### Lens: Governance (doc/schema/code single-source-of-truth)
- **Concern**: SPEC.md itself says "where the two disagree, this document is normative and the
  schema is a bug" — did this WP eliminate the disagreement everywhere, not just patch the
  symptom the issue named?
- **Result**: SPEC.md, the JSON Schema, and both code call sites (`verify_bundle`,
  `recompute_merkle_root_b64`) are now aligned on `hash_alg` being required. `SPEC_REVISION` is
  pinned to SPEC.md's own header by an executable test (`test_spec_revision_matches_spec_md`), so
  a future SPEC.md edit that bumps the revision without touching the constant (or vice versa) goes
  red instead of silently drifting the way the `required: no` row had for at least since v1.6.
  This lens is *what caught* finding B.3 (the stale schema `default`).
- **Changes**: schema `default` removal (already applied under C).
- **Residual risk, stated honestly**:
  - `docs/archive/REVIEW_v1.6.md` still shows `⬜ test_merkle_missing_hash_alg_rejected` as an open
    checklist item from that historical review. Deliberately **not** edited here — it is an
    archived historical snapshot of what was known/done *at that review's time*, and retroactively
    checking it off would misrepresent history. The test now exists
    (`test_missing_hash_alg_rejected_with_migration_hint`); the archive doc is simply stale by
    design of being an archive. Flagged, not fixed.
  - Issue #28 is currently assigned to an external contributor (`onxxdatas` / Abdulaziz) on
    GitHub. This WP closes it from the owner's side; the maintainer should acknowledge/re-triage
    the assignment when merging (attribution courtesy), which is outside what a branch commit can
    do. Flagged, not something this change can resolve.
