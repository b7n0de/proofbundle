# Roadmap front-loading — five shared foundations built once

`GO_OWNER_PB_ROADMAP_FRONTLOAD_20260716`. The 3.4.0 / 3.5.0 / 3.6.0 release deltas each need the same
vector, build, model and pack infrastructure in growing form. Built per-release, that is triple rework
(the vector format twice, the build gate late so every prior release repackages, the formal model each
round). Built ONCE, additively, each release becomes an EXTENSION delta, not a rebuild. **The release
prompts must EXTEND these foundations, never rebuild them.**

## The foundations (shipped with 3.3.1)

| # | Foundation | Where | Extend it by |
|---|---|---|---|
| **F1** | One vector corpus + one format + one comparator | `conformance/vector_schema.json`, `conformance/common_vocabulary.py`, `conformance/cross_format.py` | add cases to `conformance/`, new axes to the schema — the comparator already feeds the runner, cross-format check and Rust differential |
| **F2** | Hermetic published-artifact gate + reproducible sdist + SLSA-L3 reusable workflow | `scripts/build_reproducible.py`, `.github/workflows/published-artifact-gate.yml`, `.github/workflows/reusable-build-attest.yml` | reproducibility + hermetic cleanroom are inherited (release.yml already builds the reproducible sdist; the gate proves byte-identity on every PR). The **reusable** attest workflow is built and CI-exercised (dry_run) now; release.yml still uses its own inline build+attest — replacing that with `uses: reusable-build-attest.yml` is the remaining one-liner adoption, honestly pending (see note below) |
| **F3** | One growing, versioned formal model | `formal/model.py` | append a proof obligation (`version_added`), flip a reserved slot to `proven` |
| **F4** | Property-based type-confusion generator over the AST-discovered `verify_*` set | `scripts/type_confusion_gate.py` | a new verifier is auto-covered or honestly `NEEDS_FIXTURE` — no static list to edit |
| **F5** | Reviewer-oriented readiness-pack skeleton | `docs/readiness_pack/` | drop evidence into the release's named slot in `index.json` |
| **F7** | Adversarial internal audit gate before every tag | `scripts/pre_tag_audit_gate.py` | run the audit, record it — the gate checks it ran |

## Which foundation de-risks which release work package

| Release | Work package | De-risked by | How it extends (not rebuilds) |
|---|---|---|---|
| **3.4.0** | relation_signer + outcome-gate, decoy-parent F1 enforcement | F1, F3, F7 | decoy-parent vectors go into `conformance/relation/`; the pin/crypto separation becomes formal obligation **O5** (already a reserved slot); the signer ceremony mirrors the existing `un_review_signer` pattern |
| **3.4.0** | target-pin ⊥ cryptoValid | F3 | flip reserved **O5_TARGET_PIN_NOT_CRYPTO** to proven |
| **3.5.0** | relation_statement + Rust parity of all paths | F1, F4, F3 | the new `verify_*` is auto-covered by F4; parity goes into `rust_parity_registry.json` + `crosscheck.py`; **O6_RETRACTS_NEVER_RAISES** stays reserved (the retracts-never-raises property is code-enforced, conformance-tested and mutation-killed, but NOT yet a formal `model.py` proof — flipping the reserved slot to proven is deferred) |
| **3.6.0** | audit-candidate: 33-check matrix, payloadType obligations, fuzz-soak, differential matrix | F1, F3, F4, F5 | payloadType binding becomes **O7** (reserved); the type-confusion matrix is already structural (F4); the readiness pack's 3.6.0 slot collects fuzz-soak + differential evidence |
| **all** | hermetic + reproducible + attested release | F2 | inherited with zero per-release work |

## Honest F2 adoption status (No-Fake)

- **Reproducible sdist** — LIVE: release.yml builds the normalised sdist; `published-artifact-gate.yml`
  proves two builds are byte-identical on every PR. The wheel is built and attested but is **not**
  claimed byte-identical.
- **Hermetic cleanroom** — LIVE: `published-artifact-gate.yml` installs the built sdist into a fresh
  venv and proves the published bytes pass the demo + an emit/verify/tamper round-trip.
- **SLSA-L3 reusable signing workflow** — BUILT + CI-exercised via `dry_run`, but release.yml still
  runs its own inline build+attest. Full L3 build/attest separation lands when release.yml is switched
  to `uses: ./.github/workflows/reusable-build-attest.yml` (a caller-outputs refactor, deferred to the
  3.3.1 release GO so the publish path is changed under release review, not in this build-only branch).

## Cross-repo note (acceptance §9.7)

The four release prompts (`proofbundle_331_/_340_/_350_/_360_`) live in the 2bedone staging area, not
in this repo. Each must carry a one-line reference — *"uses Front-Load foundations F1–F5, does NOT
rebuild them; see `docs/roadmap/FRONTLOAD.md`"* — so the front-load effect actually lands. That edit is
an OPEN cross-repo action (2bedone `globe/staging/incoming/`), tracked here because this repo's build
scope cannot reach those files.
