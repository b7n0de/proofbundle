# External-audit readiness pack (Fundament F5)

Reviewer-oriented navigation: **start from a conclusion, walk to its ordered evidence.** This is the
AuditWeave (arXiv:2607.09682) lesson (b) — a reviewer should navigate from a verdict to the evidence
that backs it, not grep a repository. The machine-readable map is [`index.json`](index.json); this
page is the human entry point.

This is **preparation, not an audit.** No independent audit of proofbundle has occurred. Every
artifact referenced here is this project's OWN instrument, which is exactly the boundary an external
review exists to close (`docs/AUDIT_READINESS.md`, Finding 12). The honest progress accounting is in
[`PROGRESS.md`](PROGRESS.md); the list of things that need human judgement is in
[`OPEN_QUESTIONS.md`](OPEN_QUESTIONS.md).

Front-loaded skeleton: the slots below are laid out now (with 3.3.1) so each release delta
(3.4.0 / 3.5.0 / 3.6.0) drops its evidence into its named slot in `index.json` instead of assembling
a pack from scratch at the end (`GO_OWNER_PB_ROADMAP_FRONTLOAD_20260716`, F5).

## Conclusions → evidence

| Conclusion | In one line | Evidence entry point |
|---|---|---|
| **C1** Anchored resistance | verified is tamper-evident; anchored is tamper-**resistant** | [`tamper_resistance.md`](tamper_resistance.md) |
| **C2** verify separates authentic from forged, never raw-crashes | one corpus, one vocabulary, an independent Rust check, a structural type-confusion gate | `conformance/`, `tools/pb_verify_rs/crosscheck.py`, `scripts/type_confusion_gate.py` |
| **C3** lineage ladder logic is sound and never upgrades crypto | a versioned formal model, grounded in the code, honest about its scope | `formal/model.py`, `formal/README.md` |
| **C4** releases carry hermetic, reproducible, separated provenance | hermetic cleanroom gate, byte-reproducible sdist, SLSA-L3 reusable attest workflow | `.github/workflows/published-artifact-gate.yml`, `scripts/build_reproducible.py` |

Each conclusion in `index.json` lists its evidence **in review order** and links the open questions
it does not, and cannot, close on its own.

## Release evidence slots (front-loaded)

- `3.3.1-frontload` — **filled**: the five foundations (F1–F5) + the pre-tag audit discipline (F7).
- `3.4.0` — reserved: relation_signer receipts, decoy-parent F1 vectors, formal obligation O5.
- `3.5.0` — reserved: relation_statement Rust parity, formal obligation O6, F4 auto-coverage.
- `3.6.0` — reserved: fuzz-soak corpora, differential matrix, formal obligation O7, threat-model delta.

A `reserved` slot is declared honestly; it is not evidence yet, and nothing here counts it as such.

## How to check this pack mechanically

```bash
python scripts/readiness_pack_gate.py        # validates the skeleton + index.json consistency
python scripts/readiness_pack_gate.py --json
```

The gate fails if a referenced evidence file is missing, if a required navigation doc is absent, or
if a release slot's status is neither `filled` nor `reserved` — so this pack cannot silently drift
ahead of what exists.
