# proofbundle — Principal Review v1.6 (6 lenses + 6 orthogonal iterations)

Reviewers: Principal Security Engineer · Applied-Crypto Reviewer · AI-Eval-Infra Architect ·
OSS Maintainer · Technical Product Strategist. Method: every claim treated as proof-obligated;
findings backed by file:line and executed probes; P0 fixes landed in this release, DX/supply-chain
items specified as an issue backlog. Base: byte-exact GitHub tag v1.4.0 → v1.5.0 (per-sample) →
this v1.6.0 (review fixes).

---

## 1. Executive Verdict (hard, honest, useful)

proofbundle is an unusually *honest* small crypto tool with a real niche — offline, one-file,
eval-shaped receipts — and no shipped competitor occupying it. The cryptographic core is sound
(no home-rolled math, constant-time compares, RFC 6962 domain separation, correct RFC 9901
digest mechanics, key-material-deduped witness quorum). The review found **one genuine P0
fail-open** (bearer-downgrade via issuer-key omission) and a cluster of **verify-vs-emit
asymmetries** where a guarantee the docs imply lived only on the emit path. All of those are
fixed and regression-tested in v1.6. What still blocks external credibility is NOT crypto — it is
**demo/DX and release supply-chain**: there is no user-facing tamper demo, no pip-only quickstart,
no per-sample example, the release workflow rebuilds (so attested ≠ published), and badges/assets
over-promise a package that isn't on PyPI yet. Fix trust and demo before any new feature. The docs
are honest enough that the "claim clarity" work is mostly badge/tense cleanup, not de-hyping.

## 2. Top 10 weaknesses

| # | Weakness | Impact | Evidence | Fix | Test/artifact | Prio |
|---|---|---|---|---|---|---|
| 1 | Bearer-downgrade via issuer-key omission | cnf-bound SD-JWT strips KB + drops issuer key → passes as bearer | `bundle.py` KB block gated on `sig_ok`; probe: key absent→OK, present→FAIL | Refuse cnf-carrying SD-JWT with no issuer key (**done v1.6**) | `test_bundle_cnf_bound_no_issuer_key_fails_closed` | **P0** |
| 2 | `samples.n==n` only enforced in emitter | hand-signed claim lies about tree size → sub-sampling gap reopens | probe: `decode_eval_claim` accepted n=100/samples.n=7 | re-check on verify path (**done**) | `test_decode_rejects_samples_n_mismatch` | P1 |
| 3 | `context_binding` signed but never checked | cross-context receipt replay | grep: no verify path reads it | `decode_eval_claim(expected_context=)` (**done**) | `test_context_binding_enforced_on_verify` | P1 |
| 4 | Unbounded status snapshot = "fresh forever" | stale pre-revocation snapshot replays as current | probe: no exp/no ttl → fresh=True at now=+1e9 | `fresh=None` without a bound (**done**) | `test_no_exp_no_ttl_fresh_is_none` | P1 |
| 5 | Attested artifact ≠ published artifact | SLSA/PEP-740 provenance covers a different build than PyPI gets | `release.yml` publish job runs `python -m build` again | pass `dist/*` between jobs via pinned up/download-artifact | RELEASE.md step "published sha256 == attested subject" | P1 |
| 6 | No user-facing tamper demo | the single most persuasive reviewer artifact is missing | `grep tamper scripts/ examples/ Makefile` → nothing | `make tamper-demo` (6-variant matrix) + `proofbundle demo` | issues #2,#3 | P0(DX) |
| 7 | Quickstart requires a git checkout | `pip install` + README quickstart → FileNotFoundError | `examples/` not in wheel (`packages.find where=["src"]`) | `proofbundle demo` subcommand, pip-only | issue #4 | P0(DX) |
| 8 | Status-list issuer = bundle issuer, no domain separation | issuer self-signs its own "still valid" revocation state | probe: same key signs bundle + status token, verifies | Document status-issuer SHOULD be a distinct anchor | THREAT_MODEL row + statuslist docstring | P1 |
| 9 | Badges/assets over-promise pre-first-release | PyPI/downloads/SLSA badges render broken/false; logo+demo.svg missing | `README.md:16-24`; `assets/*.MISSING.txt` | gate badges behind first publish; supply assets | issue #21 | P1 |
| 10 | Alpha classifier vs compliance-adjacent docs | mixed maturity signal to compliance readers | `pyproject` Alpha vs COMPLIANCE.md Art.12 mapping | → Beta + "not a sole compliance control" note (**done**) | classifier diff | P2 |

## 3. P0 Patch Plan (landed in v1.6 unless marked)

1. **Fail-closed bearer-downgrade** (done) — `bundle.py`: a `cnf`-carrying SD-JWT with no issuer
   key emits `sd-jwt-key-binding=False`; whole bundle fails. Backward-compat pin for no-cnf case.
2. **Verify-side invariants** (done) — `decode_eval_claim` re-checks samples shape/n/leaf_alg/root
   and enforces `expected_context`.
3. **Status freshness + strict types** (done) — `fresh=None` when unbounded; non-int exp/ttl rejected.
4. **`merkle.hash_alg` required** (done).
5. **DX (specified, next patch)** — `proofbundle demo` (pip-only, in-memory emit→verify→tamper),
   `make tamper-demo`, `examples/persample_audit.py`. These are the highest-leverage *adoption*
   fixes; kept out of this security patch to keep the diff reviewable.

## 4. P1 Trust Plan (external credibility)

- Release: make the **attested artifact the published artifact** (`release.yml` up/download-artifact);
  add required reviewers on the `pypi` GitHub Environment; add `RELEASE.md` with a "published
  sha256 == attested subject digest" gate.
- Supply chain: add a CI dimension installing the **`cryptography` floor** (`==42`) to prove the
  floor works, not just latest; add CodeQL (SHA-pinned); fuzz the checkpoint/tlog-proof/statuslist
  parsers; add `SECURITY-INSIGHTS.yml` + OpenSSF Scorecard badge once public.
- Docs: `docs/REVIEWERS.md` (30-minute audit path, "where the bodies are buried"), FAQ-for-skeptics,
  a "where trust anchors come from" table (bundle issuer in-band self-asserting; SD-JWT/status/log/
  witness keys out-of-band; status issuer SHOULD differ from bundle issuer).
- Badges/assets: gate PyPI/downloads/SLSA/PEP-740 badges behind first publish; ship real assets or
  drop the `<picture>` block; reword SECURITY.md attestation language to conditional until a release
  exists.

## 5. P2 Research Plan (real differentiation)

Per-sample receipts (shipped v1.5) are the differentiator; deepen them: (a) a beacon-mode audit
(drand/NIST pulse after the signed timestamp) for non-interactive public re-verifiability; (b) an
`examples/persample_audit.py` + `make persample-demo` that runs the forced-random-sample check
end-to-end; (c) a short paper/JOSS submission of the audit protocol (TRUCE arXiv:2403.00393 + PoR
1−(1−m)^k bound are citation-ready) — this is a genuine research-funding hook; (d) propose an
`eval-result` predicate at in-toto / OpenSSF AI-ML WG rather than squatting a vendor URI.

## 6. README rewrite (top ~120 lines) — proposed order

1. One-paragraph problem: "an eval number is an unverifiable claim." 2. The niche (≤25 words) +
the bound sentence. 3. **60-second pip-only quickstart** (`pip install proofbundle && proofbundle
demo`) showing OK → tamper → FAIL in-memory. 4. Tamper-demo transcript. 5. "What a receipt proves
/ does NOT" (trim current lines, link THREAT_MODEL) — incl. the v1.6 context_binding/verify-side
note. 6. Eval receipts **+ per-sample audit** (promote from Roadmap). 7. Integrations. 8. 5-node
architecture mermaid. 9. Interop table (link INTEROP.md). 10. Security scope. 11. Compliance /
Roadmap / Contributing. Badges: keep CI/license (+ PyPI once published); demote the rest below the
fold. (Full text sketch in the issue backlog #22.)

## 7. New files / sections (this release + backlog)

- **REVIEW_v1.6.md** (this file) — done.
- **CHANGELOG 1.6.0** — done.
- **docs/REVIEWERS.md** — 30-min audit path, trusted-core map, invitations. *(backlog #11)*
- **docs/DEMO.md** — 3 tiers (pip-only / repo / extras) each with expected literal output. *(backlog #23)*
- **RELEASE.md** — release checklist incl. attested==published gate. *(backlog #5)*
- **FAQ-for-skeptics** (README section or docs/FAQ.md) — 10 honest Q&A. *(backlog #19)*
- **Trust-anchor provenance table** in README+SPEC. *(backlog #24)*
- **examples/persample_audit.py**, **scripts/demo_tamper.sh**, **`proofbundle demo`**. *(backlog #2,#3,#5)*

## 8. Test matrix (≥20; ≥10 adversarial). ✅ = shipped in v1.6, ⬜ = backlog

Adversarial: ✅`test_bundle_cnf_bound_no_issuer_key_fails_closed` (P0) · ✅`test_decode_rejects_samples_n_mismatch`
· ✅`test_decode_rejects_bad_leaf_alg` · ✅`test_decode_rejects_short_root` · ✅`test_context_binding_enforced_on_verify`
· ✅`test_no_exp_no_ttl_fresh_is_none` · ✅`test_string_exp_rejected` · ✅ (existing) `test_red_lying_producer_embedded_idx`
· ✅ (existing) KB strip / bit-flip / issuer-swap · ✅ (existing) witness one-key-many-names quorum stuffing
· ✅ (existing) tlog-proof wrong-leaf / index-tamper / quorum-not-met · ⬜`test_merkle_missing_hash_alg_rejected`
(covered behaviorally by the required-field change; add explicit) · ⬜`test_statuslist_self_issued_documented`
· ⬜`test_persample_record_size_cap` · ⬜`test_tlogproof_extra_not_authenticated` (confirm existing coverage).
Positive/regression: ✅`test_bundle_no_cnf_no_issuer_key_still_backward_compatible` · ✅`test_ttl_bounded_is_judged`
· ✅`test_decode_accepts_valid_samples` · ✅ full offline example roundtrips (make_example, lm_eval, eee, intoto,
checkpoint, tlog_proof, rekor_interop) · ✅ persample audit loop. Total suite: **251 tests**, 26-operator mutation gate.

## 9. Issue backlog (≥15) — title · goal · acceptance · label

1. **P0** Restore inspect fixture so `make demo` passes from a clean clone — *acc:* CI runs `make demo` green — `bug,demo`
2. **P0** `make tamper-demo` (6-variant matrix) — *acc:* exits non-zero if any tamper verifies — `demo,security`
3. **P0** `proofbundle demo` pip-only subcommand — *acc:* works with no checkout/extras/network — `dx,cli`
4. **P0** Quickstart works after bare `pip install` — *acc:* copy-paste succeeds — `docs,dx`
5. **P0** `examples/persample_audit.py` + `make persample-demo` — *acc:* challenge→open→tampered-open FAIL, in CI — `demo,persample`
6. **P1** Capture run-id + config-hash + log-native timestamp in inspect/lm_eval adapters — *acc:* provenance carries all three — `adapters,provenance`
7. **P1** `proofbundle prereg <file>` helper + prereg walkthrough — *acc:* hash stamped + verify-side disclosure demo — `cli,anti-cherry-picking`
8. **P1** Cross-check HF `value` vs disclosed claim score — *acc:* mismatch raises unless opted out — `hf,honesty`
9. **P1** Release: attested artifact == published artifact — *acc:* publish consumes attested dist — `security,release`
10. **P1** `pypi` environment required reviewers + RELEASE.md — *acc:* documented + configured — `security,release`
11. **P1** docs/REVIEWERS.md + external-review issue template — *acc:* 30-min path lands — `docs,community`
12. **P1** Status-issuer distinct-anchor guidance in THREAT_MODEL + statuslist docstring — *acc:* text present + test — `docs,security`
13. **P1** Gate PyPI/downloads/SLSA badges behind first publish; ship assets — *acc:* no broken images pre-release — `docs`
14. **P2** CI dimension: install `cryptography==42` floor — *acc:* floor job green — `security,ci`
15. **P2** CodeQL (SHA-pinned) + fuzz targets for parsers — *acc:* workflows added — `security,ci`
16. **P2** EVAL_CLAIM.md field table: add `samples` + `provenance` rows — *acc:* matches schema — `docs`
17. **P2** examples/README.md with run order + expected output — `docs,examples`
18. **P2** Makefile: `mutation`, `examples`, `coverage` targets — `dx`
19. **P2** FAQ-for-skeptics page linked from README — `docs,community`
20. **P2** Remove stale 3.9 comments (floor is 3.10) — `cleanup` (good-first-issue)
21. **P1** Reword SECURITY.md attestation to conditional until first release — `docs,security`
22. **P1** README top-120 rewrite per §6 — `docs,dx`
23. **P2** docs/DEMO.md three tiers — `docs,demo`
24. **P1** Trust-anchor provenance table (README+SPEC) — `docs,security`

Good-first-issue candidates: #16,#17,#18,#20. Help-wanted: #6,#7,#15. Expert-review: #9,#12,#24.

## 10. Outreach pack

- **Security reviewer:** "proofbundle is a small offline Python verifier for AI-eval receipts;
  we just ran an internal Principal-Security review that found and fixed a KB-JWT bearer-downgrade
  (fail-closed now, regression-tested). The trusted core is signature.py+merkle.py+bundle.py, ~600
  LOC, cryptography-only. Would you spend 30 minutes trying to make the tamper matrix verify?"
- **AI-eval-infra (Inspect/AISI):** "You closed inspect_evals PR #1610 as a layer above the
  framework — that layer is our whole project: an opt-in end-of-task hook that turns a finished
  .eval into an Ed25519-signed, offline-verifiable receipt, with a per-sample Merkle root so an
  auditor can force random-sample checks. Never touches a run unless PROOFBUNDLE_EMIT=1. Would a
  docs mention be acceptable, and what would you need audited first?"
- **Funding/grant:** "proofbundle makes AI-eval results tamper-evident and offline-verifiable, and
  its v1.5 per-sample audit protocol (TRUCE + proof-of-retrievability, 1−(1−m)^k) gives external
  reviewers forced random-sample checks without publishing the test set — the missing integrity
  layer for third-party evals. The fundable next step is the audit protocol as a spec + reference
  implementation + independent security audit. Three 1-page grant abstracts attached."

## 11. Final pitch

- **10 words:** Offline, signed, tamper-evident receipts for AI eval results.
- **25 words:** proofbundle turns an AI eval result into a portable, offline-verifiable signed
  receipt — proving authorship and integrity, with per-sample audit hooks, never claiming the
  number is true.
- **60 seconds:** Every AI eval number you read is an unverifiable claim: trust the lab. proofbundle
  makes it *attributable and tamper-evident* instead. It turns a run into one portable JSON receipt:
  these exact bytes, signed by this key, anchored under this Merkle root, with the model and dataset
  kept as salted commitments so you can prove a threshold was met without revealing them. It verifies
  fully offline — no server, no log service, one file — and interoperates with Sigstore Rekor,
  in-toto/DSSE and C2SP transparency-log formats. Since v1.5 it commits to *every individual sample*,
  so an auditor can pick random indices with a fresh nonce and demand openings — catching 1%
  cherry-picking with 95% confidence at 300 samples, regardless of run size. It is deliberately
  honest about the line it does not cross: it proves who claimed what and that nothing changed since,
  not that the number is true, the issuer honest, or the eval well-designed — those need
  pre-registration, independent reproduction, or a TEE. Small, offline, standards-native, and it
  says exactly what it is.
