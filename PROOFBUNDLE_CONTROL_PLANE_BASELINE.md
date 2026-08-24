# proofbundle Control Plane — Baseline (Phase 0 / R50)

Generated 2026-08-24T07:57:43Z (measured `date -u`). Order: clamp sheet `20260824T071500Z`
over the umsetzungsprompt (sha256 `1bfc06cefd284867271862808e4929bf7070aa8c3eb5b1ad168356a3e9891709`,
2533 lines, read in full). Scope: **Phase 0 and Phase 1 only**; phases 2–11 are blocked on
owner decisions E2–E10 and are not touched here.

Companion data file: `CONTROL_PLANE_CONSUMER_MAP.json` (same directory, same generation stamp).

## 1. Pinned states (R01)

| Repo | Commit | Context |
|---|---|---|
| proofbundle | `c669d39e3d8e8bf235ec1c03e40378cb146fba7a` | == `origin/main` at measurement; measured in a clean worktree on work branch `feat/control-plane-phase0-1-20260824`; the primary checkout carries unrelated in-flight work (7 dirty entries, another branch) and is untouched |
| private producer repo ("2bedone") | `279d453224a5d5f5a1d9169fd3e33afdfcbf1073` | working tree carries 155 uncommitted entries (night work awaiting an owner commit token); the inventory reads the working tree because that is what the runtime executes |

**Bound-snapshot comparison (R01): all 7 files the source document pinned are byte-identical
with this commit** (sha256 table in the map). The reviewer's basis IS our current `origin/main`
— no drift between research and build. Local branch `main` in the primary checkout is behind
`origin/main` (`6f7535696d81`); the worktree pins the fetched `origin/main` state instead.

## 2. Public surfaces (proofbundle)

- **Python API:** 57 exports in `__all__` (runtime-measured at the pinned commit; version 4.0.0).
- **CLI:** 19 top-level subcommands (runtime `--help` at the pinned commit): verify, emit,
  emit-eval, show-eval, verify-proof, hf-token, audit-challenge, verify-opening, verify-enclave,
  demo, intoto, svr, policy, prereg, evalcard, decision, outcome, relation-statement, anchor.
- **Entry points:** console script `proofbundle`; `inspect_ai` registry (opt-in auto-emit);
  `pytest11` plugin.

## 3. What the consumer inventory shows (categories 3–7 of R50)

Full per-entry evidence (file:line + observable effect, three states, never a green blank) is in
`CONTROL_PLANE_CONSUMER_MAP.json`. The load-bearing findings:

1. **Decision receipts have real, effect-verified consumers in both repos** — the privileged-click
   adjudication (deny on missing/invalid witness decision), the review-receipt verifier, the
   land-attestation witness (separate unix user, exit codes gate landing), trust-policy lint,
   CI gates.
2. **`safeForAutomation` has exactly ONE effective external reader** (`b7_review_receipt_verify`,
   gate branch on `is not True`) — and it uses the field exactly per the R27 semantics
   (verification-profile gate, never an action grant). Inside proofbundle nothing branches on it
   (producers + test assertions only). E7's concern is real but currently contained.
3. **`execution_proven` has NO positive reader anywhere.** proofbundle derives it and prints an
   honest self-asserted caveat when False; the private repo has four writers-of-honest-False and
   zero readers that treat it as proof of effect. R17's target state already holds in practice;
   the remaining work is profile documentation, not consumer surgery.
4. **Trust-pack and assurance consumers exist only inside proofbundle** (measured empty in the
   private repo). Reviewer trust in the private repo runs via policy files.
5. **Action-object store:** producer + atomic three-state store library exist and are
   parallel-tested (20 processes → exactly 1 EXECUTING); the Swift UI decodes NONE of the
   action-object feed fields today, and clickability is deliberately not bound to store readiness
   yet (a binding on measurement day would have locked the owner out — the order's own abort
   condition). Authoritative card-consumer numbers come from the existing measured contract map
   (61 fields, 27 effective readers, 3 steering operability) — referenced, not recomputed.

## 4. Content-root state (input to Phase 1)

- **The one primitive exists:** `canonical.py::statement_content_root` /
  `canonicalize_statement`, algorithm id `jcs-sha256-v1` (ADR 0002). Producer canonicalizes
  (RFC 8785) and signs those bytes; verifier hashes the EXACT transmitted bytes and never
  re-canonicalizes.
- **All predicate emit/verify paths delegate to it** (decision, outcome, relation,
  relation-statement, trust-pack, verification-summary, run-ledger, subject-binding — file:line
  list in the map).
- **The released 2.0.0 wire lives on as a NAMED legacy algorithm** (`legacy-sortkeys-json-v0`,
  intoto.py): a Statement declares `contentRootAlg` inside the signed payload; ABSENT ⇒ legacy
  (that is how released receipts keep verifying); absence is never silently treated as jcs;
  unknown algorithm ids fail closed; the verifier byte-compares a payload against its OWN
  declared algorithm (algorithm-confusion guard).
- The source document's P3 ("parts of the eval-result export used sorted JSON") describes the
  pre-2.1.0 state; at the pinned commit the migration is done and the residue is the *named*,
  declared legacy mode. **Removing that legacy mode would be a backwards-incompatible public
  change — stop condition 2; owner decision; explicitly NOT done in this phase.**
- Non-statement digest sites (subject binders, disclosure hashes, labeled config-digest
  fallbacks) are distinct quantities and are listed as such in the map so nobody mistakes them
  for divergent content roots.

## 5. Boundaries (in the map as `not_measurable`, not omitted)

Root crontab (unreadable from this process) · Mac LaunchAgents (not measured from here) ·
external PyPI users (unknowable). Recall of a name-based search is bounded; predicate-type
strings and field names were searched in addition to the package name.

## 6. Gate (R50)

**PASS** — every R50 category is enumerated with per-entry effect state; unmeasurable surfaces
are recorded as `not_measurable` entries. (The alternative verdict `BLOCKED_INVENTORY` was not
needed: no category came back un-enumerable.)
