# The twelve seal conditions, mapped onto TRACE

Register entry N24. This is a MAPPING, not a build. It answers one question per condition:
does TRACE already have a field for it, does filling that field need hardware we do not
have, or does TRACE not model the condition at all.

## The standard that is being mapped onto

| | |
|---|---|
| Name | TRACE — Trust, Runtime Attestation and Compliance Evidence |
| Governance | Linux Foundation, announced **2026-08-25** |
| Contributed by | OPAQUE; developed with AMD, Intel, Microsoft, TII |
| Specification read | `spec/trace-v0.2.md`, `github.com/agentrust-io/trace-spec` |
| Version and status | **0.2, and the document calls itself "RFC: Request for Comments"** |
| Retrieved | **2026-09-12** |
| Builds on | RATS, EAT, SLSA, SCITT, SPIFFE, EAR |

**Two corrections to the assumptions this mapping started from, and they matter for the
plan.** The order that commissioned this table described TRACE as a *developer preview*
with *three trust levels*. Measured against the specification:

* Its own status line says **draft / RFC**, not developer preview. The difference is not
  cosmetic: an RFC invites the field names to change, so anything built against v0.2 must
  record which revision it read. This table does, in the row above.
* **There are no three trust levels.** There is a `Level 0` (software-only, which the spec
  itself limits to "development and audit-trail tooling rather than third-party proof"),
  three provenance verification **depths** (`surface`, `builder`, `transitive`), and three
  policy **enforcement modes** (`enforce`, `silent`, `declared`). Three of something, three
  times — but not a trust ladder. Our own four identity steps (claimed / directory-bound /
  load-observed / hardware-witnessed) have no counterpart in TRACE and stay ours.

## The mapping

Field names are quoted from the v0.2 schema. `—` means the specification has no field.

| # | Condition (sheet 20) | TRACE field | Verdict |
|---|---|---|---|
| 1 | the attestation carries a nonce WE chose | `runtime.nonce` | **fillable today** — the field exists and its meaning is identical |
| 2 | checked against a trust root WE choose | `appraisal.verifier`, `appraisal.policy_ref` | **fillable today** as a field; the checking itself still needs condition 4 |
| 3 | hardware state and revocations looked up at check time | `appraisal.status`, `runtime.rim_uri` | **partly** — the reference measurement has a field, revocation does not. TRACE says so itself: *"Nothing inside a record can retract the key that signed it"* |
| 4 | the response-signing key provably comes from the sealed enclave | `cnf.jwk` | **needs hardware** — the field is the key confirmation; what it is worth depends on a TEE we do not run |
| 5 | request and response digests inside the signed structure | — | **TRACE does not model it.** `tool_transcript.hash` covers TOOL calls at an instrumented boundary, not the model exchange itself |
| 6 | the actual route: which machine, which model instance | `subject` (SPIFFE SVID), `runtime.measurement`, `model.provider`, `model.model_id`, `model.weights_digest` | **fillable today** for the naming half; the binding half needs hardware |
| 7 | no silent machine switch — a switch is a failure | — | **TRACE does not model it.** A record describes ONE run. "No silent switch" is a property of a SEQUENCE of runs, and nothing in the schema carries it forward |
| 8 | model and route stand in the plan BEFORE the run | `policy.bundle_hash` with `policy.enforcement_mode: "declared"` | **near, not equal** — declared mode records an intent, but the intent is not required to predate the run |
| 9 | recomputable later without internet, frozen key set | `transparency`, `references` | **partly** — the pointers exist; TRACE names offline revocation proof as an explicit limitation |
| 10 | price, latency, error rate, throughput on OUR tasks | — | **TRACE does not model it.** Economics is not an attestation field, and it should not become one |
| 11 | what the provider stores, and for how long | — | **TRACE does not model it.** `data_class` classifies the data in the run, never its retention. This is a contract question wearing an attestation costume |
| 12 | if attestation fails: not-run or partial, never passed | `appraisal.status` | **fillable today** as a field; the RULE (never silently "passed") stays ours — a field can carry a verdict, it cannot enforce a policy about it |

**Totals, counted from the table rather than from memory: 4 fillable today · 1 needs
hardware · 2 partly · 1 near · 4 TRACE does not model.**

*This line was wrong when it was first written* — it said "2 need hardware, 3 TRACE does
not model", and a count over the table itself gave 1 and 4. The rows had not changed; the
summary had never been derived from them. A total written beside a table instead of out of
it is the smallest possible instance of the class this whole register is about, and it is
recorded rather than quietly fixed.

## What follows, stated as three facts rather than a plan

**Where TRACE has a field, we use TRACE's field.** Conditions 1, 2, 6 and 12 get `runtime.nonce`,
`appraisal.*`, `subject`/`model.*` and `appraisal.status` — no own format next to an existing one.

**Four conditions have no TRACE field, and two of them should not get one.** Retention (11) and
economics (10) are contract and measurement questions; putting them into an attestation record
would make the record claim something its signer cannot witness. The two real gaps are 5 and 7:
the model exchange itself carries no digest field (`tool_transcript` covers tool calls at an
instrumented boundary, not the request and response), and "no silent switch" needs a SEQUENCE —
a record describes one run, and nothing in the schema carries a machine identity forward to the
next one. Both would have to be built on either side.

**Our honest level is unchanged by this table.** Today the model name comes from response data —
step one of four, `claimed`. TRACE's `Level 0` is the same statement in their vocabulary, and
their own limitation text is the one to quote when someone reads more into it: *"A privileged
operator with root access can produce a valid-looking Level 0 record for a run that never
happened."* A mapping does not raise a level. Only a measurement does.

## Sources

* Linux Foundation press release, 2026-08-25 — <https://www.linuxfoundation.org/press/linux-foundation-welcomes-trace-to-advance-verifiable-runtime-evidence-for-ai-workloads>
* Specification v0.2 (RFC) — <https://github.com/agentrust-io/trace-spec/blob/main/spec/trace-v0.2.md>
* Stated limitations — <https://github.com/agentrust-io/trace-spec/blob/main/LIMITATIONS.md>
* Sheet 20 of the explainer series, 2026-09-02, `proofbundle_modellidentitaet_siegel_erklaert_a4_20260902.pdf`
