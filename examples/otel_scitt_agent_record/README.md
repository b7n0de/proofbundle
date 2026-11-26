# An agent record from OpenTelemetry spans, anchored in SCITT

A worked example: an AI agent's run and one of its tool calls are recorded as two OpenTelemetry spans after the
GenAI semantic conventions, a person approved the call, and a signed record of all three is anchored in a SCITT
transparency service. The record carries salted fingerprints, not the spans: a reader checks offline what can be
checked without them, and the rest stays open until the spans and salts are disclosed in a dispute.

Everything here is synthetic and checked offline. The SCITT service is a local test stand-in (`scitt_local.py`),
not a registration with a real service, and every key and salt is a test value derived from a public label.

## Conventions, pinned

The span and attribute names come from
[open-telemetry/semantic-conventions-genai](https://github.com/open-telemetry/semantic-conventions-genai) at
commit `e6658f14c9d9ea0760825f029cb82e7673f48fab` (2026-11-06). Every entry used here has the status Development
there, so names can still change; the record names the commit, and `check_example.py` requires that commit.

- The run is the span `invoke_agent` of kind INTERNAL (`docs/gen-ai/gen-ai-agent-spans.md`, section "Invoke agent
  internal span", from line 168), with `gen_ai.operation.name` `invoke_agent` (Required), `gen_ai.agent.name` and
  `gen_ai.conversation.id` (both Conditionally Required). At this commit that span has no `gen_ai.agent.id`; it
  appears only on the create agent span (line 62), so the example sets none.
- The tool call is the span `gen_ai.execute_tool`, named `execute_tool {gen_ai.tool.name}`, of kind INTERNAL
  (`docs/gen-ai/execute-tool.md`, lines 28 to 173), with `gen_ai.operation.name` `execute_tool` and
  `gen_ai.tool.name` (Required), `gen_ai.tool.call.id`, `gen_ai.agent.name` and `gen_ai.conversation.id`
  (Conditionally Required), `gen_ai.tool.type` (Recommended), and the opt-in `gen_ai.tool.call.arguments` and
  `gen_ai.tool.call.result`, which are exactly the content the record must not carry in clear.
- **The approval is not standardized.** At this commit the conventions define no span and no attribute for a
  human approval: a search for approv, human, consent, confirm, elicit and permission in the two files above and
  in `docs/registry/attributes/gen-ai.md` finds only "human-readable" and "human readable" in descriptions of
  names and labels. The example carries the approval as a
  proofbundle decision receipt (`proofbundle.decision`), signed by the gate and linked to the call by
  `gen_ai.tool.call.id`. The record says so in the approval entry, and the check refuses a record that presents
  the approval as an OpenTelemetry standard (case F15).

## Files

| File | What it is |
|---|---|
| `make_example.py` | The producer. Writes the two spans, the approval receipt, the record and its anchoring into `out/`. Deterministic. |
| `scitt_local.py` | The local test stand-in for a SCITT service: it signs the statement (a COSE_Sign1 hash envelope) and returns a receipt in the CCF profile. proofbundle has no producer of signed statements; this one lives in the example only. |
| `check_example.py` | The offline check, with the states PASSED, FAILED and OPEN. |
| `measure_cases.py` | Builds the cases from the example and runs the check twice on each. |
| `cases.md` | The output of `measure_cases.py`. |
| `out/` | The files `make_example.py` writes, as produced. |
| `SHA256SUMS` | The SHA-256 of every file above. |

In `out/`: `record.dsse.json` is the signed record (DSSE, Ed25519) and `record.payload.json` its payload, an in-toto
Statement v1 in RFC 8785 form; `scitt/signed-statement.cose` is the signed statement, `scitt/receipt.cose` the
receipt and `scitt/transparent-statement.cose` both together; `statement-signer-test-cert.der` is the test
certificate in the statement's x5chain; `test-keys.json` names every test key by its label. `disclosure/` holds
what a dispute would hand over: `spans.otlp.json` (the two spans, OTLP JSON), `salts.json`, `approval.dsse.json`
(the decision receipt) and `rule.json`. In a real deployment that folder stays with the issuer.

## Check it offline

```
pip install "proofbundle[scitt]>=6.6.1"
cd examples/otel_scitt_agent_record
python check_example.py out                                  # OPEN, exit 3
python check_example.py out --disclosure out/disclosure      # PASSED, exit 0
python measure_cases.py
```

The keys are pinned in `check_example.py` and never read from the files: the recorder key, the gate key, the
statement signer's key, and the service key under the issuer `scitt.example`. The anchoring is checked with
`proofbundle.scitt_ccf.verify_transparent_statement` (profile scitt-ccf/v1), the approval with
`proofbundle.decision.verify_decision_receipt` in strict mode.

## From span to record

| In the record (`record.payload.json`) | From |
|---|---|
| entry `run`, `fingerprint` | sha256-salted-v1 (`proofbundle.evalclaim.salted_commit`, salt `run`) over the RFC 8785 form of the run span's `traceId`, `spanId`, `name`, `kind`, start and end time, and the attributes `gen_ai.operation.name`, `gen_ai.agent.name`, `gen_ai.conversation.id` |
| entry `action`, `fingerprint` | the same over the tool span's fields, its `parentSpanId`, and `gen_ai.operation.name`, `gen_ai.tool.name`, `gen_ai.tool.call.id`, `gen_ai.tool.type`, `gen_ai.agent.name`, `gen_ai.conversation.id`, `gen_ai.tool.call.arguments`, `gen_ai.tool.call.result` (salt `action`) |
| entry `approval`, `fingerprint` | the same over `{"receiptSha256": SHA-256 of approval.dsse.json}` (salt `approval`) |
| `callRef` of approval and action | sha256-salted-v1 of `gen_ai.tool.call.id` (salt `call`), one value in both entries |
| `traceRef` | sha256-salted-v1 of the trace id (salt `trace`) |
| `subject[0].digest.sha256` | the run's fingerprint |
| `policyDigest.sha256` | SHA-256 of `rule.json`; the approval receipt names the same digest |
| `conclusion` | what the recorder draws: the rule needs an approval for this call, and the call was approved before it ran |
| `seq` | the stated order: run, approval, action |
| `conventions` | the repository, commit and status of the conventions above |

The record carries no trace id, span id, conversation id, tool call id, agent name, argument or result in clear,
and no other identifier that would link it to records of other domains: the trace and call identifiers appear only
salted, with a salt per kind. `check_example.py` holds the record to closed field sets (case F13) and, with the
disclosure, searches the record for each of those values in clear (case F14D).

The anchoring: the statement's payload is the SHA-256 of the record's payload bytes, in an RFC 9995 hash envelope
(label 258 = -16) signed with ES256, with CWT Claims and the signer's certificate in the protected header. The
test service puts its CCF data-hash into a leaf of a four-leaf tree and signs the root in a receipt with vds 2
and an inclusion proof, the payload detached. Statement and receipt together are the Transparent Statement.

## What a reader checks offline, what stays open

Without the disclosure, `check_example.py out` checks, and ends in OPEN when all of it holds:

- K1: the record's signature under the pinned recorder key.
- K2: its form: an in-toto Statement v1 in RFC 8785 form with closed field sets, the conventions pinned.
- K3: every fingerprint and reference is sha256-salted-v1; the approval is marked as not standardized.
- K4: approval and action carry the same call reference (as a fingerprint); the stated order is run, approval,
  action.
- A1: the receipt under the pinned service key, the statement under the pinned statement key, and that the
  statement's payload is the digest of exactly this record.

**Open without a disclosure:** that the fingerprints belong to the real spans and the real approval, that the
content is true, and recomputing the rule. That is OPEN, not passed and not failed, in the sense of
`SCORE_WITHHELD` in `proofbundle.evalclaim`: a commitment is present, the value behind it is withheld.
A fingerprint that is an unsalted SHA-256 but claims sha256-salted-v1 also stays open here (case F02); only the
disclosure shows it (case F03).

With `--disclosure`, the check adds D1 to D6 (salts of at least 16 bytes, the spans after the conventions and of
one agent and one conversation, the fingerprints recomputed, the approval receipt with its link and time, the rule
recomputed, no identifier in clear) and ends in PASSED when all of it holds. The approval must name the call's
tool, the tool's URI, the call's agent, a tool call as the kind of action and an authorization before the action
as the kind of decision. Its signature covers the arguments only through their digest, so an approval for another
tool with the same arguments would otherwise pass (cases F25 to F29).

**Never checkable through the record:** that the recording is complete, and that the action really ran as the
spans say. The record repeats what the recorder was given.

## Choices this example makes

- A salt per kind of value (run, approval, action, call, trace), so disclosing one fingerprint's salt does not
  open the others. The salts here derive from public labels so the example is reproducible; anyone who knows a
  salt can test guesses against its fingerprint, so a real issuer draws them at random and keeps them.
- The record is our own predicate type for this example, not a registered one, and not a standard.
- The rule is one line of JSON: a transfer above a threshold needs an approval before it runs. `check_example.py`
  recomputes it over the disclosed spans.
- The test service is not CCF: it runs no consensus, no trusted execution and no registration policy. It writes
  the bytes a relying party checks, in the shape the reader in `src/proofbundle/scitt_ccf.py` takes.
- Nothing in `src/` changes. The producer of signed statements lives in this example only; making one part of
  proofbundle would be a change of its own.

MIT, like the rest of this repository.

Assisted by little helpers.
