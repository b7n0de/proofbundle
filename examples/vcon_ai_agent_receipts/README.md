# Decision receipts in a vCon for an AI agent session

A worked example for the tool-invocation extension of vCon
([draft-petrie-vcon-tool-invocation-00](https://www.ietf.org/archive/id/draft-petrie-vcon-tool-invocation-00.txt)),
vCon core ([draft-ietf-vcon-vcon-core-05](https://www.ietf.org/archive/id/draft-ietf-vcon-vcon-core-05.txt)) and
decision receipts (draft-gruszka-audit-decision-receipts-06). A synthetic Claude Code-style transcript, written for
this example, is converted into a vCon: each tool use is an operation with a policy-decision Event Object, and an
operation that is not disallowed also gets its tool-invocation and tool-result Event Objects, all linked by an
operation_id. What tool-invocation-00 does not define, such as the agent's model and the session id of the agent,
comes from the AI agent extension
([draft-birkholz-vcon-ai-agent-extension-00](https://www.ietf.org/archive/id/draft-birkholz-vcon-ai-agent-extension-00.txt)).

The producer constructs an approval record from the person's dialog response and signs one ALLOW and one DENY
decision receipt, both attached to the vCon. This demonstrates receipt binding and offline verification, not
live host enforcement. The vCon is signed in the JWS form of vCon core, once with EdDSA and once with RS256, and
in the COSE_Sign1 envelope of Appendix B of the ai_agent draft, all over the same payload bytes, and a later
receipt cites the signed record by digest. Everything is checked offline, and each receipt is verified with
proofbundle (https://proofbundle.dev).

## Files

| File | What it is |
|---|---|
| `sample_session.jsonl` | A short transcript in the line format of Claude Code, written for this example. |
| `claude_jsonl_to_vcon.py` | Converts one transcript into an unsigned vCon with the tool-invocation extension. Standard library only; its docstring lists the mapping and what it does not carry. |
| `make_example.py` | The producer. Runs the converter, adds the gate, the approval record and the receipts, signs the vCon and writes `out/`. Deterministic, because the test keys are derived from public labels. |
| `check_example.py` | The offline check of `out/` (or of any folder with the same files). |
| `measure_cases.py` | Builds 62 failure cases and four passing variants from the example and runs the check twice on each. |
| `cases.md` | The output of `measure_cases.py`. |
| `vcon_profile.py` | Helpers shared by the scripts, for strict JSON, RFC 8785, a small deterministic CBOR codec, COSE_Sign1, JWS with EdDSA and RS256, and the RSA test key derived from its label. |
| `proposal_decision_receipt.cddl` | Our proposal, one parameter for the `$$event-policy-decision-ext` socket of tool-invocation-00. Not part of any draft. |
| `out/` | The files `make_example.py` writes, as produced. |
| `SHA256SUMS` | The SHA-256 of every file above. |

In `out/`, `vcon.converted.json` and `conversion-report.json` are the converter's output for the sample;
`vcon.unsigned.json` is the vCon with the gate party and the attachments; `vcon.payload.json` holds the bytes
all signatures cover, the RFC 8785 serialization of that vCon; `vcon.signed.json` (EdDSA) and
`vcon.signed-rs256.json` (RS256) are the JWS forms and `vcon.cose` the COSE_Sign1 form; `receipts/` and
`external/` hold the decision receipts; `approval-record.json` the approval record; `recorder-test-cert.der`,
`recorder-rs256-test-cert.der` and `test-keys.json` the test certificates and the key labels.
`proposal/vcon.with-receipt-reference.unsigned.json` is the same vCon with the proposed parameter on each
policy-decision, and nothing else changed.

## Check it offline

```
pip install "proofbundle>=6.4.0"
cd examples/vcon_ai_agent_receipts
python check_example.py out
python check_example.py out --signed vcon.signed-rs256.json
python check_example.py out --proposal proposal/vcon.with-receipt-reference.unsigned.json
python measure_cases.py
```

`check_example.py` exits 0 only when every check passes, and names the first failure otherwise. It pins the gate
public key and the SHA-256 digests of the recorder's two test certificates in the script. It reads recorder public
keys from certificates in the supplied signed forms only after checking their DER hashes against those pins; it
does not trust an unpinned supplied key. Each decision receipt is also verified with
`proofbundle decision verify --strict`.

## How the pieces bind

| In the decision receipt | In the vCon |
|---|---|
| `traceContext.traceId` | `agent_session_id` of the Session Object |
| `traceContext.parentId` | `operation_id` of the policy-decision of the operation, and of its tool-invocation |
| `decision.verdict` ALLOW | policy-decision `permission-required` when a person approved, `allowed` otherwise |
| `decision.verdict` DENY | policy-decision `disallowed`, and no tool event with that `operation_id` |
| `proposedAction.parametersDigest` | SHA-256 of the RFC 8785 serialization of the tool-invocation's JSON content; for a disallowed operation the arguments are not in the vCon (tool-invocation-00 6.1.1), and the digest stands in the receipt alone |
| `agent.id`, `principal.id` | `uuid` of the party of the policy-decision, the agent, and of the person |
| approval record `approvalId`, `approver`, `session`, `approvedAt` | `entry_id`, contributing party, session and time of the person's answer in the dialog |
| verification time | time of the first tool-result, tool-failure, tool-error or tool-denied of the attempt its policy-decision precedes; an invoked operation without one, and a response without a tool-invocation of its attempt, are refused |

A receipt is an Attachment Object, inline (`encoding` json) or referenced by `url` and `content_hash`. The
`content_hash` carries a SHA-512 token over the receipt file, as vCon core requires, and a SHA-256 token over
the same bytes. The receipt's own identity, SHA-256 over its signed payload, follows from those bytes.
A policy-decision may carry neither content nor attachment (Table 3 of tool-invocation-00), so in the vCon the
link runs from the receipt to the event, by operation_id.

The citing receipt names the conversation record twice, by SHA-256 of the payload all signatures cover, which
is also the `jcs-sha256-v1` value and the `content-hash` of the COSE trace-metadata, and by SHA-256 of the
COSE_Sign1 bytes. The first survives re-serialization of the signed form; the second pins one signature.

## Our proposal

The link from the event to its receipt is the one place tool-invocation-00 leaves to another extension: its CDDL
ends each policy-decision with the socket `$$event-policy-decision-ext`. `proposal_decision_receipt.cddl` adds one
parameter there, `decision_receipt`, an object of `content_hash`, `url` where the receipt is held outside the vCon,
and `mediatype`. It is our proposal, not part of any draft. It uses neither content nor attachment, so Table 3 is
kept, and the core vCon and tool-invocation-00 are not changed. For a disallowed invocation the referenced
receipt binds the digest of the proposed arguments without putting them into the vCon. `check_example.py
--proposal` checks that the file is the signed vCon plus this parameter and nothing else, and that each
reference holds the SHA-512 of the receipt of that operation.

## What comes from which draft

The vCon lists `"tool-invocation"` and `"ai_agent"` in `extensions`. tool-invocation-00 gives the policy-decision,
tool-invocation, tool-result and tool-failure Event Objects with operation_id, attempt, server `!host` and tool.
From the ai_agent draft come only the parts tool-invocation-00 does not define:

- `agent_meta` of the agent party, with the model; tool-invocation-00 names the agent only by its party index.
- `agent_session_id`, `environment` and `format` of the Session Object; the receipt's `traceId` names the
  session by `agent_session_id`.
- `model_id`, `token_usage`, `entry_id` and `parent_id` of Dialog Objects; the approval record names the
  person's answer by its `entry_id`.
- the `reasoning` and `system-event` Event Objects with `entry_id` and `parent_id`, for thinking blocks and system
  lines, which tool-invocation-00 does not cover.
- `recording_agent` and `vcs` of the vCon.

The tool-call and tool-result Event Objects of the ai_agent draft and its permission-decision system-event are
no longer used; the Event Objects of tool-invocation-00 replace them, and they carry no entry_id.

## Choices the drafts leave open

The example had to pick one reading at each of these places; `cases.md` holds a case for most of them.

- Event Objects carry `sessions`, as `event_common_type` in the vCon core CDDL does.
- The push follows Figure 1 of tool-invocation-00: the policy-decision `permission-required` when the agent asks,
  then the person's "Approved." in a Dialog Object, then the gate's receipt, then the tool-invocation. Permission
  events are not defined yet (Section 7), so the grant is the Dialog Object that the approval record names, and
  the receipt links grant and decision by operation_id. The check holds the order policy-decision, approvedAt,
  decidedAt, tool-invocation.
- The policy-decision carries the time of the transcript's tool_use line. The transcript has no time of its own
  for sending the request; a request that waited for a grant carries the time of the tool result's line, the
  latest time at which it was sent. The DENY receipt's `decidedAt` is the time of its policy-decision.
- The converter assigns the operation_id, derived from the session id and the tool_use id; every operation has
  attempt 1. The tools of Claude Code are provided by the host, so `server` is `!host`.
- A disallowed operation's tool result in the transcript is the host's refusal, not a response of the tool, and no
  tool event is written. Its text is not carried as the `reason` either: it is free text and can repeat the proposed
  arguments, which a disallowed operation must not record.
- The invocation and the results the check binds to a receipt are those of the attempt its policy-decision
  precedes, and every tool event of the operation names the agent party of that decision. After a DENY no tool
  event of the operation may stand anywhere in the vCon, in any session, as an operation_id names one operation.
- The action bytes of a tool-invocation are the RFC 8785 serialization of its JSON content.
- Every decision for one operation is named by a receipt, every event of an operation names the same agent
  party, and a decision precedes the attempt it names, for every operation of the vCon.
- No tool event may follow a disallowed policy-decision, whether or not a receipt names the operation.
- Standing decisions are not part of this profile and are refused: the example has none, and how a tool's and a
  server's standing decisions combine is open in Section 4.1. Every operation has a decision of its own.
- Every event of an operation stands in the session of its receipt.
- Tool arguments are JSON objects: the converter refuses other input of a tool_use, and the check refuses a
  tool-invocation whose JSON content is not an object, so a copy of denied arguments is always a JSON object.
- Every attempt of an operation has the arguments its receipt names, and event content has the types of the core
  CDDL (a media type, a body that decodes in its encoding, a non-empty content_hash with a sha512 token); the
  bytes of external tool content are not fetched. Every result of an attempt comes at or after its tool-invocation.
- The check refuses a vCon in which a JSON value with the SHA-256 of a denied operation's arguments appears
  anywhere: as a value, as JSON text, inside other text, in an object key, or in a body in the base64url encoding of
  vCon core, decoded as UTF-8, UTF-16 or UTF-32 and searched again, up to eight nested layers, deeper nesting refused.
  The converter drops a text or thinking block that holds those arguments as JSON and refuses a transcript whose
  output would still hold them. A paraphrase, or a copy in a representation vCon core does not define (hex,
  compression), cannot be found from a digest and is outside what the check claims.
- This checker validates the complete synthetic example profile. It is not a general validator for every
  observation permitted by tool-invocation-00.
- Every attempt of an approved operation lies between the approval and its `validUntil`, and after the receipt's
  `decidedAt`; attempts start at 1 and go up by one.
- Redacted content is `content_hash` alone, as in the core CDDL; an `encoding` without a `body` is refused. A
  parameter that none of the drafts used here defines is refused, which is stricter than the sockets of
  Appendix D allow.
- A `content_hash` must carry a `sha512` token.
- `approvedAt` is the time the answer was sent, its `start` plus its `duration`.
- `trace-format` is "ietf-vac-v3.0" for a vCon payload, with content type "application/vcon".
- The JWS form is shown with EdDSA, whose test key derives from a label like the others, and with RS256,
  which vCon core recommends.

## What the example does not show

The receipts are the gate's own statements. The approval record is written by the gate, not signed by the
person, and the recorder's signature on the vCon does not authenticate the person either. Permission requests and
responses are not defined yet (Section 7 of tool-invocation-00); the approval stands in the dialog. Nothing is
registered with a transparency service. The transcript was written for this example, the repository and pull
request are example values, and every key is a test key whose private half anyone can derive from its label;
never use them for real records.

`claude_jsonl_to_vcon.py` drops host metadata lines, subagent lines and lines without a timestamp, and counts
them in its report. A transcript can still hold anything that was typed or read in the session; review the
output before you publish it.

MIT, like the rest of this repository.

Assisted by little helpers.
