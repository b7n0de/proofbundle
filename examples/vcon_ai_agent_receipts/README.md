# Decision receipts in a vCon for an AI agent session

A worked example for three Internet-Drafts, the AI agent extension of vCon
([draft-birkholz-vcon-ai-agent-extension-00](https://www.ietf.org/archive/id/draft-birkholz-vcon-ai-agent-extension-00.txt)),
vCon core ([draft-ietf-vcon-vcon-core-05](https://www.ietf.org/archive/id/draft-ietf-vcon-vcon-core-05.txt)) and
decision receipts (draft-gruszka-audit-decision-receipts-06). A synthetic Claude Code-style transcript, written for this example, is converted into a vCon.
The producer constructs an approval record from the person's dialog response and signs one ALLOW and one DENY
decision receipt, both attached to the vCon. This demonstrates receipt binding and offline verification, not
live host enforcement. The vCon is signed in the JWS form
of vCon core, once with EdDSA and once with RS256, and in the COSE_Sign1 envelope of Appendix B of the
ai_agent draft, all over the same payload bytes, and a later receipt cites the signed record by digest.
Everything is checked offline, and each receipt is verified with proofbundle (https://proofbundle.dev).

## Files

| File | What it is |
|---|---|
| `sample_session.jsonl` | A short transcript in the line format of Claude Code, written for this example. |
| `claude_jsonl_to_vcon.py` | Converts one transcript into an unsigned vCon with the ai_agent extension, following Appendices C and D of the draft. Standard library only; its docstring lists the mapping and what it does not carry. |
| `make_example.py` | The producer. Runs the converter, adds the gate, the approval record and the receipts, signs the vCon and writes `out/`. Deterministic, because the test keys are derived from public labels. |
| `check_example.py` | The offline check of `out/` (or of any folder with the same files). |
| `measure_cases.py` | Builds 20 failure cases and three passing variants from the example and runs the check twice on each. |
| `cases.md` | The output of `measure_cases.py`. |
| `vcon_profile.py` | Helpers shared by the scripts, for strict JSON, RFC 8785, a small deterministic CBOR codec, COSE_Sign1, JWS with EdDSA and RS256, and the RSA test key derived from its label. |
| `out/` | The files `make_example.py` writes, as produced. |
| `SHA256SUMS` | The SHA-256 of every file above. |

In `out/`, `vcon.converted.json` and `conversion-report.json` are the converter's output for the sample;
`vcon.unsigned.json` is the vCon with the gate party and the attachments; `vcon.payload.json` holds the bytes
all signatures cover, the RFC 8785 serialization of that vCon; `vcon.signed.json` (EdDSA) and
`vcon.signed-rs256.json` (RS256) are the JWS forms and `vcon.cose` the COSE_Sign1 form; `receipts/` and
`external/` hold the decision receipts; `approval-record.json` the approval record; `recorder-test-cert.der`,
`recorder-rs256-test-cert.der` and `test-keys.json` the test certificates and the key labels.

## Check it offline

```
pip install "proofbundle==6.4.0"
cd examples/vcon_ai_agent_receipts
python check_example.py out
python check_example.py out --signed vcon.signed-rs256.json
python measure_cases.py
```

`check_example.py` exits 0 only when every check passes, and names the first failure otherwise. It pins the gate public key and the SHA-256 digests of the recorder's two test certificates in the
script. It reads recorder public keys from certificates in the supplied signed forms only after checking their
DER hashes against those pins; it does not trust an unpinned supplied key. Each decision receipt is also
verified with `proofbundle decision verify --strict`.

## How the pieces bind

| In the decision receipt | In the vCon |
|---|---|
| `traceContext.traceId` | `agent_session_id` of the Session Object |
| `traceContext.parentId` | `call_id` of the tool-call Event Object |
| `proposedAction.parametersDigest` | SHA-256 of the RFC 8785 serialization of the tool call's `input` |
| `agent.id`, `principal.id` | `uuid` of the agent party and of the person |
| approval record `approvalId`, `approver`, `session`, `approvedAt` | `entry_id`, contributing party, session and time of the person's answer in the dialog |
| verification time | time of the tool result with the same `call_id` |

A receipt is an Attachment Object, inline (`encoding` json) or referenced by `url` and `content_hash`. The
`content_hash` carries a SHA-512 token over the receipt file, as vCon core requires, and a SHA-256 token over
the same bytes. The receipt's own identity, SHA-256 over its signed payload, follows from those bytes.

The citing receipt names the conversation record twice, by SHA-256 of the payload all signatures cover, which
is also the `jcs-sha256-v1` value and the `content-hash` of the COSE trace-metadata, and by SHA-256 of the
COSE_Sign1 bytes. The first survives re-serialization of the signed form; the second pins one signature.

## Choices the drafts leave open

The example had to pick one reading at each of these places; `cases.md` holds a case for most of them.

- Event Objects carry `sessions`, as `event_common_type` in the vCon core CDDL does. The prose and
  Appendix D of the ai_agent draft use `session`; the CDDL of both drafts taken together rejects the
  Appendix D example for that member alone and accepts it with `sessions`.
- The `time` of a tool call is when the agent emitted it; the gate decides after that.
- The action bytes of a tool call are the RFC 8785 serialization of its `input`.
- A `content_hash` must carry a `sha512` token.
- `approvedAt` is the time the answer was sent, its `start` plus its `duration`.
- A tool result after a DENY counts as executed unless `is_error` is true or `status` is "error".
- `trace-format` is "ietf-vac-v3.0" for a vCon payload, with content type "application/vcon".
- The JWS form is shown with EdDSA, whose test key derives from a label like the others, and with RS256,
  which vCon core recommends.

## What the example does not show

The receipts are the gate's own statements. The approval record is written by the gate, not signed by the
person, and the recorder's signature on the vCon does not authenticate the person either. Nothing is registered
with a transparency service. The transcript was written for this example, the repository and pull request are
example values, and every key is a test key whose private half anyone can derive from its label; never use
them for real records.

`claude_jsonl_to_vcon.py` drops host metadata lines, subagent lines and lines without a timestamp, and counts
them in its report. A transcript can still hold anything that was typed or read in the session; review the
output before you publish it.

MIT, like the rest of this repository.

Assisted by little helpers.
