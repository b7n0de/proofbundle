# A recorded session in a vCon, with the receipts the guard signed in it

Part 2 of the vCon example. Part 1, in the folder above, converts a synthetic transcript and signs its receipts with
test keys. This folder takes a real session instead. On 4 November 2026 a coding agent (Claude Code 2.1.318) ran in a
demonstration account behind the proofbundle guard plugin of this repository at commit
7eb0013e3af050d0cde776feb2c3abacbcb6f646. It made two calls that the guard gates. The guard signed a decision receipt
for each with its demonstration key, and the transcript of the session was kept.

- Case 1. The agent posts a comment on a pull request of the public demonstration repository
  https://github.com/b7n0de/proofbundle-guard-vcon-demo. The guard escalates, the person approves in the dialog, the
  comment is posted. Receipt verdict ESCALATE.
- Case 2. The agent tries `git push origin --delete main`, which the person had asked it to try. The guard denies.
  Receipt verdict DENY.

`make_real_session.py` builds one unsigned vCon from the transcript and the two receipts, with the converter of part 1
and nothing else. `check_real_session.py` checks it offline and verifies each receipt with proofbundle
(https://proofbundle.dev).

## What the record shows

After case 1 the agent wrote in the session that the guard had produced no ESCALATE for its call. The receipt the
guard signed when it decided says ESCALATE, and it verifies. The agent had read the guard's note to the agent, which
for this call begins with "NOT MEASURED", not the decision. Both stand in the vCon, the note as a system-event of the
guard next to the policy-decision, so a reader sees what the agent was told next to what the guard signed.

The note is a finding against the guard (GF-E001, for plugin 0.4.1). The decision and its receipt are right: the
verdict is ESCALATE, and the receipt verifies with `proofbundle decision verify --strict`. This difference only came to
light because a record was made when the decision was taken and could be read afterwards, apart from the agent's own
account.

## Files

| File | What it is |
|---|---|
| `session.jsonl` | 12 lines derived from the transcript of the session, unchanged since the recording (see below). |
| `receipts/` | The two decision receipts the guard signed, as it wrote them. |
| `gate.pub.hex` | The public half of the guard's demonstration key, in hex as the session wrote it. Pinned by its SHA-256 in `check_real_session.py`. |
| `make_real_session.py` | The producer. Deterministic; it changes no input file. |
| `check_real_session.py` | The offline check, K1 to K4, and the observation K5. |
| `out/vcon.unsigned.json` | The vCon the producer writes. |
| `out/conversion-report.json` | What the converter converted and what it left out, and which call each receipt names. |
| `SHA256SUMS` | The SHA-256 of every file in this folder. |

## Check it offline

```
pip install "proofbundle>=6.4.0"
cd examples/vcon_ai_agent_receipts/real_session
python make_real_session.py
python check_real_session.py
```

The check exits 0 only when K1 to K4 pass, names the first failure otherwise, and prints the observation K5.

| Check | What it holds |
|---|---|
| K1 | each receipt verifies with `proofbundle decision verify --strict` against the pinned demonstration key, for the audience the guard wrote, at the first whole second after its `decidedAt` |
| K2 | `traceContext.traceId` is the session's `agent_session_id`, and `traceContext.parentId`, the tool_use id, names one policy-decision through the operation_id the converter derives from it |
| K3 | the policy-decision fits the verdict, ESCALATE `permission-required` and DENY `disallowed`, and `agent`, `principal` and `decisionMaker` are the parties of the vCon |
| K4 | for ESCALATE the call stands once, after its decision, and `parametersDigest` is the SHA-256 of the `--body` argument of its `gh` command, read with shlex in POSIX mode; for DENY no tool event of the operation stands in the vCon, and no JSON value in it equals the denied arguments |
| K5 | an observation, not a pass or fail: what the guard's note to the agent begins with, next to the verdict it signed |

`tests/test_vcon_real_session_example.py` holds that `out/` is what the producer writes, that the check passes, and that
each of K1 to K4 fails on a change aimed at it.

## How it differs from part 1

- The receipts are the guard's own, signed in the session with its demonstration key. Part 1 signs its receipts with test
  keys derived from public labels.
- The verdicts are ESCALATE and DENY. Part 1 has ALLOW and DENY.
- `traceContext.parentId` is the tool_use id of the call, as the guard writes it. Part 1 writes the operation_id there.
- For case 1, `parametersDigest` covers the comment text the call posts, not the RFC 8785 form of the tool arguments.
- The DENY receipt names the arguments by `parametersRef` `urn:proofbundle:pilot:not-resolved`, because the guard did
  not resolve the push. With no digest, a copy of the arguments cannot be searched for by digest, as in part 1. K4
  compares the JSON values of the vCon with the arguments in the transcript instead.
- The vCon is not signed. The point of this folder is the receipts and their binding to the record.

## What the transcript does not hold

The transcript has no permission decision of its own. The producer hands each receipt's verdict to the converter as
the permission decision of its call, in memory: ESCALATE as the person's acceptance, because the call ran after the
person approved it in the dialog, and DENY as a rejection. The approval itself is not in the transcript, and the
receipt does not cover it. The person confirmed it afterwards.

`session.jsonl` holds the user and assistant lines with their text, tool use and tool result blocks, and the guard's
hook messages. Left out of the original transcript are whole lines of other kinds and, in the lines kept, every other
field, among them the model, usage, the working directory, the version and message ids. Claude Code writes the
signed-in account's mail address, the full system prompt and the account's connectors into such lines.

## What the example does not show

It is one session with one guard and one person. The demonstration key signs for the guard in this account only, and
the vCon records the guard's statements, not that the person approved. The person asked for the push in case 2, so the
dialog names the command; tool-invocation-00 keeps the arguments of a disallowed call out of its Event Objects, and
the converter writes neither the call nor its result. The comment of case 1 names the person by first name; it is
public on the demonstration repository, and the receipt covers exactly its bytes.

MIT, like the rest of this repository.

Assisted by little helpers.
