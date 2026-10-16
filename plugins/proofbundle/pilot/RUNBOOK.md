# Runbook: the pilot of Z405 at delta

How the operator runs the first pilot of decision and outcome receipts (docs/pilot/pilot_contract.md, profile
github-write/1) with the plugin's gate, and how a person who was not part of the sessions reruns its reconciliation
from the records alone (criterion 4). The decisions behind it are DECISIONS.md D55 to D57. This runbook names keys and
places, never a value: no key, no token and no path of a real machine stands here.

## Who runs what

| role | runs as | holds | writes |
|---|---|---|---|
| gate (decider) | the agent session's user, as a hook of Claude Code or Codex | no key | `decisions/` and `journal.jsonl` in the records |
| gate signer | an account of the operator, not the agent session's user | the gate's Ed25519 key | nothing; it answers a signature |
| observer | an account of the operator, not the agent session's user | the observer's Ed25519 key, and a read token only if the operator wants one | `api/` and `outcomes/` in the records |
| reconciliation | anyone, from a copy of the records | nothing but the records | `reconciliation/` in its copy |

The gate runs inside the agent session, under the agent's user. A key that user can read can sign anything, so the
gate holds none: it hands the bytes to sign to the program `pilot.json` names. That program must cross into an
account of the operator, for example through a sudo rule that lets the agent's user run exactly that one program as
the signer account, which alone can read the gate key. The agent can call that program too. What a decision receipt
then proves is that the operator's signer signed it, not that the gate decided it; the observer is what catches an
action that did not go as decided: other bytes (M2), another surface (M3), a write without an approval (M5), a refused
write that arrived (M6). Whether the signer should decide by itself before it signs is owner question O405-1 of the
report.

## What the operator sets up, before the first decision

1. Two Ed25519 key pairs, one for the gate signer and one for the observer, each private key readable only by its own
   account. Names used below: the gate key and the observer key; their public halves as 64 hex digits.
2. The gate signer: a program that reads bytes on stdin and writes the 64-byte Ed25519 signature of the gate key in
   base64 on stdout, reachable from the agent's user only as that one program. `probe_signer.py` in this folder has
   that interface with a key derived from a public label; it is for tests, never for the pilot.
3. The roster: the GitHub accounts or apps that only agent sessions write under, one per agent, each by the numeric id
   GitHub gives it (a rename does not change it), its login, and the agent's name the gate writes into `agent.id`:
   `[{"id": <numeric id>, "login": "<login>", "agent": "<agent name>"}]`. No person writes under them during the pilot.
4. The closing rules: `{"<surface>": "<the closing lines the surface requires>" or null}` for the five surfaces of the
   profile, as they apply at approval time.
5. The records folder, writable by the agent's user (the gate writes `decisions/` there) and by the observer account.
6. The records' inputs, kept before the first decision:

   ```
   python pilot_records.py start --records <records folder> \
     --contract <docs/pilot/pilot_contract.md> --profile <tools/pilot/github_write_profile.py> \
     --agents <AGENTS.md> --closing-rules <closing rules file> --roster <roster file> \
     --gate-public <gate public key, hex> --observer-public <observer public key, hex> \
     --verifier <the proofbundle distribution file the reconciliation runs with> \
     --environment <the interpreter version and every installed distribution with version and digest> \
     --gate-id <the gate's name> --observer-id <the observer's name>
   ```

   The verifier must be a proofbundle whose decision verifier takes `now=`, as on main since pull request 303.
7. `pilot.json` in the gate directory of the agent's machine (beside `mode`, D25; the model does not write it):

   ```
   {"profile": "github-write/1", "gate_id": "<the gate's name>", "observer_id": "<the observer's name>",
    "agent_id": "<the agent's name>", "principal_id": "<the operator's name>", "validity_seconds": <seconds>,
    "receipts": "<records folder>", "signer": ["<the signer program>", "<its arguments>"],
    "public_key": "<gate public key, hex>", "closing_rules": "<records folder>/closing_rules.json"}
   ```

   The closing rules are named in the records, so the digest each receipt names is the digest of the kept file.
8. The Level 2 hook (`install-pre-push`, D24B) in each repository the agents push to, so a push is decided with its ref
   lines and its receipt names the commit it sends.

## While the pilot runs

The gate writes a receipt for each GitHub write it decides and reads (D55); `journal.jsonl` names every receipt it could
not write. The observer runs under its own account, as often as the operator chooses, each run over a window that is
kept with it:

```
python observer.py --records <records folder> --run <run name> --repo <owner>/<repo> \
  --start <window start, RFC 3339 UTC> --end <window end> --live --key-file <observer key file>
```

It needs no credential of an agent session: the events of a public repository need none; `--token-file` reads a read
token from the operator's file, never from the environment. Each run keeps every response as GitHub returned it, with
the time it asked, and signs an outcome per effect that takes a decision.

## The reconciliation, and its rerun by someone else

```
python reconcile.py --records <records folder>
```

writes `reconciliation/reconciliation.json`: per decision the class, M1 to M4, M7, M8 and the profile's answer, and over
the window M5 and M6 with each unapproved effect. A person who was not part of the sessions reruns it so:

1. copy the records folder;
2. make a fresh environment of the kept interpreter version and install the kept verifier file after checking its
   digest against `pilot_start.json`;
3. run `reconcile.py --records <the copy>` from a checkout of this plugin;
4. compare: the same records give the same bytes, and every class and measure must be the same.

The reconciliation reads nothing the records do not keep, and checks every kept file against its digest first.

## What this does not cover

- What a receipt proves depends on who can reach the signer (above).
- The events API lists at most 300 events and 90 days; a write it does not list is not counted. "None found" in M5 and
  M6 is bounded by what it returned (contract, section 7).
- A write the gate does not read gets no receipt (D55); if it arrives it counts under M5, which is how it is found.
- Asked calls are recorded as ESCALATE: the gate does not see the person's answer in the dialog, so an asked write
  that a person allowed counts under M5 as a write without an approval of the gate.
