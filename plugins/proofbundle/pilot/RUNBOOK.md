# Runbook: the pilot of Z405 at delta

How the operator runs the first pilot of decision and outcome receipts (docs/pilot/pilot_contract.md, profile
github-write/1) with the plugin's gate, and how a person who was not part of the sessions reruns its reconciliation
from the records alone (criterion 4). The decisions behind it are DECISIONS.md D55 to D57 and D58. This runbook names
keys and places, never a value: no key, no token and no path of a real machine stands here.

## Who runs what

| role | runs as | holds | writes |
|---|---|---|---|
| gate (decider) | the agent session's user, as a hook of Claude Code or Codex | no key | `decisions/` and `journal.jsonl` in the records |
| signer service (D58) | an account of the operator, not the agent session's user | the gate's Ed25519 key and its own copy of the plugin | its own journal; it answers a signature or a refusal |
| observer | an account of the operator, not the agent session's user | the observer's Ed25519 key, and a read token only if the operator wants one | `api/` and `outcomes/` in the records |
| reconciliation | anyone, from a copy of the records | nothing but the records | `reconciliation/` in its copy |

The gate runs inside the agent session, under the agent's user. A key that user can read can sign anything, so the
gate holds none: it hands the call and the statement it proposes to the program `pilot.json` names, the signer service
(owner choice O405-1 of 2026-10-17, D58). The service runs under the signer account, which alone reads the gate key,
and decides the call again with its own copy of the gate file, whose sha256 pilot_start.json keeps. It signs only where
its own verdict, reasons, action and statement are the proposal's, byte for byte, and decidedAt lies in its window;
otherwise it signs nothing and names why, by a fixed name, in its journal and in the gate's (`signer_refused_<name>`).
The agent can call the service too, and gets a signature only for what the service's copy of the gate decides so.

What it cannot close: the service decides the state it sees when it runs. If the agent changes the working tree, the
configuration or the evidence between the gate's verdict and the service's decision, the service decides on the new
state. Whether the host then runs exactly the call a receipt names is what the observer catches: other bytes (M2),
another surface (M3), a write without an approval (M5), a refused write that arrived (M6).

## What the operator sets up, before the first decision

1. Two Ed25519 key pairs, one for the gate signer and one for the observer, each private key readable only by its own
   account. Names used below: the gate key and the observer key; their public halves as 64 hex digits.
2. The signer service (D58), in place before the pilot starts at delta:
   - a signer account of the operator, not the agent's user;
   - a copy of this plugin's folder (hooks/, pilot/, server/) owned by the signer account and not writable by the
     agent's user; its `hooks/proofbundle_gate.py` must be the same bytes as the agent's;
   - the gate key as 64 hex digits in a key file only the signer account reads (mode 600);
   - the service's configuration, in a folder only the signer account reads:

     ```
     {"schema": "proofbundle/pilot-signer-config/v1", "gate_file": "<the copy>/hooks/proofbundle_gate.py",
      "records": "<records folder>", "gate_dir": "<the gate directory of step 7>", "key_file": "<key file>",
      "journal": "<the service's journal file>", "environment": {"PATH": "<the signer account's PATH>",
      "HOME": "<the signer account's home>"}, "window_seconds": <seconds>}
     ```

     `environment` is the whole environment the service decides in: values of the signer account, never one of the
     agent's session. `window_seconds` is how old a decidedAt may be when the service reads it; the gate sets it
     just before it calls the service, so a few seconds suffice (the tests use 10);
   - read access for the signer account to every repository the agents work in, to the gate directory and to the
     records, and its own uv cache for the verifier the gate runs on an approval; what it cannot read gets no
     signature (workdir_unreadable, pilot_config_unread), never a guessed one;
   - each of those repositories as `safe.directory` in the git configuration the service's `environment` names
     (GIT_CONFIG_GLOBAL): git refuses a repository another account owns without it, and a push decided there gets no
     signature (repository_not_safe);
   - the crossing, a sudo rule that lets the agent's user run exactly this one command as the signer account and
     nothing else:

     ```
     <agent user> ALL=(<signer account>) NOPASSWD: <python> -I <the copy>/pilot/signer_service.py --config <configuration>
     ```

     and `"signer": ["<sudo, by its absolute path>", "-n", "-u", "<signer account>", "<python>", "-I",
     "<the copy>/pilot/signer_service.py", "--config", "<configuration>"]` in pilot.json; the gate reads no pilot.json
     whose signer program is not an absolute path. A socket of the signer account is the other crossing D58 allows;
     this plugin ships no client for it.
   - the public key for step 6: `signer_service.py --config <configuration> --public`, run as the signer account.

   `probe_signer.py` in this folder signs whatever it is handed, with a key derived from a public label; it is for
   tests only, never for the pilot.
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
     --gate <the service's copy of hooks/proofbundle_gate.py> \
     --verifier <the proofbundle distribution file the reconciliation runs with> \
     --environment <the interpreter version and every installed distribution with version and digest> \
     --gate-id <the gate's name> --observer-id <the observer's name>
   ```

   The verifier must be a proofbundle whose decision verifier takes `now=`, as on main since pull request 303: a
   published version, 6.3.1 or later, and until one is published the wheel built from main's src (O405-3). The
   contract and the profile are byte-identical copies of main's files, without pilot_profile.md (O405-4). The gate
   file is the one the service checks before every signature.
7. `pilot.json` in the gate directory of the agent's machine (beside `mode`, D25; the model does not write it):

   ```
   {"profile": "github-write/1", "gate_id": "<the gate's name>", "observer_id": "<the observer's name>",
    "agent_id": "<the agent's name>", "principal_id": "<the operator's name>", "validity_seconds": <seconds>,
    "receipts": "<records folder>", "signer": ["<the signer program>", "<its arguments>"],
    "public_key": "<gate public key, hex>", "closing_rules": "<records folder>/closing_rules.json"}
   ```

   The closing rules are named in the records, so the digest each receipt names is the digest of the kept file.
8. The pilot repositories declare a check, and each has the Level 2 hook (`install-pre-push`, D24B) (O405-5), so a
   push is decided with its ref lines and its receipt names the commit it sends.

## The owner's choices for the first pilot (2026-10-17, 02:2x Berlin)

- O405-1: the signer is a service under an account of the operator, decides from the hook event with the same gate
  file and signs only its own verdict; it is in place before the start at delta (step 2, D58).
- O405-2: criterion 1 of the contract counts only for git.push in the first pilot; the other four surfaces are covered
  by M5 and M6.
- O405-3: the verifier is a published proofbundle with `now=`, 6.3.1 or later; until then the wheel from main's src.
- O405-4: the contract and the profile are byte-identical copies of main, without pilot_profile.md.
- O405-5: the pilot repositories declare a check and have Level 2.

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

- A receipt proves that the service's copy of the gate decided the call so, on the state the service saw when it
  ran (above); not that the host ran exactly that call.
- Time (D58, N405-b): at Level 1 the gate's 90 s and the service's 10 s stay within the hook's 120 s; at Level 2 each
  ref line is one call of the service, and git sets no limit. A service slower than 10 s is stopped and the call gets
  no receipt (`signer_timeout` in the journal).
- The events API lists at most 300 events and 90 days; a write it does not list is not counted. "None found" in M5 and
  M6 is bounded by what it returned (contract, section 7).
- A write the gate does not read gets no receipt (D55); if it arrives it counts under M5, which is how it is found.
- Asked calls are recorded as ESCALATE: the gate does not see the person's answer in the dialog, so an asked write
  that a person allowed counts under M5 as a write without an approval of the gate.
