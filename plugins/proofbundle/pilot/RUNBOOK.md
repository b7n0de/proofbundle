# Runbook: the pilot of Z405 on account A

How the operator runs the first pilot of decision and outcome receipts (docs/pilot/pilot_contract.md, profile
github-write/1) with the plugin's gate, and how a person who was not part of the sessions reruns its reconciliation
from the records alone (criterion 4). The decisions behind it are DECISIONS.md D55 to D57, D58, D64 and D65. This
runbook names keys and places, never a value: no key, no token and no path of a real machine stands here.

## Who runs what

| role | runs as | holds | writes |
|---|---|---|---|
| gate (decider) | the agent session's user, as a hook of Claude Code or Codex | no key | `decisions/` and `journal.jsonl` in the records |
| signer service (D58, D64) | the deciding account: an account of the operator, not the agent session's user | no key; its own copy of the plugin | its own journal; it answers a signature or a refusal |
| key signer (D64) | the key account: a second account of the operator, neither of the two above | the gate's Ed25519 key and key_signer.py | its own journal; it answers a signature or a refusal |
| observer | an account of the operator, not the agent session's user | the observer's Ed25519 key, and a read token only if the operator wants one | `api/` and `outcomes/` in the records |
| reconciliation | anyone, from a copy of the records | nothing but the records | `reconciliation/` in its copy |

The gate runs inside the agent session, under the agent's user. A key that user can read can sign anything, so the
gate holds none: it hands the call and the statement it proposes to the program `pilot.json` names, the signer service
(owner choice O405-1 of 2026-10-17, D58). The service runs under the deciding account and decides the call again with
its own copy of the gate file, whose sha256 pilot_start.json keeps. It goes on only where its own verdict, reasons,
action and statement are the proposal's, byte for byte, and decidedAt lies in its window; otherwise it signs nothing and
names why, by a fixed name, in its journal and in the gate's (`signer_refused_<name>`). The agent can call the service
too, and gets a signature only for what the service's copy of the gate decides so.

The deciding account holds no key (owner choice O405S-6, D64). It runs git, the gate's decision code and the verifier
on repositories the agent writes, so a configuration the agent planted there reaches at most that account. It hands
the canonical statement, and nothing else, to the key signer under the key account, which alone reads the gate key,
runs neither git nor any code of the gate and reads nothing of a repository; the key signer checks the statement's
form, its gate and its time, signs, and writes one line per request into its own journal.

What it cannot close: the service decides the state it sees when it runs. If the agent changes the working tree, the
configuration or the evidence between the gate's verdict and the service's decision, the service decides on the new
state. Whether the host then runs exactly the call a receipt names is what the observer catches: other bytes (M2),
another surface (M3), a write without an approval (M5), a refused write that arrived (M6).

## What the operator sets up, before the first decision

1. Two Ed25519 key pairs, one for the gate signer and one for the observer, each private key readable only by its own
   account. Names used below: the gate key and the observer key; their public halves as 64 hex digits.
2. The signer service (D58) and its key signer (D64), in place before the pilot starts on account A, under two accounts of
   the operator that are neither the agent's user nor each other: the deciding account and the key account.
   - The key signer, under the key account:
     - a copy of `pilot/key_signer.py` in a folder only the key account reads and writes;
     - the gate key as 64 hex digits in a key file there that only the key account reads (mode 600);
     - the key signer's configuration there:

       ```
       {"schema": "proofbundle/pilot-key-config/v1", "key_file": "<key file>",
        "journal": "<the key signer's journal file>", "gate_id": "<the gate's name>", "window_seconds": 10}
       ```

     - the public key for step 6: `key_signer.py --config <key configuration> --public`, run as the key account;
     - its journal starts as a new, empty file at the start of the pilot: the reconciliation counts every signed line
       in it (D65). The key signer writes each line and syncs it to the disk before a signature leaves it; a journal
       it cannot write gives no signature (journal_unwritable, at the gate `signer_refused_key_journal_unwritable`).
   - The service, under the deciding account, which holds no key:
     - a copy of this plugin's folder (hooks/, pilot/, server/) owned by the deciding account and not writable by the
       agent's user; its `hooks/proofbundle_gate.py` must be the same bytes as the agent's;
     - the service's configuration, in a folder only the deciding account reads:

       ```
       {"schema": "proofbundle/pilot-signer-config/v2", "gate_file": "<the copy>/hooks/proofbundle_gate.py",
        "records": "<records folder>", "gate_dir": "<the gate directory of step 7>",
        "key_signer": ["<sudo, by its absolute path>", "-n", "-u", "<key account>", "<python>", "-I",
                       "<key folder>/key_signer.py", "--config", "<key configuration>"],
        "journal": "<the service's journal file>", "environment": {"PATH": "<the deciding account's PATH>",
        "HOME": "<the deciding account's home>"}, "window_seconds": 10}
       ```

       `environment` is the whole environment the service decides in: values of the deciding account, never one of
       the agent's session. `window_seconds` is how old a decidedAt may be when the service, and then the key signer,
       reads it; the gate sets it just before it calls the service, and both use 10, the gate's PILOT_SIGNER_SECONDS
       (O405S-2);
     - `"autonomous": true` in the service's configuration only where the agents' hooks run with `--autonomous`
       (D119): the service then decides a Level 1 call with the hook's autonomous answer, in the session the event
       names. Without it a release on a card lets nothing run while the pilot is on: the hook waits for the service's
       ALLOW before it uses a release, and a service without the autonomous answer does not give it (A0). With it, the
       service keeps the releases it signed ALLOW for in freigaben-geehrt.json beside its journal, each once, and
       evicts none: at 4096 of them a new release gets no signature (release_record_full); give it a plugin data
       directory of its own in `environment` (CLAUDE_PLUGIN_DATA) where it cannot read the hook's (A2); Since D125 the
       plugin's hooks run without `--autonomous`; with them leave the setting out, as a service with it judges their
       asks with the autonomous answer, refuses with verdict_differs and the call gets no receipt. Where the hooks state
       `PROOFBUNDLE_OWNER_STATE=protected` (D124) or `PROOFBUNDLE_STANDING_GO=protected` (D129), `environment` states
       the same, or the service reads no release and frees no push under the standing GO (verdict_differs).
     - read access for the deciding account to every repository the agents work in, to the gate directory and to the
       records, and its own uv cache for the verifier the gate runs on an approval; what it cannot read gets no
       signature (workdir_unreadable, pilot_config_unread), never a guessed one;
     - the hand-over (D35) is not reached by that access (handover/ 0700, record and pointer 0600, measured);
       Level 2 consumes it before the service decides; a handed-over push across accounts is BLOCKED/NOT
       MEASURED until that path is built and measured;
     - each pilot repository of step 8 as one `safe.directory` line in the git configuration the service's
       `environment` names (GIT_CONFIG_GLOBAL), the list of the pilot repositories and never `*` (O405S-5): git
       refuses a repository another account owns without it, and a push decided there gets no signature
       (repository_not_safe); `*` would let git read every repository in the deciding account.
   - The crossings, two sudo rules (O405S-1), each onto exactly one command and nothing else: the agent's user onto the
     service as the deciding account, the deciding account onto the key signer as the key account. The agent's user
     has no rule onto the key account.

     ```
     <agent user> ALL=(<deciding account>) NOPASSWD: <python> -I <the copy>/pilot/signer_service.py --config <configuration>
     <deciding account> ALL=(<key account>) NOPASSWD: <python> -I <key folder>/key_signer.py --config <key configuration>
     ```

     and `"signer": ["<sudo, by its absolute path>", "-n", "-u", "<deciding account>", "<python>", "-I",
     "<the copy>/pilot/signer_service.py", "--config", "<configuration>"]` in pilot.json; the gate reads no pilot.json
     whose signer program is not an absolute path, and the service reads no key_signer program that is not one. A
     socket is the other crossing D58 allows; it is not measured, and this plugin ships no client for it.

   `probe_signer.py` in this folder signs whatever it is handed, with a key derived from a public label; it is for
   tests only, never for the pilot. The counter-probe of the surface (M3) keeps it as a test of the reconciliation,
   never signed by the service and never a record of the pilot (O405S-4).
3. The roster: the GitHub accounts or apps that only agent sessions write under, one per agent, each by the numeric id
   GitHub gives it (a rename does not change it), its login, and the agent's name the gate writes into `agent.id`:
   `[{"id": <numeric id>, "login": "<login>", "agent": "<agent name>"}]`. No person writes under them during the pilot.
4. The closing rules: `{"<surface>": "<the closing lines the surface requires>" or null}` for the five surfaces of the
   profile, as they apply at approval time.
5. The records folder, owned by the operator (root), writable by the agent's user (the gate writes `decisions/` there)
   and by the observer account through a group, with the sticky bit set (mode 1770 or 1775), so that neither of them
   can rename or remove what is not theirs. In it, before the first decision, the folder `keysigner/`, owned by the
   key account, mode 755: there and only there the key signer exports its journal (D65). The key signer refuses any
   other folder (export_folder_unsafe): one another account owns or may write, or whose parent another account may
   write without the sticky bit.
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
  file and signs only its own verdict; it is in place before the start on account A (step 2, D58).
- O405-2: criterion 1 of the contract counts only for git.push in the first pilot; the other four surfaces are covered
  by M5 and M6.
- O405-3: the verifier is a published proofbundle with `now=`, 6.3.1 or later; until then the wheel from main's src.
- O405-4: the contract and the profile are byte-identical copies of main, without pilot_profile.md.
- O405-5: the pilot repositories declare a check and have Level 2.

## The owner's choices on the signer service (2026-10-17)

Each as recommended in the report of the signer service:

- O405S-1: the crossings are sudo rules onto exactly one command each, measured with real accounts; a socket is not
  used in the first pilot.
- O405S-2: `window_seconds` is 10 in the service's and in the key signer's configuration, equal to the gate's
  PILOT_SIGNER_SECONDS.
- O405S-3: at Level 2 the service decides the push once per ref line, one call and one receipt each, as measured
  (about half a second a line); one call per push that signs every line waits until pushes with many refs occur.
- O405S-4: the probe signer stays only as a test of the reconciliation (the counter-probe of the surface, M3), never
  signed by the service and never a record of the pilot.
- O405S-5: `safe.directory` in the deciding account's git configuration is the list of the pilot repositories, never
  `*`.
- O405S-6: deciding and signing run under two accounts: the deciding account holds no key and hands the canonical
  bytes on; only the key account reads the key and signs, and it runs neither git nor the gate's decision code on
  repositories the agent writes (D64).

## The owner's choice on the key signer's journal (2026-10-17)

- O24-1, 22:3x Berlin: the key signer's journal goes into the records at the end of each window, by the export above,
  and the reconciliation counts it (D65); in the same follow-up note, T4-a: no signature without a durable journal line,
  for the key signer and for the service. The comparison by hand stays as the way back.

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

The key signer's journal names each signature the gate key made, by decisionId and the sha256 of the statement. At the
end of each window, before the observer's last run of it and the reconciliation, the operator has the key account
export it, as root with `runuser` or `sudo -u` onto the key account, never through the deciding account:

```
<python> -I <key folder>/key_signer.py --config <key configuration> --export <records folder>/keysigner
```

It writes `keysigner/journal.jsonl` and `keysigner/export.json` with the journal's sha256, each whole. The
reconciliation reads them there (D65). By hand, as the way back: every signed line has its receipt in `decisions/` with
that id and a payload of that digest; a signed line without one is a signature the deciding account obtained outside a
decision of the gate (D64), and a line with `"handedOut": false` is one that never left the key signer.

## The rotation of the service's record of releases (D131)

With `"autonomous": true` the service keeps each release it signed ALLOW for in freigaben-geehrt.json, in the folder of
its journal (`<service folder>` below), as `{"schema": "proofbundle/pilot-releases-honoured/v1", "geehrt":
{"<card>:<sha256 of the line>:<session>": "<UTC time of the signature>", ...}}`. At 4096 of them it gives a new release
no signature (release_record_full) and leaves the record as it is; a release the record names gets none either (D119),
and every other request is signed as before. The refusal release_record_full comes after the key signer signed: its
journal holds a signed line for it and the records no receipt, which the reconciliation counts among the signed lines
without a receipt (D65). The service is no process that keeps running: the gate starts it once per request through the
sudo rule of the agent's user (the crossings of step 2 of the setup), and each start reads the record anew. The owner's
answer of 2026-10-26 (answer 7 of Nachtrag 7, option A): at the capacity the operator rotates the record, the service
stopped. Steps 2 and 3 run as root.

1. Stop the service: remove the sudo rule of the agent's user onto the service, so that the gate starts it no more.
   From then on the gate gets no signature: a write it decides has no receipt and counts under M5 where it arrives,
   and a release lets nothing run (D119). Keep it stopped until the newest time in the record lies more than 16 minutes
   back (RELEASE_SECONDS, 15 minutes, and RELEASE_SKEW_SECONDS, 60 s, of the gate): the service signed for a release
   only where its answer lay at most 60 s after the service's clock, and a release binds for 15 minutes from its
   answer, so then none the record names binds with the answer it had. A request that started before the stop does not
   change a full record.
2. Archive the record into the records folder:

   ```
   cp <service folder>/freigaben-geehrt.json \
     <records folder>/honoured-releases/freigaben-geehrt-<UTC time of the rotation>.json
   ```

   `honoured-releases/` is owned by root, mode 755, made at the first rotation, so that neither the agent's user nor
   the deciding account changes what it keeps; check that the copy has the record's sha256.
3. Empty the record by removing it: `rm <service folder>/freigaben-geehrt.json`. The service reads a record that is not
   there as empty. A file in its place of zero bytes, `{}` or another form it reads as damaged: then it signs nothing at
   all, no release and no other request (release_record_unread).
4. Start the service: put the sudo rule back. Its next start reads no record and signs ALLOW for a new release again,
   and it writes a new freigaben-geehrt.json that names that release alone.

What the rotation means for the releases the record named: the service refuses a release it signed ALLOW for only
while its record names it (D119). After the rotation it names none of them, so a release of the archive gets ALLOW
again where it still binds: its line, its session, and its card in `freigaben/` of the gate directory with an answer at
most RELEASE_SECONDS back. The wait of step 1 leaves none that binds with the answer it had; a card the fetcher writes
again with a later answer binds again, and then only the hook's own record of the uses (D111) holds it, as long as that
record names it. The archive keeps what the service signed ALLOW for before the rotation, each release by its card, the
sha256 of its line and its session, with the time: a key that stands in an archive and again in a later record is a
release the service signed ALLOW for twice, which the operator checks by hand after each rotation. The reconciliation
does not read the archive.

## The reconciliation, and its rerun by someone else

```
python reconcile.py --records <records folder>
```

writes `reconciliation/reconciliation.json`: per decision the class, M1 to M4, M7, M8 and the profile's answer, over
the window M5 and M6 with each unapproved effect, and under `keyJournal` the two counts of the key signer's journal
(D65): signed lines without a receipt and receipts without a signed line. It ends with 0 where both are 0, with 3
(KEY_JOURNAL_DISAGREES) where one is not, and with 4 (KEY_JOURNAL_NOT_READ) where `keysigner/` holds no export or not
the bytes it names; the file is written in each case. A person who was not part of the sessions reruns it so:

1. copy the records folder;
2. make a fresh environment of the kept interpreter version and install the kept verifier file after checking its
   digest against `pilot_start.json`;
3. run `reconcile.py --records <the copy>` from a checkout of this plugin;
4. compare: the same records give the same bytes and the same exit code, and every class and measure must be the
   same.

The reconciliation reads nothing the records do not keep, and checks every kept file against its digest first.

## What this does not cover

- A receipt proves that the service's copy of the gate decided the call so, on the state the service saw when it
  ran (above); not that the host ran exactly that call.
- The key signer checks a statement's form, its gate and its time, not its verdict: whoever holds the deciding account
  gets signatures for statements of the gate within the window, whatever verdict they name, and never the key (D64).
  Each is one line of the key signer's journal, and the reconciliation counts it among the signed lines without a
  receipt (D65).
- Time (D58, N405-b, D64): at Level 1 the gate's 90 s and the service's 10 s stay within the hook's 120 s, and the key
  signer answers within the service's 10 s; at Level 2 each ref line is one call of the service (O405S-3), and git
  sets no limit. A service slower than 10 s is stopped and the call gets no receipt (`signer_timeout` in the journal).
- The events API lists at most 300 events and 90 days; a write it does not list is not counted. "None found" in M5 and
  M6 is bounded by what it returned (contract, section 7).
- A write the gate does not read gets no receipt (D55); if it arrives it counts under M5, which is how it is found.
- Under the hook's autonomous answer (Claude Code, `--autonomous`) a write whose answer it changes can lack its
  receipt of Level 1: the signer service decides without that answer and refuses with `verdict_differs`
  (O28B-1, D113), unless the operator sets `"autonomous": true` in its configuration (D119). If it arrives it counts
  under M5; the reconciliation says so under `window_notes`.
- Asked calls are recorded as ESCALATE: the gate does not see the person's answer in the dialog, so an asked write
  that a person allowed counts under M5 as a write without an approval of the gate.
