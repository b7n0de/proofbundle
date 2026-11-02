# proofbundle plugin: target and actual state per host (stage M0)

Each row identifies a property, its actual state, a revision and the measurement behind it. A harness runs recorded
events or requests; a host measurement runs the real host. This table preserves the historical measurements cited in its
rows. A VERIFIED row applies only to the revision and environment named in that row; it is not a VERIFIED result for a
later gate. The earlier delivery used gate blob 1c4b7810 at edfb9ace. The Guard Preview stack reviewed on 2026-10-26 has
tree 229062a870ef002c8ad1fccba08100bc684abf69 and gate blob e3300f49. The harness results of that stack are those of the
supplied Guard Preview measurement package; they are not results for a later gate, whose harness results are those of
the tests at its own commit. Clean installation, update, removal and operation with real models at this stack are NOT
MEASURED. The external D28 host runs remain historical observations, including rows G-CC-5 and G-CX-3. Follow-up note 48
adds the owner answers O45-1 to O45-3 as decided and the triage of PRODUCT_SPEC.md.

## Claude Code

### Verify

| ID | Target | Actual | Status | Commit | Measurement |
|---|---|---|---|---|---|
| V-CC-1 | the plugin loads in a real Claude Code session | its hooks ran in `claude -p --plugin-dir` with a real model | VERIFIED | not named in D28 | host runs of 2026-10-08, Claude Code 2.1.294 (DECISIONS.md D28) |
| V-CC-2 | the plugin's MCP server is loaded in a real session and its tools are listed | in the house's real run the plugin's MCP server was not loaded; the cause is not known | FAILED | not recorded in this repository | house measurement RAUCH-03, as stated in follow-up note 45 |
| V-CC-3 | `verify_receipt` reports the package's own verdict and exit code | the server answers with exactly one text element holding the package's JSON result; `proofbundle_version` 6.3.0, `verified` true for a fresh receipt | VERIFIED (harness, no host) | edfb9ace | `uv run --script` of the server as the gate starts it (PLUGIN_N45, messung/server_vertrag_630.jsonl); tests/test_claude_code_plugin.py with the test interpreter |
| V-CC-4 | a request found inside a receipt is reported as data and not followed | evals `review-receipt-injection`, `verify-inspect-injection` exist; their graders read text features only | NOT MEASURED | n/a | no eval run with a real model is recorded here |
| V-CC-5 | `emit` signs only after the user confirms | eval `emit-shows-before-signing` exists | NOT MEASURED | n/a | no eval run with a real model is recorded here |

### Guard

| ID | Target | Actual | Status | Commit | Measurement |
|---|---|---|---|---|---|
| G-CC-1 | the hooks are registered under Claude Code | `hooks/hooks.json` registers every hook, the gate always with `--autonomous` | VERIFIED | edfb9ace | the manifest at the head; house measurement in the real run |
| G-CC-2 | if the gate cannot run, the Bash call does not run | the hook command exits 2 with its own line when the gate command fails; Python itself exits 2 when it cannot open the gate | VERIFIED | edfb9ace (hooks.json); D28 | D28 (measured); house measurement |
| G-CC-3 | the pre-push gate answers as DECISIONS.md says | corpus 1698 rows, satz_v1 held 30 of 30 and harmless 0 of 28, fallbook 288 rows: the same answers as at 49219d5c | VERIFIED (harness) | edfb9ace | PLUGIN_N45 acceptance |
| G-CC-4 | the same in a real host | the gate of PLUGIN_N37 ran on account A | VERIFIED (one host, one run set) | 63b88d07 | house measurement, as stated in follow-up note 45 |
| G-CC-5 | the done check holds a session until the required receipts verify | valid work ends at the first stop; missing, foreign, stale, manipulated and red receipts block | VERIFIED (host, real model) | not named in D28 | host runs of 2026-10-08, Claude Code 2.1.294 (D28) |
| G-CC-6 | the autonomous answer (D85 to D111) | tests and fallbook at the head | VERIFIED (harness) | edfb9ace | test files of the chain; fallbook (PLUGIN_N45) |
| G-CC-7 | the release of an owner (D111) frees a command once | a session can remove the record of uses through `python3 -c`, then the gate frees the same release again | FAILED | 49219d5c (gate 7584d4b9) | PLUGIN_N44, point 1, case 7; named in the limits of D111 (O44-2) |
| G-CC-8 | the Read and Grep hook denies a read of a key file | tests of D102 at the head | VERIFIED (harness) | edfb9ace | tests/test_plugin_n33_secret_paths_d102.py |
| G-CC-9 | a gated MCP write of another server (a GitHub MCP server) is checked in a real host | matcher in `hooks/hooks.json`, tests in the harness | NOT MEASURED in a host | edfb9ace | harness only |
| G-CC-10 | every GitHub write the pilot reads gets a Level 1 receipt | under the autonomous answer a write whose answer it changes gets none (verdict_differs) | FAILED (named in D113) | d5e0720f | PLUGIN_N43, point 1; PLUGIN_N44, point 1 |
| G-CC-11 | the signer service reads the hook's records across accounts (precondition of A1) | the hooks write both records with mode 0600; no other account reads them; with the files written 0640 and a setgid group the service reads them (V6, a copy, not delivered) | FAILED (as delivered), VERIFIED (V6 copy), both in the container | 49219d5c; edfb9ace for the V6 script | PLUGIN_N44, point 2; the script v6_farmer_n45.py run in the container (PLUGIN_N45) |
| G-CC-12 | the same on the operator's machine | not run | BLOCKED until the owner runs v6_farmer_n45.py on the operator's machine | n/a | n/a |
| G-CC-13 | the pilot runs on the operator's machine with three accounts | not started | NOT MEASURED | n/a | n/a |
| G-CC-14 | the signer service decides a handed-over push as the hook's Level 2 did, across accounts | the hand-over is written with handover/ 0700 and its record and pointer 0600, which another account does not read; Level 2 consumes it before the service decides | BLOCKED/NOT MEASURED | n/a | the writer modes measured in the container on 3.12 and 3.14 for P-2 of the external review of 2026-10-26; the consumption before the service read in the code, not measured |

## Codex

### Verify

| ID | Target | Actual | Status | Commit | Measurement |
|---|---|---|---|---|---|
| V-CX-1 | the plugin loads in Codex with a real model | not run | NOT MEASURED; BLOCKED until the run at the owner's machine (D16); Codex Verify counts for M1 only after that run (O45-2) | n/a | n/a |
| V-CX-2 | the server, the skills and the manifest Codex reads | tests/test_codex_plugin.py | VERIFIED (harness) | edfb9ace | test files at the head |
| V-CX-3 | every `verify_receipt` result under Codex says the server cannot see whether the hooks run | `gate_note` in the result | VERIFIED (harness) | edfb9ace | tests/test_codex_plugin.py |
| V-CX-4 | `emit_receipt` under Codex | the plugin data directory is not in the environment Codex hands the server, so `key_path` is needed | NOT MEASURED in a host (documented in the README) | n/a | n/a |

### Guard

| ID | Target | Actual | Status | Commit | Measurement |
|---|---|---|---|---|---|
| G-CX-1 | the gate answers under `--host codex` against Codex's hook schema | tests and fallbook under both hosts | VERIFIED (harness) | edfb9ace | tests/test_codex_plugin.py; fallbook (PLUGIN_N45) |
| G-CX-2 | the gate runs inside a Codex turn with a real model | not run | NOT MEASURED; BLOCKED until TG-5 (O45-2) | n/a | n/a |
| G-CX-3 | hooks run only after the user trusts them, and then block | Codex 0.161.0 with a scripted local model loads the Stop hook, runs it after trust, inserts a block in the same turn | VERIFIED (host, scripted model) | not named in D28 | host runs of 2026-10-08 (D28) |
| G-CX-4 | a plain `git push` under Codex is denied | it warns and is not denied (owner choice Karte 5 A with D) | INACTIVE | edfb9ace | README, D12 |
| G-CX-5 | no autonomous answer under Codex | `.codex-plugin/plugin.json` starts the gate with `--host codex`, without `--autonomous` | VERIFIED | edfb9ace | the manifest at the head |

## Profiles and life cycle, both hosts

| ID | Target | Actual | Status | Commit | Measurement |
|---|---|---|---|---|---|
| P-1 | house profile: Guard on, `strict`, autonomous answer under Claude Code | the one manifest set that ships | VERIFIED | edfb9ace | the manifests at the head |
| P-2 | delivery profile with the Guard off until M2, decided by the owner (O45-3) | no such setting exists | INACTIVE | n/a | n/a |
| P-3 | an observing Guard that logs and never denies or asks | not built; only on the owner's request, and then built and measured (O45-3) | INACTIVE | n/a | n/a |
| L-1 | clean install from the marketplace, per host | not run in a recorded measurement | NOT MEASURED | n/a | n/a |
| L-2 | update from one plugin version to the next, per host | not run | NOT MEASURED | n/a | n/a |
| L-3 | removal, per host, and what stays behind (data folder, keys, gate directory) | the README describes Claude Code's behaviour (`--keep-data`); not run | NOT MEASURED | n/a | n/a |
| L-4 | the pinned package | `proofbundle==6.3.0` in the server and the gate | VERIFIED | edfb9ace | the pin commit and server_vertrag_630.jsonl |
