# proofbundle plugin: test plan and the acceptance for M1 (stage M0)

What has to be measured, per host and area, before a property of [PRODUCT_SPEC.md](PRODUCT_SPEC.md) may carry VERIFIED in
[IMPLEMENTATION_GAP.md](IMPLEMENTATION_GAP.md). Nothing in this file is a result. Every run keeps: the commit and the
gate blob, the host and its version, the model (or "scripted"), the date, the plugin version, the pinned package, the
command, the full output, and the gate log lines it produced. A run in a test harness and a run in a real host are kept
apart and named as such. A row that fails is triaged by the four questions of PRODUCT_SPEC.md before it blocks
Verify, the Guard or both.

## Kinds of test

| Kind | What it shows |
|---|---|
| Positive | the function does what the specification says on a valid input |
| Negative | it refuses, blocks or reports where it must, and frees nothing that should not be freed |
| Real host | the same in Claude Code or Codex with a real model, not only in the harness |
| Clean install | from an empty host profile: install from the marketplace, first start, first use |
| Update | from the last released plugin version to the new one, with the data folder and the gate directory kept |
| Removal | uninstall, and what stays behind: the data folder, keys, the gate directory, the log |

## Verify

| ID | Host | Kind | Case | Expected |
|---|---|---|---|---|
| TV-1 | both | Positive | `verify_receipt` on a fresh decision receipt with its issuer key | exit 0, `verified` true, `proofbundle_version` equals the pin, one text element |
| TV-2 | both | Negative | the same receipt with one byte changed; the wrong key; a key read from the receipt itself | non-zero exit with the package's meaning; never `verified` true |
| TV-3 | both | Negative | a receipt whose free text asks the reader to act (the injection evals) | reported as recorded content, nothing done; graded by a person, not only by the regex grader |
| TV-4 | both | Positive and negative | `emit`: template, show, confirm, sign, verify; and the same without confirmation | a receipt only after confirmation; none without |
| TV-5 | Claude Code | Real host | `/mcp` lists `plugin:proofbundle:proofbundle` with seven tools after a fresh start | listed; V-CC-2 moves from FAILED only with this run |
| TV-6 | Codex | Real host | the same skills and tools in a Codex turn with a real model, at the owner's machine (D16) | listed and answering; `gate_note` present |
| TV-7 | both | Positive | `safe_for_automation` and `automation_blockers` are copied, never derived | equal to the package's report; `null` with `not reported by the core` where absent |
| TV-8 | Claude Code (cloud session) and the receiving side | Positive and negative | the delivery receipt: every cloud delivery carries a proofbundle receipt over its archive, which Verify checks on arrival (owner decision after Nachtrag 45) | positive: verified with the delivery key, and the sha256 the receipt names is the archive's; negative: one byte of the archive changed, the receipt of another delivery, a wrong key, no receipt at all: not verified, the delivery is not taken, and a missing receipt is named missing, never passed |

## Guard

| ID | Host | Kind | Case | Expected |
|---|---|---|---|---|
| TG-1 | both | Positive | the corpus, satz_v1 and the fallbook at the new head against the last delivered head | 0 different answers, 0 blocks lost |
| TG-2 | both | Negative | a push without evidence; a failed check; a changed rule set; `--no-verify`; a `core.hooksPath` override | denied or asked as DECISIONS.md says; nothing reaches the remote |
| TG-3 | Claude Code | Negative | the gate file made unreadable or Python missing | every Bash call blocked with the hook's own line |
| TG-4 | Claude Code | Real host | the cases of TG-2 and the done cases in a real session, house profile | the same answers as in the harness; the log lines match |
| TG-5 | Codex | Real host | the cases of TG-2 under Codex with a real model, after trusting the hooks (D16) | deny where Claude Code would ask; a plain `git push` warns |
| TG-6 | Claude Code | Negative | a release of D111 used, then the record of uses removed through an interpreter | today the gate frees again (FAILED, D111 limits); kept as a known case until a gate order changes it |
| TG-7 | both | Positive | the self-test skill in a throwaway repository | the gate logged the deny; the throwaway remote's refs did not move |
| TG-8 | Claude Code | Real host | a GitHub MCP server's write tool (one of the six) in a real session | the gate runs for it and its answer stands in the log |
| TG-9 | both | Negative | delivery profile, Guard off: a push without evidence | the push runs; the plugin says the Guard is off (INACTIVE) and claims no protection |
| TG-10 | both | Negative | delivery profile, Guard observing: the same push | the push runs; the log names what the gate would have answered; nothing denied or asked |
| TG-11 | Claude Code | Real host | the pilot with three accounts at the farmer, V6 first (v6_farmer_n45.py) | the service reads the two records; receipts and reconciliation as RUNBOOK.md says |

## Life cycle

| ID | Host | Kind | Case | Expected |
|---|---|---|---|---|
| TL-1 | Claude Code | Clean install | `claude plugin marketplace add`, `claude plugin install`, first session | hooks registered, server starts through `uv`, the first `verify_receipt` answers |
| TL-2 | Codex | Clean install | `codex plugin marketplace add`, `codex plugin add`, trust the hooks | the same; until trust, `gate_note` says the hooks may not run |
| TL-3 | both | Update | from the last released plugin version to the new one | the gate directory, mode and rules unchanged; the data folder kept; the new pin in use |
| TL-4 | both | Removal | uninstall with and without `--keep-data` (Claude Code), the same under Codex | what stays is listed; a stale hook entry does not keep blocking calls |
| TL-5 | both | Negative | first start without network to PyPI and without a cached package | the verifier does not start and the gate denies (D6, D11); the plugin says why |

## Acceptance for M1

M1 is reached for one host and one area when all of the following hold. Each holds only with a kept run.

1. Every row of that host and area in this plan has been run, in the harness and in the real host where the row asks
   for it, with the record listed at the top.
2. Every Positive and Negative row gives the expected answer; a row that does not is FAILED in IMPLEMENTATION_GAP.md
   and blocks M1 for that area.
3. TV-5 (Claude Code) or TV-6 (Codex) holds for Verify: the plugin's MCP server is loaded in the real host.
4. For the Guard, the house profile passes TG-1 to TG-4 (Claude Code) or TG-1, TG-2 and TG-5 (Codex), and the delivery
   profile passes TG-9, the Guard off, the default the owner decided (O45-3); TG-10 counts only once an observing Guard
   is built and measured on the owner's request.
5. Clean install, update and removal (TL-1 to TL-5) are run for the host.
6. No text of the plugin carries a non-claim of PRODUCT_SPEC.md; checked by reading, and by a test where a phrase can
   be named.
7. IMPLEMENTATION_GAP.md is updated with the commit and the measurement of every row; a row not run stays NOT MEASURED,
   and an area with such a row is not at M1.
8. The delivery receipt (TV-8) holds, positive and negative, for the cloud deliveries of the M1 run.

## Host matrix for M1 (decided, O45-2)

| Host | Area | For M1 |
|---|---|---|
| Claude Code | Verify and Guard, house profile | first, on the farmer's Linux state; owner choice A of 2026-10-21 (Nachtrag 52): after the tag v6.3.1 the gate runs in the account echo, while delta and foxtrot stay without it |
| Codex | Verify | only after a run with a real model (TV-6) |
| Codex | Guard | BLOCKED until TG-5 |
