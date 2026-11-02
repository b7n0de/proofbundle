# proofbundle plugin: product specification (stage M0)

Stage M0 is this text, written, nothing built. It says what the plugin is meant to be, in two areas that are released
separately, under two profiles. What is built and measured today, row by row, stands in
[IMPLEMENTATION_GAP.md](IMPLEMENTATION_GAP.md); how each property is to be measured, and the acceptance for M1, in
[TEST_PLAN.md](TEST_PLAN.md). Owner decision of 2026-10-20: Verify and Guard in one plugin, released
separately; two profiles; stages M0 to M4. Decided by the owner on 2026-10-20 (O45-1 to O45-3): the name
stays proofbundle, the first released version is 0.4.0 with M1, and there is no 1.0 before M3; the host matrix of M1
stands in TEST_PLAN.md; the delivery profile ships with the Guard off.

## One plugin, two areas

One plugin folder serves both hosts, Claude Code (`.claude-plugin/plugin.json`, `hooks/hooks.json`, `.mcp.json`) and
Codex (`.codex-plugin/plugin.json`), over the same skills, MCP server and gate. It holds two areas. Each area has its
own status, its own release decision and its own acceptance; one area can be released while the other is not.

### Verify

Reads and checks what was recorded. It changes nothing in a repository and makes no decision about an agent's call.

| Function | Where | What it does |
|---|---|---|
| Verify a receipt or a bundle | skill `verify`, tool `verify_receipt` | runs `proofbundle decision verify`, `proofbundle outcome verify` or `proofbundle verify` of the pinned package and reports its exit code, its meaning and its full output |
| Separate proof from record | skill `review-receipt` | verifies first, then says what the signature proves and what the issuer only recorded |
| Read a receipt without verifying | tool `inspect_receipt` | `proofbundle decision inspect` or `outcome inspect`, marked as not verified |
| Make a receipt (experimental) | skill `emit`, tools `receipt_template`, `emit_receipt` | fills a template with facts the user gives, shows it, signs only after the user confirms, verifies the result; runs only when the user invokes it |

What a passing verification proves: the holder of the given key signed exactly these bytes, and they have not changed
since. What it does not prove: that any recorded value is true. Every verdict and exit code is the package's own; the
plugin pins one version (`proofbundle==6.3.0` since follow-up note 45) and derives no verdict of its own.

### Guard

Decides about an agent's calls before they run, and about the end of a session.

| Function | Where | What it does |
|---|---|---|
| Pre-push gate | `PreToolUse` on Bash and on six MCP write tools, `hooks/proofbundle_gate.py` | For recognized git push, gh pr create and gh release create forms under Claude Code, checks the declared evidence. An explicitly enabled house autonomous adapter can change a base ask into a deny or apply its scoped standing work-branch authorization. The public Guard default omits the combined autonomous flag and grants no such standing authorization. Under Codex, a plain git push warns without a permission decision; other recognized push forms and gated gh writes are denied as context-unbound. Gated MCP writes ask under Claude Code and are denied under Codex because their target is not bound. An installed git pre-push hook performs a separate check. These are separate paths, not universal prevention of writes. |
| Configuration and hook writes | `PreToolUse` on the file tools | Recognized file-tool writes to repository configuration, hooks or included configuration receive a base ask under Claude Code and a deny under Codex. An explicitly enabled house Claude Code autonomous adapter denies these writes; the public base path retains its ask. Interpreter-carried and unresolved shell writes are not covered by that statement. |
| Key files | `PreToolUse` on Read and Grep, `hooks/proofbundle_secrets.py` | a read of a key file, a credential store or a folder of keys is denied; paths only, no file opened |
| Done check | `Stop` and `TaskCompleted` | where the declaration names a done check, the session ends or a task completes only with one verifying, passing receipt per required check for the commit and tree at hand; after three blocks without progress it writes `.proofbundle/done-blocker.json` and lets the session end without a done verdict |
| Autonomous answer | `--autonomous` (Claude Code) | an ask becomes a block with a verified rewrite hint, except the closed list of external effects (D85), with the cards of the work profile (D93) and the owner's release on a card (D111, only with PROOFBUNDLE_OWNER_STATE=protected, D124); the standing GO for the own work branch (D87) applies only where the hook's environment also sets PROOFBUNDLE_STANDING_GO=protected (D129). Both settings are the house's statement, not a protection. |
| Modes | `mode`, `rules.json` in the gate directory | strict is the default; with-approvals reads rules from the gate directory. The gate reads mode and rules.json only where the hook's environment sets PROOFBUNDLE_OWNER_STATE to `protected` (D124); without it the mode is strict and no rule frees. D25 reserves these settings to a person, but the gate does not enforce that boundary: the supplied probe changes mode through a relative shell write, and a gate whose hook environment carries that setting then reads with-approvals. The setting is the house's statement, not a protection. File-tool and literal-target denials do not protect all writes by the session. |
| Counts and log | `PostToolUse`, `proofbundle_answered.py`, the gate log, `bilanz` | answers per reason, open pull requests per session (D94, D110), one line per decision |
| Diagnosis | skill `selftest`, tools `gate_status`, `gate_selftest_prepare`, `gate_selftest_check` | says whether the gate ran in this session and hands out a push the gate should deny, in a throwaway repository |
| Pilot receipts (optional, experimental) | `pilot.json` in the gate directory, `pilot/` | attempts a signed decision receipt for a GitHub write the pilot recognizes, through the operator's signer, and reconciles issued receipts with recorded observations; receipt and observation coverage are not complete, and cross-account operation is BLOCKED/NOT MEASURED as listed in IMPLEMENTATION_GAP.md |

If the gate cannot run, the Bash hook blocks every call (`|| exit 2` in `hooks/hooks.json`, D6). The local gate is an
early warning; the boundary is the required CI check and git's pre-push hook where it is installed (D22, D24).

## Two profiles

| Profile | Who | Verify | Guard |
|---|---|---|---|
| House profile | the owner's own machines and sessions | on | on, `strict`, the autonomous answer under Claude Code, as today |
| Delivery profile | anyone the plugin is handed to | on | off (INACTIVE) until M2, decided by the owner (O45-3); observing only on the owner's request, and only once it is built and measured |

Observing means: the gate runs and logs what it would answer, and never denies or asks. A Guard that is off, only
observes, does not run, or that the host does not trust (Codex runs hooks only after the user trusts them, D16) is no
protection, and no text may present it as one.

Verify-only installation does not register Guard hooks. The public Guard Preview configuration registers its hooks separately and starts the base decision path without the combined --autonomous flag. The house configuration may explicitly enable autonomous adaptation, but standing authorization for work-branch pushes is not a public default and requires a separate owner-controlled choice. This does not implement the observing profile; that profile remains INACTIVE until built and measured.

## Stages

| Stage | Content |
|---|---|
| M0 | this specification, IMPLEMENTATION_GAP.md and TEST_PLAN.md, written; nothing built |
| M1 | the acceptance in TEST_PLAN.md, per host and area, measured in real hosts, with a clean install, an update and a removal; the first released version, 0.4.0 (O45-1) |
| M2 | Guard Preview; until M2 the Guard of the delivery profile stays off (O45-3) |
| M3 | Durchsetzung beim Empfänger (enforcement at the receiving side); only from here may a text call a property enforced, where the protection at the receiving side is measured (Non-claims); no version 1.0 before M3 (O45-1) |
| M4 | Piloten außerhalb des Hauses (pilots outside the house) |

The names of M2 to M4 are those of the decision of 2026-10-20; what a stage holds beyond its name and the lines above
is the owner's decision, and this text claims nothing more.

## Triage on every plugin card

The decision of 2026-10-20 (the owner's decision record,
section „Triage auf jeder Plugin-Karte“), word for word, as the owner handed it over in follow-up note 51 (O48-1):

<!-- proofbundle:verbatim-quote:begin -->
> Jede Karte zu einem Fund am Plugin beantwortet vier Fragen.
>
> 1. Trifft der Fund eine zugesagte Eigenschaft von Verify? Dann hält er die Freigabe von Verify an.
> 2. Trifft er nur einen Guard-Pfad, der im Auslieferungsprofil nicht aktiv ist? Dann hält er die Reifeaussage des Guard
>    an, nicht Verify.
> 3. Wirkt er über gemeinsamen Kern oder Paketierung auf Verify? Dann reicht die Trennung nicht, und der ganze betroffene
>    Stand wird geprüft.
> 4. Eine unbekannte Folge heißt NICHT GEMESSEN, keine Entwarnung.
<!-- proofbundle:verbatim-quote:end -->

Every finding in IMPLEMENTATION_GAP.md and every failed row of TEST_PLAN.md is triaged by these four questions before
it is called a block of Verify, of the Guard, or of both.

## Status of a property

Every property in these texts carries exactly one of these, and only on the evidence named beside it.

| Status | Meaning |
|---|---|
| VERIFIED | measured, with the commit and the measurement named, and it holds |
| FAILED | measured, and it does not hold |
| NOT MEASURED | nothing measured; no claim either way |
| BLOCKED | cannot be measured until a named precondition is met |
| REQUIRES APPROVAL | waits for a decision of the owner |
| INACTIVE | not built, switched off, not running, or not trusted by the host; never counted as protection |

A measurement in a test harness (the hook started as a process with a recorded event) and a measurement in a real host
with a real model are different measurements and are named as such.

## Non-claims

No text of the plugin, its README, its manifests, its skills or its reports may say any of the following.

- That the plugin makes an agent fulfil its task.
- That every unauthorized push is prevented.
- That all MCP write actions are controlled.
- That anything is tamper-proof.
- That a signed result is true, or that a valid receipt means a task is done.
- That `safe_for_automation: true` is an approval; it is a precondition for an automatic follow-up action that is
  already authorized.
- That something is completely checked where the evals are synthetic only.
- That something is enforced where no protection at the receiving side is measured.
- Any seal of the kind "agent secured".
- That a Guard that is off, observing only, or not running, or that the host does not trust, protects anything
  (checklist no. 10 of 2026-10-20, quoted below).

<!-- proofbundle:verbatim-quote:begin -->
„Ein Guard, der aus ist, nicht läuft oder dem der Wirt nicht vertraut, als Schutz.“
<!-- proofbundle:verbatim-quote:end -->
