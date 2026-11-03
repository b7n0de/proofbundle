# Release scope of the plugin 0.4.0

This scope covers the first plugin-specific tag and GitHub release, proofbundle--v0.4.0, of the two plugins in this
repository: proofbundle, the public verifier in plugins/proofbundle, and proofbundle-guard, the owner's house Guard in
plugins/proofbundle-guard. It does not release the Python package and does not change the package's existing v0.4.0
tag.

Version 0.4.0 has been available from the public marketplace on main since 2026-10-30. The owner keeps that version
and the default-branch installation commands. The plugin release comes before the package release 6.5.0, in the order
chosen on 2026-10-25.

The public marketplace at the repository root lists proofbundle alone. The Guard is its own house marketplace at
plugins/proofbundle-guard, which the owner's machines add from a checkout; no public catalog lists it. The release
archive holds both plugin folders.

## In

Each pull request that changes plugins/ or .claude-plugin/ before the release commit has its own row, with its
concrete change. The owner chose a manual count for this release. The release commit is main after the pull request
that adds this file. A separate reconciliation in the approval evidence records every landed commit up to the release
commit and checks these rows against the landed changes; this file does not name its own enclosing commit.

| Item | Pull request | What it brings | Branch |
|---|---|---|---|
| PR438 | 438, landed as `3a2a6146` | the verify set: the MCP server, the skills `verify`, `review-receipt` and `emit`, both host manifests at 0.4.0, the receipt fixtures, the marketplace entry, the plugin catalog, the plugin's decision record and README, and `prune plugins` in `MANIFEST.in` | `claude/landung-guard-g1-verify` |
| PR441 | 441, landed as `647ed0a2` | the pre-push gate: the Claude Code hook registration, the gate program at 0.4.0, the read check for key files, the answer counter, the pin state script, the pilot's signer files, the `selftest` skill, the CI template and the Codex runbook | `claude/landung-guard-g2-gate` |
| PR446 | 446, landed as `94e36562` | the Guard's hooks in the Codex manifest, the plugin's eval corpus, the pilot's observer and reconciliation, the design notes, the product specification, the test plan, the implementation gap list and the tests of the gate | `claude/landung-guard-g3` |
| PR456 | 456, landed as `61b585b5` | the corpus's Codex hook check reads the whole hook set and counts only a command that starts the gate; the self-test names the host that reaches the stale subject and keeps Codex NOT MEASURABLE; the plugin tests run offline from a filled uv cache | `claude/landung-guard-g4` |
| PR447 | 447, landed as `e1af1a7f` | the gate reads a text runner the shell joins from parts as a text runner, reads a line with a text runner or a command substitution the strict way as well, and reads a locale or ANSI-C part inside quotes as the text it shows; a file only the session reads is made for its account alone | `foxtrot/folge-nach-441` |
| PR460 | 460, landed as `cd0d64d1` | the public hook commands start the gate without `--autonomous`, which stays the house's opt-in; the pilot's journal is created with mode 0o644; the signer service refuses a new release at 4096 remembered ones and evicts no key; the texts of the modes | `claude/landung-guard-g5` |
| PR461 | 461, landed as `ba8466d1` | the next session start hands an open done blocker on with the fresh open checks; no hook reads a done order or a key record without the protected owner-state setting | `claude/landung-guard-g6` |
| PR464 | 464, landed as `e92eadc3` | the work profile applies only in the gate started with `--autonomous`; the signer service reads the archives of a rotated record of releases and honours a release never twice | `claude/landung-guard-g7` |
| PR466 | 466, landed as `8bb289c8` | the record of the owner releases used reads only its own fields, keeps every dropped identity as a digest, writes a use only within its window and chooses a release by the same predicate it writes it by | `fix/d119-release-record-full-refuses` |
| PR469 | 469, landed as `c1c123c3` | the verifier pin `proofbundle==6.4.0` in the gate and in the MCP server, with the texts that name it | `build/plugin-pin-6.4.0` |
| PR472 | 472, landed as `a466f4d6` | the Guard becomes the plugin proofbundle-guard in plugins/proofbundle-guard with its own house marketplace and its own copy of the server; proofbundle registers no hook; the public marketplace lists proofbundle alone; the server reads the gate's log from the Guard's data directory | `build/plugin-guard-apart-d134` |
| PR468 | 468 | a copy of an owner's release with a later answer does not extend the window of its identity | `fix/release-window-binds-to-the-first-answer` |
| RP1 | the pull request that adds this file | the release tools `scripts/plugin_release_artifacts.py` and `scripts/plugin_release_run_probe.sh` with their counterprobes in `tests/test_plugin_release_artifacts.py`, the release notes `release_notes/RELEASE_NOTES_plugin_0.4.0.md`, this scope file and its pinned state in `tests/test_release_scope_title_gate.py`, and the decision in `MANIFEST.in` and `tests/test_sdist_ohne_signierwerkzeug.py` that the sdist does not ship the two tools | `build/plugin-release-plan-0.4.0` |

Two corrections of the Guard's decision receipts are in this release as well. The owner chose on 2026-11-03 to take
them into 0.4.0. They land in one pull request before the release commit; it has no number yet and is open point 5,
item GR1. That pull request adds its own row to the table above, with its number, its change and its branch. What
changes for users:

- Trace context. A decision receipt of the Guard carries `traceContext` with `traceId` equal to the `session_id` and
  `parentId` equal to the `tool_use_id` of the hook event it decides, so a receipt can be matched to its session and
  to its tool call.
- Merge digest. For a merge of a pull request, `parametersDigest` is the SHA-256 of bytes that bind the repository,
  the pull request number, the head commit and the merge method, instead of the SHA-256 of empty bytes, so the
  receipt binds what is merged.

Acceptance records are separate from the rows. Before the release they show Claude Code M1 for the verifier and for
the house Guard at the release commit, the measured reinstall of an earlier 0.4.0 that carried the Guard's hooks, the
final loaded-component inventories of both plugins, and the generator and signature-chain checks the release plan
requires. Codex is not claimed to be at M1.

## Out

Out means that an item is not part of the plugin release; it does not prove absence of outward effects.

| Item | Why it is out |
|---|---|
| A HOME of its own for each plugin module | The owner chose on 2026-11-02 to release this fix with the package 6.6.0, not with the plugin 0.4.0. |
| The remaining bundles of the Guard after the split | The owner chose on 2026-11-01 that they follow the plugin 0.4.0. A bundle that lands on main before the release commit and changes a plugin folder needs a row in In instead, and the acceptance runs again. |
| The package rows of 6.5.0 | They change the Python package, which is released as 6.5.0 after the plugin. The plugin calls a released package through its pin and carries no package code; the sdist prunes `plugins/`. |
| A PyPI artifact for the plugin | The plugin is not a Python distribution. Claude Code and Codex install it from this repository. |
| A listing in a plugin directory of a host vendor | A submission speaks for the project to a third party. If the owner wants one, the owner sends it, apart from this release. |

## Open points

1. Pull request 468 changes two files of the Guard: a copy of an owner's release with a later answer does not extend
   the window of its identity. The owner chose on 2026-11-03 to take it into 0.4.0; it lands before this file, has
   its row in In, and the acceptance at the release commit measures it.
2. A change to plugins/, .claude-plugin/ or LICENSE that lands between this file's pull request and the release commit
   needs its own row, and the generator's inventory below is read again at the release commit.
3. The README section "Release 0.4.0 verification and migration", which the release notes link, is written after the
   measured reinstall of an earlier 0.4.0, with the exact commands of that run.
4. The acceptance records above are not yet passed. Runs under Codex stay NOT MEASURED for this release.
5. GR1, the pull request with the trace context and the merge digest of the Guard's receipts, is not open yet and has
   no number. It lands before the release commit and adds its row to In; until it has landed, no commit is the
   release commit. How a merge is recorded whose call does not name its head commit is decided with that pull
   request. The release notes name both corrections once they have landed.

## Version and pin places

`scripts/plugin_release_artifacts.py` reads each place below on its own, with its count, in the split layout. Script
dependency metadata is parsed as TOML and lists the pin alone, written proofbundle==X.Y.Z; constants and the server's tool table are read with ast, never executed. A
change of a place, a count, an entry or the tool set lands in the generator together with the change that makes it.

| Root | Place | Kind | Count | Expected |
|---|---|---|---|---|
| plugins/proofbundle | `.claude-plugin/plugin.json`, `version` | JSON member | 1 | 0.4.0 |
| plugins/proofbundle | `.codex-plugin/plugin.json`, `version` | JSON member | 1 | 0.4.0 |
| plugins/proofbundle | `server/proofbundle_mcp.py`, `SERVER_VERSION` | top-level constant | 1 | 0.4.0 |
| plugins/proofbundle | `server/proofbundle_mcp.py`, script metadata | PEP 723 block | 1 | proofbundle==6.4.0 |
| plugins/proofbundle-guard | `.claude-plugin/plugin.json`, `version` | JSON member | 1 | 0.4.0 |
| plugins/proofbundle-guard | `.codex-plugin/plugin.json`, `version` | JSON member | 1 | 0.4.0 |
| plugins/proofbundle-guard | `server/proofbundle_mcp.py`, `SERVER_VERSION` | top-level constant | 1 | 0.4.0 |
| plugins/proofbundle-guard | `server/proofbundle_mcp.py`, script metadata | PEP 723 block | 1 | proofbundle==6.4.0 |
| plugins/proofbundle-guard | `hooks/proofbundle_gate.py`, `GATE_VERSION` | top-level constant | 1 | 0.4.0 |
| plugins/proofbundle-guard | `hooks/proofbundle_gate.py`, `PINNED_PROOFBUNDLE` | top-level constant | 1 | 6.4.0 |
| plugins/proofbundle-guard | `hooks/proofbundle_gate.py`, script metadata inside `_SIGN_TOOL` | PEP 723 block in a string constant | 1 | proofbundle==6.4.0 |
| plugins/proofbundle-guard | `hooks/proofbundle_gate.py`, script metadata inside `_KEY_TOOL` | PEP 723 block in a string constant | 1 | proofbundle==6.4.0 |
| repository | `plugins/README.md`, the rows of Claude Code and Codex | version cell of a catalog row | 2 | 0.4.0 |

The marketplaces and profiles it checks in the same run:

| File or folder | Rule |
|---|---|
| `.claude-plugin/marketplace.json` | name proofbundle; exactly one entry, proofbundle with source `./plugins/proofbundle`; no differing version field |
| `plugins/proofbundle-guard/.claude-plugin/marketplace.json` | name proofbundle-house; exactly one entry, proofbundle-guard with source `./`, which resolves to the Guard's own folder |
| plugins/proofbundle | no hooks/ folder, no `hooks` field in either host manifest or its marketplace entry, no dependency on the Guard, its server registered in `.mcp.json` and in the Codex manifest exactly as main c9ab65b1 writes it, for each host its own, and none in its Claude Code manifest, and the seven tools of its server: `emit_receipt`, `gate_selftest_check`, `gate_selftest_prepare`, `gate_status`, `inspect_receipt`, `receipt_template`, `verify_receipt` |
| plugins/proofbundle-guard | `hooks/hooks.json` and the gate program present, every hook command of either host starting its program in one of the two forms the Guard writes, `python3 -I "${CLAUDE_PLUGIN_ROOT}/<path>"` in `hooks/hooks.json` and `python3 -I "${PLUGIN_ROOT}/<path>"` in the Codex manifest, at its start, alone or as `out=$(…)`, and that program present in the Guard's folder, no skills/ folder, no MCP server registered, and its copy of the server byte-equal to the verifier's |
| every archived entry | a regular file with mode 0644 or 0755; a symbolic link or a gitlink stops the build |

A JSON file the generator reads that names a member twice stops the build, so a version member counts once only
where it is written once. A hook command in any other form, one that names a plugin root a second time, or one that sh or bash does not parse,
stops the build too. The Guard registers its Claude Code hooks in `hooks/hooks.json` alone, so a hooks field in its Claude Code
manifest or in its house marketplace entry stops the build, and the hooks of its Codex manifest have to be an object.
For a constant or the tool table read with ast, every mention of its name as a Python token, in the NFKC form Python
reads it in, has to be that name at that place, written once, as the only target of its top-level assignment, and otherwise read; the tool table may besides be
looked up or read by `items`, `keys`, `values` or `get`. The Python files it reads that way have LF line ends and no BOM or encoding declaration, as at
main c9ab65b1; a CR, a BOM or such a declaration in one of them stops the build.

The plugin catalog plugins/README.md copies the manifests' version in its rows for Claude Code and Codex. It is not in
the archive; the generator reads their version cells as one more version place, with the count 2: the table runs from its head row
to the first blank line, every line of it starts and ends with a pipe and holds no backslash, the delimiter row is one --- per column of the head, the head names the
Version column, and every
row after the delimiter is the row of a host with as many cells as the head and a version X.Y.Z in that column; each
host has exactly one row, and no line outside the table holds a pipe, so the file has one table; no line holds a
character reference (&). The catalog holds no HTML,
no < at all, and no code block, and a blank line comes before its head.

Assisted by little helpers.
