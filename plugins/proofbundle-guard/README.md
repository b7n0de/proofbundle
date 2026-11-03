# proofbundle-guard

The Guard Preview of [proofbundle](../proofbundle/README.md) in the house profile of b7n0de, as a plugin of its own
(D134 in [the plugin's decisions](../proofbundle/DECISIONS.md)). It is meant for the owner's machines. To verify
receipts and evidence bundles, install proofbundle; it registers no hook.

**Status** · Claude Code: Preview, house profile only · Codex: Preview, house profile only, hook run with a real model not yet measured

## What it registers

- Under Claude Code, hooks/hooks.json: a PreToolUse hook before every Bash call, before the supported MCP writes and
  before the file tools, each starting the gate with the house's autonomous flag (D85, the opt-in of D125); a hook
  before Read and Grep that denies a key file (D102); PostToolUse hooks (D94, D110); the done check at Stop and
  TaskCompleted and its hand-over at SessionStart (D127).
- Under Codex, the hooks in .codex-plugin/plugin.json, each starting the gate with `--host codex`. Codex runs them
  only after you trust them (D16).

A hook that cannot run blocks the call (`exit 2`). Level 1 is not a security boundary, and the installed git pre-push
hook is a separate, bypassable check. The gate programs under hooks/ live here only; proofbundle holds no hooks/
folder (D134). The file under server/ is a byte-equal copy of proofbundle's server, which the gate starts from this
folder, not a link, because Codex drops a link when it installs a plugin; a test of the repository holds them
equal. The plugin adds no skill and no MCP server.

## Install on the owner's machines

The public marketplace lists proofbundle alone. This folder is a house marketplace of its own, `proofbundle-house`,
whose one entry is the folder itself; the owner's machines add it from a checkout of b7n0de/proofbundle:

```
claude plugin marketplace add b7n0de/proofbundle
claude plugin install proofbundle@proofbundle
claude plugin marketplace add <checkout>/plugins/proofbundle-guard
claude plugin install proofbundle-guard@proofbundle-house
```

Under Codex the same two steps with `codex plugin marketplace add` and `codex plugin add`; Codex reads this folder's
`.claude-plugin/marketplace.json` as it reads the public one. A Codex install of the Guard is NOT MEASURED.

The standing GO for work-branch pushes needs its own consent in the hook's environment (D129); installing this plugin
does not give it.
