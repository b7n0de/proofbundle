# Plugins

Plugins that let an AI coding agent use proofbundle. A plugin calls the `proofbundle` package from
PyPI, so every verdict is the package's own verdict. A passing verification proves who signed the
recorded bytes and that they have not changed since, not that any recorded value is true.

| Host | What it does | Plugin | Version | Maturity |
|---|---|---|---|---|
| Claude Code | Verify decision and outcome receipts and evidence bundles, and review verification results separately from recorded claims. Hooks check declared repository evidence before `git push`, `gh pr create`, `gh release create` and the six supported MCP tools for creating pull or merge requests or releases, pushing files, writing files or merging pull requests. Receipt signing is experimental and requires an explicit user request | [proofbundle](proofbundle/README.md) | 0.4.0 | Experimental |
| Codex | Verify decision and outcome receipts and evidence bundles, and review verification results separately from recorded claims. Codex runs the repository checks only after you trust the plugin's hooks. When they run, repositories without an evidence declaration get NOT MEASURED and no decision, a `git push` gets NOT MEASURED with a warning, and other unmeasurable calls are denied. Each `verify_receipt` result states that the server cannot tell whether these checks ran. Receipt signing is experimental and requires an explicit user request | [proofbundle](proofbundle/README.md) | 0.4.0 | Experimental, a plain `git push` only warns, hook run with a real model not yet measured |
| Claude Code | Guard Preview hooks in the house profile of b7n0de, installed beside proofbundle: the gate before every Bash call and before supported writes, with the house's autonomous answer; a hook that cannot run blocks the call. Not for general use | [proofbundle-guard](proofbundle-guard/README.md) | 0.4.0 | Preview, house profile only |
| Codex | Guard Preview hooks in the house profile of b7n0de, installed beside proofbundle, which Codex runs only after you trust them; a plain `git push` gets NOT MEASURED with a warning. Not for general use | [proofbundle-guard](proofbundle-guard/README.md) | 0.4.0 | Preview, house profile only, hook run with a real model not yet measured |

The version is the one in the plugin's manifest for that host. The maturity is copied from the status
line of the plugin's README. Which calls the gate covers, and which it leaves open, is in
[D8 of the plugin's decisions](proofbundle/DECISIONS.md).

## Planned

No planned plugin is recorded yet. A planned plugin is listed here, marked not built, until its folder
exists.

The package's own pytest plugin and Inspect AI hook ship inside the package and are described in
[Integrations](../INTEGRATIONS.md).
