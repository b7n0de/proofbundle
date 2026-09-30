# Plugins

Plugins that let an AI coding agent use proofbundle. A plugin calls the `proofbundle` package from
PyPI, so every verdict is the package's own verdict. A passing verification proves who signed the
recorded bytes and that they have not changed since, not that any recorded value is true.

| Host | What it does | Plugin | Version | Maturity |
|---|---|---|---|---|
| Claude Code | Verify receipts and evidence bundles, review what a verified receipt records, and verify the evidence a repository declares before `git push`, `gh pr create`, `gh release create` and six MCP tools that open a pull request, a merge request or a release, push files, write a file or merge a pull request. Emitting a signed receipt is experimental | [proofbundle](proofbundle/README.md) | 0.3.0 | Experimental |
| Codex | Verify, review, the gate and the experimental emit, as under Claude Code, from the same skills, server and gate. Codex runs the gate only after the user trusts the plugin's hooks. A repository that declares nothing gets no decision, marked NOT MEASURED, and any other call the gate cannot measure is denied. The server cannot see whether the gate ran, and every `verify_receipt` result says so | [proofbundle](proofbundle/README.md) | 0.3.0 | Experimental, hook run not yet measured |

The version is the one in the plugin's manifest for that host. The maturity is copied from the status
line of the plugin's README. Which calls the gate covers, and which it leaves open, is in
[D8 of the plugin's decisions](proofbundle/DECISIONS.md).

## Planned

No planned plugin is recorded yet. A planned plugin is listed here, marked not built, until its folder
exists.

The package's own pytest plugin and Inspect AI hook ship inside the package and are described in
[Integrations](../INTEGRATIONS.md).
