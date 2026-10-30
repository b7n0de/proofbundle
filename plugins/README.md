# Plugins

Plugins that let an AI coding agent use proofbundle. A plugin calls the `proofbundle` package from
PyPI, so every verdict is the package's own verdict. A passing verification proves who signed the
recorded bytes and that they have not changed since, not that any recorded value is true.

| Host | What it does | Plugin | Version | Maturity |
|---|---|---|---|---|
| Claude Code | Verify decision and outcome receipts and evidence bundles, and review verification results separately from recorded claims. Receipt signing is experimental and requires an explicit user request | [proofbundle](proofbundle/README.md) | 0.4.0 | Experimental |
| Codex | Verify decision and outcome receipts and evidence bundles, and review verification results separately from recorded claims. Receipt signing is experimental and requires an explicit user request | [proofbundle](proofbundle/README.md) | 0.4.0 | Experimental |

The version is the one in the plugin's manifest for that host. The maturity is copied from the status
line of the plugin's README.

## Planned

No planned plugin is recorded yet. A planned plugin is listed here, marked not built, until its folder
exists.

The package's own pytest plugin and Inspect AI hook ship inside the package and are described in
[Integrations](../INTEGRATIONS.md).
