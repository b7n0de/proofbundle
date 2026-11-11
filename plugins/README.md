# Plugins

**Use proofbundle from inside Claude Code or Codex.**

The proofbundle plugin lets your coding agent check a receipt on your own machine. It explains which signature and integrity checks passed, what was not checked, and what a receipt cannot tell you. For decision and outcome receipts, it verifies against an issuer public key you trust. An evidence bundle uses a separate check that does not by itself establish whether you should trust its signer. The same plugin serves both hosts.

## Install

**Claude Code**

```sh
claude plugin marketplace add b7n0de/proofbundle
claude plugin install proofbundle@proofbundle
```

**Codex**

```sh
codex plugin marketplace add b7n0de/proofbundle
codex plugin add proofbundle@proofbundle
```

Then ask for `/proofbundle:verify receipt.json` in Claude Code, or for the skill `proofbundle:verify` in Codex. The [plugin's README](proofbundle/README.md) shows what else it does.

## Good to know

- A passing check confirms only the signature and integrity properties checked for that receipt type, not that any recorded value is true. For decision and outcome receipts, the issuer public key must come from a source you trust. An evidence bundle can pass verification without such an externally supplied key, so a pass alone does not establish signer trust.
- Status is experimental in both hosts.
- Receipts for a pytest run or an Inspect AI eval come from the package itself, see [Integrations](../INTEGRATIONS.md).

The [technical details](#technical-details) follow below, with each host's row, its version and its maturity.

## Technical details

Plugins that let an AI coding agent use proofbundle. A plugin calls the `proofbundle` package from
PyPI, so every verdict is the package's own verdict. A passing verification proves who signed the
recorded bytes and that they have not changed since, not that any recorded value is true.

| Host | What it does | Plugin | Version | Maturity |
|---|---|---|---|---|
| Claude Code | Verifies receipts and evidence bundles against a chosen issuer key. Guard requires its separate hook configuration. Recognized shell forms can check declared evidence; supported MCP writes ask because their target is unbound. Receipt signing is experimental and its skill requests explicit invocation and confirmation, with host enforcement NOT MEASURED | [proofbundle](proofbundle/README.md) | 0.4.0 | Experimental |
| Codex | Verify decision and outcome receipts and evidence bundles, and review verification results separately from recorded claims. The repository checks are the hooks of the separate Guard (proofbundle-guard, D134), which Codex runs only after you trust them. When they run, repositories without an evidence declaration get NOT MEASURED and no decision, a plain `git push` gets NOT MEASURED with a warning, and other unmeasurable calls are denied. Each `verify_receipt` result states that the server cannot tell whether these checks ran. Receipt signing is experimental; its skill requests explicit invocation and confirmation. Enforcement of those restrictions by the host is NOT MEASURED | [proofbundle](proofbundle/README.md) | 0.4.0 | Experimental, a plain `git push` only warns, hook run with a real model not yet measured |

The version is the one in the plugin's manifest for that host. The maturity is copied from the status
line of the plugin's README. Which calls the gate covers, and which it leaves open, is in
[D8 of the plugin's decisions](proofbundle/DECISIONS.md).

## Planned

No planned plugin is recorded yet. A planned plugin is listed here, marked not built, until its folder
exists.

The package's own pytest plugin and Inspect AI hook ship inside the package and are described in
[Integrations](../INTEGRATIONS.md).
