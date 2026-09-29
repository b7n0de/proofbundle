# proofbundle plugin for Claude Code and Codex

This plugin lets a Claude Code or Codex session create, verify and review proofbundle receipts. It
calls the `proofbundle` package from PyPI, so every verdict is the package's own verdict and exit code.
One folder serves both hosts: `.claude-plugin/plugin.json` for Claude Code, `.codex-plugin/plugin.json`
for Codex, over the same skills, MCP server and gate.

A passing verification proves that the holder of the given key signed exactly these bytes and that
they have not changed since. It does not prove that any recorded value is true.

## What it adds

Skills:

| Skill | Command | What it does |
|---|---|---|
| verify | `/proofbundle:verify [file] [key]` | Verifies a decision receipt, an outcome receipt or an evidence bundle and reports the exit code and its meaning. |
| emit | `/proofbundle:emit [decision\|outcome] [out]` | Fills a template with facts you give, shows it to you, signs it after you confirm, then verifies the result. Runs only when you invoke it. |
| review-receipt | `/proofbundle:review-receipt [file] [key]` | Verifies first, then separates what the signature proves from what the issuer only recorded. |

MCP server `proofbundle` (shown as `plugin:proofbundle:proofbundle` in `/mcp`), with four tools:

| Tool | Command it runs |
|---|---|
| `receipt_template` | `proofbundle decision init` or `proofbundle outcome init` |
| `emit_receipt` | `proofbundle decision emit` or `proofbundle outcome emit` |
| `verify_receipt` | `proofbundle decision verify`, `proofbundle outcome verify` or `proofbundle verify` |
| `inspect_receipt` | `proofbundle decision inspect` or `proofbundle outcome inspect`, without verification |

Each result carries the command that ran, its exit code and its full output.

## Requirements

- [uv](https://docs.astral.sh/uv/) on `PATH`. The server starts with `uv run --script`, which installs
  the package pinned in the header of `server/proofbundle_mcp.py` into a cached environment.
- Network access to PyPI on the first start, and a Python version uv can use (3.10 or later).

## The pre-push gate

A `PreToolUse` hook runs `hooks/proofbundle_gate.py` before every Bash call. It acts before
`git push`, `gh pr create` and `gh release create`. At those calls it verifies the evidence that the
repository declares in `.proofbundle/evidence.json` at HEAD. It uses the `verify_receipt` tool of the
MCP server above.

| What the gate finds | Answer |
|---|---|
| Every declared item verifies | No permission decision. The normal permission flow applies, and a message names what was verified. |
| An item fails, is missing at HEAD, or pins no signer; the declaration is malformed; the verifier cannot run | Deny, with the reason. |
| No declaration at HEAD, an empty list, no repository, or a directory the gate cannot resolve | NOT MEASURED, and the call asks. In `claude -p` an ask is a refusal. |

The gate reads the declaration and the evidence from the commit at HEAD, not from the working tree.
It never answers allow. The declaration format and every open design choice are in
[DECISIONS.md](DECISIONS.md).

A pass proves what the declared evidence proves: who signed the recorded bytes, and that they are
unchanged. It does not prove that the pushed code is what the evidence describes (D2 in
DECISIONS.md).

## Install from this repository

The repository root carries `.claude-plugin/marketplace.json`, a marketplace with this one plugin. It
publishes nothing. After the plugin lands on the default branch:

```sh
claude plugin marketplace add b7n0de/proofbundle
claude plugin install proofbundle@proofbundle
```

## Try it from a checkout

```sh
claude plugin validate --strict plugins/proofbundle
claude plugin validate --strict .
claude --plugin-dir plugins/proofbundle
```

In the session, `/mcp` lists the server and `/proofbundle:verify` runs the verify skill.

## Codex

Codex reads `.codex-plugin/plugin.json` before the Claude Code manifest. That manifest declares the
same MCP server (started with `uv` from the plugin folder) and the same gate, run with `--host codex`.
Codex reads the skills from `skills/`. A skill's name is prefixed with the plugin's name, as in
`proofbundle:verify`.

The gate behaves differently under Codex in two ways:

- Codex has no ask decision. Under Codex, a NOT MEASURED call is denied instead of asked (D12 in
  DECISIONS.md).
- Codex runs a plugin's hooks only after you trust them, at the start-up review or in `/hooks`. Until
  then the gate does not run, and a push is not gated (D13).

Codex starts an MCP server with only a short list of environment variables. The plugin data directory
is not among them, so under Codex `emit_receipt` needs an explicit `key_path`. If `uv` needs proxy or
certificate settings to reach PyPI, add their names to the server's `env_vars` in your Codex
configuration.

Install from this repository, after the plugin lands on the default branch:

```sh
codex plugin marketplace add b7n0de/proofbundle
codex plugin add proofbundle@proofbundle
```

Codex reads the same `.claude-plugin/marketplace.json` (D15).

## Evals

`evals/` holds cases for the three skills and the gate, for `claude plugin eval`. The gate cases
seed a git repository with a scaffold script and need Bash, so they run with:

```sh
claude plugin eval plugins/proofbundle --scaffold --mocks off --no-publish \
  --allow-tools Bash "mcp__plugin_proofbundle_proofbundle__*"
```

The scaffold scripts run offline. They copy the signed fixtures in `evals/_fixtures/data/`. Those
fixtures were made once by `evals/_fixtures/make.py` with the pinned package, and they carry public
keys only.

Every eval run is a model call on your account.

## Keys

`emit_receipt` signs with the key file you name in `key_path`. Without one it uses
`${CLAUDE_PLUGIN_DATA}/keys/proofbundle-ed25519.key` and creates it on first use, with mode 0600 in a
directory with mode 0700. Claude Code keeps that directory across plugin updates and deletes it when
the plugin is uninstalled, unless you uninstall with `--keep-data`.

A relying party needs your public key through a channel it trusts. A key read from the receipt
itself proves nothing.

## Package version

The server pins one exact version of `proofbundle` in its script header. The tools report the
version they ran with in every result.

## Not part of the Python package

This directory is excluded from the sdist and the wheel (`prune plugins` in `MANIFEST.in`). The
plugin depends on the package; the package does not carry the plugin.
