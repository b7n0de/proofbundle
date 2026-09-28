# proofbundle plugin for Claude Code

This plugin lets a Claude Code session create, verify and review proofbundle receipts. It calls the
`proofbundle` package from PyPI, so every verdict is the package's own verdict and exit code.

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

## Try it from a checkout

```sh
claude plugin validate --strict plugins/claude-code
claude --plugin-dir plugins/claude-code
```

In the session, `/mcp` lists the server and `/proofbundle:verify` runs the verify skill.

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
