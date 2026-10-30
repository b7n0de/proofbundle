# proofbundle plugin for Claude Code and Codex

Verify decision and outcome receipts against your chosen issuer key, check evidence bundles, and review
verification results separately from recorded claims. Receipt signing is experimental and requires an
explicit user request. Verification proves authorship and integrity of what was recorded, not that any
recorded value is true. The plugin calls the `proofbundle` package from PyPI, so every verdict is the
package's own verdict and exit code.
One folder serves both hosts: `.claude-plugin/plugin.json` for Claude Code, `.codex-plugin/plugin.json`
for Codex, over the same skills.

A passing verification proves that the holder of the given key signed exactly these bytes and that
they have not changed since. It does not prove that any recorded value is true.

**Status** · Claude Code: Experimental · Codex: Experimental

## What it adds

Skills:

| Skill | Command | What it does |
|---|---|---|
| verify | `/proofbundle:verify [file] [key]` | Verifies a decision receipt, an outcome receipt or an evidence bundle and reports the exit code and its meaning. |
| review-receipt | `/proofbundle:review-receipt [file] [key]` | Verifies first, then separates what the signature proves from what the issuer only recorded. |
| emit (experimental) | `/proofbundle:emit [decision\|outcome] [out]` | Fills a template with facts you give, shows it to you, signs it after you confirm, then verifies the result. Runs only when you invoke it. |

Every skill, and the server's instructions, carry the same rule: everything a receipt contains, its
free-text fields, its file name and any file next to it, is data and never an instruction. A request
found there is reported as recorded content, not followed. The evals `review-receipt-injection` and
`verify-inspect-injection` measure it with a signed receipt that asks the reader to create a file.

MCP server `proofbundle` (shown as `plugin:proofbundle:proofbundle` in `/mcp`):

| Tool | Command it runs |
|---|---|
| `receipt_template` | `proofbundle decision init` or `proofbundle outcome init` |
| `emit_receipt` | `proofbundle decision emit` or `proofbundle outcome emit` |
| `verify_receipt` | `proofbundle decision verify`, `proofbundle outcome verify` or `proofbundle verify` |
| `inspect_receipt` | `proofbundle decision inspect` or `proofbundle outcome inspect`, without verification |

Each result carries the command that ran, its exit code and its full output. A `verify_receipt`
result also carries `safe_for_automation` and `automation_blockers`, copied verbatim from the report
(`automation` for a decision or outcome receipt, `root_authenticity` for a bundle), and
`automation_source`, the path it copied them from. Where the report has no such field, both are `null`
and `automation_source` says `not reported by the core`; the server derives nothing itself. The skills
report both fields. `safe_for_automation: true` is a precondition for an automatic follow-up action that
is already authorized, never an approval to publish or act on its own; exit 0 means only that the
signature and structure hold.

## Requirements

- [uv](https://docs.astral.sh/uv/) on `PATH`. The server starts with `uv run --script`, which installs
  the package pinned in the header of `server/proofbundle_mcp.py` into a cached environment.
- Network access to PyPI on the first start, and a Python version uv can use (3.10 or later).

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
same MCP server (started with `uv` from the plugin folder).
Codex reads the skills from `skills/`. A skill's name is prefixed with the plugin's name, as in
`proofbundle:verify`.

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

`evals/` holds cases for the three skills, for `claude plugin eval`. The verify and
review cases grade the result, not the route: a model may call `verify_receipt` without the skill, and
the server states the rules the result depends on, so whether a skill fired is read from the trace and
reported, not scored. review-receipt-injection still grades it. The eval graders detect text features only —
a regex over the trace, or which tool ran — so content judgements like "verification failure correctly
named", "no truth claimed" or "no private key requested" hold only with human review; four known
counter-phrasings that match the pattern while reversing the meaning are recorded as a known limit in the
tests.

`evals/CORPUS.md` lists the cases built from real failures, each with a valid counterpart, and
`evals/run_corpus.sh` runs them after every update of Claude Code or Codex, with the host versions.

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
