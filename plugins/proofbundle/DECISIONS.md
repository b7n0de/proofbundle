# Decisions of the pre-push gate

The gate in `hooks/proofbundle_gate.py` runs before every Bash call. Where the design was open, it
takes the smallest variant that fails closed. Each decision below names that choice and the options
the owner can pick instead. Nothing here is final until the owner decides.

## The declaration

A repository declares its evidence in `.proofbundle/evidence.json`:

```json
{
  "schema": "proofbundle-plugin/evidence/v0.1",
  "evidence": [
    {"kind": "bundle", "path": "evidence/build.bundle.json", "policy": ".proofbundle/policy.json"},
    {"kind": "decision", "path": "evidence/release.decision.json", "public_key": "<issuer Ed25519 key, base64>"}
  ]
}
```

- `kind` is `bundle`, `decision` or `outcome`.
- `path` and `policy` are normalised paths inside the repository.
- A `decision` or `outcome` item names the issuer key it must verify under in `public_key`.
- A `bundle` item names a trust policy in `policy`, and that policy must pin a signer (D7).
- Any other key, a repeated key, another schema, more than 32 items, or a file above its size limit
  makes the declaration malformed.

## D1. Where the evidence is declared

Chosen: `.proofbundle/evidence.json` in the repository itself.

Options:
- A. In the repository (chosen).
- B. A path the user sets per installation, through the plugin's user configuration.
- C. Outside the repository, in a policy the owner signs, so a contributor cannot weaken it by editing
  the repository.

## D2. What "evidence for the current head" means

Chosen: the declaration, every evidence file and every policy are read from the commit at HEAD with
`git cat-file`, never from the working tree. An uncommitted change can neither satisfy the gate nor
break it. The gate does not prove that the evidence is about the pushed content; it proves that the
evidence the head declares verifies.

Options:
- A. Bytes at HEAD, no subject binding (chosen).
- B. Additionally require each item to name a subject digest that equals a digest of the pushed tree.
- C. Verify at every commit in the pushed range, not only at HEAD.

## D3. Which head

Chosen: HEAD of the repository the call acts on. That repository is the hook's working directory,
changed by a literal `cd <dir>`, `pushd <dir>` or `git -C <dir>` in the same command. A directory the
gate cannot resolve literally (a variable, `popd`, `--git-dir`, `--work-tree`) is NOT MEASURED. The
refspec is not read: `git push origin other-branch` is judged by the evidence at HEAD.

Options:
- A. HEAD only (chosen).
- B. Resolve each pushed refspec and verify at each pushed commit.
- C. Treat a push whose refspec is not the current branch as NOT MEASURED.

## D4. What a pass does

Chosen: no permission decision. The gate reports what it verified to the user and to the model, and
the host's normal permission flow decides whether the call runs. The gate never answers `allow`.

Options:
- A. No decision on a pass (chosen).
- B. `allow` on a pass, which skips the permission prompt for the call.

## D5. Nothing declared

Chosen: NOT MEASURED and `ask`. This covers:
- no declaration at HEAD, or a declaration only in the working tree;
- an empty evidence list;
- a directory outside a git work tree;
- a repository without a commit;
- a directory the gate cannot resolve.

The reason starts with `NOT MEASURED:` and says that nothing was verified. In a non-interactive run
(`claude -p`) an `ask` is a refusal.

Options:
- A. `ask` (chosen, as the task sets).
- B. `deny`, so a repository without a declaration cannot push through the plugin at all.

## D6. Failure is a deny

Chosen: `deny` for each of these:
- a malformed declaration;
- a declared file or policy missing at HEAD;
- a verification that does not exit 0;
- a verifier that cannot start;
- a gate that runs out of time;
- unreadable hook input;
- any error inside the gate.

Options:
- A. `deny` (chosen).
- B. `ask` for the cases where nothing was verified (the verifier did not start, time ran out), and
  `deny` only for failed or missing evidence.

## D7. Trust anchors

Chosen:
- A `decision` or `outcome` item must carry `public_key`.
- A `bundle` item must name a policy with a non-empty `allowed_issuers` and
  `signature.require_expected_signer: true`.
- The rest of the policy is judged by the verifier.

The pin is required because a bundle carries its own public key. Without a pinned signer, a bundle
signed by anyone would pass.

Options:
- A. Pin required (chosen).
- B. Accept a bundle policy without a pinned signer.
- C. Accept a bundle without any policy.

## D8. Which calls are gated

Chosen:
- The calls: `git push` (and `git-push`), `gh pr create` or `gh pr new`, `gh release create` or
  `gh release new`.
- Where they are found:
  - anywhere in the Bash command, after `&&`, `;`, `|` and newlines;
  - behind environment assignments, `sudo`, `command` or `env`;
  - inside `$( )` and backticks;
  - inside any quoted argument, as in `bash -c "git push"`.
- Over-matching is accepted: `echo "git push"` is gated too.
- A command that cannot be tokenised is gated when a text search finds a gated call, with the directory
  NOT MEASURED.

Not seen:
- git aliases;
- scripts and make targets that push;
- `gh api`;
- other tools such as `glab`;
- MCP tools that open a pull request or a release.

Options:
- A. Bash calls only (chosen).
- B. Also gate MCP tools whose names create pull requests or releases, with a second matcher.

## D9. The hook runs on every Bash call

Chosen: the hook has no `if` filter. A filter such as `Bash(git push*)` would miss compound and nested
forms. The cost is one Python start per Bash call: median 42 ms, maximum 53 ms over 20 calls on the
build machine, for a call the gate does not gate.

Options:
- A. Every Bash call (chosen).
- B. An `if` filter, faster but blind to compound forms.

## D10. When the gate itself cannot run

Chosen:
- If `python3` is missing or the gate crashes, the hook command exits 2, which blocks the call. This
  blocks every Bash call until the plugin or the interpreter is fixed.
- The hook timeout is 120 s. The gate denies at its own 90 s deadline, because Claude Code lets a call
  run when a PreToolUse command hook times out.

Options:
- A. Block (chosen).
- B. Let the call run when the gate cannot start, and report it.

## D11. The verifier

Chosen: the gate verifies through the plugin's own MCP server, `server/proofbundle_mcp.py`, started
with `uv run --script`. Its `verify_receipt` tool is the one the skills use, and its pin
(`proofbundle==6.1.0`) is the only pin. Without `uv`, or without a cached or reachable PyPI, the
verifier does not start and the gate denies (D6).

Options:
- A. The plugin's MCP server (chosen).
- B. A `proofbundle` command on `PATH`, which would verify with whatever version is installed.

## D12. Codex has no ask

Chosen: under Codex, the gate runs with `--host codex` and answers every NOT MEASURED case with deny.
The reason still starts with `NOT MEASURED:`.

Measured in the Codex source (openai/codex at c248f6d4):
- `codex-rs/hooks/src/engine/output_parser.rs` rejects `permissionDecision: "ask"` as unsupported;
- `codex-rs/hooks/src/events/pre_tool_use.rs` then marks the hook as failed without blocking;
- an ask would therefore let the call run.

Options:
- A. Deny under Codex (chosen).
- B. Let the call run under Codex when nothing is declared, and report NOT MEASURED in a message.

## D13. Codex runs plugin hooks only after the user trusts them

Codex keeps a plugin's hooks inactive until the user reviews and trusts them: at the start-up review,
in `/hooks`, or with `--dangerously-bypass-hook-trust`. Until then the gate does not run under Codex,
and a push is not gated. The plugin cannot change this. The README says it.

Options:
- A. Document it (chosen).
- B. Also have the verify skill warn when the gate has not run in the session.

## D14. One folder, two manifests

Chosen:
- `plugins/proofbundle` carries `.claude-plugin/plugin.json` for Claude Code and
  `.codex-plugin/plugin.json` for Codex.
- Both manifests use the same `skills/`, `server/proofbundle_mcp.py` and
  `hooks/proofbundle_gate.py`. No file is copied.
- Codex reads `.codex-plugin/plugin.json` before `.claude-plugin/plugin.json`. Its manifest declares
  its MCP server and its hook inline, so Codex never reads `.mcp.json` or `hooks/hooks.json`. Codex does
  not expand `${CLAUDE_PLUGIN_ROOT}` in an MCP entry.
- Symlinks were ruled out: Codex drops them when it copies a plugin into its cache, and Claude Code
  copies them as links.
- The emit skill's rule "only when the user invokes it" is written twice, once per host:
  `disable-model-invocation` in SKILL.md for Claude Code, and `agents/openai.yaml` for Codex. It is the
  same rule in each host's own format, not a copy of one file.

Options:
- A. One folder (chosen).
- B. Two folders with byte-identical copies, held equal by a test.

## D15. One marketplace file

Chosen: no `.agents/plugins/marketplace.json`. Codex 0.159.0 reads `.claude-plugin/marketplace.json`
when no `.agents/plugins/marketplace.json` exists. Measured: `codex plugin marketplace add` on the
repository, then `codex plugin add proofbundle@proofbundle`, installed version 0.3.0 from
`.codex-plugin/plugin.json`.

Options:
- A. One file for both hosts (chosen).
- B. A separate `.agents/plugins/marketplace.json`, for Codex-only fields such as `policy.installation`
  or `category`.
