# Decisions of the pre-push gate

The gate in `hooks/proofbundle_gate.py` runs before every Bash call and before an MCP tool that opens a
pull request, a merge request or a release, pushes files, writes a file or merges a pull request. Where
the design was open, it takes the smallest variant that fails closed. Each decision below names that
choice and the options the owner can pick instead. The owner decided D2, D8, D13, D14, D16 and D17 on
2026-09-29 and D5 and D18 on 2026-09-30. D19 and later are the smallest variants for the owner's points
of 2026-09-30 that fail closed; the owner reviews them. The rest is open until the owner decides.

## The declaration

A repository declares its evidence in `.proofbundle/evidence.json`:

```json
{
  "schema": "proofbundle-plugin/evidence/v0.2",
  "evidence": [
    {"kind": "bundle", "path": ".proofbundle/build.bundle.json", "policy": ".proofbundle/policy.json",
     "subject": {"algorithm": "proofbundle-tree-sha256/v1", "digest": "<64 lowercase hex>"}},
    {"kind": "decision", "path": ".proofbundle/release.decision.json", "public_key": "<issuer Ed25519 key, base64>",
     "subject": {"algorithm": "proofbundle-tree-sha256/v1", "digest": "<64 lowercase hex>"}}
  ]
}
```

- `kind` is `bundle` or `decision`. An `outcome` item is refused: an outcome receipt has no field that
  can carry a tree subject.
- `path` and `policy` are normalised paths under `.proofbundle/`, the folder the tree digest leaves out
  (D2). Evidence anywhere else would be part of the tree it names.
- A `decision` item names the issuer key it must verify under in `public_key`.
- A `bundle` item names a trust policy in `policy`, and that policy must pin a signer (D7).
- Every item names its `subject`: the tree digest of the commit it speaks for (D2).
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

Chosen (owner, 2026-09-29): B. The declaration, every evidence file and every policy are read from the
commit at HEAD with `git cat-file`, never from the working tree, and each item is bound to the tree of
that commit.

- The subject is `proofbundle-tree-sha256/v1`: sha256 over the line `proofbundle-tree-sha256/v1`
  followed, for every file of the commit's tree sorted by the path's bytes, by
  `<mode> <sha256 of the file's bytes> <path>` and a NUL byte.
- The covered set is every file of HEAD except the top-level `.proofbundle/` folder, where the
  declaration and the evidence live. A folder of that name deeper in the tree is covered.
- The digest is computed from the commit alone, offline, and deterministically: modes come from git
  (100644, 100755, 120000) and bytes from the committed blobs, so checkout settings play no part. A tree
  with a submodule has no digest, and the gate says so.
- It is not the git tree id, which is SHA-1 and git's own object format. The README prints a recipe that
  computes the digest with git and coreutils, and `hooks/proofbundle_gate.py tree-digest` prints it.
- An item without a subject, or with a subject other than the digest of HEAD, is denied.
- After the evidence verifies, the gate reads the subject the signed part names, from the same
  committed bytes: a bundle's whole payload is `{"subject": {"algorithm": …, "digest": …}}`
  (`tree-digest --statement` prints it), and a decision receipt names it as an `inputSnapshot` entry
  with `uri` `urn:proofbundle-plugin:subject:proofbundle-tree-sha256/v1` and the digest under
  `digest.sha256`. Evidence whose signed part names another digest or none is denied.

What a pass then proves: the declared signer signed a statement that names the tree digest of the commit
at HEAD. It does not prove that any recorded value is true, and it says nothing about commits before
HEAD in the pushed range (D3).

Options:
- A. Bytes at HEAD, no subject binding.
- B. Each item names a subject digest equal to a digest of the pushed tree (chosen).
- C. Verify at every commit in the pushed range, not only at HEAD.

## D3. Which commits a push is judged by

Chosen (option B, after the external review's N1, N2 and N3, 2026-10-01): every commit newly reachable
from each pushed source relative to that target's locally known remote-tracking state. If the complete
set of updates, a target's comparison state, or the required history cannot be resolved, the push is NOT
MEASURED. The remote itself is not read.

- The repository is the hook's working directory, changed by a literal `cd <dir>`, `pushd <dir>` or
  `git -C <dir>` in the same command. A directory the gate cannot resolve literally (a variable, `popd`,
  `--git-dir`, `--work-tree`) is NOT MEASURED.
- A shell `git push` resolves its targets from the command and local configuration (`resolve_push_targets`):
  the remote must be a configured name, not a URL or path; each refspec maps to a branch or tag on the
  remote with a uniquely mapped local remote-tracking ref. There is no default-branch fallback: a new
  branch or tag, or any branch this repository does not track, has no known earlier state and is NOT
  MEASURED (N1). `--all`, `--mirror`, `--tags`, a wildcard or negative refspec, a configured
  `remote.<name>.push`, a `pushurl`, a mirror remote or `push.followTags` add updates the command does not
  name, so the push is NOT MEASURED (N2). A bare `git push` resolves only under a push configuration the
  gate can model faithfully (`push.default` simple/current/upstream, no extra ref updates).
- For each target the gate evaluates the evidence at every commit the push newly sends, not only the tip,
  so a valid tip cannot heal an intermediate commit that removes the declaration or carries evidence that
  does not verify (N3). A shallow clone, or a range longer than the gate can evaluate inside its deadline,
  is NOT MEASURED.
- A `gh pr create` or `gh release create` is judged as a push of the current branch to its upstream.
- An unresolved push is asked under Claude Code and denied under Codex (D12). The D5 inactive shortcut
  applies only when the push resolves and every sent commit and the target's state declare nothing; an
  unresolved push never switches the gate off (N2).

Options:
- A. HEAD only, refspec not read (the pre-review behaviour; a push of another branch was judged at HEAD).
- B. Every newly reachable commit per resolved target, unresolved is NOT MEASURED (chosen).
- C. Treat a push whose refspec is not the current branch as NOT MEASURED (too coarse: it would miss a
  bare push of a branch the gate can resolve).

## D4. What a pass does

Chosen: no permission decision. The gate reports what it verified to the user and to the model, and
the host's normal permission flow decides whether the call runs. The gate never answers `allow`.

Options:
- A. No decision on a pass (chosen).
- B. `allow` on a pass, which skips the permission prompt for the call.

## D5. Nothing declared

Chosen (owner, 2026-09-30): C. The gate acts only where a repository declares evidence.

- The gate measures that there is no `.proofbundle/evidence.json`, neither at HEAD nor in the working
  tree: `git ls-tree` lists nothing at that path in the commit and exits 0, and the working tree has
  nothing at that path, not even a link or a folder. Then it answers without a permission decision,
  under both hosts. The message goes to the user (`systemMessage`) and to the model
  (`additionalContext`). It starts with `NOT MEASURED:` and says that the gate is not active in this
  repository, because nothing is declared. The host's normal permission flow decides.
- Every other case where nothing was verified stays NOT MEASURED and `ask`, and `deny` under Codex
  (D12):
  - a declaration only in the working tree;
  - an empty evidence list;
  - a directory outside a git work tree;
  - a repository without a commit;
  - a directory the gate cannot resolve;
  - a HEAD or a working tree where the gate cannot measure the absence, such as a failing `git ls-tree`,
    a file where the `.proofbundle/` folder should be, or a dangling link at the declaration's path.
- Failures stay `deny` (D6).

The reason starts with `NOT MEASURED:` and says that nothing was verified. In a non-interactive run
(`claude -p`) an `ask` is a refusal.

The price of C: whoever deletes the declaration switches the gate off. After a commit that deletes it,
the next push runs without a decision of the gate. The deletion stays visible in the diff of the pushed
range, and tests/test_claude_code_plugin_gate.py measures both. Since D20 the price is smaller: when a
remote-tracking ref shows that the remote holds a declaration, a push that removes it is a change of the
evidence rules and is asked, or denied under Codex. Without any remote-tracking ref the gate cannot see
the removal and stays inactive.

Options:
- A. `ask` (chosen until 2026-09-30).
- B. `deny`, so a repository without a declaration cannot push through the plugin at all.
- C. No decision where the gate measured that nothing is declared, and NOT MEASURED in the message
  (chosen, 2026-09-30).

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
- A `decision` item must carry `public_key`.
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

Chosen (owner, 2026-09-29): B, and the three GitHub MCP tools that write without opening a pull
request, `push_files`, `create_or_update_file` and `merge_pull_request`, gated as well.
- Bash calls: `git push` (and `git-push`), `gh pr create` or `gh pr new`, `gh release create` or
  `gh release new`, found:
  - anywhere in the Bash command, after `&&`, `;`, `|` and newlines;
  - behind environment assignments, `sudo`, `command` or `env`;
  - inside `$( )` and backticks;
  - inside any quoted argument, as in `bash -c "git push"`.
  Over-matching is accepted: `echo "git push"` is gated too. A command that cannot be tokenised is gated
  when a text search finds a gated call, with the directory NOT MEASURED.
- MCP tools, through a second `PreToolUse` matcher,
  `^mcp__.+__(create_pull_request|create_merge_request|create_release|push_files|create_or_update_file|merge_pull_request)$`,
  on any server. Both hosts name an MCP tool `mcp__<server>__<tool>` in the hook event, and both read a
  matcher like this one as a regular expression (Codex at c248f6d4: `hooks/src/events/common.rs`,
  `matches_matcher`). The repository is the hook's working directory; the tool's own arguments (owner,
  repository, branch) are not read.
  - Gated tool names: `create_pull_request` (the GitHub MCP server, as `mcp__github__create_pull_request`),
    `create_merge_request` and `create_release` (names other servers use; which servers, not measured),
    and the GitHub MCP server's `push_files`, `create_or_update_file` and `merge_pull_request`.
  - What the gate cannot see, and says in every answer to an MCP tool: it judges the local repository at
    HEAD, not the remote. It cannot see the branch a tool publishes or the pull request `merge_pull_request`
    merges. The bytes `push_files` and `create_or_update_file` write come from the tool's own arguments,
    and the gate does not compare them with the tree it judged, so a pass says the local evidence holds,
    not that the pushed bytes are the ones it covers.
  - Ungated, and listed as such: every other name. Open, the owner kept them out of the gate on
    2026-09-29: `delete_file`, `create_branch`, `update_pull_request`, `update_pull_request_branch` and
    `enable_pr_auto_merge`, which write to a remote without opening a pull request. Also ungated:
    `fork_repository` and `create_repository`. A tool of another server with a different name for the
    same act is not gated either.

Not seen:
- git aliases;
- scripts and make targets that push;
- `gh api`;
- other command-line tools such as `glab`.

Options:
- A. Bash calls only.
- B. Also gate MCP tools whose names create pull requests or releases, with a second matcher (chosen),
  plus `push_files`, `create_or_update_file` and `merge_pull_request` (chosen).
- C. B plus the five open tools above.

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

Isolation from the checked repository (review N4): the gate starts the verifier from an empty temporary
directory, with `uv --no-config`, and with every `PYTHON*` environment name stripped; the server runs the
command line with `python -I` from an empty temporary directory. So no file of the checked repository
decides which code verifies: not a `proofbundle/` folder on the interpreter's path, not a `uv.toml` or
`pyproject.toml`, not an inherited `PYTHONPATH`. The measured probes no longer load repository modules
through the default working-directory path or repository uv configuration. The interpreter installation and
the user's own environment (PATH, uv, UV_* variables) remain trusted inputs, named here as the boundary of
the guarantee. Under Codex the server's manifest entry sets `cwd: "."`, so the server starts in the plugin
directory, not the checked repository; the isolation above holds whatever that directory is.

Options:
- A. The plugin's MCP server, started isolated from the checked repository (chosen).
- B. A `proofbundle` command on `PATH`, which would verify with whatever version is installed.

## D12. Codex has no ask

Chosen: under Codex, the gate runs with `--host codex` and answers every NOT MEASURED case with deny.
The reason still starts with `NOT MEASURED:`.

Measured in the Codex source (openai/codex at c248f6d4):
- `codex-rs/hooks/src/engine/output_parser.rs` rejects `permissionDecision: "ask"` as unsupported;
- `codex-rs/hooks/src/events/pre_tool_use.rs` then marks the hook as failed without blocking;
- an ask would therefore let the call run.

Follow-up of D5, C (2026-09-30): a repository the gate measured to declare nothing gets no decision
under Codex either. That answer is not an ask, so the gate does not turn it into a deny, and Codex
accepts an answer without a decision (tests/test_codex_plugin.py). Every other NOT MEASURED case is still
denied under Codex.

Options:
- A. Deny under Codex (chosen for every NOT MEASURED ask).
- B. Let the call run under Codex when nothing is declared, and report NOT MEASURED in a message (holds
  since D5, C, for the one case where the gate measured that nothing is declared).

## D13. Codex runs plugin hooks only after the user trusts them

Codex keeps a plugin's hooks inactive until the user reviews and trusts them: at the start-up review,
in `/hooks`, or with `--dangerously-bypass-hook-trust`. Until then the gate does not run under Codex,
and a push is not gated. The plugin cannot change this.

Chosen (owner, 2026-09-29): A, plus a note. The README says it, and under Codex every result of
`verify_receipt` carries a `gate_note` saying that the gate runs only if the hooks are trusted and that
the server cannot see whether they are or whether the gate ran. The verify skill passes the note on and
never states that the gate ran. Nothing the MCP server can read tells whether the hooks are trusted, so
the note is a stated limit, not a detection. The server learns that it runs under Codex from
`PROOFBUNDLE_PLUGIN_HOST=codex` in the Codex manifest's server entry.

Options:
- A. Document it (chosen, with the note).
- B. Detect in the verify skill whether the gate ran in the session. Not possible from the server.

## D14. One folder, two manifests

Chosen (owner, 2026-09-29): A, in `plugins/proofbundle`.
- `plugins/proofbundle` carries `.claude-plugin/plugin.json` for Claude Code and
  `.codex-plugin/plugin.json` for Codex.
- Both manifests use the same `skills/`, `server/proofbundle_mcp.py` and
  `hooks/proofbundle_gate.py`. No file is copied.
- Codex reads `.codex-plugin/plugin.json` before `.claude-plugin/plugin.json`. Its manifest declares
  its MCP server and its hook inline, so Codex never reads `.mcp.json` or `hooks/hooks.json`. Codex does
  not expand `${CLAUDE_PLUGIN_ROOT}` in an MCP entry.
- Symlinks were ruled out:
  - Codex drops a symlink when it copies a plugin into its cache (openai/codex
    `core-plugins/src/store.rs`).
  - Claude Code 2.1.284, measured on install, keeps a link that stays inside the plugin, and replaces
    a link pointing outside with a copy of its target.
  - A shared folder reached by symlinks would therefore work under Claude Code and vanish under Codex.
- The emit skill's rule "only when the user invokes it" is written twice, once per host:
  `disable-model-invocation` in SKILL.md for Claude Code, and `agents/openai.yaml` for Codex. It is the
  same rule in each host's own format, not a copy of one file.

Addendum (owner, 2026-09-30): In the 30 September 2026 check, Codex 0.159.2 read a root Agent Plugins `plugin.json` but did not load its hooks, including hooks in `extensions["com.openai"]`. Source inspection found the same loader code in 0.161.0-alpha.4 (`core-plugins/src/loader.rs`). The gate requires hooks, so this plugin keeps `.codex-plugin/plugin.json` and omits a root `plugin.json` until a released Codex version loads hooks for that format.

- The place in the source: openai/codex `codex-rs/core-plugins/src/loader.rs`, lines 950 to 960 at tag
  `rust-v0.159.2` and lines 952 to 962 at tag `rust-v0.161.0-alpha.4` and at `main` (read 2026-09-30
  16:11Z): `if loaded_manifest.format == PluginManifestFormat::AgentPlugin { (Vec::new(), Vec::new()) }`
  in place of `load_plugin_hooks`.
- Measured on install with Codex 0.159.2 (app-server `hooks/list`): 2 hooks from
  `.codex-plugin/plugin.json` without a root `plugin.json`, 0 hooks with one, with or without hooks in
  `extensions["com.openai"]`.
- `tests/test_codex_plugin.py` fails while the gate has hooks if the folder carries a `plugin.json` or
  `mcp.json` whose `$schema` starts with `https://agent-plugins.org/schemas/`, or a root `plugin.json`
  that is a link or not a regular file, for which Codex finds no manifest at all.

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

## D16. Whether the gate runs inside a Codex turn

Chosen (owner, 2026-09-29): C. Measured after the tag v6.2.0, at the owner's machine with the owner's
account, never in the cloud. Until then the README marks it NOT MEASURED. RUNBOOK_CODEX.md holds the
exact commands, the expected answer for each case and the pass criteria.

What is measured without a Codex turn: the gate's answers under `--host codex` against Codex's hook
output schema (tests/test_codex_plugin.py), and the manifest, server and skills Codex reads from this
folder.

Options:
- A. Measure in a cloud session with a mock model.
- B. Leave it unmeasured.
- C. Measure at the owner's machine after the tag (chosen).

## D17. The declaration format changed inside the unreleased 0.3.0

Chosen (owner, 2026-09-29): A.
- Version 0.2.0 reads `proofbundle-plugin/evidence/v0.1`. Version 0.3.0 reads only
  `proofbundle-plugin/evidence/v0.2`, whose items name a tree subject (D2), and refuses a v0.1 declaration
  with "schema must be 'proofbundle-plugin/evidence/v0.2'". There is no migration.
- Both versions go to the repository after the tag v6.2.0, as planned.
- The first marketplace entry comes only with 0.3.0. Adding it is the owner's act and part of no change
  here.

Options:
- A. Both versions to the repository after the tag, the first marketplace entry with 0.3.0 (chosen).
- B. Only 0.3.0.
- C. A reader for v0.1 in 0.3.0.

## D18. The changes of 2026-09-30 stay inside the unreleased 0.3.0

Chosen (owner, 2026-09-30): the version stays 0.3.0, because 0.3.0 is unpublished, as in D17. The
changes of that day land inside 0.3.0:
- D5 option C: no decision in a repository that declares nothing, NOT MEASURED in the message;
- the rule that everything a receipt contains is data, in every skill and in the server's instructions;
- `safe_for_automation`, `automation_blockers` and `automation_source` in every `verify_receipt` result,
  copied verbatim from the core, and the exit 1 text that no longer rules out a structure failure;
- verify first: the descriptions begin with Verify, except the marketplace's own, and receipt signing
  is marked experimental; the wording is the owner's of 2026-09-30, after an external review;
- the server reports the plugin's version, 0.3.0, as its `serverInfo` version and as `plugin_version`
  in every result, where it said 0.1.0 before; a test holds it equal to every manifest.

Options:
- A. Stay at 0.3.0 (chosen).
- B. Move to 0.4.0 before the first publication.

## D19. Every rejection says what to do

Chosen (smallest variant, 2026-09-30, for the owner's review): every deny and every ask names, in short
and in this order, the evidence it concerns (kind and path, or the declaration), what failed and the next
step. Then comes the rule never to weaken the evidence rules, word for word:

"Never weaken the evidence declaration, a trust policy or an expected key to get past the gate; obtain the
missing evidence instead or ask the user."

The detail text follows after `Details:`. A NOT MEASURED answer keeps `NOT MEASURED:` at its start. The
same text goes to both hosts; under Codex it is the `permissionDecisionReason` of a deny. Every skill and
the server's instructions carry the same rule. Each case has a stable reason id (for example
`verification_failed`, `stale_subject`, `missing_file`, `rules_changed`, `range_not_measured`).

Options:
- A. Evidence, failure, next step, then the rule and the details (chosen).
- B. Only the detail text, as before.

## D20. A push that changes the evidence rules is reported

Chosen (smallest variant that fails closed, 2026-09-30; the range tightened after the review's N1, N2, N3
on 2026-10-01):
- The evidence rules are the declaration's items without their per-release `subject` (`kind`, `path`,
  `policy`, `public_key`), whether a declaration exists at all, and the bytes of every declared policy.
  An evidence file, the declared subject and any other file under `.proofbundle/` are not rules, so a
  release that brings new evidence for a new tree is no rules change. No rule is a path to a key: a
  decision item's `public_key` is the key itself in base64, and a bundle pins its signer inside its
  policy, whose bytes are compared at both commits. Outside these rules stand the plugin's hook
  configuration, the settings of the host and of the user (a setting that turns hooks off, for example),
  the proofbundle version the plugin pins, and the programs on PATH that run the check (git, uv, python).
- The gate compares the evidence rules of each commit a push sends to a branch or tag with the rules at
  that target's remote-tracking ref (`refs/remotes/<remote>/<branch>`), resolved by D3. A deletion compares
  an absent declaration with the target. A push whose targets the gate cannot resolve, or a target without
  such a ref, is NOT MEASURED (there is no default-branch fallback, N1). The gate reads local refs only; a
  fetch updates its view of the remote and proves no rules check.
- A difference is asked under Claude Code and denied under Codex, with the change named and the note that
  changes to the evidence rules need a review. Once the target's remote-tracking ref holds the change, a
  push to that target is plain; the same change held by another branch or another remote is still a change
  for this target.
- The D5 inactive shortcut (a repository that declares nothing) applies only to a resolved push whose sent
  commits and target all declare nothing. An unresolved push never switches the gate off, even when HEAD
  declares nothing, because it may send another branch the gate did not see (N2).
- A deny for failed evidence at any sent commit comes first; the rules are compared only after the evidence
  verified.

Price: a push to a target for which this repository has no remote-tracking ref (a remote given as a URL, a
remote never fetched, a brand-new branch or tag) is asked (denied under Codex). An ordinary fresh clone has
these refs for the branches it tracks and is not affected.

Options:
- A. Compare `git rev-list HEAD --not --remotes` against every remote-tracking ref (the pre-review
  behaviour; the review showed it reads the wrong target and lets an unresolved push through, N1/N2).
- B. Resolve the push targets and compare every sent commit against each target's own tracking ref,
  unresolved is NOT MEASURED (chosen).
- C. Read the remote over the network before each push (rejected: the gate never fetches).

## D21. A local log shows whether the gate ran

Chosen (smallest variant, 2026-09-30, for the owner's review):
- Every gate call appends one JSON line to `gate-log.jsonl`: the time in UTC, the host, the gate version,
  the host's session id from the hook event, the tool, the gated actions (none for an ungated call), the
  decision sent to the host (deny, ask or none), the gate's verdict, the reason ids, and per repository its
  path, HEAD, verdict and the sha256 of every evidence and policy file read. No evidence content, no
  environment variable and no key is written. Above 1 MiB the file is moved once to `gate-log.jsonl.1`.
- The place is the first named plugin data directory the host gives the hook that is, or can be made, a
  writable directory, given as an absolute path. Measured: Claude Code 2.1.285 gives a PreToolUse hook
  `CLAUDE_PLUGIN_DATA` (a run of a probe hook, the directory existed and was writable). Codex 0.159.2
  gives `PLUGIN_DATA` and `CLAUDE_PLUGIN_DATA` (`codex-rs/hooks/src/engine/discovery.rs`, lines 262 to
  270, read in the source, not in a run); the gate takes `PLUGIN_DATA` first. Without such a directory
  there is no log. Writing the log never changes the answer.
- `gate_status` reads the log from the plugin data directory named in the server's own environment
  (`CLAUDE_PLUGIN_DATA`, then `PLUGIN_DATA`), and never looks anywhere else. "This session" is the host's
  session id (`CLAUDE_CODE_SESSION_ID`) where the server has it, else the time since the server started;
  the answer names which. Under Codex the server's entry of `.codex-plugin/plugin.json` gets neither
  variable, so the server cannot read the log and says NOT MEASURED; the `gate_note` stays.
- The self-test (skill `selftest`, tools `gate_selftest_prepare` and `gate_selftest_check`) makes a
  throwaway repository and a bare remote in a temporary folder. The repository declares a stale subject and
  tracks a named branch on the bare remote (so the push resolves, D3); the model runs one `git push` to
  that branch, which the gate is expected to deny. The check reports, observation-near, whether the gate
  logged that deny and whether the throwaway remote's target moved from the OID it stored at prepare:
  "Expected denial logged; test target unchanged." (the host kept the push out), "Expected denial logged;
  test target changed." (the host let it through), "Test target changed; no matching gate event observed."
  (the hooks did not run), or NOT MEASURABLE. Every result carries the limit that the log is local, so this
  is a local diagnosis, not an independent proof of the host's hook. It never pushes to a real remote; the
  check refuses any folder it did not create, and takes no special path for the self-test in the gate. The
  skill runs only when the user invokes it. The time window gate_status reports where there is no host
  session id is labelled as a window since the server started, not a session.

Options:
- A. A local log per host data directory, read by the server where the host names it (chosen).
- B. No log; the gate note alone.
- C. A fixed path shared by both hosts, which the server would have to guess.

## D22. The same check in CI

Chosen (smallest variant, 2026-09-30, for the owner's review):
- `proofbundle_gate.py ci-check --repo DIR --require-declaration true|false` runs the gate's own
  evaluation of HEAD (`evaluate_repository`), the same code as before a push, and prints one JSON report.
  Exit 0 only when every declared item verified and names the tree of HEAD (`verified`), or when nothing
  is declared and the input says the repository need not declare (`not_required`). Exit 1 for a missing
  declaration where one is required (`declaration_required`), for every other NOT MEASURED
  (`not_measured`) and for every deny, including a verifier that cannot start (`failed`). Exit 2 for a
  wrong call, without a report.
- Whether a repository must declare is the workflow input `require-declaration`, a required boolean
  without a default, never a field of the declaration. Deleting the declaration therefore cannot switch
  the check off where the workflow requires one.
- The CI mode checks HEAD of the checkout and has no revision option. The absence check of D5 reads the
  working tree, which is HEAD's; another revision would be judged against a working tree of another state.
  The template checks out the head of a pull request, not GitHub's merge commit, because the declaration
  names the tree of the commit that is pushed.
- The push range of D20 is not read in CI: a checkout holds no remote-tracking refs, and the question
  "does this change the evidence rules" belongs to review. The CODEOWNERS template puts `.proofbundle/`,
  the two workflows and CODEOWNERS itself under a required code owner review. The pass text of the CI
  mode says the rules were not compared, instead of the push text.
- `required=false` with nothing declared exits 0. That keeps the check usable in a repository that has
  not declared yet; the report says `not_required` and NOT MEASURED, never verified.
- The templates live in `ci/` of the plugin, not in proofbundle's own `.github/`. The workflow is a
  reusable one (`workflow_call`) that the repository copies and calls; it takes the gate from a full commit
  SHA of b7n0de/proofbundle and fails its first step on anything else. Its action pins are copied from
  proofbundle's own workflows and were not re-checked against GitHub.
- A pull request can change the workflow it runs under, including the input. The check protects only
  together with the CODEOWNERS template and a rule that requires the code owners' review; `ci/README.md`
  says so.

Options:
- A. The gate's evaluation of HEAD with the requirement as a workflow input, no range, CODEOWNERS for the
  rules (chosen).
- B. Also compare the rules with the base branch of a pull request, fetched in CI. More code and a fetch,
  and it still depends on the workflow the pull request can change.
- C. The requirement as a field of the declaration or a file under `.proofbundle/`. Deleting the file
  would switch the check off.
- D. A `--rev` option. Rejected, see the third point.

## D23. Evidence from the test run itself

Measured first (2026-09-30, PyPI 6.1.0, pytest 9.1.1, inspect_ai 0.3.266): the package's pytest receipt
names no commit, no tree and no command, and signs passed true for a run that exited 1 when the pass rate
meets the threshold. The Inspect receipt names Inspect's 7-character short commit and drops the dirty
state its own log records. Neither names the tree digest the gate checks.

Chosen (smallest variant, 2026-09-30; the report binding tightened after the review's F6, F7, N7 on
2026-10-01):
- `proofbundle_gate.py run-evidence --repo DIR --out FILE [--timeout S] -- COMMAND...` runs a named
  pytest command in the repository, without a shell, with `-p no:cacheprovider --junitxml=<a file outside
  the repository>` added and PYTHONDONTWRITEBYTECODE=1 set.
- The command must have a supported pytest form, and every testsuite in the report must carry the name set
  for this call (a fresh random `junit_suite_name`). This rejects a program that is not pytest and an
  unchanged report from another invocation. It does not authenticate the executable or the reported test
  activity: code of the repository that runs under pytest (a conftest.py, a plugin) can still write the
  report itself; see the limit below (review F6, F7, N7).
- Before the run the working tree, as `git add -A` would stage it on top of HEAD through a temporary index,
  must have the tree digest of HEAD. After the run HEAD must be the same commit and the working tree must
  still have that digest. Files git ignores are not compared, and they can influence the run.
- Exit code and counts come from the run: the process exit code, and tests, failures, errors and skipped
  from the JUnit report it wrote. There is a statement only for exit 0, no failure, no error, at least one
  passed test and counts that add up. A timeout, a missing or unreadable report, or an existing output file
  gives none.
- The statement is `{"subject": <the tree digest of HEAD>, "run": <the record>}`. The record names the
  commit, the digests before and after, the command as run, the program's path and sha256, the exit code,
  the counts, the report's sha256, the start and end time, the platform and the gate version. It holds no
  environment value.
- Nothing is signed by the tool. Signing stays experimental and runs only on the user's explicit request,
  with the pinned package: `proofbundle emit --payload-file FILE --out .proofbundle/<name>.bundle.json
  --key KEY`. The declaration is unchanged, kind `bundle`.
- The gate accepts a bundle payload with the keys `subject` and `run` beside the plain subject statement,
  and asks every run record the same questions, whoever made it: the schema and its exact keys, both digests
  equal to the subject, exit code 0, no failure, no error, at least one passed, counts that add up, and a
  command. Otherwise it answers deny `not_bound` and names what the record shows. A signed record that
  reports a red run never binds; the gate reads the recorded values, not the run. A supplied run record
  must report a green run. Subject-only evidence remains accepted and does not attest a test run.
- What the record proves is what the gate proves: who signed it and which tree it names. The runner records
  the process exit code, the JUnit counts and matching repository digests before and after the run. The
  gate checks the signed record, not whether the reported tests actually executed. Ignored files, external
  dependencies and temporary changes during the run are outside this binding: a test can edit a file and
  restore it before the run ends, and repository code under pytest can write the report.

Options:
- A. The tool above and the gate's check of a run record (chosen).
- B. Record the tree digest and the dirty state in the package's pytest plugin and Inspect hook. That is
  production code under `src/`; it ships only after 6.2.0, and the plugin pins 6.1.0.
- C. A new evidence kind in the declaration that requires a run record, so a plain subject statement no
  longer suffices. Larger: the declaration schema, the rules of D20 and the CI mode.
- D. Run the command in a fresh clone of HEAD. It keeps ignored files out, but not an editable install
  that imports the working tree; more code for a partial gain.
- E. An MCP tool that runs the command. A new execution surface over MCP; Bash already runs commands.
- F. Inspect evals. Not in this variant; they need their own runner and log reading.
