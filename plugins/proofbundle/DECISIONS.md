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

- The verification runs at **three levels** (Nachtrag 15), which see different things and stay apart:
  - **Level 1, this `PreToolUse` gate, is not a security boundary.** It reads the shell command before it
    runs and resolves the repository a push acts on only for one **strict simple command** headed by a bare
    `git`/`git-push`/`gh`; everything else is NOT MEASURED. The earlier closed grammar (Nachtrag 12) still
    resolved a `cd`/`&&` chain and a subshell; the reviewer showed (Runde 4) that a shell interpretation is
    not a safe basis for a boundary, so Level 1 narrows to the one form whose repository is certain. The
    modeled form:
    - No control operator and no expansion anywhere: a `;`, `&&`, `||`, `|`, `&`, newline, a subshell `( … )`,
      a brace group `{ … }`, a here-document, and any `$…`/`` `…` `` substitution each make it NOT MEASURED.
      There is no `cd`: a directory change is NOT MEASURED, because the gate no longer tracks it (Punkt 6).
    - At most one literal `git -C <dir>`, joined onto the working directory and resolved **physically**
      (`realpath`, so a symlinked `-C` names the same repository git walks to, review R4-2). A second `-C`,
      `--git-dir`, `--work-tree`, `--namespace`, `--exec-path`, `--no-pager`, or any other git global option
      is NOT MEASURED (R4-6).
    - Prefix assignments only from a narrow list checked to select no program (`GIT_TERMINAL_PROMPT`,
      `GIT_TRACE*`, `LANG`, `LANGUAGE`, `LC_ALL`, `LC_CTYPE`, `LC_MESSAGES`, `TZ`). A name that selects a
      program — `GIT_PAGER`/`PAGER`, `GIT_EDITOR`/`EDITOR`/`VISUAL`/`GIT_SEQUENCE_EDITOR`,
      `GIT_ASKPASS`/`SSH_ASKPASS` — counts only with a checked value (a pager of `cat` or empty, an editor or
      askpass helper of `true` or `:`), because the environment is configuration by another name
      (`GIT_EXTERNAL_DIFF` is `diff.external`, `GIT_SSH_COMMAND` is `core.sshCommand`; Runde 6, R6-2).
      Every other command-level assignment — `PATH`, every other `GIT_*`, and the configuration names
      (`GIT_CONFIG_*`, `HOME`, `XDG_CONFIG_HOME`) — makes the call NOT MEASURED, the bare `git --version`
      included, and so does such an assignment anywhere in a chain, behind `env`,
      through `export`, or in an enclosing command for a nested `bash -c` (Runde 6).
    - `git` counts only as a bare word; a `git` by a path (`/usr/bin/git`) is NOT MEASURED. A wrapper
      (`env`, `sudo`, `command`, …), a shell keyword, a function, `eval`/`source`, and a nested shell
      (`bash -lc`, `sh -c`, the `-lc`/`-cl`/`-ilc` bundles) are NOT MEASURED — but the scan still SEES the
      push inside them, so a nested push is NOT MEASURED, never passed off as checked. Trailing output
      redirections (`2>&1`, `> f`) are read and dropped.
    - A command that would turn off the real-push check is **denied**, not resolved: `git push --no-verify`,
      a command-level `core.hooksPath` override (`git -c core.hooksPath=…`), or `git config core.hooksPath …`
      (Punkt 5). The deny holds whatever the directory, so it holds inside a chain too.
    - **No git form is free except the bare `git --version`** (review Runde 9, owner choice B, 2026-10-03;
      the subsection below). Every git form that acts on a repository is NOT MEASURED: asked under Claude
      Code, denied under Codex. The free list of Nachtrag 19b, its per-entry option tables and its read of the
      repository state are removed. The subcommand list in the gate (`_GIT_LOCAL_SUBCOMMANDS`) now only picks
      the reason: a listed local subcommand asks as a repository form (`git_form_not_free`), any other
      subcommand — `send-pack`, an unknown word, every form of `rebase`, `bisect` and `submodule` — asks as a
      possible transfer (`possible_unmodeled_push`, `_MAYBE_PUSH`). Neither is free in any form, with any
      option or in any repository.
    - A per-command `git -c alias.*` (or `--config-env` of an alias) is NOT MEASURED even when the word
      `push` is absent and the subcommand is a local one, because the alias may name any command,
      a push included (Runde 5, Punkt 7).

    Because Level 1 cannot see through the shell, a push it leaves NOT MEASURED is not one it has checked. A
    NOT MEASURED answer asks (and on Codex, or under `claude -p`, denies), so Level 1 blocks rather than
    passes; it is a convenience and a record, not a boundary. No protection beyond what is measured here is
    claimed.
  - **Level 2 (prototype, D24)** is the git `pre-push` hook: it judges git's own ref lines, so it sees the
    real push whatever shell form launched it, and verifies the evidence there — but only for a push git
    actually invokes the installed hook on, and only when the required objects are readable locally. It
    narrows, it does not close, what Level 1 leaves NOT MEASURED. Measured in test fixtures only; not
    installed by the plugin; protection against every disallowed transmission is enforceable only on the
    receiving side.
  - **Level 3 (D22)** is the CI check at HEAD, off the contributor's machine: the enforcement point.
- A shell `git push` resolves its targets from the command and local configuration (`resolve_push_targets`):
  the remote must be a configured name, not a URL or path; each refspec maps to a branch or tag on the
  remote with a local remote-tracking ref that the remote's fetch refspecs map that branch to and nothing
  else, so the ref records the state of that branch and not another (review R3-2). There is no default-branch fallback: a new
  branch or tag, or any branch this repository does not track, has no known earlier state and is NOT
  MEASURED (N1). `--all`, `--mirror`, `--tags`, a wildcard or negative refspec, a configured
  `remote.<name>.push`, a mirror remote or `push.followTags` add updates the command does not name, so the
  push is NOT MEASURED (N2). Only a narrow list of target-neutral options is read; `--` ends option
  parsing; an abbreviation (git takes `--mir` for `--mirror`), `--repo`, or any option the gate does not
  model is NOT MEASURED (review R3-1). `--receive-pack` and its alias `--exec` are not neutral: they name
  the program that runs as the receiving end, which a path or `file://` transport starts on this machine
  (Runde 6, R6-2 class). Git booleans are read as git reads them (`1`, `yes`, `on` are true),
  and a value git cannot read is NOT MEASURED (R3-3). A bare `git push` resolves only under a push
  configuration the gate can model faithfully (`push.default` simple/current/upstream, no extra ref
  updates).
- The push endpoint must be one URL, equal for fetch and push, so the remote-tracking ref records the state
  of the endpoint the push updates. A `pushurl` or a second `remote.<name>.url` sends the push elsewhere or
  to a further endpoint and is NOT MEASURED (Befund 1). A `url.<base>.insteadOf` **or**
  `url.<base>.pushInsteadOf` rewrite that applies to this remote also makes the push NOT MEASURED (review
  R4-7, Runde 5 Punkt 9). Which rule applies is resolved by git's own rules (Runde 6, Punkt 2): an
  `insteadOf` rule rewrites a configured `url` or an explicit `pushurl` it is the longest matching prefix
  of; a `pushInsteadOf` rule rewrites the push side of a `url`, and git ignores it for a remote with an
  explicit `pushurl`. A rule that provably matches none of this remote's URLs is excluded, so a common
  global rule for another host no longer turns every push NOT MEASURED. A rule that does apply keeps the
  comparison NOT MEASURED even when the effective fetch and push URLs are equal: equal URLs do not prove
  where the existing tracking ref came from (a rule configured after the last fetch rewrites both), and
  how common a rule is (an SSH rewrite, say) is no reason to release a comparison it applies to. A stale
  remote-tracking ref without any rewrite stays possible (POSSIBLE) on Level 1, as an expressly limited
  verdict: the push is still resolved and compared, but every comparison verdict (pass, inactive, a
  rules change, a deletion) says it is against the last known state of the target in this repository,
  not a state read from the remote, never the actual rule change on the remote (R4-7K); Level 2 makes the
  authoritative comparison when it runs and can read the objects, and its verdicts say they compare
  against the remote's state as git reported it.
- A NOT MEASURED target comparison does not hide a measurable failure at the source (Runde 6, Befund 1).
  When the commits a push sends are uniquely determined from the command and the local branch (each
  literal refspec source, or the current branch of a bare push git pushes alone) in the uniquely bound
  repository, the gate checks their evidence even though it cannot resolve the comparison; a proven
  evidence failure stays a deny, and the comparison it could not measure is named separately in that
  verdict. A source that passes is never a verdict on the push: the push stays NOT MEASURED. When the
  source is unclear (`--all`, a wildcard, an unmodelled option, a detached HEAD, `push.default`
  matching), no check of HEAD stands in for it, so there is neither a positive verdict nor a deny derived
  from HEAD. The same holds in the shared core for a target ref that does not exist and for a range the
  gate cannot list. Under Level 1 any
  `git -c`/`--config-env` global option already makes the directory NOT MEASURED before the target is read
  (the configuration the gate's separate reads cannot see can no longer reach `resolve_push_targets`); a
  `GIT_CONFIG_*` injection in the environment is read by the gate as the push reads it, because the gate's
  git runs in the push's own environment.
- For each target the gate evaluates the evidence at every commit the push newly sends, not only the tip,
  so a valid tip cannot heal an intermediate commit that removes the declaration or carries evidence that
  does not verify (N3). A shallow clone, or a range of more than 64 commits (the gate cannot evaluate it
  inside its deadline), is NOT MEASURED. Every gate read runs with replace refs and `.git/info/grafts`
  turned off, so the gate judges the objects and ancestors the push transfers, not a local rewrite of them
  (review R3-8).
- A `gh pr create` or `gh release create` is judged as a push of the current branch to its upstream.
- An unresolved push is asked under Claude Code and denied under Codex (D12). The D5 inactive shortcut
  applies only when the push resolves and every sent commit and the target's state declare nothing; an
  unresolved push never switches the gate off (N2).

Options:
- A. HEAD only, refspec not read (the pre-review behaviour; a push of another branch was judged at HEAD).
- B. Every newly reachable commit per resolved target, unresolved is NOT MEASURED (chosen).
- C. Treat a push whose refspec is not the current branch as NOT MEASURED (too coarse: it would miss a
  bare push of a branch the gate can resolve).

### D3, no git form is free (review Runde 9, owner choice B, 2026-10-03)

Chosen (owner, 2026-10-03): option B, remove the free list. Under Claude Code the gate gives no free answer
for any git form that depends on a repository; every one asks. Under Codex every one is denied (D12). The one
form that stays free is the bare `git --version`, as exactly that command text: no program path, no wrapper,
no chain, pipeline, background job or here-document, no substitution, no prefix assignment, no redirection
and no predecessor in the same command. Every other spelling of it asks (reason id `git_form_not_free`).

Why. The free list of Nachtrag 19b read the bound repository's configuration, hook directory and the hook's
environment and left an allow-listed form free when none of the keys, variables or hooks of its row was
present. Review Runde 9 showed git starting programs through configuration values, attribute selections and
side paths that list did not know: numeric true values (`log.showSignature` of `2`, `1k` or `0x1` for
`git log` and `git show`, the same numbers in `commit.gpgSign` for `git commit`), drivers with an empty name
that an empty `.gitattributes` value selects (`filter..clean`, `filter..smudge`, `filter..process`,
`diff..command`, `diff..textconv`, `merge..driver`), and an indirect path through automatic maintenance
(`gc.recentObjectsHook` after `git commit`). Each one could be added to the list, but the class stays open, so the
list is removed, not patched. A free list comes back only with an owner choice of its own.

Removed, not patched: the per-entry profiles, the key and environment families, the option tables, the read
of the repository state for a free form, and the table this section carried until review Runde 9.

Kept:
- the push resolver and its NOT MEASURED cases (above), and the deny of a form that would turn off the
  real-push check;
- the write gate for the repository's configuration and hooks (D8), which still reads the effective
  configuration files and the effective hook directory, only to protect them from a file tool;
- the locks on the gate's own git calls: the refusal to read objects from a partial clone and
  `GIT_NO_LAZY_FETCH=1` (review Runde 7, R7-7), no filter, hook or fsmonitor in the diagnosis, in
  `tree-digest` and in `run-evidence` (review Runde 8, R8-1).

The gate's own git calls use the subcommands `rev-parse`, `config`, `ls-tree`, `cat-file` (also
`--batch`, without `--filters` or `--textconv`), `rev-list`, `symbolic-ref`, `remote`, `var` and
`ls-files` (counted in the gate's source). None of them is `log`, `show`, `commit`, `tag`, `add`, `restore`,
`checkout`, `diff`, `merge` or `stash`, the commands through which the review's values start a program, so
the gate itself reads none of these values in a way that starts a program. That none of these subcommands
runs automatic maintenance is read from the git documentation, not measured.

What a person can do: answer the question, or run the call outside the agent. The answer of the host is not
read back by the gate; nothing is remembered between calls.

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
- Since review Runde 9 (owner choice B, D3) every other git form that acts on a repository is gated too,
  found the same way: it is NOT MEASURED, asked under Claude Code and denied under Codex. Only the bare
  `git --version` is not gated.
- MCP tools, through a second `PreToolUse` matcher,
  `^mcp__.+__(create_pull_request|create_merge_request|create_release|push_files|create_or_update_file|merge_pull_request)$`,
  on any server. Both hosts name an MCP tool `mcp__<server>__<tool>` in the hook event, and both read a
  matcher like this one as a regular expression (Codex at c248f6d4: `hooks/src/events/common.rs`,
  `matches_matcher`). The repository is the hook's working directory; the tool's own arguments (owner,
  repository, branch) are not read.
  - Gated tool names: `create_pull_request` (the GitHub MCP server, as `mcp__github__create_pull_request`),
    `create_merge_request` and `create_release` (names other servers use; which servers, not measured),
    and the GitHub MCP server's `push_files`, `create_or_update_file` and `merge_pull_request`.
  - A gated MCP write is NOT MEASURED, asked under Claude Code and denied under Codex (Runde 6, R6-1): the
    hook binds neither the tool's actual target nor the bytes it writes. It cannot see the branch a tool
    publishes or the pull request `merge_pull_request` merges, and the bytes `push_files` and
    `create_or_update_file` write come from the tool's own arguments. The local repository at the hook's
    working directory never decides the call — not pass, not inactive, and not a deny for a foreign
    target; its HEAD is still checked and named in the answer as a diagnosis only. Every gated MCP call
    therefore gets a permission decision; none ends without one. The host is passed to `decide_mcp`.
  - Ungated, and listed as such: every other name. Open, the owner kept them out of the gate on
    2026-09-29: `delete_file`, `create_branch`, `update_pull_request`, `update_pull_request_branch` and
    `enable_pr_auto_merge`, which write to a remote without opening a pull request. Also ungated:
    `fork_repository` and `create_repository`. A tool of another server with a different name for the
    same act is not gated either.

- File tools (Nachtrag 19b, Punkt 6 to 8), through a third `PreToolUse` matcher, `^(Write|Edit|MultiEdit|NotebookEdit)$`
  under Claude Code and `^(apply_patch|Write|Edit|MultiEdit|NotebookEdit)$` under Codex. A write to a
  repository's configuration or hooks is NOT MEASURED, asked under Claude Code and denied under Codex
  (reason id `write_to_repo_state`): `.git/config`, `config.worktree`, `commondir` (also a missing one, which
  a write would create; review Runde 8, R8-4), a `.git` file, any file under the
  effective hook directory, every file the effective configuration was read from or includes from any origin
  (also an empty included file, and one that does not exist yet, which a write would create; an include the
  host injects through `GIT_CONFIG_COUNT`, origin `command line:`, counts like one from a file), and the
  global and system files (`git var GIT_CONFIG_GLOBAL`/`GIT_CONFIG_SYSTEM`, the defaults when unset), for the
  repository the target lies in and for the bound repository. The target counts as written and as resolved:
  a hook path that is a symlink to a file outside is still a hook path, and the file a hook entry resolves
  to, or a hard link to it or to a configuration file (compared by file identity), is protected under its
  own path too (review Runde 7, R7-5; measured is the gate's decision, not a host's file change); a
  path the gate cannot map for sure (a relative path without a known directory, an `apply_patch` with
  `*** Environment ID:` or a `***` line the gate does not read) is NOT MEASURED. Every other write gets no
  decision under Claude Code; under Codex every file-tool write is NOT MEASURED and denied, because the hook
  does not bind it to the filesystem and directory it acts in (D12; review Runde 7, R7-6).
  Host integration (review Runde 7, question 4). Measured in one real Claude Code run, 2026-10-03, Claude
  Code 2.1.288, `claude -p` with `--permission-mode acceptEdits`, the plugin loaded with `--plugin-dir` at
  5b22cc9b, git 2.43.0: in a fresh repository whose `.git/config` includes `../extra.gitconfig`, a Write to
  `extra.gitconfig` in the run's directory reached the gate (gate log: `ask`, `write_to_repo_state`), the
  reason named that path in that directory, the host refused the call (`permission_denials`) and the file
  stayed absent; a control Write to `notes.md` reached the gate (`not_gated`) and was written. One run, one
  permission mode, one tool; the other file tools and modes are not measured in a run. Codex: NOT MEASURED in
  a run (D16). Not judged: a write made by a shell command (a redirection, `cp`, `chmod` in a Bash call),
  through an MCP tool, or by a program the user starts; the matcher covers the file tools only.

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

Isolation from the checked repository (review N4, R3-4): the host starts the gate itself with `python3 -I`
(hooks/hooks.json and .codex-plugin/plugin.json) and the MCP server with `uv --no-config` (.mcp.json and
.codex-plugin/plugin.json); the gate in turn starts the verifier from an empty temporary directory, with
`uv --no-config` and every `PYTHON*` environment name stripped, and the server runs the command line with
`python -I` from an empty temporary directory. So no file of the checked repository decides which code runs:
not a `proofbundle/` folder on the interpreter's path, not a `uv.toml` or `pyproject.toml`, not an inherited
`PYTHONPATH`, and, with `python3 -I` at the host start, not a `sitecustomize.py` that would otherwise run
before the gate's own isolation (review R3-4 measured such a bypass without `-I`). Under Codex the server's
manifest entry sets `cwd: "."`, so the server starts in the plugin directory, not the checked repository.

Two boundary sentences name the limit of this guarantee. From round 2: the interpreter installation and the
user's own environment (PATH, uv, UV_* variables) remain trusted inputs. From round 3: the plugin can read
the manifests' start commands but cannot observe the host run them, so a test of the manifests measures the
path composition and the start command, not an actual host start, and the host's faithful use of the
command as written is itself a trusted input. The reason for the second sentence is the round-3 finding:
isolation that begins only inside the gate's code leaves a `sitecustomize.py` to run before it, so the start
command must carry `-I`, and only the host can be trusted to invoke the manifest's command.

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

EVERY PUSH IS NOT MEASURED UNDER CODEX (owner choice A, 02.10.2026, R5-2)
- Under `--host codex` every push Ebene 1 would otherwise resolve is NOT MEASURED and therefore denied, not
  only the pushes Claude Code would leave NOT MEASURED.
- The reason is the hook's input, not the repository's evidence state: the Codex PreToolUse hook receives the
  session directory and the command text, not the execution workdir or a remote environment, so it could
  judge a different repository than the push acts on.
- `gh pr create` and the other gated shell calls are denied the same way.
- Under Claude Code nothing changes.
- MCP tools are a separate path: a gated MCP write is NOT MEASURED on both hosts and denied under Codex
  (Runde 6, R6-1; D8).

THE CODEX EXECUTION MODEL IS AN ASSUMPTION, NOT A MEASURED FACT
- Codex is often described as running a command through a login shell (`bash -lc …`), but that is not
  absolute: `login:false` is possible, and without a setting the configuration decides.
- The shell, its startup files and the program resolution are assumptions to be checked at a real host start
  (owner machine, not a cloud session), not measured facts.
- `write_stdin` fed to a running command after the PreToolUse hook has no hook of its own, so the gate does
  not check input fed in later.

CODEX SOURCE PINS
- `codex-rs/core/src/hook_runtime.rs` at 14a477ea89712071944244022e8a10142845456e — the PreToolUse hook
  payload and its `cwd`.
- `codex-rs/core/src/tools/handlers/unified_exec/exec_command.rs` at 14a477ea89712071944244022e8a10142845456e
  — where the per-call workdir is applied at execution.
- The other pin `c248f6d4` gives the same `{"command": args.cmd}` as the tool_input handed to the hook.

### Messauftrag R5-2 (Entscheidungsvorlage, nicht umsetzen)

MEASURED (read from the Codex source at 14a477ea this session, not from a Codex run):
- The PreToolUse hook payload (`PreToolUseRequest`, `hook_runtime.rs` lines 138-149) includes
  `transcript_path` (line 142) and `tool_use_id` (line 145).
- Its `cwd` (line 141) comes from `tool_hook_cwd` (lines 152-157), which prefers a local-environment path and
  otherwise the turn context cwd — i.e. the session/turn directory, not the per-call workdir.
- There is no `environment_id` in the payload.
- The per-call workdir is applied at execution as `native_environment_cwd.join(workdir)` (`exec_command.rs`
  line 201) and comes from the model's arguments.
- The tool_input handed to the hook is only `{"command": cmd}`.

OPEN (NOT MEASURED this phase, needs the dispatch-layer source or a real host run):
- Whether the tool-call record carrying workdir is written to the file at `transcript_path` BEFORE the
  PreToolUse hook fires, and is keyed by `tool_use_id`, so the gate could recover workdir.

DECISION TEMPLATE (do NOT implement anything):
- IF that ordering holds, a future change could have the gate read `transcript_path`, find the `tool_use_id`
  entry and recover the real workdir to resolve the repository.
- UNTIL it is measured at a real host start (owner machine, not a cloud session), owner choice A stands:
  every Codex push is NOT MEASURED → deny.
- EVEN THEN the transcript workdir is model-influenced content, so the gate may trust it only if Codex
  guarantees it equals the execution workdir.

DECISION AFTER REVIEW RUNDE 6 (Nachtrag 19; the reviewer's decision, recorded here in substance)
- No transcript path is built. The better route is a context that Codex itself binds to the hook for the
  call it is about to run: the effective execution directory and the execution environment of that same
  call.
- The source reading supports the block, not a working transcript path: at pin 14a477ea the workdir is
  resolved for execution, but the PreToolUse input carries only the command; the hook's cwd does not stand
  in for that binding.
- That the model chooses workdir does not by itself disqualify it; the command comes from the model too.
  What matters is that Codex assigns the value to the very call it executes. A transcript path would in
  addition have to show untampered origin, timely availability, an unambiguous assignment to the call, and
  the effective environment; `tool_use_id` together with a file path does not establish that binding.
- Until Codex reliably binds the effective execution directory and the execution environment for the same
  call to the hook, and that binding has been checked, gated shell calls under Codex stay NOT MEASURED and
  denied.

GIT FORMS AND FILE WRITES UNDER CODEX (Nachtrag 19b, Punkt 7; review Runde 9)
- Since review Runde 9 (owner choice B, D3) no git form that acts on a repository is free on either host:
  it asks under Claude Code and is denied under Codex, with the same reason id `git_form_not_free`. A
  literal `-C` binds nothing on either host. Only the bare `git --version`, exactly that text, reads no
  repository and stays free (review Runde 7, question 5: "every git form" was too broad). A bare `git`
  without a subcommand is no longer free.
- MEASURED in the Codex source at 14a477ea89712071944244022e8a10142845456e (read, not run): the dispatcher
  asks every tool for a PreToolUse payload (`codex-rs/core/src/tools/registry.rs` line 602); a function
  tool fires the hook under its own name with its JSON arguments (lines 133-142, 833-842); `apply_patch`,
  the tool that edits files, fires it with `tool_name` `apply_patch` and `tool_input`
  `{"command": <the raw patch>}` (`codex-rs/core/src/tools/handlers/apply_patch.rs` lines 289-295 and
  414-419), and a hook matcher written as `Write` or `Edit` also selects it
  (`codex-rs/core/src/tools/hook_names.rs` lines 34-39). Shell-like tools carry `Bash` (same file, lines
  53-56) and can write files too; the gate judges only their git and gh calls (D8).
- The gate reads the target paths from the patch's `*** Add File:`, `*** Update File:`, `*** Delete File:`
  and `*** Move to:` lines. A patch path without an environment line resolves against the turn's primary
  environment (`codex-rs/core/src/tools/handlers/mod.rs` lines 160-178; the grammar's
  `*** Environment ID:` line, `codex-rs/apply-patch/src/parser.rs` line 8), while the hook's `cwd` is the
  local environment's (`codex-rs/core/src/hook_runtime.rs` lines 248-253, `tool_hook_cwd`).
- Every file-tool write under Codex is NOT MEASURED and denied (`codex_write_unbound`; review Runde 7,
  R7-6). When the primary environment is not the local one, a patch path names a file in a filesystem the
  hook does not see, and the hook input carries nothing that binds the write to the filesystem and directory
  it acts in; a missing environment line is no proof of binding, so the gate cannot tell for any path
  whether it is configuration or a hook. This makes the plugin's write path unusable under Codex until such
  a binding is carried. Whether Codex fires the hook for `apply_patch` in every approval mode is read from
  the source, not measured in a run.

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
  logged that deny and whether the throwaway remote's target still equals the OID it stored at prepare:
  "Expected denial logged; test target unchanged.", "Expected denial logged; test target changed.", "Test
  target changed; no matching gate event observed.", or NOT MEASURABLE. A missing, empty or invalid stored
  base OID is not a comparison value: the target then cannot be compared and the result is NOT MEASURABLE,
  never read as changed or unchanged against an empty string (review R3-5). Every result carries the limit,
  verbatim: "The results report whether an expected deny entry was found and whether the target still
  equals the recorded base OID. They do not establish why an observation is missing. NOT MEASURABLE means
  the observations do not support another result. The limit applies to every result." (review R3-6), and
  the round-2 caution that the log is local, so this is a local diagnosis, not an independent proof of the
  host's hook. It never pushes to a real remote; the
  check refuses any folder it did not create, and takes no special path for the self-test in the gate. The
  skill runs only when the user invokes it. The time window gate_status reports where there is no host
  session id is labelled as a window since the server started, not a session.

Options:
- A. A local log per host data directory, read by the server where the host names it (chosen).
- B. No log; the gate note alone.
- C. A fixed path shared by both hosts, which the server would have to guess.

## D22. The gate's evaluation of HEAD in CI, without the rules comparison of D20

Chosen (smallest variant, 2026-09-30; the tag and review notes added after the review's N8, N9 on
2026-10-01):
- `proofbundle_gate.py ci-check --repo DIR --require-declaration true|false` runs the gate's own
  evaluation of HEAD (`evaluate_repository`), without the push range, and prints one JSON report.
  Exit 0 only when every declared item verified and names the tree of HEAD (`verified`), or when nothing
  is declared and the input says the repository need not declare (`not_required`, a waiver, not verified).
  Exit 1 for a missing declaration where one is required (`declaration_required`), for every other NOT
  MEASURED (`not_measured`) and for every deny, including a verifier that cannot start (`failed`). Exit 2
  for a wrong call, without a report. CI fails every required check that is NOT MEASURED; with
  require-declaration false and no declaration it returns not_required, not verified.
- Whether a repository must declare is the workflow input `require-declaration`, a required boolean
  without a default, never a field of the declaration. Deleting the declaration therefore cannot switch
  the check off where the workflow requires one.
- The CI mode checks HEAD of the checkout and has no revision option. The absence check of D5 reads the
  working tree, which is HEAD's; another revision would be judged against a working tree of another state.
  The template checks out the head of a pull request, not GitHub's merge commit, because the declaration
  names the tree of the commit that is pushed.
- The push range of D20 is not read in CI: a checkout holds no remote-tracking refs, and the question
  "does this change the evidence rules" belongs to review. The CODEOWNERS template puts `.proofbundle/`,
  the whole of `.github/workflows/` and `.github/actions/`, and CODEOWNERS itself under a required code
  owner review. The pass text of the CI mode says the rules were not compared, instead of the push text.
- `required=false` with nothing declared exits 0. That keeps the check usable in a repository that has
  not declared yet; the report says `not_required` and NOT MEASURED, never verified.
- The templates live in `ci/` of the plugin, not in proofbundle's own `.github/`. The workflow is a
  reusable one (`workflow_call`) that the repository copies and calls; it takes the gate from a full commit
  SHA of b7n0de/proofbundle, fails its first step on anything else, and then requires the SHA to be
  contained in a `v*` release tag of b7n0de/proofbundle (`git tag --contains`, which allows an ancestor of
  a release tag and does not certify the SHA is the tagged commit). Its action pins are copied from
  proofbundle's own workflows and were not re-checked against GitHub. The gate runs under `python -I`.
- A pull request can change the workflow it runs under, including the input, or add one with a matching job
  name. The check protects only together with the CODEOWNERS template, a required code owner review, and
  dismissal of stale approvals on new commits; `ci/README.md` says so, and says the template is not measured
  on GitHub Actions.

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
- The command must have a supported pytest form, and the report must carry this invocation's random suite
  name. This rejects unsupported command forms and an unchanged report from another invocation; it does not
  authenticate the executable or the reported test activity. Code of the repository that runs under pytest
  (a conftest.py, a plugin) can still write the report itself; see the limit below (review F6, F7, N7,
  Befund 2).
- Before the run the working tree must hold exactly the files of HEAD's tree outside `.proofbundle/`: every
  committed file a regular file with the committed execute bit, or a symbolic link, whose own bytes (or
  link text) have the committed blob id, and no other file git does not ignore. After the run HEAD must be
  the same commit and the working tree must still hold exactly those files. Every intermediate component of a
  committed path must be a real directory, checked with lstat before and after the run whatever the ignore
  rules say; a symbolic link, another type, or a component the gate cannot check safely is refused (review
  Runde 9, R9-1: a directory replaced by a link to an outside directory with the same leaf bytes, hidden by an
  ignore rule, gave a green run for a tree on which the same test fails). The comparison runs no clean or
  smudge filter, line-ending or encoding rule, fsmonitor or hook, and models no checkout transformation. A
  working file whose bytes differ from its committed blob is refused before the run, including differences
  caused by checkout transformations. Until review Runde 8 (R8-1) the working tree was staged with `git
  add -A` through a temporary index, and a clean filter that wrote the committed value back let a run on
  another working file be recorded as a run on HEAD, measured by the reviewer. Files git ignores are not
  compared, and they can influence the run. The command is judged before the tree is read.
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

## D24. The pre-push hook is the second level (prototype)

Measured (Nachtrag 15, Runde 4): Level 1, the `PreToolUse` gate, reads the shell command, and the reviewer
showed across rounds 1 to 4 that no shell interpretation is a safe basis for a boundary — a chain, a
subshell, a wrapper, a nested shell (`bash -lc`), a `cd`, an expansion each move or hide the repository.
Level 1 answers those NOT MEASURED, which blocks under Codex and `claude -p` but is not proof. A git
`pre-push` hook runs at the push itself: git hands it, on stdin, one `<local ref> <local sha> <remote ref>
<remote sha>` line per ref, in the repository being pushed. From those lines the hook knows the exact
commits and the remote's own current state without parsing any command. It reaches a verdict only for
pushes git actually invokes the installed hook on, and only when the required objects are readable locally;
it is a bypassable prototype not installed by the plugin, and protection against every disallowed
transmission is enforceable only on the receiving side.

Chosen (a prototype, measured in test fixtures only):
- `proofbundle_gate.py pre-push <remote> <url>` reads the ref lines on stdin, builds one target per line
  (source = the local sha, None when all-zero for a deletion; dest = the remote ref; tracking = the remote
  sha, None when the remote has no such ref), and runs the same evidence core as a resolved shell push
  (`_evaluate_targets`). It exits 0 only for a pass and a measured inactive (nothing declared):
  `return 0 if verdict.decision in ("pass", "inactive") else 1`. An ask, an unknown state, a measurement
  error and any exception all block the push with exit 1. There is no release or approval switch in any
  environment the model can write or run: a rule change stays blocked, and a human handles it on a
  separately controlled path.
- A brand-new remote ref (the remote side all-zero, review R5-4) has no comparison state, so the gate
  cannot tell which commits the push newly sends. The chosen behaviour is NOT MEASURED with a block, not a
  traceback: the gate returns a NOT MEASURED verdict, which blocks the push, instead of running
  `git rev-list` with a `None` base. The reason: without a locally known target state there is no range to
  evaluate, so the push is reported unmeasured rather than crashing or being read as an absent target.
  A null object id for the remote side is a measured absence of the target ref, not an unreadable remote
  object (Runde 6, Befund 2), and the verdict says so verbatim: "NOT MEASURED: The target ref does not
  exist; this gate does not yet implement the history and initial-policy checks for creating it." Only
  this measured case carries that text; a push Level 1 cannot map to a local tracking ref keeps its own
  text. The block stays; `git rev-list <source> --not --remotes` is not a substitute (the reviewer showed a
  tracking ref of another remote can cover the whole source history while a middle commit carries an
  invalid declaration). A later measured path would have to check the whole reachable source history
  against the empty target and an explicitly defined initial-declaration policy, and stay blocked on an
  incomplete history or an exceeded limit. The evidence at the sent commit is still checked meanwhile; a
  proven failure there is a deny (Befund 1).
- It is a prototype. The plugin does not install it and sets no `core.hooksPath`, in the repository or
  globally; it is exercised only by a test that installs it in a throwaway repository's local
  `core.hooksPath`. Shipping it needs an install story a maintainer owns (where the hook lives, how it is
  trusted, how a contributor without the plugin is handled), which is out of scope here.
- `git push --no-verify` skips every pre-push hook, so Level 2 cannot see that form; that is why Level 1
  denies `--no-verify` and a command-level `core.hooksPath` override outright (Ebene 1, Punkt 5).
- Limit: the prototype judges the repository of the process it runs in (`git rev-parse --show-toplevel`
  from the hook's own working directory). A push driven from another directory with `GIT_DIR` set is not
  the modeled case; the realistic deployment is a hook in the repository the push runs from. The hook
  verifies the evidence at the pushed commits; like every level it proves what the evidence proves, not
  that any recorded value is true.
- Level 3 (D22, the CI check) stays the enforcement point a maintainer relies on, off the contributor's
  machine. The three levels see different things and are not substitutes for one another.

Options:
- A. A pre-push hook prototype, measured in tests, not installed (chosen).
- B. Ship and install the hook via `core.hooksPath`. Rejected here: it needs the maintainer's install and
  trust story, and a `core.hooksPath` the plugin sets is itself a surface (D should a plugin write git
  config). The owner decides.
- C. Rely on Level 1 alone. Rejected: the reviewer showed a shell gate is not a boundary.
- D. Rely on Level 3 (CI) alone. The honest fallback, but it catches a bad push only after it reaches the
  remote; Level 2 catches it at the contributor's machine.
