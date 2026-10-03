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
      (`GIT_CONFIG_*`, `HOME`, `XDG_CONFIG_HOME`) — makes the call NOT MEASURED, a git call the allow-list
      would otherwise leave free included, and so does such an assignment anywhere in a chain, behind `env`,
      through `export`, or in an enclosing command for a nested `bash -c` (Runde 6).
    - `git` counts only as a bare word; a `git` by a path (`/usr/bin/git`) is NOT MEASURED. A wrapper
      (`env`, `sudo`, `command`, …), a shell keyword, a function, `eval`/`source`, and a nested shell
      (`bash -lc`, `sh -c`, the `-lc`/`-cl`/`-ilc` bundles) are NOT MEASURED — but the scan still SEES the
      push inside them, so a nested push is NOT MEASURED, never passed off as checked. Trailing output
      redirections (`2>&1`, `> f`) are read and dropped.
    - A command that would turn off the real-push check is **denied**, not resolved: `git push --no-verify`,
      a command-level `core.hooksPath` override (`git -c core.hooksPath=…`), or `git config core.hooksPath …`
      (Punkt 5). The deny holds whatever the directory, so it holds inside a chain too.
    - The git subcommand must be on a short allow-list of local built-ins that, per the git documentation,
      neither transfer objects to a remote nor run an arbitrary command, **and every option it carries must
      be vetted inert for that entry.** A subcommand name alone does not establish that an invocation cannot
      execute other programs; options and Git configuration can select helpers, filters, hooks or editors
      (Runde 6, R6-2). The allow-list is therefore a positive, per-entry check: an on-list subcommand is free
      only in a checked invocation form — its bare form, plus the options enumerated for that entry in
      `_GIT_VETTED_OPTIONS` in the gate, each checked against the git documentation to take no value or a
      value that is a number, a format string, a ref, a pattern or a pathspec, never a program, a file to
      execute, an editor, a pager, a filter, a transport helper or a config key. Any other option, and any
      NOT MEASURED already established earlier in the parse (for example a `-c`, which is never lost
      afterwards), makes the whole invocation NOT MEASURED. Four single exceptions would not close that
      class, so each entry is checked positively and an entry whose option space is not vetted is free only
      in its bare form. Reproduced and now NOT MEASURED (Runde 6): `git grep --open-files-in-pager=…`,
      `git fetch --upload-pack=…`, `git -c diff.external=… diff`, and `git rebase -x…` (the attached short
      form of `--exec`). Git-documentation sources for the option semantics: git-grep, git-fetch, git-diff,
      and git-config (URL rewrites and the per-command `-c`). A subcommand off the list is NOT MEASURED as a
      possible transfer, never resolved and never inactive (`_MAYBE_PUSH`). Off-list, and so NOT MEASURED:
      `send-pack`, an unknown subcommand, every form of `rebase`, `bisect` and `submodule`, the 43 entries
      that left the list in Nachtrag 19b (below), and any allow-listed subcommand carrying an unvetted
      option. On-list (bare, or with their vetted options): `fetch` and `ls-remote` (they receive, they do
      not publish) and `config` (but `git config core.hooksPath` is denied earlier, before the list is
      consulted); `pull` and `clone` left the list in Nachtrag 19b. `git config` itself is
      free only as a read (`--get`, `--get-all`, `--get-regexp`, `--list`, `git config get|list`) or as a
      write of a key checked to select no program (`user.name`, `user.email`, `init.defaultBranch`,
      `color.ui`, `core.autocrlf`, `core.quotePath`, `pull.rebase`, `pull.ff`, `fetch.prune`,
      `push.default`, `advice.detachedHead`); a write of any other key (`diff.external`, `core.editor`,
      `core.pager`, `filter.*`, `core.fsmonitor`, `core.sshCommand`, `credential.helper`,
      `remote.*.uploadpack`, `include.path`, …), `--edit` and `--file` are NOT MEASURED, because the key
      may select a helper for a later call (git-config). Since Nachtrag 19b (review S1) Level 1 no longer
      reads the command text alone: before it leaves an allow-listed form free it reads the bound
      repository's effective configuration, its effective hook directory and the hook's own environment,
      and frees the form only when none of the keys, variables or hooks named for that entry in the table
      below is present. Named limits: an environment a session command exported earlier is not the hook's
      environment and is not seen; `PATH` and git's compiled-in default programs (the pager `less`, the
      editor `vi`, `ssh` for an SSH URL, `gpg`) are not keys and do not count. This is not a complete
      transport boundary and closes no indirect push it does not name (Runde 5, Punkt 4/6/8; Runde 6,
      R6-2).
    - A per-command `git -c alias.*` (or `--config-env` of an alias) is NOT MEASURED even when the word
      `push` is absent and the subcommand is otherwise allow-listed, because the alias may name any command,
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

### D3, the allow-list entries and what frees them (Nachtrag 19b, review S1)

Chosen (owner, Nachtrag 19b): option B, read the repository state, with option A, leave the list, as the
fallback for an entry whose list cannot be justified completely. An allow-listed form that passed the
command-text checks above is free only after the gate has read, in the repository the call is bound to and
with the hook's own environment:
- the effective configuration as git reads it (`git config --list --null --show-origin --show-scope`:
  system, global, local and worktree files, every included file, and the command scope a host injects
  through `GIT_CONFIG_COUNT` or `GIT_CONFIG_PARAMETERS`);
- the effective hook directory (`git rev-parse --path-format=absolute --git-path hooks`, which follows
  `core.hooksPath`); a hook counts only under its exact githooks(5) name and only when it is executable, as
  git starts it; a `*.sample` file never counts;
- the program-selecting variables of the hook's environment, with the neutral values named above for a
  command-level assignment.

The form stays free only when none of the keys, variables or hooks in its row is present. NOT MEASURED
instead (asked under Claude Code, denied under Codex): a directory the gate cannot bind (a `cd`, `pushd`,
`popd`, `source`, `eval` or `.` anywhere in the command, or `git` behind a wrapper, as a program path or in a
nested shell); a free form after another command of the same chain, in a pipeline, in the background, with a
here-document or with a command substitution anywhere in the command, because an earlier command can change
the configuration or the hooks before the form runs and the gate models no such predecessor (review Runde 7,
R7-4; only the first run of a sequential chain is read in the state before the command);
a configuration git itself cannot read (an include that names a directory, broken syntax: measured, git
exits 128; a missing include git skips, as git does); git output of a shape the gate does not expect; and
every free form under Codex, whose hook does not receive the directory the command runs in (D12). The
reason id is `repo_state_selects_program`, `repo_state_unreadable` or `repo_state_unbound`.

Sources: the git v2.43.0 documentation (git-config(1), githooks(5), gitattributes(5), git(1), git-var(1),
git-init(1), pretty-formats) and source (read-cache.c, fsmonitor.c, pretty.c, ref-filter.c, setup.c), the
git version of the measuring environment. Four rules rest on the source rather than the manual: an index
read queries the fsmonitor hook (read-cache.c `post_read_index_from` → `tweak_fsmonitor`, fsmonitor.c), so
`core.fsmonitor` counts for every entry; `%G` placeholders (pretty.c) and the ref-filter atom `signature`
(ref-filter.c) verify signatures, so such a value is NOT MEASURED attached or as the next word; log and
show verify only under `show_signature` (log-tree.c, set by `log.showSignature` in builtin/log.c) and stash
creates its commits without a signing key (builtin/stash.c), so `gpg.program`, `gpg.<format>.program` and
`gpg.ssh.defaultKeyCommand`, which choose the program but start none, do not count on their own, while every
key and option that starts signing or verification does. A hook counts for an entry only when githooks(5)
names it for that command (`commit`: pre-commit, prepare-commit-msg, commit-msg, post-commit, plus
reference-transaction, post-index-change and pre-auto-gc; `symbolic-ref`: reference-transaction, which git
2.43.0 does not start for a symbolic reference while git 2.51.1 does, review Runde 7, R7-3, so a profile read
from one git version is not taken as the list of another; pre-push only for `git push`); `stash`, whose internal paths githooks(5) does not name one by one, counts
every name.

Left the list (fallback A), NOT MEASURED in every form, because their program lists were not justified
completely: am, apply, archive, bugreport, checkout-index, cherry-pick, clean, clone, column, commit-tree,
fmt-merge-msg, fsck, gc, hash-object, init, maintenance, merge, merge-file, mktag, mktree, notes,
pack-objects, pack-refs, patch-id, prune, pull, range-diff, read-tree, reflog, remote, repack, rerere,
revert, sparse-checkout, stripspace, unpack-objects, update-index, update-ref, verify-commit, verify-pack,
verify-tag, worktree, write-tree (43); and every form of rebase, bisect and submodule, which were free
before outside their command-running forms. `init` left because it writes the configuration and copies
hooks from a template directory (`--template`, `$GIT_TEMPLATE_DIR`, `init.templateDir` or the compiled-in
default; git-init(1) TEMPLATE DIRECTORY), which later calls run. `fetch` and `ls-remote` left in review Runde 7
(R7-2): the transport they start is chosen by the URL argument, the effective remote URL after
`insteadOf` rewriting and the protocol environment together. A `<scheme>://` URL, as an argument or as the
configured URL, runs `git-remote-<scheme>` from the inherited PATH (gitremote-helpers(7)); an inherited
`GIT_ALLOW_PROTOCOL=ext` lets `ext::` run a command, measured by the reviewer without a gate answer. The
gate does not check the three together, and naming one more variable would not close the class, so every
form of both is NOT MEASURED until such a joint, positive check exists. The transport families in the table
below stay as the record of what that check would read; no entry carries them.

<!-- d3-entries:begin (generated from the gate; tests/test_plugin_gate_runde6b.py) -->

Every entry, in addition to its row: `core.fsmonitor` (family fsmonitor), the partial-clone keys (family promisor), `pager.<entry>`, `$GIT_EXEC_PATH` in the hook's environment, and the hook `fsmonitor-watchman` only through `core.fsmonitor`. A row with *submodules* also counts every `submodule.*` key and a `.gitmodules` file, because the gate does not read a submodule's own configuration.

| Family | Keys and values that count | Variables in the hook's environment | Source |
|---|---|---|---|
| fsmonitor | `core.fsmonitor` with a value other than a boolean (a boolean selects git's built-in daemon) | none | git-config(1) core.fsmonitor: a pathname names a hook command (true is the built-in daemon) |
| filter | `filter.<driver>.clean`, `filter.<driver>.smudge`, `filter.<driver>.process` | none | gitattributes(5) filter: filter.<driver>.clean, .smudge, .process are commands |
| diff-driver | `diff.external`, `diff.<driver>.command`, `diff.<driver>.textconv` | `$GIT_EXTERNAL_DIFF` | git-config(1) diff.external, diff.<driver>.command, diff.<driver>.textconv |
| merge-driver | `merge.<driver>.driver` | none | git-config(1) merge.<driver>.driver |
| editor | `core.editor` | `$GIT_EDITOR`, `$VISUAL`, `$EDITOR` | git-config(1) core.editor |
| transport | `core.sshCommand`, `core.gitProxy`, `core.askPass`, `core.alternateRefsCommand`, `credential.helper`, `credential.<url>.helper`, `remote.<name>.uploadpack`, `remote.<name>.vcs` | `$GIT_SSH`, `$GIT_SSH_COMMAND`, `$GIT_ASKPASS`, `$SSH_ASKPASS`, `$GIT_PROXY_COMMAND` | git-config(1) core.sshCommand, core.gitProxy, core.askPass, core.alternateRefsCommand, credential.helper, credential.<url>.helper, remote.<name>.uploadpack, remote.<name>.vcs |
| transport-helper-url | `remote.<name>.url`, `remote.<name>.pushurl` with a `<transport>::<address>` value | none | git-config(1) remote.<name>.url; gitremote-helpers(7) <transport>::<address> |
| rewrite-to-helper | `url.<base>.insteadOf`, `url.<base>.pushInsteadOf` with a `<transport>::` base | none | git-config(1) url.<base>.insteadOf with a <transport>:: base |
| protocol | `protocol.allow` of `always` or `user`; `protocol.ext.allow`, `protocol.fd.allow` other than `never` | none | git-config(1) protocol.allow, protocol.<name>.allow (ext:: runs a command) |
| pager | `core.pager` for an entry that pages by default; `pager.<entry>` for every entry unless false | `$GIT_PAGER`, `$PAGER` | git-config(1) core.pager |
| signature-format | `format.pretty`, `pretty.<name>` with a value containing `%G` | none | git-config(1) format.pretty, pretty.<name>; pretty-formats %G placeholders verify the signature (pretty.c, lines 1631-1633, check_commit_signature runs gpg.program or gpg) |
| signature-sort | `branch.sort`, `tag.sort` with a value containing `signature` | none | git-config(1) branch.sort, tag.sort; the ref-filter atom signature verifies (ref-filter.c, line 1749) |
| promisor | `extensions.partialClone`, `remote.<name>.promisor`, `remote.<name>.partialclonefilter`, whatever the value | none | git-config(1) remote.<name>.promisor, remote.<name>.partialclonefilter; partial-clone (extensions.partialClone): a missing object is fetched from the promisor remote with the transport its configuration names, by any command that reads it (review Runde 7, R7-7) |

| Entry | Options vetted beyond the bare form | Keys that make it NOT MEASURED | Hooks git starts for it (githooks(5)) | Source |
|---|---|---|---|---|
| `add` | none, the bare form only | filter, fsmonitor, *submodules* | `post-index-change` | git-add(1): clean filters, writes the index |
| `annotate` | none, the bare form only | diff-driver, filter, pager (`core.pager`) | none | git-annotate(1), as git blame |
| `blame` | `--abbrev`, `--color-lines`, `--date`, `--line-porcelain`, `--no-color`, `--porcelain`, `--show-email`, `-L`, `-e`, `-l`, `-s`, `-w` | diff-driver, filter, pager (`core.pager`) | none | git-blame(1): textconv, the worktree file |
| `branch` | `--all`, `--color`, `--contains`, `--format`, `--list`, `--merged`, `--no-color`, `--no-contains`, `--no-merged`, `--points-at`, `--remotes`, `--show-current`, `--sort`, `--verbose`, `-a`, `-l`, `-r`, `-v`, `-vv`; a word containing `signature` is NOT MEASURED | signature-sort, pager (`core.pager`) | `reference-transaction` | git-branch(1): creating a branch updates a reference; branch.sort |
| `cat-file` | `--batch-all-objects`, `--batch-check`, `-e`, `-p`, `-s`, `-t` | only the every-entry keys | none | reads objects, refs or attributes only; runs no driver, editor or hook |
| `check-attr` | none, the bare form only | only the every-entry keys | none | reads objects, refs or attributes only; runs no driver, editor or hook |
| `check-ignore` | none, the bare form only | only the every-entry keys | none | reads objects, refs or attributes only; runs no driver, editor or hook |
| `check-mailmap` | none, the bare form only | only the every-entry keys | none | reads objects, refs or attributes only; runs no driver, editor or hook |
| `check-ref-format` | none, the bare form only | only the every-entry keys | none | reads objects, refs or attributes only; runs no driver, editor or hook |
| `checkout` | none, the bare form only | filter, fsmonitor, *submodules* | `post-checkout`, `post-index-change`, `reference-transaction` | git-checkout(1), githooks(5) post-checkout |
| `cherry` | none, the bare form only | only the every-entry keys | none | git-cherry(1): patch ids by the internal diff, no driver |
| `commit` | none, the bare form only | editor, filter, fsmonitor, `commit.gpgsign` true, *submodules* | `commit-msg`, `post-commit`, `post-index-change`, `pre-auto-gc`, `pre-commit`, `prepare-commit-msg`, `reference-transaction` | git-commit(1): editor, signing, githooks(5) pre-commit, prepare-commit-msg, commit-msg, post-commit, reference-transaction, post-index-change, pre-auto-gc |
| `config` | reads: `--get`, `--get-all`, `--get-regexp`, `--get-urlmatch`, `--list`, `-l`, `git config get`, `git config list`; writes only of `advice.detachedhead`, `color.ui`, `core.autocrlf`, `core.quotepath`, `fetch.prune`, `init.defaultbranch`, `pull.ff`, `pull.rebase`, `push.default`, `user.email`, `user.name`; with `--add`, `--all`, `--bool`, `--global`, `--int`, `--local`, `--name-only`, `--null`, `--replace-all`, `--show-origin`, `--show-scope`, `--unset`, `--unset-all`, `--worktree`, `-z` | only the every-entry keys | none | reads objects, refs or attributes only; runs no driver, editor or hook |
| `count-objects` | `--human-readable`, `--verbose`, `-H`, `-v` | only the every-entry keys | none | reads objects, refs or attributes only; runs no driver, editor or hook |
| `describe` | `--abbrev`, `--all`, `--always`, `--contains`, `--dirty`, `--exclude`, `--long`, `--match`, `--tags` | filter, fsmonitor, *submodules* | `post-index-change` | git-describe(1) --dirty refreshes the index |
| `diff` | `--cached`, `--check`, `--color`, `--find-copies`, `--find-renames`, `--ignore-all-space`, `--ignore-space-change`, `--name-only`, `--name-status`, `--no-color`, `--no-patch`, `--numstat`, `--patch`, `--raw`, `--shortstat`, `--staged`, `--stat`, `--summary`, `--unified`, `-C`, `-M`, `-U`, `-b`, `-p`, `-w` | diff-driver, filter, fsmonitor, pager (`core.pager`), *submodules* | `post-index-change` | git-diff(1): drivers, worktree filters, fsmonitor, submodules |
| `diff-files` | `--name-only`, `--name-status`, `--stat`, `-p` | filter, fsmonitor, *submodules* | none | git-diff-files(1): compares the worktree |
| `diff-index` | `--cached`, `--name-only`, `--name-status`, `--stat`, `-p` | filter, fsmonitor, *submodules* | none | git-diff-index(1): compares the worktree |
| `diff-tree` | `--abbrev`, `--name-only`, `--name-status`, `--no-color`, `--root`, `--stat`, `-p`, `-r` | only the every-entry keys | none | git-diff-tree(1): two trees, plumbing, no driver without --ext-diff |
| `for-each-ref` | `--color`, `--contains`, `--count`, `--format`, `--merged`, `--no-color`, `--no-contains`, `--no-merged`, `--points-at`, `--sort`; a word containing `signature` is NOT MEASURED | only the every-entry keys | none | reads objects, refs or attributes only; runs no driver, editor or hook |
| `grep` | `--after-context`, `--basic-regexp`, `--before-context`, `--break`, `--cached`, `--color`, `--context`, `--count`, `--extended-regexp`, `--files-with-matches`, `--files-without-match`, `--fixed-strings`, `--heading`, `--ignore-case`, `--invert-match`, `--line-number`, `--no-color`, `--no-index`, `--perl-regexp`, `--untracked`, `--word-regexp`, `-A`, `-B`, `-C`, `-E`, `-F`, `-G`, `-H`, `-L`, `-P`, `-c`, `-e`, `-h`, `-i`, `-l`, `-n`, `-v`, `-w` | pager (`core.pager`), *submodules* | none | git-grep(1), submodule.recurse |
| `log` | `--abbrev-commit`, `--all`, `--author`, `--branches`, `--color`, `--committer`, `--date`, `--decorate`, `--first-parent`, `--format`, `--graph`, `--grep`, `--max-count`, `--merges`, `--name-only`, `--name-status`, `--no-abbrev-commit`, `--no-color`, `--no-decorate`, `--no-merges`, `--no-patch`, `--numstat`, `--oneline`, `--patch`, `--pretty`, `--remotes`, `--reverse`, `--shortstat`, `--since`, `--skip`, `--stat`, `--summary`, `--tags`, `--until`, `-m`, `-n`, `-p`; a word containing `%G` is NOT MEASURED | diff-driver, signature-format, pager (`core.pager`), `log.showsignature` true | none | git-log(1), git-config(1) diff.*, log.showSignature, format.pretty, pretty.* |
| `ls-files` | `--cached`, `--deleted`, `--error-unmatch`, `--full-name`, `--modified`, `--others`, `--stage`, `--unmerged`, `-c`, `-d`, `-m`, `-o`, `-s`, `-u`, `-z` | filter, fsmonitor | none | git-ls-files(1) -m/-d compare the worktree |
| `ls-tree` | `--abbrev`, `--full-name`, `--full-tree`, `--long`, `--name-only`, `--name-status`, `-d`, `-l`, `-r`, `-t`, `-z` | only the every-entry keys | none | reads objects, refs or attributes only; runs no driver, editor or hook |
| `merge-base` | `--all`, `--fork-point`, `--independent`, `--is-ancestor`, `--octopus` | only the every-entry keys | none | reads objects, refs or attributes only; runs no driver, editor or hook |
| `mv` | none, the bare form only | fsmonitor, *submodules* | `post-index-change` | git-mv(1): writes the index |
| `name-rev` | `--all`, `--name-only`, `--refs`, `--stdin`, `--tags` | only the every-entry keys | none | reads objects, refs or attributes only; runs no driver, editor or hook |
| `reset` | none, the bare form only | filter, fsmonitor, *submodules* | `post-index-change`, `reference-transaction` | git-reset(1) |
| `restore` | none, the bare form only | filter, fsmonitor, *submodules* | `post-index-change` | git-restore(1): smudge filters |
| `rev-list` | `--all`, `--branches`, `--count`, `--first-parent`, `--left-right`, `--max-count`, `--merges`, `--no-merges`, `--no-walk`, `--oneline`, `--remotes`, `--reverse`, `--tags`, `-n` | only the every-entry keys | none | reads objects, refs or attributes only; runs no driver, editor or hook |
| `rev-parse` | `--abbrev-ref`, `--all`, `--branches`, `--default`, `--git-common-dir`, `--git-dir`, `--is-bare-repository`, `--is-inside-work-tree`, `--quiet`, `--remotes`, `--short`, `--show-toplevel`, `--symbolic`, `--symbolic-full-name`, `--tags`, `--verify`, `-q` | only the every-entry keys | none | reads objects, refs or attributes only; runs no driver, editor or hook |
| `rm` | none, the bare form only | filter, fsmonitor, *submodules* | `post-index-change` | git-rm(1): compares the worktree, writes the index |
| `shortlog` | `--all`, `--email`, `--no-color`, `--numbered`, `--summary`, `-e`, `-n`, `-s` | pager (`core.pager`) | none | git-shortlog(1) |
| `show` | `--abbrev-commit`, `--color`, `--format`, `--name-only`, `--name-status`, `--no-color`, `--no-patch`, `--numstat`, `--oneline`, `--patch`, `--pretty`, `--stat`, `-p`, `-s`; a word containing `%G` is NOT MEASURED | diff-driver, signature-format, pager (`core.pager`), `log.showsignature` true | none | git-show(1), as git log |
| `show-branch` | none, the bare form only | pager (`core.pager`) | none | git-show-branch(1) |
| `show-ref` | `--abbrev`, `--dereference`, `--hash`, `--head`, `--heads`, `--quiet`, `--tags`, `--verify`, `-d`, `-q`, `-s` | only the every-entry keys | none | reads objects, refs or attributes only; runs no driver, editor or hook |
| `stash` | none, the bare form only | diff-driver, filter, fsmonitor, merge-driver, pager (`core.pager`), *submodules* | every githooks(5) name | git-stash(1): show diffs, apply/pop merge, writes refs/stash and the index |
| `status` | `--branch`, `--color`, `--ignored`, `--long`, `--no-color`, `--no-untracked-files`, `--porcelain`, `--short`, `--show-stash`, `--untracked-files`, `--verbose`, `-b`, `-s`, `-u`, `-v`, `-z` | filter, fsmonitor, *submodules* | `post-index-change` | git-status(1) BACKGROUND REFRESH writes the index; submodules |
| `switch` | none, the bare form only | filter, fsmonitor, *submodules* | `post-checkout`, `post-index-change`, `reference-transaction` | git-switch(1), githooks(5) post-checkout |
| `symbolic-ref` | `--delete`, `--quiet`, `--short`, `-d`, `-q` | only the every-entry keys | `reference-transaction` | git-symbolic-ref(1); githooks(5) reference-transaction: git 2.43.0 does not start it for a symbolic reference (measured), git 2.51.1 does (review Runde 7, R7-3), so it counts for every form |
| `tag` | `--color`, `--contains`, `--format`, `--list`, `--merged`, `--no-color`, `--no-contains`, `--no-merged`, `--points-at`, `--sort`, `-l`, `-n`; a word containing `signature` is NOT MEASURED | editor, signature-sort, pager (`core.pager`), `tag.gpgsign` true | `reference-transaction` | git-tag(1), tag.gpgSign, tag.sort |
| `var` | none, the bare form only | only the every-entry keys | none | reads objects, refs or attributes only; runs no driver, editor or hook |
| `whatchanged` | none, the bare form only; a word containing `%G` is NOT MEASURED | diff-driver, signature-format, pager (`core.pager`), `log.showsignature` true | none | git-whatchanged(1), as git log |

<!-- d3-entries:end -->

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
  (reason id `write_to_repo_state`): `.git/config`, `config.worktree`, a `.git` file, any file under the
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
  decision. Not judged: a write made by a shell command (a redirection, `cp`, `chmod` in a Bash call),
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

FREE GIT FORMS AND FILE WRITES UNDER CODEX (Nachtrag 19b, Punkt 7)
- Codex stays strict: every git form Level 1 would leave free under Claude Code is NOT MEASURED under
  `--host codex` and denied (`repo_state_unbound`), because the hook does not receive the directory the
  command runs in, so the gate cannot read that repository's configuration and hooks.
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
- Named limit: when the primary environment is not the local one, a relative patch path names a file in a
  filesystem the hook does not see, and the gate resolves it against the hook's `cwd`. A patch that names
  an environment, or carries a `***` line the gate does not read, is NOT MEASURED and denied. Whether
  Codex fires the hook for `apply_patch` in every approval mode is read from the source, not measured in a
  run.

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
