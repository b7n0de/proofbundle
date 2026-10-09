# Decisions of the pre-push gate

The gate in `hooks/proofbundle_gate.py` runs before every Bash call and before an MCP tool that opens a
pull request, a merge request or a release, pushes files, writes a file or merges a pull request. Where
the design was open, it takes the smallest variant that fails closed. Each decision below names that
choice and the options the owner can pick instead. D26 and D27 follow the owner's choices of 2026-10-08 for the
user path "Claude says done" (a local hook as early warning, the hard boundary in CI). The owner decided D2, D8, D13, D14, D16 and D17 on
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
    - **The former free list for local git commands has been removed** (review Runde 9, owner choice B,
      2026-10-03, the subsection below; wording of review Runde 10, R10-3). Those forms are NOT MEASURED,
      asked under Claude Code and denied under Codex. Only the exact bare command text `git --version` is
      exempt from judgment as a git form, and, since owner choice K-NW-2 B of 2026-10-08, exactly two forms
      after a state check of their repository (`git add` and `git commit -m`, the subsection "two forms after
      a state check" below). The separate push path remains. Under Claude Code it may return
      `pass` or `inactive` after its checks; under Codex every push is NOT MEASURED because its execution
      context is unbound, and since owner choice Karte 5 A of 2026-10-08 it warns instead of being denied (D12).
      The free
      list of Nachtrag 19b, its per-entry option tables and its read of the
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
- An unresolved push is asked under Claude Code; under Codex every push is NOT MEASURED and, since Karte 5 A,
  warned about rather than denied (D12). The D5 inactive shortcut
  applies only when the push resolves and every sent commit and the target's state declare nothing; an
  unresolved push never switches the gate off (N2).

Options:
- A. HEAD only, refspec not read (the pre-review behaviour; a push of another branch was judged at HEAD).
- B. Every newly reachable commit per resolved target, unresolved is NOT MEASURED (chosen).
- C. Treat a push whose refspec is not the current branch as NOT MEASURED (too coarse: it would miss a
  bare push of a branch the gate can resolve).

### D3, no git form is free (review Runde 9, owner choice B, 2026-10-03)

Chosen (owner, 2026-10-03): option B, remove the free list. The former free list for local git commands has
been removed. Those forms are NOT MEASURED, asked under Claude Code and denied under Codex (D12). Only the
exact bare command text `git --version` is exempt from judgment as a git form. The separate push path remains.
Under Claude Code it may return `pass` or `inactive` after its checks; under Codex every push is denied because
its execution context is unbound (wording of review Runde 10, R10-3; since owner choice Karte 5 A of 2026-10-08 a
`git push` under Codex warns instead, D12). The one free form, the bare
`git --version`, is exactly that command text: no program path, no wrapper,
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

### D3, two forms after a state check (owner choice K-NW-2 B, 2026-10-08)

Chosen (owner, 2026-10-08, card K-NW-2): option B. `git add` and `git commit` are free when the check of the
repository's state finds no configuration that starts a program for them: no filter, no hook, no fsmonitor, no
signature program, and no include onto one of them.

What is free. Exactly two forms, each as the whole command headed by a bare `git` with no global option, no
redirection, no chain and no unvetted prefix assignment (the conditions of the bare `git --version` above):
- `git add` with pathspecs and only `-A`, `--all`, `-u`, `--update` and `--`;
- `git commit` with at least one message (`-m`, `--message`, a cluster of `a`, `q` and `m` such as `-am`), and only
  `-a`, `--all`, `-q`, `--quiet`, `--` and pathspecs.
Any other option (`-p`, `-i`, `-e`, `--renormalize`, `-S`, `-v`, `--amend`, `-F`, `-C`, `-c`, `--trailer`,
`--no-verify`, …) keeps the form as before, because an editor, a signer, a diff or a trailer command can start. The
answer is a `pass`: a message, no permission decision, so the host's own permission flow applies. Reason id
`free_after_state_check`.

A word the shell may rewrite before git sees it is not the word the gate read (review 2026-10-09, F2, measured at
91a52faa: with a file named `--edit`, `git commit -m msg *` was free and bash makes `*` into `--edit`, which starts an
editor). Before the `--` that ends the options, a message included, every word must be literal: no unquoted glob
(`*`, `?`, `[`), brace (`{`), zsh extended glob (`^`, `#`), leading `~`, `~` after `=` or `:`, or leading `=`
(`_shell_rewrites`). Otherwise the form is not free. After that `--` a rewritten word is a pathspec and the form stays
free (`git commit -m msg -- *`). The same predicate decides, for the same reason, the plain push under Codex (D12),
every push and gh call Level 1 resolves under Claude Code (a rewritten word anywhere leaves its repository and target
NOT MEASURED) and the candidates for a human rule of D25 (a command with a rewritten word is none: the approved text
is not the command git gets). zsh's `~` inside a word excludes only together with another glob character (measured
with zsh 5.9), so alone it is literal. The value of a `-C` keeps the plain `~` and `~name` the gate joins with
os.path.expanduser; `~+`, `~-` and `~N` name directories of the shell's state and leave it NOT MEASURED.

The state check (`_add_commit_state_problem`), in the hook's environment, so git reads the same files the call reads:
- the effective configuration with every include, read by `git config --list --show-origin --show-scope`. A key of
  a program source is named as such: `filter.*` (an empty driver name included), `hook.*` and
  `gc.recentObjectsHook` (a hook), `core.fsmonitor` unless false, `gpg.program`, `gpg.<format>.program`,
  `gpg.ssh.defaultKeyCommand` and `commit.gpgSign` unless false (a signature program; a number is true, review
  Runde 9), `maintenance.*` and `gc.*` (automatic maintenance). An entry that came in through an include is named
  with the included file. Every other key must be on the positive list `_STATE_INERT_KEYS` /
  `_STATE_INERT_PATTERN` (repository format, stat and line-ending options, identity, editor and pager, signing
  settings that act only when signing is on, the settings of other commands, the transport settings), or the form
  is not free;
- the effective hook directory, `core.hooksPath` resolved by git: only `*.sample` files and the hooks githooks(5)
  of git 2.43 documents and neither form runs (push, receive, rebase, checkout, merge, am, send-email, p4 and
  `fsmonitor-watchman`) may be there. A pre-push hook of Level 2 (D24) therefore keeps both forms free;
- the hook's `GIT_*` environment: only the configuration files and entries git reads into the same list, the
  identity, the editor, sequence editor and pager neither form starts, and the transport settings neither form uses.

Not free is answered as before (asks under Claude Code, denied under Codex, reason id `git_form_not_free`), with the
source the check found. A human rule of D25 frees the plain form as before, also where the state check refuses it.

Measured with git 2.43.0 (tests/test_plugin_gate_k_nw_2_b.py): plain git starts the marker for a clean filter and an
empty-named filter on `git add`, for the hooks pre-commit, reference-transaction and post-index-change, for a hook in
the `core.hooksPath` directory, for fsmonitor on both forms, for `commit.gpgSign` of `true`, `2`, `1k`, `0x1`, `yes`
and `on`, for `gpg.ssh.program` with signing on, for an include onto a filter and for an includeIf onto a signature
program and onto a hook directory; the gate refuses each and names the source. Not started under 2.43.0, refused
anyway: `gc.recentObjectsHook` (started under git 2.51.1, review Runde 9), and a signing program while signing is
off. A pre-push hook was not started by either form.

Codex. The Codex hook names the session directory, not the directory a command runs in (measured with Codex 0.161.0
on 2026-10-08: a `workdir` the model set reached the command, `pwd` printed it, while the event carried the session
directory as `cwd` and only `{"command": ...}` as tool input). The check reads the session directory, and the pass
under Codex says so. This is the class of R5-2 and of D27: Level 1 is an early warning; the boundary is CI.

Delimitation from Nachtrag 37. Nachtrag 37 frees only what the gate positively understands, for the command text:
the net and the lexer must account for every git word, and a form the net reports NOT MEASURED is never free, here
as for a rule. K-NW-2 B applies the same principle to the repository state: the check frees only a state whose every
key, hook and environment name is on a positive list, and does not try to enumerate the ways git starts a program.
It is not the free list of Nachtrag 19b back: that list freed many forms and read a profile of keys per form, and
review Runde 9 showed values and side paths it did not know. Here two forms are free, every key outside the list
keeps them not free, and the cases of review Runde 9 for these forms stand as tests.

Not read: the program `PATH` selects (`git` itself, the interpreter of a hook) is the D27 class (F15-3); a shell can
build a form the gate does not see (D27). gitattributes are not read, because they select a driver only a `filter.*`
or `diff.*` key defines, and those keys are refused.

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
  when a text search finds a gated call, with the directory NOT MEASURED; since review Runde 10 (R10-1) the
  search counts the word `git` alone, because every git form is gated.
- A shell comment is dropped before the scan (review Runde 10, R10-1): a `#` that begins a word, up to the end
  of its line, as long as every character before it outside the comments already dropped is plain text (no
  quote, escape, expansion, substitution, glob, bracket, brace or here-document). The command is then judged
  as it is without the comment. After the first other character a `#` is kept as a word character, because it
  may sit in a string, a here-document or an arithmetic command the shell runs; a command that is unparsable
  then falls back to the text search.
- Since review Runde 9 (owner choice B, D3) every other git form that acts on a repository is gated too,
  found the same way: it is NOT MEASURED, asked under Claude Code and denied under Codex. Only the bare
  `git --version` is not gated.
- A safety net closes what the lexer misses (review Runde 11, owner choice A of 2026-10-04; Runde 12, R12-1
  and R12-2; Nachtrag 33, K1). It always runs, not only when the structured scan found nothing. The gate builds
  a normal form of the whole command text — comments and substitutions included — in which every ANSI-C quote
  `$'…'` is evaluated toward the bytes bash would run, as far as the normal form can build them safely and
  completely — otherwise the command is NOT MEASURED, see below — every single and double quote and every backslash is removed,
  and only the letters A to Z are lower-cased, each in place (so an expanding case fold such as U+0130 cannot
  shift the indices, R12-3). A command word is a word of that normal form, split on the separators (whitespace,
  `;` `&` `|` `(` `)` `{` `}` newline backtick), whose basename is `git`, `gh` or a `git-<subcommand>`, behind a
  path (`…/git`) or not. A longer word (`.gitignore`, `digit`, `foo-git`, an assignment `X=git` the separators
  leave whole) is not a command word; the quote and `name=` exceptions of earlier rounds fall away, because the
  normal form has already removed the quotes. Every command word must correspond to a call the structured scan
  resolved; one it did not account for — the scan found nothing, or found fewer calls than the net counts — is
  NOT MEASURED (reason id `net_unmodeled_git`), never a pass or an inactive gate. An overmatch asks under Claude
  Code and denies under Codex. The exemption stays the exact bare `git --version`. The net never frees a call and
  never resolves a push.
  - The ANSI-C quote and the executable-form class (Nachtrag 33, widened to a rule by Nachtrag 35). A command
    word whose executed bytes the normal form cannot build SAFELY AND COMPLETELY is a defect class, not one
    spelling, and its answer is NOT MEASURED — asked under Claude Code, denied under Codex, never no answer. Exact
    evaluation stays only where the normal form can reproduce the executed bytes completely AND it lowers the
    everyday cost; in doubt the answer is NOT MEASURED. At 096b7191 the net dropped the `$'…'` shell and stripped
    the quote without evaluating the escape, so `$'\147it'` (octal), `$'\x67'it` (hex), `$'\u0067it'`
    (Unicode) read as `147it`/`x67it`/`\u0067it` and no answer was given, though bash — and zsh, measured 5.9 —
    run each as `git`. The net now evaluates `$'…'` (octal, hex `\x`, Unicode `\u`/`\U`, control `\cX`, the
    named escapes; an unrecognised escape keeps its backslash) only so that the common non-git ANSI-C quote in an
    agent's own commands (`IFS=$'\n'`, `grep $'\t'`, `sort -t$'\t'`) keeps its silent pass; evaluation that
    saves no everyday cost is not a goal in itself. The earlier claim that the net evaluates `$'…'` exactly like
    bash is withdrawn: where the executed bytes cannot be built completely the answer is NOT MEASURED, not the
    net's own untranslated bytes. Named, each measured against bash and zsh at the fixed commit:
    - A decoded NUL (`$'\0'`, `$'\x00'`, `$'\u0000'`, `$'\c@'`) truncates the ANSI-C sub-word in bash and
      the rest of the word is appended, so `$'g\0'it` runs `git`; the normal form does not model that
      concatenation, so the whole command is NOT MEASURED (review Runde 14, R13-1).
    - An active backslash line continuation is removed before the word test, so `$'g'\<newline>it` reads as the one
      word `git` and is gated; a literal backslash kept in single quotes stays a word character (R13-2).
    - Every embedded executable context is read as its own executable text, and its ANSI-C quotes are evaluated
      there: a command substitution `$(…)`, a backquote inside double quotes as well, a process substitution
      `<(…)`/`>(…)`. A single global quote-state variable cannot model nested execution, so the net recurses into
      each body to a bounded depth (R13-3).
    - The locale quote `$"…"`, whose message-catalogue translation the gate cannot read, stays NOT MEASURED
      whatever its word count (Nachtrag 33).
  - Active expansion in a command-word position, as a positive-role rule (review Runde 14, R13-4; Runde 15,
    R14-1/R14-2/R14-3; Nachtrag 37). Two `man bash` expansions can construct a command word from text that is not
    literally `git`: brace expansion (`{g,}it` → `git it`, the range `g{i..i}t`) and pathname globbing (`gi*`,
    `g?`, `g[i]t` where a matching file exists). The net does not enumerate the expansion. Instead it frees an
    active brace or glob (`{…,…}`, `{a..b}`, `*`, `?`, `[`) ONLY when it can prove the expansion is a data
    argument of a program word it has positively recognised in place — a plain literal that is not itself an
    expansion or a substitution, not `--`, not a known wrapper and not a reserved word. Only then is the expansion
    data and free (`ls *.py`, `cp f.{txt,bak}`, `grep -n foo *.py`, `if true; then ls *.py; fi`). In every other
    position the role is not proven and the expansion is NOT MEASURED:
    - A wrapper option, `--` or a reserved word shifts the real program position. The net does not model each
      wrapper's options, so once a known wrapper (`sudo`, `env`, `command`, `exec`, `time`, `xargs`, `timeout`, …)
      or a reserved word (`if`, `while`, `case`, `for`, …) heads the command, the program position is unproven and
      any active expansion at or after it is NOT MEASURED — `env -- gi*`, `command -- gi*`, `time -p gi*` and
      `if gi* …` all run git under bash. The wrapper and reserved-word lists only ADD strictness: a word in neither
      is treated as an ordinary program, so a genuinely unknown program (like an alias or a function) is a named
      recognition boundary, never a silent git/gh pass. Extending the lists can only move more forms to NOT
      MEASURED, never free one — the fix is this positive-role rule, not a longer wrapper list (R14-1, R14-5).
    - The expansion check runs inside every executable subcontext (`echo "$(gi* status)"`), and a context the
      lexer cannot parse (`: $'x'; gi* status`) is NOT MEASURED at an unclear program position, not treated as
      expansion-free (R14-2).
    - An embedded command's boundary counts only under understood syntax: a backslash-escaped `)`, a `)` in a
      comment and a `case`-pattern `)` no longer end a `$(…)` early, and a `$(…)` body whose `case`/`esac` do not
      balance is NOT MEASURED because the boundary cannot be trusted (R14-3).
    The whole understood-versus-NOT-MEASURED decision is made at one site (`_net_unmodeled`); every free exit of
    the net goes through it, and a per-class test fails if a form bypasses it (Punkt 2). The named recognition
    boundaries the net does not see — a program word built in a variable, an alias, a function, an executable
    context nested past the depth limit, and the locale quote `$"…"` — can still pass without a gate answer; that
    is the declared scope of NOT MEASURED, and no claim is made that the net catches a git/gh word behind them.

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
The reason still starts with `NOT MEASURED:`. One case warns instead since owner choice Karte 5 A
(2026-10-08): a `git push` in its plain form (owner choice K5-1 C, 2026-10-08), below.

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
- Since owner choice Karte 5 A (2026-10-08) such a `git push` warns instead of being denied, and since owner
  choice K5-1 C (2026-10-08) only in its plain form; the next two blocks.

A GIT PUSH UNDER CODEX WARNS (owner choice Karte 5 A, with D, 2026-10-08)
- Chosen: under `--host codex` a plain `git push` (next block) keeps the NOT MEASURED reason above, field by
  field, and its reason
  id `codex_context_unbound`. The answer carries no permission decision: the reason goes out as the message and
  as context for the model, followed by one warning sentence (`CODEX_PUSH_WARNING` in the gate). The gate log
  records the verdict `warn` and the decision `none`.
- Why: the boundary is the done check at the end of the session (D26) and the required CI check (D22, D27). Under
  Codex the push check is carried by git's own `pre-push` hook (Level 2, D24, option D of the card), because git
  starts it in the repository the push acts on, with git's ref lines.
- Unchanged: Claude Code. A push that turns the push check off (`--no-verify`, a command-level `core.hooksPath`,
  `git config core.hooksPath`) is denied under both hosts, because it switches off the Level-2 check this choice
  relies on. `gh pr create`, `gh release create` and the other gated gh calls stay denied, because gh starts no
  pre-push hook. `git send-pack`, a per-command `-c alias.*` and every other form Level 1 leaves as a possible
  transfer stay denied, because they are not a `git push`. A gated MCP write stays denied (R6-1). A command that
  holds a push and any denied call is denied; deny ranks above ask, ask above warn.
- What the warning does not do: it checks nothing. Without an installed `pre-push` hook nothing local stops a
  push under Codex. The user installs that hook with `install-pre-push` (D24B); this choice installs nothing.
- Known way around, the D27 class: an environment setting that turns hooks off without a word Level 1 reads (for
  example `GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.hooksPath GIT_CONFIG_VALUE_0=/dev/null git push`) keeps git
  from starting the Level-2 hook. Claude Code asks for such a push (`directory_unresolved`); under Codex it warned
  like any other push at 31031eb6 (measured on 2026-10-08). Owner choice K5-1 C closes it under Codex, next block.
  The boundary stays the required CI check.

UNDER CODEX ONLY THE PLAIN GIT PUSH WARNS (owner choice K5-1 C, 2026-10-08)
- Chosen: the plain form is one command headed by a bare `git` with `push` right after it: no prefix assignment of
  any kind (a neutral one like `LANG=C` included), no chain, pipeline, background, subshell or group, no wrapper
  (`env`, `command`, `exec`, `nice`, `time`, `bash -c`, `sh -c`, `eval`), no global option before `push` (`-c`,
  `-C`, `--git-dir`, `--exec-path`), no other git path or program (`/usr/bin/git`, `./git`, `git-push`, a quoted
  `'git'`) and no expansion. Options and arguments after `push` and a redirection keep the form plain, as long as
  every word before the `--` that ends the push's options is literal (D3, `_shell_rewrites`; review 2026-10-09, F2:
  `git push --no-verif?` with a file named `--no-verify` warned at 91a52faa, and bash makes it `--no-verify`). A `--`
  ends the options only after a word that takes no value; after `-o` it may be that option's value.
- Only that form warns (`_codex_plain_push` in the gate). Every other push form gets the reason id
  `codex_push_not_plain` and is denied under Codex, with the next step to run the plain form on its own or to have
  a person push. A form that turns hooks off on the command line keeps its earlier `hooks_disabled` deny.
- Why: the warning rests on git starting the Level-2 hook in the repository the push acts on. A prefix assignment
  can switch that hook off without a word Level 1 reads, and a chain, wrapper, global option or other git program
  can push from elsewhere or step around the hook; the hook input cannot tell (R5-2). The plain form is the one
  form whose text leaves git's own hook path in place.
- Unchanged: Claude Code. Each of these forms gets there what it got before (tests/test_plugin_gate_k5_1_c.py).

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
  every Codex push is NOT MEASURED → deny (since owner choice Karte 5 A of 2026-10-08: → a warning, D12).
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
  denied (a `git push` warns since Karte 5 A, above).

GIT FORMS AND FILE WRITES UNDER CODEX (Nachtrag 19b, Punkt 7; review Runde 9)
- Since review Runde 9 (owner choice B, D3) the former free list for local git commands has been removed.
  Since owner choice K-NW-2 B (2026-10-08, D3) `git add` and `git commit -m` are free after a state check, under
  Codex of the session directory the hook names. Those forms ask under Claude Code and are denied under Codex, with
  the same reason id `git_form_not_free`;
  a literal `-C` on such a local form does not change that decision (it never frees it). Only the exact bare
  command text `git --version` is exempt (review Runde 7, question 5: "every git form" was too broad; wording
  of review Runde 11, R11-5). The separate push path remains: under Claude Code it may return `pass` or
  `inactive` after its checks; under Codex every push is NOT MEASURED because its execution context is unbound,
  and warns since Karte 5 A (above) — the `-C` sentence above is about the freed local forms, not that push path. A bare `git` without a subcommand is
  no longer free.
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
- C. Warn on a `git push` under Codex, with the boundary at the done check and CI and the push check in the
  pre-push hook (owner choice Karte 5 A with D, 2026-10-08; above).

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
  Since owner choice N2C-1 B (2026-10-08) the done check is a rule too: the whole `done` section (its policy,
  each check's id, arguments and receipt, `paths` and `max_blocks`) and the bytes of the done policy (D30).
  An evidence file, a receipt, the declared subject and any other file under `.proofbundle/` are not rules, so
  a release that brings new evidence for a new tree is no rules change. No rule is a path to a key: a
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
  must report a green run. Subject-only evidence remains accepted and does not attest a test run. An
  evidence document or signed payload that repeats a key in any object, at any depth, is denied `not_bound`
  as ambiguous before its subject, run record or counts are read; the policy the gate checks for a pinned
  signer, the verifier's answers and the hook event are read the same way (review Runde 9, R9-4: a correctly
  signed payload with first a red and then a green run, or first a wrong and then the matching subject, was
  read by its last value and passed).
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
- It is a prototype. The plugin does not install it by itself and sets no `core.hooksPath`, in the repository
  or globally. Since owner choice K5-D C (2026-10-08) the user installs it with `install-pre-push`, in the
  repository where they call it (D24B).
- `git push --no-verify` skips every pre-push hook, so Level 2 cannot see that form; that is why Level 1
  denies `--no-verify` and a command-level `core.hooksPath` override outright (Ebene 1, Punkt 5).
- Limit: the prototype judges the repository of the process it runs in (`git rev-parse --show-toplevel`
  from the hook's own working directory). A push driven from another directory with `GIT_DIR` set is not
  the modeled case; the realistic deployment is a hook in the repository the push runs from. The hook
  verifies the evidence at the pushed commits; like every level it proves what the evidence proves, not
  that any recorded value is true.
- Level 3 (D22, the CI check) stays the enforcement point a maintainer relies on, off the contributor's
  machine. The three levels see different things and are not substitutes for one another.
- Since owner choice N2 C (2026-10-08) the hook also runs the done check at every pushed commit (D30), and under
  Codex it carries the push check, where Level 1 only warns (Karte 5 A with D, D12). It is installed only by
  `install-pre-push`, on the user's call (D24B).

Options:
- A. A pre-push hook prototype, measured in tests, not installed (chosen).
- B. Ship and install the hook via `core.hooksPath`. Rejected here: it needs the maintainer's install and
  trust story, and a `core.hooksPath` the plugin sets is itself a surface (D should a plugin write git
  config). The owner decides.
- C. Rely on Level 1 alone. Rejected: the reviewer showed a shell gate is not a boundary.
- D. Rely on Level 3 (CI) alone. The honest fallback, but it catches a bad push only after it reaches the
  remote; Level 2 catches it at the contributor's machine.

## D24B. How the pre-push hook is installed (owner choice K5-D C, 2026-10-08)

Chosen: a command of its own, `proofbundle_gate.py install-pre-push [--repo DIR]`, which the user runs in the
repository where they want Level 2. The plugin never runs it by itself: no hook configuration of either host names
it, and no other path of the gate writes a hook.
- What it writes: one file, `pre-push`, in the hook folder git uses for that repository: `.git/hooks`, or a
  `core.hooksPath` set in the repository's local or worktree configuration that points inside the repository. It
  sets no configuration, local or global. Reading of the owner's words "the local core.hooksPath of the repository":
  the hook folder that is the repository's own; the command does not set `core.hooksPath`.
- What it refuses, writing nothing: a `core.hooksPath` from the global, system or command configuration (a hook
  there acts beyond this repository), a local one outside the repository, `GIT_DIR`, `GIT_WORK_TREE` or
  `GIT_COMMON_DIR` in the environment, a folder that is not a working tree, and an existing `pre-push` that it did
  not write: a regular file without its mark on the second line (`PRE_PUSH_MARK`), a link or a folder. The message
  names that hook's path; the hook is left as it is. Its own hook it replaces, atomically.
- The wrapper is fixed text (`pre_push_wrapper`). It records the plugin folder it was installed from and finds the
  gate at each push (`_PRE_PUSH_RESOLVER`): that folder's gate, or, when the folder is a version folder of an
  installed plugin (`…/proofbundle/<version>`, as Claude Code and Codex cache it), the gate of the newest version
  folder beside it, by number. So a plugin update needs no new install. It runs that gate as `pre-push` with
  git's arguments and ref lines; when it finds no gate, or `python3` is missing, it denies the push (exit 1).
- Limits: the wrapper runs the `python3` on PATH at push time and reads the plugin folders as the user's files; an
  agent that can write those folders or the hook itself can change what runs (the D27 class: local hooks are an
  early warning). `git push --no-verify` skips it, which is why Level 1 denies that form (D24). The boundary stays
  the required CI check (D22).

Measured (tests/test_plugin_gate_install_pre_push.py, 2026-10-08): the wrapper lands in `.git/hooks` or a local
`core.hooksPath` inside the repository with no configuration changed; a foreign hook (script, link, folder, a mark
not on the second line), a global, command-scope or outside hook folder and a moved repository are refused; through
git, a push without a receipt keeps the remote ref and a valid receipt moves it; after a version change (0.3.0
replaced by 0.3.1) the hook runs the new version's gate; with the plugin removed, or without `python3`, the push is
denied. Red at 31031eb6: 21 of 22 (the command did not exist; the one green is the valid push, which needs no
hook to move the ref).

Measured under Codex 0.161.0 with `--sandbox workspace-write` and the network off (2026-10-08, a scripted model, the
hook installed by `install-pre-push` from the plugin cache):
- The sandbox keeps `.git` read-only: `git add` and `git commit` fail (`.git/index.lock`: read-only file system), and
  a push cannot update its remote-tracking ref.
- With the commit made by the user beforehand, git starts the installed hook, the wrapper finds the gate and the gate
  runs, but the verifier does not start: uv cannot write its cache (`/root/.cache/uv`, read-only), and with a
  writable empty cache (`UV_CACHE_DIR`) it cannot reach the package index (name resolution fails). The gate refuses
  the run and denies the push (exit 1); the remote ref stays where it was.
- Codex's own hooks ran outside the sandbox in the same runs: the Stop hook started the verifier and reached a verdict.
- So under that sandbox Level 2 is fail-closed and of no use for a push that needs the verifier; such a push is a
  person's, outside the sandbox. Not measured: a sandbox with network on, or with a writable, filled uv cache.

LEVEL 2 NAMES THE SANDBOX (owner choice K02-A, A with C, 2026-10-08)
- A: in the Codex sandbox a person pushes; the boundary is the required CI check (D22).
- C: where the verifier cannot start for want of a writable cache or of the network, Level 2 says so with a text and
  a reason of its own, `sandbox_verifier_unavailable`: "NOT MEASURED: the verifier cannot start here, so this push was
  not checked: <what was measured>. These are the signs of a sandbox without network or without a writable cache. The
  push belongs to a person outside the sandbox; the boundary is the required CI check (D22, D24B)." The exit code and
  the outcome stay as they were: the push is denied (exit 1) and the remote ref does not move.
- Only from measured signs (`_verifier_start_sign`): uv's own answer must report a failed write (`Read-only file
  system`, os error 30 or 13) or a failed name resolution, and a probe of the gate's own must confirm it: a write of a
  probe file in the cache folder uv names (`uv cache dir`), or the nearest folder above it that exists, which fails;
  or every place uv would go out of reach (each proxy the environment names, by a connection where it is an address
  literal and by a name resolution otherwise, and pypi.org). An environment name such as `CODEX_SANDBOX` decides
  nothing; uv's words without a confirming probe keep the generic text; the probe file is removed at once and no
  folder is created.
- Only Level 2 shows the text; Level 1, the Stop hook and the CI mode keep the generic start failure, whose message is
  unchanged (`VerifierCannotStart` is a `GateError`).
- Measured (tests/test_plugin_gate_k02a_c.py, 2026-10-08, the two sandboxes rebuilt with bubblewrap: a read-only root,
  a network namespace of its own): no writable cache and a cache without network each get the text and exit 1, also
  through git with the hook from `install-pre-push`, where the remote ref stays; network and a writable cache get the
  push's own verdict; uv's words alone (cache writable, or network reachable) and `CODEX_SANDBOX` alone keep the
  generic path. Red at 12068a47: 6 of 10 (the four controls green). The same three situations with the real uv, at
  12068a47 and after: exit 1, 1 and 0 at both, with the generic text before and this text after.

Options:
- A. Leave it open; Level 2 only by hand after the README.
- B. `done-init` sets the hook up, on an explicit switch.
- C. A command of its own with a fixed wrapper that finds the plugin at push time (chosen).
- D. CI only.

## D25. Approval by a human click or a pre-set rule (Nachtrag 24)

Owner word (2026-10-03, 16:51 Berlin): after the free list was removed (D3/owner choice B, Runde 9), every
repository-dependent git form asks. The human wants two ways to spare a repeated question without the model ever
freeing anything itself — a one-time click for a command form in a repository, or a rule the human sets in
advance. The principle (Z355): gate yes, own judgment no. The decision never comes from the model; it comes from
the human's click or a pre-set rule, and the plugin only executes the rule.

Chosen (owner choice A, 2026-10-04, two modes in the plugin):
- Two modes, set only by a human. `strict` is the default: every repository-dependent git form asks, and
  neither a click nor a rule acts. `with-approvals` lets a pre-set rule act (the click path is deferred, see
  the cards). The model cannot change the mode: a write to the mode location is deny, like the rule file.
  A missing or unreadable mode is strict. Under Codex both modes deny (D12/D16: the Codex hook does not bind the
  execution directory). The mode is named in every gate-log entry and in the answer.
- Where the mode, the rules and the log live (owner card 3, stricter default): an absolute, user-wide directory,
  never inside a repository. `$PROOFBUNDLE_GATE_DIR` when it is absolute, else `$XDG_CONFIG_HOME/proofbundle`,
  else `~/.config/proofbundle`. A relative override or no home yields no directory, and the gate stays strict.
  A file the model could reach through the repository it works in, or by a relative path, is not a human-only
  location. `<dir>/mode` (one word), `<dir>/rules.json` (the human writes it, the plugin only reads it),
  `<dir>/gate-log.jsonl` (the audit log).
- The rule file is a JSON array; each rule is exactly `{repo, form, effect, state_digest}`. `repo` is an
  absolute repository path, `form` the exact text of one plain strict `git` command (as the strict grammar
  produces it), `effect` is `free` or `ask`, `state_digest` is the hex sha256 of the repository's
  program-selecting state at the time the human wrote the rule. A rule acts on a call only if the mode is
  `with-approvals`, the host is not Codex, the resolved repository matches, the command text matches exactly,
  the effect is `free`, and the current state digest equals the rule's. `push` and `gh` are never freeable, and
  a form that touches the gate directory (the mode, the rules or the log) is never free. `effect: ask` lets a
  human force a question even in `with-approvals` mode. Any mismatch, a malformed, duplicate-keyed, oversized or
  unreadable rule file, or a state digest that cannot be computed falls through to the normal decision, which
  asks. What cannot be measured, asks.
- The state binding (Punkt 4): the digest is the sha256 of a canonical serialization of the repository's
  effective configuration (`git config` with scope and origin), its effective hook directory (each hook's name,
  mode and sha256, including a `core.hooksPath` override), its attributes source, and the program-selecting
  environment. A rule carries the digest of the state when the human wrote it; the gate recomputes and compares.
  If the configuration, the hooks or that environment change, the digest differs and the rule stops acting — the
  gate asks again. A human computes the digest for a rule with `proofbundle_gate.py state-digest [--repo DIR]`.
- No file tool can create an approval (Punkt 3): `decide_write` denies — not asks — every write by a file
  tool whose target is the mode file, the rule file, the log file, or anything under the gate directory, under
  both hosts. A git command that would change those paths is never free. The gate has no code path that writes a
  rule or an approval; the rule file is read-only to the gate. A shell command can still write the gate directory
  (review Runde 15, F15-2, measured by the reviewer with `printf with-approvals > "$PROOFBUNDLE_GATE_DIR/mode"`).
  Under the owner's rule for the user path (2026-10-08, D27) making that visible is enough: every call a rule
  frees names the mode and rules files, when each last changed and its sha256, and says that the gate cannot tell
  who wrote them.
- Logging (Punkt 5): each gate-log entry carries the `mode`, and when a rule acted, `applied_rule`
  (origin `rule`, the form, the effect, the state match). A human revokes an approval by editing the rule file;
  the gate re-reads it on every call. The click path, when it ships, logs origin `click`.
- A rule never frees a form the net reports NOT MEASURED (owner correction to Nachtrag 37, part of the Punkt-2
  class). `_rule_candidate` consults the net's single decision site (`_net_unresolved`/`_net_unmodeled`), so an
  approval is possible only for a form the net also positively understood, in `with-approvals` mode as in `strict`.
  Without this a plain `git <local>` form the net could not build exactly like bash — a locale quote `$"…"`, a
  decoded NUL — could have been freed by a rule; now it is NOT MEASURED first and the rule cannot reach it.

Open owner cards (Nachtrag 24, Punkt 9; built strict until answered):
- Card 1 — the click path. Owner choice A (2026-10-04, 11:0x Berlin): measure by behavior which approval
  mechanisms the host Claude Code version offers and who can trigger each, with a small `claude -p` run and a
  logging hook, without reading the Claude Code binary (the classifier refusal stands). Until the click path is
  measured and chosen, it is absent: only the read-only rule file acts, so the model can never trigger an
  approval. The report carries the measured table.
- Card 3 — the rule-file location. The stricter default above (user-wide, never in a repository) is built now,
  because a rule file inside a repository is writable by the model through the Bash tool and by anyone who can
  push. Whether the owner also wants to allow a repository-local rule, under a human-owned control, is the card.

Options:
- A. Two modes in the plugin, a human-only gate directory, a read-only rule file bound by a state digest,
  write-deny on the gate directory, the click path deferred to a measured owner choice (chosen).
- B. One mode with always-on rules. Rejected: the owner asked for two modes, and a strict default is the safe
  one when the setting is missing.
- C. Rules inside the repository. Rejected as the default: the model and any pusher could write them (card 3).

## D26. Done only with a receipt (the Stop hook)

Owner choices (2026-10-08, 12:0x Berlin, Z169 aim E3): the user path "Claude says done" gets a local hook as an
early warning, with the hard boundary in CI. The promise: when Claude says done, that can be checked; the tests
ran at exactly this state, and anyone checks it without a network.

Chosen:
- The declaration may carry `"done": {"receipt": <path under .proofbundle/>, "policy": <path under
  .proofbundle/>}`, exactly these two keys. The schema string stays `proofbundle-plugin/evidence/v0.2`; the key
  is additive inside the unreleased 0.3.0 (D17, D18). A declaration with a done check and an empty evidence list
  declares no evidence for a push (`done_only`); since owner choice N2 C the push runs the done check at the
  pushed commit instead (D30). Measured on 2026-10-08 (at 395f0a87): the push path, `gh pr create`, the pre-push hook, the CI mode and the
  MCP diagnosis read such a committed declaration as an uncommitted one and asked (`declaration_uncommitted`,
  "a declaration exists in the working tree but is not committed"), and the CI mode failed it with exit 1 even
  without `require-declaration`. Repaired: each path reads it as declaring no evidence (`done_only`); the CI mode
  answers `not_required`, or `declaration_required` where the workflow requires evidence
  (tests/test_plugin_gate_done_only.py).
- A `Stop` command hook (`proofbundle_gate.py stop`) reads the declaration and the policy from HEAD (D2) and the
  receipt from the working tree. The turn ends only when the receipt verifies under that policy (which must pin a
  signer, D7), its signed claim says that every test passed — pytest, `pass_rate`, comparator `>=`, threshold 1,
  `passed` true, `n` at least 1 and `provenance.exit_status` 0 — and the tree it ran on equals the tree id of the
  working state now. A threshold below 1 signs `passed` true for failing tests, and pytest's receipt signs
  `passed` true for a run that exited 1 when the rate met the threshold (measured 2026-09-30, D23), so neither is
  done.
- The tree the receipt ran on is `provenance.git_tree` when `git_clean` is true and `git_worktree_tree` when it
  is false; the package's pytest plugin writes both (the core change of the same date). The working state is the
  files of HEAD and every other file git does not ignore, outside untracked files of the top-level `.proofbundle/`
  folder and of `__pycache__` folders, read as raw bytes and modes (100755 when the owner may execute a file)
  without filters, fsmonitor, hooks or the index, and hashed into git's tree object format. The package and the
  gate use the same rules, so both name the same tree for the same bytes; a test compares the gate's tree id with
  git's own for a working tree without filters.
- No declaration, or a declaration without a done check: no block and no message (NOT MEASURED, as D5). A
  declaration only in the working tree, a missing policy or receipt, a receipt that is a link, a verifier that
  cannot run, a working state that cannot be read as files and any error inside the check block: the turn does
  not end on a check that reached no verdict. Every block is one line with what is missing, the command that
  delivers it and the rule never to weaken the declaration, the policy or the key (D19).
- `done-check --repo DIR [--receipt FILE]` is the same check for CI (exit 0 only for a pass), and `done-init`
  sets the check up: a local test key with the package's key path in the gate directory, a policy that pins it,
  the done section and an ignore rule for the receipt, staged.

Limits: Claude Code ends the turn after nine blocks in a row without a tool call (measured with Claude Code
2.1.294 in the eval done-receipt-other-tree-blocks on 2026-10-08: "A hook blocked the turn from ending 9
consecutive times — overriding and ending turn"; `CLAUDE_CODE_STOP_HOOK_BLOCK_CAP` raises the limit), so the hook
is an early warning; the boundary is the required CI check. The agent
that runs the tests can read the test key, and repository code under pytest can write the receipt. A receipt binds
the tree, not which tests the run selected: a run that leaves a failing test out (`-k`, a path, `--deselect`,
`PYTEST_ADDOPTS`) signs passed true for the same tree (measured with `-k`, 2026-10-08), so only a run with the
repository's own command, as in the CI job, decides which tests count. Codex is not
wired: NOT MEASURED there. (D28 wires Codex to the same Stop hook and binds the selection of each check.)

Options:
- A. The done section in the declaration, a command Stop hook and the same check in CI (chosen).
- B. A Stop hook that runs the tests itself. Rejected: a hook that runs repository code at every end of a turn is
  a new execution surface and slow; the receipt already records the run.
- C. A done check without a declaration, for every repository. Rejected: it would block repositories that never
  asked for it, against D5.

## D27. Local hooks are an early warning; the ways around the shell check are a class

Owner rule (2026-10-08, for findings on the plugin from now on):
- Local hooks are an early warning, not a boundary. The boundary for publishing is the required CI check (D22,
  D26).
- The ways around the shell check of the `PreToolUse` gate are not chased one by one any more. They stand here
  as one known limit, a class with examples: R14-1 to R14-4 (a wrapper option or a reserved word that shifts the
  program position, a context the lexer cannot parse, a `$(…)` boundary the net could misread, the verifier's
  initialisation and notification contract), F15-1 (an extended glob such as `bash -O extglob -c 'g@(it)
  status'` builds the program word `git`), F15-3 (the state digest binds the search path, not the program it
  selects, so a swapped `git` at the same path keeps a rule acting) and others of the same kind. A shell can
  build a command from text the gate does not model; Level 1 cannot close that class.
- Repaired is what makes a receipt, a verify or the required CI check falsely green, and what lets the agent
  switch the early warning off silently. F15-4 is repaired: no JSON read of the gate or the server takes `NaN`,
  `Infinity` or `-Infinity`, and a logging notification with a level MCP does not define refuses the verifier
  run (at 13753b7e a progress notification with `NaN` let a green reply through). F15-2 is made visible (D25).
- Review round 15 in its former form is dropped; the review of the whole user path replaces it. D24B was an
  owner decision then; the owner decided it on 2026-10-08 (K5-D C).


## D28. The order: required checks, each bound to HEAD, for both hosts

Owner choices (2026-10-08, 16:3x and 18:32 Berlin, cards KRAXO-CLOUD-NUTZERWEG-SCHAERFEN-01 and
KRAXO-CLOUD-NUTZERWEG-NORDSTERN-01): done only with a receipt for commit and tree, from one folder for Claude Code
and Codex; a task names its required checks; a missing step is named and handed back; only the matching closure is
accepted.

Measured first (2026-10-08): the decision receipt (`decision-receipt/v0.1`) carries a signed authorization whose
`decision.obligations` and `decision.allowedScope` are untyped arrays, so it carries checks and paths only by a
convention on those arrays that no format defines; the signed evaluation receipt carries a `criteria_digest` of a
criteria set, not commands, paths or a key. Neither carries the order as it stands.

Chosen (option B of the owner card for N1):
- The `done` section may be the order `{"policy", "checks"[, "paths"][, "max_blocks"]}`. Each check is
  `{"id", "args", "receipt"}`: a name, the pytest arguments the run must have been given, and the receipt it leaves
  under `.proofbundle/`. `paths` are fnmatch patterns (`*` also matches `/`) of the paths the work must and may
  change, compared between the tree of the commit that declared the order and the working state (since owner choice
  Nordstern B, D31; before, the last commit that changed the declaration); `max_blocks` is 1 to 7, default 3. The
  one-check form `{"receipt", "policy"}` stays and is one check, `tests`, with any selection. The order is changed
  by a commit; who may change it is whoever may merge a change to `.proofbundle/`, which CODEOWNERS assigns in CI.
  Locally the hook cannot tell the owner's commit from the agent's.
- Every check needs its own receipt that verifies under the policy at HEAD, says that every test passed (D26),
  names HEAD's commit and tree, names the tree of the working state now, and, under the order, was run with exactly
  the check's pytest arguments, an empty `PYTEST_ADDOPTS` and no deselected test. The package's pytest plugin
  writes `pytest_args`, `pytest_addopts` and `n_deselected` into `provenance` (core change of the same date).
- A block names the first open check, its kind (no change, missing, unverified, red, other selection, no state,
  stale, outside paths), the command that closes it and the other open checks, in one line. Claude Code and Codex read
  the same answer: `decision` and `reason` for a block, `systemMessage` for a pass or a blocker; the hook never
  sets `continue`. Codex runs the same `stop` from `.codex-plugin/plugin.json` with `--host codex`.
- After `max_blocks` blocks with the same open points (kind and check, not the trees) in the same session, the hook
  writes `.proofbundle/done-blocker.json` with the open points, their commands and the commit, tree and working
  tree it measured, and lets the session end without a done verdict. A pass removes the blocker. `open` is every
  open point of the last verdict in its order (status, what was found, the command, and the paths for
  outside_paths), `paths` the order's patterns and `order_base` the commit that declared the order; `checks` lists
  every check. Measured by the review of 2026-10-09 (F5) and in the host runs codex_run_nochange and
  codex_sandbox-nochange of 2026-10-08: before, the blocker listed only the checks, all green, and an empty
  `outside_paths`, so the one open point, no change in the order's paths, was not in it.
- Every refusal counts toward `max_blocks`, also one that comes before the checks are read (review 2026-10-09, F6,
  measured at 91a52faa: a shallow clone, order_base_not_measured, blocked at every stop and never reached the
  blocker). An uncommitted declaration (`declaration`), a missing policy (`policy`), a working state that cannot be
  read as files (`state`) and a history cut before the order (`paths`) are each the one open point of their result,
  and a check that fails (`gate_error`, `internal_error`) is the open point `done-check` of what it had reached.
  Where no order could be read, the default limit of 3 applies. Input that names no repository counts nothing.
  `.proofbundle/done-metrics.json` counts blocked ends, blocked task completions, missing checks, ends completed
  after a block, blockers and passes; `.proofbundle/done-state.json` holds the current count. The files are written
  through a fresh temporary file that replaces them, never through a link, and are untracked under `.proofbundle/`,
  so they are not part of the working state. Their content is counted, never trusted for a verdict.
- Claude Code's `TaskCompleted` hook runs the same check. The gate prints the line and exits 0; the hook command
  turns a printed line into exit 2 with the line on stderr, and any other exit into exit 2 with its own line,
  because Python itself exits 2 when it cannot open the gate (measured). Codex has no such event.
- `done-check --receipt-dir DIR` reads one receipt per check from `DIR/<id>.json` for CI.
- `done-check --at-commit REV` gives the verdict for that commit, as the check at a pushed commit does (N2 C): the
  declaration, the policy and the order from the commit, its tree in place of the working state, and at a commit
  only a clean run counts (`git_clean` true; a receipt for a working state that differed from the commit fails,
  whatever tree ids it names). The CI template passes the commit it checked out, from the event, never HEAD,
  because the test command runs the code under review and can change the working tree and move HEAD. Measured by
  the review of 2026-10-09 (F1) at 91a52faa: without it, the job checked the working state the test command left
  behind and passed a receipt with `git_clean` false that the pre-push hook rejected.

Measured in host runs on 2026-10-08 (runs2 of the report): with Claude Code 2.1.294 and `claude -p --plugin-dir`,
valid work ends at the first stop; missing, foreign, stale, manipulated and red receipts block with their kind
and end in the blocker after three blocks when the agent is told not to run anything; the agent that is told to
run one of two checks is blocked with the other one's command, runs it and ends with a pass; `TaskUpdate` to
completed is refused with the same line. With Codex 0.161.0 and a scripted local model, the same cases give the
same answers in the same order.

Limits: everything in D26 and D27. The agent can commit a changed order or write the count file; the first changes
what the local hook asks for, the second can only end the session without a done verdict. A check binds the pytest
arguments, not plugins or conftest code that skip, select or rewrite tests. The `PreToolUse` gate asks before (Claude
Code) or denies (Codex) `git add` and `git commit` (D3, Nachtrag 23), so in a run without a person the agent cannot
commit and the done check can only pass on an uncommitted state. The `TaskCompleted` hook keeps every task open in a
repository whose order is not done.

Options for the carrier of the order (owner card N1):
- A. A decision receipt signed by the owner's key, with the checks in `obligations` and the paths in
  `allowedScope`. Carries the key that may change it, but needs a convention for both arrays, which is a new
  profile of the format, and a pin of the owner key that the agent cannot rewrite.
- B. The `done` section of the declaration at HEAD (chosen). No new evidence format; the key that may change it is
  not carried, review of `.proofbundle/` decides.
- C. The criteria set of a signed evaluation receipt. Carries criteria, not commands, paths or a key; rejected.

## D29. The done check as an in-toto Statement v1 in DSSE

Owner choice (2026-10-08): the output also as an in-toto Statement v1 in a DSSE envelope, built as
draft-gruszka-evaluation-receipt-mappings describes, with commit and tree as subject and the receipt cited by
digest; no new format and no new predicate type.

Measured first: the mappings draft cites a receipt from an in-toto Statement only in the SLSA Verification Summary
(its Section 4.3, `inputAttestations`); it does not cite from the test-result predicate (Section 4.2), and its DSSE
form (Section 4.1) carries the receipt's bytes, not a subject. The receipts of this user path are pytest receipts of
the package (`proofbundle/eval-claim/v0.1` in a `proofbundle/v0.1` bundle), not signed evaluation receipts of
draft-gruszka-signed-evaluation-receipts, which no release of the package writes yet.

Chosen:
- `done-statement --repo DIR --key FILE --out FILE --resource-uri URI [--receipt-dir DIR]` writes, only for a passing
  done check on a clean state, a Statement v1 with predicate type `https://slsa.dev/verification_summary/v1`:
  subject `{"name": <resource URI>, "digest": {"gitCommit", "gitTree"}}` of HEAD; `inputAttestations` one
  `{"digest": {"sha256": <SHA-256 over the receipt's signed payload bytes B>}}` per check, in the declared order;
  `policy` with the URI `<resource URI>@<commit>#<policy path>` and its `sha256` and `gitBlob`; `verifier.id` the
  plugin's done check with the versions of the plugin and the pinned package; `verificationResult` `PASSED`;
  `verifiedLevels` `["SLSA_SOURCE_LEVEL_UNEVALUATED"]`; `slsaVersion` `1.2`. The envelope is the package's own DSSE
  (`dsse.sign_envelope`), with `keyid` the SHA-256 of the raw public key, signed with the key file through the pinned
  package. A resource URI with user information is refused, so no token lands in a signed statement.
- A foreign reader is a test (`PROOFBUNDLE_FOREIGN_INTOTO_PYTHON`): securesystemslib 1.5.1 verifies the envelope with
  the test key and refuses another key and a changed payload; in-toto-attestation 0.9.3 reads and validates the
  Statement.

Measured on the foreign reader: the VSA v1 binding of in-toto-attestation 0.9.3 types `verifiedLevels` as one string
where SLSA VSA v1.2 has an array, has no `verifier.version`, and reads only `uri` and `digest` in an
`inputAttestation`; it refuses the specification's shape even with unknown fields ignored, and refuses the
`mediaType` of the mappings draft's own example in strict mode. The statement follows the specification and cites by
digest alone; the test holds the binding's refusal so that a release that reads the specification turns it red.

Options:
- A. A Verification Summary from the done check (chosen): the only way the mappings draft cites a receipt from a
  Statement.
- B. A test-result Statement from the pytest plugin: the draft does not cite from it, and the producer would attest
  its own run.
- C. The receipt itself as a DSSE envelope: no subject, no Statement.
- D. The package's own `verification-summary/v0.1` predicate: not the draft's mapping, and a predicate type the
  owner did not choose.

## D30. A push requires the done check at the pushed commit (owner choice N2 C, 2026-10-08)

Chosen: a push runs the done check of D26 and D28 at every commit it sends as a tip, the same check as at the end
of a session, for the tree the push sends.
- Where: Level 1 under Claude Code (`git push`, and `gh pr create` and `gh release create` as a push of the
  current branch to its upstream), and Level 2, the pre-push hook (D24). Under Codex Level 1 only warns (D12,
  Karte 5 A), so Level 2 carries the check there (Karte 5 D).
- What: the declaration, the done policy and the order are read from the pushed commit; its tree, read from git
  (`commit_state`), stands in for the working state; the receipts are read from the working tree, where the
  tests left them. A receipt passes the push only when it verifies under that policy, says that every test
  passed, was run with the check's selection, names the pushed commit and its tree, and ran on that tree; with
  `paths`, the pushed tree changes at least one of them and no other path since the commit that declared the order
  (D31).
- An uncommitted change in the working tree does not matter for the push (it does for the end of a session),
  and a receipt of a run on uncommitted changes does not pass the push, because the tree it ran on is not the
  tree the push sends. A push of a commit that is not HEAD names it, and the next step says to check it out
  before the tests run.
- A failed done check denies the push before any ask, as a failed evidence check does, and also where the
  target comparison is NOT MEASURED (a branch the repository does not track, a new remote ref): the pushed
  commit is still known, so the failure is proven (Befund 1 of review Runde 6). A pass cannot heal an
  unmeasured comparison. A pushed commit whose declaration has no done check gets none.
- Evidence and done are both required where both are declared; a push that declares only a done check passes
  on a passed done check (reason `done`).

Measured (tests/test_plugin_gate_n2c_push_done.py, 2026-10-08): the counter-probes missing (`no_receipt`),
foreign key and manipulated receipt (`verification_failed`), receipt for an earlier commit (`stale_receipt`) and
red tests (`not_done`) deny at Level 1 and make the pre-push hook exit 1; a valid receipt passes both. Through git
itself, with the hook in a throwaway repository's local `core.hooksPath`, a missing or stale receipt keeps the
remote ref where it was and a valid one moves it.

THE DONE CHECK IS AN EVIDENCE RULE (owner choice N2C-1 B, 2026-10-08)
- Measured at 31031eb6 (2026-10-08): a push whose own commit swapped the done policy to a new key, with a receipt
  signed by that key, passed Level 1 (`pass`, reason `done`) and the pre-push hook exited 0, because the done
  section and the done policy were not rules of the push comparison (D20).
- Chosen: both are rules (D20). A push whose sent commits change the `done` section or the bytes of the done
  policy against the target's known state asks under Claude Code (`rules_changed`, with "the done policy ...
  changes", "the done check changes", "the push adds a done check" or "the push removes the done check"), and
  Level 2 blocks it (exit 1). Under Codex the plain push still only warns at Level 1 (D12), so Level 2 carries it.
- Order: a failed done check at the pushed commit still denies first; the rules are compared after it, as after a
  failed evidence check (D20).
- Price: a new order is a rules change. Declaring or changing an order and pushing it asks once, as a new evidence
  policy does; a person reviews it, and once the target's remote-tracking ref holds it, later pushes are plain.
- Measured (tests/test_plugin_gate_n2c1_b.py; probe_done_policy_swap): the swap to a new key, a rewritten policy
  with the same key, each part of the section, an added and a removed done check ask at Level 1 and exit 1 at Level
  2; an unchanged done check with a valid receipt passes; a receipt and a note under `.proofbundle/` are no rule.
  Red at 31031eb6: 13 of 14 (the one green is that control).
- Still the boundary: the local test key is readable by the agent anyway (D26); the required CI check with its
  own key and the review of `.proofbundle/` decide.

Options:
- A. Unchanged: a push runs only the evidence check (D20).
- B. A push additionally verifies a declared bundle item's run record (D23 option C).
- C. A push requires the done check at the pushed commit (chosen).

## D31. An order that names paths is done only with a change in them (owner choice Nordstern B, 2026-10-08)

Measured in the real Claude Code run Lauf 1 of KARTEN-01 (2026-10-08): the agent changed nothing, ran both checks of
the order with receipts, and the Stop hook said done, because the receipts named the unchanged state and no path
outside the order had changed.

Chosen:
- Where the order names `paths`, the done check also requires a change in them: at least one path that matches a
  pattern differs (bytes or mode) between the tree of the commit that declared the order and the state the receipts
  are for. At the end of a session that is the working state, uncommitted changes included (owner choice K1 C); at a
  push it is the tree of the pushed commit (D30), so an uncommitted change does not count for the push.
- Without such a change the end of the session blocks with the open point `no_change` first, before missing
  receipts, naming the paths and the commit that declared the order, with the next step "do the work the order asks
  for in <paths>, then run the checks again"; a push is denied at Level 1 under Claude Code and at Level 2 (reason
  `no_change`). A change only outside the paths is both `no_change` and `outside_paths`.
- The commit that declared the order (`order_base`): on the first-parent line, the newest commit that changed the
  declaration and whose first parent declares another order or none. A later change of the declaration that keeps
  the done section as it is (an evidence item, a subject, a reformatting) does not move it; a new order does, and
  work before it does not count for it. The same base now serves `outside_paths` (D28).
- Where it cannot be determined, the check is NOT MEASURED and blocks, never a pass (`order_base_not_measured`):
  a shallow clone cut before it (the cut commit is in git's shallow list), more than `MAX_ORDER_WALK` (256) commits
  that changed the declaration, or git cannot list them. The next step is `git fetch --unshallow` or a person.
- An order without paths, and the one-check form, are as before: no change is required.

Delimitation from D26: D26 makes "done" mean that receipts signed by the pinned key name exactly the state at hand
and say that every test passed; it never said that the work was done, and it still does not. D31 adds one measured
fact for an order with paths: something in those paths changed since the order was declared. It does not say that
the change does what the order asks, that the tests test it, or that a change in a test file alone is the work;
`tests/*` in the paths counts like any other pattern. The patterns are the owner's; an order that names a path the
agent may change at will gets a weak check. As in D26, the local hook is an early warning (D27); the boundary is
the required CI check and the review of `.proofbundle/`.

Measured (tests/test_plugin_gate_nordstern_b.py, 2026-10-08): no change blocks with the missing work named; a change
only outside the paths blocks as no change and outside paths; a change in the paths passes, committed or not; the
missing work comes before missing receipts; an order without paths is as before; a later declaration change that
keeps the order does not move the base, a new order does; a root commit can declare the order; a shallow clone cut
before the order is NOT MEASURED and one deep enough passes; past the walk limit the base is NOT MEASURED; a push of
a commit without a change in the paths is denied at Level 1 and Level 2, and one with the work passes; an
uncommitted change does not count for the push. Red at 31031eb6: 11 of 14 (the three green are the controls: an
order without paths, a deep enough shallow clone, a push with the work).

Options (owner card Nordstern of KARTEN-01):
- A. Leave it: done means green receipts for the state at hand (D26).
- B. With paths, done requires a change in them since the commit that declared the order (chosen).
