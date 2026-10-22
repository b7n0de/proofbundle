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
  with a submodule has no digest, and the gate says so. Nor has a tree that names a path twice, a file or a folder
  at any depth, the `.proofbundle` folder included: git's lookup reads the first of the two entries and a checkout
  writes the last, so no one manifest stands for it. Every place that makes or checks the digest refuses such a tree
  the same way: the gate's function and with it the evidence check, the CI mode, `run-evidence` and the
  `tree-digest` command, and the README's recipe; the digest of every tree that names each path once stays
  byte-equal (review round 12 of 2026-10-13, B-17, owner's choice to fix it now: `src/` naming `app.py` twice had
  given two records for one path, and evidence signed over them had passed the CI mode).
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
      a state check" below), and, since the owner's answer 1 of 2026-10-14, under Claude Code the read forms of
      class a after the read profile of their repository (D34). The separate push path remains. Under Claude
      Code it denies an evidenced failure at the commits a push sends and otherwise asks: the resolution of the
      push's destination is NOT MEASURED whatever the fetch rules (D3, review round 9 of 2026-10-11, R9-1), and the comparison with the
      destination's state is Level 2's, on git's own ref lines (review round 10, R10-5); a repository that declares
      nothing stays outside Level 1, as local inactivity with no decision, where the four conditions of owner choice
      1 A of 2026-10-11 hold (D5); under Codex every push
      is NOT MEASURED because its execution context is unbound, and since owner choice Karte 5 A of 2026-10-08
      it warns instead of being denied (D12).
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
  else, so the ref records the state of that branch and not another (review R3-2). The fetch rules are read as git
  2.43.0 reads them, every remote's (review round 6 of 2026-10-10, R6-3; refspec.c, remote.c, measured): a negative
  refspec excludes the remote refs it names, exactly or by a pattern whose one `*` may stand anywhere, so an
  excluded target branch is never fetched into its tracking ref (`git fetch` exits 0 and leaves it as it was) and
  the comparison is NOT MEASURED, while an excluded source writes nothing and is no collision; a `*` in the middle of
  a side maps as a trailing one does; a short name or an empty source (the remote's HEAD) writes the tracking ref like
  any other source; another remote whose fetch rules write the tracking ref makes it record that remote; and a rule
  git refuses is NOT MEASURED. A source without `*` names whatever ref of the remote git resolves it to (review round
  7 of 2026-10-10, R7-4; remote.c get_remote_ref, measured with git 2.43.0 and 2.51.1): `other` is refs/heads/other,
  and refs/heads/gone is refs/heads/refs/heads/gone where the branch gone is missing, and a negative refspec is
  compared with that resolved ref, so `^other` excludes nothing. The remote's refs are not evidenced here, so a plain
  source that writes the tracking ref, or any plain source of the pushing remote, makes the comparison NOT MEASURED;
  the single-branch rule `+refs/heads/main:refs/remotes/origin/main` of `git clone --single-branch` among them. Owner
  choice A of 2026-10-10 (question A of round 7) keeps the single-branch rule NOT MEASURED; its exact form is not taken
  as read. `git clone --depth` writes the single-branch rule unless `--no-single-branch` is given. With
  `--no-single-branch` git writes the pattern rule; as long as the clone stays shallow, the check of the newly
  reachable commits is NOT MEASURED all the same (measured with git 2.43.0 and 2.51.1: `--depth 1` wrote
  `+refs/heads/main:refs/remotes/origin/main`, `--depth 1 --no-single-branch` wrote `+refs/heads/*:refs/remotes/origin/*`,
  both clones shallow). A full clone with a pattern fetch rule avoids both restrictions. git fetch --unshallow removes
  the shallow-history restriction but leaves the fetch rules unchanged. The
  gate had read `^other` as excluding `+other:refs/remotes/origin/main` and passed. The gate had skipped every fetch refspec without a colon and every `*` not at the end.
  There is no default-branch fallback: a new
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
  updates), and to the target git sets, or to none (review round 6 of 2026-10-10, R6-2 and its class; measured
  with git 2.43.0, builtin/push.c and remote.c): the remote is the first of `branch.<name>.pushRemote`,
  `remote.pushDefault` and `branch.<name>.remote` that is present, whatever its value, else the one configured
  remote, else `origin`. A present empty value is not an absent one: git takes it and cannot push ("no path
  specified"), so the push is NOT MEASURED, where the gate had fallen through to the next key and passed. The
  destination follows git's own refusals: `simple` to the branch's own remote needs exactly one upstream, written as
  the branch's full ref, and a branch remote; `upstream` needs the branch's own remote and one upstream;
  `push.autoSetupRemote` stands in for an upstream not set at all. `push.default` is read with its case, as git
  reads it. The branch is HEAD's full refname, never its short form, which a tag of the same name turns into
  `heads/main` (review round 7 of 2026-10-10, R7-2: the gate had read `branch.heads/main.*` and compared against a
  remote branch `heads/main`). A refspec source that names more than one ref, a branch and a tag of one name, is NOT
  MEASURED: git push refuses it ("matches more than one", measured with git 2.43.0 and 2.51.1), while `rev-parse`
  takes the tag. The destination is resolved in git's meaning, not read from its spelling (review round 8 of
  2026-10-10, R8-2; remote.c count_refspec_match with the rules of refs.c ref_rev_parse_rules, measured with git 2.43.0
  and 2.51.1): git looks the destination value up among every ref the remote advertises, so for refs/heads/main it also
  matches refs/heads/refs/heads/main, refs/tags/refs/heads/main and refs/refs/heads/main, and for a short main
  refs/tags/main and refs/main. Two such matches make git refuse the push ("dst refspec refs/heads/main matches more
  than one"), and where refs/heads/main is missing git writes the other ref; a match under refs/remotes/ counts only
  where there is no other. The value is the part after the colon, and for a refspec without one the source's own full
  name (`git push origin rel` with a tag rel writes refs/tags/rel). The gate had passed `git push origin main` beside a
  remote refs/heads/refs/heads/main, where git refused the push and left both refs as they were. The remote is not
  read, and nothing this repository holds shows a candidate absent there (review round 9 of 2026-10-11, R9-1;
  measured with git 2.43.0 and 2.51.1): a configured fetch rule proves no fetch that ran under it,
  and a fetch and a push see different sets of the remote's refs, since `uploadpack.hideRefs` hides a ref from the
  fetch and not from the push. So every candidate other than the destination leaves the resolution unevidenced, every
  value has such candidates, and every Level 1 push is NOT MEASURED, whatever the fetch rules and the spelling of the
  destination (owner choice C of 2026-10-11: A stays, read strictly). A candidate this repository records is named in
  the answer as what this repository records, never as what the remote holds. Withdrawn: round 8 said here, in the
  answer and in its report that two further fetch rules, `+refs/tags/*:refs/recorded/<remote>/tags/*` and
  `+refs/refs/*:refs/recorded/<remote>/refs/*`, make a full destination measurable after the next fetch. With a
  candidate hidden from the fetch by `uploadpack.hideRefs`, or with the two rules set after a fetch with `--no-tags`
  and no fetch since, the gate passed `git push origin main` where git refused it ("dst refspec refs/heads/main matches
  more than one") and left both refs as they were. Level 2 is not affected: the pre-push hook gets the remote ref git
  resolved against what the remote advertised to the push. Outlook, not built: a later handover of a push whose
  resolution is NOT MEASURED to Level 2 would, by the review of round 9, need four conditions: only the resolution
  reason is handed over (an evidenced failure stays a deny, and a gh, MCP or send-pack route is no handover); the call
  is bound to the git program, repository, worktree, environment, effective configuration, hook path, full hook
  bytes, plugin version and runtime, and `--no-verify` or a change to any of them voids it; git runs the hook with the
  real ref lines, every ref is checked with its newly reachable commits, every failure stops the push and no verdict
  is inherited; and only a Level 2 that ran gives the verdict, so inactive or empty ref lines are no positive finding.
  Built since 2026-10-14 with the transport rule and the contract of review round 18 (D35): a push whose one open
  reason is the default destination case, whose transport a person approved and for which a bound Level 2 is
  installed, is handed over with no permission decision; every other push asks as described here.
  A configuration key git cannot parse is not read as unset: unset is exit 1 with nothing said. Every
  push value git parses is read before any step of the resolution, explicit or bare, whatever the case needs (review
  round 7 of 2026-10-10, R7-3; measured with git 2.43.0 and 2.51.1): `push.autoSetupRemote`, `push.followTags`,
  `push.useForceIfIncludes`, `push.negotiate`, `push.useBitmaps` and `submodule.recurse` as booleans, every value;
  `push.gpgSign` as a boolean or `if-asked`; `push.recurseSubmodules` as false, `check`, `on-demand` or `only`;
  `push.pushOption` with a value, read as the list git builds from it: each value appended, an empty value clearing
  the values before it, and any `-o`/`--push-option` of the command replacing the list for that push, so an option of
  the list git uses that holds a newline stops git push and the push is NOT MEASURED, while a newline value an empty
  value cleared, or the command line replaced, does not count (review round 8 of 2026-10-10, R8-3: `pushOption =
  "one\ntwo"` had passed while git refused the push with exit 128, measured with git 2.43.0 and 2.51.1; `-o` with a
  newline on the command line had passed too); `color.push` and its slots. A value git refuses stops git push, also one before a
  valid value, so the push is NOT MEASURED. A present `on-demand` or `only` of `push.recurseSubmodules`, or a present
  true `submodule.recurse`, is NOT MEASURED whatever value follows it: with such a value in effect git pushes the
  submodules' commits besides, git takes the last value, so a later false turns that off, and the gate does not decide
  which value is in effect (owner choice B: A, 2026-10-10). Its reason names the value present, not what git pushes:
  "The configuration contains submodule.recurse=true; submodule push behavior is NOT MEASURED." (review round 8 of
  2026-10-10, R8-5: the gate had said git pushes the submodules' commits where a later false and
  `push.recurseSubmodules=false` kept the transport off, measured by the reviewer with git 2.43.0 and 2.51.1). The
  answer carries the reason the gate found, this one verbatim, with a next step for it; so does the answer for a
  newline in a push option and for a destination whose resolution is not evidenced, whose next step is a person's
  review of the push, since no fetch rule makes that resolution evidenced (R9-1; round 8 had named two fetch rules
  there; found in the milestone runs of round 8: the reason had stayed inside the gate, and the answer
  had listed other causes, a URL remote, --all, a wildcard, and told the user to name the refspec they had named). The
  gate had read `push.autoSetupRemote` only for a branch without an upstream. The source
  check of an unresolved bare push takes the same choice, so it no longer names HEAD where git pushes a configured
  push list of another remote. Every name and list the resolution reads from git keeps the bytes git printed (review round 5 of
  2026-10-09, R5-1): a configuration value and the branch of HEAD lose only their one closing newline, the
  remotes are one per line, value lists, URLs and fetch refspecs are read whole (`--null`, a blank URL counts), and a
  fetch refspec loses only its one force sign (git maps nothing for `++refs/heads/*:refs/remotes/origin/*`).
  Measured with git 2.43.0: a `pushRemote` of `origin ` pushes to that remote, a branch ending in U+0085 is a new
  branch on the remote, a second `pushurl` of one blank is a second endpoint, and an `insteadOf` prefix holding
  U+0085 rewrites the URL; the gate had judged each against `origin/main`.
- The push endpoint must be one URL, equal for fetch and push, so the remote-tracking ref records the state
  of the endpoint the push updates. A `pushurl` or a second `remote.<name>.url` sends the push elsewhere or
  to a further endpoint and is NOT MEASURED (Befund 1). `remote.<name>.url` is a list git reads with a reset rule
  and a fallback (review round 8 of 2026-10-10, the class of R8-3; measured with git 2.43.0 and 2.51.1): git 2.51.1
  clears it with an empty value, git 2.43.0 keeps the empty value as a URL and refuses the push ("no path
  specified"), and where no URL is left both take the remote's own name for one (remote.c, add_url_alias) and push
  to that path below the top level, into a repository that stands there. Only exactly one non-empty configured value
  reads the same under both, so any other URL list is NOT MEASURED, a list newer git resets to one URL included;
  `git remote get-url` had shown `origin` on both sides and the gate had passed. A `url.<base>.insteadOf` **or**
  `url.<base>.pushInsteadOf` rewrite that applies to this remote also makes the push NOT MEASURED (review
  R4-7, Runde 5 Punkt 9). Which rule applies is resolved by git's own rules (Runde 6, Punkt 2): an
  `insteadOf` rule rewrites a configured `url` or an explicit `pushurl` it is the longest matching prefix
  of; a `pushInsteadOf` rule rewrites the push side of a `url`, and git ignores it for a remote with an
  explicit `pushurl`. A rule that provably matches none of this remote's URLs is excluded, so a common
  global rule for another host no longer turns every push NOT MEASURED. A rule that does apply keeps the
  comparison NOT MEASURED even when the effective fetch and push URLs are equal: equal URLs do not prove
  where the existing tracking ref came from (a rule configured after the last fetch rewrites both), and
  how common a rule is (an SSH rewrite, say) is no reason to release a comparison it applies to. Since round 9
  (R9-1) Level 1 compares nothing against a remote-tracking ref: every push ends NOT MEASURED at the destination
  check, whatever the rewrites and the fetch rules, and the comparison with the destination's state is Level 2's,
  on git's own ref lines, whose verdicts say they compare against the remote's state as git reported it (review
  round 10 of 2026-10-11, R10-5: this paragraph had still described a Level 1 comparison against the last known
  state of the target, with pass and inactive among its verdicts).
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
- The environment, name by name (review round 6 of 2026-10-10, the class of R6-1; the names of git(1) 2.43.0 and
  those compiled into the installed binary): every gate read runs in the environment the git it judges runs in, so
  `GIT_DIR`, `GIT_WORK_TREE`, `GIT_COMMON_DIR`, `GIT_CEILING_DIRECTORIES`, `GIT_DISCOVERY_ACROSS_FILESYSTEM`,
  `GIT_OBJECT_DIRECTORY`, `GIT_ALTERNATE_OBJECT_DIRECTORIES`, `GIT_CONFIG_GLOBAL`, `GIT_CONFIG_SYSTEM`,
  `GIT_CONFIG_NOSYSTEM`, `GIT_CONFIG_COUNT`/`_KEY_<n>`/`_VALUE_<n>` and `GIT_CONFIG_PARAMETERS` are read from the
  same source, and in the same meaning (review round 7 of 2026-10-10, R7-1; measured with git 2.43.0 and 2.51.1): git
  takes a relative `GIT_DIR` or `GIT_WORK_TREE` once, against the directory it starts in, while the gate's reads after
  the first run in the work tree that directory names, so each of them carries the absolute values git named in the
  call's directory, and the git directory git found there where `GIT_WORK_TREE` comes without `GIT_DIR`. Started
  outside its work tree, git reads a relative value of `GIT_INDEX_FILE`, `GIT_OBJECT_DIRECTORY`, `GIT_COMMON_DIR`,
  `GIT_ALTERNATE_OBJECT_DIRECTORIES`, `GIT_SHALLOW_FILE`, `GIT_CONFIG_GLOBAL`, `GIT_CONFIG_SYSTEM`, `HOME`,
  `XDG_CONFIG_HOME`, `core.excludesFile` or `core.attributesFile` against that directory in one command and against
  the work tree in another (`ls-files --others` and `status` read two index files), so it is NOT MEASURED there. The
  gate had taken `GIT_WORK_TREE=repo` against the work tree and attested an empty subdirectory. Neutralized for the gate's reads: replace refs and grafts (above), `GIT_INDEX_FILE` (the working state
  is read with an index of the gate's own), `GIT_CONFIG` (it moves only `git config`, not push, add or commit, so the
  gate's `git config` reads would have read another file than the push), and the pathspec names
  (`GIT_LITERAL_PATHSPECS` set, `GIT_GLOB_PATHSPECS`, `GIT_NOGLOB_PATHSPECS`, `GIT_ICASE_PATHSPECS` dropped: the
  gate's paths are its own literal paths), and the trace variables `GIT_TRACE*` (they change what git prints, not what
  it reads; with a trace on stderr every absent configuration key had read as unreadable after R6-2, so every push
  was NOT MEASURED). `GIT_SHALLOW_FILE` is read through git's own view of each commit's parents
  (D28). Refused: `GIT_NAMESPACE` at Level 1, where git writes the push under `refs/namespaces/` on a local remote
  while the tracking ref records the plain branch; at Level 2 git reports the namespaced target's state itself (absent,
  so NOT MEASURED).
- A `gh pr create` or `gh release create` is judged as a push of the current branch to its upstream.
- An unresolved push is asked under Claude Code; under Codex every push is NOT MEASURED and, since Karte 5 A,
  warned about rather than denied (D12). Since R9-1 no Level 1 push resolves, and HEAD declaring nothing never
  switches the gate off on its own (N2); the one exception is owner choice 1 A of 2026-10-11 (D5): a push from a
  repository that declares nothing, whose sources are determined and in whose whole source history and local
  destination records nothing is declared, is locally inactive.
- Where neither the source nor the destination of a push is resolved, the answer names both reasons, the source's
  first, each found on its own (owner choice 2 A of 2026-10-11). A source that matches two strong refs here is named
  as one git push refuses (measured with git 2.43.0 and 2.51.1: a branch and a tag `main`); a source that answers to
  a strong and a weak ref is named as not determined (measured: git pushed refs/heads/main beside
  refs/remotes/main/HEAD). A destination whose resolution is unknown is never named as an ambiguity on the remote,
  and no commit is checked in place of an unresolved source.

Options:
- A. HEAD only, refspec not read (the pre-review behaviour; a push of another branch was judged at HEAD).
- B. Every newly reachable commit per resolved target, unresolved is NOT MEASURED (chosen).
- C. Treat a push whose refspec is not the current branch as NOT MEASURED (too coarse: it would miss a
  bare push of a branch the gate can resolve).

### D3, no git form is free (review Runde 9, owner choice B, 2026-10-03)

Chosen (owner, 2026-10-03): option B, remove the free list. The former free list for local git commands has
been removed. Those forms are NOT MEASURED, asked under Claude Code and denied under Codex (D12). Only the
exact bare command text `git --version` is exempt from judgment as a git form. The separate push path remains.
Under Claude Code it denies an evidenced failure at the commits a push sends and otherwise asks: the resolution of the push's destination is NOT MEASURED whatever the fetch rules (D3, review round 9 of 2026-10-11, R9-1), and the comparison with the destination's state is Level 2's, on git's own ref lines; a repository that declares nothing stays outside Level 1 where the four conditions of owner choice 1 A hold (D5); under Codex every push is denied because
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
- the locks on the gate's own git calls: the refusal to read objects under promisor-related configuration and
  `GIT_NO_LAZY_FETCH=1` (review Runde 7, R7-7), no filter, hook or fsmonitor in the diagnosis, in
  `tree-digest` and in `run-evidence` (review Runde 8, R8-1). The refusal reads the keys remote.<name>.promisor,
  remote.<name>.partialclonefilter and extensions.partialClone by their presence, whatever the value, and says that
  the gate does not evaluate that configuration; it claims no partial clone (owner choice of 2026-10-13, 15:1x
  Berlin, on C-5 of review round 14: true followed by false still started the transport program at an object read).

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

What is free. Exactly two forms, each as the whole command headed by a bare `git` with no global option (since D40
also with exactly one `-C` and a literal absolute path, which names the repository), no redirection, no chain and no
unvetted prefix assignment (the conditions of the bare `git --version` above); since the owner's choice of 2026-10-14,
16:2x Berlin, also as steps of a plain chain of `&&` and `;` (D33):
- `git add` with pathspecs and only `-A`, `--all`, `-u`, `--update` and `--`;
- `git commit` with at least one message (`-m`, `--message`, a cluster of `a`, `q` and `m` such as `-am`, and since D40
  `-F <file>` or `--file=<file>` with a literal file other than `-`), and only `-a`, `--all`, `-q`, `--quiet`, `--` and
  pathspecs.
Any other option (`-p`, `-i`, `-e`, `--renormalize`, `-S`, `-v`, `--amend`, `-F -`, `-C`, `-c`, `--trailer`,
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
with zsh 5.9), so alone it is literal. The value of a `-C` keeps the plain `~`, alone or before a slash, which the gate
joins with os.path.expanduser. `~name` is not modelled: zsh resolves it through its table of named directories
(`hash -d`), state of the running shell the gate cannot read, so with `hash -d pb_review_named=/path/B` zsh runs
`git -C ~pb_review_named` in B while bash and os.path.expanduser read a literal directory (review round 3 of
2026-10-09, R3-2). Like `~+`, `~-` and `~N`, which name directories of the shell's state too, it leaves the call
NOT MEASURED, and no verdict is given about either directory.

The predicate reads a word at the characters the shell expands (review round 2 of 2026-10-09, R2-6, measured at
87dcbed8 with bash 5.2 and zsh 5.9): a line continuation (backslash-newline) is removed first and an empty quote adds
nothing, so `''~` (zsh) and a backslash-newline before `~` (bash and zsh) are a leading `~`, and an `=` right after an
unquoted `=` or `:` is a rewrite as well (zsh under MAGIC_EQUAL_SUBST turns `a==git` into `a=` and the git program's
path). A `-C` value is joined as a home directory only when the word as written starts with an unquoted `~`; a quoted
or escaped `~` is the directory named `~` under the command's directory, where git runs it (R2-3: `git -C '~'` was
judged at the home repository).

A redirection is no longer dropped by the lexer (R2-1, R2-2). It is a token with its target, and two rules read it.
The hook check reads every redirection target as a word too, so a hook-disabling word denies whether the shell reads
it as an argument or as a target: zsh reads `<1-2> --no-verify` as a numeric glob and an option, bash as two
redirections. And no positive answer is given to a form whose redirection opens a file: only a duplication or a
close of a descriptor (`2>&1`, `>&2`, `2>&-`) and `/dev/null` written exactly so keep a push resolved under Claude
Code, the plain push under Codex (D12) and a rule candidate (D25); `> .git/hooks/pre-pus?` empties the pre-push hook
in bash and zsh before git starts. The two free forms were free only without any redirection already.

A refused `git add` or `git commit -m` whose words the shell may rewrite names the narrower spelling the gate frees,
when there is one: the paths after `--` (`git add -- *.py`) and a rewritten message in single quotes
(`git commit -m 'fix#12'`). The spelling is judged by the same scan first, so the hint never names a refused form.

The state check (`_add_commit_state_problem`), in the hook's environment, so git reads the same files the call reads:
- the effective configuration with every include, read by `git config --list --show-origin --show-scope`. A key of
  a program source is named as such: `filter.*` (an empty driver name included), `hook.*` and
  `gc.recentObjectsHook` (a hook), `core.fsmonitor` unless false, `gpg.program`, `gpg.<format>.program`,
  `gpg.ssh.defaultKeyCommand` and `commit.gpgSign` unless false (a signature program; a number is true, review
  Runde 9), `maintenance.*` and `gc.*` (automatic maintenance). "False" is what git itself reads as false
  (`git config --type=bool` on the value, no configuration read): `0`, ` 0`, `00`, `FALSE` and the empty value are
  false; ` no`, `no `, ` false`, `false ` and `0 ` are no boolean, and core.fsmonitor then names a program git starts
  (measured with git 2.43.0, review round 5 of 2026-10-09, the class of R5-1; a strip had read them as false, and
  `00` and the empty value, which start nothing, as on). An entry that came in through an include is named
  as such (since Nachtrag 21 by its scope, not the included file's path: D49). Every other key must be on the positive list `_STATE_INERT_KEYS` /
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
the host's normal permission flow decides whether the call runs. Since D53 a pass prints nothing: its verdict and its
reason ids stand in the log (D21). The gate never answers `allow`. A push handed over to
Level 2 (D35) is answered the same way: no permission decision, and a message that names the hand-over.

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
  repository, because nothing is declared. The host's normal permission flow decides. Since D53 the user sees a short
  line in its place, once per session and repository, and the model gets the message as before.
- Every other case where nothing was verified stays NOT MEASURED and `ask`, and `deny` under Codex
  (D12):
  - a declaration only in the working tree;
  - an empty evidence list;
  - a directory outside a git work tree;
  - a repository without a commit;
  - a directory the gate cannot resolve;
  - a HEAD or a working tree where the gate cannot measure the absence, such as a failing `git ls-tree`,
    a file where the `.proofbundle/` folder should be, or a dangling link at the declaration's path;
  - a commit where a tree on the way to the path the gate reads, the root tree included, names one entry twice.
    git's lookup of `<commit>:<path>` takes the first of the two and a checkout writes the last, so neither is a
    whole reading of the path, for its bytes, its object id or its absence, and the gate gives none (review round 11
    of 2026-10-12, the class of R11-4: with the declared `.proofbundle` folder first and a second one after it, the
    pre-push hook passed the commit while its checkout declared an empty evidence list or held another policy).
  The answer keeps three cases apart: a measured absence (inactive, or `declaration_uncommitted` where the working
  tree holds a declaration the commit lacks), and a declaration the gate could not read at the commit, over the
  read limit, in a tree not read whole or in a commit this repository does not hold (`declaration_unread`, NOT
  MEASURED, with the cause and a fitting next step, never called absent or uncommitted; review round 12 of
  2026-10-13, B-12: a committed declaration of 65537 bytes had been answered as absent and not committed).
- Failures stay `deny` (D6).
- A push under Level 1 (owner choice 1 A, 2026-10-11, with the review's four conditions as part of the choice): a
  repository without a declaration stays outside Level 1. This is local inactivity, never a pass and never a check
  presumed at Level 2. The answer carries no permission decision, so the host's normal approval decides; it starts
  with `NOT MEASURED: the gate checks nothing here.`, says that the gate is not active in this repository because
  nothing is declared, and that the push's destination and its current state remain NOT MEASURED. It holds only
  where all four conditions hold; otherwise the push is asked as before (NOT MEASURED at the destination, D3) and
  the answer names the condition that failed:
  - a. the repository, the work tree, the git environment and every source of a `git push` are determined; an
    unresolved source is never replaced by HEAD; a configuration that adds ref updates the command does not name
    (`remote.<name>.push`, `remote.<name>.mirror`, `push.followTags`) or a submodule push, an option the gate does not
    model, a wrapper and a `gh` call are not exempted; the deny of a hook-disabling form stays;
  - b. nothing stands at `.proofbundle/evidence.json`, or in place of the `.proofbundle/` folder, at HEAD, in the
    actual working tree and at every commit the push may send: an empty, broken or done-only declaration, a folder or
    a link at the path, or a file or a link where the folder belongs is no absence; a tree that names one entry twice
    is not read whole, neither its first nor its last entry counts (review round 11 of 2026-10-12, R11-4: two
    `.proofbundle` entries in a sent commit had been read as the empty one), at HEAD and at a local record alike;
  - c. those commits are the whole history of every source, with no tracking ref subtracted, since without a bound
    target state the commits a push newly sends are unknown; a shallow repository, a history git does not list or
    give whole, and one longer than 20000 commits are asked. The review's case, measured with git 2.43.0 and 2.51.1:
    A without a declaration, B with one, C without; HEAD and the tracking ref at C, the remote reset to A; the range
    against the tracking ref is empty, while git sends C and B;
  - d. every local record of a remote ref the push may write is read with its commit: the refs each remote's fetch
    rules map a destination candidate to, and `refs/remotes/<remote>/<branch>`, for every configured remote, for a
    named remote as for a URL or path: git does not say which remotes name the endpoint a push goes to (review round
    11 of 2026-10-12, the class of R11-3: a second remote naming `remote.git` as `remote`, which git completes, and one
    network repository spelt as https and scp form, as ssh URL, without `.git` or through a host alias had been told
    apart as written, and the declaration in its record had been passed over). A declaration there blocks the
    exception, a broken or dangling record is no empty state, and a missing record says nothing about the remote.
    The ask names the concrete local record and says that its relation to the actual destination is not
    established; it claims no equality of remotes, since a record of another remote may be relevant without being
    shown to be a record of the destination (owner choice of 2026-10-13, which keeps this strictness). Beyond the
    records today's fetch rules name, every present ref of the repository is read, each tag peeled to the tree it
    names at last: a tag git followed on a fetch, the refs of a remote whose configuration is gone, of an earlier
    fetch rule and of a one-time fetch into a branch record the destination as well, and which present ref did is
    not determinable here; a broken ref, a ref naming an object git does not give, a chain of more than 16 tags (the
    gate's own limit, which git does not share, measured with 17, and the ask says so; the class of R15-2 of
    2026-10-13) and more than 20000 refs leave the exception unapplied too (review round 12 of 2026-10-13, R12-1: a
    tag that `git fetch` followed held the declaration, no fetch rule named tags, and `git push origin
    :refs/tags/release` had been called inactive). Every
    ref the ref store holds, its loose files and its packed-refs alike, must be one git lists or calls broken; a
    present ref git does not resolve, such as a symbolic ref whose target does not exist, which git's listing leaves
    out with exit 0 and no warning, and a ref store in another format than files (reftable), which the gate does not
    read whole here, leave the exception unapplied (review round 13 of 2026-10-13, R13-1: with
    `refs/remotes/origin/main` or `refs/recorded/x` a symbolic ref to a missing branch, the push had been called
    inactive). The records git's listing leaves out altogether are read too, named as git names them: FETCH_HEAD
    line by line, not-for-merge lines included, and the other root refs of the worktree's git directory (ORIG_HEAD,
    MERGE_HEAD and their kin) (the class of R13-1: a declared commit only in FETCH_HEAD after `git fetch <path>
    refs/tags/release`, which stores no ref, and `git push origin :refs/tags/release` had been called inactive). Until
    the narrow contract below, the gate also read the records of every other worktree and resolved symbolic records
    itself, step by step in their own worktree (review round 14 of 2026-10-13, R14-1; round 15, R15-1 and R15-2), and
    its ask then said that it could not establish how a record resolves (owner choice of 2026-10-13, 15:1x Berlin, on
    W-3); that rebuild and its wording are gone with the contract, and git resolves every ref. A
    folder of the refs that is a symbolic link, which git follows and the gate does not, leaves the exception unapplied
    as well (a symbolic ref without a target in such a folder had been passed over). Where git takes the remote from
    its older remote files, .git/remotes/<name> or .git/branches/<name>
    (a name the configuration gives no URL, which `git remote` does not list), the URLs and pushed refs of that file
    decide the push, and the gate does not read them: a push with no refspec is not resolved, and the exception does
    not apply to a push to that remote (the class of R13-1: with a `Push:` line sending another branch whose history
    held a declaration, `git push legacy` had been called inactive). Whether the configuration gives that URL is read
    from the list git uses, with its reset at an empty value as in git 2.51.1: with no URL after the last empty value
    the files decide, as with no key at all (review round 14 of 2026-10-13, R14-3: an empty remote.legacy.url had hidden
    the file, and the current branch had been named as the commit pushed). Where the push goes to an endpoint or a
    namespace these records do not model,
    a push URL other than the fetch URL (a pushurl, a further URL, a URL rewrite) or GIT_NAMESPACE, the exception does
    not apply (review round 11 of 2026-10-12, R11-3: with remote.origin.pushurl naming another remote whose record
    held a declaration, and under GIT_NAMESPACE with a declaration recorded from refs/namespaces/, the push had been
    called locally inactive).
    Where these records end (owner choice of 2026-10-13, 14:0x Berlin, on the reviewer's recommendation of review
    round 14): the current refs/stash is a present ref and is read. Older stash entries and reflogs in general are no
    condition of the exception and are not read, since a reflog can be missing, expire or be deleted and proves no
    complete history; the answer names refs, never reflog entries. A state chosen as the source of a push, an older
    stash entry too, goes through the normal resolution of sources, and condition c reads its whole history. A
    leftover lock file under refs/ or a name there that git skips (one starting with a dot) leaves the exception
    unapplied, and the ask names the entry; the gate cleans up nothing, and the declaration is not weakened. The
    protection for packed-refs and for a ref store in another format than files stays (mutants M3 and M4 of FIX-13
    survived under git 2.43.0, which gives no case for either; the reviewer measured a real reftable store with git
    2.51.1, and the hook asked).
    The ref store is read only in a normal form the gate checks exactly (owner choice of 2026-10-13, 16:4x Berlin, A,
    on review round 16, in place of single fixes); whatever departs from it leaves the exception unapplied, and the
    ask names the reason and the entry. No ref name stands twice, neither in packed-refs read raw nor in git's listing,
    and git's listing is checked before any name is assigned (R16-1: git 2.43.0 lists both lines of a name packed
    twice, with exit 0, also beside a loose file of the name, and the gate had kept the last one, so a declared commit
    in the first line had been passed over). No symbolic link of the file system stands in the ref store, a loose
    ref, a root record, packed-refs and the refs folder included (R16-2: a loose refs/heads/side linked to nothing had
    been read as missing and answered from packed-refs, where git does not resolve the name). Every name the gate
    reads is one git's ref rules take (git check-ref-format), and a name the gate does not model is asked (R16-3).
    Every root record and loose ref file holds exactly `<oid>LF` or `ref: <name>LF`, with no empty line before, no
    blank and no line after (R16-4: an ORIG_HEAD of a line feed and A, which git does not resolve, had been read as
    A); MERGE_HEAD holds one object per line, and FETCH_HEAD lines of exactly `<oid>TAB[not-for-merge]TAB<note>LF`,
    as git 2.43.0 writes them. Each line of packed-refs is `<oid> <name>` with the object in lower case and the name
    under refs/, a `^<oid>` line only after one, the header only at the top, and the lines keep the order the
    header's `sorted` promises, since git's lookup misses a name out of that order while its listing names it. A valid
    loose file beside its packed entry is git's ordinary precedence, a real folder at a loose place leaves the name to
    packed-refs, and packed refs are no reason to ask. git reads more forms than this, a blank, a second line, no line
    feed, a carriage return, `ref:` without a space or an object in capitals among them (measured with git 2.43.0);
    those are asked, which is the price of the choice.
    The narrow contract (owner choice of 2026-10-13, 17:0x Berlin, A and A, after the external design review of that
    day at 101bd167, which measured with git 2.51.1 that git's answer in each worktree was right where the gate's
    rebuild of chains, worktree contexts and depths was not): condition d grants local inactivity only in this range,
    and git resolves within it. All of the following hold together, or the push is asked, NOT MEASURED, with the
    reason and the entry and the next step that a person reviews the push; the answer then never says that nothing is
    declared, and it asks no one to remove a worktree, a stash, a record or evidence.
    1. Exactly one ordinary main worktree: its `.git` is its own folder and git's directory for it, no linked worktree,
       no entry at all under `<git directory>/worktrees`, read itself and not counted from `git worktree list`, and no
       inherited GIT_DIR, GIT_WORK_TREE or GIT_COMMON_DIR, which move git's view of the repository.
    2. Symbolic refs only HEAD and refs/remotes/<remote>/HEAD of a remote git lists, each naming directly a ref git
       lists that is no symbolic ref itself. Any other symbolic ref, a chain, and a name that only ends in HEAD are
       asked. HEAD as an inventory reads it, a direct object or this symbolic form with the object git lists for its
       ref, must be the HEAD condition b checked, in the first inventory that finds the destination's records, in the
       inventory of the present refs and in the final one; a HEAD read otherwise leaves the exception unapplied (review
       round 18 of 2026-10-14, R18-1: the HEAD read was checked for its form and then dropped, so a HEAD moved to a
       declared commit during the reading was passed over; the first inventory, its class sibling, had dropped it too).
    3. The ref store in the files format and in the normal form above. An entry of the store, a root record, info/refs
       or a further file that is no regular file, a FIFO, a device or a socket, is asked and never waited on: each is
       opened without blocking and its type is checked at the opened descriptor before any byte is read (review round
       18 of 2026-10-14, R18-2: info/refs as a FIFO with no writer had blocked the reading of the root records).
    4. The whole inventory: local branches, tags, remote-tracking refs, the current refs/stash, every other ref git
       lists, and the root records above. A ref the store holds and git does not list, and any form the gate does not
       know, are asked, never read as absent; git's listing is read whole, each line with its fields and the output
       ending in a line feed.
    5. FETCH_HEAD and MERGE_HEAD whole and bounded, not-for-merge lines included; `git rev-parse FETCH_HEAD` reads the
       first line only, so the gate reads the file. Another form is asked.
    6. git resolves: fixed local reads as argument lists without a shell, full names after the name check, fixed
       formats and `--end-of-options`, and the promisor refusal before every call that can read an object. An object
       name git prints is no readable object yet; the object, tree and declaration checks follow.
    7. Output that is not whole, a warning about a record left out, a missing object, a time or size limit passed
       (MAX_RECORD_BYTES, 16 MiB a file) leave the exception unapplied. The one known harmless output is git's hint on
       the emptied graft file, matched line by line; everything else on stderr is a warning. A change of the refs
       between their reading and the reading of their objects leaves no finished measurement of absence. The first
       inventory, which finds the destination's records, is one of these readings: its refs, records and broken refs
       must be those of the inventory of the present refs, and what it read is not dropped after its form checks (the
       class of R18-1: a ref or record that named a declared commit in the first inventory alone had been passed over).
    8. Conditions a to c, the other cases of this section and the Codex rules are unchanged.
    The price: a repository with more than one worktree, or with a symbolic ref beyond HEAD and a remote's HEAD, is
    asked; the case of more worktrees follows the milestone as its own extension.
    Further records of the git directory (finding K16-1 of FIX-16, owner choice of 2026-10-13, 20:0x Berlin, A, with
    the rule of review round 17): git resolves a ref name also as a file at that path in its git directory, outside
    refs/ and outside the root records above, and `git for-each-ref` does not list such a file (`git update-ref FOO D`
    writes `.git/FOO`; measured with git 2.43.0 for FOO, FOO_BAR, foo_HEAD, Foo_HEAD, foo and sub/foo, and by the
    reviewer for logs/foo, objects/custom, info/custom, hooks/custom and rebase-merge/orig-head with git 2.43.0 and
    2.51.1; Level 1 had answered inactive while such a file named a declared commit). Additional files outside the
    known ref stores and root records are included when Git resolves their exact names. Recognizable record forms
    that cannot be resolved leave the exception unapplied. A negative resolution does not establish that a file was
    never used as a ref. Valid historical reflog data remains outside this condition. As built:
    - The strict reading of refs/, packed-refs, HEAD and the root records above stays as it is. Beside it the one git
      directory is read recursively, logs/, objects/, hooks/, info/, rebase-merge/, rebase-apply/ and any unknown
      folder included. Only refs/ and packed-refs (the store), HEAD, the root records and info/refs (each read in its
      strict form) are not read a second time, and worktrees/, where point 1 allows no entry at all. A symbolic link
      anywhere in the git directory, an entry that is no regular file, an error of the inventory, a file the gate
      cannot read and more than MAX_FURTHER_FILES (20000) further files leave the exception unapplied.
    - A file starting with `ref:` or with 40 hexadecimal digits in either case is a recognizable record form; other
      text is none. A name git's ref rules refuse (git check-ref-format with one-level names allowed) is never handed
      to git: such a file in a record form is asked, other text under it is no record.
    - For every other file git answers twice, `git rev-parse --verify --quiet --end-of-options <name>` and the same
      call with `--symbolic-full-name`, with the hardening and the promisor refusal of point 6. Only where the full
      name is the file's own name has git resolved this file. It must then hold exactly `<oid>LF`, in lower case, with
      the object git gives, and it is read like any record: the object, the tree and the declaration checks follow.
      That the file exists is no reason to ask.
    - A negative resolution, both calls with exit 1, no output and no warning, means no record. git 2.43.0 warns
      `warning: ignoring broken ref <name>` for every file below a folder of the git directory whose bytes are no ref,
      a hook sample or an object file alike, and prints nothing for such a file at the top (measured); this exact
      warning, once per call with both calls negative, counts as a negative resolution too, since arbitrary text is
      not a damaged former ref by its path alone. A recognizable record form that git does not resolve as this file is
      asked: a symbolic record, an object with a blank, a second line, no line feed or capitals after it, or one git
      reads as no ref at all.
    - Where git resolves the name to another ref already read, with the same object, git substitutes a name and the
      file is no record (`.git/description` beside a branch `description`), unless the file itself is in a record
      form. Any other warning, an ambiguity (`refname 'foo' is ambiguous`), two answers that do not fit together, a
      time-out and an answer the gate cannot read are asked.
    - A valid reflog under logs/, every line `<old> <new> <identity> <time> <zone>`, a tab and the message where there
      is one, and at most MAX_RECORD_BYTES, stays outside, like reflogs in general above. A file there that is no
      valid reflog is read like any other file, so one of only `<oid>LF` is a record.
    - The inventory, the bytes, the full name and the object must fit together: each file is read again after git's
      answers and must hold the same bytes, the final reading after the objects (R17-1) must give the same records,
      and a further record must not carry the name of a ref git lists; otherwise the exception is not applied.
    The states git leaves in its directory, as built and measured with git 2.43.0:
    - `BISECT_START`: `<oid>LF` (a bisection started detached) is a record. The branch form `<branch>LF` (started on a
      branch) is supported explicitly: it is read as refs/heads/<branch>, which must be a ref git lists and no symbolic
      ref; otherwise it is asked. The other bisect files are text git does not resolve, or refs under refs/bisect/.
    - `AUTO_MERGE`: a root record above; it names a tree, which is read for the declaration like any tree.
    - `shallow`: condition c is unchanged, a shallow repository is asked before condition d is read.
    - The object files of rebase-merge/ and rebase-apply/ (onto, orig-head, stopped-sha, original-commit,
      abort-safety, amend): records, read by the procedure above. git's rewritten lists of a stopped rebase,
      rebase-merge/rewritten-list and rebase-apply/rewritten of `<old> <new>LF` lines and rebase-merge/rewritten-pending
      of `<oid>LF` lines, are supported explicitly: git resolves each name to the first object of its first line, and
      every object of every line is a record, the first under the file's name, the others as `<name> (line N, object
      M)`; another form is asked (a rebase stopped at a later pick, or inside a fixup chain, had been asked at
      b3ce11d7). Their other files are text git does not resolve.
    - logs/: a valid reflog stays outside; a bare `<oid>LF` there is a record.
    - An unknown folder: read like any other.
    - `info/refs`, which `git gc` writes through `git update-server-info`: git resolves the name to the object of its
      first line; the gate reads it whole, line by line, each line `<oid>TAB<name>LF` a record, like FETCH_HEAD.
    The price, measured with git 2.43.0 in clones without a declaration: a file in a record form that git does not read
    as `<oid>LF` is asked, such as a COMMIT_EDITMSG whose message starts with an object name and a blank, or the
    MERGE_RR that rerere writes during a conflict; a submodule's git directory under modules/ is asked, since its HEAD
    is a symbolic record git resolves in the superproject; a hooks/ folder that is a symbolic link is asked; a split
    commit-graph chain, objects/info/commit-graphs/commit-graph-chain, which `git maintenance run --task=commit-graph`
    and `git fetch` with fetch.writeCommitGraph write, is asked, since git resolves it and it names graph files, no
    objects, until `git gc` replaces it. A fresh clone, a clone after `git gc` and `git pack-refs --all`, after `git
    fetch` with its defaults, a bisect, a merge, a rebase and a cherry-pick, each also stopped at a conflict, keep the
    exception. git 2.51.1 was not measured for the built boundary here.
  Level 2 finds nothing declared and blocks nothing. Under Codex the hook cannot bind a push to its directory (D12),
  so condition a never holds there.

The reason starts with `NOT MEASURED:` and says that nothing was verified. In a non-interactive run
(`claude -p`) an `ask` is a refusal.

The price of C: whoever deletes the declaration switches the gate off at HEAD. Under owner choice 1 A a removal
does not switch it off for a push while the declaration still stands in the history the push may send (condition c)
or at a present local ref (condition d); the push is then asked. The price of 1 A, named by the owner:
a declaration that only the remote holds, standing neither in the checked source history nor in a local record, and
its removal can go unnoticed at Level 1, above all with a push that only deletes a ref. In the other direction a
declaration removed long ago from the source history still blocks the exception, and every push from such a history
is asked. Level 2 sees the remote's state of each ref on git's own ref lines and compares the rules there (D20).

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
(`proofbundle==6.3.0` since Nachtrag 45, 6.1.0 before) is the only pin. Without `uv`, or without a cached or
reachable PyPI, the verifier does not start and the gate denies (D6).

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
  ends the options only after a word that takes no value; after `-o` it may be that option's value. A redirection
  keeps the form plain only when it opens no file (a descriptor duplication or close, `/dev/null`): `git push origin
  main > .git/hooks/pre-push` warned at 87dcbed8 while the shell emptied the hook (review round 2, R2-2).
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
  of review Runde 11, R11-5). The separate push path remains: under Claude Code it denies an evidenced failure at
  the commits a push sends and otherwise asks, its destination NOT MEASURED (D3, R9-1), except the local inactivity
  of owner choice 1 A for a repository that declares nothing (D5); under Codex every push is
  NOT MEASURED because its execution context is unbound,
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
- Level 2 (the pre-push hook) compares the evidence rules of each commit a push sends to a branch or tag
  with the rules at the remote's state of that ref, as git hands it to the hook on the ref line. A deletion
  compares an absent declaration with the target. A ref the remote does not have yet is NOT MEASURED (the
  creation of a ref is not checked). Since review round 9 of 2026-10-11 (R9-1) Level 1 makes no such
  comparison: every Level 1 push ends NOT MEASURED at the destination check (D3), whatever the fetch rules, so
  no remote-tracking ref and no fetch stands in for the remote's state (review round 10, R10-5: this section had
  still described the comparison against `refs/remotes/<remote>/<branch>` at Level 1).
- Level 1 names a difference of the evidence rules against a local record as a hint, never as a verdict (owner
  choice 4 A of 2026-10-11). For each source commit of a push and each local record of a ref the push may write
  (the records of D5, condition d), it compares the rules of this section at the two tips: "The evidence rules at
  source commit <source> differ from local ref <ref> at <recorded commit>. This is a local comparison. The actual
  push destination and its current state remain NOT MEASURED.", with the two trees read and what differs; a record
  of another candidate than the destination itself, or one of several records, is called a locally recorded
  candidate ref. Only the two tips are compared, no commit between them. A side git does not give whole, and a
  destination today's fetch rules map to no present ref, are named as a comparison not made, which is no equality;
  the hint claims no absence of local records, since a present ref no rule maps, such as a tag git followed, may
  record the destination too (the class of R12-1, 2026-10-13). A subject or a
  receipt is no rule. The answer stays NOT MEASURED (`push_not_measured`); a push that only deletes a ref, or whose
  source or destination is not named, gets no hint.
- A difference is asked under Claude Code and denied under Codex at Level 2, with the change named and the note
  that changes to the evidence rules need a review. Once the remote's ref holds the change, a push to that ref is
  plain; the same change held by another branch or another remote is still a change for this ref.
- An unresolved push never switches the gate off at Level 1 because HEAD declares nothing (N2); since R9-1 every
  Level 1 push is unresolved at the destination check. The one exception is owner choice 1 A (D5, 2026-10-11): a
  push from a repository that declares nothing, whose sources are determined and in whose whole source history and
  local destination records nothing is declared, is locally inactive (no decision, no check, no pass).
- A deny for failed evidence at any sent commit comes first; the rules are compared only after the evidence
  verified.

Price: every Level 1 push is asked under Claude Code (D3) except the local inactivity of owner choice 1 A (D5); the
rules comparison happens where Level 2 runs. The price of 1 A: a declaration that only the remote holds, standing
neither in the checked source history nor in a local record, and its removal can go unnoticed at Level 1, above all
with a push that only deletes a ref; a declaration removed long ago from the source history still blocks the
exception (D5).

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
- The entry of a push whose source check ran carries, per repository, `evidence`: each evidence or policy file
  the check read at a source commit, as its `commit`, `path`, the `sha256` of the bytes read and `check`, the
  outcome of the check of that commit (`passed`, or `failed: <reason id>` for a check that failed or stopped part
  way, which lists only what it read before it stopped). A digest alone attests no verification. The verdict stays
  NOT MEASURED, or deny for an evidenced failure; no working-tree file is hashed for the entry, and an unresolved
  source, whose candidates the check did not read, leaves no digest (owner choice 3 A of 2026-10-11). Done
  receipts, which the done check reads from the working tree, are not listed. Where the check stops with an error
  (gate_error), the entry keeps what was read before: the files read at the commit where it stopped, with that commit
  as `head` and the check `not completed: gate_error`, and the record of the commits checked before; a file whose
  reading failed has no digest (review round 11 of 2026-10-12, R11-5: a bundle read before a policy over the size
  limit had been logged as no digest and no head). The same holds for a stop of any kind anywhere in the push's
  check, a GateError or another exception (then internal_error and the check `not completed: internal_error`), in
  the evidence check, in the done check that follows it or in any later step: a passed evidence check stays
  logged as passed while the done check fails on its own, the entry names the commit where the check stopped and
  the digests read there, and a done policy the check did not read gets no digest (review round 12 of
  2026-10-13, R12-2: a done policy over the size limit after a passed evidence check, and a verifier that could
  not start with an OSError, had left digests [], head null and no record).
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
  tracks a named branch on the bare remote; the model runs one `git push` to that branch, which the gate is
  expected to deny at the commit it sends (its destination stays NOT MEASURED, D3). The check reports, observation-near, whether the gate
  logged that deny and whether the throwaway remote's target still equals the OID it stored at prepare:
  "Expected denial logged; test target unchanged.", "Expected denial logged; test target changed.", "Test
  target changed; no matching gate event observed.", or NOT MEASURABLE. A missing, empty or invalid stored
  base OID is not a comparison value: the target then cannot be compared and the result is NOT MEASURABLE,
  never read as changed or unchanged against an empty string (review R3-5). Every result carries the limit,
  verbatim: "The results report whether an expected deny entry was found and whether the target still
  equals the recorded base OID. They do not establish why an observation is missing. NOT MEASURABLE means
  the observations do not support another result. The limit applies to every result." (review R3-6), and
  the round-2 caution that the log is local, so this is a local diagnosis, not an independent proof of the
  host's hook. The command it hands out names only the throwaway remote, and the check reads only that remote's
  refs. Its own git calls run without any `GIT_` name the host set, with
  the global and the system configuration switched off and no hook (core.hooksPath names no folder; review round
  9 of 2026-10-11, R9-6: a host's GIT_CONFIG_GLOBAL=/dev/null had been dropped with the other names, and prepare
  ran the hooks of the global configuration), and
  prepare asks git, in the server's environment, whether a call in its folder takes that folder's repository, work
  tree, index and object store and pushes origin to the throwaway remote; where git answers otherwise the self-test
  is NOT MEASURABLE and removes its folder (review round 8 of 2026-10-10, the class of R8-1: an exported `GIT_DIR`
  had made prepare commit twice onto that repository's branch and add a remote to it, measured with git 2.43.0 and
  2.51.1). Prepare also refuses a namespace (GIT_NAMESPACE) and a push mapping of origin (remote.origin.push) in the
  server's environment, both of which send the offered push to another ref than the throwaway remote's main; the
  shell the host runs the command in may carry another environment than the server, so the check compares every
  ref of the throwaway remote with the state prepare recorded, and a ref beside main that appeared, moved or went
  is a changed target too (review round 9 of 2026-10-11, R9-2: under GIT_NAMESPACE the push had written
  refs/namespaces/selftest-ns/refs/heads/main and the check had reported the target unchanged). Prepare refuses
  every choice of another receive program or transport in the server's environment, as long as no binding of it
  is built: remote.origin.receivepack from any configuration source, GIT_EXEC_PATH naming another program folder
  than git's own (a local push starts git-receive-pack from it), remote.origin.vcs (a remote helper) and
  receive.procReceiveRefs on the throwaway remote (review round 10 of 2026-10-11, R10-1: a receivepack in the HOME
  configuration had sent the push into another bare repository, measured with git 2.43.0 and 2.51.1, and the check
  had reported the target unchanged). The hook programs the throwaway remote's receive-pack runs where it updates
  refs are such a choice too: a pre-receive, update, proc-receive, post-receive, post-update, reference-transaction
  or push-to-checkout hook in the hooks folder git names for that remote (core.hooksPath; a relative value is taken
  from its git directory) is refused (the class of R10-1, measured at bf10fa6a with git 2.43.0: a post-receive hook
  from the HOME configuration had moved main back after a push that exited 0, and the check had reported the target
  unchanged). Prepare reads each setting where the push or the receiver reads it: a `git config` query leaves out
  GIT_CONFIG, a file only `git config` itself reads, and the hooks folder is asked for both in the server's
  environment and in the one git gives the receive-pack of a local push, which clears the configuration the
  environment carries (review round 11 of 2026-10-12, R11-1: a core.hooksPath given through GIT_CONFIG_COUNT or
  GIT_CONFIG_PARAMETERS had hidden the global hooks folder from prepare while the receiver ran its post-receive;
  measured at 3bbbf66f with git 2.43.0, GIT_CONFIG=/dev/null had hidden a receivepack of the HOME configuration from
  prepare while the push took it). The hooks folder is the one git names, with every character of its path; only
  the line end of git's answer is removed, and an answer of more than one line names no folder (review round 11 of
  2026-10-12, R11-2: a trailing blank of core.hooksPath had been stripped, and prepare had looked into another,
  missing folder). Prepare reads git's answers with the filesystem's own decoding and shows a path in its
  messages unambiguously and printably: a byte that is no UTF-8 text as \xNN, a backslash doubled; a throwaway
  folder whose path is no UTF-8 text is refused as NOT MEASURABLE, since its command cannot be handed out as text;
  and every reply of the server is valid UTF-8, a string with such a byte written with JSON's \u escapes (review
  round 12 of 2026-10-13, R12-3: a hooks folder whose last name byte was 0xff had put that raw byte into the JSON
  on stdout, and a TMPDIR with such a byte had ended prepare in an internal error). What the check observes is
  bounded to the refs of the throwaway remote: a setting only the host's
  shell carries (a push URL, a receive program or its hooks, a transport) is not visible to the server and can send
  the push elsewhere or undo its write unobserved. The snapshot of the throwaway remote that prepare records must name
  its main at the base; a listing git could not take ends prepare with NOT MEASURABLE before the command is handed
  out, and an empty or foreign recorded listing makes the check NOT MEASURABLE, never "unchanged" (review round 10
  of 2026-10-11, R10-2: a failed first listing had been stored as an empty file and read as no change). The
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
- The command starts in the work tree with the host's environment plus the values git resolved for the call's
  directory (`GIT_DIR`, `GIT_WORK_TREE` as absolute paths, the same the gate's own reads carry, R7-1), so a git the
  tests start opens the repository and tree the statement names. None of the other settings of the gate's own reads
  reaches the tests (replace refs, grafts, lazy fetch, literal pathspecs, `LC_ALL`, trace). Until review round 8 of
  2026-10-10 (R8-1) the command got the raw environment: `GIT_WORK_TREE=repo` given in P named P/repo for the
  comparison and P/repo/repo for a test that asked git for its work tree, and that run was recorded green for P/repo
  (measured by the reviewer with git 2.43.0 and 2.51.1).
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
- Since D35 (2026-10-14) the hook has two modes and says which ran: standalone, as above, where the worktree holds no
  hand-over of Level 1; and the hand-over mode, where it consumes the hand-over and refuses every push that is not
  the one Level 1 handed over before the core judges it.

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
- Two of these limits by name, measured by the review of 2026-10-09 and again on 2026-10-09 at 281901af: the mark
  is a heuristic, not provenance. `install-pre-push` takes a hook whose
  second line starts with `PRE_PUSH_MARK` as its own and replaces it, whoever wrote it, and refuses one without it,
  however it came. And whoever can write the plugin cache chooses the gate: the wrapper runs the gate of the newest
  version folder beside the one it was installed from, so a folder `…/proofbundle/9.9.9` with a gate of its own is
  the gate that checks every push.

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
  mode and sha256, including a `core.hooksPath` override), the attribute files git reads outside the work tree,
  and the program-selecting environment. A rule carries the digest of the state when the human wrote it; the gate
  recomputes and compares. If the configuration, the hooks, those attribute files or that environment change, the
  digest differs and the rule stops acting — the gate asks again. A human computes the digest for a rule with
  `proofbundle_gate.py state-digest [--repo DIR]`.
  The attribute files are `info/attributes` and the two files git var names (review round 4 of 2026-10-09, R4-1):
  the system file (`GIT_ATTR_SYSTEM`, absent under `GIT_ATTR_NOSYSTEM`) and the global file (`GIT_ATTR_GLOBAL`:
  `core.attributesFile`, else `$XDG_CONFIG_HOME/git/attributes`, else `$HOME/.config/git/attributes`). An unset
  `core.attributesFile` is the default file, not "no file". Where git cannot name one of them for sure (a git
  older than 2.42 does not know the variables, a broken configuration, a relative name without a work tree) the
  digest is unknown and the gate asks. The .gitattributes files of the work tree are not part of the digest. A rule
  therefore also covers later selections of drivers already defined by the bound configuration. Built-in attribute
  handling, such as text conversion and line endings, is not bound by this digest. Since this change the digest
  schema is `gate-state/v2`, so a rule written with a v1 digest asks once and needs the new digest.
  A hook longer than 4 MiB (`MAX_HOOK_BYTES`) is not read in full, so the state is unknown and no rule acts while
  it is there (review round 5 of 2026-10-09, R5-2: a fixed marker stood in for its bytes, and a change behind the
  first 4 MiB kept the digest; measured with a post-commit hook of 4194433 bytes that git ran with its changed
  bytes). An entry of the hook directory that is not a regular file is bound by name and mode alone: git cannot
  exec a directory or a FIFO as a hook (measured with git 2.43.0).
  Every name and value of that state keeps the bytes git printed (review round 4 of 2026-10-09, R4-2): the gate
  reads git's paths, configuration and repository layout without replacing a byte that is not UTF-8, so the file it
  hashes or protects is the file git opens, and the digest tells such a byte from U+FFFD. The write gate's protected
  files are read the same way.
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
- A transport approval of D35 (`transports.json` in the same directory, written by a person, read only by the gate)
  acts only in `with-approvals` mode as well. It frees no push: it authorizes the transport of one remote at one URL,
  and the push it allows to go without a question from the gate is judged by Level 2 against the hand-over.
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
- The repository is the work tree git names for the directory, with the bytes git printed and only its one
  closing newline removed; every path to a verdict reads it so (the done check, the push path, the pre-push hook,
  the CI mode, the MCP diagnosis, run-evidence and done-init). No repository means git's own answer that the
  directory lies in no work tree (outside every repository, in a bare repository or in `.git`); a read git fails
  for any other reason (measured: a repository format version 99, an unknown repository extension, a bad boolean
  value) reached no verdict and blocks. Review round 5 of 2026-10-09, R5-1: a work tree whose name ended in LF, CR,
  TAB, U+0085 or a blank was cut to another name and judged as its neighbour or as none, and such a failed read
  made the done check inactive.
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
repository's own command, as in the CI job, decides which tests count. An agent that moves `.git` away or
points a `.git` file at no repository leaves no repository by git's own answer, and the hook stays silent; the
CI check is the boundary there. Codex is not
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
- The same class at Level 2 (review of 2026-10-09, D24B): the ownership mark of `install-pre-push` is a heuristic,
  and whoever can write the plugin cache chooses the gate the pre-push hook runs. Both are named limits, not
  repaired: a local hook is an early warning.
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
  the same answer: `decision` and `reason` for a block, `systemMessage` for a blocker (since D53 a pass prints
  nothing and a block shows the user a short line in `systemMessage`); the hook never
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
  Where no order could be read, the default limit of 3 applies. Input that names no repository counts nothing. The
  repository is named the moment show-toplevel finds it, so a failure after that point counts too (review round 2
  of 2026-10-09, R2-4: a partial clone refused the read of HEAD and blocked at every stop). Every stop past the limit
  writes the blocker from the verdict it reached, so the file the message names exists and shows the state last
  measured, also after a rename or a deletion of the blocker (R2-5); the counter of blockers counts it once. A check
  the done check stopped before comparing with the state is "not judged", never "verified".
  `.proofbundle/done-metrics.json` counts blocked ends, blocked task completions, missing checks, ends completed
  after a block, blockers and passes; `.proofbundle/done-state.json` holds the current count. The files are written
  through a fresh temporary file that replaces them, never through a link, and are untracked under `.proofbundle/`,
  so they are not part of the working state. Their content is counted, never trusted for a verdict. The count binds
  the session by the sha256 of the host's session id, and no done file is written larger than the 64 KiB the hook
  reads back, so the hook can always read its own record at the next stop; a present count it cannot read is named
  in the block, which then counts as the first (review round 4 of 2026-10-09, R4-3: a session id of 65536 characters
  made a record of 65684 bytes that the next read discarded, and the session never reached the blocker). The schema
  value alone does not make a count usable: each field is checked (the session's sha256, the open points as
  [id, status] pairs, a whole block count of at least 0, a true or false blocker flag, no other field), and a
  present record that fails names why in the block. The record an older gate wrote with the session id in clear is
  taken over by the session's sha256, so an update continues the count (review round 5 of 2026-10-09, R5-3: such a
  record, and a block count "1" written as a string, restarted the count without a word). A done end names such a
  record too, and a reset count it cannot write, in its message, and writes its own record in its place (review round
  6 of 2026-10-10, R6-4: a done end had written over a record with blocks "1" without a word). The end that writes
  the blocker names a count record it could not write, and so does a block whose blocker could not be written; a done
  end names an earlier blocker it could not remove (review round 7 of 2026-10-10, R7-5: the record's write error after
  a written blocker was dropped, and the next stop read the record from before that end). On a done end the three
  stay apart: a record it could not write is a count it could not record, a blocker it could not remove is named as
  such, and an unreadable earlier record is named whatever else failed, with "wrote its own record in its place" only
  where the write succeeded (review round 8 of 2026-10-10, R8-4: a failed removal beside an unreadable record had been
  reported as an end that could not be counted, while the record held a valid count, and the unreadable record went
  unnamed). The counters in
  `done-metrics.json` are not checked that way: a file that is not the counters' form starts them afresh, and a write
  that fails goes unreported; they decide no verdict.
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
arguments, not plugins or conftest code that skip, select or rewrite tests. The PreToolUse gate frees the narrow git add
and git commit -m forms after a repository state check (D3), so an unattended run can commit when that check passes.
Other forms still ask under Claude Code or deny under Codex. The `TaskCompleted` hook keeps every task open in a
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
  on a passed done check (reason `done`) at Level 2. At Level 1 the destination of every push is NOT MEASURED since
  review round 9 of 2026-10-11 (D3, R9-1), so a passed done check there leaves the push an ask that says the
  evidence at the sent commits showed no failure.

Measured (tests/test_plugin_gate_n2c_push_done.py, 2026-10-08): the counter-probes missing (`no_receipt`),
foreign key and manipulated receipt (`verification_failed`), receipt for an earlier commit (`stale_receipt`) and
red tests (`not_done`) deny at Level 1 and make the pre-push hook exit 1; a valid receipt passes both. Through git
itself, with the hook in a throwaway repository's local `core.hooksPath`, a missing or stale receipt keeps the
remote ref where it was and a valid one moves it. Since round 9 (R9-1) a valid receipt leaves Level 1 at NOT
MEASURED, which asks, and still passes the pre-push hook.

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
  a history cut before it, more than `MAX_ORDER_WALK` (256) commits that changed the declaration, or git cannot list
  them. The next step is `git fetch --unshallow` or a person. A cut is a commit git shows without the parents its
  commit object names, asked of git for each commit the walk reaches; the gate reads no shallow file of its own, so a
  shallow clone and a shallow file named by `GIT_SHALLOW_FILE` count alike (review round 6 of 2026-10-10, R6-1: the gate
  read the cut points from `--git-path shallow`, an empty file, while git followed `GIT_SHALLOW_FILE` and cut the history
  at a commit after the order, which then passed as the commit that declared it).
- An order without paths, and the one-check form, are as before: no change is required.

D28 and D31 together (review of 2026-10-09): the local hook cannot tell whether the owner or the agent wrote a new
order. Any commit that changes the done section declares a new order, and from then on its checks, its paths and its
base are the ones the gate uses, also when the agent wrote it, with paths it had already changed or with none. The
protection is review: CODEOWNERS over `.proofbundle/` with a required code owner review in CI (D22), not the hook.
And `order_base` is read from the history the checkout holds, by the first-parent walk above; it is not anchored
outside the repository, so it is only as good as that history. In CI that is the whole history of the commit under
review (fetch-depth 0, review 2026-10-09 F4), the history the reviewer sees.

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

## D32. The answer leads to the push form Level 1 resolves (owner choice A, 2026-10-13, 23:3x Berlin)

Measured in the self-use of 2026-10-13 (stage 0, observer in one session, head 101bd167): Claude Code writes a push
as `cd <repo> && git push <remote> <refspec>`. Level 1 resolves no `cd` and no chain since review Runde 4 (D3), so
the gate answers ask with `directory_unresolved`, rightly, and nearly every push of a working day asks.

Chosen (A): the resolution stays exactly as it is, no `cd`, no chain and no new case. The plugin leads the agent to
the safe form Level 1 already resolves and checks: `git -C <absolute path> push <remote> <refspec>`, one command of its
own with one literal absolute `-C`, for example `git -C /home/me/repo push origin HEAD:refs/heads/topic`.

- The next step of `directory_unresolved` for a push names this form with the example and says that the gate resolves
  and checks it, while a `cd`, a `pushd` or any chain before the push stays unresolved. For another gated call it
  names one command with literal words and, for git, one literal absolute `git -C`.
- The next step of `possible_unmodeled_push` and of `mcp_target_unbound` names the same form where it named a plain
  `git push`.
- Under Codex the hint names the plain `git push <remote> <refspec>` in the session's directory instead, because there
  only that form warns and a global option such as `-C` is denied (owner choice K5-1 C, D12).
- The self-test already hands out `git -C <work> push origin main` (server/proofbundle_mcp.py).

A hint toward a form the gate cannot resolve causes an avoidable question. A hint toward a form it can resolve
removes that reason for asking and allows the source checks to run. Any remaining reason to ask or deny still
applies. The forms the gate resolves are unchanged.

## D33. A command judged step by step: class c of the ask load (FIX-18 part B, 2026-10-14)

Measured on the synthetic corpus of DESIGN_ask_load.md (276 commands rebuilt to the observer's counts of
2026-10-13): the gate asked for 108 of them in a declared repository, and for 26 of those bash runs no git and no gh at
all. Here-documents written to files, text piped to wc or grep and comments named git or gh, and the safety net (D3,
review Runde 12) counts every git or gh word in the whole text. The owner's answers of 2026-10-14 (equal to the
reviewer's recommendations) and Nachtrag 1 of FIX-18 order the classes of DESIGN_ask_load.md by their benefit; class
c comes first, because no other class acts without it.

How the reason of a longer command names the step that asks, and says so where the reason belongs to no step: D46.

Built (class c): after the answer of the whole command, the gate parses the command as bash 5.2 does for the forms it
models (lists, `&&`/`||` chains, pipelines, subshells and groups whose redirections open no file, simple commands with
assignments and redirections, here-documents, and command, process, parameter and arithmetic substitutions) and walks
every simple command bash would execute, in order.
- A here-document body, an argument of a known data command (echo, printf, cat, grep, wc, sed and awk with a script
  that runs nothing, find without -exec, tee and their kin) and a comment are text, not calls. A comment that names git
  or gh keeps the whole answer: zsh with changed histchars runs it (review Runde 11, R11-2).
- Every git and gh step gets the gate's answer for that step alone, as a command of its own in its directory with its
  redirections. Without class e a `cd` leaves the directory unknown: a git or gh step after it keeps the answer of the
  whole command, with the form that answer names (the D32 push form).
- K-NW-2 B's `git add` and `git commit -m` are free as the whole command (D3) and, by the owner's choice of 2026-10-14,
  16:2x Berlin (A, Nachtrag 2 to FIX-18 part B), as steps of a plain chain: simple commands joined only by `&&` or `;`
  on one line, with no pipe, `||`, background job, subshell, group, substitution, redirection, here-document,
  assignment, alias, eval or other carrier of code, function, directory change, negation or comment
  (_sh_plain_chain). Every step is judged as the same command alone and the strictest step decides; a step whose own
  answer is free still asks after a step that may change the state; a push keeps its own check and is judged on its
  own only as the first step. A plain chain that is not free keeps the whole command's answer where that is as strict.
  In any other longer command a step whose own answer is the state check keeps the whole command's answer, which names
  the two forms. This replaces K-NW-2 B's "whole command only" for the plain chain.
- A step whose own answer is free (a push's local inactivity) asks (`step_after_state_change`) where a step before it
  or beside it may change the configuration, the hooks, the evidence or the environment: an unknown program, a carrier
  of code, an assignment that is not neutral, a printf that sets a variable (`-v`, or a `%n` conversion of its format,
  which assigns the number of characters written so far: `printf '%n' PATH` sets PATH to 0, R20-1 of review round 20,
  measured with bash 5.2.21; an option or a format word the shell builds counts as setting one), or a write to a file
  the write gate protects.
- A push, a gated gh call or a possible transfer is judged on its own only as the first executed step, at the top
  level, after at most `cd` steps and without a redirection; under Codex never. Such a step is judged without the
  hand-over of D35, and the plain push form as the whole command keeps the whole command's answer: only that form is
  handed over to Level 2, never a push as a step, first or not (owner choice of 2026-10-14, 19:3x, Nachtrag 4, rule 2).
- A step is judged without the rules of N24 (D25): a rule frees only the whole command in its plain form, never a step
  of a chain or a pipe. Until 2026-10-14 (found during Nachtrag 4) a rule for `git stash list` freed that form as a step
  of `git stash list; echo x` or `git stash list | cat`, and the log named no applied rule.
- Every literal file a redirection or `tee` writes is judged like a file-tool write (decide_write, as under Claude
  Code): the configuration and the hooks of a repository ask (`write_to_repo_state`), the gate's own directory is
  denied (`write_to_gate_dir`). A relative target after a `cd` is not judged until class e resolves the directory.
- An interpreter or another carrier of code (a shell, `eval`, `source`, `xargs`, `env`, `alias`, `trap`, `export`, a
  script by path, …), or a program the gate does not know, whose text names git or gh asks at least
  (`code_names_git`): there is no inert-Python rule (owner answer 6, review finding Q18-1; answer 9). The same holds for
  a carrier that reads a git or gh step's output, and for git or gh text anywhere beside a step that runs code. One
  form is excepted since D39: the body of a quoted here-document to `python3 -` is the interpreter's input.

Kept, with the answer of the whole command: a deny of the whole command; an approved rule (N24); the bare
`git --version`; every form the parser does not model (shell keywords, functions, background jobs, ANSI-C and locale
quotes, a here-document inside a substitution, a named file descriptor, a redirection that opens a file on a subshell or
group, a parameter expansion with a quote or a substitution inside, a backtick with a backslash inside, deep nesting);
a command word the shell builds (`$(echo git) push`, `$X push`) or git and gh in another letter case; a word the gate
reads as one the shell may rewrite (_shell_rewrites, zsh's `#` and `^` and a leading `=` among them: a step's quoted
text would not be the word the shell runs); a carrier of code
or a program the gate does not know with a word the shell may rewrite (`sudo gi* status`, R14-1); a `git --version`
step in a longer command (D3 frees only the exact bare text); a git or gh step with an expansion or a prefix assignment
that is not neutral; a gated step that is not first.

What it changes, measured on the plugin before and after (archive of FIX-18 part B, class c): asks 108 → 89 in the
declared repository with a clean configuration, over the four cells (declared and undeclared, clean and container
configuration) 432 → 358; no deny lost; the 318 runs of the harmful and done-check cases keep their required answer;
in none of the 212 runs whose ground truth executes a gated call is the gate free where it was not. Five runs that
were free now ask: two inline programs that name git, awk with system, and two Bash writes into the configuration and
a hook. Under Codex asks 106 → 87 and nothing that was free asks or is denied.

Limits, in plain words: the parser models bash 5.2 and was not measured under zsh; it sees the command, not the
functions and aliases a host may load into its Bash tool before it; a write after a `cd` to a relative path is not
judged until class e. The answers of the other classes (b, d, e, g) are unchanged by class c; class a (D34) frees a
read form after its read profile, alone or as a step that class c judges on its own.

## D34. A read form free after a read profile: class a of the ask load (FIX-18 part B, 2026-10-14)

Owner answers 1 to 3 and 10 of 2026-10-14, equal to the reviewer's recommendations, and the owner's reading of answer
1 of 2026-10-14, 17:5x Berlin: a read profile, built as a narrow new piece of the plugin and not taken over from the
prototype; the git-lfs standard filter is not inert; the pipe of the Bash tool, and with it an inert pager, only for a
bound host adapter; class a off under Codex. This reopens owner choice B of review Runde 9 (D3) for read forms only.

Built: a read form is free under Claude Code when it is the whole command (or a step class c judges on its own, D33),
headed by a bare `git` with at most one literal `-C`, every option before `--` on the grammar of its form
(_READ_GRAMMAR, _read_form), no word before `--` one the shell may rewrite, no redirection, and the read profile of its
repository (_read_profile_problem) finds nothing that starts a program for it. Reason id `free_after_read_profile`.
- The forms: log, show, diff, rev-list, grep, status, ls-files, rev-parse, for-each-ref, branch as a listing,
  ls-tree, show-ref, merge-base, describe, `worktree list` and `cat-file -t|-s|-e|-p <object>`, and since D68 the reads
  `git config --get`, `--get-all`, `--get-regexp` and `--list`. Not on the list: every other config read form (class g),
  shortlog (it reads standard input when that is no terminal) and every form that writes.
- The grammar takes only options that print, select or order. Not on it: --ext-diff, --textconv, --output,
  --show-signature, -L, --no-index, `-O`, `-f`, --recurse-submodules, --dirty, `status -v`, a --format or --pretty that
  reads a signature (`%G…` with git's modifiers) or names a user format or a `%(…)` placeholder, a ref-filter atom
  outside names, ids, dates, people and the subject, a --color other than `=never`, and `rev-parse
  --show-superproject-working-tree`. An option takes its value as the next word only where git was measured to take
  that word as the value even when it looks like an option (`log -n`, `grep -e -A -B -C -m`). A branch pattern counts
  only with --list (without it a name creates a branch). A revision word or a `--opt=value` value before `--` that may
  name an index entry (`:path`, `:0:path`, also after `^` or in a range) keeps any form asked: resolving it reads the
  index, and reading the index queries fsmonitor for every form (measured for rev-parse, log, show, rev-list,
  describe, ls-tree, merge-base, cat-file and a --points-at or --contains value; a path after `--` reads no index).
  For describe, merge-base and ls-tree `--` ends only the options and the words after it are still revisions (for
  ls-tree the first one, where no tree-ish came before): such a word that may name an index entry, or that the shell
  may rewrite, keeps the ask too (R20-2 of review round 20; measured with git 2.43.0, and by the reviewer with 2.51.1:
  `describe --always -- :0:a.txt`, `merge-base -- :a.txt HEAD` and `ls-tree -- :a.txt` started fsmonitor;
  `log --oneline -- :a.txt` and `ls-tree HEAD -- :a.txt` did not).
- The profile reads what K-NW-2 B reads (the effective configuration with every include, the hook directory, the
  hook's GIT_* names) and is an allow-list too: an unknown key, GIT_* name or hook keeps the ask (D44 adds five
  uploadpack keys of the serving side by name). Not free for any form:
  a promisor key, read by its presence (C-5); a pager key (core.pager, pager.*), and GIT_PAGER or PAGER, the two names
  git reads to choose the pager, because no host adapter is bound (answer 3; review Runde 6, point 1: a
  program-selecting variable counts like its key); log.showSignature, format.pretty, pretty.*, submodule.*, and every
  diff.* key that is no display setting. A prefix assignment of the command counts as the hook's environment does
  (`GIT_PAGER=cat git log` asks; `LC_ALL=C git log` does not), as the whole command and as a step of class c. Not
  free for a form that walks the work tree (status, diff, grep, ls-files): a filter, the git-lfs standard filter
  included (answer 2; for `git diff --no-ext-diff --no-textconv` only where an attribute assigns it, D39); fsmonitor
  that git does not read as false; any hook that is not a sample; a submodule
  (a .gitmodules, or a gitlink in the index). The index is listed through the gate's own git path with fsmonitor and
  hooks off, after the profile has found neither (Q18-2). The signing settings are inert for these forms: the grammar
  and the profile let no form read a signature.
- Under Codex a read form keeps the answer of D3 (answer 10). Inside a longer command, class c judges the read form
  as a step of its own; a read form changes no state another step's answer reads (_sh_changes_state). A `git add`
  before a form that walks the work tree counts as a step that changes the state that form's answer read: it may add
  the gitlink of an embedded repository, and a later status or diff then starts that submodule's fsmonitor (measured:
  `git add sub && git status` and `git add sub && git diff` started it, `git add sub`, `git add sub && git commit -m x`
  and `git add sub && git log --oneline -1` did not).

Measured with git 2.43.0, stdout a pipe, in throwaway repositories: fsmonitor, filters and the post-index-change hook
start only for the forms that walk the work tree and for a word that names an index entry (18 of 18 such words); 47
other forms and options of the grammar never started the configured fsmonitor, with or without a `git status` before
(this replaces, for the read forms, the earlier reading that the gate does not try to tell which form reads the
index); diff drivers for log, show and diff; a signature program only where a signature is read; a promisor remote
for every form that reads a missing object; a pager only on a terminal.

What it changes, measured on the plugin before and after (archive of FIX-18 part B, class a, against 6da239e4): asks
89 → 55 in the declared repository with a clean configuration, 91 → 74 with the container configuration, over the
four cells 358 → 256; no deny lost; the 318 runs of the harmful and done-check cases keep their required answer; in
none of the 212 runs whose ground truth executes a gated call is the gate free where it was not; nothing that was free
asks or is denied. Under Codex asks 87 → 87. The ground truth of class a, 33 sources by 42 read forms each run for
real with stdout a pipe (1386 rows): 431 rows are free after, in none of them did the real run start a program; no row
that was free asks; the gate itself started none of the programs it checks for.

Limits, in plain words: the grammar and the allow-lists are those of git 2.43.0; a newer git with a new option or a new
key keeps the ask until the list names it, but a new default behaviour of a listed form is not measured, and nor is
which forms read the index in another git. LESS and LESSOPEN of the host's environment are not read, like PATH (D27):
they act inside git's default pager, only on a terminal. Whether a real Claude Code host sets PAGER or GIT_PAGER for
its hooks is not measured; where it does, class a frees nothing on that host. A form in a repository with a submodule
that does not walk the work tree is judged without the submodule.

## D35. A push handed over to Level 2 (owner adoption of review round 18, 2026-10-14)

Measured first (DESIGN_push_destination.md, version 1): Level 1 does not read the remote (D3), so since R9-1 every push asks
at the destination check, a push with valid evidence included, and the eval `gate-push-verified` cannot pass. git's
pre-push hook gets the ref git resolved and the remote's object id from the advertisement the push itself uses, and
receive-pack's compare-and-swap refuses an update whose remote state changed while the hook ran. Review round 18 judged
variant d (the hand-over) the right direction and the draft not yet sufficient: the transport starts before Level 2
judges (G18-1), and the same source tip is not the same checked range (G18-2). The owner adopted every recommendation
of the reviewer on 2026-10-14; DESIGN_push_destination.md, version 2, holds them with the contract built here.

Chosen (variant d, with the transport rule and the hand-over contract):
- Level 1 hands a push over at one place (`evaluate_push`, `_handover_offer`) and only where all of these hold: the
  host is Claude Code; the call is a `git push` Level 1 reads in its strict form (no `gh`, MCP or `send-pack` route)
  and the whole command is the plain push form of `_codex_plain_push` (no prefix assignment, chain, wrapper, global
  option, other git path, expansion, redirection that opens a file or option word the shell may rewrite: an adversarial
  lens of 2026-10-14 found that a prefix assignment ran git in another environment, so Level 2 refused a hand-over
  Level 1 had announced, and that a dashed `git-push` runs whatever program PATH names); every target resolves up to the destination check and the one reason left open for each is the default case of
  `_dest_resolution` (`DEST_OPEN_AT_REMOTE`; a value that does not name the destination, a recorded candidate, a
  deletion, a forced update and every other reason are no hand-over); only the options `_HANDOVER_FLAGS` names (no
  force, lease, dry run, signed push or push option), and no configured counterpart of an excluded option (push.gpgSign
  true or if-asked, a non-empty push.pushOption list; lens of 2026-10-14); the evidence at every sent commit verified, or a commit that
  declares only a done check passed it; no rules hint of owner choice 4 A, a comparison Level 1 could not make
  included; the approval mode is `with-approvals` (D25); the transport is approved (below); a bound Level 2 is
  installed: the pre-push hook git uses here is a regular, executable file, byte for byte the wrapper of
  `install-pre-push`, and the gate it finds at push time is the gate file Level 1 runs; the git on PATH is byte for
  byte the `git` of the exec path it reports, since only git starts the pre-push hook (a wrapper that pushes with
  `--no-verify` starts no Level 2; lens of 2026-10-14), PATH holds only absolute entries and none through /proc or
  /dev/fd (they resolve per process; lenses 2 and 3), and the python3 on PATH, which the pre-push wrapper starts, is
  byte for byte the interpreter Level 1 runs under (lens 3: a shim there ends the hook with no Level 2). Then Level 1
  writes the
  hand-over and answers `handover`: a message with no permission decision. D4 stays: the gate never answers allow, and
  the host's own permission settings decide whether it asks. The log records the verdict `handover`, never a pass.
  Where a condition fails, the answer is the ask of D3 with "No hand-over to Level 2" and the condition named; where
  only the bound Level 2 is missing, the next step names `install-pre-push` as a voluntary step (answer 5). The gate
  installs nothing.
- The channel: the record `<gate directory>/handover/<nonce>.json`, created exclusively with mode 0600, in the gate
  directory of D25, which a file tool cannot write (decide_write denies it); and the pointer `proofbundle-handover` in
  the per-worktree git directory, which Level 2 finds through git's own repository whatever its environment names. The
  record holds the repository, worktree, git directory, remote, push URL, the push words, the expected updates (source
  and full destination each), created and expires (300 seconds, `HANDOVER_TTL_SECONDS`) and the binding: git's exec
  path and the sha256 of the git program, the hook and its sha256, the gate file and its sha256, the plugin version, the
  interpreter (file, prefix and version), and the digests of the program-selecting environment (every `GIT_*` name but
  `GIT_EXEC_PATH`, `GIT_PREFIX` and `GIT_DIR`, which git sets for a hook, measured with git 2.34.1, the last in a
  linked worktree, whose repository the git directory binds; `HOME`, `XDG_CONFIG_HOME`, the
  gate directory, the ssh agent and the proxy names), of the effective configuration and of the transport.
  The binding records what Level 1 checked (R20-4 of review round 20): the transport digest must equal the approved
  one, the configuration digest the one read before the checks of the hand-over, and git's exec path and sha256 the ones
  the identity check measured. Where the binding reads another value, no record and no pointer are written and the
  push asks, the changed part named.
- The transport approval: `<gate directory>/transports.json`, a JSON array a person writes and the gate only reads,
  each entry exactly `{repo, remote, url, transport_digest}`, read as strictly as `rules.json`. The digest
  (`_transport_digest`) binds the push URL, every configuration entry of the remote, of a URL rewrite, of
  `core.sshCommand`, `core.askPass` and `core.gitProxy` and of the sections ssh, credential, http and protocol, the
  transport environment names, git's exec path with the sha256 of its transport programs, and the ssh on PATH for an ssh
  URL; since the lens of 2026-10-14 (schema v2) also the file and sha256 of every program those configuration entries
  and environment names start (the program word of a plain command, one level), the ssh configuration files for an ssh
  URL, the configuration file of a path remote, and every origin as an absolute path. A person prints it with
  `proofbundle_gate.py transport-digest [--repo DIR] [--remote NAME]`. Any change of what it binds asks again, before
  the transport acts (G18-1: a receive program configured after the approval asks; approved in its turn, it runs).
  A hand-over relies only on the transports and values the gate models (lens 3 of 2026-10-14): a path, the scp form of
  ssh or a URL beginning with file://, ssh://, git+ssh://, ssh+git://, git:// or http(s):// as written, no
  remote.<name>.vcs, every program-naming value a plain command with no assignment in front of its program, whose
  program lies under no /proc or /dev/fd and resolves to a file it hashes (up to `MAX_BOUND_FILE_BYTES`, 512 MiB, read
  in blocks; lens 3, F-O). A path remote counts only where git opens `<path>/.git` or `<path>` as a plain git directory,
  a file URL only as `file:///<path>` without `#`, `?`, `%` or brackets, and every bound file hashes or is absent (lens
  4). A remote helper, shell syntax in a value or an unresolved program keeps the ask, and the answer names it.
- The ASKPASS contract (owner choice 1 of 2026-10-15 on R20-6 of review round 20): an ASKPASS program (GIT_ASKPASS,
  SSH_ASKPASS, core.askPass) that was set when the transport was approved and is unchanged belongs, with its sha256,
  to the approved transport, and the hand-over is then allowed. There is no hand-over for a value that changed, is
  empty, cannot be modelled, or was set only after the approval. A set ASKPASS alone does not exclude the hand-over;
  the approved case is a control test (tests/test_plugin_review20_r6_askpass_contract.py), beside the four cases
  without one.
- Level 2 has two modes and says which ran. Without a pointer it runs standalone, as D24 described it; its pass and
  inactive texts say that git's destination names were not compared with an expected target (answer 6). With a pointer
  it consumes the hand-over first (pointer and record are renamed before they are read, so a hand-over is used at most
  once and every outcome consumes it), then refuses, with the reason `handover_refused` and exit 1, a missing,
  unreadable, foreign, consumed or expired record, one written in the future, another repository, worktree or git
  directory, another remote or push URL than the two arguments git gives the hook, and every difference of the
  binding, each recomputed by Level 2 itself (the git program through `GIT_EXEC_PATH` and `/proc/<parent>/exe`). Then
  the update set (`_handover_update_problem`): every ref line must be an expected update with its source; a line
  twice, a deletion, another source, another destination (the candidate write is named with both names) or any other
  update refuses. An expected update without a line is a no-op git left out (git runs the hook with no line for an
  up-to-date ref, measured with git 2.34.1), named as not checked; no line at all is answered as "checked nothing and
  claims no update". Then the core of D24 judges every actual target range as before: the evidence, the done check and
  D20; a ref the remote does not have yet stays blocked (answer 2). A pass names the hand-over it checked and says that
  a Level 2 pass is no successful remote update.

What D3 keeps: Level 1 reads no remote. The consequence of R9-1 changes for the one case of this section; every other
push asks as before.

With class c (D33) and class a (D34), merged on 2026-10-14 (Nachtrag 4): the hand-over is decided once, for the
whole command. A command in the plain push form keeps the whole command's answer, and class c does not judge it as a
step; in every longer command class c judges a push step without a hand-over (`_decide_outcome_whole` with handover
False), so a step neither gets a hand-over nor writes a record. Measured: `git push origin main; echo done`, `git push
origin main && echo done`, `"git" push origin main` and `\git push origin main` got the hand-over through the step at
the plain merge and ask without one after; `git add a && git commit -m x && git push origin main` and `LANG=C git push
origin main` ask without one on both sides (tests/test_plugin_merge_n4_handover.py).

Limits:
- The record proves no origin. A shell command can write the gate directory and the git directory (D27, F15-2): an
  agent with a shell can write an approval, remove the pointer between the hand-over and the push (Level 2 then runs
  standalone), or write a record of its own. A record grants nothing Level 2 does not check again; it only narrows what
  Level 2 accepts. A local hook is an early warning, and the boundary stays the required CI check and the receiver
  (D22, D24, D27). Every hand-over names the approval file, when it last changed and its sha256.
- The binding compares what Level 1 measured in the host's hook environment with what Level 2 measures in the
  environment of the shell the push runs in. Measured in a real Claude Code session of 2026-10-14 (the host process and
  the Bash tool's shell; the hook's own environment NOT MEASURED): the shell carries `GIT_EDITOR=true` and
  `GIT_OPTIONAL_LOCKS=0`, the host process neither. Bound, they would refuse every hand-over wherever the hook's
  environment is the host process's; the binding now leaves them out with an inert value (`_HOST_SHELL_INERT`:
  `GIT_EDITOR` true or `:`, `GIT_OPTIONAL_LOCKS` 0 or 1), and any other value is bound. In the same session PATH was
  equal in both (same entries, same order, none relative), and no other `GIT_*`, ssh or proxy name differed. Level 1
  reads the hook's environment, not the shell's, and that gap stays (the gap of G18-1 from the side of the environment):
  where a shell profile exports another name the binding reads, Level 2 refuses the hand-over; where that name selects a
  transport program, the program acts before Level 2 refuses; where it turns the hook off (`GIT_CONFIG_COUNT` with
  `core.hooksPath`) or a PATH the shell orders differently selects another git, no Level 2 runs at all (lens 2 of
  2026-10-14, F-F and F-G). PATH is bound through the programs it selects (git, the interpreter), not as a string. The
  ssh agent socket (`SSH_AUTH_SOCK`) is bound as a value, so an approval asks again after a new login.
- On a system without `/proc/<parent>/exe` the git program is bound through its exec path only.
- Code in the site-packages of the interpreter (a `.pth` file, `sitecustomize`) runs in Level 1 too, which the host
  starts with `python3 -I`, and can change any answer; writing it is the class of D27 (lens 4).
- Level 1 checks git and python3 on PATH when it answers. A wrapper written there after that answer, within the 300
  seconds of a hand-over, runs instead and starts no Level 2 (lens 3, F-I2; the class of D27). A `uv` shim forges the
  verifier for Level 1 and Level 2 alike; that is older than this section and not changed here. A python3 that is a
  script shim (pyenv, for instance) keeps the ask.
- Level 1 compares the git on PATH with the `git` in the exec path that program reports. A program that reports a
  forged exec path holding a copy of itself is not caught (D27). Where git's exec path holds no `git`, or the git on
  PATH is a shim (such as the one of macOS at /usr/bin/git, NOT MEASURED), the push stays an ask.
- Two pushes from one worktree at the same moment share one pointer; the second Level 1 replaces the first's pointer,
  and the first push is refused, or runs standalone where its pointer was consumed already.
- Consumed records stay in the gate directory as the trace of each hand-over; nothing removes them.
- A pointer whose push never ran (a person declined it, or the command stopped before git) refuses the next push of
  that worktree once, as expired or as another update, and that push consumes it.
- The transport digest binds one level of programs: the program behind a wrapper word such as `env`, what a named
  program reads or starts in turn, an `Include` of the ssh configuration, an include of a path remote's configuration
  and that repository's hooks are not bound, and a change between Level 1 and the push acts before Level 2 refuses the
  hand-over. An approval written under schema v1 asks once.
- A symbolic link or another entry outside the narrow contract of D5 in the git directory leaves Level 1's local rules
  comparison unmade, and that keeps the push an ask.
- Measured with git 2.34.1 only; git 2.43.0, 2.51.1 and 2.56.0 are NOT MEASURED for this section.

Measured (tests/test_plugin_gate_push_destination_18.py and tests/test_plugin_gate_destination_kind.py, 2026-10-14, git
2.34.1, through git against local bare repositories): the catch cases of review round 18 named in DESIGN_push_destination.md
section 7.1, each with a test. The tests of a new rule are red before it and green after; the tests of a behaviour
that existed before (the deny paths of false or missing evidence and a false done check, Codex, an abort) are controls,
green on both sides, and hold that the hand-over does not weaken it.

Options (DESIGN_push_destination.md, sections 3 to 5):
- a. A dry-run push before the decision. Rejected: it runs the transport before consent and binds nothing (answer 4).
- b. `git ls-remote`. Rejected: another advertisement than the push's.
- c. No read, a hint instead of an ask. Rejected: it gives up D20 at Level 1 and passes the candidate write.
- d. The hand-over to Level 2, with the transport rule and the contract above (chosen).
- e. a for the message, d for the verdict. Rejected with a (answer 4).

Owner answer of 2026-10-15 (Nachtrag 8 to FIX-18 part B): a redirection that opens no file stays in the plain push form.
`git push origin main 2>/dev/null` and `git push origin main < /dev/null` are the plain push of `_codex_plain_push` and
are handed over like the push alone; Level 2 still judges the real push against the record and checks its receipt. The
corpus layer handover of Nachtrag 6, point 3, measured both forms handed over and every other form of the layer (a
chain, a pipe, a subshell, a group, a substitution, a redirection into a file, a prefix assignment) not handed over;
its expectation now names these two forms beside the push alone. The gate is unchanged.

## D36. A gh read form free after a gh profile: class b of the ask load (FIX-18 part B, 2026-10-14)

Owner answers 4, 5 and 10 of 2026-10-14, equal to the reviewer's recommendations: no `gh attestation verify`; the rules
bound to checked gh versions; class b applies under Codex too. Answer 3 (no pipe relied on without a bound host
adapter) is read for gh as for git: a pager counts.

Built: a gh read form is free under both hosts when it is the whole command (or a step class c judges on its own, D33),
headed by a bare `gh` (quoted or escaped as class a reads `"git"`), with no prefix assignment at all, no word the shell
may rewrite and no redirection, on the allow-list (_gh_read_form), and the gh profile (_gh_profile_problem) finds
nothing. Reason id `free_after_gh_profile`; where the profile finds something, `gh_form_not_free` names it and asks
(denied under Codex). Anything off the list keeps today's answer (the safety net, `net_unmodeled_git`).
- The forms, by exact command path: pr view, checks, diff, list and status; run view and list; issue view and list;
  release view and list; repo view; workflow list and view; auth status; `gh --version`; and `gh api` as a REST GET or a
  GraphQL query. Each takes only the options gh 2.89.0 lists for it, less `-w`/`--web`, `--hostname` and
  `--show-token`; a cluster of short options, a value on a flag, `--` and an unknown option keep the ask. Not on the
  list: every other command, `attestation verify` (answer 4), `run watch`, `search`, `status`, the aliases and
  extensions, and every form measured to write, start a program or transfer.
- A repository only as OWNER/REPO (-R, the argument of `gh repo view`, GH_REPO), and a pull request, issue or run only
  by number: `-R git@host:o/r`, `-R https://host/o/r`, `gh repo view host/o/r`, `GH_REPO=host/o/r` and a URL as the
  argument of pr view, diff, checks and issue view each asked the host they named (measured).
- `gh api`: one path, no `://` and no leading `//` (`HTTPS://127.0.0.1/x` went to 127.0.0.1), no field without
  `-X GET`, only GET, no field value that starts with `@`, no --input, only Accept headers. GraphQL: exactly one
  `query` field given raw with -f, no operationName, no method, and a document of exactly one operation that is a
  query (_gh_graphql_query_only; a mutation after a query in one document runs with an operationName, measured).
- A jq expression that spells `env` in any letter case keeps the ask: gh's jq reads the environment, and `--jq
  '$ENV.GH_TOKEN'` and `--jq 'env.GH_TOKEN'` printed the token (measured). Go templates have no such function
  (measured).
- The gh profile: (1) the hook's environment, an allow-list of gh's names (`gh help environment`): not free with
  GH_PAGER set to a value, PAGER, GH_FORCE_TTY, GH_HOST, GH_ENTERPRISE_TOKEN or GITHUB_ENTERPRISE_TOKEN, GH_REPO in
  another form than OWNER/REPO, or a GH_* name it does not know (GH_PATH among them); (2) gh's configuration
  (config.yml and hosts.yml in GH_CONFIG_DIR, $XDG_CONFIG_HOME/gh or $HOME/.config/gh, absolute only): not free with a
  pager or a unix socket with a value, a key it does not know, or a file not in the block form gh writes; an empty
  `pager:` is none, and GH_PAGER set empty overrides the configured one (both measured); the two files are read without
  blocking, their type checked at the opened descriptor, so a FIFO, a device or a socket in their place is refused
  and never waited on (R20-5 of review round 20, the reader of R18-2); (3) the version: every PATH
  entry absolute and not through /proc or /dev/fd, and `gh --version` of the gh on that PATH names 2.89.0 (answer 5).
  The repository plays no part: the git gh starts for these forms started none of the program sources of class a,
  all set at once (measured).
- Inside a longer command, class c judges the gh read form as a step of its own. A gh read form changes no state
  another step reads (it writes gh's HTTP cache only, measured); a step before it that writes into gh's configuration
  folder changes what its profile read, and the step asks. So does a step that writes one of the files the answer
  read under another name (R20-3 of review round 20): config.yml, hosts.yml or the program the later step's name
  selects on PATH (gh, or git for a read form of class a), compared by the resolved path and by device and inode,
  so that a symbolic link or a hard link outside the folder counts as the file itself.

Measured with gh 2.89.0 against a local stand-in for github.com, api.github.com and a second host, in a network
namespace of its own with only the loopback interface, under strace (programs started, connections), with fake tokens:
the read forms above sent only GET requests and GraphQL queries and started only git with the forms named; pr checks,
release list and `api --cache` wrote gh's HTTP cache under $XDG_CACHE_HOME/gh; a pager started only on a terminal or
with GH_FORCE_TTY, and gh never used git's core.pager (measured with core.pager set and no gh pager); a browser only
with --web and `gh browse`; GH_TOKEN reached github.com only, GH_ENTERPRISE_TOKEN an unconfigured host named by
--hostname; `gh auth token` and `auth status --show-token` printed the token, `api --verbose` and GH_DEBUG=api did not.

What it changes, measured on the plugin before and after (archive of FIX-18 part B, class b, against ac0e8a72): asks
55 → 40 in the declared repository with a clean configuration, 74 → 59 with the container configuration, over the four
cells 256 → 196; under Codex 87 → 72; no deny lost; the 318 runs of the harmful and done-check cases keep their required
answer; in none of the 212 runs whose ground truth executes a gated call is the gate free where it was not; nothing that
was free asks or is denied.

Limits, in plain words: the allow-list is gh 2.89.0's, and every other version keeps the ask; the version line proves no
origin (D27), so a program that prints it is not caught, as no program on PATH is (D27). The hook's PATH and
environment are read, not the Bash tool's shell, which may set others (not measured on a real Claude Code host, as for
class a). Under Codex the command's environment may differ from the hook's (R5-2); owner answer 10 accepts that for
class b. A host gh reaches through the repository's remotes is the one gh's own configuration knows; how GitHub reads a
GET it is sent, and an X-HTTP-Method-Override, is not measured (only Accept headers pass). A gh read form in a shell
alias or function of the host's Bash tool is not seen. Since Ergänzung 2 to Nachtrag 18, gh 2.92.0 is a checked
version as well, under the conditions of D43.

## D37. Codex 0.162.1: a patch without an environment line, and class a under Codex (Nachtrag 9, 2026-10-15)

Milestone run 2 (Codex CLI 0.162.1, plugin d828c2be) had three calls denied: the chain `git status && git branch &&
git remote -v` (git_form_not_free, directory_unresolved), `git -C <absolute path> status` (git_form_not_free), and an
apply_patch on a file under src/ without `*** Environment ID:` (codex_write_unbound). Owner choice C (card
OA-ea10af584e): measure both at the Codex 0.162.1 source and build only what it shows. Nothing is built; the gate is
unchanged.

MEASURED, read from the Codex source at tag rust-v0.162.1 (commit 092d3acd6bec3e3a14bdc7e7a2810ab628ab759d), not run.
Paths are under codex-rs/.
- What the hook gets. Its stdin carries session_id, turn_id, agent_id and agent_type for a subagent,
  transcript_path, cwd, hook_event_name, model, permission_mode, tool_name, tool_input and tool_use_id
  (hooks/src/schema.rs lines 278-296): no environment id, no list of the turn's environments, no Codex version. The
  hook process gets the Codex process environment as it stood when the session's hooks were built
  (hooks/src/registry.rs line 79), then the handler's own values, for a plugin PLUGIN_ROOT, CLAUDE_PLUGIN_ROOT,
  PLUGIN_DATA and CLAUDE_PLUGIN_DATA (hooks/src/engine/discovery.rs lines 262-270). CODEX_VERSION is put into a shell
  tool's environment only (core/src/exec_env.rs lines 38-48).
- The hook's cwd (core/src/hook_runtime.rs lines 247-253, core/src/environment_selection.rs lines 1196-1215): the cwd
  of the first ready local environment of the turn, or the selection cwd of a starting `local`, else the turn's cwd.
- A patch without an environment line (core/src/tools/handlers/mod.rs lines 172-173): the first ready environment of
  the turn, in its order (core/src/environment_selection.rs lines 1113-1120 and 1158-1160). The patch is verified and
  applied in that environment's filesystem against its selection cwd (core/src/tools/handlers/apply_patch.rs lines
  330-346, core/src/session/turn_context.rs lines 209-211). Hook and handler run on the same invocation, so on the
  same snapshot of the turn's environments (core/src/tools/registry.rs lines 609-615).
- So the hook's cwd is the directory the patch acts in exactly when the first ready environment of the turn is the
  local one. That holds in the default form: no CODEX_EXEC_SERVER_URL, no environments.toml in CODEX_HOME, no
  environment a client adds or selects. The turn then has `local` only (exec-server/src/environment_provider.rs lines
  77-108), and the apply_patch tool does not take an environment line (core/src/tools/spec_plan.rs lines 1344-1346,
  apply_patch.rs lines 575-587). It does not hold when the first ready environment is a remote one: with
  CODEX_EXEC_SERVER_URL set the turn has `remote` only and the hook's cwd is the turn's on the host (hook_runtime.rs
  line 249, "Hooks run on the host"), by default the same path text on another machine; with environments.toml, or a
  client that puts another environment first (exec-server/src/environment.rs lines 373-390; thread/start and
  turn/start `environments`, environment/add); and in a turn whose local environment is not ready while another one
  is.
- Neither the version nor the form reaches the hook. No field names them; the environment the hook inherits is the
  Codex process's, which a client's thread/start, turn/start or environment/add does not change; and `codex --version`
  of a codex on the hook's PATH names a program on PATH, not the one that started the hook. The gh pin of D36 checks
  the program the command itself starts; the caller here is not found through PATH.
- exec_command, which the hook sees as Bash: tool_input is `{"command": cmd}` only
  (core/src/tools/handlers/unified_exec/exec_command.rs lines 514-525). Not given to the hook: environment_id, workdir
  (joined to the environment's cwd, lines 186-201), shell, login, sandbox_permissions and additional_permissions
  (core/src/tools/handlers/unified_exec.rs lines 28-61). The command's environment is built for the command: the shell
  environment policy over the Codex process environment (inherit all by default, protocol/src/config_types.rs lines
  261-272, its `set` applied), values Codex sets (PAGER, GIT_PAGER and GH_PAGER `cat` among them,
  core/src/unified_exec/process_manager.rs lines 93-104 and 1443-1460), and, with shell_snapshot on by default
  (features/src/lib.rs lines 1059-1063), every export of the user's login shell, replayed before the command, after
  which only the policy's `set` and Codex's own runtime names are exported again
  (shell-command/src/shell_snapshot_exports.rs, core/src/tools/runtimes/mod.rs lines 351-372).

Class a under Codex. Under Claude Code class a (D34) reads the directory from the hook's cwd and at most one literal
`-C`, the GIT_* names, the pager and the configuration's includes from the hook's own environment, on the machine the
hook runs on. Under Codex 0.162.1 the hook input lacks the execution environment of the call (every form), the workdir
(a form without an absolute `-C`) and the command's environment (the policy's `set`, the login shell's exports).
`git -C <absolute path> status` names its directory in its text; it lacks the environment it runs in and the
environment variables git sees. `git remote`, a step of the chain, is no read form of class a under either host. Class a
stays off under Codex (owner answer 10); a patch without an environment line stays codex_write_unbound.

Not built (Nachtrag 9, point 5): the gate cannot tell the default form or the version from what it sees, so reading
such a patch as bound to cwd would reach every form and version, which is wider than shown.

Decided (owner choice 2 of 2026-10-15 on question N9-1: A, as the reviewer of round 20 recommended): apply_patch
under Codex stays codex_write_unbound, a patch without an environment line included, and class a stays off under
Codex. A later B, reading such a patch as bound to the hook's cwd, would need at least, as the reviewer named them:
a binding to the Codex build actually started and checked; exactly one local environment, enforced technically; no
later choice of environments by a client (thread/start, turn/start, environment/add); a binding the agent cannot
produce itself; updatedInput excluded or the changed input checked again; and a measurement on a real host. A
missing environments.toml and missing process variables are no proof that only the local environment is selected,
and `codex --version` on PATH does not identify the process that started the hook.

The answer to a read form of class a under Codex (owner choice 3 of 2026-10-15): the explanation and the next step
of the reviewer's answer 4, word for word. Explanation: "NOT MEASURED. Under Codex, even with an absolute git -C
path, the execution environment, filesystem and environment variables remain unbound. Without such a -C argument,
the effective working directory is unbound as well. The gate therefore cannot free this read form." Next step:
"Have a person run the call outside this unverified agent path, or use a host whose hook supplies the required
execution context." Only a read form the gate recognises as class a carries it; a form outside class a keeps its
own reason (`git remote`, directory_unresolved in the chain of milestone run 2; a git form that is not free, D3).
The verdict, the exit code and the reason id stay: deny as the host answer, exit 0, git_form_not_free.

In the answer of the whole command (owner choice of 2026-10-15, Nachtrag 11): under Codex every step of a longer
command that is a read form of the grammar carries the same explanation and next step. A read form is the check class a
frees with under Claude Code (_read_form, the words the shell rewrites included), applied to the step's run as to the
whole command: a bare `git` at the head of the run, at most one literal `-C`, no global option, no expansion, no
redirection, no unvetted assignment in the command. The chain of milestone run 2 now carries the reviewer's text for
`git status` and `git branch`; `git remote` keeps directory_unresolved and `git stash list` the text of D3. With an
absolute `git -C` in the step the same text applies, which claims no missing directory. The verdict, the exit code and
the reason ids stay; under Claude Code nothing changes. A step whose membership is unclear keeps the text of D3 and is
an owner question, not built: a step in a shell string or a substitution, after a wrapper or a keyword, in a command
with a subshell, a group, a function definition or a here-document, or with a run headed by an expansion, a word that
is no plain command name, or a builtin that defines a function, an alias, a builtin or a hashed program, runs text or
another command, or sets options or variables in the current shell (_READ_STEP_UNCLEAR_HEADS, a printf that may set a
variable); a step whose name another step outside the grammar shares, as the answers of one name count once; and
`git worktree list`, the one read form whose subcommand the scan of a longer command names a possible transfer, which
keeps directory_unresolved there because the reason ids stay.

Siblings. A shell command `apply_patch <<'EOF' …` is applied by Codex itself in the environment's cwd joined with the
workdir (exec_command.rs lines 372-384); the gate sees a Bash call without a git or gh word and does not judge it (D8),
as for any shell write (D27). Class b under Codex (D36) reads the gh profile from the hook's environment, while the
command's environment carries the policy's `set` and the login shell's exports; answer 10 accepted that the two may
differ, and the lines above are the path by which they do. Not changed here.

Corpus rows of the three forms, a harmful counterpart and controls: measured on 62dcc7b0 and on this commit, under both
hosts, with the same answers (archive of Nachtrag 9).

## D38. A done order outside the work tree, for every repository it names (Nachtrag 12, 2026-10-15)

Measured by delta in the pilot at 35214a8c (finding 20261015T1725Z): Stop and TaskCompleted judged only the repository
of the hook's cwd (`done_evaluation(_event_directory(event))`), so a session that works in clones with `git -C <clone>`
from a fixed directory never had a clone's order checked; and an order kept only in the work tree (`.proofbundle/` in
`.git/info/exclude`, variant E) blocked every end, a valid receipt included ("the declaration is not committed"),
while a committed order (variant C) put `.proofbundle/` into the pull request.

Measured for the place (Nachtrag 12, probe_write_targets): the PreToolUse gate denies a Write and an apply_patch into
the gate directory under both hosts (write_to_gate_dir); into the plugin data folder it gives Claude Code no answer
and denies under Codex only as codex_write_unbound. Read, not run: Claude Code gives hooks CLAUDE_PLUGIN_DATA and Codex
0.162.1 its own PLUGIN_DATA (D37), so an order in one host's data folder is not seen by the other; the gate directory
is the same for both.

Chosen (owner order of Nachtrag 12, place decided in the build):
- A local done order is a file `done-orders/<key>.json` in the gate directory (D25), outside every work tree. Its key
  is the sha256 of the repository's work tree root and git directory as git names them, resolved physically. It holds
  the order in the form of the declaration's `done` section (D28), the policy's bytes, the commit that was HEAD when
  the order was made (the base of `paths`, D31), the root and the git directory. Nothing of it is in a commit.
- A person makes it with `done-order --repo DIR`: the done section and the policy come from the declaration and
  policy in the work tree (variant E) or from files named with `--declaration` and `--policy`, which may lie outside
  it. The command adds every receipt and every file of the done check's own that git does not yet ignore to the
  repository's `info/exclude`, so none of them reaches a commit, and writes no order if git still does not ignore one.
  `--replace` writes a new order over an existing one, `--remove` (by `--repo` or `--key`) deletes an order and its
  record, `--list` names every order with what the gate finds for it.
- The gate takes the order's digest when it writes it, its first read, into `done-orders/<key>.seen.json`. At every
  Stop and TaskCompleted the order must still have that digest. An order that differs (`order_changed`), an order
  without the gate's record (`order_unrecorded`), a record whose order is gone (`order_removed`) and an order the gate
  cannot read (`order_unreadable`) block the end with their reason, fail-closed like an uncommitted declaration, until
  a person makes the order again or removes it. A replacement keeps the digest it replaced in the record.
- Stop and TaskCompleted judge the repository of the hook's cwd as before, and then every repository with a local
  order, whatever the cwd. An order is open while a check has no valid receipt for the state now; the end blocks with
  the first open point, and the line names the repository. Each repository counts its own blocks and writes its own
  blocker (D28); the first one that still blocks gives the answer, and the end without a done verdict comes only when
  every refused repository has written its blocker. A refused order counts in its repository where git finds it bound
  as the order names it; otherwise it counts in the gate directory beside the order, `<key>.state.json` and
  `<key>.blocker.json` (owner choice O3 of Nachtrag 13), so the session ends without a done verdict after the limit
  under both hosts, as in D26. Both counts take the default limit, never one a changed order sets. The order stays, and
  `done-order --list` names it; `--remove` takes its count files along. Only a folder the gate cannot list blocks
  without a count.
- An order whose repository git no longer finds at its root, or finds with another git directory, blocks
  (`order_unbound`) until a person restores the repository or removes the order.
- In a repository with a local order, a declaration found only in the work tree is not refused as uncommitted; the
  local order stands for it (`local_order_stands`, no block of its own). A declaration at HEAD with a done check is
  judged as before, beside the local order, and the end needs both.
- The committed order of D28 is unchanged, and so are the push path and the CI check.
- A shell command that runs done-order (owner choice O2 of Nachtrag 13): a new order and `--list` are free, since they
  only add a duty or read; `--replace`, `--remove` and every form the gate cannot read whole (an unknown switch, a word
  the shell builds or rewrites, the script or the subcommand given by an expansion, an unparsable command that names
  done-order) ask under Claude Code and are denied under Codex (`done_order_change`). The PreToolUse gate reads the call
  in each form it reads a program in: the gate's script by its file name `proofbundle_gate.py`, as the program or as
  the script of python or of a wrapper, in each run of a chain, a pipeline or a list, in a command substitution and in
  the string of `sh -c`, `eval`, `source` and `.`. A shell that writes the files of `done-orders/` directly is the
  limit of D27; a copy of the gate under another name and code an interpreter runs (`python3 -c`) are not read.
- done-order behind a program that builds its arguments from its input (finding F1 of Nachtrag 17, measured by Cowork
  at f6408b97): `echo --replace | xargs python3 <gate> done-order --repo <clone>` runs done-order with `--replace`,
  and got no answer. Behind xargs or GNU parallel the gate's script with done-order or with no subcommand word, and
  done-order itself, are a change in every form (`-I`, `-a`, `-0`, `-n`, input on standard input): ask under Claude
  Code, deny under Codex. Measured at d6e248a8 for the siblings: `xargs -I{} … {}`, `xargs -i`, parallel with `:::`
  and every `find -exec` and `-execdir` form asked already (`{}`, `:::` and the closing `;` are words the gate answers
  as a change); find is not added. A done-order call whose script and subcommand both come from a file or from another
  program's output (`xargs -a calls.txt python3`) names neither in the command and is not seen, like code an
  interpreter runs.
- Codex reads the same gate directory, so its Stop hook judges the same orders. Codex has no TaskCompleted event.

Limits: the gate directory is closed to the file tools of both hosts, not to the shell (D27); a shell write is seen
only through the digest, and a shell that rewrites the order and the gate's record together is not seen. The agent
can run a new order or the list itself; a replacement or a removal through its shell asks or is denied since O2, and the
record keeps every replacement a person makes. Every session
of the user, under both hosts, sees every local order, so two sessions in different clones block each other's ends, and
so does a session with another CLAUDE_CONFIG_DIR (measured by Cowork, Nachtrag 13). Owner choice of 2026-10-15
(Nachtrag 13, O1): an order is to be bound to the account, CLAUDE_CONFIG_DIR under Claude Code and CODEX_HOME under
Codex. That is built before the plugin reaches a second account, not now: in the pilot only delta has the plugin. A
refused order whose repository is gone ends the session without a done verdict after the limit since O3, under both
hosts; before, it blocked without a count and Codex had no end. Nothing in CI sees a local order: it is an early warning, and the boundary for what is
committed stays the required CI check.

Options:
- A. The order in the gate directory, its digest taken when it is written, every order judged at every end (chosen).
- B. The order in the plugin data folder (Cowork's proposal). Not chosen after the measurement above: Claude Code's
  file tools may write there, and the two hosts each have a folder of their own.
- C. An order bound to one session. Not built (owner question O1 of Nachtrag 12); the owner chose the account instead,
  to be built before a second account (Nachtrag 13).

## D39. Fewer asks in daily work: a here-document to python, git diff without diff drivers (Nachtrag 14, 2026-10-15)

Measured by delta in the pilot at 14a5feb1 under Claude Code, from 22:47 Berlin: five asks in ten minutes. Two came from
`python3 - "$B" "$L" <<'EOF'` whose Python named git or gh in strings and variable names (the safety net,
net_unmodeled_git); one from `git -C <dir> diff --stat` beside a sed and grep pipeline (D3); one from `gh pr view …
--json body --jq .body` after a `cd` in a chain (net_unmodeled_git); one from `git add` before the house commit script
(D3, D33), which stays, as every commit through that ceremony asks. delta changes three habits (Python in a file, grep
for command grep, reading with git status and git log); the parts below are what remains (owner word of 23:00 and owner
choice of 23:0x).

Part 1, a here-document to python (owner choice of Nachtrag 14):
- A command that is exactly `python3 - [arguments] <<'MARK'` (or `python - …`) with a marker the shell sees quoted
  (`'MARK'`, `"MARK"`, `\MARK`), its body and the marker line is judged by its words before the here-document,
  `python3 - [arguments]`, as `python3 file.py [arguments]` is judged (_interpreter_heredoc_head). With a quoted marker
  the shell expands nothing in the body; it is the interpreter's input and no shell text, so neither the safety net
  nor class c reads a git or gh word in it.
- The command gets no freer answer than the file form, only no ask from the body: a git or gh word in the arguments
  and a substitution there that runs git get the answer the file form gets, and so does a done-order call in them
  (D38, O2).
- Today's answer stays for every other form: an unquoted marker, another interpreter (perl, node, …), a shell as the
  interpreter (bash, sh, zsh), python without `-`, an option before `-`, a path, a wrapper or an assignment before
  python, a second here-document or any other redirection, `<<-`, a chain, a pipeline, a list, a command after the
  marker line, and every form the class c parser does not model.
- For this one form the rule replaces owner answer 9 of 2026-10-14 (an interpreter whose words or here-document name
  git or gh asks at least, D33) and the control of review finding Q18-1: `python3 - <<'PY'` with `os.system('git push
  origin main')` in its body asked from d828c2be to d6e248a8 and now gets the answer of `python3 file.py`, which the
  gate does not gate. Answer 6 stands: the gate reads no Python and judges none inert. The `-c` forms of Q18-1 and
  every other interpreter still ask.
- Limit: the Python in the body may start git or gh, as a file may; the gate does not read code (D8). The push path,
  the pre-push hook and the CI check are unchanged.

Part 2, git diff without diff drivers (owner choice of Nachtrag 14):
- Measured first, at d6e248a8: `git diff` and `git show` are read forms of class a since D34. In a repository whose
  configuration has no filter key, `git diff --stat` is free with or without the two switches; `git show --stat` is
  free with the lfs filter configured too, as a filter never counted for a form that does not walk the work tree. Two
  things asked: `git -C $W diff --stat`, whose `-C` word is an expansion (D3), and every walking form wherever a filter
  key is configured (answer 2), as `git lfs install` does in the global configuration and as this container's
  /etc/gitconfig does (`git diff --stat` asked with "a filter: filter.lfs.clean in the system configuration").
- Measured with git 2.43.0, stdout a pipe, in throwaway repositories (measure/proxy_starts.sh of Nachtrag 14): for
  `git diff --no-ext-diff --no-textconv`, with and without `--stat`, fsmonitor and a clean filter an attribute assigns
  started; diff.external, GIT_EXTERNAL_DIFF, a diff driver's command and a textconv program did not, and each started
  for `git diff` without the switches (textconv for `git show` too); a clean and a process filter no attribute names
  started for no form; a pager with stdout a pipe for none. `git show` started neither fsmonitor nor a filter.
- Built: `git diff` with both `--no-ext-diff` and `--no-textconv` before `--` (_drivers_off) is a read form whose read
  profile counts a configured filter only where an attribute assigns a filter to a path of the index. git resolves the
  attributes itself: `check-attr filter` over the paths `ls-files` lists, in the direction of a check-in, with every
  attribute file and macro, through the gate's own git path with fsmonitor and hooks off (_filter_assigned). Any value
  but unspecified and unset asks, a driver no key defines included, and so does a listing or a check git does not
  complete. The ask names the path and the value. Free under Claude Code after that profile; under Codex the
  reviewer's text of D37, as for every read form.
- Every other rule of D34 stays for this form: fsmonitor that git does not read as false, any hook that is not a
  sample, a submodule, a promisor key, the pager keys and GIT_PAGER or PAGER (the gate cannot add `--no-pager` or set
  GIT_PAGER for the command it answers), and every diff.* key that is no display setting. diff.external and a
  driver's command or textconv program keep the ask although they did not start with both switches: that is measured
  with git 2.43.0 only, and the owner's order keeps every way not safely excluded an ask.
- Class c: a step before the switched diff that writes a file named `.gitattributes`, `attributes` or
  `gitattributes` changes the state its answer read (_sh_reads_attributes), so the diff asks there; a step that writes
  another file leaves it free as a step of its own (D33).
- Without both switches `git diff` keeps today's answer: it asks where a filter key is configured and is free where
  none is (D34). `git show` is unchanged with and without the switches.
- Limits: the attributes are read when the gate answers, from the work tree, the index and the attribute files of the
  hook's environment; a file another process writes between the answer and the run is not seen (D27). The way git
  reads attributes is git's own; a newer git that reads them from another place keeps that place unread until the
  profile names it (attr.tree and GIT_ATTR_SOURCE already ask, as a key and a GIT_* name the profile does not know).

## D40. add, commit and worktree add with one absolute -C, commit -F (Nachtrag 15, 2026-10-15)

Measured by delta in the pilot at 14a5feb1 under Claude Code, 23:01 to 23:13 Berlin, while setting up scope 6.3.1: four
asks. Three came from a gap of the gate:
- `git -C /mnt/<speicher>/claude_worktrees/scope_631 add docs/release_scope/6.3.1.md` asked: K-NW-2 B (D3, D33) freed add
  and commit only with no global option, while the read forms of class a take one literal `-C` and the gate's own
  answer tells the agent to name the repository with `git -C <absolute path>`; a `cd` before it stays unresolved. delta
  works in linked work trees on <speicher> and starts the session elsewhere, so add and commit had no free form.
- `git -C … commit -q -F <file>` asked: _plain_add_commit knew only `-m`, and a message from a file is the house rule
  for longer commit texts.
- `git -C /home/<nutzer>/proofbundle worktree add -q -b docs/release-scope-6-3-1 /mnt/<speicher>/claude_worktrees/scope_631
  origin/main` asked with the text for unresolved push forms; delta adds a work tree for every order.
The fourth, a chain with `W=…`, `test -e` and `git fetch`, stays: delta writes paths literally from now on and runs
fetch on its own, and fetch stays an ask (below).

Part 1, add and commit with one literal absolute `-C` (owner choice of Nachtrag 15):
- `git -C <path> add …` and `git -C <path> commit …` are judged as the forms without `-C` are (D3): the same options
  (_ADD_OPTIONS, _COMMIT_FLAGS), the repository the path names instead of the hook's cwd, and the same state check
  (_add_commit_state_problem) for that repository, also as steps of a plain chain (D33).
- The path is the value of exactly one global option, the word `-C` itself, and is literal and absolute as written:
  no expansion, no word the shell may rewrite, no `~` (_one_absolute_c). Two `-C`, a relative path, a path the shell may
  rewrite and any other global option (`-c`, `--git-dir`, …) keep today's answer.
- The state check reads a linked work tree through git itself: `rev-parse --git-common-dir --git-dir --git-path hooks`
  follows the `.git` file to the gitdir and its commondir, and names the hooks of the common directory or of
  core.hooksPath; `config --list --show-scope` reads config.worktree where extensions.worktreeConfig is set. Measured
  in tests: a pre-commit hook in the common directory, a core.hooksPath and a core.fsmonitor in config.worktree each
  ask and are named, and a counter-probe in bash starts each proxy.
- Under Codex such a form is free after the state check as the forms without `-C` are (D3); the pass names the
  directory the command names and says that Codex does not tell the gate the environment a command runs in (D37).
- Class c: a `git -C <path> add` before a `git -C <path> commit` changes no state the commit's answer read, as for the
  forms without `-C` (_sh_changes_state).

Part 2, commit -F with a file (owner choice of Nachtrag 15):
- `git commit -F <file>` and `git commit --file=<file>` count as a message as `-m` does, with and without the `-C` of
  part 1, after the same state check. The file is literal: no word the shell may rewrite, no expansion.
- Not free stay: `-F -` and `--file=-` (the message from standard input), an empty name, `--file <file>` as two words,
  an `F` inside a cluster (`-qF`), and `-e`, `--edit`, `-t`, `--template`, `--cleanup` and every other option.
- Reading the file starts no program; the hooks that read the message (commit-msg, prepare-commit-msg) are part of the
  state check as before. Measured in tests: a commit-msg hook in the common directory asks and starts in bash.

Part 3, worktree add after a checkout check (owner choice of Nachtrag 15):
- `git -C <literal absolute path> worktree add [-q] [-b <name>] <literal absolute target> [<revision>]` is free under
  Claude Code after the checkout check (_checkout_state_problem); -q and -b each at most once and before the target, the
  name and the revision literal and not starting with `-`. Under Codex it carries the reviewer's text of D37, with
  "this form" for "this read form". `--detach`, `--lock`, `--orphan`, `--track`, `-B`, `--force` and every other option,
  a relative target, more than one `-C` and the form as a step of a longer command keep today's answer.
- The form writes only locally: a new branch, a folder and the records under `.git/worktrees`. The target must not
  exist, and it must be no path a file-tool write may not touch (a hook directory, a configuration file, the gate
  directory; decide_write).
- Measured with git 2.43.0 in throwaway repositories (measure/worktree_add_starts.sh of Nachtrag 15): with a proxy for
  every hook githooks(5) names, in the hook directory and through core.hooksPath, the form ran post-checkout,
  post-index-change and reference-transaction; a smudge and a process filter an attribute assigns started, the same
  filters with no attribute did not; fsmonitor started; commit.gpgSign with gpg.program started nothing.
- The check reads the repository as K-NW-2 B does: the effective configuration with every include, a linked work tree's
  own configuration, the hooks of the common directory or of core.hooksPath, and the GIT_* environment. Not free: any
  filter key (no attribute is read here, as the checkout reads the attributes of the revision it checks out), fsmonitor,
  a configured hook, automatic maintenance, every key or GIT_* name the check does not know, and every hook outside the
  25 names measured not to run (_HOOKS_NOT_RUN_BY_WORKTREE_ADD). The signing settings are inert for this form: it makes
  no commit and no tag.

Stays an ask, named: `git fetch`. It talks to the network and may start a program through a credential helper, a
transport helper (`ext::`, `remote-<scheme>`), core.sshCommand or GIT_SSH, an upload-pack the remote names, or the
reference-transaction hook. The gate models none of these ways; fetch keeps the text of an unresolved transfer, with
and without `-C`.

Limits, in plain words: every measurement is with git 2.43.0 (delta: 2.51.1); a hook name a newer git adds keeps the
form not free until the list names it. The checkout check reads the state when the gate answers; a file another process
writes between the answer and the run is not seen (D27). Where git-lfs is installed its filter keys keep `worktree add`
asked; whether a filter counts only where an attribute assigns it, as for `git diff` in D39, is an owner question and
not built.

## D41. The Bash tool's own environment, the pager of gh reads, the reasons for fetch and worktree add (Nachtrag 16, 2026-10-16)

Measured by Cowork at 82255a7c under Claude Code, after Nachtrag 17 (pilot count 71 gate lines, 19 asks, 0 denies):
with GIT_OPTIONAL_LOCKS=0 in the environment, five forms asked with "an environment setting the check does not know":
`git log -3 --oneline`, `git -C <abs> diff --no-ext-diff --no-textconv --stat`, `git -C <abs> add`,
`git -C <abs> commit -F <file>` and `git -C <abs> worktree add …`.

Part 1, GIT_OPTIONAL_LOCKS=0 (owner choice of Nachtrag 16):
- The read profile (D34), K-NW-2 B (D3, D40 part 1) and the checkout check (D40 part 3) accept GIT_OPTIONAL_LOCKS in the
  hook's environment with the value `0` (_TOOL_INERT_ENV, _tool_inert). Any other value, `1` and the empty value among
  them, and every GIT_* name the lists do not name keep the form not free, as before.
- Evidence that it starts no program: git reads it as a boolean, and with 0 git leaves out the optional work that takes
  a lock, the index refresh of `git status`. Measured with git 2.43.0 (measure/optional_locks_starts.py of Nachtrag 16):
  with a proxy for every hook, fsmonitor, a clean and a smudge filter an attribute assigns, diff.external and core.pager,
  the five forms started the same programs with it unset, 0 and 1; `git status` with 0 started one fewer (no
  post-index-change: the index is not written).
- A prefix assignment of the command (`GIT_OPTIONAL_LOCKS=0 git log`) keeps its answer: the prefix rules of _assign_class
  are unchanged. Whether the value 0 counts as neutral there is an owner question and not built.
- What else the Bash tool sets, read in the binary of Claude Code 2.1.301 and in a session's shell of 2026-10-16: the
  environment the host process carries, then SHELL, GIT_EDITOR=true, CLAUDECODE=1, CLAUDE_CODE_SESSION_ID,
  CLAUDE_CODE_CHILD_SESSION, CLAUDE_CODE_SESSION_ATTENDED, CLAUDE_PID, AI_AGENT, CLAUDE_EFFORT and, with tracing on,
  TRACEPARENT. A hook gets the same names but SHELL and GIT_EDITOR, and CLAUDE_PROJECT_DIR besides. None is added:
  GIT_EDITOR is on both lists already (the forms start no editor: D3, D34), and the other names are neither GIT_* nor
  PAGER, so no check reads them and none hinders a form today.
- In 2.1.301 the binary names GIT_OPTIONAL_LOCKS only for Claude Code's own git calls (one with 0, a `git status` with
  1), and the session's shell did not carry it. D35 recorded GIT_OPTIONAL_LOCKS=0 in the Bash tool's shell in a session
  of 2026-10-14 (_HOST_SHELL_INERT), and Cowork measured it on its host. Where it comes from there is NOT MEASURED; the
  rule judges the name and the value, wherever they come from.

Part 2, the pager of gh reads (class b; owner choice of Nachtrag 16: measure both ways under Claude Code 2.1.301 and
take the one shown):
- Measured with the Claude Code binary 2.1.301, run with no network in a namespace of its own against a stand-in for
  the Messages API and the stand-in for github.com of D36, fake keys only (host/host_cases.py of Nachtrag 16).
- Way (a), GH_PAGER=cat through updatedInput: Claude Code ran the command a PreToolUse hook gave back, from the user's
  settings and from a plugin, with permissionDecision allow and with none, in the print and the interactive form. But
  with a permission rule `Bash(gh pr view:*)` the rewritten `GH_PAGER=cat gh pr view …` ran only when the hook also said
  allow; with no decision Claude Code asked for approval, as it does for that command typed with the prefix. Way (a)
  frees the form only by making the gate approve a call, which it does nowhere else. The binary also names sessions in
  which a hook from the user's own files may not change a call ("a restricted session: CLAUDE_CODE_RESTRICTED", "a
  session that restricts your own Claude Code files: CLAUDE_CODE_RESTRICT_PERSONAL_CONFIG"), and there the call is not
  made; CLAUDE_CODE_RESTRICT_PERSONAL_CONFIG=1 as an environment name alone did not bring that about (measured), how
  such a session starts is NOT MEASURED. Not built.
- Way (b), no terminal: in the print and the interactive form, and for a command run in the background, the command
  got a pipe on standard output, no terminal on standard input and error, and no controlling terminal (`/dev/tty` could
  not be opened). gh 2.89.0 started no pager there with PAGER, GH_PAGER or a pager in its configuration; on a terminal
  of script(1) it started each, and with GH_FORCE_TTY too. A hook got AI_AGENT=claude-code_2-1-301_harness, the command
  claude-code_2-1-301_agent. Built.
- The rule: under Claude Code, when the hook's AI_AGENT names a host in _NO_TERMINAL_HOSTS (only
  claude-code_2-1-301_harness), a pager PAGER, GH_PAGER or gh's configuration (config.yml, a host block) names does not
  count for a class b read form (_no_terminal_host, _gh_profile_problem); the pass names the pager and the host. This
  is the bound host adapter owner answer 3 asks for: the gate relies on the pipe only for a host measured to give one.
- Not changed: GH_FORCE_TTY (gh then pages as on a terminal), every other finding of the gh profile (another host, an
  Enterprise token, a unix socket, an unknown GH_* name or key, the gh version), Codex (the reviewer's text stays as
  today), and every form that is not a class b read form whose standard output is the tool's or a pipe: a redirection,
  an `exec` step before it, a group or subshell with a redirection, a prefix assignment, and a program that opens a
  terminal of its own (script, unbuffer, ssh -t, tmux, python's pty) keep today's ask (measured on the gate).
- Limits, in plain words: AI_AGENT names a version, not an origin (D27); a host that sets the name falsely is not caught.
  The rule holds for 2.1.301 only; a new version keeps the ask until it is measured and added. Class a (D34) counts
  GIT_PAGER, PAGER and the pager keys for the same reason; that sibling is not built here and is an owner question.

Part 3, the reasons of fetch, ls-remote and worktree add (owner choice of Nachtrag 16):
- `git ls-remote`, `git fetch` and every `git worktree add` but the one form D40 frees asked with the text for unresolved
  push forms ("the commits and refs this command might send … not one strict push form"). They stay asks, denied under
  Codex; the answer now names the reason the form has.
- ls-remote and fetch (_REMOTE_READS, reason id `remote_read_not_modeled`): the form reaches a remote and may start a
  credential helper, a transport helper, core.sshCommand or GIT_SSH, a proxy command, the upload-pack the remote's
  configuration names, and for fetch fsmonitor and the reference-transaction hook where a ref changes; it sends no
  commits. Measured with git 2.43.0 from a remote given as a local path (measure/fetch_starts.sh of Nachtrag 16):
  ls-remote started the configured upload-pack; fetch started it, fsmonitor and, where a ref changed,
  reference-transaction. The network ways are named after git's documentation and D40, not measured (no network).
  Since D45 one fetch form from github.com is free under Claude Code after a fetch profile, measured against a
  stand-in; where that profile finds something, the fetch keeps this reason id and the reason names the finding.
- worktree add (reason id `checkout_not_modeled`): the checkout may start the hooks post-checkout, post-index-change and
  reference-transaction, a smudge or process filter an attribute assigns, and fsmonitor (measured in D40); the gate
  checks them only for the one form of D40, as the whole command under Claude Code. Under Claude Code the next step
  names that form; under Codex, where it is not free either, it names a person's review.
- Under Claude Code, fetch and ls-remote get the same text as the first step of a chain (corpus B211: `git fetch origin
  && git log …`). Not changed: after another step, and under Codex in any chain, their repository is not resolved, and
  worktree add is free only as the whole command (D40), so these keep `directory_unresolved`, which was never the push
  text. send-pack, a per-command alias, pull, clone and remote update keep the push text; pull, clone and remote update
  read a remote too, and whether they get the same text is an owner question.
- Owner choice of 2026-10-16 (Ergänzung 1 to Nachtrag 18): the binding holds for the series 2.1.x, as Claude Code
  updates itself on delta's machine (2.1.299 and 2.1.301 ran there between 2026-10-14 and 2026-10-16). _NO_TERMINAL_HOSTS
  is a pattern: AI_AGENT exactly `claude-code_2-1-<ASCII digits>_harness`, nothing before or after it. Only under Claude
  Code, never under Codex; `_agent` for `_harness`, another series (2.2.x, 3.x), a space or line end around the value,
  a prefix, a suffix, a letter or a digit that is no ASCII digit keep the ask. Measured is 2.1.301 only (by the cloud
  session, D41 and D42). Condition of the choice: delta probes on each run of its plugin balance, on the real host,
  whether a command of the Bash tool has a terminal, and reports a card at once if one does; the binding is then taken
  back.

## D42. git's pager under a host whose Bash tool gives no terminal: class a (Nachtrag 18, 2026-10-16)

Measured by Cowork at ba65da56 in delta's environment (GIT_OPTIONAL_LOCKS=0, GIT_EDITOR=true, the hook's AI_AGENT
claude-code_2-1-301_harness) with PAGER=less, which stands in the environment of delta's Bash tool and Claude Code
process: `git log -3 --oneline` and `git -C <abs> diff --no-ext-diff --no-textconv --stat` asked with "a pager: PAGER in
the hook's environment"; add, commit -F and worktree add were free. Owner answers to Nachtrag 16: O16-1 build this;
O16-2 a prefix assignment `GIT_OPTIONAL_LOCKS=0` keeps asking; O16-3 pull, clone and remote update keep the push text.

The rule (owner choice of Nachtrag 18): under Claude Code, when _no_terminal_host holds (the hook's AI_AGENT names a
host _NO_TERMINAL_HOSTS names, D41: claude-code_2-1-301_harness when this rule was built, the series 2.1.x
since Ergänzung 1), a pager does not count in the read profile of class
a (D34): PAGER and GIT_PAGER in the hook's environment, core.pager and pager.<command> in the configuration
(_read_profile_problem, _read_free_verdict). The pass names each pager and the host. Every other finding of the read
profile is read on and still counts.

Evidence per source, measured under Claude Code 2.1.301 with git 2.43.0, run with no network in a namespace of its own
against the stand-in for the Messages API of D41 (host/host_cases_n18.py of Nachtrag 18): for `git log -3 --oneline`,
`git show --stat HEAD`, `git diff --no-ext-diff --no-textconv --stat` and `git grep -n a`, each run once as the Bash
tool runs it and once on a terminal of script(1):
- PAGER naming a proxy: no start in any of the four tool runs; a start in each of the four terminal runs.
- GIT_PAGER naming a proxy: the same.
- core.pager naming a proxy: the same.
- pager.<command> naming a proxy (pager.log, pager.show, pager.diff, pager.grep): the same.
- pager.<command>=true, which selects git's default pager (`pager` on this build, as `git var GIT_PAGER` names it; less
  on others), with a fake of that name first on PATH: the same.
git starts its pager only when its standard output is a terminal; the Bash tool of the bound host gives a pipe (D41).

Not changed: Codex (class a stays off, the reviewer's text of D37); every other host and every other value of AI_AGENT,
the command's own `claude-code_2-1-301_agent` among them; a prefix assignment of a pager in the command (`PAGER=…`,
`GIT_PAGER=…`, judged by _resolve_single as before); an option that forces or sets a pager (`-p`, `--paginate`, `-c
core.pager=…`, `-c pager.<command>=…`); every form that may give git a terminal (script, unbuffer, python's pty, ssh -t,
tmux, `exec >` or a redirection onto /dev/pts, a group or subshell with a redirection), which is no class a read form or
a class c step that asks; and every other finding (an unknown key or GIT_* name, GIT_OPTIONAL_LOCKS other than 0, a
promisor remote, fsmonitor, a hook, a filter, a submodule).

Limits, in plain words: since Ergänzung 1 the binding holds for the series 2.1.x (D41, owner choice of 2026-10-16),
measured with 2.1.301 only; the condition is delta's probe for a terminal on each run of its plugin balance, and the
binding is taken back when it finds one. AI_AGENT names a version, not an origin (D27). git's pager selection was
measured with git 2.43.0 (delta: 2.51.1).

## D43. gh 2.92.0 in the gh profile, with a condition per deviation (Ergänzung 2 to Nachtrag 18, 2026-10-16)

At delta, gh 2.92.0 at /usr/bin/gh made every gh read ask with "the gh on PATH ... is version 2.92.0, whose read forms
the gate has not measured" (owner answer 5 of 2026-10-14: the rules are bound to checked versions). The order: measure
2.92.0 as 2.89.0 was measured for D36; if it behaves the same at every point it joins the checked versions; every
deviation is named and the form it touches keeps asking.

Measured: the release binary gh_2.92.0_linux_amd64.tar.gz of github.com/cli/cli, sha256
b57848131bdf0c229cd35e1f2a51aa718199858b2e728410b37e89a428943ec4 as the release's gh_2.92.0_checksums.txt names it, in
the three class b measurements of D36 (121, 31 and 6 cases: read forms with each listed option, browser, editor, pager
with and without a terminal, another host, Enterprise token, unix socket, tokens in the output, the writing and running
forms), each run with 2.89.0 and with 2.92.0 against the local stand-in for github.com in a network namespace of its
own. Equal for every case: the requests the stand-in saw (host, method, path, query, GraphQL operation, token), the
exit codes, the local files changed, the tokens in the output, and the markers of a pager, browser, editor, alias or
extension start; the differences outside the two deviations below were run-to-run noise of the harness (the order of
two requests, a random label colour, a start strace missed in one run; a second run of 2.89.0 shows the same kind).
The help of the sixteen read paths, their options included, is the same; `gh help environment` and `gh help config`
add only the telemetry settings.

Deviation 1, git in the extension folder: on every command, `--version` included, 2.92.0 starts
`git -C <folder> config remote.origin.url` for each gh-* folder of its extension folder, $XDG_DATA_HOME/gh/extensions
when XDG_DATA_HOME is set and not empty, else $HOME/.local/share/gh/extensions (a relative one is read from the
working directory). With no such folder, or with only files or other folders in it, it starts none; telemetry and the
notifier settings change nothing. 2.89.0 starts none. The rule: under 2.92.0 a read form is free only when that folder
is an absolute path and is missing or empty (_gh_extension_problem, _GH_GIT_IN_EXTENSIONS); any entry asks and is
named.

Deviation 2, telemetry: on by default (`telemetry` in config.yml, `enabled | disabled | log`, default enabled). Each
command, `--version` included, writes gh/device-id into gh's state folder ($XDG_STATE_HOME/gh, else
$HOME/.local/state/gh, relative to the working directory without HOME) once it is missing; for a sample of commands
it starts `gh send-telemetry`, which sends the command, its flags, the device id and the platform to GitHub. With
GH_TELEMETRY_SAMPLE_RATE=100 every `gh pr view` started it, and it connected to GH_TELEMETRY_ENDPOINT_URL; at the
default rate none of 158 + 120 runs did, so the default rate is low, not shown to be zero. Off, each measured with the
rate forced (no `gh send-telemetry`, no device id), in gh's documented order: GH_TELEMETRY false or 0 (it decides when
set: true over `telemetry: disabled` and over DO_NOT_TRACK=1 stayed on), else DO_NOT_TRACK true or 1, else
`telemetry: disabled`. `log` sends nothing but prints the event and writes the device id. The rule: under 2.92.0 a read
form is free only with telemetry off in that order (_gh_telemetry_off, _GH_TELEMETRY_ON_BY_DEFAULT); GH_TELEMETRY with
any other value asks for every version, and values gh read as off without documenting them (GH_TELEMETRY off, no or
empty; `telemetry: false` or `off`; DO_NOT_TRACK=TRUE) are not relied on. GH_TELEMETRY_SAMPLE_RATE and
GH_TELEMETRY_ENDPOINT_URL stay unknown names and ask.

gh 2.89.0 has no telemetry (no GH_TELEMETRY, DO_NOT_TRACK or send-telemetry in its binary; `telemetry:` in config.yml
changed none of its starts and writes, measured), so GH_TELEMETRY false or 0 and the key `telemetry` in config.yml no
longer ask there.

The gate's own `gh --version` now runs with GH_TELEMETRY=false and XDG_DATA_HOME=/dev/null. Measured with 2.92.0 and an
extension under HOME: without them it started git in that folder and wrote gh/device-id into the state folder under
HOME; with them it started nothing and wrote nothing; 2.89.0 printed the same line either way. Before this change, a
gate that met 2.92.0 wrote that device id into the user's home and, with an extension installed, started git there
(the farmer's home: not measured).

The pass for a read form under 2.92.0 names the version and how telemetry is off. Unchanged: every other version
(2.91.0, 2.92.1, 2.93.0 and the rest), the read forms and options of D36, every finding of the gh profile, and D41.

Limits, in plain words: at delta the reads stay asked until telemetry is off there (a setting of the user, not of the
gate) and no extension is installed; whether the sampled telemetry may stay on is the owner's question (O18-1 of the
report). The measurements ran on linux amd64 with git 2.43.0 and no network; the default sample rate and the endpoint
gh sends to by default were not observed.

## D44. The uploadpack keys of the serving side in the read profile: class a (Nachtrag 19, 2026-10-16)

Measured by delta at ba65da56: `git log -3 --oneline` in a repository whose .git/config carries
uploadpack.allowAnySHA1InWant asked with "a configuration key the read profile does not know to start no program". The
key acts only in upload-pack, the serving side of a fetch from this repository. Owner choice of 2026-10-16: measure each
key first; only a key shown to start no program and open no connection joins the read profile, by its own name, not by a
pattern; uploadpack.packObjectsHook and every key that names a program keep asking.

The rule: _READ_UPLOADPACK_KEYS names uploadpack.allowAnySHA1InWant, uploadpack.allowTipSHA1InWant,
uploadpack.allowReachableSHA1InWant, uploadpack.allowRefInWant and uploadpack.allowFilter, and _READ_INERT_KEYS takes
them in. The value is not judged: true, false, an invalid value and a key without a value were measured alike. Every
other finding of the read profile is read on and still counts.

Evidence, measured with git 2.43.0 under strace -f (execve, execveat, connect, socket), stdout a pipe, a fresh HOME, no
system configuration, in a network namespace of its own (truth_n19.py of Nachtrag 19):
- The 23 spellings of the read forms of the grammar (log, show, diff, grep and status first, two or three spellings
  each; then rev-list, ls-files, rev-parse, for-each-ref, branch --list, ls-tree, show-ref, merge-base, describe,
  worktree list and cat-file), each with one of the five keys set true, false, `bogus` or without a value, and with
  `[uploadPack] allowAnySHA1InWant = true`: 483 runs, no program started, no connection or socket opened, exit code and
  length of the output equal to the run without the key.
- The same with uploadpack.packObjectsHook naming a program, uploadpack.keepAlive and uploadpack.hideRefs: nothing
  started. packObjectsHook keeps asking all the same: it names a program, and upload-pack reads it from the global
  configuration (measured: a fetch from the repository started the hook with it in the global file, not with it in the
  repository's own).
- Positive controls of the harness: diff.external started its program for the three diff runs, core.fsmonitor for
  diff, grep, status and ls-files, and `git ls-remote http://127.0.0.1:9/x` showed git-remote-http and its connect.
- Counter-check (gegenprobe_n19.py): a fetch from the repository over file:// started git-upload-pack; with each key
  set `bogus` it ended with "bad boolean config value" for that key and exit 128, with true and false it ended 0.

Not changed: uploadpack.packObjectsHook; every other uploadpack.* and uploadpackfilter.* key and every name that is
none of the five (uploadpack.allowAnySHA1InWants, uploadpack.allowSHA1InWant, uploadpack.<sub>.allowAnySHA1InWant,
receivepack.allowAnySHA1InWant); a key the command sets (`git -c …`, a prefix assignment of GIT_CONFIG_PARAMETERS);
Codex (class a stays off, D37); and the state check of add, commit -m and worktree add (K-NW-2 B, D3, D40), which keeps
its own list and still asks for these keys (measured with the same keys under strace: add, commit -m and worktree add
start the same programs with and without them; whether they join that list is the owner's question O19-1).

Limits, in plain words: measured with git 2.43.0 (delta: 2.51.1); a later git that gives one of these keys a meaning
outside upload-pack is not measured. Measured with an empty global and no system configuration. What a key changes in a
fetch was not shown, only that upload-pack reads it: a fetch over file:// of a commit no ref names, by its id, ended 0
with allowAnySHA1InWant true and with false alike.

## D45. git fetch from github.com after a fetch profile (Ergänzung 1 to Nachtrag 19, part B, 2026-10-16)

Owner choice of 2026-10-16, 11:5x Berlin. Until now every fetch asked (D41). Free now, under Claude Code and never under
Codex: `git -C <literal absolute path> fetch` with at most -q/--quiet, --prune and --no-tags, then a remote name and
branch names without `:` (_fetch_form, _fetch_branch: no `+`, `^`, glob, `..`, `@{`, part starting with `.`, `.lock`,
`refs/` or the word `tag`), as the whole command or as a step of class c, when the fetch profile of its repository
(_fetch_profile_problem) finds nothing. As a step it stands on its own wherever it stands only where its own answer is
free; a fetch of the form the profile does not free stays a gated step, as every fetch was (D33), and asks with the
reason id and text of D41 and what the profile found. Every other form keeps the ask of D41: no or another `-C`, any
other global or fetch option, an option after the remote, `--`, a URL or path as the remote, a refspec, a word the shell
may rewrite, a prefix assignment the profile does not accept, a redirection.

Ground truth, measured with git 2.43.0 under strace -f (execve, connect) with no network, in a network and mount
namespace of its own whose /etc/hosts names github.com, against a local stand-in for github.com serving the
repositories with `git http-backend` over TLS, a second host and a CONNECT proxy (truth_fetch_e1.py, 68 cases; each
source set alone in a fresh copy of a clone under an absolute path, stdout a pipe or a terminal of script(1)):
- The form from https://github.com/<owner>/<repo> (with and without `.git`, each option, on a terminal too) started
  git-remote-https, unpack-objects, rev-list and `maintenance run --auto`, all git's own, and connected only to
  github.com:443 (and tried nscd's socket); with gc due (gc.auto=1 and two loose objects in objects/17) `gc --auto`
  with repack, pack-objects, prune, pack-refs, reflog expire, worktree prune and rerere gc; maintenance.auto=false
  started none of them. It wrote FETCH_HEAD, objects, the tracking refs and their reflogs, tags, packed-refs, and with
  gc packs, gc.log and info/refs.
- Started a program or reached another host, each kept asking: a reference-transaction hook (twice per fetch, eight
  times with gc), pre-auto-gc with gc due, core.fsmonitor, remote.<name>.vcs (git-remote-<vcs>), url.*.insteadOf (the
  other host served the fetch), http.proxy, HTTPS_PROXY, https_proxy and ALL_PROXY (the proxy got CONNECT
  github.com:443), a submodule with the default recursion (a fetch of the submodule from its own URL; with
  fetch.recurseSubmodules=false none).
- On a 401 of the stand-in: `credential.helper=store` started git credential-store (get, then store after the
  success); `cache` started git credential-cache and left git credential-cache--daemon running after the fetch returned
  (measured without strace: still running 3 s later), so it is not on the list; `!<program>` and a name on PATH
  (git-credential-<name>) started that program; `!gh auth git-credential` with gh 2.89.0 started gh twice, which
  connected nowhere; GIT_ASKPASS, SSH_ASKPASS and core.askPass started their program; without any of them the fetch
  failed without a start. On a public repository no helper and no askpass started.
- Started nothing for an https fetch: the 26 other hooks githooks(5) documents, all present, with gc due and with
  --prune; a clean, smudge and process filter an attribute assigns; core.sshCommand, GIT_SSH, GIT_SSH_COMMAND;
  remote.<name>.uploadpack; PAGER, GIT_PAGER and core.pager, on a terminal too; GIT_OPTIONAL_LOCKS=0; fetch.prune; a
  shallow clone (its shallow file was not written).
- A redirect of the server to another host was followed (http.followRedirects=initial); with
  http.followRedirects=false the fetch failed. A remapped fetch rule writes another branch into the tracking ref.
- delta's chain with origin on the stand-in, run whole: git's own programs, tail, ls and grep, and github.com:443 only.

The profile, not free (each with a test that asks, and the finding named in the reason):
- the target: remote.<name>.url other than exactly one https://github.com/<owner>/<repo>[.git], a fetch rule other
  than exactly +refs/heads/*:refs/remotes/<name>/*, any other key of that remote (uploadpack, vcs, proxy, pushurl, …;
  another remote's url, pushurl, fetch and push are not read), any url.* and http.* key, a proxy name;
- programs: a hook the fetch or its maintenance runs (reference-transaction, pre-auto-gc, and every hook of another
  name; the 26 others do not count, the pre-push hook of Level 2 among them), fsmonitor that git does not read as
  false, core.sshCommand, core.askPass, GIT_SSH, GIT_SSH_COMMAND, GIT_ASKPASS, SSH_ASKPASS (owner choice: they ask,
  though an https fetch started none of the ssh ones), a promisor key, a pager as in class a (D34; not under the bound
  host of D42);
- a credential helper other than the empty value, `store` and `!<gh> auth git-credential` naming the gh on PATH while
  the gh profile of D36 and D43 is free for it (_fetch_gh_helper; since D54 only in its two literal forms); any other
  credential.* key;
- a submodule (a .gitmodules, a gitlink in the index, a git directory under modules/) unless fetch.recurseSubmodules
  reads false; fetch.recurseSubmodules with another value, submodule.recurse;
- any key or GIT_* name the profile does not know (GIT_SSL_*, GIT_HTTP_*, GIT_TRACE*, GIT_EXEC_PATH among them; the
  keys the read profile knows, fetch.prune and filter drivers are known; GIT_OPTIONAL_LOCKS=0 of the Bash tool is inert,
  D41).

The state a free fetch changes (point 4 of the order). It writes the tracking refs, FETCH_HEAD, objects and
packed-refs, and its maintenance packs, gc.log and info/refs. The push check reads the tracking ref as what the remote
is known to hold (D20, the commits a push newly sends), and the destination check reads every present ref and the
records beside them, FETCH_HEAD among them (D35): both bases change. The done check reads HEAD's first-parent history,
the declaration and the working state, which a fetch does not write. Where the basis changes, the ask stays for the
following step: within one command a push or a gated gh call after the fetch is a gated step that is not the first step
and keeps the answer of the whole command (class c, D33); a later push of its own is judged against the tracking refs as
github.com gave them under the one fetch rule the profile requires, which maps each branch to its own tracking ref.
No later step's own answer reads what a fetch writes (the read, state, gh and fetch profiles read the configuration, the
hooks, the environment, the index's gitlinks and the attributes), so a free fetch is no state change for the steps
after it (_sh_changes_state); a step before a fetch that may change what its profile read keeps it asking
(step_after_state_change), a write of .gitmodules and a `git add` among them. Under Codex the fetch stays a gated step.

Limits, in plain words: measured with git 2.43.0 (delta: 2.51.1) and gh 2.89.0 against a stand-in, not against
github.com; whether github.com answers a fetch with a redirect, and to where, is not measured; the gh helper under gh
2.92.0 rests on D43's measurement of that version, not on a run of `gh auth git-credential` with it. SSL_CERT_FILE,
CURL_CA_BUNDLE and other names libcurl reads for its trust are not read. A fetch over ssh, from another host or with
another remote form keeps the ask. The program PATH selects is not read (D27), as for class a.

## D46. The reason of a longer command names the step that asks (Ergänzung 1 to Nachtrag 19, part A, 2026-10-16)

Measured by Cowork at 1db350a1 in delta's environment, a clone under an absolute path with origin on a local
repository: delta's chain of 09:53Z (`git -C <abs> status --porcelain --branch; … rev-parse HEAD; … log -1 --format=%B
<sha> | tail -3; … fetch -q origin main; … rev-parse origin/main; … merge-base --is-ancestor <sha> HEAD; echo …; ls
<abs>/.git/hooks/ | grep -v sample`) asked; each step alone was free but the fetch (remote_read_not_modeled), and the
chain without the fetch was free. The reason named status, rev-parse and log, each with "Evidence: none, the gate reads
no repository state for a git form", first, and the fetch only later and with "the gate cannot tell which repository
git fetch acts on"; the owner read from it that `git -C` itself asked. Reproduced at 1db350a1: the fetch is a gated step
(not on _GIT_LOCAL_SUBCOMMANDS), and a gated step that is not the first step makes class c keep the answer of the whole
command, which gives every git step of a longer command the not-free answer of D3.

The rule, under Claude Code: only the text of the reason changes; the decision and the verdicts with their reason ids
stay as they were.
- A longer command class c judges step by step (_sh_steps_reason): where a git or gh step has the decision on its own,
  the text names that step first with its reason ids and its own text, then in one sentence which git and gh steps
  would be free on their own, then the steps that have the decision on their own too, then every other text of the
  decision. Where no step has it on its own (a step after a state change, a write), the text says that the reason
  belongs to the command, not to one step; where a step's directory is unknown after a `cd`, it says that.
- A longer command class c keeps whole (_sh_keep_reason): first why. A form of the command (one the parser does not
  model, a carrier of code, an expansion) belongs to no step, and the text says so before the whole command's texts.
  A gated step that is not the first step is named with its own answer (a push or a gated gh call is not judged on its
  own there; its texts are the whole command's, the safe push form of D32 among them), then which other steps would be
  free on their own and which ask on their own too, then the whole command's texts that name a finding; the answer
  every other git step of a longer command gets there names no finding for that step and is left out. delta's chain
  with origin on a local path is such a command: its fetch is not free (D45) and is named first.
- Every reason keeps the house prefix and its evidence, failure and next step (D19).
Under Codex the texts stay as they were (D37 fixes them word for word). A single command keeps its text.

## D47. The uploadpack keys of D44 in the state check of add, commit and worktree add (Nachtrag 20, 2026-10-16)

D44 freed the five uploadpack keys for the read forms of class a and left the state check of K-NW-2 B (D3) and of the
checkout of worktree add (D40) as it was; there the keys still asked, and in the corpus with the keys in every
.git/config 6 rows asked only for them (O19-1 of Nachtrag 19). Owner choice of 2026-10-16, 18:3x Berlin: yes.

The rule: _STATE_INERT_KEYS takes in _READ_UPLOADPACK_KEYS, the same five names, by name. The value is not judged.
Under Codex the same state check runs, so the keys are inert there too. Every other finding of the state check is read
on and still counts.

Evidence, measured in Nachtrag 19 with git 2.43.0 under strace -f, stdout a pipe, a fresh HOME, no system
configuration, no network (truth_n19_state.py, truth_n19_state.jsonl, 45 runs plus three without a key): `git add`,
`git commit -m` and `git worktree add -q` with each of the five keys set true, false or `bogus` started the same programs
as without the key and opened no connection.

Not changed: uploadpack.packObjectsHook and every neighbouring name keep asking, as in D44.

## D48. git's pager does not count for the fetch form of D45, under any host (Nachtrag 20, 2026-10-16)

D45 judged a pager as class a does (D34, D42): it did not count only under a bound host whose Bash tool gives the
command no terminal, and asked everywhere else. The measurement of D45 had shown more than that rule used: git fetch
started no pager with PAGER, GIT_PAGER or core.pager set, also on a terminal of script(1) (O19-2 of Nachtrag 19). Owner
choice of 2026-10-16, 18:3x Berlin: yes, for the fetch form of D45 under every host.

The rule: for the fetch form of D45, core.pager (any scope) and PAGER and GIT_PAGER in the hook's environment are noted
in the pass text and do not count. Only what was measured: a pager.<command> key of git and the pager of gh in the gh
helper's gh profile (D43) keep the rule of D42, since the measurement did not cover them. Every read form of class a
keeps D34 and D42, a fetch under Codex keeps its ask (D41), and a prefix assignment of PAGER is not the form.

## D49. No reason names a value from the configuration, the environment or a file (Nachtrag 20, 2026-10-16)

Found by Cowork reading a8ca017a: the fetch profile gave the URL of the remote and the value of a credential helper
word for word in its reason. A URL can carry a user and a token, and a reason is text the session reads.

The rule: a reason names the key, its scope and its file, never the value. For a URL it says at most which form the
profile asks for and did not find. A key whose subsection holds an @ (url.<base>.insteadOf, credential.<url>.*,
http.<url>.*, includeIf.hasconfig:…) is named by its section and variable, without the subsection (_shown_key). Words
of the command itself stay. A value the gate names only after it matched a closed form of its own (AI_AGENT of the
bound host, GH_TELEMETRY false or 0, DO_NOT_TRACK true or 1, push.recurseSubmodules on-demand or only) stays (O20-1);
numbers the gate checks as counts stay.

The class was searched over every f-string of the gate at a8ca017a (1265 interpolations); the list of what changed and
what stays, with lines, is in the report of Nachtrag 20 (klassenliste_teil3.md). Changed: the state check, the read
profile and the fetch profile (keys with a user), the filter an attribute names, the credential helper, the URL and the
fetch rules of the fetch profile and its pass, the paths of the declaration, a push setting, the URL rewrites of a push,
the programs and URLs of the transport binding, the URLs and the exec path of the Level 2 hand-over, the value of an
include, the pytest arguments and PYTEST_ADDOPTS of a receipt, a count of a test report.

Sharpened by Nachtrag 21 (review Runde 24, R24-2, owner choice of 2026-10-16: the class, one marker test). Found by
the reviewer at 6459ff53: the fetch profile named the hook directory core.hooksPath resolves to, word for word. D49
kept the values out and let the paths resolved from them in. The rule now: no reason, long, short or in the log, names
a value from the configuration, the environment or a file, nor a path resolved from one. It names the key, the scope
and the file by its role:
- a configuration entry by its key and scope, and whether it stands in the scope's own file or in one an include
  brings in (_origin_namer), never the file's path, which HOME, XDG_CONFIG_HOME, GIT_CONFIG_GLOBAL, GIT_CONFIG_SYSTEM,
  GIT_DIR, a linked worktree's .git file or an include's value decides;
- a hook by its file name and the directory by its role, the repository's own or the one core.hooksPath names;
- gh's configuration file by the setting that places it (GH_CONFIG_DIR, XDG_CONFIG_HOME) or as ~/.config/gh, the gh
  on PATH as such, the extension folder by its setting or as ~/.local/share/gh/extensions;
- git's own error text is not quoted: it names the file and the value it refused; the reason gives the exit status;
- a local done order by the first twelve characters of its file name, never the root, git directory or base it
  records; `done-order --list` names them to a person;
- the closed forms O20-1 let stand (AI_AGENT of the bound host, GH_TELEMETRY, DO_NOT_TRACK) are named, not their
  values.
Words of the command and fixed built-in default paths stay. The list of what changed and what stays, with lines, is
in the report of Nachtrag 21 (klassenliste_teil2.md); its last table names what the class holds outside the profiles
and was left as it is: the paths in the gate directory, the values of the declaration in the done check, the
repository field of a local order's log line (D21). tests/test_plugin_n21_marker_in_no_reason.py puts one marker into
every value a profile reads, under Claude Code, under Codex and through the hook with its log, and finds it in no
text.

## D50. extensions.worktreeConfig in the read profile, the state check and the fetch profile (Ergänzung 1 to Nachtrag 20, 2026-10-16)

Measured by delta at a8ca017a: `git log` in 2bedone asked for extensions.worktreeconfig in the local configuration.
Owner order of 2026-10-16, 18:4x Berlin: the key joins the lists only if it starts nothing itself and every key of
config.worktree is still judged.

Evidence, git 2.43.0 under strace -f, no network, a fresh HOME, no system configuration (truth_n20_local.py,
truth_n20_fetch.py): with the key true or false, under core.repositoryformatversion 0 and 1, ten read forms, `git add`,
`git commit -m` and `git worktree add -q` started the programs they start without it and opened no connection; the
fetch of D45 started git-remote-https alone and reached github.com alone. An invalid value ended every form with exit
128 before it started anything. With the key true, config.worktree took effect in the main and in a linked worktree
(core.fsmonitor and diff.external started), and `git config --list --show-scope --show-origin`, the listing every check
reads (_config_entries), named those keys with the scope worktree; with the key absent, config.worktree did nothing.

The rule: extensions.worktreeconfig joins _STATE_INERT_KEYS, and with it the read profile (D34) and the fetch profile
(D45), which take that list in. Every key of config.worktree stays in the listing and is judged like any other.

## D51. url.<base>.insteadOf counts for the fetch of D45 only where it acts on it (Ergänzung 1 to Nachtrag 20, 2026-10-16)

D45 let any url.* key ask, because an insteadOf took a fetch to another host (measured). delta measured at a8ca017a that
every fetch in 2bedone asked for url.https://github.com/.insteadof in the global configuration. Owner order of
2026-10-16, 18:4x Berlin.

Evidence, at the stand-in for github.com, git 2.43.0 under strace -f, no network (truth_n20_fetch.py): git puts the
base in place of the longest insteadOf value that is a prefix of the URL. An entry whose value is no prefix of
https://github.com/o/r (git@github.com:, ssh://git@github.com/, both on one base, delta's form in the global file) left
the fetch as it was: the same programs, connection, requests and written refs. A matching prefix took the fetch to
another host or to another repository on github.com; an empty base and a base without a scheme made the URL a local path
that git served with upload-pack through a shell; pushInsteadOf on a matching prefix left the fetch as it was.

The rule, in the fetch profile: url.<base>.pushInsteadOf does not count; url.<base>.insteadOf counts when its value is a
prefix of the remote's URL (an entry without a value and an empty value included), or when its base is empty or has no
scheme; every other url.* key asks. The profile reads the values and names none of them (D49). Under Codex the fetch
keeps its ask (D41).

## D52. remote.<name>.pushurl and remote.<name>.push do not count for the fetch of D45 (Ergänzung 2 to Nachtrag 20, 2026-10-16)

Cowork held delta's key list (names only) against the lists of a8ca017a: the clone pr31_strict_decoding carries
remote.origin.pushurl, and the fetch profile asked for every key of the remote but url and fetch.

Evidence, at the stand-in for github.com, git 2.43.0 under strace -f, no network (truth_n20_fetch.py): a fetch with a
pushurl on another host, with a push rule, with both and with a pushurl that names a user started the same programs,
opened the same connection, made the same requests and wrote the same refs as without them.

The rule: the fetch profile does not count remote.<remote>.pushurl and remote.<remote>.push. Every other key of the
remote asks as in D45. A push later in the same command stays a gated step that is not the first and keeps the answer
of the whole command (D33, D45); a push on its own is judged by the push check, which reads its own destination.

## D53. Silent on a pass, one short line otherwise, in the language a person sets (Ergänzung 3 to Nachtrag 20, 2026-10-16)

Measured by Cowork on delta's screen (Claude Code 2.1.301, 19:51 Berlin): every free command carried a grey block of
some 700 characters, `PreToolUse:Bash says: proofbundle gate: git diff is free. The read profile …`. answer() gave every
pass and every inactive gate its reason as systemMessage (the user) and as additionalContext (the model). Owner choice of
2026-10-16, 20:2x Berlin: a free command shows nothing; an ask or a block shows one short line with the step that asks
(D46), the reason in everyday words and the D number.

The rule:
- A pass prints nothing: no systemMessage, no additionalContext, no permission decision (D4); the hook ends with 0.
  One pass stays visible: a call a human rule frees (D25). Review Runde 15, F15-2, made every such call name the mode
  and the rules and when each last changed, because a shell command can change them unseen, and the owner's rule there
  was that making it visible is enough. It shows one short line, `Gate frees <step> by a rule a person wrote, mode and
  rules as of <time> (D25).`, and the model gets the long reason with the files and their digests, still without a
  permission decision. Whether such a call should be silent too is the owner's question O20-3.
  The Stop hook is silent on a passed end without a finding. The log line of every call stays what it was (D21): the
  verdict, the reason ids, the repositories with HEAD and digests. The log never held the text of a reason, and it
  does not now; a text can quote words of the command, which D21 keeps out of the log.
- An inactive gate (D5) shows its line once per session and repository: the first inactive answer of a session for a
  repository creates an empty file in `inactive-shown/` of the plugin data directory (O_EXCL), and later inactive
  answers of that session for that repository print nothing. Without a session id or a writable data directory every
  inactive answer shows, as before. A SessionStart hook cannot know which repositories a session will touch, so the
  line comes at the first command there, not at the start of the session.
- Every other answer shows the user one line of at most 160 characters: `Gate asks at <step> because <reason> (D<n>).`,
  `Gate blocks …`, `Gate warns at …`, `Gate hands <step> over to the pre-push check (D35).`, `Gate is not active here
  because …`, and at the Stop hook `Gate holds the end because …`. In German: `Tor fragt bei <Schritt>, weil <Grund>
  (D<n>).`, `Tor sperrt …`, `Tor warnt bei …`, `Tor übergibt <Schritt> an die Prüfung beim Push (D35).`, `Tor ist hier
  nicht aktiv, weil …`, `Tor hält das Ende auf, weil …`; real umlauts, no dash and no colon between clauses, no path.
  The step is `git <subcommand>` or the gh call of the step that has the decision (D46), `MCP <tool>`, or the file
  tool; the reason and the D number come from the reason id (_SHORT_REASONS); for the profiles of class a and b and
  the fetch of D45 the D number is the last one the long reason names.
- The long reason goes to the model as before: additionalContext always, permissionDecisionReason of a deny under
  Claude Code. The dialog of an ask shows permissionDecisionReason to the user, so under Claude Code it carries the
  short line. Codex has no dialog (D12): its deny carries the short line in permissionDecisionReason, and for an ask
  turned into a deny the line ends with `Codex cannot ask, so the gate blocks the call.` The long reason keeps the
  sentence `Codex cannot ask, so the gate denies the call.` (D37).
- The language is a file `language` in the gate directory, beside `mode`, read like it: `de` gives German, anything
  else, an absent file or an unreadable one gives English, the default of the public repository. The model cannot set
  it: decide_write denies every write to the gate directory (D25). The owner sets it for delta and echo, in their gate
  directory, not in the code.
- What the silence costs (Nachtrag 21, part 4; review Runde 24, question 3). A free call shows no explanation at the
  call any more: neither the person nor the model learns there why the gate let it through. The log keeps the verdict
  and the reason ids of the call, with the repositories, HEAD and digests (D21), not the long reason: what a profile
  read and found is not kept, and a later reading of the log says that a call was free and by which reason id, not what
  the profile saw (owner question O20-2). The silence removes no duty to approve: a pass carries no permission decision
  (D4), so the host's normal permission flow decides the call as it would without the gate, and the gate answered allow
  before D53 no more than after it. Visibility was never a power to decide.

## D54. The gh helper of D45 only in its two literal forms (Nachtrag 21, review Runde 24, R24-1, 2026-10-16)

Found by the reviewer of round 24 at 6459ff53: the fetch profile split credential.helper with shlex and checked the
words, but git hands the value after the `!` to a shell. `!"<tmp>/`touch review24_marker`/gh" auth git-credential`
was one absolute word ending in /gh for shlex, and the gh on PATH when its folder bears that very name, so the fetch was
free; the shell ran `touch` first. Owner choice of 2026-10-16: R24-1 after 6.3.1 and before Z405.

Evidence, git 2.43.0 and dash with a stand-in gh, `git credential fill` per form under strace -f, no network
(truth_n21_helper.py): a backtick and $(…) in a double-quoted path ran their command before gh; $HOME and ${HOME} there
put the hook's HOME in place, and a gh in that folder started instead of the one the profile checked; a line end after
git-credential made git's own `get` a second command of the shell; single quotes, a space or a line end in a quoted
path and a tab between the words started the stand-in gh alone. `!gh auth git-credential` and `!<abs>/gh auth
git-credential` started the stand-in gh with `auth git-credential get` and nothing else.

The rule: the gh helper is free only where the value, as git keeps it, is exactly `!gh auth git-credential` or
`!<abs> auth git-credential`: one space between the words, <abs> an absolute path of A-Z a-z 0-9 / . _ + - only that
ends in /gh, nothing before or after. No quote, $, backtick, backslash, space, tab or line end, no other shell
character. The check reads the text (_GH_HELPER_FORM), never the words of a split. Every other value asks with the
reason of an unknown helper, a form the shell reads literally included. Then, as before, the gh it names must be the gh
on PATH and the gh profile of D36 and D43 must be free for it.

## D55. A signed decision receipt for each GitHub write the gate decides, outside the decision (Z405, part 1, 2026-10-16)

Order CLOUD-KRAXO-Z405-EIGENER-PILOT-01, owner choice of 2026-10-16, 23:0x Berlin. The pilot contract on main
(docs/pilot/pilot_contract.md, pull request 305) wants a decision receipt of each write an agent session makes to GitHub,
issued by the outbound gate before the write, for an approval as for a refusal, and the pilot profile github-write/1
(docs/pilot/pilot_profile.md and tools/pilot/github_write_profile.py, pull request 303) fixes how it is written.

The rule:
- The pilot is on when a person wrote `pilot.json` into the gate directory, beside `mode` (D25), read like it, so the
  model does not write it. It names the profile (`github-write/1`), the names of the gate, the observer, the agent and
  the principal, the validity in seconds, the receipt folder, the signer, the gate's public key and the closing rules
  of the surfaces. Any other key, a missing one, a value outside its form or an unreadable file is no pilot, and the
  gate writes nothing. Without the file the gate does exactly what it did.
- After its verdict and before its answer the gate writes one decision-receipt/v0.1 per GitHub write the pilot reads, in
  the form of the profile: `decisionId` is `<action id>#<attempt>`, the action id a digest of the surface, the target,
  the bytes and the agent, the attempt the first number no receipt of that id holds; `validity.nonce` is the decisionId,
  the audience the observer, `decidedAt` the gate's clock with six fraction digits, `expiresAt` that plus the validity;
  the version signal `proofbundle-pilot/github-write` and revision `1`; the subject derived from the predicate; strict
  mode's fields present. The receipt is a DSSE envelope of the in-toto Statement in its RFC 8785 form.
- The verdict: pass is ALLOW, deny is DENY, ask is ESCALATE, an ask that the gate answers as a deny under Codex (D4) is
  DENY. inactive, handover and warn get no receipt: there the gate leaves the write to another check (D5, D35, D12), and
  Level 2 decides a push it hands over. Level 2 records its own verdict per ref line: pass is ALLOW, every other verdict
  but inactive DENY, as the hook's exit code is.
- What the pilot reads: a push at Level 2 from git's ref lines (the bytes are `<sha>` and a line feed of the commit it
  sends, the target `https://github.com/<owner>/<repo>#<ref>` when the push URL is a plain GitHub URL, nothing of a URL
  with a user, a password, a port or a query); a plain `git push` at Level 1, without target and bytes, since the gate
  does not resolve them there (D3); `gh pr comment`, `gh pr edit --body`, `gh pr merge` and `gh pr create` in their plain
  forms with literal words, a reply in a review thread through `gh api repos/<o>/<r>/pulls/<n>/comments/<id>/replies -f
  body=…`, and the gated MCP tools from their own arguments. A pull request is named `https://github.com/<o>/<r>/pull/<n>`
  on every surface, a new one `…/compare/<base>...<head>`. A merge writes no text of the agent; its bytes are empty. Any
  other form is not read: the gate decides it as before and writes no receipt, so an effect of it counts under M5 of
  the contract.
- The receipt carries no value of the configuration, the environment or a credential (the rule of D49): the names of
  the roles, digests, reason ids and a target in the one GitHub form. A refused action keeps only the digest of the
  proposed bytes (contract, section 8).
- The gate holds no key. It hands the DSSE pre-authentication bytes to the signer `pilot.json` names, which writes the
  64-byte Ed25519 signature in base64; the receipt names the key by its OpenSSH fingerprint. Whose key that is decides
  what a receipt proves: the gate runs as the agent session's user, so a key that user can reach can sign anything.
  The pilot's runbook (part 3 of Z405) puts the signer behind a boundary of the operator; here only the probe signer
  runs, with a key derived from a public label (plugins/proofbundle/pilot/probe_signer.py).
- A receipt changes nothing the gate answers: not the decision, not the exit code, not the log line (D21), not a byte
  on stdout or stderr. A receipt the gate cannot issue (the signer fails, the closing rules are unreadable, a byte
  outside ASCII) is a line in `journal.jsonl` of the receipt folder with a fixed name, never an answer.

## D56. The records of the pilot and an observer that signs what the GitHub API shows (Z405, part 2, 2026-10-16)

The contract keeps every input of the reconciliation beside the records before the first decision (section 8), and an
observer run by the operator signs an action-outcome/v0.1 for what GitHub shows of a decision (section 4).

The rule:
- The records are one folder, the receipt folder of D55. `pilot_records.py start` keeps in it, before the first
  decision and never after, the contract, the profile github-write/1 as its executable file, AGENTS.md, the closing
  rules the gate digests, the roster of agent identities (GitHub's numeric id, the login, the agent's name), the two
  public keys, the verifier's distribution file and its environment, and writes `pilot_start.json` with the sha256 of
  each. Every reader checks each kept file against its digest before it uses it; a changed file stops it.
- The observer reads `GET /repos/{owner}/{repo}/events`, 100 to a page, at most three pages, the 300 events GitHub lists.
  It keeps every response as returned, with the time it asked, its status and its sha256, under `api/<run>/`, beside the
  run's window. A run is kept as it was and never rewritten. One code path reads: a transport answers GET live against
  api.github.com or from recorded files; the live path runs first in the pilot at delta.
- An effect is an event of an agent identity of the roster inside the window: a push (`<head>` and a line feed on
  `https://github.com/<o>/<r>#<ref>`), a comment on a pull request's conversation, a reply in a review thread, a pull
  request opened (on `…/compare/<base>...<head>`) or its body edited, a merge (empty bytes, the merge commit as its
  object), and every other event under its own name, which matches no decision and counts under M5. A person's write is
  no agent write and is not read.
- The observer matches effects to decisions by the rule of the contract, section 5 (`pilot_records.match`), from the
  decisions whose signature verifies with the pinned gate key, and signs an outcome for each effect that takes a
  decision: decisionRef is the decision's content root, requestedActionDigest its parametersDigest, effectDigest the
  sha256 of the stored bytes, actualActionDigest the digest of the scope descriptor {surface, target, objectId} beside
  it, the nonce the decision's, the audience the observer. A decision that names no bytes gets no outcome; the run says
  so. The outcome is built and signed with the profile the records keep.
- The observer needs no credential an agent session holds: a public repository's events need none, and a token, if the
  operator gives one, is read from the operator's file, never from the environment. Its key is the operator's; the
  probe label derives a key from a public label for tests only.

## D57. The reconciliation of the pilot, from the records alone (Z405, part 3, 2026-10-16)

The contract joins decision and outcome per action and measures M1 to M8 (section 5), and a person who was not part of
the sessions reruns it from the records and from nothing else (criterion 4).

The rule:
- `reconcile.py` reads the records folder of D56 and nothing else: the decisions, the responses the observer kept, the
  outcomes, and the inputs `pilot_start.json` keeps, each checked against its digest. It recomputes the match of the
  contract, section 5, from the kept responses, an event listed by two runs counted once, so its classes come from the
  files and not from the observer's own match. The same records give the same bytes.
- A decision whose signature does not verify with the pinned gate key takes part in no match, and is named. An effect
  it would have taken counts under M5.
- Per decision: M1 arrived, not arrived, ambiguous, not yet observed (no run whose window holds its decidedAt), or
  unknown (no target the gate resolved); M2, M3 and M4 only for an approval that arrived, else `not measured`; M4 against
  the closing rules whose digest the decision names, the stored bytes ending with the rule's lines, a null rule
  requiring none; M7 the seconds from decidedAt to the first reading of the effect, recorded and never judged; M8 the
  decisions that share the action id. Over the window: M5 and M6 as counts, `not measured` without a run, never 0.
- The class names the mismatch: an approval arrived as approved, not arrived, before the approval (GitHub dates the
  effect before decidedAt), with other bytes, on another surface, without its closing lines; a refusal not arrived, or refused but arrived; an escalation arrived without an approval of
  the gate; an ambiguous effect; a receipt that does not verify; and where the observer's outcome and the records'
  match disagree (an outcome bound to a decision no effect of the records took, or an effect with no outcome bound),
  that class, whatever the profile answers.
- Beside the measures each decision carries the answer of the profile the records keep, for the decision and the
  outcome bound to it: accepted, not accepted or unknown, with the reasons.
- `plugins/proofbundle/pilot/RUNBOOK.md` names what the operator sets up at delta (the two keys, the signer behind an
  account of the operator, the roster, the closing rules, the records, pilot.json, Level 2), how the observer runs, and
  how someone else reruns the reconciliation; names and places, no values.

## D58. The signer of the pilot is a service that decides the call again and signs only its own verdict (Z405 signer service, 2026-10-17)

Order CLOUD-KRAXO-Z405-SIGNIERER-DIENST-01, owner choices O405-1 to O405-5 of 2026-10-17, 02:2x Berlin. D55 left open
whose signature a receipt carries: the gate runs as the agent session's user, and a signer that user can call signed
whatever bytes it was handed, so a receipt proved that the operator's signer signed, not that the gate decided.

The rule (O405-1):
- The service, `plugins/proofbundle/pilot/signer_service.py`, runs under an account of the operator, and only that
  account reads the private key. The agent's user reaches it only through one fixed program: a sudo rule on exactly
  that program as the signer account, or a socket of the signer account. `signer` in pilot.json names that program.
  It is in place before the pilot starts at delta.
- The gate hands it a request on stdin (PILOT_SIGN_REQUEST, `proofbundle/pilot-sign-request/v1`): at Level 1 the hook
  event as the host gave it and the host, the working directory being the event's; at Level 2 the repository, the
  remote, the URL, git's ref lines and the line the receipt is for; and the statement the gate proposes, in base64.
- The service checks its own copy of the gate file against the sha256 that pilot_start.json keeps under `files.gate`
  (`pilot_records.py start --gate`), loads that copy, and decides the call with it in its own environment (`environment`
  of its configuration and the gate directory it names), never with a value of the agent's session. Surface, target,
  bytes, verdict and reasons are its own: at Level 1 the gate's tool_outcome, at Level 2 pre_push_verdict.
- It builds the statement again from its own decision, the pilot's configuration in the gate directory and the
  decision's id and instant the proposal names, and signs the DSSE pre-authentication bytes only where the action id is
  the one of its own action, every byte equals the proposal, and decidedAt lies within `window_seconds` (1 to 300)
  before its clock and at most CLOCK_SKEW_SECONDS (2) after it.
- Otherwise it signs nothing, exits 3 (the gate's PILOT_SIGNER_REFUSES) with one fixed reason name on stdout, and
  writes a journal line. The names: request_malformed, statement_malformed, start_unread, gate_file_unread,
  gate_file_differs, pilot_config_unread, ids_differ, outside_window, workdir_unreadable, out_of_time,
  not_a_pilot_write, no_receipt_for_this_decision, action_differs, repository_not_safe, verdict_differs,
  reasons_differ, policy_differs, statement_differs, internal_error. The gate journals `signer_refused_<name>`, `signer_timeout` for a service it
  stopped after PILOT_SIGNER_SECONDS, and answers the call as before: a receipt never changes the answer (D55).
- What the service cannot see gives no signature with its reason, never a guessed one: a working directory its
  account does not read is workdir_unreadable; a repository git refuses for its account (owned by another account and
  not named as safe.directory in the service's git configuration), where the decision then came out otherwise, is
  repository_not_safe; a gate directory or pilot.json it does not read is pilot_config_unread; a value only in the
  agent's environment that changes the decision gives verdict_differs or reasons_differ, because the service decided
  without it.
- The gate file is one file: the service's copy and the agent's must be the same bytes. A gate changed on the agent's
  side names another policy digest (policy_differs) or another verdict (verdict_differs); the service's verdict is its
  own either way.
- Its journal line names the instant, whether it signed, the reason, the milliseconds, the level, the decisionId, the
  surface and the verdict: no path, no command, no value (the rule of D49).
- N405-a: the pilot reads the number of a pull request with its own rule, `_PILOT_GH_NUMBER`; `_GH_NUMBER` keeps
  `[0-9]+`, the rule of the read forms of class b (D36). No name is bound twice at module level of the plugin's code
  (tests/test_plugin_z405_module_names.py).
- The probe signer (`probe_signer.py`, a key derived from a public label) stays for tests only.

The remaining limit, said as it is: the service decides the state it sees when it runs, not the state the gate saw.
If the agent changes the working tree, the configuration or the evidence between the gate's verdict and the service's
decision, the service decides on the new state, and a receipt it signs then names its verdict on the new state. The
same holds for a call the agent makes to the service directly: it may hand over an event of its own making, and the
service signs it only where its own copy of the gate decides that event so; the receipt says no more than that.
Whether the host then runs exactly that call is what the observer measures (M2, M3, M5), not the receipt.

Time, N405-b, as a calculation:
- Level 1: hooks.json gives each PreToolUse hook 120 s. main sets the gate's deadline, DEADLINE_SECONDS = 90 s, before
  it reads the event, and each git, gh or uv step gets at most the time left, so the decision ends within 90 s of that
  point. A Level 1 call is at most one GitHub write the pilot reads, so one receipt and one call of the service, which
  the gate stops after PILOT_SIGNER_SECONDS = 10 s. 90 s + 10 s = 100 s < 120 s: 20 s remain for the interpreter's
  start before the deadline is set, pilot.json, the closing rules, the receipt, the journal and the answer. The
  service decides within its own deadline of PILOT_SIGNER_SECONDS - MARGIN_SECONDS = 9 s; a decision that takes
  longer is refused as out_of_time, never signed late.
- Level 2: git runs the pre-push hook without a timeout. A push of n ref lines is decided within 90 s, then each line
  is one call of the service of at most 10 s, which decides the whole push again: at most 90 s + n x 10 s, and no host
  limit. A push the service decides in more than 9 s gets no receipt.
- The measured times per surface (median and maximum of the service's elapsedMs) stand in the delivery's report, not
  here.

The other owner choices of 2026-10-17, 02:2x Berlin:
- O405-2: criterion 1 of the contract counts only for git.push in the first pilot; the other four surfaces are
  covered by M5 and M6.
- O405-3: the pilot's verifier is a published proofbundle whose decision verifier takes `now=`, 6.3.1 or later; until
  one is published, the wheel built from main's src.
- O405-4: the contract and the profile in the records are byte-identical copies of main, without pilot_profile.md.
- O405-5: the pilot repositories declare a check and have Level 2 (install-pre-push, D24B).

## D59. git ls-remote from github.com after the fetch profile of D45 (Nachtrag 22, part 3, 2026-10-17)

Every ls-remote asked (_REMOTE_READS, D41), also where the fetch of D45 is free; delta stopped at it on 2026-10-17 at
09:09Z. Owner choice of 2026-10-17, 11:1x Berlin: the gate frees ls-remote in the form and with the profile of the fetch
of D45, in round 26 with the quick round. D55 to D58 are the numbers of Z405 and its signer service, which came over
this quick round with part 4 of the addendum (Nachtrag 24) and stand before D59.

Free now, under Claude Code and never under Codex: `git -C <literal absolute path> ls-remote [-q|--quiet]
[--heads|--branches] [--tags] [--refs] <remote> [<pattern>…]` as the whole command, when the fetch profile of D45
(_fetch_profile_problem) finds nothing for that remote in the repository the -C path names. The grammar of _fetch_form
(_ls_remote_form): the options first and each without a value, then a remote name (no URL, no path), every word
literal, no `$`, no word the shell may rewrite, no `--`; a pattern (_ls_remote_pattern) may start with `refs/` and
carries no `:`, `+`, `^`, `@`, `..`, glob, space or backslash. Every other option (--upload-pack, -o, --server-option,
--get-url, --symref, --sort, --exit-code, …), an option after the remote, a URL or path as the remote, a prefix
assignment the fetch profile does not accept, a redirection, another global option or `-C`, and every longer command
that holds the form keep the answer of D41 (an ls-remote step stays a gated step, as in D33). A finding of the profile
asks with the reason id and text of D41, what the profile found and "so this ls-remote is not the one D59 frees"; the
short line of D53 names ls-remote, no longer a fetch: "this ls-remote is not the form the gate frees", with D59 for a
finding of the profile and D41 for every other ask.

Ground truth, measured with git 2.43.0 under strace -f (execve, connect) with no network, in a network and mount
namespace of its own whose /etc/hosts names github.com, against the stand-in of D45 for github.com, a second host and a
CONNECT proxy (truth_ls_remote_n22.py, 58 cases; each source set alone in a fresh copy of a clone under an absolute path,
stdout a pipe or a terminal of script(1)), the fetch profile asked for each case in the same repository and
environment:
- The form from https://github.com/<owner>/<repo> (with and without `.git`, each option, patterns, on a terminal, from a
  shallow clone) started git-remote-https only and connected only to github.com:443 (and tried nscd's socket). It wrote
  nothing under .git in any of the 58 cases, so no reference-transaction hook, gc or maintenance ran. git 2.43.0 does
  not know --branches: exit 129, nothing started.
- Started a program or reached another host, and the profile found each: pager.ls-remote on a terminal (its pager),
  remote.<name>.vcs (git-remote-<vcs>), url.*.insteadOf (the other host served it), http.proxy, HTTPS_PROXY,
  https_proxy and ALL_PROXY (the proxy got CONNECT), on a 401 `!<program>`, a name on PATH, GIT_ASKPASS, SSH_ASKPASS
  and core.askPass (their program), and a remote word with no remote of that name (git read it as the path of a local
  repository and started upload-pack through a shell). On a 401 credential.helper=store started git credential-store
  and the gh helper started gh, both admitted by the profile as for the fetch (D45, D54); credential.helper=cache
  started git credential-cache, which the profile asks for as for the fetch (D45: its daemon outlives the call).
- Started nothing for an https ls-remote, while the profile asks for it: all 28 hooks githooks(5) documents, also
  through core.hooksPath and with gc due; core.fsmonitor; core.sshCommand, GIT_SSH, GIT_SSH_COMMAND, core.askPass and
  GIT_ASKPASS on a public repository; remote.<name>.uploadpack; a remapped fetch rule; a submodule with the default
  recursion and with submodule.recurse; a shallow clone's single-branch rule. A clean, smudge and process filter an
  attribute assigns started nothing and does not count, as for the fetch.
- Pagers: PAGER, GIT_PAGER and core.pager started nothing, on a terminal too, and do not count for this form (as D48
  for the fetch); pager.ls-remote counts unless the host's Bash tool gives the command no terminal (D42).
- Not covered: a redirect of github.com itself to another host was followed (http.followRedirects=initial), with
  nothing in the configuration or the environment the profile could find; as for the fetch (O19-4), it is github.com's
  answer, not a setting of the session.

Tests: tests/test_plugin_n22_ls_remote_d59.py (the form and each option free, each excluded option and word asking
with D41, the whole command only, Codex with D41, each finding of the profile asking with what it found, the short
line in English and German).

## D60. The shell's test command `[` is no glob for the safety net (Nachtrag 23, part 1, 2026-10-17)

Counted at delta (gate log 09:33Z, balance 07:32Z; 183 asks in 1457 gate lines since 2026-10-15): `until [ -s <file> ];
do sleep 3; done` asked with D27, and so did `while [ … ]` and `if [ … ]`, with no git or gh word in them, while
`test -s <file>`, a for loop and `head` stayed silent. The net (D27, review Runde 14, R14-1) asks where an active
expansion stands in the program position, as it could name git; it read the word `[` as a pathname glob. bash opens a
bracket expression only where a `]` follows in the same word, and matches a `[` without one literally: `[` is the
shell's test command and `[[` its keyword. Owner choice of 2026-10-17, 12:3x and 13:0x Berlin.

The rule (_unquoted_active_expansion): a `[` is an active glob only where a `]` follows it in the word, a quoted `]`
included (that only asks more often); `*`, `?` and a brace group with `,` or `..` stay active as before. So a bracket
test without git or gh is silent, `[[ … ]]` too (its words stay data after the keyword; a glob among them still asks,
as `[[` leaves the program position unproven). Unchanged: a bracket test with git or gh in it or beside it asks
(`[ -n "$(git status)" ]`, `if [ … ]; then git push …; fi`, `[ -x git ]`), and so does a glob in the program word
(`g[i]t status`).

Found beside it and not changed here: a parameter expansion as the program word (`$CMD status`, `CMD=git; $CMD push
origin main`) is silent at 9f578c2a and before; a bracket test before it had made such a command ask only by the
reading of `[` this decision corrects. Named as an owner question in the delivery.

Tests: tests/test_plugin_n23_bracket_test_d60.py.

## D61. A push that creates a branch in a repository of b7n0de, against the remote's refs the gate measures (Ergänzung 1 to Nachtrag 23, 2026-10-17)

Measured on delta's screen on 2026-10-17 at 13:45Z and 13:54Z: `git -C <abs> push origin <sha>:refs/heads/<new>` and
`git -C <abs> push origin HEAD:refs/heads/fix/<new>`, the push form the gate itself names (D32), asked with D3. Since
R9-1 Level 1 resolves no push, because git resolves the destination against refs of the remote the gate did not read,
and a branch the remote does not have is never resolved (TARGET_ABSENT_TEXT). Every new pull request starts with such
a push. Owner words of 15:45 and 15:54 Berlin; owner choice of 15:5x Berlin: this part first and alone. D60 is the
number of part 1 of Nachtrag 23, the shell's test command `[`.

Resolved now, under Claude Code and never under Codex: `git -C <literal absolute path> push <remote>
<source>:refs/heads/<name>` as the whole command (_new_branch_push_form): every word literal as written, no option,
one refspec without `+`, the source HEAD, a branch of the repository or a literal full object name, the name read like
a branch of D45 (_fetch_branch) and not main, release, release/… or HEAD. In order (_new_branch_push):
- a remote the configuration names, with no push list, mirror setting, push.followTags, pushurl or URL rewrite, and a
  push configuration git reads (as resolve_push_targets: _push_config_problem, _push_adds_unnamed_refs,
  _endpoint_consistent);
- the fetch profile of D45 finds nothing for the remote, so the gate's own ls-remote is the form D59 measured, and the
  URL is https://github.com/b7n0de/<repo>[.git] (NEW_BRANCH_OWNER);
- the source names one commit as git push reads it (_push_source); a source that is not HEAD or a full object name must
  be a branch of the repository;
- the gate measures the remote's branches and tags with its own `git -C <repo> ls-remote --heads --tags <remote>`, in
  the hook's environment with GIT_TERMINAL_PROMPT=0, at most 20 s (_measured_remote_refs); the destination is not
  among them;
- the commits the push sends are those the source reaches and no measured branch or tag reaches:
  `rev-list <source> --not <every measured object that is a commit in the repository>`, from a full clone, at most 64
  (_new_branch_range), and at least one commit on the remote they start from (rev-list --boundary).
Then the checks of a push to an existing branch (_evaluate_targets), unchanged: the evidence at every sent commit and at
the source, where a missing or failing piece denies (D26); the done check at the source (owner choice N2 C); an ask at
a sent commit asks; the evidence rules at every sent commit equal to those at the commits on the remote it starts
from, else rules_changed asks; starting commits whose rules differ keep the ask of D3. A pass is verified_new_branch,
silent as every pass (D53); a push whose commits declare nothing is inactive as before.

Why the measured refs and not `rev-list <source> --not --remotes=<remote>`, the expression of the order: a tracking ref
can name a commit the remote no longer holds. GitHub deletes the branch of a merged pull request, and without `fetch
--prune` its tracking ref stays; `--remotes` leaves its commits out, while git push sends them unchecked. With the
measured refs they are checked (tests/test_plugin_n23_push_new_branch_d61.py: a stale tracking ref's commit with
evidence that does not verify denies). Where the tracking refs equal the remote's branches, both expressions give the
same commits. A measured tip the clone does not hold is not subtracted, as git push does not subtract it either. Only
branches and tags are subtracted: refs/pull/* is left out, so the gate checks more commits, never fewer.

Keeps the answer of D3, which then names why D61 did not apply: main, a release branch, a tag, a force (`+`, --force,
--force-with-lease), more than one refspec, any option, a destination that is not written in full, a URL or path as
the remote, a remote outside b7n0de, a finding of the fetch profile, a remote whose refs the gate cannot measure (no
answer in time, an exit status other than 0; git's own text is not quoted, D49), a destination the remote already has,
a shallow clone, more than 64 commits, a history that shares no commit with the remote's branches and tags, every
longer command (a chain, a pipeline, a redirection, a prefix assignment) and every push under Codex.

Not changed: Level 2. The pre-push hook still answers target_ref_absent for a branch the remote does not have; where it
is installed, a push D61 resolves at Level 1 still stops there. The remote can change between the gate's measurement
and the push; a branch or tag deleted in that window makes git send commits the gate did not check, at most those that
branch or tag alone held.

## D62. A read of core.hooksPath turns no hook off and is not denied (Nachtrag 23, part 2, 2026-10-17)

Counted at delta: `git config --get core.hooksPath`, a pure read, was denied with hooks_disabled since 2026-10-16
17:42Z, a false alarm. Since Punkt 5 every `git config` whose words named core.hooksPath was denied, because setting it
redirects or turns off the pre-push hook. Owner choice of 2026-10-17, 12:3x and 13:0x Berlin.

The rule (_config_reads_only): a `git config` that only reads is no hook-disabling form. A read is: every option one of
the read actions `--get`, `--get-all`, `--get-regexp`, `-l`/`--list` or the switches of scope, origin, type and
separators (`--local`, `--global`, `--system`, `--worktree`, `--show-origin`, `--show-scope`, `-z`/`--null`,
`--name-only`, `--includes`, `--no-includes`, `--type=…` and the older type switches), at most one action; with
`--get`, `--get-all` or `--get-regexp` one name and at most one value pattern, with `--list` no word, with no action
the name alone, which git reads. Every word literal: no `$` and no word the shell may rewrite (`--g*` may become
`--global` or `--add`). Such a read is judged as any read form: for `git config`, which was no read form of class a,
that is the ask of D3 (git_form_not_free), under Claude Code and under Codex; since D68 the four reads of class a there
are free under Claude Code after the read profile. Keep the deny: a value after the name,
`--unset`, `--unset-all`, `--add`, `--replace-all`, every option the gate does not read as a read (`--file`, `--blob`,
`--default`, `--edit` when it names core.hooksPath, …), two actions, a rewritten word, and a `-c core.hooksPath=…` or
`--config-env` override before any subcommand.

Tests: tests/test_plugin_n23_hookspath_read_d62.py.

Corrected in Nachtrag 28 (O27-2, owner choice of 2026-10-18, 09:2x Berlin, as recommended): git 2.43.0 reads every word
after the first non-option of `git config` as a name or a value, whatever it looks like. Measured in a fresh repository:
`git config core.hooksPath --show-origin`, `--null`, `-z` and `--get` after the name each set core.hooksPath to that
word; D62 read them as a read with a switch, so the gate asked with D3 under Claude Code instead of denying with D24.
Now _config_reads_only reads a switch only before the first name, as _config_read_form of D68 does: these four forms,
and every other value after the name, deny with D24 (hooks_disabled) under both hosts. A word after the name of a
read with an action is its value pattern, as git reads it (`git config --get core.hooksPath --null` stays a read and is
not denied). Tests: tests/test_plugin_n28_hookspath_position_d62.py.

## D63. The class of R25-1 at four more sites: a reason names the key, never the value read (Nachtrag 23, part 3, 2026-10-17)

The class search of R25-1 (review Runde 25: a reason gives a value the gate read, also as a fixed text) found four more
sites at 9f578c2a, each measured, owner questions O22-2 to O22-5 of the report of R25-1. Owner choice of 2026-10-17,
12:3x and 13:0x Berlin: each as recommended, each with a marker case. The verdicts do not change.
- O22-2, the push check (_push_config_problem): `The configuration contains submodule.recurse=true; submodule push
  behavior is NOT MEASURED.` is now `The configuration sets submodule.recurse; submodule push behavior is NOT
  MEASURED.` For the review round: the old text is the wording owner choice B: A of 2026-10-10 took from review round 8
  (R8-5) word for word; this decision replaces that wording, and its tests
  (test_plugin_review_fix8_r5_recursion_reason.py, test_plugin_review_fix9_r3_unresolved_answer.py) now hold the new
  one.
- O22-3, the same check: `The configuration contains push.recurseSubmodules=<value>; …`, the value read after it
  matched on-demand or only, is now `The configuration sets push.recurseSubmodules to a value that recurses; submodule
  push behavior is NOT MEASURED.` D49 of Nachtrag 20 had let this value stand (O20-1); its sharpening by Nachtrag 21
  names AI_AGENT, GH_TELEMETRY and DO_NOT_TRACK only, and this key now joins them as named, not valued.
- O22-4, the gh profile (_gh_extension_problem): the first entry of gh's extension folder was named by its name, read
  from the folder; now `an entry in <the folder by the setting that places it>`.
- O22-5, the gh profile (_gh_config_problem): an unknown key, a pager or a unix socket of hosts.yml was named by its
  key path, whose first part is a host and, under users, whose third part is a user, both read from the file; now they
  stand as `<host>` and `<user>` (_gh_keys_shown). A key of config.yml stays named, as D49 names keys.
Tests: tests/test_plugin_n23_class_r25_1_d63.py, one marker case per site, under Claude Code and Codex where both
answer.

## D64. Deciding and signing under two accounts: the account that decides holds no key (Z405, owner choice O405S-6, 2026-10-17)

Owner choice O405S-6 of 2026-10-17 (Nachtrag 24, part 4 of Nachtrag 22), owner question of the delivery of the signer
service: the service of D58 ran the gate's decision code, git and the verifier on repositories the agent writes, in
the account that read the gate key. The read hardening of the gate (no fsmonitor, no hook, no pager, the D series) was
then the only wall between a configuration the agent planted in such a repository and the key.

The rule:
- `plugins/proofbundle/pilot/signer_service.py` decides as D58 says, under an account of the operator that holds no
  key, the deciding account. Its configuration is `proofbundle/pilot-signer-config/v2`: `key_signer`, a program by its
  absolute path and its arguments, takes the place of `key_file`; a configuration of v1 is no configuration of the
  service, and it has no `--public` any more.
- Where D58 signed, the service hands the key signer a request on stdin (KEY_SIGN_REQUEST,
  `proofbundle/pilot-key-request/v1`): the canonical statement it decided, in base64, and nothing else; from the root
  folder, with PATH set to os.defpath and LANG to C, no value of its own environment. It passes the answer on only
  where it is a signature that verifies over the DSSE pre-authentication bytes with the gate's public key of
  pilot.json.
- `plugins/proofbundle/pilot/key_signer.py` runs under a second account, the key account, and only that account reads
  the key. It imports nothing that starts a process and runs neither git nor any code of the gate: it reads its
  configuration (`proofbundle/pilot-key-config/v1`: key_file, journal, gate_id, window_seconds), its key and the
  request, and writes its journal; nothing of a repository.
- It signs where the request holds exactly the schema and the statement; the statement is ASCII, at most 64 KiB, JSON
  without a repeated key and in the canonical form the gate writes, byte for byte; it is an in-toto Statement v1 of
  decision-receipt/v0.1 with exactly the fields the gate writes; its one subject is `decision:<decisionId>` with the
  sha256 of the canonical predicate; its decision's maker is the gate_id of its configuration; and decidedAt lies
  within `window_seconds` before its clock and at most CLOCK_SKEW_SECONDS (2) after it.
- Otherwise it signs nothing, exits 3 with one fixed name on stdout and writes a journal line. The key signer's names:
  request_malformed, statement_malformed, statement_not_canonical, statement_type, subject_differs, gate_differs,
  outside_window, internal_error. The service passes such a refusal on as `key_<name>`; its own names for what the key
  signer gave it: key_signer_timeout, key_signer_failed, key_signer_answer, key_differs. The gate journals
  `signer_refused_<name>` as D58 says.
- The key signer's journal line names the instant, whether it signed, the reason, the milliseconds, the decisionId and
  the sha256 of the statement: no path, no value. Each signature the key makes is one line there, out of reach of the
  deciding account.
- The crossings are fixed programs: the agent's user reaches the deciding account only through the service's command
  (D58); the deciding account reaches the key account only through the key signer's command. The agent's user has no
  way onto the key account.

What it closes, and what not, said as it is:
- A configuration the agent plants in a repository reaches at most the deciding account. That account can be made to
  run a program; it does not read the key, and the key account runs no program a repository names.
- Whoever holds the deciding account still gets signatures for statements of the gate within the window, whatever
  verdict they name: the key signer checks the form, the gate and the time, not the verdict; judging the verdict is the
  deciding account's (D58). Such a signature is one line of the key signer's journal, and a line without a receipt in
  the records shows it. The remaining limit of D58 holds unchanged.

Time: the decision ends by PILOT_SIGNER_SECONDS - MARGIN_SECONDS = 9 s after the service started (D58); the key
signer's answer by PILOT_SIGNER_SECONDS - KEY_MARGIN_SECONDS = 9.5 s, which leaves the key signer at least 0.5 s and
0.5 s for the journal line and the answer. A key signer that does not answer by then is stopped (key_signer_timeout).
The gate's PILOT_SIGNER_SECONDS and the calculation N405-b of D58 are unchanged.

The gate is unchanged: the request it hands the service and the answer it reads are those of D58, and the gate file
the records keep is the same bytes.
Tests: tests/test_plugin_z405_key_signer.py; tests/test_plugin_z405_signer_service.py with the service and its key
signer.

The other owner choices on the service, of 2026-10-17 (Nachtrag 24), each as recommended; the runbook says how:
- O405S-1: the crossings are sudo rules onto exactly one command each; a socket is not used in the first pilot.
- O405S-2: `window_seconds` is 10 for the service and for the key signer, equal to PILOT_SIGNER_SECONDS.
- O405S-3: at Level 2 the service decides the push once per ref line, one call and one receipt each.
- O405S-4: the probe signer stays only as a test of the reconciliation (the counter-probe of the surface, M3), never
  signed by the service and never a record of the pilot.
- O405S-5: `safe.directory` in the deciding account's git configuration is the list of the pilot repositories, never
  `*`.

## D65. No signature without a durable journal line, and the key signer's journal in the reconciliation (Nachtrag 25, 2026-10-17)

Nachtrag 25 (CLOUD-KRAXO-FIX18-TEIL-B-NACHTRAG-25): finding T4-a of the re-measurement of the delivery of Teil 4, read
and not tried there, and owner choice of 2026-10-17, 22:3x Berlin on O24-1: both now, before the pilot starts at delta.

T4-a, the rule:
- Before: the key signer signed, then wrote its journal line, and passed over a journal it could not write
  (`except OSError: pass`). On a full disk or with its rights taken away there was a signature without a line, while
  D64 rests on every signature being one line of that journal.
- Now the line that names a signature (decisionId, the sha256 of the statement, the instant) is appended and synced to
  the disk (fsync, and for a file it created, its folder as well) before a byte of the signature is written on stdout.
  A journal the key signer cannot write gives no signature: it exits 3 with one name. The key signer's name for a
  journal it cannot write: journal_unwritable.
- After the signature is out, a second line names the decisionId and the sha256 with `handedOut` true or false: a
  signature stdout did not take is recognizable by `"handedOut": false`. A signed line without its second line is
  unconfirmed and counts as handed out.
- A line an earlier write left without its end is closed first, so it stands alone and the next line reads.
- The service keeps the same rule for its own journal: its line is synced before its signature is written, a journal
  it cannot write gives no signature, and a second line names `handedOut`. The service's name for a journal it cannot
  write: journal_unwritable. The key signer's journal_unwritable reaches the gate as key_journal_unwritable (D64's
  `key_<name>`), and the gate journals `signer_refused_<name>` as D58 says.
- A refusal is journaled as before, as far as the journal takes it; a journal that cannot take a refusal leaves it a
  refusal.
- The gate is unchanged.
Tests: tests/test_plugin_z405_journal_first.py; the journal helpers of tests/test_plugin_z405_signer_service.py and
tests/test_plugin_z405_key_signer.py read the decision lines and the `handedOut` lines apart.

O24-1, the rule (the key signer's journal in the records and in the reconciliation):
- At the end of each window, before the reconciliation, the key account exports its journal into keysigner/ of the
  records: `key_signer.py --config <key configuration> --export <records>/keysigner` writes journal.jsonl and
  export.json (`proofbundle/pilot-key-journal-export/v1`: the file, its sha256, its lines, the instant), each written
  whole: a new file beside it, synced, renamed over it, the folder synced.
- The way the agent's account cannot write: the key signer exports only into a folder it owns that no other account
  may write, whose parent belongs to root or to the key account and is writable by no one else, or carries the sticky
  bit, which keeps others from renaming or removing what is not theirs. The export's name for any other folder:
  export_folder_unsafe. The records folder therefore belongs to the operator, the agent's user and the observer write
  in it through a group, and its sticky bit keeps keysigner/ in place; the operator makes keysigner/ for the key
  account before the first decision.
- reconcile.py reads the journal only where it is the bytes export.json names by their sha256 and matches its lines to
  the receipts in decisions/ by the sha256 of the statement each receipt carries. It names two counts of its own:
  signed lines without a receipt (a signed line marked `"handedOut": false` never left the key signer and is counted
  apart; one without its second line counts) and receipts without a signed line. Either count not 0 ends it with
  KEY_JOURNAL_DISAGREES (3); a journal that is not in the records, or not the bytes of its export, ends it with
  KEY_JOURNAL_NOT_READ (4). It writes reconciliation.json either way, `keyJournal` with the counts, the lines and
  receipts they name, and the number of lines that do not read.
- Records the probe signer signed keep no such export; their reconciliation ends with KEY_JOURNAL_NOT_READ.
- The comparison by hand of D64 stays as the way back.
Tests: tests/test_plugin_z405_key_journal_reconcile.py; tests/test_plugin_z405_reconcile.py reads the exit code of
records without an export.

## D66. A command whose every program only reads calls no done-order: D38 does not ask for it (Nachtrag 26, 2026-10-17)

Measured at delta on 2026-10-17, 20:54Z (gate at 9f578c2a), and again at 3694e34e: a find over a session folder under
~/.claude-*/projects, `xargs grep -l "proofbundle_gate.py"` and a while loop that counts with
`grep -c proofbundle_gate.py "$f"` asked with D38 ("the command changes a local done order"), under Codex it was denied.
The cause: _done_order_run reads every word named proofbundle_gate.py as the gate's script, wherever it stands in a run,
and in `grep -c proofbundle_gate.py "$f"` the word after it is one the shell builds, which D38 answers as a done-order
call it cannot read whole (owner choice O2 of Nachtrag 13). The path under ~/.claude-*/projects plays no part; the
pattern of `xargs grep -l` alone stayed silent there, because the redirection to /dev/null follows it.

The rule: a command that is wholly of the closed read forms of _read_only_form runs no done-order, whatever words it
names, and D38 does not ask for it:
- find without -delete, -exec, -execdir, -ok, -okdir, -fprint, -fprint0, -fprintf and -fls, every word literal;
- xargs that runs grep, with at most -0, --null, -r and --no-run-if-empty before it;
- grep, read and echo; the words while, do and done of a loop around them;
- a pipe or a list (`;`, a new line) between them; `&&`, `||`, `&`, a subshell, a process substitution and an input
  redirection are outside the set;
- an output redirection only to /dev/null, and a descriptor only onto 1 or 2;
- every program word a literal bare name, and every command substitution such a command in turn.
Every other command is read as before. The same command that writes a file (under ~/.claude-* or anywhere), removes,
moves, edits in place, tees, or runs a program through -exec or xargs that is not grep, asks with D38 as it did, and
under Codex is denied. Local writes the gate never asked for (`rm`, `xargs rm`, `find -delete` on their own) stay as
they were: nothing is freed. The other answers of the gate are untouched; a find whose grep pattern names git still asks
with D27.
Strict stays the default; no check of the evidence falls away.
Tests: tests/test_plugin_n26_read_only_d66.py.

## D67. A program word the same command line sets to git or gh is judged with its value (Nachtrag 27, O23-6, Teil a, 2026-10-18)

Measured at 9f578c2a, ab14e1ae and 76dc0cfc (the head of Nachtrag 26): `CMD=git; $CMD push origin main` and
`X=gh; ${X} pr merge 1` got no answer under either host; `export G=/usr/bin/git && "$G" push` asked only because the
word `G=/usr/bin/git` itself ends in git, with the answer of a git form (D3), never as the push it runs. Neither the
structured scan nor the safety net reads a parameter expansion at the program position as git or gh. Owner choice of
2026-10-18, 03:3x Berlin: build it now.

The rule (_program_values, applied in decide before every other reading): where a parameter expansion stands at the
program position of a simple command, spelled `$X`, `${X}`, `"$X"` or `"${X}"`, and the same command line sets X to a
value that names git or gh as a command, the gate judges the command with that value substituted, as if it were written
there. A value names git or gh as the safety net's command words do (_net_command_word): `git`, `gh` or
`git-<subcommand>`, by name or behind a path ending in /git, /gh or /git-<subcommand>. An unquoted expansion splits into
its fields first, as the shell does with the default IFS, so `G="git push"; $G origin main` is judged as `git push
origin main`. The line sets X with an assignment word before the program of a simple command, or with an assignment word
among the arguments of export, declare, typeset, local or readonly (behind `builtin` or `command` too); values are read
from the whole line, before the expansion or after it. The program position is the first word after the start, a
control operator, a new line, `(`, `)`, `{` or `}`, past the assignment words and the reserved words `!`, `if`, `then`,
`else`, `elif`, `while`, `until`, `do` and `time`; a command substitution is read in turn, with the values of the line
around it. The long reason then ends with a sentence that says so; the short line is the substituted command's.

What it does not change: an expansion whose value is not git or gh (`"$PYTHON" -m pytest`, `$EDITOR datei`,
`"$SHELL" -c true`, with or without an assignment in the line) keeps the answer it had, and so does every expansion the
line does not set (Teil b of Nachtrag 27, measured, not built), a value the shell builds (`G=$(command -v git)`), every
other spelling (`${G:-git}`, `${G[0]}`), and a program word behind a wrapper, `bash -c`, `eval` or `sudo`, which the safety
net already asks for (D33). The rule only ever shows the gate more git or gh, never less: no write becomes free, and a
command without such an expansion is judged byte for byte as before.
Strict stays the default; no check of the evidence falls away.
Tests: tests/test_plugin_n27_program_variable_d67.py.

## D68. The reads `git config --get`, `--get-all`, `--get-regexp` and `--list` are read forms of class a (Nachtrag 27, O23-7, 2026-10-18)

Owner choice O23-7 of Nachtrag 23, answered on 2026-10-18 at 03:3x Berlin as recommended, with D66: these reads are a
read form of class a (D34), but only after a measurement of what they start, as D59 measured ls-remote.

Measured with git 2.43.0 under strace -f (execve, execveat), with no network, in a fresh repository with a fresh HOME and
no system configuration (truth_config_n27.py of the delivery): fourteen forms, `--get`, `--get-all` and `--get-regexp`
(each with and without a value pattern), `--list`, `--list --show-origin`, `--list --null`, `--show-origin --get`,
`--null --get-all`, `--show-origin --null --get-regexp`, `--get` of core.hooksPath and `--get` with the two switches
after the name, each under 30 sources, standard output a pipe or the terminal of script(1), with `git log -1 --oneline`,
`git branch --list` and `git show --stat HEAD` as controls, 426 reads:
- With standard output a pipe no read started a program or wrote a file under .git or HOME, whatever was set: a pager
  (core.pager, pager.config, PAGER, GIT_PAGER, core.pager through GIT_CONFIG_PARAMETERS or an include), core.fsmonitor,
  every documented hook in .git/hooks and through core.hooksPath, core.editor and GIT_EDITOR, credential.helper,
  core.sshCommand, core.askPass, GIT_SSH_COMMAND, GIT_ASKPASS, gpg.program with a signing key, diff.external and a
  textconv driver, alias.config, core.alternateRefsCommand, uploadpack.packObjectsHook, a filter an attribute
  assigns, include.path and includeIf (gitdir, hasconfig), a promisor remote, a submodule.
- A trace target writes its file for every form: trace2.eventTarget and GIT_TRACE naming a file. The read profile does
  not know those names and keeps asking.
- On a terminal --get-all, --get-regexp and --list start the pager, git's default one where none is set, as the three
  controls do; --get starts none. A configured pager counts in the read profile as for every read form (D34; D42 for a
  host whose Bash tool gives no terminal).
- `git config --get user.name --show-origin --null` ends with a usage error (exit 129): git reads every word after the
  first non-option as a name or a value. So `git config user.name --get` sets user.name to `--get` (measured).

The rule (_config_read_form, one of the fixed forms of _read_form): exactly one of the actions `--get`, `--get-all`,
`--get-regexp` and `--list`, beside it only `--show-origin` and `--null`, every option before the first other word; with
`--get`, `--get-all` or `--get-regexp` one name and at most one value pattern, with `--list` no word; no word the shell
may rewrite, no `$`, and no word after the options that starts with `-`. Class a then frees it under Claude Code after
the read profile of its repository, with at most one literal `-C`, as the whole command or a step class c judges on its
own; under Codex class a stays off. Every write form keeps its answer: a value, `--add`, `--unset`, `--unset-all`,
`--replace-all`, `--rename-section`, `--remove-section`, `--edit` and `-e`; so do `-l`, `-z`, `--show-scope`,
`--name-only`, a type, `--includes`, the scope switches, `--file`, `--blob`, `--default`, `--get-urlmatch`,
`--get-color` and the subcommands of git 2.46 (`git config get`), which the order does not name. The deny of
core.hooksPath stays as D62 leaves it: setting, unsetting, adding and replacing it deny; a read of it is a read form here
like any key, and the reads D62 knows that are not of this form keep the ask of D3.
Strict stays the default; no check of the evidence falls away.
Tests: tests/test_plugin_n27_config_read_d68.py; the answers D68 changes on purpose in
tests/test_plugin_n23_hookspath_read_d62.py, tests/test_plugin_runde6_r62.py, tests/test_plugin_gate_runde6b.py and
tests/test_plugin_ask_load_a_read.py.

Added in Nachtrag 28 (O27-4, owner choice of 2026-10-18, 09:2x Berlin, as recommended): `-l` (the same action as
`--list`), and the switches `-z` (the same as `--null`), `--show-scope`, `--name-only`, `--local`, `--global`, `--system`
and `--worktree`. Measured the same way first (truth_config_n28.py of the delivery, sixteen forms by 30 sources, the
system configuration a file of the case's own): with standard output a pipe, 336 reads, none started a program or wrote a
file under .git or HOME, but the trace targets, which keep asking; on a terminal the list forms start the pager as
before, `--get` with a scope switch none. Every write form keeps its answer, with a scope switch or without
(`git config --local user.name x`, `git config --global --add a.b c`); a type, `--includes`, `--file`, `--blob` and
`--default` stay off the list. Tests: tests/test_plugin_n28_config_switches_d68.py; the answers this changes on purpose
in tests/test_plugin_n27_config_read_d68.py, tests/test_plugin_n23_hookspath_read_d62.py, tests/test_plugin_runde6_r62.py
and tests/test_plugin_ask_load_a_read.py.

## D69. A program word the line does not set asks before what Level 2 does not check (Nachtrag 28, O27-1 C, 2026-10-18)

Measured in Nachtrag 27, Teil b: a parameter expansion at the program position whose value the command line does not
set (`$GIT push origin main`, `"$GH" pr merge 1`) got no answer under either host. Level 2 catches such a push only where
its pre-push hook is installed; it was not installed at delta (measured by Cowork, 2026-10-18, O23-2), a hook switched
off (`--no-verify`, `-c core.hooksPath=…`) skips it (measured), and gh never runs it. At delta, 1 of 6047 simple
commands in two and a half days had a program as a variable, set to another program; 0 left it unset. Owner choice of
2026-10-18, 09:2x Berlin: option C.

The rule (_unknown_program_word, applied in decide after D67): where the program word of a simple command holds a
parameter expansion whose value the line does not set, and a later word of the same simple command is `push`,
`--no-verify`, a word that names core.hooksPath (any case), or two words in a row that name a gh pair that writes (the
pairs the gate gates, pr create, pr new, release create, release new, and pr merge), the gate asks under Claude Code and
denies under Codex, reason id program_word_unknown. A program word D67 reads is none of these: one of its four spellings
with a name the line sets, whatever the value. Every spelling counts otherwise: `$X`, `${X}`, `"$X"`, `${X:-git}`, `$1`,
`"$@"`, and a word with an expansion and literal text (`$HOME/bin/tool`). The program position is D67's, a command
substitution is read in turn. A command that asks or denies already keeps its answer.

What it does not change: every other such command keeps its answer, so `$GIT commit -am x`, `$GIT reset --hard HEAD~1`,
`"$PYTHON" -m pytest`, `$EDITOR datei`, `"$SHELL" -c true`, `$SUBCOMMAND --repo /work/clone` and `$CMD -c
proofbundle_gate.py …` stay without an answer. A word built by the shell is not read as `push` (`$GIT $SUB`).
Strict stays the default; no check of the evidence falls away.
Tests: tests/test_plugin_n28_unknown_program_d69.py.

## D70. A command wholly of the closed read forms of D66 names no program for D27 and D3 either (Nachtrag 28, O26-2, 2026-10-18)

Measured in Nachtrag 26: `find … | xargs grep -l "git push"` asked with D27, the safety net counting the word git in the
pattern as a command word, and `find … | xargs grep -l git` with D3, the scan reading the word git after xargs as the
program xargs starts; under Codex both were denied. At delta, 4 of the 19 asks of the last period were false alarms of
this kind, a git word standing only as text in an argument (Cowork, 2026-10-18). Owner choice O26-2 of Nachtrag 26, as
recommended (2026-10-18, 09:2x Berlin): measure first what xargs grep starts, then the same closed read form as D66.

Measured with strace -f (execve, execveat) in bash -c, as the Bash tool runs a command, with no network
(truth_xargs_grep_n28.py of the delivery): eleven forms (find into xargs grep with a pattern that names `git push`, git
and `gh pr create`, with -0, -r and --no-run-if-empty, grep -rn and grep -l alone, a while loop that counts with grep
-c, output to /dev/null, xargs with no input), each under four sources (none; a program named git and one named gh first
on PATH, each writing a marker when started; GREP_OPTIONS and GREP_COLORS; LC_ALL=C and POSIXLY_CORRECT), 44 runs: the
programs started besides bash were find, xargs and grep, and nothing else; no marker was written; no file in the work
folder or HOME changed.

The rule (_decide_outcome): a command that is wholly of the closed read forms of _read_only_form (D66) gets no answer:
find without an action that deletes, runs a program or writes a file; xargs that runs grep, with at most -0, --null, -r
and --no-run-if-empty; grep, read and echo; the words of a while loop around them; a pipe or a list; output only to
/dev/null or onto descriptor 1 or 2; every program word a literal bare name; every command substitution such a command
in turn. A word that names git or gh there is a pattern of grep or an argument of echo, never a program.
Every other command is read as before, and asks where it did: `xargs git push`, `xargs -I{} git push {}`, `find …
-exec git push \;`, grep with a command substitution in its pattern (`grep "$(git push)" a.md`), `xargs sh -c …`,
`xargs env git …`, the same search followed by `; git push`, and output into a file. Strict stays the default; no
check of the evidence falls away; no write becomes free (the closed set writes nothing).
Tests: tests/test_plugin_n28_read_only_search_d70.py.

## D71. The work profile of Claude Code: reads, local changes that can be taken back and `gh pr merge --auto` in a declared repository of b7n0de (Nachtrag 29, 2026-10-18)

Owner word of 2026-10-18, 10:26 Berlin: constant asks; at delta every `gh pr merge <n> -R b7n0de/proofbundle --auto
--merge` asked with D27, and the owner approved each. delta's balance from 2026-10-15 20:46Z to 2026-10-18 07:16Z: 282
entries, 177 as the rule says, 59 false alarms, 46 neutral, no catch. Owner choice of 2026-10-18, 10:3x Berlin, "Lokal
frei, gh pr merge --auto frei": in declared repositories of b7n0de reads and local changes are free, and so is
`gh pr merge --auto`, because GitHub merges only after the required checks; the asks stay for a push to a protected
branch, a merge without --auto, a tag, a release, force and every way of turning a hook off.

Where (_work_repo_problem): under Claude Code only, never under Codex; in a repository whose HEAD holds a declaration
the gate reads (parse_declaration, the evidence list may be empty) and whose every remote has, for fetch and for push,
every URL https://github.com/b7n0de/<repo>[.git] as git resolves it, url.<base>.insteadOf and pushInsteadOf applied
(`git remote get-url [--push] --all`, measured in Nachtrag 28, Teil B, O23-8: no program started, no ssh file read).
A remote over ssh, in scp form or with a host word of its own (delta's remotes at the time of this decision, O23-8),
another owner, a second remote of another owner and a repository that overlaps the gate directory keep D71 out.

What (_work_form): the whole command is one simple command of literal words, headed by a bare `git` with at most one
`-C` and a literal absolute path, or by a bare `gh`; no operator, redirection, prefix assignment, expansion or word the
shell may rewrite. The forms, each with the check of its class (_work_check_problem):
- reads, after the read profile of D34 (a pager under the host of D42 noted, not counted): `git tag` and `git tag
  -l|--list [<pattern>…]` with -i, --no-column and the ref-filter values --sort, --format, --contains, --no-contains,
  --merged, --no-merged and --points-at as `--opt=value`; `git stash list`; `git bundle verify <file>`. The reads class
  a frees already (diff, log, show, status, branch as a list, rev-parse, ls-files, cat-file, worktree list) keep the
  answer of D34; D71 adds nothing to them;
- fetch and ls-remote, after the fetch profile of D45 and D59: their forms without `-C`, in the session directory;
- local changes, after the state check of D40 with the hooks of D71 (_HOOKS_NOT_RUN_BY_WORK), the refs
  (_work_refs_problem) and, for the forms that write the work tree, the guard that no configuration file and no hook
  directory lies in the work tree (_work_tree_guard_problem): `git commit` with a message or with --amend and
  --no-edit, -a, -q, --allow-empty and -s; `git checkout <branch>`, `<full object name>`, `--detach <rev>`, `-b <new>
  [<start>]`; `git switch <branch>`, `--detach|-d <rev>`, `-c|--create <new> [<start>]`; `git branch <new>
  [<start>]`; `git stash`, `git stash push` with -m, -u, -k and -q; `git merge` with one revision and --no-edit,
  --ff-only or --squash (so no editor starts), and `git merge --abort`; `git rebase [--onto <rev>] <upstream>
  [<branch>]` and `git rebase --abort`; `git worktree add` of D40 without `-C`, after the checkout check of D40; `git
  bundle create <file> <revisions>` to a file that does not exist and that a file write may reach (decide_write). A
  branch must exist (for checkout also no path of its name in the work tree), a new name must be free, a start must
  be a commit and no remote-tracking branch (git would write the upstream into the configuration);
- gh, after the gh profile of D36 and, where the command names no repository, GH_REPO absent or of b7n0de: `gh pr
  merge <number> [-R b7n0de/<repo>] --auto` with exactly one of --merge, --squash and --rebase, `gh pr merge <number>
  [-R b7n0de/<repo>] --disable-auto`, and `gh pr edit <number> [-R b7n0de/<repo>]` with --title, --body, the label,
  reviewer and assignee options, --milestone or --remove-milestone. gh pr view, list, checks and diff keep class b
  (D36).
D71 turns only an ask into a pass, and only an ask whose every reason is one of _WORK_REPLACEABLE (the not-free and
not-modeled answers of D3, D27, D40 and D41); a deny, every other ask (a push the gate does not resolve, a finding of
a profile, a done order of D38 after it) and every answer under Codex stay. Where the repository is one of D71 and the
check of the form finds something, the ask stays and its text names what the check found.

Measured before the build (point 1 of the order; point1_forms_n29.py and point1_corpus_n29.py of the delivery): of
79 forms of delta's command heads and the counter cases, in a repository D71 is written for, 60 asked at c8e1e8d7, 18
were free already (diff, log, status, add, commit -m, the `-C` forms of fetch, ls-remote and worktree add, gh pr view,
gh api), 26 were forms of D71 that asked with a reason D71 replaces (git_form_not_free 11, net_unmodeled_git 6,
possible_unmodeled_push 5, remote_read_not_modeled 3, checkout_not_modeled 1), and none of the 35 counter cases was one.

Measured with git 2.43.0 under strace -f, no network (truth_work_n29.py of the delivery: 34 forms, 45 runs, every
documented hook a marker, core.editor, sequence.editor and core.pager markers): no form ran a hook of
_HOOKS_NOT_RUN_BY_WORK (pre-push among them); the hooks they ran are pre-commit, prepare-commit-msg, commit-msg,
post-commit, pre-merge-commit, post-merge, pre-rebase, post-checkout, post-rewrite, post-index-change and
reference-transaction, each of which keeps the form asking; no form started the editor, on a pipe or on a terminal of
script(1); on a terminal the tag lists started the pager, as the read forms of D34 do; no form started any other
program.

Keeps its answer, as today: a push to main, to release/* and to chore/prepare-*, every tag and every push of a tag;
force in every form (push -f, --force, --force-with-lease, checkout -f and -B, switch -C, --force and
--discard-changes, branch -f, rebase -f, worktree add -f, gh pr merge --admin); gh pr merge without --auto, with
--delete-branch or with any option D71 does not know; gh release; gh api with a method that writes; --no-verify,
setting core.hooksPath and every other way of turning a hook off (D24); every write into the gate directory and into
the configuration (decide_write); every command the gate cannot read whole (D27); every chain, pipe, `cd`, redirection
and prefix assignment; and every form that loses work not yet saved: reset --hard, clean -f, checkout or restore of a
path, stash drop and clear, branch -D, worktree remove --force (point 3 of the order, owner question O29-2). A push to
another branch follows D61.

Limits, in plain words: D71 applies at delta only once its remotes are of the form above (O28-3, O29-1); until then it
changes no answer there. Whether `gh pr merge --auto` merges at once when a pull request is already mergeable, and
whether main of each repository requires checks, is not measured; the owner's reasoning rests on GitHub's branch
protection, which the gate does not read. The declaration is read at HEAD, which a free commit can create. A checkout
replaces an ignored file that the target branch tracks under the same path (git's default --overwrite-ignore, read in
the documentation, not measured). Strict stays the default for everything outside D71; no check of the evidence falls
away.
Tests: tests/test_plugin_n29_work_profile_d71.py; tests/test_plugin_n20_short_line.py knows free_work_profile as a
pass.

## D72. The short line names the step that decides (Nachtrag 30, 2026-10-18)

delta's review of the real mishaps from 2026-09-27 to 2026-10-18 at 0efaf38d: of 13 mishaps the gate sees before Bash it
stopped 9; 7 at the step that was wrong but none with a reason that names the mishap, 2 at another step. The short line
named only D3, D27 or D33, and at S1 (`gh pr checks … && gh pr merge … --admin --merge`) the harmless first step. Owner
choice of 2026-10-18, 11:5x Berlin: the line names the danger.

Every ask, deny and warning names the simple command whose answer decides and the word that carries it, under both
hosts; the reason ids in the log stay as they are. Where several steps of a command carry the decision, the line names
the heaviest; the decision first (deny before ask before warn), then the weight of the step (_d72_step_weight, read by
the scan of the step's own text, no repository read): 5 a form that turns off the check of a push, 4 a push, a gated gh
call or a gh call the gate does not model, 3 a local change, 2 a call that may transfer objects (fetch, ls-remote,
worktree add), 1 a read (the read forms of D34 and those of D71: the tag and stash lists, bundle verify); the first of
the heaviest by place. Class c names the heaviest step whose own answer decides
(_sh_deciding); where class c keeps the whole command's answer, the line names the heaviest git or gh step
(_sh_heaviest, the kept step where it weighs as much); where the step parser does not model the command, the heaviest
call of the scan (_short_step_name). A gh step is named by its command words (`gh pr merge`, `gh pr checks`, `gh run
view`, _gh_short_name), no longer by `gh` alone. The reason in the line is the one of that step (Outcome.cause): its own
verdict in class c, else the verdict of the whole command that names it (_d72_cause: its failure starts with the step's
name, or the verdict names it as the call it cannot place, or for a gh step the verdict of the net). The short reason of
directory_unresolved says that the gate cannot tell which repository the step acts on; "after a cd" was wrong where no
`cd` stands in the command (a push in a chain).
Measured at the forms of the order (probe_lines_n30.py of the delivery): `git log -1 && git reset --hard HEAD~1` named
`git log` and names `git reset`; `gh pr checks … && gh pr merge … --merge` named `gh` and names `gh pr merge` (D27);
`git status && git push origin main` named `git push` with the reason of `git status` and names it with its own (D33
under Claude Code, D12 under Codex).
A write the gate guards weighs the most a line can name (_D72_WRITES): one into the gate's own directory (D25), which
may never run, and one into the configuration or the hooks of a repository (D8), which chooses the programs later git
calls run, as a form that turns off the check of a push does. Where such a write carries the decision, the line gives
its reason (_d72_write); class c knows the step that writes and names it where it is a git or gh step, though a step
before it weighs as much; where a later stage rebuilds the answer without step and cause (the done order of D38), the
reason comes from _d72_cause and the step named is the heaviest git or gh step. A write by another program (echo,
printf) is no step the line names (D53), so the line names the git or gh step beside it with the reason of the write.
Found in the corpus of the acceptance at b96ce3e1: `git status > .git/hooks/post-index-change` (S295) gave D3 of
`git status`, though `git status` alone is a free read form (D34) and the write decides; `printf … >> .git/config &&
git status` (S296, profile container) gave D34.
Tests: tests/test_plugin_n30_short_line_d72.py (the rows of the order, the gh names, class c, the heaviest of equal
weight, the writes the gate guards).

## D73. House rules: --admin, a tag going out, the limit of open pull requests, a kill that can end its own line (Nachtrag 30, 2026-10-18)

Owner choice of 2026-10-18, 11:5x Berlin: house rules into the gate, the line names the danger. They go before every
answer that lets a call run, D71 and a rule of a person included, under both hosts (_with_house_rules, after
_work_profile and the done order of D38). A house deny decides; a house ask decides unless the gate itself denies. The
house verdicts follow the gate's own in the log (house_admin_merge, house_protection_api, house_tag_out,
house_pr_limit, house_kill_pattern, house_kill_own); the short line names the rule, its step and its word (D72). The
long reason leads with the rule where it changes the decision and follows the gate's text where both ask. Under Codex
an ask is a deny, as every ask (D12).

The command is read run by run (_house_runs): by the step parser of class c, which leaves the body of a here-document
out; where it does not model the command (a keyword, a loop, a function, a background job), by the gate's lexer after the
bodies of here-documents are removed (_house_strip_heredocs), with every command substitution read in turn; the string
of `bash -c`, `sh -lc` and every shell of _SHELL_DASH_C, eval, watch and `su -c` read the same way, to MAX_NESTING. The
program of a run stands at its head or behind wrappers (sudo, env, timeout, nice, xargs, nohup, command, exec, time,
flock, … with their value options, _HOUSE_WRAPPERS); a word elsewhere in a run is an argument, so `echo gh pr merge 1
--admin` and `grep -rn pkill .` stay as they are.

H1, deny. `gh pr merge` with `--admin` or `--admin=<value>` anywhere after `merge`, in any quoting, also with `--auto`
(measured with gh 2.89.0 offline: `--admin` before `merge` is refused by gh, `--admin=true` and `--admin=false` are
taken, a word after `--subject`, `--body` or `-t` is their value). Not --admin: the value of a value option of `gh pr
merge` (`--subject --admin`, `-t --admin`, `-dt --admin`), a word after `--`, `--ADMIN` and `--adm` (gh refuses both),
`--admin` as text inside an argument. A `gh api` call that bypasses or changes a protection rule, as far as its text
shows it, with a method that writes (-X/--method, else POST where a field or --input is given, as gh does; a method the
shell builds counts as a write): `repos/<o>/<r>/branches/<b>/protection` and below it, `repos/<o>/<r>/rulesets`,
`orgs/<o>/rulesets`, `enterprises/<e>/rulesets` and below, `repos/<o>/<r>/tags/protection`,
`repos/<o>/<r>/environments/<e>` with its deployment branch policies and protection rules, a path of
`bypass-requests` or `push-protection-bypasses`, and `repos/<o>/<r>/pulls/<n>/merge` (the merge without gh's check, the
call --admin makes); the endpoint with a leading slash, with `{owner}/{repo}` or as a full URL; GraphQL with the
mutations create/update/deleteBranchProtectionRule, create/update/deleteRepositoryRuleset, updateEnvironment and
mergePullRequest in a query given with -f or -F. The paths are those of the GitHub REST API as written down here;
none was called (no network, NOT MEASURED). A query read from a file (`query=@file`) is not recognised.

H2, ask. A tag that goes out: a push with --tags, --follow-tags, --mirror (in every abbreviation git takes) or `-c
push.followTags=true`; a refspec side with `refs/tags/`; the word `tag` before a name; a name in the form of a version
(v6.2.0, 6.2.0, v1, v1.0-rc1) on either side; as the source, a name a `git tag` of the same command creates, or a name
the repository holds as a tag and not as a branch (read with the gate's own git, `for-each-ref`, where the directory is
known; a name that is both is refused by git as ambiguous and sends nothing); `gh release create|new <tag>`; a `gh api`
write that names `refs/tags/` or writes a release; a GraphQL mutation that names `refs/tags/`. The line names the tag
and says that a v-tag can start a release that needs an owner GO. A local `git tag` without a push stays as it is. Not
recognised: a tag a plain `git push` sends because the repository's configuration says so (push.followTags,
remote.<name>.push, remote.<name>.mirror); such a push asks already through the push configuration check, with its own
reason.

H3, ask. `gh pr create` and `gh pr new`, a `gh api` POST to `repos/<o>/<r>/pulls` and the GraphQL mutation
createPullRequest. A session may hold at most HOUSE_PR_LIMIT = 8 open pull requests; every session writes through the
account b7n0de, so a count by author counts all sessions, and the gate has no count per session (owner question O30-1),
so each of these asks and its line names the limit.

H4, ask. `pkill -f` (also --full and in a bundle such as -fx) in a chain with further work (any other run in the line),
or where its pattern can match its own command line: the command, the shell Claude Code runs it in (_HOUSE_CLAUDE_SHELL,
measured in this session: `/bin/bash -c "source <snapshot> … && eval '<command>' && pwd -P >| /tmp/claude-<id>-cwd"`),
and the hosts (claude, node, codex); the pattern is read as a regular expression where the POSIX reading and Python's
agree, any other pattern can match. killall in a chain, or where a name names a program of its own line (the shell, a
program of the command, the host), killall and pkill match process names, not command lines. Measured siblings that end
the command's own shell (procps-ng 4.0.4, psmisc 23.7, bash 5.2.21, each in a PID namespace of its own): pkill without
-f whose pattern names such a program (`pkill bash`; `pkill node` asks for the host, not measured), kill of the own
shell, its parent or its process group (`kill $$`, `kill $PPID`, `kill 0`), pgrep -f or pidof whose pattern can match
the own line in a command that also runs kill (`kill $(pgrep -f x)`, `pgrep -f x | xargs kill`). A negative target
(`kill -9 -1`, another process group) asks as well; that one is not measured, the namespace held no other process.
Measured: `pkill -f <pattern>` alone ends no shell under plain `bash -c` (bash runs it in its own place) but ends a
shell that runs a script in the form of Claude Code's, which runs more after it; in a chain it ends the shell; `pkill -A -f` (ignore ancestors) and a pattern that does not match its own text
(`[s]erver`) leave it. `pkill <name>` alone and `kill <pid>` stay as they are. The line says the pattern can also match
its own command line and to run it alone.

Counter cases, unchanged at ffa7d39a and at the head: `gh pr merge <n> --auto --merge` (free under D71), `git tag -l`,
`git push origin <branch>`, `pkill <name>`, `kill <pid>`, `--admin` as text or as the value of an option, a GET of a
protection rule (free under D36), a here-document that names the forms. The strictness stays the default; no rule falls
away and nothing that asked or denied before is free.
Tests: tests/test_plugin_n30_house_rules_d73.py; the tests that pin the reason ids of a tag push and of `gh pr create`
name the house id after the gate's own.

## D74. The filter block of git-lfs and core.fsmonitor set true in the person's own global or system file (Nachtrag 31, R1, 2026-10-18)

delta asked five times between 15:25 and 15:34 Berlin, each answered Yes. Cowork set the forms again at 44db2056 with one
line of the global configuration: `git status` and `git diff` asked once the global file held the filter block `git lfs
install` writes or core.fsmonitor set true (D34, the key filter.lfs.clean named). Owner choice of 2026-10-18, 15:3x
Berlin: the four entries of that block, with exactly its values, and core.fsmonitor set true count as known, from the
global or the system file only, if the measurement holds.

Measured with git 2.43.0 and git-lfs 3.4.1 under strace, with no network (truth_lfs_n31.py of the delivery, 338 runs of
status, diff, log, show, add, commit -m, checkout, stash and fetch, a stand-in git-lfs in front of PATH that writes a
marker and runs the real one):
- with the block at the global or the system scope, in its plain form and in the form of --skip-smudge, and with the
  container's own system file, git-lfs started for no form where no attribute assigns a filter;
- where an attribute assigns the filter to a path, status, diff, add, commit, checkout and stash started
  `git-lfs filter-process`; its first run in a repository wrote four hooks into the hook directory (post-checkout,
  post-commit, post-merge, pre-push), and with the plain form a checkout or stash whose object the clone did not hold
  tried the network (about 1300 connect calls, then exit 128); log, show, diff between two commits and fetch started it
  for no state;
- core.fsmonitor set true, yes or 1 started nothing for any form: git 2.43.0 on Linux has no fsmonitor daemon
  (`git fsmonitor--daemon status` exits 128, "not supported on this platform"); a path as the value started that program
  for the forms that walk the work tree and for fetch.

So the measurement holds where no attribute assigns a filter, and the rule is built that far:
- _LFS_KNOWN holds the four keys and the values `git lfs install` and `git lfs install --skip-smudge` write (the test
  runs git-lfs and compares). An entry counts as known (_lfs_known) only with one of these values and in the person's
  own file (_own_file): the scope global or system, the very file `git var GIT_CONFIG_GLOBAL` or `GIT_CONFIG_SYSTEM`
  names for it, neither name set in the hook's environment. The local and worktree files, a file an include brings in
  (from the work tree or anywhere), GIT_CONFIG_COUNT and its keys and `-c` (scope command), and a file GIT_CONFIG_GLOBAL
  or GIT_CONFIG_SYSTEM names are never the person's own file. Another value, another filter.lfs key and every other
  filter driver count as before.
- The read profile of class a (D34) treats a known entry as D39 treats a filter under `--no-ext-diff --no-textconv`: it
  counts only where an attribute assigns a filter to a path of the index (_filter_assigned). status and diff hash no
  untracked path.
- The state check (_add_commit_state_problem) does the same for the two forms of K-NW-2 B under Claude Code and for the
  forms of D71 that bring no other tree into the work tree (_WORK_LFS_FORMS: commit, stash push, branch, bundle
  create), with the untracked paths git add would take (not ignored) checked as well. checkout, switch, merge, rebase,
  their --abort and worktree add read the attributes of another commit, which the check does not read: there the block
  counts as any filter does.
- core.fsmonitor counts as known (_fsmonitor_known) where git reads the value as true (_git_true), the person's own file
  holds it and this git has no daemon (`git fsmonitor--daemon status`: exit 128, not supported on this platform), in
  the read profile, in the state check of the forms above and in the fetch profile of D45 alone. Where git has the
  daemon it starts it, which was not measured (macOS, Windows): the key counts there as before. A path as the value,
  and true in the local file, count as before. ls-remote (D59), the remote read of D61 and worktree add (D40) were not
  among the measured forms and keep their rule.
- Under Codex nothing changes: no read form is free there (D37), and the relaxation of the state check is for Claude
  Code alone, so no case that is blocked under Codex today becomes free.
The gate reads no file of ~/.ssh, no key and no credential for this, and calls no network.
Tests: tests/test_plugin_n31_own_config_d74.py (the read forms, K-NW-2 B and the forms of D71 with the block in both
forms; fsmonitor true, yes and 1; the counter cases of the order; the untracked path; the forms that bring another tree;
_own_file; a git that has the fsmonitor daemon; the values git-lfs writes).

## D75. The read forms of `git remote` are read forms of class a (Nachtrag 31, R2, 2026-10-18)

delta's `git -C <wt> remote -v` asked every time with possible_unmodeled_push ("may send objects … (D8)"), though it reads
the configuration. Owner choice of 2026-10-18, 15:3x Berlin: `git remote`, `git remote -v`, `git remote get-url [--push]
[--all] <name>` and `git remote show -n <name>` become read forms of class a after strace.

Measured with git 2.43.0 under strace against a stand-in for github.com in a network namespace of its own
(truth_remote_n31.py of the delivery, 105 runs): the eight read forms (`git remote`, `-v`, `--verbose`, `get-url <name>`,
with --push, with --all, with both, `show -n <name>`) started no program besides git, connected nowhere and wrote
nothing under .git, with no source, with core.pager and PAGER on a terminal of script(1), with a credential helper,
core.sshCommand, core.fsmonitor naming a program, a filter an attribute assigns, every documented hook, a URL rewrite
onto another host, an ssh URL with core.sshCommand, and remote.origin.uploadpack. pager.remote started its pager on a
terminal. `git remote show origin` and `git remote prune origin` connected to the stand-in, `git remote update` fetched,
add, set-url, remove and rename wrote the configuration, and `git remote show` with no name lists the remotes.

The rule (_remote_read_form, in _read_form): the forms above with literal words, --push and --all each at most once, one
remote name that does not start with `-`. They pass under Claude Code after the read profile of D34 (no walk of the work
tree, so a filter, fsmonitor and a hook do not count for them; a pager key, a promisor key and a key the profile does
not know do). `git remote show` without -n, `show` with no name, update, prune, add, set-url, remove, rename, a second
name, an unknown option, a redirection and a global option keep their answer. Under Codex no read form is free (D37):
these forms now ask there with the reason of D37 instead of possible_unmodeled_push, as before denied.
Tests: tests/test_plugin_n31_remote_read_d75.py. Two older tests used `git remote -v` as their form outside class a
and use `git remote show origin` now, which reaches the remote and stays outside (tests/test_plugin_codex_read_steps_text.py,
tests/test_plugin_review20_codex_read_text.py).

## D76. An ssh setting alone does not hold the ask of the fetch of D45 from https on github.com (Nachtrag 31, R3, 2026-10-18)

delta's `git -C <wt> fetch -q --prune origin` asked once core.sshCommand stood in the configuration (the text named
core.sshcommand). D45 kept core.sshCommand, GIT_SSH and GIT_SSH_COMMAND asking by owner choice, though an https fetch
started none of them (measured then). Owner choice of 2026-10-18, 15:3x Berlin: where every URL of the remote, with
insteadOf applied, is https://github.com/<owner>/<repo>, these three alone no longer hold the ask, after a measurement
that an https fetch then starts no ssh.

Measured with git 2.43.0 under strace against a stand-in for github.com in a network namespace of its own
(truth_remote_n31.py of the delivery): `git fetch -q --prune origin` from https://github.com/o/r with core.sshCommand,
GIT_SSH or GIT_SSH_COMMAND naming a marker program, with all three, and with all three and an ssh push URL beside the
https URL, started the programs of the baseline (git-remote-https, rev-list, unpack-objects, maintenance), no marker,
and connected only to github.com:443. With an ssh URL, an ssh:// URL or url.git@github.com:.insteadOf onto the https
URL the fetch started the marker as its ssh.

The rule (_fetch_profile_problem with own_known, for the fetch form of D45 and so for the fetch of D71, never for
ls-remote of D59 or the remote read of D61): core.sshCommand at any scope and GIT_SSH and GIT_SSH_COMMAND in the hook's
environment are noted instead of counted. They hold no ask only where every URL of the remote is https on github.com:
the one URL is (D45, and no insteadOf acts on it, D51), each push URL is and no insteadOf acts on it, and without a push
URL no pushInsteadOf acts on the URL; the order says every URL of the remote, and a fetch reads no push URL (D52), so
these are held to the rule of the order, not to what the fetch reads. The pass names the settings and D76.
core.askPass, GIT_ASKPASS, SSH_ASKPASS, GIT_SSH_VARIANT, ssh.variant, a prefix assignment of the command and every
other key or name keep their rule. Under Codex the fetch is never free (D45).
Tests: tests/test_plugin_n31_ssh_https_fetch_d76.py. tests/test_plugin_fetch_github_profile.py listed core.sshCommand,
GIT_SSH and GIT_SSH_COMMAND among the configuration and environment that ask; they left the lists with a note to D76.

## D77. head, tail, ls, date, sleep, wc and the test command `[` in a chain that only reads (Ergänzung 1 to Nachtrag 31, O26-1, 2026-10-18)

Counted at delta (Cowork, 2026-10-18, count 0752Z over 282 asks and denies): 25 carried the word that set them off only
as an argument (D27 19, D3 4, D38 2); 6 of them only read, and none of those got by with the set of D66, for want of `[`
(4 commands), head (4), ls (2), sleep (2), date (1), sort (1), tail (1) and cd (1). Owner choice O26-1 of 2026-10-18,
16:4x Berlin: head, tail, ls, sort, date, `[`, sleep and wc become free in a chain that only reads, each after a
measurement with strace; cd does not.

Measured with GNU coreutils 9.4 and bash 5.2.21 under strace -f in bash -c, as the Bash tool runs a command, with no
network (truth_readprog_e1.py of the delivery, 336 runs): 84 forms from the corpus and of the order (head and tail with
-n, -c, -NUM, --lines, -q, -v; ls with -la, -1, -R, -d, -t, -S, -A, -F, -n, --color=never; date with +FORMAT, -u, -I,
-R, -d, -r, --iso-8601; sleep with whole and decimal seconds and a unit; wc with -l, -c, -w, -m, -L, --lines; sort
with -r, -u, -n, -t and -k, -V, -c, -z, -f, -b, -s; `[` with
-f, -d, -n, -e, -s, -x, `!`, = and -lt, in an if and with && and ||; xargs that runs wc, head, tail and ls; chains of
them), each under four sources (none; a program named git and one named gh first on PATH that write a marker; LC_ALL=C
and POSIXLY_CORRECT; TMPDIR, LS_COLORS, TZ, TIME_STYLE and QUOTING_STYLE). Each program started only itself, `[` nothing
(a builtin of bash); no file was opened for writing but /dev/null; no socket was made but the lookup of a user name over
the local socket of nscd (bash itself, and ls -l), which failed here; no file in the work folder, HOME or TMPDIR changed;
no marker was written. sort is the exception (truth_sort_temp_e1.sh): with none of -o, -T, -S and --compress-program it
created, in TMPDIR, files of its own (O_RDWR|O_CREAT|O_EXCL, mode 0600) and removed them, from a piped input of 0.8 MB on
(2 files at 798,895 bytes of seq, none at 588,895, 616 at 619 MB), and from a regular file of 619 MB (2 files, none at
151 MB). That is a write outside /dev/null, so sort is not built (owner question O31E1-1 of the delivery).

The rule (_read_only_command, in _decide_outcome for D27 and D3 and in _done_order_verdict for D38), under Claude Code:
a command wholly of the closed read forms of D66 and of these gets no answer. Each read program has a closed grammar of
switches (_READ_PROGRAMS); every word after it is literal (a word the shell builds or rewrites may be any switch); after
`--` only operands count. head and tail take -n, -c, -q, -v, -z, their long names and an obsolete `-NUM`; tail no `+N`
operand (the obsolete form that may follow with f). wc takes -c, -m, -l, -w, -L and their long names. ls takes the
switches that list, sort and format, named one by one, and no --dired, --hyperlink or --zero. date takes -u, -R, -I, -d,
-r and their long names, and at most one operand, a format that starts with `+`. sleep takes durations only. `[` takes
any words and ends with a literal `]`; test has no operator that writes. xargs (with the switches of D66) may start head,
ls or wc, whose every option only reads, as the words of its input become their arguments; tail, date and sort it may
not. The chain may hold the words of an if (if, then, elif, else, fi) and `&&` and `||` besides `|` and `;`: whichever
runs the shell starts, each only reads. Every read program the command starts must be GNU coreutils of a measured
version (9.4): every PATH entry absolute and not dependent on the process, and `<name> --version` of the program on
that PATH names it, as for gh (D27: this shows a version, not an origin). Another version, BSD, BusyBox, a program that
fails, and a PATH entry that is not absolute leave the command as before D77 (NOT MEASURED).

Unchanged: tail -f, -F, --follow, --retry, --pid, -s; date -s, --set, -f, --file and a time as operand; sort; cd (D33);
a redirection into a file; a program beside them that writes or is not in the set (tee, rm, cp, cd); a wrapper other
than xargs (timeout, env, command, nice); a program as a variable; a background job, a subshell and `!`; `[[`; a bracket
test beside git or gh. Under Codex every ask is a deny, so D77 would free a command Codex denies today: there the set of
D66 stays as it was. Not measured: other versions of coreutils, BSD and BusyBox, zsh and dash as the shell of `[`, a
lookup of user names through another source than files (ls -l, as for every program that names a user), and functions
or aliases of the shell snapshot Claude Code sources before the command.
Tests: tests/test_plugin_n31e1_read_programs_d77.py. tests/test_plugin_n23_bracket_test_d60.py listed `[ -x git ]`
among the commands that ask; it tests a file named git and is a chain wholly of `[`, so it moved to a control that asks
under Codex and is silent under Claude Code.

## D78. For a read form only a hook counts that this form starts (Ergänzung 1 to Nachtrag 31, point 2, 2026-10-18)

At delta (Cowork, 2026-10-18, list 1442Z) the three asks of D34 at `git status` and `git diff` came from the pre-commit
hook of the clone (the key named six times: `hook pre-commit` in the repository's hook directory). The read profile
counted every hook that is not a sample for the forms that walk the work tree.

Measured with git 2.43.0 under GIT_TRACE2_EVENT, with every hook githooks(5) of git 2.43 documents and one of another
name in place, each writing a marker, with no network (truth_hooks_e1.py of the delivery, 840 runs): twenty forms
(status with --short, --porcelain, --branch, -uno; diff with --stat, --cached, HEAD, --name-only and two commits; log
with --oneline, -p; stash list; grep; ls-files with -m; show --stat) in seven states (clean, a file whose modification
time changed in another second, a changed file, a new file, an index older than the files, a stash, a changed time and
content), with and without GIT_OPTIONAL_LOCKS=0, in the hook directory, through core.hooksPath and in a linked work
tree. Marker and trace2 agreed in every run. status started post-index-change in each of the seven states, not under
GIT_OPTIONAL_LOCKS=0; diff of the work tree (diff, --stat, HEAD, --name-only) started it after a change of a file's time
(three states), also under GIT_OPTIONAL_LOCKS=0; diff --cached, diff of two commits, grep, ls-files, log, show and stash
list started no hook; no form started pre-commit, any other documented hook or the hook of the other name.

The rule (_read_profile_problem, _HOOKS_STARTED_BY_READ): for a form that walks the work tree a hook counts where that
form starts it (post-index-change for status and diff, none for grep and ls-files) or where git does not document its
name (_GIT_HOOK_NAMES, the 28 names of githooks(5) of git 2.43): such a name keeps the ask, as the gate does not know what
starts it. fsmonitor-watchman runs only where core.fsmonitor names it, which the profile judges as a key (D74). A sample
never counted. Every other rule of the profile stays; the forms that do not walk the work tree read no hook, as before.
Under Codex no read form is free (D37). Not measured: git 2.51.1 of delta's machine; a hook that git starts through
configuration (hook.<name>.command of later versions; a key the profile does not know keeps the ask).
Tests: tests/test_plugin_n31e1_read_hooks_d78.py. tests/test_plugin_ask_load_a_read.py held every walking form not free
beside a post-index-change hook; git grep and git ls-files started it in no measured state and are free there now.

## D79. The block of the Stop hook names the key file done-init made (Nachtrag 32, B30-2, 2026-10-18)

Measured in Nachtrag 30 (messung/stop_hook, with_key_option): `done-init --key <path>` made the key at that path, and
the block of the Stop hook named the default key file of the gate directory, which did not exist; the command the block
named could not close the check.

The rule (done_init, check_command): done-init records in the gate directory, in done-keys.json, the key file it made
for the repository, as the absolute path under the real path of the repository's top level; never a key, and nothing
the key file holds. The command of a block names PROOFBUNDLE_KEY where it is an absolute path, else the recorded key
file of the repository, else the default key file of the gate directory, as before. A record the gate does not read
(not a regular file, a FIFO included, larger than MAX_STATE_BYTES, not strict JSON of one object, a relative path, the
record of another repository) names the default. The record is written through a fresh file of mode 0600 that replaces
it, never through a link; the gate directory is the person's (D25), so the agent's tools cannot change it. Where no gate
directory is known, done-init says that the block will name the default.
Tests: tests/test_plugin_n32_done_key_b30_2.py.

## D80. The Stop hook holds a claim of the last message that has no evidence (Nachtrag 32, O30-2, 2026-10-18)

Measured by delta (WIRKUNG_plugin_20261018.json, gate 0efaf38d): five false completion messages, none held; neither
repository declares a done check, so the Stop hook ended with `nothing_declared`. Measured in Nachtrag 32 with Claude
Code 2.1.302 (messung/transcript_summary.txt, stop_hook_active_summary.txt): the Stop event carries
`last_assistant_message` and `transcript_path`; a Bash call is a `tool_use` item with input.command, its result a
`tool_result` item with is_error false for exit code 0 and true otherwise; stop_hook_active is false at the first Stop
of a turn and true at each Stop after a block; after nine blocks 2.1.302 ends without a tenth event.

The rule (claim_check, message_claims, stop_command), under Claude Code, where the done check lets the end through:

- The claims are a closed list in German and English: done (fertig, erledigt, done, finished, completed, in a clause of
  at most eight words that does not name what was done), the tests pass (a test word before a green word, or a count of
  passed tests, in a sentence that names no red ones), pushed (gepusht, pushed), merged or landed (gemergt, gelandet,
  merged, landed; not where the clause says local), a verdict (WITHSTANDS, PASS, PASSED, FREIGABE, FREIGEGEBEN in
  capitals), OK of a check script (OK in capitals beside a script file or a word such as Skript, Kreuzprobe, check).
  Fenced code, quoted lines and text in quotation marks claim nothing. A question claims nothing; a clause claims
  nothing where a negation, a part, a condition, a modal or future form or an alternative stands among the four words
  before its claim. Such a word takes back its own clause only: a claim in another clause stays a claim.
- Each claim needs its own evidence at the current state. The tests pass, or the work is done: the declared done check
  passed at this end (a receipt with the git state of the work tree), or a test run of the closed list of runners after
  the last change in the transcript whose exit code is its own and 0 (nothing after the runner but `&&`, or a pipe
  with `set -o pipefail` before it; no `||` between the runner and the list before it; not in the background, not
  interrupted). A change is an edit of a file tool, a subagent (Task, Agent: its own calls stand in a transcript of
  their own, which the check does not read), or a Bash command that is not of the closed list of commands that change
  no file of the work tree (reads, git and gh calls that leave the work tree as it is, test runners); a command the gate
  cannot read is a change. Each Python version the claim names needs such a run that names it, in its
  command, its output or the version its interpreter showed. Done needs no run where the transcript shows no change.
  Pushed: a fetch, pull or push succeeded in the transcript and a remote-tracking ref points at the reported state (the
  commits the sentence names, else HEAD), or a push's output names the reported commit as the new value. Merged or
  landed: a fetch, pull or push succeeded and the default branch of a remote (main, master or its HEAD) contains the
  reported state; where the sentence names no commit, a merge of gh without --auto or of the GitHub tools that
  succeeded. A verdict: a digest of at least twelve hex characters in its sentence, and a receipt in .proofbundle/ (a
  JSON file whose name says receipt) that names exactly that digest; the gate reads the name, it does not verify the
  receipt. OK of a check script: the last run of that script (or of any script, where none is named) exited 0 and its
  output names a number beside OK.
- A claim without evidence blocks with the one line "proofbundle claim check: …" (every open claim, the smallest next
  step of the first, and that the agent may end with a status that claims nothing) and the short line "Gate holds the
  end because a claim has no evidence (D80)."; the log names each claim's kind and whether it has evidence, never the
  message.
- Point 4 of Nachtrag 32: a status that claims nothing ends without a receipt. The same block (the same open claims,
  HEAD, status of the work tree and remote-tracking refs) comes at most CLAIM_MAX_BLOCKS = 2 times in a row in a
  session; the next Stop after a block ends with a message that names the claim open and not confirmed. The count lives
  in claim-state.json of the plugin data directory, per session by the sha256 of its id, at most 64 sessions. A Stop
  with stop_hook_active false counts as the first. A tool call that changes none of these is no new state, so an
  agent cannot keep a block alive with calls that change nothing (Claude Code ends a loop by itself only where no tool
  is called). Where the count cannot be kept, a Stop after a block ends with the claim open, so no loop depends on a
  file the hook cannot write.

Not under Codex: its transcript form is not measured, and its Stop event names `last_assistant_message` as nullable
(owner question). The words of the list are a closed list, not an understanding of the message: a claim in other words
is not held, and a status in words outside the list can be held (the cap of two bounds it). Tests:
tests/test_plugin_n32_claims_d80.py.

## D81. A hint before a run that reads its evidence wrongly, never a question (Nachtrag 32, point 3, 2026-10-18)

Measured in Nachtrag 32 with Claude Code 2.1.302 (messung/hint_path_summary.txt): of the outputs of a PreToolUse hook
only hookSpecificOutput.additionalContext reaches the model without a question, as a message of role system
("PreToolUse:Bash hook additional context: …"); systemMessage, the reason of an allow, plain stdout and stderr do not.
Delta's cases: F4, the exit code came from `tail` after a `timeout`; F5, `-rs` read an empty set of red tests. Counted
(messung/hints_corpus.json): the corpus has 435 rows, 3 test runs, 4 check-script runs and no row with a hint; the Bash
commands of the transcript of this cloud session have 3572 rows, 581 with the pipe hint and 1 with the -r hint. Delta's
command list was not delivered: NOT MEASURED.

The rule (evidence_hints, main), under Claude Code, for a Bash call that is not denied: a test runner of the closed list
of D80 or a check script whose output goes into a pipe without `set … pipefail` before it gets the hint
pipe_without_pipefail; pytest with a -r selection that names neither f, E, a nor A gets pytest_r_without_failures. The
hint stands in additionalContext, after the long reason where the gate asks; it sets no permission decision, so a pass
stays silent for the user (D53) and an ask stays an ask. The log names the hint ids. Not under Codex: its handling of
additionalContext is not measured.

Not built: a hint on a receipt that names fewer interpreters than the declaration requires. The receipt of the pytest
plugin names no interpreter, and the declaration has no field for the interpreters it requires (owner question). The
evidence check of D80 asks each Python version a claim names for a run that names it.
Tests: tests/test_plugin_n32_hints_d81.py.

## D82. A substitution bash runs is seen wherever bash runs it (Nachtrag 34, C31-1 to C31-3, 2026-10-18)

D79 to D81 are taken by Nachtrag 32, which follows this one.

Found by Cowork in the gate of Nachtrag 31 and measured here with GNU bash 5.2.21 and a marker program in place of a real
command (messung/truth_n34.jsonl): bash runs a substitution in the index of a name it reads, single quotes or not
(`[ -v 'a[$(…)]' ]`, `test -v`, `[[ -v`, `read 'a[$(…)]'`); in an arithmetic expansion, quoted or not (`$(( $(…) ))`,
`$(( '…' ))`, `$[ … ]`); in the index of a parameter expansion (`${a['$(…)']}`, `"${x:-'$(…)'}"`); after an apostrophe
inside double quotes (`"it's $(…)"`) and after an escaped quote (`it\'s $(…)`); and in `$((…) )`, which bash reads as a
command substitution of a subshell. It does not run one for `-R`, the arithmetic comparisons of `[`, the options of
`read` other than its names and `-a`, or a default in single quotes in an unquoted `${…}`. The gate of 89d2e8b7 let each
of the first through with `git push origin main` hidden in it (messung/probe_89d2e8b7.jsonl): the read forms of D66 and
D77 freed the command before the scan, the data steps of D72 freed `test -v`, and the scanner of substitutions that D3,
D38, D66, D67, D69 and D73 share skipped the inside of `$(( ))` and believed quotes bash does not.

The rule:
- The scanner of substitutions (_subst_bodies) reads quotes as bash does: a single quote inside double quotes or after a
  backslash is no quote; it counts every substitution inside an arithmetic expansion and a parameter expansion, quoted
  or not; it reads `$((…) )` as a command substitution where the inner parenthesis closes before the end; it counts a
  process substitution. Every rule that reads it sees the same bodies.
- The net (D27) takes these bodies too, so a substitution inside an arithmetic or a parameter expansion is a context of
  its own for the program position.
- `read` is a read form (D66) only where each word it takes as a name is a plain name written as such: the operands
  after its options and the value of -a; an option outside `help read` makes the run no read form.
- `[` (D77) and `test` count `-v` only before a plain name, in the read forms and in the data steps of D72.
- The step parser of D72 refuses `$[ ]`, as it refuses `$(( ))` with a substitution or an index.

Nothing gets freer (messung/probe_fix.jsonl against messung/probe_89d2e8b7.jsonl): of 296 probe rows 132 go from free to
held, none from held to free. Not modeled: an arithmetic over the value of a variable the command does not set
(`$((X))`, `${!X}`), where the value comes from the environment of the host and the agent sets none in a read form
(owner question). Tests: tests/test_plugin_n34_hidden_commands_d82.py.

## D83. sort in a read-only chain under Claude Code (Nachtrag 34, owner choice O31E1-1 A, 2026-10-18)

Measured in Ergänzung 1 to Nachtrag 31 under strace -f, GNU coreutils 9.4 (truth_readprog_e1.py): sort with -b, -c, -f,
-n, -r, -s, -u, -V, -z, -k and -t started only itself, opened no file for writing and made no socket. From a pipe of 0.8
MB on it writes temporary files of its own in TMPDIR, opened with O_EXCL and mode 0600 and removed by sort itself
(truth_sort_temp_e1.sh); from a file it writes none up to 600 MB.

The rule: sort is a read program of D77 under Claude Code, with exactly the options measured (short switches b c f n r s
u V z without a value, k and t with one), the version check of D77 and the temporary files as the named exception of
owner choice O31E1-1 A. -o, -T, -S, -m, -R, every long option and every option not measured stay out; sort behind xargs
stays out (its input could become an option); under Codex nothing changes (D37). It frees a chain the steps of D72 do
not free, such as `find … | xargs grep -l git | sort`; a chain of data steps alone was free before.
Tests: tests/test_plugin_n34_sort_d83.py.

## D84. The test builtin like `[` under Claude Code (Nachtrag 34, owner choice O31E1-5, 2026-10-18)

Measured under strace -f in bash -c (messung/truth_test.jsonl, truth_test_n34.py, 44 runs under the four sources of
Ergänzung 1 to Nachtrag 31): test with -f, -d, -n, -e, a string comparison with a substitution, -lt, `!` -s, -x, -v
before a plain name, -z and -nt started no program besides bash, opened no file for writing, made no socket and changed
no file, as `[` did in Ergänzung 1.

The rule: under Claude Code `test` is a read form of D77 like `[`, with the rule of D82 (`-v` only before a plain name).
Under Codex nothing changes (D37). It frees a chain the steps of D72 do not free, such as `find … | xargs grep -l git &&
test -x .git/hooks/pre-push`; a chain of data steps alone was free before. Tests: tests/test_plugin_n34_test_builtin_d84.py.

## D89. A read form counts only the hooks git starts for it, by name (Nachtrag 36, B36-3, 2026-10-18)

Found by delta at the Farmer (gate 89d2e8b7): `git status` kept asking in 2bedone because the hook directory holds
`pre-commit.local`, which D78 counted as a hook of a name git does not document. git never starts such a file itself; a
dispatcher pre-commit calls it, and status starts no pre-commit.

Measured with git 2.43.0 under GIT_TRACE2_EVENT, each hook writing a marker (messung/truth_hooks_n36.jsonl,
truth_hooks_n36.py, 840 runs: seven states of the work tree and the index, with and without GIT_OPTIONAL_LOCKS=0, in the
hook directory, through core.hooksPath and in a linked work tree; every name of githooks(5) and pre-commit.local,
pre-push.vor-ruff-20260919, post-index-change.local, post-index-change.sample and zz-unknown-name beside them): status
and diff started post-index-change in every state without GIT_OPTIONAL_LOCKS=0, a clean one included, and never with it;
no form started any other file.

The rule: for a form that walks the work tree a file of the effective hook directory counts where its name, in lower
case, is a hook git starts for that form (_HOOKS_STARTED_BY_READ: post-index-change for status and diff, none for grep and
ls-files). Lower case, because a file system that does not tell the cases apart finds `Post-Index-Change` too. A file of
any other name does not count; a sample never did. Under Codex nothing changes (D37). Not changed here: the state check
of add and commit (D40), fetch (D45), ls-remote (D59) and worktree add still count a file of a name git does not
document; point 5 of Nachtrag 33 is ordered for them. Tests: tests/test_plugin_n36_hook_names_b36_3.py; changed:
tests/test_plugin_n31e1_read_hooks_d78.py (its control of the old rule now states the new one) and
tests/test_plugin_n21_marker_in_no_reason.py (two cases whose hook of another name no longer makes a read form ask
add post-index-change beside it, so they still read a reason of the read profile).

## D90. The word is not the program: D77 and the session's aliases and functions (Nachtrag 36, B36-2, 2026-10-18)

Found by delta at the Farmer (gate 89d2e8b7, zsh 5.8.1): `ls` is an alias for colorls in the session's shell, so the
command text `ls` starts another program than /usr/bin/ls, while D77 judged by the word.

Measured with bash 5.2.21 as Claude Code runs a command (the snapshot sourced, the text evaluated), a marker program in
place of the other one (messung/truth_alias_n36.tsv, truth_alias_n36.sh, 30 cases): a function, a `hash -p` entry, an
exported function (BASH_FUNC_ls%%) and a function from BASH_ENV make a bare `ls` run another program, an alias does once
expand_aliases is on (the snapshot of this container turns it off; zsh expands aliases, not installed here, NOT
MEASURED); `command ls` runs its own program past an alias and a function, not past `hash -p ls`, a function named
command or an alias `command='command '`; `/usr/bin/ls` runs another program only where a function carries that path as
its name; functions named `test` and `[` replace the builtins; `xargs ls` runs its own program in every case.

How the gate measures, without running the session's shell (_session_definitions): it reads every file of the folder in
which Claude Code keeps the snapshots of the shell (shell-snapshots under CLAUDE_CONFIG_DIR, else ~/.claude; measured
with Claude Code 2.1.302: aliases, functions written as `eval $'name () …'`, shell options and PATH) for the definition of
the names it needs, by pattern, and the names of exported functions in its environment, not their values; under zsh also
the global zshenv files. It keeps and logs nothing of what it read. Not measured: a shell other than bash, sh, dash and
zsh; BASH_ENV or ENV set; a .zshenv of the person under zsh (the gate reads no shell file of the person, which may hold a
credential); a snapshot folder that is no directory, more than 64 files in it, one that is no regular file or larger than
1 MiB. No snapshot folder under bash, sh or dash is measured as nothing defined.

The rule: a bare read program of D77, `[` and `test` are silent only where the session is measured and defines none of
them (alias, function, hashed path, builtin); `command <name>` with a read program of D77 is silent unless a measured
session defines `command` or hashes the name; a read program of D77 written as its absolute path is silent unless a
measured session defines that path as a name, with the version check of D77 on that path; a program xargs starts counts
whatever the session holds. Under Codex nothing changes (D37). Not changed here, the same class: the programs of D66
(find, xargs, grep, echo, read), the data steps of D72 and git and gh themselves are judged by the word (owner question
O36-3). Tests: tests/test_plugin_n36_session_names_b36_2.py; changed: tests/test_plugin_n31e1_read_programs_d77.py
(`command head` is a read form now, its counter case is `command -p head`).

## D85. The autonomous answer under Claude Code: the gate asks only for an external effect (Nachtrag 35, 2026-10-18)

Owner word of 2026-10-18, 20:40 Berlin: the owner confirms too much, the plugin has to work largely on its own. delta
counted 97 real asks in the period of 0efaf38d (D3, D27, D33 and D34 the most), four of them on the owner's screens.

The rule: decide() judges as before; under Claude Code the hook started with `--autonomous` (AUTONOMOUS_FLAG), as the
plugin's hooks.json starts it for every PreToolUse matcher, answers an ask of it (autonomous_outcome)
- with the ask where the command is one simple call with an external effect of the closed list AUTONOMY_EFFECTS (a
  push, a push that deletes a remote branch, a tag, a release, a merge without --auto, a pull request, an issue, a
  comment or a review, a setting of a repository, a gh call that writes, a change of a done order of D38), and for a
  gated MCP tool: the owner clicks. The list is owner question O35-1;
- with a deny that names a rewrite, where the gate rewrote the command into calls of its own (a chain into its steps, a
  `cd <path>` into `git -C <path>`, a `$( )` around one git or gh call into a call before it whose output the next one
  takes, `$( )` of the current branch in a push into HEAD, `$(pwd)` and `$PWD` into the directory, a pipe into its git
  or gh call where every other stage reads, a here-document written by cat or tee into a Write, the text of `-F -` or
  `--body-file -` and the message of `git commit -m "$(cat <<'EOF' … EOF)"` into a file named in its place, a word the
  shell may rewrite into the narrower spelling of D3) and judged every call with decide() free or one call of the closed
  list, at least one free or the rewrite one call: a detour the session takes without a person. The rewrite only
  splits, lifts and drops; every git or gh call in it stands in the command as written; every other call is a data step
  of D72 that writes nothing (no carrier, interpreter, unknown program, tee or redirection: a script a Write wrote is
  never run by a rewrite); a here-document becomes a Write only where bash expands nothing in it and the target is no
  hidden file in the work tree or the temp folder. A rewrite of several calls that are all external effects keeps the
  ask of the whole command;
- with a deny that names no way, where no rewrite is free: the call is no external effect and no form of it is free (a
  form that loses work not yet saved, rewrites history, starts git from code, writes the hooks, or any form the gate does
  not free). The text tells the session not to try another spelling and to tell the person.
A file tool whose write asks (D8) is blocked the same way. Under Codex nothing changes (D12, D37): its manifest starts
the gate without the flag, the flag changes nothing under Codex, its asks are denies as before. Started without the
flag the gate answers as decide() judges, as before Nachtrag 35: the tests of every earlier rule start it so and read
the judgement; the tests of D85 to D88 start it as hooks.json does (owner question O35-7). Nothing gets freer: an ask becomes an ask or a deny, every other answer
stays, and a failure inside D85 keeps the ask.

The answer: the deny's reason leads with the rewrite and its calls, because only the reason of a deny reaches the model
(measured with Claude Code 2.1.302, n35/messung/deny_path_summary.txt: the tool does not run, the model reads
"PreToolUse:Bash hook error: <reason>"); the same rewrite stands in a field of its own, rewriteHint (ids, text, calls),
which Claude Code accepts without reaching the model; the short line names the rewrite before the reason. The log keeps
what decide() gave as the verdict, what was sent as the decision, and the record (autonomy: klasse aussen, umweg or
sperre, the hints, the effects). Tests: tests/test_plugin_n35_autonomy_d85.py; changed: tests/test_codex_plugin.py
(the command of the Claude Code hook carries --autonomous, the Codex one does not).

## D86. The targets of a push, measured from its words and the local refs (Nachtrag 35, point 5; Nachtrag 33, point 2, 2026-10-18)

The case book of Nachtrag 33 (delta, FALLBUCH_plugin_20261018, adopted by Cowork): a forced push (f01 to f03), a mirror
(g03) and a push to main (m01, m02) are to be blocked with a reason of their own, a push that deletes a remote branch (z01,
z02) asked with one. Under Claude Code the gate asked each with push_not_measured: since R9-1 Level 1 does not resolve a
destination, because git resolves it against refs of the remote the gate does not read.

The rule: in the autonomous answer of D85, under Claude Code, an ask of decide() for one `git push` call is measured
(_push_measure) from its words, its refspecs, the push configuration git reads for a push without refspec (_default_push)
and the local refs (the full name of a source, every local branch for --all, refs/remotes/<remote>/HEAD), never the
network: whether it forces (-f, --force, --force-with-lease, --force-if-includes, a `+` refspec), mirrors, deletes (-d,
--delete, --prune, `:dst`) or sends tags, and the full refs it updates. A forced push (push_force), a mirror (push_mirror),
a push to a protected branch (push_protected: main, master, release, release/… and the branch the remote's HEAD names
here) and a push whose targets the words and the local refs do not name (push_unmeasured: a URL or path remote, a global
`-c`, a wildcard, an option D86 does not read, a refspec of no single ref, a bare push git pushes no single branch for)
are blocked. A push that deletes a remote branch asks with push_delete. A tag asks as before (H2 of D73), and so does a
push to another branch (the closed list of D85). A deny of decide() stays (D24 among them); under Codex nothing changes.
A `$( )` that names the current branch in a push (`git rev-parse --abbrev-ref HEAD`, `git branch --show-current`, `git
symbolic-ref --short HEAD`) is rewritten to HEAD by D85 (push_HEAD), which git pushes as the same branch under its own
name. Owner question O35-2: m01 and m02 are blocked as the case book says, while the list of point 1 of the order
named a push to main among the asks. Tests: tests/test_plugin_n35_push_targets_d86.py.

## D87. A push to the own work branch is free under the standing GO, once measured (Nachtrag 35, point 5, 2026-10-18)

The order: a push to an own work branch is to be free under the standing GO for work branches once it is measured.
AGENTS.md names the work branches `<agent>/<topic>`; under Claude Code the own ones are refs/heads/claude/…
(GO_WORK_BRANCH_PREFIX, owner question O35-3).

The rule: in the autonomous answer, under Claude Code, one `git push` call passes (free_work_branch_go) where every one of
these holds: decide() asked only because the destination's state on the remote is not measured (push_not_measured), and
the evidence at every commit the push sends showed no failure (Verdict.sources_clean, set where the source check ran and
no local inactivity applied); D86 measured exactly one destination under the prefix, with the branch grammar of the fetch
form, no force, mirror, deletion or tag, to a configured remote; the repository is one of D71 (its HEAD declares, every
URL of every remote is a repository of b7n0de on github.com); the push configuration adds nothing the command does not
name, the push URL is the fetch URL and GIT_NAMESPACE is unset; and the evidence rules at the commit it sends (D20,
_rules_at) equal those at every local record of the destination or, where there is none (a new branch), at the record
of the branch refs/remotes/<remote>/HEAD names. The pass shows one line to the user and carries no permission decision,
as a call a rule frees does (D25); the log keeps the ask of decide() as the verdict. A chain, a step of a chain, a push
under Codex and every push that misses one condition keep their answer. Nothing else gets freer. Tests:
tests/test_plugin_n35_work_branch_go_d87.py.

## D88. Owner clicks, detours, catches and blocks, in the log and the bilanz (Nachtrag 35, points 3 and 4, 2026-10-18)

The order: count apart the owner's clicks (asks), the detours (a deny with a rewrite, then free in the new form) and the
catches; the bilanz per lane (schema b7n0de.plugin_bilanz) carries per period owner_klicks, umwege, faenge and sperren.

The rule: a deny with a rewrite (D85) keeps in the plugin data directory (autonomy-state.json), per session by the sha256
of its id, the keys of its calls: a sha256 of the words with a hole for the output of an earlier call, and of the path of
a Write; never the words, which may name a value the gate must not keep. A later call of the same session that the gate
lets run (no answer, pass, inactive, hand-over) and whose words, or whose Write or Edit path, match a key completes the
detour once: its log line carries `umweg` with the hints and the time of the deny. At most 8 pending detours per
session and 64 sessions; a failure there never changes an answer. `proofbundle_gate.py bilanz [--log FILE] [--bahn
NAME] [--zeitraum tag|gesamt]` reads the log and its rotated part and counts per UTC day (or the whole log): the calls,
owner_klicks (asks sent under Claude Code), umwege (lines that completed a detour), faenge (asks and denies whose reasons
name a caught danger, FANG_REASONS, owner question O35-5) and sperren (denies sent), with the asks and the denies per
reason. The rest of the schema b7n0de.plugin_bilanz is Cowork's and not here (owner question O35-6).
Tests: tests/test_plugin_n35_counts_d88.py.

## D91. The local class that can be taken back is free in autonomous operation (Nachtrag 37, Ergänzung 1, 2026-10-18)

Owner word of 2026-10-18, 23:11 Berlin, with two screens of delta (gate 89d2e8b7): `git merge` of main into the own
branch with a message from a file asked (D8), and so did `git -C <absolute path> merge-tree --write-tree <sha>
refs/remotes/origin/main`; neither was a danger. Owner choice of 23:2x Berlin (A): the gate judges a command by its
effect, not by whether it can read its spelling; add, commit, merge and merge-tree, a branch or a work tree made, stash,
all in the own clone without the network, are free and stand in the gate log; a write into hooks, the configuration,
the gate directory or the declaration blocks.

Measured with git 2.43.0 under strace -f, no network, every hook of githooks(5) a marker, core.editor a marker
(n37/werkzeug/truth_local_n37.py of the delivery, 21 forms, 30 runs): `git merge` with -m, -F <file> or --file=<file>,
with and without --no-ff and -q, fast-forward or not, starts no editor on a pipe or on a terminal of script(1); it runs
the hooks of a merge commit (pre-merge-commit, prepare-commit-msg, commit-msg, post-merge, post-index-change,
reference-transaction). `git merge-tree --write-tree` with two revisions, with --name-only, --no-messages, -z and
--merge-base=<rev>, with and without a conflict, started no hook and no program and changed no path outside the object
store. `git stash pop` and `apply`, with -q, --index and stash@{0}, ran post-index-change and reference-transaction.

The rule (_autonomy_local, in the autonomous answer of D85, under Claude Code only): an ask of decide() whose every
reason is one D71 replaces (_WORK_REPLACEABLE), for a command that is one form of the local class (_local_form: the
read, local and target forms of D71, never fetch, ls-remote or gh; and in the same literal grammar `git merge` with a
message of its own and one revision, `git merge-tree --write-tree` with two revisions, `git stash pop|apply [-q]
[--index] ['stash@{<n>}']`), in any repository that does not overlap the gate directory, the declared ones of b7n0de
and every other:
- passes (free_local_reversible, klasse lokal in the log, no line to the user) where the check of its class finds
  nothing: the read profile of D34 for a read, the checkout check of D40 for `worktree add`, the state check of D40 with
  the hooks of D71 for every local form, and for merge-tree the state check with no hook counted (it starts none);
- is blocked where the form would write a configuration file or a hook (the work-tree guard of D71, decide_write for
  the target of `worktree add` and `bundle create`: write_to_repo_state) or the declaration (write_to_declaration: a
  merge or rebase whose other side changed .proofbundle/evidence.json since the merge base, a checkout or switch to a
  tree with another declaration, a stash entry that changed it);
- keeps the ask (local_program, effect "programm" of the closed list) where it starts a program of the clone the gate
  does not see: a hook git starts for the form, a filter, fsmonitor, a merge driver, a key or GIT_* name the check does
  not know. Whether such a hook may run free is owner question O37-1;
- leaves the answer to D85 where git would refuse the form (a branch that does not exist, a taken name, a target that
  exists, no stash entry): such a form changes nothing.
A rewrite of D85 counts a call of the local class as free (cd before a merge becomes `git -C <path> merge …`).

Not changed: decide() and D71 judge as before, and every answer without --autonomous and under Codex stays. add and
commit stay as D3 and D40 free them, also where a commit takes a changed declaration (owner question O37-2); a switch
or checkout that D71 frees in a declared repository of b7n0de stays free there. A form the grammar does not read whole
(an editor, standard input, two revisions to merge, merge-tree without --write-tree, an unquoted `stash@{0}`, a
strategy option) keeps the answer of D85. Limits: every measurement is with git 2.43.0; the state check reads the
state when the gate answers (D27); a Bash command that writes a hook file directly is not gated (D8) and is the class
O37-1 names. Tests: tests/test_plugin_n37_local_class_d91.py; changed: tests/test_plugin_n35_autonomy_d85.py (the closed
list carries the effect programm of D91).

## D92. A machine check in place of a click, with a receipt in the gate log (Nachtrag 37, Ergänzung 2, 2026-10-18)

Owner word of 2026-10-18, 23:11 Berlin, with two screens of delta: `git push` to the own work branch
`chore/empty-evidence-declaration` asked (D3), and so did `gh pr edit 388 -R b7n0de/proofbundle --body-file <file>` at
the own pull request (D27). Owner choice of 23:2x Berlin (A): an external action on own ground that can be taken back
is free where a check carries it, and leaves a receipt in the gate log.

The push (D87 widened, _go_source): the standing GO of D87 frees a push whose one destination D86 measured is the local
branch of the same name: a refspec `<branch>`, `<branch>:<branch>` or `<branch>:refs/heads/<branch>`, `HEAD` on that
branch, or no refspec where the push configuration names it. The branch is neither a protected one nor the default
branch, which the remote's HEAD names here and which must be recorded (refs/remotes/<remote>/HEAD), so it is measured.
Every other condition of D87 stays: a repository of D71, decide() asked only with push_not_measured after the evidence
at every commit sent showed no failure, no force, mirror, deletion or tag, the push configuration and URL add nothing,
GIT_NAMESPACE unset, and the evidence rules at the commit sent equal those of the local record of the destination or of
the remote's HEAD. The prefix refs/heads/claude/ of D87 (owner question O35-3) gives way to this: which branch is the
own one is the one the session pushes under its own name (owner question O37-3). The log carries a receipt (quittung:
art push, the destination, the remote, the commit, the checks); the user sees one line.

gh pr edit (_autonomy_pr_edit): `gh pr edit <number> [-R b7n0de/<repo>] --body-file <file> [--title <title>]` (also -F,
-t, --repo=, --body-file=; no option twice, no other option), GH_REPO absent or of b7n0de where -R is not given, in a
repository of D71, passes (free_pr_edit_form, klasse maschine, one line to the user, a receipt with the number, the
checker's blob id and the sha256 of the text) where the house's form checker passes the text, and is blocked
(pr_form_red, with the checker's reasons in its own fixed words) where it finds a red. The checker is
scripts/b7_pr_form_gate.py (b7n0de/proofbundle since PR 308) as the remote's default branch records it here
(refs/remotes/<remote>/HEAD of origin or of the one remote), never the copy in the work tree, which the session writes.
The gate writes it, the text and a small driver into a folder of its own and runs it with its own interpreter (-I),
only PATH and the locale in the environment, at most 20 seconds; the driver calls the checker's judge() with the text
as the body of a pull request and drops rule (a), the milestone, which the edit does not change. A measured red of
rule (b) or (c) blocks; where the checker is missing, fails, runs out of time or can only say NOT MEASURABLE (rule (c)
needs the CommonMark parser markdown-it-py), the answer of the last class stands (D93). The file must lie in the work
tree of the hook's directory or in the temp folder, with no part of its real path below that place starting with a dot
(so never ~/.ssh), be a regular file, no link, of at most 256 KiB and UTF-8. A title alone stays as D71 frees it.

Measured (n37/messung/house_form_n37.jsonl): the checker of origin/main (blob c91589b5) through the gate's
_house_form_judge, with markdown-it-py 4.2.0, gave green for a body in the house form, and "(b) the description does
not end with exactly the two lines of the house footer", "(c) the description carries a tool attribution" and "(c)
the description carries a session link" for the three counter bodies; with the system interpreter of this container,
which has no markdown-it-py, it gave the (b) red and NOT MEASURABLE for the others.

Not measured: whose pull request the number names (the gate calls no network; owner question O37-4); whether delta's
interpreter has markdown-it-py. Limits: the checker is code of the repository's default branch as recorded here; a
record a session rewrites by hand through Bash is the D27 class. Under Codex and without --autonomous nothing changes.
Tests: tests/test_plugin_n37_machine_check_d92.py; changed tests of this delivery: tests/test_plugin_n35_push_targets_d86.py
and tests/test_plugin_n35_work_branch_go_d87.py (`git push origin topic` passes, `claude/x:claude/y` asks, the short line
names D92).

## D93. A card in the Leitstand in place of an ask in the terminal, in the work profile of b7n0de (Nachtrag 37, Ergänzung 3, 2026-10-18)

Owner word of 2026-10-18, 16:52 Berlin: no options in the terminal. Owner choice of 23:2x Berlin (A): for the closed
list of D85 the gate does not ask in the terminal in the work profile of b7n0de but blocks with the hint to put a card
in the Leitstand; outside b7n0de the ask stays, as there is no Leitstand; how the profile is recognised the session
sets and measures, and without a measurement the general behaviour holds.

The profile: the repository condition of D71 (_work_repo_problem), read without the network: under Claude Code, a
declaration the gate reads at HEAD, every URL of every remote, for fetch and for push with insteadOf and pushInsteadOf
applied, https://github.com/b7n0de/<repo>, and no overlap with the gate directory. The repository is the one the
literal absolute `-C` of a single git call names, else the hook's directory. Measured in
tests/test_plugin_n37_card_d93.py: a declared repository of b7n0de is in the profile; a repository of another owner, one
without a declaration, one without a remote, one with an ssh remote, one with a second remote of another owner, a push
URL of another owner and an insteadOf onto another owner are not.

The rule (_autonomy_card, after D85 to D92, under Claude Code with --autonomous): an ask of the closed list (klasse
aussen) whose effects are not only the programm of D91 becomes, in the profile, a deny (autonomy_card, klasse karte, the
effects kept in the log) whose reason names the effect and tells the session to put a card in the Leitstand that names
the command, what it does outside and why, and to wait for the owner's answer there, without another spelling of the
call. The ask of a program of the clone (local_program, D91) stays an ask also in the profile (owner question O37-1).
Outside the profile, where the profile cannot be read, under Codex and without --autonomous the ask stays. Nothing gets
freer: an ask becomes a deny. A card counts as a block in the bilanz (D88) and of its own (D94).

How the card reaches the Leitstand is Cowork's: the gate names it and blocks; it writes no card and calls no network.
Tests: tests/test_plugin_n37_card_d93.py; changed tests of this delivery: tests/test_plugin_n35_autonomy_d85.py and
tests/test_plugin_n35_push_targets_d86.py (the asks of the closed list are read in a repository of another owner),
tests/test_plugin_n35_work_branch_go_d87.py (its asks in the profile are cards), tests/test_plugin_n35_counts_d88.py (the
push to topic is a card: 0 clicks, 4 blocks).

## D94. The answers to the asks per reason, and the candidates to free (Nachtrag 37, Ergänzung 4, 2026-10-18)

Owner word of 2026-10-18, 23:2x Berlin: the functionality, but no needless constant asks most users wave through with
yes. Owner choice (A): the bilanz of D88 counts per reason id how often an ask was answered yes and how often no and
whether it ever caught something; a reason with nearly only yes and no catch over a period the session proposes appears
as a candidate to free, as an owner question; the gate frees nothing itself.

Measured with Claude Code 2.1.302 on a pseudo terminal, a fresh HOME, the stand-in API on the loopback, no network
(n37/werkzeug/ask_answer_n37.py of the delivery; a PreToolUse hook that asks, a hook on every other event that logs it):
after a yes in the dialog Claude Code sent PermissionRequest (without a tool_use_id), then PostToolUse with the
tool_use_id of the PreToolUse event, PostToolBatch and Stop; where the command failed, PostToolUseFailure in place of
PostToolUse with the same id; after a no (Escape) it sent no event for the call, no PermissionDenied either.

The rule: with --autonomous, under Claude Code, the gate keeps for every ask it sends the key of its tool_use_id (the
first 32 hex digits of its sha256; the store never holds the id) with the time and the reasons in the plugin data
directory (asks-pending.json, at most 256, the oldest dropped, under a lock), and writes the key into the log line
(frage). A hook of its own, hooks/proofbundle_answered.py, runs on PostToolUse and PostToolUseFailure for the matchers of
the gate's PreToolUse hooks: where the event's tool_use_id has a kept key it removes the key and appends one line to the
gate log (decision answered, antwort ja, the key, the reasons, the time of the ask). It is a file of its own so that the
hook after every gated call loads only the standard library; it prints nothing, calls no network, and every failure
ends with exit 0 (`|| true` in hooks.json besides), so it never blocks or fails a call. The gate loads its helpers from
the same file. The Codex manifest has no such hook.

The bilanz (`bilanz`, D88): an ask with a key is ja where an answer line names it, nein where its session made a later
call or the newest line of the log is an hour after it, else offen; an ask without a key (older lines, no tool_use_id)
counts as ohne_schluessel. Per period and reason: fragen, ja, nein, offen, ohne_schluessel and fang (the reason is one
of FANG_REASONS); per period also karten (the denies of D93); the answer lines are no calls. kandidaten_zum_freigeben:
over the last 14 days of the log, every reason not in FANG_REASONS with at least 20 answered asks of which at least 95 %
were yes, with ja, nein and ja_quote, each owner question O37-5.

Limits: a no and a yes after which Claude Code never ran the call (a crash, the session ended) read alike; the measure of
yes is the call that ran. A tool_use_id of two calls is not one the gate tells apart. Tests: tests/test_plugin_n37_answers_d94.py.

## D98. The fetch of a local bundle into refs/remotes/beilage/ is free (Nachtrag 40, B40-1, 2026-10-19)

Found by delta at f9e5f18e (20261019T0819Z, card OA-f4a38d2ac0): under the switch of D85 the gate blocked, with no free
way and no card, `git -C <clone> fetch -q <local bundle> refs/heads/<branch>:refs/remotes/beilage/<name>`
(remote_read_not_modeled). Every order to delta brings its heads as a bundle; before D85 that cost a click, under D85 a
block only the owner can lift at the terminal. Order: free, with no transport helper, no upload-pack and no network; catch
cases at least a folder in place of the file, ext:: and every other transport form, a symbolic link as the bundle, a
target outside refs/remotes/beilage/, a `+` before the refspec, a foreign refspec among several, --upload-pack, and -c
before fetch.

Measured with git 2.43.0 under GIT_TRACE2_EVENT and strace -f, every hook of githooks(5) a marker in a fresh clone, no
network (n40/werkzeug of the delivery, truth_b40.py, 24 forms): the fetch of a regular bundle file of version 2 or 3 by
its absolute path started git's own programs and the hook reference-transaction (twice) and nothing else, connected
nowhere and wrote the tracking ref the refspec names (no tag, also from a bundle with tags); fetched again, it changed
nothing and started no hook. http.proxy, a credential helper, core.sshCommand, core.askPass, HTTPS_PROXY, GIT_SSH,
GIT_SSH_COMMAND, GIT_ASKPASS, SSH_ASKPASS, another remote's proxy and hook files git does not start (pre-push.local,
pre-commit.local) started nothing for it, and --upload-pack was ignored (a warning). A folder in the bundle's place, and a
url.<base>.insteadOf whose value was the bundle's path, made git start git-upload-pack through a shell; core.fsmonitor set
to a program started it; a symbolic link to the bundle was followed; a remote named as the path was ignored with a
warning. Without a refspec the fetch failed (no HEAD).

The rule: `git -C <literal absolute path> fetch [-q|--quiet] [--no-tags] <absolute path> <ref>:refs/remotes/beilage/
<name>…`, as the whole command with no prefix assignment, no redirection and no other global option, every word
literal, is free under Claude Code (free_bundle_fetch) where
- the path lies in no folder named .ssh, as written and once resolved, and names a regular file, no symbolic link, whose
  first 16 bytes are the signature of a git bundle (`# v2 git bundle` or `# v3 git bundle`); the gate reads those bytes
  and nothing else of it (_bundle_file_problem);
- every refspec is a ref name without `+`, glob, `^`, `..` or `@{` to a name under refs/remotes/beilage/ that git accepts
  (_bundle_fetch_form);
- the bundle check of the repository finds nothing (_bundle_fetch_problem): the fetch profile of D45 without what a bundle
  does not reach, that is no promisor key, no fsmonitor git does not read as false (D74 for git's own daemon), no
  url.<base>.insteadOf without a value or with one that is a prefix of the path, no remote named as the path, no hook
  reference-transaction or pre-auto-gc (by name in lower case, B36-3), no submodule unless fetch.recurseSubmodules reads
  false, and no other key or GIT_* name the fetch profile does not know.
Every other form keeps its answer: the ask of D41 (remote_read_not_modeled) with what the check found, the block of D85
under the switch. Under Codex the fetch keeps the ask of D41, as the fetch of D45 does. As a step of a longer command it
keeps the whole command's answer (_ShKeep), as ls-remote does (D59).

Limits: the file can change between the gate's check and git's run; the check reads it once. A bundle with prerequisites
the clone lacks makes git fail, which changes nothing. Measured with git 2.43.0 only; git 2.34.1 at the farmer is NOT
MEASURED. Tests: tests/test_plugin_n40_bundle_b40.py.


## D99. The heads of a bundle and the state of git's own fsmonitor daemon are reads (Nachtrag 40, B40-2 and B40-3, 2026-10-19)

Found by delta at f9e5f18e: `git -C <clone> bundle list-heads <bundle>` and `git fsmonitor--daemon status` were blocked
under the switch (possible_unmodeled_push); `git -C <clone> bundle verify <bundle>` ran free (D91). Order: list-heads and
verify of a file are reads; fsmonitor--daemon status is a read, start, stop and run are not.

Measured with git 2.43.0 (truth_b40.py): `bundle list-heads <file>`, inside a repository and outside, and `bundle verify
[-q] <file>` started git only (verify a second git for the connectivity check), no hook, and wrote nothing;
`fsmonitor--daemon` status, start, stop and run exited 128 on this platform ("not supported on this platform"), started
nothing and wrote nothing. git added the daemon in 2.36; on an older git such as delta's 2.34.1 the word
`fsmonitor--daemon` is no built-in command, and git runs an alias of that name or a program git-fsmonitor--daemon on PATH
in its place (gitcli, read, not measured on 2.34.1).

The rule: `git bundle list-heads <file>` (one file, not `-`, no option) joins `git bundle verify` as a read form of D71
and of the local class of D91, and so does `git fsmonitor--daemon status` (status alone); both are free where the read
profile of D34 finds nothing, and the read profile frees fsmonitor--daemon only where the git on PATH lists it among its
built-in commands (`git --list-cmds=builtins`, _git_builtin). The same question now comes before the gate's own probe of
D74: _fsmonitor_known runs `git fsmonitor--daemon status` only on a git that has it built in, else the person's
core.fsmonitor counts as it did before D74.

Limits: list-heads with ref names, list-heads or verify of standard input, and the daemon's other subcommands keep their
answer. Under Codex both keep the ask of D41. The forms are free under the switch (D91) and in the work profile of D71,
not by decide() alone. Tests: tests/test_plugin_n40_bundle_b40.py.
## D95. A data step that writes a file is a write, read as getopt reads its words (Nachtrag 37, point 4, and Nachtrag 39, F35-3, 2026-10-19)

Order (B37-1, B37-2): a data step that writes a file counts as writing, read as getopt reads it (bundled short options,
a value directly at the option, abbreviations of long options, `-` and `--` as operands), measured with GNU coreutils 9.4
and 8.32; every program of _SH_DATA that can write a file checked, built or not affected, with a measurement; a write
into `.git/hooks`, `.git/config` or the gate's directory carries the weight of _D72_WRITES. Measured by Cowork at
89d2e8b7 and 9e0d071b under Claude Code without an ask: `sort -uo <file>` and uniq with an output file as its second
operand write the file, into `.git/hooks` and `.git/config` too; the lines of _sh_changes_state read only words that
start with `-o` or `--output` and operands that do not start with `-` (135f9f9f, class c). Nachtrag 39 (F35-3): a data
step with an effect is no read (`date -s`, `sort -T`, `sort --compress-program`, the siblings in _SH_DATA); found in
PLUGIN_N35, where `date -s 2020-01-01 && git status` was free.

Measured with GNU coreutils 9.4 under strace -f, one empty folder per form, no network (n37b/werkzeug of the delivery:
truth_data_writes_n37.py, 70 forms, and truth_getopt_n37b.py, 121 forms; date only as the user nobody with an empty
capability set and EPERM injected into every call that sets the clock, so no form could set it):
- sort writes the file of every -o as getopt reads it (`-uoF`, `-uo F`, `--o=F`, `--outp F`, `F` after the operands);
  `-` is a file there, not the standard output; `-t -o`, `-k -o`, `-to` and `-- -o` write nothing (the option takes the
  word, or it is an operand); `+POS1 -POS2` is a key; from a large input it writes temporary files `sortXXXXXX` into
  the folder of -T (in every spelling, `--t=` and `--te=` included) or of TMPDIR; an abbreviated --compress-program
  (`--compress-p=`, `--co=`, `--co P`) starts the program, `--c=` is ambiguous and starts nothing; `-y` takes an
  attached value and a following word only of digits.
- uniq writes its second operand unless it is `-`; the obsolete `+N` is an option before `--` and a file after it, and
  under POSIXLY_CORRECT every word after the first operand is a file (`uniq IN -c` writes `-c`).
- tee writes every operand, `-` included, and every word after `--` (`tee -- -x` writes `-x`).
- tac writes `cutmpXXXXXX` into TMPDIR when its input is a pipe.
- date calls clock_settime for -s, --set, --se, -us and an operand that is no `+FORMAT` (`date 0101000020`).
- Every other program of _SH_DATA (echo, printf, cat, head, tail, grep, rg, wc, cut, tr, nl, column, jq, fold, fmt, rev,
  ls, pwd, basename, dirname, realpath, readlink, stat, sleep, seq, expr, comm, join, paste, the sum programs, cmp,
  diff, du, df, id, whoami, uname, printenv, which, test, sed and awk in their data forms, find without an action)
  opened no file for writing in the forms measured: not affected. sed with -i or a w command, awk with output into a
  file and find with an action were carriers before D95 and stay so.
GNU coreutils 8.32 is NOT MEASURED: no such program in this container, no network.

The rule: _GETOPT_SPECS holds for sort, uniq, tee and date the short options as getopt's string and the long options
with the option each stands for, as measured; _getopt_read reads the words as GNU getopt_long does (a bundle letter by
letter, a value attached or the next word, a long option by its name or by a prefix that names one option or several
that stand for the same option with the same kind of value, `-` an operand, `--` ends the options, under POSIXLY_CORRECT
the first operand ends them for uniq and tee). _getopt_writes gives the files the step writes: the outputs of every
reading the hook's environment may hold (default, POSIXLY_CORRECT, the strict obsolete `+N`), the temporary files in the
folder of -T or of a TMPDIR assignment before the step (sort, tac), and, where a word is not literal or getopt would
refuse an option, every word that may be a file. These files join the step's redirections in write_targets: each is
judged as a file-tool write (decide_write), so a write into the configuration or the hooks asks (write_to_repo_state)
and one into the gate's directory is denied (write_to_gate_dir), alone and in a chain, with the weight of _D72_WRITES
on the line. _getopt_kind makes the step no data step where date sets the clock (other), where sort starts a compress
program in any spelling (carrier), and where a word is not literal or getopt refuses an option (other). The old rules
stay: an -o word of sort or two operands of uniq change the state, the full --compress-program is a carrier; the reading
of getopt adds every other spelling of the same.

Limits: a TMPDIR the session's environment holds, not the command, is not read (the gate reads no value of the hook's
environment for this). A file a program writes because a word the shell builds names it is not judged, as for a
redirection the shell builds (D33), except `~/x` and `$HOME/x`, which D96 names; the step is no data step, so a git
step after it is not free. A copy command (cp, mv, install, ln) is no data step; D96 judges its words. Tests:
tests/test_plugin_n37_data_writes_d95.py.

## D96. A program the gate does not model writes what its words name (Nachtrag 39, F35-1, 2026-10-19)

Order: a Bash command that writes into the hook folder (`cp`, `mv`, `tee`, `install`, `ln`, a redirection) carries the
weight of _D72_WRITES. Found in PLUGIN_N35 (F35-1): `cp <file> <repo>/.git/hooks/pre-commit` got no answer at 9e0d071b
and f9e5f18e; only a file tool (Write, Edit) asked. The class: every program of the shell the gate does not model that
writes, removes or re-modes a file by a path one of its words names, and every word the shell turns into such a path.

Measured with GNU coreutils 9.4 and curl under strace -f, one empty folder per form, no network (n39/werkzeug of the
delivery, truth_path_words_n39.py, 35 forms): cp, mv, install, ln, dd, touch, truncate, rm, chmod, mkdir, curl -o, tar
-cf and patch -o each create, change, remove or re-mode the path one of their words names or a file in that folder, in
every spelling (`-t DIR`, `-tDIR`, `--t=DIR`, `of=OUT`, `-oOUT`, `--output OUT`); mv removes its source; cat and ls
change nothing. rsync is not in the container (NOT MEASURED).

The rule: for a step of a program the gate does not model (other) and for a carrier, every path its words name is judged
as a file-tool write (decide_write), each the way bash makes it (_sh_word_path): a literal word; a tilde at its start
with a literal rest, for the session's HOME or a user's home from the password database; `$HOME` or `${HOME}` at its
start, quoted or not, with a literal rest, from the hook's environment, which is the session's; a glob in its last
component only, which names files in that folder. Of a literal word also each value after `=` and each rest of a short
option bundle count (_sh_path_words). The same naming holds for a redirection and for the outputs of the data steps of
D95, so `cat > ~/.x` is judged where it was not known before. A write into the configuration or the hooks asks
(write_to_repo_state), one into the gate's directory is denied (write_to_gate_dir), and the line gives the write its
weight (D72). Class c judges the writes of the steps first (_sh_write_verdicts) and a command that keeps the whole
command's answer (_ShKeep, a word the shell builds) carries them (_sh_with_writes): the stricter decision, the verdicts
of both. The state files of a folder are read once per command (_STATE_FILES_MEMO).

Cost, named: the gate does not know whether such a program reads or writes, so `cp .git/hooks/pre-commit.sample /tmp/x`
and `cp ~/.bashrc /tmp/x` ask as a copy into them does. A program that runs code (python3 -c, bash -c) writes what its
code says, which the gate does not read (D8). After `cd` a relative path is not judged (D33, class e not built). Tests:
tests/test_plugin_n39_path_words_d96.py.

## D97. A write into a file the shell runs before a later call (Nachtrag 39, F35-2, owner question O38-1, 2026-10-19)

Order: a write into the snapshots of the shell of Claude Code, into the start files of bash and into a file BASH_ENV
names carries the weight of _D72_WRITES; first measure which files Claude Code runs before a Bash call. Found in
PLUGIN_N35 (F35-2): `cat > ~/.bashrc <<'EOF' … EOF` got no answer; owner choice O38-1 (19.10.2026): close the class of
O34-1 at the write, not at the arithmetic.

Measured with Claude Code 2.1.303 and GNU bash 5.2.21 under strace -f (execve, openat), a fresh HOME whose start files
append their names to a marker log, the stand-in API on the loopback with two Bash calls, no network, with and without
BASH_ENV (n39/werkzeug of the delivery, truth_shell_start_n39.sh): before every Bash call bash reads /etc/bash.bashrc
(and what it sources), ~/.bashrc and the snapshot; when Claude Code makes the snapshot, once per session, bash also reads
/etc/profile, the files of /etc/profile.d, ~/.bash_profile (the first of it, ~/.bash_login and ~/.profile) and the file
BASH_ENV names, which the calls after it do not read. Claude Code 2.1.302 is no longer in this container (NOT MEASURED).
Read, not measured: the start files of zsh (none installed) and ~/.bash_aliases, which the .bashrc of Debian and Ubuntu
reads.

The rule: decide_write names a write into one of these files, through a symbolic or a hard link too, or into a file of
the snapshot folder (CLAUDE_CONFIG_DIR/shell-snapshots, else ~/.claude/shell-snapshots), /etc/profile.d or /etc/zsh, as
write_to_shell_start (_shell_start_problem): an ask under Claude Code (a deny under the switch of D85), with the weight
of _D72_WRITES on the line and as a catch in the bilanz (FANG_REASONS). It holds for the file tools and for every write
class c finds in a command (redirections, D95, D96). The gate reads names of the environment (HOME, ZDOTDIR,
CLAUDE_CONFIG_DIR, BASH_ENV) and paths, never a file's content.

Limits: a relative BASH_ENV is not read (the shell's folder decides it). A file a start file sources by another name is
not named, but ~/.bash_aliases. The settings of Claude Code (~/.claude/settings.json) are no start file of the shell
(passages w01 and w02 of satz_v1, Nachtrag 33). Tests: tests/test_plugin_n39_shell_start_d97.py.

## D100. A path the command spells out itself is judged as a literal one (Nachtrag 39, the siblings of F35-1 and F35-2, 2026-10-19)

Order of Nachtrag 39: a Bash command that writes into the hook folder, and one that writes a start file of the shell,
carries the weight of _D72_WRITES, as a class with its siblings. Measured at the head of D97 (n39/werkzeug of the
delivery, siblings_n39.py, 26 forms): D96 and D97 judged `cp f.txt .git/hooks/pre-commit`, but `bash -c 'cp f.txt
.git/hooks/pre-commit'`, `sh -c 'echo x > .git/hooks/pre-commit'`, `R=.git/hooks; cp f.txt $R/pre-commit` and
`cp f.txt .git/hook{s,x}/pre-commit` got no answer there, as at f9e5f18e.

Measured with GNU bash 5.2.21 and dash as sh, an empty folder per form with HOME in it, no network (truth_siblings_n39.py,
25 forms): the script of `bash -c`, `bash -lc`, `bash -c --`, `sh -c`, `env bash -c` and of eval (one word or several)
wrote what it says, nested too; a variable a step of the command set alone (`R=DIR;`, `R=DIR &&`), with export or with
declare wrote where `$R/x`, `"$R/x"` and `${R}/x` name, a value `~/x` or `$HOME/x` from HOME; a brace wrote each word bash
makes of it (`{q,r}`, `s{1..3}`, `{t,u{v,w}}`, `~/.{a,b}`), `x{y}` was a name. A prefix assignment (`H=DIR touch ./$H/o`)
and one in a subshell did not reach the word. Added after the mutants of D100 (30 forms): a script the outer shell
expands first wrote where the expansion points (`bash -c "touch $HOME/DIR/x"`, `eval "touch $HOME/DIR/x"`,
`R=DIR; sh -c "touch $R/x"`), and an unquoted value with a blank was split into two files (`F='a b'; touch $F`), a quoted
one was not.

The rule: class c judges, as the command's own steps and in the step's directory, the steps of the script of a shell of
_SHELL_DASH_C run with -c (named by any word of a step the gate does not model, so behind env or sudo too) and of eval,
to a depth of MAX_NESTING (_sh_nested_steps); an expansion in that script is read as written, which the outer shell
expands first with the same values, so the reading is the same or stricter; a word `$X/rest`, `${X}/rest` or `"$X/rest"` of a
variable the command sets in a step of assignments only or with export, declare, typeset, local or readonly names each of
its values with the rest, an unquoted value also split into its fields (_sh_line_values, _sh_word_paths); a word with
braces and no quote or substitution names each word of its brace expansion, at most _SH_BRACE_MAX (64), a range longer
than that none (_sh_brace_expand). Each such path is judged as D96 and D97 judge one (decide_write): an ask, a deny into
the gate's directory, the weight of _D72_WRITES on the line; the step that runs the script is the one that writes.

Limits, named: a variable the command does not set and one with a default (`${X:-y}`), a script that is only a
substitution or a variable the gate cannot name (`bash -c "$CMD"`), the code of another language (python3 -c, perl -e, an awk program), what xargs reads from its input, and a relative path after
cd (D33) keep their answer; an assignment in a subshell counts, which is stricter than bash. Tests:
tests/test_plugin_n39_path_siblings_d100.py.

## D101. A write into the settings of the host is denied (Nachtrag 33, fallbook w01 and w02, 2026-10-19)

Order of Nachtrag 33, point 1: Edit and Write on the settings of the host are denied, under Claude Code and Codex, for
the account and the project. Found by delta's fallbook (gate 44db2056): `Edit` and `Write` on the settings got no
answer under Claude Code; measured again at 63b88d07 (n33/werkzeug of the delivery, probe_n33.py): no answer for the
file tools and for `echo '{}' > ~/.claude/settings.json`.

Measured with Claude Code 2.1.303, the stand-in API on the loopback with one Bash call, a fresh HOME, no network
(truth_host_n33.sh settings): in each candidate file a hook that names the file; the hooks of ~/.claude/settings.json,
<project>/.claude/settings.json and <project>/.claude/settings.local.json ran, the one of ~/.claude/settings.local.json
did not; under strace Claude Code also read ~/.claude.json, ~/.claude/settings.local.json,
/etc/claude-code/managed-settings.json and the folder managed-settings.d beside it, <project>/.mcp.json, whose servers it
starts, and the plugins under ~/.claude/plugins, whose hooks it runs. Codex is not in this container: its folder
(CODEX_HOME, else ~/.codex) and the .codex folder of a project count whole, read, not measured.

The rule: decide_write denies a write into one of these files or folders as write_to_host_settings
(_host_settings_problem), under both hosts and before the host split, so Codex names this reason and not the unbound
write of R7-6: the account files under CLAUDE_CONFIG_DIR or ~/.claude (settings.json, settings.local.json, .claude.json)
and ~/.claude.json, the folder of the plugins, the folder of Codex, the folders of managed settings, and wherever it
stands a file `.claude/settings.json`, `.claude/settings.local.json` or `.mcp.json` and every file in a folder `.codex`.
The path counts written and resolved, a hard link to an account file too, as for D97. It holds for the file tools and for
every write class c finds in a command (redirections, D95, D96, D100), with the weight of _D72_WRITES on the line and
as a catch in the bilanz (FANG_REASONS). The gate reads names of the environment and paths, never a file's content.

Limits, named: a copy out of a settings file (`cp ~/.claude/settings.json /tmp/x`) is denied too, since D96 reads no
direction of cp (owner question O39-2); the plugins folder of a plugin loaded from elsewhere (`--plugin-dir`) and the
files a hook of the settings runs are not named; the plugin's own .mcp.json in a checkout of proofbundle is a settings
file by its name. Tests: tests/test_plugin_n33_host_settings_d101.py.

## D102. A call that names a key file, a credential store or a folder of keys is denied (Nachtrag 33, fallbook l01 and l02, 2026-10-19)

Order of Nachtrag 33, point 1: a matcher for Read, and reading key paths in Bash denied; the gate compares paths only,
it never opens such a file. Found by delta's fallbook (gate 44db2056): `Read <key>` reached no hook of either host, and
`cat <key>` got no answer; measured again at 63b88d07 (probe_n33.py): the same, and `base64 < ~/.ssh/id_ed25519` too.

The rule: proofbundle_secrets.py beside the gate names the key paths by role: a folder `.ssh` or `.gnupg` anywhere in a
path and every file in it; a store of credentials by its last parts (`.netrc`, `.git-credentials`, `.aws/credentials`,
`.config/gh/hosts.yml`, `.docker/config.json`, `.kube/config`, `.pypirc`, `.npmrc`, `.claude/.credentials.json`,
`.codex/auth.json`, the two files of gcloud); a private key of ssh by its name (`id_rsa`, `id_ed25519` and their kin); a key
file by its ending (`.key`, `.pem`, `.p12`, `.pfx`, `.ppk`, `.jks`, `.keystore`) unless its name says it is public
(`.pub`, `public`, `cert`, `.crt`, `chain`). A path counts as written and after the links it goes through; the walk
stops before it touches a part that is a key path, so the gate never stats, lists or opens anything in a folder of keys.

The hook of Read and Grep (hooks.json, matcher `^(Read|Grep)$`) runs proofbundle_secrets.py on its own: it lets every
other read pass without starting the gate (measured with Python 3.13: 39 ms a call, the gate 350 ms, most of it the
compilation of the gate), and it hands a key path, or an event it cannot read, to the gate, which denies it as
secret_path, logs it and writes the short line (decide_read). In Bash, every word, assignment and redirection of every
step, the steps of a script a step runs as text included (D100), that names such a path is denied under both hosts, as
a house rule is (_guard_secret in _with_house_rules); ls, test and [ count by their redirections only, since they only
name or test a path. A tilde after `=` counts as at the start of a word, which is stricter than bash. Where the parser
does not model the command, every word of the net's normal form counts. Without proofbundle_secrets.py beside it the
gate denies every Bash call (GateError). A reason names the word as the command wrote it and the role, never a path
HOME decides (D49).

Limits, named: Codex has no Read tool, its reads are Bash calls; a key under another name and ending is not named;
`cat ~/.ssh/id_rsa.pub` and `ssh -i <key>` are denied, being in the folder; a word that only mentions `.ssh/` as text
(`grep -rn .ssh/ src`) is denied; the code of another language (python3 -c) is not read (D8). Tests:
tests/test_plugin_n33_secret_paths_d102.py.

## D103. Sending a file or data to a host outside asks (Nachtrag 33, fallbook c01 and c02, 2026-10-19)

Order of Nachtrag 33, point 1: an upload to a foreign host asks, over a closed list of forms (such as `curl -F`,
`--data*`, `-T`, `wget --post-*`, scp and rsync to a foreign host); fetching stays free. Found by delta's fallbook (gate
44db2056): `curl -F <file> <url>` and `curl --data-binary <file> <url>` got no answer under either host; the same at
63b88d07 (probe_n33.py).

The rule: _upload_form reads a call of curl, wget, scp or rsync, behind a wrapper (sudo, env, timeout and the others of
D73) and in a script a step runs as text (D100) too. curl sends with -F, -d or -T, in a bundle of short options too, or
with --form, --form-string, --data, --data-ascii, --data-binary, --data-raw, --data-urlencode, --json or --upload-file;
wget with --post-data, --post-file, --body-data, --body-file, or a --method of POST, PUT or PATCH; scp and rsync where the
last operand names a path on a host (`[user@]host:path`, `host::module`, `scp://`, `rsync://`) and an earlier one is
local. A host other than the loopback, or one the gate cannot read from a word with `://` (a variable, a host without
a scheme), makes the call an upload_to_host: an ask under Claude Code, which in autonomous operation stays an ask of the
owner (the effect `upload` of AUTONOMY_EFFECTS, and a card in the profile of b7n0de, D93), a deny under Codex. The forms
are read from the manuals of curl 8, wget 1.21, OpenSSH scp 9 and rsync 3, not measured with strace: this container has
no host to send to.

Limits, named: nc, ftp, sftp, the clients of clouds (aws s3, gsutil), `gh gist create` and code of another language that
sends are not read; an upload to the loopback without a scheme (`localhost:8080/x`) asks; `curl -X POST` without a body
is no upload. Tests: tests/test_plugin_n33_upload_d103.py.

## D104. A recursive delete or an append outside the work folder is denied (Nachtrag 33, fallbook r01 and S9, 2026-10-19)

Order of Nachtrag 33, point 1: recursive delete and append outside the work folder are denied; the work folder is the
repository of cwd and the scratch of the session, further ones only from a declaration with names; measure on the corpus
first which targets occur today, and name every new ask. Found by delta's fallbook (gate 44db2056): `rm -rf <path>` and
`python3 <script> >> <audit log>` outside got no answer; the same at 63b88d07.

Measured before the rule (n33/werkzeug of the delivery, ziele_n33.py): the corpus (435 commands) has no `rm -r` and six
appends, all to a relative path in the repository; the 4846 Bash commands of the session that built this delete
recursively 211 times in its scratch, 94 times through a variable of it, 60 times by a relative path and three times in
another place of /tmp (one a probe of its own, two the fallbook's forms written into a file), and append 137 times
relatively, 67 times into the scratch, once to /dev, twice to /tmp and five times to ~ (the fallbook's and D97's forms).
Measured with Claude Code 2.1.303 (truth_host_n33.sh hint env): the hook's environment carries CLAUDE_PROJECT_DIR and
CLAUDE_CODE_SESSION_ID and no TMPDIR, and Claude Code keeps a folder of the session at
<temp>/claude-<uid>/<project>/<session id>/.

The rule: _guard_outside denies, under both hosts, `rm` with -r, -R or --recursive and `find … -delete` whose target is
not in a work folder or is the root of one (delete_outside_work), and an append (`>>`, `&>>`, `tee -a`) into a file not in
a work folder (append_outside_work). The work folders (_work_folders): the repository of the step's directory, found by
its .git without running git; the repository, else the folder, of CLAUDE_PROJECT_DIR; the folder of the session under
the temp folder where CLAUDE_CODE_SESSION_ID names one; and each folder the file work-folders.json in the gate's
directory names with a name (schema proofbundle-plugin/work-folders/v0.1, `{"ordner": [{"name": …, "pfad": …}]}`), which
only a person writes (D25); an entry without a name or an unreadable file names none. A delete counts after the links of
its folder, an append also after the link of the file. /dev/null, /dev/stdout, /dev/stderr, /dev/tty and /dev/fd/* open
no file.

Limits, named: a step whose directory the gate cannot tell (after a `cd` it does not resolve, D33), a word it cannot
name (`rm -rf "$X"/y` with X not set in the command), the code of another language and xargs keep their answer; a write
with `>` outside is no append and gets the hint of D105 at most. Tests: tests/test_plugin_n33_outside_work_d104.py.

## D105. A hint is a pass with a line and a context for the model, never an ask (Nachtrag 33, fallbook S6 and S8, 2026-10-19)

Order of Nachtrag 33, point 1, and reading 2 of Cowork: S6, S8 and S10 are hints, the call goes on with a message to the
agent and no ask; measure which way brings the message into the context of the agent. Found by delta's fallbook: `mv`
took the manifest out of the package where cp was meant (S6), and a here-document went to /tmp, which is not the
scratch of the session (S8).

Measured with Claude Code 2.1.303 and the stand-in API (truth_host_n33.sh hint, one PreToolUse hook per variant, no
permission decision): additionalContext reached the model, as a system message after the tool's result, and the call
ran; systemMessage, plain stdout and stderr did not reach the model; the additionalContext of a PostToolUse hook did,
after the call. Claude Code 2.1.302 is no longer in this container (NOT MEASURED).

The rule: _guard_hints gives a pass with hint_move_out where `mv` (behind a wrapper too) takes a file of the repository
out of it, and, where the hook's environment names a session of Claude Code, hint_tmp_not_scratch where a step writes
(a redirection, a data step of D95, the target of mv, cp or install) into /tmp or the temp folder outside the folder of
the session and the other work folders of D104 (a repository that lies in /tmp is one). The hook prints the short line as systemMessage and the long reason as additionalContext, no
permissionDecision (pre_tool_answer); a hint stands beside an ask or a deny of the same call and never changes it. The
log names the hint's reason. S10 is no rule: the fallbook writes its form without the redirection it speaks of (owner
question O33-4).

Limits, named: Codex shows a hint as Codex shows a warning (D12), not measured; a move of a file the index does not
track counts as one of the repository. Tests: tests/test_plugin_n33_hints_d105.py.

## D106. A hook of the own clone is free where the owner recorded the hook state (Nachtrag 41, O39-1, 2026-10-19)

Order of Nachtrag 41, point 1 (owner answers of 2026-10-19 14:5x Berlin, O39-1 and O37-1 as recommended): a hook of the
own clone is free where the owner recorded the hook state; the forms of delta, `git add`, `git commit` and `git merge`
of main in the own work clone with a pre-commit hook, under the flag; caught at least a changed hook, a new hook,
core.hooksPath on a foreign folder and a hook as a link. Found by delta's card OA-4d2e5b284c (PR 328): at 63b88d07,
under `--autonomous` with a pre-commit hook, `git add` was blocked (D3 asks, no form of D91, no rewrite:
autonomy_blocked), and `git commit` and `git merge -F <file> main` kept the owner's ask (local_program of D91).

Measured at 63b88d07 (n41/d106/probe_base.py of the delivery, git 2.43.0, three repositories): without a hook every
form of the list is free; with a pre-commit hook add is blocked and commit and merge ask, in the declared repository of
b7n0de and in the others alike. A bare `git merge main` is blocked with and without a hook: it is no form of D91 (an
editor on a terminal), and D106 does not change that (owner question in the report).

The rule: the file hook-state.json in the gate's directory, which only a person writes (D25: decide_write and the
redirections of a Bash step into the gate directory are denied, write_to_gate_dir), records clones,
`{"schema": "proofbundle-plugin/hook-state/v0.1", "klone": [{"pfad": <absolute path>, "haken": {<name>: <sha256>}}]}`;
`proofbundle_gate.py hook-state <path>` prints the entry of a clone as it is now and writes nothing. A file that does
not read whole records nothing: no regular file, more than 64 KiB, a repeated key, another schema, another key, a
relative path, a hook name of another shape, a value that is not 64 lower-case hex digits. In autonomous operation
(Claude Code with the flag, D85), and only for `git add`, `git commit` and `git merge`:
- an ask whose every verdict that is no pass is the not-free answer of D3 for add or commit (a form of its own or their
  chain, _autonomy_recorded), and a form of D91 named git commit or git merge whose only finding is a program
  (_autonomy_local), is free (free_recorded_hooks, klasse lokal, no line to the user) where the state check of D3 or
  D91 finds nothing once the recorded hooks are left out of its count; a rewrite of D85 counts such a call as free;
- a hook is left out only where git takes the hooks from the clone's own hook directory (core.hooksPath on another
  folder, or a hook directory that is a link, records nothing), where exactly one entry names the clone by its work
  tree or by its common directory (a linked work tree shares the hooks of its clone), and where the hook is a regular
  file, opened without following a link, whose bytes, at most 1 MiB, hash to the recorded value. A changed hook, a new
  hook, a link and every other source of a program the state check reads (a filter, fsmonitor, a key or GIT_* name it
  does not know) count as before.

Not changed: decide(), every answer without the flag and every answer under Codex; the other forms of D91 (switch,
checkout, worktree add, stash, rebase) count their hooks as before; a repository that overlaps the gate directory gets
no free answer. Limits, named: the record binds the bytes of the hook, not what the hook reads or starts (a hook that
runs a script of the work tree, or the pre-commit framework, which reads .pre-commit-config.yaml of the work tree, runs
what the session wrote there); the gate reads the hook when it answers and git opens it later, so a swap in between
needs a second process (D27, the class of the D98 limit); a Bash step in another language that writes a hook is not
gated (D8). Tests: tests/test_plugin_n33_recorded_hooks_d106.py.

Nachtrag 51, point 1 (owner answer O46-3 of 2026-10-21, finding 1 of PLUGIN_N46): the step in another language was a
gap in the same line, not only in a second process. With the hook recorded, `python3 -c '…pre-commit…' && git commit -m
work` and the same with `perl -e` were free (free_recorded_hooks; measured at 70e98e91 and d3ce27a2,
probe_n46_d106_sibling.py): the gate read the recorded bytes, the first step changed them, git ran the changed hook.
D114 had the rule against this from the start. Now _autonomy_recorded answers only the command that rule takes
(_pinned_command): plain git calls of add, commit and the read forms of D115, joined by `&&` or `;`, each
`git [-C <absolute path>] <form> …` in the literal grammar, no other program, no redirection, no pipe, no expansion.
Every other command gets the answer of D91 and D85, as without a record; nothing that was blocked becomes free. The
merge of D91 is unchanged: _local_form already takes only a command that is one literal git form. Tests:
tests/test_plugin_n51_d106_command_rule.py.

## D107. A file of the hook folder counts as a hook only by a name git runs and where git may run it (Nachtrag 33, point 5, 2026-10-19)

Order of Nachtrag 33, point 5: as a hook counts only a file with exactly the name of a hook git runs and with the right
to execute; red with `pre-push.vor-ruff-<date>`, green after, a counter case with a real `pre-push`. Found by delta
(1518Z): a backup `pre-push.vor-ruff-20260919` in the hook folder let fetch, `worktree add` and push ask despite https.
Measured at 63b88d07 (hook_names_n33.py): with the backup the fetch of an https remote asked (remote_read_not_modeled),
without it and with a real pre-push it was free (free_after_fetch_profile); worktree add and push asked in all three for
reasons of their own.

Measured with git 2.43.0 (truth_hook_names_n33.sh: `git commit` and a fetch from a local repository, each hook a
marker): git ran pre-commit, post-commit and reference-transaction by their name when executable and through a symbolic
link to an executable file, not when not executable, and never under a name with a suffix (.vor-ruff-20260919, .local,
.bak).

The rule (_hook_problem, _hook_runnable): a file of the effective hook folder counts only where its name, in any letter
case, is one of _GIT_HOOK_NAMES (githooks(5) of git 2.43; a file system that ignores the case finds `Pre-Commit` as
pre-commit, so the case does not free a name) and where git may run it: an executable file, or a link whatever it
points to now (its target can change outside the hook folder, so a link to a file without the right to execute, or to
no file, counts too). The lists of the forms (D3, D40, D45, D78, D91) then say which of these hooks the form runs; D106
then leaves the recorded ones out. B36-3 had settled the names for the read forms (D78); D107 settles them for every
count. A hook git runs counts as before.

Limits, named: a file without the right to execute does not count, and a Bash step that sets the right (chmod) is
denied where the gate reads it (write_to_repo_state), but not in the code of another language (D8); the gate reads the
folder when it answers (D27). Tests: tests/test_plugin_n33_hook_names_d107.py.

## D108. A gh text with a literal backslash-n is denied (Nachtrag 33, point 3, fallbook S4, 2026-10-19)

Order of Nachtrag 33, point 3: where a command names a text that goes out, the gate checks it with the house's form;
the fallbook's S4 denies a `gh api` reply whose text carries a literal line break character. Found by delta's fallbook
(gate 44db2056): `gh api <path> -f <value>` asked, but for the net (net_unmodeled_git), never for the text.

The rule (_guard_text_newline, in the guards of Nachtrag 33): the texts a gh call sends as written (_gh_text_values,
gh 2.89.0 by `gh <command> --help`) are the value of --body, -b, --title, -t, --subject, --notes and -n, and under
`gh api` the value after `key=` of each field (-f, --raw-field, -F, --field), as the next word, after `=` or joined to a
short option; behind a wrapper, in a chain and in a string a shell runs too. Outside `gh api`, -F names a body file and
-m a milestone or the merge strategy, so neither is a text; a word the shell builds (an expansion, a substitution) is
no text as written. A text that carries the two characters backslash and n is denied under both hosts
(text_literal_newline, a catch of D88): bash keeps them as they are in single and double quotes, and GitHub shows them
as two characters where a line break was meant. A text in $'…' carries the line break itself and is no case. The way
the reason names: the text in a file, sent with --body-file or `-F body=@<file>`, or the line breaks in $'…'.

Limits, named: a text that means the two characters (a path such as `C:\new`, a snippet of code) is denied too; a text
from a file is judged by D109, not here; a text built by the shell is not read. Tests:
tests/test_plugin_n33_text_newline_d108.py.

## D109. The text of a file a gh call sends is judged by the house's form checker (Nachtrag 33, point 3, fallbook C3, 2026-10-19)

Order of Nachtrag 33, point 3: where the command names a file as the body, the gate reads it and checks it with the
form checkers of the house way; where the form fails, it denies; where there is no checker, it asks and says so. Found
by delta's fallbook (gate 44db2056): `gh pr comment <n> -R <repo> --body-file <file>` asked for the net
(net_unmodeled_git), never for the text.

The rule (_guard_text_form, in the guards of Nachtrag 33, under both hosts): the file of `gh pr create|new|edit|comment|
review` and `gh issue create|new|edit|comment` given with --body-file, --body-file=, -F or -F joined to the name, and of
`gh api` with a field `-F body=@<file>` (also --field, --field=, -F joined), behind a wrapper, in a chain and in a string
a shell runs. The gate reads it only where it lies in the work tree or the temp folder and no part below them starts
with a dot (_autonomy_write_place, as D92), where it is no key path (D102, checked before any read; D102 denies the
call) and where it is a regular UTF-8 file of at most MAX_PR_BODY_BYTES. The house's form checker (scripts/
b7_pr_form_gate.py at the default branch the remote records, never the work tree) judges it as D92 runs it
(_house_form_judge): rules (b) and (c) for the description of a pull request, rule (c) alone for a comment, a review or
an issue, since the house footer belongs to a description; where rule (c) cannot measure, such a text is unchecked,
whatever rule (b) says. Red: a deny (text_form_red, a catch of D88) with the checker's reasons. No checker, a checker
that cannot measure, or a file the gate does not read: an ask that says which (text_form_unchecked, NOT MEASURED).
Green adds nothing; the call keeps its answer, under --autonomous the owner's ask or card for its external effect (D85,
D93).

Changed: `gh pr edit <n> --body-file <file>` with a red body is denied by D109 in decide() before the autonomous answer
of D92, with the same checker's rule; D92 and its receipt answer a body D109 lets through
(tests/test_plugin_n37_machine_check_d92.py). Limits, named: the house has no checker for a commit message, so a push's
commit messages are not judged (S3, owner question); the notes of a release (`gh release create -F`), `gh api --input`
and a text on standard input are not read; the text of --body in the command is judged by D108 only; the gate reads
the file when it answers (D27). Tests: tests/test_plugin_n33_text_form_d109.py.

## D110. The open pull requests of a session are counted, and house rule H3 reads the count (Nachtrag 33, point 6, owner choice O30-1 A, 2026-10-19)

Order of Nachtrag 33, point 6, owner choice O30-1 A of 2026-10-18: a counter of open pull requests per session in the
plugin data directory, kept through PostToolUse, taken down at `gh pr merge` and `gh pr close` of the session; C2 of the
fallbook as its case: at `gh pr create` the gate asks because the session already holds 8 open pull requests. Until
now H3 (D73) asked at every new pull request, as the gate could not count the pull requests of one session.

Measured with Claude Code 2.1.303 and the stand-in API (n41/werkzeug/truth_post_n41.sh of the delivery, two Bash
calls): PostToolUse of a call that ended 0 carries tool_response with stdout, the address of the pull request the call
printed; PostToolUseFailure of a call that ended 1 carries no tool_response, only error; CLAUDE_CODE_SESSION_ID in the
environment of the PreToolUse, PostToolUse and PostToolUseFailure hooks equals the session_id of the event.

The rule: the hook after a call (proofbundle_answered.py, already run after every Bash call for D94) keeps
open-prs.json in CLAUDE_PLUGIN_DATA, `{"schema": "proofbundle-plugin/open-prs/v0.1", "sitzungen": {<session id>:
["owner/repo#number", …]}}`, the 64 sessions written last. After a Bash call that ran (PostToolUse only), where the
command may open a pull request (a gh call of `pr create` or `pr new`, the mutation createPullRequest, `gh api` on a
…/pulls endpoint with a method POST, a field or an input and no GET; read wide on purpose, in any shell syntax), it
adds each address of a pull request the output names, else one entry of unknown number: the count errs high, never
low. Where `gh pr merge` or `gh pr close` names a pull request by number or address as a whole command of its own, it
takes that entry off; a number without -R takes off the one entry of that number and none where two repositories hold
it; a merge of the current branch, a word of another kind or a command with shell syntax takes nothing off. It never
blocks or changes a call, and D94 goes on as before. The gate's H3 (_house_counted, _open_prs_count) reads the count of
the session CLAUDE_CODE_SESSION_ID names: below HOUSE_PR_LIMIT (8) its ask falls away, at 8 or more it asks with the
count (house_pr_limit_reached, a catch of D88), and where the environment names no session or no data folder, or the
file does not read whole (strict JSON, the schema, at most 256 KiB), it asks as before (house_pr_limit, NOT MEASURED).
No file in the folder is a count of 0.

Not changed: a call that opens a pull request keeps every other answer it has (the ask of D85 for its external effect,
the card of D93); under Codex, whose hook names no session of Claude Code, H3 asks as before. Limits, named: `gh pr
merge --auto` takes the pull request off when auto-merge is set, not when it merges (the owner's word: at gh pr merge);
a pull request merged or closed on GitHub or by another session stays counted; an MCP tool that opens one is not
counted; the file lies in the plugins folder of Claude Code, which D101 guards against writes the gate reads, not
against code of another language (D8). Tests: tests/test_plugin_n33_pr_count_d110.py.

## D111. An owner's release on a card frees exactly one command once (Nachtrag 42, 2026-10-19)

Order of Nachtrag 42 (owner word of 2026-10-19, 16:32 Berlin, choice A: the work goes from the phone, not in the
terminal): an owner's release frees exactly one command once, bound to the sha256 of the command as written, the
session that put the card and 15 minutes from the answer; its source is a file only the fetcher at the farmer writes,
never the session, and a write of the session into it or its folder is denied with the weight of _D72_WRITES; a second
call, another command, another session or an expired release stay blocked; the log names the card and the sha256 and
the bilanz counts the release. Found by the owner: twice on 2026-10-19 the owner typed a line with `!` into delta's
terminal after answering A on the card (the fetch of the bundle N37, card OA-aab72ad709; `git add` and `git commit` for
PR 328, card OA-bd5cf3ae01). D93 makes an external effect a card and D94 counts yes and no; the way back from the answer
to the gate was missing.

The rule (_autonomy_release, in autonomous_outcome after D85 to D93, Claude Code with the flag, Bash calls only): the
fetcher leaves one file per release in the folder freigaben of the gate's directory (_releases), `{"schema":
"proofbundle-plugin/freigabe/v0.1", "karte": "OA-<10 hex>", "sitzung": <session id>, "sha256": <64 hex>, "antwort":
"<YYYY-MM-DDTHH:MM:SSZ>"}`; a file that does not read whole is no release (no .json name, a link or no regular file,
more than 4 KiB, not strict JSON, another schema or key, a card, a session, a sha256 or a time of another shape), and
the folder must be a folder and no link. For a call decide() asked about whose autonomous answer does not let it run (a
card, a block, a detour, the owner's ask), a release whose sha256 is that of the command's words as written (UTF-8),
whose session is the one the hook's environment names (CLAUDE_CODE_SESSION_ID, measured with Claude Code 2.1.303 equal
to the session_id of the event) and whose answer lies at most 15 minutes back (and not more than 60 seconds ahead, the
clock skew between the farmer and the Leitstand) lets the call run once (released_by_owner, klasse freigabe, a line
"Gate lets … run once: the owner released it on the card …" and the long reason with card, time and sha256 to the
model). Before the pass the gate writes the use to freigaben-genutzt.json in the plugin data directory, under the lock
of the answer hook (D94); where it cannot write or read that record, nothing is released. The log line carries the
receipt {art freigabe, karte, sha256, antwort}, and the bilanz counts it per period (freigaben).

Not changed: a deny of decide() stays a deny (a hard rule no dialog may override: a write into the gate's directory,
hooks turned off, a key path, house rule H1); every answer without the flag and under Codex stays; the session never
writes a release: every write of a Bash step or a file tool into the gate's directory is denied (write_to_gate_dir,
D25), mkdir, rm, mv and a link included. A release frees the same as the terminal dialog's yes for the ask of decide(),
a forced push the autonomous answer blocks included (owner question in the report). Limits, named: the card id is read
by its form only, the gate does not know the cards of the Leitstand; the fetcher's file is trusted as the owner's
answer, as the gate's directory is trusted as a person's (D25); a release of another spelling of the same effect frees
nothing; the time is the farmer's clock; once holds only as long as the record of uses in the plugin data directory
does, which the session's account can write: a Bash write to it is denied where the folder lies under
~/.claude/plugins (D101), but code an interpreter runs (`python3 -c`), which the gate does not read, can remove it,
and the gate then frees the same release a second time (measured in Nachtrag 44, case 7; owner choice O44-2).
Tests: tests/test_plugin_n42_release_d111.py.

## D112. A variable of the hook's environment like HOME in a path word is put in (Nachtrag 41, point 2, O40-3, 2026-10-19)

Order: variables from the environment of the hook like HOME are put in by the gate, after a measurement; code of other
languages stays unread (D8), cd stays class e; no case that asks or denies today becomes free. Found in PLUGIN_N35 as
the open siblings of F35-1 and F35-2 (O40-3): a word `$D/x` of a variable the command does not set named no path, so
`rm -r $ELSE/build`, `echo x >> $RC/.bashrc`, `cp f $CFG/settings.json` or `cat $KEYS/config` got no answer where
the same words with the path written out are denied.

Measured with Claude Code 2.1.303 (truth_env_o403.sh: the stand-in API on the loopback, three Bash calls, a fresh
HOME, no network; the names of each environment with a sha256 prefix of the value, never the value): without a start
file 24 names have the same value in the PreToolUse hook and in the Bash call, among them HOME, PATH, TMPDIR,
XDG_CONFIG_HOME, LANG and a name set when Claude Code started; PWD differs after a cd, CLAUDE_PROJECT_DIR is the
hook's only, AI_AGENT has another value, and an export of one call is gone in the next (O34-1). With a ~/.bashrc that
exports TMPDIR and XDG_CONFIG_HOME anew, exactly these two differ: a start file of the shell may set another value.

The rule (_sh_env_word_paths in _sh_word_paths and _sh_line_values, so every guard that reads the paths of a word has
it: D96, D97, D100, D101, D102, D104, D105): a word that starts with `$X` or `${X}` (quoted or not, with a literal
rest), or with `${X:-w}` or `${X-w}` with a literal w, where X is in the hook's environment and the command does not
set it, names the path with the hook's value too, an unquoted value split into its fields as bash splits it; for
`${X:-w}` and `${X-w}` with X unset there (or empty, with the colon) the literal w. Not put in: the names the call sets
itself or did not see with the hook's value (_HOOK_ENV_NOT_IN_CALL: PWD, OLDPWD, SHLVL, _, CLAUDE_PROJECT_DIR,
AI_AGENT, and every name starting with BASH), and a name the command sets (D100 reads it; set in a way the gate cannot
read, `$(mktemp -d)`, it keeps today's answer). The path is a candidate: a target that was not known stays not known
where the gate counts that (write_targets), so nothing that asked or denied becomes free. A write the gate judges as a
file-tool write (D96, D97, the state of a repository) names the word as written where the shell makes its path of
the environment, never the path (_sh_spelled, D49); found with this rule for `~/.bashrc` and `$HOME/.bashrc` already
at f18b3183.

Limits, named: a start file that sets another value (measured for TMPDIR and XDG_CONFIG_HOME) makes the gate judge
the hook's value, which may be another file; a step that uses a name before another step of the command sets it is
judged with the command's value only, where bash takes the hook's; code of other languages, xargs and a relative path
after cd stay as they are. Under Codex the same words are put in (not measured; the paths only add). Tests:
tests/test_plugin_n41_hook_env_d112.py.

## D113. The window says where a receipt of Level 1 can be missing under the autonomous answer (Nachtrag 43, owner choice O28B-1, 2026-10-20)

Found in PLUGIN_N28B_KETTE (finding 2) and measured end to end in Nachtrag 43, point 1: the hook of Claude Code runs
with --autonomous (hooks.json, D85), and the signer service decides the call again with tool_outcome, without the
autonomous answer (D58), and signs only where both decisions are the same. For a GitHub write the pilot reads and the
autonomous answer changes (a pass under the standing GO of D87 or D92, a release on a card of D111, a block of a card of
D93 or of a push target of D86) it refuses with verdict_differs, and that write gets no receipt of Level 1. The answer of
the hook stays as it was: a receipt never changes the answer (D55).

Owner choice O28B-1 of 2026-10-20: measure first, and until then the window says so. The rule: the reconciliation of
every window carries under window_notes one sentence (LEVEL1_UNDER_AUTONOMY in reconcile.py) and prints it after M5
and M6: under the hook's autonomous answer a write whose answer it changes can lack its receipt of Level 1, and M5
counts such a write that reaches GitHub, as an effect without an approval, as it counted it before. Nothing about the
decisions, the receipts, the gate or the service changes.

Measured for choice A (a service that knows the autonomous answer from the operator's setting, never from the
request; a copy for the measurement only, not delivered): in the hook's environment it agrees with the hook in every
measured case but the release of D111, which the hook has used up before the service decides; with a data folder of its
own it agrees on the release and differs on the count of open pull requests of D110 (reasons_differ). A write in the
form of D67 gets no receipt either (O28-4, so left in the first pilot); M5 counts it where it arrives. Tests:
tests/test_plugin_n43_window_note_o28b1.py, tests/test_plugin_n43_d67_form_o28_4.py.

Numbering (owner choice O43-2, 2026-10-20): D113 belongs to this chain; the main line counts on from D114.

## D114. git add and git commit are free in the own tree on the own claude/ branch where the owner pinned its state (Nachtrag 46, Teil B, point 1, 2026-10-20)

Order of Nachtrag 46, Teil B, point 1 (owner choice of 2026-10-20 17:4x Berlin, B lower the cost): in the house profile
a local `git add` and `git commit` ask no more where the session works in its own tree on its own claude/ branch and the
hooks, core.hooksPath and .git/config are unchanged against a pinned state; where any of them is new, changed or points
elsewhere, the ask stays. Push, gh, the MCP write tools and every external effect do not change, and the delivery
profile does not change (point 3). Reported by the owner from delta (gate 63b88d07, 2026-10-20): add and commit asked in
the own tree on the own claude/ branch because the repository has a pre-commit hook of its own.

Measured at 70e98e91 (n46/werkzeug/probe_n46_ist.py of the delivery, 1836 answers, repositories of b7n0de and foreign,
branches claude/topic, topic and main, six configuration states): with a pre-commit hook that is not recorded (D106)
every add and commit asks or is blocked under `--autonomous`, with commit signing, fsmonitor or an unknown key of
.git/config also without a hook.

The rule: the file pin-state.json in the gate's directory, which only a person writes (D25: decide_write and the
redirections of a Bash step into the gate directory are denied, write_to_gate_dir), pins clones,
`{"schema": "proofbundle-plugin/pin-state/v0.1", "klone": [{"pfad": <work tree>, "hakenordner": <the hook directory git
uses>, "haken": {<name>: <sha256>}, "konfig": <sha256 of .git/config>}]}`; `proofbundle_gate.py pin-state <path>`
prints the entry of a clone as it is now and writes nothing. A file that does not read whole pins nothing (no regular
file, more than 64 KiB, a repeated key, another schema, another key, a relative path, a hook name or a value of another
shape). In autonomous operation (Claude Code with the flag, D85), an ask whose every verdict that is no pass is the
not-free answer of D3 for add or commit is free (free_pinned_state, klasse lokal, no line to the user) where all of this
holds when the gate answers:
- the command is plain git calls of the pinned forms joined by `&&` or `;` (_pinned_command), each spelled `git` as
  written (no quotes, no backslash, no path): no other program, no redirection, no pipe, no expansion, no word the
  shell may rewrite, so no other step of the line writes a hook or the configuration between the check and git;
- exactly one entry names the work tree, HEAD is a branch under refs/heads/claude/, the hook directory git uses lies
  inside the clone (its git directory or its work tree; a core.hooksPath that points elsewhere pins nothing, and
  pin-state refuses it), is the pinned one and holds exactly the pinned hooks with their bytes (a link, a new, a
  changed or a missing hook pins nothing), .git/config is a regular file with the pinned bytes, and there is no
  config.worktree;
- the repository does not overlap the gate directory, and the state check of D3 finds nothing once the pinned hooks and
  the keys of the pinned .git/config it does not know are left out. A key that names a program by path keeps the
  answer (a filter, fsmonitor with a command, a signature program, a configuration hook); commit.gpgSign with git's
  default signing program and git's automatic maintenance do not. Every key of another file (an include, the global
  or system file, `-c`) and every GIT_* name counts as before.

Not changed: decide(), every answer without the flag and every answer under Codex, push, gh, fetch, tag and every form
outside add and commit; the delivery profile. Limits, named: the pin binds the bytes of the hooks and of .git/config,
not what a hook reads or starts (a hook that runs a script of the work tree runs what the session wrote there); the
gate reads them when it answers and git opens them later, so a swap in between needs a second process (D27, the class of
the D98 limit); "own tree" is the tree the owner pinned, the gate cannot tell which tree a session was given. Tests:
tests/test_plugin_n46_pinned_state_d114_d115.py.

## D115. The read forms of the order are free under the same pin (Nachtrag 46, Teil B, point 2, 2026-10-20)

Order of Nachtrag 46, Teil B, point 2: reading git without an ask under the condition of D114, for rev-parse, status,
log, show, diff, ls-files, merge-base and cat-file, each only with switches that start no foreign program (no pager, no
external diff, no textconv, no fsmonitor); what the condition cannot prove keeps asking. Reported by the owner from
delta (2026-10-20): a read-only command with `git rev-parse` was blocked, line verbatim "Tor sperrt git rev-parse: kein
freier Weg, es fragt nur bei Außenwirkung (D85). Weil git ein Programm starten kann, das das Tor nicht sieht (D3)."
Measured at 70e98e91 (the probe of D114): with an unknown key of .git/config every read form of the probe is blocked
under `--autonomous`, with core.pager every one, with fsmonitor 36 of 78.

The rule: an ask whose every verdict that is no pass is the not-free answer of D3 for a read form of the list, whose
options the read grammar of D34 took, is free (free_pinned_state) where the pin of D114 holds for its repository and the
read profile of D34 finds nothing once the pinned hooks and the keys of the pinned .git/config it does not know are left
out. The pager keys, fsmonitor, the filter and promisor keys and every key that names a program keep the answer, pinned
or not: a key that _program_source names (written for add and commit) and every key whose last part names a program, a
driver, a tool, a hook or a signature (_READ_PROGRAM_KEY: diff.external, the textconv and command of a diff driver,
log.showSignature, core.alternateRefsCommand and their kind). The first pin of D115 (2e464928) left those out where
_program_source named none: in the pinned variant of the corpus, git diff, log and show went free in the contexts
prog_diffext, prog_textconv and prog_showsig; the fix of the same day keeps them. An option that starts a program
(`--ext-diff`, `--textconv`, `--show-signature`, a format that reads a signature, `-c core.pager=…`) keeps its answer
with the pin as without it, and so does a form outside the list (rev-list, measured). The command rule of D114 holds
here too: `git log | head` keeps its answer.
Not changed and limits: as D114. Tests: tests/test_plugin_n46_pinned_state_d114_d115.py.

## D116. The short line of an ask or a block names what can go wrong, before the D number (Nachtrag 46, Teil C, points 4 and 5, 2026-10-20)

Order of Nachtrag 46, Teil C (owner choice of 2026-10-20 17:4x Berlin, C sharpen the reasons): for every D number that
asks or blocks, a short line in everyday words of what can go wrong, before the id; the id stays at the end. Found by
the retrospective at 89d2e8b7 (delta, 2026-10-18): of 13 mishaps the gate saw, it held 9, only 3 of them with a
fitting reason, a line that names the danger and not only an id like D3 or D27.

The rule: the short line of D53 for an ask, a deny, a warning, a block of D85 (sperre, umweg) and a card of D93 (karte)
takes its reason from _SHORT_DANGER, one pair of English and German clauses per reason id, "because <what can go wrong>
(<D number>)". The not-free answer of D3 names its form (git commit, git add, a read) and the source it found;
ls-remote, the read forms under Codex and an unknown case have a clause of their own (_SHORT_DANGER_SPECIAL). Eleven
reason ids already named the danger in their reason and keep it (_SHORT_DANGER_IN_REASON: the house rules H1 to H4, the
forced, mirrored and deleting push, the literal backslash-n). A card names the danger of the step the line names (D72)
where that is more than the gate's blind spot, else the first ask of the answer that is, else the step's own
(_short_card_cause), then the card: "Tor sperrt <step>, weil <danger> (<D>); Karte an den Owner (D93)." A line that
would be longer than 160 characters first takes the short form of the Codex sentence ("Codex kann nicht fragen."), then
a shorter step name, at least 12 characters, where that makes it fit; only then is it cut, so the danger and its D
number stay whole (measured for the 95 reason ids, the forms ask, deny, warn, sperre, umweg, karte and the Codex deny,
steps of 9, 20 and 40 characters, both languages, 3990 lines: none longer than 160 characters, none without its danger
and D number whole, no Codex line without its sentence; at 70e98e91, 13 German Codex lines with a step of 9 characters
lost it).

Not changed: the long reason for the model, the reason ids in the log and the bilanz, every decision. The end of a
session the Stop hook holds keeps its line (Nachtrag 47). The retrospective's 18 cases are a fixture with mishap and
today's reason; a test shows per case that the line names the danger by its words; whether it fits is judged by the
retrospective at echo, not here. Tests: tests/test_plugin_n46_danger_line_d116.py.
