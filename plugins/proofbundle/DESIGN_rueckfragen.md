# Lowering the ask load of Level 1: design draft with measurements

Status: Fassung 2 of 2026-10-14 (FOXTROT-CLOUD-NUTZERWEG-REVIEW-FIX-18, part B, with Nachtrag 1). It replaces Fassung 1,
which was delivered with the FIX-17 report and not committed. It carries the owner's answers of 2026-10-14, which equal
the reviewer's recommendations (section 9), the review findings Q18-1 to Q18-3 (section 6) and the build order of the
classes (section 7). The push destination (class f, section 3.6) is built separately, on its own branch; this draft
does not build it.
Measured on the plugin at 3604ba5364226ebf9ab2847974f7126a12845cf2 (Fassung 1) and at
d828c2beba3724c4102e4e77fd9e9143efd22474 (the build order in section 7). The setup was git 2.43.0, gh 2.89.0, GNU bash
5.2.21, Python 3.11.17, Linux, 4 CPUs.
The prototype lives outside the plugin. It wraps the gate unchanged and adds the proposed rules around it
(`prototyp.py`, `shparse.py`). The measurement copy for the build order (`prototyp18.py`) carries the owner's answers.
The plugin's build follows section 7, one class per delivery; it is written for the plugin, not copied from the
prototype.

## 1. The question

The observer at head 101bd167 saw 276 Bash calls on 2026-10-13 between 20:55Z and 23:55Z:

| Measure | Count |
|---|---|
| allow | 165 (all not_gated) |
| ask | 108 (39.1 %) |
| deny | 2 |
| error | 1 |

The reasons were net_unmodeled_git 72, git_form_not_free 40, directory_unresolved 10 and push_not_measured 2.
The shapes were pipe or chain 45, substitution 17, here-document 35 and simple only 4.
`net_unmodeled_git` also fires on git or gh words that are only text in a here-document or in Python code.

Owner choice A asks for one draft for the whole ask load (north star N5). Level 1 stays no security boundary, and
nothing that checks evidence may get weaker.

## 2. Method

Every figure below comes from one of five measurements. The scripts and raw lines are in `rueckfragen/`.

1. **Class measurements with real programs, no network.**
   - git read forms against marker programs, one per configuration source, with stdout a pipe:
     `a_lesen.jsonl` (16 sources × 17 forms) and `a_lesen2.jsonl` (13 sources × 21 forms).
   - gh against a local TLS stand-in for github.com and a second host, inside a network namespace that has only the
     loopback interface and a private `/etc/hosts`: `b_gh.jsonl`, 121 runs. Each run records strace (execve,
     connect), the HTTP method and path, the token sent and the local files changed. Only placeholder tokens were
     used; the session's tokens were removed from the environment.
   - git config forms against the gate: `g_config.jsonl`, 57 forms.
2. **Corpus** (`korpus.jsonl`, 435 entries).
   - 276 commands rebuilt to the observer's counts: 165 without git or gh, 111 with git or gh. The observer's
     protocol itself was not available, so this is a model of it.
   - 155 harmful cases across classes a to g, each with the answer it must keep.
   - 4 done-check cases.
3. **Ground truth** (`wahrheit.jsonl`). Every corpus command was run for real in bash, without network, in a fresh
   copy of its scaffold. Stand-ins for git and gh logged their argv and their physical and logical working directory.
   Python, sh, sed, awk, xargs, find and env reach the stand-ins through PATH.
4. **Today against the prototype** (`auswertung.jsonl`, 6427 rows).
   - Scaffolds: `evals/_fixtures/scaffold.sh` at 3604ba53, a declared repository (repo-valid) and an undeclared one
     (repo-nodecl), plus 16 further contexts.
   - Four call environments:
     - `sauber`: no system configuration; the global configuration holds the identity only.
     - `signiert`: as `sauber`, plus SSH signing as a developer machine has it.
     - `container`: this machine as it is: HOME=/root with SSH signing, and git-lfs in the system configuration.
     - `container_lfs`: as `container`, with the git-lfs standard filter counted as inert (option l). The owner
       declined option l (answer 2); the environment stays in Fassung 1's figures only.
5. **Done check, run time and Codex.**
   - `abschluss.jsonl`: the Stop hook before and after each command, in the done-red scaffold, without network. The
     verifier ran from the existing uv cache (UV_OFFLINE=1).
   - `zeit_codex.jsonl`: wall time and the answers under `--host codex`.

Fassung 2 adds a sixth: **the build order** (`reihenfolge.jsonl`, 24288 rows). The measurement copy `prototyp18.py`
decided the 276 commands in the declared and the undeclared repository, each in `sauber` and `container`, for every
class set of a greedy search (section 7). Every row has exactly one result; none ended with an error.

## 3. Per class: what the ask protects today, what loosening costs, the proposal

### 3.1 Class a, read git forms

**What it protects, measured with git 2.43.0 and stdout a pipe.** A read form starts a program only through these
sources:

- **core.fsmonitor.** Started by grep, ls-files, status and diff.
- **diff drivers.** diff.external and diff.<drv>.textconv or command: started by log -p, show and diff.
- **Filters.** filter.<drv>.clean or process: started by diff and diff --stat. The git-lfs standard filter starts only
  for diff on paths with filter=lfs.
- **Hooks.** post-index-change runs on status.
- **Signature verification.** It starts gpg.program, or the `gpg` on PATH, only with --show-signature, a `%G`
  placeholder or log.showSignature. A configured SSH program without allowedSignersFile started nothing.
- **Lazy fetch.** A promisor remote starts uploadpack for a missing object (log -p, show, diff).
- **Environment.** GIT_EXTERNAL_DIFF and GIT_CONFIG_COUNT do the same as the keys they carry.
- **Submodules.** A submodule's own core.fsmonitor runs under status and diff of the superproject.
- **Pager.** The pager runs only on a terminal. The Bash tool of this Claude Code session has no terminal on stdin,
  stdout or stderr (measured with `test -t`).
- **Options.** --ext-diff, --textconv, --output=<file> and `git grep -O` / `--open-files-in-pager` start a program or
  write a file.

These keys started nothing for any read form: credential.helper, core.sshCommand, core.askPass, http.proxy,
core.editor, sequence.editor, merge drivers, and gc.auto=1 with maintenance.auto. With gc.auto the pre-auto-gc
marker never ran.

rev-parse, for-each-ref and worktree list started nothing under any source.

**What the existing state check (K-NW-2 B) does with read forms.** It is built for add and commit -m. It flags SSH
signing set-ups (gpg.ssh.program, commit.gpgsign) and gc.auto, which no read form starts. It also flags the git-lfs
system filter for every form. On this machine it therefore frees no read form, and on a signing developer machine
none either.

It misses two sources that matter for reads:

- the configuration of a submodule;
- log.showSignature without a configured program. This was found by the corpus: gpg came from PATH.

**Proposal, as the owner decided it (answers 1 to 3).** A read profile, built as a narrow new piece of the plugin and
not taken over from the prototype. It frees a read form after a read profile of its repository, with three parts.

- *Option allow-list per form* (log, show, diff, rev-list, shortlog, status, grep, rev-parse, for-each-ref,
  ls-files, ls-tree, show-ref, merge-base, describe, cat-file -t/-s/-e/-p, worktree list, branch listing, and config
  read forms from class g). An unknown option keeps the ask.
- *Read profile instead of the add/commit profile.* It is built on the same allow-list principle: an unknown key
  keeps the ask.
  - Filters count only for diff and status. The git-lfs standard filter of the system configuration counts like any
    filter (answer 2: git-lfs is not inert).
  - Diff drivers count only for the diff family.
  - fsmonitor and hooks count only for forms that walk the work tree.
  - Signature programs count only when a signature is read, and then always, because gpg may come from PATH.
  - Promisor keys always count.
  - The pager is inert under the pipe only where the host adapter is bound and its Bash tool is known to give no
    terminal (answer 3). Anywhere else the pager keys count.
- *No submodule* for forms that walk the work tree, and *no step before it that may change state*. A step may change
  state if it is an unknown program, a carrier of code, an assignment, or a redirection to anything but a harmless
  file. Every git read the gate makes for this check, the submodule listing included, goes through its hardened git
  path, with fsmonitor and hooks off (Q18-2, section 6).

**Built in the plugin (D34), and what the measurement copy of the prototype missed.** The plugin's read profile is
written anew from these rules (owner answer 1, read again on 2026-10-14, 17:5x). Measured against real git in
throwaway repositories: a signature is also read where a default format (`format.pretty`) or a named format
(`pretty.<name>`) holds a `%G` placeholder; `git log -1` and `git show HEAD` then started the `gpg` on PATH. The
measurement copy of the prototype counted `format.pretty` as inert and freed both forms; the plugin's profile does not
know these keys and asks. No host adapter is bound in the plugin, so every pager key counts (answer 3).

Three more holes, found while the plugin's profile was built and closed before its commit (each a test of its own):

- A word that names an index entry (`git rev-parse :a.txt`, `git show :a.txt`, `git cat-file -p :a.txt`, a
  `--points-at=:a.txt`) reads the index, and reading the index queries fsmonitor for a form that does not walk the
  work tree too. Such a word keeps any form asked.
- PAGER is the second name git reads to choose the pager, beside GIT_PAGER; it counts like core.pager, in the hook's
  environment and as a prefix assignment of the command. Class c judged a step without its prefix assignments; it
  now judges the step as written.
- A `git add` of an embedded repository adds a gitlink, and a later `git status` or `git diff` in the same chain then
  starts that submodule's fsmonitor. A `git add` counts as a state change before a form that walks the work tree.

**Cost.** This reopens owner choice B of review Runde 9 for read forms. The removed free list was a deny-list with
per-entry profiles. The read profile is an allow-list, like K-NW-2 B, and git itself reads booleans (`_git_false`).

What stays unmeasured: a key no measurement here covered. Such a key keeps the ask, so the profile's coverage decides
the benefit, not its safety.

### 3.2 Class b, gh read and write

**Measured with gh 2.89.0 against a local stand-in.**

What the read forms send:

- pr view, checks, diff, list and status, run view and list, issue view and list, release view and list, repo view,
  workflow list and view, auth status, and `gh api <path>` without fields send only GET and GraphQL queries.
- The git that gh starts for these forms is remote -v, config --get-regexp, config push.default and
  remote.pushDefault, symbolic-ref and rev-parse --symbolic-full-name. It started none of the class-a sources even
  with all of them set at once.

The edges that turn a read into something else:

- **Fields.** Any -f, -F, --field, --raw-field or --input without `-X GET` makes `gh api` a POST.
- **Local file sent out.** `-X GET -F x=@file` sends the content of a local file as a query parameter.
- **Body on GET.** `-X GET --input` sends a body on a GET.
- **GraphQL documents.** A GraphQL mutation can hide behind `--input` or `-F query=@file`. A document whose first
  operation is a query runs its mutation when `operationName` names it.
- **Program starts.** --web and `gh browse` start the browser. The pager starts only with a terminal or
  GH_FORCE_TTY=1.
- **Secrets in the output.** `gh auth token` and `gh auth status --show-token` print the token.
- **Aliases and extensions.** They act only on words that are not builtin commands. `gh view x` with the alias
  `view: pr comment 1 --body` posted a comment, and `gh foo` started an extension. An alias or extension named `api`
  did not shadow the builtin.
- **Other hosts.** A token from hosts.yml goes only to its own host. GH_ENTERPRISE_TOKEN went to the unconfigured host
  127.0.0.1. GH_TOKEN did not.
- **attestation verify.** It looked up the Sigstore TUF host (DNS to 8.8.8.8 and 8.8.4.4) and wrote a TUF cache under
  ~/.cache/gh.
- **Local writes and transfers.** pr checkout and repo clone start git with gh as credential helper. pr checkout also
  ran the repository's fsmonitor and wrote FETCH_HEAD.

**What the ask protects today.** Every gh word except pr/release create is `net_unmodeled_git`, so all of the above
asks. The two gated forms keep their own check.

**Proposal.** Allow builtin read forms by exact command path, with these limits:

- no --web, --hostname or --show-token;
- -R only as OWNER/REPO;
- no prefix assignment;
- no GH_FORCE_TTY in the environment.

For `gh api`:

- REST GET only: no field without `-X GET`, no `@file` value, no --input, only Accept headers, no full URL;
- GraphQL only with exactly one `query` field holding one query operation, and no operationName.

Every other gh form keeps today's answer. `attestation verify` keeps it too (answer 4). The allow-list applies only to
a gh version the gate has checked; any other version keeps today's answer (answer 5).

**Built in the plugin (D36), and what the build measured beyond the proposal.** Three more measurements with gh
2.89.0 against the stand-in, each now a rule with a test of its own:

- A repository or a pull request in another spelling names its own host: `-R git@127.0.0.1:o/r`, `-R
  https://127.0.0.1/o/r`, `gh repo view 127.0.0.1/o/r`, `GH_REPO=127.0.0.1/o/r` and a pull request or issue URL as the
  argument all asked 127.0.0.1. -R and GH_REPO are taken only as OWNER/REPO, an argument only as a number.
- gh's jq reads the environment: `--jq '$ENV.GH_TOKEN'` and `--jq 'env.GH_TOKEN'` printed the token. An expression that
  spells `env` keeps the ask. `import`, `include` and `input_filename` read nothing; a Go template has no `env`.
- A pager comes from gh's own sources only (GH_PAGER, the configuration, PAGER), never from git's core.pager; an empty
  `pager:` in the configuration starts none, and GH_PAGER set empty overrides a configured one. As in class a, a pager
  with a value counts (answer 3), in the environment and in config.yml and hosts.yml.

A path of `gh api` written `HTTPS://host/x` is a full URL too; `//host/x` stayed on api.github.com, but the build
refuses both. A GraphQL query is read by a small lexer of its own: one operation, a query, fragments beside it.

**Cost.** The allow-list is tied to gh's measured behaviour at 2.89.0, and the version check costs one gh start per
judgement (two for a command class c judges as a step).

### 3.3 Class c, compound commands, here-documents and strings

**What the ask protects, measured against the ground truth.**

- **No call at all in 26 of the 108 asked commands.** These were here-documents written to files, text piped to wc or
  grep, and inline Python whose strings name git or gh. All 26 are false alarms.
- **Calls hidden in text that the stand-ins did catch:**
  - a here-document piped or fed to bash;
  - an unquoted here-document body with `$(git push …)`;
  - `echo "$(git push …)"` and backticks;
  - `sh -c`, `bash -c` and `eval`;
  - Python with subprocess, os.system, `sys.modules['os']` or `__import__('os')`;
  - `git log --format=%s | sh`, xargs, `find -exec`, `sed 'e …'`, `awk 'BEGIN{system(…)}'`;
  - env, command, timeout and nohup;
  - a script written by a here-document and then run.

**Proposal, as the owner decided it (answers 6 and 9).** Parse the command and judge every executed simple command on
its own:

- here-document bodies and quoted arguments of known data commands are text;
- substitutions are commands;
- inline Python is never text: there is no inert-Python rule (answer 6, Q18-1). An interpreter, or a program the gate
  does not know, whose words or here-document name git or gh asks at least (answer 9).

Today's answer stays for:

- every carrier of code whose code text names git or gh, raised to at least ask;
- an interpreter that reads a git or gh step's output;
- git or gh text next to any step that runs code;
- a gated step that is not the first executed step after at most `cd` steps;
- a step with an expansion or a prefix assignment;
- every shell construct the parser does not model (keywords, functions, background jobs, a here-document inside a
  substitution, ANSI-C quotes).

**Parser against the ground truth.** In 380 of 384 compared rows, the executed git and gh calls of the parser equal
those of bash, and the working directory never differed. The 4 differences are pushes after a failing cd (`cd fehlt &&`,
`cd - &&`, `cd ~/x &&`, `cd sub ||`). The parser judges the push although bash does not run it, which errs towards
asking.

**Cost.** The parser models bash 5.2. It was not measured under zsh, the default shell on macOS (section 10).

### 3.4 Class d, undeclared repositories (D5 C)

**When a call surely belongs to such a repository (measured in the prototype).** All of the following must hold:

- the directory is resolved;
- no GIT_DIR-type variable is set (GIT_DIR, GIT_WORK_TREE, GIT_COMMON_DIR, GIT_INDEX_FILE, GIT_OBJECT_DIRECTORY,
  GIT_ALTERNATE_OBJECT_DIRECTORIES, GIT_NAMESPACE);
- no --git-dir or other global option (it stays today's answer);
- git names a work tree there;
- nothing stands at the declaration at HEAD (`_declaration_at`) or in the working tree (`_working_tree_declares`).

Results:

- repo-worktree-only was not undeclared.
- `GIT_DIR=<declared>/.git git log` and `git --git-dir=…` stayed asked.
- `git -C <declared> log` from an undeclared directory was judged in the declared repository.
- A linked worktree of a declared repository, on a branch whose HEAD declares nothing, counted as undeclared in
  Fassung 1. The owner left linked worktrees out of class d (answer 7): a linked worktree, and a repository that has
  linked worktrees, is not surely undeclared.
- The proofbundle checkout of this session (HEAD 19c3b0b9) declares nothing. The observer's repositories were not
  measured.

**Proposal.** In a repository that surely declares nothing, every local git form is inactive. A local form is a
`_GIT_LOCAL_SUBCOMMANDS` entry other than a hooks_disabled form. Push keeps owner choice 1 A with its four conditions.
Possible transfers and gh calls keep today's answer.

### 3.5 Class e, directory change

**Measured.**

- Nachtrag 1 already turned the agents' push form into `git -C <absolute path> push` (D32).
- The prototype resolves `cd <literal>` like bash's logical cd: normpath, the directory must exist, no CDPATH, and no
  prefix assignment on the cd. A cd inside a subshell or a pipeline element does not carry on; after `||` the
  directory is unknown.
- Against the ground truth the resolved directory equalled bash's physical working directory in every compared row,
  `cd link/..` included.
- These stay unresolved: cd to a missing directory, `cd -`, `cd $HOME`, `cd ~/x`, `CDPATH=… cd`, pushd, and `cd x ||`
  (12 harmful cases).
- A push after a resolved cd gets the verdict of the `git -C` form. Tampered and missing evidence via
  `cd {repo} && git push` became deny (today: ask directory_unresolved).

### 3.6 Class f, push destination (Gegenstelle)

Variants a to d with their measurements are in `gegenstelle/DESIGN_gegenstelle.md`. The owner chose on 2026-10-14 to
drive both weaknesses in parallel: the push destination is built on its own branch, with its own draft. This draft and
its build do not touch the hand-over from Level 1 to Level 2; a change that touches it is named in the delivery's
report.

In the rebuilt corpus 5 of the 25 remaining asks of Fassung 1 are pushes with push_not_measured. NOT MEASURED on the
corpus.

### 3.7 Class g, `git config` and core.hooksPath (Nachtrag 2)

**Measured at 3604ba53.**

- `_strict_git` denies every `git config` whose words contain `core.hooksPath` in any case (`_hooks_off`), whatever
  the direction. Every read form that names the key gets deny hooks_disabled, under Claude and Codex, declared and
  undeclared, also with `-C` and inside chains. The forms are --get, --get-all, --get-regexp core.hooksPath,
  --get-urlmatch, --show-origin, --show-scope, --type=path, --null, --default, --file, the bare
  `git config core.hooksPath` and the observer's `git config --global --get core.hooksPath`.
- Read forms that do not name the key literally get only ask git_form_not_free: --list, -l, --show-origin -l,
  --get-regexp hookspath, `--get-regexp '^core\.'`.
- Run for real with all class-a sources set, no read form started a program or changed the configuration.
- Siblings in the other direction: `--remove-section core`, `--rename-section core …`, `include.path …` and `--edit`
  change or remove core.hooksPath without naming it, and get only ask.
- `git -c core.hooksPath=/dev/null status` and `… log -1` are denied although neither pushes.
- install-pre-push refuses with the words "core.hooksPath is set in the global configuration". Reading that setting is
  the natural next step for a user. This is an inference; the observer's context at 21:54:54Z was not available.

**Proposal, as the owner decided it (answer 8).** Classify the direction with a closed read grammar (git 2.43 options,
plus `get`/`list` of newer git). Any unknown option, --blob or value word makes the form a write.
Read-only config forms receive the read-profile decision. Explicit hook overrides retain deny. Other configuration
changes retain at least their existing ask decision until their effect is established.

**Cost.** Misreading a write as a read would lose a deny. The grammar is a fixed allow-list. In the corpus, 14 setting
forms kept the deny, and the 8 read forms were freed; 6 of those 8 were denied today and 2 (--list) were asked.

## 4. Siblings found on the way, which strengthen today's answer

- **Bash writes to configuration, hooks or the gate's directory are not gated today; the file tools are.**
  `echo x > .git/hooks/pre-push` and `printf … >> .git/config` are not_gated at 3604ba53. The prototype judges every
  literal redirection and tee target with `decide_write`, as Claude Code's file tool would be judged: ask
  (write_to_repo_state). The owner confirmed this (answer 9).
- **Code text in some interpreters is not gated today.**
  `python3 -c "import os; os.system('git push origin main')"` and `awk 'BEGIN{system("git push origin main")}'` are
  not_gated at 3604ba53, while `sh -c 'git push …'` asks. Every interpreter, and every program the gate does not know,
  whose words name git or gh asks at least (answer 9). The `-c` forms of Q18-1 are not_gated at d828c2be as well.

Both strengthenings added no ask in the observer corpus of Fassung 1.

## 5. Measured effect

On the synthetic corpus in the declared clean scaffold, the prototype reduced ask decisions from 108 to 25. This is not a replay of the observer session and does not estimate the ask rate in normal use. Two required-case runs ended with an error and need to be rerun. The tested cases do not establish that every required push, PR, release or completion decision is preserved. Additional review probes found cases in which the prototype changes ask to allow incorrectly.

The two runs were the harmful case S283 (`git log -p -1` in a repository with promisor configuration), in `sauber`
and `container`. Rerun on 2026-10-14 with the measurement copy, which denies where the gate raises its promisor
refusal as the hook does: deny in both, so the required answer (not free) is kept (`s283_neu.jsonl`). The review probes
of Q18-1 are in section 6.

The figures of Fassung 1, observer corpus, 276 commands, all classes, with the prototype as it was before the owner's
answers. Each cell gives asks today → with the prototype, then denies today → with the prototype:

| environment | declared repository | undeclared repository |
|---|---|---|
| sauber | 108 → 25 (39.1 % → 9.1 %), deny 2 → 1 | 107 → 19 (38.8 % → 6.9 %), deny 2 → 1 |
| signiert | 109 → 27 (9.8 %), deny 2 → 1 | 108 → 19 |
| container (git-lfs strict) | 109 → 35 (12.7 %), deny 2 → 1 | 108 → 19 |
| container_lfs (option l) | 109 → 27 (9.8 %), deny 2 → 1 | 108 → 19 |

With the owner's answers (measurement copy `prototyp18.py`, at d828c2be), the same corpus gives, asks in the declared
and the undeclared repository, `sauber` and `container`:

| class set | declared sauber | declared container | undeclared sauber | undeclared container |
|---|---|---|---|---|
| today | 108 | 109 | 107 | 108 |
| c | 91 | 93 | 90 | 92 |
| c, a | 54 | 63 | 53 | 62 |
| c, a, b | 37 | 46 | 36 | 45 |
| c, a, b, d | 37 | 46 | 34 | 34 |
| c, a, b, d, e | 35 | 45 | 29 | 29 |
| c, a, b, d, e, g | 35 | 45 | 29 | 29 |

Any class without c equals today in all 1104 rows: only c makes the command parts visible to the others.

The figures for the plugin are measured per delivery, on the plugin itself, before and after the class.

Codex, Fassung 1, declared, sauber: asks 106 → 63, deny 2 → 1, no command that is free today asks or denies. Only b,
c and g apply, because the Codex hook carries no execution directory (R5-2, answer 10).

Run time of Fassung 1, declared, sauber, one process:

| | median | p95 | maximum |
|---|---|---|---|
| today | 0.000 s | 0.001 s | 0.74 s |
| prototype (including today's call) | 0.002 s | 0.030 s | 1.30 s |

The hook's deadline is 90 s and its cap 120 s.

## 6. What the tested cases show, and the review findings Q18-1 to Q18-3

What the rows of Fassung 1 show, and no more:

- **Rows with a gated call.** With the corrected oracle of Q18-3, 343 rows run a gated call according to the ground
  truth (git push, send-pack, a -c alias, gh pr/release create, a gh write, a core.hooksPath setting). In none of them
  is the prototype free where today is not.
- **Harmful cases.** 325 rows kept their required answer, 0 were violated. Four rows expected deny where today already
  asks. With the prototype they became deny: tampered and missing evidence via `cd {repo} && git push`.
- **deny stays deny.** 27 rows lost a deny, all of them class g read forms of core.hooksPath. A deny for text only
  (`cat <<'EOF' > n.md` with `git push --no-verify` in the body) is held by a guard, although no call runs.
- **Done check.** The Stop hook blocked before and after each of the four commands and the control. The reasons were
  red before, and red, unverified or stale after, including after a forged receipt written by a here-document or by
  Python, and after copying the valid receipt of another tree.

These rows are the tested cases. They do not establish that every required decision is preserved.

**Q18-1, the inert-Python rule changed ask to allow.** Measured with the prototype of Fassung 1 at d828c2be
(`q18_1_formen.jsonl`): `python3 - <<'PY'` with `from pathlib import os` and `os.system('git push origin main')` in the
body is asked today and was not_gated with the prototype, because the import is allowed and no forbidden name occurs.
`python3 -c "from pathlib import os; os.system('git push origin main')"`, the same through `pathlib.os.system`, and that
form with a further argument are not_gated both today and with the prototype. Answer 6 removes the rule; with answer 9
every interpreter whose words name git or gh asks at least. In the measurement copy all these forms ask.

**Q18-2, the submodule check started fsmonitor.** The prototype's `has_submodule` ran `git ls-files --stage` without
the gate's hardening, so a repository's core.fsmonitor ran, and could unset itself afterwards. Every helper read of the
build goes through the gate's hardened git path, with core.fsmonitor off, an empty hook folder and the untracked
cache off; the measurement copy does the same. Each delivery carries this as a counter-probe.

**Q18-3, the error count left out the error rows.** `kennzahlen.py` counted errors only among rows with an answer, so
it said 0 while S283 had ended with an error twice. The corrected `kennzahlen18.py` counts over every row (2 errors in
Fassung 1's rows), checks that every combination of the run plan has exactly one result (6427 of 6427), and judges a gh
write with an oracle of its own instead of the prototype's gh_read. With that oracle the rows with a gated call are
343, not 348, and the prototype frees none of them where today does not.

## 7. Build order, measured by benefit

The owner asked for the classes to be built one after the other, each delivered on its own as soon as it is green,
ordered by its benefit in the synthetic corpus. The measurement copy chose greedily, each round the class that left the
fewest asks over the four cells of section 5 (declared and undeclared, `sauber` and `container`, 1104 rows a set):

| round | chosen | asks over the four cells | runner-up |
|---|---|---|---|
| — | today | 432 | — |
| 1 | c | 366 | — (no other class acts without c) |
| 2 | a | 232 | d, 286 |
| 3 | b | 164 | d, 219 |
| 4 | d | 151 | e, 152 |
| 5 | e | 138 | g, 151 |
| 6 | g | 138 | — |

1. **c, compound commands and text.**
   - Benefit: the precondition for every other class; 66 asks of 432.
   - Risk: a parser that differs from the shell. Bounded by keeping today's answer on everything unmodelled, and by
     the ground-truth corpus as a test.
2. **a, read forms with a read profile, built narrow and new (answer 1).**
   - Benefit: 134 asks of 366.
   - Risk: an unmeasured program source. Bounded by the allow-list principle; reopens owner choice B of Runde 9.
3. **b, gh read forms.**
   - Benefit: 68 asks of 232.
   - Risk: gh version drift, bounded by the version check (answer 5).
4. **d, local forms in undeclared repositories.**
   - Benefit: 13 asks of 164, all in the undeclared repository.
   - Risk: a repository wrongly taken as undeclared; linked worktrees are out (answer 7).
5. **e, literal cd.**
   - Benefit: 13 asks of 151, and stricter pushes with tampered or missing evidence.
   - Risk: low (logical cd, existing directory).
6. **g, read and set of core.hooksPath.**
   - Benefit: no ask; 1 deny of 2 in the observer window becomes free.
   - Risk: a misread write. Bounded by the closed grammar.
7. **f, push destination.** Built separately (section 3.6).
8. **Siblings of section 4.** They come with c, where the steps are judged.

Under Codex a, d and e stay off (answer 10).

## 8. What becomes of D3 and D5

**D3.** Every Level 1 push stays NOT MEASURED at the destination (R9-1). Two things change:

- a push after literal cd steps resolves like the D32 form `git -C`;
- the sentence "the former free list has been removed" no longer holds for read forms, which are free under the read
  profile.

Owner choice B of Runde 9 stands for every other local form. K-NW-2 B (add and commit -m) frees its two forms as the
whole command and, by the owner's choice of 2026-10-14, 16:2x Berlin (A, Nachtrag 2), as steps of a plain chain:
simple commands joined only by `&&` or `;`, each judged as the same command alone, the strictest step deciding. Pipes,
`||`, background jobs, subshells and groups, substitutions, redirections, here-documents, assignments, alias, eval,
functions and a directory change in the chain keep the chain's answer, which names the two forms; so does anything
the parser does not recognise as exactly this form. A push in the chain keeps its own check.

**D5.** D5 C extends from the push (owner choice 1 A, unchanged) to local forms: inactive where the repository surely
declares nothing, as in 3.4. The push keeps its four conditions.

## 9. Owner answers of 2026-10-14, equal to the reviewer's recommendations

1. a: a read profile only as a narrow new build, not the prototype.
2. a: the git-lfs standard filter is not inert (option l declined).
3. a: the pipe property, and with it the inert pager, only for a bound host adapter.
4. b: no `gh attestation verify` (option b_att declined).
5. b: bind the rules to checked gh versions.
6. c: the inert-Python rule is rejected.
7. d: linked worktrees stay out of class d.
8. g: separate reading from setting for core.hooksPath; explicit hook overrides keep deny, also for a subcommand that
   is no push; indirect changes keep at least ask.
9. Siblings: judge redirection and tee targets with decide_write; an interpreter, or a program the gate does not know,
   with git or gh text asks at least.
10. Codex: a, d and e stay off.

## 10. Not measured

- The observer's real protocol, which the observer re-measures later. The one error is not rebuilt.
- zsh, the default shell on macOS, against the parser.
- Real Codex, and the Codex sandbox.
- gh versions other than 2.89.0, and git versions other than 2.43.0.
- GitHub's own handling of X-HTTP-Method-Override and of multi-operation GraphQL documents. The stand-in followed the
  GraphQL specification.
- The real git-lfs binary; a marker stood in.
- The terminal state of the Bash tool on a desktop Claude Code.
- Shell functions and aliases a host loads into its Bash tool before the command; the parser sees only the command.
- Windows.
- Run time under load.
- The plugin's suite for Fassung 1. Each delivery of the build runs it.

## 11. Files

`rueckfragen/skripte/`:

- `gate_inproc.py`
- `lesen.py`, `lesen2.py`
- `gh/gh_b.py`, `gh/gql.py`, `gh/lauf_b.sh`, `gh/zeige_b.py`
- `g/g_config.py`
- `shparse.py`, `prototyp.py`, `prototyp18.py`
- `korpus.py`, `aufbau.py`, `wahrheit.py`, `auswertung.py`, `kennzahlen.py`, `kennzahlen18.py`, `reihenfolge.py`
- `abschluss.py`, `zeit_codex.py`

`rueckfragen/messungen/`:

- `a_lesen.jsonl`, `a_lesen2.jsonl`
- `b_gh.jsonl`
- `g_config.jsonl`
- `korpus.jsonl`, `wahrheit.jsonl`, `auswertung.jsonl`
- `kennzahlen.txt`, `kennzahlen.json`, and the corrected `kennzahlen18.txt`
- `s283_neu.jsonl`, `reihenfolge.jsonl`
- `abschluss.jsonl`, `zeit_codex.jsonl`
