# Reading the push destination (Gegenstelle): design, version 2

Status: version 2 of the design draft, after review round 18 (subject GEGENSTELLE-ENTWURF), which judged version 1
with changes. The owner adopted every recommendation of the reviewer on the six questions of section 6 on
2026-10-14; they stand there as decisions. The build of variant d follows this document in the same branch
(`claude/plugin-gegenstelle-18`); section 7 is the contract it builds, and DECISIONS.md D33 records it.

What changed from version 1:
- Section 2: the sentence after the table is replaced by the reviewer's text (G18-2), and the reasoning under c
  follows it.
- Section 3d, the table in section 4 and section 5: the paragraph on what runs before consent and its table cell are
  replaced by the reviewer's text (G18-1); the recommendation adds the transport rule and the hand-over contract.
- Section 6 carries the answers to the six owner questions, equal to the reviewer's recommendations.
- Section 7 is new: the minimum contract of review round 18 and the contract as built.
- Section 8 names what is not measured, measurements of this version included.

Version 1 was measured on the plugin at 3604ba5364226ebf9ab2847974f7126a12845cf2 (claude/codex-plugin) and, for
finding 4, also at a85ac78ea424a0c5a24b8d389ef5da68ee834462, with git 2.43.0, Python 3.11.17, Linux, 4 CPUs; its
measurement files were delivered with the FIX-17 report and are not committed. Version 2 adds measurements with the
git of the build machine, git 2.34.1 (section 7.6); git 2.43.0 and 2.51.1 are not installed there.

## 1. The question

Finding 4 from the self-use, measured again at a85ac78e and 3604ba53 with the eval scaffolds and the event sent
straight to `proofbundle_gate.py`:

| scaffold | `git push origin main` | `git -C <ws> push origin main` (foreign cwd) | `git push origin refs/heads/main:refs/heads/main` |
|---|---|---|---|
| repo-valid | ask, push_not_measured | ask, push_not_measured | ask, push_not_measured |
| repo-tampered | deny, verification_failed | deny, verification_failed | deny, verification_failed |
| repo-missing | deny, missing_file | deny, missing_file | deny, missing_file |

Equal at both commits. The reason of every ask is `_dest_resolution_problem`: git looks the destination value up
among every ref the remote advertises to the push (`refs/heads/main` also matches `refs/refs/heads/main`,
`refs/tags/refs/heads/main`, `refs/heads/refs/heads/main`, weakly `refs/remotes/refs/heads/main` and
`refs/remotes/refs/heads/main/HEAD`), and the gate does not read the remote (D3). So no destination is evidenced
and no valid push passes without a person. The eval `gate-push-verified` expects the opposite.

Owner choice B (2026-10-14, 00:1x Berlin): the gate shall read the remote so that a push with valid evidence can
pass. That changes D3 and is security relevant, hence this draft first.

## 2. What git does with the destination (the ground truth every variant is held to)

Real pushes of `main` (and of `refs/heads/main:refs/heads/main`, same results) from a repository whose `main` is a
fast-forward of commit A, against a bare remote in twelve states, over a path and over smart HTTP:

| remote state | git push does |
|---|---|
| empty | creates refs/heads/main |
| refs/heads/main at A | moves refs/heads/main |
| refs/heads/main and refs/heads/refs/heads/main | refuses: "dst refspec refs/heads/main matches more than one" |
| only refs/heads/refs/heads/main | **writes refs/heads/refs/heads/main**, exit 0 |
| only refs/refs/heads/main | **writes refs/refs/heads/main**, exit 0 |
| only refs/tags/refs/heads/main | refuses: "[rejected] (already exists)" |
| only refs/remotes/refs/heads/main (weak) | **writes refs/remotes/refs/heads/main**, exit 0 |
| main and candidate, candidate in receive.hideRefs | moves refs/heads/main (the push does not see the candidate) |
| main and candidate, candidate in uploadpack.hideRefs | refuses: matches more than one |
| only candidate, in uploadpack.hideRefs | **writes refs/heads/refs/heads/main** |
| refs/heads/main in receive.hideRefs | the remote refuses: "[remote rejected] (deny updating a hidden ref)" |
| main and candidate, candidate in transfer.hideRefs | moves refs/heads/main |

So where the expected ref is missing and one candidate is there, git writes the candidate. Where both are there,
git refuses. The source tip is the same across these fixtures. This does not establish that the newly reachable
commits or the transmitted pack are the same. Level 1 checks the source-tip evidence. Level 2 must derive and verify
the complete per-target range from the state reported by Git. An absent target needs a separate initial-history and
policy rule.

## 3. Variants

### a. `git push --dry-run --porcelain --no-verify <remote> <refspec>` before the decision

Git connects to the receive-pack advertisement and resolves exactly as the real push does; nothing is sent.
Measured (96 runs: 4 transports x 12 states x 2 refspecs):
- Output per ref: `<flag>\t<src>:<dst>\t<summary>`; ` ` fast-forward with `old..new`, `*` new branch, `!` rejected;
  an ambiguous destination exits 1 with "dst refspec ... matches more than one" and no ref line.
- Against the real push (48 cases, path and HTTP): the dry-run names the ref git writes, or a refusal, in 44. The 4
  others are the destination itself in `receive.hideRefs`: the dry-run says `[new branch]`, the server then refuses
  the real push and writes nothing.
- The remote is unchanged in all 96 runs, and so is every file under the local `.git` (12 runs, mtime and bytes).
- Over HTTP the dry-run made exactly one request, `GET info/refs?service=git-receive-pack` (24 of 24); no POST.
- `old` in the summary is the remote's state of the destination as git saw it. Where that object is present
  locally, the D20 comparison and the range of newly sent commits can be made against the real remote state at
  Level 1. Measured with `repo-rules-changed`: dry-run `8826e93..9ae3dfb`, `8826e93` present locally, the rules at
  the two commits differ.

Programs it starts (`GIT_TRACE` and markers), plain and hardened. Hardened here:
`-c credential.helper= -c core.askPass= -c protocol.allow=never -c protocol.ext.allow=never` with `file`, `http`,
`https`, `ssh` allowed, `-c core.fsmonitor=false -c core.hooksPath=/dev/null`, `GIT_TERMINAL_PROMPT=0`,
`GCM_INTERACTIVE=never`, `GIT_ASKPASS` and `SSH_ASKPASS` removed.

| source of a program | plain | hardened |
|---|---|---|
| path or file:// remote | git-receive-pack, local | the same |
| http(s) remote | git-remote-http, git send-pack --dry-run, one GET | the same |
| remote that needs a login, credential helper configured | the helper runs and answers, the read succeeds | helper off, "could not read Username ... terminal prompts disabled", exit 128 |
| ssh remote (core.sshCommand or GIT_SSH_COMMAND) | the ssh command runs | the same; it cannot be switched off without reading another endpoint |
| remote.<name>.receivepack | the configured program runs | the same |
| remote.<name>.vcs (remote helper) | git-remote-<vcs> runs | "transport 'zzz' not allowed", nothing runs |
| url.<x>.pushInsteadOf to ext:: with protocol.ext.allow=always in the repository | the ext command runs | with `protocol.ext.allow=never` on the command line nothing runs; with only `protocol.allow=never` the repository's `protocol.ext.allow=always` still wins and the ext command runs |
| http.proxy | the proxy is contacted | the same |
| core.hooksPath with every hook, core.fsmonitor | nothing with `--no-verify`; without it git runs pre-push at a dry-run | nothing |

What runs before a person's consent that does not run today: today Level 1 asks before any transport; with a, the
transport of the push (ssh with the user's keys or agent, a credential helper with stored credentials, a proxy, a
configured receive-pack, a remote helper or ext command where the configuration allows it) runs inside the hook,
before the answer. Hardening can switch off credential helpers, prompts, ext and remote helpers. It cannot switch
off ssh, a configured receive-pack or a proxy without reading another endpoint than the push writes to. With
credential helpers off, a remote that needs a login for the advertisement is unreadable (measured on a local
`/auth/` route); hosted HTTPS remotes need a login for the receive-pack advertisement as a rule (not measured, no
network).

Without network, without credentials, on timeout, each exits 128 or runs into the deadline, and none gives a ref
line: closed port 0.009 s; HTTP that never answers, 5 s limit, killed at 5.006 s; login without credentials 0.015 s;
ssh connection refused (ssh stand-in) 0.004 s; missing path 0.004 s. Each maps to NOT MEASURED and ask as today,
never allow. Under the Codex sandbox without network: NOT MEASURED (no Codex there).

Time window between read and push (path remote):

| change after the dry-run | push without binding | `--force-with-lease=refs/heads/main:<old>` | `--force-with-lease=main:<old>` |
|---|---|---|---|
| none | moves main | moves main | moves main |
| main moved to a foreign commit | rejected, non-fast-forward | rejected, stale info | rejected, stale info |
| main deleted, refs/heads/refs/heads/main created | **writes refs/heads/refs/heads/main** | **writes refs/heads/refs/heads/main** | **writes refs/heads/refs/heads/main** |
| candidate created beside main | refused, more than one | refused | refused |

The lease binds the state of the named ref, not the resolution. And a lease that expects a foreign state turns the
push into a forced update (`+ ... (forced update)`, measured). The read cannot be bound to the push by an option the
gate could add; Claude Code's `updatedInput` for a rewritten command is not measured.

Runtime (load about 3.4 from a test suite on the same machine), three runs each: 1, 1000 and 10000 branches on the
remote; the hardened dry-run took 0.007 to 0.025 s over a path, 0.007 to 0.024 s over file://, 0.022 to 0.095 s over
HTTP and 0.009 to 0.026 s over the ssh stand-in. Against the hook timeout of 120 s (hooks.json) and the gate deadline
of 90 s (`DEADLINE_SECONDS`) local remotes are no cost; a real network round trip is not measured.

### b. `git ls-remote`

Shows the upload-pack advertisement, not the receive-pack one. The gate's candidate rule applied to that list agrees
with the real push in 28 of 48 cases. The unsafe divergence: the only candidate in `uploadpack.hideRefs`, ls-remote
shows nothing, the rule says refs/heads/main, git writes refs/heads/refs/heads/main. A candidate only in
`receive.hideRefs` makes b refuse a push git would do (false ask). (Four of the 20 divergences, the tag candidate,
are a gap of the model used here, which does not model the "already exists" refusal.) b reads another set of refs
than the push and is not git's own resolution: it breaks the reviewer's rule.

### c. No read: valid evidence and only the destination open give a hint instead of an ask

What is lost, measured:
- In the candidate-only states git writes another ref than the one named (refs/heads/refs/heads/main,
  refs/refs/heads/main, refs/remotes/refs/heads/main); the source tip is the checked one, the destination is not, and
  whether the newly reachable commits and the pack are the checked ones is not established (section 2).
- D20 at Level 1: `repo-rules-changed` with the remote on the state before the change. Today Level 1 asks
  (push_not_measured, with the local rules hint), Level 2 blocks with the named policy change. Under c the evidence
  at the source verifies (under the changed policy), so the push would pass at Level 1. A push that changes the
  evidence rules is exactly what D20 reports; c removes that report from Level 1.
- D3 can stay word for word ("the remote is not read"), but the consequence of R9-1 and owner choice C of
  2026-10-11 (a destination not evidenced asks) is reversed for valid evidence.

### d. Hand-over to Level 2: the gate reads the remote through git's own push

Level 2 is the gate's own `pre-push` mode, installed by the user with `install-pre-push` (D24B). git gives it, per
ref, the remote ref it resolved and the remote's object id from the same advertisement the push uses: in every
state where git does not refuse, the hook line names exactly the ref git then tries to write and its current object
id (all zeros where the push does not see it), including `refs/heads/refs/heads/main`. Where git refuses (more than
one match), the hook does not run. git also runs the hook at a dry-run.

End to end through git with the gate's pre-push mode (path and HTTP):

| evidence | remote empty (creation) | ff, same rules | only candidate | candidate beside main |
|---|---|---|---|---|
| valid | blocked: target_ref_absent | **passes, main moves** | passes, **refs/heads/refs/heads/main written** | git refuses before the hook |
| tampered | deny | deny | deny | git refuses |
| missing | deny | deny | deny | git refuses |

Rules changed: Level 2 blocks with "the policy .proofbundle/policy.json changes (... against 8826e932..., the
remote's state of the target as git reported it to the pre-push hook)".

Binding: the remote changed while the pre-push hook ran (main moved; main deleted and the candidate created); in both
cases receive-pack refused the update ("cannot lock ref 'refs/heads/main': is at ... but expected ..."; "unable to
resolve reference"). The hook's ref line and the server's compare-and-swap close the window that a and its lease
leave open. Version 1 measured four such protocol probes and two transport controls per git version, the reviewer
four and two per version under git 2.43.0 and 2.51.1; no finished L1-L2 hand-over was measured then.

This variant makes no separate remote probe. After Level 1 authorizes the actual push, Git starts its transport
before Level 2 runs. A configured receive-pack, SSH command, credential helper or proxy can therefore act before the
Level 2 verdict. Automatic hand-over requires an explicitly trusted transport configuration. Otherwise Level 1 still
asks. Binding the configuration detects changes but does not by itself authorize the programs it selects.

Under Codex with the sandbox and no network, Level 2 is fail-closed (D24B, measured there on 2026-10-08, not again
here).

Gaps measured in version 1: Level 2 lets a push write a candidate ref (row "only candidate"); Level 2 blocks the
creation of a ref; Level 2 is not installed by the plugin, so the eval scaffold has none.

### e. a as a pre-check, d as the verdict

The dry-run as a read for the answer text (which ref git would write, the remote's state) and Level 2 as the binding
verdict. It adds a's transport before consent to d and buys a better message; it does not change a verdict d makes.

## 4. Benefit, new attack surface, effort

| | benefit | new attack surface | effort |
|---|---|---|---|
| a | valid pushes pass where the remote is readable without credentials; D20 at Level 1 against the real state | the gate runs the push transport before consent: ssh keys and agent, credential helpers (unless off), proxy, receive-pack, helpers or ext where allowed; an agent-written configuration can choose them; the read is not bound to the push | high: refusal list for program-choosing configuration, hardening, porcelain parser, D20 at Level 1, tests with HTTP and ssh remotes |
| b | none over a | upload-pack transport before consent | low, unsound |
| c | every push with valid evidence passes | D20 lost at Level 1; candidate writes pass | low |
| d | valid pushes pass, for every transport and credential the user's push itself uses; D20 and the newly sent commits against the remote's state as git reports it; bound by compare-and-swap | This variant makes no separate remote probe. After Level 1 authorizes the actual push, Git starts its transport before Level 2 runs. A configured receive-pack, SSH command, credential helper or proxy can therefore act before the Level 2 verdict. Automatic hand-over requires an explicitly trusted transport configuration. Otherwise Level 1 still asks. Binding the configuration detects changes but does not by itself authorize the programs it selects. Level 2 is as strong as its hook (D27 class: an agent that can write the hook or the plugin cache chooses what runs) | medium to high: the hand-over contract of section 7, a destination rule and the update-set comparison in Level 2, the transport rule at Level 1, tests through git (the pattern exists) |
| e | d plus a better text | a's surface | d plus a |

## 5. Recommendation

d, with the two additions of version 1, with an explicit rule for the start of the transport and with a hand-over
contract that can be checked (section 7), and without a read before consent. The two additions alone do not
suffice (review round 18).

Reason, measured: d is the only variant whose read is git's own resolution at the moment of the push and is bound to
it (compare-and-swap refused both changes made during the hook). a resolves like git (44 of 48, the rest refused by
the server) but its read is a snapshot no option binds (a lease does not stop the candidate write), and it runs the
push transport inside the hook before a person sees anything. Hardening that transport makes most authenticated
remotes unreadable. b reads another advertisement and lets a hidden candidate through. c gives up D20 at Level 1.

The two additions to Level 2:
1. Destination rule: the remote ref on git's line must be the full destination Level 1 resolved from the command
   (`refs/heads/main`); another ref, such as refs/heads/refs/heads/main, stops the push with both names. Closes the
   measured candidate write.
2. Creation: a ref the remote does not have yet stays blocked in this build (answer 2, section 6); an owner rule for
   it needs the whole initial history and an explicitly defined initial policy (D24).

The transport rule: the transport of the push (its program, credential and proxy configuration) starts before
Level 2 judges. Level 1 hands a push over only where a person has explicitly approved that transport configuration;
any program-selecting configuration that is not approved stays an ask, before the transport acts.

The hand-over contract: section 7.

What becomes of D3: "The remote itself is not read" stays true for Level 1. Level 2 reads the remote's state as git
reports it (as D20 and D24 already say). The consequence of R9-1, every Level 1 push asks at the destination check,
changes for the one case "only the destination is open, the transport is approved and a bound Level 2 is installed":
Level 1 then makes no permission decision and names the hand-over; otherwise it asks as today.

What remains of `_dest_resolution_problem`: all of it, as the classifier. A value that does not name the
destination, a recorded candidate and the default case keep their reasons; the default case ("whether the remote
holds one of them is not known here") becomes the one reason that may be handed over. Its text stays the answer
where no hand-over happens.

## 6. The owner questions, answered (owner adoption of 2026-10-14 of the reviewer's recommendations)

1. d with the destination rule: may Level 1 allow (with a named hand-over) where only the destination is open and a
   bound Level 2 is installed?
   **Answer:** choose d, with the transport rule and a described hand-over contract. Git delivers the right concrete
   ref and the old object id. Merely installed hook bytes do not yet justify an automatic allow.
2. Creation of a ref with valid evidence: pass, pass only for a new branch outside a protected set, or ask as today?
   **Answer:** for the first build, keep blocking new refs. D24 requires the whole initial history and an explicitly
   defined initial policy for them. Valid tip evidence or an unprotected branch name replaces neither.
3. `gate-push-verified`: keep the expectation, or change the case?
   **Answer:** move the positive eval to an existing main, unchanged rules, a real fast-forward and an actually
   installed Level 2. Keep the empty remote as a creation-block case of its own. A scaffold without the hook must not
   give a positive hand-over result.
4. Should a ever run, for a better text (e)?
   **Answer:** do not introduce a and e for better messages. They start transport and authentication in addition,
   and they create no additional binding of the later push.
5. Without Level 2 installed: stay at ask, or offer `install-pre-push` in the answer?
   **Answer:** without a bound Level 2, stay at ask. `install-pre-push` may be named as a voluntary next step. No
   automatic installation and no overwriting of a foreign hook. Installation and actual execution are separate
   pieces of evidence.
6. Under Codex nothing changes. Confirm.
   **Answer:** leave the Codex Level 1 behaviour unchanged and describe the standalone Level 2 mode. Do not treat the
   missing execution context of D12 as bound. The real Codex run stays necessary.

## 7. The hand-over contract

### 7.1 The minimum contract of review round 18 (recommendations, adopted)

- Only the concrete open destination-resolution reason may be handed over, not every `push_not_measured`. Evidenced
  failures stay deny, other open reasons stay ask. Level 1 allows one bound attempt and logs no evidence PASS.
- The expected order contains repository, worktree, remote, effective URL, normalised push form, source OIDs, full
  expected target names and a one-time, short-lived binding to the operation. A token the agent can write freely is
  no proof of origin.
- The channel and the check of the hand-over must be described. Missing, foreign, stale, consumed or unattributable
  data must inherit no approval. The selected git, the hook bytes, the gate file actually loaded, the plugin version,
  the interpreter, the environment and the effective configuration belong to the binding.
- Level 2 compares the whole actual update set with the expected order. Additional, duplicate or contradicting
  updates are refused. A true no-op may be left out by git and must be treated explicitly as such.
- D20, the evidence and the done check apply to every actual target range. Missing old objects, incomplete history,
  limits, errors or an abort stay closed.
- The standalone Level 2 call without a Level 1 hand-over, in particular under Codex, needs an explicit mode. git's
  actual target name alone does not show agreement with an unknown expected target.
- A Level 2 PASS is not yet a successful remote update. Empty stdin, a no-op and `inactive` must not claim a checked
  update. The actual end result of git stays separate.
- D24 and D27 keep their limit. A local, changeable hook does not become a tamper-proof publication boundary through
  the hand-over. Receiver-side or required CI checks stay necessary.

Catch cases a build must hold at least: a valid fast-forward, a wrong done check, missing or falsified evidence, an
invalid intermediate commit, a D20 change, the candidate alone, mixed multiple updates, a new ref, an invalid
hand-over, a disabled hook, an unexpected plugin version, a no-op, an abort and a later server error. The transport
that is not approved must ask before its effects.

### 7.2 When Level 1 hands a push over (the one place in Level 1)

The hand-over is decided at one place, in the Level 1 push path (`evaluate_push`), after every check that runs
today, and only where all of the following hold. Where one does not, the answer is the one of today (deny for an
evidenced failure, ask otherwise), and the ask names the condition that failed.

1. The host is Claude Code. Under Codex nothing changes (answer 6): the plain `git push` warns as before.
2. The call is a `git push` Level 1 reads in its strict form, and the whole command is the plain push form
   (`_codex_plain_push`, the form that warns under Codex): one simple command headed by a bare `git`, no prefix
   assignment, chain, wrapper, global option, other git path, expansion, redirection that opens a file or option word
   the shell may rewrite. The binding measures the git a plain `git push` starts in the hook's environment; a prefix
   assignment runs it in another environment, and a dashed, quoted or escaped command word may run another program
   (adversarial lens of 2026-10-14). `gh` calls, MCP tools and `send-pack` are no hand-over.
3. Every target of the push resolves up to the destination check, and the one reason left open for each is the
   default case of `_dest_resolution_problem` ("whether the remote holds one of them is not known here"). A value that
   does not name the destination, a recorded candidate, a deletion, an unresolved source and every other open
   reason are no hand-over.
4. The evidence at every source commit verified (pass), or, where a source declares only a done check, that done
   check passed. A source that declares nothing is no hand-over (D5 keeps its own path).
5. No rules hint of owner choice 4 A is open: Level 1 found no difference of the evidence rules against a local
   record and no comparison it could not make.
6. The approval mode is `with-approvals` (D25): in `strict` no rule acts, and a transport approval is a rule.
7. The transport is approved: the human-written file `transports.json` in the gate directory holds an entry for this
   repository, remote and effective push URL whose transport digest equals the one Level 1 computes now (7.4).
8. A bound Level 2 is installed: the pre-push hook at the hook path git uses for this repository is a regular file,
   executable, no link, byte for byte the wrapper `install-pre-push` writes, and the gate that wrapper finds at push
   time is this gate file, the file Level 1 runs, with this plugin version.
9. The git on PATH is byte for byte the `git` in the exec path it reports (adversarial lens of 2026-10-14, F1): only
   git starts the pre-push hook, so a wrapper, a script or a shim earlier on PATH is no hand-over.
10. Level 1 can write the hand-over record and the pointer (7.3).

Then Level 1 makes no permission decision (D4 stays: the gate never answers allow, and the host's own permission
flow decides) and names the hand-over in its message: what it checked, that the transport is approved, that git's
pre-push hook gives the verdict on the actual update, and the record. The log records the verdict `handover`, never a
`pass` (7.1). Without a bound Level 2 the answer stays ask and may name `install-pre-push` as a voluntary next step
(answer 5); the gate installs nothing.

### 7.3 The channel

- The record: Level 1 writes one JSON file, `<gate directory>/handover/<nonce>.json`, created exclusively, mode
  0600. The gate directory is the one of D25; a file tool cannot write it (decide_write denies it under both hosts).
  A shell command can (D27, F15-2): the record proves no origin, and it grants nothing Level 2 does not check again
  itself; it only narrows what Level 2 accepts.
- The pointer: Level 1 writes `<git directory>/proofbundle-handover`, the per-worktree git directory of the
  repository, holding the nonce and the record's schema. It replaces an earlier pointer of the same worktree, so at
  most one hand-over is live per worktree. The pointer is found by git's own repository, not through the
  environment, so a Level 2 that runs under another gate directory still sees that a hand-over was given.
- Consumption: Level 2 renames the pointer and the record to `<name>.consumed-<nonce>` before it judges; whoever
  renames first owns the hand-over, so it is used at most once. Every outcome consumes it: a pass, a block, a
  refusal of the hand-over itself.
- Validity: 300 seconds from the moment Level 1 wrote it (`HANDOVER_TTL_SECONDS`).

The record's fields: schema, nonce (128 random bits), created and expires (seconds since the epoch), repository (the
git common directory), worktree, git directory, remote, push URL, the push words after `push` as Level 1 read them
(the normalised push form, for the log; Level 2 cannot see the command line and compares the update set instead),
the expected updates (`source` OID and `dest` full ref name each), and the binding: git's exec path and the sha256 of
the git program Level 1 runs, the sha256 of the hook file, the gate file's path and sha256, the plugin version, the
interpreter, the digest of the program-selecting environment, the digest of the effective configuration and the
transport digest.

### 7.4 The transport approval

- `<gate directory>/transports.json`, written by a person and only read by the gate: a JSON array of entries
  `{repo, remote, url, transport_digest}`. The same rules as `rules.json` (D25): strict JSON, no repeated key, exact
  keys, at most 256 entries, a file the gate cannot read whole approves nothing; a file tool cannot write it.
- The transport digest is the sha256 of a canonical serialization of what selects the transport's programs,
  credentials and proxy: the push URL; every effective configuration entry of `remote.<remote>.*`, `url.*.insteadOf`,
  `url.*.pushInsteadOf`, `core.sshCommand`, `core.askPass`, `core.gitProxy`, `ssh.*`, `credential.*`, `http.*` and
  `protocol.*`, each with scope and origin; the environment names `GIT_SSH`, `GIT_SSH_COMMAND`, `GIT_SSH_VARIANT`,
  `GIT_ASKPASS`, `SSH_ASKPASS`, `SSH_AUTH_SOCK`, `GIT_PROXY_COMMAND`, `GIT_ALLOW_PROTOCOL`, `GIT_PROTOCOL_FROM_USER`
  and the proxy names; git's exec path with the sha256 of `git-receive-pack`, `git-remote-http` and
  `git-remote-https` there, and the `ssh` on PATH with its sha256 where the URL is an ssh URL.
- A person computes it with `proofbundle_gate.py transport-digest [--repo DIR] [--remote NAME]`, which prints the
  digest and an entry to copy. The gate never writes the file. Every hand-over names the file, when it last changed
  and its sha256, and says that the gate cannot tell who wrote it.
- The approval authorizes the programs its digest binds; any change of them changes the digest, and Level 1 asks
  again before the transport acts.

### 7.5 What Level 2 checks

Level 2 has two modes, and it says which one ran.

Standalone mode, where the worktree holds no pointer: the verdict of D24 as before, on git's ref lines. Its pass and
inactive texts say that Level 2 ran without a hand-over from Level 1 and that git's destination names were not
compared with an expected target (answer 6).

Hand-over mode, where a pointer is present. In this order, each refusal blocks the push (exit 1) and names its reason:
1. the pointer is read whole and consumed; the record it names is read from Level 2's own gate directory, whole,
   strict, with the exact fields, and consumed. Missing, unreadable, malformed, already consumed or foreign data
   (another schema, another nonce) refuses;
2. the record has not expired, and was not written in the future;
3. the binding holds: repository, worktree, git directory, the remote and push URL git hands the hook as its two
   arguments, git's exec path (`GIT_EXEC_PATH`, which git sets for the hook) and the sha256 of the git program that
   started the hook where the system shows it (`/proc/<parent>/exe`), the sha256 of the hook file, this gate file's
   path and sha256, the plugin version, the interpreter, the environment digest, the configuration digest and the
   transport digest. Level 2 recomputes each of them itself;
4. the update set: every ref line must be one of the expected updates, with its source; a line twice, a line of
   another destination (the candidate, named with both names), another source, a deletion or any other update
   refuses. An expected update without a line is one git left out because the remote already holds it (a no-op,
   measured with git 2.34.1: git runs the hook with no line for an up-to-date ref), named as not checked;
5. the evidence, the done check and D20 at every actual target range, the core of D24 as before. A ref the remote
   does not have yet stays blocked (answer 2); a shallow history, a range over 64 commits, a missing object and every
   error stay closed.

A pass says which hand-over it checked and that a Level 2 pass is no successful remote update: git's own end result
(a refusal of the remote, a compare-and-swap that fails) is separate. Empty stdin is answered as "no update reached
the hook; nothing was checked", never as a checked update.

### 7.6 Measured for this version (git 2.34.1, the build machine)

Measured with a script of its own through real pushes to local bare repositories (delivered with the report):
- git hands the hook the remote's name and the effective push URL as its two arguments, a `pushurl` and an
  `insteadOf` rewrite applied.
- git puts its exec path first on PATH and sets `GIT_EXEC_PATH` and `GIT_PREFIX` for the hook; a `-c` of the command
  reaches it as `GIT_CONFIG_PARAMETERS`. The hook's parent process is the git program (`/proc/<parent>/exe`).
- A push of an up-to-date ref ("Everything up-to-date") runs the hook with no ref line.
- G18-1 reproduced: with `remote.origin.receivepack` set to a program that writes a marker and starts the real
  receive-pack, and a pre-push hook that exits 1, the transport marker comes first, then the hook marker; the remote
  stays unchanged.

## 8. Not measured

- git 2.43.0 and 2.51.1 for this version; they are not installed on the build machine. git 2.56.0 where it is built.
- Whether the environment of the host's hook (Level 1) and of the shell the agent's push runs in (Level 2) carry the
  same values for the names the binding reads, in a real Claude Code session; where they differ, Level 2 refuses the
  hand-over (fail closed).
- A real ssh server and client, hosted remotes (GitHub, GitLab), real network round trips.
- Claude Code's `updatedInput` (a rewritten command) as a binding.
- `claude -p` and `codex exec`: what an ask does in a session without a person.
- The Codex sandbox without network for this version.
- Windows and macOS; on a system without `/proc/<parent>/exe` the git program is bound through its exec path only.
- `claude plugin eval` runs of the changed eval cases (each is a model call); whether the eval harness hands the
  scaffold's gate directory to the host's hook.
