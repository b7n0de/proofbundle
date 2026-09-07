# Residual risk, release 6.0.0 — the record before the closing gate round

This file exists because the release may take the `PARTIAL_GATE_NO_WITHSTANDS` exit, as 5.1.0 did.
That exit comes with one condition: every finding that stays open is named here, with its class,
its funnel verdict and the reason. A residual risk that is not written down is not a residual
risk, it is an omission.

**Nothing in this file is a claim that the release is defect free.** It is the list of what was
known and open when the tree was frozen, and why each item was judged not to block.

## Why this file is committed before the round, not after it

For 5.1.0 the record was written after the closing round. For 6.0.0 the owner fixed the order on
2026-09-05: this file lands on `main` first, the head that carries it is the frozen tree (the
byte-freeze standard of 2026-07-31: freeze first, publish later, never reload mid-sequence), and the
closing gate round — DEEP, six lenses, refute-to-kill jury — runs on exactly that frozen head. The
pre-tag receipt that the tag depends on binds this file by its sha256, so it cannot be edited once
the receipt exists.

What follows from that order is stated plainly: a finding of the closing round that must be fixed
or must be written down is a **new iteration with a new freeze** (standard, rule 2), never an edit
of this file and never a second file next to it — a new top-level file would move the tree digest
the receipt binds. The round's own outcome (verdict tag, lens count, the standing targets by name)
is recorded in `audit_artifacts/600/README.md` next to the receipt, where 5.1.0 recorded it too.

## The funnel, so the verdicts below can be checked

A finding blocks this release only if it can reach a user of the shipped package: a wrong
verification result, a receipt that verifies when it should not or is refused when it should not,
data loss, an import error in the shipped package, a security hole, a broken public interface.

A finding does not block if it lives in the guards above the guards, in ratchets, in test
coverage, or in the self consistency of test files. Those are recorded, classified, and written to
the class ledger. They are not nothing, they are simply not this release.

## Carried over from 5.1.0, measured again on 2026-09-05 at `658ed063`

Each row says whether it was re-measured. "Not re-measured" is a state, not a pass.

### R1 · A shipped specification artefact contradicts the shipped code — open, re-measured

`scripts/rust_parity_registry.json` (in the sdist) still says of the v0.2 verifier that it
"deliberately does not decide that for it (`policy_decision stays None`)" — one occurrence, measured
with `grep -c`. In 6.0.0 the same state is reported as `policy_decision: null` plus the advisory
code `POLICY_NOT_EVALUATED`, and `automation.safeForAutomation` is `false` for it (CHANGELOG
6.0.0, "a named policy axis"). The registry frames that state as neutral; the verifier treats it as
"not authorised for automation". `POLICY_NOT_EVALUATED` appears three times in
`automation_verdict.py`, as at 5.1.0.

**Funnel: it can reach a reader** building a second implementation from the registry. **Why it does
not block:** it shipped unchanged since 5.0.0, and correcting the registry would move the frozen
tree for a defect this cycle did not introduce. **Class:** a shipped document describing intended
behaviour that the shipped code no longer has.

### R2 · A subfield reads safer than before, against the invariant the round enforced — open, NOT re-measured

The 36-case measurement of 5.1.0 (`referencesResolved` false → true, `subject_binding_ok`
False → None when `SUBJECT_NAME_UNDERIVABLE` fails the structure early) was not repeated in this
cycle. Nothing in the 6.0.0 diff touches that code path by intent, and that is an argument, not a
measurement. Funnel as before: `safeForAutomation` stayed `false` in all 36 cases.

### R3 · `resolve_receipt_chain` raises a raw exception on a non-mapping envelope — open, re-measured

Measured at `658ed063` against `proofbundle.agent_review.resolve_receipt_chain`:

    resolve_receipt_chain(None,     verified=None)  TypeError: 'NoneType' object is not iterable
    resolve_receipt_chain(42,       verified=None)  TypeError: 'int' object is not iterable
    resolve_receipt_chain(['text'], verified=None)  AttributeError: 'str' object has no attribute 'get'
    resolve_receipt_chain([42],     verified=None)  AttributeError: 'int' object has no attribute 'get'
    resolve_receipt_chain([{}],     verified=None)  returns a dict, no raise

Unchanged. One fact is added this cycle because the deep gate's public contract needs it: the name
is **not exported** (`"resolve_receipt_chain" in dir(proofbundle)` is `False`), so under the
never-raise contract of the public surface it is an internal helper whose public callers must
wrap it. The round attacks the public entry points; a crash reachable only through the helper
called directly stays recorded here, not as a gate finding.

**Funnel: it reaches a caller who passes malformed input** and produces a crash instead of a
verdict, never a wrong verdict.

### R4 · Verify sites report an internal error for a truthy non-list — open, re-measured in count only

`or []` occurs **19 times** in `agent_review.py` at `658ed063` (13 at 5.1.0; the module grew by
582 lines with v0.2). The four reachable verify sites named at 5.1.0 were not re-derived for the
new positions, and the new occurrences were not classified as reachable or not. That is a gap of
this record, stated rather than smoothed over. Funnel as before: reaching a site requires the
trusted key; a foreign key yields `crypto_ok=False` first.

### R5 · The guard that should catch changelog omissions is blind to content — open, unchanged by design

`scripts/check_version_and_changelog.py` verifies that a `## [6.0.0]` heading exists (its own
docstring, rule 2) and never reads the section. The 6.0.0 section was therefore written and checked
by hand from the merged pull requests (#171 to #186), and the closing round's fidelity lens reads
it again. **Funnel: no user is affected.**

### R6 · The witness cannot see the lenses of a round run in a foreign repository — open, unchanged

`scripts/b7_abschluss_beleg.py` counts lens artefacts under
`office/governance/berkeley_gate/runs/lenses/<topic>` inside the tree it signs — this repository's
tree, which carries no such directory. The closing evidence record for 6.0.0 will therefore read
`PARTIAL` with `0 of 6 lenses` as its named cause, exactly as the 5.1.0 record did, while the six
lenses live in the operator's repository. **Funnel: no user is affected.** A witness that reads a
second tree is filed on the operator's side and is not part of this release.

### R7 · Three numbers in shipped artefacts are wrong, each already wrong when written — open, re-measured

Measured at `658ed063`:

    pyproject.toml:111   claims `test_adapters.py` "19 of 19"   -> 10 `def test_` in that file
    MANIFEST.in:43       claims "14 conformance cases"          -> 30 `case.json` under conformance/agent_review/
    pyproject.toml:140   claims mypy over "63 files"            -> 68 source files (measured on
                                                                    the release candidate)

All three still wrong; two drifted further since 5.1.0 (14 → 30, 63 → 68). Both files are inside
the sdist. **Funnel: no user breaks** — no code path reads these comments. **Why they stay open:**
correcting them moves the frozen object for three comment lines; that trade is the owner's to make,
and it was not made for 6.0.0.

**A correction to this very entry, and it is the same class R7 complains about (2026-09-06).** The
third line above said "67 source files". That number is correct at `658ed063`, the head R7 names as
its own measuring point — and already wrong at the release candidate, where `mypy src` reports 68,
because `src/proofbundle/_statement_payload.py` was added in between. An entry that catches a
comment for describing an older tree described an older tree itself. The figure now states the
candidate and says which head it was measured on. Found by an independent review lens, not by the
author of the entry — which is the honest part of the story.

## New in this cycle, known before the round

| Id | Finding | Class | Funnel verdict |
|---|---|---|---|
| N1 | Lens 2 on PR 185: the flip oracle of the A5 corpus test read one field; fixed to require `ok` (`bc95dd6`). The wider class — narrow-scope comparison oracles — is not swept repo-wide | test integrity | does not reach a user; recorded |
| N2 | Lens 2: the corpus input key serialised the whole `params`; fixed to the keys the runner reads, meta test both ways (`bc95dd6`) | test integrity | does not reach a user |
| N3 | Lens 3: the `Receipt:` line of a published disclosure block is the file hash, not `receipt_digest()`; documented in 6.0.0 rather than changed, because two published receipts carry it | documentation, chain semantics | can mislead a reader who copies the line into `priorDigest`; written down in the CHANGELOG and AGENT_REVIEW_PREDICATE.md |
| N4 | `POLICY_NOT_EVALUATED` and `AGENT_REVIEW_LEGACY_V01` moved from `reason_codes` to `advisory_codes`; a consumer of an unpublished pre-6.0.0 build that branched on `reason_codes` changes behaviour | interface | none for published users — no release carried either code before 6.0.0 |
| N5 | `agent-review/v0.2` emits only `selfDeclared` assurance; a witness outside the agent workspace is not provided | scope | documented honest limit |
| N6 | The `time` block of a policy file is new and evaluated only when present; the shipped standard policy carries none (`time_policy_decision: null`) | interface | documented |
| N7 | The sibling-venv full run on PR 185 reported 3245 passed and 22 skipped; the skipped set was not enumerated. The audit run of the freeze (`pytest -rs`) enumerates it and the receipt README lists it | test coverage | recorded when measured; not a package defect |
| N8 | `audit-candidate-matrix` reports C12.1 as not applicable on a pull request and as absent on `main` until the signed 6.0.0 receipt exists — the gate at work, not a defect | process | none |
| N9 | The relative `CHANGELOG.md` link in the new README section was dead in the sdist; fixed to an absolute URL (`72c21e7`). Class: links on surfaces without a root; the shipped-docs test checks its named links, the README was not swept beyond them | documentation | none after the fix |
| N10 | CAP-1 coverage (`feat/cap1-abdeckung`, target 6.1.0) is not part of 6.0.0 by decision; the branch is not in the frozen tree | scope | none |
| N11 | The canonical full mutation run (`scripts/mutation_check.py`, docs/PRE_TAG_AUDIT.md: "a tag is never cut on a sharded run alone") was started on `658ed063`, the merge of PR 186, before this file existed. Its inputs — `src/`, `tests/` and `scripts/` — must be byte-identical between `658ed063` and the frozen head for the result to count; that identity is measured with `git diff --stat` and recorded in the receipt README, or the run is repeated | process | none if identical, repeated otherwise |
| N12 | The learned-class ledger replay that gates the round cannot finish inside the fixed 240 s window its runner carries as a default: the 182 nodes measured 479 s on the release machine, and three runs ended `env_blocked` at exactly 240 s — at load 22, at load 6.4, and against the healed ledger. The replay itself is sound: measured to completion under a wide window it reports `pass`, 188 tests, 0 unexplained classes, 0 unusable evidence fields, with head and ledger digest identical before and after. The window is a property of the release-side replay runner, not of shipped code | process, gate instrumentation | none for a user of the package. For the round it means the phase-1 evidence comes from a measured run under a wide window, named here rather than left implicit |
| N13 | The same replay set contains at least one node whose result depends on runtime state OUTSIDE the tree under test: `tests/test_warte_riegel.py::test_l2it2_...` was reported red by one runner (`failures=1`, status `regression`) with a literal assertion over a hook line reading `TUER-OHNE-KARTE-Pruefung nicht auswertbar (FileNotFoundError) — durchgelassen`, and green on re-measurement under both interpreters (125.78 s and 157.61 s). A `regression` from this source aborts the gate as FIX_FIRST without any learned class having actually returned. Both the hook and the replay runner belong to the 2bedone repository, not to this package | process, foreign repository, non-determinism | none for a user of the package; recorded because it can decide this package's gate verdict |
| N14 | Class: a signing path in the shipped tree. INSTANCE `scripts/sign_readiness_artifact.py` is CLOSED — the inline `--privkey-file` mode is gone and, measured by AST, no code path in that file loads a private key. INSTANCE `scripts/pre_tag_receipt.py` is DEFUSED, not closed: its inline mode remains as the owner's signing path on the Mac, but the script is excluded from the sdist (`MANIFEST.in` lists `scripts/` file by file since 2026-09-06) and refuses to run inline unless `PB_INLINE_SIGNING=1` marks the key-holding machine, and never on an automated build host. The CLASS itself — a build host that can reach a private key at all — is answered by the separate signing principal (NACHTRAG2 Teil E) from 6.1 onward, not in 6.0.0 | supply chain, self-certification | defused for 6.0.0 by packaging exclusion plus owner signature on the Mac; the exclusion is measured against a really built sdist (`tests/test_sdist_ohne_signierwerkzeug.py`, AST-based so a docstring mention does not count as a code path), and the inline mode refuses to run without an explicit `PB_INLINE_SIGNING=1` and never on an automated build host. The CLASS — a build host that can reach a private key at all — is carried to 6.1 with the separate signing principal (Teil E); this entry stays OPEN in the register until then. Owner decision 2026-09-06, card OA-8b1a31cc4f, revision withdrawn the same day; reported to the reviewer in round 3 as a neighbour finding with this reasoning |
| N15 | Both distributions of 6.0.0 are **bit-reproducible as shipped**, and this section states the property with the path to recompute it rather than a digest, because a digest written inside the tree that produces the artefact is a fixed point nobody can hold: changing the number changes the tree, the tree changes the artefact, the artefact changes the number. The digests of what is actually delivered belong in the `SHA256SUMS` of the GitHub Release, outside the tree — the same place 5.1.0 publishes them. **How a reader checks it.** Export `SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)"`, then run `python scripts/build_reproducible.py --outdir dist --with-wheel` — exactly the ONE line `.github/workflows/release.yml` runs (line 143). **This instruction was wrong until 2026-09-07 and following it would have misled you**: it named two lines, the second a bare `python -m build --wheel`, which produces a wheel the release does not ship — a reader would have computed a digest that differs from the delivered artefact and could reasonably have concluded the artefacts do not reproduce. The correction was applied to `audit_artifacts/600/README.md` and to the changelog on 2026-09-07 and NOT here; a gegenlesung found the leftover. That matters more here than elsewhere, because this file's sha256 is what the pre-tag receipt binds as `audit_output_digest` — the sentence goes out signed. Do it twice into two separate directories and compare with `sha256sum`. Measured on this candidate: both runs byte-identical, for the wheel and for the sdist. Note that `SOURCE_DATE_EPOCH` is bound to the HEAD commit time, so a checkout at a different commit legitimately yields different digests; reproducibility here means "the same tree twice", not "the same number forever". **About the sdist, in four statements, because the earlier wording accused this release of something it does not do.** First: the sdist that ships is the NORMALISED one — `release.yml` builds it with `scripts/build_reproducible.py`, never the raw `python -m build --sdist` output — and it came out byte-identical across two independent runs. Second: the RAW setuptools output is genuinely not bit-reproducible, and the cause is measured to the byte — the sdist path of setuptools 84.0.0 (`setuptools/_distutils/archive_util.py::make_tarball`, which calls `tar.add(base_dir, filter=_set_uid_gid)` and normalises uid and gid but not mtime) does not honour `SOURCE_DATE_EPOCH`; the variable occurs exactly once in the whole setuptools tree, in the vendored wheel writer (`setuptools/_vendor/wheel/wheelfile.py:53`). Each raw archive therefore carries a pax header with the wall clock at sub-second precision, and the differing number of decimals changes the pax record length by one byte, which cascades into the header checksum and the compressed size. Third: whoever builds this project with plain setuptools instead of the shipped path will therefore NOT reproduce, and that is said here plainly rather than left for them to discover. Fourth: the normalisation exists precisely for this reason, and `tests/test_reproducible_build_361.py` has asserted it since 3.3.1. Owner decision 2026-09-06 (card `OA-b94f677926`, option A): the concrete wheel digest comes out of this entry, the property with its recomputation path takes its place, and the delivered digest goes where it is not circular. The earlier wording said "the sdist is not [bit-reproducible]" — true of the raw intermediate, false of what is delivered. A false self-accusation is as wrong as an overclaim, only in the other direction. The build-backend change remains a 6.1 item with its own measurement and no time pressure. | build-tool reproducibility, corrected 2026-09-06 | none for a user of the package — both delivered artefacts reproduce; the digests live in the Release SHA256SUMS |

## What was measured and did not become a finding

At `658ed063`, before the round: the version is single-sourced (6.0.0 in `pyproject.toml`,
`__init__.py`, `CITATION.cff`, `check_version_and_changelog.py` OK); the 6.0.0 section exists and
carries the break in one sentence; the readiness slot for 6.0.0 is filled and the advisory
candidate matrix was green on the pull request head `5657a98`; the CI of PR 186 was green on all
33 checks before the merge; the CAP-1 branch is outside the tree.

## Added after the closing round, on an explicit owner instruction (2026-09-06)

**This section is an exception to the rule three sections above, and it names itself as one.** That
rule says a finding of the closing round is "never an edit of this file". Its stated reason is the
freeze plus the fact that the pre-tag receipt binds this file by sha256. Both premises changed by
owner decision on 2026-09-06: the ceremony opened the tree for the register commit, the release
note and the rebuilt distributions, and the receipt does not exist yet. The owner then asked for
this file explicitly. So the edit is authorised rather than assumed — and it adds no finding text
to the pre-round record above, which stands unchanged as R1-R7 and N1-N15.

**Where the closing round is recorded.** The verdict is `FIX_FIRST`; no `WITHSTANDS_DEEPGATE` is
claimed for 6.0.0. The round's own record — verdict, the three confirmed findings with their
measurements, the scope each statement holds over, and the one operator whose outcome is not
measurable — lives in [`audit_artifacts/600/README.md`](audit_artifacts/600/README.md), next to the
receipt, where 5.1.0 recorded it too. The `## [6.0.0]` section of `CHANGELOG.md` carries the same
facts for a reader who never opens this file.

**The structured, signed carrier is the register, not this prose.** `audit_artifacts/findings_register_361.json`
(the path is historical; the register inside is version-bound and states `6.0.0`) holds **20 entries
as of `generated_at` = `2026-09-06T10:27:05Z`**: 13 closed, 7 open — `N14`, `N15`, `N16`, `N17`,
`N18`, `N19`, `N20` — and **0 open P0/P1**. It is signed with the release anchor key, and
`audit_candidate_matrix` check `C12.2` counts from those structured fields, never from a sentence
here. If this section and the register ever disagree, the register is the one that decides.

**The register is a STATE AT `generated_at`, not a closure — and its own preamble does not say so.**
Its docstring calls it the SINGLE STRUCTURED SOURCE for the open-P0/P1 count without naming the
time cut. That wording is correct about *what it decides* and silent about *when it was taken*, and
the silence matters: the review lens kept running after the signature and found more. The signed
artifact cannot be changed any more, so the correction lives here and in the release note, by owner
decision of 2026-09-06 (card `OA-3aef42655d`, option A with four conditions). **Read the count as:
20 entries, 0 open P0/P1, measured at 2026-09-06T10:27:05Z.** For 6.1 the register gets a field
that names its own time cut and where later findings are recorded, so a machine reader does not
have to take it out of prose.

**The five entries this round added, in one line each**, so that a reader of the residual-risk
record does not have to open a second file to learn that they exist:

| Id | In one line | Closed where |
|---|---|---|
| N16 | The published composite action interpolates two untrusted inputs straight into a `run:` shell body; byte-identical to the public `v1.0.0` tag, so 6.0.0 neither creates nor removes it | follow-up release; the ref decision is outward-facing and needs its own owner GO |
| N17 | The parity gate swallows an unparseable source file and then rules from the ABSENCE of complaints over what is left; on this candidate the population is complete (68 of 68) | follow-up release |
| N18 | `pip install <sdist> && pytest` without the `[test]` extras is RED, not skipped, while `pyproject.toml` promises "clean skips" | follow-up release: honour the promise or reword it |
| N19 | The mutation gate collects with `unittest discover` and therefore measures 2537 of 3702 tests, **measured at `59d0679`**; 59 of 252 test files are invisible to that collector. The suite grew after that measurement (closing-round fixes added test files; 3727 collected / 254 files at the time of writing), so the figure names its commit rather than claiming a ratio for the tagged tree | follow-up release: move the collector |
| N20 | One mutation operator is NOT MEASURABLE rather than killed or survived — it removes the resource ceiling under test and the run reached 111 GiB resident before being stopped deliberately | follow-up release: bound the operator |
| N21 | **The release-deciding check `C12.2` flips PASS to FAIL on 2027-09-07 by design.** The closing-round fix makes an expired anchor key authorise nothing *now*, and the sole key carries `not_after=2027-09-06`. An empty authorised set is a FAIL, not `DATA_BLOCKED` — only an unreadable anchor is the latter — so from that day the audit matrix goes red until the key is rotated. This is the intended behaviour of a validity window and not a defect; it is listed because a gate that turns red on a calendar date must be written down before it does, not explained afterwards | rotate the key before 2027-09-06, or accept the red |

## Found AFTER the register was signed (owner condition 2, card `OA-3aef42655d`)

These were found by the mandatory review lane **after** `generated_at` = `2026-09-06T10:27:05Z`, so
none of them is in the signed register. Each gets its own row — a collective line would hide which
assurance each one touches. None of them changes the assurance **0 open P0/P1**: that count speaks
about P0 and P1, and every entry here is P2 or P3.

| Id | Severity | Assurance touched | What it is | State |
|---|---|---|---|---|
| A1 | P2 | Candidate binding: the readiness artifacts bind a `trust_anchor_digest` | The trust anchor lives in `audit_artifacts/`, the one directory the subject tree digest excludes. The anchor is therefore outside the digest that is supposed to pin the candidate's trust basis | open; follow-up release |
| A2 | P2 | `C4.1`/`C4.2`: completeness of the population they rule over | Both read their result without reading the `population_complete` bound — the same shape as `N17`, one gate over. A verdict from an incomplete population reads like a verdict over all of it | open; follow-up release |
| A3 | P3 | Evidence paths of the release-deciding checks | The evidence paths are hard-wired to `audit_artifacts/360` instead of being derived from the version under test. It works today because 6.0.0 reuses that directory; it silently reads the wrong release's evidence the moment it does not | open; follow-up release |
| A4 | P1 | `C12.2`: which key may sign the register | `not_after` was never evaluated on the register path, so an expired anchor key kept the ability to sign the register — a revocation by lowering `not_after` would have looked effective and done nothing. **Closed**, in `7eba21e` and its two corrections `3385d80` and `2ba939b` | closed |

**`A4` is a code path changed AFTER the mutation run and after the closing round** — the same
disclosure the owner asked for in the earlier condition about `7eba21e`. No gate round saw it. What
did see it: the mandatory review lane (which rejected the first attempt), four catch-proofs with
planted defects, a before/after comparison of all 33 matrix checks with no verdict change, and the
full test suite.

## What "0 open P0/P1" can and cannot say (owner condition 4, card `OA-3aef42655d`)

**Zero open P0 and P1 speaks only about the findings already found.** It is a statement about the
contents of the register at its time cut, never about the tree. `A4` above proves the point in the
sharpest possible way: it is a **P1**, it was found *after* the register was signed, and while it
was open the register still said 0 open P0/P1 — truthfully, because nobody had found it yet.

This is the sixth instance of one class on a single day, and this time it sits in the register
itself. The other five: a mutation figure that ruled over a subset of the suite without saying so; a
parity gate ruling from the absence of complaints; `C4.1`/`C4.2` ruling without the completeness
bound; a coverage figure that paired a class count with a node count; and a test-count in the README
that described a tree that no longer existed. The shared shape is always the same — **a verdict over
an excerpt, phrased as a verdict over the whole.** The honest form names the excerpt in the same
sentence as the verdict, which is what this section does for the register.

## The distribution digests name the candidate build, not the package (owner card `OA-b92bd4ff84`)

The readiness artifacts bind `candidate.sdist_sha256` and `candidate.wheel_sha256`. **Those two
values identify the candidate build on `a382eae`.** They are not a statement about the artifact
published to PyPI or attached to the release; **the digests of the shipped artifacts are in the
release's `SHA256SUMS`**, outside this tree.

Measured before signing anything, in a real clone with two worktrees: `SOURCE_DATE_EPOCH` comes from
the HEAD commit's time, so a build on the commit the tag carries yields *different* digests than the
build on `a382eae` — `168d1e4c…`/`be66743a…` versus `c4490ac4…`/`58759ce9…` — at identical byte size,
because only the embedded timestamps move. `audit_artifacts/` is not in the package at all
(`MANIFEST.in`: `prune audit_artifacts`), so a later evidence commit changes the clock and nothing
else.

Both fields are MANDATORY parts of the candidate binding, and the gate recomputes them from the
files in `dist/` at gate time, never from a fresh build — so they bind *evidence to candidate*, and
must not be read as an assurance about the installed package. Pinning the epoch to the candidate
commit is the cleaner mechanism and is deferred to 6.1 by the same owner decision, because it
changes the release path itself.

## Honest limit of this file

Written by the same agent that made the changes, before the closing round, from measurements
taken on 2026-09-05 at `658ed063` and from the 5.1.0 record. It lists what is known to be open; it
does not list what no lens has looked for yet. Coverage of the measurements above is one
interpreter (CPython 3.10) and one platform; the Rust counter implementation was not run.

## Three matrix lines are RED because their binding broke, not because a measurement failed (owner instruction 2026-09-07, path A)

Measured on 2026-09-07 with `PYTHONPATH=src python scripts/audit_candidate_matrix.py --json`
against head `ca2478d8f4dda53f25df4ee6a3dbe9ea462a7159`: **28 PASS, 4 FAIL, 1 EXTERNAL_PENDING**,
`version_pin` `bound`. Three of the four FAILs are the lines below; the fourth was C12.1, and it is
closed by the receipt this release carries.

- **C6.2** — `audit_artifacts/360/fuzz_soak_latest.json` binds commit `9e742bfa989e`, and the head
  measured against was `ca2478d8f4dd`. The gate allows a bound commit only when every path changed
  since it lies inside the mutable-evidence set.
- **C6.3** — the same artefact, `audit_artifacts/360/fuzz_soak_latest.json`, binds commit
  `9e742bfa989e` against head `ca2478d8f4dd`. C6.3 additionally stays `DATA_BLOCKED` for 6.0.0 on
  its own merits: the recorded soak is a 300 s smoke, not the full 24 h artefact, and the artefact
  says so itself via `is_full_soak_24h=false`.
- **C8.2** — `audit_artifacts/360/rust_differential_matrix.json` binds commit `9e742bfa989e`
  against head `ca2478d8f4dd`.

**These three are binding breaks caused by the two freeze commits, not substantive defects.** The
two freeze commits landed the fixes the required gate demanded — three `ruff` violations, and three
assertions in one test file that had nailed transitional states down as invariants. Neither commit
touched the measurements these artefacts carry; both moved the head they are bound to.

Why they were not re-signed: `tree_digest` (the readiness artefacts) excludes recursively exactly
the two mutable paths — and a receipt committed under `audit_artifacts/600/` is not one of them.

**CORRECTED 2026-09-07, because the sentence that stood here described a function this branch has
since changed.** It read: "`subject_tree_digest` (the receipt) excludes the whole top-level
`audit_artifacts` entry and is therefore unchanged by any commit into it". That was true until
`b9d35d4`. The whole-directory exclusion is exactly the hole that commit closed — it hid the trust
anchors from the binding, so a key could be introduced in the very commit it would go on to
authorise. `subject_tree_digest` now excludes only the receipt file itself (a pattern, since every
version writes its own) plus the same two mutable paths.

Measured on the new function, four ceremony steps:

| step | old digest | new digest |
|---|---|---|
| the receipt itself is committed | stable | stable |
| an audit record beside it, same version folder | stable | **moves** |
| a mutable evidence file is rewritten | stable | stable |
| a key is added to the trust anchor | stable | **moves** |

The last row is the point of the change. The second row is a NEW ORDERING CONSTRAINT and is
recorded here so nobody rediscovers it during a signing round: **everything else under
`audit_artifacts/<token>/` must be committed BEFORE the receipt context is produced.** Anything
written there after signing invalidates the receipt. The natural order already satisfies this — the
gate reads the audit record from the committed tree, so the record must exist before the gate runs
— but it is now load-bearing rather than incidental.

What this does NOT break: the already-shipped v5.0.0 and v5.1.0 receipts. Measured — each binds
`gate_source_digest = fa6a019b…`, which matches `scripts/pre_tag_audit_gate.py` **in its own tag
tree** and already differs from today's head (`44f7d50c…`). Those receipts were therefore only ever
re-verifiable by checking the tag out, where the old gate and the old library sit together and
agree. That path is untouched. The combination the new function does change — today's library
against an old tree — already failed on `gate_source_digest` before this commit. **There is no commit order in which both bind the
head they are checked at.** Re-signing the readiness artefacts would require a second owner
signature after the receipt commit; the owner decided one signature round (2026-09-07, path A) and
required this section instead. The tag path is not affected: `.github/workflows/release.yml` line 76
runs `pre_tag_audit_gate.py --repo . --version <v> --strict` as its only audit check, and the
candidate matrix does not run there.

**A number in this section that a later commit makes stale.** `ca2478d8f4dd` was the head when the
matrix was run; committing this very section moves the head again. The statement is therefore
written as a *measurement with its date and object*, not as a claim about the current head. What
stays true regardless is the part that carries the finding: the three artefacts bind
`9e742bfa989e`, and every head after it is a later one. Register entry:
`ZAHL-IM-TEXT-STATT-PLATZHALTER-VERALTET-STILL-01`.

## The release gate loads its signature check from the tree it judges (owner decision 2026-09-07, path A)

Finding `DAS-TOR-LAEDT-SEINEN-VERIFIZIERER-AUS-DEM-BAUM-DEN-ES-BEURTEILT-01`. Carried into 6.0.0
**knowingly**, on an explicit owner decision: path A, an entry here now, the fix as the first card
after the tag.

**The attack, reproduced — not argued.** `scripts/pre_tag_receipt_lib.py` imports `verify_ed25519`
from `proofbundle.signature`, and when the gate runs against a checkout, that module comes from the
very tree the gate is about to judge. Three probes failed before one worked, and the two that failed
are worth recording because they mark the boundary of the finding:

* *Does not work:* a **foreign** signer — it dies at `signer_pubkey is not in the trusted set`, and
  that check runs **before** the signature check.
* *Does not work:* a **committed** backdoor — it breaks the tree binding anyway.
* *Works:* the attacker takes the trusted public key **out of the anchor** (it is committed in the
  repo), sets it as `signer_pubkey`, forges the signature — and replaces
  `src/proofbundle/signature.py` **in the working tree only**. No private key is needed.

Measured, two repositories, one state each:

| case | without the fix | with the fix |
|---|---|---|
| forged signature, clean working tree | `ok=False` | `ok=False` |
| the same case, `signature.py` replaced in the working tree | **`ok=True`** | `ok=False` |

**Why this is acceptable for 6.0.0, and the reasoning is the owner's.** The working step the attack
needs is *write access to the release tree at signing time*. That is exactly the trust boundary the
release process already assumes: an actor who can rewrite the tree between the audit and the
signature can also rewrite what is signed. The gate does not defend against its own operator, and it
never claimed to. What the finding shows is that the gate is **not an additional layer** against
that actor — not that a new door was opened.

**Scope of the pending fix, measured:** 25 files in the tree name `verify_ed25519` (six modules under
`src/proofbundle`, three scripts). The prepared patch touches **one** — the import line in
`scripts/pre_tag_receipt_lib.py`. `proofbundle.signature` stays untouched; what changes is the source
**the gate** takes its check from, and only there does the judged tree sit on `sys.path[0]`.

**Not measured:** whether that patch passes the full suite. It has never run against the candidate,
because the candidate is what this release ships. It belongs to the round that lands it.

**The condition under which this entry would have been wrong.** The owner tied path A to the register
not carrying this finding as P0 or P1. Measured on this candidate: the register carries ten P2 and
ten P3 entries and **no** P0 or P1 at all, so condition 6 of the release standard does not engage and
path A stands. Register key: `DAS-TOR-LAEDT-SEINEN-VERIFIZIERER-AUS-DEM-BAUM-DEN-ES-BEURTEILT-01`.
